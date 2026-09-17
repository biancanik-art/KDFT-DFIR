use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use anyhow::{bail, Context, Result};
use rusqlite::{params, TransactionBehavior};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::progress;
use crate::types::{CarveOptions, CarveResult};
use crate::{
    active_case_id, add_entry_category, audit_actor, available_processing_worker_count,
    ensure_evidence_source, open_disk_image, open_existing_case,
    upsert_filesystem_entry_with_content, CONTENT_INDEX_BYTES,
};

pub const CARVE_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const CARVE_LENGTH_CHUNK_BYTES: usize = 64 * 1024;
/// Formats without a supported footer or declared-size rule cannot be allowed
/// to claim the rest of a disk after a coincidental header. This is a disclosed
/// protective extent limit, not a completeness claim: hitting it makes both
/// the carved entry and the carve job explicitly truncated.
pub const CARVE_UNKNOWN_LENGTH_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct CarveSignature {
    pub header: &'static [u8],
    pub extension: &'static str,
    pub label: &'static str,
}

pub const CARVE_SIGNATURES: &[CarveSignature] = &[
    CarveSignature {
        header: &[0xFF, 0xD8, 0xFF],
        extension: "jpg",
        label: "JPEG image",
    },
    CarveSignature {
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        extension: "png",
        label: "PNG image",
    },
    CarveSignature {
        header: &[0x47, 0x49, 0x46, 0x38],
        extension: "gif",
        label: "GIF image",
    },
    CarveSignature {
        header: &[0x25, 0x50, 0x44, 0x46, 0x2D],
        extension: "pdf",
        label: "PDF document",
    },
    CarveSignature {
        header: &[0x50, 0x4B, 0x03, 0x04],
        extension: "zip",
        label: "ZIP/Office container",
    },
    CarveSignature {
        header: &[0x42, 0x4D],
        extension: "bmp",
        label: "BMP image",
    },
    CarveSignature {
        header: &[0x1F, 0x8B, 0x08],
        extension: "gz",
        label: "GZIP stream",
    },
    CarveSignature {
        header: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
        extension: "rar",
        label: "RAR archive",
    },
];

/// Examiner-driven signature carving: scans the decoded image for known file
/// headers and records each hit as a carved file under
/// /Image Analysis/Carved. Never runs automatically. A zero scan-size or file
/// limit means unlimited. Explicit examiner limits and protective extent
/// limits are always reflected by a truncated job with a reason; carved bytes
/// are served on demand via the physical-extent reader rather than copied into
/// the case database.
pub fn carve_evidence(
    case_path: &Path,
    evidence_id: i64,
    options: CarveOptions,
) -> Result<CarveResult> {
    carve_evidence_with_protective_limit(
        case_path,
        evidence_id,
        options,
        CARVE_UNKNOWN_LENGTH_MAX_BYTES,
    )
}

pub(crate) fn carve_evidence_with_protective_limit(
    case_path: &Path,
    evidence_id: i64,
    options: CarveOptions,
    unknown_length_limit: u64,
) -> Result<CarveResult> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let (source_kind, source_path): (String, String) = conn.query_row(
        "SELECT source_kind, source_path FROM evidence_sources
         WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if source_kind != "image" {
        bail!("carving is only supported for disk-image evidence");
    }

    let mut opened = open_disk_image(Path::new(&source_path))?;
    let scan_limit = if options.max_scan_bytes == 0 {
        opened.decoded_size
    } else {
        options.max_scan_bytes.min(opened.decoded_size)
    };
    progress::progress_set_unit("bytes");
    progress::progress_set_total(Some(scan_limit));
    progress::progress_current(source_path.clone());
    // Zero is the public unlimited value. Keep that requested value in job
    // provenance rather than disguising it as usize::MAX/i64::MAX.
    let max_files = if options.max_files == 0 {
        usize::MAX
    } else {
        options.max_files
    };
    let effective_max_files =
        (options.max_files != 0).then(|| i64::try_from(options.max_files).unwrap_or(i64::MAX));
    let overlap = CARVE_SIGNATURES
        .iter()
        .map(|sig| sig.header.len())
        .max()
        .unwrap_or(8);
    let signature_matcher = AhoCorasick::builder()
        .match_kind(MatchKind::Standard)
        .build(CARVE_SIGNATURES.iter().map(|signature| signature.header))
        .context("building the raw-carve multi-signature matcher")?;
    let signature_matcher_kind = match signature_matcher.kind() {
        AhoCorasickKind::DFA => "aho-corasick-dfa",
        AhoCorasickKind::ContiguousNFA => "aho-corasick-contiguous-nfa",
        AhoCorasickKind::NoncontiguousNFA => "aho-corasick-noncontiguous-nfa",
        _ => "aho-corasick",
    };
    let cpu_worker_threads = available_processing_worker_count();

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'carve', 'running',
                 json_object('max_scan_bytes', ?3,
                             'effective_scan_bytes', ?4,
                             'max_files', ?5,
                             'effective_max_files', ?6,
                             'signature_matcher', ?7,
                             'cpu_worker_threads', ?8,
                             'gpu_acceleration', 'not used: bounded CPU matcher plus parallel EWF decompression is the deterministic path'),
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![
            case_id,
            evidence_id,
            i64::try_from(options.max_scan_bytes).unwrap_or(i64::MAX),
            i64::try_from(scan_limit).unwrap_or(i64::MAX),
            i64::try_from(options.max_files).unwrap_or(i64::MAX),
            effective_max_files,
            signature_matcher_kind,
            i64::try_from(cpu_worker_threads).unwrap_or(i64::MAX),
        ],
    )?;
    let job_id = tx.last_insert_rowid();
    progress::progress_set_job_id(job_id);

    let mut carved = 0_usize;
    let mut truncated = false;
    let mut truncation_reasons = Vec::new();
    let mut protective_extent_limit_hits = 0_usize;
    let mut carry: Vec<u8> = Vec::new();
    let mut carry_base = 0_u64;
    let mut scan_cursor = 0_u64;
    let mut bytes_scanned = 0_u64;
    let mut min_next_offset = 0_u64;
    let mut buffer = vec![0_u8; CARVE_CHUNK_BYTES];

    'scan: while scan_cursor < scan_limit {
        opened.reader.seek(SeekFrom::Start(scan_cursor))?;
        let want = ((scan_limit - scan_cursor) as usize).min(CARVE_CHUNK_BYTES);
        let read = opened.reader.read(&mut buffer[..want])?;
        if read == 0 {
            let reason = format!(
                "carving source reached an unexpected end after {scan_cursor} of {scan_limit} requested decoded bytes"
            );
            truncated = true;
            truncation_reasons.push(reason.clone());
            progress::progress_truncated(reason);
            break;
        }
        bytes_scanned = scan_cursor.saturating_add(read as u64);
        // Window = leftover overlap from the previous chunk + this chunk, so a
        // header straddling a chunk boundary is still detected.
        let mut window = std::mem::take(&mut carry);
        window.extend_from_slice(&buffer[..read]);
        // There is no future chunk to complete an overlap at the end of the
        // requested scan scope, so the final trailing bytes are searchable now.
        let searchable = if bytes_scanned >= scan_limit {
            window.len()
        } else {
            window.len().saturating_sub(overlap)
        };
        for signature_match in signature_matcher.find_overlapping_iter(&window) {
            let index = signature_match.start();
            if index >= searchable {
                break;
            }
            let absolute = carry_base + index as u64;
            if absolute < min_next_offset {
                continue;
            }
            let sig = &CARVE_SIGNATURES[signature_match.pattern().as_usize()];
            let available_len = scan_limit.saturating_sub(absolute);
            let carved_length = carve_length_with_protective_limit(
                &mut *opened.reader,
                absolute,
                sig,
                available_len,
                unknown_length_limit,
            )?;
            let length = carved_length.length;
            opened.reader.seek(SeekFrom::Start(scan_cursor))?;
            if length < sig.header.len() as u64 {
                continue;
            }
            carved += 1;
            // A measured file can suppress nested signatures inside its own
            // bytes. An unverified extent must not hide later independent
            // headers merely because its provisional bound is large.
            min_next_offset = absolute.saturating_add(if carved_length.definitive {
                length
            } else {
                sig.header.len() as u64
            });
            let name = format!("carved-{carved:05}-0x{absolute:X}.{}", sig.extension);
            let logical_path = format!("/Image Analysis/Carved/{name}");
            let extent_truncation_reason = carved_length.protective_limit_hit.then(|| {
                format!(
                    "{} at decoded offset 0x{absolute:X} reached the {}-byte protective extent limit; its end was not verified",
                    sig.label, unknown_length_limit
                )
            });
            if extent_truncation_reason.is_some() {
                protective_extent_limit_hits = protective_extent_limit_hits.saturating_add(1);
            }
            let mut metadata = serde_json::json!({
                "artifact_kind": "carved_file",
                "recovery_source": "signature_carving",
                "recovery_status": if carved_length.definitive {
                    "carved from image by file signature"
                } else {
                    "carved from image by file signature (length not verified - see carve_length_basis)"
                },
                "recovery_read": "physical_extent",
                "storage_area": "carved",
                "carve_format": sig.label,
                "carve_signature": sig
                    .header
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                "carve_length_basis": carved_length.basis,
                "carve_length_definitive": carved_length.definitive,
                "carve_extent_truncated": carved_length.protective_limit_hit,
                "carve_extent_truncation_reason": extent_truncation_reason,
                "carve_protective_extent_limit_bytes": if carved_length.protective_limit_hit {
                    Some(unknown_length_limit)
                } else {
                    None
                },
                "file_data_physical_offset": absolute,
                "file_data_logical_offset": absolute,
                "size_bytes": length,
            });
            add_entry_category(&mut metadata, &logical_path, &name, "file");
            let content_head = {
                let head_len = (CONTENT_INDEX_BYTES as u64).min(length) as usize;
                let mut head = vec![0_u8; head_len];
                opened.reader.seek(SeekFrom::Start(absolute))?;
                let head_read = opened.reader.read(&mut head)?;
                head.truncate(head_read);
                opened.reader.seek(SeekFrom::Start(scan_cursor))?;
                head
            };
            upsert_filesystem_entry_with_content(
                &tx,
                case_id,
                evidence_id,
                &logical_path,
                &name,
                "file",
                Some(i64::try_from(length).unwrap_or(i64::MAX)),
                &metadata.to_string(),
                job_id,
                Some(&content_head),
            )?;
            if carved >= max_files {
                let reason =
                    format!("carving stopped at the examiner-requested {max_files} file limit");
                truncated = true;
                truncation_reasons.push(reason.clone());
                progress::progress_truncated(reason);
                progress::progress_set_processed(bytes_scanned, Some(source_path.clone()));
                break 'scan;
            }
        }
        // Preserve the trailing overlap so a boundary-spanning header survives.
        let keep = window.len().min(overlap);
        carry_base += (window.len() - keep) as u64;
        carry = window.split_off(window.len() - keep);
        scan_cursor += read as u64;
        progress::progress_set_processed(scan_cursor, Some(source_path.clone()));
    }

    if scan_limit < opened.decoded_size {
        let reason = format!(
            "carving scanned {scan_limit} of {} decoded bytes because of the examiner-requested scan limit",
            opened.decoded_size
        );
        truncated = true;
        truncation_reasons.push(reason.clone());
        progress::progress_truncated(reason);
    }
    if protective_extent_limit_hits > 0 {
        let reason = format!(
            "{protective_extent_limit_hits} carved extent(s) reached the {}-byte protective limit because their formats have no supported end rule; each affected entry records its exact decoded offset and cutoff reason",
            unknown_length_limit
        );
        truncated = true;
        truncation_reasons.push(reason.clone());
        progress::progress_truncated(reason);
    }

    let status = if truncated { "truncated" } else { "completed" };
    let truncation_reason = truncated.then(|| truncation_reasons.join("; "));
    let truncation_reasons_json = serde_json::to_string(&truncation_reasons)
        .context("serializing carve truncation reasons")?;
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?2,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             error = ?3,
             parameters_json = json_set(
                 parameters_json,
                 '$.carved_files', ?4,
                 '$.bytes_scanned', ?5,
                 '$.truncated', json(?6),
                 '$.protective_extent_limit_hits', ?7,
                 '$.truncation_reasons', json(?8))
         WHERE id = ?1",
        params![
            job_id,
            status,
            truncation_reason,
            i64::try_from(carved).unwrap_or(i64::MAX),
            i64::try_from(bytes_scanned).unwrap_or(i64::MAX),
            if truncated { "true" } else { "false" },
            i64::try_from(protective_extent_limit_hits).unwrap_or(i64::MAX),
            truncation_reasons_json,
        ],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.carve', ?2, 'evidence', ?3,
                 json_object('job_id', ?4,
                             'carved_files', ?5,
                             'bytes_scanned', ?6,
                             'truncated', ?7,
                             'status', ?8,
                             'truncation_reason', ?9,
                             'protective_extent_limit_hits', ?10))",
        params![
            case_id,
            actor,
            evidence_id,
            job_id,
            i64::try_from(carved).unwrap_or(i64::MAX),
            i64::try_from(bytes_scanned).unwrap_or(i64::MAX),
            truncated,
            status,
            truncation_reason,
            i64::try_from(protective_extent_limit_hits).unwrap_or(i64::MAX),
        ],
    )?;
    tx.commit()?;

    Ok(CarveResult {
        evidence_id,
        carved_files: carved,
        bytes_scanned,
        truncated,
        status: status.to_string(),
        truncation_reasons,
        protective_extent_limit_hits,
    })
}

/// How a carved file's recorded length was established. An examiner must be
/// able to tell a measured length (structure footer, valid declared size)
/// from a fallback cap - a capped length means "the real end was never
/// found", and exporting such a carve yields window-sized bytes, not a
/// verified file.
pub(crate) struct CarvedLength {
    pub(crate) length: u64,
    pub(crate) basis: &'static str,
    pub(crate) definitive: bool,
    pub(crate) protective_limit_hit: bool,
}

struct FooterSearchResult {
    length: Option<u64>,
    bytes_read: u64,
}

/// Determines a carved extent's length without loading the extent into memory.
/// Footer-based formats are searched through the entire available scan scope
/// using a bounded rolling window. Only formats for which KDFT has no reliable
/// end rule use the disclosed protective limit. The limit is injected so the
/// cutoff behavior can be tested with tiny deterministic fixtures.
pub(crate) fn carve_length_with_protective_limit(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start: u64,
    sig: &CarveSignature,
    available_len: u64,
    unknown_length_limit: u64,
) -> Result<CarvedLength> {
    if available_len == 0 {
        return Ok(CarvedLength {
            length: 0,
            basis: "no data available at carve offset",
            definitive: false,
            protective_limit_hit: false,
        });
    }

    let footer_rule = match sig.extension {
        "jpg" => Some((&[0xFF, 0xD9][..], 0)),
        "png" => Some((&[0x49, 0x45, 0x4E, 0x44][..], 4)),
        "gif" => Some((&[0x00, 0x3B][..], 0)),
        // Stop at the first complete PDF revision. Searching to the last EOF
        // in the remaining disk could merge later, independent PDF files into
        // this carve and suppress their headers from the main scan.
        "pdf" => Some((b"%%EOF" as &[u8], 0)),
        _ => None,
    };
    if let Some((footer, trailing)) = footer_rule {
        let search = stream_footer_search(reader, start, available_len, footer, trailing)?;
        return Ok(match search.length {
            Some(length) => CarvedLength {
                length,
                basis: "format footer signature located by streaming search",
                definitive: true,
                protective_limit_hit: false,
            },
            None => CarvedLength {
                length: search.bytes_read,
                basis: "no footer found before end of available scan scope; end not verified",
                definitive: false,
                protective_limit_hit: false,
            },
        });
    }

    if sig.extension == "bmp" {
        let mut header = [0_u8; 6];
        let mut filled = 0_usize;
        reader.seek(SeekFrom::Start(start))?;
        let wanted =
            usize::try_from(available_len.min(header.len() as u64)).unwrap_or(header.len());
        while filled < wanted {
            let read = reader.read(&mut header[filled..wanted])?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled >= header.len() {
            let declared = u64::from(u32::from_le_bytes([
                header[2], header[3], header[4], header[5],
            ]));
            if declared >= sig.header.len() as u64 {
                return Ok(if declared <= available_len {
                    CarvedLength {
                        length: declared,
                        basis: "BMP header declared file size",
                        definitive: true,
                        protective_limit_hit: false,
                    }
                } else {
                    CarvedLength {
                        length: available_len,
                        basis: "BMP header declared size exceeded the available scan scope; end not verified",
                        definitive: false,
                        protective_limit_hit: false,
                    }
                });
            }
        }
    }

    // ZIP, GZIP and RAR currently have no validated structural end parser in
    // the carving path. Bound those ambiguous extents, but make the cutoff a
    // first-class truncation fact instead of silently presenting it as a file.
    let protective_limit = unknown_length_limit.max(sig.header.len() as u64);
    let read_limit = available_len.min(protective_limit);
    reader.seek(SeekFrom::Start(start))?;
    let buffer_len = CARVE_LENGTH_CHUNK_BYTES
        .min(usize::try_from(read_limit).unwrap_or(usize::MAX))
        .max(1);
    let mut buffer = vec![0_u8; buffer_len];
    let mut bytes_read = 0_u64;
    while bytes_read < read_limit {
        let wanted = usize::try_from((read_limit - bytes_read).min(buffer.len() as u64))
            .unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            break;
        }
        bytes_read += read as u64;
    }
    let protective_limit_hit = bytes_read == read_limit && read_limit < available_len;
    Ok(CarvedLength {
        length: bytes_read,
        basis: if protective_limit_hit {
            "no supported end rule; protective extent limit reached, end not verified"
        } else {
            "no supported end rule before end of available scan scope; end not verified"
        },
        definitive: false,
        protective_limit_hit,
    })
}

fn stream_footer_search(
    reader: &mut dyn disk_forensic::container::ReadSeek,
    start: u64,
    available_len: u64,
    footer: &[u8],
    trailing: usize,
) -> Result<FooterSearchResult> {
    if footer.is_empty() || available_len == 0 {
        return Ok(FooterSearchResult {
            length: None,
            bytes_read: 0,
        });
    }
    reader.seek(SeekFrom::Start(start))?;
    let mut buffer = vec![0_u8; CARVE_LENGTH_CHUNK_BYTES];
    let mut tail = Vec::new();
    let mut bytes_read = 0_u64;
    let keep = footer.len().saturating_add(trailing).saturating_sub(1);

    while bytes_read < available_len {
        let wanted = usize::try_from((available_len - bytes_read).min(buffer.len() as u64))
            .unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            break;
        }
        let window_base = bytes_read.saturating_sub(tail.len() as u64);
        let mut window = std::mem::take(&mut tail);
        window.extend_from_slice(&buffer[..read]);
        bytes_read += read as u64;

        if window.len() >= footer.len().saturating_add(trailing) {
            for pos in 0..=window.len() - footer.len() {
                if &window[pos..pos + footer.len()] != footer {
                    continue;
                }
                let end = pos.saturating_add(footer.len()).saturating_add(trailing);
                if end > window.len() {
                    continue;
                }
                let length = window_base.saturating_add(end as u64);
                return Ok(FooterSearchResult {
                    length: Some(length),
                    bytes_read,
                });
            }
        }

        let keep_now = keep.min(window.len());
        tail = window.split_off(window.len() - keep_now);
    }

    Ok(FooterSearchResult {
        length: None,
        bytes_read,
    })
}
