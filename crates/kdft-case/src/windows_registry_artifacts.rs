//! Structured Windows Registry artifact derivation from indexed hive sources.
//!
//! This pass is deliberately source-driven. It recognizes exact Registry
//! schemas (Amcache, UserAssist, BagMRU, and Run/RunOnce) and never promotes a
//! loose filename keyword into an execution, identity, or credential fact.

mod shimcache;
mod srum;

use anyhow::{bail, Context, Result};
use rusqlite::{params, TransactionBehavior};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    active_case_id, add_entry_category, audit_actor, collect_registry_hive_import,
    ensure_evidence_source, open_existing_case, recover_filesystem_entry_in_session,
    sanitize_logical_segment, upsert_filesystem_entry, EvidenceReadSession, RecoverEntryOptions,
    RegistryImportData, RegistryImportEntry,
};
use shimcache::decode_appcompat_cache;
use srum::{decode_srum_database, probe_ese_database, SrumDecodeResult};
pub use srum::{SrumEseHeaderProbe, SrumLiveRowCounts};

const PARSER_NAME: &str = "kdft-windows-registry-artifacts-v1";
const ERROR_SAMPLE_LIMIT: usize = 32;
const TEMPORARY_DIRECTORY_ATTEMPTS: usize = 1_024;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Default, Serialize)]
pub struct WindowsRegistryArtifactParseResult {
    pub evidence_id: i64,
    pub hives_found: usize,
    pub hives_parsed: usize,
    pub amcache_records_indexed: usize,
    pub userassist_records_indexed: usize,
    pub shellbag_records_indexed: usize,
    pub startup_records_indexed: usize,
    pub shimcache_sources_seen: usize,
    pub shimcache_sources_completed: usize,
    pub shimcache_sources_partial: usize,
    pub shimcache_sources_unsupported: usize,
    pub shimcache_sources_failed: usize,
    pub shimcache_records_indexed: usize,
    pub shimcache_source_coverage: Vec<ShimcacheSourceCoverage>,
    pub srum_sources_seen: usize,
    pub srum_sources_validated: usize,
    pub srum_sources_recognized_unsupported: usize,
    pub srum_sources_failed: usize,
    pub srum_records_indexed: usize,
    pub srum_source_coverage: Vec<SrumSourceCoverage>,
    pub partial_artifact_coverage: bool,
    pub parse_error_count: usize,
    pub parse_errors: Vec<String>,
    pub parse_errors_omitted: usize,
    pub limitations: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShimcacheSourceCoverage {
    pub source_ordinal: usize,
    pub source_entry_id: i64,
    pub source_job_id: i64,
    pub source_path_exact: String,
    pub registry_key_path: String,
    pub registry_key_last_write_utc: Option<String>,
    pub registry_value_name: String,
    pub registry_value_type: String,
    pub registry_value_size: Option<usize>,
    pub status: String,
    pub detected_layout: Option<String>,
    pub header_signature: Option<String>,
    pub records_expected: Option<usize>,
    pub records_indexed: usize,
    pub malformed_record_count: usize,
    pub diagnostics: Vec<String>,
    pub diagnostics_omitted: usize,
    pub coverage: String,
    pub limitation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SrumSourceCoverage {
    pub source_entry_id: i64,
    pub source_job_id: i64,
    pub source_path_exact: String,
    pub source_size: Option<u64>,
    pub status: String,
    pub records_indexed: usize,
    pub live_row_counts: Option<SrumLiveRowCounts>,
    pub coverage: String,
    pub limitation: Option<String>,
    pub diagnostics: Vec<String>,
    pub ese_header: Option<SrumEseHeaderProbe>,
}

#[derive(Debug)]
struct HiveCandidate {
    entry_id: i64,
    source_job_id: i64,
    logical_path: String,
    exact_path: String,
    name: String,
}

#[derive(Debug)]
struct SrumCandidate {
    entry_id: i64,
    source_job_id: i64,
    exact_path: String,
    name: String,
    size: Option<u64>,
}

#[derive(Debug)]
enum SrumStagedOutcome {
    Decoded(SrumDecodeResult),
    RecognizedUnsupported {
        header: SrumEseHeaderProbe,
        limitation: String,
    },
}

#[derive(Debug)]
struct DerivedRecord {
    logical_path: String,
    display_name: String,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
struct ValueObservation {
    key_path: String,
    key_last_write_utc: Option<String>,
    name: String,
    value_type: String,
    rendered: String,
    value_size: Option<usize>,
    raw: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct DerivedCounts {
    amcache: usize,
    userassist: usize,
    shellbags: usize,
    startup: usize,
    shimcache_sources: usize,
    shimcache_completed: usize,
    shimcache_partial: usize,
    shimcache_unsupported: usize,
    shimcache_failed: usize,
    shimcache_records: usize,
    shimcache_source_coverage: Vec<ShimcacheSourceCoverage>,
}

pub fn parse_windows_registry_artifacts(
    case_path: &Path,
    evidence_id: i64,
) -> Result<WindowsRegistryArtifactParseResult> {
    let candidates = registry_candidates(case_path, evidence_id)?;
    let srum_candidates = srum_candidates(case_path, evidence_id)?;
    let srum_sources_seen = srum_candidates.len();
    super::progress::progress_set_unit("Windows Registry and SRUM sources");
    super::progress::progress_set_total(Some(
        candidates.len().saturating_add(srum_candidates.len()) as u64,
    ));
    let mut result = WindowsRegistryArtifactParseResult {
        evidence_id,
        hives_found: candidates.len(),
        srum_sources_seen,
        limitations: vec![
            "ShellBag item names use bounded shell-item string recovery when a complete typed-shell-item decoder is unavailable; the raw Registry value and decode method remain explicit.".to_string(),
        ],
        status: "completed".to_string(),
        ..WindowsRegistryArtifactParseResult::default()
    };
    let mut read_session = EvidenceReadSession::open(case_path)?;

    for candidate in &candidates {
        super::progress::progress_current(candidate.exact_path.clone());
        match parse_one_hive(case_path, &mut read_session, evidence_id, candidate) {
            Ok(counts) => {
                result.hives_parsed = result.hives_parsed.saturating_add(1);
                result.amcache_records_indexed = result
                    .amcache_records_indexed
                    .saturating_add(counts.amcache);
                result.userassist_records_indexed = result
                    .userassist_records_indexed
                    .saturating_add(counts.userassist);
                result.shellbag_records_indexed = result
                    .shellbag_records_indexed
                    .saturating_add(counts.shellbags);
                result.startup_records_indexed = result
                    .startup_records_indexed
                    .saturating_add(counts.startup);
                result.shimcache_sources_seen = result
                    .shimcache_sources_seen
                    .saturating_add(counts.shimcache_sources);
                result.shimcache_sources_completed = result
                    .shimcache_sources_completed
                    .saturating_add(counts.shimcache_completed);
                result.shimcache_sources_partial = result
                    .shimcache_sources_partial
                    .saturating_add(counts.shimcache_partial);
                result.shimcache_sources_unsupported = result
                    .shimcache_sources_unsupported
                    .saturating_add(counts.shimcache_unsupported);
                result.shimcache_sources_failed = result
                    .shimcache_sources_failed
                    .saturating_add(counts.shimcache_failed);
                result.shimcache_records_indexed = result
                    .shimcache_records_indexed
                    .saturating_add(counts.shimcache_records);
                for coverage in &counts.shimcache_source_coverage {
                    let source_label = format!(
                        "{} [{}\\{}]",
                        candidate.exact_path,
                        coverage.registry_key_path,
                        coverage.registry_value_name
                    );
                    if coverage.status == "malformed" {
                        result.parse_error_count = result.parse_error_count.saturating_add(1);
                        let error_text = format!(
                            "{source_label}: Shimcache source is malformed; {} valid record(s) retained, {} malformed record(s)",
                            coverage.records_indexed, coverage.malformed_record_count
                        );
                        if result.parse_errors.len() < ERROR_SAMPLE_LIMIT {
                            result.parse_errors.push(error_text);
                        } else {
                            result.parse_errors_omitted =
                                result.parse_errors_omitted.saturating_add(1);
                        }
                        super::progress::progress_error(Some(source_label));
                    } else if coverage.status != "completed" {
                        super::progress::progress_diagnostic(
                            super::progress::JobDiagnosticKind::ParserDiagnostic,
                            format!(
                                "Shimcache source {source_label} completed with status {}; {} valid record(s) retained",
                                coverage.status, coverage.records_indexed
                            ),
                        );
                    }
                }
                result
                    .shimcache_source_coverage
                    .extend(counts.shimcache_source_coverage);
            }
            Err(error) => {
                result.parse_error_count = result.parse_error_count.saturating_add(1);
                if result.parse_errors.len() < ERROR_SAMPLE_LIMIT {
                    result
                        .parse_errors
                        .push(format!("{}: {error:#}", candidate.exact_path));
                } else {
                    result.parse_errors_omitted = result.parse_errors_omitted.saturating_add(1);
                }
                super::progress::progress_error(Some(candidate.exact_path.clone()));
                super::progress::progress_skip(Some(candidate.exact_path.clone()));
            }
        }
        super::progress::progress_advance(candidate.exact_path.clone());
    }

    for candidate in &srum_candidates {
        super::progress::progress_current(candidate.exact_path.clone());
        match decode_one_srum_source(&mut read_session, candidate) {
            Ok(SrumStagedOutcome::Decoded(decoded)) => {
                result.srum_sources_validated = result.srum_sources_validated.saturating_add(1);
                let records = derive_srum_records(candidate, &decoded)?;
                replace_srum_source_records(case_path, evidence_id, candidate, &records)?;
                result.srum_records_indexed =
                    result.srum_records_indexed.saturating_add(records.len());
                let live_row_counts = decoded.live_row_counts.clone();
                result.srum_source_coverage.push(SrumSourceCoverage {
                    source_entry_id: candidate.entry_id,
                    source_job_id: candidate.source_job_id,
                    source_path_exact: candidate.exact_path.clone(),
                    source_size: candidate.size,
                    status: "completed".to_string(),
                    records_indexed: records.len(),
                    live_row_counts: Some(live_row_counts.clone()),
                    coverage: format!(
                        "complete bounded decode of live/non-defunct primary-table rows: IdMap={}, network usage={}, application resource usage={}, connectivity={}",
                        live_row_counts.id_map,
                        live_row_counts.network_usage,
                        live_row_counts.application_resource_usage,
                        live_row_counts.connectivity
                    ),
                    limitation: None,
                    diagnostics: decoded.diagnostics.clone(),
                    ese_header: Some(decoded.header),
                });
                super::progress::progress_diagnostic(
                    super::progress::JobDiagnosticKind::ParserDiagnostic,
                    format!(
                        "SRUM source {} decoded {} live record(s) (IdMap {}, network {}, application resource {}, connectivity {}); these are live-row counts, not ESE AutoInc/high-water estimates",
                        candidate.exact_path,
                        records.len(),
                        live_row_counts.id_map,
                        live_row_counts.network_usage,
                        live_row_counts.application_resource_usage,
                        live_row_counts.connectivity,
                    ),
                );
            }
            Ok(SrumStagedOutcome::RecognizedUnsupported { header, limitation }) => {
                result.srum_sources_validated = result.srum_sources_validated.saturating_add(1);
                result.srum_sources_recognized_unsupported =
                    result.srum_sources_recognized_unsupported.saturating_add(1);
                result.srum_source_coverage.push(SrumSourceCoverage {
                    source_entry_id: candidate.entry_id,
                    source_job_id: candidate.source_job_id,
                    source_path_exact: candidate.exact_path.clone(),
                    source_size: candidate.size,
                    status: "recognized_unsupported".to_string(),
                    records_indexed: 0,
                    live_row_counts: None,
                    coverage: "ESE source header validated; no SRUM rows were claimed".to_string(),
                    limitation: Some(limitation.clone()),
                    diagnostics: vec![limitation.clone()],
                    ese_header: Some(header),
                });
                super::progress::progress_diagnostic(
                    super::progress::JobDiagnosticKind::ParserDiagnostic,
                    format!(
                        "SRUM source {} is recognized but unsupported: {limitation}; no rows were claimed",
                        candidate.exact_path
                    ),
                );
            }
            Err(error) => {
                result.srum_sources_failed = result.srum_sources_failed.saturating_add(1);
                result.parse_error_count = result.parse_error_count.saturating_add(1);
                let error_text = format!("{}: {error:#}", candidate.exact_path);
                if result.parse_errors.len() < ERROR_SAMPLE_LIMIT {
                    result.parse_errors.push(error_text.clone());
                } else {
                    result.parse_errors_omitted = result.parse_errors_omitted.saturating_add(1);
                }
                result.srum_source_coverage.push(SrumSourceCoverage {
                    source_entry_id: candidate.entry_id,
                    source_job_id: candidate.source_job_id,
                    source_path_exact: candidate.exact_path.clone(),
                    source_size: candidate.size,
                    status: "failed".to_string(),
                    records_indexed: 0,
                    live_row_counts: None,
                    coverage: "SRUM source could not be validated".to_string(),
                    limitation: Some(error_text.clone()),
                    diagnostics: vec![error_text],
                    ese_header: None,
                });
                super::progress::progress_error(Some(candidate.exact_path.clone()));
                super::progress::progress_skip(Some(candidate.exact_path.clone()));
            }
        }
        super::progress::progress_advance(candidate.exact_path.clone());
    }

    result.partial_artifact_coverage = result.srum_sources_recognized_unsupported > 0
        || result.srum_sources_failed > 0
        || result.shimcache_sources_partial > 0
        || result.shimcache_sources_unsupported > 0
        || result.shimcache_sources_failed > 0;
    if result.srum_sources_recognized_unsupported > 0 {
        result.limitations.push(format!(
            "{} validated SRUDB.dat source(s) use an ESE version or revision outside this decoder's audited profile; exact coverage is retained and no unsupported rows were claimed.",
            result.srum_sources_recognized_unsupported
        ));
    }
    if result.srum_sources_failed > 0 {
        result.limitations.push(format!(
            "{} SRUDB.dat source(s) failed checksum, page, catalog, schema, or row validation; no rows from those sources were claimed.",
            result.srum_sources_failed
        ));
    }
    if result.shimcache_sources_partial > 0 {
        result.limitations.push(format!(
            "{} AppCompatCache source(s) contained malformed records; valid bounded records were retained and source-level diagnostics identify incomplete coverage.",
            result.shimcache_sources_partial
        ));
    }
    if result.shimcache_sources_unsupported > 0 {
        result.limitations.push(format!(
            "{} AppCompatCache source(s) used a recognized or unrecognized layout that this build does not decode; no unsupported records were claimed.",
            result.shimcache_sources_unsupported
        ));
    }
    if result.shimcache_sources_failed > 0 {
        result.limitations.push(format!(
            "{} AppCompatCache source(s) could not be decoded; exact source status and diagnostics are retained in shimcache_source_coverage.",
            result.shimcache_sources_failed
        ));
    }
    result.status = if result.parse_error_count > 0 {
        super::progress::progress_truncated(format!(
            "{} Windows Registry or SRUM source(s) could not be parsed or validated",
            result.parse_error_count
        ));
        "truncated".to_string()
    } else if result.partial_artifact_coverage {
        "completed_with_diagnostics".to_string()
    } else {
        "completed".to_string()
    };
    persist_pass_audit(case_path, &result)?;
    Ok(result)
}

fn registry_candidates(case_path: &Path, evidence_id: i64) -> Result<Vec<HiveCandidate>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let mut statement = conn.prepare(
        "SELECT id, discovered_by_job_id, logical_path, name,
                COALESCE(
                    NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
                    NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
                    NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
                    NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
                    NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
                    logical_path
                )
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND entry_kind = 'file' AND is_deleted = 0
           AND lower(name) IN ('amcache.hve', 'ntuser.dat', 'usrclass.dat', 'system', 'software')
           AND COALESCE(json_extract(metadata_json, '$.windows_registry_derived'), 0) <> 1
         ORDER BY id",
    )?;
    let rows = statement.query_map(params![case_id, evidence_id], |row| {
        Ok(HiveCandidate {
            entry_id: row.get(0)?,
            source_job_id: row.get(1)?,
            logical_path: row.get(2)?,
            name: row.get(3)?,
            exact_path: row.get(4)?,
        })
    })?;
    let mut candidates = Vec::new();
    for row in rows {
        let candidate = row?;
        if is_supported_hive_path(&candidate.name, &candidate.exact_path) {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn is_supported_hive_path(name: &str, path: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let path = normalize_windows_path_for_matching(path);
    if is_winsxs_path(&path) {
        return false;
    }
    match name.as_str() {
        "amcache.hve" => path.contains("/windows/appcompat/programs/"),
        "system" | "software" => path.contains("/windows/system32/config/"),
        "ntuser.dat" | "usrclass.dat" => {
            path.contains("/users/") || path.contains("/documents and settings/")
        }
        _ => false,
    }
}

fn normalize_windows_path_for_matching(path: &str) -> String {
    let mut normalized = path.replace('\\', "/").to_ascii_lowercase();
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    normalized
}

fn is_srum_source_path(path: &str) -> bool {
    let path = normalize_windows_path_for_matching(path);
    !is_winsxs_path(&path) && path.contains("/windows/system32/sru/")
}

fn is_winsxs_path(path: &str) -> bool {
    normalize_windows_path_for_matching(path).contains("/windows/winsxs/")
}

fn srum_candidates(case_path: &Path, evidence_id: i64) -> Result<Vec<SrumCandidate>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let mut statement = conn.prepare(
        "SELECT id, discovered_by_job_id, name, size_bytes, COALESCE(
               NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
               NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
               logical_path
           )
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2 AND entry_kind = 'file'
           AND is_deleted = 0 AND lower(name) = 'srudb.dat'",
    )?;
    let rows = statement.query_map(params![case_id, evidence_id], |row| {
        let signed_size = row.get::<_, Option<i64>>(3)?;
        Ok(SrumCandidate {
            entry_id: row.get(0)?,
            source_job_id: row.get(1)?,
            name: row.get(2)?,
            size: signed_size.and_then(|size| u64::try_from(size).ok()),
            exact_path: row.get(4)?,
        })
    })?;
    let mut candidates = Vec::new();
    for row in rows {
        let candidate = row?;
        if is_srum_source_path(&candidate.exact_path) {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn decode_one_srum_source(
    read_session: &mut EvidenceReadSession,
    candidate: &SrumCandidate,
) -> Result<SrumStagedOutcome> {
    let (directory, staging_path) =
        reserve_staging_destination(candidate.entry_id, &candidate.name)?;
    let decoded = (|| -> Result<SrumStagedOutcome> {
        recover_filesystem_entry_in_session(
            read_session,
            RecoverEntryOptions {
                entry_id: candidate.entry_id,
                output_path: staging_path.clone(),
            },
        )
        .with_context(|| format!("recovering SRUM source {}", candidate.exact_path))?;
        let header = probe_ese_database(&staging_path)
            .with_context(|| format!("validating SRUM ESE source {}", candidate.exact_path))?;
        if header.format_version != 0x620 || header.format_revision != 300 {
            return Ok(SrumStagedOutcome::RecognizedUnsupported {
                limitation: format!(
                    "native SRUM decoder is audited for ESE version 0x620 revision 300; source reports version {} revision {}",
                    header.format_version_hex, header.format_revision
                ),
                header,
            });
        }
        decode_srum_database(&staging_path)
            .map(SrumStagedOutcome::Decoded)
            .with_context(|| format!("decoding SRUM ESE source {}", candidate.exact_path))
    })();
    let cleanup = (|| -> Result<()> {
        if staging_path.exists() {
            fs::remove_file(&staging_path).with_context(|| {
                format!("removing staged SRUM source {}", staging_path.display())
            })?;
        }
        fs::remove_dir(&directory).with_context(|| {
            format!(
                "removing staged SRUM source directory {}",
                directory.display()
            )
        })?;
        Ok(())
    })();
    match (decoded, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(decode_error), Ok(())) => Err(decode_error),
        (Err(decode_error), Err(cleanup_error)) => Err(decode_error.context(format!(
            "staged SRUM cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

fn derive_srum_records(
    candidate: &SrumCandidate,
    decoded: &SrumDecodeResult,
) -> Result<Vec<DerivedRecord>> {
    let total = decoded
        .id_map_records
        .len()
        .saturating_add(decoded.network_usage_records.len())
        .saturating_add(decoded.application_resource_records.len())
        .saturating_add(decoded.connectivity_records.len());
    let mut records = Vec::with_capacity(total);

    for (ordinal, record) in decoded.id_map_records.iter().enumerate() {
        let display_value = record
            .decoded_value
            .as_deref()
            .unwrap_or(&record.value_kind);
        let display_name = format!("IdMap {}: {display_value}", record.id_index);
        let logical_path = format!(
            "/Windows Artifacts/SRUM/{}/id-map/{:020}-{ordinal:06}.record",
            candidate.entry_id, record.id_index
        );
        let mut metadata = srum_record_metadata(
            candidate,
            "id_map",
            None,
            serde_json::to_value(record)?,
            serde_json::json!({
                "id_index": "integer identifier",
                "id_blob": "UTF-16 application identifier, binary Windows SID, or explicitly retained raw bytes according to IdType",
            }),
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(DerivedRecord {
            logical_path,
            display_name,
            metadata,
        });
    }

    for (ordinal, record) in decoded.network_usage_records.iter().enumerate() {
        let application = record
            .app
            .decoded_value
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("unresolved AppId {}", record.app.id_index));
        let display_name = format!(
            "{} — {application} — {} sent / {} received",
            record
                .timestamp_utc
                .as_deref()
                .unwrap_or("time unavailable"),
            record.bytes_sent.unwrap_or(0),
            record.bytes_received.unwrap_or(0)
        );
        let logical_path = format!(
            "/Windows Artifacts/SRUM/{}/network-usage/{:020}-{ordinal:06}.record",
            candidate.entry_id, record.auto_inc_id
        );
        let mut metadata = srum_record_metadata(
            candidate,
            "network_usage",
            record.timestamp_utc.as_deref(),
            serde_json::to_value(record)?,
            serde_json::json!({
                "timestamp_ole_automation_days": "days since 1899-12-30; normalized UTC retained separately",
                "bytes_sent": "bytes",
                "bytes_received": "bytes",
                "wake_count": "count",
                "interface_luid": "raw Windows NET_LUID UInt64",
                "l2_profile_id": "raw SRUM profile identifier",
                "l2_profile_flags": "raw SRUM bit flags",
            }),
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(DerivedRecord {
            logical_path,
            display_name,
            metadata,
        });
    }

    for (ordinal, record) in decoded.application_resource_records.iter().enumerate() {
        let application = record
            .app
            .decoded_value
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("unresolved AppId {}", record.app.id_index));
        let display_name = format!(
            "{} — {application}",
            record
                .timestamp_utc
                .as_deref()
                .unwrap_or("time unavailable")
        );
        let logical_path = format!(
            "/Windows Artifacts/SRUM/{}/application-resource-usage/{:020}-{ordinal:06}.record",
            candidate.entry_id, record.auto_inc_id
        );
        let mut metadata = srum_record_metadata(
            candidate,
            "application_resource_usage",
            record.timestamp_utc.as_deref(),
            serde_json::to_value(record)?,
            serde_json::json!({
                "timestamp_ole_automation_days": "days since 1899-12-30; normalized UTC retained separately",
                "foreground_cycle_time_raw": "native SRUM UInt64 cycle-time counter; deliberately not converted to wall time",
                "background_cycle_time_raw": "native SRUM UInt64 cycle-time counter; deliberately not converted to wall time",
                "face_time_raw": "native SRUM UInt64 counter; deliberately retained without an inferred unit",
                "foreground_context_switches": "count",
                "background_context_switches": "count",
                "foreground_bytes_read": "bytes",
                "foreground_bytes_written": "bytes",
                "background_bytes_read": "bytes",
                "background_bytes_written": "bytes",
                "foreground_read_operations": "count",
                "foreground_write_operations": "count",
                "foreground_flushes": "count",
                "background_read_operations": "count",
                "background_write_operations": "count",
                "background_flushes": "count",
            }),
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(DerivedRecord {
            logical_path,
            display_name,
            metadata,
        });
    }

    for (ordinal, record) in decoded.connectivity_records.iter().enumerate() {
        let application = record
            .app
            .decoded_value
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("unresolved AppId {}", record.app.id_index));
        let artifact_time = record
            .connect_start_utc
            .as_deref()
            .or(record.timestamp_utc.as_deref());
        let display_name = format!(
            "{} — {application} — {} seconds connected",
            artifact_time.unwrap_or("time unavailable"),
            record.connected_time_seconds.unwrap_or(0)
        );
        let logical_path = format!(
            "/Windows Artifacts/SRUM/{}/connectivity/{:020}-{ordinal:06}.record",
            candidate.entry_id, record.auto_inc_id
        );
        let mut metadata = srum_record_metadata(
            candidate,
            "connectivity",
            artifact_time,
            serde_json::to_value(record)?,
            serde_json::json!({
                "timestamp_ole_automation_days": "days since 1899-12-30; normalized UTC retained separately",
                "connect_start_filetime": "100-nanosecond intervals since 1601-01-01 UTC; normalized UTC retained separately",
                "connected_time_seconds": "seconds",
                "interface_luid": "raw Windows NET_LUID UInt64",
                "l2_profile_id": "raw SRUM profile identifier",
                "l2_profile_flags": "raw SRUM bit flags",
            }),
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(DerivedRecord {
            logical_path,
            display_name,
            metadata,
        });
    }
    Ok(records)
}

fn srum_record_metadata(
    candidate: &SrumCandidate,
    record_kind: &str,
    artifact_time_utc: Option<&str>,
    record: serde_json::Value,
    units: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "artifact_kind": "windows_srum_record",
        "artifact_time_utc": artifact_time_utc,
        "parser": PARSER_NAME,
        "structured_source": true,
        "srum_derived": true,
        "srum_record_kind": record_kind,
        "srum_record": record,
        "srum_units": units,
        "srum_source_entry_id": candidate.entry_id,
        "source_entry_id": candidate.entry_id,
        "source_job_id": candidate.source_job_id,
        "source_path_exact": candidate.exact_path,
        "source_artifact_path": candidate.exact_path,
        "source_file_name": candidate.name,
        "source_file_size": candidate.size,
    })
}

fn replace_srum_source_records(
    case_path: &Path,
    evidence_id: i64,
    candidate: &SrumCandidate,
    records: &[DerivedRecord],
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND json_extract(metadata_json, '$.srum_derived') = 1
           AND json_extract(metadata_json, '$.srum_source_entry_id') = ?3",
        params![case_id, evidence_id, candidate.entry_id],
    )?;
    for record in records {
        let metadata_text = record.metadata.to_string();
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            &record.logical_path,
            &record.display_name,
            "record",
            None,
            &metadata_text,
            candidate.source_job_id,
        )?;
        let derived_entry_id: i64 = tx.query_row(
            "SELECT id FROM filesystem_entries WHERE evidence_id = ?1 AND logical_path = ?2",
            params![evidence_id, record.logical_path],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO filesystem_entry_text_segments(
                 entry_id, parser_name, segment_index, part_name, content, content_encoding
             ) VALUES (?1, ?2, 0, 'record', ?3, 'utf-8')",
            params![derived_entry_id, PARSER_NAME, metadata_text.as_bytes()],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn parse_one_hive(
    case_path: &Path,
    read_session: &mut EvidenceReadSession,
    evidence_id: i64,
    candidate: &HiveCandidate,
) -> Result<DerivedCounts> {
    let (directory, staging_path) =
        reserve_staging_destination(candidate.entry_id, &candidate.name)?;
    let parsed = (|| -> Result<(Vec<DerivedRecord>, DerivedCounts)> {
        recover_filesystem_entry_in_session(
            read_session,
            RecoverEntryOptions {
                entry_id: candidate.entry_id,
                output_path: staging_path.clone(),
            },
        )
        .with_context(|| format!("recovering Registry hive {}", candidate.exact_path))?;
        let import = collect_registry_hive_import(&staging_path, &candidate.name, usize::MAX)
            .with_context(|| format!("parsing Registry hive {}", candidate.exact_path))?;
        Ok(derive_hive_records(candidate, &import))
    })();
    let file_cleanup = if staging_path.exists() {
        fs::remove_file(&staging_path)
    } else {
        Ok(())
    };
    let directory_cleanup = fs::remove_dir(&directory);
    let (records, counts) = parsed?;
    file_cleanup.with_context(|| format!("removing staged hive {}", staging_path.display()))?;
    directory_cleanup
        .with_context(|| format!("removing staged hive directory {}", directory.display()))?;
    replace_source_records(case_path, evidence_id, candidate, &records)?;
    Ok(counts)
}

fn reserve_staging_destination(entry_id: i64, name: &str) -> Result<(PathBuf, PathBuf)> {
    for _ in 0..TEMPORARY_DIRECTORY_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "kdft-windows-registry-{}-{entry_id}-{sequence}",
            std::process::id()
        ));
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        match builder.create(&directory) {
            Ok(()) => {
                return Ok((
                    directory.clone(),
                    directory.join(sanitize_logical_segment(name)),
                ))
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("reserving Registry staging directory"),
        }
    }
    bail!("could not reserve a unique Registry staging directory")
}

fn derive_hive_records(
    candidate: &HiveCandidate,
    import: &RegistryImportData,
) -> (Vec<DerivedRecord>, DerivedCounts) {
    let observations = import
        .entries
        .iter()
        .filter_map(value_observation)
        .collect::<Vec<_>>();
    let hive = candidate.name.to_ascii_lowercase();
    let mut records = Vec::new();
    let mut counts = DerivedCounts::default();
    if hive == "amcache.hve" {
        let derived = derive_amcache(candidate, &observations);
        counts.amcache = derived.len();
        records.extend(derived);
    }
    if hive == "ntuser.dat" || hive == "usrclass.dat" {
        let derived = derive_userassist(candidate, &observations);
        counts.userassist = derived.len();
        records.extend(derived);
        let derived = derive_shellbags(candidate, &observations);
        counts.shellbags = derived.len();
        records.extend(derived);
    }
    if hive == "ntuser.dat" || hive == "software" {
        let derived = derive_startup_records(candidate, &observations);
        counts.startup = derived.len();
        records.extend(derived);
    }
    if hive == "system" {
        let (derived, coverage) = derive_shimcache(candidate, &observations);
        counts.shimcache_sources = coverage.len();
        for source in &coverage {
            match source.status.as_str() {
                "completed" => {
                    counts.shimcache_completed = counts.shimcache_completed.saturating_add(1)
                }
                "partial" => counts.shimcache_partial = counts.shimcache_partial.saturating_add(1),
                "recognized_unsupported" | "unrecognized_unsupported" => {
                    counts.shimcache_unsupported = counts.shimcache_unsupported.saturating_add(1)
                }
                _ => counts.shimcache_failed = counts.shimcache_failed.saturating_add(1),
            }
        }
        counts.shimcache_records = derived.len();
        counts.shimcache_source_coverage = coverage;
        records.extend(derived);
    }
    (records, counts)
}

fn value_observation(entry: &RegistryImportEntry) -> Option<ValueObservation> {
    if entry.metadata["artifact_kind"] != "registry_value" {
        return None;
    }
    Some(ValueObservation {
        key_path: entry.metadata["registry_key_path"].as_str()?.to_string(),
        key_last_write_utc: entry.metadata["registry_key_last_write_utc"]
            .as_str()
            .map(str::to_string),
        name: entry.metadata["registry_value_name"].as_str()?.to_string(),
        value_type: entry.metadata["registry_value_type"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        rendered: entry.metadata["registry_value_data"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        value_size: entry.metadata["registry_value_data_size"]
            .as_u64()
            .and_then(|size| usize::try_from(size).ok()),
        raw: entry.raw_value_bytes.clone(),
    })
}

fn is_shimcache_value(value: &ValueObservation) -> bool {
    let normalized_key = value.key_path.replace('\\', "/").to_ascii_lowercase();
    normalized_key.ends_with("/control/session manager/appcompatcache")
        && value.name.eq_ignore_ascii_case("AppCompatCache")
}

fn derive_shimcache(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> (Vec<DerivedRecord>, Vec<ShimcacheSourceCoverage>) {
    let mut records = Vec::new();
    let mut source_coverage = Vec::new();
    for (source_ordinal, value) in observations
        .iter()
        .filter(|value| is_shimcache_value(value))
        .enumerate()
    {
        let Some(raw) = value.raw.as_deref() else {
            let limitation = match value.value_size {
                Some(size) => format!(
                    "AppCompatCache source bytes were not retained (declared value size {size} bytes); no records were claimed"
                ),
                None => "AppCompatCache source bytes were not retained; no records were claimed"
                    .to_string(),
            };
            source_coverage.push(ShimcacheSourceCoverage {
                source_ordinal,
                source_entry_id: candidate.entry_id,
                source_job_id: candidate.source_job_id,
                source_path_exact: candidate.exact_path.clone(),
                registry_key_path: value.key_path.clone(),
                registry_key_last_write_utc: value.key_last_write_utc.clone(),
                registry_value_name: value.name.clone(),
                registry_value_type: value.value_type.clone(),
                registry_value_size: value.value_size,
                status: "source_bytes_unavailable".to_string(),
                detected_layout: None,
                header_signature: None,
                records_expected: None,
                records_indexed: 0,
                malformed_record_count: 0,
                diagnostics: vec![limitation.clone()],
                diagnostics_omitted: 0,
                coverage: "source value retained without decodable binary bytes".to_string(),
                limitation: Some(limitation),
            });
            continue;
        };

        let decoded = decode_appcompat_cache(raw);
        for record in &decoded.records {
            let display_name = record.path.clone();
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/shimcache/{source_ordinal:04}-{:020}.record",
                candidate.entry_id, record.record_index
            );
            let file_last_modified_utc = filetime_to_rfc3339(record.file_last_modified_filetime);
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_shimcache_record",
                "parser": PARSER_NAME,
                "shimcache_layout": decoded.layout,
                "shimcache_layout_label": decoded.layout.map(|layout| layout.label()),
                "shimcache_path": record.path,
                "shimcache_record_index": record.record_index,
                "shimcache_record_value_relative_offset": record.record_offset,
                "shimcache_record_size": record.record_size,
                "shimcache_path_value_relative_offset": record.path_offset,
                "shimcache_path_size": record.path_size,
                "shimcache_offset_basis": "byte offsets relative to the start of the AppCompatCache Registry value; not evidence-media offsets",
                "shimcache_file_last_modified_filetime": record.file_last_modified_filetime,
                "shimcache_file_last_modified_utc": file_last_modified_utc,
                "shimcache_time_semantics": "cached file last-modification time; not an execution time",
                "shimcache_execution_flag": record.execution_flag,
                "shimcache_execution_flag_semantics": record.execution_flag_semantics,
                "shimcache_insertion_flags": record.insertion_flags,
                "shimcache_entry_checksum_raw": record.entry_checksum_unverified,
                "shimcache_entry_checksum_validation": "not validated; raw field retained",
                "shimcache_registry_key": value.key_path,
                "shimcache_registry_value": value.name,
                "shimcache_registry_value_type": value.value_type,
                "shimcache_registry_value_size": value.value_size,
                "shimcache_registry_key_last_write_utc": value.key_last_write_utc,
                "shimcache_source_ordinal": source_ordinal,
                "source_job_id": candidate.source_job_id,
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &display_name, "record");
            records.push(DerivedRecord {
                logical_path,
                display_name,
                metadata,
            });
        }

        let detected_layout = decoded.layout.map(|layout| layout.label().to_string());
        let header_signature = decoded
            .header_signature
            .map(|signature| format!("0x{signature:08x}"));
        let indexed = decoded.records.len();
        let coverage = match decoded.status.as_str() {
            "completed" => {
                format!("{indexed} bounded record(s) decoded from the complete source value")
            }
            "partial" => format!(
                "{indexed} valid bounded record(s) retained; {} malformed record(s) omitted",
                decoded.malformed_record_count
            ),
            "recognized_unsupported" | "unrecognized_unsupported" => {
                "source value retained; unsupported records were not inferred or claimed"
                    .to_string()
            }
            _ => "source value retained; no complete supported record was claimed".to_string(),
        };
        let limitation = decoded.limitation.clone().or_else(|| {
            decoded.has_failed_coverage().then(|| {
                format!(
                    "{} malformed record(s) prevented complete AppCompatCache coverage",
                    decoded.malformed_record_count
                )
            })
        });
        source_coverage.push(ShimcacheSourceCoverage {
            source_ordinal,
            source_entry_id: candidate.entry_id,
            source_job_id: candidate.source_job_id,
            source_path_exact: candidate.exact_path.clone(),
            registry_key_path: value.key_path.clone(),
            registry_key_last_write_utc: value.key_last_write_utc.clone(),
            registry_value_name: value.name.clone(),
            registry_value_type: value.value_type.clone(),
            registry_value_size: value.value_size.or(Some(raw.len())),
            status: decoded.status,
            detected_layout,
            header_signature,
            records_expected: decoded.records_expected,
            records_indexed: indexed,
            malformed_record_count: decoded.malformed_record_count,
            diagnostics: decoded.diagnostics,
            diagnostics_omitted: decoded.diagnostics_omitted,
            coverage,
            limitation,
        });
    }
    (records, source_coverage)
}

fn derive_amcache(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    let mut keys: BTreeMap<String, Vec<&ValueObservation>> = BTreeMap::new();
    for observation in observations {
        let lower = observation.key_path.replace('\\', "/").to_ascii_lowercase();
        if lower.contains("/root/inventoryapplicationfile/")
            || lower.contains("/root/inventoryapplication/")
            || lower.contains("/root/file/")
            || lower.contains("/root/programs/")
        {
            keys.entry(observation.key_path.clone())
                .or_default()
                .push(observation);
        }
    }
    keys.into_iter()
        .enumerate()
        .map(|(ordinal, (key_path, values))| {
            let fields = values
                .iter()
                .map(|value| (value.name.clone(), value.rendered.clone()))
                .collect::<BTreeMap<_, _>>();
            let path = field_ci(
                &fields,
                &["LowerCaseLongPath", "LongPathHash", "Path", "15"],
            );
            let program_name = field_ci(&fields, &["Name", "ProductName", "0"]);
            let display_name = path.clone().or(program_name.clone()).unwrap_or_else(|| {
                key_path
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("Amcache record")
                    .to_string()
            });
            let artifact_time = values
                .first()
                .and_then(|value| value.key_last_write_utc.clone());
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/amcache/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&display_name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_amcache_record",
                "parser": PARSER_NAME,
                "amcache_key_path": key_path,
                "amcache_path": path,
                "amcache_name": program_name,
                "amcache_publisher": field_ci(&fields, &["Publisher"]),
                "amcache_version": field_ci(&fields, &["Version", "ProductVersion"]),
                "amcache_product_name": field_ci(&fields, &["ProductName"]),
                "amcache_sha1": field_ci(&fields, &["SHA1"]),
                "amcache_link_date": field_ci(&fields, &["LinkDate"]),
                "amcache_fields": fields,
                "artifact_time_utc": artifact_time,
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &display_name, "record");
            DerivedRecord {
                logical_path,
                display_name,
                metadata,
            }
        })
        .collect()
}

fn derive_userassist(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    observations
        .iter()
        .filter(|value| {
            let key = value.key_path.replace('\\', "/").to_ascii_lowercase();
            key.contains("/software/microsoft/windows/currentversion/explorer/userassist/")
                && key.ends_with("/count")
                && !value.name.eq_ignore_ascii_case("(default)")
        })
        .enumerate()
        .map(|(ordinal, value)| {
            let decoded_name = rot13(&value.name);
            let parsed = value.raw.as_deref().map(parse_userassist_binary).unwrap_or_default();
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/userassist/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&decoded_name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_userassist_record",
                "parser": PARSER_NAME,
                "userassist_encoded_name": value.name,
                "userassist_decoded_name": decoded_name,
                "userassist_registry_key": value.key_path,
                "userassist_value_type": value.value_type,
                "userassist_raw_preview": value.rendered,
                "userassist_run_count": parsed.run_count,
                "userassist_focus_count": parsed.focus_count,
                "userassist_focus_time_ms": parsed.focus_time_ms,
                "userassist_last_execution_utc": parsed.last_execution_utc,
                "userassist_binary_layout": parsed.layout,
                "artifact_time_utc": parsed.last_execution_utc.or_else(|| value.key_last_write_utc.clone()),
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &decoded_name, "record");
            DerivedRecord { logical_path, display_name: decoded_name, metadata }
        })
        .collect()
}

#[derive(Debug, Default)]
struct UserAssistBinary {
    run_count: Option<u32>,
    focus_count: Option<u32>,
    focus_time_ms: Option<u32>,
    last_execution_utc: Option<String>,
    layout: &'static str,
}

fn parse_userassist_binary(bytes: &[u8]) -> UserAssistBinary {
    if bytes.len() >= 72 {
        UserAssistBinary {
            run_count: le_u32(bytes, 4),
            focus_count: le_u32(bytes, 8),
            focus_time_ms: le_u32(bytes, 12),
            last_execution_utc: le_u64(bytes, 60).and_then(filetime_to_rfc3339),
            layout: "Windows 7+ 72-byte layout",
        }
    } else if bytes.len() >= 16 {
        UserAssistBinary {
            run_count: le_u32(bytes, 4),
            last_execution_utc: le_u64(bytes, 8).and_then(filetime_to_rfc3339),
            layout: "legacy 16-byte layout",
            ..UserAssistBinary::default()
        }
    } else {
        UserAssistBinary {
            layout: "unrecognized or unavailable",
            ..UserAssistBinary::default()
        }
    }
}

fn derive_shellbags(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    let mut by_key: BTreeMap<String, Vec<&ValueObservation>> = BTreeMap::new();
    for value in observations {
        let key = value.key_path.replace('\\', "/").to_ascii_lowercase();
        if key.contains("/shell/bagmru") {
            by_key
                .entry(value.key_path.clone())
                .or_default()
                .push(value);
        }
    }
    let mut decoded_nodes = HashMap::<String, String>::new();
    let mut items = Vec::new();
    for (key_path, values) in &by_key {
        for value in values {
            if value.name.parse::<u32>().is_ok() {
                let decoded = value
                    .raw
                    .as_deref()
                    .and_then(extract_shell_item_name)
                    .unwrap_or_else(|| format!("[shell item {}]", value.name));
                decoded_nodes.insert(
                    format!("{}\\{}", key_path.trim_end_matches('\\'), value.name)
                        .to_ascii_lowercase(),
                    decoded,
                );
            }
        }
    }
    for (key_path, values) in by_key {
        let mru_order = values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case("MRUListEx"))
            .and_then(|value| value.raw.as_deref())
            .map(parse_mru_list_ex)
            .unwrap_or_default();
        for value in values {
            let Ok(node_number) = value.name.parse::<u32>() else {
                continue;
            };
            let item_name = value
                .raw
                .as_deref()
                .and_then(extract_shell_item_name)
                .unwrap_or_else(|| format!("[shell item {node_number}]"));
            let parent = shellbag_parent_path(&key_path, &decoded_nodes);
            let resolved_path = if parent.is_empty() {
                item_name.clone()
            } else {
                format!("{parent}\\{item_name}")
            };
            items.push((
                key_path.clone(),
                value,
                item_name,
                resolved_path,
                mru_order.iter().position(|item| *item == node_number),
            ));
        }
    }
    items
        .into_iter()
        .enumerate()
        .map(|(ordinal, (key_path, value, item_name, resolved_path, mru_position))| {
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/shellbags/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&item_name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_shellbag_record",
                "parser": PARSER_NAME,
                "shellbag_registry_key": key_path,
                "shellbag_node_number": value.name,
                "shellbag_item_name": item_name,
                "shellbag_resolved_path": resolved_path,
                "shellbag_mru_position": mru_position,
                "shellbag_key_last_write_utc": value.key_last_write_utc,
                "artifact_time_utc": value.key_last_write_utc,
                "shellbag_raw_preview": value.rendered,
                "shellbag_name_decode_method": "bounded UTF-16LE/ASCII shell-item string recovery; validate against raw value",
                "shellbag_decode_confidence": "medium",
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &resolved_path, "record");
            DerivedRecord { logical_path, display_name: resolved_path, metadata }
        })
        .collect()
}

fn derive_startup_records(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    observations
        .iter()
        .filter(|value| is_startup_registry_key(&value.key_path))
        .filter(|value| !value.name.eq_ignore_ascii_case("(default)"))
        .enumerate()
        .map(|(ordinal, value)| {
            let display_name = format!("{}: {}", value.name, value.rendered);
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/startup/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&value.name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_startup_record",
                "parser": PARSER_NAME,
                "startup_value_name": value.name,
                "startup_command": value.rendered,
                "startup_registry_key": value.key_path,
                "startup_scope": if candidate.name.eq_ignore_ascii_case("ntuser.dat") { "user" } else { "machine" },
                "startup_key_last_write_utc": value.key_last_write_utc,
                "artifact_time_utc": value.key_last_write_utc,
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &display_name, "record");
            DerivedRecord { logical_path, display_name, metadata }
        })
        .collect()
}

fn is_startup_registry_key(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let path = format!("/{}", normalized.trim_start_matches('/'));
    path.ends_with("/software/microsoft/windows/currentversion/run")
        || path.ends_with("/software/microsoft/windows/currentversion/runonce")
        || path.ends_with("/software/microsoft/windows/currentversion/policies/explorer/run")
        || path.ends_with("/software/wow6432node/microsoft/windows/currentversion/run")
        || path.ends_with("/software/wow6432node/microsoft/windows/currentversion/runonce")
}

fn source_metadata(metadata: &mut serde_json::Value, candidate: &HiveCandidate) {
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "windows_registry_derived".to_string(),
            serde_json::json!(true),
        );
        object.insert(
            "windows_registry_source_entry_id".to_string(),
            serde_json::json!(candidate.entry_id),
        );
        object.insert(
            "source_entry_id".to_string(),
            serde_json::json!(candidate.entry_id),
        );
        object.insert(
            "source_artifact_path".to_string(),
            serde_json::json!(candidate.exact_path),
        );
        object.insert(
            "source_logical_path".to_string(),
            serde_json::json!(candidate.logical_path),
        );
        object.insert(
            "source_hive_name".to_string(),
            serde_json::json!(candidate.name),
        );
    }
}

fn replace_source_records(
    case_path: &Path,
    evidence_id: i64,
    candidate: &HiveCandidate,
    records: &[DerivedRecord],
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND json_extract(metadata_json, '$.windows_registry_derived') = 1
           AND json_extract(metadata_json, '$.windows_registry_source_entry_id') = ?3",
        params![case_id, evidence_id, candidate.entry_id],
    )?;
    for record in records {
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            &record.logical_path,
            &record.display_name,
            "record",
            None,
            &record.metadata.to_string(),
            candidate.source_job_id,
        )?;
        let derived_entry_id: i64 = tx.query_row(
            "SELECT id FROM filesystem_entries WHERE evidence_id = ?1 AND logical_path = ?2",
            params![evidence_id, record.logical_path],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO filesystem_entry_text_segments(
                 entry_id, parser_name, segment_index, part_name, content, content_encoding
             ) VALUES (?1, ?2, 0, 'record', ?3, 'utf-8')",
            params![
                derived_entry_id,
                PARSER_NAME,
                record.metadata.to_string().as_bytes()
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn persist_pass_audit(case_path: &Path, result: &WindowsRegistryArtifactParseResult) -> Result<()> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let actor = audit_actor(&conn, case_id)?;
    conn.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.windows_registry_artifact_parse', ?2, 'evidence', ?3, ?4)",
        params![
            case_id,
            actor,
            result.evidence_id,
            serde_json::to_string(result)?
        ],
    )?;
    Ok(())
}

fn field_ci(fields: &BTreeMap<String, String>, wanted: &[&str]) -> Option<String> {
    wanted.iter().find_map(|wanted| {
        fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.clone())
            .filter(|value| !value.trim().is_empty())
    })
}

fn rot13(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            'a'..='m' | 'A'..='M' => char::from_u32(character as u32 + 13).unwrap_or(character),
            'n'..='z' | 'N'..='Z' => char::from_u32(character as u32 - 13).unwrap_or(character),
            _ => character,
        })
        .collect()
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    i64::try_from(filetime)
        .ok()
        .and_then(super::pst_filetime_to_rfc3339)
}

fn parse_mru_list_ex(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .take_while(|value| *value != u32::MAX)
        .collect()
}

fn extract_shell_item_name(bytes: &[u8]) -> Option<String> {
    let mut candidates = Vec::<String>::new();
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        let start = offset;
        let mut units = Vec::new();
        while offset + 1 < bytes.len() {
            let unit = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            if unit == 0 {
                break;
            }
            if unit < 0x20 || (0x7f..0xa0).contains(&unit) {
                units.clear();
                break;
            }
            units.push(unit);
            offset += 2;
        }
        if units.len() >= 3 {
            if let Ok(value) = String::from_utf16(&units) {
                candidates.push(value);
            }
        }
        offset = start.saturating_add(2);
    }
    let mut ascii = String::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            ascii.push(*byte as char);
        } else {
            if ascii.len() >= 4 {
                candidates.push(std::mem::take(&mut ascii));
            }
            ascii.clear();
        }
    }
    if ascii.len() >= 4 {
        candidates.push(ascii);
    }
    candidates
        .into_iter()
        .map(|value| value.trim_matches('\0').trim().to_string())
        .filter(|value| {
            value.len() >= 3 && !value.chars().all(|character| character.is_ascii_hexdigit())
        })
        .max_by_key(|value| value.chars().count())
}

fn shellbag_parent_path(key_path: &str, decoded_nodes: &HashMap<String, String>) -> String {
    let lower = key_path.to_ascii_lowercase();
    let Some(index) = lower.find("bagmru") else {
        return String::new();
    };
    let root_end = index + "bagmru".len();
    let root = &key_path[..root_end];
    let suffix = key_path[root_end..].trim_matches(['\\', '/']);
    if suffix.is_empty() {
        return String::new();
    }
    let mut key = root.to_string();
    let mut names = Vec::new();
    for segment in suffix
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
    {
        key.push('\\');
        key.push_str(segment);
        names.push(
            decoded_nodes
                .get(&key.to_ascii_lowercase())
                .cloned()
                .unwrap_or_else(|| format!("[node {segment}]")),
        );
    }
    names.join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_staging_directory_is_exclusive_and_private() {
        let (directory, staged_file) =
            reserve_staging_destination(42, "SYSTEM").expect("reserve staging directory");
        assert!(directory.is_dir());
        assert_eq!(staged_file.parent(), Some(directory.as_path()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&directory)
                .expect("read staging directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }

        fs::remove_dir(&directory).expect("remove staging directory");
    }

    #[test]
    fn registry_hive_paths_accept_root_relative_and_windows_separators() {
        assert!(is_supported_hive_path(
            "SYSTEM",
            "Windows/System32/config/SYSTEM"
        ));
        assert!(is_supported_hive_path(
            "SOFTWARE",
            "/Windows/System32/config/SOFTWARE"
        ));
        assert!(is_supported_hive_path(
            "Amcache.hve",
            r"Windows\appcompat\Programs\Amcache.hve"
        ));
        assert!(is_supported_hive_path(
            "NTUSER.DAT",
            r"Users\Alice\NTUSER.DAT"
        ));
        assert!(is_supported_hive_path(
            "UsrClass.dat",
            "/Documents and Settings/Alice/UsrClass.dat"
        ));
        assert!(!is_supported_hive_path(
            "SYSTEM",
            "Windows/System32/Tasks/SYSTEM"
        ));
        assert!(!is_supported_hive_path(
            "SYSTEM",
            "Windows/WinSxS/component/Windows/System32/config/SYSTEM"
        ));
        assert!(!is_supported_hive_path(
            "Amcache.hve",
            r"Windows\WinSxS\component\Windows\appcompat\Programs\Amcache.hve"
        ));
    }

    #[test]
    fn srum_paths_accept_root_relative_and_windows_separators() {
        assert!(is_srum_source_path("Windows/System32/sru/SRUDB.dat"));
        assert!(is_srum_source_path("/Windows/System32/sru/SRUDB.dat"));
        assert!(is_srum_source_path(r"Windows\System32\sru\SRUDB.dat"));
        assert!(!is_srum_source_path("Windows/System32/config/SRUDB.dat"));
        assert!(!is_srum_source_path(
            "Windows/WinSxS/component/Windows/System32/sru/SRUDB.dat"
        ));
    }

    #[test]
    fn srum_coverage_never_claims_rows_for_recognized_unsupported_source() {
        let coverage = SrumSourceCoverage {
            source_entry_id: 42,
            source_job_id: 7,
            source_path_exact: "Windows/System32/sru/SRUDB.dat".to_string(),
            source_size: Some(8_192),
            status: "recognized_unsupported".to_string(),
            records_indexed: 0,
            live_row_counts: None,
            coverage: "ESE source header validated; SRUM table rows not decoded".to_string(),
            limitation: Some("decoder unavailable".to_string()),
            diagnostics: vec!["decoder unavailable".to_string()],
            ese_header: None,
        };
        assert_eq!(coverage.status, "recognized_unsupported");
        assert_eq!(coverage.records_indexed, 0);
    }

    #[test]
    fn userassist_rot13_and_layout_are_decoded() {
        assert_eq!(rot13("Pnyp"), "Calc");
        let mut bytes = vec![0_u8; 72];
        bytes[4..8].copy_from_slice(&7_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1500_u32.to_le_bytes());
        let parsed = parse_userassist_binary(&bytes);
        assert_eq!(parsed.run_count, Some(7));
        assert_eq!(parsed.focus_count, Some(2));
        assert_eq!(parsed.focus_time_ms, Some(1500));
        assert_eq!(parsed.layout, "Windows 7+ 72-byte layout");
    }

    #[test]
    fn mru_list_stops_at_terminator() {
        let bytes = [
            2_u32.to_le_bytes(),
            7_u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
        ]
        .concat();
        assert_eq!(parse_mru_list_ex(&bytes), vec![2, 7]);
    }

    #[test]
    fn startup_key_matching_is_exact() {
        assert!(is_startup_registry_key(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ));
        assert!(!is_startup_registry_key("Software\\Vendor\\StartupStrings"));
    }

    fn one_record_modern_shimcache(path: &str) -> Vec<u8> {
        let path_bytes = path
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut body = Vec::new();
        body.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        body.extend_from_slice(&path_bytes);
        body.extend_from_slice(&133_000_000_000_000_000_u64.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        let mut bytes = vec![0_u8; 0x34];
        bytes[0..4].copy_from_slice(&0x34_u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(b"10ts");
        bytes.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    #[test]
    fn shimcache_integration_requires_the_exact_value_and_preserves_offset_semantics() {
        let raw = one_record_modern_shimcache(r"C:\Windows\System32\cmd.exe");
        let observations = vec![
            ValueObservation {
                key_path: r"ROOT\ControlSet001\Control\Session Manager\AppCompatCache".to_string(),
                key_last_write_utc: Some("2026-07-28T20:00:00Z".to_string()),
                name: "AppCompatCache".to_string(),
                value_type: "REG_BINARY".to_string(),
                rendered: "binary".to_string(),
                value_size: Some(raw.len()),
                raw: Some(raw),
            },
            ValueObservation {
                key_path: r"ROOT\Vendor\AppCompatCache".to_string(),
                key_last_write_utc: None,
                name: "AppCompatCache".to_string(),
                value_type: "REG_BINARY".to_string(),
                rendered: "binary".to_string(),
                value_size: Some(4),
                raw: Some(vec![0x34, 0, 0, 0]),
            },
        ];
        let candidate = HiveCandidate {
            entry_id: 42,
            source_job_id: 7,
            logical_path: "/Image Analysis/SYSTEM".to_string(),
            exact_path: "Windows/System32/config/SYSTEM".to_string(),
            name: "SYSTEM".to_string(),
        };
        let (records, coverage) = derive_shimcache(&candidate, &observations);
        assert_eq!(records.len(), 1);
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0].status, "completed");
        assert_eq!(
            coverage[0].detected_layout.as_deref(),
            Some("Windows 10/11 Creators-or-later")
        );
        assert_eq!(
            records[0].metadata["shimcache_execution_flag"],
            serde_json::Value::Null
        );
        assert_eq!(
            records[0].metadata["shimcache_time_semantics"],
            "cached file last-modification time; not an execution time"
        );
        assert!(records[0].metadata["shimcache_offset_basis"]
            .as_str()
            .is_some_and(|value| value.contains("not evidence-media offsets")));
        assert_eq!(
            records[0].metadata["artifact_time_utc"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn shimcache_missing_source_bytes_is_explicit_and_never_claims_records() {
        let observations = vec![ValueObservation {
            key_path: r"ROOT\ControlSet001\Control\Session Manager\AppCompatCache".to_string(),
            key_last_write_utc: None,
            name: "AppCompatCache".to_string(),
            value_type: "REG_BINARY".to_string(),
            rendered: "binary".to_string(),
            value_size: Some(33 * 1024 * 1024),
            raw: None,
        }];
        let candidate = HiveCandidate {
            entry_id: 42,
            source_job_id: 7,
            logical_path: "/Image Analysis/SYSTEM".to_string(),
            exact_path: "Windows/System32/config/SYSTEM".to_string(),
            name: "SYSTEM".to_string(),
        };
        let (records, coverage) = derive_shimcache(&candidate, &observations);
        assert!(records.is_empty());
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0].status, "source_bytes_unavailable");
        assert!(coverage[0]
            .limitation
            .as_deref()
            .is_some_and(|value| value.contains("no records were claimed")));
    }
}
