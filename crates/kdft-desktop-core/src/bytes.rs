#![forbid(unsafe_code)]

//! Native bounded byte-reading service.
//!
//! Provides bounded byte access across indexed entries, live image filesystems,
//! standalone MFT records, raw decoded media, and BitLocker-decrypted streams.
//! Whole files are never materialized into memory.

use crate::unlock::{TransientUnlockManager, BITLOCKER_LOCKED_FILESYSTEM};
use anyhow::{anyhow, Context, Result};
use kdft_case::{
    list_image_volumes, read_bitlocker_ntfs_file_bytes, read_filesystem_entry_bytes,
    read_image_directory_bytes, read_image_raw_bytes, read_local_evidence_bytes,
    ReadEntryBytesOptions,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_BYTE_READ_LENGTH: usize = 512;
pub const MAX_BOUNDED_BYTE_READ: usize = 256 * 1024; // 256 KB max per page

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteSourceNamespace {
    LogicalFile,
    FilesystemRelative,
    PartitionRelative,
    AbsoluteDecodedMedia,
    E01LogicalMedia,
    LocalEvidence,
}

impl ByteSourceNamespace {
    pub fn label(&self) -> &'static str {
        match self {
            Self::LogicalFile => "Logical File Offset",
            Self::FilesystemRelative => "Filesystem-Relative Offset",
            Self::PartitionRelative => "Partition-Relative Offset",
            Self::AbsoluteDecodedMedia => "Absolute Decoded-Media Offset",
            Self::E01LogicalMedia => "E01 Logical-Media Offset",
            Self::LocalEvidence => "Local File Offset",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::LogicalFile => {
                "Byte position within the uncompressed/reassembled logical file content."
            }
            Self::FilesystemRelative => {
                "Byte position relative to the beginning of the containing filesystem."
            }
            Self::PartitionRelative => {
                "Byte position relative to the beginning of the partition sector."
            }
            Self::AbsoluteDecodedMedia => {
                "Linear byte position across the decoded storage device/media; not an acquisition-container offset."
            }
            Self::E01LogicalMedia => {
                "Byte position within the reassembled forensic E01 raw media stream; not a compressed segment offset."
            }
            Self::LocalEvidence => "Byte position within the host-local evidence file.",
        }
    }
}

use crate::browse::VolumeIdentity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedByteRequest {
    pub case_path: PathBuf,
    pub evidence_id: i64,
    pub volume_index: usize,
    pub volume_identity: Option<VolumeIdentity>,
    pub request_id: u64,
    pub path: Option<String>,
    pub entry_id: Option<i64>,
    /// Optional indexed identity used only to resolve forensic coordinates
    /// while bytes continue to come from the live Browse reader.
    #[serde(default)]
    pub mapping_entry_id: Option<i64>,
    pub namespace: ByteSourceNamespace,
    pub offset: u64,
    pub length: usize,
    pub raw_media: bool,
}

impl BoundedByteRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn simple(
        case_path: PathBuf,
        evidence_id: i64,
        volume_index: usize,
        path: Option<String>,
        entry_id: Option<i64>,
        namespace: ByteSourceNamespace,
        offset: u64,
        length: usize,
        raw_media: bool,
    ) -> Self {
        Self {
            case_path,
            evidence_id,
            volume_index,
            volume_identity: None,
            request_id: 0,
            path,
            entry_id,
            mapping_entry_id: None,
            namespace,
            offset,
            length,
            raw_media,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedByteResponse {
    pub request_id: u64,
    pub reader_label: String,
    pub namespace: ByteSourceNamespace,
    pub requested_offset: u64,
    pub returned_offset: u64,
    pub bytes: Vec<u8>,
    pub total_logical_size: Option<u64>,
    pub eof: bool,
    pub partition_start: Option<u64>,
    pub filesystem_offset: Option<u64>,
    pub absolute_media_offset: Option<u64>,
    /// Authoritative NTFS FILE-record size for the mounted volume.  Present
    /// only for native NTFS logical-file reads.
    pub ntfs_file_record_size: Option<u64>,
    pub provenance: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportTerminalState {
    Complete,
    Partial,
    Canceled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportReport {
    pub source_path: String,
    pub dest_path: PathBuf,
    pub bytes_written: u64,
    pub sha256_hex: String,
    pub terminal_state: ExportTerminalState,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCalculationReport {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub logical_path: String,
    pub entry_id: Option<i64>,
    pub bytes_processed: u64,
    pub sha256_hex: String,
    pub persisted: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityTerminalState {
    Verified,
    ComputedNoExpected,
    Mismatch,
    Deferred,
    Skipped,
    Canceled,
    Failed,
}

impl IntegrityTerminalState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::ComputedNoExpected => "computed_no_expected",
            Self::Mismatch => "mismatch",
            Self::Deferred => "deferred",
            Self::Skipped => "skipped",
            Self::Canceled => "canceled",
            Self::Failed => "failed",
        }
    }

    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Verified => "Verified",
            Self::ComputedNoExpected => "Computed, no expected value",
            Self::Mismatch => "Mismatch",
            Self::Deferred => "Deferred",
            Self::Skipped => "Skipped with reason",
            Self::Canceled => "Canceled",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIntegrityRequest {
    pub case_path: PathBuf,
    pub evidence_id: i64,
    pub expected_sha256: Option<String>,
    pub skip_reason: Option<String>,
    pub is_skip: bool,
    pub is_defer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIntegrityReport {
    pub evidence_id: i64,
    pub terminal_state: IntegrityTerminalState,
    pub algorithm: String,
    pub computed_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
    pub rate_bytes_per_sec: Option<f64>,
    pub duration_ms: u64,
    pub scope_description: String,
    pub skip_reason: Option<String>,
    pub error: Option<String>,
    pub segment_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderExportManifestEntry {
    pub logical_path: String,
    pub destination_relative_path: String,
    pub size_bytes: Option<i64>,
    pub sha256_hex: String,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderExportManifest {
    pub export_version: String,
    pub started_at_utc: String,
    pub completed_at_utc: String,
    pub evidence_id: i64,
    pub volume_index: usize,
    pub source_root_path: String,
    pub destination_directory: String,
    pub terminal_state: ExportTerminalState,
    pub total_files_exported: usize,
    pub total_files_failed: usize,
    pub total_bytes_exported: u64,
    pub entries: Vec<FolderExportManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderExportReport {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub source_root_path: String,
    pub dest_dir: PathBuf,
    pub terminal_state: ExportTerminalState,
    pub files_exported: usize,
    pub files_failed: usize,
    pub bytes_written: u64,
    pub manifest_path: Option<PathBuf>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveHashReport {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub source_root_path: String,
    pub files_hashed: usize,
    pub files_failed: usize,
    pub bytes_hashed: u64,
    pub terminal_state: ExportTerminalState,
    pub error: Option<String>,
}

fn verified_entry_range_mapping(
    case_path: &Path,
    entry_id: i64,
    file_offset: u64,
    length: u64,
    warnings: &mut Vec<String>,
) -> (Option<u64>, Option<u64>, Option<u64>) {
    let Ok(location) = kdft_case::filesystem_entry_disk_location(case_path, entry_id) else {
        warnings.push(
            "The indexed identity could not be resolved to forensic media coordinates.".to_string(),
        );
        return (None, None, None);
    };
    if let Some(warning) = location.warning.clone() {
        warnings.push(warning);
    }
    if !location.available {
        return (location.partition_start_offset, None, None);
    }

    let file_base = location.file_relative_offset.unwrap_or(0);
    let Some(delta) = file_offset.checked_sub(file_base) else {
        warnings.push(
            "The selected logical range precedes the first verified file-data extent; filesystem/media offsets are withheld."
                .to_string(),
        );
        return (location.partition_start_offset, None, None);
    };
    let range_is_verified = location.exact_start
        && location.direct_logical_mapping
        && location.contiguous_bytes.is_some_and(|contiguous| {
            delta
                .checked_add(length)
                .is_some_and(|end| end <= contiguous)
        });
    if !range_is_verified {
        warnings.push(
            "The logical bytes are readable, but this range is not wholly covered by a verified direct contiguous media extent; filesystem/media offsets are withheld."
                .to_string(),
        );
        return (location.partition_start_offset, None, None);
    }

    (
        location.partition_start_offset,
        location
            .volume_relative_offset
            .and_then(|offset| offset.checked_add(delta)),
        location
            .decoded_media_offset
            .and_then(|offset| offset.checked_add(delta)),
    )
}

pub struct NativeByteService;

impl NativeByteService {
    /// Streams bytes from the requested target into a destination file, computing SHA-256 and reporting state.
    pub fn stream_export_file(
        request: &BoundedByteRequest,
        dest_path: &Path,
        unlock_mgr: Option<&TransientUnlockManager>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        progress_cb: Option<&dyn Fn(u64, Option<u64>)>,
    ) -> Result<ExportReport> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        use std::sync::atomic::Ordering;

        let logical_path = request.path.as_deref().unwrap_or("<unknown>").to_string();
        if let Some(parent) = dest_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut file = std::fs::File::create(dest_path)
            .with_context(|| format!("creating destination file at {}", dest_path.display()))?;
        let mut hasher = Sha256::new();
        let mut bytes_written: u64 = 0;
        let mut offset: u64 = 0;
        let chunk_size = 64 * 1024;
        let mut total_size = None;

        loop {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    let digest = format!("{:x}", hasher.finalize());
                    let _ = file.flush();
                    return Ok(ExportReport {
                        source_path: logical_path,
                        dest_path: dest_path.to_path_buf(),
                        bytes_written,
                        sha256_hex: digest,
                        terminal_state: ExportTerminalState::Canceled,
                        error: None,
                    });
                }
            }

            let mut req = request.clone();
            req.offset = offset;
            req.length = chunk_size;

            let resp = match Self::read_bytes(&req, unlock_mgr) {
                Ok(r) => r,
                Err(e) => {
                    let digest = format!("{:x}", hasher.finalize());
                    let _ = file.flush();
                    return Ok(ExportReport {
                        source_path: logical_path,
                        dest_path: dest_path.to_path_buf(),
                        bytes_written,
                        sha256_hex: digest,
                        terminal_state: if bytes_written > 0 {
                            ExportTerminalState::Partial
                        } else {
                            ExportTerminalState::Failed
                        },
                        error: Some(e.to_string()),
                    });
                }
            };

            if total_size.is_none() {
                total_size = resp.total_logical_size;
            }

            if resp.bytes.is_empty() {
                break;
            }

            if let Err(e) = file.write_all(&resp.bytes) {
                let digest = format!("{:x}", hasher.finalize());
                let _ = file.flush();
                return Ok(ExportReport {
                    source_path: logical_path,
                    dest_path: dest_path.to_path_buf(),
                    bytes_written,
                    sha256_hex: digest,
                    terminal_state: if bytes_written > 0 {
                        ExportTerminalState::Partial
                    } else {
                        ExportTerminalState::Failed
                    },
                    error: Some(e.to_string()),
                });
            }

            hasher.update(&resp.bytes);
            let n = resp.bytes.len() as u64;
            bytes_written += n;
            offset += n;

            if let Some(cb) = progress_cb {
                cb(bytes_written, total_size);
            }

            if resp.eof {
                break;
            }

            if let Some(tot) = total_size {
                if offset >= tot {
                    break;
                }
            }
        }

        let _ = file.flush();
        let digest = format!("{:x}", hasher.finalize());

        Ok(ExportReport {
            source_path: logical_path,
            dest_path: dest_path.to_path_buf(),
            bytes_written,
            sha256_hex: digest,
            terminal_state: ExportTerminalState::Complete,
            error: None,
        })
    }

    /// Calculates SHA-256 hash by streaming logical file chunks and persists digest to SQLite.
    pub fn calculate_file_hashes(
        request: &BoundedByteRequest,
        unlock_mgr: Option<&TransientUnlockManager>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        progress_cb: Option<&dyn Fn(u64, Option<u64>)>,
    ) -> Result<HashCalculationReport> {
        use sha2::{Digest, Sha256};
        use std::sync::atomic::Ordering;

        let logical_path = request.path.as_deref().unwrap_or("<unknown>").to_string();
        let mut hasher = Sha256::new();
        let mut bytes_processed: u64 = 0;
        let mut offset: u64 = 0;
        let chunk_size = 64 * 1024;
        let mut total_size = None;

        loop {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    let digest = format!("{:x}", hasher.finalize());
                    return Ok(HashCalculationReport {
                        evidence_id: request.evidence_id,
                        volume_index: request.volume_index,
                        logical_path,
                        entry_id: request.entry_id,
                        bytes_processed,
                        sha256_hex: digest,
                        persisted: false,
                        error: Some("Operation canceled by user".to_string()),
                    });
                }
            }

            let mut req = request.clone();
            req.offset = offset;
            req.length = chunk_size;

            let resp = match Self::read_bytes(&req, unlock_mgr) {
                Ok(r) => r,
                Err(e) => {
                    let digest = format!("{:x}", hasher.finalize());
                    return Ok(HashCalculationReport {
                        evidence_id: request.evidence_id,
                        volume_index: request.volume_index,
                        logical_path,
                        entry_id: request.entry_id,
                        bytes_processed,
                        sha256_hex: digest,
                        persisted: false,
                        error: Some(e.to_string()),
                    });
                }
            };

            if total_size.is_none() {
                total_size = resp.total_logical_size;
            }

            if resp.bytes.is_empty() {
                break;
            }

            hasher.update(&resp.bytes);
            let n = resp.bytes.len() as u64;
            bytes_processed += n;
            offset += n;

            if let Some(cb) = progress_cb {
                cb(bytes_processed, total_size);
            }

            if resp.eof {
                break;
            }

            if let Some(tot) = total_size {
                if offset >= tot {
                    break;
                }
            }
        }

        let digest = format!("{:x}", hasher.finalize());
        let now_utc = chrono::Utc::now().to_rfc3339();

        // Persist to database if case_path is valid
        let persisted = (|| -> Result<()> {
            let conn = Connection::open(&request.case_path)?;
            let existing_id: Option<i64> = if let Some(eid) = request.entry_id {
                Some(eid)
            } else {
                conn.query_row(
                    "SELECT id FROM filesystem_entries WHERE evidence_id = ?1 AND logical_path = ?2",
                    rusqlite::params![request.evidence_id, &logical_path],
                    |row| row.get(0),
                ).ok()
            };

            if let Some(entry_id) = existing_id {
                let existing_meta: Option<String> = conn.query_row(
                    "SELECT metadata_json FROM filesystem_entries WHERE id = ?1",
                    [entry_id],
                    |row| row.get(0),
                ).ok().flatten();

                let mut obj: serde_json::Map<String, serde_json::Value> = existing_meta
                    .as_deref()
                    .and_then(|m| serde_json::from_str(m).ok())
                    .unwrap_or_default();

                obj.insert("file_sha256".to_string(), serde_json::Value::String(digest.clone()));
                obj.insert("file_sha256_input".to_string(), serde_json::Value::String("complete reconstructed file content".to_string()));
                obj.insert("file_sha256_at".to_string(), serde_json::Value::String(now_utc.clone()));

                let new_meta = serde_json::to_string(&obj)?;
                conn.execute(
                    "UPDATE filesystem_entries SET metadata_json = ?1 WHERE id = ?2",
                    rusqlite::params![new_meta, entry_id],
                )?;
            } else {
                let mut obj = serde_json::Map::new();
                obj.insert("file_sha256".to_string(), serde_json::Value::String(digest.clone()));
                obj.insert("file_sha256_input".to_string(), serde_json::Value::String("complete reconstructed file content".to_string()));
                obj.insert("file_sha256_at".to_string(), serde_json::Value::String(now_utc.clone()));
                let new_meta = serde_json::to_string(&obj)?;
                let file_name = Path::new(&logical_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&logical_path);

                let case_id: i64 = conn.query_row(
                    "SELECT case_id FROM evidence_sources WHERE id = ?1",
                    [request.evidence_id],
                    |row| row.get(0),
                ).unwrap_or(1);

                conn.execute(
                    "INSERT INTO filesystem_entries(
                        case_id, evidence_id, parent_id, logical_path, name, entry_kind,
                        size_bytes, is_deleted, discovered_by_job_id, metadata_json
                    ) VALUES(?1, ?2, NULL, ?3, ?4, 'file', ?5, 0, NULL, ?6)",
                    rusqlite::params![
                        case_id,
                        request.evidence_id,
                        &logical_path,
                        file_name,
                        bytes_processed as i64,
                        new_meta,
                    ],
                )?;
            }
            Ok(())
        })().is_ok();

        Ok(HashCalculationReport {
            evidence_id: request.evidence_id,
            volume_index: request.volume_index,
            logical_path,
            entry_id: request.entry_id,
            bytes_processed,
            sha256_hex: digest,
            persisted,
            error: None,
        })
    }

    /// Reads a bounded slice of bytes from the requested forensic target.
    pub fn read_bytes(
        request: &BoundedByteRequest,
        unlock_mgr: Option<&TransientUnlockManager>,
    ) -> Result<BoundedByteResponse> {
        let length = request.length.clamp(1, MAX_BOUNDED_BYTE_READ);
        let mut warnings = Vec::new();

        // 1. Indexed entry byte read
        if let Some(entry_id) = request.entry_id {
            let res = read_filesystem_entry_bytes(
                &request.case_path,
                ReadEntryBytesOptions {
                    entry_id,
                    offset: request.offset,
                    length,
                },
            )
            .with_context(|| format!("reading bytes for entry {entry_id}"))?;

            let (partition_start, filesystem_offset, absolute_media_offset) =
                verified_entry_range_mapping(
                    &request.case_path,
                    entry_id,
                    request.offset,
                    res.bytes.len() as u64,
                    &mut warnings,
                );

            let eof = request.offset.saturating_add(res.bytes.len() as u64) >= res.total_size;
            let ntfs_file_record_size = (|| -> Option<u64> {
                let conn = Connection::open(&request.case_path).ok()?;
                let (source_kind, source_path): (String, String) = conn
                    .query_row(
                        "SELECT source_kind, source_path FROM evidence_sources WHERE id = ?1",
                        [request.evidence_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .ok()?;
                (source_kind == "image")
                    .then(|| {
                        kdft_case::ntfs_forensic::ntfs_forensic_file_record_size(
                            Path::new(&source_path),
                            request.volume_index,
                        )
                        .ok()
                    })
                    .flatten()
            })();

            return Ok(BoundedByteResponse {
                request_id: request.request_id,
                reader_label: "Indexed Filesystem Entry Reader".to_string(),
                namespace: request.namespace,
                requested_offset: request.offset,
                returned_offset: request.offset,
                bytes: res.bytes,
                total_logical_size: Some(res.total_size),
                eof,
                partition_start,
                filesystem_offset,
                absolute_media_offset,
                ntfs_file_record_size,
                provenance: format!("Indexed file entry #{entry_id}"),
                warnings,
            });
        }

        // 2. Query evidence source
        let conn = Connection::open(&request.case_path)
            .with_context(|| format!("opening case at {}", request.case_path.display()))?;
        let (source_kind, source_path): (String, String) = conn
            .query_row(
                "SELECT source_kind, source_path FROM evidence_sources WHERE id = ?1",
                [request.evidence_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| format!("evidence source {} not found", request.evidence_id))?;
        drop(conn);

        // 3. Raw media reading
        if request.raw_media {
            if source_kind != "image" {
                warnings
                    .push("Raw media byte reading is only valid for image evidence.".to_string());
            }
            let (bytes, total_size) = read_image_raw_bytes(
                &request.case_path,
                request.evidence_id,
                request.offset,
                length,
            )?;
            let eof = request.offset.saturating_add(bytes.len() as u64) >= total_size;
            return Ok(BoundedByteResponse {
                request_id: request.request_id,
                reader_label: "Raw Media Reader".to_string(),
                namespace: ByteSourceNamespace::AbsoluteDecodedMedia,
                requested_offset: request.offset,
                returned_offset: request.offset,
                bytes,
                total_logical_size: Some(total_size),
                eof,
                partition_start: None,
                filesystem_offset: None,
                absolute_media_offset: Some(request.offset),
                ntfs_file_record_size: None,
                provenance: "Decoded storage device raw stream".to_string(),
                warnings,
            });
        }

        // 4. Live path reading
        let path = request.path.as_deref().unwrap_or("/");

        match source_kind.as_str() {
            "folder" | "file" => {
                let (bytes, total_size) = read_local_evidence_bytes(
                    &request.case_path,
                    request.evidence_id,
                    path,
                    request.offset,
                    length,
                )?;
                let eof = request.offset.saturating_add(bytes.len() as u64) >= total_size;
                Ok(BoundedByteResponse {
                    request_id: request.request_id,
                    reader_label: "Local Filesystem Reader".to_string(),
                    namespace: ByteSourceNamespace::LocalEvidence,
                    requested_offset: request.offset,
                    returned_offset: request.offset,
                    bytes,
                    total_logical_size: Some(total_size),
                    eof,
                    partition_start: None,
                    filesystem_offset: None,
                    absolute_media_offset: None,
                    ntfs_file_record_size: None,
                    provenance: format!("Local evidence path: {path}"),
                    warnings,
                })
            }
            "image" => {
                let image_path = Path::new(&source_path);
                let volumes = list_image_volumes(image_path)
                    .with_context(|| format!("listing volumes for {}", image_path.display()))?;
                let volume = volumes
                    .get(request.volume_index)
                    .ok_or_else(|| anyhow!("volume index {} out of range", request.volume_index))?;

                let partition_start = Some(volume.start_offset);

                let is_bitlocker = volume.filesystem.contains("BitLocker")
                    || volume.bitlocker.is_some()
                    || volume.filesystem == BITLOCKER_LOCKED_FILESYSTEM;

                if is_bitlocker {
                    let cred = unlock_mgr
                        .and_then(|mgr| mgr.get_credential(request.evidence_id, request.volume_index))
                        .ok_or_else(|| {
                            anyhow!("BitLocker volume is locked. Please unlock the volume with your password or recovery key.")
                        })?;

                    let (bytes, total_size) = read_bitlocker_ntfs_file_bytes(
                        image_path,
                        request.volume_index,
                        cred.as_case_credential(),
                        path,
                        request.offset,
                        length,
                    )?;
                    let eof = request.offset.saturating_add(bytes.len() as u64) >= total_size;
                    Ok(BoundedByteResponse {
                        request_id: request.request_id,
                        reader_label: "Decrypted BitLocker NTFS Reader".to_string(),
                        namespace: ByteSourceNamespace::LogicalFile,
                        requested_offset: request.offset,
                        returned_offset: request.offset,
                        bytes,
                        total_logical_size: Some(total_size),
                        eof,
                        partition_start,
                        filesystem_offset: None,
                        absolute_media_offset: None,
                        ntfs_file_record_size: None,
                        provenance: format!("Decrypted BitLocker NTFS path: {path}"),
                        warnings,
                    })
                } else if volume.filesystem == "NTFS" {
                    let ntfs_file_record_size =
                        kdft_case::ntfs_forensic::ntfs_forensic_file_record_size(
                            image_path,
                            request.volume_index,
                        )
                        .ok();
                    let (bytes, total_size) =
                        kdft_case::ntfs_forensic::read_ntfs_forensic_file_bytes(
                            image_path,
                            request.volume_index,
                            path,
                            request.offset,
                            length,
                            None,
                        )?;
                    let eof = request.offset.saturating_add(bytes.len() as u64) >= total_size;
                    let (mapped_partition, filesystem_offset, absolute_media_offset) = request
                        .mapping_entry_id
                        .map(|entry_id| {
                            verified_entry_range_mapping(
                                &request.case_path,
                                entry_id,
                                request.offset,
                                bytes.len() as u64,
                                &mut warnings,
                            )
                        })
                        .unwrap_or((None, None, None));
                    Ok(BoundedByteResponse {
                        request_id: request.request_id,
                        reader_label: "Forensic NTFS Reader".to_string(),
                        namespace: ByteSourceNamespace::LogicalFile,
                        requested_offset: request.offset,
                        returned_offset: request.offset,
                        bytes,
                        total_logical_size: Some(total_size),
                        eof,
                        partition_start: mapped_partition.or(partition_start),
                        filesystem_offset,
                        absolute_media_offset,
                        ntfs_file_record_size,
                        provenance: format!("Live NTFS file: {path}"),
                        warnings,
                    })
                } else if volume.filesystem == "FAT" {
                    let (bytes, total_size) = read_image_directory_bytes(
                        image_path,
                        request.volume_index,
                        path,
                        request.offset,
                        length,
                    )?;
                    let eof = request.offset.saturating_add(bytes.len() as u64) >= total_size;
                    Ok(BoundedByteResponse {
                        request_id: request.request_id,
                        reader_label: "FAT32 Reader".to_string(),
                        namespace: ByteSourceNamespace::LogicalFile,
                        requested_offset: request.offset,
                        returned_offset: request.offset,
                        bytes,
                        total_logical_size: Some(total_size),
                        eof,
                        partition_start,
                        filesystem_offset: None,
                        absolute_media_offset: None,
                        ntfs_file_record_size: None,
                        provenance: format!("Live FAT file: {path}"),
                        warnings,
                    })
                } else if volume.filesystem == "EXT" {
                    let (bytes, total_size) = read_image_directory_bytes(
                        image_path,
                        request.volume_index,
                        path,
                        request.offset,
                        length,
                    )?;
                    let eof = request.offset.saturating_add(bytes.len() as u64) >= total_size;
                    Ok(BoundedByteResponse {
                        request_id: request.request_id,
                        reader_label: "EXT4 Superblock Reader".to_string(),
                        namespace: ByteSourceNamespace::LogicalFile,
                        requested_offset: request.offset,
                        returned_offset: request.offset,
                        bytes,
                        total_logical_size: Some(total_size),
                        eof,
                        partition_start,
                        filesystem_offset: None,
                        absolute_media_offset: None,
                        ntfs_file_record_size: None,
                        provenance: format!("Live EXT file: {path}"),
                        warnings,
                    })
                } else {
                    anyhow::bail!(
                        "Unsupported filesystem '{}' on volume index {}. Reading bytes requires NTFS, FAT, EXT, or Decrypted BitLocker; no silent fallback is permitted.",
                        volume.filesystem,
                        request.volume_index
                    );
                }
            }
            other => {
                warnings.push(format!("Unsupported source kind: {other}"));
                Ok(BoundedByteResponse {
                    request_id: request.request_id,
                    reader_label: "Unsupported Source Reader".to_string(),
                    namespace: request.namespace,
                    requested_offset: request.offset,
                    returned_offset: request.offset,
                    bytes: Vec::new(),
                    total_logical_size: Some(0),
                    eof: true,
                    partition_start: None,
                    filesystem_offset: None,
                    absolute_media_offset: None,
                    ntfs_file_record_size: None,
                    provenance: format!("Unsupported evidence {other}"),
                    warnings,
                })
            }
        }
    }

    pub fn verify_evidence_integrity(
        request: &EvidenceIntegrityRequest,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        progress_cb: Option<&dyn Fn(u64, Option<u64>)>,
    ) -> Result<EvidenceIntegrityReport> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        use std::sync::atomic::Ordering;

        let start_time = std::time::Instant::now();
        let started_at_utc = chrono::Utc::now().to_rfc3339();

        if request.is_defer {
            let details = serde_json::json!({
                "action": "defer",
                "recorded_at": started_at_utc,
            });
            let _ = kdft_case::update_evidence_intake_metadata(
                &request.case_path,
                request.evidence_id,
                None,
                Some("deferred"),
                request.expected_sha256.as_deref(),
                Some(&details.to_string()),
            );
            return Ok(EvidenceIntegrityReport {
                evidence_id: request.evidence_id,
                terminal_state: IntegrityTerminalState::Deferred,
                algorithm: "sha256".to_string(),
                computed_sha256: None,
                expected_sha256: request.expected_sha256.clone(),
                bytes_processed: 0,
                total_bytes: None,
                rate_bytes_per_sec: None,
                duration_ms: start_time.elapsed().as_millis() as u64,
                scope_description: "Deferred by examiner".to_string(),
                skip_reason: None,
                error: None,
                segment_count: 0,
            });
        }

        if request.is_skip {
            let reason = request
                .skip_reason
                .clone()
                .unwrap_or_else(|| "Examiner requested skip".to_string());
            let details = serde_json::json!({
                "action": "skip",
                "reason": &reason,
                "recorded_at": started_at_utc,
            });
            let _ = kdft_case::update_evidence_intake_metadata(
                &request.case_path,
                request.evidence_id,
                None,
                Some("skipped"),
                request.expected_sha256.as_deref(),
                Some(&details.to_string()),
            );
            return Ok(EvidenceIntegrityReport {
                evidence_id: request.evidence_id,
                terminal_state: IntegrityTerminalState::Skipped,
                algorithm: "sha256".to_string(),
                computed_sha256: None,
                expected_sha256: request.expected_sha256.clone(),
                bytes_processed: 0,
                total_bytes: None,
                rate_bytes_per_sec: None,
                duration_ms: start_time.elapsed().as_millis() as u64,
                scope_description: "Skipped by examiner with reason".to_string(),
                skip_reason: Some(reason),
                error: None,
                segment_count: 0,
            });
        }

        let evidence =
            crate::browse::read_evidence_record(&request.case_path, request.evidence_id)?;
        let src_path = PathBuf::from(&evidence.source_path);
        let segment_set = kdft_case::detect_acquisition_segments(&src_path)?;
        let segment_count = segment_set.paths.len();
        let scope_description = if segment_set.scheme == "ewf_numbered_segments" {
            format!("E01 segment set ({} segment files)", segment_count)
        } else if segment_set.scheme == "split_raw_segments" {
            format!("Split raw segments ({} segment files)", segment_count)
        } else {
            "Complete source file".to_string()
        };

        let mut total_bytes: u64 = 0;
        for p in &segment_set.paths {
            if let Ok(meta) = std::fs::metadata(p) {
                total_bytes = total_bytes.saturating_add(meta.len());
            }
        }

        let mut hasher = Sha256::new();
        let mut bytes_processed: u64 = 0;
        let mut buffer = vec![0u8; 1024 * 1024];

        for seg_path in &segment_set.paths {
            let mut file = match std::fs::File::open(seg_path) {
                Ok(f) => f,
                Err(e) => {
                    let err_msg = format!("Failed to open segment {}: {e}", seg_path.display());
                    let details = serde_json::json!({
                        "status": "failed",
                        "error": &err_msg,
                        "bytes_processed": bytes_processed,
                        "failed_at": chrono::Utc::now().to_rfc3339(),
                    });
                    let _ = kdft_case::update_evidence_intake_metadata(
                        &request.case_path,
                        request.evidence_id,
                        None,
                        Some("failed"),
                        request.expected_sha256.as_deref(),
                        Some(&details.to_string()),
                    );
                    return Ok(EvidenceIntegrityReport {
                        evidence_id: request.evidence_id,
                        terminal_state: IntegrityTerminalState::Failed,
                        algorithm: "sha256".to_string(),
                        computed_sha256: None,
                        expected_sha256: request.expected_sha256.clone(),
                        bytes_processed,
                        total_bytes: Some(total_bytes),
                        rate_bytes_per_sec: None,
                        duration_ms: start_time.elapsed().as_millis() as u64,
                        scope_description,
                        skip_reason: None,
                        error: Some(err_msg),
                        segment_count,
                    });
                }
            };

            loop {
                if let Some(c) = cancel {
                    if c.load(Ordering::Relaxed) {
                        let details = serde_json::json!({
                            "status": "canceled",
                            "bytes_processed": bytes_processed,
                            "canceled_at": chrono::Utc::now().to_rfc3339(),
                        });
                        let _ = kdft_case::update_evidence_intake_metadata(
                            &request.case_path,
                            request.evidence_id,
                            None,
                            Some("canceled"),
                            request.expected_sha256.as_deref(),
                            Some(&details.to_string()),
                        );
                        return Ok(EvidenceIntegrityReport {
                            evidence_id: request.evidence_id,
                            terminal_state: IntegrityTerminalState::Canceled,
                            algorithm: "sha256".to_string(),
                            computed_sha256: None,
                            expected_sha256: request.expected_sha256.clone(),
                            bytes_processed,
                            total_bytes: Some(total_bytes),
                            rate_bytes_per_sec: None,
                            duration_ms: start_time.elapsed().as_millis() as u64,
                            scope_description,
                            skip_reason: None,
                            error: Some("Integrity verification canceled by user".to_string()),
                            segment_count,
                        });
                    }
                }

                let read = match file.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        let err_msg = format!("Read error during verification: {e}");
                        return Ok(EvidenceIntegrityReport {
                            evidence_id: request.evidence_id,
                            terminal_state: IntegrityTerminalState::Failed,
                            algorithm: "sha256".to_string(),
                            computed_sha256: None,
                            expected_sha256: request.expected_sha256.clone(),
                            bytes_processed,
                            total_bytes: Some(total_bytes),
                            rate_bytes_per_sec: None,
                            duration_ms: start_time.elapsed().as_millis() as u64,
                            scope_description,
                            skip_reason: None,
                            error: Some(err_msg),
                            segment_count,
                        });
                    }
                };

                hasher.update(&buffer[..read]);
                bytes_processed = bytes_processed.saturating_add(read as u64);
                if let Some(cb) = progress_cb {
                    cb(bytes_processed, Some(total_bytes));
                }
            }
        }

        let computed_digest = format!("{:x}", hasher.finalize());
        let duration = start_time.elapsed();
        let duration_secs = duration.as_secs_f64();
        let rate = if duration_secs > 0.0 {
            Some(bytes_processed as f64 / duration_secs)
        } else {
            None
        };

        let terminal_state = match request.expected_sha256.as_deref() {
            Some(exp) if !exp.trim().is_empty() => {
                if exp.trim().eq_ignore_ascii_case(&computed_digest) {
                    IntegrityTerminalState::Verified
                } else {
                    IntegrityTerminalState::Mismatch
                }
            }
            _ => IntegrityTerminalState::ComputedNoExpected,
        };

        let finished_at_utc = chrono::Utc::now().to_rfc3339();
        let details = serde_json::json!({
            "algorithm": "sha256",
            "computed_sha256": &computed_digest,
            "expected_sha256": request.expected_sha256.as_deref(),
            "bytes_processed": bytes_processed,
            "total_bytes": total_bytes,
            "scope": &scope_description,
            "segment_count": segment_count,
            "terminal_state": terminal_state.as_str(),
            "started_at": &started_at_utc,
            "finished_at": &finished_at_utc,
            "duration_ms": duration.as_millis() as u64,
        });

        let conn = rusqlite::Connection::open(&request.case_path)?;
        conn.execute(
            "UPDATE evidence_sources
             SET sha256_hex = ?1,
                 hashed_at = ?2,
                 sha256_scope = ?3,
                 integrity_status = ?4,
                 expected_sha256 = ?5,
                 integrity_details_json = ?6
             WHERE id = ?7",
            rusqlite::params![
                &computed_digest,
                &finished_at_utc,
                &scope_description,
                terminal_state.as_str(),
                request.expected_sha256.as_deref(),
                &details.to_string(),
                request.evidence_id,
            ],
        )?;

        let case_id: i64 = conn
            .query_row(
                "SELECT case_id FROM evidence_sources WHERE id = ?1",
                rusqlite::params![request.evidence_id],
                |r| r.get(0),
            )
            .unwrap_or(1);
        let _ = conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (?1, 'evidence.integrity_verification', 'examiner', 'evidence', ?2, ?3)",
            rusqlite::params![case_id, request.evidence_id, &details.to_string()],
        );

        Ok(EvidenceIntegrityReport {
            evidence_id: request.evidence_id,
            terminal_state,
            algorithm: "sha256".to_string(),
            computed_sha256: Some(computed_digest),
            expected_sha256: request.expected_sha256.clone(),
            bytes_processed,
            total_bytes: Some(total_bytes),
            rate_bytes_per_sec: rate,
            duration_ms: duration.as_millis() as u64,
            scope_description,
            skip_reason: None,
            error: None,
            segment_count,
        })
    }

    pub fn detect_companion_expected_sha256(evidence_path: &Path) -> Option<String> {
        detect_companion_expected_sha256(evidence_path)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stream_export_folder(
        case_path: &Path,
        evidence_id: i64,
        volume_index: usize,
        source_root_path: &str,
        dest_dir: &Path,
        unlock_mgr: Option<&TransientUnlockManager>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        progress_cb: Option<&dyn Fn(usize, usize, u64)>,
    ) -> Result<FolderExportReport> {
        use std::sync::atomic::Ordering;

        let started_at_utc = chrono::Utc::now().to_rfc3339();
        let entries = crate::browse::recursive_collect_files(
            case_path,
            evidence_id,
            volume_index,
            source_root_path,
            unlock_mgr,
            cancel,
            50_000,
        )?;

        let total_files = entries.len();
        let mut files_exported = 0;
        let mut files_failed = 0;
        let mut total_bytes_written = 0u64;
        let mut manifest_entries = Vec::new();
        let mut is_canceled = false;

        let norm_root = source_root_path.trim_end_matches('/');

        for entry in &entries {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    is_canceled = true;
                    break;
                }
            }

            let rel_path_str = if entry.logical_path.starts_with(norm_root) {
                entry.logical_path[norm_root.len()..].trim_start_matches('/')
            } else {
                entry.name.as_str()
            };

            let sanitized_rel: PathBuf = rel_path_str
                .split('/')
                .map(|segment| {
                    segment
                        .chars()
                        .map(|c| match c {
                            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                            _ => c,
                        })
                        .collect::<String>()
                })
                .collect();

            let mut dest_file = dest_dir.join(&sanitized_rel);
            if let Some(parent) = dest_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            if dest_file.exists() {
                let stem = dest_file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file")
                    .to_string();
                let ext = dest_file
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(ToString::to_string);
                let parent = dest_file.parent().unwrap_or(dest_dir).to_path_buf();
                let mut collision_idx = 1;
                loop {
                    let new_name = match &ext {
                        Some(e) => format!("{stem}_{collision_idx}.{e}"),
                        None => format!("{stem}_{collision_idx}"),
                    };
                    let candidate = parent.join(new_name);
                    if !candidate.exists() {
                        dest_file = candidate;
                        break;
                    }
                    collision_idx += 1;
                }
            }

            let req = BoundedByteRequest::simple(
                case_path.to_path_buf(),
                evidence_id,
                volume_index,
                Some(entry.logical_path.clone()),
                entry.canonical_entry_id,
                ByteSourceNamespace::LogicalFile,
                0,
                64 * 1024,
                false,
            );

            match Self::stream_export_file(&req, &dest_file, unlock_mgr, cancel, None) {
                Ok(rep) => {
                    total_bytes_written = total_bytes_written.saturating_add(rep.bytes_written);
                    if rep.terminal_state == ExportTerminalState::Complete {
                        files_exported += 1;
                        manifest_entries.push(FolderExportManifestEntry {
                            logical_path: entry.logical_path.clone(),
                            destination_relative_path: dest_file
                                .strip_prefix(dest_dir)
                                .unwrap_or(&dest_file)
                                .to_string_lossy()
                                .to_string(),
                            size_bytes: entry.size_bytes,
                            sha256_hex: rep.sha256_hex,
                            status: "complete".to_string(),
                            error: None,
                        });
                    } else if rep.terminal_state == ExportTerminalState::Canceled {
                        is_canceled = true;
                        manifest_entries.push(FolderExportManifestEntry {
                            logical_path: entry.logical_path.clone(),
                            destination_relative_path: dest_file
                                .strip_prefix(dest_dir)
                                .unwrap_or(&dest_file)
                                .to_string_lossy()
                                .to_string(),
                            size_bytes: entry.size_bytes,
                            sha256_hex: rep.sha256_hex,
                            status: "canceled".to_string(),
                            error: rep.error,
                        });
                        break;
                    } else {
                        files_failed += 1;
                        manifest_entries.push(FolderExportManifestEntry {
                            logical_path: entry.logical_path.clone(),
                            destination_relative_path: dest_file
                                .strip_prefix(dest_dir)
                                .unwrap_or(&dest_file)
                                .to_string_lossy()
                                .to_string(),
                            size_bytes: entry.size_bytes,
                            sha256_hex: rep.sha256_hex,
                            status: "failed".to_string(),
                            error: rep.error,
                        });
                    }
                }
                Err(e) => {
                    files_failed += 1;
                    manifest_entries.push(FolderExportManifestEntry {
                        logical_path: entry.logical_path.clone(),
                        destination_relative_path: dest_file
                            .strip_prefix(dest_dir)
                            .unwrap_or(&dest_file)
                            .to_string_lossy()
                            .to_string(),
                        size_bytes: entry.size_bytes,
                        sha256_hex: String::new(),
                        status: "failed".to_string(),
                        error: Some(e.to_string()),
                    });
                }
            }

            if let Some(cb) = progress_cb {
                cb(
                    files_exported + files_failed,
                    total_files,
                    total_bytes_written,
                );
            }
        }

        let terminal_state = if is_canceled {
            ExportTerminalState::Canceled
        } else if files_failed > 0 && files_exported > 0 {
            ExportTerminalState::Partial
        } else if files_failed > 0 && files_exported == 0 {
            ExportTerminalState::Failed
        } else {
            ExportTerminalState::Complete
        };

        let completed_at_utc = chrono::Utc::now().to_rfc3339();
        let manifest = FolderExportManifest {
            export_version: "1.0".to_string(),
            started_at_utc,
            completed_at_utc,
            evidence_id,
            volume_index,
            source_root_path: source_root_path.to_string(),
            destination_directory: dest_dir.display().to_string(),
            terminal_state,
            total_files_exported: files_exported,
            total_files_failed: files_failed,
            total_bytes_exported: total_bytes_written,
            entries: manifest_entries,
        };

        let manifest_path = dest_dir.join("export_manifest.json");
        if let Ok(manifest_json) = serde_json::to_string_pretty(&manifest) {
            let _ = std::fs::write(&manifest_path, manifest_json);
        }

        Ok(FolderExportReport {
            evidence_id,
            volume_index,
            source_root_path: source_root_path.to_string(),
            dest_dir: dest_dir.to_path_buf(),
            terminal_state,
            files_exported,
            files_failed,
            bytes_written: total_bytes_written,
            manifest_path: Some(manifest_path),
            error: None,
        })
    }

    pub fn calculate_hashes_recursive(
        case_path: &Path,
        evidence_id: i64,
        volume_index: usize,
        source_root_path: &str,
        unlock_mgr: Option<&TransientUnlockManager>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        progress_cb: Option<&dyn Fn(usize, usize, u64)>,
    ) -> Result<RecursiveHashReport> {
        use std::sync::atomic::Ordering;

        let entries = crate::browse::recursive_collect_files(
            case_path,
            evidence_id,
            volume_index,
            source_root_path,
            unlock_mgr,
            cancel,
            50_000,
        )?;

        let total_files = entries.len();
        let mut files_hashed = 0;
        let mut files_failed = 0;
        let mut total_bytes_hashed = 0u64;
        let mut is_canceled = false;

        for entry in &entries {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    is_canceled = true;
                    break;
                }
            }

            let req = BoundedByteRequest::simple(
                case_path.to_path_buf(),
                evidence_id,
                volume_index,
                Some(entry.logical_path.clone()),
                entry.canonical_entry_id,
                ByteSourceNamespace::LogicalFile,
                0,
                64 * 1024,
                false,
            );

            match Self::calculate_file_hashes(&req, unlock_mgr, cancel, None) {
                Ok(rep) => {
                    if rep.error.as_deref() == Some("Operation canceled by user") {
                        is_canceled = true;
                        break;
                    }
                    total_bytes_hashed = total_bytes_hashed.saturating_add(rep.bytes_processed);
                    if rep.error.is_none() {
                        files_hashed += 1;
                    } else {
                        files_failed += 1;
                    }
                }
                Err(_) => {
                    files_failed += 1;
                }
            }

            if let Some(cb) = progress_cb {
                cb(files_hashed + files_failed, total_files, total_bytes_hashed);
            }
        }

        let terminal_state = if is_canceled {
            ExportTerminalState::Canceled
        } else if files_failed > 0 && files_hashed > 0 {
            ExportTerminalState::Partial
        } else if files_failed > 0 && files_hashed == 0 {
            ExportTerminalState::Failed
        } else {
            ExportTerminalState::Complete
        };

        Ok(RecursiveHashReport {
            evidence_id,
            volume_index,
            source_root_path: source_root_path.to_string(),
            files_hashed,
            files_failed,
            bytes_hashed: total_bytes_hashed,
            terminal_state,
            error: None,
        })
    }
}

pub fn extract_64_hex(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 64 <= bytes.len() {
        let slice = &text[i..i + 64];
        if slice.chars().all(|c| c.is_ascii_hexdigit()) {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_hexdigit();
            let next_ok = i + 64 == bytes.len() || !bytes[i + 64].is_ascii_hexdigit();
            if prev_ok && next_ok {
                return Some(slice.to_ascii_lowercase());
            }
        }
        i += 1;
    }
    None
}

pub fn parse_expected_sha256_from_text(content: &str) -> Option<String> {
    for line in content.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("sha256") || lower.contains("sha-256") || lower.contains("sha 256") {
            if let Some(hash) = extract_64_hex(&lower) {
                return Some(hash);
            }
        }
    }
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(hash) = extract_64_hex(trimmed) {
            if trimmed.starts_with(&hash) {
                return Some(hash);
            }
        }
    }
    None
}

pub fn detect_companion_expected_sha256(evidence_path: &Path) -> Option<String> {
    let parent = evidence_path.parent()?;
    let stem = evidence_path.file_stem()?.to_str()?;
    let file_name = evidence_path.file_name()?.to_str()?;

    let candidate_extensions = ["info", "txt", "log", "sha256", "md5"];
    let mut candidate_paths = Vec::new();

    for ext in &candidate_extensions {
        candidate_paths.push(parent.join(format!("{stem}.{ext}")));
        candidate_paths.push(parent.join(format!("{file_name}.{ext}")));
    }

    for path in candidate_paths {
        if path.is_file() {
            if let Ok(file) = std::fs::File::open(&path) {
                use std::io::Read;
                let mut reader = file.take(512 * 1024);
                let mut text = String::new();
                if reader.read_to_string(&mut text).is_ok() {
                    if let Some(sha256) = parse_expected_sha256_from_text(&text) {
                        return Some(sha256);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinate_namespace_labels_are_truthful() {
        assert_eq!(
            ByteSourceNamespace::AbsoluteDecodedMedia.label(),
            "Absolute Decoded-Media Offset"
        );
        assert!(!ByteSourceNamespace::E01LogicalMedia
            .description()
            .contains("container-segment"));
        assert!(ByteSourceNamespace::E01LogicalMedia
            .description()
            .contains("raw media stream"));
    }

    #[test]
    fn test_evidence_integrity_terminal_states() {
        use crate::workflow::{
            AttachEvidenceRequest, CreateCaseRequest, NativeEvidenceKind, NativeWorkflowService,
        };
        use sha2::{Digest, Sha256};
        use std::fs;

        let temp_dir = std::env::temp_dir().join(format!("kdft-bytes-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let case_path = temp_dir.join("test_case.kdft");
        let _ = fs::remove_file(&case_path);

        NativeWorkflowService::create_case(CreateCaseRequest {
            case_path: case_path.clone(),
            name: "Byte Test Case".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("CASE-1".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        })
        .expect("create case");

        let test_file = temp_dir.join("image.raw");
        let content = b"Forensic evidence data payload 1234567890";
        fs::write(&test_file, content).expect("write file");

        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected_sha256 = format!("{:x}", hasher.finalize());

        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: test_file.clone(),
            kind: NativeEvidenceKind::File,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: Some("image.raw".to_string()),
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })
        .expect("attach evidence");

        // 1. Verified with matching expected hash
        let report_verified = NativeByteService::verify_evidence_integrity(
            &EvidenceIntegrityRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                expected_sha256: Some(expected_sha256.clone()),
                skip_reason: None,
                is_skip: false,
                is_defer: false,
            },
            None,
            None,
        )
        .expect("verify integrity");

        assert_eq!(
            report_verified.terminal_state,
            IntegrityTerminalState::Verified
        );
        assert_eq!(
            report_verified.computed_sha256.as_deref(),
            Some(expected_sha256.as_str())
        );
        assert_eq!(report_verified.bytes_processed, content.len() as u64);

        // 2. Mismatch with incorrect expected hash
        let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let report_mismatch = NativeByteService::verify_evidence_integrity(
            &EvidenceIntegrityRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                expected_sha256: Some(bad_hash.to_string()),
                skip_reason: None,
                is_skip: false,
                is_defer: false,
            },
            None,
            None,
        )
        .expect("verify integrity mismatch");

        assert_eq!(
            report_mismatch.terminal_state,
            IntegrityTerminalState::Mismatch
        );
        assert_eq!(
            report_mismatch.computed_sha256.as_deref(),
            Some(expected_sha256.as_str())
        );

        // 3. Computed, no expected value
        let report_computed = NativeByteService::verify_evidence_integrity(
            &EvidenceIntegrityRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                expected_sha256: None,
                skip_reason: None,
                is_skip: false,
                is_defer: false,
            },
            None,
            None,
        )
        .expect("verify integrity computed");

        assert_eq!(
            report_computed.terminal_state,
            IntegrityTerminalState::ComputedNoExpected
        );
        assert_eq!(
            report_computed.computed_sha256.as_deref(),
            Some(expected_sha256.as_str())
        );

        // 4. Skipped with reason
        let report_skipped = NativeByteService::verify_evidence_integrity(
            &EvidenceIntegrityRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                expected_sha256: None,
                skip_reason: Some("Triage intake on large live image".to_string()),
                is_skip: true,
                is_defer: false,
            },
            None,
            None,
        )
        .expect("verify integrity skipped");

        assert_eq!(
            report_skipped.terminal_state,
            IntegrityTerminalState::Skipped
        );
        assert_eq!(
            report_skipped.skip_reason.as_deref(),
            Some("Triage intake on large live image")
        );

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_evidence_integrity_split_segments() {
        use crate::workflow::{
            AttachEvidenceRequest, CreateCaseRequest, NativeEvidenceKind, NativeWorkflowService,
        };
        use sha2::{Digest, Sha256};
        use std::fs;

        let temp_dir = std::env::temp_dir().join(format!("kdft-split-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let case_path = temp_dir.join("test_case.kdft");
        let _ = fs::remove_file(&case_path);

        NativeWorkflowService::create_case(CreateCaseRequest {
            case_path: case_path.clone(),
            name: "Split Test Case".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("CASE-2".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        })
        .expect("create case");

        let seg1 = temp_dir.join("disk.001");
        let seg2 = temp_dir.join("disk.002");
        let chunk1 = b"PART ONE FORENSIC CONTENT";
        let chunk2 = b"PART TWO MORE DATA CHUNK";
        fs::write(&seg1, chunk1).expect("write seg1");
        fs::write(&seg2, chunk2).expect("write seg2");

        let mut hasher = Sha256::new();
        hasher.update(chunk1);
        hasher.update(chunk2);
        let combined_sha256 = format!("{:x}", hasher.finalize());

        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: seg1.clone(),
            kind: NativeEvidenceKind::Image,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: Some("disk.001".to_string()),
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })
        .expect("attach evidence");

        let report = NativeByteService::verify_evidence_integrity(
            &EvidenceIntegrityRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                expected_sha256: Some(combined_sha256.clone()),
                skip_reason: None,
                is_skip: false,
                is_defer: false,
            },
            None,
            None,
        )
        .expect("verify integrity across segments");

        assert_eq!(report.terminal_state, IntegrityTerminalState::Verified);
        assert_eq!(report.segment_count, 2);
        assert_eq!(report.bytes_processed, (chunk1.len() + chunk2.len()) as u64);
        assert_eq!(
            report.computed_sha256.as_deref(),
            Some(combined_sha256.as_str())
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_folder_export_manifest_and_collision_handling() {
        use crate::unlock::TransientUnlockManager;
        use crate::workflow::{
            AttachEvidenceRequest, CreateCaseRequest, NativeEvidenceKind, NativeWorkflowService,
        };
        use rusqlite::Connection;
        use std::fs;

        let temp_dir =
            std::env::temp_dir().join(format!("kdft-export-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let case_path = temp_dir.join("test_case.kdft");
        let _ = fs::remove_file(&case_path);

        NativeWorkflowService::create_case(CreateCaseRequest {
            case_path: case_path.clone(),
            name: "Export Test Case".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("CASE-3".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        })
        .expect("create case");

        // Create a source tree to attach as folder evidence
        let source_root = temp_dir.join("source_root");
        let dir_a = source_root.join("sub_a");
        let dir_b = source_root.join("sub_b");
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();

        // Same filename "report.pdf" in two different subdirectories to test collision handling
        fs::write(dir_a.join("report.pdf"), b"report alpha bytes").unwrap();
        fs::write(dir_b.join("report.pdf"), b"report beta different bytes").unwrap();

        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: source_root.clone(),
            kind: NativeEvidenceKind::Folder,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: Some("source_root".to_string()),
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })
        .expect("attach folder");

        // Populate filesystem_entries for this evidence
        let conn = Connection::open(&case_path).unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries (case_id, evidence_id, parent_id, logical_path, name, entry_kind, size_bytes, is_deleted, discovered_by_job_id)
             VALUES (1, ?1, NULL, '/sub_a', 'sub_a', 'folder', NULL, 0, NULL)",
            [attached.evidence_id],
        ).unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries (case_id, evidence_id, parent_id, logical_path, name, entry_kind, size_bytes, is_deleted, discovered_by_job_id)
             VALUES (1, ?1, NULL, '/sub_b', 'sub_b', 'folder', NULL, 0, NULL)",
            [attached.evidence_id],
        ).unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries (case_id, evidence_id, parent_id, logical_path, name, entry_kind, size_bytes, is_deleted, discovered_by_job_id)
             VALUES (1, ?1, 1, '/sub_a/report.pdf', 'report.pdf', 'file', 18, 0, NULL)",
            [attached.evidence_id],
        ).unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries (case_id, evidence_id, parent_id, logical_path, name, entry_kind, size_bytes, is_deleted, discovered_by_job_id)
             VALUES (1, ?1, 2, '/sub_b/report.pdf', 'report.pdf', 'file', 27, 0, NULL)",
            [attached.evidence_id],
        ).unwrap();
        drop(conn);

        let export_dir = temp_dir.join("exported_output");
        // Pre-create sub_a/report.pdf to force a collision on the first exported file
        fs::create_dir_all(export_dir.join("sub_a")).unwrap();
        fs::write(
            export_dir.join("sub_a").join("report.pdf"),
            b"pre-existing collision target",
        )
        .unwrap();

        let unlock_mgr = TransientUnlockManager::default();

        let report = NativeByteService::stream_export_folder(
            &case_path,
            attached.evidence_id,
            0,
            "/",
            &export_dir,
            Some(&unlock_mgr),
            None,
            None,
        )
        .expect("stream export folder");

        assert_eq!(report.files_exported, 2);
        assert_eq!(report.files_failed, 0);
        assert_eq!(report.terminal_state, ExportTerminalState::Complete);

        // Check that exported files exist
        let exported_manifest_path = export_dir.join("export_manifest.json");
        assert!(exported_manifest_path.exists());

        let manifest_content = fs::read_to_string(&exported_manifest_path).unwrap();
        let manifest: FolderExportManifest = serde_json::from_str(&manifest_content).unwrap();
        assert_eq!(manifest.entries.len(), 2);

        // Verify collision handling: sub_a/report.pdf collided and was exported as report_1.pdf
        assert!(export_dir.join("sub_a").join("report_1.pdf").exists());
        assert!(export_dir.join("sub_b").join("report.pdf").exists());
        // Pre-existing file was preserved
        assert_eq!(
            fs::read(export_dir.join("sub_a").join("report.pdf")).unwrap(),
            b"pre-existing collision target"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn parse_expected_sha256_from_guymager_info_text() {
        let sample_guymager = r#"
GUYMAGER ACQUISITION INFO FILE
==============================
Hash calculation        : MD5, SHA-1 and SHA-256
MD5 hash                   : 438e834e6a992ee1f2ea3756c95f8b9b
SHA1 hash                  : 857bf3bb9fbb88c47f01c63705814b98b8a08fad
SHA256 hash                : f3dc80a98ebdf00556924a6c9476709080eb1d6897cc98388b0ec4f28ab1c0c9
SHA256 hash verified source: --
SHA256 hash verified image : f3dc80a98ebdf00556924a6c9476709080eb1d6897cc98388b0ec4f28ab1c0c9
"#;
        let detected = parse_expected_sha256_from_text(sample_guymager);
        assert_eq!(
            detected.as_deref(),
            Some("f3dc80a98ebdf00556924a6c9476709080eb1d6897cc98388b0ec4f28ab1c0c9")
        );
    }

    #[test]
    fn parse_expected_sha256_from_ftk_text() {
        let sample_ftk = r#"
Created By AccessData® FTK® Imager 4.5.0.3
Case Information:
Evidence Source: Physical Drive 0
[Computed Hashes]
MD5 checksum: 1234567890abcdef1234567890abcdef
SHA256 checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#;
        let detected = parse_expected_sha256_from_text(sample_ftk);
        assert_eq!(
            detected.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn detect_companion_expected_sha256_finds_sibling_file() {
        use std::fs;
        let temp_dir =
            std::env::temp_dir().join(format!("kdft-companion-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let image_path = temp_dir.join("evidence.E01");
        fs::write(&image_path, b"test image").unwrap();
        let info_path = temp_dir.join("evidence.info");
        fs::write(
            &info_path,
            "SHA256 hash: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let found = detect_companion_expected_sha256(&image_path);
        assert_eq!(
            found.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
