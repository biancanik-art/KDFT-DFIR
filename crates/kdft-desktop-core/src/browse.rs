use crate::protocol::{
    ArtifactCoordinate, ArtifactDetail, ArtifactDetailCompleteness, ArtifactMetadataState,
    ArtifactProvenanceField, ArtifactSectionAvailability, ArtifactTimestamp,
    ArtifactValueAvailability, CoverageState,
};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_DIRECTORY_PAGE_SIZE: usize = 200;
pub const MAX_DIRECTORY_PAGE_SIZE: usize = 1_000;
pub const BITLOCKER_LOCKED_MSG: &str = "Locked / unlock not yet available in native Desktop. Key acquisition and decryption are deferred to preserve security and forensic isolation.";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VolumeIdentity {
    pub case_id: i64,
    pub evidence_id: i64,
    pub volume_index: usize,
    pub partition_start: u64,
    pub partition_length: u64,
    pub filesystem_type: String,
    pub encryption_type: Option<String>,
    pub volume_fingerprint: String,
    pub transient_unlock_generation: Option<u64>,
}

impl VolumeIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        case_id: i64,
        evidence_id: i64,
        volume_index: usize,
        partition_start: u64,
        partition_length: u64,
        filesystem_type: impl Into<String>,
        encryption_type: Option<String>,
        unlock_generation: Option<u64>,
    ) -> Self {
        let fs_type = filesystem_type.into();
        let enc_str = encryption_type.as_deref().unwrap_or("none");
        let volume_fingerprint = format!(
            "case:{}:ev:{}:vol:{}:start:{}:len:{}:fs:{}:enc:{}",
            case_id, evidence_id, volume_index, partition_start, partition_length, fs_type, enc_str
        );
        Self {
            case_id,
            evidence_id,
            volume_index,
            partition_start,
            partition_length,
            filesystem_type: fs_type,
            encryption_type,
            volume_fingerprint,
            transient_unlock_generation: unlock_generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeAccessState {
    Accessible,
    Locked { message: String },
    UnlockedForSession { generation: u64 },
    InvalidCredential { message: String },
    UnsupportedCipher { cipher: String },
    FilesystemParseError { error: String },
    EvidenceIoError { error: String },
    UnsupportedFilesystem { filesystem: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowseHistoryEntry {
    pub volume_identity: VolumeIdentity,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceVolume {
    pub index: usize,
    pub name: String,
    pub filesystem: String,
    pub start_offset: u64,
    pub size_bytes: u64,
    pub browsable: bool,
    pub is_bitlocker: bool,
    pub bitlocker_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowseEntry {
    pub name: String,
    pub logical_path: String,
    pub is_dir: bool,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub provenance: Option<String>,
    pub reconstruction_status: Option<String>,
    pub file_record_number: Option<u64>,
    pub physical_offset: Option<u64>,
    pub canonical_entry_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowseDirectoryPage {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub volume_identity: Option<VolumeIdentity>,
    pub access_state: VolumeAccessState,
    pub reader_label: String,
    pub request_id: u64,
    pub path: String,
    pub entries: Vec<BrowseEntry>,
    pub total_entries: usize,
    pub offset: usize,
    pub next_offset: Option<usize>,
    pub truncated: bool,
    pub filesystem: String,
    pub is_locked: bool,
    pub locked_message: Option<String>,
    pub is_unsupported: bool,
    pub unsupported_message: Option<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    #[allow(dead_code)]
    pub id: i64,
    pub case_id: i64,
    pub source_kind: String,
    pub source_path: String,
    pub display_name: String,
    pub size_bytes: Option<i64>,
}

pub struct NativeBrowseService;

impl NativeBrowseService {
    pub fn list_volumes(case_path: &Path, evidence_id: i64) -> Result<Vec<EvidenceVolume>> {
        let evidence = read_evidence_record(case_path, evidence_id)?;
        match evidence.source_kind.as_str() {
            "image" => {
                let img_path = Path::new(&evidence.source_path);
                if !img_path.exists() {
                    bail!("evidence image file does not exist: {}", img_path.display());
                }
                let raw_volumes = kdft_case::list_image_volumes(img_path)
                    .with_context(|| format!("listing volumes of {}", img_path.display()))?;
                let volumes = raw_volumes
                    .into_iter()
                    .map(|v| {
                        let is_bitlocker = v.filesystem.contains("BitLocker")
                            || v.bitlocker.is_some()
                            || (!v.browsable && v.filesystem == "BitLocker (Locked)");
                        let bitlocker_status = v.bitlocker.map(|b| b.status);
                        EvidenceVolume {
                            index: v.index,
                            name: v.name,
                            filesystem: v.filesystem,
                            start_offset: v.start_offset,
                            size_bytes: v.size_bytes,
                            browsable: v.browsable && !is_bitlocker,
                            is_bitlocker,
                            bitlocker_status,
                        }
                    })
                    .collect();
                Ok(volumes)
            }
            "folder" | "file" => {
                let size = evidence.size_bytes.unwrap_or(0);
                Ok(vec![EvidenceVolume {
                    index: 0,
                    name: evidence.display_name.clone(),
                    filesystem: "LOCAL".to_string(),
                    start_offset: 0,
                    size_bytes: if size > 0 { size as u64 } else { 0 },
                    browsable: true,
                    is_bitlocker: false,
                    bitlocker_status: None,
                }])
            }
            other => bail!("live browsing is not supported for {other} evidence"),
        }
    }

    pub fn read_directory_page(
        case_path: &Path,
        evidence_id: i64,
        volume_index: usize,
        dir_path: &str,
        offset: usize,
        limit: usize,
        unlock_mgr: Option<&crate::unlock::TransientUnlockManager>,
    ) -> Result<BrowseDirectoryPage> {
        let evidence = read_evidence_record(case_path, evidence_id)?;
        let limit = limit.clamp(1, MAX_DIRECTORY_PAGE_SIZE);
        let normalized_path = normalize_browse_path(dir_path);

        match evidence.source_kind.as_str() {
            "image" => {
                let img_path = Path::new(&evidence.source_path);
                if !img_path.exists() {
                    bail!("evidence image file does not exist: {}", img_path.display());
                }
                let raw_volumes = kdft_case::list_image_volumes(img_path)
                    .with_context(|| format!("listing volumes of {}", img_path.display()))?;
                let volume = raw_volumes
                    .get(volume_index)
                    .with_context(|| format!("volume index {volume_index} out of range"))?;

                let is_bitlocker = volume.filesystem.contains("BitLocker")
                    || volume.bitlocker.is_some()
                    || (!volume.browsable && volume.filesystem == "BitLocker (Locked)");

                let unlock_gen = if is_bitlocker {
                    unlock_mgr.and_then(|m| m.unlock_generation(evidence_id, volume_index))
                } else {
                    None
                };

                let volume_identity = VolumeIdentity::new(
                    evidence.case_id,
                    evidence_id,
                    volume_index,
                    volume.start_offset,
                    volume.size_bytes,
                    volume.filesystem.clone(),
                    if is_bitlocker {
                        Some("BitLocker".to_string())
                    } else {
                        None
                    },
                    unlock_gen,
                );

                if is_bitlocker {
                    if let Some(cred) =
                        unlock_mgr.and_then(|m| m.get_credential(evidence_id, volume_index))
                    {
                        match kdft_case::list_bitlocker_ntfs_directory(
                            img_path,
                            volume_index,
                            cred.as_case_credential(),
                            &normalized_path,
                        ) {
                            Ok(entries) => {
                                let total_entries = entries.len();
                                let mut paged: Vec<BrowseEntry> = entries
                                    .into_iter()
                                    .skip(offset)
                                    .take(limit)
                                    .map(|e| {
                                        let item_path = join_browse_path(&normalized_path, &e.name);
                                        BrowseEntry {
                                            name: e.name,
                                            logical_path: item_path,
                                            is_dir: e.is_dir,
                                            size_bytes: e.size_bytes,
                                            is_deleted: false,
                                            created_utc: e.created_utc,
                                            modified_utc: e.modified_utc,
                                            accessed_utc: e.accessed_utc,
                                            provenance: Some(format!(
                                                "Volume {volume_index} (BitLocker Unlocked)"
                                            )),
                                            reconstruction_status: None,
                                            file_record_number: e.ntfs_file_record_number,
                                            physical_offset: e.file_data_physical_offset,
                                            canonical_entry_id: None,
                                        }
                                    })
                                    .collect();
                                let _ = resolve_canonical_entry_ids(
                                    case_path,
                                    evidence.case_id,
                                    evidence_id,
                                    &mut paged,
                                );
                                let next_offset = if offset + paged.len() < total_entries {
                                    Some(offset + paged.len())
                                } else {
                                    None
                                };
                                return Ok(BrowseDirectoryPage {
                                    evidence_id,
                                    volume_index,
                                    volume_identity: Some(volume_identity),
                                    access_state: VolumeAccessState::UnlockedForSession {
                                        generation: unlock_gen.unwrap_or(0),
                                    },
                                    reader_label: "Decrypted BitLocker NTFS Reader".to_string(),
                                    request_id: 0,
                                    path: normalized_path,
                                    entries: paged,
                                    total_entries,
                                    offset,
                                    next_offset,
                                    truncated: next_offset.is_some(),
                                    filesystem: "NTFS (BitLocker Unlocked)".to_string(),
                                    is_locked: false,
                                    locked_message: None,
                                    is_unsupported: false,
                                    unsupported_message: None,
                                    diagnostics: Vec::new(),
                                });
                            }
                            Err(e) => {
                                return Ok(BrowseDirectoryPage {
                                    evidence_id,
                                    volume_index,
                                    volume_identity: Some(volume_identity),
                                    access_state: VolumeAccessState::FilesystemParseError {
                                        error: format!("BitLocker read error: {e}"),
                                    },
                                    reader_label: "Decrypted BitLocker NTFS Reader".to_string(),
                                    request_id: 0,
                                    path: normalized_path,
                                    entries: Vec::new(),
                                    total_entries: 0,
                                    offset,
                                    next_offset: None,
                                    truncated: false,
                                    filesystem: volume.filesystem.clone(),
                                    is_locked: true,
                                    locked_message: Some(format!("BitLocker read error: {e}")),
                                    is_unsupported: false,
                                    unsupported_message: None,
                                    diagnostics: vec![format!("Decryption read error: {e}")],
                                });
                            }
                        }
                    } else {
                        return Ok(BrowseDirectoryPage {
                            evidence_id,
                            volume_index,
                            volume_identity: Some(volume_identity),
                            access_state: VolumeAccessState::Locked {
                                message: BITLOCKER_LOCKED_MSG.to_string(),
                            },
                            reader_label: "BitLocker Locked".to_string(),
                            request_id: 0,
                            path: normalized_path,
                            entries: Vec::new(),
                            total_entries: 0,
                            offset,
                            next_offset: None,
                            truncated: false,
                            filesystem: volume.filesystem.clone(),
                            is_locked: true,
                            locked_message: Some(BITLOCKER_LOCKED_MSG.to_string()),
                            is_unsupported: false,
                            unsupported_message: None,
                            diagnostics: Vec::new(),
                        });
                    }
                }

                if volume.filesystem == "NTFS" {
                    let browse_options =
                        kdft_case::ntfs_forensic::NtfsForensicBrowseOptions { limit, offset };
                    let dir_res = kdft_case::ntfs_forensic::list_ntfs_forensic_directory(
                        img_path,
                        volume_index,
                        &normalized_path,
                        &browse_options,
                        None,
                    );
                    let listing = match dir_res {
                        Ok(listing) => listing,
                        Err(err) => {
                            return Ok(BrowseDirectoryPage {
                                evidence_id,
                                volume_index,
                                volume_identity: Some(volume_identity),
                                access_state: VolumeAccessState::FilesystemParseError {
                                    error: err.to_string(),
                                },
                                reader_label: "Forensic NTFS Reader".to_string(),
                                request_id: 0,
                                path: normalized_path,
                                entries: Vec::new(),
                                total_entries: 0,
                                offset,
                                next_offset: None,
                                truncated: false,
                                filesystem: volume.filesystem.clone(),
                                is_locked: false,
                                locked_message: None,
                                is_unsupported: true,
                                unsupported_message: Some(format!(
                                    "NTFS forensic directory read failure: {err}"
                                )),
                                diagnostics: vec![err.to_string()],
                            });
                        }
                    };

                    let mut entries = Vec::with_capacity(listing.entries.len());
                    for e in listing.entries {
                        let item_path = join_browse_path(&normalized_path, &e.name);
                        entries.push(BrowseEntry {
                            name: e.name,
                            logical_path: item_path,
                            is_dir: e.is_dir,
                            size_bytes: e.size_bytes,
                            is_deleted: e.is_deleted,
                            created_utc: e.created_utc,
                            modified_utc: e.modified_utc,
                            accessed_utc: e.accessed_utc,
                            provenance: Some(e.provenance),
                            reconstruction_status: Some(e.reconstruction_status),
                            file_record_number: Some(e.ntfs_file_record_number),
                            physical_offset: e.file_data_physical_offset,
                            canonical_entry_id: None,
                        });
                    }

                    resolve_canonical_entry_ids(
                        case_path,
                        evidence.case_id,
                        evidence_id,
                        &mut entries,
                    )?;

                    let total_entries = listing.total_children;
                    let next_offset = if offset.saturating_add(entries.len()) < total_entries {
                        Some(offset.saturating_add(entries.len()))
                    } else {
                        None
                    };

                    Ok(BrowseDirectoryPage {
                        evidence_id,
                        volume_index,
                        volume_identity: Some(volume_identity),
                        access_state: VolumeAccessState::Accessible,
                        reader_label: "Forensic NTFS Reader".to_string(),
                        request_id: 0,
                        path: normalized_path,
                        entries,
                        total_entries,
                        offset,
                        next_offset,
                        truncated: listing.truncated,
                        filesystem: volume.filesystem.clone(),
                        is_locked: false,
                        locked_message: None,
                        is_unsupported: false,
                        unsupported_message: None,
                        diagnostics: listing.diagnostics,
                    })
                } else if volume.filesystem == "FAT" || volume.filesystem == "EXT" {
                    let dir_res = kdft_case::list_image_directory_page(
                        img_path,
                        volume_index,
                        &normalized_path,
                        offset,
                        limit,
                    );
                    let (raw_entries, total_entries, truncated) = match dir_res {
                        Ok(res) => res,
                        Err(err) => {
                            return Ok(BrowseDirectoryPage {
                                evidence_id,
                                volume_index,
                                volume_identity: Some(volume_identity),
                                access_state: VolumeAccessState::FilesystemParseError {
                                    error: err.to_string(),
                                },
                                reader_label: if volume.filesystem == "EXT" {
                                    "EXT4 Superblock Reader".to_string()
                                } else {
                                    "FAT32 Reader".to_string()
                                },
                                request_id: 0,
                                path: normalized_path,
                                entries: Vec::new(),
                                total_entries: 0,
                                offset,
                                next_offset: None,
                                truncated: false,
                                filesystem: volume.filesystem.clone(),
                                is_locked: false,
                                locked_message: None,
                                is_unsupported: true,
                                unsupported_message: Some(format!(
                                    "Volume directory read failure: {err}"
                                )),
                                diagnostics: vec![err.to_string()],
                            });
                        }
                    };

                    let mut entries = Vec::with_capacity(raw_entries.len());
                    for e in raw_entries {
                        let item_path = join_browse_path(&normalized_path, &e.name);
                        entries.push(BrowseEntry {
                            name: e.name,
                            logical_path: item_path,
                            is_dir: e.is_dir,
                            size_bytes: e.size_bytes,
                            is_deleted: false,
                            created_utc: e.created_utc,
                            modified_utc: e.modified_utc,
                            accessed_utc: e.accessed_utc,
                            provenance: Some(format!(
                                "Volume {volume_index} ({})",
                                volume.filesystem
                            )),
                            reconstruction_status: None,
                            file_record_number: e.ntfs_file_record_number,
                            physical_offset: e.file_data_physical_offset,
                            canonical_entry_id: None,
                        });
                    }

                    resolve_canonical_entry_ids(
                        case_path,
                        evidence.case_id,
                        evidence_id,
                        &mut entries,
                    )?;

                    let next_offset = if truncated {
                        Some(offset.saturating_add(entries.len()))
                    } else {
                        None
                    };

                    Ok(BrowseDirectoryPage {
                        evidence_id,
                        volume_index,
                        volume_identity: Some(volume_identity),
                        access_state: VolumeAccessState::Accessible,
                        reader_label: if volume.filesystem == "EXT" {
                            "EXT4 Superblock Reader".to_string()
                        } else {
                            "FAT32 Reader".to_string()
                        },
                        request_id: 0,
                        path: normalized_path,
                        entries,
                        total_entries,
                        offset,
                        next_offset,
                        truncated,
                        filesystem: volume.filesystem.clone(),
                        is_locked: false,
                        locked_message: None,
                        is_unsupported: false,
                        unsupported_message: None,
                        diagnostics: Vec::new(),
                    })
                } else {
                    Ok(BrowseDirectoryPage {
                        evidence_id,
                        volume_index,
                        volume_identity: Some(volume_identity),
                        access_state: VolumeAccessState::UnsupportedFilesystem {
                            filesystem: volume.filesystem.clone(),
                        },
                        reader_label: "Unsupported Reader".to_string(),
                        request_id: 0,
                        path: normalized_path,
                        entries: Vec::new(),
                        total_entries: 0,
                        offset,
                        next_offset: None,
                        truncated: false,
                        filesystem: volume.filesystem.clone(),
                        is_locked: false,
                        locked_message: None,
                        is_unsupported: true,
                        unsupported_message: Some(format!(
                            "Unsupported volume filesystem: {}. Browsing requires NTFS, FAT, or EXT.",
                            volume.filesystem
                        )),
                        diagnostics: Vec::new(),
                    })
                }
            }
            "folder" | "file" => {
                let volume_identity = VolumeIdentity::new(
                    evidence.case_id,
                    evidence_id,
                    0,
                    0,
                    evidence.size_bytes.unwrap_or(0).max(0) as u64,
                    "LOCAL",
                    None,
                    None,
                );

                let dir_res = kdft_case::list_local_directory_offset_page(
                    case_path,
                    evidence_id,
                    &normalized_path,
                    offset,
                    limit,
                );
                let listing = match dir_res {
                    Ok(listing) => listing,
                    Err(err) => {
                        return Ok(BrowseDirectoryPage {
                            evidence_id,
                            volume_index: 0,
                            volume_identity: Some(volume_identity),
                            access_state: VolumeAccessState::EvidenceIoError {
                                error: err.to_string(),
                            },
                            reader_label: "Local Filesystem Reader".to_string(),
                            request_id: 0,
                            path: normalized_path,
                            entries: Vec::new(),
                            total_entries: 0,
                            offset,
                            next_offset: None,
                            truncated: false,
                            filesystem: "LOCAL".to_string(),
                            is_locked: false,
                            locked_message: None,
                            is_unsupported: true,
                            unsupported_message: Some(format!(
                                "Local directory read failure: {err}"
                            )),
                            diagnostics: vec![err.to_string()],
                        });
                    }
                };

                let total_entries = listing.total_entries;
                let mut entries = Vec::with_capacity(listing.entries.len());
                for e in listing.entries {
                    let item_path = join_browse_path(&normalized_path, &e.name);
                    entries.push(BrowseEntry {
                        name: e.name,
                        logical_path: item_path,
                        is_dir: e.is_dir,
                        size_bytes: e.size_bytes,
                        is_deleted: false,
                        created_utc: e.created_utc,
                        modified_utc: e.modified_utc,
                        accessed_utc: e.accessed_utc,
                        provenance: Some("Local Filesystem".to_string()),
                        reconstruction_status: None,
                        file_record_number: None,
                        physical_offset: None,
                        canonical_entry_id: None,
                    });
                }

                resolve_canonical_entry_ids(
                    case_path,
                    evidence.case_id,
                    evidence_id,
                    &mut entries,
                )?;

                let next_offset = if listing.truncated {
                    Some(offset.saturating_add(entries.len()))
                } else {
                    None
                };

                Ok(BrowseDirectoryPage {
                    evidence_id,
                    volume_index: 0,
                    volume_identity: Some(volume_identity),
                    access_state: VolumeAccessState::Accessible,
                    reader_label: "Local Filesystem Reader".to_string(),
                    request_id: 0,
                    path: normalized_path,
                    entries,
                    total_entries,
                    offset,
                    next_offset,
                    truncated: listing.truncated,
                    filesystem: "LOCAL".to_string(),
                    is_locked: false,
                    locked_message: None,
                    is_unsupported: false,
                    unsupported_message: None,
                    diagnostics: Vec::new(),
                })
            }
            other => bail!("live browsing is not supported for {other} evidence"),
        }
    }

    pub fn find_canonical_entry_id(
        case_path: &Path,
        evidence_id: i64,
        logical_path: &str,
    ) -> Result<Option<i64>> {
        let conn = open_ro_conn(case_path)?;
        let case_id: i64 =
            conn.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
                row.get(0)
            })?;
        let mut stmt = conn.prepare_cached(
            "SELECT id FROM filesystem_entries
             WHERE case_id = ?1 AND evidence_id = ?2 AND (logical_path = ?3 OR logical_path = ?4)
             LIMIT 1",
        )?;
        let trimmed = logical_path.trim_end_matches('/');
        let alternate = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{trimmed}")
        };
        let mut rows = stmt.query(params![case_id, evidence_id, logical_path, alternate])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn build_live_artifact_detail(
        case_path: &Path,
        evidence_id: i64,
        volume_index: usize,
        entry: &BrowseEntry,
        generation: i64,
    ) -> Result<ArtifactDetail> {
        let evidence = read_evidence_record(case_path, evidence_id)?;

        let mut timestamps = Vec::new();
        if let Some(created) = entry.created_utc.as_deref() {
            timestamps.push(ArtifactTimestamp {
                semantic_field: "created_utc".to_string(),
                label: "Created (UTC)".to_string(),
                raw_value: created.to_string(),
                value_truncated: false,
                basis: Some("live_filesystem_record".to_string()),
                basis_truncated: false,
                timezone: Some("UTC".to_string()),
                source: "live_browse_provider".to_string(),
            });
        }
        if let Some(modified) = entry.modified_utc.as_deref() {
            timestamps.push(ArtifactTimestamp {
                semantic_field: "modified_utc".to_string(),
                label: "Modified (UTC)".to_string(),
                raw_value: modified.to_string(),
                value_truncated: false,
                basis: Some("live_filesystem_record".to_string()),
                basis_truncated: false,
                timezone: Some("UTC".to_string()),
                source: "live_browse_provider".to_string(),
            });
        }
        if let Some(accessed) = entry.accessed_utc.as_deref() {
            timestamps.push(ArtifactTimestamp {
                semantic_field: "accessed_utc".to_string(),
                label: "Accessed (UTC)".to_string(),
                raw_value: accessed.to_string(),
                value_truncated: false,
                basis: Some("live_filesystem_record".to_string()),
                basis_truncated: false,
                timezone: Some("UTC".to_string()),
                source: "live_browse_provider".to_string(),
            });
        }

        let timestamps_status = if timestamps.is_empty() {
            ArtifactSectionAvailability {
                state: ArtifactValueAvailability::NotRecorded,
                reason: Some("No timestamp recorded in live entry.".to_string()),
                omitted_count: 0,
            }
        } else {
            ArtifactSectionAvailability {
                state: ArtifactValueAvailability::Recorded,
                reason: None,
                omitted_count: 0,
            }
        };

        let mut coordinates = Vec::new();
        if let Some(offset) = entry.physical_offset {
            coordinates.push(ArtifactCoordinate {
                name: "source_offset".to_string(),
                label: "Source physical offset".to_string(),
                namespace: "decoded_evidence_media".to_string(),
                availability: ArtifactValueAvailability::Recorded,
                value: Some(offset.to_string()),
                value_truncated: false,
                exact: true,
                unit: Some("bytes".to_string()),
                basis: Some("decoded_evidence_media_bytes".to_string()),
                basis_truncated: false,
                scope: Some("decoded_evidence_media".to_string()),
                scope_truncated: false,
                warning: Some(
                    "Live source offset: not verified against parsed case index.".to_string(),
                ),
            });
        }
        let coordinates_status = if coordinates.is_empty() {
            ArtifactSectionAvailability {
                state: ArtifactValueAvailability::NotRecorded,
                reason: Some("No media coordinate is recorded for this live entry; zero was not substituted.".to_string()),
                omitted_count: 0,
            }
        } else {
            ArtifactSectionAvailability {
                state: ArtifactValueAvailability::Recorded,
                reason: Some(
                    "Live source coordinate read from volume boot/MFT structure.".to_string(),
                ),
                omitted_count: 0,
            }
        };

        let hashes_status = ArtifactSectionAvailability {
            state: ArtifactValueAvailability::NotRecorded,
            reason: Some("Hashes are uncomputed for unindexed live source files; zero or synthetic digests were not substituted.".to_string()),
            omitted_count: 0,
        };

        let mut provenance = vec![
            ArtifactProvenanceField {
                name: "browse_provider".to_string(),
                label: "Provider".to_string(),
                value: "Native Live Volume Browse".to_string(),
                value_truncated: false,
                source: "kdft_desktop_core::browse".to_string(),
            },
            ArtifactProvenanceField {
                name: "volume_index".to_string(),
                label: "Volume index".to_string(),
                value: volume_index.to_string(),
                value_truncated: false,
                source: "live_evidence".to_string(),
            },
            ArtifactProvenanceField {
                name: "indexing_state".to_string(),
                label: "Indexing state".to_string(),
                value: "Live source (not indexed in case database)".to_string(),
                value_truncated: false,
                source: "case_database".to_string(),
            },
        ];
        if let Some(frn) = entry.file_record_number {
            provenance.push(ArtifactProvenanceField {
                name: "file_record_number".to_string(),
                label: "File record number (MFT)".to_string(),
                value: frn.to_string(),
                value_truncated: false,
                source: "ntfs_forensic".to_string(),
            });
        }
        if let Some(prov) = entry.provenance.as_deref() {
            provenance.push(ArtifactProvenanceField {
                name: "reconstruction_provenance".to_string(),
                label: "Provenance claim".to_string(),
                value: prov.to_string(),
                value_truncated: false,
                source: "ntfs_forensic".to_string(),
            });
        }

        let completeness = ArtifactDetailCompleteness {
            state: CoverageState::Partial,
            is_complete: false,
            detail: "Live source view — this file is projected directly from the evidence source and has not been indexed into the case database.".to_string(),
            diagnostics: vec![
                "Live source projection; run Process Evidence to index canonical entries and cryptographic hashes.".to_string(),
            ],
            diagnostics_omitted: 0,
        };

        Ok(ArtifactDetail {
            generation,
            case_id: evidence.case_id,
            entry_id: 0, // 0 indicates live source / unindexed
            evidence_id,
            parent_id: None,
            source_job_id: None,
            source_job_type: None,
            source_job_type_truncated: false,
            source_job_status: None,
            source_job_status_truncated: false,
            parser_schema_version: None,
            parser_schema_version_truncated: false,
            logical_path: entry.logical_path.clone(),
            logical_path_truncated: false,
            source_path: evidence.source_path.clone(),
            source_path_truncated: false,
            display_name: entry.name.clone(),
            display_name_truncated: false,
            evidence_display_name: evidence.display_name,
            evidence_display_name_truncated: false,
            source_kind: evidence.source_kind,
            source_kind_truncated: false,
            entry_kind: if entry.is_dir { "directory".to_string() } else { "file".to_string() },
            entry_kind_truncated: false,
            artifact_kind: Some("live_source_file".to_string()),
            artifact_kind_truncated: false,
            size_bytes: entry.size_bytes,
            is_deleted: entry.is_deleted,
            metadata_state: ArtifactMetadataState::Absent,
            fields: Vec::new(),
            fields_omitted: 0,
            timestamps,
            timestamps_omitted: 0,
            timestamps_status,
            hashes: Vec::new(),
            hashes_status,
            coordinates,
            coordinates_status,
            provenance,
            provenance_omitted: 0,
            completeness,
            warnings: vec![
                "Live source projection: not indexed in the case database. Hashes, deep parser coordinates, and canonical SQLite entry ID are not recorded.".to_string(),
            ],
            warnings_omitted: 0,
        })
    }
}

fn open_ro_conn(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

pub fn read_evidence_record(case_path: &Path, evidence_id: i64) -> Result<EvidenceRecord> {
    let conn = open_ro_conn(case_path)?;
    let case_id: i64 = conn.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
        row.get(0)
    })?;
    let mut stmt = conn.prepare(
        "SELECT id, case_id, source_kind, source_path, display_name, size_bytes
         FROM evidence_sources
         WHERE case_id = ?1 AND id = ?2",
    )?;
    let evidence = stmt
        .query_row(params![case_id, evidence_id], |row| {
            Ok(EvidenceRecord {
                id: row.get(0)?,
                case_id: row.get(1)?,
                source_kind: row.get(2)?,
                source_path: row.get(3)?,
                display_name: row.get(4)?,
                size_bytes: row.get(5)?,
            })
        })
        .with_context(|| format!("evidence {evidence_id} not found in case database"))?;
    Ok(evidence)
}

fn resolve_canonical_entry_ids(
    case_path: &Path,
    case_id: i64,
    evidence_id: i64,
    entries: &mut [BrowseEntry],
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let conn = open_ro_conn(case_path)?;
    let mut stmt = conn.prepare_cached(
        "SELECT id, logical_path FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2 AND logical_path = ?3
         LIMIT 1",
    )?;
    for entry in entries.iter_mut() {
        let mut rows = stmt.query(params![case_id, evidence_id, entry.logical_path])?;
        if let Some(row) = rows.next()? {
            entry.canonical_entry_id = Some(row.get(0)?);
        }
    }
    Ok(())
}

fn normalize_browse_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" || trimmed == "\\" {
        return "/".to_string();
    }
    let mut cleaned = trimmed.replace('\\', "/");
    if !cleaned.starts_with('/') {
        cleaned.insert(0, '/');
    }
    while cleaned.len() > 1 && cleaned.ends_with('/') {
        cleaned.pop();
    }
    cleaned
}

fn join_browse_path(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

pub fn recursive_collect_files(
    case_path: &Path,
    evidence_id: i64,
    volume_index: usize,
    root_path: &str,
    unlock_mgr: Option<&crate::unlock::TransientUnlockManager>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
    max_files: usize,
) -> Result<Vec<BrowseEntry>> {
    use std::collections::{HashSet, VecDeque};
    use std::sync::atomic::Ordering;

    let mut collected = Vec::new();
    let mut dir_queue = VecDeque::new();
    let mut visited_dirs = HashSet::new();

    let norm_root = normalize_browse_path(root_path);
    dir_queue.push_back(norm_root.clone());
    visited_dirs.insert(norm_root);

    while let Some(current_dir) = dir_queue.pop_front() {
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) {
                break;
            }
        }

        let mut offset = 0;
        loop {
            if let Some(c) = cancel {
                if c.load(Ordering::Relaxed) {
                    break;
                }
            }

            let page = match NativeBrowseService::read_directory_page(
                case_path,
                evidence_id,
                volume_index,
                &current_dir,
                offset,
                100,
                unlock_mgr,
            ) {
                Ok(p) => p,
                Err(_) => break, // Skip inaccessible directory gracefully
            };

            for entry in page.entries {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                if entry.is_dir {
                    let child_dir = normalize_browse_path(&entry.logical_path);
                    if !visited_dirs.contains(&child_dir) {
                        visited_dirs.insert(child_dir.clone());
                        dir_queue.push_back(child_dir);
                    }
                } else {
                    collected.push(entry);
                    if collected.len() >= max_files {
                        return Ok(collected);
                    }
                }
            }

            match page.next_offset {
                Some(next) if next > offset => offset = next,
                _ => break,
            }
        }
    }

    Ok(collected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn setup_fixture_case() -> (PathBuf, PathBuf) {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kdft-browse-fixture-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create fixture dir");

        fs::write(dir.join("alpha.txt"), b"alpha content").expect("write alpha");
        fs::write(dir.join("beta.txt"), b"beta content").expect("write beta");
        fs::write(dir.join("gamma.txt"), b"gamma content").expect("write gamma");

        let case_path = std::env::temp_dir().join(format!(
            "kdft-browse-case-{}-{serial}.sqlite",
            std::process::id()
        ));
        let request = crate::workflow::CreateCaseRequest {
            case_path: case_path.clone(),
            name: "Browse Case".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("C-1".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        };
        crate::workflow::NativeWorkflowService::create_case(request).expect("create case");

        let conn = Connection::open(&case_path).expect("open fixture db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name, size_bytes)
             VALUES(1, 1, 'folder', ?1, 'Synthetic Folder', 300)",
            params![dir.display().to_string()],
        ).expect("insert evidence");

        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
             VALUES(42, 1, 1, '/alpha.txt', 'alpha.txt', 'file', 13, 0)",
            [],
        ).expect("insert indexed row");

        (case_path, dir)
    }

    #[test]
    fn path_normalization_handles_various_slashes() {
        assert_eq!(normalize_browse_path(""), "/");
        assert_eq!(normalize_browse_path("/"), "/");
        assert_eq!(normalize_browse_path("\\"), "/");
        assert_eq!(normalize_browse_path("/foo/bar/"), "/foo/bar");
        assert_eq!(normalize_browse_path("foo/bar"), "/foo/bar");
        assert_eq!(
            normalize_browse_path("\\Windows\\System32\\"),
            "/Windows/System32"
        );
    }

    #[test]
    fn path_joining_handles_root_and_subdirectories() {
        assert_eq!(join_browse_path("/", "file.txt"), "/file.txt");
        assert_eq!(join_browse_path("/foo", "bar"), "/foo/bar");
        assert_eq!(join_browse_path("/foo/bar/", "baz.dat"), "/foo/bar/baz.dat");
    }

    #[test]
    fn bounded_folder_directory_page_and_canonical_id_matching() {
        let (case_path, dir) = setup_fixture_case();

        let volumes = NativeBrowseService::list_volumes(&case_path, 1).expect("list volumes");
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].filesystem, "LOCAL");
        assert!(volumes[0].browsable);

        let page1 = NativeBrowseService::read_directory_page(&case_path, 1, 0, "/", 0, 2, None)
            .expect("read page 1");
        assert_eq!(page1.entries.len(), 2);
        assert_eq!(page1.total_entries, 3);
        assert!(page1.truncated);
        assert_eq!(page1.next_offset, Some(2));

        // Find alpha.txt in page1
        let alpha = page1
            .entries
            .iter()
            .find(|e| e.name == "alpha.txt")
            .expect("alpha found");
        assert_eq!(alpha.canonical_entry_id, Some(42)); // Matches indexed entry

        let page2 = NativeBrowseService::read_directory_page(&case_path, 1, 0, "/", 2, 2, None)
            .expect("read page 2");
        assert_eq!(page2.entries.len(), 1);
        assert_eq!(page2.next_offset, None);

        let _ = fs::remove_file(case_path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn live_artifact_detail_projection_preserves_forensic_truth() {
        let (case_path, dir) = setup_fixture_case();
        let entry = BrowseEntry {
            name: "beta.txt".to_string(),
            logical_path: "/beta.txt".to_string(),
            is_dir: false,
            size_bytes: Some(12),
            is_deleted: false,
            created_utc: Some("2026-10-17T12:00:00Z".to_string()),
            modified_utc: Some("2026-10-17T12:05:00Z".to_string()),
            accessed_utc: None,
            provenance: Some("Local Test".to_string()),
            reconstruction_status: None,
            file_record_number: None,
            physical_offset: Some(1024),
            canonical_entry_id: None,
        };

        let detail = NativeBrowseService::build_live_artifact_detail(&case_path, 1, 0, &entry, 9)
            .expect("build live detail");
        assert_eq!(detail.entry_id, 0); // Unindexed sentinel
        assert_eq!(detail.display_name, "beta.txt");
        assert_eq!(detail.logical_path, "/beta.txt");
        assert_eq!(detail.artifact_kind.as_deref(), Some("live_source_file"));
        assert_eq!(detail.timestamps.len(), 2);
        assert!(detail.hashes.is_empty());
        assert_eq!(
            detail.hashes_status.state,
            ArtifactValueAvailability::NotRecorded
        );
        assert!(detail.warnings[0].contains("Live source projection: not indexed"));

        let _ = fs::remove_file(case_path);
        let _ = fs::remove_dir_all(dir);
    }
}
