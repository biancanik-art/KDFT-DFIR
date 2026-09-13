//! Transient, forensic-grade live NTFS browser.
//!
//! This module builds an in-memory catalog of an NTFS volume directly from the
//! $MFT stream.  It exposes allocated records, deleted records whose original
//! path can be reconstructed, and unresolved/orphan records under a synthetic
//! recovery folder.  Nothing is written to the case database.
//!
//! The catalog is cached in process memory per (image, volume) and reused for
//! subsequent directory listings and byte reads so a 126 GB E01 is scanned only
//! once per unchanged volume.

use crate::progress::JobProgressTracker;
use crate::{
    copy_ntfs_mft_stream_to_temp, list_image_volumes, normalized_mft_ntfs_path,
    ntfs_default_data_location, open_disk_image, read_ntfs_file_record_bytes,
    reconstruct_validated_deleted_mft_path, sanitize_logical_segment, LiveTreeFileRef,
    LiveTreeListResult, LiveVolume,
};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const ORPHAN_FOLDER_NAME: &str = "$OrphanFiles";
const ORPHAN_SENTINEL_RECORD: u64 = u64::MAX;
const CACHE_MAX_VOLUMES: usize = 8;
const CACHE_MAX_AGE: Duration = Duration::from_secs(1800);
const CANCELLATION_CHECK_INTERVAL: usize = 1024;

/// Identifies a cached forensic catalog in process memory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NtfsForensicCacheKey {
    pub image_path: PathBuf,
    pub volume_start_offset: u64,
    pub volume_size_bytes: u64,
    pub source_modified_utc: Option<String>,
    pub source_size_bytes: u64,
}

/// Provenance of a forensic live-browse entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NtfsForensicProvenance {
    /// Allocated record whose path was reconstructed from MFT parent references.
    AllocatedMft,
    /// Deleted record whose original path was validated and reconstructed.
    DeletedReconstructed,
    /// Deleted (or unresolvable) record placed under the synthetic orphan folder.
    DeletedOrphan,
    /// Allocated record whose parent chain cannot be validated. It remains
    /// allocated evidence, but is surfaced under the recovery folder because
    /// no trustworthy original path can be claimed.
    AllocatedOrphan,
    /// Synthetic recovery folder created by KDFT.
    SyntheticRecovery,
}

impl NtfsForensicProvenance {
    fn as_str(self) -> &'static str {
        match self {
            Self::AllocatedMft => "allocated_mft",
            Self::DeletedReconstructed => "deleted_reconstructed",
            Self::DeletedOrphan => "deleted_orphan",
            Self::AllocatedOrphan => "allocated_orphan",
            Self::SyntheticRecovery => "synthetic_recovery",
        }
    }
}

/// Lightweight metadata extracted from one MFT record and kept in memory.
#[derive(Debug, Clone)]
pub struct NtfsForensicRecord {
    pub record_number: u64,
    pub sequence_number: u16,
    pub parent_record_number: u64,
    pub parent_sequence_number: u16,
    pub name: String,
    pub is_directory: bool,
    pub allocated: bool,
    pub size_bytes: u64,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub mft_record_modification_time_utc: Option<String>,
    pub namespace: String,
    /// Authoritative location of this FILE record in the NTFS volume. It is
    /// resolved lazily through the native NTFS parser; record_number * record
    /// size is not a valid physical claim when $MFT is fragmented.
    pub mft_record_logical_offset: Option<u64>,
    pub provenance: NtfsForensicProvenance,
    pub reconstruction_status: String,
    pub recovery_status: String,
    pub diagnostics: Vec<String>,
}

/// Transient in-memory catalog for one NTFS volume.
#[derive(Debug)]
pub struct NtfsForensicCacheEntry {
    pub key: NtfsForensicCacheKey,
    pub record_count: u64,
    pub records: HashMap<u64, NtfsForensicRecord>,
    pub children: HashMap<u64, Vec<u64>>,
    pub path_to_record: HashMap<String, u64>,
    pub orphan_records: Vec<u64>,
    pub diagnostics: Vec<String>,
    pub built_at: Instant,
}

/// One entry returned by the forensic live directory endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct NtfsForensicEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub provenance: String,
    pub reconstruction_status: String,
    pub recovery_status: String,
    pub ntfs_file_record_number: u64,
    pub ntfs_sequence_number: u16,
    pub ntfs_parent_record_number: u64,
    pub mft_record_logical_offset: Option<u64>,
    pub mft_record_physical_offset: Option<u64>,
    pub file_data_logical_offset: Option<u64>,
    pub file_data_physical_offset: Option<u64>,
    pub file_data_file_offset: Option<u64>,
    pub file_data_contiguous_bytes: Option<u64>,
    pub physical_offset_basis: Option<String>,
    pub file_data_direct_logical_mapping: Option<bool>,
    pub offset_coordinate_system: Option<String>,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub mft_record_modification_time_utc: Option<String>,
    pub diagnostics: Vec<String>,
}

/// Directory listing result.
#[derive(Debug, Clone, Serialize)]
pub struct NtfsForensicDirectory {
    pub path: String,
    pub entries: Vec<NtfsForensicEntry>,
    pub total_children: usize,
    pub truncated: bool,
    pub orphan_count: usize,
    pub diagnostic_count: usize,
    pub diagnostics: Vec<String>,
}

/// Cache status returned to callers.
#[derive(Debug, Clone, Serialize)]
pub struct ForensicCacheStatus {
    pub cached: bool,
    pub record_count: Option<u64>,
    pub allocated_count: Option<u64>,
    pub deleted_reconstructed_count: Option<u64>,
    pub orphan_count: Option<u64>,
    pub diagnostic_count: Option<u64>,
    pub built_at_ms_ago: Option<u64>,
}

/// Options for a forensic directory listing.
#[derive(Debug, Clone, Default)]
pub struct NtfsForensicBrowseOptions {
    /// Maximum entries to return. 0 means unlimited.
    pub limit: usize,
    /// Zero-based offset into the stable directory sort order.
    pub offset: usize,
}

struct CacheSlot {
    entry: Arc<NtfsForensicCacheEntry>,
    last_used: Instant,
}

#[derive(Default)]
struct ForensicCacheState {
    map: HashMap<NtfsForensicCacheKey, CacheSlot>,
    building: HashSet<NtfsForensicCacheKey>,
}

fn forensic_cache() -> &'static (Mutex<ForensicCacheState>, Condvar) {
    static CACHE: OnceLock<(Mutex<ForensicCacheState>, Condvar)> = OnceLock::new();
    CACHE.get_or_init(|| (Mutex::new(ForensicCacheState::default()), Condvar::new()))
}

/// Build or retrieve the forensic catalog for a volume.
///
/// If a fresh catalog already exists in memory it is returned immediately.
/// Otherwise the $MFT stream is copied, parsed once, and indexed.
pub fn build_ntfs_forensic_volume_cache(
    image_path: &Path,
    volume_index: usize,
    tracker: Option<&JobProgressTracker>,
) -> Result<Arc<NtfsForensicCacheEntry>> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    if volume.filesystem != "NTFS" {
        bail!("forensic catalog is only supported for NTFS volumes");
    }

    let key = cache_key_for_volume(image_path, volume)?;

    // Fast path and per-volume build serialization. A second tab waits for the
    // first build instead of copying/parsing the same $MFT again.
    let (cache_mutex, cache_ready) = forensic_cache();
    loop {
        let mut state = cache_mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        evict_stale_and_overflow(&mut state);
        if let Some(slot) = state.map.get_mut(&key) {
            if slot.entry.key == key {
                slot.last_used = Instant::now();
                let entry = Arc::clone(&slot.entry);
                return Ok(entry);
            }
        }
        if state.building.insert(key.clone()) {
            break;
        }
        let _state = cache_ready
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }

    if let Some(tracker) = tracker {
        tracker.start_stage(
            "Reconstructing NTFS file records",
            1,
            Some(1),
            "MFT records",
            None,
        );
    }

    let build_result = (|| {
        let mut opened = open_disk_image(image_path)?;
        use crate::PartitionSlice;
        let mut slice =
            PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
        build_forensic_cache_from_reader(
            &mut slice,
            volume.start_offset,
            volume.size_bytes,
            &key,
            tracker,
        )
        .map(Arc::new)
    })();

    let mut state = cache_mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.building.remove(&key);
    if let Ok(cache) = &build_result {
        evict_stale_and_overflow(&mut state);
        state.map.insert(
            key.clone(),
            CacheSlot {
                entry: Arc::clone(cache),
                last_used: Instant::now(),
            },
        );
        evict_stale_and_overflow(&mut state);
    }
    cache_ready.notify_all();
    drop(state);
    build_result
}

/// List the children of a directory from the transient forensic catalog.
pub fn list_ntfs_forensic_directory(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
    options: &NtfsForensicBrowseOptions,
    tracker: Option<&JobProgressTracker>,
) -> Result<NtfsForensicDirectory> {
    let cache = build_ntfs_forensic_volume_cache(image_path, volume_index, tracker)?;
    let volume = list_image_volumes(image_path)?
        .into_iter()
        .nth(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;

    let normalized = normalize_dir_path(dir_path);
    let mut opened = open_disk_image(image_path)?;
    let mut slice =
        crate::PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume for forensic listing")?;

    let dir_record = resolve_path_to_record(&cache, &normalized)
        .with_context(|| format!("directory not found in forensic catalog: {dir_path}",))?;

    let record = cache
        .records
        .get(&dir_record)
        .with_context(|| format!("directory record {dir_record} missing from catalog"))?;
    if !record.is_directory && dir_record != ORPHAN_SENTINEL_RECORD {
        bail!("path is a file, not a directory: {dir_path}");
    }

    let mut children_ids = cache.children.get(&dir_record).cloned().unwrap_or_default();
    sort_forensic_record_ids(&cache, &mut children_ids);
    let total_children = children_ids.len();

    let start = options.offset.min(total_children);
    let end = if options.limit == 0 {
        total_children
    } else {
        start.saturating_add(options.limit).min(total_children)
    };
    let mut entries = Vec::with_capacity(end.saturating_sub(start));
    for &child_record in &children_ids[start..end] {
        let entry = entry_for_record(
            &cache,
            &volume,
            child_record,
            &ntfs,
            &mut slice,
            volume.start_offset,
        )?;
        entries.push(entry);
    }

    let truncated = end < total_children;

    Ok(NtfsForensicDirectory {
        path: if normalized.is_empty() {
            "/".to_string()
        } else {
            format!("/{normalized}")
        },
        entries,
        total_children,
        truncated,
        orphan_count: cache.orphan_records.len(),
        diagnostic_count: cache.diagnostics.len(),
        diagnostics: cache.diagnostics.iter().take(16).cloned().collect(),
    })
}

/// Recursively list files from the transient NTFS forensic catalog. This is
/// the live-browse equivalent of `list_image_tree_files`, but it also follows
/// sequence-validated deleted paths and the synthetic `$OrphanFiles` view.
/// Nothing is written to the case database while the catalog is built.
pub fn list_ntfs_forensic_tree_files(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
    max_files: usize,
) -> Result<LiveTreeListResult> {
    const MAX_PATH_DEPTH: usize = 256;
    const MAX_SKIP_NOTES: usize = 128;

    let cache = build_ntfs_forensic_volume_cache(image_path, volume_index, None)?;
    let volume = list_image_volumes(image_path)?
        .into_iter()
        .nth(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let normalized = normalize_dir_path(dir_path);
    let root_record = resolve_path_to_record(&cache, &normalized)
        .with_context(|| format!("directory not found in forensic catalog: {dir_path}"))?;
    let root = cache
        .records
        .get(&root_record)
        .with_context(|| format!("directory record {root_record} missing from catalog"))?;
    if !root.is_directory && root_record != ORPHAN_SENTINEL_RECORD {
        bail!("path is a file, not a directory: {dir_path}");
    }

    let mut opened = open_disk_image(image_path)?;
    let mut slice =
        crate::PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume for forensic tree")?;

    let file_limit = (max_files != 0).then_some(max_files);
    let mut files = Vec::new();
    let mut directories_visited = 0_u64;
    let mut skipped = Vec::new();
    let mut skipped_count = 0_u64;
    let mut truncated = false;
    let mut file_limit_reached = false;
    let mut seen = HashSet::new();
    let mut stack = vec![(root_record, Vec::<String>::new())];

    'walk: while let Some((directory_record, relative_parts)) = stack.pop() {
        if !seen.insert(directory_record) {
            skipped_count = skipped_count.saturating_add(1);
            truncated = true;
            if skipped.len() < MAX_SKIP_NOTES {
                skipped.push(format!(
                    "NTFS directory record {directory_record} was already visited and was skipped to prevent a cycle"
                ));
            }
            continue;
        }
        directories_visited = directories_visited.saturating_add(1);
        let mut child_ids = cache
            .children
            .get(&directory_record)
            .cloned()
            .unwrap_or_default();
        sort_forensic_record_ids(&cache, &mut child_ids);

        // Push in reverse so the depth-first walk remains stable in the same
        // case-insensitive sort order displayed by the directory table.
        let mut child_directories = Vec::new();
        for child_record in child_ids {
            let Some(record) = cache.records.get(&child_record) else {
                skipped_count = skipped_count.saturating_add(1);
                truncated = true;
                if skipped.len() < MAX_SKIP_NOTES {
                    skipped.push(format!("record {child_record} is missing from the catalog"));
                }
                continue;
            };
            let mut child_parts = relative_parts.clone();
            child_parts.push(record.name.clone());
            if record.is_directory {
                if child_parts.len() > MAX_PATH_DEPTH {
                    skipped_count = skipped_count.saturating_add(1);
                    truncated = true;
                    if skipped.len() < MAX_SKIP_NOTES {
                        skipped.push(format!(
                            "{}: directory depth exceeds the {MAX_PATH_DEPTH}-component corruption/cycle guard",
                            child_parts.join("/")
                        ));
                    }
                } else {
                    child_directories.push((child_record, child_parts));
                }
                continue;
            }

            if file_limit.is_some_and(|limit| files.len() >= limit) {
                file_limit_reached = true;
                truncated = true;
                break 'walk;
            }

            match entry_for_record(
                &cache,
                &volume,
                child_record,
                &ntfs,
                &mut slice,
                volume.start_offset,
            ) {
                Ok(entry) => files.push(LiveTreeFileRef {
                    relative_path: child_parts.join("/"),
                    name: entry.name,
                    size_bytes: entry.size_bytes.unwrap_or(0).max(0) as u64,
                    created_utc: entry.created_utc,
                    modified_utc: entry.modified_utc,
                    accessed_utc: entry.accessed_utc,
                    is_deleted: entry.is_deleted,
                    provenance: Some(entry.provenance),
                    reconstruction_status: Some(entry.reconstruction_status),
                    recovery_status: Some(entry.recovery_status),
                    ntfs_file_record_number: Some(entry.ntfs_file_record_number),
                    ntfs_sequence_number: Some(entry.ntfs_sequence_number),
                    ntfs_parent_record_number: Some(entry.ntfs_parent_record_number),
                    mft_record_logical_offset: entry.mft_record_logical_offset,
                    mft_record_physical_offset: entry.mft_record_physical_offset,
                    file_data_logical_offset: entry.file_data_logical_offset,
                    file_data_physical_offset: entry.file_data_physical_offset,
                    file_data_file_offset: entry.file_data_file_offset,
                    file_data_contiguous_bytes: entry.file_data_contiguous_bytes,
                    physical_offset_basis: entry.physical_offset_basis,
                    file_data_direct_logical_mapping: entry.file_data_direct_logical_mapping,
                    offset_coordinate_system: entry.offset_coordinate_system,
                }),
                Err(error) => {
                    skipped_count = skipped_count.saturating_add(1);
                    truncated = true;
                    if skipped.len() < MAX_SKIP_NOTES {
                        skipped.push(format!("{}: {error:#}", child_parts.join("/")));
                    }
                }
            }
        }

        for child in child_directories.into_iter().rev() {
            stack.push(child);
        }
    }

    if skipped_count > skipped.len() as u64 {
        skipped.push(format!(
            "... and {} more skipped items",
            skipped_count - skipped.len() as u64
        ));
    }

    Ok(LiveTreeListResult {
        files,
        directories_visited,
        skipped,
        skipped_count,
        file_limit,
        file_limit_reached,
        truncated,
    })
}

/// Read bytes from a file identified by its forensic path.
pub fn read_ntfs_forensic_file_bytes(
    image_path: &Path,
    volume_index: usize,
    file_path: &str,
    offset: u64,
    length: usize,
    tracker: Option<&JobProgressTracker>,
) -> Result<(Vec<u8>, u64)> {
    const MAX_LEN: usize = 8 * 1024 * 1024;
    let length = length.min(MAX_LEN);

    let cache = build_ntfs_forensic_volume_cache(image_path, volume_index, tracker)?;
    let volume = list_image_volumes(image_path)?
        .into_iter()
        .nth(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;

    let normalized = normalize_file_path(file_path);
    let file_record = resolve_path_to_record(&cache, &normalized)
        .with_context(|| format!("file not found in forensic catalog: {file_path}"))?;

    let record = cache
        .records
        .get(&file_record)
        .with_context(|| format!("file record {file_record} missing from catalog"))?;
    if record.is_directory {
        bail!("path is a directory, not a file: {file_path}");
    }

    let mut opened = open_disk_image(image_path)?;
    let mut slice =
        crate::PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume for byte read")?;
    let native_file = ntfs
        .file(&mut slice, file_record)
        .with_context(|| format!("opening NTFS record {file_record}"))?;
    let total_size =
        crate::ntfs_default_data_size(&native_file, &mut slice).unwrap_or(record.size_bytes);
    drop(native_file);
    let bytes = read_ntfs_file_record_bytes(
        &ntfs,
        &mut slice,
        file_record,
        offset.saturating_add(length as u64) as usize,
    )
    .with_context(|| format!("reading NTFS record {file_record}"))?;
    let start = (offset as usize).min(bytes.len());
    let end = start.saturating_add(length).min(bytes.len());
    Ok((bytes[start..end].to_vec(), total_size))
}

/// Export one allocated or deleted NTFS file from the transient catalog. The
/// destination is published atomically and the evidence source remains
/// read-only; no case-index rows are created.
pub fn export_ntfs_forensic_file(
    image_path: &Path,
    volume_index: usize,
    file_path: &str,
    output_path: &Path,
) -> Result<crate::LiveExportResult> {
    let cache = build_ntfs_forensic_volume_cache(image_path, volume_index, None)?;
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let normalized = normalize_file_path(file_path);
    let record_number = resolve_path_to_record(&cache, &normalized)
        .with_context(|| format!("file not found in forensic catalog: {file_path}"))?;
    let record = cache
        .records
        .get(&record_number)
        .with_context(|| format!("file record {record_number} missing from catalog"))?;
    if record.is_directory {
        bail!("path is a directory, not a file: {file_path}");
    }
    let mut opened = open_disk_image(image_path)?;
    let mut slice =
        crate::PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume for forensic export")?;
    let native_file = ntfs
        .file(&mut slice, record_number)
        .with_context(|| format!("opening NTFS record {record_number}"))?;
    let total_size =
        crate::ntfs_default_data_size(&native_file, &mut slice).unwrap_or(record.size_bytes);
    drop(native_file);
    if total_size > crate::LIVE_EXPORT_MAX_BYTES {
        bail!(
            "file is {total_size} bytes; live export is capped at {} bytes - process the evidence to export it",
            crate::LIVE_EXPORT_MAX_BYTES
        );
    }
    let max_bytes = usize::try_from(total_size)
        .context("NTFS file size exceeds this platform's address space")?;
    let bytes = read_ntfs_file_record_bytes(&ntfs, &mut slice, record_number, max_bytes)
        .with_context(|| format!("reading NTFS record {record_number} for export"))?;
    if bytes.len() as u64 != total_size {
        bail!(
            "NTFS record {record_number} reported {} bytes but yielded {}; no output was published",
            total_size,
            bytes.len()
        );
    }
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating export folder {}", parent.display()))?;
    }
    crate::write_new_file_atomically(output_path, &bytes)
        .with_context(|| format!("writing exported file {}", output_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(crate::LiveExportResult {
        output_path: output_path.display().to_string(),
        bytes_written: bytes.len() as u64,
        total_size,
        sha256_hex: format!("{:x}", hasher.finalize()),
    })
}

/// Recursively export a reconstructed directory (including deleted/orphan
/// records) while preserving the transient catalog's hierarchy and writing
/// the same SHA-256 manifest as ordinary live export.
pub fn export_ntfs_forensic_tree(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
    output_root: &Path,
    max_files: Option<usize>,
) -> Result<crate::LiveTreeExportResult> {
    let cache = build_ntfs_forensic_volume_cache(image_path, volume_index, None)?;
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let normalized = normalize_dir_path(dir_path);
    let root_record = resolve_path_to_record(&cache, &normalized)
        .with_context(|| format!("directory not found in forensic catalog: {dir_path}"))?;
    let root = cache
        .records
        .get(&root_record)
        .with_context(|| format!("directory record {root_record} missing from catalog"))?;
    if !root.is_directory {
        bail!("path is a file, not a directory: {dir_path}");
    }

    let mut sink = crate::TreeExportSink::new(output_root, max_files);
    sink.prepare_output_root()?;
    let mut opened = open_disk_image(image_path)?;
    let mut slice =
        crate::PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
    let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume for forensic export")?;
    let mut stack = vec![(root_record, Vec::<String>::new())];
    let mut seen_directories = HashSet::new();

    while let Some((directory_record, relative_parts)) = stack.pop() {
        if !sink.file_budget_left() {
            sink.mark_file_limit_reached();
            break;
        }
        if !seen_directories.insert(directory_record) {
            sink.skip(format!(
                "NTFS directory record {directory_record} was already visited and was skipped to prevent a cycle"
            ));
            continue;
        }
        sink.dirs = sink.dirs.saturating_add(1);
        for &child_record in cache
            .children
            .get(&directory_record)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if !sink.file_budget_left() {
                sink.mark_file_limit_reached();
                break;
            }
            let Some(child) = cache.records.get(&child_record) else {
                sink.skip(format!(
                    "NTFS record {child_record} is missing from the catalog"
                ));
                continue;
            };
            let mut child_parts = relative_parts.clone();
            child_parts.push(child.name.clone());
            if child.is_directory {
                if child_parts.len() > crate::LIVE_TREE_MAX_PATH_DEPTH {
                    sink.skip(format!(
                        "{}: directory depth exceeds the {}-component corruption/cycle guard",
                        child_parts.join("/"),
                        crate::LIVE_TREE_MAX_PATH_DEPTH
                    ));
                    continue;
                }
                stack.push((child_record, child_parts));
                continue;
            }
            let native_size = ntfs
                .file(&mut slice, child_record)
                .ok()
                .and_then(|file| crate::ntfs_default_data_size(&file, &mut slice))
                .unwrap_or(child.size_bytes);
            if native_size > crate::LIVE_EXPORT_MAX_BYTES {
                sink.skip_oversized(&format!("/{}", child_parts.join("/")), native_size);
                continue;
            }
            let max_bytes = match usize::try_from(native_size) {
                Ok(value) => value,
                Err(_) => {
                    sink.skip(format!(
                        "/{}: size exceeds this platform's address space",
                        child_parts.join("/")
                    ));
                    continue;
                }
            };
            match read_ntfs_file_record_bytes(&ntfs, &mut slice, child_record, max_bytes) {
                Ok(bytes) if bytes.len() as u64 == native_size => {
                    sink.write_file(&child_parts, &bytes)?;
                }
                Ok(bytes) => sink.skip(format!(
                    "/{}: expected {} bytes but recovered {}",
                    child_parts.join("/"),
                    native_size,
                    bytes.len()
                )),
                Err(error) => sink.skip(format!("/{}: {error:#}", child_parts.join("/"))),
            }
        }
    }
    sink.finish()
}

/// Report whether a forensic catalog is currently in memory for a volume.
pub fn forensic_cache_status(
    image_path: &Path,
    volume_index: usize,
) -> Result<ForensicCacheStatus> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let key = cache_key_for_volume(image_path, volume)?;

    let state = forensic_cache()
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(slot) = state.map.get(&key) else {
        return Ok(ForensicCacheStatus {
            cached: false,
            record_count: None,
            allocated_count: None,
            deleted_reconstructed_count: None,
            orphan_count: None,
            diagnostic_count: None,
            built_at_ms_ago: None,
        });
    };

    let entry = &slot.entry;
    let allocated_count = entry
        .records
        .values()
        .filter(|r| r.allocated && r.record_number != ORPHAN_SENTINEL_RECORD)
        .count() as u64;
    let deleted_reconstructed_count = entry
        .records
        .values()
        .filter(|r| !r.allocated && r.provenance == NtfsForensicProvenance::DeletedReconstructed)
        .count() as u64;
    let orphan_count = entry.orphan_records.len() as u64;

    Ok(ForensicCacheStatus {
        cached: true,
        record_count: Some(entry.record_count),
        allocated_count: Some(allocated_count),
        deleted_reconstructed_count: Some(deleted_reconstructed_count),
        orphan_count: Some(orphan_count),
        diagnostic_count: Some(entry.diagnostics.len() as u64),
        built_at_ms_ago: Some(slot.last_used.elapsed().as_millis() as u64),
    })
}

/// Evict the forensic catalog for a volume from process memory.
pub fn drop_ntfs_forensic_cache(image_path: &Path, volume_index: usize) -> Result<bool> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let key = cache_key_for_volume(image_path, volume)?;
    let mut state = forensic_cache()
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(state.map.remove(&key).is_some())
}

// ---------------------------------------------------------------------------
// Cache construction
// ---------------------------------------------------------------------------

fn build_forensic_cache_from_reader<T: Read + Seek>(
    fs: &mut T,
    _partition_start_offset: u64,
    partition_size_bytes: u64,
    key: &NtfsForensicCacheKey,
    tracker: Option<&JobProgressTracker>,
) -> Result<NtfsForensicCacheEntry> {
    let ntfs = ntfs::Ntfs::new(fs).context("opening NTFS volume for forensic catalog")?;
    let file_record_size = u64::from(ntfs.file_record_size());
    if !(24..=64 * 1024).contains(&file_record_size) {
        bail!("NTFS reports an unsafe file-record size of {file_record_size}");
    }

    if let Some(tracker) = tracker {
        tracker.set_current_volume(Some(key.image_path.to_string_lossy().to_string()));
    }

    let guard = copy_ntfs_mft_stream_to_temp(&ntfs, fs, partition_size_bytes)
        .context("copying NTFS $MFT stream for forensic catalog")?;
    let mut parser = mft::MftParser::from_path(guard.path()).with_context(|| {
        format!(
            "parsing extracted NTFS $MFT stream {}",
            guard.path().display()
        )
    })?;
    let record_count = parser.get_entry_count();

    if let Some(tracker) = tracker {
        tracker.set_total_items(Some(record_count));
        tracker.set_item_unit("MFT records");
    }

    let mut records: HashMap<u64, NtfsForensicRecord> = HashMap::new();
    let mut children: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut path_to_record: HashMap<String, u64> = HashMap::new();
    let mut orphan_records: Vec<u64> = Vec::new();
    let mut diagnostics: Vec<String> = Vec::new();
    let mut used_paths: HashSet<String> = HashSet::new();

    // Synthetic orphan recovery folder, child of the NTFS root.
    let orphan_sentinel = NtfsForensicRecord {
        record_number: ORPHAN_SENTINEL_RECORD,
        sequence_number: 0,
        parent_record_number: 5,
        parent_sequence_number: 5,
        name: ORPHAN_FOLDER_NAME.to_string(),
        is_directory: true,
        allocated: true,
        size_bytes: 0,
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        mft_record_modification_time_utc: None,
        namespace: "POSIX".to_string(),
        mft_record_logical_offset: None,
        provenance: NtfsForensicProvenance::SyntheticRecovery,
        reconstruction_status: "synthetic_recovery_folder".to_string(),
        recovery_status: "metadata only".to_string(),
        diagnostics: Vec::new(),
    };
    records.insert(ORPHAN_SENTINEL_RECORD, orphan_sentinel);
    children.entry(5).or_default().push(ORPHAN_SENTINEL_RECORD);
    path_to_record.insert(ORPHAN_FOLDER_NAME.to_string(), ORPHAN_SENTINEL_RECORD);
    used_paths.insert(ORPHAN_FOLDER_NAME.to_string());

    for record_number in 0..record_count {
        if (record_number as usize).is_multiple_of(CANCELLATION_CHECK_INTERVAL) {
            crate::progress::check_cancellation()?;
            if let Some(tracker) = tracker {
                tracker.advance(0, Some(format!("$MFT record {record_number}")));
                tracker.set_processed_items(
                    record_number,
                    Some(format!("$MFT record {record_number}")),
                );
            }
        }

        let entry = match parser.get_entry(record_number) {
            Ok(e) => e,
            Err(error) => {
                diagnostics.push(format!("record {record_number} parse error: {error}"));
                continue;
            }
        };

        if !entry.header.is_valid() {
            continue;
        }

        let is_directory = entry.is_dir();
        let allocated = entry.is_allocated();
        let sequence_number = entry.header.sequence;
        let best_name = match entry.find_best_name_attribute() {
            Some(n) => n,
            None => {
                diagnostics.push(format!("record {record_number} has no usable FILE_NAME"));
                continue;
            }
        };

        let name = best_name.name.clone();
        let parent_record_number = best_name.parent.entry;
        let parent_sequence_number = best_name.parent.sequence;
        let size_bytes = if is_directory {
            0
        } else {
            best_name.logical_size
        };
        let created_utc = Some(best_name.created.to_string());
        let modified_utc = Some(best_name.modified.to_string());
        let accessed_utc = Some(best_name.accessed.to_string());
        let mft_record_modification_time_utc = Some(best_name.mft_modified.to_string());
        let namespace = format!("{:?}", best_name.namespace);
        let mut record_diagnostics = Vec::new();
        let mut provenance = NtfsForensicProvenance::AllocatedMft;
        let mut reconstruction_status = "mft_parent_reference".to_string();
        let recovery_status = if is_directory {
            "metadata only"
        } else {
            "not yet located"
        }
        .to_string();
        let mut path: Option<String> = None;

        if record_number == 5 {
            // The NTFS root references itself. It belongs in the catalog, but
            // must never be classified as an orphan or emitted as its own
            // child.
            path = Some(String::new());
        } else if allocated {
            match ntfs_path_for_allocated_record(&mut parser, &entry, record_number) {
                Ok(Some(p)) => {
                    path = Some(p);
                }
                Ok(None) => {
                    record_diagnostics
                        .push("allocated record has no reconstructable path".to_string());
                    provenance = NtfsForensicProvenance::AllocatedOrphan;
                    reconstruction_status = "no_reconstructable_path".to_string();
                }
                Err(status) => {
                    record_diagnostics.push(format!(
                        "allocated record path reconstruction failed: {status}"
                    ));
                    provenance = NtfsForensicProvenance::AllocatedOrphan;
                    reconstruction_status = status.to_string();
                }
            }
        } else {
            match reconstruct_validated_deleted_mft_path(&mut parser, &entry) {
                Ok(resolved) => {
                    path = normalized_mft_ntfs_path(Path::new(&resolved.ntfs_path));
                    provenance = NtfsForensicProvenance::DeletedReconstructed;
                    reconstruction_status = "resolved_and_sequence_validated".to_string();
                }
                Err(status) => {
                    record_diagnostics.push(format!(
                        "deleted record path reconstruction failed: {status}"
                    ));
                    provenance = NtfsForensicProvenance::DeletedOrphan;
                    reconstruction_status = status.to_string();
                }
            }
        }

        let is_orphan = matches!(
            provenance,
            NtfsForensicProvenance::DeletedOrphan | NtfsForensicProvenance::AllocatedOrphan
        );
        let final_parent = if is_orphan {
            ORPHAN_SENTINEL_RECORD
        } else {
            parent_record_number
        };

        let final_path = if is_orphan {
            let base = format!(
                "{ORPHAN_FOLDER_NAME}/{}-mft{record_number}-{sequence_number}",
                sanitize_logical_segment(&name)
            );
            let mut candidate = base.clone();
            let mut suffix = 2_usize;
            while !used_paths.insert(candidate.clone()) {
                candidate = format!("{base}-{suffix}");
                suffix = suffix.saturating_add(1);
            }
            candidate
        } else if let Some(p) = path {
            let mut candidate = p.clone();
            let mut suffix = 2_usize;
            while !used_paths.insert(candidate.clone()) {
                candidate = format!("{p}-{suffix}");
                suffix = suffix.saturating_add(1);
            }
            candidate
        } else {
            // Should not happen; fall back to orphan naming.
            let base = format!(
                "{ORPHAN_FOLDER_NAME}/{}-mft{record_number}-{sequence_number}",
                sanitize_logical_segment(&name)
            );
            let mut candidate = base.clone();
            let mut suffix = 2_usize;
            while !used_paths.insert(candidate.clone()) {
                candidate = format!("{base}-{suffix}");
                suffix = suffix.saturating_add(1);
            }
            candidate
        };

        if is_orphan {
            orphan_records.push(record_number);
        }

        let display_name = final_path
            .rsplit('/')
            .next()
            .filter(|component| !component.is_empty())
            .unwrap_or(&name)
            .to_string();
        let record = NtfsForensicRecord {
            record_number,
            sequence_number,
            parent_record_number: final_parent,
            parent_sequence_number,
            name: display_name,
            is_directory,
            allocated,
            size_bytes,
            created_utc,
            modified_utc,
            accessed_utc,
            mft_record_modification_time_utc,
            namespace,
            mft_record_logical_offset: None,
            provenance,
            reconstruction_status,
            recovery_status,
            diagnostics: record_diagnostics,
        };

        records.insert(record_number, record);
        if record_number == 5 {
            path_to_record.insert(String::new(), record_number);
            continue;
        }
        children
            .entry(final_parent)
            .or_default()
            .push(record_number);
        path_to_record.insert(final_path, record_number);
    }

    drop(parser);
    drop(guard);

    if let Some(tracker) = tracker {
        tracker.set_processed_items(record_count, Some("reconstruction complete".to_string()));
    }

    Ok(NtfsForensicCacheEntry {
        key: key.clone(),
        record_count,
        records,
        children,
        path_to_record,
        orphan_records,
        diagnostics,
        built_at: Instant::now(),
    })
}

fn ntfs_path_for_allocated_record<R: Read + Seek>(
    parser: &mut mft::MftParser<R>,
    entry: &mft::MftEntry,
    _record_number: u64,
) -> std::result::Result<Option<String>, &'static str> {
    let best_name = entry
        .find_best_name_attribute()
        .ok_or("missing_file_name")?;
    let parent = parser
        .get_entry(best_name.parent.entry)
        .map_err(|_| "missing_parent")?;
    if parent.header.sequence != best_name.parent.sequence {
        return Err("parent_sequence_mismatch");
    }
    if !parent.is_dir() {
        return Err("parent_not_directory");
    }
    let path = parser
        .get_full_path_for_entry(entry)
        .map_err(|_| "path_reconstruction_error")?;
    Ok(path.as_deref().and_then(normalized_mft_ntfs_path))
}

// ---------------------------------------------------------------------------
// Cache access helpers
// ---------------------------------------------------------------------------

fn resolve_path_to_record(cache: &NtfsForensicCacheEntry, path: &str) -> Option<u64> {
    if path.is_empty() || path == "/" {
        return Some(5); // NTFS root directory record.
    }

    // Fast exact match for known paths.
    if let Some(&record) = cache.path_to_record.get(path) {
        return Some(record);
    }

    // Walk component by component, case-insensitive, robust to implicit dirs.
    let mut current = 5_u64;
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let child_ids = cache.children.get(&current)?;
        let mut found = None;
        for &child_id in child_ids {
            let child = cache.records.get(&child_id)?;
            if child.name.eq_ignore_ascii_case(component) {
                found = Some(child_id);
                break;
            }
        }
        current = found?;
    }
    Some(current)
}

fn entry_for_record<T: Read + Seek>(
    cache: &NtfsForensicCacheEntry,
    _volume: &LiveVolume,
    record_number: u64,
    ntfs: &ntfs::Ntfs,
    fs: &mut T,
    partition_start_offset: u64,
) -> Result<NtfsForensicEntry> {
    let record = cache
        .records
        .get(&record_number)
        .with_context(|| format!("record {record_number} missing from catalog"))?;

    let (mft_record_logical_offset, data_location, native_data_size) =
        if record_number == ORPHAN_SENTINEL_RECORD {
            (None, None, None)
        } else {
            match ntfs.file(fs, record_number) {
                Ok(file) => {
                    let mft_offset = file.position().value().map(|position| position.get());
                    let native_data_size = (!record.is_directory)
                        .then(|| crate::ntfs_default_data_size(&file, fs))
                        .flatten();
                    let data_location = (!record.is_directory)
                        .then(|| ntfs_default_data_location(&file, fs))
                        .flatten();
                    (mft_offset, data_location, native_data_size)
                }
                Err(_) => (None, None, None),
            }
        };

    let mft_record_physical_offset =
        mft_record_logical_offset.and_then(|offset| partition_start_offset.checked_add(offset));
    let file_data_physical_offset = data_location
        .as_ref()
        .and_then(|loc| partition_start_offset.checked_add(loc.filesystem_offset));

    Ok(NtfsForensicEntry {
        name: record.name.clone(),
        is_dir: record.is_directory,
        size_bytes: if record.is_directory {
            None
        } else {
            Some(i64::try_from(native_data_size.unwrap_or(record.size_bytes)).unwrap_or(i64::MAX))
        },
        is_deleted: !record.allocated && record_number != ORPHAN_SENTINEL_RECORD,
        provenance: record.provenance.as_str().to_string(),
        reconstruction_status: record.reconstruction_status.clone(),
        recovery_status: if record.is_directory {
            "metadata only".to_string()
        } else {
            data_location
                .as_ref()
                .map(|_| "data_stream_located".to_string())
                .unwrap_or_else(|| "data_stream_not_located".to_string())
        },
        ntfs_file_record_number: record.record_number,
        ntfs_sequence_number: record.sequence_number,
        ntfs_parent_record_number: record.parent_record_number,
        mft_record_logical_offset,
        mft_record_physical_offset,
        file_data_logical_offset: data_location.as_ref().map(|loc| loc.filesystem_offset),
        file_data_physical_offset,
        file_data_file_offset: data_location.as_ref().map(|loc| loc.file_offset),
        file_data_contiguous_bytes: data_location.as_ref().and_then(|loc| loc.contiguous_bytes),
        physical_offset_basis: data_location.as_ref().map(|loc| loc.basis.to_string()),
        file_data_direct_logical_mapping: data_location
            .as_ref()
            .map(|loc| loc.direct_logical_mapping),
        offset_coordinate_system: file_data_physical_offset
            .map(|_| "decoded_media_byte_stream".to_string()),
        created_utc: record.created_utc.clone(),
        modified_utc: record.modified_utc.clone(),
        accessed_utc: record.accessed_utc.clone(),
        mft_record_modification_time_utc: record.mft_record_modification_time_utc.clone(),
        diagnostics: record.diagnostics.clone(),
    })
}

// ---------------------------------------------------------------------------
// Cache maintenance
// ---------------------------------------------------------------------------

fn cache_key_for_volume(image_path: &Path, volume: &LiveVolume) -> Result<NtfsForensicCacheKey> {
    let metadata = std::fs::metadata(image_path)
        .with_context(|| format!("reading source metadata {}", image_path.display()))?;
    let source_modified_utc = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string());
    Ok(NtfsForensicCacheKey {
        image_path: image_path.to_path_buf(),
        volume_start_offset: volume.start_offset,
        volume_size_bytes: volume.size_bytes,
        source_modified_utc,
        source_size_bytes: metadata.len(),
    })
}

fn evict_stale_and_overflow(state: &mut ForensicCacheState) {
    let now = Instant::now();
    state
        .map
        .retain(|_, slot| now.duration_since(slot.last_used) < CACHE_MAX_AGE);
    while state.map.len() > CACHE_MAX_VOLUMES {
        let oldest = state
            .map
            .iter()
            .min_by_key(|(_, slot)| slot.last_used)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            state.map.remove(&k);
        } else {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn normalize_dir_path(path: &str) -> String {
    path.trim().replace('\\', "/").trim_matches('/').to_string()
}

fn normalize_file_path(path: &str) -> String {
    normalize_dir_path(path)
}

fn sort_forensic_record_ids(cache: &NtfsForensicCacheEntry, record_ids: &mut [u64]) {
    record_ids.sort_by(|left_id, right_id| {
        let left = cache.records.get(left_id);
        let right = cache.records.get(right_id);
        match (left, right) {
            (Some(left), Some(right)) => (right.is_directory as u8)
                .cmp(&(left.is_directory as u8))
                .then_with(|| {
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase())
                })
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.record_number.cmp(&right.record_number)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left_id.cmp(right_id),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_folder_name_is_synthetic() {
        assert!(ORPHAN_FOLDER_NAME.starts_with('$'));
        assert_eq!(ORPHAN_SENTINEL_RECORD, u64::MAX);
    }

    #[test]
    fn normalize_dir_path_handles_backslashes_and_slashes() {
        assert_eq!(normalize_dir_path("/Users/Admin/"), "Users/Admin");
        assert_eq!(normalize_dir_path("\\Users\\Admin"), "Users/Admin");
        assert_eq!(normalize_dir_path("/"), "");
    }

    /// Manual, read-only validation against a real examiner image. The test is
    /// ignored in ordinary CI because the evidence path is supplied locally.
    #[test]
    #[ignore = "requires KDFT_FORENSIC_TEST_IMAGE to name a local NTFS image"]
    fn manual_real_image_builds_transient_forensic_catalog() -> Result<()> {
        let image_path = std::env::var_os("KDFT_FORENSIC_TEST_IMAGE")
            .map(PathBuf::from)
            .context("KDFT_FORENSIC_TEST_IMAGE is not set")?;
        let volumes = list_image_volumes(&image_path)?;
        let volume_index = volumes
            .iter()
            .position(|volume| volume.filesystem == "NTFS")
            .context("the image has no NTFS volume")?;

        let cache = build_ntfs_forensic_volume_cache(&image_path, volume_index, None)?;
        let root = list_ntfs_forensic_directory(
            &image_path,
            volume_index,
            "/",
            &NtfsForensicBrowseOptions::default(),
            None,
        )?;
        let allocated = cache
            .records
            .values()
            .filter(|record| record.allocated && record.record_number != ORPHAN_SENTINEL_RECORD)
            .count();
        let deleted_reconstructed = cache
            .records
            .values()
            .filter(|record| {
                !record.allocated
                    && record.provenance == NtfsForensicProvenance::DeletedReconstructed
            })
            .count();
        eprintln!(
            "records={} allocated={} deleted_reconstructed={} orphan={} root_children={} diagnostics={}",
            cache.record_count,
            allocated,
            deleted_reconstructed,
            cache.orphan_records.len(),
            root.total_children,
            cache.diagnostics.len()
        );

        assert!(cache.record_count > 0);
        assert!(root
            .entries
            .iter()
            .any(|entry| entry.name == ORPHAN_FOLDER_NAME));
        assert!(!root
            .entries
            .iter()
            .any(|entry| entry.ntfs_file_record_number == 5));

        let orphan = list_ntfs_forensic_directory(
            &image_path,
            volume_index,
            ORPHAN_FOLDER_NAME,
            &NtfsForensicBrowseOptions::default(),
            None,
        )?;
        assert_eq!(orphan.total_children, cache.orphan_records.len());
        let orphan_names = orphan
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(orphan_names.len(), orphan.entries.len());
        assert!(orphan.entries.iter().all(|entry| {
            resolve_path_to_record(&cache, &format!("{ORPHAN_FOLDER_NAME}/{}", entry.name))
                == Some(entry.ntfs_file_record_number)
        }));

        let recursive =
            list_ntfs_forensic_tree_files(&image_path, volume_index, ORPHAN_FOLDER_NAME, 5)?;
        assert_eq!(recursive.files.len(), 5);
        assert!(recursive.file_limit_reached);
        assert!(recursive.truncated);
        assert!(recursive.files.iter().all(|file| {
            file.ntfs_file_record_number.is_some()
                && file
                    .provenance
                    .as_deref()
                    .is_some_and(|value| value == "deleted_orphan" || value == "allocated_orphan")
                && file.reconstruction_status.is_some()
                && file.recovery_status.is_some()
        }));

        let (deleted_path, deleted_record) = cache
            .path_to_record
            .iter()
            .find_map(|(path, record_number)| {
                cache.records.get(record_number).and_then(|record| {
                    (!record.is_directory
                        && record.provenance == NtfsForensicProvenance::DeletedReconstructed)
                        .then_some((path.clone(), *record_number))
                })
            })
            .context("no reconstructed deleted file was found")?;
        let (deleted_parent, deleted_name) = deleted_path
            .rsplit_once('/')
            .unwrap_or(("", deleted_path.as_str()));
        let deleted_parent_listing = list_ntfs_forensic_directory(
            &image_path,
            volume_index,
            deleted_parent,
            &NtfsForensicBrowseOptions::default(),
            None,
        )?;
        let deleted_entry = deleted_parent_listing
            .entries
            .iter()
            .find(|entry| {
                entry.name == deleted_name
                    && entry.ntfs_file_record_number == deleted_record
                    && entry.is_deleted
            })
            .context("reconstructed deleted file was not browsable at its claimed path")?;
        eprintln!(
            "deleted_sample=/{deleted_path} record={} mft_physical={:?} data_physical={:?}",
            deleted_entry.ntfs_file_record_number,
            deleted_entry.mft_record_physical_offset,
            deleted_entry.file_data_physical_offset
        );
        Ok(())
    }
}
