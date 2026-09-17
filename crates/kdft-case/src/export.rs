//! Live and container export pipelines for attached evidence.
//!
//! Provides direct (un-indexed) file and directory tree extraction from disk
//! images (EXT4, FAT, NTFS) and local filesystems, generating integrity manifests
//! with SHA-256 hashes and recording comprehensive audit events.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::atomic_output::{write_new_file_atomically, AtomicOutput};
use crate::{
    active_case_id, audit_actor, collect_ntfs_dir_children, ensure_under_evidence_root,
    ext4_list_dir, ext4_read_file_bytes, ext4_resolve_inode, fatfs_date_to_rfc3339,
    fatfs_datetime_to_rfc3339, list_image_volumes, live_volume_numbering, open_disk_image,
    open_existing_case, open_ext4_superblock, read_local_live_evidence,
    read_ntfs_file_record_bytes, resolve_local_folder_path, resolve_local_live_file_path,
    sanitize_logical_segment, system_time_rfc3339, PartitionSlice,
};

#[derive(Debug, Clone, Serialize)]
pub struct LiveExportResult {
    pub output_path: String,
    pub bytes_written: u64,
    pub total_size: u64,
    pub sha256_hex: String,
}

/// Safety ceiling for live (un-indexed) file export. A partial copy would look
/// complete on disk, so oversized files fail loudly instead of truncating.
pub const LIVE_EXPORT_MAX_BYTES: u64 = 1024 * 1024 * 1024;

pub fn export_local_file(
    case_path: &Path,
    evidence_id: i64,
    relative_path: &str,
    output_path: &Path,
) -> Result<LiveExportResult> {
    let source = read_local_live_evidence(case_path, evidence_id)?;
    let path = resolve_local_live_file_path(&source, relative_path)?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("reading evidence file metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("live export does not follow symlinks: {}", path.display());
    }
    if !metadata.is_file() {
        bail!("local live path is not a file: {}", path.display());
    }
    let total_size = metadata.len();
    if total_size > LIVE_EXPORT_MAX_BYTES {
        bail!(
            "file is {total_size} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it"
        );
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating export folder {}", parent.display()))?;
    }

    let mut source_file = fs::File::open(&path)
        .with_context(|| format!("opening evidence file {}", path.display()))?;
    let mut output = AtomicOutput::create(output_path)
        .with_context(|| format!("creating exported file {}", output_path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut bytes_written = 0_u64;
    loop {
        let read = source_file
            .read(&mut buffer)
            .with_context(|| format!("reading evidence file {}", path.display()))?;
        if read == 0 {
            break;
        }
        if bytes_written.saturating_add(read as u64) > LIVE_EXPORT_MAX_BYTES {
            bail!(
                "file is larger than live export cap ({LIVE_EXPORT_MAX_BYTES} bytes): {}",
                path.display()
            );
        }
        output
            .write_all(&buffer[..read])
            .with_context(|| format!("writing exported file {}", output_path.display()))?;
        hasher.update(&buffer[..read]);
        bytes_written += read as u64;
    }
    if bytes_written != total_size {
        bail!(
            "source size changed during export (expected {total_size} bytes, read {bytes_written}); no final output was published"
        );
    }
    output
        .commit()
        .with_context(|| format!("publishing exported file {}", output_path.display()))?;

    Ok(LiveExportResult {
        output_path: output_path.display().to_string(),
        bytes_written,
        total_size,
        sha256_hex: format!("{:x}", hasher.finalize()),
    })
}

/// Copy one file directly from an attached disk image without indexing while
/// hashing the written bytes. The caller records the
/// audit event via `record_live_export`.
pub fn export_image_file(
    image_path: &Path,
    volume_index: usize,
    file_path: &str,
    output_path: &Path,
) -> Result<LiveExportResult> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = file_path.trim_matches('/');

    let bytes: Vec<u8> = match volume.filesystem.as_str() {
        "EXT" => {
            let fs = open_ext4_superblock(image_path, volume.start_offset)?;
            ext4_read_file_bytes(&fs, &format!("/{relative}"))?
        }
        "FAT" => {
            let mut opened = open_disk_image(image_path)?;
            let slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
                .context("opening FAT volume")?;
            let mut file = fs
                .root_dir()
                .open_file(relative)
                .with_context(|| format!("opening FAT file {relative}"))?;
            let total = file.seek(SeekFrom::End(0))?;
            if total > LIVE_EXPORT_MAX_BYTES {
                bail!(
                    "file is {total} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it"
                );
            }
            file.seek(SeekFrom::Start(0))?;
            let mut data = Vec::with_capacity(total as usize);
            file.read_to_end(&mut data)?;
            data
        }
        "NTFS" => {
            let mut opened = open_disk_image(image_path)?;
            let mut slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume")?;
            let mut record = ntfs
                .root_directory(&mut slice)
                .context("opening NTFS root directory")?
                .file_record_number();
            let components: Vec<&str> = relative.split('/').filter(|v| !v.is_empty()).collect();
            let Some((file_name, dir_components)) = components.split_last() else {
                bail!("no file path given");
            };
            for component in dir_components {
                let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?.children;
                let child = children
                    .iter()
                    .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
                    .with_context(|| format!("directory not found: {component}"))?;
                record = child.file_record_number;
            }
            let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?.children;
            let target = children
                .iter()
                .find(|child| !child.is_directory && child.name.eq_ignore_ascii_case(file_name))
                .with_context(|| format!("file not found: {file_name}"))?;
            if target.size_bytes > LIVE_EXPORT_MAX_BYTES {
                bail!(
                    "file is {} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it",
                    target.size_bytes
                );
            }
            read_ntfs_file_record_bytes(
                &ntfs,
                &mut slice,
                target.file_record_number,
                target.size_bytes as usize,
            )?
        }
        other => bail!("live export is not supported for {other} volumes"),
    };

    if bytes.len() as u64 > LIVE_EXPORT_MAX_BYTES {
        bail!(
            "file is {} bytes; live export is capped at {LIVE_EXPORT_MAX_BYTES} bytes - process the evidence to export it",
            bytes.len()
        );
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating export folder {}", parent.display()))?;
    }
    write_new_file_atomically(output_path, &bytes)
        .with_context(|| format!("writing exported file {}", output_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256_hex = format!("{:x}", hasher.finalize());
    Ok(LiveExportResult {
        output_path: output_path.display().to_string(),
        bytes_written: bytes.len() as u64,
        total_size: bytes.len() as u64,
        sha256_hex,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveTreeExportResult {
    pub output_dir: String,
    pub manifest_path: String,
    pub files_exported: u64,
    pub bytes_written: u64,
    pub directories_visited: u64,
    pub skipped: Vec<String>,
    pub skipped_count: u64,
    pub oversized_files_skipped: u64,
    pub protective_file_size_limit_bytes: u64,
    pub file_limit: Option<usize>,
    pub file_limit_reached: bool,
    pub truncated: bool,
}

pub(crate) const LIVE_TREE_EXPORT_MAX_SKIP_NOTES: usize = 100;
/// Corrupt directory cycles must not grow paths forever after removal of the
/// old breadth caps. This is a path-depth/cycle guard, not a directory-count
/// limit: any number of sibling directories remain traversable.
pub(crate) const LIVE_TREE_MAX_PATH_DEPTH: usize = 1_024;

pub(crate) fn normalize_optional_file_limit(max_files: Option<usize>) -> Option<usize> {
    max_files.filter(|limit| *limit != 0)
}

pub(crate) fn file_limit_allows(processed: u64, max_files: Option<usize>) -> bool {
    max_files
        .map(|limit| processed < u64::try_from(limit).unwrap_or(u64::MAX))
        .unwrap_or(true)
}

pub(crate) fn live_tree_depth_allowed(relative_parts: &[String]) -> bool {
    relative_parts.len() <= LIVE_TREE_MAX_PATH_DEPTH
}

pub(crate) struct TreeExportSink {
    pub(crate) output_root: PathBuf,
    pub(crate) canonical_output_root: Option<PathBuf>,
    pub(crate) manifest: String,
    pub(crate) files: u64,
    pub(crate) bytes: u64,
    pub(crate) dirs: u64,
    pub(crate) skipped: Vec<String>,
    pub(crate) skipped_count: u64,
    pub(crate) oversized_files_skipped: u64,
    pub(crate) max_files: Option<usize>,
    pub(crate) file_limit_reached: bool,
    pub(crate) truncated: bool,
    pub(crate) written: HashSet<PathBuf>,
}

impl TreeExportSink {
    pub(crate) fn new(output_root: &Path, max_files: Option<usize>) -> Self {
        Self::new_with_size_header(output_root, max_files, "size_bytes")
    }

    pub(crate) fn new_with_size_header(
        output_root: &Path,
        max_files: Option<usize>,
        size_header: &str,
    ) -> Self {
        Self {
            output_root: output_root.to_path_buf(),
            canonical_output_root: None,
            manifest: format!("relative_path,{size_header},sha256\r\n"),
            files: 0,
            bytes: 0,
            dirs: 0,
            skipped: Vec::new(),
            skipped_count: 0,
            oversized_files_skipped: 0,
            max_files: normalize_optional_file_limit(max_files),
            file_limit_reached: false,
            truncated: false,
            written: HashSet::new(),
        }
    }

    pub(crate) fn file_budget_left(&self) -> bool {
        file_limit_allows(self.files, self.max_files)
    }

    pub(crate) fn prepare_output_root(&mut self) -> Result<()> {
        fs::create_dir_all(&self.output_root)
            .with_context(|| format!("creating export folder {}", self.output_root.display()))?;
        let metadata = fs::symlink_metadata(&self.output_root).with_context(|| {
            format!(
                "reading export-folder metadata {}",
                self.output_root.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "export root must be a real directory, not a link or another file type: {}",
                self.output_root.display()
            );
        }
        self.canonical_output_root =
            Some(self.output_root.canonicalize().with_context(|| {
                format!("resolving export folder {}", self.output_root.display())
            })?);
        Ok(())
    }

    pub(crate) fn mark_file_limit_reached(&mut self) {
        self.file_limit_reached = true;
        self.truncated = true;
    }

    pub(crate) fn skip(&mut self, note: String) {
        self.skipped_count = self.skipped_count.saturating_add(1);
        self.truncated = true;
        if self.skipped.len() < LIVE_TREE_EXPORT_MAX_SKIP_NOTES {
            self.skipped.push(note);
        }
    }

    pub(crate) fn skip_oversized(&mut self, logical_path: &str, size: u64) {
        self.oversized_files_skipped = self.oversized_files_skipped.saturating_add(1);
        self.skip(format!(
            "{logical_path}: {size} bytes exceeds the protective per-file live export limit of {LIVE_EXPORT_MAX_BYTES} bytes"
        ));
    }

    pub(crate) fn unique_output_path(&mut self, rel_parts: &[String]) -> Result<PathBuf> {
        let canonical_root = self
            .canonical_output_root
            .as_ref()
            .context("export root was not prepared")?;
        let mut target = self.output_root.clone();
        let Some((file_name, directory_parts)) = rel_parts.split_last() else {
            bail!("exported file has no relative path components");
        };
        for part in directory_parts {
            target.push(sanitize_logical_segment(part));
            match fs::symlink_metadata(&target) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        bail!(
                            "export path component must be a real directory: {}",
                            target.display()
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&target)
                        .with_context(|| format!("creating export folder {}", target.display()))?;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("reading export-folder metadata {}", target.display())
                    });
                }
            }
            let canonical = target
                .canonicalize()
                .with_context(|| format!("resolving export folder {}", target.display()))?;
            if !canonical.starts_with(canonical_root) {
                bail!(
                    "export path escaped the selected output directory: {}",
                    target.display()
                );
            }
        }
        target.push(sanitize_logical_segment(file_name));
        let mut unique = target.clone();
        let mut suffix = 2;
        while unique.exists() || !self.written.insert(unique.clone()) {
            unique = target.with_file_name(format!(
                "{}-{}",
                target
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".to_string()),
                suffix
            ));
            suffix += 1;
        }
        if let Some(parent) = unique.parent() {
            let canonical = parent
                .canonicalize()
                .with_context(|| format!("resolving export folder {}", parent.display()))?;
            if !canonical.starts_with(canonical_root) {
                bail!(
                    "export destination escaped the selected output directory: {}",
                    unique.display()
                );
            }
        }
        Ok(unique)
    }

    pub(crate) fn append_manifest_row(&mut self, output_path: &Path, size: u64, sha256_hex: &str) {
        let rel = output_path
            .strip_prefix(&self.output_root)
            .unwrap_or(output_path)
            .display()
            .to_string();
        self.manifest.push_str(&format!(
            "\"{}\",{},{}\r\n",
            rel.replace('"', "\"\""),
            size,
            sha256_hex
        ));
    }

    pub(crate) fn write_file(&mut self, rel_parts: &[String], bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 > LIVE_EXPORT_MAX_BYTES {
            self.skip_oversized(&local_tree_note_path(rel_parts), bytes.len() as u64);
            return Ok(());
        }
        let unique = self.unique_output_path(rel_parts)?;
        write_new_file_atomically(&unique, bytes)
            .with_context(|| format!("writing exported file {}", unique.display()))?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let sha = format!("{:x}", hasher.finalize());
        self.append_manifest_row(&unique, bytes.len() as u64, &sha);
        self.files += 1;
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    pub(crate) fn write_file_from_path(
        &mut self,
        rel_parts: &[String],
        source_path: &Path,
        expected_size: u64,
    ) -> Result<()> {
        if expected_size > LIVE_EXPORT_MAX_BYTES {
            self.skip_oversized(&local_tree_note_path(rel_parts), expected_size);
            return Ok(());
        }
        let unique = self.unique_output_path(rel_parts)?;
        let mut source = fs::File::open(source_path)
            .with_context(|| format!("opening evidence file {}", source_path.display()))?;
        let mut output = AtomicOutput::create(&unique)
            .with_context(|| format!("creating exported file {}", unique.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut written = 0_u64;
        loop {
            let read = source
                .read(&mut buffer)
                .with_context(|| format!("reading evidence file {}", source_path.display()))?;
            if read == 0 {
                break;
            }
            if written.saturating_add(read as u64) > LIVE_EXPORT_MAX_BYTES {
                self.skip_oversized(
                    &local_tree_note_path(rel_parts),
                    written.saturating_add(read as u64),
                );
                return Ok(());
            }
            output
                .write_all(&buffer[..read])
                .with_context(|| format!("writing exported file {}", unique.display()))?;
            hasher.update(&buffer[..read]);
            written += read as u64;
        }
        if written != expected_size {
            self.skip(format!(
                "{}: size changed during export (expected {}, read {}); no output was published",
                source_path.display(),
                expected_size,
                written
            ));
            return Ok(());
        }
        output
            .commit()
            .with_context(|| format!("publishing exported file {}", unique.display()))?;
        let sha = format!("{:x}", hasher.finalize());
        self.append_manifest_row(&unique, written, &sha);
        self.files += 1;
        self.bytes += written;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<LiveTreeExportResult> {
        if self.canonical_output_root.is_none() {
            self.prepare_output_root()?;
        }
        let mut manifest_path = self.output_root.join("kdft-manifest.csv");
        let mut suffix = 2_u64;
        while manifest_path.exists() || self.written.contains(&manifest_path) {
            manifest_path = self.output_root.join(format!("kdft-manifest-{suffix}.csv"));
            suffix = suffix.saturating_add(1);
        }
        write_new_file_atomically(&manifest_path, self.manifest.as_bytes())
            .with_context(|| format!("writing manifest {}", manifest_path.display()))?;
        if self.skipped_count > self.skipped.len() as u64 {
            self.skipped.push(format!(
                "... and {} more skipped items",
                self.skipped_count - self.skipped.len() as u64
            ));
        }
        Ok(LiveTreeExportResult {
            output_dir: self.output_root.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            files_exported: self.files,
            bytes_written: self.bytes,
            directories_visited: self.dirs,
            skipped: self.skipped,
            skipped_count: self.skipped_count,
            oversized_files_skipped: self.oversized_files_skipped,
            protective_file_size_limit_bytes: LIVE_EXPORT_MAX_BYTES,
            file_limit: self.max_files,
            file_limit_reached: self.file_limit_reached,
            truncated: self.truncated,
        })
    }
}

/// Recursive live export: copy a whole directory out of an attached disk
/// image (no indexing), preserving the folder structure under `output_root`
/// and writing a `kdft-manifest.csv` with per-file SHA-256. The filesystem is
/// opened once. `None`/`Some(0)` means unlimited files; a positive examiner
/// limit is honored exactly. Oversized or unreadable files are skipped and
/// make the result explicitly partial with bounded diagnostic samples.
pub fn export_image_tree(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
    output_root: &Path,
    max_files: Option<usize>,
) -> Result<LiveTreeExportResult> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = dir_path.trim_matches('/').to_string();
    let mut sink = TreeExportSink::new(output_root, max_files);
    sink.prepare_output_root()?;

    match volume.filesystem.as_str() {
        "EXT" => {
            let fs = open_ext4_superblock(image_path, volume.start_offset)?;
            let start = if relative.is_empty() {
                "/".to_string()
            } else {
                format!("/{relative}")
            };
            let mut stack: Vec<(String, Vec<String>)> = vec![(start, Vec::new())];
            let mut seen_directory_inodes = HashSet::new();
            seen_directory_inodes.insert(ext4_resolve_inode(&fs, &stack[0].0)?.number);
            while let Some((ext_path, rel_parts)) = stack.pop() {
                if !sink.file_budget_left() {
                    sink.mark_file_limit_reached();
                    break;
                }
                sink.dirs += 1;
                let children = match ext4_list_dir(&fs, &ext_path) {
                    Ok(children) => children,
                    Err(err) => {
                        sink.skip(format!("{ext_path}: {err}"));
                        continue;
                    }
                };
                for child in children {
                    if !sink.file_budget_left() {
                        sink.mark_file_limit_reached();
                        break;
                    }
                    let child_path = if ext_path == "/" {
                        format!("/{}", child.name)
                    } else {
                        format!("{ext_path}/{}", child.name)
                    };
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(child.name.clone());
                    if child.is_dir {
                        if !live_tree_depth_allowed(&child_rel) {
                            sink.skip(format!(
                                "{child_path}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard"
                            ));
                            continue;
                        }
                        if !seen_directory_inodes.insert(child.inode_number) {
                            sink.skip(format!(
                                "{child_path}: repeated ext directory inode {} skipped to prevent a cycle",
                                child.inode_number
                            ));
                            continue;
                        }
                        stack.push((child_path, child_rel));
                        continue;
                    }
                    if child.size > LIVE_EXPORT_MAX_BYTES {
                        sink.skip_oversized(&child_path, child.size);
                        continue;
                    }
                    match ext4_read_file_bytes(&fs, &child_path) {
                        Ok(bytes) => sink.write_file(&child_rel, &bytes)?,
                        Err(err) => sink.skip(format!("{child_path}: {err}")),
                    }
                }
            }
        }
        "FAT" => {
            let mut opened = open_disk_image(image_path)?;
            let slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
                .context("opening FAT volume")?;
            let root = fs.root_dir();
            let mut stack: Vec<(String, Vec<String>)> = vec![(relative.clone(), Vec::new())];
            while let Some((fat_path, rel_parts)) = stack.pop() {
                if !sink.file_budget_left() {
                    sink.mark_file_limit_reached();
                    break;
                }
                sink.dirs += 1;
                let dir = if fat_path.is_empty() {
                    root.clone()
                } else {
                    match root.open_dir(&fat_path) {
                        Ok(dir) => dir,
                        Err(err) => {
                            sink.skip(format!("{fat_path}: {err}"));
                            continue;
                        }
                    }
                };
                for entry in dir.iter() {
                    if !sink.file_budget_left() {
                        sink.mark_file_limit_reached();
                        break;
                    }
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            sink.skip(format!(
                                "{fat_path}: FAT directory entry could not be read: {err}"
                            ));
                            continue;
                        }
                    };
                    let name = entry.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let child_path = if fat_path.is_empty() {
                        name.clone()
                    } else {
                        format!("{fat_path}/{name}")
                    };
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(name.clone());
                    if entry.is_dir() {
                        if !live_tree_depth_allowed(&child_rel) {
                            sink.skip(format!(
                                "{child_path}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard"
                            ));
                            continue;
                        }
                        stack.push((child_path, child_rel));
                        continue;
                    }
                    if entry.len() > LIVE_EXPORT_MAX_BYTES {
                        sink.skip_oversized(&child_path, entry.len());
                        continue;
                    }
                    let mut file = entry.to_file();
                    let mut bytes = Vec::with_capacity(entry.len() as usize);
                    match file.read_to_end(&mut bytes) {
                        Ok(_) => sink.write_file(&child_rel, &bytes)?,
                        Err(err) => sink.skip(format!("{child_path}: {err}")),
                    }
                }
            }
        }
        "NTFS" => {
            let mut opened = open_disk_image(image_path)?;
            let mut slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume")?;
            let mut record = ntfs
                .root_directory(&mut slice)
                .context("opening NTFS root directory")?
                .file_record_number();
            for component in relative.split('/').filter(|v| !v.is_empty()) {
                let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?.children;
                let child = children
                    .iter()
                    .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
                    .with_context(|| format!("directory not found: {component}"))?;
                record = child.file_record_number;
            }
            let mut stack: Vec<(u64, Vec<String>)> = vec![(record, Vec::new())];
            let mut seen_records: HashSet<u64> = HashSet::new();
            while let Some((dir_record, rel_parts)) = stack.pop() {
                if !sink.file_budget_left() {
                    sink.mark_file_limit_reached();
                    break;
                }
                if !seen_records.insert(dir_record) {
                    sink.skip(format!(
                        "NTFS directory record {dir_record} was already visited and was skipped to prevent a cycle"
                    ));
                    continue;
                }
                sink.dirs += 1;
                let children = match collect_ntfs_dir_children(&ntfs, &mut slice, dir_record) {
                    Ok(result) => {
                        for diagnostic in result.diagnostics.iter().take(8) {
                            sink.skip(format!("record {dir_record}: {diagnostic}"));
                        }
                        result.children
                    }
                    Err(err) => {
                        sink.skip(format!("record {dir_record}: {err}"));
                        continue;
                    }
                };
                for child in children {
                    if !sink.file_budget_left() {
                        sink.mark_file_limit_reached();
                        break;
                    }
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(child.name.clone());
                    if child.is_directory {
                        if !live_tree_depth_allowed(&child_rel) {
                            sink.skip(format!(
                                "{}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard",
                                child.name
                            ));
                            continue;
                        }
                        stack.push((child.file_record_number, child_rel));
                        continue;
                    }
                    if child.size_bytes > LIVE_EXPORT_MAX_BYTES {
                        sink.skip_oversized(&child.name, child.size_bytes);
                        continue;
                    }
                    match read_ntfs_file_record_bytes(
                        &ntfs,
                        &mut slice,
                        child.file_record_number,
                        child.size_bytes as usize,
                    ) {
                        Ok(bytes) => sink.write_file(&child_rel, &bytes)?,
                        Err(err) => sink.skip(format!("{}: {err}", child.name)),
                    }
                }
            }
        }
        other => bail!("live export is not supported for {other} volumes"),
    }

    sink.finish()
}

fn local_tree_note_path(parts: &[String]) -> String {
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

pub fn export_local_tree(
    case_path: &Path,
    evidence_id: i64,
    dir_path: &str,
    output_root: &Path,
    max_files: Option<usize>,
) -> Result<LiveTreeExportResult> {
    let source = read_local_live_evidence(case_path, evidence_id)?;
    if source.source_kind != "folder" {
        bail!("recursive live export is only available for folder evidence");
    }
    let (root, start) = resolve_local_folder_path(&source.source_path, dir_path)?;
    let metadata = fs::symlink_metadata(&start)
        .with_context(|| format!("reading evidence directory metadata {}", start.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("live export does not follow symlinks: {}", start.display());
    }
    if !metadata.is_dir() {
        bail!("local live path is not a directory: {}", start.display());
    }

    let mut sink = TreeExportSink::new_with_size_header(output_root, max_files, "size");
    sink.prepare_output_root()?;
    let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(start, Vec::new())];
    let mut seen_directories: HashSet<PathBuf> = HashSet::new();
    while let Some((dir, rel_parts)) = stack.pop() {
        if !sink.file_budget_left() {
            sink.mark_file_limit_reached();
            break;
        }
        let canonical_dir = match ensure_under_evidence_root(&root, &dir) {
            Ok(canonical) => canonical,
            Err(err) => {
                sink.skip(format!("{}: {err:#}", local_tree_note_path(&rel_parts)));
                continue;
            }
        };
        if !seen_directories.insert(canonical_dir.clone()) {
            sink.skip(format!(
                "{}: canonical directory was already visited and was skipped to prevent a cycle",
                local_tree_note_path(&rel_parts)
            ));
            continue;
        }
        let metadata = match fs::symlink_metadata(&canonical_dir) {
            Ok(metadata) => metadata,
            Err(err) => {
                sink.skip(format!("{}: {err}", local_tree_note_path(&rel_parts)));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            sink.skip(format!(
                "{}: symlink skipped",
                local_tree_note_path(&rel_parts)
            ));
            continue;
        }
        if !metadata.is_dir() {
            sink.skip(format!(
                "{}: not a directory",
                local_tree_note_path(&rel_parts)
            ));
            continue;
        }
        sink.dirs += 1;
        let read_dir = match fs::read_dir(&canonical_dir) {
            Ok(read_dir) => read_dir,
            Err(err) => {
                sink.skip(format!("{}: {err}", local_tree_note_path(&rel_parts)));
                continue;
            }
        };
        for child in read_dir {
            if !sink.file_budget_left() {
                sink.mark_file_limit_reached();
                break;
            }
            let child = match child {
                Ok(child) => child,
                Err(err) => {
                    sink.skip(format!("{}: {err}", local_tree_note_path(&rel_parts)));
                    continue;
                }
            };
            let child_path = child.path();
            let name = child
                .file_name()
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|| child.file_name().to_string_lossy().into_owned());
            let mut child_rel = rel_parts.clone();
            child_rel.push(name);
            let child_note = local_tree_note_path(&child_rel);
            let metadata = match fs::symlink_metadata(&child_path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    sink.skip(format!("{child_note}: {err}"));
                    continue;
                }
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                sink.skip(format!("{child_note}: symlink skipped"));
                continue;
            }
            if file_type.is_dir() {
                if !live_tree_depth_allowed(&child_rel) {
                    sink.skip(format!(
                        "{child_note}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard"
                    ));
                    continue;
                }
                match ensure_under_evidence_root(&root, &child_path) {
                    Ok(canonical) => stack.push((canonical, child_rel)),
                    Err(err) => sink.skip(format!("{child_note}: {err:#}")),
                }
                continue;
            }
            if !file_type.is_file() {
                sink.skip(format!("{child_note}: unsupported file type"));
                continue;
            }
            let size = metadata.len();
            if size > LIVE_EXPORT_MAX_BYTES {
                sink.skip_oversized(&child_note, size);
                continue;
            }
            let canonical = match ensure_under_evidence_root(&root, &child_path) {
                Ok(canonical) => canonical,
                Err(err) => {
                    sink.skip(format!("{child_note}: {err:#}"));
                    continue;
                }
            };
            if let Err(err) = sink.write_file_from_path(&child_rel, &canonical, size) {
                sink.skip(format!("{child_note}: {err:#}"));
            }
        }
        if sink.file_limit_reached {
            break;
        }
    }

    sink.finish()
}

/// Compatibility value for callers that used the former recursive-bookmark
/// default. Zero now means unlimited; there is no hidden default ceiling.
pub const RECURSIVE_FOLDER_BOOKMARK_DEFAULT_LIMIT: usize = 0;
/// Compatibility value for callers that used the former hard ceiling. Zero
/// now means unlimited; only a positive examiner-supplied value is a limit.
pub const RECURSIVE_FOLDER_BOOKMARK_LIMIT: usize = 0;

pub struct LiveTreeFileRef {
    pub relative_path: String,
    pub name: String,
    pub size_bytes: u64,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
}

pub struct LiveTreeListResult {
    pub files: Vec<LiveTreeFileRef>,
    pub directories_visited: u64,
    pub skipped: Vec<String>,
    pub skipped_count: u64,
    pub file_limit: Option<usize>,
    pub file_limit_reached: bool,
    pub truncated: bool,
}

pub(crate) struct TreeListSink {
    pub(crate) files: Vec<LiveTreeFileRef>,
    pub(crate) dirs: u64,
    pub(crate) skipped: Vec<String>,
    pub(crate) skipped_count: u64,
    pub(crate) max_files: Option<usize>,
    pub(crate) file_limit_reached: bool,
    pub(crate) truncated: bool,
}

impl TreeListSink {
    pub(crate) fn new(max_files: usize) -> Self {
        Self {
            files: Vec::new(),
            dirs: 0,
            skipped: Vec::new(),
            skipped_count: 0,
            max_files: (max_files != 0).then_some(max_files),
            file_limit_reached: false,
            truncated: false,
        }
    }

    pub(crate) fn file_budget_left(&self) -> bool {
        file_limit_allows(self.files.len() as u64, self.max_files)
    }

    pub(crate) fn mark_file_limit_reached(&mut self) {
        self.file_limit_reached = true;
        self.truncated = true;
    }

    pub(crate) fn skip(&mut self, note: String) {
        self.skipped_count = self.skipped_count.saturating_add(1);
        self.truncated = true;
        if self.skipped.len() < LIVE_TREE_EXPORT_MAX_SKIP_NOTES {
            self.skipped.push(note);
        }
    }

    pub(crate) fn push(
        &mut self,
        rel_parts: &[String],
        size_bytes: u64,
        created_utc: Option<String>,
        modified_utc: Option<String>,
        accessed_utc: Option<String>,
    ) {
        let relative_path = rel_parts.join("/");
        let name = rel_parts.last().cloned().unwrap_or_default();
        self.files.push(LiveTreeFileRef {
            relative_path,
            name,
            size_bytes,
            created_utc,
            modified_utc,
            accessed_utc,
        });
    }

    pub(crate) fn finish(mut self) -> LiveTreeListResult {
        if self.skipped_count > self.skipped.len() as u64 {
            self.skipped.push(format!(
                "... and {} more skipped items",
                self.skipped_count - self.skipped.len() as u64
            ));
        }
        LiveTreeListResult {
            files: self.files,
            directories_visited: self.dirs,
            skipped: self.skipped,
            skipped_count: self.skipped_count,
            file_limit: self.max_files,
            file_limit_reached: self.file_limit_reached,
            truncated: self.truncated,
        }
    }
}

/// Recursively lists files under `dir_path` in one volume of a disk image, read
/// live (no indexing). Mirrors `export_image_tree`'s per-filesystem walk but
/// never reads file content - used to bulk-create bookmark items for
/// "Bookmark folder (recursive)" in live browse without the cost/side-effect of
/// a real export. `max_files == 0` is unlimited; positive values are explicit
/// examiner limits.
pub fn list_image_tree_files(
    image_path: &Path,
    volume_index: usize,
    dir_path: &str,
    max_files: usize,
) -> Result<LiveTreeListResult> {
    let volumes = list_image_volumes(image_path)?;
    let volume = volumes
        .get(volume_index)
        .with_context(|| format!("volume index {volume_index} out of range"))?;
    let relative = dir_path.trim_matches('/').to_string();
    let mut sink = TreeListSink::new(max_files);

    match volume.filesystem.as_str() {
        "EXT" => {
            let fs = open_ext4_superblock(image_path, volume.start_offset)?;
            let start = if relative.is_empty() {
                "/".to_string()
            } else {
                format!("/{relative}")
            };
            let mut stack: Vec<(String, Vec<String>)> = vec![(start, Vec::new())];
            let mut seen_directory_inodes = HashSet::new();
            seen_directory_inodes.insert(ext4_resolve_inode(&fs, &stack[0].0)?.number);
            while let Some((ext_path, rel_parts)) = stack.pop() {
                if !sink.file_budget_left() {
                    sink.mark_file_limit_reached();
                    break;
                }
                sink.dirs += 1;
                let children = match ext4_list_dir(&fs, &ext_path) {
                    Ok(children) => children,
                    Err(err) => {
                        sink.skip(format!("{ext_path}: {err}"));
                        continue;
                    }
                };
                for child in children {
                    if !sink.file_budget_left() {
                        sink.mark_file_limit_reached();
                        break;
                    }
                    let child_path = if ext_path == "/" {
                        format!("/{}", child.name)
                    } else {
                        format!("{ext_path}/{}", child.name)
                    };
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(child.name.clone());
                    if child.is_dir {
                        if !live_tree_depth_allowed(&child_rel) {
                            sink.skip(format!(
                                "{child_path}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard"
                            ));
                            continue;
                        }
                        if !seen_directory_inodes.insert(child.inode_number) {
                            sink.skip(format!(
                                "{child_path}: repeated ext directory inode {} skipped to prevent a cycle",
                                child.inode_number
                            ));
                            continue;
                        }
                        stack.push((child_path, child_rel));
                        continue;
                    }
                    sink.push(
                        &child_rel,
                        child.size,
                        child.btime_utc.or(child.ctime_utc),
                        child.mtime_utc,
                        child.atime_utc,
                    );
                }
            }
        }
        "FAT" => {
            let mut opened = open_disk_image(image_path)?;
            let slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let fs = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
                .context("opening FAT volume")?;
            let root = fs.root_dir();
            let mut stack: Vec<(String, Vec<String>)> = vec![(relative.clone(), Vec::new())];
            while let Some((fat_path, rel_parts)) = stack.pop() {
                if !sink.file_budget_left() {
                    sink.mark_file_limit_reached();
                    break;
                }
                sink.dirs += 1;
                let dir = if fat_path.is_empty() {
                    root.clone()
                } else {
                    match root.open_dir(&fat_path) {
                        Ok(dir) => dir,
                        Err(err) => {
                            sink.skip(format!("{fat_path}: {err}"));
                            continue;
                        }
                    }
                };
                for entry in dir.iter() {
                    if !sink.file_budget_left() {
                        sink.mark_file_limit_reached();
                        break;
                    }
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            sink.skip(format!(
                                "{fat_path}: FAT directory entry could not be read: {err}"
                            ));
                            continue;
                        }
                    };
                    let name = entry.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let child_path = if fat_path.is_empty() {
                        name.clone()
                    } else {
                        format!("{fat_path}/{name}")
                    };
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(name.clone());
                    if entry.is_dir() {
                        if !live_tree_depth_allowed(&child_rel) {
                            sink.skip(format!(
                                "{child_path}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard"
                            ));
                            continue;
                        }
                        stack.push((child_path, child_rel));
                        continue;
                    }
                    sink.push(
                        &child_rel,
                        entry.len(),
                        fatfs_datetime_to_rfc3339(&entry.created()),
                        fatfs_datetime_to_rfc3339(&entry.modified()),
                        fatfs_date_to_rfc3339(&entry.accessed()),
                    );
                }
            }
        }
        "NTFS" => {
            let mut opened = open_disk_image(image_path)?;
            let mut slice =
                PartitionSlice::new(&mut *opened.reader, volume.start_offset, volume.size_bytes);
            let ntfs = ntfs::Ntfs::new(&mut slice).context("opening NTFS volume")?;
            let mut record = ntfs
                .root_directory(&mut slice)
                .context("opening NTFS root directory")?
                .file_record_number();
            for component in relative.split('/').filter(|v| !v.is_empty()) {
                let children = collect_ntfs_dir_children(&ntfs, &mut slice, record)?.children;
                let child = children
                    .iter()
                    .find(|child| child.is_directory && child.name.eq_ignore_ascii_case(component))
                    .with_context(|| format!("directory not found: {component}"))?;
                record = child.file_record_number;
            }
            let mut stack: Vec<(u64, Vec<String>)> = vec![(record, Vec::new())];
            let mut seen_records: HashSet<u64> = HashSet::new();
            while let Some((dir_record, rel_parts)) = stack.pop() {
                if !sink.file_budget_left() {
                    sink.mark_file_limit_reached();
                    break;
                }
                if !seen_records.insert(dir_record) {
                    sink.skip(format!(
                        "NTFS directory record {dir_record} was already visited and was skipped to prevent a cycle"
                    ));
                    continue;
                }
                sink.dirs += 1;
                let children = match collect_ntfs_dir_children(&ntfs, &mut slice, dir_record) {
                    Ok(result) => {
                        for diagnostic in result.diagnostics.iter().take(8) {
                            sink.skip(format!("record {dir_record}: {diagnostic}"));
                        }
                        result.children
                    }
                    Err(err) => {
                        sink.skip(format!("record {dir_record}: {err}"));
                        continue;
                    }
                };
                for child in children {
                    if !sink.file_budget_left() {
                        sink.mark_file_limit_reached();
                        break;
                    }
                    let mut child_rel = rel_parts.clone();
                    child_rel.push(child.name.clone());
                    if child.is_directory {
                        if !live_tree_depth_allowed(&child_rel) {
                            sink.skip(format!(
                                "{}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard",
                                child.name
                            ));
                            continue;
                        }
                        stack.push((child.file_record_number, child_rel));
                        continue;
                    }
                    sink.push(
                        &child_rel,
                        child.size_bytes,
                        child
                            .standard_creation_time_utc
                            .clone()
                            .or(child.creation_time_utc.clone()),
                        child
                            .standard_modification_time_utc
                            .clone()
                            .or(child.modification_time_utc.clone()),
                        child
                            .standard_access_time_utc
                            .clone()
                            .or(child.access_time_utc.clone()),
                    );
                }
            }
        }
        other => bail!("live browsing is not supported for {other} volumes"),
    }

    Ok(sink.finish())
}

/// Recursively lists files under `dir_path` for local-folder live evidence.
/// Mirrors `export_local_tree`'s walk but never reads file content. A zero
/// `max_files` is unlimited.
pub fn list_local_tree_files(
    case_path: &Path,
    evidence_id: i64,
    dir_path: &str,
    max_files: usize,
) -> Result<LiveTreeListResult> {
    let source = read_local_live_evidence(case_path, evidence_id)?;
    if source.source_kind != "folder" {
        bail!("recursive live listing is only available for folder evidence");
    }
    let (root, start) = resolve_local_folder_path(&source.source_path, dir_path)?;
    let metadata = fs::symlink_metadata(&start)
        .with_context(|| format!("reading evidence directory metadata {}", start.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("live listing does not follow symlinks: {}", start.display());
    }
    if !metadata.is_dir() {
        bail!("local live path is not a directory: {}", start.display());
    }

    let start = ensure_under_evidence_root(&root, &start)
        .with_context(|| format!("resolving evidence directory {}", start.display()))?;
    let mut sink = TreeListSink::new(max_files);
    let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(start.clone(), Vec::new())];
    let mut seen_directories = HashSet::new();
    seen_directories.insert(start);
    while let Some((dir, rel_parts)) = stack.pop() {
        if !sink.file_budget_left() {
            sink.mark_file_limit_reached();
            break;
        }
        let dir = match ensure_under_evidence_root(&root, &dir) {
            Ok(dir) => dir,
            Err(err) => {
                sink.skip(format!("{}: {err:#}", dir.display()));
                continue;
            }
        };
        let metadata = match fs::symlink_metadata(&dir) {
            Ok(metadata) => metadata,
            Err(err) => {
                sink.skip(format!("{}: {err}", dir.display()));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            sink.skip(format!("{}: symbolic link not followed", dir.display()));
            continue;
        }
        if !metadata.is_dir() {
            sink.skip(format!("{}: expected a directory", dir.display()));
            continue;
        }
        sink.dirs += 1;
        let read_dir = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(err) => {
                sink.skip(format!("{}: {err}", dir.display()));
                continue;
            }
        };
        for child in read_dir {
            if !sink.file_budget_left() {
                sink.mark_file_limit_reached();
                break;
            }
            let child = match child {
                Ok(child) => child,
                Err(err) => {
                    sink.skip(format!(
                        "{}: directory entry could not be read: {err}",
                        dir.display()
                    ));
                    continue;
                }
            };
            let child_path = child.path();
            let name = child
                .file_name()
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|| child.file_name().to_string_lossy().into_owned());
            let mut child_rel = rel_parts.clone();
            child_rel.push(name);
            let child_note = child_rel.join("/");
            let metadata = match fs::symlink_metadata(&child_path) {
                Ok(metadata) => metadata,
                Err(err) => {
                    sink.skip(format!("{child_note}: {err}"));
                    continue;
                }
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                sink.skip(format!("{child_note}: symbolic link not followed"));
                continue;
            }
            if file_type.is_dir() {
                if !live_tree_depth_allowed(&child_rel) {
                    sink.skip(format!(
                        "{child_note}: directory depth exceeds the {LIVE_TREE_MAX_PATH_DEPTH}-component corruption/cycle guard"
                    ));
                    continue;
                }
                match ensure_under_evidence_root(&root, &child_path) {
                    Ok(canonical) if seen_directories.insert(canonical.clone()) => {
                        stack.push((canonical, child_rel));
                    }
                    Ok(_) => sink.skip(format!(
                        "{child_note}: repeated canonical directory skipped to prevent a cycle"
                    )),
                    Err(err) => sink.skip(format!("{child_note}: {err:#}")),
                }
                continue;
            }
            if !file_type.is_file() {
                sink.skip(format!("{child_note}: unsupported file type"));
                continue;
            }
            sink.push(
                &child_rel,
                metadata.len(),
                system_time_rfc3339(metadata.created().ok()),
                system_time_rfc3339(metadata.modified().ok()),
                system_time_rfc3339(metadata.accessed().ok()),
            );
        }
        if sink.file_limit_reached {
            break;
        }
    }

    Ok(sink.finish())
}

/// Audit trail for a recursive live folder export.
fn evidence_live_volume_numbering(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    requested_volume_index: usize,
) -> Result<(usize, Option<usize>)> {
    let (source_kind, source_path): (String, String) = conn
        .query_row(
            "SELECT source_kind, source_path FROM evidence_sources
             WHERE case_id = ?1 AND id = ?2",
            params![case_id, evidence_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("evidence source not found for live-volume audit")?;
    live_volume_numbering(&source_kind, &source_path, requested_volume_index)
}

pub fn record_live_tree_export(
    case_path: &Path,
    evidence_id: i64,
    volume_index: usize,
    dir_path: &str,
    result: &LiveTreeExportResult,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (volume_index_zero_based, partition_number_one_based) =
        evidence_live_volume_numbering(&conn, case_id, evidence_id, volume_index)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'live.export_tree', ?2, 'evidence', ?3,
                 json_object('volume', ?4,
                             'volume_index_zero_based', ?5,
                             'partition_number_one_based', ?6,
                             'dir_path', ?7, 'output_dir', ?8,
                             'files_exported', ?9, 'bytes_written', ?10,
                             'skipped', ?11, 'oversized_files_skipped', ?12,
                             'protective_file_size_limit_bytes', ?13,
                             'file_limit', ?14, 'file_limit_reached', ?15,
                             'truncated', ?16, 'manifest_path', ?17))",
        params![
            case_id,
            actor,
            evidence_id,
            volume_index as i64,
            i64::try_from(volume_index_zero_based).unwrap_or(i64::MAX),
            partition_number_one_based.and_then(|value| i64::try_from(value).ok()),
            dir_path,
            result.output_dir,
            result.files_exported as i64,
            result.bytes_written as i64,
            result.skipped_count as i64,
            result.oversized_files_skipped as i64,
            i64::try_from(result.protective_file_size_limit_bytes).unwrap_or(i64::MAX),
            result
                .file_limit
                .and_then(|value| i64::try_from(value).ok()),
            result.file_limit_reached,
            result.truncated,
            result.manifest_path
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// Audit trail for a live (un-indexed) file export.
pub fn record_live_export(
    case_path: &Path,
    evidence_id: i64,
    volume_index: usize,
    file_path: &str,
    result: &LiveExportResult,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (volume_index_zero_based, partition_number_one_based) =
        evidence_live_volume_numbering(&conn, case_id, evidence_id, volume_index)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'live.export', ?2, 'evidence', ?3,
                 json_object('volume', ?4,
                             'volume_index_zero_based', ?5,
                             'partition_number_one_based', ?6,
                             'file_path', ?7, 'output_path', ?8,
                             'bytes_written', ?9, 'sha256', ?10))",
        params![
            case_id,
            actor,
            evidence_id,
            volume_index as i64,
            i64::try_from(volume_index_zero_based).unwrap_or(i64::MAX),
            partition_number_one_based.and_then(|value| i64::try_from(value).ok()),
            file_path,
            result.output_path,
            result.bytes_written as i64,
            result.sha256_hex
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn record_live_tree_export_with_source_kind(
    case_path: &Path,
    evidence_id: i64,
    source_kind: &str,
    volume_index: usize,
    dir_path: &str,
    result: &LiveTreeExportResult,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (volume_index_zero_based, partition_number_one_based) =
        evidence_live_volume_numbering(&conn, case_id, evidence_id, volume_index)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'live.export_tree', ?2, 'evidence', ?3,
                 json_object('source_kind', ?4, 'volume', ?5,
                             'volume_index_zero_based', ?6,
                             'partition_number_one_based', ?7,
                             'dir_path', ?8, 'output_dir', ?9, 'files_exported', ?10,
                             'bytes_written', ?11, 'skipped', ?12,
                             'oversized_files_skipped', ?13,
                             'protective_file_size_limit_bytes', ?14,
                             'file_limit', ?15, 'file_limit_reached', ?16,
                             'truncated', ?17, 'manifest_path', ?18))",
        params![
            case_id,
            actor,
            evidence_id,
            source_kind,
            volume_index as i64,
            i64::try_from(volume_index_zero_based).unwrap_or(i64::MAX),
            partition_number_one_based.and_then(|value| i64::try_from(value).ok()),
            dir_path,
            result.output_dir,
            result.files_exported as i64,
            result.bytes_written as i64,
            result.skipped_count as i64,
            result.oversized_files_skipped as i64,
            i64::try_from(result.protective_file_size_limit_bytes).unwrap_or(i64::MAX),
            result
                .file_limit
                .and_then(|value| i64::try_from(value).ok()),
            result.file_limit_reached,
            result.truncated,
            result.manifest_path
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn record_live_export_with_source_kind(
    case_path: &Path,
    evidence_id: i64,
    source_kind: &str,
    volume_index: usize,
    file_path: &str,
    result: &LiveExportResult,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (volume_index_zero_based, partition_number_one_based) =
        evidence_live_volume_numbering(&conn, case_id, evidence_id, volume_index)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'live.export', ?2, 'evidence', ?3,
                 json_object('source_kind', ?4, 'volume', ?5,
                             'volume_index_zero_based', ?6,
                             'partition_number_one_based', ?7,
                             'file_path', ?8, 'output_path', ?9,
                             'bytes_written', ?10, 'sha256', ?11))",
        params![
            case_id,
            actor,
            evidence_id,
            source_kind,
            volume_index as i64,
            i64::try_from(volume_index_zero_based).unwrap_or(i64::MAX),
            partition_number_one_based.and_then(|value| i64::try_from(value).ok()),
            file_path,
            result.output_path,
            result.bytes_written as i64,
            result.sha256_hex
        ],
    )?;
    tx.commit()?;
    Ok(())
}
