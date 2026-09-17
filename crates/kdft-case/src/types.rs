//! Foundational data types, request/response options, and result structures for KDFT-DFIR.
//!
//! This module centralizes public data models used across case management, evidence
//! processing, deep search, bookmarks, reporting, and live exploration.

#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// Case & Evidence Management
// ============================================================================

#[derive(Debug, Clone)]
pub struct CreateCaseOptions {
    pub name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub case_type: Option<String>,
    pub description: Option<String>,
    pub default_export_folder: Option<PathBuf>,
    pub temporary_folder: Option<PathBuf>,
    pub index_folder: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub enum EvidenceKind {
    Auto,
    File,
    Folder,
    Image,
}

impl EvidenceKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "file" => Ok(Self::File),
            "folder" => Ok(Self::Folder),
            "image" => Ok(Self::Image),
            other => Err(anyhow!("unsupported evidence kind: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddEvidenceOptions {
    pub path: PathBuf,
    pub kind: EvidenceKind,
    pub read_file_system_requested: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CaseInfo {
    pub id: i64,
    pub name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub case_type: Option<String>,
    pub description: Option<String>,
    pub default_export_folder: Option<String>,
    pub temporary_folder: Option<String>,
    pub index_folder: Option<String>,
    pub timezone: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct EvidenceSource {
    pub id: i64,
    pub case_id: i64,
    pub source_kind: String,
    pub source_path: String,
    pub display_name: String,
    pub size_bytes: Option<i64>,
    pub read_file_system_requested: bool,
    pub attach_status: String,
    pub encryption_status: String,
    pub attached_at: String,
    pub indexed_at: Option<String>,
    pub notes: Option<String>,
    /// Status of the most recent indexing/import job ("completed", "truncated", ...),
    /// so the UI can distinguish empty folders from not-yet-indexed ones.
    pub last_job_status: Option<String>,
    /// Whether the most recent filesystem_index job captured file content
    /// (`capture_content` processing option). `Some(false)` = metadata-only
    /// index: Deep Search content matching is unavailable for this evidence
    /// and the UI must say so. `None` = never indexed or a pre-option job.
    pub content_indexed: Option<bool>,
    /// SHA-256 of the evidence source (decoded stream for disk images),
    /// computed by the examiner-driven hash job.
    pub sha256_hex: Option<String>,
    pub hashed_at: Option<String>,
    /// Meaning of `sha256_hex`: `logical_media` for a decoded disk-image
    /// stream or `file` for ordinary file evidence.
    pub sha256_scope: Option<String>,
    /// Per-file acquisition/container hashes. This remains separate from the
    /// decoded logical-media digest so either representation can be verified.
    pub acquisition_manifest_json: Option<AcquisitionManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcquisitionSegmentManifest {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcquisitionManifest {
    pub scheme: String,
    pub segments: Vec<AcquisitionSegmentManifest>,
    pub total_size: u64,
    pub segment_count: usize,
    pub complete: bool,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct HashEvidenceResult {
    pub evidence_id: i64,
    pub sha256_hex: String,
    pub sha256_scope: String,
    pub bytes_hashed: u64,
    pub hashed_at: String,
    pub acquisition_manifest_json: Option<AcquisitionManifest>,
}

#[derive(Debug, Clone)]
pub struct CarveOptions {
    /// Cap on bytes scanned from the decoded image (0 = whole image).
    pub max_scan_bytes: u64,
    /// Cap on carved files recorded (0 = unlimited).
    pub max_files: usize,
}

#[derive(Debug, Serialize)]
pub struct CarveResult {
    pub evidence_id: i64,
    pub carved_files: usize,
    pub bytes_scanned: u64,
    pub truncated: bool,
    pub status: String,
    pub truncation_reasons: Vec<String>,
    /// Files whose end could not be established before the protective extent
    /// inspection limit. Each affected entry also carries its exact offset and
    /// reason in metadata.
    pub protective_extent_limit_hits: usize,
}

#[derive(Debug, Serialize)]
pub struct RemoveEvidenceResult {
    pub evidence_id: i64,
    pub removed_entries: i64,
    pub removed_jobs: i64,
}

#[derive(Debug, Serialize)]
pub struct RemoveBookmarkResult {
    pub bookmark_id: i64,
    pub removed_items: i64,
}

#[derive(Debug, Serialize)]
pub struct BulkBookmarkItemsResult {
    pub bookmark_id: i64,
    pub items_added: i64,
    pub skipped_entry_ids: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct RemoveBookmarkItemResult {
    pub item_id: i64,
    pub bookmark_id: i64,
}

#[derive(Debug, Serialize)]
pub struct RemoveBookmarkFolderResult {
    pub folder_id: i64,
    pub name: String,
}

#[derive(Debug, Serialize, Default)]
pub struct ClearStaleFindingsResult {
    pub removed_folders: i64,
    pub removed_bookmarks: i64,
    pub removed_items: i64,
}

#[derive(Debug, Clone)]
pub struct ProcessEvidenceOptions {
    pub evidence_id: i64,
    pub max_entries: usize,
}

/// Examiner-selectable sub-operations for one "read file system" processing
/// run, modeled on the processing-options dialogs of the major commercial
/// forensic suites: the base metadata walk is always performed, while each
/// content-touching extra is opt-in/out. Turning `capture_content` off skips
/// every per-file content read (the dominant cost on compressed containers),
/// producing a fast metadata-only index; Deep Search content matching is then
/// unavailable for that evidence until it is re-processed with content on,
/// and the job record says so.
#[derive(Debug, Clone, Copy)]
pub struct ProcessingProfile {
    /// Read each file's leading bytes into content_head for content search.
    pub capture_content: bool,
    /// Parse .eml / RFC-822 text messages into email metadata during the walk.
    pub parse_emails: bool,
    /// Parse browser profiles found on the evidence (history/downloads/etc.)
    /// into browser artifact records.
    pub parse_browsers: bool,
}

impl Default for ProcessingProfile {
    fn default() -> Self {
        Self {
            capture_content: true,
            parse_emails: true,
            parse_browsers: true,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ProcessEvidenceResult {
    pub job_id: i64,
    pub evidence_id: i64,
    pub entries_indexed: usize,
    pub truncated: bool,
    pub status: String,
    pub bookmark_items_relinked: usize,
    pub truncation_reasons: Vec<String>,
}

// ============================================================================
// Deep Search
// ============================================================================

#[derive(Debug, Clone)]
pub struct DeepSearchOptions {
    /// Text to search for. A `hex:` prefix switches to byte-pattern mode
    /// (e.g. `hex:FF D8 FF`), which scans indexed file content and reports
    /// byte offsets.
    pub query: String,
    pub evidence_id: Option<i64>,
    pub include_content: bool,
    pub max_results: usize,
    pub max_file_bytes: u64,
    /// Restrict hits to entries whose stored category fields contain this text,
    /// case-insensitive. Examiner-added categories match the same way.
    pub category: Option<String>,
    /// Restrict hits to these file extensions (without the dot).
    pub file_types: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct DeepSearchResult {
    pub evidence_id: i64,
    pub entry_id: i64,
    /// Collision-safe KDFT database/navigation key. Retained as
    /// `logical_path` for compatibility, but never presented as the source
    /// filesystem path.
    pub logical_path: String,
    pub internal_path_key: String,
    /// Parser-native path exactly as recorded on the source filesystem.
    pub source_path_exact: Option<String>,
    pub display_name: String,
    pub entry_kind: String,
    pub match_kind: String,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
}

/// Opaque-in-practice continuation returned by `deep_search_page`. The UI
/// echoes this value unchanged; fields are public only so serde clients can
/// transport it without maintaining server-side search sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeepSearchCursor {
    pub phase: String,
    pub evidence_id: Option<i64>,
    pub logical_path: Option<String>,
    pub entry_id: Option<i64>,
    pub scope_token: String,
}

#[derive(Debug, Serialize)]
pub struct DeepSearchPage {
    pub results: Vec<DeepSearchResult>,
    pub next_cursor: Option<DeepSearchCursor>,
    pub complete: bool,
    /// This is a response-page size selected by the examiner/client, not a
    /// search-coverage cap. When `complete` is false, `next_cursor` resumes
    /// at the first result not present in this response.
    pub page_size: usize,
    pub coverage: DeepSearchCoverage,
}

#[derive(Debug, Serialize)]
pub struct DeepSearchCoverage {
    /// Applies across the complete cursor sequence, subject only to the
    /// examiner's evidence/category/file-type filters.
    pub indexed_entry_scope: &'static str,
    /// Generic file content is captured during processing as a bounded head;
    /// this is a coverage limit, not a response-page limit.
    pub generic_file_content_bytes_per_file: usize,
    /// Structured parsers persist complete emitted text segments separately
    /// from the generic file head. Unsupported parts remain parser metadata.
    pub parser_derived_text_scope: &'static str,
    /// Deep Search never implies whole-device coverage; raw mode is separate.
    pub raw_evidence_bytes_included: bool,
}

// ============================================================================
// Browser Import
// ============================================================================

#[derive(Debug, Clone)]
pub struct ImportBrowserHistoryOptions {
    pub history_path: PathBuf,
    pub max_visits: usize,
    pub evidence_name: Option<String>,
}

/// Options for browser artifacts derived from an already-attached evidence
/// source. Unlike a manual browser-history import, this keeps the parsed
/// records under the parent evidence and replaces the same profile's previous
/// derived records on every run.
#[derive(Debug, Clone)]
pub struct ImportBrowserArtifactsIntoEvidenceOptions {
    pub evidence_id: i64,
    pub history_path: PathBuf,
    pub max_visits: usize,
    /// Exact profile directory path as recorded by the source filesystem.
    pub source_profile_path: String,
    pub volume_index_zero_based: Option<usize>,
    /// Auto-import label used by older builds. Matching standalone derived
    /// evidence rows are retired after their bookmarks have been migrated.
    pub legacy_evidence_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BrowserHistoryImportResult {
    pub evidence_id: i64,
    pub job_id: i64,
    pub source_path: String,
    pub entries_indexed: usize,
    pub visits_indexed: usize,
    pub bookmarks_indexed: usize,
    pub preferences_indexed: usize,
    pub truncated: bool,
    pub visit_limit_reached: bool,
    pub artifact_limit_reached: bool,
    pub limited_artifact_kinds: Vec<String>,
    pub status: String,
    pub parse_errors: Vec<String>,
    pub parse_error_count: u64,
    pub parse_error_samples_omitted: u64,
}

// ============================================================================
// Filesystem Entries & Recovery
// ============================================================================

#[derive(Debug, Serialize)]
pub struct FilesystemEntry {
    pub id: i64,
    pub case_id: i64,
    pub evidence_id: i64,
    pub parent_id: Option<i64>,
    pub logical_path: String,
    pub internal_path_key: String,
    pub source_path_exact: Option<String>,
    pub name: String,
    pub entry_kind: String,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub metadata_json: serde_json::Value,
    pub discovered_by_job_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ReadEntryBytesOptions {
    pub entry_id: i64,
    pub offset: u64,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct RecoverEntryOptions {
    pub entry_id: i64,
    pub output_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct EntryBytes {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub logical_path: String,
    pub offset: u64,
    pub requested_length: usize,
    pub bytes_read: usize,
    pub total_size: u64,
    pub eof: bool,
    pub bytes: Vec<u8>,
}

/// First authoritative decoded-media location for an indexed file. This is
/// intentionally separate from file-relative byte reads: a filesystem view
/// shows the underlying evidence stream and must never substitute a partition
/// start merely because the file's own extent is unknown.
#[derive(Debug, Clone, Serialize)]
pub struct EntryDiskLocation {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub available: bool,
    pub decoded_media_offset: Option<u64>,
    pub file_relative_offset: Option<u64>,
    pub contiguous_bytes: Option<u64>,
    pub exact_start: bool,
    pub basis: String,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawFindKind {
    Text,
    Hex,
}

impl RawFindKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "hex" => Ok(Self::Hex),
            other => Err(anyhow!("unsupported raw find kind: {other}")),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ImageRawFindResult {
    pub match_offset: Option<u64>,
    pub match_length: Option<usize>,
    pub scanned_to: u64,
    pub next_scan_offset: u64,
    pub eof: bool,
}

#[derive(Debug, Serialize)]
pub struct RecoverEntryResult {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub output_path: String,
    pub bytes_written: u64,
    pub total_size: u64,
    pub status: String,
}

// ============================================================================
// Signature Analysis
// ============================================================================

#[derive(Debug, Clone)]
pub struct AnalyzeSignaturesOptions {
    pub evidence_id: Option<i64>,
    pub max_entries: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeSignaturesResult {
    pub job_id: i64,
    pub evidence_id: Option<i64>,
    /// Number of eligible indexed-file rows present when the pass started, including checkpoints.
    pub eligible_files_total: usize,
    /// Number already committed by the current signature-analysis version and safely reused.
    pub up_to_date_files_skipped: usize,
    /// Number of pending eligible rows when this pass started.
    pub candidates_total: usize,
    /// Number of candidate rows visited, including disclosed skips/errors.
    pub candidates_processed: usize,
    pub files_examined: usize,
    pub files_skipped: usize,
    pub matches: usize,
    pub aliases: usize,
    pub mismatches: usize,
    pub unknown: usize,
    pub no_extension: usize,
    pub unreadable: usize,
    pub metadata_parse_errors: usize,
    pub errors: Vec<String>,
    pub errors_omitted: usize,
    pub truncated: bool,
    pub status: String,
}

// ============================================================================
// Bookmarks
// ============================================================================

#[derive(Debug, Serialize)]
pub struct BookmarkFolder {
    pub id: i64,
    pub case_id: i64,
    pub parent_id: Option<i64>,
    pub name: String,
    pub folder_comment: Option<String>,
    pub show_in_report: bool,
    pub report_order: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkType {
    NotableFile,
    FileGroup,
    HighlightedData,
    FolderInfo,
    Email,
    Record,
}

impl BookmarkType {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "notable_file" => Ok(Self::NotableFile),
            "file_group" => Ok(Self::FileGroup),
            "highlighted_data" => Ok(Self::HighlightedData),
            "folder_info" => Ok(Self::FolderInfo),
            "email" => Ok(Self::Email),
            "record" => Ok(Self::Record),
            other => Err(anyhow!(
                "unsupported bookmark type: {other}; expected one of notable_file, file_group, highlighted_data, folder_info, email, record"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotableFile => "notable_file",
            Self::FileGroup => "file_group",
            Self::HighlightedData => "highlighted_data",
            Self::FolderInfo => "folder_info",
            Self::Email => "email",
            Self::Record => "record",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateBookmarkOptions {
    pub folder_id: i64,
    pub bookmark_type: BookmarkType,
    pub data_type: Option<String>,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    pub in_report: bool,
    pub source_ref_json: serde_json::Value,
    pub content_ref_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Bookmark {
    pub id: i64,
    pub case_id: i64,
    pub folder_id: i64,
    pub bookmark_type: String,
    pub data_type: Option<String>,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    pub in_report: bool,
    pub source_ref_json: serde_json::Value,
    pub content_ref_json: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct CreateBookmarkItemOptions {
    pub bookmark_id: i64,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub item_order: Option<i64>,
    pub display_name: Option<String>,
    pub logical_path: Option<String>,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub item_ref_json: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct BookmarkItem {
    pub id: i64,
    pub bookmark_id: i64,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub item_order: i64,
    pub display_name: Option<String>,
    pub logical_path: Option<String>,
    pub internal_path_key: Option<String>,
    pub source_path_exact: Option<String>,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub item_ref_json: serde_json::Value,
    pub created_at: String,
}

// ============================================================================
// Reports
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ReportData {
    pub case: CaseInfo,
    pub evidence: Vec<ReportEvidence>,
    pub directory_trees: Vec<ReportDirectoryTree>,
    pub folders: Vec<ReportFolder>,
}

#[derive(Debug, Serialize)]
pub struct ReportEvidence {
    pub id: i64,
    pub display_name: String,
    pub source_kind: String,
    pub source_path: String,
    pub file_extension: Option<String>,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub sha256_scope: Option<String>,
    pub acquisition_manifest_json: Option<AcquisitionManifest>,
    pub attached_at: String,
    pub indexed_at: Option<String>,
    pub entries_indexed: i64,
    pub latest_process_job_id: Option<i64>,
    pub latest_process_job_type: Option<String>,
    pub latest_process_job_status: Option<String>,
    /// Exact examiner request. `Some(0)` means unlimited; `None` means no
    /// applicable processing job/limit was recorded.
    pub requested_entry_limit: Option<i64>,
    pub latest_process_entries_indexed: Option<i64>,
    pub processing_truncation_reason: Option<String>,
    pub processing_coverage: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportDirectoryTree {
    pub evidence_id: i64,
    pub evidence_name: String,
    pub total_entries: i64,
    pub truncated: bool,
    pub lines: Vec<ReportTreeLine>,
}

#[derive(Debug, Serialize)]
pub struct ReportTreeLine {
    pub depth: usize,
    pub name: String,
    pub entry_kind: String,
    pub size_bytes: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RenderedReport {
    pub html: String,
    /// SHA-256 of every report byte preceding the integrity footer. This is
    /// the digest embedded in the footer itself (a report cannot embed its
    /// own whole-file hash), so it is deliberately NOT the hash of the final
    /// file on disk - that one is computed after writing and recorded as
    /// `report_file_sha256`.
    pub content_prefix_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ReportFolder {
    pub id: i64,
    pub name: String,
    pub folder_comment: Option<String>,
    pub report_order: i64,
    pub bookmarks: Vec<ReportBookmark>,
}

#[derive(Debug, Serialize)]
pub struct ReportBookmark {
    pub id: i64,
    pub folder_id: i64,
    pub bookmark_type: String,
    pub data_type: Option<String>,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    pub source_ref_json: serde_json::Value,
    pub content_ref_json: serde_json::Value,
    pub created_at: String,
    pub items: Vec<BookmarkItem>,
}

// ============================================================================
// Global Options & Installed Resources
// ============================================================================

#[derive(Debug, Serialize)]
pub struct GlobalOptions {
    pub id: i64,
    pub config_root: Option<String>,
    pub evidence_library_root: Option<String>,
    pub default_storage_root: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateGlobalOptions {
    pub config_root: Option<GlobalOptionPathUpdate>,
    pub evidence_library_root: Option<GlobalOptionPathUpdate>,
    pub default_storage_root: Option<GlobalOptionPathUpdate>,
}

#[derive(Debug, Clone)]
pub enum GlobalOptionPathUpdate {
    Set(PathBuf),
    Clear,
}

impl UpdateGlobalOptions {
    pub fn has_changes(&self) -> bool {
        self.config_root.is_some()
            || self.evidence_library_root.is_some()
            || self.default_storage_root.is_some()
    }
}

#[derive(Debug, Serialize)]
pub struct InstalledResource {
    pub id: i64,
    pub resource_key: String,
    pub display_name: String,
    pub config_file_name: String,
    pub resource_kind: String,
    pub storage_scope: String,
    pub version: String,
    pub enabled: bool,
    pub notes: Option<String>,
}
