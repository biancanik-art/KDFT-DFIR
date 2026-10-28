#![forbid(unsafe_code)]

//! State definitions for the native KDFT examiner desktop workbench.

use kdft_case::CategoryEntryCursor;
use kdft_desktop_core::{
    artifacts::{ArtifactCategoryNode, ArtifactRow},
    browse::VolumeIdentity,
    bytes::ByteSourceNamespace,
    processing::{ProcessingPreset, ProcessorGroupSelection},
    reports::ReportPreview,
    search::{DeepSearchResultSummary, NativeMatchMode},
    timeline::TimelineEvent,
    CaseSummary, CreateCaseRequest, DesktopBackend, EntryPage, EvidencePage, EvidenceVolume,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Workbench layout sizes and collapsed states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkbenchLayoutState {
    pub browse_upper_height: f32,
    pub browse_lower_collapsed: bool,
    pub browse_properties_width: f32,
    pub browse_properties_collapsed: bool,
    pub artifacts_tree_width: f32,
    pub artifacts_tree_collapsed: bool,
    pub artifacts_detail_width: f32,
    pub artifacts_detail_collapsed: bool,
    pub data_interpreter_window_open: bool,
}

impl Default for WorkbenchLayoutState {
    fn default() -> Self {
        Self {
            browse_upper_height: 340.0,
            browse_lower_collapsed: false,
            browse_properties_width: 320.0,
            browse_properties_collapsed: false,
            artifacts_tree_width: 260.0,
            artifacts_tree_collapsed: false,
            artifacts_detail_width: 340.0,
            artifacts_detail_collapsed: false,
            data_interpreter_window_open: false,
        }
    }
}

/// Application theme options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AppTheme {
    Light,
    #[default]
    Dark,
    System,
}

/// Top-level workbench navigation tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TopLevelTab {
    #[default]
    Case,
    Evidence,
    Browse,
    Process,
    Artifacts,
    Search,
    Timeline,
    Bookmarks,
    Reports,
}

impl TopLevelTab {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Case => "Case",
            Self::Evidence => "Evidence",
            Self::Browse => "Browse",
            Self::Process => "Process",
            Self::Artifacts => "Artifacts",
            Self::Search => "Search",
            Self::Timeline => "Timeline",
            Self::Bookmarks => "Bookmarks",
            Self::Reports => "Reports",
        }
    }
}

/// Legacy work area enum preserved for backwards-compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WorkArea {
    #[default]
    Evidence,
    BrowseSource,
    Results,
    Bookmarks,
}

#[derive(Debug)]
pub struct OpenedCase {
    pub path: PathBuf,
    pub backend: DesktopBackend,
    pub summary: CaseSummary,
    pub page: EntryPage,
    pub evidence: Result<EvidencePage, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactSelection {
    pub entry_id: i64,
    pub generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookmarkTarget {
    IndexedResult {
        evidence_id: i64,
        entry_id: i64,
        logical_path: String,
        artifact_kind: String,
        is_deleted: bool,
    },
    SearchResult {
        evidence_id: i64,
        entry_id: i64,
        logical_path: String,
        artifact_kind: String,
        match_field: String,
        match_snippet: String,
        selection_offset: Option<u64>,
        selection_length: Option<u64>,
    },
    LiveSourceFile {
        evidence_id: i64,
        volume_index: usize,
        logical_path: String,
        is_dir: bool,
        is_deleted: bool,
    },
    Folder {
        evidence_id: i64,
        volume_index: usize,
        logical_path: String,
        is_indexed: bool,
    },
    EvidenceSource {
        evidence_id: i64,
        source_name: String,
    },
}

#[derive(Debug, Default, Clone)]
pub struct BookmarkDialogState {
    pub visible: bool,
    pub folder_name: String,
    pub title: String,
    pub comment: String,
    pub target: Option<BookmarkTarget>,
    pub is_recursive: bool,
    pub max_entries: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateFolderDialogState {
    pub visible: bool,
    pub name: String,
    pub comment: String,
    pub show_in_report: bool,
    pub error: Option<String>,
}

impl Default for CreateFolderDialogState {
    fn default() -> Self {
        Self {
            visible: false,
            name: String::new(),
            comment: String::new(),
            show_in_report: true,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RemovalTarget {
    Folder { folder_id: i64, name: String },
    Bookmark { bookmark_id: i64, title: String },
    Item { item_id: i64, name: String },
}

#[derive(Debug, Default, Clone)]
pub struct RemovalConfirmationState {
    pub visible: bool,
    pub target: Option<RemovalTarget>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct NewCaseForm {
    pub visible: bool,
    pub case_path: String,
    pub name: String,
    pub examiner_name: String,
    pub case_number: String,
    pub error: Option<String>,
}

impl NewCaseForm {
    pub fn request(&self) -> Result<CreateCaseRequest, String> {
        let path = self.case_path.trim();
        if path.is_empty() {
            return Err("Choose a destination for the new case database.".to_string());
        }
        if self.name.trim().is_empty() {
            return Err("Enter a case name.".to_string());
        }
        Ok(CreateCaseRequest {
            case_path: PathBuf::from(path),
            name: self.name.trim().to_string(),
            examiner_name: if self.examiner_name.trim().is_empty() {
                None
            } else {
                Some(self.examiner_name.trim().to_string())
            },
            case_number: if self.case_number.trim().is_empty() {
                None
            } else {
                Some(self.case_number.trim().to_string())
            },
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct BitLockerDialogState {
    pub visible: bool,
    pub is_unlocking: bool,
    pub evidence_id: i64,
    pub volume_index: usize,
    pub volume_label: String,
    pub is_recovery_key: bool,
    pub credential_input: String,
    pub reveal_credential: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntakeIntegrityChoice {
    #[default]
    VerifyNow,
    ComputeOnly,
    Defer,
    Skip,
}

#[derive(Debug, Clone)]
pub struct EvidenceIntakeDialogState {
    pub visible: bool,
    pub source_path: PathBuf,
    pub detected_kind: kdft_desktop_core::NativeEvidenceKind,
    pub segment_count: usize,
    pub segment_scheme: String,
    pub display_name: String,
    pub timezone: String,
    pub timezone_filter: String,
    pub integrity_choice: IntakeIntegrityChoice,
    pub expected_sha256: String,
    pub skip_reason: String,
    pub scope_description: String,
    pub error: Option<String>,
}

impl Default for EvidenceIntakeDialogState {
    fn default() -> Self {
        Self {
            visible: false,
            source_path: PathBuf::new(),
            detected_kind: kdft_desktop_core::NativeEvidenceKind::Image,
            segment_count: 1,
            segment_scheme: "single_container_file".to_string(),
            display_name: String::new(),
            timezone: "UTC".to_string(),
            timezone_filter: String::new(),
            integrity_choice: IntakeIntegrityChoice::VerifyNow,
            expected_sha256: String::new(),
            skip_reason: String::new(),
            scope_description: String::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaseSettingsDialogState {
    pub visible: bool,
    pub current_timezone: String,
    pub selected_timezone: String,
    pub timezone_filter: String,
    pub error: Option<String>,
}

impl Default for CaseSettingsDialogState {
    fn default() -> Self {
        Self {
            visible: false,
            current_timezone: "UTC".to_string(),
            selected_timezone: "UTC".to_string(),
            timezone_filter: String::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessingOptionsDialogState {
    pub visible: bool,
    pub evidence_id: i64,
    pub evidence_name: String,
    pub evidence_path: String,
    pub volumes: Vec<EvidenceVolume>,
    pub selected_volumes: Vec<usize>,
    pub preset: ProcessingPreset,
    pub groups: ProcessorGroupSelection,
    pub content_capture_enabled: bool,
    pub capture_limit: String,
    pub max_entries: String,
    pub error: Option<String>,
}

impl Default for ProcessingOptionsDialogState {
    fn default() -> Self {
        Self {
            visible: false,
            evidence_id: 0,
            evidence_name: String::new(),
            evidence_path: String::new(),
            volumes: Vec::new(),
            selected_volumes: Vec::new(),
            preset: ProcessingPreset::FullForensicAnalysis,
            groups: ProcessorGroupSelection::default(),
            // Full Forensic is the default preset, so its bounded content
            // capture setting must also be enabled by default. Keeping this
            // false silently overrode ProcessorGroupSelection's preset value
            // when the job was launched and left Deep Search path-only.
            content_capture_enabled: true,
            capture_limit: "64 KiB".to_string(),
            max_entries: "0".to_string(),
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HexViewerState {
    pub active: bool,
    pub source_namespace: ByteSourceNamespace,
    pub evidence_id: Option<i64>,
    pub volume_index: usize,
    pub volume_identity: Option<VolumeIdentity>,
    pub request_id: u64,
    pub logical_path: String,
    pub entry_id: Option<i64>,
    /// Indexed identity used only for coordinate lookup while Browse bytes are
    /// still read from the live evidence path.
    pub mapping_entry_id: Option<i64>,
    pub current_offset: u64,
    pub total_size: Option<u64>,
    pub bytes_per_row: usize,
    pub selected_byte_offset: Option<usize>,
    /// Length of the highlighted range beginning at `selected_byte_offset`.
    /// Manual byte selection uses one; search matches retain their bounded
    /// logical-file selection length.
    pub selected_byte_length: Option<usize>,
    /// Page-relative byte where a pointer drag began.  This is deliberately
    /// separate from the normalized range start so backwards selections stay
    /// stable and auditable.
    pub selection_drag_anchor: Option<usize>,
    /// Exact volume-relative byte represented by `current_offset`, when the
    /// reader proved a direct contiguous mapping for the loaded page.
    pub mapped_filesystem_offset: Option<u64>,
    /// Exact decoded-media byte represented by `current_offset`, when proven.
    pub mapped_decoded_media_offset: Option<u64>,
    pub partition_start_offset: Option<u64>,
    /// NTFS FILE record size read from the mounted filesystem.  Used only for
    /// /$MFT coordinates; never guessed from a common default.
    pub ntfs_file_record_size: Option<u64>,
    pub mapping_provenance: Option<String>,
    pub mapping_warnings: Vec<String>,
    pub copy_notice: Option<String>,
    pub loaded_bytes: Vec<u8>,
    pub jump_offset_input: String,
    pub loading: bool,
    pub error: Option<String>,
}

impl Default for HexViewerState {
    fn default() -> Self {
        Self {
            active: false,
            source_namespace: ByteSourceNamespace::LogicalFile,
            evidence_id: None,
            volume_index: 0,
            volume_identity: None,
            request_id: 0,
            logical_path: String::new(),
            entry_id: None,
            mapping_entry_id: None,
            current_offset: 0,
            total_size: None,
            bytes_per_row: 16,
            selected_byte_offset: None,
            selected_byte_length: None,
            selection_drag_anchor: None,
            mapped_filesystem_offset: None,
            mapped_decoded_media_offset: None,
            partition_start_offset: None,
            ntfs_file_record_size: None,
            mapping_provenance: None,
            mapping_warnings: Vec::new(),
            copy_notice: None,
            loaded_bytes: Vec::new(),
            jump_offset_input: "0".to_string(),
            loading: false,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataInterpreterState {
    pub cursor_offset: u64,
    pub endianness_le: bool,
}

impl Default for DataInterpreterState {
    fn default() -> Self {
        Self {
            cursor_offset: 0,
            endianness_le: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArtifactsViewState {
    pub category_tree: Vec<ArtifactCategoryNode>,
    pub selected_category: Option<String>,
    pub selected_sub_category: Option<String>,
    pub search_filter: String,
    pub extension_filter: String,
    pub deleted_only: bool,
    pub current_page: usize,
    pub page_size: usize,
    pub cursor: Option<CategoryEntryCursor>,
    pub cursor_history: Vec<Option<CategoryEntryCursor>>,
    pub current_rows: Vec<ArtifactRow>,
    pub has_more: bool,
    pub total_count: Option<i64>,
    pub loading: bool,
    pub error: Option<String>,
    pub cached_generation: Option<i64>,
    pub active_tree_request_id: u64,
    pub active_page_request_id: u64,
    pub selected_evidence_id: Option<i64>,
    pub selected_artifact: Option<ArtifactRow>,
}

impl ArtifactsViewState {
    pub fn invalidate(&mut self) {
        self.category_tree.clear();
        self.current_rows.clear();
        self.cursor = None;
        self.cursor_history.clear();
        self.current_page = 0;
        self.total_count = None;
        self.cached_generation = None;
        self.selected_artifact = None;
        self.error = None;
        self.loading = false;
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchViewState {
    pub query: String,
    pub match_mode: NativeMatchMode,
    pub results: Vec<DeepSearchResultSummary>,
    pub cursor: Option<kdft_case::DeepSearchCursor>,
    pub cursor_history: Vec<Option<kdft_case::DeepSearchCursor>>,
    pub page_index: usize,
    pub has_more: bool,
    pub total_matches: Option<usize>,
    pub coverage_statement: Option<String>,
    pub loading: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TimelineViewState {
    pub category_filter: String,
    pub type_filter: String,
    pub text_filter: String,
    pub from_date: String,
    pub to_date: String,
    pub events: Vec<TimelineEvent>,
    pub page: usize,
    pub page_size: usize,
    pub has_more: bool,
    pub total_matching: usize,
    pub loading: bool,
    pub error: Option<String>,
}

impl Default for TimelineViewState {
    fn default() -> Self {
        Self {
            category_filter: String::new(),
            type_filter: String::new(),
            text_filter: String::new(),
            from_date: String::new(),
            to_date: String::new(),
            events: Vec::new(),
            page: 0,
            page_size: 100,
            has_more: false,
            total_matching: 0,
            loading: false,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportViewState {
    pub report_type: String,
    pub include_metadata: bool,
    pub include_artifacts: bool,
    pub include_timeline: bool,
    pub include_bookmarks: bool,
    pub preview: Option<ReportPreview>,
    pub export_status: Option<String>,
    pub loading: bool,
    pub error: Option<String>,
}

impl Default for ReportViewState {
    fn default() -> Self {
        Self {
            report_type: "html".to_string(),
            include_metadata: true,
            include_artifacts: true,
            include_timeline: true,
            include_bookmarks: true,
            preview: None,
            export_status: None,
            loading: false,
            error: None,
        }
    }
}
