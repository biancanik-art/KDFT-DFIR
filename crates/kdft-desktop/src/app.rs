#![forbid(unsafe_code)]

//! Main desktop application implementation and examiner workbench.

use crate::dialogs::{bitlocker, bookmark, case_settings, intake, processing_options};
use crate::state::*;
use crate::views::{
    artifacts, bookmarks, case, evidence, hex_viewer, inspector, processing, reports, search,
    source_browser, splitter, timeline,
};
use crate::workers::*;
use eframe::egui::{self, Color32, RichText};
use kdft_desktop_core::{
    artifacts::{ArtifactPageQuery, NativeArtifactService},
    bytes::{BoundedByteRequest, ByteSourceNamespace, NativeByteService},
    processing::{NativeAnalysisConfig, NativeProcessingService},
    reports::NativeReportService,
    search::{NativeSearchQuery, NativeSearchService},
    timeline::{NativeTimelineService, TimelineQuery},
    unlock::{TransientBitLockerCredential, TransientUnlockManager},
    *,
};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

pub const APP_TITLE: &str = "KDFT Desktop";
pub const MAX_OPERATION_WARNINGS: usize = 8;
pub const CLOSE_GRACE_PERIOD: Duration = Duration::from_secs(15);

pub struct KDFTDesktopApp {
    pub case_path: String,
    pub opened_path: Option<PathBuf>,
    pub backend: Option<DesktopBackend>,
    pub summary: Option<CaseSummary>,
    pub page: Option<EntryPage>,
    pub page_starts: Vec<Option<EntryCursor>>,
    pub page_index: usize,
    pub evidence_page: Option<EvidencePage>,
    pub evidence_page_starts: Vec<Option<i64>>,
    pub evidence_page_index: usize,
    pub evidence_error: Option<String>,
    pub selected_evidence_id: Option<i64>,
    pub processing_profile: NativeProcessingProfile,
    pub max_entries: String,
    pub pending: Option<Receiver<WorkerResult>>,
    pub processing: Option<ProcessingJob>,
    pub last_process: Option<ProcessEvidenceSummary>,
    pub new_case: NewCaseForm,
    pub status: String,
    pub error: Option<String>,
    pub operation_warnings: Vec<String>,
    pub operation_warnings_omitted: usize,
    pub close_after_background_work: bool,
    pub close_request_started_at: Option<std::time::Instant>,
    pub view_stale: bool,
    pub selected_artifact: Option<ArtifactSelection>,
    pub artifact_detail: Option<ArtifactDetail>,
    pub artifact_detail_error: Option<String>,
    pub artifact_pending: Option<Receiver<ArtifactWorkerResult>>,
    pub active_work_area: WorkArea,
    pub browse_evidence_id: Option<i64>,
    pub browse_evidence_name: String,
    pub browse_volumes: Vec<EvidenceVolume>,
    pub browse_selected_volume: usize,
    pub browse_path: String,
    pub browse_history_back: Vec<String>,
    pub browse_history_forward: Vec<String>,
    pub browse_page: Option<BrowseDirectoryPage>,
    pub browse_offset: usize,
    pub browse_loading: bool,
    pub browse_error: Option<String>,
    pub browse_pending: Option<Receiver<BrowseWorkerResult>>,
    pub bookmark_folders: Vec<BookmarkFolderSummary>,
    pub bookmark_folders_page: Option<BookmarkFoldersPage>,
    pub bookmark_folders_cursors: Vec<Option<BookmarkCursor>>,
    pub bookmark_folders_page_index: usize,
    pub selected_bookmark_folder: Option<i64>,
    pub bookmarks: Vec<BookmarkSummary>,
    pub bookmarks_page: Option<BookmarksPage>,
    pub bookmarks_cursors: Vec<Option<BookmarkCursor>>,
    pub bookmarks_page_index: usize,
    pub selected_bookmark_id: Option<i64>,
    pub bookmark_items: Vec<BookmarkItemSummary>,
    pub bookmark_items_page: Option<BookmarkItemsPage>,
    pub bookmark_items_cursors: Vec<Option<BookmarkCursor>>,
    pub bookmark_items_page_index: usize,
    pub selected_bookmark_item_id: Option<i64>,
    pub selected_bookmark_item_detail: Option<BookmarkItemDetail>,
    pub bookmark_loading: bool,
    pub bookmark_error: Option<String>,
    pub bookmark_pending: Option<Receiver<BookmarkWorkerResult>>,
    pub bookmark_dialog: BookmarkDialogState,
    pub create_folder_dialog: CreateFolderDialogState,
    pub removal_dialog: RemovalConfirmationState,
    pub resuming_bookmark_id: Option<i64>,
    pub browse_request_id: u64,
    pub hex_request_id: u64,
    pub active_volume_identity: Option<VolumeIdentity>,
    pub browse_history: Vec<BrowseHistoryEntry>,
    pub selected_browser_entry: Option<crate::views::source_browser::SelectedBrowserEntry>,
    pub layout: WorkbenchLayoutState,
    pub job_history: Vec<ProcessingJobRecord>,
    pub coverage_records: Vec<ProcessorCoverageRecord>,
    pub processing_history_pending: Option<Receiver<ProcessingHistoryWorkerResult>>,
    pub processing_history_request_id: u64,
    pub last_processing_history_refresh: Option<std::time::Instant>,
    pub processing_history_error: Option<String>,

    // Enhanced Workbench State
    pub active_tab: TopLevelTab,
    pub theme: AppTheme,
    pub unlock_manager: TransientUnlockManager,
    pub unlock_pending: Option<Receiver<UnlockWorkerResult>>,
    pub bitlocker_dialog: BitLockerDialogState,
    pub processing_options_dialog: ProcessingOptionsDialogState,
    pub hex_viewer_state: HexViewerState,
    pub data_interpreter_state: DataInterpreterState,
    pub hex_pending: Option<Receiver<HexWorkerResult>>,
    pub artifacts_state: ArtifactsViewState,
    pub artifacts_tree_pending: Option<Receiver<ArtifactsTreeWorkerResult>>,
    pub artifacts_page_pending: Option<Receiver<ArtifactsPageWorkerResult>>,
    pub artifacts_probe_pending: Option<Receiver<ArtifactsProbeWorkerResult>>,
    pub artifacts_tree_request_id: u64,
    pub artifacts_page_request_id: u64,
    pub artifacts_probe_request_id: u64,
    pub last_probe_time: Option<std::time::Instant>,
    pub inspector_pinned: bool,
    pub inspector_origin: Option<TopLevelTab>,
    pub search_state: SearchViewState,
    pub search_pending: Option<Receiver<SearchWorkerResult>>,
    pub timeline_state: TimelineViewState,
    pub timeline_pending: Option<Receiver<TimelineWorkerResult>>,
    pub report_state: ReportViewState,
    pub report_pending: Option<Receiver<ReportWorkerResult>>,
    pub export_pending: Option<Receiver<ExportWorkerResult>>,
    pub export_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub hash_pending: Option<Receiver<HashWorkerResult>>,
    pub hash_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub evidence_intake_dialog: EvidenceIntakeDialogState,
    pub case_settings_dialog: CaseSettingsDialogState,
    pub integrity_pending: Option<Receiver<IntegrityWorkerResult>>,
    pub integrity_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub integrity_running_id: Option<i64>,
    pub integrity_progress: Option<(u64, Option<u64>)>,
    pub folder_export_pending: Option<Receiver<FolderExportWorkerResult>>,
    pub folder_export_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub folder_hash_pending: Option<Receiver<FolderHashWorkerResult>>,
    pub folder_hash_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub pending_intake_verification: Option<kdft_desktop_core::EvidenceIntegrityRequest>,
    pub hex_viewer_origin_tab: Option<TopLevelTab>,
}

impl KDFTDesktopApp {
    pub fn new(_context: &eframe::CreationContext<'_>, initial_case_path: Option<PathBuf>) -> Self {
        Self::from_initial_path(initial_case_path)
    }

    pub fn empty() -> Self {
        Self::from_initial_path(None)
    }

    pub fn from_initial_path(initial_case_path: Option<PathBuf>) -> Self {
        let mut app = Self {
            case_path: initial_case_path
                .as_ref()
                .map_or_else(String::new, |path| path.display().to_string()),
            opened_path: None,
            backend: None,
            summary: None,
            page: None,
            page_starts: Vec::new(),
            page_index: 0,
            evidence_page: None,
            evidence_page_starts: Vec::new(),
            evidence_page_index: 0,
            evidence_error: None,
            selected_evidence_id: None,
            processing_profile: NativeProcessingProfile::default(),
            max_entries: "0".to_string(),
            pending: None,
            processing: None,
            last_process: None,
            new_case: NewCaseForm::default(),
            status: "Create a case or open an existing KDFT case database.".to_string(),
            error: None,
            operation_warnings: Vec::new(),
            operation_warnings_omitted: 0,
            close_after_background_work: false,
            close_request_started_at: None,
            view_stale: false,
            selected_artifact: None,
            artifact_detail: None,
            artifact_detail_error: None,
            artifact_pending: None,
            active_work_area: WorkArea::Evidence,
            browse_evidence_id: None,
            browse_evidence_name: String::new(),
            browse_volumes: Vec::new(),
            browse_selected_volume: 0,
            browse_path: "/".to_string(),
            browse_history_back: Vec::new(),
            browse_history_forward: Vec::new(),
            browse_page: None,
            browse_offset: 0,
            browse_loading: false,
            browse_error: None,
            browse_pending: None,
            bookmark_folders: Vec::new(),
            bookmark_folders_page: None,
            bookmark_folders_cursors: vec![None],
            bookmark_folders_page_index: 0,
            selected_bookmark_folder: None,
            bookmarks: Vec::new(),
            bookmarks_page: None,
            bookmarks_cursors: vec![None],
            bookmarks_page_index: 0,
            selected_bookmark_id: None,
            bookmark_items: Vec::new(),
            bookmark_items_page: None,
            bookmark_items_cursors: vec![None],
            bookmark_items_page_index: 0,
            selected_bookmark_item_id: None,
            selected_bookmark_item_detail: None,
            bookmark_loading: false,
            bookmark_error: None,
            bookmark_pending: None,
            bookmark_dialog: BookmarkDialogState::default(),
            create_folder_dialog: CreateFolderDialogState::default(),
            removal_dialog: RemovalConfirmationState::default(),
            resuming_bookmark_id: None,
            browse_request_id: 0,
            hex_request_id: 0,
            active_volume_identity: None,
            browse_history: Vec::new(),
            selected_browser_entry: None,
            layout: WorkbenchLayoutState::default(),
            job_history: Vec::new(),
            coverage_records: Vec::new(),
            processing_history_pending: None,
            processing_history_request_id: 0,
            last_processing_history_refresh: None,
            processing_history_error: None,

            active_tab: TopLevelTab::Case,
            theme: AppTheme::Dark,
            unlock_manager: TransientUnlockManager::default(),
            unlock_pending: None,
            bitlocker_dialog: BitLockerDialogState::default(),
            processing_options_dialog: ProcessingOptionsDialogState::default(),
            hex_viewer_state: HexViewerState::default(),
            data_interpreter_state: DataInterpreterState::default(),
            hex_pending: None,
            artifacts_state: ArtifactsViewState::default(),
            artifacts_tree_pending: None,
            artifacts_page_pending: None,
            artifacts_probe_pending: None,
            artifacts_tree_request_id: 0,
            artifacts_page_request_id: 0,
            artifacts_probe_request_id: 0,
            last_probe_time: None,
            inspector_pinned: false,
            inspector_origin: None,
            search_state: SearchViewState::default(),
            search_pending: None,
            timeline_state: TimelineViewState::default(),
            timeline_pending: None,
            report_state: ReportViewState::default(),
            report_pending: None,
            export_pending: None,
            export_cancel: None,
            hash_pending: None,
            hash_cancel: None,
            evidence_intake_dialog: EvidenceIntakeDialogState::default(),
            case_settings_dialog: CaseSettingsDialogState::default(),
            integrity_pending: None,
            integrity_cancel: None,
            integrity_running_id: None,
            integrity_progress: None,
            folder_export_pending: None,
            folder_export_cancel: None,
            folder_hash_pending: None,
            folder_hash_cancel: None,
            pending_intake_verification: None,
            hex_viewer_origin_tab: None,
        };

        if let Some(path) = initial_case_path {
            if path.exists() {
                let ctx = egui::Context::default();
                app.begin_open(ctx);
            }
        }

        app
    }

    pub fn is_busy(&self) -> bool {
        self.pending.is_some()
            || self.processing.is_some()
            || self.bookmark_pending.is_some()
            || self.export_pending.is_some()
            || self.hash_pending.is_some()
            || self.integrity_pending.is_some()
            || self.folder_export_pending.is_some()
            || self.folder_hash_pending.is_some()
    }

    pub fn clear_inspector(&mut self) {
        self.selected_artifact = None;
        self.artifact_detail = None;
        self.artifact_detail_error = None;
        self.artifact_pending = None;
        self.inspector_origin = None;
        self.clear_hex_viewer();
    }

    pub fn clear_hex_viewer(&mut self) {
        // Invalidate an in-flight read before dropping its receiver so a late
        // result can never repopulate a viewer that has changed ownership.
        self.hex_request_id = self.hex_request_id.wrapping_add(1);
        self.hex_pending = None;
        self.hex_viewer_origin_tab = None;
        self.hex_viewer_state = HexViewerState::default();
    }

    /// Clear the unpinned Browse selection and its byte-view ownership.
    /// Every directory/evidence/volume transition must call this before the
    /// replacement listing is requested.
    pub fn clear_browse_preview(&mut self) {
        self.selected_browser_entry = None;
        self.clear_hex_viewer();
    }

    pub fn clear_opened_view(&mut self) {
        self.clear_inspector();
        self.inspector_pinned = false;
        self.artifacts_probe_pending = None;
        self.last_probe_time = None;
        self.processing_history_pending = None;
        self.processing_history_request_id = self.processing_history_request_id.wrapping_add(1);
        self.last_processing_history_refresh = None;
        self.processing_history_error = None;
        self.job_history.clear();
        self.coverage_records.clear();
        self.opened_path = None;
        self.backend = None;
        self.summary = None;
        self.page = None;
        self.page_starts.clear();
        self.page_index = 0;
        self.evidence_page = None;
        self.evidence_page_starts.clear();
        self.evidence_page_index = 0;
        self.evidence_error = None;
        self.selected_evidence_id = None;
        self.last_process = None;
        self.view_stale = false;
        self.browse_evidence_id = None;
        self.browse_evidence_name.clear();
        self.browse_volumes.clear();
        self.browse_selected_volume = 0;
        self.browse_path = "/".to_string();
        self.browse_history_back.clear();
        self.browse_history_forward.clear();
        self.browse_page = None;
        self.browse_offset = 0;
        self.browse_loading = false;
        self.browse_error = None;
        self.browse_pending = None;
        self.bookmark_folders.clear();
        self.selected_bookmark_folder = None;
        self.bookmarks.clear();
        self.selected_bookmark_id = None;
        self.bookmark_items.clear();
        self.bookmark_loading = false;
        self.bookmark_error = None;
        self.bookmark_pending = None;
        self.resuming_bookmark_id = None;
        self.unlock_manager.clear();
        self.unlock_pending = None;
        self.hex_viewer_state = HexViewerState::default();
        self.artifacts_state = ArtifactsViewState::default();
        self.artifacts_tree_pending = None;
        self.artifacts_page_pending = None;
        self.search_state = SearchViewState::default();
        self.timeline_state = TimelineViewState::default();
        self.report_state = ReportViewState::default();
    }

    pub fn install_opened(&mut self, opened: OpenedCase) {
        self.processing_history_pending = None;
        self.processing_history_request_id = self.processing_history_request_id.wrapping_add(1);
        self.last_processing_history_refresh = None;
        self.processing_history_error = None;
        let new_gen = opened.summary.generation;
        let old_gen = self.summary.as_ref().map(|s| s.generation);
        if old_gen != Some(new_gen) {
            if !self.inspector_pinned {
                self.clear_inspector();
            }
            self.hex_viewer_state = HexViewerState::default();
            self.artifacts_state.invalidate();
            self.artifacts_tree_pending = None;
            self.artifacts_page_pending = None;
            self.artifacts_probe_pending = None;
        }
        self.opened_path = Some(opened.path.clone());
        self.case_path = opened.path.display().to_string();
        self.backend = Some(opened.backend);
        self.summary = Some(opened.summary);
        self.page = Some(opened.page);
        self.page_starts = vec![None];
        self.page_index = 0;
        self.view_stale = false;
        self.evidence_page_starts = vec![None];
        self.evidence_page_index = 0;
        match opened.evidence {
            Ok(page) => {
                self.selected_evidence_id = retained_selection(self.selected_evidence_id, &page);
                self.evidence_page = Some(page);
                self.evidence_error = None;
            }
            Err(error) => {
                self.evidence_page = None;
                self.evidence_error = Some(error);
                self.selected_evidence_id = None;
            }
        }
        self.browse_page = None;
        self.browse_error = None;
        self.refresh_processing_history();
    }

    pub fn refresh_processing_history(&mut self) {
        if let Some(case_path) = &self.opened_path {
            let jobs = NativeProcessingService::list_jobs(case_path)
                .map_err(|error| format!("job history: {error}"));
            let coverage =
                NativeProcessingService::get_coverage_records(case_path, self.selected_evidence_id)
                    .map_err(|error| format!("processor coverage: {error}"));
            self.install_processing_history_results(jobs, Some(coverage));
        }
    }

    fn install_processing_history_results(
        &mut self,
        jobs: Result<Vec<ProcessingJobRecord>, String>,
        coverage: Option<Result<Vec<ProcessorCoverageRecord>, String>>,
    ) {
        let mut errors = Vec::new();
        match jobs {
            Ok(jobs) => self.job_history = jobs,
            Err(error) => errors.push(error),
        }
        if let Some(coverage) = coverage {
            match coverage {
                Ok(coverage) => self.coverage_records = coverage,
                Err(error) => errors.push(error),
            }
        }
        self.processing_history_error = if errors.is_empty() {
            None
        } else {
            Some(format!(
                "Could not refresh persisted processing status; the last successful history remains displayed. {}",
                errors.join("; ")
            ))
        };
    }

    pub fn begin_processing_history_refresh(&mut self, context: egui::Context) {
        if self.processing_history_pending.is_some() {
            return;
        }
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        let evidence_id = self.selected_evidence_id;
        self.processing_history_request_id = self.processing_history_request_id.wrapping_add(1);
        let request_id = self.processing_history_request_id;
        let worker_case_path = case_path.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let jobs = NativeProcessingService::list_jobs(&worker_case_path)
                .map_err(|error| format!("job history: {error}"));
            let coverage =
                NativeProcessingService::get_coverage_records(&worker_case_path, evidence_id)
                    .map_err(|error| format!("processor coverage: {error}"));
            let _ = sender.send(ProcessingHistoryWorkerResult {
                request_id,
                case_path: worker_case_path,
                evidence_id,
                jobs,
                coverage: Some(coverage),
            });
            context.request_repaint();
        });
        self.processing_history_pending = Some(receiver);
    }

    /// Refresh only the lightweight persisted job/stage rows while processing
    /// is active. Coverage performs full-table aggregate scans and previously
    /// blocked this channel, making the job history appear frozen for hours.
    pub fn begin_live_job_history_refresh(&mut self, context: egui::Context) {
        if self.processing_history_pending.is_some() {
            return;
        }
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        let evidence_id = self.selected_evidence_id;
        self.processing_history_request_id = self.processing_history_request_id.wrapping_add(1);
        let request_id = self.processing_history_request_id;
        let worker_case_path = case_path.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let jobs = NativeProcessingService::list_jobs(&worker_case_path)
                .map_err(|error| format!("job history: {error}"));
            let _ = sender.send(ProcessingHistoryWorkerResult {
                request_id,
                case_path: worker_case_path,
                evidence_id,
                jobs,
                coverage: None,
            });
            context.request_repaint();
        });
        self.processing_history_pending = Some(receiver);
    }

    pub fn clear_operation_warnings(&mut self) {
        self.operation_warnings.clear();
        self.operation_warnings_omitted = 0;
    }

    pub fn push_operation_warning(&mut self, warning: String) {
        if self.operation_warnings.len() < MAX_OPERATION_WARNINGS {
            self.operation_warnings.push(warning);
        } else {
            self.operation_warnings_omitted += 1;
        }
    }

    pub fn install_operation_warnings(&mut self, warnings: Vec<String>, omitted: usize) {
        let (warnings, omitted) = bound_operation_warnings(warnings, omitted);
        self.operation_warnings = warnings;
        self.operation_warnings_omitted = omitted;
    }

    pub fn generation_matches(&self, received: i64) -> bool {
        self.summary
            .as_ref()
            .is_none_or(|summary| summary.generation == received)
    }

    pub fn lock_stale_inspector(&mut self, message: String) {
        self.view_stale = true;
        self.clear_inspector();
        self.error = Some(message.clone());
        self.artifact_detail_error = Some(message);
    }

    pub fn mark_view_stale(&mut self, message: String) {
        self.view_stale = true;
        self.clear_inspector();
        self.push_operation_warning(message);
    }

    pub fn worker_error(&mut self, error: String, status: &str) {
        self.error = Some(error);
        self.status = if self.backend.is_some() {
            format!("{status} The current case remains displayed.")
        } else {
            status.to_string()
        };
    }

    pub fn handle_close_request(&mut self, context: &egui::Context) {
        if !context.input(|input| input.viewport().close_requested()) || !self.is_busy() {
            return;
        }

        // A second close request is an explicit examiner override. Let the
        // viewport close even if a defective worker ignored cooperative
        // cancellation; durable orphan reconciliation will run next time the
        // case opens.
        if self.close_after_background_work {
            return;
        }

        context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        self.close_after_background_work = true;
        self.close_request_started_at = Some(std::time::Instant::now());
        self.request_background_cancellation();
        self.status = format!(
            "Close requested. Cancelling background work; the window will close after graceful shutdown or after {} seconds.",
            CLOSE_GRACE_PERIOD.as_secs()
        );
        context.request_repaint_after(Duration::from_millis(100));
    }

    pub(crate) fn request_background_cancellation(&self) {
        if let Some(job) = &self.processing {
            job.tracker.request_cancellation();
        }
        for cancellation in [
            self.export_cancel.as_ref(),
            self.hash_cancel.as_ref(),
            self.integrity_cancel.as_ref(),
            self.folder_export_cancel.as_ref(),
            self.folder_hash_cancel.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            cancellation.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub(crate) fn deferred_close_ready(&self) -> bool {
        self.close_after_background_work
            && (!self.is_busy()
                || self
                    .close_request_started_at
                    .is_some_and(|started| started.elapsed() >= CLOSE_GRACE_PERIOD))
    }

    pub fn poll_deferred_close(&mut self, context: &egui::Context) {
        if !self.close_after_background_work {
            return;
        }
        if self.deferred_close_ready() {
            context.send_viewport_cmd(egui::ViewportCommand::Close);
        } else {
            context.request_repaint_after(Duration::from_millis(100));
        }
    }

    // --- Background Operations ---

    pub fn begin_open(&mut self, context: egui::Context) {
        if self.is_busy() {
            return;
        }
        if self.case_path.trim().is_empty() {
            self.error = Some("Choose a case database first.".to_string());
            return;
        }
        let path = PathBuf::from(self.case_path.trim());
        self.error = None;
        self.clear_operation_warnings();
        self.status = format!("Opening {}…", path.display());
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = NativeProcessingService::reconcile_orphaned_jobs_in_case(&path);
            let _ = sender.send(WorkerResult::Open(open_case(&path)));
            context.request_repaint();
        });
        self.pending = Some(receiver);
    }

    pub fn begin_create(&mut self, context: egui::Context) {
        if self.is_busy() {
            return;
        }
        let request = match self.new_case.request() {
            Ok(request) => request,
            Err(error) => {
                self.new_case.error = Some(error);
                return;
            }
        };
        let case_path = request.case_path.clone();
        self.new_case.error = None;
        self.error = None;
        self.clear_operation_warnings();
        self.status = format!("Creating {}…", case_path.display());
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mutation =
                NativeWorkflowService::create_case(request).map_err(|error| error.to_string());
            let refreshed = mutation.as_ref().ok().map(|_| open_case(&case_path));
            let _ = sender.send(WorkerResult::Create {
                mutation,
                refreshed,
            });
            context.request_repaint();
        });
        self.pending = Some(receiver);
    }

    pub fn begin_attach(
        &mut self,
        context: egui::Context,
        evidence_path: PathBuf,
        kind: NativeEvidenceKind,
    ) {
        self.begin_attach_with_options(context, evidence_path, kind, None, None, None, None, None);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_attach_with_options(
        &mut self,
        context: egui::Context,
        evidence_path: PathBuf,
        kind: NativeEvidenceKind,
        display_name: Option<String>,
        display_timezone: Option<String>,
        integrity_status: Option<String>,
        expected_sha256: Option<String>,
        integrity_details_json: Option<String>,
    ) {
        if self.is_busy() {
            return;
        }
        if self.view_stale {
            self.error =
                Some("Reopen the case before attaching more evidence to a stale view.".to_string());
            return;
        }
        let Some(case_path) = self.opened_path.clone() else {
            self.error = Some("Create or open a case before attaching evidence.".to_string());
            return;
        };
        let source_name = display_name
            .clone()
            .or_else(|| {
                evidence_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "Evidence source".to_string());

        let request = AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path,
            kind,
            read_file_system_requested: true,
            notes: None,
            display_timezone,
            display_name,
            integrity_status,
            expected_sha256,
            integrity_details_json,
        };
        self.error = None;
        self.clear_operation_warnings();
        self.status = format!("Attaching {source_name} without processing it…");
        let worker_name = source_name.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mutation =
                NativeWorkflowService::attach_evidence(request).map_err(|error| error.to_string());
            let refreshed = mutation.as_ref().ok().map(|_| open_case(&case_path));
            let _ = sender.send(WorkerResult::Attach {
                mutation,
                refreshed,
                source_name: worker_name,
            });
            context.request_repaint();
        });
        self.pending = Some(receiver);
    }

    pub fn open_intake_wizard(&mut self, path: PathBuf, detected_kind: NativeEvidenceKind) {
        let (segment_scheme, segment_count, scope_description) = match detected_kind {
            NativeEvidenceKind::Image => {
                match kdft_desktop_core::detect_acquisition_segments(&path) {
                    Ok(segs) => {
                        let count = segs.paths.len();
                        let scheme = segs.scheme.clone();
                        let desc = if scheme == "ewf_numbered_segments" {
                            format!("E01 segment set ({} files) + decoded logical media", count)
                        } else if scheme == "split_raw_segments" {
                            format!("Split raw segments ({} files)", count)
                        } else {
                            "Complete container file + decoded logical media".to_string()
                        };
                        (scheme, count, desc)
                    }
                    Err(_) => (
                        "single_container_file".to_string(),
                        1,
                        "Complete container file".to_string(),
                    ),
                }
            }
            NativeEvidenceKind::Folder => (
                "folder".to_string(),
                1,
                "Folder files and contents".to_string(),
            ),
            NativeEvidenceKind::File => (
                "single_file".to_string(),
                1,
                "Complete source file".to_string(),
            ),
            NativeEvidenceKind::Auto => (
                "auto".to_string(),
                1,
                "Automatic evidence detection".to_string(),
            ),
        };

        let display_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Evidence Source")
            .to_string();

        let case_tz = self
            .summary
            .as_ref()
            .map(|s| s.timezone.clone())
            .unwrap_or_else(|| "UTC".to_string());
        let detected_expected =
            kdft_desktop_core::detect_companion_expected_sha256(&path).unwrap_or_default();

        self.evidence_intake_dialog = EvidenceIntakeDialogState {
            visible: true,
            source_path: path,
            detected_kind,
            segment_count,
            segment_scheme,
            display_name,
            timezone: case_tz,
            timezone_filter: String::new(),
            integrity_choice: IntakeIntegrityChoice::VerifyNow,
            expected_sha256: detected_expected,
            skip_reason: String::new(),
            scope_description,
            error: None,
        };
    }

    pub fn begin_process(&mut self, context: egui::Context) {
        if self.is_busy() {
            return;
        }
        if self.view_stale {
            self.error =
                Some("Reopen the case before processing evidence from a stale view.".to_string());
            return;
        }
        let Some(case_path) = self.opened_path.clone() else {
            self.error = Some("Create or open a case before processing evidence.".to_string());
            return;
        };
        let Some(evidence_id) = self.selected_evidence_id else {
            self.error = Some("Select one evidence source to process.".to_string());
            return;
        };
        let max_entries = match parse_max_entries(&self.max_entries) {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let evidence_name = self
            .evidence_page
            .as_ref()
            .and_then(|page| page.items.iter().find(|item| item.id == evidence_id))
            .map_or_else(
                || format!("Evidence #{evidence_id}"),
                |item| item.display_name.clone(),
            );
        let request = ProcessEvidenceRequest {
            case_path: case_path.clone(),
            evidence_id,
            max_entries,
            profile: self.processing_profile,
        };
        let tracker = JobProgressTracker::new(
            format!("native-process-{}-{evidence_id}", std::process::id()),
            "process",
            None,
        );
        let worker_tracker = tracker.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeWorkflowService::process_evidence(request, &worker_tracker)
                .map_err(|error| error.to_string());
            let refreshed = open_case(&case_path);
            let _ = sender.send(ProcessWorkerResult { result, refreshed });
            context.request_repaint();
        });
        self.error = None;
        self.clear_operation_warnings();
        self.last_process = None;
        self.status = format!("Processing {evidence_name} in the background…");
        self.processing = Some(ProcessingJob {
            evidence_name,
            tracker,
            receiver,
        });
    }

    pub fn begin_page(
        &mut self,
        context: egui::Context,
        target_page: usize,
        target_cursor: Option<EntryCursor>,
    ) {
        if self.is_busy() {
            return;
        }
        if self.view_stale {
            self.error = Some("Reopen the case before paging a stale result view.".to_string());
            return;
        }
        let Some(backend) = self.backend.clone() else {
            return;
        };
        self.status = format!("Loading result page {}…", target_page + 1);
        let worker_cursor = target_cursor.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = read_page(&backend, worker_cursor.clone());
            let _ = sender.send(WorkerResult::Page {
                result,
                target_page,
                target_cursor: worker_cursor,
            });
            context.request_repaint();
        });
        self.pending = Some(receiver);
    }

    pub fn begin_evidence_page(
        &mut self,
        context: egui::Context,
        target_page: usize,
        target_after_id: Option<i64>,
    ) {
        if self.is_busy() {
            return;
        }
        if self.view_stale {
            self.error = Some("Reopen the case before paging a stale evidence view.".to_string());
            return;
        }
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        let expected_generation = self.summary.as_ref().map(|summary| summary.generation);
        self.status = format!("Loading evidence source page {}…", target_page + 1);
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = read_evidence_page(&case_path, target_after_id, expected_generation);
            let _ = sender.send(WorkerResult::EvidencePage {
                result,
                target_page,
                target_after_id,
            });
            context.request_repaint();
        });
        self.pending = Some(receiver);
    }

    pub fn begin_artifact_detail(&mut self, context: egui::Context, selection: ArtifactSelection) {
        if self.view_stale {
            self.clear_inspector();
            self.error = Some(
                "Reopen the case before inspecting a row from a stale result view.".to_string(),
            );
            return;
        }
        if self.selected_artifact == Some(selection)
            && self
                .artifact_detail
                .as_ref()
                .is_some_and(|detail| artifact_detail_matches(selection, detail))
            && self.artifact_detail_error.is_none()
            && self.artifact_pending.is_none()
        {
            return;
        }
        let Some(backend) = self.backend.clone() else {
            self.error = Some("Open a case before inspecting a result row.".to_string());
            return;
        };
        if !self.generation_matches(selection.generation) {
            self.lock_stale_inspector(
                "The selected row is from a different case generation. Reopen the case and select it again."
                    .to_string(),
            );
            return;
        }
        self.selected_artifact = Some(selection);
        self.artifact_detail = None;
        self.artifact_detail_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = match backend.dispatch(BackendCommand::ArtifactDetail {
                query: ArtifactDetailQuery {
                    entry_id: selection.entry_id,
                    expected_generation: selection.generation,
                },
            }) {
                BackendResponse::ArtifactDetail { detail } => Ok(*detail),
                BackendResponse::Error { code, message } => Err(format!("{code}: {message}")),
                _ => Err("desktop backend returned an unexpected inspector response".to_string()),
            };
            let _ = sender.send(ArtifactWorkerResult { selection, result });
            context.request_repaint();
        });
        self.artifact_pending = Some(receiver);
    }

    pub fn begin_browse_volumes(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        source_name: String,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        // A live Browse preview is scoped to the evidence/volume/directory
        // selection that produced it.  Never retain an unpinned byte buffer
        // while moving to another evidence source.
        self.clear_browse_preview();
        self.browse_loading = true;
        self.browse_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBrowseService::list_volumes(&case_path, evidence_id)
                .map_err(|error| error.to_string());
            let _ = sender.send(BrowseWorkerResult::Volumes {
                evidence_id,
                source_name,
                result,
            });
            context.request_repaint();
        });
        self.browse_pending = Some(receiver);
    }

    pub fn begin_browse_directory(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        volume_index: usize,
        path: String,
        offset: usize,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        // Directory changes, history navigation, volume changes, pagination,
        // and refreshes all flow through this method.  Clearing here prevents
        // a previous file (for example /$MFT) from being presented under the
        // newly displayed directory context.
        self.clear_browse_preview();
        self.browse_request_id += 1;
        let req_id = self.browse_request_id;
        self.browse_loading = true;
        self.browse_error = None;
        let worker_path = path.clone();
        let unlock_mgr = self.unlock_manager.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBrowseService::read_directory_page(
                &case_path,
                evidence_id,
                volume_index,
                &worker_path,
                offset,
                DEFAULT_DIRECTORY_PAGE_SIZE,
                Some(&unlock_mgr),
            )
            .map_err(|error| error.to_string());
            let _ = sender.send(BrowseWorkerResult::DirectoryPage {
                request_id: req_id,
                evidence_id,
                volume_index,
                path: worker_path,
                offset,
                result,
            });
            context.request_repaint();
        });
        self.browse_pending = Some(receiver);
    }

    pub fn begin_load_bookmark_folders(
        &mut self,
        context: egui::Context,
        cursor: Option<BookmarkCursor>,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::list_folders_page(
                &case_path,
                cursor,
                DEFAULT_BOOKMARK_PAGE_SIZE,
            )
            .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::Folders(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_load_bookmarks(
        &mut self,
        context: egui::Context,
        folder_id: Option<i64>,
        cursor: Option<BookmarkCursor>,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::list_bookmarks_page(
                &case_path,
                folder_id,
                cursor,
                DEFAULT_BOOKMARK_PAGE_SIZE,
            )
            .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::Bookmarks { folder_id, result });
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_load_bookmark_items(
        &mut self,
        context: egui::Context,
        bookmark_id: i64,
        cursor: Option<BookmarkCursor>,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::list_bookmark_items_page(
                &case_path,
                Some(bookmark_id),
                cursor,
                DEFAULT_BOOKMARK_PAGE_SIZE,
            )
            .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::Items {
                bookmark_id,
                result,
            });
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_load_bookmark_item_detail(&mut self, context: egui::Context, item_id: i64) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::get_bookmark_item_detail(&case_path, item_id, None)
                .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::ItemDetail { item_id, result });
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_create_folder(
        &mut self,
        context: egui::Context,
        request: CreateBookmarkFolderRequest,
    ) {
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result =
                NativeBookmarkService::create_folder(request).map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::CreatedFolder(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_create_bookmark(
        &mut self,
        context: egui::Context,
        request: CreateBookmarkRequest,
    ) {
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result =
                NativeBookmarkService::create_bookmark(request).map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::Created(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_create_recursive_bookmark(
        &mut self,
        context: egui::Context,
        request: RecursiveFolderBookmarkRequest,
    ) {
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::bookmark_folder_recursive(request)
                .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::RecursiveCreated(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_remove_folder(&mut self, context: egui::Context, folder_id: i64) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::remove_bookmark_folder(&case_path, folder_id)
                .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::RemovedFolder(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_remove_bookmark(&mut self, context: egui::Context, bookmark_id: i64) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::remove_bookmark(&case_path, bookmark_id)
                .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::RemovedBookmark(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn begin_remove_item(&mut self, context: egui::Context, item_id: i64) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.bookmark_loading = true;
        self.bookmark_error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = NativeBookmarkService::remove_bookmark_item(&case_path, item_id)
                .map_err(|error| error.to_string());
            let _ = sender.send(BookmarkWorkerResult::RemovedItem(result));
            context.request_repaint();
        });
        self.bookmark_pending = Some(receiver);
    }

    pub fn execute_create_single_bookmark(&mut self, context: egui::Context) {
        let Some(case_path) = self.opened_path.clone() else {
            self.bookmark_dialog.error = Some("No open case.".to_string());
            return;
        };
        let (
            bookmark_type,
            target_evidence_id,
            item_entry_id,
            item_logical_path,
            item_name,
            is_dir,
            is_del,
            selection_offset,
            selection_length,
            data_preview,
            match_field,
        ) = match &self.bookmark_dialog.target {
            Some(BookmarkTarget::IndexedResult {
                evidence_id,
                entry_id,
                logical_path,
                artifact_kind,
                is_deleted,
            }) => {
                let btype = match artifact_kind.as_str() {
                    "file" => BookmarkType::NotableFile,
                    "email" => BookmarkType::Email,
                    _ => BookmarkType::Record,
                };
                let name = Path::new(logical_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(logical_path)
                    .to_string();
                (
                    btype,
                    Some(*evidence_id),
                    Some(*entry_id),
                    Some(logical_path.clone()),
                    Some(name),
                    false,
                    *is_deleted,
                    None,
                    None,
                    None,
                    None,
                )
            }
            Some(BookmarkTarget::SearchResult {
                evidence_id,
                entry_id,
                logical_path,
                artifact_kind,
                match_field,
                match_snippet,
                selection_offset,
                selection_length,
            }) => {
                let btype = match artifact_kind.as_str() {
                    "file" => BookmarkType::NotableFile,
                    "email" => BookmarkType::Email,
                    _ => BookmarkType::Record,
                };
                let name = Path::new(logical_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(logical_path)
                    .to_string();
                (
                    btype,
                    Some(*evidence_id),
                    Some(*entry_id),
                    Some(logical_path.clone()),
                    Some(name),
                    false,
                    false,
                    selection_offset.and_then(|value| i64::try_from(value).ok()),
                    selection_length.and_then(|value| i64::try_from(value).ok()),
                    (!match_snippet.is_empty()).then(|| match_snippet.clone()),
                    Some(match_field.clone()),
                )
            }
            Some(BookmarkTarget::LiveSourceFile {
                evidence_id,
                logical_path,
                is_dir,
                is_deleted,
                ..
            }) => {
                let name = Path::new(logical_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(logical_path)
                    .to_string();
                let btype = if *is_dir {
                    BookmarkType::FolderInfo
                } else {
                    BookmarkType::NotableFile
                };
                (
                    btype,
                    Some(*evidence_id),
                    None,
                    Some(logical_path.clone()),
                    Some(name),
                    *is_dir,
                    *is_deleted,
                    None,
                    None,
                    None,
                    None,
                )
            }
            Some(BookmarkTarget::Folder {
                evidence_id,
                logical_path,
                ..
            }) => {
                let name = Path::new(logical_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(logical_path)
                    .to_string();
                (
                    BookmarkType::FolderInfo,
                    Some(*evidence_id),
                    None,
                    Some(logical_path.clone()),
                    Some(name),
                    true,
                    false,
                    None,
                    None,
                    None,
                    None,
                )
            }
            Some(BookmarkTarget::EvidenceSource {
                evidence_id,
                source_name,
            }) => (
                BookmarkType::FileGroup,
                Some(*evidence_id),
                None,
                None,
                Some(source_name.clone()),
                false,
                false,
                None,
                None,
                None,
                None,
            ),
            None => (
                BookmarkType::NotableFile,
                None,
                None,
                None,
                None,
                false,
                false,
                None,
                None,
                None,
                None,
            ),
        };

        let request = CreateBookmarkRequest {
            case_path,
            folder_name: optional_trimmed(&self.bookmark_dialog.folder_name)
                .unwrap_or_else(|| "General Bookmarks".to_string()),
            title: self.bookmark_dialog.title.trim().to_string(),
            bookmark_type,
            data_type: None,
            examiner_comment: optional_trimmed(&self.bookmark_dialog.comment),
            evidence_id: target_evidence_id,
            entry_id: item_entry_id,
            display_name: item_name,
            logical_path: item_logical_path,
            selection_offset,
            selection_length,
            data_preview,
            item_ref_json: Some(serde_json::json!({
                "is_directory": is_dir,
                "is_deleted": is_del,
                "search_match_field": match_field,
            })),
        };
        self.begin_create_bookmark(context, request);
    }

    pub fn execute_create_recursive_bookmark(&mut self, context: egui::Context) {
        let Some(case_path) = self.opened_path.clone() else {
            self.bookmark_dialog.error = Some("No open case.".to_string());
            return;
        };
        let (evidence_id, volume_index, folder_path, is_indexed) =
            match &self.bookmark_dialog.target {
                Some(BookmarkTarget::Folder {
                    evidence_id,
                    volume_index,
                    logical_path,
                    is_indexed,
                }) => (
                    *evidence_id,
                    *volume_index,
                    logical_path.clone(),
                    *is_indexed,
                ),
                _ => {
                    self.bookmark_dialog.error =
                        Some("Recursive bookmarking requires a folder target.".to_string());
                    return;
                }
            };

        let max_entries = match parse_recursive_limit(&self.bookmark_dialog.max_entries) {
            Ok(v) => v,
            Err(e) => {
                self.bookmark_dialog.error = Some(e);
                return;
            }
        };

        let checkpoint = if let Some(bm_id) = self.resuming_bookmark_id {
            match NativeBookmarkService::get_incomplete_recursive_bookmark(&case_path, bm_id) {
                Ok(Some(s)) => Some(s.checkpoint),
                Ok(None) => None,
                Err(err) => {
                    self.bookmark_dialog.error =
                        Some(format!("Failed to retrieve checkpoint: {err}"));
                    return;
                }
            }
        } else {
            None
        };

        let request = RecursiveFolderBookmarkRequest {
            case_path,
            evidence_id,
            volume_index,
            path: folder_path,
            is_live: !is_indexed,
            max_entries,
            folder_name: optional_trimmed(&self.bookmark_dialog.folder_name)
                .unwrap_or_else(|| "Evidence Folders".to_string()),
            title: optional_trimmed(&self.bookmark_dialog.title),
            examiner_comment: optional_trimmed(&self.bookmark_dialog.comment),
            bitlocker_password: None,
            bitlocker_recovery_key: None,
            checkpoint,
            bookmark_id: self.resuming_bookmark_id,
        };
        self.begin_create_recursive_bookmark(context, request);
    }

    pub fn execute_resume_bookmark(&mut self, context: egui::Context, bookmark_id: i64) {
        let Some(case_path) = self.opened_path.clone() else {
            self.bookmark_error = Some("No open case.".to_string());
            return;
        };

        let summary =
            match NativeBookmarkService::get_incomplete_recursive_bookmark(&case_path, bookmark_id)
            {
                Ok(Some(s)) => s,
                Ok(None) => {
                    self.bookmark_error = Some(format!(
                        "No incomplete recursive checkpoint found for bookmark #{bookmark_id}."
                    ));
                    return;
                }
                Err(e) => {
                    self.bookmark_error = Some(format!("Failed to load bookmark checkpoint: {e}"));
                    return;
                }
            };

        let request = RecursiveFolderBookmarkRequest {
            case_path,
            evidence_id: summary.evidence_id,
            volume_index: summary.volume_index,
            path: summary.path,
            is_live: summary.is_live,
            max_entries: 0,
            folder_name: summary.folder_name,
            title: Some(summary.title),
            examiner_comment: None,
            bitlocker_password: None,
            bitlocker_recovery_key: None,
            checkpoint: Some(summary.checkpoint),
            bookmark_id: Some(bookmark_id),
        };

        self.resuming_bookmark_id = Some(bookmark_id);
        self.begin_create_recursive_bookmark(context, request);
    }

    // --- Enhanced Services Dispatchers ---

    pub fn begin_hex_read(&mut self, context: egui::Context, mut req: BoundedByteRequest) {
        self.hex_viewer_origin_tab = Some(self.active_tab);
        self.hex_request_id += 1;
        let req_id = self.hex_request_id;
        req.request_id = req_id;
        if req.volume_identity.is_none() {
            req.volume_identity = self.active_volume_identity.clone();
        }
        self.hex_viewer_state.request_id = req_id;
        self.hex_viewer_state.volume_identity = req.volume_identity.clone();
        self.hex_viewer_state.loading = true;
        self.hex_viewer_state.error = None;
        let unlock_mgr = self.unlock_manager.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result =
                NativeByteService::read_bytes(&req, Some(&unlock_mgr)).map_err(|e| e.to_string());
            let _ = sender.send(HexWorkerResult::Loaded(result));
            context.request_repaint();
        });
        self.hex_pending = Some(receiver);
    }

    pub fn begin_artifacts_probe(&mut self, context: egui::Context) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.artifacts_probe_request_id += 1;
        let req_id = self.artifacts_probe_request_id;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let gen_res = (|| -> anyhow::Result<i64> {
                let conn = kdft_case::open_existing_case(&case_path)?;
                let case_id = kdft_case::active_case_id(&conn).ok();
                kdft_case::read_case_generation(&conn, case_id)
            })()
            .map_err(|e| e.to_string());
            let _ = sender.send(ArtifactsProbeWorkerResult {
                request_id: req_id,
                generation: gen_res,
            });
            context.request_repaint();
        });
        self.artifacts_probe_pending = Some(receiver);
    }

    pub fn begin_artifacts_tree(&mut self, context: egui::Context) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        let evidence_id = self.selected_evidence_id;
        self.artifacts_tree_request_id += 1;
        let req_id = self.artifacts_tree_request_id;
        self.artifacts_state.active_tree_request_id = req_id;
        self.artifacts_state.selected_evidence_id = evidence_id;
        self.artifacts_state.loading = true;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let snap =
                NativeArtifactService::get_category_tree_snapshot(&case_path, evidence_id, req_id)
                    .map_err(|e| e.to_string());
            let _ = sender.send(ArtifactsTreeWorkerResult { snapshot: snap });
            context.request_repaint();
        });
        self.artifacts_tree_pending = Some(receiver);
    }

    pub fn begin_artifacts_page(&mut self, context: egui::Context, mut query: ArtifactPageQuery) {
        self.artifacts_page_request_id += 1;
        let req_id = self.artifacts_page_request_id;
        query.request_id = req_id;
        self.artifacts_state.active_page_request_id = req_id;
        self.artifacts_state.loading = true;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let snap = NativeArtifactService::query_artifacts_page_snapshot(&query)
                .map_err(|e| e.to_string());
            let _ = sender.send(ArtifactsPageWorkerResult { snapshot: snap });
            context.request_repaint();
        });
        self.artifacts_page_pending = Some(receiver);
    }

    pub fn begin_search(&mut self, context: egui::Context, query: NativeSearchQuery) {
        self.search_state.loading = true;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            match NativeSearchService::search_page(&query) {
                Ok(page) => {
                    let count = page.results.len();
                    let _ = sender.send(SearchWorkerResult {
                        results: Ok(page.results),
                        next_cursor: page.next_cursor,
                        has_more: page.has_more,
                        total_matches: Some(count),
                        coverage_statement: Some(page.coverage_statement),
                    });
                }
                Err(e) => {
                    let _ = sender.send(SearchWorkerResult {
                        results: Err(e.to_string()),
                        next_cursor: None,
                        has_more: false,
                        total_matches: None,
                        coverage_statement: None,
                    });
                }
            }
            context.request_repaint();
        });
        self.search_pending = Some(receiver);
    }

    pub fn begin_timeline(&mut self, context: egui::Context, query: TimelineQuery) {
        self.timeline_state.loading = true;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let res = NativeTimelineService::query_timeline(&query).map_err(|e| e.to_string());
            let _ = sender.send(TimelineWorkerResult::Page(res));
            context.request_repaint();
        });
        self.timeline_pending = Some(receiver);
    }

    pub fn begin_report_preview(&mut self, context: egui::Context) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        self.report_state.loading = true;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let res = NativeReportService::generate_preview(&case_path).map_err(|e| e.to_string());
            let _ = sender.send(ReportWorkerResult::Preview(res));
            context.request_repaint();
        });
        self.report_pending = Some(receiver);
    }

    pub fn begin_report_export(&mut self, context: egui::Context, destination: PathBuf) {
        let Some(case_path) = self.opened_path.clone() else {
            return;
        };
        let examiner = self.summary.as_ref().and_then(|s| s.examiner_name.clone());
        self.report_state.loading = true;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let res =
                NativeReportService::export_report(&case_path, &destination, examiner.as_deref())
                    .map_err(|e| e.to_string());
            let _ = sender.send(ReportWorkerResult::Exported(res));
            context.request_repaint();
        });
        self.report_pending = Some(receiver);
    }

    pub fn begin_export_file(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        volume_index: usize,
        logical_path: String,
        entry_id: Option<i64>,
        dest_path: PathBuf,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            self.status = "Export Failed: No open case.".to_string();
            return;
        };
        let req = BoundedByteRequest::simple(
            case_path,
            evidence_id,
            volume_index,
            Some(logical_path.clone()),
            entry_id,
            ByteSourceNamespace::LogicalFile,
            0,
            64 * 1024,
            false,
        );
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.export_cancel = Some(cancel.clone());
        let unlock_mgr = self.unlock_manager.clone();
        let (sender, receiver) = mpsc::channel();
        self.export_pending = Some(receiver);
        self.status = format!("Exporting {logical_path} -> {}...", dest_path.display());

        std::thread::spawn(move || {
            let res = NativeByteService::stream_export_file(
                &req,
                &dest_path,
                Some(&unlock_mgr),
                Some(&cancel),
                None,
            )
            .map_err(|e| e.to_string());
            let _ = sender.send(ExportWorkerResult::Finished(res));
            context.request_repaint();
        });
    }

    pub fn begin_calculate_hashes(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        volume_index: usize,
        logical_path: String,
        entry_id: Option<i64>,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            self.status = "Hash calculation failed: No open case.".to_string();
            return;
        };
        let req = BoundedByteRequest::simple(
            case_path,
            evidence_id,
            volume_index,
            Some(logical_path.clone()),
            entry_id,
            ByteSourceNamespace::LogicalFile,
            0,
            64 * 1024,
            false,
        );
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.hash_cancel = Some(cancel.clone());
        let unlock_mgr = self.unlock_manager.clone();
        let (sender, receiver) = mpsc::channel();
        self.hash_pending = Some(receiver);
        self.status = format!("Calculating SHA-256 for {logical_path}...");

        std::thread::spawn(move || {
            let res = NativeByteService::calculate_file_hashes(
                &req,
                Some(&unlock_mgr),
                Some(&cancel),
                None,
            )
            .map_err(|e| e.to_string());
            let _ = sender.send(HashWorkerResult::Finished(res));
            context.request_repaint();
        });
    }

    pub fn begin_verify_integrity(
        &mut self,
        context: egui::Context,
        req: kdft_desktop_core::EvidenceIntegrityRequest,
    ) {
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.integrity_cancel = Some(cancel.clone());
        self.integrity_running_id = Some(req.evidence_id);
        self.integrity_progress = None;
        let (sender, receiver) = mpsc::channel();
        self.integrity_pending = Some(receiver);
        let ev_id = req.evidence_id;
        self.status = format!("Verifying cryptographic integrity for evidence #{ev_id}...");

        let sender_clone = sender.clone();
        let ctx_clone = context.clone();

        std::thread::spawn(move || {
            let res = NativeByteService::verify_evidence_integrity(
                &req,
                Some(&cancel),
                Some(&move |done, total| {
                    let _ = sender_clone.send(IntegrityWorkerResult::Progress {
                        evidence_id: ev_id,
                        done,
                        total,
                    });
                    ctx_clone.request_repaint();
                }),
            )
            .map_err(|e| e.to_string());
            let _ = sender.send(IntegrityWorkerResult::Finished(res));
            context.request_repaint();
        });
    }

    pub fn begin_export_folder(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        volume_index: usize,
        source_root_path: String,
        dest_dir: PathBuf,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            self.status = "Export Failed: No open case.".to_string();
            return;
        };
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.folder_export_cancel = Some(cancel.clone());
        let unlock_mgr = self.unlock_manager.clone();
        let (sender, receiver) = mpsc::channel();
        self.folder_export_pending = Some(receiver);
        self.status = format!(
            "Exporting folder {source_root_path} -> {}...",
            dest_dir.display()
        );

        let sender_clone = sender.clone();
        let ctx_clone = context.clone();

        std::thread::spawn(move || {
            let res = NativeByteService::stream_export_folder(
                &case_path,
                evidence_id,
                volume_index,
                &source_root_path,
                &dest_dir,
                Some(&unlock_mgr),
                Some(&cancel),
                Some(&move |files_done, total_files, bytes_done| {
                    let _ = sender_clone.send(FolderExportWorkerResult::Progress {
                        files_done,
                        total_files,
                        bytes_done,
                    });
                    ctx_clone.request_repaint();
                }),
            )
            .map_err(|e| e.to_string());
            let _ = sender.send(FolderExportWorkerResult::Finished(res));
            context.request_repaint();
        });
    }

    pub fn begin_calculate_hashes_recursive(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        volume_index: usize,
        source_root_path: String,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            self.status = "Recursive hash calculation failed: No open case.".to_string();
            return;
        };
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.folder_hash_cancel = Some(cancel.clone());
        let unlock_mgr = self.unlock_manager.clone();
        let (sender, receiver) = mpsc::channel();
        self.folder_hash_pending = Some(receiver);
        self.status = format!("Calculating SHA-256 recursively for {source_root_path}...");

        let sender_clone = sender.clone();
        let ctx_clone = context.clone();

        std::thread::spawn(move || {
            let res = NativeByteService::calculate_hashes_recursive(
                &case_path,
                evidence_id,
                volume_index,
                &source_root_path,
                Some(&unlock_mgr),
                Some(&cancel),
                Some(&move |files_done, total_files, bytes_done| {
                    let _ = sender_clone.send(FolderHashWorkerResult::Progress {
                        files_done,
                        total_files,
                        bytes_done,
                    });
                    ctx_clone.request_repaint();
                }),
            )
            .map_err(|e| e.to_string());
            let _ = sender.send(FolderHashWorkerResult::Finished(res));
            context.request_repaint();
        });
    }

    pub fn apply_case_timezone(&mut self, context: egui::Context, new_timezone: String) {
        let Some(case_path) = self.opened_path.clone() else {
            self.error = Some("No open case to update timezone.".to_string());
            return;
        };
        match NativeWorkflowService::set_case_display_timezone(
            case_path.clone(),
            new_timezone.clone(),
        ) {
            Ok(()) => {
                self.status = format!("Case display timezone updated to {new_timezone} (canonical timestamps remain UTC).");
                if let Some(sum) = &mut self.summary {
                    sum.timezone = new_timezone;
                }
                self.begin_open(context);
            }
            Err(e) => {
                self.error = Some(format!("Failed to update case timezone: {e}"));
            }
        }
    }

    pub fn begin_bitlocker_unlock(
        &mut self,
        context: egui::Context,
        evidence_id: i64,
        volume_index: usize,
        is_recovery_key: bool,
        credential: zeroize::Zeroizing<String>,
    ) {
        let Some(case_path) = self.opened_path.clone() else {
            self.bitlocker_dialog.error = Some("No case is open.".to_string());
            self.bitlocker_dialog.is_unlocking = false;
            return;
        };
        self.bitlocker_dialog.is_unlocking = true;
        self.bitlocker_dialog.error = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let secret_str = credential.to_string();
            let cred = if is_recovery_key {
                TransientBitLockerCredential::recovery_key(secret_str)
            } else {
                TransientBitLockerCredential::password(secret_str)
            };
            let record =
                match kdft_desktop_core::browse::read_evidence_record(&case_path, evidence_id) {
                    Ok(rec) => rec,
                    Err(e) => {
                        let _ = sender.send(UnlockWorkerResult {
                            evidence_id,
                            volume_index,
                            result: Err(format!("Failed to read evidence record: {e}")),
                        });
                        context.request_repaint();
                        return;
                    }
                };
            let img_path = PathBuf::from(record.source_path);
            let test_mgr = TransientUnlockManager::new();
            match test_mgr.unlock_volume(&img_path, evidence_id, volume_index, cred.clone()) {
                Ok(_) => {
                    let _ = sender.send(UnlockWorkerResult {
                        evidence_id,
                        volume_index,
                        result: Ok(cred),
                    });
                }
                Err(e) => {
                    let _ = sender.send(UnlockWorkerResult {
                        evidence_id,
                        volume_index,
                        result: Err(e.to_string()),
                    });
                }
            }
            context.request_repaint();
        });
        self.unlock_pending = Some(receiver);
    }

    // --- Polling Loops ---

    pub fn poll_worker(&mut self, context: &egui::Context) {
        let poll = self.pending.as_ref().map(Receiver::try_recv);
        let message = match poll {
            Some(Ok(message)) => message,
            Some(Err(TryRecvError::Empty)) => {
                context.request_repaint_after(Duration::from_millis(100));
                return;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.pending = None;
                self.status = "Background operation stopped unexpectedly.".to_string();
                self.error = Some(
                    "The native worker exited without a result; no completion is asserted."
                        .to_string(),
                );
                return;
            }
            None => return,
        };
        self.pending = None;
        match message {
            WorkerResult::Open(Ok(opened)) => {
                let rows = opened.page.items.len();
                self.install_opened(opened);
                self.status = page_status(1, rows);
                self.error = None;
            }
            WorkerResult::Create {
                mutation: Ok(created),
                refreshed: Some(Ok(opened)),
            } => {
                let projection_missing = created.timezone.is_none()
                    || created.created_at.is_none()
                    || created.case_generation.is_none();
                let mut warnings = created.post_commit_warnings;
                if projection_missing {
                    warnings.push(
                        "The committed create result omitted optional projection fields; the native view was refreshed from the case database."
                            .to_string(),
                    );
                }
                self.install_operation_warnings(warnings, created.post_commit_warnings_omitted);
                self.install_opened(opened);
                self.new_case.visible = false;
                self.status = format!(
                    "COMMITTED: Created case {}. Do not retry Create. Add evidence when ready.",
                    created.name
                );
                self.error = None;
            }
            WorkerResult::Create {
                mutation: Ok(created),
                refreshed: Some(Err(refresh_error)),
            } => {
                let mut warnings = created.post_commit_warnings;
                warnings.push(
                    "The committed create result could not be refreshed; reopen the case before continuing."
                        .to_string(),
                );
                self.install_operation_warnings(warnings, created.post_commit_warnings_omitted);
                self.clear_opened_view();
                self.case_path = created.case_path.display().to_string();
                self.new_case.visible = false;
                self.status = format!(
                    "COMMITTED: Created case {}, but the native view could not be refreshed. Do not retry Create.",
                    created.name
                );
                self.error = Some(format!(
                    "The case was created successfully at {}. Do not retry Create; use Open Case to refresh it. Refresh error: {refresh_error}",
                    created.case_path.display()
                ));
            }
            WorkerResult::Attach {
                mutation: Ok(attached),
                refreshed: Some(Ok(opened)),
                source_name,
            } => {
                let projection_missing =
                    attached.evidence.is_none() || attached.case_generation.is_none();
                let evidence_id = attached.evidence_id;
                let mut warnings = attached.post_commit_warnings;
                if projection_missing {
                    warnings.push(
                        "The committed attach result omitted its optional projection or generation; the native view was refreshed from the case database."
                            .to_string(),
                    );
                }
                self.install_operation_warnings(warnings, attached.post_commit_warnings_omitted);
                self.install_opened(opened);
                self.status = format!(
                    "COMMITTED: Attached {source_name} as evidence #{evidence_id}. Do not attach it again. Select it and choose Process selected evidence."
                );
                self.error = None;
                if let Some(mut req) = self.pending_intake_verification.take() {
                    req.evidence_id = evidence_id;
                    req.case_path = self.opened_path.clone().unwrap_or_default();
                    self.begin_verify_integrity(context.clone(), req);
                }
            }
            WorkerResult::Attach {
                mutation: Ok(attached),
                refreshed: Some(Err(refresh_error)),
                source_name,
            } => {
                let evidence_id = attached.evidence_id;
                let mut warnings = attached.post_commit_warnings;
                warnings.push(
                    "The committed attach result could not be refreshed; reopen the case before continuing."
                        .to_string(),
                );
                self.install_operation_warnings(warnings, attached.post_commit_warnings_omitted);
                self.view_stale = true;
                self.status = format!(
                    "COMMITTED: Attached {source_name} as evidence #{evidence_id}, but the native view is stale. Do not attach it again."
                );
                self.error = Some(format!(
                    "Evidence #{} was attached successfully. Do not attach it again; reopen the case before interpreting the evidence list. Refresh error: {refresh_error}",
                    evidence_id
                ));
            }
            WorkerResult::Open(Err(error)) => {
                self.clear_opened_view();
                self.worker_error(error, "Case was not opened.");
            }
            WorkerResult::Create {
                mutation: Err(error),
                ..
            } => {
                self.clear_opened_view();
                self.new_case.error = Some(error.clone());
                self.worker_error(error, "Case was not created.");
            }
            WorkerResult::Attach {
                mutation: Err(error),
                ..
            } => self.worker_error(error, "Evidence was not attached."),
            WorkerResult::Create {
                mutation: Ok(created),
                refreshed: None,
            } => {
                let mut warnings = created.post_commit_warnings;
                warnings.push(
                    "The committed create result was not refreshed; open the case before continuing."
                        .to_string(),
                );
                self.install_operation_warnings(warnings, created.post_commit_warnings_omitted);
                self.clear_opened_view();
                self.case_path = created.case_path.display().to_string();
                self.new_case.visible = false;
                self.status = format!(
                    "COMMITTED: Created case {}, but no refresh was attempted. Do not retry Create.",
                    created.name
                );
                self.error = Some(
                    "The case was created successfully. Do not retry Create; use Open Case."
                        .to_string(),
                );
            }
            WorkerResult::Attach {
                mutation: Ok(attached),
                refreshed: None,
                source_name,
            } => {
                let evidence_id = attached.evidence_id;
                let mut warnings = attached.post_commit_warnings;
                warnings.push(
                    "The committed attach result was not refreshed; reopen the case before continuing."
                        .to_string(),
                );
                self.install_operation_warnings(warnings, attached.post_commit_warnings_omitted);
                self.view_stale = true;
                self.status = format!(
                    "COMMITTED: Attached {source_name} as evidence #{evidence_id}, but no refresh was attempted. Do not attach it again."
                );
                self.error = Some(
                    "The evidence was attached successfully. Do not attach it again; reopen the case."
                        .to_string(),
                );
            }
            WorkerResult::Page {
                result: Ok(page),
                target_page,
                target_cursor,
            } => {
                if !self.generation_matches(page.generation) {
                    self.lock_stale_inspector(mixed_generation_error(
                        self.summary.as_ref().map(|summary| summary.generation),
                        page.generation,
                        None,
                    ));
                    return;
                }
                let rows = page.items.len();
                self.clear_inspector();
                self.page = Some(page);
                self.page_index = target_page;
                self.page_starts.truncate(target_page);
                self.page_starts.push(target_cursor);
                self.status = page_status(target_page + 1, rows);
                self.error = None;
            }
            WorkerResult::Page {
                result: Err(error), ..
            } => {
                if is_stale_cursor_error(&error) {
                    self.lock_stale_inspector(error);
                } else {
                    self.worker_error(error, "Result page was not changed.");
                }
            }
            WorkerResult::EvidencePage {
                result: Ok(page),
                target_page,
                target_after_id,
            } => {
                if !self.generation_matches(page.case_generation) {
                    let expected = self.summary.as_ref().map(|summary| summary.generation);
                    let error = mixed_generation_error(
                        expected,
                        expected.unwrap_or(page.case_generation),
                        Some(page.case_generation),
                    );
                    self.lock_stale_inspector(error.clone());
                    self.evidence_error = Some(error);
                    return;
                }
                self.selected_evidence_id = retained_selection(self.selected_evidence_id, &page);
                self.evidence_page = Some(page);
                self.evidence_page_index = target_page;
                self.evidence_page_starts.truncate(target_page);
                self.evidence_page_starts.push(target_after_id);
                self.evidence_error = None;
                self.status = format!("Showing evidence source page {}.", target_page + 1);
            }
            WorkerResult::EvidencePage {
                result: Err(error), ..
            } => {
                if is_stale_cursor_error(&error) {
                    self.lock_stale_inspector(error.clone());
                }
                self.evidence_error = Some(error);
                self.status = if self.view_stale {
                    "Evidence source page was not changed; reopen the case.".to_string()
                } else {
                    "Evidence source page was not changed.".to_string()
                };
            }
        }
    }

    pub fn poll_artifact_worker(&mut self, _context: &egui::Context) {
        let poll = self.artifact_pending.as_ref().map(Receiver::try_recv);
        let message = match poll {
            Some(Ok(message)) => message,
            Some(Err(TryRecvError::Empty)) => return,
            Some(Err(TryRecvError::Disconnected)) => {
                self.artifact_pending = None;
                return;
            }
            None => return,
        };

        self.artifact_pending = None;

        let ArtifactWorkerResult { selection, result } = message;

        if self.selected_artifact != Some(selection) {
            return;
        }

        match result {
            Ok(detail) => {
                if !artifact_detail_matches(selection, &detail)
                    || !self.generation_matches(detail.generation)
                {
                    self.lock_stale_inspector(format!(
                        "Artifact detail did not match the selected row snapshot (entry #{}, generation {}). Reopen the case and reselect the row.",
                        selection.entry_id, selection.generation
                    ));
                    return;
                }
                self.artifact_detail = Some(detail);
                self.artifact_detail_error = None;
                self.status = format!(
                    "Showing bounded Inspector detail for entry #{} from snapshot generation {}.",
                    selection.entry_id, selection.generation
                );
                self.error = None;
            }
            Err(error) => {
                if is_stale_artifact_detail_error(&error) {
                    self.lock_stale_inspector(error);
                } else {
                    self.artifact_detail = None;
                    self.artifact_detail_error = Some(error.clone());
                    self.worker_error(error, "Artifact detail was not loaded.");
                }
            }
        }
    }

    pub fn poll_browse_worker(&mut self, context: &egui::Context) {
        let poll = self.browse_pending.as_ref().map(Receiver::try_recv);
        let message = match poll {
            Some(Ok(message)) => message,
            Some(Err(TryRecvError::Empty)) => return,
            Some(Err(TryRecvError::Disconnected)) => {
                self.browse_pending = None;
                self.browse_loading = false;
                self.browse_error = Some("Browse worker disconnected unexpectedly.".to_string());
                return;
            }
            None => return,
        };
        self.browse_pending = None;
        self.browse_loading = false;
        match message {
            BrowseWorkerResult::Volumes {
                evidence_id,
                source_name,
                result: Ok(vols),
            } => {
                self.browse_volumes = vols;
                self.browse_selected_volume = 0;
                self.browse_path = "/".to_string();
                self.browse_history_back.clear();
                self.browse_history_forward.clear();
                self.browse_offset = 0;
                self.browse_error = None;
                if self.browse_volumes.is_empty() {
                    self.status = format!(
                        "Evidence #{evidence_id} ({source_name}) has no partitions or volumes."
                    );
                } else {
                    self.status = format!(
                        "Discovered {} volume(s) in {source_name}.",
                        self.browse_volumes.len()
                    );
                    self.begin_browse_directory(
                        context.clone(),
                        evidence_id,
                        0,
                        "/".to_string(),
                        0,
                    );
                }
            }
            BrowseWorkerResult::Volumes {
                result: Err(err), ..
            } => {
                self.browse_error = Some(err.clone());
                self.status = format!("Failed to list volumes: {err}");
            }
            BrowseWorkerResult::DirectoryPage {
                request_id,
                evidence_id,
                volume_index,
                path,
                offset,
                result,
            } => {
                if request_id != self.browse_request_id
                    || Some(evidence_id) != self.browse_evidence_id
                    || volume_index != self.browse_selected_volume
                {
                    // Stale async response rejected: generation/request/volume no longer active
                    return;
                }
                match result {
                    Ok(page) => {
                        self.browse_path = page.path.clone();
                        self.browse_offset = offset;
                        self.browse_page = Some(page);
                        self.browse_error = None;
                        self.status = format!("Loaded directory {path}.");
                    }
                    Err(err) => {
                        self.browse_error = Some(err.clone());
                        self.status = format!("Directory read failed: {err}");
                    }
                }
            }
        }
    }

    pub fn poll_bookmark_worker(&mut self, context: &egui::Context) {
        let poll = self.bookmark_pending.as_ref().map(Receiver::try_recv);
        let message = match poll {
            Some(Ok(message)) => message,
            Some(Err(TryRecvError::Empty)) => return,
            Some(Err(TryRecvError::Disconnected)) => {
                self.bookmark_pending = None;
                self.bookmark_loading = false;
                self.bookmark_error =
                    Some("Bookmark worker disconnected unexpectedly.".to_string());
                return;
            }
            None => return,
        };
        self.bookmark_pending = None;
        self.bookmark_loading = false;
        match message {
            BookmarkWorkerResult::Folders(Ok(page)) => {
                self.bookmark_folders = page.folders.clone();
                self.bookmark_folders_page = Some(page);
                self.bookmark_error = None;
                if let Some(folder_id) = self.selected_bookmark_folder {
                    if !self.bookmark_folders.iter().any(|f| f.id == folder_id) {
                        self.selected_bookmark_folder = self.bookmark_folders.first().map(|f| f.id);
                    }
                } else if !self.bookmark_folders.is_empty() {
                    self.selected_bookmark_folder = self.bookmark_folders.first().map(|f| f.id);
                }
                self.bookmarks_cursors = vec![None];
                self.bookmarks_page_index = 0;
                self.begin_load_bookmarks(context.clone(), self.selected_bookmark_folder, None);
            }
            BookmarkWorkerResult::Folders(Err(err)) => {
                self.bookmark_error = Some(err);
            }
            BookmarkWorkerResult::Bookmarks {
                result: Ok(page), ..
            } => {
                self.bookmarks = page.bookmarks.clone();
                self.bookmarks_page = Some(page);
                self.bookmark_error = None;
                if let Some(b_id) = self.selected_bookmark_id {
                    if !self.bookmarks.iter().any(|b| b.id == b_id) {
                        self.selected_bookmark_id = self.bookmarks.first().map(|b| b.id);
                    }
                } else if !self.bookmarks.is_empty() {
                    self.selected_bookmark_id = self.bookmarks.first().map(|b| b.id);
                } else {
                    self.selected_bookmark_id = None;
                    self.bookmark_items.clear();
                    self.bookmark_items_page = None;
                    self.selected_bookmark_item_id = None;
                    self.selected_bookmark_item_detail = None;
                }
                if let Some(b_id) = self.selected_bookmark_id {
                    self.bookmark_items_cursors = vec![None];
                    self.bookmark_items_page_index = 0;
                    self.selected_bookmark_item_id = None;
                    self.selected_bookmark_item_detail = None;
                    self.begin_load_bookmark_items(context.clone(), b_id, None);
                }
            }
            BookmarkWorkerResult::Bookmarks {
                result: Err(err), ..
            } => {
                self.bookmark_error = Some(err);
            }
            BookmarkWorkerResult::Items {
                bookmark_id,
                result: Ok(page),
            } => {
                if self.selected_bookmark_id == Some(bookmark_id) {
                    self.bookmark_items = page.items.clone();
                    self.bookmark_items_page = Some(page);
                    self.bookmark_error = None;
                    if let Some(item_id) = self.selected_bookmark_item_id {
                        if !self.bookmark_items.iter().any(|i| i.id == item_id) {
                            self.selected_bookmark_item_id = None;
                            self.selected_bookmark_item_detail = None;
                        }
                    }
                }
            }
            BookmarkWorkerResult::Items {
                result: Err(err), ..
            } => {
                self.bookmark_error = Some(err);
            }
            BookmarkWorkerResult::ItemDetail {
                item_id,
                result: Ok(detail),
            } => {
                if self.selected_bookmark_item_id == Some(item_id) {
                    self.selected_bookmark_item_detail = Some(detail);
                    self.bookmark_error = None;
                }
            }
            BookmarkWorkerResult::ItemDetail {
                result: Err(err), ..
            } => {
                self.bookmark_error = Some(err);
            }
            BookmarkWorkerResult::CreatedFolder(Ok(created)) => {
                self.install_operation_warnings(created.post_commit_warnings, 0);
                self.status = format!(
                    "COMMITTED: Created bookmark folder #{} with generation #{:?}.",
                    created.folder_id, created.case_generation
                );
                self.create_folder_dialog.visible = false;
                self.create_folder_dialog.name.clear();
                self.create_folder_dialog.comment.clear();
                self.selected_bookmark_folder = Some(created.folder_id);
                self.bookmark_folders_cursors = vec![None];
                self.bookmark_folders_page_index = 0;
                self.begin_load_bookmark_folders(context.clone(), None);
            }
            BookmarkWorkerResult::CreatedFolder(Err(err)) => {
                self.create_folder_dialog.error = Some(err.clone());
                self.status = format!("Failed to create bookmark folder: {err}");
            }
            BookmarkWorkerResult::Created(Ok(created)) => {
                self.install_operation_warnings(created.post_commit_warnings, 0);
                self.status = format!(
                    "COMMITTED: Created bookmark #{}. Do not retry.",
                    created.bookmark_id
                );
                self.bookmark_dialog.visible = false;
                self.bookmark_folders_cursors = vec![None];
                self.bookmark_folders_page_index = 0;
                self.begin_load_bookmark_folders(context.clone(), None);
            }
            BookmarkWorkerResult::Created(Err(err)) => {
                self.bookmark_dialog.error = Some(err.clone());
                self.status = format!("Failed to create bookmark: {err}");
            }
            BookmarkWorkerResult::RecursiveCreated(Ok(created)) => {
                let has_warnings = !created.post_commit_warnings.is_empty();
                self.install_operation_warnings(created.post_commit_warnings.clone(), 0);

                let is_completed = created
                    .checkpoint
                    .as_ref()
                    .map(|cp| cp.completed)
                    .unwrap_or(false)
                    && !created.truncated
                    && !has_warnings;

                if is_completed {
                    self.status = format!(
                        "COMMITTED: Recursive folder bookmark completed (added {}, skipped {}, total candidates {}). Do not retry.",
                        created.items_added,
                        created.skipped_count,
                        created.total_candidates
                    );
                    self.bookmark_dialog.visible = false;
                    self.resuming_bookmark_id = None;
                    self.bookmark_dialog.error = None;
                } else if has_warnings {
                    self.status = format!(
                        "WARNING: Recursive folder bookmark saved (added {} items), but checkpoint persistence warning: {}.",
                        created.items_added,
                        created.post_commit_warnings.join("; ")
                    );
                    self.bookmark_dialog.visible = true;
                    self.resuming_bookmark_id = None;
                    self.bookmark_dialog.error = Some(self.status.clone());
                } else {
                    self.status = format!(
                        "PARTIAL: Recursive bookmark saved. Resume available for bookmark #{}. (added {}, skipped {}, total candidates {}).",
                        created.bookmark_id,
                        created.items_added,
                        created.skipped_count,
                        created.total_candidates
                    );
                    self.bookmark_dialog.visible = true;
                    self.resuming_bookmark_id = Some(created.bookmark_id);
                    self.bookmark_dialog.error = None;
                }
                self.bookmark_folders_cursors = vec![None];
                self.bookmark_folders_page_index = 0;
                self.begin_load_bookmark_folders(context.clone(), None);
            }
            BookmarkWorkerResult::RecursiveCreated(Err(err)) => {
                self.bookmark_dialog.error = Some(err.clone());
                self.status = format!("Failed to recursively bookmark folder: {err}");
            }
            BookmarkWorkerResult::RemovedFolder(Ok(res)) => {
                self.install_operation_warnings(res.post_commit_warnings, 0);
                self.status = "COMMITTED: Removed bookmark folder.".to_string();
                self.removal_dialog.visible = false;
                self.selected_bookmark_folder = None;
                self.bookmarks.clear();
                self.bookmarks_page = None;
                self.selected_bookmark_id = None;
                self.bookmark_items.clear();
                self.bookmark_items_page = None;
                self.selected_bookmark_item_id = None;
                self.selected_bookmark_item_detail = None;
                self.bookmark_folders_cursors = vec![None];
                self.bookmark_folders_page_index = 0;
                self.begin_load_bookmark_folders(context.clone(), None);
            }
            BookmarkWorkerResult::RemovedFolder(Err(err)) => {
                self.removal_dialog.error = Some(err.clone());
                self.status = format!("Failed to remove bookmark folder: {err}");
            }
            BookmarkWorkerResult::RemovedBookmark(Ok(res)) => {
                self.install_operation_warnings(res.post_commit_warnings, 0);
                self.status = "COMMITTED: Removed bookmark.".to_string();
                self.removal_dialog.visible = false;
                self.selected_bookmark_id = None;
                self.bookmark_items.clear();
                self.bookmark_items_page = None;
                self.selected_bookmark_item_id = None;
                self.selected_bookmark_item_detail = None;
                self.bookmarks_cursors = vec![None];
                self.bookmarks_page_index = 0;
                self.begin_load_bookmarks(context.clone(), self.selected_bookmark_folder, None);
            }
            BookmarkWorkerResult::RemovedBookmark(Err(err)) => {
                self.removal_dialog.error = Some(err.clone());
                self.status = format!("Failed to remove bookmark: {err}");
            }
            BookmarkWorkerResult::RemovedItem(Ok(res)) => {
                self.install_operation_warnings(res.post_commit_warnings, 0);
                self.status = "COMMITTED: Removed bookmark item.".to_string();
                self.removal_dialog.visible = false;
                self.selected_bookmark_item_id = None;
                self.selected_bookmark_item_detail = None;
                if let Some(b_id) = self.selected_bookmark_id {
                    self.bookmark_items_cursors = vec![None];
                    self.bookmark_items_page_index = 0;
                    self.begin_load_bookmark_items(context.clone(), b_id, None);
                }
            }
            BookmarkWorkerResult::RemovedItem(Err(err)) => {
                self.removal_dialog.error = Some(err.clone());
                self.status = format!("Failed to remove bookmark item: {err}");
            }
        }
    }

    pub fn poll_processing(&mut self, context: &egui::Context) {
        let poll = self.processing.as_ref().map(|job| job.receiver.try_recv());
        let message = match poll {
            Some(Ok(message)) => message,
            Some(Err(TryRecvError::Empty)) => {
                context.request_repaint_after(Duration::from_millis(100));
                return;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.processing = None;
                self.error = Some(
                    "The processing worker stopped without a terminal result; coverage is unknown."
                        .to_string(),
                );
                self.status = "Processing stopped unexpectedly.".to_string();
                return;
            }
            None => return,
        };
        self.processing = None;
        let refresh_error = match message.refreshed {
            Ok(opened) => {
                self.install_opened(opened);
                if self.active_tab == TopLevelTab::Artifacts {
                    self.begin_artifacts_probe(context.clone());
                }
                None
            }
            Err(error) => {
                self.view_stale = true;
                Some(error)
            }
        };
        match message.result {
            Ok(result) => {
                self.status = process_status_text(&result, refresh_error.is_none());
                self.last_process = Some(result);
                self.error = refresh_error.map(|error| {
                    format!(
                        "Processing reached a committed terminal outcome, but the displayed case could not be refreshed. Reopen the case before interpreting the result grid. Refresh error: {error}"
                    )
                });
            }
            Err(error) => {
                self.status =
                    "Processing failed; inspect the error and coverage status.".to_string();
                self.error = Some(match refresh_error {
                    Some(refresh_error) => format!(
                        "{error} The case view also could not be refreshed: {refresh_error}"
                    ),
                    None => error,
                });
            }
        }
        self.refresh_processing_history();
    }

    pub fn poll_processing_history_worker(&mut self) {
        let Some(receiver) = &self.processing_history_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(result) => {
                self.processing_history_pending = None;
                if result.request_id != self.processing_history_request_id
                    || self.opened_path.as_ref() != Some(&result.case_path)
                    || self.selected_evidence_id != result.evidence_id
                {
                    return;
                }
                self.install_processing_history_results(result.jobs, result.coverage);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.processing_history_pending = None;
                self.processing_history_error = Some(
                    "The processing-history refresh worker stopped unexpectedly; the last successful history remains displayed."
                        .to_string(),
                );
            }
        }
    }

    pub fn poll_hex_worker(&mut self) {
        let Some(receiver) = &self.hex_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(HexWorkerResult::Loaded(res)) => {
                self.hex_pending = None;
                self.hex_viewer_state.loading = false;
                match res {
                    Ok(b) => {
                        if b.request_id != self.hex_request_id {
                            return;
                        }
                        self.hex_viewer_state.loaded_bytes = b.bytes;
                        self.hex_viewer_state.current_offset = b.returned_offset;
                        self.hex_viewer_state.total_size = b.total_logical_size;
                        self.hex_viewer_state.partition_start_offset = b.partition_start;
                        self.hex_viewer_state.mapped_filesystem_offset = b.filesystem_offset;
                        self.hex_viewer_state.mapped_decoded_media_offset = b.absolute_media_offset;
                        self.hex_viewer_state.ntfs_file_record_size = b.ntfs_file_record_size;
                        self.hex_viewer_state.mapping_provenance = Some(b.provenance);
                        self.hex_viewer_state.mapping_warnings = b.warnings;
                        self.hex_viewer_state.copy_notice = None;
                        self.hex_viewer_state.error = None;
                    }
                    Err(e) => {
                        // Never display bytes from the previous request beneath
                        // an error for the newly selected target.
                        self.hex_viewer_state.loaded_bytes.clear();
                        self.hex_viewer_state.mapped_filesystem_offset = None;
                        self.hex_viewer_state.mapped_decoded_media_offset = None;
                        self.hex_viewer_state.partition_start_offset = None;
                        self.hex_viewer_state.ntfs_file_record_size = None;
                        self.hex_viewer_state.mapping_provenance = None;
                        self.hex_viewer_state.mapping_warnings.clear();
                        self.hex_viewer_state.error = Some(e);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.hex_pending = None;
                self.hex_viewer_state.loading = false;
            }
        }
    }

    pub fn poll_artifacts_worker(&mut self, context: &egui::Context) {
        if let Some(receiver) = &self.artifacts_probe_pending {
            match receiver.try_recv() {
                Ok(res) => {
                    self.artifacts_probe_pending = None;
                    if res.request_id == self.artifacts_probe_request_id {
                        match res.generation {
                            Ok(db_gen) => {
                                if self.artifacts_state.cached_generation != Some(db_gen) {
                                    if !self.inspector_pinned {
                                        self.clear_inspector();
                                    }
                                    self.artifacts_state.invalidate();
                                    self.artifacts_tree_pending = None;
                                    self.artifacts_page_pending = None;
                                    self.begin_artifacts_tree(context.clone());
                                }
                            }
                            Err(e) => {
                                self.artifacts_state.error =
                                    Some(format!("Database generation check failed: {e}"));
                            }
                        }
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.artifacts_probe_pending = None;
                }
            }
        }

        if let Some(receiver) = &self.artifacts_tree_pending {
            match receiver.try_recv() {
                Ok(res) => {
                    self.artifacts_tree_pending = None;
                    match res.snapshot {
                        Ok(snap) => {
                            if snap.request_id == self.artifacts_state.active_tree_request_id
                                && snap.evidence_id == self.selected_evidence_id
                            {
                                self.artifacts_state.category_tree = snap.tree;
                                self.artifacts_state.cached_generation = Some(snap.case_generation);
                                self.artifacts_state.selected_evidence_id = snap.evidence_id;
                                self.artifacts_state.loading =
                                    self.artifacts_page_pending.is_some();
                                self.artifacts_state.error = None;

                                if self.artifacts_state.current_rows.is_empty()
                                    && self.artifacts_page_pending.is_none()
                                {
                                    let selected_main = self
                                        .artifacts_state
                                        .selected_category
                                        .clone()
                                        .unwrap_or_default();
                                    let selected_sub =
                                        self.artifacts_state.selected_sub_category.clone();
                                    if let Some(case_path) = self.opened_path.clone() {
                                        self.begin_artifacts_page(
                                            context.clone(),
                                            ArtifactPageQuery {
                                                case_path,
                                                evidence_id: self.selected_evidence_id,
                                                request_id: 0,
                                                category_main: selected_main,
                                                category_sub: selected_sub,
                                                name_filter: if self
                                                    .artifacts_state
                                                    .search_filter
                                                    .trim()
                                                    .is_empty()
                                                {
                                                    None
                                                } else {
                                                    Some(self.artifacts_state.search_filter.clone())
                                                },
                                                extension_filter: if self
                                                    .artifacts_state
                                                    .extension_filter
                                                    .trim()
                                                    .is_empty()
                                                {
                                                    None
                                                } else {
                                                    Some(
                                                        self.artifacts_state
                                                            .extension_filter
                                                            .clone(),
                                                    )
                                                },
                                                entry_type_filter: None,
                                                deleted_only: self.artifacts_state.deleted_only,
                                                date_from_utc: None,
                                                date_to_utc: None,
                                                cursor: None,
                                                limit: 100,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            self.artifacts_state.loading = self.artifacts_page_pending.is_some();
                            self.artifacts_state.error = Some(e);
                        }
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.artifacts_tree_pending = None;
                    self.artifacts_state.loading = self.artifacts_page_pending.is_some();
                }
            }
        }

        if let Some(receiver) = &self.artifacts_page_pending {
            match receiver.try_recv() {
                Ok(res) => {
                    self.artifacts_page_pending = None;
                    match res.snapshot {
                        Ok(snap) => {
                            if snap.request_id == self.artifacts_state.active_page_request_id
                                && snap.evidence_id == self.selected_evidence_id
                            {
                                if let Some(expected_gen) = self.artifacts_state.cached_generation {
                                    if snap.case_generation != expected_gen {
                                        self.artifacts_state.invalidate();
                                        self.begin_artifacts_tree(context.clone());
                                        return;
                                    }
                                } else {
                                    self.artifacts_state.cached_generation =
                                        Some(snap.case_generation);
                                }

                                self.artifacts_state.current_rows = snap.rows;
                                self.artifacts_state.has_more = snap.has_more;
                                self.artifacts_state.cursor = snap.next_cursor;
                                self.artifacts_state.total_count = Some(snap.total_matching);
                                self.artifacts_state.loading =
                                    self.artifacts_tree_pending.is_some();
                                self.artifacts_state.error = None;
                            }
                        }
                        Err(e) => {
                            self.artifacts_state.loading = self.artifacts_tree_pending.is_some();
                            self.artifacts_state.error = Some(e);
                        }
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.artifacts_page_pending = None;
                    self.artifacts_state.loading = self.artifacts_tree_pending.is_some();
                }
            }
        }
    }

    pub fn poll_search_worker(&mut self) {
        let Some(receiver) = &self.search_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(SearchWorkerResult {
                results,
                next_cursor,
                has_more,
                total_matches,
                coverage_statement,
            }) => {
                self.search_pending = None;
                self.search_state.loading = false;
                match results {
                    Ok(r) => {
                        self.search_state.results = r;
                        self.search_state.cursor = next_cursor;
                        self.search_state.has_more = has_more;
                        self.search_state.total_matches = total_matches;
                        self.search_state.coverage_statement = coverage_statement;
                        self.search_state.error = None;
                    }
                    Err(e) => {
                        self.search_state.error = Some(e);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.search_pending = None;
                self.search_state.loading = false;
            }
        }
    }

    pub fn poll_timeline_worker(&mut self) {
        let Some(receiver) = &self.timeline_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(TimelineWorkerResult::Page(res)) => {
                self.timeline_pending = None;
                self.timeline_state.loading = false;
                match res {
                    Ok(p) => {
                        self.timeline_state.events = p.events;
                        self.timeline_state.total_matching = p.total_matching;
                        self.timeline_state.has_more = p.has_more;
                        self.timeline_state.error = None;
                    }
                    Err(e) => {
                        self.timeline_state.error = Some(e);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.timeline_pending = None;
                self.timeline_state.loading = false;
            }
        }
    }

    pub fn poll_report_worker(&mut self) {
        let Some(receiver) = &self.report_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(ReportWorkerResult::Preview(res)) => {
                self.report_pending = None;
                self.report_state.loading = false;
                match res {
                    Ok(prev) => {
                        self.report_state.preview = Some(prev);
                        self.report_state.error = None;
                    }
                    Err(e) => {
                        self.report_state.error = Some(e);
                    }
                }
            }
            Ok(ReportWorkerResult::Exported(res)) => {
                self.report_pending = None;
                self.report_state.loading = false;
                match res {
                    Ok(path) => {
                        self.report_state.export_status =
                            Some(format!("Exported report to {}", path.display()));
                        self.report_state.error = None;
                    }
                    Err(e) => {
                        self.report_state.error = Some(e);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.report_pending = None;
                self.report_state.loading = false;
            }
        }
    }

    pub fn poll_unlock_worker(&mut self, context: &egui::Context) {
        let Some(receiver) = &self.unlock_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(UnlockWorkerResult {
                evidence_id,
                volume_index,
                result,
            }) => {
                self.unlock_pending = None;
                self.bitlocker_dialog.is_unlocking = false;
                match result {
                    Ok(cred) => {
                        self.unlock_manager.store_unverified_session(
                            evidence_id,
                            volume_index,
                            "NTFS (BitLocker Unlocked)".to_string(),
                            cred,
                        );
                        self.bitlocker_dialog.visible = false;
                        self.bitlocker_dialog.error = None;
                        self.status =
                            format!("Successfully unlocked BitLocker volume #{volume_index}.");
                        if self.browse_evidence_id == Some(evidence_id) {
                            self.begin_browse_volumes(
                                context.clone(),
                                evidence_id,
                                self.browse_evidence_name.clone(),
                            );
                            self.begin_browse_directory(
                                context.clone(),
                                evidence_id,
                                volume_index,
                                "/".to_string(),
                                0,
                            );
                        }
                    }
                    Err(e) => {
                        self.bitlocker_dialog.error = Some(e.clone());
                        self.bitlocker_dialog.visible = true;
                        self.status = format!("BitLocker unlock failed: {e}");
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.unlock_pending = None;
                self.bitlocker_dialog.is_unlocking = false;
                self.bitlocker_dialog.error =
                    Some("BitLocker unlock worker disconnected.".to_string());
            }
        }
    }

    pub fn poll_export_worker(&mut self) {
        let Some(receiver) = &self.export_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(ExportWorkerResult::Finished(res)) => {
                self.export_pending = None;
                self.export_cancel = None;
                match res {
                    Ok(rep) => {
                        let state_str = match rep.terminal_state {
                            ExportTerminalState::Complete => "Complete",
                            ExportTerminalState::Partial => "Partial",
                            ExportTerminalState::Canceled => "Canceled",
                            ExportTerminalState::Failed => "Failed",
                        };
                        let err_suffix = rep
                            .error
                            .map(|e| format!(" (Error: {e})"))
                            .unwrap_or_default();
                        self.status = format!(
                            "Export {state_str}: {} -> {} ({} bytes, SHA-256: {}{err_suffix})",
                            rep.source_path,
                            rep.dest_path.display(),
                            rep.bytes_written,
                            rep.sha256_hex
                        );
                    }
                    Err(e) => {
                        self.status = format!("Export Failed: {e}");
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.export_pending = None;
                self.export_cancel = None;
            }
        }
    }

    pub fn poll_hash_worker(&mut self) {
        let Some(receiver) = &self.hash_pending else {
            return;
        };
        match receiver.try_recv() {
            Ok(HashWorkerResult::Finished(res)) => {
                self.hash_pending = None;
                self.hash_cancel = None;
                match res {
                    Ok(rep) => {
                        let persist_str = if rep.persisted {
                            "persisted"
                        } else {
                            "not persisted"
                        };
                        self.status = format!(
                            "Hash Complete: {} SHA-256: {} ({persist_str})",
                            rep.logical_path, rep.sha256_hex
                        );
                        if let Some(entry) = &mut self.selected_browser_entry {
                            if entry.path == rep.logical_path {
                                entry.sha256 = Some(rep.sha256_hex);
                            }
                        }
                    }
                    Err(e) => {
                        self.status = format!("Hash Calculation Failed: {e}");
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.hash_pending = None;
                self.hash_cancel = None;
            }
        }
    }

    pub fn poll_integrity_worker(&mut self) {
        let Some(receiver) = &self.integrity_pending else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(IntegrityWorkerResult::Progress {
                    evidence_id,
                    done,
                    total,
                }) => {
                    self.integrity_running_id = Some(evidence_id);
                    self.integrity_progress = Some((done, total));
                }
                Ok(IntegrityWorkerResult::Finished(res)) => {
                    self.integrity_pending = None;
                    self.integrity_cancel = None;
                    self.integrity_running_id = None;
                    self.integrity_progress = None;
                    match res {
                        Ok(rep) => {
                            let label = rep.terminal_state.display_label();
                            let digest_str = rep.computed_sha256.as_deref().unwrap_or("none");
                            self.status = format!(
                                "Integrity #{}: {} (SHA-256: {})",
                                rep.evidence_id, label, digest_str
                            );
                            if let Some(case_path) = &self.opened_path {
                                if let Ok(page) = read_evidence_page(case_path, None, None) {
                                    self.evidence_page = Some(page);
                                }
                            } else if let Some(page) = &mut self.evidence_page {
                                if let Some(item) =
                                    page.items.iter_mut().find(|i| i.id == rep.evidence_id)
                                {
                                    item.integrity_status =
                                        Some(rep.terminal_state.as_str().to_string());
                                    item.sha256_hex = rep.computed_sha256.clone();
                                }
                            }
                        }
                        Err(e) => {
                            self.status = format!("Integrity verification failed: {e}");
                        }
                    }
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.integrity_pending = None;
                    self.integrity_cancel = None;
                    self.integrity_running_id = None;
                    self.integrity_progress = None;
                    break;
                }
            }
        }
    }

    pub fn poll_folder_export_worker(&mut self) {
        let Some(receiver) = &self.folder_export_pending else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(FolderExportWorkerResult::Progress {
                    files_done,
                    total_files,
                    bytes_done,
                }) => {
                    self.status = format!("Exporting folder: {files_done}/{total_files} files ({bytes_done} bytes)...");
                }
                Ok(FolderExportWorkerResult::Finished(res)) => {
                    self.folder_export_pending = None;
                    self.folder_export_cancel = None;
                    match res {
                        Ok(rep) => {
                            let state_str = match rep.terminal_state {
                                ExportTerminalState::Complete => "Complete",
                                ExportTerminalState::Partial => "Partial",
                                ExportTerminalState::Canceled => "Canceled",
                                ExportTerminalState::Failed => "Failed",
                            };
                            let manifest_info = rep
                                .manifest_path
                                .map(|p| format!(" (Manifest: {})", p.display()))
                                .unwrap_or_default();
                            self.status = format!(
                                "Folder Export {state_str}: {} -> {} ({} files exported, {} failed, {} bytes){manifest_info}",
                                rep.source_root_path,
                                rep.dest_dir.display(),
                                rep.files_exported,
                                rep.files_failed,
                                rep.bytes_written,
                            );
                        }
                        Err(e) => {
                            self.status = format!("Folder Export Failed: {e}");
                        }
                    }
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.folder_export_pending = None;
                    self.folder_export_cancel = None;
                    break;
                }
            }
        }
    }

    pub fn poll_folder_hash_worker(&mut self) {
        let Some(receiver) = &self.folder_hash_pending else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(FolderHashWorkerResult::Progress {
                    files_done,
                    total_files,
                    bytes_done,
                }) => {
                    self.status = format!("Calculating hashes: {files_done}/{total_files} files ({bytes_done} bytes)...");
                }
                Ok(FolderHashWorkerResult::Finished(res)) => {
                    self.folder_hash_pending = None;
                    self.folder_hash_cancel = None;
                    match res {
                        Ok(rep) => {
                            let state_str = match rep.terminal_state {
                                ExportTerminalState::Complete => "Complete",
                                ExportTerminalState::Partial => "Partial",
                                ExportTerminalState::Canceled => "Canceled",
                                ExportTerminalState::Failed => "Failed",
                            };
                            self.status = format!(
                                "Recursive Hash {state_str}: {} ({} files hashed, {} failed, {} bytes)",
                                rep.source_root_path,
                                rep.files_hashed,
                                rep.files_failed,
                                rep.bytes_hashed,
                            );
                        }
                        Err(e) => {
                            self.status = format!("Recursive hash calculation failed: {e}");
                        }
                    }
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.folder_hash_pending = None;
                    self.folder_hash_cancel = None;
                    break;
                }
            }
        }
    }

    pub fn apply_theme(&self, ctx: &egui::Context) {
        match self.theme {
            AppTheme::Light => ctx.set_visuals(egui::Visuals::light()),
            AppTheme::Dark => ctx.set_visuals(egui::Visuals::dark()),
            AppTheme::System => ctx.set_visuals(egui::Visuals::dark()),
        }
    }

    pub fn render_browse_lower_pane(&mut self, ui: &mut egui::Ui, lower_h: f32, total_w: f32) {
        let ctx = ui.ctx().clone();
        ui.allocate_ui_with_layout(
            egui::Vec2::new(total_w, lower_h),
            egui::Layout::left_to_right(egui::Align::Min),
            |lower_ui| {
                let available_lower_w = lower_ui.available_width();
                let prop_w = if self.layout.browse_properties_collapsed {
                    0.0
                } else {
                    self.layout.browse_properties_width.clamp(160.0, (available_lower_w - 200.0).max(160.0))
                };
                const SPLITTER_W: f32 = 8.0;
                let hex_w = if self.layout.browse_properties_collapsed {
                    // Keep the divider inside the visible layout so its
                    // expand control remains reachable while properties are
                    // collapsed.
                    (available_lower_w - SPLITTER_W).max(180.0)
                } else {
                    (available_lower_w - prop_w - SPLITTER_W).max(180.0)
                };

                // Left pane: Hex viewer
                lower_ui.allocate_ui_with_layout(
                    egui::Vec2::new(hex_w, lower_h),
                    egui::Layout::top_down(egui::Align::Min),
                    |hex_ui| {
                        let hex_act = hex_viewer::show(
                            hex_ui,
                            &mut self.hex_viewer_state,
                            &mut self.data_interpreter_state,
                        );
                        match hex_act {
                            hex_viewer::HexViewerAction::NavigateOffset(off) => {
                                if let Some(case_path) = self.opened_path.clone() {
                                    self.hex_viewer_state.current_offset = off;
                                    self.hex_viewer_state.selected_byte_offset = None;
                                    self.hex_viewer_state.selected_byte_length = None;
                                    let ev_id = self.hex_viewer_state.evidence_id.unwrap_or(0);
                                    let vol_idx = self.hex_viewer_state.volume_index;
                                    let p = if self.hex_viewer_state.logical_path.is_empty() {
                                        None
                                    } else {
                                        Some(self.hex_viewer_state.logical_path.clone())
                                    };
                                    let mut request = BoundedByteRequest::simple(
                                            case_path,
                                            ev_id,
                                            vol_idx,
                                            p,
                                            self.hex_viewer_state.entry_id,
                                            self.hex_viewer_state.source_namespace,
                                            off,
                                            512,
                                            self.hex_viewer_state.source_namespace == ByteSourceNamespace::AbsoluteDecodedMedia,
                                        );
                                    request.mapping_entry_id = self.hex_viewer_state.mapping_entry_id;
                                    self.begin_hex_read(ctx.clone(), request);
                                }
                            }
                            hex_viewer::HexViewerAction::PrevPage => {
                                if let (Some(off), Some(case_path)) = (
                                    hex_viewer::previous_page_offset(&self.hex_viewer_state),
                                    self.opened_path.clone(),
                                ) {
                                    self.hex_viewer_state.current_offset = off;
                                    self.hex_viewer_state.selected_byte_offset = None;
                                    self.hex_viewer_state.selected_byte_length = None;
                                    let ev_id = self.hex_viewer_state.evidence_id.unwrap_or(0);
                                    let vol_idx = self.hex_viewer_state.volume_index;
                                    let p = if self.hex_viewer_state.logical_path.is_empty() {
                                        None
                                    } else {
                                        Some(self.hex_viewer_state.logical_path.clone())
                                    };
                                    let mut request = BoundedByteRequest::simple(
                                            case_path,
                                            ev_id,
                                            vol_idx,
                                            p,
                                            self.hex_viewer_state.entry_id,
                                            self.hex_viewer_state.source_namespace,
                                            off,
                                            512,
                                            self.hex_viewer_state.source_namespace == ByteSourceNamespace::AbsoluteDecodedMedia,
                                        );
                                    request.mapping_entry_id = self.hex_viewer_state.mapping_entry_id;
                                    self.begin_hex_read(ctx.clone(), request);
                                }
                            }
                            hex_viewer::HexViewerAction::NextPage => {
                                if let (Some(off), Some(case_path)) = (
                                    hex_viewer::next_page_offset(&self.hex_viewer_state),
                                    self.opened_path.clone(),
                                ) {
                                    self.hex_viewer_state.current_offset = off;
                                    self.hex_viewer_state.selected_byte_offset = None;
                                    self.hex_viewer_state.selected_byte_length = None;
                                    let ev_id = self.hex_viewer_state.evidence_id.unwrap_or(0);
                                    let vol_idx = self.hex_viewer_state.volume_index;
                                    let p = if self.hex_viewer_state.logical_path.is_empty() {
                                        None
                                    } else {
                                        Some(self.hex_viewer_state.logical_path.clone())
                                    };
                                    let mut request = BoundedByteRequest::simple(
                                            case_path,
                                            ev_id,
                                            vol_idx,
                                            p,
                                            self.hex_viewer_state.entry_id,
                                            self.hex_viewer_state.source_namespace,
                                            off,
                                            512,
                                            self.hex_viewer_state.source_namespace == ByteSourceNamespace::AbsoluteDecodedMedia,
                                        );
                                    request.mapping_entry_id = self.hex_viewer_state.mapping_entry_id;
                                    self.begin_hex_read(ctx.clone(), request);
                                }
                            }
                            hex_viewer::HexViewerAction::ToggleDataInterpreter => {
                                self.layout.data_interpreter_window_open = !self.layout.data_interpreter_window_open;
                            }
                            hex_viewer::HexViewerAction::Close => {
                                self.clear_hex_viewer();
                            }
                            hex_viewer::HexViewerAction::None => {}
                        }
                    },
                );

                // Vertical splitter between Hex and Properties
                splitter::vertical_splitter(
                    lower_ui,
                    "browse_prop_splitter",
                    &mut self.layout.browse_properties_width,
                    &mut self.layout.browse_properties_collapsed,
                    320.0,
                    180.0,
                    (available_lower_w - 200.0).max(180.0),
                    true,
                );

                // Right pane: Properties
                if !self.layout.browse_properties_collapsed {
                    let actual_prop_w = lower_ui.available_width();
                    lower_ui.allocate_ui_with_layout(
                        egui::Vec2::new(actual_prop_w, lower_h),
                        egui::Layout::top_down(egui::Align::Min),
                        |prop_ui| {
                            prop_ui.group(|ui| {
                                ui.heading("Properties");
                                ui.separator();
                                egui::ScrollArea::vertical()
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        if let Some(entry) = &self.selected_browser_entry {
                                            egui::Grid::new("selected_item_prop_grid")
                                                .num_columns(2)
                                                .spacing([12.0, 4.0])
                                                .show(ui, |ui| {
                                                    ui.strong("Name:");
                                                    ui.label(&entry.name);
                                                    ui.end_row();

                                                    ui.strong("Path:");
                                                    ui.monospace(&entry.path);
                                                    ui.end_row();

                                                    ui.strong("Type:");
                                                    ui.label(if entry.is_dir { "Directory" } else { "File" });
                                                    ui.end_row();

                                                    ui.strong("Size:");
                                                    ui.label(format!("{} ({} bytes)", source_browser::format_size_human(entry.size_bytes), entry.size_bytes.unwrap_or(0)));
                                                    ui.end_row();

                                                    if let Some(sha) = &entry.sha256 {
                                                        ui.strong("SHA-256:");
                                                        ui.monospace(sha);
                                                        ui.end_row();
                                                    }

                                                    ui.strong("Allocated size:");
                                                    ui.weak("Not recorded by the live directory provider");
                                                    ui.end_row();

                                                    ui.strong("File slack:");
                                                    ui.weak("Not calculated — allocated size is unavailable");
                                                    ui.end_row();

                                                    ui.strong("Status:");
                                                    ui.label(if entry.is_deleted { "Deleted / Recovered" } else { "Active" });
                                                    ui.end_row();

                                                    ui.strong("Created (UTC):");
                                                    ui.label(entry.created_utc.as_deref().unwrap_or("Not recorded"));
                                                    ui.end_row();

                                                    ui.strong("Modified (UTC):");
                                                    ui.label(entry.modified_utc.as_deref().unwrap_or("-"));
                                                    ui.end_row();

                                                    ui.strong("Accessed (UTC):");
                                                    ui.label(entry.accessed_utc.as_deref().unwrap_or("Not recorded"));
                                                    ui.end_row();

                                                    if let Some(record) = entry.file_record_number {
                                                        ui.strong("MFT record #:");
                                                        ui.monospace(record.to_string());
                                                        ui.end_row();
                                                    }

                                                    if let Some(offset) = entry.physical_offset {
                                                        ui.strong("Decoded-media offset:");
                                                        ui.monospace(format!("0x{offset:X} ({offset} bytes)"));
                                                        ui.end_row();
                                                    }

                                                    if let Some(entry_id) = entry.canonical_entry_id {
                                                        ui.strong("Case entry ID:");
                                                        ui.monospace(entry_id.to_string());
                                                        ui.end_row();
                                                    }

                                                    if let Some(status) = &entry.reconstruction_status {
                                                        ui.strong("Reconstruction:");
                                                        ui.label(status);
                                                        ui.end_row();
                                                    }

                                                    if let Some(provenance) = &entry.provenance {
                                                        ui.strong("Provenance:");
                                                        ui.label(provenance);
                                                        ui.end_row();
                                                    }

                                                    if let Some(vol) = &self.active_volume_identity {
                                                        ui.strong("Filesystem:");
                                                        ui.label(&vol.filesystem_type);
                                                        ui.end_row();

                                                        ui.strong("Encryption:");
                                                        ui.label(vol.encryption_type.as_deref().unwrap_or("None"));
                                                        ui.end_row();

                                                        ui.strong("Part. Start:");
                                                        ui.monospace(format!("0x{:X}", vol.partition_start));
                                                        ui.end_row();
                                                    }
                                                });
                                        } else {
                                            ui.weak("Select an item above to view forensic properties.");
                                            if let Some(page) = &self.browse_page {
                                                ui.add_space(8.0);
                                                ui.strong("Current Directory:");
                                                ui.monospace(&page.path);
                                                ui.label(format!("Total entries: {}", page.total_entries));
                                                ui.label(format!("Reader: {}", page.reader_label));
                                            }
                                        }
                                    });
                            });
                        },
                    );
                }
            },
        );
    }

    fn show_artifact_inspector_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.weak("Drag this panel's upper border to resize it.");
        });
        let selection_tuple = self
            .selected_artifact
            .map(|selection| (selection.entry_id, selection.generation));
        let response = inspector::show(
            ui,
            selection_tuple,
            self.artifact_detail.as_ref(),
            self.artifact_pending.is_some(),
            self.artifact_detail_error.as_deref(),
            self.view_stale,
            &mut self.inspector_pinned,
        );
        if response.close_clicked {
            self.clear_inspector();
        } else if response.bookmark_clicked {
            if let Some(detail) = &self.artifact_detail {
                self.bookmark_dialog.visible = true;
                self.bookmark_dialog.title = format!("Inspected Entry #{}", detail.entry_id);
                self.bookmark_dialog.target = Some(BookmarkTarget::IndexedResult {
                    evidence_id: self.selected_evidence_id.unwrap_or(1),
                    entry_id: detail.entry_id,
                    logical_path: detail.logical_path.clone(),
                    artifact_kind: detail
                        .artifact_kind
                        .clone()
                        .unwrap_or_else(|| "record".to_string()),
                    is_deleted: false,
                });
            }
        }
    }
}

impl eframe::App for KDFTDesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.apply_theme(&ctx);
        self.handle_close_request(&ctx);

        // Poll background receivers
        self.poll_worker(&ctx);
        self.poll_artifact_worker(&ctx);
        self.poll_browse_worker(&ctx);
        self.poll_bookmark_worker(&ctx);
        self.poll_processing(&ctx);
        self.poll_processing_history_worker();
        self.poll_hex_worker();
        self.poll_artifacts_worker(&ctx);
        self.poll_search_worker();
        self.poll_timeline_worker();
        self.poll_report_worker();
        self.poll_unlock_worker(&ctx);
        self.poll_export_worker();
        self.poll_hash_worker();
        self.poll_integrity_worker();
        self.poll_folder_export_worker();
        self.poll_folder_hash_worker();
        self.poll_deferred_close(&ctx);

        if self.processing.is_some() {
            let should_refresh = self
                .last_processing_history_refresh
                .is_none_or(|time| time.elapsed() >= Duration::from_millis(750));
            if should_refresh && self.processing_history_pending.is_none() {
                self.last_processing_history_refresh = Some(std::time::Instant::now());
                self.begin_live_job_history_refresh(ctx.clone());
            }
        }

        if self.active_tab == TopLevelTab::Artifacts && self.processing.is_some() {
            let should_probe = match self.last_probe_time {
                Some(t) => t.elapsed() >= Duration::from_millis(750),
                None => true,
            };
            if should_probe && self.artifacts_probe_pending.is_none() {
                self.last_probe_time = Some(std::time::Instant::now());
                self.begin_artifacts_probe(ctx.clone());
            }
        }

        // Top Navigation & Theme Bar
        egui::Panel::top("top_workbench_panel").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(RichText::new("KDFT Workbench").strong());
                ui.separator();

                // Top-Level Tabs
                for tab in [
                    TopLevelTab::Case,
                    TopLevelTab::Evidence,
                    TopLevelTab::Browse,
                    TopLevelTab::Process,
                    TopLevelTab::Artifacts,
                    TopLevelTab::Search,
                    TopLevelTab::Timeline,
                    TopLevelTab::Bookmarks,
                    TopLevelTab::Reports,
                ] {
                    let is_sel = self.active_tab == tab;
                    if ui.selectable_label(is_sel, tab.label()).clicked() && self.active_tab != tab
                    {
                        self.active_tab = tab;
                        if !self.inspector_pinned {
                            self.clear_inspector();
                        }
                        if tab == TopLevelTab::Artifacts && self.opened_path.is_some() {
                            self.begin_artifacts_probe(ctx.clone());
                            if self.artifacts_state.category_tree.is_empty() {
                                self.begin_artifacts_tree(ctx.clone());
                            }
                        }
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Theme selection
                    egui::ComboBox::from_id_salt("theme_selector")
                        .selected_text(match self.theme {
                            AppTheme::Light => "Light Theme",
                            AppTheme::Dark => "Dark Theme",
                            AppTheme::System => "System Theme",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.theme, AppTheme::Light, "Light");
                            ui.selectable_value(&mut self.theme, AppTheme::Dark, "Dark");
                            ui.selectable_value(&mut self.theme, AppTheme::System, "System");
                        });

                    if ui.button("⚙ Case Settings...").clicked() {
                        let cur_tz = self
                            .summary
                            .as_ref()
                            .map(|s| s.timezone.clone())
                            .unwrap_or_else(|| "UTC".to_string());
                        self.case_settings_dialog.current_timezone = cur_tz.clone();
                        self.case_settings_dialog.selected_timezone = cur_tz;
                        self.case_settings_dialog.timezone_filter.clear();
                        self.case_settings_dialog.error = None;
                        self.case_settings_dialog.visible = true;
                    }

                    if let Some(sum) = &self.summary {
                        ui.label(RichText::new(format!("TZ: {}", sum.timezone)).weak());
                    }

                    if let Some(path) = &self.opened_path {
                        ui.label(
                            RichText::new(path.file_name().unwrap_or_default().to_string_lossy())
                                .weak(),
                        );
                    }
                });
            });
        });

        // Bottom Status Bar
        egui::Panel::bottom("bottom_status_panel").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status).strong());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.is_busy() {
                        ui.spinner();
                    }

                    if self.hex_viewer_state.active {
                        ui.separator();
                        ui.monospace(format!(
                            "Hex: [{:?}] Offset: 0x{:08X}",
                            self.hex_viewer_state.source_namespace,
                            self.hex_viewer_state.current_offset
                        ));
                    }

                    if let Some(sum) = &self.summary {
                        ui.separator();
                        ui.label(format!("Audit Gen #{}", sum.generation));
                    }
                });
            });
        });

        // Artifact details live in a dedicated resizable panel so long records
        // remain readable on Search and Timeline instead of extending below the
        // application viewport.
        if self.selected_artifact.is_some() {
            egui::Panel::bottom("artifact_inspector_panel")
                .resizable(true)
                .default_size(330.0)
                .min_size(140.0)
                .show(ui, |ui| self.show_artifact_inspector_panel(ui));
        }

        // Central Area Routing
        egui::CentralPanel::default().show(ui, |ui| {
            match self.active_tab {
                TopLevelTab::Case => {
                    let is_busy = self.is_busy();
                    let summary_ref = self.summary.as_ref();
                    let act = case::show(
                        ui,
                        &mut self.case_path,
                        self.opened_path.as_ref(),
                        summary_ref,
                        &mut self.new_case,
                        is_busy,
                        self.error.as_deref(),
                    );
                    match act {
                        case::CaseViewAction::OpenCase(_) => self.begin_open(ctx.clone()),
                        case::CaseViewAction::CreateCase => self.begin_create(ctx.clone()),
                        case::CaseViewAction::CloseCase => self.clear_opened_view(),
                        case::CaseViewAction::BrowseCasePath => {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("KDFT Case (*.kdft, *.sqlite)", &["kdft", "sqlite"])
                                .pick_file()
                            {
                                self.case_path = p.display().to_string();
                            }
                        }
                        case::CaseViewAction::None => {}
                    }
                }
                TopLevelTab::Evidence => {
                    let ev_ref = self.evidence_page.as_ref();
                    let act = evidence::show(
                        ui,
                        ev_ref,
                        self.evidence_page_index,
                        self.selected_evidence_id,
                        &self.browse_volumes,
                        self.is_busy(),
                        self.error.as_deref(),
                        self.integrity_running_id,
                        self.integrity_progress,
                    );
                    match act {
                        evidence::EvidenceViewAction::AttachImage => {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter(
                                    "Forensic Images (*.dd, *.raw, *.img, *.e01)",
                                    &["dd", "raw", "img", "e01"],
                                )
                                .pick_file()
                            {
                                self.open_intake_wizard(p, NativeEvidenceKind::Image);
                            }
                        }
                        evidence::EvidenceViewAction::AttachLocalFolder => {
                            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                self.open_intake_wizard(p, NativeEvidenceKind::Folder);
                            }
                        }
                        evidence::EvidenceViewAction::VerifyIntegrity(id) => {
                            let case_path = self.opened_path.clone().unwrap_or_default();
                            let expected = self.evidence_page.as_ref().and_then(|p| {
                                p.items.iter().find(|i| i.id == id).and_then(|item| {
                                    item.expected_sha256.clone().or_else(|| {
                                        let src = kdft_desktop_core::browse::read_evidence_record(std::path::Path::new(&case_path), id)
                                            .map(|r| std::path::PathBuf::from(r.source_path))
                                            .unwrap_or_else(|_| std::path::PathBuf::from(&item.source_path_preview));
                                        kdft_desktop_core::detect_companion_expected_sha256(&src)
                                    })
                                })
                            });
                            self.begin_verify_integrity(ctx.clone(), kdft_desktop_core::EvidenceIntegrityRequest {
                                case_path,
                                evidence_id: id,
                                expected_sha256: expected,
                                skip_reason: None,
                                is_skip: false,
                                is_defer: false,
                            });
                        }
                        evidence::EvidenceViewAction::CancelIntegrity => {
                            if let Some(c) = &self.integrity_cancel {
                                c.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        evidence::EvidenceViewAction::SelectEvidence(id) => {
                            self.selected_evidence_id = Some(id);
                            self.browse_evidence_id = Some(id);
                            if let Some(page) = &self.evidence_page {
                                if let Some(item) = page.items.iter().find(|i| i.id == id) {
                                    self.browse_evidence_name = item.display_name.clone();
                                    self.begin_browse_volumes(
                                        ctx.clone(),
                                        id,
                                        item.display_name.clone(),
                                    );
                                }
                            }
                        }
                        evidence::EvidenceViewAction::AnalyzeEvidence(id) => {
                            self.processing_options_dialog.visible = true;
                            self.processing_options_dialog.evidence_id = id;
                            if let Some(page) = &self.evidence_page {
                                if let Some(item) = page.items.iter().find(|i| i.id == id) {
                                    self.processing_options_dialog.evidence_name =
                                        item.display_name.clone();
                                    self.processing_options_dialog.evidence_path =
                                        item.source_path_preview.clone();
                                }
                            }
                            self.processing_options_dialog.volumes = self.browse_volumes.clone();
                            self.processing_options_dialog.selected_volumes =
                                self.browse_volumes.iter().map(|v| v.index).collect();
                        }
                        evidence::EvidenceViewAction::BrowseEvidence(id) => {
                            self.active_tab = TopLevelTab::Browse;
                            self.browse_evidence_id = Some(id);
                            self.selected_evidence_id = Some(id);
                            if let Some(page) = &self.evidence_page {
                                if let Some(item) = page.items.iter().find(|i| i.id == id) {
                                    self.browse_evidence_name = item.display_name.clone();
                                    self.begin_browse_volumes(
                                        ctx.clone(),
                                        id,
                                        item.display_name.clone(),
                                    );
                                }
                            }
                        }
                        evidence::EvidenceViewAction::ViewRawBytes(id) => {
                            if let Some(case_path) = self.opened_path.clone() {
                                self.hex_viewer_state.active = true;
                                self.hex_viewer_state.source_namespace =
                                    ByteSourceNamespace::AbsoluteDecodedMedia;
                                self.hex_viewer_state.evidence_id = Some(id);
                                self.begin_hex_read(
                                    ctx.clone(),
                                    BoundedByteRequest::simple(
                                        case_path,
                                        id,
                                        0,
                                        None,
                                        None,
                                        ByteSourceNamespace::AbsoluteDecodedMedia,
                                        0,
                                        512,
                                        true,
                                    ),
                                );
                            }
                        }
                        evidence::EvidenceViewAction::UnlockVolume {
                            evidence_id,
                            volume_index,
                            volume_label,
                        } => {
                            self.bitlocker_dialog.visible = true;
                            self.bitlocker_dialog.evidence_id = evidence_id;
                            self.bitlocker_dialog.volume_index = volume_index;
                            self.bitlocker_dialog.volume_label = volume_label;
                        }
                        evidence::EvidenceViewAction::PrevPage => {
                            if self.evidence_page_index > 0 {
                                let target = self.evidence_page_index - 1;
                                let after_id =
                                    self.evidence_page_starts.get(target).copied().flatten();
                                self.begin_evidence_page(ctx.clone(), target, after_id);
                            }
                        }
                        evidence::EvidenceViewAction::NextPage => {
                            let target = self.evidence_page_index + 1;
                            let after_id = self
                                .evidence_page
                                .as_ref()
                                .and_then(|p| p.items.last().map(|i| i.id));
                            if self.evidence_page_starts.len() <= target {
                                self.evidence_page_starts.resize(target + 1, None);
                            }
                            self.evidence_page_starts[target] = after_id;
                            self.begin_evidence_page(ctx.clone(), target, after_id);
                        }
                        evidence::EvidenceViewAction::None => {}
                    }
                }
                TopLevelTab::Browse => {
                    let ev_items = self
                        .evidence_page
                        .as_ref()
                        .map(|p| p.items.as_slice())
                        .unwrap_or(&[]);

                    let total_size = ui.available_size();
                    let total_w = total_size.x;
                    let total_h = total_size.y;

                    const SPLITTER_H: f32 = 8.0;
                    const MIN_UPPER: f32 = 120.0;
                    const MIN_LOWER: f32 = 120.0;

                    let (upper_h, lower_h) = if self.layout.browse_lower_collapsed {
                        ((total_h - SPLITTER_H).max(MIN_UPPER), 0.0)
                    } else {
                        let max_upper = (total_h - SPLITTER_H - MIN_LOWER).max(MIN_UPPER);
                        let upper = self.layout.browse_upper_height.clamp(MIN_UPPER, max_upper);
                        let lower = (total_h - upper - SPLITTER_H).max(MIN_LOWER);
                        (upper, lower)
                    };

                    let upper_table_height = (upper_h - 100.0).max(60.0);
                    let act = ui.allocate_ui_with_layout(
                        egui::Vec2::new(total_w, upper_h),
                        egui::Layout::top_down(egui::Align::Min),
                        |upper_ui| {
                            source_browser::show(
                                upper_ui,
                                ev_items,
                                self.browse_evidence_id,
                                &self.browse_evidence_name,
                                &self.browse_volumes,
                                self.browse_selected_volume,
                                &self.browse_path,
                                &self.browse_history_back,
                                &self.browse_history_forward,
                                self.browse_page.as_ref(),
                                self.browse_loading,
                                self.browse_error.as_deref(),
                                self.selected_browser_entry.as_ref(),
                                upper_table_height,
                                &self.unlock_manager,
                            )
                        },
                    ).inner;

                    match act {
                        source_browser::SourceBrowserAction::SelectEvidence(id) => {
                            self.browse_evidence_id = Some(id);
                            self.selected_evidence_id = Some(id);
                            if let Some(page) = &self.evidence_page {
                                if let Some(item) = page.items.iter().find(|i| i.id == id) {
                                    self.browse_evidence_name = item.display_name.clone();
                                    self.begin_browse_volumes(
                                        ctx.clone(),
                                        id,
                                        item.display_name.clone(),
                                    );
                                }
                            }
                        }
                        source_browser::SourceBrowserAction::SelectVolume(idx) => {
                            self.browse_selected_volume = idx;
                            self.browse_history_back.clear();
                            self.browse_history_forward.clear();
                            self.browse_path = "/".to_string();
                            self.selected_browser_entry = None;
                            if let Some(vol) = self.browse_volumes.get(idx) {
                                if let Some(ev_id) = self.browse_evidence_id {
                                    self.active_volume_identity = Some(VolumeIdentity::new(
                                        self.summary.as_ref().map(|s| s.id).unwrap_or(0),
                                        ev_id,
                                        idx,
                                        vol.start_offset,
                                        vol.size_bytes,
                                        vol.filesystem.clone(),
                                        if vol.is_bitlocker {
                                            Some("BitLocker".to_string())
                                        } else {
                                            None
                                        },
                                        None,
                                    ));
                                }
                            }
                            if let Some(id) = self.browse_evidence_id {
                                self.begin_browse_directory(
                                    ctx.clone(),
                                    id,
                                    idx,
                                    "/".to_string(),
                                    0,
                                );
                            }
                        }
                        source_browser::SourceBrowserAction::LockVolume { evidence_id, volume_index } => {
                            self.unlock_manager.lock_volume(evidence_id, volume_index);
                            self.browse_page = None;
                            self.hex_viewer_state.loaded_bytes.clear();
                            self.hex_viewer_state.active = false;
                            self.begin_browse_directory(
                                ctx.clone(),
                                evidence_id,
                                volume_index,
                                self.browse_path.clone(),
                                0,
                            );
                        }
                        source_browser::SourceBrowserAction::NavigatePath(p) => {
                            if self.browse_path != p {
                                self.browse_history_back.push(self.browse_path.clone());
                                self.browse_history_forward.clear();
                            }
                            self.browse_path = p.clone();
                            self.selected_browser_entry = None;
                            if let Some(id) = self.browse_evidence_id {
                                self.begin_browse_directory(
                                    ctx.clone(),
                                    id,
                                    self.browse_selected_volume,
                                    p,
                                    0,
                                );
                            }
                        }
                        source_browser::SourceBrowserAction::NavigateOffset(offset) => {
                            if let Some(id) = self.browse_evidence_id {
                                self.begin_browse_directory(
                                    ctx.clone(),
                                    id,
                                    self.browse_selected_volume,
                                    self.browse_path.clone(),
                                    offset,
                                );
                            }
                        }
                        source_browser::SourceBrowserAction::SelectEntry {
                            evidence_id,
                            volume_index,
                            path,
                            name,
                            is_dir,
                            is_deleted,
                            size_bytes,
                            created_utc,
                            modified_utc,
                            accessed_utc,
                            provenance,
                            reconstruction_status,
                            file_record_number,
                            physical_offset,
                            canonical_entry_id,
                        } => {
                            let sha256 = self.opened_path.as_ref().and_then(|cp| {
                                let conn = rusqlite::Connection::open(cp).ok()?;
                                let meta: Option<String> = conn.query_row(
                                    "SELECT metadata_json FROM filesystem_entries WHERE evidence_id = ?1 AND logical_path = ?2",
                                    rusqlite::params![evidence_id, &path],
                                    |r| r.get(0),
                                ).ok().flatten();
                                let val: serde_json::Value = serde_json::from_str(&meta?).ok()?;
                                val.get("file_sha256").and_then(|s| s.as_str()).map(|s| s.to_string())
                            });

                            self.selected_browser_entry = Some(crate::views::source_browser::SelectedBrowserEntry {
                                name: name.clone(),
                                path: path.clone(),
                                is_dir,
                                is_deleted,
                                size_bytes,
                                created_utc,
                                modified_utc,
                                accessed_utc,
                                provenance,
                                reconstruction_status,
                                file_record_number,
                                physical_offset,
                                canonical_entry_id,
                                sha256,
                            });
                            if !is_dir {
                                if let Some(case_path) = self.opened_path.clone() {
                                    self.clear_hex_viewer();
                                    self.hex_viewer_state.active = true;
                                    self.hex_viewer_state.source_namespace = ByteSourceNamespace::LogicalFile;
                                    self.hex_viewer_state.logical_path = path.clone();
                                    self.hex_viewer_state.evidence_id = Some(evidence_id);
                                    self.hex_viewer_state.volume_index = volume_index;
                                    self.hex_viewer_state.entry_id = None;
                                    self.hex_viewer_state.mapping_entry_id = canonical_entry_id;
                                    self.hex_viewer_state.current_offset = 0;
                                    let mut request = BoundedByteRequest::simple(
                                            case_path,
                                            evidence_id,
                                            volume_index,
                                            Some(path),
                                            None,
                                            ByteSourceNamespace::LogicalFile,
                                            0,
                                            512,
                                            false,
                                        );
                                    request.mapping_entry_id = canonical_entry_id;
                                    self.begin_hex_read(ctx.clone(), request);
                                }
                            }
                        }
                        source_browser::SourceBrowserAction::OpenEntry {
                            evidence_id,
                            volume_index,
                            path,
                            is_dir,
                            canonical_entry_id,
                        } => {
                            if is_dir {
                                if self.browse_path != path {
                                    self.browse_history_back.push(self.browse_path.clone());
                                    self.browse_history_forward.clear();
                                }
                                self.browse_path = path.clone();
                                self.selected_browser_entry = None;
                                self.begin_browse_directory(
                                    ctx.clone(),
                                    evidence_id,
                                    volume_index,
                                    path,
                                    0,
                                );
                            } else if let Some(case_path) = self.opened_path.clone() {
                                self.clear_hex_viewer();
                                self.hex_viewer_state.active = true;
                                self.hex_viewer_state.source_namespace = ByteSourceNamespace::LogicalFile;
                                self.hex_viewer_state.logical_path = path.clone();
                                self.hex_viewer_state.evidence_id = Some(evidence_id);
                                self.hex_viewer_state.volume_index = volume_index;
                                self.hex_viewer_state.entry_id = None;
                                self.hex_viewer_state.mapping_entry_id = canonical_entry_id;
                                self.hex_viewer_state.current_offset = 0;
                                let mut request = BoundedByteRequest::simple(
                                        case_path,
                                        evidence_id,
                                        volume_index,
                                        Some(path),
                                        None,
                                        ByteSourceNamespace::LogicalFile,
                                        0,
                                        512,
                                        false,
                                    );
                                request.mapping_entry_id = canonical_entry_id;
                                self.begin_hex_read(ctx.clone(), request);
                            }
                        }
                        source_browser::SourceBrowserAction::BookmarkFolder {
                            evidence_id,
                            volume_index,
                            path,
                            is_recursive,
                        } => {
                            self.bookmark_dialog.visible = true;
                            self.bookmark_dialog.folder_name = "Live Sources".to_string();
                            self.bookmark_dialog.title = format!("Folder: {path}");
                            self.bookmark_dialog.target = Some(BookmarkTarget::Folder {
                                evidence_id,
                                volume_index,
                                logical_path: path,
                                is_indexed: false,
                            });
                            self.bookmark_dialog.is_recursive = is_recursive;
                        }
                        source_browser::SourceBrowserAction::BookmarkFile {
                            evidence_id,
                            volume_index,
                            path,
                            is_dir,
                            is_deleted,
                        } => {
                            self.bookmark_dialog.visible = true;
                            self.bookmark_dialog.folder_name = "Live Sources".to_string();
                            self.bookmark_dialog.title = format!("File: {path}");
                            self.bookmark_dialog.target = Some(BookmarkTarget::LiveSourceFile {
                                evidence_id,
                                volume_index,
                                logical_path: path,
                                is_dir,
                                is_deleted,
                            });
                            self.bookmark_dialog.is_recursive = false;
                        }
                        source_browser::SourceBrowserAction::ExportEntry {
                            evidence_id,
                            volume_index,
                            path,
                            is_dir,
                        } => {
                            if is_dir {
                                let dest = rfd::FileDialog::new().pick_folder();
                                if let Some(dest_dir) = dest {
                                    self.begin_export_folder(
                                        ctx.clone(),
                                        evidence_id,
                                        volume_index,
                                        path,
                                        dest_dir,
                                    );
                                } else {
                                    self.status = format!("Export Canceled: no destination chosen for folder {path}.");
                                }
                            } else {
                                let file_name = Path::new(&path)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("exported_file");
                                let dest = rfd::FileDialog::new()
                                    .set_file_name(file_name)
                                    .save_file();
                                if let Some(dest_path) = dest {
                                    self.begin_export_file(
                                        ctx.clone(),
                                        evidence_id,
                                        volume_index,
                                        path,
                                        None,
                                        dest_path,
                                    );
                                } else {
                                    self.status = format!("Export Canceled: no destination chosen for {path}.");
                                }
                            }
                        }
                        source_browser::SourceBrowserAction::CalculateHashes {
                            evidence_id,
                            volume_index,
                            path,
                            is_dir,
                            is_recursive,
                        } => {
                            if is_dir || is_recursive {
                                self.begin_calculate_hashes_recursive(
                                    ctx.clone(),
                                    evidence_id,
                                    volume_index,
                                    path,
                                );
                            } else {
                                self.begin_calculate_hashes(
                                    ctx.clone(),
                                    evidence_id,
                                    volume_index,
                                    path,
                                    None,
                                );
                            }
                        }
                        source_browser::SourceBrowserAction::ShowInTimeline { path } => {
                            self.active_tab = TopLevelTab::Timeline;
                            self.timeline_state.text_filter = path.clone();
                            self.timeline_state.category_filter.clear();
                            self.timeline_state.page = 0;
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_timeline(
                                    ctx.clone(),
                                    TimelineQuery {
                                        case_path,
                                        evidence_id: self.browse_evidence_id,
                                        from_utc: None,
                                        to_utc: None,
                                        category_filter: None,
                                        timestamp_type_filter: None,
                                        text_filter: Some(path),
                                        page: 0,
                                        page_size: 50,
                                    },
                                );
                            }
                        }
                        source_browser::SourceBrowserAction::ToggleDataInterpreter => {
                            self.layout.data_interpreter_window_open = !self.layout.data_interpreter_window_open;
                        }
                        source_browser::SourceBrowserAction::None => {}
                    }

                    // Draggable splitter between upper directory table and lower hex/properties pane
                    splitter::horizontal_splitter(
                        ui,
                        "browse_splitter",
                        &mut self.layout.browse_upper_height,
                        &mut self.layout.browse_lower_collapsed,
                        340.0,
                        MIN_UPPER,
                        (total_h - SPLITTER_H - MIN_LOWER).max(MIN_UPPER),
                    );

                    // Lower area: Hex Viewer and Selected Item Properties
                    if !self.layout.browse_lower_collapsed && lower_h > 0.0 {
                        self.render_browse_lower_pane(ui, lower_h, total_w);
                    }
                }
                TopLevelTab::Process => {
                    let is_proc = self.processing.is_some();
                    let name = self.processing.as_ref().map(|j| j.evidence_name.as_str());
                    let snap = self.processing.as_ref().map(|j| j.tracker.snapshot());
                    let last = self.last_process.as_ref();

                    let act = processing::show(
                        ui,
                        is_proc,
                        name,
                        snap.as_ref(),
                        last,
                        self.error.as_deref(),
                        self.processing_history_error.as_deref(),
                        &self.job_history,
                        &self.coverage_records,
                    );
                    match act {
                        processing::ProcessingViewAction::CancelProcessing => {
                            if let Some(job) = &self.processing {
                                job.tracker.request_cancellation();
                            }
                        }
                        processing::ProcessingViewAction::AcknowledgeSummary => {
                            self.last_process = None;
                        }
                        processing::ProcessingViewAction::RefreshHistory => {
                            self.last_processing_history_refresh =
                                Some(std::time::Instant::now());
                            self.begin_processing_history_refresh(ctx.clone());
                        }
                        processing::ProcessingViewAction::None => {}
                    }
                }
                TopLevelTab::Artifacts => {
                    let has_c = self.opened_path.is_some();
                    let selected_entry_id = self.selected_artifact.map(|item| item.entry_id);
                    let act =
                        artifacts::show(ui, &mut self.artifacts_state, selected_entry_id, has_c);
                    match act {
                        artifacts::ArtifactsViewAction::SelectCategory { main, sub } => {
                            self.artifacts_state.selected_category = Some(main.clone());
                            self.artifacts_state.selected_sub_category = sub.clone();
                            self.artifacts_state.current_page = 0;
                            self.artifacts_state.cursor = None;
                            self.artifacts_state.cursor_history.clear();
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_artifacts_page(
                                    ctx.clone(),
                                    ArtifactPageQuery {
                                        case_path,
                                        evidence_id: self.selected_evidence_id,
                                        request_id: 0,
                                        category_main: main,
                                        category_sub: sub,
                                        name_filter: if self
                                            .artifacts_state
                                            .search_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.artifacts_state.search_filter.clone())
                                        },
                                        extension_filter: if self
                                            .artifacts_state
                                            .extension_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.artifacts_state.extension_filter.clone())
                                        },
                                        entry_type_filter: None,
                                        deleted_only: self.artifacts_state.deleted_only,
                                        date_from_utc: None,
                                        date_to_utc: None,
                                        cursor: None,
                                        limit: 100,
                                    },
                                );
                            }
                        }
                        artifacts::ArtifactsViewAction::RefreshAll => {
                            self.artifacts_state.invalidate();
                            self.begin_artifacts_tree(ctx.clone());
                        }
                        artifacts::ArtifactsViewAction::RefreshQuery => {
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_artifacts_page(
                                    ctx.clone(),
                                    ArtifactPageQuery {
                                        case_path,
                                        evidence_id: self.selected_evidence_id,
                                        request_id: 0,
                                        category_main: self
                                            .artifacts_state
                                            .selected_category
                                            .clone()
                                            .unwrap_or_else(|| "Filesystem".to_string()),
                                        category_sub: self
                                            .artifacts_state
                                            .selected_sub_category
                                            .clone(),
                                        name_filter: if self
                                            .artifacts_state
                                            .search_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.artifacts_state.search_filter.clone())
                                        },
                                        extension_filter: if self
                                            .artifacts_state
                                            .extension_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.artifacts_state.extension_filter.clone())
                                        },
                                        entry_type_filter: None,
                                        deleted_only: self.artifacts_state.deleted_only,
                                        date_from_utc: None,
                                        date_to_utc: None,
                                        cursor: self.artifacts_state.cursor.clone(),
                                        limit: 100,
                                    },
                                );
                            }
                        }
                        artifacts::ArtifactsViewAction::InspectEntry { entry_id, path: _ } => {
                            let gen = self.summary.as_ref().map(|s| s.generation).unwrap_or(0);
                            self.artifacts_state.selected_artifact = self
                                .artifacts_state
                                .current_rows
                                .iter()
                                .find(|r| r.id == entry_id)
                                .cloned();
                            self.begin_artifact_detail(
                                ctx.clone(),
                                ArtifactSelection {
                                    entry_id,
                                    generation: gen,
                                },
                            );
                            // A normal row selection loads the SQLite-backed
                            // Inspector only. Evidence byte recovery can be
                            // materially slower and belongs to the explicit
                            // View Hex action (double-click/context menu).
                            // Clear an older unowned byte view so it cannot be
                            // mistaken for the newly selected row.
                            self.clear_hex_viewer();
                        }
                        artifacts::ArtifactsViewAction::ViewHex { entry_id, path } => {
                            if let Some(case_path) = self.opened_path.clone() {
                                self.hex_viewer_state.active = true;
                                self.hex_viewer_state.source_namespace =
                                    ByteSourceNamespace::LogicalFile;
                                self.hex_viewer_state.entry_id = Some(entry_id);
                                self.hex_viewer_state.logical_path = path.clone();
                                self.begin_hex_read(
                                    ctx.clone(),
                                    BoundedByteRequest::simple(
                                        case_path,
                                        self.selected_evidence_id.unwrap_or(0),
                                        0,
                                        Some(path),
                                        Some(entry_id),
                                        ByteSourceNamespace::LogicalFile,
                                        0,
                                        512,
                                        false,
                                    ),
                                );
                            }
                        }
                        artifacts::ArtifactsViewAction::BookmarkEntry {
                            entry_id,
                            path,
                            kind,
                            is_deleted,
                        } => {
                            self.bookmark_dialog.visible = true;
                            self.bookmark_dialog.title = format!(
                                "Bookmark {}",
                                Path::new(&path)
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                            );
                            self.bookmark_dialog.target = Some(BookmarkTarget::IndexedResult {
                                evidence_id: self.selected_evidence_id.unwrap_or(1),
                                entry_id,
                                logical_path: path,
                                artifact_kind: kind,
                                is_deleted,
                            });
                        }
                        artifacts::ArtifactsViewAction::ExportEntry { entry_id, path } => {
                            let evidence_id = self.selected_evidence_id.unwrap_or(1);
                            let file_name = std::path::Path::new(&path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("exported_file");
                            let dest = rfd::FileDialog::new()
                                .set_file_name(file_name)
                                .save_file();
                            if let Some(dest_path) = dest {
                                self.begin_export_file(
                                    ctx.clone(),
                                    evidence_id,
                                    self.browse_selected_volume,
                                    path,
                                    Some(entry_id),
                                    dest_path,
                                );
                            } else {
                                self.status = format!("Export Canceled: no destination chosen for {path}.");
                            }
                        }
                        artifacts::ArtifactsViewAction::CalculateHashes { entry_id, path } => {
                            let evidence_id = self.selected_evidence_id.unwrap_or(1);
                            self.begin_calculate_hashes(
                                ctx.clone(),
                                evidence_id,
                                self.browse_selected_volume,
                                path,
                                Some(entry_id),
                            );
                        }
                        artifacts::ArtifactsViewAction::ShowInTimeline { path } => {
                            self.active_tab = TopLevelTab::Timeline;
                            self.timeline_state.text_filter = path.clone();
                            self.timeline_state.category_filter.clear();
                            self.timeline_state.page = 0;
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_timeline(
                                    ctx.clone(),
                                    TimelineQuery {
                                        case_path,
                                        evidence_id: self.selected_evidence_id,
                                        from_utc: None,
                                        to_utc: None,
                                        category_filter: None,
                                        timestamp_type_filter: None,
                                        text_filter: Some(path),
                                        page: 0,
                                        page_size: 50,
                                    },
                                );
                            }
                        }
                        artifacts::ArtifactsViewAction::PrevPage => {
                            if self.artifacts_state.current_page > 0 {
                                self.artifacts_state.current_page -= 1;
                                let prev_cursor =
                                    self.artifacts_state.cursor_history.pop().flatten();
                                self.artifacts_state.cursor = prev_cursor.clone();
                                if let Some(case_path) = self.opened_path.clone() {
                                    self.begin_artifacts_page(
                                        ctx.clone(),
                                        ArtifactPageQuery {
                                            case_path,
                                            evidence_id: self.selected_evidence_id,
                                            request_id: 0,
                                            category_main: self
                                                .artifacts_state
                                                .selected_category
                                                .clone()
                                                .unwrap_or_else(|| "Filesystem".to_string()),
                                            category_sub: self
                                                .artifacts_state
                                                .selected_sub_category
                                                .clone(),
                                            name_filter: if self
                                                .artifacts_state
                                                .search_filter
                                                .trim()
                                                .is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.artifacts_state.search_filter.clone())
                                            },
                                            extension_filter: if self
                                                .artifacts_state
                                                .extension_filter
                                                .trim()
                                                .is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.artifacts_state.extension_filter.clone())
                                            },
                                            entry_type_filter: None,
                                            deleted_only: self.artifacts_state.deleted_only,
                                            date_from_utc: None,
                                            date_to_utc: None,
                                            cursor: prev_cursor,
                                            limit: 100,
                                        },
                                    );
                                }
                            }
                        }
                        artifacts::ArtifactsViewAction::NextPage => {
                            self.artifacts_state
                                .cursor_history
                                .push(self.artifacts_state.cursor.clone());
                            self.artifacts_state.current_page += 1;
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_artifacts_page(
                                    ctx.clone(),
                                    ArtifactPageQuery {
                                        case_path,
                                        evidence_id: self.selected_evidence_id,
                                        request_id: 0,
                                        category_main: self
                                            .artifacts_state
                                            .selected_category
                                            .clone()
                                            .unwrap_or_else(|| "Filesystem".to_string()),
                                        category_sub: self
                                            .artifacts_state
                                            .selected_sub_category
                                            .clone(),
                                        name_filter: if self
                                            .artifacts_state
                                            .search_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.artifacts_state.search_filter.clone())
                                        },
                                        extension_filter: if self
                                            .artifacts_state
                                            .extension_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.artifacts_state.extension_filter.clone())
                                        },
                                        entry_type_filter: None,
                                        deleted_only: self.artifacts_state.deleted_only,
                                        date_from_utc: None,
                                        date_to_utc: None,
                                        cursor: self.artifacts_state.cursor.clone(),
                                        limit: 100,
                                    },
                                );
                            }
                        }
                        artifacts::ArtifactsViewAction::None => {}
                    }
                }
                TopLevelTab::Search => {
                    let has_c = self.opened_path.is_some();
                    let act = search::show(ui, &mut self.search_state, has_c);
                    match act {
                        search::SearchViewAction::ExecuteSearch => {
                            if let Some(case_path) = self.opened_path.clone() {
                                self.search_state.page_index = 0;
                                self.search_state.cursor = None;
                                self.search_state.cursor_history.clear();
                                self.begin_search(
                                    ctx.clone(),
                                    NativeSearchQuery {
                                        case_path,
                                        query: self.search_state.query.clone(),
                                        match_mode: self.search_state.match_mode,
                                        evidence_id: self.selected_evidence_id,
                                        include_content: true,
                                        category: None,
                                        file_types: None,
                                        cursor: None,
                                        page_size: 100,
                                    },
                                );
                            }
                        }
                        search::SearchViewAction::InspectEntry { entry_id } => {
                            self.clear_hex_viewer();
                            let gen = self.summary.as_ref().map(|s| s.generation).unwrap_or(0);
                            self.begin_artifact_detail(
                                ctx.clone(),
                                ArtifactSelection {
                                    entry_id,
                                    generation: gen,
                                },
                            );
                        }
                        search::SearchViewAction::ViewHex {
                            evidence_id,
                            entry_id,
                            path,
                            match_offset,
                            match_length,
                        } => {
                            if let Some(case_path) = self.opened_path.clone() {
                                let window =
                                    search::hex_window_for_match(match_offset, match_length);
                                self.hex_viewer_state.active = true;
                                self.hex_viewer_state.source_namespace =
                                    ByteSourceNamespace::LogicalFile;
                                self.hex_viewer_state.evidence_id = Some(evidence_id);
                                self.hex_viewer_state.entry_id = Some(entry_id);
                                self.hex_viewer_state.logical_path = path.clone();
                                self.hex_viewer_state.current_offset = window.page_offset;
                                self.hex_viewer_state.selected_byte_offset =
                                    window.selected_byte_offset;
                                self.hex_viewer_state.selected_byte_length =
                                    window.selected_byte_length;
                                self.begin_hex_read(
                                    ctx.clone(),
                                    BoundedByteRequest::simple(
                                        case_path,
                                        evidence_id,
                                        0,
                                        Some(path),
                                        Some(entry_id),
                                        ByteSourceNamespace::LogicalFile,
                                        window.page_offset,
                                        512,
                                        false,
                                    ),
                                );
                            }
                        }
                        search::SearchViewAction::BookmarkResult {
                            evidence_id,
                            entry_id,
                            logical_path,
                            kind,
                            match_field,
                            match_snippet,
                            match_offset,
                            match_length,
                        } => {
                            self.bookmark_dialog.visible = true;
                            self.bookmark_dialog.title = format!(
                                "Search Result: {}",
                                Path::new(&logical_path)
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                            );
                            self.bookmark_dialog.target = Some(BookmarkTarget::SearchResult {
                                evidence_id,
                                entry_id,
                                logical_path,
                                artifact_kind: kind,
                                match_field,
                                match_snippet,
                                selection_offset: match_offset,
                                selection_length: match_length,
                            });
                        }
                        search::SearchViewAction::ExportResult {
                            evidence_id,
                            entry_id,
                            logical_path,
                            display_name,
                        } => {
                            let file_name = if display_name.trim().is_empty() {
                                "exported_file"
                            } else {
                                display_name.as_str()
                            };
                            if let Some(dest_path) = rfd::FileDialog::new()
                                .set_file_name(file_name)
                                .save_file()
                            {
                                self.begin_export_file(
                                    ctx.clone(),
                                    evidence_id,
                                    self.browse_selected_volume,
                                    logical_path,
                                    Some(entry_id),
                                    dest_path,
                                );
                            } else {
                                self.status = format!(
                                    "Export canceled: no destination chosen for {display_name}."
                                );
                            }
                        }
                        search::SearchViewAction::PrevPage => {
                            if self.search_state.page_index > 0 {
                                self.search_state.page_index -= 1;
                                let prev = self.search_state.cursor_history.pop().flatten();
                                self.search_state.cursor = prev.clone();
                                if let Some(case_path) = self.opened_path.clone() {
                                    self.begin_search(
                                        ctx.clone(),
                                        NativeSearchQuery {
                                            case_path,
                                            query: self.search_state.query.clone(),
                                            match_mode: self.search_state.match_mode,
                                            evidence_id: self.selected_evidence_id,
                                            include_content: true,
                                            category: None,
                                            file_types: None,
                                            cursor: prev,
                                            page_size: 100,
                                        },
                                    );
                                }
                            }
                        }
                        search::SearchViewAction::NextPage => {
                            self.search_state
                                .cursor_history
                                .push(self.search_state.cursor.clone());
                            self.search_state.page_index += 1;
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_search(
                                    ctx.clone(),
                                    NativeSearchQuery {
                                        case_path,
                                        query: self.search_state.query.clone(),
                                        match_mode: self.search_state.match_mode,
                                        evidence_id: self.selected_evidence_id,
                                        include_content: true,
                                        category: None,
                                        file_types: None,
                                        cursor: self.search_state.cursor.clone(),
                                        page_size: 100,
                                    },
                                );
                            }
                        }
                        search::SearchViewAction::None => {}
                    }
                }
                TopLevelTab::Timeline => {
                    let has_c = self.opened_path.is_some();
                    let act = timeline::show(ui, &mut self.timeline_state, has_c);
                    match act {
                        timeline::TimelineViewAction::RefreshQuery => {
                            if let Some(case_path) = self.opened_path.clone() {
                                // A new filter always starts at the first event page. Retaining
                                // an old page index can otherwise yield an empty page while the
                                // database truthfully reports matching events.
                                self.timeline_state.page = 0;
                                self.begin_timeline(
                                    ctx.clone(),
                                    TimelineQuery {
                                        case_path,
                                        evidence_id: self.selected_evidence_id,
                                        from_utc: if self.timeline_state.from_date.trim().is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.from_date.clone())
                                        },
                                        to_utc: if self.timeline_state.to_date.trim().is_empty() {
                                            None
                                        } else {
                                            Some(self.timeline_state.to_date.clone())
                                        },
                                        category_filter: if self
                                            .timeline_state
                                            .category_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.category_filter.clone())
                                        },
                                        timestamp_type_filter: if self
                                            .timeline_state
                                            .type_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.type_filter.clone())
                                        },
                                        text_filter: if self
                                            .timeline_state
                                            .text_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.text_filter.clone())
                                        },
                                        page: self.timeline_state.page,
                                        page_size: self.timeline_state.page_size,
                                    },
                                );
                            }
                        }
                        timeline::TimelineViewAction::InspectEntry { entry_id } => {
                            let gen = self.summary.as_ref().map(|s| s.generation).unwrap_or(0);
                            self.begin_artifact_detail(
                                ctx.clone(),
                                ArtifactSelection {
                                    entry_id,
                                    generation: gen,
                                },
                            );
                        }
                        timeline::TimelineViewAction::BookmarkEvent {
                            entry_id,
                            path,
                            kind,
                        } => {
                            self.bookmark_dialog.visible = true;
                            self.bookmark_dialog.title = format!(
                                "Event: {}",
                                Path::new(&path)
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                            );
                            self.bookmark_dialog.target = Some(BookmarkTarget::IndexedResult {
                                evidence_id: self.selected_evidence_id.unwrap_or(1),
                                entry_id,
                                logical_path: path,
                                artifact_kind: kind,
                                is_deleted: false,
                            });
                        }
                        timeline::TimelineViewAction::PrevPage => {
                            if self.timeline_state.page > 0 {
                                self.timeline_state.page -= 1;
                                if let Some(case_path) = self.opened_path.clone() {
                                    self.begin_timeline(
                                        ctx.clone(),
                                        TimelineQuery {
                                            case_path,
                                            evidence_id: self.selected_evidence_id,
                                            from_utc: if self
                                                .timeline_state
                                                .from_date
                                                .trim()
                                                .is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.timeline_state.from_date.clone())
                                            },
                                            to_utc: if self.timeline_state.to_date.trim().is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.timeline_state.to_date.clone())
                                            },
                                            category_filter: if self
                                                .timeline_state
                                                .category_filter
                                                .trim()
                                                .is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.timeline_state.category_filter.clone())
                                            },
                                            timestamp_type_filter: if self
                                                .timeline_state
                                                .type_filter
                                                .trim()
                                                .is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.timeline_state.type_filter.clone())
                                            },
                                            text_filter: if self
                                                .timeline_state
                                                .text_filter
                                                .trim()
                                                .is_empty()
                                            {
                                                None
                                            } else {
                                                Some(self.timeline_state.text_filter.clone())
                                            },
                                            page: self.timeline_state.page,
                                            page_size: self.timeline_state.page_size,
                                        },
                                    );
                                }
                            }
                        }
                        timeline::TimelineViewAction::NextPage => {
                            self.timeline_state.page += 1;
                            if let Some(case_path) = self.opened_path.clone() {
                                self.begin_timeline(
                                    ctx.clone(),
                                    TimelineQuery {
                                        case_path,
                                        evidence_id: self.selected_evidence_id,
                                        from_utc: if self.timeline_state.from_date.trim().is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.from_date.clone())
                                        },
                                        to_utc: if self.timeline_state.to_date.trim().is_empty() {
                                            None
                                        } else {
                                            Some(self.timeline_state.to_date.clone())
                                        },
                                        category_filter: if self
                                            .timeline_state
                                            .category_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.category_filter.clone())
                                        },
                                        timestamp_type_filter: if self
                                            .timeline_state
                                            .type_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.type_filter.clone())
                                        },
                                        text_filter: if self
                                            .timeline_state
                                            .text_filter
                                            .trim()
                                            .is_empty()
                                        {
                                            None
                                        } else {
                                            Some(self.timeline_state.text_filter.clone())
                                        },
                                        page: self.timeline_state.page,
                                        page_size: self.timeline_state.page_size,
                                    },
                                );
                            }
                        }
                        timeline::TimelineViewAction::None => {}
                    }
                }
                TopLevelTab::Bookmarks => {
                    let has_c = self.opened_path.is_some();
                    let act = bookmarks::show(
                        ui,
                        has_c,
                        self.bookmark_loading,
                        self.bookmark_error.as_deref(),
                        &self.bookmark_folders,
                        self.bookmark_folders_page.as_ref(),
                        self.bookmark_folders_page_index,
                        self.selected_bookmark_folder,
                        &self.bookmarks,
                        self.bookmarks_page.as_ref(),
                        self.bookmarks_page_index,
                        self.selected_bookmark_id,
                        &self.bookmark_items,
                        self.bookmark_items_page.as_ref(),
                        self.bookmark_items_page_index,
                        self.selected_bookmark_item_id,
                        self.selected_bookmark_item_detail.as_ref(),
                    );
                    match act {
                        bookmarks::BookmarksViewAction::NewFolder => {
                            self.create_folder_dialog.visible = true;
                        }
                        bookmarks::BookmarksViewAction::Refresh => {
                            self.bookmark_folders_cursors = vec![None];
                            self.bookmark_folders_page_index = 0;
                            self.begin_load_bookmark_folders(ctx.clone(), None);
                        }
                        bookmarks::BookmarksViewAction::SelectFolder(id) => {
                            self.selected_bookmark_folder = Some(id);
                            self.bookmarks_cursors = vec![None];
                            self.bookmarks_page_index = 0;
                            self.begin_load_bookmarks(ctx.clone(), Some(id), None);
                        }
                        bookmarks::BookmarksViewAction::SelectBookmark(id) => {
                            self.selected_bookmark_id = Some(id);
                            self.bookmark_items_cursors = vec![None];
                            self.bookmark_items_page_index = 0;
                            self.begin_load_bookmark_items(ctx.clone(), id, None);
                        }
                        bookmarks::BookmarksViewAction::SelectItem(id) => {
                            self.selected_bookmark_item_id = Some(id);
                            self.begin_load_bookmark_item_detail(ctx.clone(), id);
                        }
                        bookmarks::BookmarksViewAction::ResumeBookmark(id) => {
                            self.execute_resume_bookmark(ctx.clone(), id);
                        }
                        bookmarks::BookmarksViewAction::RemoveFolder(f) => {
                            self.begin_remove_folder(ctx.clone(), f.id);
                        }
                        bookmarks::BookmarksViewAction::RemoveBookmark(b) => {
                            self.begin_remove_bookmark(ctx.clone(), b.id);
                        }
                        bookmarks::BookmarksViewAction::RemoveItem(i) => {
                            self.begin_remove_item(ctx.clone(), i.id);
                        }
                        bookmarks::BookmarksViewAction::InspectItem(entry_id) => {
                            let gen = self.summary.as_ref().map(|s| s.generation).unwrap_or(0);
                            self.begin_artifact_detail(
                                ctx.clone(),
                                ArtifactSelection {
                                    entry_id,
                                    generation: gen,
                                },
                            );
                        }
                        bookmarks::BookmarksViewAction::LoadFoldersPage(c) => {
                            self.begin_load_bookmark_folders(ctx.clone(), c)
                        }
                        bookmarks::BookmarksViewAction::LoadBookmarksPage(c) => {
                            self.begin_load_bookmarks(ctx.clone(), self.selected_bookmark_folder, c)
                        }
                        bookmarks::BookmarksViewAction::LoadItemsPage(c) => {
                            if let Some(id) = self.selected_bookmark_id {
                                self.begin_load_bookmark_items(ctx.clone(), id, c);
                            }
                        }
                        bookmarks::BookmarksViewAction::None => {}
                    }
                }
                TopLevelTab::Reports => {
                    let has_c = self.opened_path.is_some();
                    let act = reports::show(ui, &mut self.report_state, has_c);
                    match act {
                        reports::ReportsViewAction::GeneratePreview => {
                            self.begin_report_preview(ctx.clone());
                        }
                        reports::ReportsViewAction::ExportReport(fmt) => {
                            let filter_ext = match fmt.as_str() {
                                "json" => &["json"][..],
                                "md" => &["md"][..],
                                _ => &["html", "htm"][..],
                            };
                            if let Some(dest) = rfd::FileDialog::new()
                                .set_file_name(format!("forensic_report.{}", fmt))
                                .add_filter("Report File", filter_ext)
                                .save_file()
                            {
                                self.begin_report_export(ctx.clone(), dest);
                            }
                        }
                        reports::ReportsViewAction::None => {}
                    }
                }
            }

            // If Hex Viewer is Active and not already embedded in Browse tab, render in bottom panel
            // only when on the tab where hex viewing was explicitly requested.
            if self.hex_viewer_state.active
                && self.active_tab != TopLevelTab::Browse
                && self.hex_viewer_origin_tab == Some(self.active_tab)
            {
                ui.add_space(8.0);
                let hex_act = hex_viewer::show(
                    ui,
                    &mut self.hex_viewer_state,
                    &mut self.data_interpreter_state,
                );
                match hex_act {
                    hex_viewer::HexViewerAction::NavigateOffset(off) => {
                        if let Some(case_path) = self.opened_path.clone() {
                            self.hex_viewer_state.current_offset = off;
                            self.hex_viewer_state.selected_byte_offset = None;
                            self.hex_viewer_state.selected_byte_length = None;
                            let p = if self.hex_viewer_state.logical_path.is_empty() {
                                None
                            } else {
                                Some(self.hex_viewer_state.logical_path.clone())
                            };
                            self.begin_hex_read(
                                ctx.clone(),
                                BoundedByteRequest::simple(
                                    case_path,
                                    self.hex_viewer_state.evidence_id.unwrap_or(0),
                                    self.hex_viewer_state.volume_index,
                                    p,
                                    self.hex_viewer_state.entry_id,
                                    self.hex_viewer_state.source_namespace,
                                    off,
                                    512,
                                    self.hex_viewer_state.source_namespace
                                        == ByteSourceNamespace::AbsoluteDecodedMedia,
                                ),
                            );
                        }
                    }
                    hex_viewer::HexViewerAction::PrevPage => {
                        if let (Some(off), Some(case_path)) = (
                            hex_viewer::previous_page_offset(&self.hex_viewer_state),
                            self.opened_path.clone(),
                        ) {
                            self.hex_viewer_state.current_offset = off;
                            self.hex_viewer_state.selected_byte_offset = None;
                            self.hex_viewer_state.selected_byte_length = None;
                            let p = if self.hex_viewer_state.logical_path.is_empty() {
                                None
                            } else {
                                Some(self.hex_viewer_state.logical_path.clone())
                            };
                            self.begin_hex_read(
                                ctx.clone(),
                                BoundedByteRequest::simple(
                                    case_path,
                                    self.hex_viewer_state.evidence_id.unwrap_or(0),
                                    self.hex_viewer_state.volume_index,
                                    p,
                                    self.hex_viewer_state.entry_id,
                                    self.hex_viewer_state.source_namespace,
                                    off,
                                    512,
                                    self.hex_viewer_state.source_namespace
                                        == ByteSourceNamespace::AbsoluteDecodedMedia,
                                ),
                            );
                        }
                    }
                    hex_viewer::HexViewerAction::NextPage => {
                        if let (Some(off), Some(case_path)) = (
                            hex_viewer::next_page_offset(&self.hex_viewer_state),
                            self.opened_path.clone(),
                        ) {
                            self.hex_viewer_state.current_offset = off;
                            self.hex_viewer_state.selected_byte_offset = None;
                            self.hex_viewer_state.selected_byte_length = None;
                            let p = if self.hex_viewer_state.logical_path.is_empty() {
                                None
                            } else {
                                Some(self.hex_viewer_state.logical_path.clone())
                            };
                            self.begin_hex_read(
                                ctx.clone(),
                                BoundedByteRequest::simple(
                                    case_path,
                                    self.hex_viewer_state.evidence_id.unwrap_or(0),
                                    self.hex_viewer_state.volume_index,
                                    p,
                                    self.hex_viewer_state.entry_id,
                                    self.hex_viewer_state.source_namespace,
                                    off,
                                    512,
                                    self.hex_viewer_state.source_namespace
                                        == ByteSourceNamespace::AbsoluteDecodedMedia,
                                ),
                            );
                        }
                    }
                    hex_viewer::HexViewerAction::ToggleDataInterpreter => {
                        self.layout.data_interpreter_window_open =
                            !self.layout.data_interpreter_window_open;
                    }
                    hex_viewer::HexViewerAction::Close => {
                        self.clear_hex_viewer();
                    }
                    hex_viewer::HexViewerAction::None => {}
                }
            }

            // Floating Data Interpreter Window
            if self.layout.data_interpreter_window_open {
                let mut is_open = true;
                egui::Window::new("Data Interpreter")
                    .open(&mut is_open)
                    .resizable(true)
                    .default_width(320.0)
                    .show(&ctx, |ui| {
                        let offset = self.hex_viewer_state.selected_byte_offset.unwrap_or(0);
                        crate::views::data_interpreter::show(
                            ui,
                            &mut self.data_interpreter_state,
                            &self.hex_viewer_state.loaded_bytes,
                            offset,
                        );
                    });
                if !is_open {
                    self.layout.data_interpreter_window_open = false;
                }
            }

        });

        // Dialog Modals
        let bt_act = bitlocker::show(&ctx, &mut self.bitlocker_dialog);
        if let bitlocker::BitLockerDialogAction::Unlock {
            evidence_id,
            volume_index,
            is_recovery_key,
            credential,
        } = bt_act
        {
            self.begin_bitlocker_unlock(
                ctx.clone(),
                evidence_id,
                volume_index,
                is_recovery_key,
                credential,
            );
        }

        let proc_act = processing_options::show(
            &ctx,
            &mut self.processing_options_dialog,
            Some(&self.unlock_manager),
        );
        if let processing_options::ProcessingOptionsAction::UnlockVolume {
            evidence_id,
            volume_index,
            volume_name,
        } = &proc_act
        {
            self.bitlocker_dialog.visible = true;
            self.bitlocker_dialog.evidence_id = *evidence_id;
            self.bitlocker_dialog.volume_index = *volume_index;
            self.bitlocker_dialog.volume_label = volume_name.clone();
        }
        if let processing_options::ProcessingOptionsAction::StartProcessing {
            evidence_id,
            selected_volumes,
            preset,
            groups,
            content_capture_enabled,
            max_entries,
        } = proc_act
        {
            if self.processing.is_some() {
                // Repeated clicks on Start Processing are idempotent while a job is running or startup is pending
                return;
            }
            if let Some(case_path) = self.opened_path.clone() {
                // A new run owns the Process view. Do not carry a stale attach,
                // refresh, or prior-run message into the live monitor.
                self.error = None;
                self.last_process = None;
                self.clear_operation_warnings();
                self.processing_history_error = None;
                let evidence_name = self.processing_options_dialog.evidence_name.clone();
                let tracker = JobProgressTracker::new(
                    format!("analysis-{}-{evidence_id}", std::process::id()),
                    "analysis",
                    None,
                );
                let worker_tracker = tracker.clone();
                let mut processors = groups;
                processors.hashing_content_capture = content_capture_enabled;
                let config = NativeAnalysisConfig {
                    case_path: case_path.clone(),
                    evidence_id,
                    evidence_path: self.processing_options_dialog.evidence_path.clone(),
                    source_kind: "image".to_string(),
                    preset,
                    volumes: self
                        .processing_options_dialog
                        .volumes
                        .iter()
                        .map(|v| {
                            let is_unlocked = self.unlock_manager.is_unlocked(evidence_id, v.index);
                            kdft_desktop_core::processing::VolumeInclusion {
                                volume_index: v.index,
                                name: v.name.clone(),
                                filesystem: v.filesystem.clone(),
                                start_offset: v.start_offset,
                                size_bytes: v.size_bytes,
                                is_bitlocker: v.is_bitlocker,
                                unlocked_for_session: is_unlocked,
                                included: selected_volumes.contains(&v.index),
                            }
                        })
                        .collect(),
                    processors,
                    max_entries,
                };
                let mgr = self.unlock_manager.clone();
                let (sender, receiver) = mpsc::channel();
                let ctx_clone = ctx.clone();
                std::thread::spawn(move || {
                    let result = NativeProcessingService::execute_analysis(
                        &config,
                        &worker_tracker,
                        Some(&mgr),
                    )
                    .map(|r| r.into_summary())
                    .map_err(|e| format!("{e:#}"));
                    let refreshed = open_case(&case_path);
                    let _ = sender.send(ProcessWorkerResult { result, refreshed });
                    ctx_clone.request_repaint();
                });
                self.status = format!("Started forensic processing for {evidence_name}…");
                self.active_tab = TopLevelTab::Process;
                self.processing = Some(ProcessingJob {
                    evidence_name,
                    tracker,
                    receiver,
                });
            }
        }

        let bm_act = bookmark::show_bookmark_dialog(
            &ctx,
            &mut self.bookmark_dialog,
            self.resuming_bookmark_id,
            self.bookmark_loading,
        );
        match bm_act {
            bookmark::BookmarkDialogAction::CreateSingle => {
                self.execute_create_single_bookmark(ctx.clone())
            }
            bookmark::BookmarkDialogAction::CreateRecursive => {
                self.execute_create_recursive_bookmark(ctx.clone())
            }
            _ => {}
        }

        let cf_act = bookmark::show_create_folder_dialog(
            &ctx,
            &mut self.create_folder_dialog,
            self.bookmark_loading,
        );
        if let bookmark::CreateFolderDialogAction::Create {
            name,
            comment,
            show_in_report,
        } = cf_act
        {
            if let Some(case_path) = self.opened_path.clone() {
                self.begin_create_folder(
                    ctx.clone(),
                    CreateBookmarkFolderRequest {
                        case_path,
                        parent_id: None,
                        name,
                        folder_comment: comment,
                        show_in_report,
                    },
                );
            }
        }

        let rm_act =
            bookmark::show_removal_dialog(&ctx, &mut self.removal_dialog, self.bookmark_loading);
        if let bookmark::RemovalConfirmationAction::Confirm(target) = rm_act {
            match target {
                RemovalTarget::Folder { folder_id, .. } => {
                    self.begin_remove_folder(ctx.clone(), folder_id)
                }
                RemovalTarget::Bookmark { bookmark_id, .. } => {
                    self.begin_remove_bookmark(ctx.clone(), bookmark_id)
                }
                RemovalTarget::Item { item_id, .. } => self.begin_remove_item(ctx.clone(), item_id),
            }
        }

        let is_busy = self.is_busy();
        let intake_act = intake::show(&ctx, &mut self.evidence_intake_dialog, is_busy);
        if let intake::EvidenceIntakeAction::Attach {
            source_path,
            detected_kind,
            display_name,
            timezone,
            integrity_choice,
            expected_sha256,
            skip_reason,
        } = intake_act
        {
            let initial_status = match integrity_choice {
                IntakeIntegrityChoice::VerifyNow => "unverified".to_string(),
                IntakeIntegrityChoice::ComputeOnly => "unverified".to_string(),
                IntakeIntegrityChoice::Defer => "deferred".to_string(),
                IntakeIntegrityChoice::Skip => "skipped".to_string(),
            };
            let initial_details = match integrity_choice {
                IntakeIntegrityChoice::Skip => Some(
                    serde_json::json!({
                        "action": "skip",
                        "reason": skip_reason.as_deref().unwrap_or("Examiner skipped verification"),
                        "recorded_at": chrono::Utc::now().to_rfc3339(),
                    })
                    .to_string(),
                ),
                IntakeIntegrityChoice::Defer => Some(
                    serde_json::json!({
                        "action": "defer",
                        "recorded_at": chrono::Utc::now().to_rfc3339(),
                    })
                    .to_string(),
                ),
                _ => None,
            };
            if integrity_choice == IntakeIntegrityChoice::VerifyNow
                || integrity_choice == IntakeIntegrityChoice::ComputeOnly
            {
                self.pending_intake_verification =
                    Some(kdft_desktop_core::EvidenceIntegrityRequest {
                        case_path: self.opened_path.clone().unwrap_or_default(),
                        evidence_id: 0,
                        expected_sha256: expected_sha256.clone(),
                        skip_reason: None,
                        is_skip: false,
                        is_defer: false,
                    });
            }
            self.begin_attach_with_options(
                ctx.clone(),
                source_path,
                detected_kind,
                Some(display_name),
                Some(timezone),
                Some(initial_status),
                expected_sha256,
                initial_details,
            );
        }

        let is_busy = self.is_busy();
        let cs_act = case_settings::show(&ctx, &mut self.case_settings_dialog, is_busy);
        if let case_settings::CaseSettingsAction::ApplyTimezone { new_timezone } = cs_act {
            self.apply_case_timezone(ctx.clone(), new_timezone);
        }
    }
}

// --- Helper Functions ---

pub fn open_case(path: &Path) -> Result<OpenedCase, String> {
    match open_case_once(path) {
        Err(error) if error.starts_with("case changed while loading native snapshot") => {
            open_case_once(path)
        }
        result => result,
    }
}

pub fn open_case_once(path: &Path) -> Result<OpenedCase, String> {
    let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let backend = DesktopBackend::open(&canonical_path).map_err(|error| error.to_string())?;
    let summary = match backend.dispatch(BackendCommand::CaseSummary) {
        BackendResponse::CaseSummary { summary } => summary,
        BackendResponse::Error { code, message } => return Err(format!("{code}: {message}")),
        _ => return Err("desktop backend returned an unexpected case response".to_string()),
    };
    let page = read_page(&backend, None)?;
    let evidence = read_evidence_page(&canonical_path, None, None);
    validate_snapshot_generations(
        summary.generation,
        page.generation,
        evidence.as_ref().ok().map(|page| page.case_generation),
    )?;
    Ok(OpenedCase {
        path: canonical_path,
        backend,
        summary,
        page,
        evidence,
    })
}

pub fn read_page(
    backend: &DesktopBackend,
    cursor: Option<EntryCursor>,
) -> Result<EntryPage, String> {
    match backend.dispatch(BackendCommand::EntryPage {
        query: EntryPageQuery {
            evidence_id: None,
            cursor,
            limit: Some(DEFAULT_PAGE_SIZE),
        },
    }) {
        BackendResponse::EntryPage { page } => Ok(page),
        BackendResponse::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("desktop backend returned an unexpected page response".to_string()),
    }
}

pub fn read_artifact_detail(
    backend: &DesktopBackend,
    selection: ArtifactSelection,
) -> Result<ArtifactDetail, String> {
    match backend.dispatch(BackendCommand::ArtifactDetail {
        query: ArtifactDetailQuery {
            entry_id: selection.entry_id,
            expected_generation: selection.generation,
        },
    }) {
        BackendResponse::ArtifactDetail { detail } => Ok(*detail),
        BackendResponse::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("desktop backend returned an unexpected Inspector response".to_string()),
    }
}

pub fn read_evidence_page(
    case_path: &Path,
    after_id: Option<i64>,
    expected_generation: Option<i64>,
) -> Result<EvidencePage, String> {
    NativeWorkflowService::list_evidence(EvidenceListRequest {
        case_path: case_path.to_path_buf(),
        after_id,
        limit: Some(DEFAULT_EVIDENCE_PAGE_SIZE),
        expected_generation,
    })
    .map_err(|error| error.to_string())
}

pub fn validate_snapshot_generations(
    summary_generation: i64,
    entry_generation: i64,
    evidence_generation: Option<i64>,
) -> Result<(), String> {
    if summary_generation == entry_generation
        && evidence_generation.is_none_or(|value| value == summary_generation)
    {
        return Ok(());
    }
    Err(mixed_generation_error(
        Some(summary_generation),
        entry_generation,
        evidence_generation,
    ))
}

pub fn mixed_generation_error(
    expected_generation: Option<i64>,
    received_generation: i64,
    evidence_generation: Option<i64>,
) -> String {
    format!(
        "case changed while loading native snapshot: expected generation {}, result generation {received_generation}, evidence generation {}. Reopen the case before interpreting these rows.",
        expected_generation.map_or_else(|| "unknown".to_string(), |value| value.to_string()),
        evidence_generation.map_or_else(|| "not loaded".to_string(), |value| value.to_string())
    )
}

pub fn page_status(page_number: usize, rows: usize) -> String {
    format!(
        "Showing bounded result page {page_number}: {rows} rows loaded in memory (hard maximum {DEFAULT_PAGE_SIZE})."
    )
}

pub fn optional_trimmed(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub fn parse_max_entries(value: &str) -> Result<usize, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(0);
    }
    value.parse::<usize>().map_err(|_| {
        "Entry limit must be a non-negative whole number (0 means unlimited).".to_string()
    })
}

pub fn parse_recursive_limit(value: &str) -> Result<usize, String> {
    let value = value.trim();
    if value.is_empty() || value == "0" || value.eq_ignore_ascii_case("unlimited") {
        return Ok(0);
    }
    value.parse::<usize>().map_err(|_| {
        "Limit must be a valid positive integer, or leave blank / 0 for no limit.".to_string()
    })
}

pub fn retained_selection(selected: Option<i64>, page: &EvidencePage) -> Option<i64> {
    selected.filter(|id| page.items.iter().any(|item| item.id == *id))
}

pub fn is_stale_cursor_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("stale page cursor") || error.contains("stale evidence cursor")
}

pub fn is_stale_artifact_detail_error(error: &str) -> bool {
    error.to_ascii_lowercase().contains("stale artifact detail")
}

pub fn artifact_detail_matches(selection: ArtifactSelection, detail: &ArtifactDetail) -> bool {
    detail.entry_id == selection.entry_id && detail.generation == selection.generation
}

pub fn bound_operation_warnings(mut warnings: Vec<String>, omitted: usize) -> (Vec<String>, usize) {
    let additionally_omitted = warnings.len().saturating_sub(MAX_OPERATION_WARNINGS);
    warnings.truncate(MAX_OPERATION_WARNINGS);
    (warnings, omitted.saturating_add(additionally_omitted))
}

pub fn progress_state_label(state: JobProgressState) -> &'static str {
    match state {
        JobProgressState::Active => "ACTIVE",
        JobProgressState::Complete => "COMPLETE",
        JobProgressState::CompleteWithDiagnostics => "COMPLETE WITH DIAGNOSTICS",
        JobProgressState::Truncated => "TRUNCATED",
        JobProgressState::Cancelled => "CANCELLED",
        JobProgressState::Failed => "FAILED",
    }
}

pub fn process_status_text(result: &ProcessEvidenceSummary, view_refreshed: bool) -> String {
    let status = result.status.to_ascii_lowercase();
    let outcome = match status.as_str() {
        "cancelled" => "cancelled safely; no complete examination is asserted",
        "failed" => "reported a failed terminal state",
        _ if result.truncated => "truncated; no complete examination is asserted",
        _ if result.partial_artifact_coverage || result.completed_with_diagnostics => {
            "completed with diagnostics; coverage remains partial"
        }
        "completed" => "completed",
        _ => "returned an unrecognized terminal status; coverage is unknown",
    };
    if view_refreshed {
        format!(
            "Processing {outcome}: {} canonical entries are shown in the refreshed view.",
            result.retained_entry_count
        )
    } else {
        format!(
            "Processing {outcome}: the case reports {} retained canonical entries, but the displayed grid is stale.",
            result.retained_entry_count
        )
    }
}

pub fn format_elapsed(elapsed_ms: u64) -> String {
    let seconds = elapsed_ms / 1_000;
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else {
        format!("{minutes}m {seconds:02}s")
    }
}

pub fn coverage_badge(coverage: &CoverageBanner) -> &'static str {
    match coverage.state {
        CoverageState::NotProcessed => "NOT PROCESSED",
        CoverageState::InProgress => "IN PROGRESS",
        CoverageState::Complete => "COMPLETE",
        CoverageState::Partial => "PARTIAL",
        CoverageState::Failed => "FAILED",
        CoverageState::Unknown => "UNKNOWN",
    }
}

pub fn coverage_colors(state: CoverageState) -> (Color32, Color32) {
    match state {
        CoverageState::NotProcessed | CoverageState::Unknown => (
            Color32::from_rgb(47, 51, 58),
            Color32::from_rgb(180, 186, 198),
        ),
        CoverageState::InProgress => (
            Color32::from_rgb(55, 48, 23),
            Color32::from_rgb(242, 198, 72),
        ),
        CoverageState::Complete => (
            Color32::from_rgb(25, 57, 43),
            Color32::from_rgb(76, 213, 139),
        ),
        CoverageState::Partial => (
            Color32::from_rgb(67, 43, 19),
            Color32::from_rgb(245, 159, 69),
        ),
        CoverageState::Failed => (
            Color32::from_rgb(74, 28, 32),
            Color32::from_rgb(238, 91, 104),
        ),
    }
}

pub fn format_size(size: Option<i64>) -> String {
    let Some(size) = size else {
        return "—".to_string();
    };
    if size < 0 {
        return format!("{size} B (invalid)");
    }
    let size = size as u64;
    const KIB: u64 = 1_024;
    const MIB: u64 = KIB * 1_024;
    const GIB: u64 = MIB * 1_024;
    if size >= GIB {
        format!("{:.2} GiB", size as f64 / GIB as f64)
    } else if size >= MIB {
        format!("{:.2} MiB", size as f64 / MIB as f64)
    } else if size >= KIB {
        format!("{:.2} KiB", size as f64 / KIB as f64)
    } else {
        format!("{size} B")
    }
}
