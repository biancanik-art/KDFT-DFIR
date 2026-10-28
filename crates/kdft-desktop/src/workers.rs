#![forbid(unsafe_code)]

//! Background workers and message types for the native desktop workbench.

use crate::state::{ArtifactSelection, OpenedCase};
use kdft_desktop_core::{
    artifacts::{
        ArtifactCategoryNode, ArtifactCategoryTreeSnapshot, ArtifactPageSnapshot, ArtifactRow,
    },
    bytes::BoundedByteResponse,
    reports::ReportPreview,
    search::DeepSearchResultSummary,
    timeline::TimelinePage,
    unlock::TransientBitLockerCredential,
    ArtifactDetail, AttachEvidenceResult, BookmarkFoldersPage, BookmarkItemDetail,
    BookmarkItemsPage, BookmarksPage, BrowseDirectoryPage, CreateBookmarkFolderResult,
    CreateBookmarkResult, CreateCaseResult, EntryCursor, EntryPage, EvidenceIntegrityReport,
    EvidencePage, EvidenceVolume, ExportReport, FolderExportReport, HashCalculationReport,
    JobProgressTracker, ProcessEvidenceSummary, ProcessingJobRecord, ProcessorCoverageRecord,
    RecursiveFolderBookmarkResult, RecursiveHashReport, RemoveBookmarkFolderResult,
    RemoveBookmarkItemResult, RemoveBookmarkResult,
};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

#[derive(Debug)]
pub struct UnlockWorkerResult {
    pub evidence_id: i64,
    pub volume_index: usize,
    pub result: Result<TransientBitLockerCredential, String>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum WorkerResult {
    Open(Result<OpenedCase, String>),
    Create {
        mutation: Result<CreateCaseResult, String>,
        refreshed: Option<Result<OpenedCase, String>>,
    },
    Attach {
        mutation: Result<AttachEvidenceResult, String>,
        refreshed: Option<Result<OpenedCase, String>>,
        source_name: String,
    },
    Page {
        result: Result<EntryPage, String>,
        target_page: usize,
        target_cursor: Option<EntryCursor>,
    },
    EvidencePage {
        result: Result<EvidencePage, String>,
        target_page: usize,
        target_after_id: Option<i64>,
    },
}

#[derive(Debug)]
pub struct ArtifactWorkerResult {
    pub selection: ArtifactSelection,
    pub result: Result<ArtifactDetail, String>,
}

#[derive(Debug)]
// Directory pages are transferred as one owned worker message; boxing the dominant
// variant would add an allocation to every browse response without reducing live data.
#[allow(clippy::large_enum_variant)]
pub enum BrowseWorkerResult {
    Volumes {
        evidence_id: i64,
        source_name: String,
        result: Result<Vec<EvidenceVolume>, String>,
    },
    DirectoryPage {
        request_id: u64,
        evidence_id: i64,
        volume_index: usize,
        path: String,
        offset: usize,
        result: Result<BrowseDirectoryPage, String>,
    },
}

#[derive(Debug)]
pub enum BookmarkWorkerResult {
    Folders(Result<BookmarkFoldersPage, String>),
    Bookmarks {
        folder_id: Option<i64>,
        result: Result<BookmarksPage, String>,
    },
    Items {
        bookmark_id: i64,
        result: Result<BookmarkItemsPage, String>,
    },
    CreatedFolder(Result<CreateBookmarkFolderResult, String>),
    Created(Result<CreateBookmarkResult, String>),
    RecursiveCreated(Result<RecursiveFolderBookmarkResult, String>),
    RemovedFolder(Result<RemoveBookmarkFolderResult, String>),
    RemovedBookmark(Result<RemoveBookmarkResult, String>),
    RemovedItem(Result<RemoveBookmarkItemResult, String>),
    ItemDetail {
        item_id: i64,
        result: Result<BookmarkItemDetail, String>,
    },
}

#[derive(Debug)]
pub struct ProcessWorkerResult {
    pub result: Result<ProcessEvidenceSummary, String>,
    pub refreshed: Result<OpenedCase, String>,
}

pub struct ProcessingJob {
    pub evidence_name: String,
    pub tracker: JobProgressTracker,
    pub receiver: Receiver<ProcessWorkerResult>,
}

#[derive(Debug)]
pub struct ProcessingHistoryWorkerResult {
    pub request_id: u64,
    pub case_path: PathBuf,
    pub evidence_id: Option<i64>,
    pub jobs: Result<Vec<ProcessingJobRecord>, String>,
    /// Coverage is intentionally optional. The live 750 ms job-history probe
    /// must not wait behind the much more expensive aggregate COUNT queries.
    pub coverage: Option<Result<Vec<ProcessorCoverageRecord>, String>>,
}

#[derive(Debug)]
pub enum HexWorkerResult {
    Loaded(Result<BoundedByteResponse, String>),
}

#[derive(Debug)]
pub struct ArtifactsTreeWorkerResult {
    pub snapshot: Result<ArtifactCategoryTreeSnapshot, String>,
}

#[derive(Debug)]
pub struct ArtifactsPageWorkerResult {
    pub snapshot: Result<ArtifactPageSnapshot, String>,
}

#[derive(Debug)]
pub struct ArtifactsProbeWorkerResult {
    pub request_id: u64,
    pub generation: Result<i64, String>,
}

#[derive(Debug)]
pub enum ArtifactsWorkerResult {
    Tree(Result<Vec<ArtifactCategoryNode>, String>),
    Page {
        rows: Result<Vec<ArtifactRow>, String>,
        has_more: bool,
        next_cursor: Option<kdft_case::CategoryEntryCursor>,
        total_count: Option<i64>,
    },
}

#[derive(Debug)]
pub struct SearchWorkerResult {
    pub results: Result<Vec<DeepSearchResultSummary>, String>,
    pub next_cursor: Option<kdft_case::DeepSearchCursor>,
    pub has_more: bool,
    pub total_matches: Option<usize>,
    pub coverage_statement: Option<String>,
}

#[derive(Debug)]
pub enum TimelineWorkerResult {
    Page(Result<TimelinePage, String>),
}

#[derive(Debug)]
pub enum ReportWorkerResult {
    Preview(Result<ReportPreview, String>),
    Exported(Result<PathBuf, String>),
}

#[derive(Debug)]
pub enum ExportWorkerResult {
    Finished(Result<ExportReport, String>),
}

#[derive(Debug)]
pub enum HashWorkerResult {
    Finished(Result<HashCalculationReport, String>),
}

#[derive(Debug)]
pub enum IntegrityWorkerResult {
    Progress {
        evidence_id: i64,
        done: u64,
        total: Option<u64>,
    },
    Finished(Result<EvidenceIntegrityReport, String>),
}

#[derive(Debug)]
pub enum FolderExportWorkerResult {
    Progress {
        files_done: usize,
        total_files: usize,
        bytes_done: u64,
    },
    Finished(Result<FolderExportReport, String>),
}

#[derive(Debug)]
pub enum FolderHashWorkerResult {
    Progress {
        files_done: usize,
        total_files: usize,
        bytes_done: u64,
    },
    Finished(Result<RecursiveHashReport, String>),
}
