#![forbid(unsafe_code)]

//! Transport-neutral application core for KDFT's standalone desktop shell.
//!
//! This crate intentionally contains no HTTP listener and no GUI runtime. A
//! native shell calls [`DesktopBackend::dispatch`] in-process (or through the
//! shell's private IPC mechanism). The existing browser workbench remains a
//! separate front end while its handlers are progressively moved behind this
//! same bounded command contract.

mod artifact_detail;
pub mod artifacts;
mod bookmarks;
pub mod browse;
pub mod bytes;
pub mod processing;
mod protocol;
mod read_model;
pub mod reports;
pub mod search;
pub mod timeline;
pub mod unlock;
mod workflow;

pub use artifacts::{
    ArtifactCategoryNode, ArtifactCategoryTreeSnapshot, ArtifactPageQuery, ArtifactPageSnapshot,
    ArtifactRow, ArtifactsPage, NativeArtifactService, DEFAULT_ARTIFACTS_PAGE_SIZE,
    MAX_ARTIFACTS_PAGE_SIZE,
};

pub use bookmarks::{
    BookmarkCursor, BookmarkFolderSummary, BookmarkFoldersPage, BookmarkItemDetail,
    BookmarkItemSummary, BookmarkItemsPage, BookmarkSummary, BookmarksPage,
    CreateBookmarkFolderRequest, CreateBookmarkFolderResult, CreateBookmarkRequest,
    CreateBookmarkResult, IncompleteBookmarkSummary, NativeBookmarkService,
    RecursiveFolderBookmarkRequest, RecursiveFolderBookmarkResult, RemoveBookmarkFolderResult,
    RemoveBookmarkItemResult, RemoveBookmarkResult, DEFAULT_BOOKMARK_PAGE_SIZE,
    MAX_BOOKMARK_PAGE_SIZE, MAX_BOOKMARK_PREVIEW_CHARS, MAX_ITEM_DETAIL_PREVIEW_BYTES,
    MAX_ITEM_DETAIL_REF_BYTES,
};
pub use browse::{
    BrowseDirectoryPage, BrowseEntry, BrowseHistoryEntry, EvidenceVolume, NativeBrowseService,
    VolumeAccessState, VolumeIdentity, BITLOCKER_LOCKED_MSG, DEFAULT_DIRECTORY_PAGE_SIZE,
    MAX_DIRECTORY_PAGE_SIZE,
};
pub use bytes::{
    detect_companion_expected_sha256, parse_expected_sha256_from_text, BoundedByteRequest,
    BoundedByteResponse, ByteSourceNamespace, EvidenceIntegrityReport, EvidenceIntegrityRequest,
    ExportReport, ExportTerminalState, FolderExportManifest, FolderExportManifestEntry,
    FolderExportReport, HashCalculationReport, IntegrityTerminalState, NativeByteService,
    RecursiveHashReport, DEFAULT_BYTE_READ_LENGTH, MAX_BOUNDED_BYTE_READ,
};
pub use kdft_case::{
    detect_acquisition_segments, normalized_timezone, AcquisitionSegmentSet, BookmarkType,
    LiveTraversalCheckpoint,
};

pub use artifact_detail::{
    MAX_ARTIFACT_DETAIL_COORDINATES, MAX_ARTIFACT_DETAIL_DIAGNOSTICS, MAX_ARTIFACT_DETAIL_FIELDS,
    MAX_ARTIFACT_DETAIL_HASHES, MAX_ARTIFACT_DETAIL_PATH_CHARS, MAX_ARTIFACT_DETAIL_PROVENANCE,
    MAX_ARTIFACT_DETAIL_TEXT_CHARS, MAX_ARTIFACT_DETAIL_TIMESTAMPS, MAX_ARTIFACT_DETAIL_WARNINGS,
    MAX_ARTIFACT_METADATA_BYTES,
};
pub use protocol::{
    ArtifactCoordinate, ArtifactDetail, ArtifactDetailCompleteness, ArtifactDetailField,
    ArtifactDetailQuery, ArtifactHash, ArtifactMetadataState, ArtifactProvenanceField,
    ArtifactSectionAvailability, ArtifactTimestamp, ArtifactValueAvailability, BackendCommand,
    BackendResponse, CaseSummary, CoverageBanner, CoverageState, EntryCursor, EntryPage,
    EntryPageQuery, EntrySummary, JobCoverage,
};
pub use read_model::{DesktopBackend, DEFAULT_PAGE_SIZE, MAX_IPC_COMMAND_BYTES, MAX_PAGE_SIZE};
pub use workflow::{
    AttachEvidenceRequest, AttachEvidenceResult, CreateCaseRequest, CreateCaseResult,
    EvidenceListRequest, EvidencePage, EvidenceSummary, NativeEvidenceKind,
    NativeProcessingProfile, NativeWorkflowService, ProcessEvidenceRequest, ProcessEvidenceSummary,
    DEFAULT_EVIDENCE_PAGE_SIZE, MAX_EVIDENCE_PAGE_SIZE,
};

pub use processing::{
    reconcile_orphaned_jobs_in_case, NativeAnalysisConfig, NativeAnalysisResult,
    NativeProcessingService, ProcessingJobRecord, ProcessingJobState, ProcessingPreset,
    ProcessorCoverageRecord, ProcessorExecutionRecord, ProcessorGroupSelection, VolumeInclusion,
};

pub use kdft_case::VolumeTarget;

pub use kdft_case::progress::{
    JobProgressPhase, JobProgressSnapshot, JobProgressState, JobProgressTracker, ProgressObserver,
};
