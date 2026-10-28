use serde::{Deserialize, Serialize};

/// Stable command envelope for a fully native UI or other in-process client.
///
/// Commands are deliberately coarse and paged. No response may contain an
/// unbounded artifact collection or full metadata blob set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum BackendCommand {
    CaseSummary,
    Coverage { evidence_id: Option<i64> },
    EntryPage { query: EntryPageQuery },
    ArtifactDetail { query: ArtifactDetailQuery },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum BackendResponse {
    CaseSummary { summary: CaseSummary },
    Coverage { coverage: CoverageBanner },
    EntryPage { page: EntryPage },
    ArtifactDetail { detail: Box<ArtifactDetail> },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseSummary {
    pub id: i64,
    pub name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub timezone: String,
    pub created_at: String,
    /// Monotonic case mutation marker. Clients must discard cached pages when
    /// this changes.
    pub generation: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryPageQuery {
    pub evidence_id: Option<i64>,
    pub cursor: Option<EntryCursor>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryCursor {
    pub after_id: i64,
    pub generation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryPage {
    pub items: Vec<EntrySummary>,
    pub next_cursor: Option<EntryCursor>,
    pub generation: i64,
    /// Every result page carries coverage. A UI must render this instead of
    /// allowing a page-sized response to look like a complete examination.
    pub coverage: CoverageBanner,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntrySummary {
    pub id: i64,
    pub evidence_id: i64,
    pub parent_id: Option<i64>,
    pub logical_path: String,
    pub name: String,
    pub entry_kind: String,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub discovered_by_job_id: Option<i64>,
}

/// Exact, generation-locked selection for the native Inspector.
///
/// The generation is mandatory so a row selected from one result snapshot can
/// never silently resolve against a later mutation of the case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDetailQuery {
    pub entry_id: i64,
    pub expected_generation: i64,
}

/// Describes what the case database actually records for a value. Callers must
/// not turn any non-`Recorded` state into a zero or empty-string value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValueAvailability {
    Recorded,
    NotRecorded,
    RecordedNull,
    Invalid,
    WithheldOversized,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactMetadataState {
    Absent,
    Empty,
    Parsed,
    Malformed,
    Oversized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactSectionAvailability {
    pub state: ArtifactValueAvailability,
    pub reason: Option<String>,
    pub omitted_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDetailField {
    /// Stable allowlisted database/metadata field name.
    pub name: String,
    pub label: String,
    pub value: String,
    pub value_truncated: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactTimestamp {
    pub semantic_field: String,
    pub label: String,
    /// Persisted timestamp text without date/time reinterpretation.
    pub raw_value: String,
    pub value_truncated: bool,
    pub basis: Option<String>,
    pub basis_truncated: bool,
    pub timezone: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactHash {
    pub algorithm: String,
    pub label: String,
    pub value: String,
    pub value_truncated: bool,
    pub scope: Option<String>,
    pub scope_truncated: bool,
    pub scope_availability: ArtifactValueAvailability,
    pub hashed_at: Option<String>,
    pub hashed_at_truncated: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactCoordinate {
    pub name: String,
    pub label: String,
    /// Coordinate system recorded by the parser contract, such as
    /// `decoded_evidence_media` or `registry_hive_file_relative`.
    pub namespace: String,
    pub availability: ArtifactValueAvailability,
    pub value: Option<String>,
    pub value_truncated: bool,
    /// True only when an explicit persisted exactness flag is true.
    pub exact: bool,
    pub unit: Option<String>,
    pub basis: Option<String>,
    pub basis_truncated: bool,
    pub scope: Option<String>,
    pub scope_truncated: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactProvenanceField {
    pub name: String,
    pub label: String,
    pub value: String,
    pub value_truncated: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDetailCompleteness {
    pub state: CoverageState,
    pub is_complete: bool,
    pub detail: String,
    pub diagnostics: Vec<String>,
    pub diagnostics_omitted: usize,
}

/// Bounded, read-only Inspector projection for one canonical filesystem entry.
/// No field contains raw file bytes, arbitrary metadata JSON, or parser logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDetail {
    pub generation: i64,
    pub case_id: i64,
    pub entry_id: i64,
    pub evidence_id: i64,
    pub parent_id: Option<i64>,
    pub source_job_id: Option<i64>,
    pub source_job_type: Option<String>,
    pub source_job_type_truncated: bool,
    pub source_job_status: Option<String>,
    pub source_job_status_truncated: bool,
    pub parser_schema_version: Option<String>,
    pub parser_schema_version_truncated: bool,
    pub logical_path: String,
    pub logical_path_truncated: bool,
    pub source_path: String,
    pub source_path_truncated: bool,
    pub display_name: String,
    pub display_name_truncated: bool,
    pub evidence_display_name: String,
    pub evidence_display_name_truncated: bool,
    pub source_kind: String,
    pub source_kind_truncated: bool,
    pub entry_kind: String,
    pub entry_kind_truncated: bool,
    pub artifact_kind: Option<String>,
    pub artifact_kind_truncated: bool,
    pub size_bytes: Option<i64>,
    pub is_deleted: bool,
    pub metadata_state: ArtifactMetadataState,
    pub fields: Vec<ArtifactDetailField>,
    pub fields_omitted: usize,
    pub timestamps: Vec<ArtifactTimestamp>,
    pub timestamps_omitted: usize,
    pub timestamps_status: ArtifactSectionAvailability,
    pub hashes: Vec<ArtifactHash>,
    pub hashes_status: ArtifactSectionAvailability,
    pub coordinates: Vec<ArtifactCoordinate>,
    pub coordinates_status: ArtifactSectionAvailability,
    pub provenance: Vec<ArtifactProvenanceField>,
    pub provenance_omitted: usize,
    pub completeness: ArtifactDetailCompleteness,
    pub warnings: Vec<String>,
    pub warnings_omitted: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// No processor job exists in the requested scope. This is not complete.
    NotProcessed,
    InProgress,
    Complete,
    Partial,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageBanner {
    pub state: CoverageState,
    pub is_complete: bool,
    pub title: String,
    pub detail: String,
    pub jobs: Vec<JobCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobCoverage {
    pub id: i64,
    pub evidence_id: Option<i64>,
    pub job_type: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// Presence only: detailed diagnostics remain a separate, examiner-driven
    /// request so ordinary grids cannot accidentally materialize large logs.
    pub has_error: bool,
}
