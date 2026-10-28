use crate::{BackendCommand, BackendResponse, CaseSummary, DesktopBackend};
use anyhow::{anyhow, bail, Context, Result};
use kdft_case::progress::{self, JobProgressState, JobProgressTracker};
use kdft_case::{
    AddEvidenceOptions, CreateCaseOptions, EvidenceKind, ProcessEvidenceOptions, ProcessingProfile,
};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_EVIDENCE_PAGE_SIZE: u32 = 50;
pub const MAX_EVIDENCE_PAGE_SIZE: u32 = 200;

const MAX_CASE_NAME_CHARS: usize = 512;
const MAX_OPTION_TEXT_CHARS: usize = 4_096;
const MAX_STATUS_PREVIEW_CHARS: usize = 256;
const MAX_TIMEZONE_PREVIEW_CHARS: usize = 128;
const MAX_REASON_PREVIEW_CHARS: usize = 2_048;
const MAX_PROCESS_REASONS: usize = 16;
const MAX_POST_COMMIT_WARNINGS: usize = 4;
const MAX_WARNING_PREVIEW_CHARS: usize = 2_048;
const SQLITE_CACHE_KIB: i64 = 8 * 1_024;

/// Transport-neutral write/process service for the native desktop shell.
///
/// Unlike [`DesktopBackend`], this type deliberately performs examiner-driven
/// mutations. It has no network or GUI dependency and keeps every collection
/// returned to a caller explicitly bounded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeWorkflowService;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateCaseRequest {
    pub case_path: PathBuf,
    pub name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub case_type: Option<String>,
    pub description: Option<String>,
    pub default_export_folder: Option<PathBuf>,
    pub temporary_folder: Option<PathBuf>,
    pub index_folder: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateCaseResult {
    pub case_id: i64,
    pub case_path: PathBuf,
    pub name: String,
    pub timezone: Option<String>,
    pub created_at: Option<String>,
    /// Mutation marker used by the read-only backend. Native views should
    /// discard cached pages whenever this value changes. `None` means the
    /// mutation committed but its post-commit summary could not be refreshed.
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
    pub post_commit_warnings_omitted: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeEvidenceKind {
    Auto,
    File,
    Folder,
    Image,
}

impl From<NativeEvidenceKind> for EvidenceKind {
    fn from(value: NativeEvidenceKind) -> Self {
        match value {
            NativeEvidenceKind::Auto => Self::Auto,
            NativeEvidenceKind::File => Self::File,
            NativeEvidenceKind::Folder => Self::Folder,
            NativeEvidenceKind::Image => Self::Image,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachEvidenceRequest {
    pub case_path: PathBuf,
    pub evidence_path: PathBuf,
    pub kind: NativeEvidenceKind,
    pub read_file_system_requested: bool,
    pub notes: Option<String>,
    /// Optional examiner-selected IANA display timezone. Canonical parsed
    /// timestamps remain UTC. When absent, the current case timezone is used.
    pub display_timezone: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub integrity_status: Option<String>,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub integrity_details_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachEvidenceResult {
    pub evidence_id: i64,
    /// `None` means the attachment committed but its bounded post-commit
    /// projection could not be refreshed. The mandatory ID remains truthful.
    pub evidence: Option<EvidenceSummary>,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
    pub post_commit_warnings_omitted: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceListRequest {
    pub case_path: PathBuf,
    pub after_id: Option<i64>,
    pub limit: Option<u32>,
    /// Generation returned with the previous page. Supplying it prevents a
    /// cursor from mixing rows from two different case snapshots.
    #[serde(default)]
    pub expected_generation: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePage {
    pub items: Vec<EvidenceSummary>,
    pub next_after_id: Option<i64>,
    pub has_more: bool,
    pub returned: u32,
    pub case_generation: i64,
}

/// Bounded evidence projection for native list views. Full manifests and
/// arbitrary metadata are intentionally excluded from this type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub id: i64,
    pub source_kind: String,
    pub display_name: String,
    pub display_name_truncated: bool,
    pub source_path_preview: String,
    pub source_path_truncated: bool,
    pub size_bytes: Option<i64>,
    pub read_file_system_requested: bool,
    pub attach_status: String,
    pub encryption_status: String,
    pub attached_at: String,
    pub indexed_at: Option<String>,
    pub display_timezone: String,
    pub last_job_status: Option<String>,
    pub content_indexed: Option<bool>,
    pub sha256_hex: Option<String>,
    pub hashed_at: Option<String>,
    pub sha256_scope: Option<String>,
    pub notes_preview: Option<String>,
    pub notes_truncated: bool,
    pub is_standalone_mft: bool,
    #[serde(default)]
    pub integrity_status: Option<String>,
    #[serde(default)]
    pub expected_sha256: Option<String>,
    #[serde(default)]
    pub integrity_details_json: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeProcessingProfile {
    pub capture_content: bool,
    pub parse_emails: bool,
    pub parse_browsers: bool,
}

impl Default for NativeProcessingProfile {
    fn default() -> Self {
        Self {
            capture_content: true,
            parse_emails: true,
            parse_browsers: true,
        }
    }
}

impl From<NativeProcessingProfile> for ProcessingProfile {
    fn from(value: NativeProcessingProfile) -> Self {
        Self {
            capture_content: value.capture_content,
            parse_emails: value.parse_emails,
            parse_browsers: value.parse_browsers,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessEvidenceRequest {
    pub case_path: PathBuf,
    pub evidence_id: i64,
    /// Zero means no examiner-requested entry limit.
    pub max_entries: usize,
    pub profile: NativeProcessingProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessEvidenceSummary {
    pub job_id: i64,
    pub evidence_id: i64,
    pub entries_indexed: usize,
    pub attempt_entries_indexed: usize,
    pub replacement_committed: bool,
    pub canonical_generation_preserved: bool,
    pub retained_entry_count: usize,
    pub truncated: bool,
    pub partial_artifact_coverage: bool,
    pub completed_with_diagnostics: bool,
    pub status: String,
    pub bookmark_items_relinked: usize,
    pub truncation_reasons: Vec<String>,
    pub truncation_reasons_omitted: usize,
    /// `None` means the committed result is valid but refreshing the
    /// read-only generation marker failed. See `post_commit_warnings`.
    pub case_generation: Option<i64>,
    pub progress_summary_persisted: bool,
    /// Bounded secondary failures after the canonical processing transaction
    /// committed. These warnings never turn a committed result into `Err`.
    pub post_commit_warnings: Vec<String>,
    pub post_commit_warnings_omitted: usize,
}

impl NativeWorkflowService {
    pub fn create_case(request: CreateCaseRequest) -> Result<CreateCaseResult> {
        create_case_with_refresh(request, case_summary_snapshot)
    }

    pub fn attach_evidence(request: AttachEvidenceRequest) -> Result<AttachEvidenceResult> {
        attach_evidence_with_refresh(request, |case_path, evidence_id| {
            read_evidence_snapshot(case_path, 0, 1, None, Some(evidence_id))
        })
    }

    pub fn set_case_display_timezone(case_path: PathBuf, timezone: String) -> Result<()> {
        kdft_case::set_case_display_timezone(&case_path, &timezone)
    }

    pub fn update_evidence_intake_metadata(
        case_path: PathBuf,
        evidence_id: i64,
        display_name: Option<String>,
        integrity_status: Option<String>,
        expected_sha256: Option<String>,
        integrity_details_json: Option<String>,
    ) -> Result<()> {
        kdft_case::update_evidence_intake_metadata(
            &case_path,
            evidence_id,
            display_name.as_deref(),
            integrity_status.as_deref(),
            expected_sha256.as_deref(),
            integrity_details_json.as_deref(),
        )
    }

    pub fn list_evidence(request: EvidenceListRequest) -> Result<EvidencePage> {
        let after_id = request.after_id.unwrap_or(0);
        if after_id < 0 {
            bail!("evidence cursor cannot be negative");
        }
        let limit = request.limit.unwrap_or(DEFAULT_EVIDENCE_PAGE_SIZE);
        if limit == 0 || limit > MAX_EVIDENCE_PAGE_SIZE {
            bail!("evidence page limit must be between 1 and {MAX_EVIDENCE_PAGE_SIZE}");
        }

        let snapshot = read_evidence_snapshot(
            &request.case_path,
            after_id,
            limit,
            request.expected_generation,
            None,
        )?;
        let mut items = snapshot.items;
        let has_more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_after_id = has_more.then(|| items.last().map(|item| item.id)).flatten();
        Ok(EvidencePage {
            returned: u32::try_from(items.len()).unwrap_or(limit),
            items,
            next_after_id,
            has_more,
            case_generation: snapshot.generation,
        })
    }

    /// Runs the base filesystem processing pipeline synchronously on the
    /// caller's thread. The caller should retain a clone of `tracker` for live
    /// snapshots and examiner cancellation from another thread.
    pub fn process_evidence(
        request: ProcessEvidenceRequest,
        tracker: &JobProgressTracker,
    ) -> Result<ProcessEvidenceSummary> {
        if request.evidence_id <= 0 {
            bail!("evidence id must be positive");
        }
        if tracker.snapshot().state.is_terminal() {
            bail!("progress tracker is already terminal");
        }

        tracker.set_evidence_id(request.evidence_id);
        tracker.start_stage(
            if request.profile.capture_content {
                "Filesystem inventory and content capture"
            } else {
                "Filesystem inventory"
            },
            1,
            Some(1),
            "entries",
            None,
        );
        tracker.set_auto_advance_database_entries(true);
        let processed = progress::with_job_progress(tracker, || {
            kdft_case::process_evidence_with_profile(
                &request.case_path,
                ProcessEvidenceOptions {
                    evidence_id: request.evidence_id,
                    max_entries: request.max_entries,
                },
                request.profile.into(),
            )
        });
        tracker.set_auto_advance_database_entries(false);

        let processed = match processed {
            Ok(processed) => processed,
            Err(error) => {
                tracker.record_error(None);
                tracker.finish(JobProgressState::Failed);
                let snapshot = tracker.snapshot();
                let mut progress_warning = None;
                if let Some(job_id) = snapshot.job_id {
                    if let Err(progress_error) = kdft_case::record_job_progress_summary(
                        &request.case_path,
                        job_id,
                        &snapshot,
                    ) {
                        progress_warning = Some(
                            preview(
                                &format!(
                                    "terminal failure telemetry also could not be persisted: {progress_error:#}"
                                ),
                                MAX_WARNING_PREVIEW_CHARS,
                            )
                            .0,
                        );
                    }
                }
                let context = match progress_warning {
                    Some(warning) => format!("processing evidence in native workflow; {warning}"),
                    None => "processing evidence in native workflow".to_string(),
                };
                return Err(error).context(context);
            }
        };

        let terminal_state = if processed.status == "cancelled" {
            JobProgressState::Cancelled
        } else if processed.truncated {
            JobProgressState::Truncated
        } else if processed.completed_with_diagnostics || processed.partial_artifact_coverage {
            JobProgressState::CompleteWithDiagnostics
        } else if processed.status == "completed" {
            JobProgressState::Complete
        } else {
            JobProgressState::CompleteWithDiagnostics
        };
        tracker.finish(terminal_state);
        let snapshot = tracker.snapshot();
        let mut post_commit_warnings = Vec::new();
        let progress_summary_persisted = match kdft_case::record_job_progress_summary(
            &request.case_path,
            processed.job_id,
            &snapshot,
        ) {
            Ok(()) => true,
            Err(error) => {
                push_bounded_warning(
                        &mut post_commit_warnings,
                        format!(
                            "Processing committed, but terminal progress telemetry could not be persisted: {error:#}"
                        ),
                    );
                false
            }
        };

        let total_reasons = processed.truncation_reasons.len();
        let truncation_reasons = processed
            .truncation_reasons
            .into_iter()
            .take(MAX_PROCESS_REASONS)
            .map(|reason| preview(&reason, MAX_REASON_PREVIEW_CHARS).0)
            .collect::<Vec<_>>();
        let case_generation = match case_generation(&request.case_path) {
            Ok(generation) => Some(generation),
            Err(error) => {
                push_bounded_warning(
                    &mut post_commit_warnings,
                    format!(
                        "Processing committed, but the refreshed case generation could not be read: {error:#}"
                    ),
                );
                None
            }
        };
        let post_commit_warning_count = post_commit_warnings.len();
        post_commit_warnings.truncate(MAX_POST_COMMIT_WARNINGS);
        Ok(ProcessEvidenceSummary {
            job_id: processed.job_id,
            evidence_id: processed.evidence_id,
            entries_indexed: processed.entries_indexed,
            attempt_entries_indexed: processed.attempt_entries_indexed,
            replacement_committed: processed.replacement_committed,
            canonical_generation_preserved: processed.canonical_generation_preserved,
            retained_entry_count: processed.retained_entry_count,
            truncated: processed.truncated,
            partial_artifact_coverage: processed.partial_artifact_coverage,
            completed_with_diagnostics: processed.completed_with_diagnostics,
            status: preview(&processed.status, MAX_STATUS_PREVIEW_CHARS).0,
            bookmark_items_relinked: processed.bookmark_items_relinked,
            truncation_reasons,
            truncation_reasons_omitted: total_reasons.saturating_sub(MAX_PROCESS_REASONS),
            case_generation,
            progress_summary_persisted,
            post_commit_warnings,
            post_commit_warnings_omitted: post_commit_warning_count
                .saturating_sub(MAX_POST_COMMIT_WARNINGS),
        })
    }
}

fn create_case_with_refresh<F>(request: CreateCaseRequest, refresh: F) -> Result<CreateCaseResult>
where
    F: FnOnce(&Path) -> Result<CaseSummary>,
{
    let CreateCaseRequest {
        case_path,
        name,
        examiner_name,
        case_number,
        case_type,
        description,
        default_export_folder,
        temporary_folder,
        index_folder,
    } = request;
    let name = required_text("case name", name, MAX_CASE_NAME_CHARS)?;
    let committed_name = name.clone();
    let examiner_name = optional_text("examiner name", examiner_name, MAX_OPTION_TEXT_CHARS)?;
    let case_number = optional_text("case number", case_number, MAX_OPTION_TEXT_CHARS)?;
    let case_type = optional_text("case type", case_type, MAX_OPTION_TEXT_CHARS)?;
    let description = optional_text("case description", description, MAX_OPTION_TEXT_CHARS)?;
    let case_id = kdft_case::create_case(
        &case_path,
        CreateCaseOptions {
            name,
            examiner_name,
            case_number,
            case_type,
            description,
            default_export_folder,
            temporary_folder,
            index_folder,
        },
    )
    .context("creating native KDFT case")?;

    let mut post_commit_warnings = Vec::new();
    let (name, timezone, created_at, case_generation) = match refresh(&case_path) {
        Ok(summary) => (
            summary.name,
            Some(summary.timezone),
            Some(summary.created_at),
            Some(summary.generation),
        ),
        Err(error) => {
            push_bounded_warning(
                &mut post_commit_warnings,
                format!(
                    "Case creation committed, but its read-only summary could not be refreshed: {error:#}"
                ),
            );
            (committed_name, None, None, None)
        }
    };
    let post_commit_warning_count = post_commit_warnings.len();
    post_commit_warnings.truncate(MAX_POST_COMMIT_WARNINGS);
    Ok(CreateCaseResult {
        case_id,
        case_path,
        name,
        timezone,
        created_at,
        case_generation,
        post_commit_warnings,
        post_commit_warnings_omitted: post_commit_warning_count
            .saturating_sub(MAX_POST_COMMIT_WARNINGS),
    })
}

fn attach_evidence_with_refresh<F>(
    request: AttachEvidenceRequest,
    refresh: F,
) -> Result<AttachEvidenceResult>
where
    F: FnOnce(&Path, i64) -> Result<EvidenceSnapshot>,
{
    let AttachEvidenceRequest {
        case_path,
        evidence_path,
        kind,
        read_file_system_requested,
        notes,
        display_timezone,
        display_name,
        integrity_status,
        expected_sha256,
        integrity_details_json,
    } = request;
    if evidence_path.as_os_str().is_empty() {
        bail!("evidence path cannot be empty");
    }
    let notes = optional_text("evidence notes", notes, MAX_OPTION_TEXT_CHARS)?;
    let options = AddEvidenceOptions {
        path: evidence_path,
        kind: kind.into(),
        read_file_system_requested,
        notes,
    };
    // Browser databases deliberately retain their typed kdft-case error in
    // this first native slice. There is no silent browser-import fallback.
    let evidence_id = match display_timezone.as_deref() {
        Some(timezone) => {
            if timezone.chars().count() > MAX_TIMEZONE_PREVIEW_CHARS {
                bail!("display timezone exceeds {MAX_TIMEZONE_PREVIEW_CHARS} characters");
            }
            kdft_case::add_evidence_with_timezone(&case_path, options, timezone)
        }
        None => kdft_case::add_evidence(&case_path, options),
    }
    .context("attaching evidence to native KDFT case")?;

    if display_name.is_some()
        || integrity_status.is_some()
        || expected_sha256.is_some()
        || integrity_details_json.is_some()
    {
        let _ = kdft_case::update_evidence_intake_metadata(
            &case_path,
            evidence_id,
            display_name.as_deref(),
            integrity_status.as_deref(),
            expected_sha256.as_deref(),
            integrity_details_json.as_deref(),
        );
    }

    let mut post_commit_warnings = Vec::new();
    let (evidence, case_generation) = match refresh(&case_path, evidence_id) {
        Ok(snapshot) => {
            let generation = Some(snapshot.generation);
            let evidence = snapshot
                .items
                .into_iter()
                .find(|source| source.id == evidence_id);
            if evidence.is_none() {
                push_bounded_warning(
                    &mut post_commit_warnings,
                    format!(
                        "Evidence attachment committed as #{evidence_id}, but its bounded post-commit projection returned no row"
                    ),
                );
            }
            (evidence, generation)
        }
        Err(error) => {
            push_bounded_warning(
                &mut post_commit_warnings,
                format!(
                    "Evidence attachment committed as #{evidence_id}, but its bounded post-commit projection could not be refreshed: {error:#}"
                ),
            );
            (None, None)
        }
    };
    let post_commit_warning_count = post_commit_warnings.len();
    post_commit_warnings.truncate(MAX_POST_COMMIT_WARNINGS);
    Ok(AttachEvidenceResult {
        evidence_id,
        evidence,
        case_generation,
        post_commit_warnings,
        post_commit_warnings_omitted: post_commit_warning_count
            .saturating_sub(MAX_POST_COMMIT_WARNINGS),
    })
}

fn required_text(label: &str, value: String, max_chars: usize) -> Result<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("{label} cannot be empty");
    }
    if value.chars().count() > max_chars {
        bail!("{label} exceeds {max_chars} characters");
    }
    Ok(value)
}

fn optional_text(label: &str, value: Option<String>, max_chars: usize) -> Result<Option<String>> {
    value
        .map(|value| required_text(label, value, max_chars))
        .transpose()
}

fn preview(value: &str, max_chars: usize) -> (String, bool) {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(max_chars).collect::<String>();
    let truncated = chars.next().is_some();
    (preview, truncated)
}

struct EvidenceSnapshot {
    items: Vec<EvidenceSummary>,
    generation: i64,
}

fn read_evidence_snapshot(
    case_path: &Path,
    after_id: i64,
    limit: u32,
    expected_generation: Option<i64>,
    exact_id: Option<i64>,
) -> Result<EvidenceSnapshot> {
    // Open through kdft-case first so supported older cases receive the same
    // schema migrations as every other application surface. The bounded read
    // itself uses a fresh query-only snapshot below.
    kdft_case::case_info(case_path).context("validating case before listing evidence")?;
    let mut conn = Connection::open_with_flags(
        case_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening case read-only: {}", case_path.display()))?;
    conn.busy_timeout(Duration::from_secs(2))?;
    conn.pragma_update(None, "query_only", true)?;
    conn.pragma_update(None, "cache_size", -SQLITE_CACHE_KIB)?;
    conn.pragma_update(None, "mmap_size", 0_i64)?;

    let tx = conn
        .transaction()
        .context("starting stable evidence-list snapshot")?;
    let generation = tx
        .query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
            row.get(0)
        })
        .context("reading evidence-list generation")?;
    if let Some(expected) = expected_generation {
        if expected != generation {
            bail!(
                "stale evidence cursor: case generation changed from {expected} to {generation}; restart the query"
            );
        }
    }

    let fetch_limit = i64::from(limit) + 1;
    let items = {
        let mut statement = tx.prepare_cached(
            "SELECT e.id,
                    substr(e.source_kind, 1, 256),
                    substr(e.source_path, 1, 4096),
                    CASE WHEN length(e.source_path) > 4096 THEN 1 ELSE 0 END,
                    substr(e.display_name, 1, 1024),
                    CASE WHEN length(e.display_name) > 1024 THEN 1 ELSE 0 END,
                    e.size_bytes,
                    e.read_file_system_requested,
                    substr(e.attach_status, 1, 256),
                    substr(e.encryption_status, 1, 256),
                    substr(e.attached_at, 1, 128),
                    substr(e.indexed_at, 1, 128),
                    substr(e.notes, 1, 1024),
                    CASE WHEN length(e.notes) > 1024 THEN 1 ELSE 0 END,
                    substr(e.display_timezone, 1, 128),
                    substr((SELECT j.status FROM evidence_jobs j
                     WHERE j.case_id = e.case_id AND j.evidence_id = e.id
                       AND j.job_type = CASE WHEN e.source_kind = 'browser_history'
                           THEN 'browser_history_import' ELSE 'filesystem_index' END
                     ORDER BY j.id DESC LIMIT 1), 1, 256),
                    substr(e.sha256_hex, 1, 128),
                    substr(e.hashed_at, 1, 128),
                    substr(e.sha256_scope, 1, 256),
                    (SELECT CASE
                        WHEN j.job_type = 'content_head_backfill' THEN
                            CASE WHEN j.status = 'completed' THEN 1 ELSE 0 END
                        ELSE json_extract(
                            CASE WHEN json_valid(j.parameters_json)
                                THEN j.parameters_json ELSE '{}' END,
                            '$.capture_content'
                        )
                     END
                     FROM evidence_jobs j
                     WHERE j.case_id = e.case_id AND j.evidence_id = e.id
                       AND j.job_type IN ('filesystem_index', 'content_head_backfill')
                       AND j.status IN (
                           'completed', 'completed_with_diagnostics', 'truncated',
                           'cancelled', 'failed'
                       )
                     ORDER BY j.id DESC LIMIT 1),
                    EXISTS(
                        SELECT 1 FROM filesystem_entries fe
                        WHERE fe.case_id = e.case_id AND fe.evidence_id = e.id
                          AND json_extract(
                              CASE WHEN json_valid(fe.metadata_json)
                                  THEN fe.metadata_json ELSE '{}' END,
                              '$.virtual_filesystem'
                          ) = 'standalone_mft_reconstruction'
                    ),
                    substr(e.integrity_status, 1, 64),
                    substr(e.expected_sha256, 1, 128),
                    substr(e.integrity_details_json, 1, 4096)
             FROM evidence_sources e
             WHERE e.attach_status <> 'superseded'
               AND ((?3 IS NULL AND e.id > ?1) OR e.id = ?3)
             ORDER BY e.id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_id, fetch_limit, exact_id], |row| {
            let source_path: String = row.get(2)?;
            let source_path_truncated = row.get::<_, i64>(3)? != 0;
            let display_name: String = row.get(4)?;
            let display_name_truncated = row.get::<_, i64>(5)? != 0;
            let notes_preview: Option<String> = row.get(12)?;
            let notes_truncated = row.get::<_, i64>(13)? != 0;
            let has_mft_entries = row.get::<_, i64>(20)? != 0;
            Ok(EvidenceSummary {
                id: row.get(0)?,
                source_kind: row.get(1)?,
                display_name,
                display_name_truncated,
                source_path_preview: source_path.clone(),
                source_path_truncated,
                size_bytes: row.get(6)?,
                read_file_system_requested: row.get::<_, i64>(7)? != 0,
                attach_status: row.get(8)?,
                encryption_status: row.get(9)?,
                attached_at: row.get(10)?,
                indexed_at: row.get(11)?,
                display_timezone: row.get(14)?,
                last_job_status: row.get(15)?,
                content_indexed: row.get::<_, Option<i64>>(19)?.map(|value| value != 0),
                sha256_hex: row.get(16)?,
                hashed_at: row.get(17)?,
                sha256_scope: row.get(18)?,
                notes_preview,
                notes_truncated,
                is_standalone_mft: has_mft_entries
                    || (!source_path_truncated
                        && !display_name_truncated
                        && kdft_case::is_standalone_mft_evidence_candidate(
                            Path::new(&source_path),
                            &row.get::<_, String>(4)?,
                        )),
                integrity_status: row.get(21)?,
                expected_sha256: row.get(22)?,
                integrity_details_json: row.get(23)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("reading bounded evidence page")?
    };
    tx.commit().context("closing evidence-list snapshot")?;
    Ok(EvidenceSnapshot { items, generation })
}

fn push_bounded_warning(warnings: &mut Vec<String>, warning: String) {
    warnings.push(preview(&warning, MAX_WARNING_PREVIEW_CHARS).0);
}

fn case_generation(case_path: &std::path::Path) -> Result<i64> {
    Ok(case_summary_snapshot(case_path)?.generation)
}

fn case_summary_snapshot(case_path: &Path) -> Result<CaseSummary> {
    let backend = DesktopBackend::open(case_path)?;
    match backend.dispatch(BackendCommand::CaseSummary) {
        BackendResponse::CaseSummary { summary } => Ok(summary),
        BackendResponse::Error { code, message } => {
            Err(anyhow!("read-only backend {code}: {message}"))
        }
        _ => Err(anyhow!("read-only backend returned an unexpected response")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntryPageQuery, MAX_PAGE_SIZE};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);

    struct TestWorkspace {
        root: PathBuf,
    }

    impl TestWorkspace {
        fn new(label: &str) -> Result<Self> {
            let serial = NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "kdft-native-workflow-{label}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&root)?;
            Ok(Self { root })
        }

        fn case_path(&self) -> PathBuf {
            self.root.join("case.kdft.sqlite")
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn create_request(case_path: PathBuf) -> CreateCaseRequest {
        CreateCaseRequest {
            case_path,
            name: "Native fixture".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("NATIVE-1".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        }
    }

    #[test]
    fn committed_case_creation_survives_summary_refresh_failure() -> Result<()> {
        let workspace = TestWorkspace::new("create-refresh-warning")?;
        let case_path = workspace.case_path();
        let created = create_case_with_refresh(create_request(case_path.clone()), |_| {
            Err(anyhow!("synthetic case summary refresh failure"))
        })?;

        assert_eq!(created.case_id, 1);
        assert_eq!(created.name, "Native fixture");
        assert!(created.timezone.is_none());
        assert!(created.created_at.is_none());
        assert!(created.case_generation.is_none());
        assert_eq!(created.post_commit_warnings.len(), 1);
        assert!(created.post_commit_warnings[0].contains("creation committed"));
        assert!(created.post_commit_warnings[0].len() <= MAX_WARNING_PREVIEW_CHARS);

        // The refresh error cannot reclassify the already-committed mutation.
        let viewer = DesktopBackend::open(&case_path)?;
        match viewer.dispatch(BackendCommand::CaseSummary) {
            BackendResponse::CaseSummary { summary } => assert_eq!(summary.id, created.case_id),
            other => panic!("unexpected viewer response: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn committed_attachment_survives_projection_refresh_failure() -> Result<()> {
        let workspace = TestWorkspace::new("attach-refresh-warning")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        let evidence_path = workspace.root.join("committed-evidence.bin");
        fs::write(&evidence_path, b"synthetic")?;

        let attached = attach_evidence_with_refresh(
            AttachEvidenceRequest {
                case_path: case_path.clone(),
                evidence_path,
                kind: NativeEvidenceKind::File,
                read_file_system_requested: true,
                notes: None,
                display_timezone: None,
                display_name: None,
                integrity_status: None,
                expected_sha256: None,
                integrity_details_json: None,
            },
            |_, _| Err(anyhow!("synthetic evidence projection refresh failure")),
        )?;

        assert_eq!(attached.evidence_id, 1);
        assert!(attached.evidence.is_none());
        assert!(attached.case_generation.is_none());
        assert_eq!(attached.post_commit_warnings.len(), 1);
        assert!(attached.post_commit_warnings[0].contains("attachment committed"));
        assert!(attached.post_commit_warnings[0].len() <= MAX_WARNING_PREVIEW_CHARS);

        // The evidence exists exactly once; the examiner must refresh rather
        // than retrying the attachment after a projection-only failure.
        let page = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path,
            after_id: None,
            limit: Some(MAX_EVIDENCE_PAGE_SIZE),
            expected_generation: None,
        })?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, attached.evidence_id);
        Ok(())
    }

    #[test]
    fn create_attach_and_list_evidence_are_bounded() -> Result<()> {
        let workspace = TestWorkspace::new("create-attach-list")?;
        let case_path = workspace.case_path();
        let created = NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        assert_eq!(created.case_id, 1);
        assert_eq!(created.timezone.as_deref(), Some("UTC"));
        assert!(created.post_commit_warnings.is_empty());
        DesktopBackend::open(&case_path)?;

        let auto_path = workspace.root.join("auto.txt");
        let file_path = workspace.root.join("file.bin");
        let image_path = workspace.root.join("disk.img");
        let folder_path = workspace.root.join("folder");
        fs::write(&auto_path, b"synthetic auto")?;
        fs::write(&file_path, b"synthetic file")?;
        fs::write(&image_path, b"synthetic image placeholder")?;
        fs::create_dir(&folder_path)?;
        for (index, (evidence_path, kind)) in [
            (auto_path, NativeEvidenceKind::Auto),
            (file_path, NativeEvidenceKind::File),
            (image_path, NativeEvidenceKind::Image),
            (folder_path, NativeEvidenceKind::Folder),
        ]
        .into_iter()
        .enumerate()
        {
            let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
                case_path: case_path.clone(),
                evidence_path,
                kind,
                read_file_system_requested: true,
                notes: Some(format!("synthetic evidence {index}")),
                display_timezone: None,
                display_name: None,
                integrity_status: None,
                expected_sha256: None,
                integrity_details_json: None,
            })?;
            let expected_id = i64::try_from(index + 1)?;
            assert_eq!(attached.evidence_id, expected_id);
            assert_eq!(
                attached.evidence.as_ref().map(|evidence| evidence.id),
                Some(expected_id)
            );
            assert!(attached.post_commit_warnings.is_empty());
        }

        // A large or malformed manifest is deliberately outside the bounded
        // list projection. This would make kdft_case::list_evidence parse the
        // complete source collection and fail before returning the first row.
        let conn = Connection::open(&case_path)?;
        conn.execute(
            "UPDATE evidence_sources
             SET acquisition_manifest_json = '{not-json',
                 source_path = ?1,
                 display_name = ?2,
                 notes = ?3
             WHERE id = 4",
            params!["p".repeat(10_000), "d".repeat(2_000), "n".repeat(3_000)],
        )?;
        drop(conn);

        let first = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path: case_path.clone(),
            after_id: None,
            limit: Some(2),
            expected_generation: None,
        })?;
        assert_eq!(first.returned, 2);
        assert!(first.has_more);
        assert_eq!(first.next_after_id, Some(2));
        let second = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path,
            after_id: first.next_after_id,
            limit: Some(2),
            expected_generation: Some(first.case_generation),
        })?;
        assert_eq!(second.items.len(), 2);
        assert!(!second.has_more);
        assert!(second.next_after_id.is_none());
        let bounded = second
            .items
            .iter()
            .find(|item| item.id == 4)
            .expect("fourth summary");
        assert_eq!(bounded.source_path_preview.chars().count(), 4_096);
        assert!(bounded.source_path_truncated);
        assert_eq!(bounded.display_name.chars().count(), 1_024);
        assert!(bounded.display_name_truncated);
        assert_eq!(bounded.notes_preview.as_deref().map(str::len), Some(1_024));
        assert!(bounded.notes_truncated);
        Ok(())
    }

    #[test]
    fn evidence_cursor_rejects_a_different_case_generation() -> Result<()> {
        let workspace = TestWorkspace::new("evidence-generation")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        let first_path = workspace.root.join("first.txt");
        fs::write(&first_path, b"first")?;
        NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: first_path,
            kind: NativeEvidenceKind::File,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: None,
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })?;
        let first_page = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path: case_path.clone(),
            after_id: None,
            limit: Some(1),
            expected_generation: None,
        })?;

        let second_path = workspace.root.join("second.txt");
        fs::write(&second_path, b"second")?;
        NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: second_path,
            kind: NativeEvidenceKind::File,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: None,
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })?;
        let error = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path,
            after_id: first_page.next_after_id,
            limit: Some(1),
            expected_generation: Some(first_page.case_generation),
        })
        .expect_err("a changed generation must invalidate the evidence cursor");
        assert!(error.to_string().contains("stale evidence cursor"));
        Ok(())
    }

    #[test]
    fn supplied_tracker_cancels_without_publishing_partial_entries() -> Result<()> {
        let workspace = TestWorkspace::new("cancel")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        let evidence_dir = workspace.root.join("evidence");
        fs::create_dir(&evidence_dir)?;
        for index in 0..32 {
            fs::write(
                evidence_dir.join(format!("item-{index:03}.txt")),
                b"synthetic content",
            )?;
        }
        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: evidence_dir,
            kind: NativeEvidenceKind::Folder,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: None,
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })?;

        let tracker = JobProgressTracker::new("native-cancel-test", "process", None);
        let cancellation_handle = tracker.clone();
        cancellation_handle.request_cancellation();
        let result = NativeWorkflowService::process_evidence(
            ProcessEvidenceRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                max_entries: 0,
                profile: NativeProcessingProfile::default(),
            },
            &tracker,
        )?;
        assert_eq!(result.status, "cancelled");
        assert_eq!(result.entries_indexed, 0);
        assert_eq!(result.retained_entry_count, 0);
        assert_eq!(tracker.snapshot().state, JobProgressState::Cancelled);

        // The viewer remains the same separately opened read-only backend; a
        // cancelled writer cannot make an unpublished partial page visible.
        let viewer = DesktopBackend::open(&case_path)?;
        let response = viewer.dispatch(BackendCommand::EntryPage {
            query: EntryPageQuery {
                evidence_id: Some(attached.evidence_id),
                cursor: None,
                limit: Some(MAX_PAGE_SIZE),
            },
        });
        match response {
            BackendResponse::EntryPage { page } => assert!(page.items.is_empty()),
            other => panic!("unexpected viewer response: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn committed_processing_survives_progress_persistence_failure() -> Result<()> {
        let workspace = TestWorkspace::new("progress-persistence-warning")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        let evidence_dir = workspace.root.join("evidence");
        fs::create_dir(&evidence_dir)?;
        fs::write(evidence_dir.join("committed.txt"), b"committed content")?;
        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: evidence_dir,
            kind: NativeEvidenceKind::Folder,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: None,
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })?;

        let conn = Connection::open(&case_path)?;
        conn.execute_batch(
            "CREATE TRIGGER fail_native_progress_summary
             BEFORE UPDATE OF parameters_json ON evidence_jobs
             WHEN json_type(NEW.parameters_json, '$.progress') IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'synthetic terminal progress persistence failure');
             END;",
        )?;
        drop(conn);

        let tracker = JobProgressTracker::new("native-progress-warning", "process", None);
        let result = NativeWorkflowService::process_evidence(
            ProcessEvidenceRequest {
                case_path: case_path.clone(),
                evidence_id: attached.evidence_id,
                max_entries: 0,
                profile: NativeProcessingProfile {
                    capture_content: false,
                    parse_emails: false,
                    parse_browsers: false,
                },
            },
            &tracker,
        )?;
        assert_eq!(result.status, "completed");
        assert!(result.retained_entry_count > 0);
        assert!(!result.progress_summary_persisted);
        assert_eq!(result.post_commit_warnings.len(), 1);
        assert!(result.post_commit_warnings[0].contains("Processing committed"));
        assert!(result.case_generation.is_some());

        let viewer = DesktopBackend::open(&case_path)?;
        let response = viewer.dispatch(BackendCommand::EntryPage {
            query: EntryPageQuery {
                evidence_id: Some(attached.evidence_id),
                cursor: None,
                limit: Some(MAX_PAGE_SIZE),
            },
        });
        match response {
            BackendResponse::EntryPage { page } => assert!(!page.items.is_empty()),
            other => panic!("unexpected viewer response: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn progress_persistence_failure_does_not_mask_processor_error() -> Result<()> {
        let workspace = TestWorkspace::new("processor-error-preserved")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        let evidence_path = workspace.root.join("removed-before-processing.bin");
        fs::write(&evidence_path, b"synthetic")?;
        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: evidence_path.clone(),
            kind: NativeEvidenceKind::File,
            read_file_system_requested: true,
            notes: None,
            display_timezone: None,
            display_name: None,
            integrity_status: None,
            expected_sha256: None,
            integrity_details_json: None,
        })?;
        fs::remove_file(&evidence_path)?;

        let conn = Connection::open(&case_path)?;
        conn.execute_batch(
            "CREATE TRIGGER fail_native_failure_progress_summary
             BEFORE UPDATE OF parameters_json ON evidence_jobs
             WHEN json_type(NEW.parameters_json, '$.progress') IS NOT NULL
             BEGIN
                 SELECT RAISE(FAIL, 'synthetic failure progress persistence failure');
             END;",
        )?;
        drop(conn);

        let tracker = JobProgressTracker::new("native-error-warning", "process", None);
        let error = NativeWorkflowService::process_evidence(
            ProcessEvidenceRequest {
                case_path,
                evidence_id: attached.evidence_id,
                max_entries: 0,
                profile: NativeProcessingProfile {
                    capture_content: false,
                    parse_emails: false,
                    parse_browsers: false,
                },
            },
            &tracker,
        )
        .expect_err("the removed evidence must fail processing");
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("terminal failure telemetry"));
        assert!(error_chain.contains("reading file evidence metadata"));
        assert_eq!(tracker.snapshot().state, JobProgressState::Failed);
        Ok(())
    }

    #[test]
    fn invalid_evidence_page_limits_are_rejected() -> Result<()> {
        let workspace = TestWorkspace::new("page-limit")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        for limit in [0, MAX_EVIDENCE_PAGE_SIZE + 1] {
            let error = NativeWorkflowService::list_evidence(EvidenceListRequest {
                case_path: case_path.clone(),
                after_id: None,
                limit: Some(limit),
                expected_generation: None,
            })
            .expect_err("unbounded evidence page must fail");
            assert!(error.to_string().contains("evidence page limit"));
        }
        Ok(())
    }

    #[test]
    fn case_display_timezone_persists_and_audits_without_modifying_utc() -> Result<()> {
        let workspace = TestWorkspace::new("timezone-audit")?;
        let case_path = workspace.case_path();
        let created = NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        assert_eq!(created.timezone.as_deref(), Some("UTC"));

        // Change display timezone to Europe/Bucharest
        NativeWorkflowService::set_case_display_timezone(
            case_path.clone(),
            "Europe/Bucharest".to_string(),
        )?;

        // Verify stored case options has new timezone
        let conn = Connection::open(&case_path)?;
        let tz: String = conn.query_row(
            "SELECT timezone FROM case_options WHERE case_id = 1",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(tz, "Europe/Bucharest");

        // Verify audit event was logged
        let (action, details): (String, String) = conn.query_row(
            "SELECT event_type, details_json FROM audit_events WHERE event_type = 'case.display_timezone'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!(action, "case.display_timezone");
        assert!(details.contains("old_timezone"));
        assert!(details.contains("UTC"));
        assert!(details.contains("new_timezone"));
        assert!(details.contains("Europe/Bucharest"));
        assert!(details.contains("canonical_timestamps"));

        // Reject invalid timezone
        let err = NativeWorkflowService::set_case_display_timezone(
            case_path.clone(),
            "Invalid/Fake_Zone".to_string(),
        );
        assert!(err.is_err());

        // Verify timezone was unchanged on failure
        let tz_after: String = conn.query_row(
            "SELECT timezone FROM case_options WHERE case_id = 1",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(tz_after, "Europe/Bucharest");
        Ok(())
    }

    #[test]
    fn evidence_intake_metadata_updates_and_audits() -> Result<()> {
        let workspace = TestWorkspace::new("intake-metadata-audit")?;
        let case_path = workspace.case_path();
        NativeWorkflowService::create_case(create_request(case_path.clone()))?;
        let file_path = workspace.root.join("intake_test.bin");
        fs::write(&file_path, b"intake test bytes")?;

        let attached = NativeWorkflowService::attach_evidence(AttachEvidenceRequest {
            case_path: case_path.clone(),
            evidence_path: file_path,
            kind: NativeEvidenceKind::File,
            read_file_system_requested: true,
            notes: None,
            display_timezone: Some("UTC".to_string()),
            display_name: Some("Initial Label".to_string()),
            integrity_status: Some("deferred".to_string()),
            expected_sha256: None,
            integrity_details_json: None,
        })?;
        assert_eq!(attached.evidence_id, 1);

        let page = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path: case_path.clone(),
            after_id: None,
            limit: Some(10),
            expected_generation: None,
        })?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].display_name, "Initial Label");
        assert_eq!(page.items[0].integrity_status.as_deref(), Some("deferred"));

        // Update metadata
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        NativeWorkflowService::update_evidence_intake_metadata(
            case_path.clone(),
            attached.evidence_id,
            Some("Updated Forensic Label".to_string()),
            Some("verified".to_string()),
            Some(expected.to_string()),
            Some(r#"{"status":"verified"}"#.to_string()),
        )?;

        let updated_page = NativeWorkflowService::list_evidence(EvidenceListRequest {
            case_path: case_path.clone(),
            after_id: None,
            limit: Some(10),
            expected_generation: None,
        })?;
        assert_eq!(updated_page.items[0].display_name, "Updated Forensic Label");
        assert_eq!(
            updated_page.items[0].integrity_status.as_deref(),
            Some("verified")
        );
        assert_eq!(
            updated_page.items[0].expected_sha256.as_deref(),
            Some(expected)
        );

        // Verify audit event: 1 from attach, 1 from update
        let conn = Connection::open(&case_path)?;
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM audit_events WHERE event_type = 'evidence.intake_metadata'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(count, 2);
        Ok(())
    }
}
