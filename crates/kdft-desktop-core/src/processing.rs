#![forbid(unsafe_code)]

//! Enhanced native processing configuration and multi-stage execution.
//!
//! Exposes real forensic processors with presets, per-volume inclusion,
//! truthful cancellation, and multi-stage progress reporting.

use crate::unlock::{TransientUnlockManager, BITLOCKER_LOCKED_FILESYSTEM};
use anyhow::{anyhow, bail, Context, Result};
use kdft_case::progress::{JobProgressState, JobProgressTracker};
use kdft_case::{
    list_image_volumes, parse_archive_artifacts, parse_document_artifacts,
    parse_embedded_mailboxes, parse_identity_artifacts,
    windows_artifacts::{
        parse_windows_artifacts_with_bitlocker_and_filter, parse_windows_artifacts_with_filter,
        WindowsArtifactFilter,
    },
    windows_registry_artifacts::{
        parse_windows_registry_artifacts, parse_windows_registry_artifacts_with_bitlocker,
    },
    ProcessEvidenceOptions, ProcessingProfile,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Formal processing job lifecycle and terminal states across core and UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessingJobState {
    Queued,
    Running,
    CancelRequested,
    Canceled,
    Complete,
    CompleteWithWarnings,
    Partial,
    Failed,
    Interrupted,
}

impl ProcessingJobState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::CancelRequested => "Cancel Requested",
            Self::Canceled => "Canceled",
            Self::Complete => "Complete",
            Self::CompleteWithWarnings => "Complete (with warnings)",
            Self::Partial => "Partial",
            Self::Failed => "Failed",
            Self::Interrupted => "Interrupted",
        }
    }

    pub fn from_status_str(status: &str) -> Self {
        match status.trim().to_lowercase().as_str() {
            "queued" => Self::Queued,
            "running" | "active" => Self::Running,
            "cancelrequested" | "cancel_requested" => Self::CancelRequested,
            "canceled" | "cancelled" => Self::Canceled,
            "complete" | "completed" | "success" => Self::Complete,
            "completewithwarnings"
            | "complete_with_warnings"
            | "completewithdiagnostics"
            | "complete_with_diagnostics" => Self::CompleteWithWarnings,
            "partial" | "truncated" => Self::Partial,
            "failed" | "error" => Self::Failed,
            "interrupted" => Self::Interrupted,
            _ => Self::Partial,
        }
    }
}

/// Persisted individual processor execution stage within a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorExecutionRecord {
    pub id: i64,
    pub job_id: i64,
    pub processor_name: String,
    pub stage_index: u32,
    pub status: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub items_discovered: usize,
    pub items_indexed: usize,
    pub diagnostics_json: Option<String>,
}

/// Persisted execution record of a processing job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingJobRecord {
    pub id: i64,
    pub evidence_id: i64,
    pub evidence_name: String,
    pub job_type: String,
    pub status: ProcessingJobState,
    pub raw_status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub stage_executions: Vec<ProcessorExecutionRecord>,
}

/// Verifiable coverage projection for each forensic processor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorCoverageRecord {
    pub group_name: String,
    pub scope: String,
    pub status: String,
    pub count: usize,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProcessingPreset {
    #[default]
    FullForensicAnalysis,
    IncidentResponseTriage,
    FilesystemMetadataOnly,
    Custom,
}

impl ProcessingPreset {
    pub fn label(&self) -> &'static str {
        match self {
            Self::FullForensicAnalysis => "Full forensic analysis",
            Self::IncidentResponseTriage => "Incident-response triage",
            Self::FilesystemMetadataOnly => "Filesystem metadata only",
            Self::Custom => "Custom",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullForensicAnalysis => "full_forensic",
            Self::IncidentResponseTriage => "ir_triage",
            Self::FilesystemMetadataOnly => "filesystem_metadata_only",
            Self::Custom => "custom",
        }
    }

    pub fn apply(&self, groups: &mut ProcessorGroupSelection) {
        match self {
            Self::FilesystemMetadataOnly => {
                groups.filesystem_metadata = true;
                groups.deleted_recovery_metadata = true;
                groups.windows_registry = false;
                groups.windows_event_logs = false;
                groups.browser_activity = false;
                groups.email = false;
                groups.lnk_jump_lists = false;
                groups.prefetch = false;
                groups.scheduled_tasks = false;
                groups.srum_network = false;
                groups.accounts_identity = false;
                groups.archives_containers = false;
                groups.office_documents = false;
                groups.sqlite_databases = false;
                groups.pictures_media = false;
                groups.hashing_content_capture = false;
            }
            Self::IncidentResponseTriage => {
                groups.filesystem_metadata = true;
                groups.deleted_recovery_metadata = true;
                groups.windows_registry = true;
                groups.windows_event_logs = true;
                groups.browser_activity = true;
                groups.email = false;
                groups.lnk_jump_lists = true;
                groups.prefetch = true;
                groups.scheduled_tasks = true;
                groups.srum_network = true;
                groups.accounts_identity = true;
                groups.archives_containers = false;
                groups.office_documents = false;
                groups.sqlite_databases = false;
                groups.pictures_media = false;
                groups.hashing_content_capture = false;
            }
            Self::FullForensicAnalysis => {
                groups.filesystem_metadata = true;
                groups.deleted_recovery_metadata = true;
                groups.windows_registry = true;
                groups.windows_event_logs = true;
                groups.browser_activity = true;
                groups.email = true;
                groups.lnk_jump_lists = true;
                groups.prefetch = true;
                groups.scheduled_tasks = true;
                groups.srum_network = true;
                groups.accounts_identity = true;
                groups.archives_containers = true;
                groups.office_documents = true;
                groups.sqlite_databases = true;
                groups.pictures_media = true;
                groups.hashing_content_capture = true;
            }
            Self::Custom => {}
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessorGroupSelection {
    pub filesystem_metadata: bool,
    pub deleted_recovery_metadata: bool,
    pub windows_registry: bool,
    pub windows_event_logs: bool,
    pub browser_activity: bool,
    pub email: bool,
    pub lnk_jump_lists: bool,
    pub prefetch: bool,
    pub scheduled_tasks: bool,
    pub srum_network: bool,
    pub accounts_identity: bool,
    pub archives_containers: bool,
    pub office_documents: bool,
    pub sqlite_databases: bool,
    pub pictures_media: bool,
    pub hashing_content_capture: bool,
}

impl Default for ProcessorGroupSelection {
    fn default() -> Self {
        let mut groups = Self {
            filesystem_metadata: true,
            deleted_recovery_metadata: true,
            windows_registry: true,
            windows_event_logs: true,
            browser_activity: true,
            email: true,
            lnk_jump_lists: true,
            prefetch: true,
            scheduled_tasks: true,
            srum_network: true,
            accounts_identity: true,
            archives_containers: true,
            office_documents: true,
            sqlite_databases: true,
            pictures_media: true,
            hashing_content_capture: true,
        };
        ProcessingPreset::FullForensicAnalysis.apply(&mut groups);
        groups
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInclusion {
    pub volume_index: usize,
    pub name: String,
    pub filesystem: String,
    pub start_offset: u64,
    pub size_bytes: u64,
    pub is_bitlocker: bool,
    #[serde(default)]
    pub unlocked_for_session: bool,
    pub included: bool,
}

impl VolumeInclusion {
    pub fn is_locked_bitlocker(&self) -> bool {
        self.is_bitlocker && !self.unlocked_for_session
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeAnalysisConfig {
    pub case_path: PathBuf,
    pub evidence_id: i64,
    pub evidence_path: String,
    pub source_kind: String,
    pub preset: ProcessingPreset,
    pub volumes: Vec<VolumeInclusion>,
    pub processors: ProcessorGroupSelection,
    /// 0 means unlimited
    pub max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct NativeAnalysisResult {
    pub job_id: i64,
    pub evidence_id: i64,
    pub entries_indexed: usize,
    pub truncated: bool,
    pub partial: bool,
    pub cancelled: bool,
    pub completed_with_diagnostics: bool,
    pub terminal_state: JobProgressState,
    pub stage_summaries: Vec<String>,
}

impl NativeAnalysisResult {
    pub fn into_summary(self) -> crate::ProcessEvidenceSummary {
        crate::ProcessEvidenceSummary {
            job_id: self.job_id,
            evidence_id: self.evidence_id,
            entries_indexed: self.entries_indexed,
            attempt_entries_indexed: self.entries_indexed,
            replacement_committed: true,
            canonical_generation_preserved: true,
            retained_entry_count: self.entries_indexed,
            truncated: self.truncated,
            partial_artifact_coverage: self.partial,
            completed_with_diagnostics: self.completed_with_diagnostics,
            status: format!("{:?}", self.terminal_state).to_lowercase(),
            bookmark_items_relinked: 0,
            truncation_reasons: Vec::new(),
            truncation_reasons_omitted: 0,
            case_generation: None,
            progress_summary_persisted: true,
            post_commit_warnings: self.stage_summaries,
            post_commit_warnings_omitted: 0,
        }
    }
}

impl From<NativeAnalysisResult> for crate::ProcessEvidenceSummary {
    fn from(r: NativeAnalysisResult) -> Self {
        r.into_summary()
    }
}

static ACTIVE_ANALYSIS_WORKERS: Mutex<Option<HashMap<(PathBuf, i64), i64>>> = Mutex::new(None);

fn active_analysis_workers_guard() -> MutexGuard<'static, Option<HashMap<(PathBuf, i64), i64>>> {
    // Preserve duplicate-job protection even if an earlier holder panicked. The
    // registry contains only process-local ownership markers, so retaining its
    // inner map is safer than silently treating every worker as absent.
    ACTIVE_ANALYSIS_WORKERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn active_worker_job_id(case_path: &Path, evidence_id: i64) -> Option<i64> {
    let canonical = std::fs::canonicalize(case_path).unwrap_or_else(|_| case_path.to_path_buf());
    let lock = active_analysis_workers_guard();
    lock.as_ref()
        .and_then(|map| map.get(&(canonical, evidence_id)).copied())
}

pub fn is_active_worker_registered(case_path: &Path, evidence_id: i64) -> bool {
    let canonical = std::fs::canonicalize(case_path).unwrap_or_else(|_| case_path.to_path_buf());
    let lock = active_analysis_workers_guard();
    if let Some(map) = lock.as_ref() {
        map.contains_key(&(canonical, evidence_id))
    } else {
        false
    }
}

pub fn register_active_worker(case_path: &Path, evidence_id: i64, job_id: i64) -> Result<()> {
    let canonical = std::fs::canonicalize(case_path).unwrap_or_else(|_| case_path.to_path_buf());
    let mut lock = active_analysis_workers_guard();
    let map = lock.get_or_insert_with(HashMap::new);
    if let Some(&existing) = map.get(&(canonical.clone(), evidence_id)) {
        bail!(
            "Evidence #{evidence_id} already has an active forensic analysis worker in this process (Job #{existing})"
        );
    }
    map.insert((canonical, evidence_id), job_id);
    Ok(())
}

pub fn unregister_active_worker(case_path: &Path, evidence_id: i64) {
    let canonical = std::fs::canonicalize(case_path).unwrap_or_else(|_| case_path.to_path_buf());
    let mut lock = active_analysis_workers_guard();
    if let Some(map) = lock.as_mut() {
        map.remove(&(canonical, evidence_id));
    }
}

/// Reserves one in-process analysis slot before any durable job rows are created.
/// This closes the commit-then-register race between concurrent Start requests.
struct ActiveWorkerReservation {
    case_path: PathBuf,
    evidence_id: i64,
    release_on_drop: bool,
}

impl ActiveWorkerReservation {
    fn acquire(case_path: &Path, evidence_id: i64) -> Result<Self> {
        let canonical =
            std::fs::canonicalize(case_path).unwrap_or_else(|_| case_path.to_path_buf());
        let mut lock = active_analysis_workers_guard();
        let map = lock.get_or_insert_with(HashMap::new);
        if let Some(&existing) = map.get(&(canonical.clone(), evidence_id)) {
            if existing > 0 {
                bail!(
                    "Evidence #{evidence_id} already has an active forensic analysis job (Job #{existing}) in progress"
                );
            }
            bail!("Evidence #{evidence_id} already has forensic analysis startup in progress");
        }
        // Zero is a private in-memory sentinel. It is never persisted.
        map.insert((canonical.clone(), evidence_id), 0);
        Ok(Self {
            case_path: canonical,
            evidence_id,
            release_on_drop: true,
        })
    }

    fn promote(&self, job_id: i64) -> Result<()> {
        let mut lock = active_analysis_workers_guard();
        let map = lock
            .as_mut()
            .ok_or_else(|| anyhow!("Active analysis reservation registry is unavailable"))?;
        let slot = map
            .get_mut(&(self.case_path.clone(), self.evidence_id))
            .ok_or_else(|| anyhow!("Active analysis reservation was lost before job creation"))?;
        if *slot != 0 {
            bail!(
                "Active analysis reservation was replaced by Job #{} before Job #{job_id} could start",
                *slot
            );
        }
        *slot = job_id;
        Ok(())
    }

    fn hand_off(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for ActiveWorkerReservation {
    fn drop(&mut self) {
        if self.release_on_drop {
            unregister_active_worker(&self.case_path, self.evidence_id);
        }
    }
}

/// Reconciles dangling 'running', 'active', or 'cancelrequested' jobs whose in-memory worker is no longer alive.
pub fn reconcile_orphaned_jobs_in_case(case_path: &Path) -> Result<usize> {
    let mut conn = kdft_case::open_existing_case(case_path)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    let mut stmt = tx.prepare(
        "SELECT id, evidence_id FROM evidence_jobs
         WHERE status IN ('running', 'active', 'cancelrequested')",
    )?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let mut count = 0;
    for (job_id, evidence_id) in rows {
        if !is_active_worker_registered(case_path, evidence_id) {
            tx.execute(
                "UPDATE evidence_jobs
                 SET status = 'interrupted',
                     finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP),
                     error = COALESCE(error, 'Job was interrupted by unexpected application restart')
                 WHERE id = ?1",
                [job_id],
            )?;
            tx.execute(
                "UPDATE processor_executions
                 SET status = 'interrupted',
                     completed_at = COALESCE(completed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                     diagnostics_json = json_object('interrupted', true, 'reason', 'Engine restarted while stage was running')
                 WHERE job_id = ?1 AND status = 'running'",
                [job_id],
            )?;
            tx.execute(
                "UPDATE processor_executions
                 SET status = 'not_started',
                     completed_at = COALESCE(completed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                     diagnostics_json = json_object('not_started', true, 'reason', 'Job ended before this queued stage began')
                 WHERE job_id = ?1 AND status = 'queued'",
                [job_id],
            )?;
            tx.execute(
                "UPDATE processing_plans
                 SET status = 'interrupted'
                 WHERE evidence_id = ?1 AND status IN ('running', 'active')",
                [evidence_id],
            )?;
            count += 1;
        }
    }
    tx.commit()?;
    Ok(count)
}

/// Centralized lifecycle coordinator guaranteeing truthful, durable terminal persistence.
pub struct JobLifecycleCoordinator {
    case_path: PathBuf,
    evidence_id: i64,
    master_job_id: i64,
    plan_id: i64,
    stage_executions: HashMap<String, i64>,
    current_running_stage: Option<String>,
    terminalized: bool,
}

impl JobLifecycleCoordinator {
    pub fn new(
        case_path: PathBuf,
        evidence_id: i64,
        master_job_id: i64,
        plan_id: i64,
        stage_executions: HashMap<String, i64>,
    ) -> Self {
        Self {
            case_path,
            evidence_id,
            master_job_id,
            plan_id,
            stage_executions,
            current_running_stage: None,
            terminalized: false,
        }
    }

    pub fn master_job_id(&self) -> i64 {
        self.master_job_id
    }

    pub fn plan_id(&self) -> i64 {
        self.plan_id
    }

    pub fn stage_execution_id(&self, processor_name: &str) -> Option<i64> {
        self.stage_executions.get(processor_name).copied()
    }

    pub fn start_stage(&mut self, processor_name: &str) -> Result<i64> {
        let exec_id = self
            .stage_executions
            .get(processor_name)
            .copied()
            .ok_or_else(|| {
                anyhow!("Processor '{processor_name}' was not recorded in the execution plan")
            })?;
        let conn = kdft_case::open_existing_case(&self.case_path)?;
        let rows = conn.execute(
            "UPDATE processor_executions
             SET status = 'running', started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND status = 'queued'",
            [exec_id],
        )?;
        if rows == 0 {
            bail!("Failed to transition processor '{processor_name}' (execution #{exec_id}) from queued to running");
        }
        self.current_running_stage = Some(processor_name.to_string());
        Ok(exec_id)
    }

    pub fn finish_stage(
        &mut self,
        processor_name: &str,
        status: &str,
        count: usize,
        diagnostics: &serde_json::Value,
    ) -> Result<()> {
        self.finish_stage_with_counts(processor_name, status, count, count, diagnostics)
    }

    pub fn finish_stage_with_counts(
        &mut self,
        processor_name: &str,
        status: &str,
        items_discovered: usize,
        terminal_items: usize,
        diagnostics: &serde_json::Value,
    ) -> Result<()> {
        // `partial` and `truncated` are job/result-level outcomes. The
        // processor_executions schema represents both as a successful stage
        // with explicit diagnostics, while the master job remains partial.
        let persisted_status = match status {
            "partial" | "truncated" => "completed_with_diagnostics",
            other => other,
        };
        let exec_id = self
            .stage_executions
            .get(processor_name)
            .copied()
            .ok_or_else(|| {
                anyhow!("Processor '{processor_name}' was not recorded in the execution plan")
            })?;
        let conn = kdft_case::open_existing_case(&self.case_path)?;
        kdft_case::update_processor_execution_status(
            &conn,
            exec_id,
            persisted_status,
            items_discovered,
            terminal_items,
            diagnostics,
        )?;
        if self.current_running_stage.as_deref() == Some(processor_name) {
            self.current_running_stage = None;
        }
        Ok(())
    }

    pub fn finalize(
        &mut self,
        terminal_state: JobProgressState,
        any_diagnostics: bool,
        original_error: Option<&anyhow::Error>,
    ) -> Result<String> {
        if self.terminalized {
            return Ok(String::new());
        }
        let mut conn = kdft_case::open_existing_case(&self.case_path)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let (master_status, plan_status) = if original_error.is_some() {
            ("failed", "failed")
        } else if terminal_state == JobProgressState::Cancelled {
            ("cancelled", "cancelled")
        } else if terminal_state == JobProgressState::Truncated {
            ("partial", "completed_with_diagnostics")
        } else if any_diagnostics || terminal_state == JobProgressState::CompleteWithDiagnostics {
            ("completed_with_diagnostics", "completed_with_diagnostics")
        } else {
            ("completed", "completed")
        };

        // Terminate any currently running stage
        if let Some(running_stage) = &self.current_running_stage {
            if let Some(&exec_id) = self.stage_executions.get(running_stage) {
                let stage_term_status = if original_error.is_some() {
                    "failed"
                } else if terminal_state == JobProgressState::Cancelled {
                    "cancelled"
                } else {
                    "completed_with_diagnostics"
                };
                let diag = if let Some(err) = original_error {
                    serde_json::json!({ "error": err.to_string(), "interrupted": true })
                } else {
                    serde_json::json!({ "interrupted": true })
                };
                let rows = tx.execute(
                    "UPDATE processor_executions
                     SET status = ?1, completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), diagnostics_json = ?2
                     WHERE id = ?3 AND status = 'running'",
                    rusqlite::params![stage_term_status, diag.to_string(), exec_id],
                )?;
                if rows != 1 {
                    bail!(
                        "running processor '{running_stage}' (execution #{exec_id}) could not be terminalized: expected one row, updated {rows}"
                    );
                }
            }
        }

        // Cancel / mark not_started any remaining queued stages
        let queued_status = if terminal_state == JobProgressState::Cancelled {
            "cancelled"
        } else {
            "not_started"
        };
        tx.execute(
            "UPDATE processor_executions
             SET status = ?1, completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), diagnostics_json = json_object('not_started', true)
             WHERE job_id = ?2 AND status = 'queued'",
            rusqlite::params![queued_status, self.master_job_id],
        )?;

        // Update processing_plans
        let plan_rows = tx.execute(
            "UPDATE processing_plans
             SET status = ?1
             WHERE plan_id = ?2",
            rusqlite::params![plan_status, self.plan_id],
        )?;
        if plan_rows != 1 {
            bail!(
                "processing plan #{} could not be terminalized: expected one row, updated {plan_rows}",
                self.plan_id
            );
        }

        // Update evidence_jobs
        let err_msg = original_error.map(|e| e.to_string());
        let job_rows = tx.execute(
            "UPDATE evidence_jobs
             SET status = ?1, finished_at = CURRENT_TIMESTAMP, error = ?2
             WHERE id = ?3",
            rusqlite::params![master_status, err_msg, self.master_job_id],
        )?;
        if job_rows != 1 {
            bail!(
                "master evidence job #{} could not be terminalized: expected one row, updated {job_rows}",
                self.master_job_id
            );
        }

        tx.commit()?;
        // Disarm the Drop recovery path only after the durable terminal
        // transaction has committed. If any statement or the commit fails,
        // Drop must still reconcile this job instead of leaving it active.
        self.terminalized = true;
        unregister_active_worker(&self.case_path, self.evidence_id);
        Ok(master_status.to_string())
    }
}

impl Drop for JobLifecycleCoordinator {
    fn drop(&mut self) {
        if !self.terminalized {
            if let Ok(mut conn) = kdft_case::open_existing_case(&self.case_path) {
                if let Ok(tx) =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                {
                    let _ = tx.execute(
                        "UPDATE processor_executions
                         SET status = 'interrupted', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                             diagnostics_json = json_object('interrupted', true, 'reason', 'Worker aborted unexpectedly')
                         WHERE job_id = ?1 AND status = 'running'",
                        [self.master_job_id],
                    );
                    let _ = tx.execute(
                        "UPDATE processor_executions
                         SET status = 'not_started', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                             diagnostics_json = json_object('not_started', true, 'reason', 'Job ended before this queued stage began')
                         WHERE job_id = ?1 AND status = 'queued'",
                        [self.master_job_id],
                    );
                    let _ = tx.execute(
                        "UPDATE processing_plans
                         SET status = 'interrupted'
                         WHERE plan_id = ?1",
                        [self.plan_id],
                    );
                    let _ = tx.execute(
                        "UPDATE evidence_jobs
                         SET status = 'interrupted', finished_at = CURRENT_TIMESTAMP,
                             error = 'Processing aborted unexpectedly before finalization'
                         WHERE id = ?1 AND status IN ('running', 'active')",
                        [self.master_job_id],
                    );
                    let _ = tx.commit();
                }
            }
            unregister_active_worker(&self.case_path, self.evidence_id);
        }
    }
}

pub struct NativeProcessingService;

impl NativeProcessingService {
    /// Inspects evidence partitions and initializes an analysis configuration.
    pub fn inspect_evidence(
        case_path: &Path,
        evidence_id: i64,
        unlock_mgr: Option<&TransientUnlockManager>,
    ) -> Result<NativeAnalysisConfig> {
        let conn = Connection::open(case_path)?;
        let (source_kind, source_path): (String, String) = conn
            .query_row(
                "SELECT source_kind, source_path FROM evidence_sources WHERE id = ?1",
                [evidence_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .with_context(|| format!("evidence {evidence_id} not found"))?;
        drop(conn);

        let mut volumes = Vec::new();
        if source_kind == "image" {
            if let Ok(vols) = list_image_volumes(Path::new(&source_path)) {
                for (idx, vol) in vols.into_iter().enumerate() {
                    let is_bitlocker = vol.bitlocker.is_some()
                        || vol.filesystem.to_lowercase().contains("bitlocker")
                        || vol.filesystem == BITLOCKER_LOCKED_FILESYSTEM;
                    let is_unlocked = unlock_mgr.is_some_and(|m| m.is_unlocked(evidence_id, idx));
                    volumes.push(VolumeInclusion {
                        volume_index: idx,
                        name: vol.name,
                        filesystem: vol.filesystem,
                        start_offset: vol.start_offset,
                        size_bytes: vol.size_bytes,
                        is_bitlocker,
                        unlocked_for_session: is_unlocked,
                        included: !is_bitlocker || is_unlocked,
                    });
                }
            }
        }

        Ok(NativeAnalysisConfig {
            case_path: case_path.to_path_buf(),
            evidence_id,
            evidence_path: source_path,
            source_kind,
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes,
            processors: ProcessorGroupSelection::default(),
            max_entries: 0, // 0 = unlimited
        })
    }

    fn parse_browser_activity_for_evidence(
        case_path: &Path,
        evidence_id: i64,
        dynamic_bitlocker: Option<(usize, &crate::unlock::TransientBitLockerCredential)>,
    ) -> Result<usize> {
        let candidates = kdft_case::find_browser_profile_candidates(case_path, evidence_id)?;
        if candidates.is_empty() {
            return Ok(0);
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_nanos())
            .unwrap_or(0);
        let temp_base = std::env::temp_dir().join(format!(
            "kdft-browser-staging-{}-{}",
            std::process::id(),
            unique
        ));
        let mut total_records = 0;
        for (idx, candidate) in candidates.iter().enumerate() {
            let staging_folder = temp_base.join(format!("profile-{}", idx));
            let _ = std::fs::create_dir_all(&staging_folder);
            let vol_idx = candidate.volume_index_zero_based.unwrap_or(0);
            let export_result = if let Some((bl_vol, cred)) = dynamic_bitlocker {
                if bl_vol == vol_idx {
                    let ctx = kdft_case::BitLockerProcessingContext {
                        volume_index: bl_vol,
                        credential: cred.as_case_credential(),
                    };
                    kdft_case::export_indexed_browser_profile_with_bitlocker(
                        case_path,
                        evidence_id,
                        &candidate.profile_path,
                        vol_idx,
                        &staging_folder,
                        ctx,
                    )
                } else {
                    kdft_case::export_indexed_browser_profile(
                        case_path,
                        evidence_id,
                        &candidate.profile_path,
                        Some(vol_idx),
                        &staging_folder,
                    )
                }
            } else {
                kdft_case::export_indexed_browser_profile(
                    case_path,
                    evidence_id,
                    &candidate.profile_path,
                    Some(vol_idx),
                    &staging_folder,
                )
            };

            if let Ok(files_exported) = export_result {
                if files_exported > 0 {
                    let import_opts = kdft_case::ImportBrowserArtifactsIntoEvidenceOptions {
                        evidence_id,
                        history_path: staging_folder.clone(),
                        max_visits: 0,
                        source_profile_path: candidate.profile_path.clone(),
                        volume_index_zero_based: Some(vol_idx),
                        legacy_evidence_name: None,
                    };
                    if let Ok(res) =
                        kdft_case::import_browser_artifacts_into_evidence(case_path, import_opts)
                    {
                        total_records += res.entries_indexed;
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&staging_folder);
        }
        let _ = std::fs::remove_dir_all(&temp_base);
        Ok(total_records)
    }

    /// Executes multi-stage forensic analysis.
    pub fn execute_analysis(
        config: &NativeAnalysisConfig,
        tracker: &JobProgressTracker,
        unlock_mgr: Option<&TransientUnlockManager>,
    ) -> Result<NativeAnalysisResult> {
        tracker.set_evidence_id(config.evidence_id);
        let mut stage_summaries = Vec::new();

        let selected_vols: Vec<_> = config.volumes.iter().filter(|v| v.included).collect();
        if config.source_kind == "image" && !config.volumes.is_empty() && selected_vols.is_empty() {
            bail!("No target volumes selected for image analysis");
        }

        // Restrict multiple BitLocker volumes in a single analysis run (Requirement 7)
        let bitlocker_targets: Vec<_> = selected_vols
            .iter()
            .filter(|v| {
                v.is_bitlocker
                    || v.filesystem.to_lowercase().contains("bitlocker")
                    || v.filesystem == BITLOCKER_LOCKED_FILESYSTEM
            })
            .collect();
        if bitlocker_targets.len() > 1 {
            bail!(
                "Multiple BitLocker target volumes were selected for a single analysis run (volumes: {:?}). To preserve credential isolation and forensic integrity, run analysis on one BitLocker volume per job.",
                bitlocker_targets.iter().map(|v| v.volume_index).collect::<Vec<_>>()
            );
        }

        // The transient unlock manager is the authority at execution time. The
        // configuration flag is only a UI snapshot and may be stale after a
        // relock, so it must never authorize processing by itself.
        for vol in &bitlocker_targets {
            let has_live_credential = unlock_mgr
                .and_then(|manager| manager.get_credential(config.evidence_id, vol.volume_index))
                .is_some();
            if !has_live_credential {
                bail!(
                    "Target volume #{} ({}) is BitLocker-encrypted and locked. Unlock the volume before starting analysis.",
                    vol.volume_index,
                    vol.name
                );
            }
        }

        let dynamic_bitlocker = selected_vols.iter().find_map(|v| {
            unlock_mgr.and_then(|m| {
                m.get_credential(config.evidence_id, v.volume_index)
                    .map(|c| (v.volume_index, c))
            })
        });

        let target_volumes: Vec<kdft_case::VolumeTarget> = selected_vols
            .iter()
            .map(|v| {
                let is_bitlocker = v.is_bitlocker
                    || v.filesystem.to_lowercase().contains("bitlocker")
                    || v.filesystem == BITLOCKER_LOCKED_FILESYSTEM;
                let is_unlocked = is_bitlocker
                    && unlock_mgr
                        .and_then(|manager| {
                            manager.get_credential(config.evidence_id, v.volume_index)
                        })
                        .is_some();
                kdft_case::VolumeTarget {
                    evidence_id: config.evidence_id,
                    discovered_volume_id: format!("vol-{}", v.volume_index),
                    partition_table_index: Some(v.volume_index as u32),
                    partition_start_offset: v.start_offset,
                    partition_length: v.size_bytes,
                    partition_type: None,
                    partition_guid: None,
                    filesystem_kind: Some(v.filesystem.clone()),
                    filesystem_label: Some(v.name.clone()),
                    encryption_kind: if is_bitlocker {
                        "bitlocker".to_string()
                    } else {
                        "none".to_string()
                    },
                    encryption_state: if is_bitlocker {
                        if is_unlocked {
                            "unlocked_for_session".to_string()
                        } else {
                            "locked".to_string()
                        }
                    } else {
                        "unencrypted".to_string()
                    },
                    unlocked_for_session: is_unlocked,
                    discovery_generation: 1,
                }
            })
            .collect();

        // Reserve ownership before opening the job-creation transaction. A
        // concurrent Start request must fail before either request can commit
        // a second running master row for the same evidence source.
        let mut worker_reservation =
            ActiveWorkerReservation::acquire(&config.case_path, config.evidence_id)?;

        // Create master forensic_analysis job record, plan, and all requested stage execution records in ONE immediate transaction.
        let (master_job_id, plan_id, stage_executions) = {
            let mut conn = kdft_case::open_existing_case(&config.case_path)?;
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let case_id = kdft_case::active_case_id(&tx)?;

            // 1. Prevent duplicate active jobs: atomically check for existing active jobs for this evidence source.
            let mut active_stmt = tx.prepare(
                "SELECT id, status FROM evidence_jobs
                 WHERE evidence_id = ?1 AND status IN ('running', 'active', 'cancelrequested')
                 ORDER BY id DESC",
            )?;
            let active_jobs: Vec<(i64, String)> = active_stmt
                .query_map([config.evidence_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(active_stmt);

            for (active_id, _st) in &active_jobs {
                if active_worker_job_id(&config.case_path, config.evidence_id)
                    .is_some_and(|job_id| job_id > 0)
                {
                    bail!(
                        "Evidence #{} already has an active forensic analysis job (Job #{active_id}) in progress",
                        config.evidence_id
                    );
                }
            }

            // If there are orphaned active jobs without an active worker in this process, reconcile them immediately.
            if !active_jobs.is_empty() {
                tx.execute(
                    "UPDATE evidence_jobs
                     SET status = 'interrupted',
                         finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP),
                         error = COALESCE(error, 'Job was interrupted by unexpected application restart')
                     WHERE evidence_id = ?1 AND status IN ('running', 'active', 'cancelrequested')",
                    [config.evidence_id],
                )?;
                tx.execute(
                    "UPDATE processor_executions
                     SET status = 'interrupted',
                         completed_at = COALESCE(completed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                         diagnostics_json = json_object('interrupted', true, 'reason', 'Engine restarted while stage was running')
                     WHERE job_id IN (SELECT id FROM evidence_jobs WHERE evidence_id = ?1) AND status = 'running'",
                    [config.evidence_id],
                )?;
                tx.execute(
                    "UPDATE processor_executions
                     SET status = 'not_started',
                         completed_at = COALESCE(completed_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                         diagnostics_json = json_object('not_started', true, 'reason', 'Job ended before this queued stage began')
                     WHERE job_id IN (SELECT id FROM evidence_jobs WHERE evidence_id = ?1) AND status = 'queued'",
                    [config.evidence_id],
                )?;
            }

            // 2. Insert master evidence_jobs row in 'running' status.
            let job_id: i64 = tx.query_row(
                "INSERT INTO evidence_jobs (case_id, evidence_id, job_type, status, started_at)
                 VALUES (?1, ?2, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)
                 RETURNING id",
                rusqlite::params![case_id, config.evidence_id],
                |row| row.get(0),
            )?;

            // 3. Insert processing_plans row in 'running' status.
            let target_summary = serde_json::json!({
                "target_count": target_volumes.len(),
                "targets": target_volumes,
            });
            let requested_processors = serde_json::to_value(&config.processors).unwrap_or_default();
            let plan_id: i64 = tx.query_row(
                "INSERT INTO processing_plans (
                     case_id, evidence_id, plan_type, preset_name, status,
                     target_summary_json, requested_processors_json
                 ) VALUES (?1, ?2, 'forensic_analysis', ?3, 'running', ?4, ?5)
                 RETURNING plan_id",
                rusqlite::params![
                    case_id,
                    config.evidence_id,
                    config.preset.as_str(),
                    target_summary.to_string(),
                    requested_processors.to_string(),
                ],
                |row| row.get(0),
            )?;

            // 4. Record execution rows for all requested stages in 'queued' status.
            let mut requested_stages: Vec<(&'static str, usize)> = Vec::new();
            requested_stages.push(("filesystem_inventory", 1));
            if config.processors.windows_registry {
                requested_stages.push(("windows_registry", 2));
            }
            if config.processors.windows_event_logs
                || config.processors.lnk_jump_lists
                || config.processors.prefetch
                || config.processors.srum_network
                || config.processors.scheduled_tasks
            {
                requested_stages.push(("windows_artifacts", 3));
            }
            if config.processors.browser_activity {
                requested_stages.push(("browser_activity", 4));
            }
            if config.processors.accounts_identity {
                requested_stages.push(("accounts_identity", 5));
            }
            if config.processors.office_documents {
                requested_stages.push(("documents", 6));
            }
            if config.processors.archives_containers {
                requested_stages.push(("archives", 7));
            }
            if config.processors.email {
                requested_stages.push(("email", 8));
            }

            let mut stage_map = HashMap::new();
            for (proc_name, stage_idx) in requested_stages {
                let exec_id: i64 = tx.query_row(
                    "INSERT INTO processor_executions (
                         job_id, processor_name, stage_index, status,
                         items_discovered, items_indexed, diagnostics_json, completed_at
                     ) VALUES (?1, ?2, ?3, 'queued', 0, 0, json_object('queued', true), NULL)
                     RETURNING id",
                    rusqlite::params![job_id, proc_name, stage_idx as i64],
                    |row| row.get(0),
                )?;
                stage_map.insert(proc_name.to_string(), exec_id);
            }

            tx.commit()?;
            (job_id, plan_id, stage_map)
        };

        tracker.set_job_id(master_job_id);
        let mut coordinator = JobLifecycleCoordinator::new(
            config.case_path.clone(),
            config.evidence_id,
            master_job_id,
            plan_id,
            stage_executions,
        );
        // If promotion ever fails, coordinator Drop terminalizes the durable
        // rows and reservation Drop releases the startup slot.
        worker_reservation.promote(master_job_id)?;
        worker_reservation.hand_off();

        // Wrap the entire multi-stage analysis pipeline in with_job_progress so
        // all downstream parsers and worker pools share the active job tracker.
        let pipeline_res = kdft_case::progress::with_job_progress(
            tracker,
            || -> Result<NativeAnalysisResult> {
                // Stage 1: Filesystem Walk
                coordinator.start_stage("filesystem_inventory")?;
                tracker.start_stage(
                    if config.processors.hashing_content_capture {
                        "Filesystem inventory and content capture"
                    } else {
                        "Filesystem metadata inventory"
                    },
                    1,
                    Some(8),
                    "entries",
                    if config.max_entries > 0 {
                        Some(config.max_entries as u64)
                    } else {
                        None
                    },
                );

                let profile = ProcessingProfile {
                    capture_content: config.processors.hashing_content_capture,
                    parse_emails: config.processors.email,
                    parse_browsers: config.processors.browser_activity,
                };

                let bitlocker_ctx = dynamic_bitlocker.as_ref().map(|(vol_idx, cred)| {
                    kdft_case::BitLockerProcessingContext {
                        volume_index: *vol_idx,
                        credential: cred.as_case_credential(),
                    }
                });

                tracker.set_auto_advance_database_entries(true);
                let job_ctx = kdft_case::ForensicJobContext {
                    existing_job_id: Some(master_job_id),
                    retain_job_running: true,
                };
                let base_res = kdft_case::process_evidence_with_targets_and_job_context(
                    &config.case_path,
                    ProcessEvidenceOptions {
                        evidence_id: config.evidence_id,
                        max_entries: config.max_entries,
                    },
                    profile,
                    bitlocker_ctx,
                    if target_volumes.is_empty() {
                        None
                    } else {
                        Some(&target_volumes)
                    },
                    Some(job_ctx),
                );
                tracker.set_auto_advance_database_entries(false);

                let base_res = match base_res {
                    Ok(r) => {
                        let diag = serde_json::json!({
                            "truncated": r.truncated,
                            "partial": r.partial_artifact_coverage,
                        });
                        coordinator.finish_stage(
                            "filesystem_inventory",
                            &r.status,
                            r.entries_indexed,
                            &diag,
                        )?;
                        r
                    }
                    Err(e) => {
                        tracker.record_error(None);
                        tracker.finish(JobProgressState::Failed);
                        let orig_err = e.context("Stage 1 filesystem processing failed");
                        if let Err(fin_err) =
                            coordinator.finalize(JobProgressState::Failed, true, Some(&orig_err))
                        {
                            return Err(anyhow!(
                                "{orig_err}; secondary persistence failure: {fin_err}"
                            ));
                        }
                        return Err(orig_err);
                    }
                };

                let is_cancelled =
                    base_res.status == "cancelled" || tracker.is_cancellation_requested();
                let is_truncated = base_res.truncated;

                stage_summaries.push(format!(
                    "Filesystem inventory: {} entries indexed (status: {})",
                    base_res.entries_indexed, base_res.status
                ));

                if is_cancelled || is_truncated {
                    let terminal = if is_cancelled {
                        JobProgressState::Cancelled
                    } else {
                        JobProgressState::Truncated
                    };
                    tracker.finish(terminal);
                    coordinator.finalize(terminal, false, None)?;
                    return Ok(NativeAnalysisResult {
                        job_id: master_job_id,
                        evidence_id: config.evidence_id,
                        entries_indexed: base_res.entries_indexed,
                        truncated: is_truncated,
                        partial: true,
                        cancelled: is_cancelled,
                        completed_with_diagnostics: false,
                        terminal_state: terminal,
                        stage_summaries,
                    });
                }

                let mut any_stage_diagnostics =
                    base_res.completed_with_diagnostics || base_res.partial_artifact_coverage;
                let mut any_stage_failed = false;

                // Stage 2: Windows Registry & SRUM
                if (config.processors.windows_registry || config.processors.srum_network)
                    && !tracker.is_cancellation_requested()
                {
                    coordinator.start_stage("windows_registry")?;
                    tracker.start_stage(
                        "Windows Registry & SRUM System Resource Usage",
                        2,
                        Some(8),
                        "hives",
                        None,
                    );
                    let reg_res = if let Some((vol_idx, ref cred)) = dynamic_bitlocker {
                        let ctx = kdft_case::BitLockerProcessingContext {
                            volume_index: vol_idx,
                            credential: cred.as_case_credential(),
                        };
                        parse_windows_registry_artifacts_with_bitlocker(
                            &config.case_path,
                            config.evidence_id,
                            ctx,
                        )
                    } else {
                        parse_windows_registry_artifacts(&config.case_path, config.evidence_id)
                    };
                    let (status, discovered, terminal, diag) = match reg_res {
                        Ok(res) => {
                            stage_summaries.push(format!(
                                "Registry & SRUM: {} hives parsed, {} values indexed (status: {})",
                                res.hives_parsed, res.generic_values_indexed, res.status
                            ));
                            let stage_status = if res.status == "cancelled" {
                                "cancelled"
                            } else if res.hives_parsed == 0 && res.status == "failed" {
                                any_stage_failed = true;
                                "failed"
                            } else if res.partial_artifact_coverage || res.status == "partial" {
                                any_stage_diagnostics = true;
                                "partial"
                            } else if res.status == "truncated"
                                || res.status == "completed_with_diagnostics"
                            {
                                any_stage_diagnostics = true;
                                "completed_with_diagnostics"
                            } else {
                                "completed"
                            };
                            (
                                stage_status,
                                res.discovered_sources(),
                                res.terminal_sources(),
                                serde_json::json!({
                                    "derived_registry_values": res.generic_values_indexed,
                                    "sources_discovered": res.discovered_sources(),
                                    "terminal_sources": res.terminal_sources(),
                                    "hives_found": res.hives_found,
                                    "hives_parsed": res.hives_parsed,
                                    "hives_failed": res.hives_failed,
                                    "hives_cancelled": res.hives_cancelled,
                                    "srum_sources_seen": res.srum_sources_seen,
                                    "srum_sources_validated": res.srum_sources_validated,
                                    "srum_sources_failed": res.srum_sources_failed,
                                    "srum_sources_cancelled": res.srum_sources_cancelled,
                                    "status": res.status,
                                    "partial_artifact_coverage": res.partial_artifact_coverage,
                                }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            stage_summaries.push(format!("Registry & SRUM note: {e}"));
                            (
                                "failed",
                                0,
                                0,
                                serde_json::json!({ "error": e.to_string() }),
                            )
                        }
                    };
                    coordinator.finish_stage_with_counts(
                        "windows_registry",
                        status,
                        discovered,
                        terminal,
                        &diag,
                    )?;
                }

                // Stage 3: Windows Artifacts (Event logs, LNK, Prefetch, Tasks)
                if (config.processors.windows_event_logs
                    || config.processors.lnk_jump_lists
                    || config.processors.prefetch
                    || config.processors.scheduled_tasks)
                    && !tracker.is_cancellation_requested()
                {
                    coordinator.start_stage("windows_artifacts")?;
                    tracker.start_stage(
                        "Windows Artifacts & Event Logs",
                        3,
                        Some(8),
                        "artifacts",
                        None,
                    );
                    let filter = WindowsArtifactFilter {
                        lnk_jump_lists: config.processors.lnk_jump_lists,
                        prefetch: config.processors.prefetch,
                        windows_event_logs: config.processors.windows_event_logs,
                        scheduled_tasks: config.processors.scheduled_tasks,
                    };
                    let win_res = if let Some((vol_idx, ref cred)) = dynamic_bitlocker {
                        let ctx = kdft_case::BitLockerProcessingContext {
                            volume_index: vol_idx,
                            credential: cred.as_case_credential(),
                        };
                        parse_windows_artifacts_with_bitlocker_and_filter(
                            &config.case_path,
                            config.evidence_id,
                            ctx,
                            filter,
                        )
                    } else {
                        parse_windows_artifacts_with_filter(
                            &config.case_path,
                            config.evidence_id,
                            filter,
                        )
                    };
                    let (status, discovered, terminal, diag) = match win_res {
                        Ok(res) => {
                            stage_summaries.push(format!(
                                "Windows artifacts: {} derived entries",
                                res.derived_entries
                            ));
                            let stage_stat = if res.status == "cancelled" {
                                "cancelled"
                            } else if res.status == "failed"
                                || (res.parsed_sources == 0 && res.failed_sources > 0)
                            {
                                any_stage_failed = true;
                                "failed"
                            } else if res.failed_sources > 0
                                || res.partial_sources > 0
                                || res.reused_partial_sources > 0
                            {
                                any_stage_diagnostics = true;
                                "partial"
                            } else if res.status == "truncated"
                                || !res.supported_scope_complete
                                || res.diagnostic_count > 0
                            {
                                any_stage_diagnostics = true;
                                "completed_with_diagnostics"
                            } else {
                                "completed"
                            };
                            (
                                stage_stat,
                                res.supported_source_count as usize,
                                (res.up_to_date_sources_skipped
                                    + res.parsed_sources
                                    + res.failed_sources
                                    + res.cancelled_sources)
                                    as usize,
                                serde_json::json!({
                                    "derived_entries": res.derived_entries,
                                    "sources_discovered": res.supported_source_count,
                                    "terminal_sources": res.up_to_date_sources_skipped + res.parsed_sources + res.failed_sources + res.cancelled_sources,
                                    "up_to_date_sources": res.up_to_date_sources_skipped,
                                    "parsed_sources": res.parsed_sources,
                                    "failed_sources": res.failed_sources,
                                    "cancelled_sources": res.cancelled_sources,
                                    "partial_sources": res.partial_sources,
                                    "status": res.status,
                                }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            stage_summaries.push(format!("Windows artifacts note: {e}"));
                            (
                                "failed",
                                0,
                                0,
                                serde_json::json!({ "error": e.to_string() }),
                            )
                        }
                    };
                    coordinator.finish_stage_with_counts(
                        "windows_artifacts",
                        status,
                        discovered,
                        terminal,
                        &diag,
                    )?;
                }

                // Stage 4: Web Browser Activity
                if config.processors.browser_activity && !tracker.is_cancellation_requested() {
                    coordinator.start_stage("browser_activity")?;
                    tracker.start_stage("Web Browser Activity", 4, Some(8), "profiles", None);
                    let b_res = Self::parse_browser_activity_for_evidence(
                        &config.case_path,
                        config.evidence_id,
                        dynamic_bitlocker.as_ref().map(|(v, c)| (*v, c)),
                    );
                    let (status, count, diag) = match b_res {
                        Ok(records_count) => {
                            stage_summaries
                                .push(format!("Browser: {records_count} activity records indexed"));
                            (
                                "completed",
                                records_count,
                                serde_json::json!({ "records_indexed": records_count }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            stage_summaries.push(format!("Browser note: {e}"));
                            ("failed", 0, serde_json::json!({ "error": e.to_string() }))
                        }
                    };
                    coordinator.finish_stage("browser_activity", status, count, &diag)?;
                }

                // Stage 5: Accounts and Identity
                if config.processors.accounts_identity && !tracker.is_cancellation_requested() {
                    coordinator.start_stage("accounts_identity")?;
                    tracker.start_stage("Accounts and Identity", 5, Some(8), "accounts", None);
                    let id_res = parse_identity_artifacts(&config.case_path, config.evidence_id);
                    let (status, count, diag) = match id_res {
                        Ok(res) => {
                            stage_summaries.push(format!(
                                "Identity: {} local accounts, {} profiles",
                                res.local_accounts_indexed, res.user_profiles_indexed
                            ));
                            (
                                "completed",
                                res.local_accounts_indexed + res.user_profiles_indexed,
                                serde_json::json!({
                                    "local_accounts": res.local_accounts_indexed,
                                    "user_profiles": res.user_profiles_indexed,
                                }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            ("failed", 0, serde_json::json!({ "error": e.to_string() }))
                        }
                    };
                    coordinator.finish_stage("accounts_identity", status, count, &diag)?;
                }

                // Stage 6: Documents and Office
                if config.processors.office_documents && !tracker.is_cancellation_requested() {
                    coordinator.start_stage("documents")?;
                    tracker.start_stage(
                        "Office & Document Metadata",
                        6,
                        Some(8),
                        "documents",
                        None,
                    );
                    let doc_res = parse_document_artifacts(&config.case_path, config.evidence_id);
                    let (status, count, diag) = match doc_res {
                        Ok(res) => {
                            stage_summaries.push(format!(
                                "Documents: {} parsed, {} segments",
                                res.documents_parsed, res.segments_indexed
                            ));
                            (
                                "completed",
                                res.segments_indexed,
                                serde_json::json!({
                                    "documents_parsed": res.documents_parsed,
                                    "segments_indexed": res.segments_indexed,
                                }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            ("failed", 0, serde_json::json!({ "error": e.to_string() }))
                        }
                    };
                    coordinator.finish_stage("documents", status, count, &diag)?;
                }

                // Stage 7: Archives and Containers
                if config.processors.archives_containers && !tracker.is_cancellation_requested() {
                    coordinator.start_stage("archives")?;
                    tracker.start_stage("Archives and Containers", 7, Some(8), "archives", None);
                    let arc_res = parse_archive_artifacts(&config.case_path, config.evidence_id);
                    let (status, count, diag) = match arc_res {
                        Ok(res) => {
                            stage_summaries
                                .push(format!("Archives: {} members indexed", res.members_indexed));
                            (
                                "completed",
                                res.members_indexed,
                                serde_json::json!({ "members_indexed": res.members_indexed }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            ("failed", 0, serde_json::json!({ "error": e.to_string() }))
                        }
                    };
                    coordinator.finish_stage("archives", status, count, &diag)?;
                }

                // Stage 8: Embedded Mailboxes
                if config.processors.email && !tracker.is_cancellation_requested() {
                    coordinator.start_stage("email")?;
                    tracker.start_stage("Embedded Mailboxes", 8, Some(8), "mailboxes", None);
                    let eml_res =
                        parse_embedded_mailboxes(&config.case_path, config.evidence_id, 0);
                    let (status, count, diag) = match eml_res {
                        Ok(res) => {
                            stage_summaries.push(format!(
                                "Mailboxes: {} entries indexed",
                                res.entries_indexed
                            ));
                            (
                                "completed",
                                res.entries_indexed,
                                serde_json::json!({ "entries_indexed": res.entries_indexed }),
                            )
                        }
                        Err(e) => {
                            any_stage_failed = true;
                            ("failed", 0, serde_json::json!({ "error": e.to_string() }))
                        }
                    };
                    coordinator.finish_stage("email", status, count, &diag)?;
                }

                let terminal = if tracker.is_cancellation_requested() {
                    JobProgressState::Cancelled
                } else if any_stage_failed {
                    if base_res.entries_indexed == 0 && stage_summaries.len() <= 1 {
                        JobProgressState::Failed
                    } else {
                        JobProgressState::Truncated
                    }
                } else if any_stage_diagnostics {
                    JobProgressState::CompleteWithDiagnostics
                } else {
                    JobProgressState::Complete
                };

                tracker.finish(terminal);
                coordinator.finalize(terminal, any_stage_diagnostics, None)?;

                Ok(NativeAnalysisResult {
                    job_id: master_job_id,
                    evidence_id: config.evidence_id,
                    entries_indexed: base_res.entries_indexed,
                    truncated: false,
                    partial: terminal != JobProgressState::Complete,
                    cancelled: tracker.is_cancellation_requested(),
                    completed_with_diagnostics: base_res.completed_with_diagnostics
                        || any_stage_diagnostics,
                    terminal_state: terminal,
                    stage_summaries,
                })
            },
        );

        match pipeline_res {
            Ok(res) => Ok(res),
            Err(err) => {
                tracker.finish(JobProgressState::Failed);
                if let Err(fin_err) =
                    coordinator.finalize(JobProgressState::Failed, true, Some(&err))
                {
                    return Err(anyhow!(
                        "{err}; secondary lifecycle persistence failure: {fin_err}"
                    ));
                }
                Err(err)
            }
        }
    }

    /// Lists recorded processor execution stages for a specific job from `processor_executions`.
    pub fn list_processor_executions_for_job(
        conn: &rusqlite::Connection,
        job_id: i64,
    ) -> Result<Vec<ProcessorExecutionRecord>> {
        let mut stmt = match conn.prepare(
            "SELECT id, job_id, processor_name, stage_index, status, started_at, completed_at, items_discovered, items_indexed, diagnostics_json
             FROM processor_executions
             WHERE job_id = ?1
             ORDER BY stage_index ASC, id ASC",
        ) {
            Ok(stmt) => stmt,
            Err(_) => return Ok(Vec::new()),
        };
        let rows = stmt.query_map([job_id], |row| {
            let id: i64 = row.get(0)?;
            let job_id: i64 = row.get(1)?;
            let processor_name: String = row.get(2)?;
            let stage_index: u32 = row.get(3)?;
            let status: String = row.get(4)?;
            let started_at: Option<String> = row.get(5)?;
            let completed_at: Option<String> = row.get(6)?;
            let items_discovered: usize =
                row.get::<_, i64>(7).map(|v| v.max(0) as usize).unwrap_or(0);
            let items_indexed: usize = row.get::<_, i64>(8).map(|v| v.max(0) as usize).unwrap_or(0);
            let diagnostics_json: Option<String> = row.get(9)?;
            Ok(ProcessorExecutionRecord {
                id,
                job_id,
                processor_name,
                stage_index,
                status,
                started_at,
                completed_at,
                items_discovered,
                items_indexed,
                diagnostics_json,
            })
        })?;
        let mut list = Vec::new();
        for entry in rows.flatten() {
            list.push(entry);
        }
        Ok(list)
    }

    /// Lists persisted processing jobs from the case SQLite database.
    pub fn list_jobs(case_path: &Path) -> Result<Vec<ProcessingJobRecord>> {
        let conn = rusqlite::Connection::open(case_path)?;
        let mut stmt = conn.prepare(
            "SELECT j.id, j.evidence_id, COALESCE(e.display_name, 'Evidence #' || j.evidence_id),
                    j.job_type, j.status, j.started_at, j.finished_at, j.error
             FROM evidence_jobs j
             LEFT JOIN evidence_sources e ON e.id = j.evidence_id
             ORDER BY j.id DESC
             LIMIT 50",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let evidence_id: i64 = row.get(1)?;
            let evidence_name: String = row.get(2)?;
            let job_type: String = row.get(3)?;
            let raw_status: String = row.get(4)?;
            let started_at: Option<String> = row.get(5)?;
            let finished_at: Option<String> = row.get(6)?;
            let error: Option<String> = row.get(7)?;
            let status = ProcessingJobState::from_status_str(&raw_status);
            Ok(ProcessingJobRecord {
                id,
                evidence_id,
                evidence_name,
                job_type,
                status,
                raw_status,
                started_at,
                finished_at,
                error,
                stage_executions: Vec::new(),
            })
        })?;
        let mut records = Vec::new();
        for mut rec in rows.flatten() {
            rec.stage_executions =
                Self::list_processor_executions_for_job(&conn, rec.id).unwrap_or_default();
            records.push(rec);
        }
        Ok(records)
    }

    /// Reconciles dangling active/running jobs and stages left by an abrupt process termination.
    pub fn reconcile_orphaned_jobs_in_case(case_path: &Path) -> Result<usize> {
        // Keep the desktop entry point and the public free function on one
        // implementation. The shared implementation checks the in-process
        // worker registry before classifying a durable running row as an
        // orphan; bypassing that check can interrupt a live job when a case
        // view is refreshed or reopened in the same application process.
        reconcile_orphaned_jobs_in_case(case_path)
    }

    /// Evaluates verifiable coverage records for all artifact processors based on database contents.
    pub fn get_coverage_records(
        case_path: &Path,
        evidence_id: Option<i64>,
    ) -> Result<Vec<ProcessorCoverageRecord>> {
        let conn = rusqlite::Connection::open(case_path)?;
        let mut records = Vec::new();

        // Check whether processor_executions exists
        let has_proc_execs = conn
            .prepare("SELECT 1 FROM processor_executions LIMIT 0")
            .is_ok();
        let mut execution_map: std::collections::HashMap<String, (String, usize, usize)> =
            std::collections::HashMap::new();
        if has_proc_execs {
            let mut stmt = conn.prepare(
                "SELECT processor_name, status, items_indexed, items_discovered
                 FROM processor_executions
                 WHERE (?1 IS NULL OR job_id IN (SELECT id FROM evidence_jobs WHERE evidence_id = ?1))
                 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map([evidence_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2).map(|v| v.max(0) as usize).unwrap_or(0),
                    row.get::<_, i64>(3).map(|v| v.max(0) as usize).unwrap_or(0),
                ))
            })?;
            for (name, status, indexed, disc) in rows.flatten() {
                execution_map.insert(name, (status, indexed, disc));
            }
        }

        let has_cat_col = conn
            .prepare("SELECT category_main FROM filesystem_entries LIMIT 0")
            .is_ok();
        let cat_col = if has_cat_col {
            "category_main"
        } else {
            "COALESCE(json_extract(metadata_json, '$.category_main'), '')"
        };

        // Helper to resolve processor coverage status
        let resolve_coverage = |group_name: &str,
                                scope: &str,
                                proc_key: Option<&str>,
                                row_count: usize|
         -> ProcessorCoverageRecord {
            if let Some(key) = proc_key {
                let exec_entry = execution_map.get(key).or_else(|| {
                    if key == "filesystem_walk" {
                        execution_map.get("filesystem_inventory")
                    } else {
                        None
                    }
                });
                if let Some((status, indexed, disc)) = exec_entry {
                    let (disp_status, msg) = match status.as_str() {
                        "completed" => (
                            "Complete".to_string(),
                            Some(format!(
                                "Execution complete: {indexed} of {disc} candidate sources reached a terminal outcome; {row_count} output rows are available."
                            )),
                        ),
                        "completed_with_diagnostics" => (
                            "Complete (with warnings)".to_string(),
                            Some(format!(
                                "Execution completed with diagnostics: {indexed} of {disc} candidate sources reached a terminal outcome; {row_count} output rows are available."
                            )),
                        ),
                        "partial" => (
                            "Partial".to_string(),
                            Some("Processor stopped or was truncated before finishing all candidates.".to_string()),
                        ),
                        "canceled" | "cancelled" => (
                            "Canceled".to_string(),
                            Some("Processor execution was canceled by examiner.".to_string()),
                        ),
                        "failed" => (
                            "Failed".to_string(),
                            Some("Processor reported a terminal failure.".to_string()),
                        ),
                        "running" => (
                            "Active".to_string(),
                            Some(format!(
                                "Processor is executing: {indexed} of {disc} candidate sources are terminal; {row_count} output rows are currently available."
                            )),
                        ),
                        "queued" => (
                            "Queued".to_string(),
                            Some(format!(
                                "Processor has not started; {row_count} output rows from earlier executions remain available."
                            )),
                        ),
                        "not_started" => (
                            "Not started".to_string(),
                            Some(format!(
                                "Processor did not start; {row_count} output rows from earlier executions remain available."
                            )),
                        ),
                        "interrupted" => (
                            "Interrupted".to_string(),
                            Some("Processor was interrupted before finishing.".to_string()),
                        ),
                        other => (other.to_string(), None),
                    };
                    return ProcessorCoverageRecord {
                        group_name: group_name.to_string(),
                        scope: scope.to_string(),
                        status: disp_status,
                        count: row_count,
                        message: msg,
                    };
                }
            }
            ProcessorCoverageRecord {
                group_name: group_name.to_string(),
                scope: scope.to_string(),
                status: projected_output_status(row_count),
                count: row_count,
                message: projected_output_message(row_count),
            }
        };

        let fs_count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM filesystem_entries WHERE (?1 IS NULL OR evidence_id = ?1)",
                [evidence_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Filesystem & NTFS Metadata",
            "All allocated and indexed files",
            Some("filesystem_walk"),
            fs_count,
        ));

        let del_count: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM filesystem_entries WHERE is_deleted = 1 AND (?1 IS NULL OR evidence_id = ?1)",
                [evidence_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Deleted & Recovery Records",
            "Carved and flagged deleted MFT entries",
            Some("filesystem_walk"),
            del_count,
        ));

        let reg_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} = 'Registry' OR COALESCE(json_extract(metadata_json, '$.windows_registry_derived'), 0) = 1) AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let reg_count: usize = conn
            .query_row(&reg_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Windows Registry",
            "System, SAM, Software, NTUSER hives",
            Some("windows_registry"),
            reg_count,
        ));

        let evtx_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} = 'Event Logs' OR logical_path LIKE '%.evtx') AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let evtx_count: usize = conn
            .query_row(&evtx_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Windows Event Logs",
            "Winevt/Logs EVTX records",
            Some("windows_artifacts"),
            evtx_count,
        ));

        let web_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} = 'Web Activity' OR {cat_col} = 'Browser' OR COALESCE(json_extract(metadata_json, '$.artifact_kind'), '') LIKE 'browser_%') AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let web_count: usize = conn
            .query_row(&web_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Web Browsers",
            "Chrome, Edge, Firefox history & cache",
            Some("browser_activity"),
            web_count,
        ));

        let pf_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} LIKE '%Execution%' OR logical_path LIKE '%.pf' OR COALESCE(json_extract(metadata_json, '$.artifact_kind'), '') = 'windows_prefetch') AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let pf_count: usize = conn
            .query_row(&pf_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Prefetch & Execution",
            "Windows Prefetch (*.pf)",
            Some("windows_artifacts"),
            pf_count,
        ));

        let lnk_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} LIKE '%LNK%' OR logical_path LIKE '%.lnk' OR logical_path LIKE '%.automaticDestinations-ms') AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let lnk_count: usize = conn
            .query_row(&lnk_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "LNK & Jump Lists",
            "Shell shortcuts and AutomaticDestinations",
            Some("windows_artifacts"),
            lnk_count,
        ));

        let doc_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} = 'Documents') AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let doc_count: usize = conn
            .query_row(&doc_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Documents & Office",
            "Office, PDF, text documents",
            Some("documents"),
            doc_count,
        ));

        let id_sql = format!(
            "SELECT COUNT(*) FROM filesystem_entries WHERE ({cat_col} = 'Accounts & Identity' OR COALESCE(json_extract(metadata_json, '$.artifact_kind'), '') = 'local_account') AND (?1 IS NULL OR evidence_id = ?1)"
        );
        let id_count: usize = conn
            .query_row(&id_sql, [evidence_id], |r| r.get(0))
            .unwrap_or(0);
        records.push(resolve_coverage(
            "Accounts & Identity",
            "User profiles, security identifiers",
            Some("accounts_identity"),
            id_count,
        ));

        records.push(ProcessorCoverageRecord {
            group_name: "SQLite Databases".to_string(),
            scope: "Arbitrary SQLite schema recovery".to_string(),
            status: "Unsupported".to_string(),
            count: 0,
            message: Some("SQLite database parser is not implemented in this build.".to_string()),
        });

        records.push(ProcessorCoverageRecord {
            group_name: "Pictures & Media Metadata".to_string(),
            scope: "EXIF and media stream analysis".to_string(),
            status: "Unsupported".to_string(),
            count: 0,
            message: Some(
                "Picture/media metadata parser is not implemented in this build.".to_string(),
            ),
        });

        Ok(records)
    }
}

fn projected_output_status(count: usize) -> String {
    if count == 0 {
        "Not run".to_string()
    } else {
        "Not proven".to_string()
    }
}

fn projected_output_message(count: usize) -> Option<String> {
    (count > 0).then(|| {
        "Rows are present in the case database, but row presence alone does not prove that the requested processor completed its full candidate scope. A terminal parser execution or coverage record is required."
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_configure_processor_groups_truthfully() {
        let mut groups = ProcessorGroupSelection::default();
        ProcessingPreset::FilesystemMetadataOnly.apply(&mut groups);
        assert!(groups.filesystem_metadata);
        assert!(!groups.windows_registry);
        assert!(!groups.hashing_content_capture);

        ProcessingPreset::FullForensicAnalysis.apply(&mut groups);
        assert!(groups.filesystem_metadata);
        assert!(groups.windows_registry);
        assert!(groups.hashing_content_capture);
    }

    #[test]
    fn output_rows_alone_never_claim_complete_processor_coverage() {
        let unique = format!(
            "kdft-coverage-projection-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let conn = rusqlite::Connection::open(&case_path).expect("create coverage fixture");
        conn.execute_batch(
            "CREATE TABLE filesystem_entries(
                 id INTEGER PRIMARY KEY,
                 evidence_id INTEGER NOT NULL,
                 logical_path TEXT NOT NULL,
                 category_main TEXT,
                 is_deleted INTEGER NOT NULL DEFAULT 0
             );
             INSERT INTO filesystem_entries(
                 id, evidence_id, logical_path, category_main, is_deleted
             ) VALUES
                 (1, 7, '/Windows/System32/config/SYSTEM', 'Registry', 0),
                 (2, 7, '/Windows/Prefetch/EXAMPLE.PF', 'Execution', 0),
                 (3, 7, '/Recovery/deleted.bin', 'Recovery', 1);",
        )
        .expect("populate coverage fixture");
        drop(conn);

        let records = NativeProcessingService::get_coverage_records(&case_path, Some(7))
            .expect("read coverage projection");
        assert!(records.iter().all(|record| record.status != "Complete"));
        assert!(records
            .iter()
            .filter(|record| record.count > 0)
            .all(|record| record.status == "Not proven"));
        assert!(records
            .iter()
            .filter(|record| record.count > 0)
            .all(|record| record
                .message
                .as_deref()
                .is_some_and(|message| { message.contains("row presence alone does not prove") })));

        std::fs::remove_file(case_path).expect("remove coverage fixture");
    }

    #[test]
    fn locked_bitlocker_volume_analysis_fails_closed_before_execution() {
        let unique = format!(
            "kdft-locked-bitlocker-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let tracker = JobProgressTracker::new("test-locked", "analysis", None);
        let unlock_mgr = TransientUnlockManager::default();

        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id: 42,
            evidence_path: "C:/mock/image.E01".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![
                VolumeInclusion {
                    volume_index: 0,
                    name: "EFI".to_string(),
                    filesystem: "FAT32".to_string(),
                    start_offset: 1048576,
                    size_bytes: 104857600,
                    is_bitlocker: false,
                    unlocked_for_session: false,
                    included: false,
                },
                VolumeInclusion {
                    volume_index: 2,
                    name: "Windows".to_string(),
                    filesystem: BITLOCKER_LOCKED_FILESYSTEM.to_string(),
                    start_offset: 209715200,
                    size_bytes: 200000000000,
                    is_bitlocker: true,
                    unlocked_for_session: false,
                    included: true,
                },
            ],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let result =
            NativeProcessingService::execute_analysis(&config, &tracker, Some(&unlock_mgr));
        assert!(
            result.is_err(),
            "analysis of a locked bitlocker volume must fail closed"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("BitLocker-encrypted and locked"),
            "expected locked error, got: {err_msg}"
        );
    }

    #[test]
    fn unlocked_session_bitlocker_target_passes_backend_preflight() {
        let unique = format!(
            "kdft-unlocked-bitlocker-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let tracker = JobProgressTracker::new("test-unlocked", "analysis", None);
        let unlock_mgr = TransientUnlockManager::default();
        unlock_mgr.store_unverified_session(
            42,
            2,
            "BitLocker".to_string(),
            crate::unlock::TransientBitLockerCredential::password("test-only-password".to_string()),
        );

        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id: 42,
            evidence_path: "C:/mock/image.E01".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![VolumeInclusion {
                volume_index: 2,
                name: "Windows OS".to_string(),
                filesystem: "BitLocker".to_string(),
                start_offset: 209715200,
                size_bytes: 200000000000,
                is_bitlocker: true,
                unlocked_for_session: true,
                included: true,
            }],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        // When execute_analysis runs, it MUST pass the BitLocker preflight check.
        // Because the mock case database does not exist on disk, it will proceed past preflight
        // and fail on database opening, NOT on "BitLocker-encrypted and locked".
        let result =
            NativeProcessingService::execute_analysis(&config, &tracker, Some(&unlock_mgr));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            !err_msg.contains("BitLocker-encrypted and locked"),
            "Unlocked BitLocker volume MUST pass preflight, but got locked error: {err_msg}"
        );
    }

    #[test]
    fn stale_unlocked_snapshot_cannot_bypass_backend_preflight() {
        let unique = format!(
            "kdft-stale-unlocked-bitlocker-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let tracker = JobProgressTracker::new("test-stale-unlocked", "analysis", None);
        let unlock_mgr = TransientUnlockManager::default();

        let config = NativeAnalysisConfig {
            case_path,
            evidence_id: 42,
            evidence_path: "C:/mock/image.E01".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![VolumeInclusion {
                volume_index: 2,
                name: "Windows OS".to_string(),
                filesystem: "BitLocker".to_string(),
                start_offset: 209715200,
                size_bytes: 200000000000,
                is_bitlocker: true,
                // This was true when the dialog was opened, but the live
                // manager no longer has a session (for example after relock).
                unlocked_for_session: true,
                included: true,
            }],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let error = NativeProcessingService::execute_analysis(&config, &tracker, Some(&unlock_mgr))
            .expect_err("a stale UI unlock snapshot must fail closed");
        assert!(error.to_string().contains("BitLocker-encrypted and locked"));
    }

    #[test]
    fn multiple_bitlocker_volumes_fail_closed_with_restriction() {
        let unique = format!(
            "kdft-multi-bitlocker-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let tracker = JobProgressTracker::new("test-multi-bl", "analysis", None);
        let unlock_mgr = TransientUnlockManager::default();

        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id: 42,
            evidence_path: "C:/mock/image.E01".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![
                VolumeInclusion {
                    volume_index: 2,
                    name: "Windows C:".to_string(),
                    filesystem: "BitLocker".to_string(),
                    start_offset: 209715200,
                    size_bytes: 100000000000,
                    is_bitlocker: true,
                    unlocked_for_session: true,
                    included: true,
                },
                VolumeInclusion {
                    volume_index: 3,
                    name: "Data D:".to_string(),
                    filesystem: "BitLocker".to_string(),
                    start_offset: 309715200,
                    size_bytes: 100000000000,
                    is_bitlocker: true,
                    unlocked_for_session: true,
                    included: true,
                },
            ],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let result =
            NativeProcessingService::execute_analysis(&config, &tracker, Some(&unlock_mgr));
        assert!(
            result.is_err(),
            "multiple BitLocker volumes in single job must fail closed"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Multiple BitLocker target volumes were selected"),
            "expected multi-bitlocker restriction error, got: {err_msg}"
        );
    }

    #[test]
    fn unselected_volumes_are_rejected_when_empty() {
        let unique = format!(
            "kdft-empty-targets-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let tracker = JobProgressTracker::new("test-empty", "analysis", None);
        let unlock_mgr = TransientUnlockManager::default();

        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id: 42,
            evidence_path: "C:/mock/image.E01".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![VolumeInclusion {
                volume_index: 0,
                name: "EFI".to_string(),
                filesystem: "FAT32".to_string(),
                start_offset: 1048576,
                size_bytes: 104857600,
                is_bitlocker: false,
                unlocked_for_session: false,
                included: false,
            }],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let result =
            NativeProcessingService::execute_analysis(&config, &tracker, Some(&unlock_mgr));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No target volumes selected"));
    }

    #[test]
    fn processing_pipeline_tables_persist_plans_and_processor_executions() {
        let unique = format!(
            "kdft-pipeline-schema-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let _case_id = kdft_case::create_case(
            &case_path,
            kdft_case::CreateCaseOptions {
                name: "Pipeline Test Case".to_string(),
                examiner_name: Some("Examiner".to_string()),
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
        .expect("create test case");

        let conn = rusqlite::Connection::open(&case_path).expect("open test case");

        // Verify tables exist
        let plan_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM processing_plans", [], |r| r.get(0))
            .expect("query processing_plans");
        assert_eq!(plan_count, 0);

        let target_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM processing_job_targets", [], |r| {
                r.get(0)
            })
            .expect("query processing_job_targets");
        assert_eq!(target_count, 0);

        let exec_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM processor_executions", [], |r| {
                r.get(0)
            })
            .expect("query processor_executions");
        assert_eq!(exec_count, 0);

        // Insert mock evidence source and job for foreign key validity
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, display_name, source_kind, source_path)
             VALUES (10, 1, 'Test Evidence', 'file', 'C:/mock/test.txt')",
            [],
        )
        .expect("insert mock evidence source");

        conn.execute(
            "INSERT INTO evidence_jobs(id, case_id, evidence_id, job_type, status, parameters_json)
             VALUES (50, 1, 10, 'analysis', 'running', '{}')",
            [],
        )
        .expect("insert mock job");

        // Test inserting plan
        let plan_id = kdft_case::record_processing_plan(
            &conn,
            1,
            10,
            "forensic_analysis",
            "full_forensic",
            &serde_json::json!({"targets": [2]}),
            &serde_json::json!({"windows_registry": true}),
        )
        .expect("record plan");
        assert!(plan_id > 0);

        kdft_case::update_processing_plan_status(&conn, plan_id, "completed")
            .expect("update plan status");

        let status: String = conn
            .query_row(
                "SELECT status FROM processing_plans WHERE plan_id = ?1",
                [plan_id],
                |r| r.get(0),
            )
            .expect("query status");
        assert_eq!(status, "completed");

        let exec_id = kdft_case::record_processor_execution(
            &conn,
            50,
            "windows_registry",
            2,
            "completed",
            12,
            12,
            &serde_json::json!({"hives": 2}),
        )
        .expect("record processor execution");
        assert!(exec_id > 0);

        let exec_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM processor_executions WHERE job_id = 50",
                [],
                |r| r.get(0),
            )
            .expect("query processor_executions count");
        assert_eq!(exec_count, 1);

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn get_coverage_records_and_list_jobs_reflect_processor_executions() {
        let unique = format!(
            "kdft-coverage-execs-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let _case_id = kdft_case::create_case(
            &case_path,
            kdft_case::CreateCaseOptions {
                name: "Coverage Exec Case".to_string(),
                examiner_name: Some("Examiner".to_string()),
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
        .expect("create test case");

        let conn = rusqlite::Connection::open(&case_path).expect("open test case");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, display_name, source_kind, source_path)
             VALUES (10, 1, 'Target Disk', 'image', 'C:/mock/image.E01')",
            [],
        )
        .expect("insert mock evidence source");

        conn.execute(
            "INSERT INTO evidence_jobs(id, case_id, evidence_id, job_type, status, parameters_json)
             VALUES (50, 1, 10, 'analysis', 'complete', '{}')",
            [],
        )
        .expect("insert mock job");

        kdft_case::record_processor_execution(
            &conn,
            50,
            "windows_registry",
            2,
            "completed",
            42,
            42,
            &serde_json::json!({"hives": 3}),
        )
        .expect("record windows_registry execution");

        kdft_case::record_processor_execution(
            &conn,
            50,
            "browser_activity",
            4,
            "completed",
            128,
            128,
            &serde_json::json!({"profiles": 1}),
        )
        .expect("record browser_activity execution");

        drop(conn);

        let cov = NativeProcessingService::get_coverage_records(&case_path, Some(10))
            .expect("get coverage records");
        let reg_cov = cov
            .iter()
            .find(|c| c.group_name == "Windows Registry")
            .expect("reg cov");
        assert_eq!(reg_cov.status, "Complete");
        assert_eq!(reg_cov.count, 0);
        assert!(reg_cov
            .message
            .as_deref()
            .is_some_and(|message| message.contains("42 of 42 candidate sources")
                && message.contains("0 output rows")));

        let web_cov = cov
            .iter()
            .find(|c| c.group_name == "Web Browsers")
            .expect("web cov");
        assert_eq!(web_cov.status, "Complete");
        assert_eq!(web_cov.count, 0);

        let jobs = NativeProcessingService::list_jobs(&case_path).expect("list jobs");
        assert_eq!(jobs.len(), 1);
        let job = &jobs[0];
        assert_eq!(job.id, 50);
        assert_eq!(job.stage_executions.len(), 2);
        assert_eq!(job.stage_executions[0].processor_name, "windows_registry");
        assert_eq!(job.stage_executions[0].items_indexed, 42);
        assert_eq!(job.stage_executions[1].processor_name, "browser_activity");
        assert_eq!(job.stage_executions[1].items_indexed, 128);

        let _ = std::fs::remove_file(case_path);
    }

    fn create_test_case_and_evidence(prefix: &str) -> (PathBuf, i64) {
        let unique = format!(
            "kdft-{prefix}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let case_path = std::env::temp_dir().join(unique);
        let _ = kdft_case::create_case(
            &case_path,
            kdft_case::CreateCaseOptions {
                name: format!("Case {prefix}"),
                examiner_name: Some("Examiner".to_string()),
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
        .expect("create test case");

        let conn = rusqlite::Connection::open(&case_path).expect("open test case");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, display_name, source_kind, source_path)
             VALUES (10, 1, 'Mock Evidence', 'image', 'C:/mock/synthetic.raw')",
            [],
        )
        .expect("insert mock evidence");
        (case_path, 10)
    }

    #[test]
    fn test_g_atomic_job_start_failure_rolls_back() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-g");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "CREATE TRIGGER abort_plan_insert BEFORE INSERT ON processing_plans
             BEGIN
                 SELECT RAISE(ABORT, 'injected atomic plan failure');
             END;",
            [],
        )
        .expect("install failure trigger");
        drop(conn);

        let tracker = JobProgressTracker::new("test-g", "analysis", None);
        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id,
            evidence_path: "C:/mock/synthetic.raw".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![VolumeInclusion {
                volume_index: 0,
                name: "OS".to_string(),
                filesystem: "NTFS".to_string(),
                start_offset: 1048576,
                size_bytes: 100000000,
                is_bitlocker: false,
                unlocked_for_session: false,
                included: true,
            }],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let result = NativeProcessingService::execute_analysis(&config, &tracker, None);
        assert!(
            result.is_err(),
            "job start must fail when plan insertion fails"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("injected atomic plan failure"),
            "expected injected error, got: {err_msg}"
        );

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        let running_jobs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM evidence_jobs WHERE status = 'running'",
                [],
                |r| r.get(0),
            )
            .expect("query running jobs");
        assert_eq!(
            running_jobs, 0,
            "no master job row must remain in running status"
        );

        let total_jobs: i64 = conn
            .query_row("SELECT COUNT(*) FROM evidence_jobs", [], |r| r.get(0))
            .expect("query total jobs");
        assert_eq!(
            total_jobs, 0,
            "master job row must be rolled back completely"
        );

        let total_plans: i64 = conn
            .query_row("SELECT COUNT(*) FROM processing_plans", [], |r| r.get(0))
            .expect("query total plans");
        assert_eq!(total_plans, 0, "plans table must have 0 rows");

        let total_execs: i64 = conn
            .query_row("SELECT COUNT(*) FROM processor_executions", [], |r| {
                r.get(0)
            })
            .expect("query total executions");
        assert_eq!(total_execs, 0, "executions table must have 0 rows");

        assert!(!is_active_worker_registered(&case_path, evidence_id));

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_h_stage_execution_persistence_failure() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-h");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (100, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (200, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        ).expect("insert plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (300, 100, 'windows_registry', 2, 'running', 0, 0, '{}', NULL)",
            [],
        ).expect("insert stage");

        conn.execute(
            "CREATE TRIGGER fail_exec_update BEFORE UPDATE ON processor_executions
             BEGIN
                 SELECT RAISE(ABORT, 'injected disk write failure on processor_executions');
             END;",
            [],
        )
        .expect("create trigger");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 100).expect("register worker");

        let mut stage_map = HashMap::new();
        stage_map.insert("windows_registry".to_string(), 300);
        let mut coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 100, 200, stage_map);

        let finish_res =
            coordinator.finish_stage("windows_registry", "completed", 50, &serde_json::json!({}));
        assert!(
            finish_res.is_err(),
            "persistence failure must be returned as Err"
        );

        drop(coordinator);

        assert!(!is_active_worker_registered(&case_path, evidence_id));

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        let job_status: String = conn
            .query_row("SELECT status FROM evidence_jobs WHERE id = 100", [], |r| {
                r.get(0)
            })
            .expect("query status");
        assert_eq!(
            job_status, "interrupted",
            "master job must transition to terminal interrupted status on unhandled drop"
        );

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_h2_failed_finalize_keeps_drop_recovery_armed() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-h2");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (110, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (210, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        )
        .expect("insert plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (310, 110, 'windows_registry', 2, 'queued', 0, 0, '{}', NULL)",
            [],
        )
        .expect("insert stage");
        conn.execute(
            "CREATE TRIGGER fail_plan_finalize BEFORE UPDATE ON processing_plans
             BEGIN
                 SELECT RAISE(ABORT, 'injected plan finalization failure');
             END;",
            [],
        )
        .expect("create failure trigger");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 110).expect("register worker");
        let mut stage_map = HashMap::new();
        stage_map.insert("windows_registry".to_string(), 310);
        let mut coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 110, 210, stage_map);
        coordinator
            .start_stage("windows_registry")
            .expect("start stage");

        let finalize_result = coordinator.finalize(JobProgressState::Complete, false, None);
        assert!(
            finalize_result.is_err(),
            "injected finalization write failure must be returned"
        );
        assert!(
            is_active_worker_registered(&case_path, evidence_id),
            "failed finalization must keep ownership registered until recovery"
        );

        let conn = rusqlite::Connection::open(&case_path).expect("reopen case");
        conn.execute("DROP TRIGGER fail_plan_finalize", [])
            .expect("remove injected failure before Drop recovery");
        drop(conn);

        drop(coordinator);

        assert!(
            !is_active_worker_registered(&case_path, evidence_id),
            "Drop recovery must release worker ownership"
        );
        let conn = rusqlite::Connection::open(&case_path).expect("inspect recovered case");
        let job_status: String = conn
            .query_row("SELECT status FROM evidence_jobs WHERE id = 110", [], |r| {
                r.get(0)
            })
            .expect("query recovered job");
        assert_eq!(job_status, "interrupted");
        let stage_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 310",
                [],
                |r| r.get(0),
            )
            .expect("query recovered stage");
        assert_eq!(stage_status, "interrupted");

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_h3_missing_execution_row_is_a_persistence_failure() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-h3");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (120, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (220, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        )
        .expect("insert plan");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 120).expect("register worker");
        let mut stage_map = HashMap::new();
        stage_map.insert("windows_registry".to_string(), 999_999);
        let mut coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 120, 220, stage_map);

        let finish_result =
            coordinator.finish_stage("windows_registry", "completed", 1, &serde_json::json!({}));
        assert!(
            finish_result.is_err(),
            "an update that matched no execution row must fail closed"
        );

        drop(coordinator);
        let conn = rusqlite::Connection::open(&case_path).expect("inspect recovered case");
        let job_status: String = conn
            .query_row("SELECT status FROM evidence_jobs WHERE id = 120", [], |r| {
                r.get(0)
            })
            .expect("query recovered job");
        assert_eq!(job_status, "interrupted");

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_h4_missing_plan_row_prevents_false_terminal_success() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-h4");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (130, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 130).expect("register worker");
        let mut coordinator = JobLifecycleCoordinator::new(
            case_path.clone(),
            evidence_id,
            130,
            999_999,
            HashMap::new(),
        );

        let finalize_result = coordinator.finalize(JobProgressState::Complete, false, None);
        assert!(
            finalize_result.is_err(),
            "a missing processing plan must not be reported as durable completion"
        );
        assert!(
            is_active_worker_registered(&case_path, evidence_id),
            "failed finalization must keep Drop recovery armed"
        );

        drop(coordinator);
        let conn = rusqlite::Connection::open(&case_path).expect("inspect recovered case");
        let job_status: String = conn
            .query_row("SELECT status FROM evidence_jobs WHERE id = 130", [], |r| {
                r.get(0)
            })
            .expect("query recovered job");
        assert_eq!(job_status, "interrupted");

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_i_stage_1_failure_with_and_without_execution_row() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-i");
        let tracker = JobProgressTracker::new("test-i", "analysis", None);
        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id,
            evidence_path: "C:/mock/nonexistent_image_12345.raw".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![VolumeInclusion {
                volume_index: 0,
                name: "OS".to_string(),
                filesystem: "NTFS".to_string(),
                start_offset: 1048576,
                size_bytes: 100000000,
                is_bitlocker: false,
                unlocked_for_session: false,
                included: true,
            }],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let result = NativeProcessingService::execute_analysis(&config, &tracker, None);
        assert!(
            result.is_err(),
            "analysis must fail when stage 1 filesystem walk fails"
        );

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        let (master_status, master_err, finished_at): (String, Option<String>, Option<String>) =
            conn.query_row(
                "SELECT status, error, finished_at FROM evidence_jobs ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("query master job");
        assert_eq!(
            master_status, "failed",
            "master job must terminate as 'failed'"
        );
        assert!(master_err.is_some_and(|e| e.contains("Stage 1 filesystem processing failed")));
        assert!(
            finished_at.is_some(),
            "master job must have finished_at timestamp"
        );

        let stage1_status: String = conn.query_row(
            "SELECT status FROM processor_executions WHERE processor_name = 'filesystem_inventory'",
            [],
            |r| r.get(0),
        ).expect("query stage 1");
        assert_eq!(stage1_status, "failed");

        let queued_remain: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM processor_executions WHERE status = 'queued'",
                [],
                |r| r.get(0),
            )
            .expect("query queued count");
        assert_eq!(queued_remain, 0, "no queued stages may remain");

        let not_started_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM processor_executions WHERE status = 'not_started'",
                [],
                |r| r.get(0),
            )
            .expect("query not_started count");
        assert!(
            not_started_count > 0,
            "subsequent stages must be marked 'not_started'"
        );

        assert!(!is_active_worker_registered(&case_path, evidence_id));

        let mut empty_coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 999, 888, HashMap::new());
        let start_res = empty_coordinator.start_stage("filesystem_inventory");
        assert!(
            start_res.is_err(),
            "starting unrecorded stage must return Err"
        );
        assert!(start_res
            .unwrap_err()
            .to_string()
            .contains("was not recorded in the execution plan"));

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_j_later_stage_partial_failure() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-j");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (500, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (600, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        ).expect("insert plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (701, 500, 'filesystem_inventory', 1, 'queued', 0, 0, '{}', NULL),
                    (702, 500, 'windows_registry', 2, 'queued', 0, 0, '{}', NULL)",
            [],
        ).expect("insert stages");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 500).expect("register worker");

        let mut stage_map = HashMap::new();
        stage_map.insert("filesystem_inventory".to_string(), 701);
        stage_map.insert("windows_registry".to_string(), 702);
        let mut coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 500, 600, stage_map);

        coordinator
            .start_stage("filesystem_inventory")
            .expect("start stage 1");
        coordinator
            .finish_stage(
                "filesystem_inventory",
                "completed",
                1000,
                &serde_json::json!({}),
            )
            .expect("finish stage 1");

        coordinator
            .start_stage("windows_registry")
            .expect("start stage 2");
        let diag = serde_json::json!({ "error": "corrupt SYSTEM hive header", "partial": true });
        coordinator
            .finish_stage("windows_registry", "completed_with_diagnostics", 15, &diag)
            .expect("finish stage 2");

        let status = coordinator
            .finalize(JobProgressState::CompleteWithDiagnostics, true, None)
            .expect("finalize");
        assert_eq!(status, "completed_with_diagnostics");

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        let (master_status, plan_status): (String, String) = conn.query_row(
            "SELECT j.status, p.status FROM evidence_jobs j JOIN processing_plans p ON p.plan_id = 600 WHERE j.id = 500",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).expect("query statuses");

        assert_eq!(
            master_status, "completed_with_diagnostics",
            "master must be completed_with_diagnostics, NEVER completed"
        );
        assert_eq!(
            plan_status, "completed_with_diagnostics",
            "plan must be completed_with_diagnostics, NEVER completed"
        );

        conn.execute(
            "UPDATE evidence_jobs SET status = 'running' WHERE id = 500",
            [],
        )
        .expect("reset");
        let mut coordinator_trunc =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 500, 600, HashMap::new());
        let trunc_status = coordinator_trunc
            .finalize(JobProgressState::Truncated, false, None)
            .expect("finalize trunc");
        assert_eq!(trunc_status, "partial");
        let job_status: String = conn
            .query_row("SELECT status FROM evidence_jobs WHERE id = 500", [], |r| {
                r.get(0)
            })
            .expect("query");
        assert_eq!(job_status, "partial");

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn stage_execution_persists_discovered_and_terminal_counts_separately() {
        let (case_path, evidence_id) = create_test_case_and_evidence("stage-source-counts");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (750, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (751, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        )
        .expect("insert plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (752, 750, 'windows_artifacts', 3, 'queued', 0, 0, '{}', NULL)",
            [],
        )
        .expect("insert execution");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 750).expect("register worker");
        let mut stage_map = HashMap::new();
        stage_map.insert("windows_artifacts".to_string(), 752);
        let mut coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 750, 751, stage_map);
        coordinator
            .start_stage("windows_artifacts")
            .expect("start stage");
        coordinator
            .finish_stage_with_counts(
                "windows_artifacts",
                "partial",
                959,
                122,
                &serde_json::json!({"sources_discovered": 959, "terminal_sources": 122}),
            )
            .expect("finish stage");

        let conn = rusqlite::Connection::open(&case_path).expect("reopen case");
        let persisted: (String, i64, i64) = conn
            .query_row(
                "SELECT status, items_discovered, items_indexed FROM processor_executions WHERE id = 752",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read source counts");
        assert_eq!(
            persisted,
            ("completed_with_diagnostics".to_string(), 959, 122)
        );
        drop(conn);

        coordinator
            .finalize(JobProgressState::Truncated, true, None)
            .expect("finalize job");
        drop(coordinator);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_k_cancellation_matrix() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-k");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (800, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (900, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        ).expect("insert plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (951, 800, 'filesystem_inventory', 1, 'queued', 0, 0, '{}', NULL),
                    (952, 800, 'windows_registry', 2, 'queued', 0, 0, '{}', NULL),
                    (953, 800, 'windows_artifacts', 3, 'queued', 0, 0, '{}', NULL)",
            [],
        ).expect("insert stages");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 800).expect("register worker");

        let mut stage_map = HashMap::new();
        stage_map.insert("filesystem_inventory".to_string(), 951);
        stage_map.insert("windows_registry".to_string(), 952);
        stage_map.insert("windows_artifacts".to_string(), 953);
        let mut coordinator =
            JobLifecycleCoordinator::new(case_path.clone(), evidence_id, 800, 900, stage_map);

        coordinator
            .start_stage("filesystem_inventory")
            .expect("start stage 1");
        coordinator
            .finish_stage(
                "filesystem_inventory",
                "completed",
                500,
                &serde_json::json!({}),
            )
            .expect("finish stage 1");

        coordinator
            .start_stage("windows_registry")
            .expect("start stage 2");

        let cancel_res = coordinator
            .finalize(JobProgressState::Cancelled, false, None)
            .expect("finalize cancel");
        assert_eq!(cancel_res, "cancelled");

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        let (job_status, plan_status): (String, String) = conn.query_row(
            "SELECT j.status, p.status FROM evidence_jobs j JOIN processing_plans p ON p.plan_id = 900 WHERE j.id = 800",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).expect("query status");
        assert_eq!(job_status, "cancelled");
        assert_eq!(plan_status, "cancelled");

        let stage2_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 952",
                [],
                |r| r.get(0),
            )
            .expect("query stage 2");
        assert_eq!(stage2_status, "cancelled");

        let stage3_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 953",
                [],
                |r| r.get(0),
            )
            .expect("query stage 3");
        assert_eq!(stage3_status, "cancelled");

        let non_terminal_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM processor_executions WHERE job_id = 800 AND status IN ('running', 'queued')",
            [],
            |r| r.get(0),
        ).expect("query non-terminal count");
        assert_eq!(
            non_terminal_count, 0,
            "cancellation must leave zero running or queued processor execution records"
        );

        assert!(!is_active_worker_registered(&case_path, evidence_id));

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_l_duplicate_start_prevention() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-l");
        register_active_worker(&case_path, evidence_id, 777).expect("register active worker");
        assert!(is_active_worker_registered(&case_path, evidence_id));

        let dup_reg = register_active_worker(&case_path, evidence_id, 778);
        assert!(
            dup_reg.is_err(),
            "concurrent registration for same evidence must fail"
        );
        assert!(dup_reg
            .unwrap_err()
            .to_string()
            .contains("already has an active forensic analysis worker"));

        let tracker = JobProgressTracker::new("test-l", "analysis", None);
        let config = NativeAnalysisConfig {
            case_path: case_path.clone(),
            evidence_id,
            evidence_path: "C:/mock/synthetic.raw".to_string(),
            source_kind: "image".to_string(),
            preset: ProcessingPreset::FullForensicAnalysis,
            volumes: vec![VolumeInclusion {
                volume_index: 0,
                name: "OS".to_string(),
                filesystem: "NTFS".to_string(),
                start_offset: 1048576,
                size_bytes: 100000000,
                is_bitlocker: false,
                unlocked_for_session: false,
                included: true,
            }],
            processors: ProcessorGroupSelection::default(),
            max_entries: 0,
        };

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (777, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert job");
        drop(conn);

        let exec_res = NativeProcessingService::execute_analysis(&config, &tracker, None);
        assert!(
            exec_res.is_err(),
            "execute_analysis must reject duplicate active job"
        );
        let msg = exec_res.unwrap_err().to_string();
        assert!(msg.contains("already has an active forensic analysis job"));

        unregister_active_worker(&case_path, evidence_id);
        assert!(!is_active_worker_registered(&case_path, evidence_id));

        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_l2_startup_reservation_closes_commit_then_register_race() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-l2");

        let mut first = ActiveWorkerReservation::acquire(&case_path, evidence_id)
            .expect("first start reserves evidence before database writes");
        assert_eq!(active_worker_job_id(&case_path, evidence_id), Some(0));

        let second = ActiveWorkerReservation::acquire(&case_path, evidence_id);
        let second_error = match second {
            Ok(_) => panic!("a concurrent startup must fail immediately"),
            Err(error) => error,
        };
        assert!(second_error.to_string().contains("startup in progress"));

        first
            .promote(4242)
            .expect("promote reservation to job owner");
        assert_eq!(active_worker_job_id(&case_path, evidence_id), Some(4242));
        first.hand_off();
        drop(first);
        assert_eq!(
            active_worker_job_id(&case_path, evidence_id),
            Some(4242),
            "handoff must retain ownership for JobLifecycleCoordinator"
        );

        unregister_active_worker(&case_path, evidence_id);
        assert!(!is_active_worker_registered(&case_path, evidence_id));
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_m_orphan_recovery() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-m");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (4001, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert orphan job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (5001, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        ).expect("insert orphan plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (6001, 4001, 'filesystem_inventory', 1, 'running', 0, 0, '{}', NULL),
                    (6002, 4001, 'windows_registry', 2, 'queued', 0, 0, '{}', NULL)",
            [],
        ).expect("insert orphan stages");
        drop(conn);

        assert!(!is_active_worker_registered(&case_path, evidence_id));

        let reconciled = reconcile_orphaned_jobs_in_case(&case_path).expect("reconcile");
        assert_eq!(reconciled, 1, "exactly 1 orphaned job should be reconciled");

        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        let (job_status, job_err, finished_at): (String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT status, error, finished_at FROM evidence_jobs WHERE id = 4001",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("query job");
        assert_eq!(job_status, "interrupted");
        assert!(
            job_err.is_some_and(|e| e.contains("interrupted by unexpected application restart"))
        );
        assert!(finished_at.is_some());

        let plan_status: String = conn
            .query_row(
                "SELECT status FROM processing_plans WHERE plan_id = 5001",
                [],
                |r| r.get(0),
            )
            .expect("query plan");
        assert_eq!(plan_status, "interrupted");

        let stage1_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 6001",
                [],
                |r| r.get(0),
            )
            .expect("query stage 1");
        assert_eq!(stage1_status, "interrupted");

        let stage2_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 6002",
                [],
                |r| r.get(0),
            )
            .expect("query stage 2");
        assert_eq!(stage2_status, "not_started");

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }

    #[test]
    fn test_m2_desktop_reconciliation_never_interrupts_a_live_registered_worker() {
        let (case_path, evidence_id) = create_test_case_and_evidence("test-m2");
        let conn = rusqlite::Connection::open(&case_path).expect("open case");
        conn.execute(
            "INSERT INTO evidence_jobs (id, case_id, evidence_id, job_type, status, started_at)
             VALUES (4101, 1, ?1, 'forensic_analysis', 'running', CURRENT_TIMESTAMP)",
            [evidence_id],
        )
        .expect("insert active job");
        conn.execute(
            "INSERT INTO processing_plans (plan_id, case_id, evidence_id, plan_type, preset_name, status, target_summary_json, requested_processors_json)
             VALUES (5101, 1, ?1, 'forensic_analysis', 'full_forensic', 'running', '{}', '{}')",
            [evidence_id],
        )
        .expect("insert active plan");
        conn.execute(
            "INSERT INTO processor_executions (id, job_id, processor_name, stage_index, status, items_discovered, items_indexed, diagnostics_json, completed_at)
             VALUES (6101, 4101, 'filesystem_inventory', 1, 'running', 0, 0, '{}', NULL)",
            [],
        )
        .expect("insert active stage");
        drop(conn);

        register_active_worker(&case_path, evidence_id, 4101).expect("register live worker");
        let reconciled = NativeProcessingService::reconcile_orphaned_jobs_in_case(&case_path)
            .expect("reconcile while worker is live");
        assert_eq!(reconciled, 0, "a live registered worker is not an orphan");

        let conn = rusqlite::Connection::open(&case_path).expect("inspect live case");
        let job_status: String = conn
            .query_row(
                "SELECT status FROM evidence_jobs WHERE id = 4101",
                [],
                |r| r.get(0),
            )
            .expect("query active job");
        let stage_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 6101",
                [],
                |r| r.get(0),
            )
            .expect("query active stage");
        let plan_status: String = conn
            .query_row(
                "SELECT status FROM processing_plans WHERE plan_id = 5101",
                [],
                |r| r.get(0),
            )
            .expect("query active plan");
        assert_eq!(job_status, "running");
        assert_eq!(stage_status, "running");
        assert_eq!(plan_status, "running");
        drop(conn);

        unregister_active_worker(&case_path, evidence_id);
        let reconciled = NativeProcessingService::reconcile_orphaned_jobs_in_case(&case_path)
            .expect("reconcile after worker disappears");
        assert_eq!(reconciled, 1, "the abandoned job is now an orphan");

        let conn = rusqlite::Connection::open(&case_path).expect("inspect reconciled case");
        let job_status: String = conn
            .query_row(
                "SELECT status FROM evidence_jobs WHERE id = 4101",
                [],
                |r| r.get(0),
            )
            .expect("query interrupted job");
        let stage_status: String = conn
            .query_row(
                "SELECT status FROM processor_executions WHERE id = 6101",
                [],
                |r| r.get(0),
            )
            .expect("query interrupted stage");
        let plan_status: String = conn
            .query_row(
                "SELECT status FROM processing_plans WHERE plan_id = 5101",
                [],
                |r| r.get(0),
            )
            .expect("query interrupted plan");
        assert_eq!(job_status, "interrupted");
        assert_eq!(stage_status, "interrupted");
        assert_eq!(plan_status, "interrupted");

        drop(conn);
        let _ = std::fs::remove_file(case_path);
    }
}
