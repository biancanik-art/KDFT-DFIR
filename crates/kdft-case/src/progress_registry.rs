//! In-process progress-operation registry shared by every KDFT interface.
//!
//! The registry deliberately owns no network, UI, or durable-storage behavior.
//! It keeps only case identity, operation identity, sequence metadata, and
//! cloned [`JobProgressTracker`] handles in memory. Callers remain responsible
//! for any durable job state or diagnostic logging they require.

use crate::progress::{
    DiagnosticObserver, JobProgressSnapshot, JobProgressTracker, ProgressObserver,
};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Maximum number of active and recently finished progress operations retained
/// by the default registry.
pub const DEFAULT_MAX_RETAINED_PROGRESS_JOBS: usize = 64;

/// A bounded, case-scoped registry of in-process progress trackers.
///
/// Operation identifiers are unique only within one case. Active trackers are
/// never evicted. When the registry reaches its configured bound, starting a
/// new operation evicts the oldest finished tracker; if every retained tracker
/// is active, the new operation is rejected.
pub struct ProgressRegistry {
    state: Mutex<ProgressRegistryState>,
    max_retained_jobs: usize,
}

#[derive(Default)]
struct ProgressRegistryState {
    next_sequence: u64,
    jobs: HashMap<ProgressOperationKey, RegisteredProgress>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProgressOperationKey {
    case_identity: PathBuf,
    operation_id: String,
}

struct RegisteredProgress {
    sequence: u64,
    tracker: JobProgressTracker,
}

impl Default for ProgressRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(ProgressRegistryState::default()),
            max_retained_jobs: DEFAULT_MAX_RETAINED_PROGRESS_JOBS,
        }
    }
}

impl ProgressRegistry {
    /// Creates a registry with a caller-selected total retention bound.
    ///
    /// The bound includes active operations so that a stalled interface cannot
    /// grow the registry without limit. Finished operations are always chosen
    /// for eviction before a new operation is accepted.
    pub fn with_max_retained_jobs(max_retained_jobs: usize) -> Result<Self> {
        if max_retained_jobs == 0 {
            bail!("progress registry retention limit must be greater than zero");
        }
        Ok(Self {
            state: Mutex::new(ProgressRegistryState::default()),
            max_retained_jobs,
        })
    }

    /// Starts an operation without observers.
    pub fn start(
        &self,
        case_path: &Path,
        operation_id: &str,
        job_type: &str,
    ) -> Result<JobProgressTracker> {
        self.start_with_observers(case_path, operation_id, job_type, None, None)
    }

    /// Starts an operation and attaches optional in-process observers.
    ///
    /// Observers are invoked by [`JobProgressTracker`]; the registry neither
    /// buffers their output nor persists it.
    pub fn start_with_observers(
        &self,
        case_path: &Path,
        operation_id: &str,
        job_type: &str,
        progress_observer: Option<ProgressObserver>,
        diagnostic_observer: Option<DiagnosticObserver>,
    ) -> Result<JobProgressTracker> {
        let key = progress_operation_key(case_path, operation_id)?;
        let mut state = self.lock_state();

        if state
            .jobs
            .get(&key)
            .is_some_and(|registered| !registered.tracker.snapshot().state.is_terminal())
        {
            bail!("a progress operation with this id is already active for this case");
        }

        let replaces_finished_operation = state.jobs.contains_key(&key);
        if !replaces_finished_operation && state.jobs.len() >= self.max_retained_jobs {
            let removable = state
                .jobs
                .iter()
                .filter(|(_, registered)| registered.tracker.snapshot().state.is_terminal())
                .min_by_key(|(_, registered)| registered.sequence)
                .map(|(key, _)| key.clone());
            if let Some(removable) = removable {
                state.jobs.remove(&removable);
            } else {
                bail!("too many progress operations are active");
            }
        }

        state.next_sequence = state.next_sequence.saturating_add(1);
        let sequence = state.next_sequence;
        let tracker = JobProgressTracker::new_with_diagnostic_observer(
            operation_id,
            job_type,
            progress_observer,
            diagnostic_observer,
        );
        state.jobs.insert(
            key,
            RegisteredProgress {
                sequence,
                tracker: tracker.clone(),
            },
        );
        Ok(tracker)
    }

    /// Returns the latest snapshot for one case-scoped operation.
    pub fn snapshot(
        &self,
        case_path: &Path,
        operation_id: &str,
    ) -> Result<Option<JobProgressSnapshot>> {
        let key = progress_operation_key(case_path, operation_id)?;
        let state = self.lock_state();
        Ok(state
            .jobs
            .get(&key)
            .map(|registered| registered.tracker.snapshot()))
    }

    /// Returns active operations for a case in start order, oldest first.
    pub fn active_snapshots_for_case(&self, case_path: &Path) -> Result<Vec<JobProgressSnapshot>> {
        let case_identity = progress_case_identity(case_path)?;
        let state = self.lock_state();
        let mut active = state
            .jobs
            .iter()
            .filter_map(|(key, registered)| {
                if key.case_identity != case_identity {
                    return None;
                }
                let snapshot = registered.tracker.snapshot();
                (!snapshot.state.is_terminal()).then_some((registered.sequence, snapshot))
            })
            .collect::<Vec<_>>();
        active.sort_by_key(|(sequence, _)| *sequence);
        Ok(active.into_iter().map(|(_, snapshot)| snapshot).collect())
    }

    /// Cooperatively requests cancellation of one active operation.
    ///
    /// Returns `true` only when the operation exists and is still active. The
    /// processing loop observes the request through its cloned
    /// [`JobProgressTracker`].
    pub fn cancel(&self, case_path: &Path, operation_id: &str) -> Result<bool> {
        let key = progress_operation_key(case_path, operation_id)?;
        let state = self.lock_state();
        let Some(registered) = state.jobs.get(&key) else {
            return Ok(false);
        };
        if registered.tracker.snapshot().state.is_terminal() {
            return Ok(false);
        }
        registered.tracker.request_cancellation();
        Ok(true)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ProgressRegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Validates the stable identifier accepted by progress-registry operations.
pub fn validate_progress_id(operation_id: &str) -> Result<()> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("progress_id must be 1-128 ASCII letters, digits, hyphens, or underscores");
    }
    Ok(())
}

fn progress_operation_key(case_path: &Path, operation_id: &str) -> Result<ProgressOperationKey> {
    validate_progress_id(operation_id)?;
    Ok(ProgressOperationKey {
        case_identity: progress_case_identity(case_path)?,
        operation_id: operation_id.to_string(),
    })
}

fn progress_case_identity(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("case path must not be empty");
    }
    Ok(std::fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::JobProgressState;

    fn case(name: &str) -> PathBuf {
        PathBuf::from(format!("progress-registry-test-{name}"))
    }

    #[test]
    fn operation_ids_are_validated_at_every_lookup_boundary() {
        let registry = ProgressRegistry::default();
        let case_path = case("validation");

        assert!(registry.start(&case_path, "", "process").is_err());
        assert!(registry.start(&case_path, "has/slash", "process").is_err());
        assert!(registry
            .start(&case_path, &"a".repeat(129), "process")
            .is_err());
        assert!(registry.snapshot(&case_path, "has space").is_err());
        assert!(registry.cancel(&case_path, "bad.dot").is_err());
        assert!(registry
            .start(Path::new(""), "valid-id_1", "process")
            .is_err());
    }

    #[test]
    fn duplicate_active_operations_are_rejected_only_within_the_same_case() {
        let registry = ProgressRegistry::default();
        let first_case = case("duplicate-a");
        let second_case = case("duplicate-b");

        let first = registry.start(&first_case, "shared-id", "process").unwrap();
        let error = registry
            .start(&first_case, "shared-id", "process")
            .err()
            .expect("same case and id must be rejected while active");
        assert!(error.to_string().contains("already active for this case"));

        let second = registry
            .start(&second_case, "shared-id", "process")
            .expect("the same operation id is valid in another case");
        first.finish(JobProgressState::Complete);
        registry
            .start(&first_case, "shared-id", "process")
            .expect("a finished case-scoped operation may be replaced");
        second.finish(JobProgressState::Complete);
    }

    #[test]
    fn retention_evicts_the_oldest_finished_operation_and_never_active_work() {
        let registry = ProgressRegistry::with_max_retained_jobs(2).unwrap();
        let case_path = case("retention");
        let oldest = registry.start(&case_path, "oldest", "process").unwrap();
        oldest.finish(JobProgressState::Complete);
        let active = registry.start(&case_path, "active", "process").unwrap();

        registry
            .start(&case_path, "new", "process")
            .expect("the oldest finished operation should be evicted");
        assert!(registry.snapshot(&case_path, "oldest").unwrap().is_none());
        assert!(registry.snapshot(&case_path, "active").unwrap().is_some());
        assert!(!active.is_cancellation_requested());

        let all_active = ProgressRegistry::with_max_retained_jobs(2).unwrap();
        all_active.start(&case_path, "one", "process").unwrap();
        all_active.start(&case_path, "two", "process").unwrap();
        let error = all_active
            .start(&case_path, "three", "process")
            .err()
            .expect("a full registry of active work must reject new work");
        assert!(error.to_string().contains("too many progress operations"));
    }

    #[test]
    fn active_snapshots_are_case_scoped_ordered_and_exclude_finished_jobs() {
        let registry = ProgressRegistry::default();
        let first_case = case("active-a");
        let second_case = case("active-b");

        registry.start(&first_case, "first", "process").unwrap();
        let finished = registry.start(&first_case, "finished", "process").unwrap();
        finished.finish(JobProgressState::CompleteWithDiagnostics);
        registry.start(&second_case, "foreign", "process").unwrap();
        registry.start(&first_case, "second", "process").unwrap();

        let snapshots = registry.active_snapshots_for_case(&first_case).unwrap();
        let ids = snapshots
            .iter()
            .map(|snapshot| snapshot.operation_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["first", "second"]);
    }

    #[test]
    fn cancellation_is_cooperative_case_scoped_and_ignores_terminal_jobs() {
        let registry = ProgressRegistry::default();
        let case_path = case("cancel");
        let other_case = case("cancel-other");
        let tracker = registry.start(&case_path, "job", "process").unwrap();

        assert!(!registry.cancel(&other_case, "job").unwrap());
        assert!(registry.cancel(&case_path, "job").unwrap());
        assert!(tracker.is_cancellation_requested());

        tracker.finish(JobProgressState::Cancelled);
        assert!(!registry.cancel(&case_path, "job").unwrap());
        assert_eq!(
            registry
                .snapshot(&case_path, "job")
                .unwrap()
                .expect("finished snapshot remains retained")
                .state,
            JobProgressState::Cancelled
        );
    }

    #[test]
    fn zero_retention_is_rejected() {
        assert!(ProgressRegistry::with_max_retained_jobs(0).is_err());
    }
}
