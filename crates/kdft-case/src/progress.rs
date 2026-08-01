use serde::Serialize;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PUBLICATION_INTERVAL: Duration = Duration::from_millis(250);
const RATE_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
const RATE_WINDOW: Duration = Duration::from_secs(10);
const MIN_RATE_SAMPLE_COUNT: usize = 3;
const MIN_RATE_SPAN: Duration = Duration::from_secs(1);
const STALLED_AFTER: Duration = Duration::from_secs(5);
const RECENT_OBJECT_LIMIT: usize = 3;
const TRUNCATION_REASON_LIMIT: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobProgressState {
    Active,
    Complete,
    Truncated,
    Cancelled,
    Failed,
}

impl JobProgressState {
    pub fn is_terminal(self) -> bool {
        self != Self::Active
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EtaStatus {
    Unavailable,
    Calculating,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateStatus {
    Calculating,
    Available,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompletedStageProgress {
    pub name: String,
    pub stage_index: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobProgressSnapshot {
    pub operation_id: String,
    pub job_type: String,
    pub job_id: Option<i64>,
    pub evidence_id: Option<i64>,
    pub state: JobProgressState,
    pub stage_name: Option<String>,
    pub stage_index: Option<usize>,
    pub stage_count: Option<usize>,
    pub stage_elapsed_ms: u64,
    pub completed_stages: Vec<CompletedStageProgress>,
    pub elapsed_ms: u64,
    pub processed_items: u64,
    pub total_items: Option<u64>,
    pub item_unit: String,
    pub percentage: Option<f64>,
    pub rate_status: RateStatus,
    pub rate_per_second: Option<f64>,
    pub eta_status: EtaStatus,
    pub eta_seconds: Option<u64>,
    pub current_volume: Option<String>,
    pub current_object: Option<String>,
    pub recently_processed: Vec<String>,
    pub skipped_count: u64,
    pub error_count: u64,
    /// Exact number of structured diagnostic events emitted for this run.
    /// The UI may show only bounded samples, while an attached observer can
    /// stream every event to durable examiner-readable storage.
    pub diagnostic_event_count: u64,
    /// Number of truncation-reason reports observed. The accompanying vector
    /// is deliberately de-duplicated and bounded for long-running/corrupt
    /// inputs.
    pub truncation_reason_count: u64,
    /// Number of reason reports whose text could not be added to
    /// `truncation_reasons` after the bounded diagnostic sample filled.
    pub truncation_reasons_omitted: u64,
    pub truncation_reasons: Vec<String>,
}

pub type ProgressObserver = Arc<dyn Fn(JobProgressSnapshot) + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobDiagnosticKind {
    Stage,
    Skip,
    Error,
    PartialCoverage,
    ParserDiagnostic,
    Terminal,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JobDiagnosticEvent {
    pub sequence: u64,
    pub elapsed_ms: u64,
    pub stage_name: Option<String>,
    pub stage_index: Option<usize>,
    pub kind: JobDiagnosticKind,
    pub message: String,
}

pub type DiagnosticObserver = Arc<dyn Fn(JobDiagnosticEvent) + Send + Sync + 'static>;

trait MonotonicClock: Send + Sync {
    fn now(&self) -> Duration;
}

struct InstantClock {
    origin: Instant,
}

impl InstantClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for InstantClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[derive(Clone)]
pub struct JobProgressTracker {
    shared: Arc<TrackerShared>,
}

struct TrackerShared {
    clock: Arc<dyn MonotonicClock>,
    observer: Option<ProgressObserver>,
    diagnostic_observer: Option<DiagnosticObserver>,
    state: Mutex<TrackerState>,
}

impl TrackerShared {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, TrackerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct TrackerState {
    operation_id: String,
    job_type: String,
    job_id: Option<i64>,
    evidence_id: Option<i64>,
    state: JobProgressState,
    started_at: Duration,
    finished_at: Option<Duration>,
    stage: Option<ActiveStage>,
    completed_stages: Vec<CompletedStageProgress>,
    processed_items: u64,
    total_items: Option<u64>,
    item_unit: String,
    current_volume: Option<String>,
    current_object: Option<String>,
    recently_processed: VecDeque<String>,
    skipped_count: u64,
    error_count: u64,
    diagnostic_sequence: u64,
    truncation_reason_count: u64,
    truncation_reasons_omitted: u64,
    truncation_reasons: Vec<String>,
    auto_advance_database_entries: bool,
    samples: VecDeque<ProgressSample>,
    last_progress_at: Duration,
    last_publish_at: Option<Duration>,
}

struct ActiveStage {
    name: String,
    stage_index: usize,
    stage_count: Option<usize>,
    started_at: Duration,
    finished_at: Option<Duration>,
}

#[derive(Clone, Copy)]
struct ProgressSample {
    at: Duration,
    processed: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RateValidity {
    Calculating,
    Valid,
    Invalid,
}

impl JobProgressTracker {
    pub fn new(
        operation_id: impl Into<String>,
        job_type: impl Into<String>,
        observer: Option<ProgressObserver>,
    ) -> Self {
        Self::with_clock(
            operation_id,
            job_type,
            observer,
            None,
            Arc::new(InstantClock::new()),
        )
    }

    pub fn new_with_diagnostic_observer(
        operation_id: impl Into<String>,
        job_type: impl Into<String>,
        observer: Option<ProgressObserver>,
        diagnostic_observer: Option<DiagnosticObserver>,
    ) -> Self {
        Self::with_clock(
            operation_id,
            job_type,
            observer,
            diagnostic_observer,
            Arc::new(InstantClock::new()),
        )
    }

    fn with_clock(
        operation_id: impl Into<String>,
        job_type: impl Into<String>,
        observer: Option<ProgressObserver>,
        diagnostic_observer: Option<DiagnosticObserver>,
        clock: Arc<dyn MonotonicClock>,
    ) -> Self {
        let now = clock.now();
        Self {
            shared: Arc::new(TrackerShared {
                clock,
                observer,
                diagnostic_observer,
                state: Mutex::new(TrackerState {
                    operation_id: operation_id.into(),
                    job_type: job_type.into(),
                    job_id: None,
                    evidence_id: None,
                    state: JobProgressState::Active,
                    started_at: now,
                    finished_at: None,
                    stage: None,
                    completed_stages: Vec::new(),
                    processed_items: 0,
                    total_items: None,
                    item_unit: "items".to_string(),
                    current_volume: None,
                    current_object: None,
                    recently_processed: VecDeque::new(),
                    skipped_count: 0,
                    error_count: 0,
                    diagnostic_sequence: 0,
                    truncation_reason_count: 0,
                    truncation_reasons_omitted: 0,
                    truncation_reasons: Vec::new(),
                    auto_advance_database_entries: false,
                    samples: VecDeque::new(),
                    last_progress_at: now,
                    last_publish_at: None,
                }),
            }),
        }
    }

    pub fn start_stage(
        &self,
        name: impl Into<String>,
        stage_index: usize,
        stage_count: Option<usize>,
        item_unit: impl Into<String>,
        total_items: Option<u64>,
    ) {
        let name = name.into();
        let diagnostic_name = name.clone();
        self.mutate(true, |state, now| {
            state.finish_current_stage(now);
            state.stage = Some(ActiveStage {
                name,
                stage_index,
                stage_count,
                started_at: now,
                finished_at: None,
            });
            state.processed_items = 0;
            state.total_items = total_items;
            state.item_unit = item_unit.into();
            state.current_volume = None;
            state.current_object = None;
            state.recently_processed.clear();
            state.auto_advance_database_entries = false;
            state.samples.clear();
            state.samples.push_back(ProgressSample {
                at: now,
                processed: 0,
            });
            state.last_progress_at = now;
        });
        self.emit_diagnostic(JobDiagnosticKind::Stage, diagnostic_name);
    }

    pub fn set_job_id(&self, job_id: i64) {
        self.mutate(false, |state, _| {
            if state.job_id.is_none() {
                state.job_id = Some(job_id);
            }
        });
    }

    pub(crate) fn replace_job_id(&self, job_id: i64) {
        self.mutate(false, |state, _| state.job_id = Some(job_id));
    }

    pub fn set_evidence_id(&self, evidence_id: i64) {
        self.mutate(false, |state, _| state.evidence_id = Some(evidence_id));
    }

    pub fn set_total_items(&self, total_items: Option<u64>) {
        self.mutate(false, |state, _| state.total_items = total_items);
    }

    pub fn set_item_unit(&self, item_unit: impl Into<String>) {
        self.mutate(false, |state, _| state.item_unit = item_unit.into());
    }

    pub fn set_current_volume(&self, volume: Option<String>) {
        self.mutate(false, |state, _| state.current_volume = volume);
    }

    pub fn set_auto_advance_database_entries(&self, enabled: bool) {
        self.mutate(false, |state, _| {
            state.auto_advance_database_entries = enabled
        });
    }

    pub fn set_current_object(&self, current_object: impl Into<String>) {
        let current_object = current_object.into();
        self.mutate(false, |state, _| {
            state.update_current_object(current_object)
        });
    }

    pub fn advance(&self, amount: u64, current_object: Option<String>) {
        self.mutate(false, |state, now| {
            if let Some(current_object) = current_object {
                state.update_current_object(current_object);
            }
            let previous = state.processed_items;
            state.processed_items = state.processed_items.saturating_add(amount);
            if state.processed_items != previous {
                state.last_progress_at = now;
            }
            state.capture_rate_sample(now);
        });
    }

    pub fn set_processed_items(&self, processed_items: u64, current_object: Option<String>) {
        self.mutate(false, |state, now| {
            if let Some(current_object) = current_object {
                state.update_current_object(current_object);
            }
            if processed_items < state.processed_items {
                state.samples.clear();
                state.samples.push_back(ProgressSample {
                    at: now,
                    processed: processed_items,
                });
            }
            if processed_items != state.processed_items {
                state.last_progress_at = now;
            }
            state.processed_items = processed_items;
            state.capture_rate_sample(now);
        });
    }

    pub fn record_skip(&self, current_object: Option<String>) {
        let diagnostic_object = current_object.clone();
        self.mutate(false, |state, _| {
            state.skipped_count = state.skipped_count.saturating_add(1);
            if let Some(current_object) = current_object {
                state.update_current_object(current_object);
            }
        });
        self.emit_diagnostic(
            JobDiagnosticKind::Skip,
            diagnostic_object.unwrap_or_else(|| "unspecified skipped item".to_string()),
        );
    }

    pub fn record_error(&self, current_object: Option<String>) {
        self.record_errors(1, current_object);
    }

    /// Records an exact batch of parser/staging errors without retaining an
    /// item per error or forcing one UI publication per error.
    pub fn record_errors(&self, amount: u64, current_object: Option<String>) {
        let diagnostic_object = current_object.clone();
        self.mutate(false, |state, _| {
            state.error_count = state.error_count.saturating_add(amount);
            if let Some(current_object) = current_object {
                state.update_current_object(current_object);
            }
        });
        self.emit_diagnostic(
            JobDiagnosticKind::Error,
            match diagnostic_object {
                Some(object) if amount == 1 => object,
                Some(object) => format!("{amount} errors reported for {object}"),
                None if amount == 1 => "unspecified processing error".to_string(),
                None => format!("{amount} processing errors reported"),
            },
        );
    }

    pub fn record_truncation(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let diagnostic_reason = reason.clone();
        self.mutate(false, |state, _| {
            state.truncation_reason_count = state.truncation_reason_count.saturating_add(1);
            // Repeated reports of an already retained reason add no examiner
            // information. New reports beyond the diagnostic sample are
            // counted rather than retained, keeping memory bounded while
            // making the omission explicit in every snapshot.
            if state.truncation_reasons.iter().any(|item| item == &reason) {
                return;
            }
            if state.truncation_reasons.len() < TRUNCATION_REASON_LIMIT {
                state.truncation_reasons.push(reason);
            } else {
                state.truncation_reasons_omitted =
                    state.truncation_reasons_omitted.saturating_add(1);
            }
        });
        self.emit_diagnostic(JobDiagnosticKind::PartialCoverage, diagnostic_reason);
    }

    /// Emits a complete examiner-facing parser diagnostic without adding it
    /// to the bounded truncation-reason sample or changing job counters.
    pub fn record_diagnostic(&self, kind: JobDiagnosticKind, message: impl Into<String>) {
        self.emit_diagnostic(kind, message.into());
    }

    pub fn finish(&self, terminal_state: JobProgressState) {
        debug_assert!(terminal_state.is_terminal());
        self.mutate(true, |state, now| {
            state.state = terminal_state;
            state.finished_at = Some(now);
            state.finish_current_stage(now);
        });
        self.emit_diagnostic(
            JobDiagnosticKind::Terminal,
            format!("job finished with state {terminal_state:?}"),
        );
    }

    pub fn snapshot(&self) -> JobProgressSnapshot {
        let now = self.shared.clock.now();
        let state = self.shared.lock_state();
        state.snapshot(now)
    }

    pub fn truncation_reasons(&self) -> Vec<String> {
        self.shared.lock_state().truncation_reasons.clone()
    }

    fn mutate(&self, force_publish: bool, update: impl FnOnce(&mut TrackerState, Duration)) {
        let now = self.shared.clock.now();
        let snapshot = {
            let mut state = self.shared.lock_state();
            update(&mut state, now);
            let should_publish = force_publish
                || state
                    .last_publish_at
                    .map(|last| now.saturating_sub(last) >= PUBLICATION_INTERVAL)
                    .unwrap_or(true);
            if should_publish {
                state.last_publish_at = Some(now);
                Some(state.snapshot(now))
            } else {
                None
            }
        };
        if let (Some(observer), Some(snapshot)) = (&self.shared.observer, snapshot) {
            observer(snapshot);
        }
    }

    fn emit_diagnostic(&self, kind: JobDiagnosticKind, message: String) {
        let Some(observer) = self.shared.diagnostic_observer.as_ref() else {
            return;
        };
        let now = self.shared.clock.now();
        let event = {
            let mut state = self.shared.lock_state();
            state.diagnostic_sequence = state.diagnostic_sequence.saturating_add(1);
            JobDiagnosticEvent {
                sequence: state.diagnostic_sequence,
                elapsed_ms: duration_ms(now.saturating_sub(state.started_at)),
                stage_name: state.stage.as_ref().map(|stage| stage.name.clone()),
                stage_index: state.stage.as_ref().map(|stage| stage.stage_index),
                kind,
                message,
            }
        };
        observer(event);
    }
}

impl TrackerState {
    fn finish_current_stage(&mut self, now: Duration) {
        let Some(stage) = self.stage.as_mut() else {
            return;
        };
        if stage.finished_at.is_some() {
            return;
        }
        stage.finished_at = Some(now);
        self.completed_stages.push(CompletedStageProgress {
            name: stage.name.clone(),
            stage_index: stage.stage_index,
            elapsed_ms: duration_ms(now.saturating_sub(stage.started_at)),
        });
    }

    fn update_current_object(&mut self, current_object: String) {
        if self.current_object.as_deref() == Some(current_object.as_str()) {
            return;
        }
        if let Some(previous) = self.current_object.replace(current_object) {
            if self.recently_processed.front() != Some(&previous) {
                self.recently_processed.push_front(previous);
            }
            while self.recently_processed.len() > RECENT_OBJECT_LIMIT {
                self.recently_processed.pop_back();
            }
        }
    }

    fn capture_rate_sample(&mut self, now: Duration) {
        let should_capture = self
            .samples
            .back()
            .map(|sample| now.saturating_sub(sample.at) >= RATE_SAMPLE_INTERVAL)
            .unwrap_or(true);
        if !should_capture {
            return;
        }
        self.samples.push_back(ProgressSample {
            at: now,
            processed: self.processed_items,
        });
        while self.samples.len() > 2
            && self
                .samples
                .front()
                .map(|sample| now.saturating_sub(sample.at) > RATE_WINDOW)
                .unwrap_or(false)
        {
            self.samples.pop_front();
        }
    }

    fn snapshot(&self, now: Duration) -> JobProgressSnapshot {
        let effective_now = self.finished_at.unwrap_or(now);
        let stage_elapsed = self.stage.as_ref().map_or(Duration::ZERO, |stage| {
            stage
                .finished_at
                .unwrap_or(effective_now)
                .saturating_sub(stage.started_at)
        });
        let percentage = self.total_items.map(|total| {
            if total == 0 {
                100.0
            } else {
                ((self.processed_items as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
            }
        });
        let (rate_per_second, rate_validity) = self.recent_rate(effective_now);
        let rate_status = match rate_validity {
            RateValidity::Calculating => RateStatus::Calculating,
            RateValidity::Valid => RateStatus::Available,
            RateValidity::Invalid => RateStatus::Unknown,
        };
        let (eta_status, eta_seconds) = self.eta(rate_per_second, rate_validity);
        JobProgressSnapshot {
            operation_id: self.operation_id.clone(),
            job_type: self.job_type.clone(),
            job_id: self.job_id,
            evidence_id: self.evidence_id,
            state: self.state,
            stage_name: self.stage.as_ref().map(|stage| stage.name.clone()),
            stage_index: self.stage.as_ref().map(|stage| stage.stage_index),
            stage_count: self.stage.as_ref().and_then(|stage| stage.stage_count),
            stage_elapsed_ms: duration_ms(stage_elapsed),
            completed_stages: self.completed_stages.clone(),
            elapsed_ms: duration_ms(effective_now.saturating_sub(self.started_at)),
            processed_items: self.processed_items,
            total_items: self.total_items,
            item_unit: self.item_unit.clone(),
            percentage,
            rate_status,
            rate_per_second,
            eta_status,
            eta_seconds,
            current_volume: self.current_volume.clone(),
            current_object: self.current_object.clone(),
            recently_processed: self.recently_processed.iter().cloned().collect(),
            skipped_count: self.skipped_count,
            error_count: self.error_count,
            diagnostic_event_count: self.diagnostic_sequence,
            truncation_reason_count: self.truncation_reason_count,
            truncation_reasons_omitted: self.truncation_reasons_omitted,
            truncation_reasons: self.truncation_reasons.clone(),
        }
    }

    fn recent_rate(&self, now: Duration) -> (Option<f64>, RateValidity) {
        if self.state == JobProgressState::Active
            && now.saturating_sub(self.last_progress_at) >= STALLED_AFTER
        {
            return (None, RateValidity::Invalid);
        }
        let Some(first) = self.samples.front() else {
            return (None, RateValidity::Calculating);
        };
        let Some(last) = self.samples.back() else {
            return (None, RateValidity::Calculating);
        };
        let span = last.at.saturating_sub(first.at);
        if self.samples.len() < MIN_RATE_SAMPLE_COUNT || span < MIN_RATE_SPAN {
            return (None, RateValidity::Calculating);
        }
        let completed = last.processed.saturating_sub(first.processed);
        if completed == 0 || span.is_zero() {
            return (None, RateValidity::Invalid);
        }
        let rate = completed as f64 / span.as_secs_f64();
        if rate.is_finite() && rate > 0.0 {
            (Some(rate), RateValidity::Valid)
        } else {
            (None, RateValidity::Invalid)
        }
    }

    fn eta(
        &self,
        rate_per_second: Option<f64>,
        rate_validity: RateValidity,
    ) -> (EtaStatus, Option<u64>) {
        let Some(total) = self.total_items else {
            return (EtaStatus::Unavailable, None);
        };
        if self.state.is_terminal() {
            return (EtaStatus::Unavailable, None);
        }
        if total == 0 || self.processed_items >= total {
            return (EtaStatus::Estimated, Some(0));
        }
        match (rate_per_second, rate_validity) {
            (Some(rate), RateValidity::Valid) => {
                let remaining = total.saturating_sub(self.processed_items) as f64;
                let seconds = (remaining / rate).ceil();
                if seconds.is_finite() && seconds >= 0.0 {
                    (EtaStatus::Estimated, Some(seconds as u64))
                } else {
                    (EtaStatus::Unknown, None)
                }
            }
            (_, RateValidity::Calculating) => (EtaStatus::Calculating, None),
            _ => (EtaStatus::Unknown, None),
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

thread_local! {
    static ACTIVE_PROGRESS: RefCell<Option<JobProgressTracker>> = const { RefCell::new(None) };
}

struct ActiveProgressGuard {
    previous: Option<JobProgressTracker>,
}

impl Drop for ActiveProgressGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        ACTIVE_PROGRESS.with(|active| {
            active.replace(previous);
        });
    }
}

pub fn with_job_progress<T>(tracker: &JobProgressTracker, operation: impl FnOnce() -> T) -> T {
    let previous = ACTIVE_PROGRESS.with(|active| active.replace(Some(tracker.clone())));
    let _guard = ActiveProgressGuard { previous };
    operation()
}

fn with_active_progress(operation: impl FnOnce(&JobProgressTracker)) {
    ACTIVE_PROGRESS.with(|active| {
        if let Some(tracker) = active.borrow().as_ref() {
            operation(tracker);
        }
    });
}

pub(crate) fn progress_set_job_id(job_id: i64) {
    with_active_progress(|tracker| tracker.set_job_id(job_id));
}

pub(crate) fn progress_replace_job_id(job_id: i64) {
    with_active_progress(|tracker| tracker.replace_job_id(job_id));
}

pub(crate) fn progress_set_evidence_id(evidence_id: i64) {
    with_active_progress(|tracker| tracker.set_evidence_id(evidence_id));
}

pub(crate) fn progress_set_total(total_items: Option<u64>) {
    with_active_progress(|tracker| tracker.set_total_items(total_items));
}

pub(crate) fn progress_set_unit(item_unit: &str) {
    with_active_progress(|tracker| tracker.set_item_unit(item_unit));
}

pub(crate) fn progress_set_volume(volume: Option<String>) {
    with_active_progress(|tracker| tracker.set_current_volume(volume));
}

pub(crate) fn progress_current(current_object: impl Into<String>) {
    let current_object = current_object.into();
    with_active_progress(|tracker| tracker.set_current_object(current_object));
}

pub(crate) fn progress_advance(current_object: impl Into<String>) {
    let current_object = current_object.into();
    with_active_progress(|tracker| tracker.advance(1, Some(current_object)));
}

pub(crate) fn progress_database_entry(current_object: impl Into<String>) {
    let current_object = current_object.into();
    with_active_progress(|tracker| {
        let (auto_advance, has_stage) = {
            let state = tracker.shared.lock_state();
            (state.auto_advance_database_entries, state.stage.is_some())
        };
        if auto_advance {
            tracker.advance(1, Some(current_object));
        } else if has_stage {
            tracker.set_current_object(current_object);
        }
    });
}

pub(crate) fn progress_advance_by(amount: u64, current_object: Option<String>) {
    with_active_progress(|tracker| tracker.advance(amount, current_object));
}

pub(crate) fn progress_set_processed(processed_items: u64, current_object: Option<String>) {
    with_active_progress(|tracker| tracker.set_processed_items(processed_items, current_object));
}

pub(crate) fn progress_skip(current_object: Option<String>) {
    with_active_progress(|tracker| tracker.record_skip(current_object));
}

pub(crate) fn progress_error(current_object: Option<String>) {
    with_active_progress(|tracker| tracker.record_error(current_object));
}

pub(crate) fn progress_errors(amount: u64, current_object: Option<String>) {
    with_active_progress(|tracker| tracker.record_errors(amount, current_object));
}

pub(crate) fn progress_truncated(reason: impl Into<String>) {
    let reason = reason.into();
    with_active_progress(|tracker| tracker.record_truncation(reason));
}

pub(crate) fn progress_diagnostic(kind: JobDiagnosticKind, message: impl Into<String>) {
    let message = message.into();
    with_active_progress(|tracker| tracker.record_diagnostic(kind, message));
}

pub(crate) fn has_active_progress() -> bool {
    ACTIVE_PROGRESS.with(|active| active.borrow().is_some())
}

pub(crate) fn active_truncation_reasons() -> Vec<String> {
    ACTIVE_PROGRESS.with(|active| {
        active
            .borrow()
            .as_ref()
            .map(JobProgressTracker::truncation_reasons)
            .unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct FakeClock {
        millis: AtomicU64,
    }

    impl FakeClock {
        fn advance_ms(&self, millis: u64) {
            self.millis.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for FakeClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
    }

    fn tracker(clock: Arc<FakeClock>) -> JobProgressTracker {
        JobProgressTracker::with_clock("test-operation", "process", None, None, clock)
    }

    #[test]
    fn elapsed_time_uses_injected_monotonic_clock() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock.clone());
        tracker.start_stage("Inventory", 1, Some(1), "entries", None);
        clock.advance_ms(5_250);
        assert_eq!(tracker.snapshot().elapsed_ms, 5_250);
        assert_eq!(tracker.snapshot().stage_elapsed_ms, 5_250);
    }

    #[test]
    fn percentage_is_only_calculated_from_a_known_total() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock);
        tracker.start_stage("Inventory", 1, Some(1), "entries", Some(200));
        tracker.set_processed_items(50, None);
        assert_eq!(tracker.snapshot().percentage, Some(25.0));
    }

    #[test]
    fn eta_is_unavailable_when_total_is_unknown() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock.clone());
        tracker.start_stage("Inventory", 1, Some(1), "entries", None);
        clock.advance_ms(500);
        tracker.set_processed_items(10, None);
        clock.advance_ms(500);
        tracker.set_processed_items(20, None);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.eta_status, EtaStatus::Unavailable);
        assert_eq!(snapshot.eta_seconds, None);
    }

    #[test]
    fn eta_calculates_only_after_sufficient_samples() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock.clone());
        tracker.start_stage("Inventory", 1, Some(1), "entries", Some(100));
        clock.advance_ms(500);
        tracker.set_processed_items(10, None);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.eta_status, EtaStatus::Calculating);
        assert_eq!(snapshot.rate_status, RateStatus::Calculating);
        assert_eq!(snapshot.rate_per_second, None);
    }

    #[test]
    fn eta_uses_deterministic_windowed_rate_samples() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock.clone());
        tracker.start_stage("Inventory", 1, Some(1), "entries", Some(100));
        clock.advance_ms(500);
        tracker.set_processed_items(10, None);
        clock.advance_ms(500);
        tracker.set_processed_items(20, None);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.rate_per_second, Some(20.0));
        assert_eq!(snapshot.eta_status, EtaStatus::Estimated);
        assert_eq!(snapshot.eta_seconds, Some(4));
    }

    #[test]
    fn zero_rate_and_stalled_progress_make_eta_unknown() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock.clone());
        tracker.start_stage("Inventory", 1, Some(1), "entries", Some(100));
        clock.advance_ms(500);
        tracker.set_processed_items(0, None);
        clock.advance_ms(500);
        tracker.set_processed_items(0, None);
        assert_eq!(tracker.snapshot().eta_status, EtaStatus::Unknown);
        clock.advance_ms(5_000);
        let stalled = tracker.snapshot();
        assert_eq!(stalled.rate_per_second, None);
        assert_eq!(stalled.rate_status, RateStatus::Unknown);
        assert_eq!(stalled.eta_status, EtaStatus::Unknown);
    }

    #[test]
    fn terminal_job_states_are_preserved() {
        for state in [
            JobProgressState::Complete,
            JobProgressState::Cancelled,
            JobProgressState::Failed,
            JobProgressState::Truncated,
        ] {
            let clock = Arc::new(FakeClock::default());
            let tracker = tracker(clock);
            tracker.start_stage("Finalization", 1, Some(1), "steps", Some(1));
            tracker.finish(state);
            assert_eq!(tracker.snapshot().state, state);
        }
    }

    #[test]
    fn poisoned_progress_state_does_not_crash_the_analysis() {
        let tracker = tracker(Arc::new(FakeClock::default()));
        let poisoner = tracker.clone();
        let result = std::thread::spawn(move || {
            let _guard = poisoner.shared.state.lock().unwrap();
            panic!("deliberately poison the test mutex");
        })
        .join();
        assert!(result.is_err());

        tracker.start_stage("Recovery", 1, Some(1), "entries", Some(1));
        tracker.set_processed_items(1, Some("recovered".to_string()));
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.processed_items, 1);
        assert_eq!(snapshot.current_object.as_deref(), Some("recovered"));
    }

    #[test]
    fn publication_is_rate_limited_but_transitions_are_immediate() {
        let clock = Arc::new(FakeClock::default());
        let published = Arc::new(Mutex::new(Vec::new()));
        let captured = published.clone();
        let observer: ProgressObserver = Arc::new(move |snapshot| {
            captured.lock().unwrap().push(snapshot);
        });
        let tracker = JobProgressTracker::with_clock(
            "test-operation",
            "process",
            Some(observer),
            None,
            clock.clone(),
        );
        tracker.start_stage("Inventory", 1, Some(2), "entries", None);
        for index in 1..=10 {
            clock.advance_ms(20);
            tracker.set_processed_items(index, None);
        }
        tracker.set_evidence_id(42);
        tracker.set_total_items(Some(100));
        tracker.set_item_unit("records");
        tracker.record_truncation("bounded test reason");
        assert_eq!(published.lock().unwrap().len(), 1);
        clock.advance_ms(50);
        tracker.set_processed_items(11, None);
        assert_eq!(published.lock().unwrap().len(), 2);
        tracker.start_stage("Finalization", 2, Some(2), "steps", Some(1));
        tracker.finish(JobProgressState::Complete);
        assert_eq!(published.lock().unwrap().len(), 4);
    }

    #[test]
    fn batched_errors_are_exact_saturating_and_rate_limited() {
        let clock = Arc::new(FakeClock::default());
        let published = Arc::new(Mutex::new(Vec::new()));
        let captured = published.clone();
        let observer: ProgressObserver = Arc::new(move |snapshot| {
            captured.lock().unwrap().push(snapshot);
        });
        let tracker = JobProgressTracker::with_clock(
            "test-operation",
            "process",
            Some(observer),
            None,
            clock.clone(),
        );
        tracker.start_stage("Browser parsing", 1, Some(1), "profiles", Some(1));
        tracker.record_errors(u64::MAX - 3, Some("profile-a".to_string()));
        tracker.record_errors(10, Some("profile-b".to_string()));
        assert_eq!(tracker.snapshot().error_count, u64::MAX);
        assert_eq!(
            tracker.snapshot().current_object.as_deref(),
            Some("profile-b")
        );
        // Both batches landed internally, but neither bypassed the normal
        // four-per-second publication limit.
        assert_eq!(published.lock().unwrap().len(), 1);
        clock.advance_ms(250);
        tracker.record_errors(0, None);
        assert_eq!(published.lock().unwrap().len(), 2);
        assert_eq!(published.lock().unwrap()[1].error_count, u64::MAX);
    }

    #[test]
    fn diagnostic_observer_receives_every_event_beyond_the_ui_sample_limit() {
        let clock = Arc::new(FakeClock::default());
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        let captured = diagnostics.clone();
        let observer: DiagnosticObserver = Arc::new(move |event| {
            captured.lock().unwrap().push(event);
        });
        let tracker = JobProgressTracker::with_clock(
            "diagnostic-stream",
            "process",
            None,
            Some(observer),
            clock,
        );
        tracker.start_stage("Inventory", 1, Some(1), "entries", None);
        for index in 0..(TRUNCATION_REASON_LIMIT + 9) {
            tracker.record_truncation(format!("reason-{index:02}"));
        }
        tracker.record_diagnostic(
            JobDiagnosticKind::ParserDiagnostic,
            "record 77 [file_name]: invalid attribute",
        );

        let events = diagnostics.lock().unwrap();
        assert_eq!(events.len(), TRUNCATION_REASON_LIMIT + 11);
        assert_eq!(
            events.last().unwrap().kind,
            JobDiagnosticKind::ParserDiagnostic
        );
        assert!(events.iter().any(|event| event.message == "reason-24"));
        assert_eq!(
            tracker.snapshot().diagnostic_event_count,
            events.len() as u64
        );
        assert_eq!(
            tracker.snapshot().truncation_reasons.len(),
            TRUNCATION_REASON_LIMIT
        );
        assert_eq!(tracker.snapshot().truncation_reasons_omitted, 9);
    }

    #[test]
    fn stage_transitions_retain_per_stage_elapsed_times() {
        let clock = Arc::new(FakeClock::default());
        let tracker = tracker(clock.clone());
        tracker.start_stage("Inventory", 1, Some(2), "entries", None);
        clock.advance_ms(1_250);
        tracker.start_stage("Finalization", 2, Some(2), "steps", Some(1));
        clock.advance_ms(750);
        tracker.finish(JobProgressState::Complete);
        assert_eq!(
            tracker.snapshot().completed_stages,
            vec![
                CompletedStageProgress {
                    name: "Inventory".to_string(),
                    stage_index: 1,
                    elapsed_ms: 1_250,
                },
                CompletedStageProgress {
                    name: "Finalization".to_string(),
                    stage_index: 2,
                    elapsed_ms: 750,
                },
            ]
        );
        assert_eq!(tracker.snapshot().elapsed_ms, 2_000);
    }

    #[test]
    fn current_object_preserves_canonical_names_and_recent_list_is_bounded() {
        let clock = Arc::new(FakeClock::default());
        let progress = tracker(clock);
        progress.start_stage("Inventory", 1, Some(1), "entries", None);
        let canonical = "/Image Analysis/Volumes/003/$MFT:$DATA";
        progress.advance(1, Some(canonical.to_string()));
        for item in ["two", "three", "four", "five"] {
            progress.advance(1, Some(item.to_string()));
        }
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.current_object.as_deref(), Some("five"));
        assert_eq!(snapshot.recently_processed, vec!["four", "three", "two"]);

        let exact_tracker = tracker(Arc::new(FakeClock::default()));
        exact_tracker.start_stage("Inventory", 1, Some(1), "entries", None);
        exact_tracker.advance(1, Some(canonical.to_string()));
        assert_eq!(
            exact_tracker.snapshot().current_object.as_deref(),
            Some(canonical)
        );
    }

    #[test]
    fn truncation_reason_sample_is_bounded_and_reports_omissions() {
        let progress = tracker(Arc::new(FakeClock::default()));
        for index in 0..TRUNCATION_REASON_LIMIT + 3 {
            progress.record_truncation(format!("reason-{index:02}"));
        }
        // A duplicate retained reason is counted as a report, but its text is
        // already represented and therefore is not an omitted diagnostic.
        progress.record_truncation("reason-00");

        let snapshot = progress.snapshot();
        assert_eq!(snapshot.truncation_reasons.len(), TRUNCATION_REASON_LIMIT);
        assert_eq!(
            snapshot.truncation_reason_count,
            (TRUNCATION_REASON_LIMIT + 4) as u64
        );
        assert_eq!(snapshot.truncation_reasons_omitted, 3);
        assert_eq!(snapshot.truncation_reasons.first().unwrap(), "reason-00");
        assert_eq!(snapshot.truncation_reasons.last().unwrap(), "reason-15");
    }
}
