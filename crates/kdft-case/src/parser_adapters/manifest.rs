use super::contract::{
    validate_nonempty, validate_secret_safe_text, validate_sha256, AdapterDescriptor,
    ImportSummary, LockedCommand, SecretSafeConfiguration, StagedInput, ToolLock,
};
use anyhow::{bail, Result};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PARSER_RUN_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLimitKind {
    WallTime,
    StdoutBytes,
    StderrBytes,
    OutputFiles,
    OutputBytes,
    ImportedRows,
}

/// Per-run resource bounds. The runner must enforce these values and terminate
/// the complete process tree when a time/output limit or cancellation occurs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLimits {
    pub wall_time_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output_files: u64,
    pub output_bytes: u64,
    pub imported_rows: u64,
}

impl RunLimits {
    pub fn validate(&self) -> Result<()> {
        if self.wall_time_ms == 0
            || self.stdout_bytes == 0
            || self.stderr_bytes == 0
            || self.output_files == 0
            || self.output_bytes == 0
            || self.imported_rows == 0
        {
            bail!("every parser run limit must be greater than zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTermination {
    Completed,
    ExitFailure,
    IntegrityFailure,
    TimedOut,
    Cancelled,
    LimitExceeded,
    SpawnFailed,
}

/// Strongest process-tree termination mechanism available to the runner.
///
/// `DirectChildOnly` is an explicit limitation, not a claim that descendant
/// processes were stopped. KDFT's crate forbids unsafe code, so the Windows
/// implementation uses direct `taskkill.exe /T` when available rather than a
/// native Job Object until a safe audited wrapper is introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TerminationCapability {
    #[default]
    DirectChildOnly,
    WindowsTaskkillTree,
    PosixProcessGroup,
}

/// Bounded execution result. This is deliberately independent of a concrete
/// process runner, so the current browser service and a future desktop worker
/// can emit the same auditable manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedRunOutcome {
    pub termination: RunTermination,
    #[serde(default)]
    pub process_started: bool,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output_file_count: u64,
    pub output_bytes: u64,
    pub imported_rows: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    #[serde(default)]
    pub termination_capability: TerminationCapability,
    pub process_tree_termination_attempted: bool,
    pub process_tree_terminated: bool,
    pub limit_hit: Option<RunLimitKind>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

impl BoundedRunOutcome {
    pub fn validate(&self, limits: &RunLimits) -> Result<()> {
        limits.validate()?;
        if self.termination != RunTermination::LimitExceeded
            && (self.stdout_bytes > limits.stdout_bytes
                || self.stderr_bytes > limits.stderr_bytes
                || self.output_file_count > limits.output_files
                || self.output_bytes > limits.output_bytes
                || self.imported_rows > limits.imported_rows)
        {
            bail!("parser run outcome exceeds its declared resource bounds");
        }
        if self.termination == RunTermination::Completed && self.exit_code != Some(0) {
            bail!("completed parser run must have exit code zero");
        }
        if self.termination == RunTermination::Completed && !self.process_started {
            bail!("completed parser run must have started a process");
        }
        if self.termination == RunTermination::SpawnFailed && self.process_started {
            bail!("spawn-failed parser run cannot claim that the process started");
        }
        if self.termination == RunTermination::LimitExceeded && self.limit_hit.is_none() {
            bail!("limit-exceeded parser run must identify the limit that was hit");
        }
        if self.termination != RunTermination::LimitExceeded && self.limit_hit.is_some() {
            bail!("only a limit-exceeded parser run may identify a hit limit");
        }
        if self.process_tree_terminated && !self.process_tree_termination_attempted {
            bail!("process tree cannot be marked terminated when termination was not attempted");
        }
        if self.process_started
            && matches!(
                self.termination,
                RunTermination::TimedOut | RunTermination::Cancelled
            )
            && !self.process_tree_termination_attempted
        {
            bail!("timed-out or cancelled parser run must attempt termination");
        }
        if self.process_tree_termination_attempted
            && !self.process_tree_terminated
            && self.termination_capability != TerminationCapability::DirectChildOnly
            && self.diagnostics.is_empty()
        {
            bail!("failed process-tree termination requires a diagnostic");
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            validate_secret_safe_text(diagnostic, &format!("outcome.diagnostics[{index}]"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCoverageStatus {
    Complete,
    Partial,
    Failed,
    Cancelled,
    Unsupported,
    NotAttempted,
}

impl AdapterCoverageStatus {
    pub const fn requires_prominent_disclosure(self) -> bool {
        !matches!(self, Self::Complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCoverage {
    pub status: AdapterCoverageStatus,
    pub scope: String,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl AdapterCoverage {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty("adapter coverage scope", &self.scope)?;
        if self.status.requires_prominent_disclosure() && self.reasons.is_empty() {
            bail!("incomplete adapter coverage requires at least one disclosure reason");
        }
        for (index, reason) in self.reasons.iter().enumerate() {
            validate_nonempty("adapter coverage reason", reason)?;
            validate_secret_safe_text(reason, &format!("coverage.reasons[{index}]"))?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserRunManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub descriptor: AdapterDescriptor,
    pub tool_lock: ToolLock,
    pub parser_version_reported: Option<String>,
    pub command: LockedCommand,
    pub configuration: SecretSafeConfiguration,
    pub limits: RunLimits,
    pub started_at_utc: String,
    pub finished_at_utc: String,
    pub outcome: BoundedRunOutcome,
    #[serde(default)]
    pub inputs: BTreeMap<String, StagedInput>,
    /// Logical output name -> SHA-256.
    #[serde(default)]
    pub output_sha256: BTreeMap<String, String>,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub importer_schema: String,
    pub import_summary: ImportSummary,
    pub coverage: AdapterCoverage,
}

impl std::fmt::Debug for ParserRunManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParserRunManifest")
            .field("schema_version", &self.schema_version)
            .field("run_id", &self.run_id)
            .field("adapter_id", &self.descriptor.adapter_id)
            .field("parser_name", &self.tool_lock.parser_name)
            .field("command", &self.command)
            .field("input_count", &self.inputs.len())
            .field("output_count", &self.output_sha256.len())
            .field("outcome", &self.outcome.termination)
            .field("coverage", &self.coverage.status)
            .finish()
    }
}

impl ParserRunManifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PARSER_RUN_MANIFEST_SCHEMA_VERSION {
            bail!(
                "parser run manifest schema version must be {PARSER_RUN_MANIFEST_SCHEMA_VERSION}"
            );
        }
        validate_nonempty("parser run id", &self.run_id)?;
        self.descriptor.validate()?;
        self.tool_lock.validate_command(&self.command)?;
        if self.descriptor.adapter_id != self.tool_lock.adapter_id {
            bail!("adapter descriptor and tool lock ids do not match");
        }
        if self.descriptor.parser_name != self.tool_lock.parser_name {
            bail!("adapter descriptor and tool lock parser names do not match");
        }
        if self.importer_schema != self.descriptor.importer_schema {
            bail!("manifest importer schema does not match the adapter descriptor");
        }
        if let Some(reported) = &self.parser_version_reported {
            validate_nonempty("reported parser version", reported)?;
            if reported != &self.tool_lock.parser_version {
                bail!("reported parser version does not match the accepted tool lock");
            }
        }
        validate_utc_timestamp("started_at_utc", &self.started_at_utc)?;
        validate_utc_timestamp("finished_at_utc", &self.finished_at_utc)?;
        let started = DateTime::parse_from_rfc3339(&self.started_at_utc)?;
        let finished = DateTime::parse_from_rfc3339(&self.finished_at_utc)?;
        if finished < started {
            bail!("parser run finished before it started");
        }
        self.outcome.validate(&self.limits)?;
        for (name, input) in &self.inputs {
            validate_nonempty("input manifest logical name", name)?;
            input.validate()?;
        }
        for (name, sha256) in &self.output_sha256 {
            validate_nonempty("output manifest logical name", name)?;
            validate_sha256(&format!("output {name} SHA-256"), sha256)?;
        }
        validate_optional_stream_hash("stdout", self.outcome.stdout_bytes, &self.stdout_sha256)?;
        validate_optional_stream_hash("stderr", self.outcome.stderr_bytes, &self.stderr_sha256)?;
        validate_nonempty("manifest importer schema", &self.importer_schema)?;
        self.import_summary.validate()?;
        self.coverage.validate()?;
        if self.coverage.status == AdapterCoverageStatus::Complete
            && (self.outcome.termination != RunTermination::Completed
                || self.outcome.stdout_truncated
                || self.outcome.stderr_truncated
                || self.import_summary.rejected_rows > 0
                || self.import_summary.imported_rows < self.import_summary.emitted_rows)
        {
            bail!("complete coverage cannot hide execution, capture, or import gaps");
        }
        Ok(())
    }
}

fn validate_utc_timestamp(label: &str, value: &str) -> Result<()> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| anyhow::anyhow!("{label} must be an RFC 3339 timestamp"))?;
    if parsed.offset().local_minus_utc() != 0 {
        bail!("{label} must use a zero UTC offset");
    }
    Ok(())
}

fn validate_optional_stream_hash(label: &str, bytes: u64, hash: &Option<String>) -> Result<()> {
    match (bytes, hash) {
        (0, None) => Ok(()),
        (_, Some(hash)) => validate_sha256(&format!("{label} SHA-256"), hash),
        (_, None) => bail!("non-empty {label} capture requires a SHA-256"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser_adapters::ExecutableIdentity;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture_path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join("kdft-parser-adapter-manifest-tests")
            .join(name)
    }

    fn manifest() -> ParserRunManifest {
        let descriptor = AdapterDescriptor {
            adapter_id: "evtxecmd-json-v1".to_string(),
            adapter_schema_version: "1".to_string(),
            parser_name: "EvtxECmd".to_string(),
            importer_schema: "kdft.evtxecmd.v1".to_string(),
            supported_source_kinds: ["evtx".to_string()].into_iter().collect(),
            supported_artifact_kinds: ["windows_event_log_record".to_string()]
                .into_iter()
                .collect(),
        };
        let executable_path = fixture_path("EvtxECmd.exe");
        let run_directory = fixture_path("run");
        let executable = ExecutableIdentity {
            path: executable_path.clone(),
            sha256: SHA_A.to_string(),
            size_bytes: 10,
        };
        let tool_lock = ToolLock {
            adapter_id: descriptor.adapter_id.clone(),
            parser_name: descriptor.parser_name.clone(),
            parser_version: "2026.5.0".to_string(),
            source_repository: "https://github.com/EricZimmerman/evtx".to_string(),
            source_commit: "03a7a1fba32760f20841bea3c12099169f9ecf2d".to_string(),
            executable,
            companion_sha256: BTreeMap::new(),
            allowed_switches: ["-f", "--json", "--jsonf", "--fj"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
            network_allowed: false,
        };
        ParserRunManifest {
            schema_version: PARSER_RUN_MANIFEST_SCHEMA_VERSION,
            run_id: "run-1".to_string(),
            descriptor,
            tool_lock,
            parser_version_reported: Some("2026.5.0".to_string()),
            command: LockedCommand {
                program: executable_path,
                argv: vec![
                    "-f".to_string(),
                    fixture_path("stage-Security.evtx")
                        .to_string_lossy()
                        .into_owned(),
                    "--json".to_string(),
                    fixture_path("run-output").to_string_lossy().into_owned(),
                    "--jsonf".to_string(),
                    "events.json".to_string(),
                ],
                working_directory: run_directory,
            },
            configuration: SecretSafeConfiguration::empty(),
            limits: RunLimits {
                wall_time_ms: 60_000,
                stdout_bytes: 1_048_576,
                stderr_bytes: 1_048_576,
                output_files: 10,
                output_bytes: 10_000_000,
                imported_rows: 100_000,
            },
            started_at_utc: "2026-10-16T00:00:00Z".to_string(),
            finished_at_utc: "2026-10-16T00:00:01Z".to_string(),
            outcome: BoundedRunOutcome {
                termination: RunTermination::Completed,
                process_started: true,
                exit_code: Some(0),
                elapsed_ms: 1_000,
                stdout_bytes: 0,
                stderr_bytes: 0,
                output_file_count: 1,
                output_bytes: 512,
                imported_rows: 2,
                stdout_truncated: false,
                stderr_truncated: false,
                termination_capability: TerminationCapability::DirectChildOnly,
                process_tree_termination_attempted: false,
                process_tree_terminated: false,
                limit_hit: None,
                diagnostics: Vec::new(),
            },
            inputs: BTreeMap::new(),
            output_sha256: [("events.json".to_string(), SHA_A.to_string())]
                .into_iter()
                .collect(),
            stdout_sha256: None,
            stderr_sha256: None,
            importer_schema: "kdft.evtxecmd.v1".to_string(),
            import_summary: ImportSummary {
                emitted_rows: 2,
                imported_rows: 2,
                rejected_rows: 0,
                duplicate_rows: 0,
                linked_rows: 2,
            },
            coverage: AdapterCoverage {
                status: AdapterCoverageStatus::Complete,
                scope: "all EVTX records in staged source".to_string(),
                reasons: Vec::new(),
            },
        }
    }

    #[test]
    fn complete_manifest_validates() {
        manifest().validate().unwrap();
    }

    #[test]
    fn incomplete_coverage_requires_a_prominent_disclosure_reason() {
        let mut manifest = manifest();
        manifest.coverage.status = AdapterCoverageStatus::Partial;
        assert!(manifest.coverage.status.requires_prominent_disclosure());
        assert!(manifest.validate().is_err());
        manifest.coverage.reasons = vec!["one corrupt EVTX chunk was skipped".to_string()];
        manifest.validate().unwrap();
    }

    #[test]
    fn complete_coverage_rejects_silent_import_truncation() {
        let mut manifest = manifest();
        manifest.import_summary.emitted_rows = 3;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn interrupted_run_requires_process_tree_termination() {
        let mut outcome = manifest().outcome;
        outcome.termination = RunTermination::TimedOut;
        outcome.exit_code = None;
        assert!(outcome.validate(&manifest().limits).is_err());
        outcome.process_tree_termination_attempted = true;
        outcome.termination_capability = TerminationCapability::DirectChildOnly;
        outcome.validate(&manifest().limits).unwrap();
    }

    #[test]
    fn outcome_cannot_exceed_resource_bounds() {
        let manifest = manifest();
        let mut outcome = manifest.outcome;
        outcome.output_bytes = manifest.limits.output_bytes + 1;
        assert!(outcome.validate(&manifest.limits).is_err());
    }
}
