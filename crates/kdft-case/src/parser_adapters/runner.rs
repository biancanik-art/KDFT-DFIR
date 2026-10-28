//! Bounded, offline-by-policy process runner for locked parser adapters.
//!
//! The runner performs no tool discovery and never downloads or updates a
//! parser. It verifies an examiner-accepted tool lock immediately before
//! launch, clears the child environment, passes discrete argv directly to the
//! operating system, captures bounded stdout/stderr prefixes, monitors output
//! growth, and verifies the installation again after the process exits.
//!
//! OS-level network isolation is not available through Rust's safe standard
//! library. `ToolLock::network_allowed == false` is therefore an enforced KDFT
//! policy and command/profile constraint, not a firewall claim. Callers must
//! disclose that limitation until the desktop worker supplies an audited OS
//! sandbox.

use super::contract::{
    validate_nonempty, validate_sha256, ExecutableIdentity, LockedCommand, StagedInput, ToolLock,
};
use super::manifest::{
    BoundedRunOutcome, RunLimitKind, RunLimits, RunTermination, TerminationCapability,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CAPTURE_BUFFER_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunDirectoryPrivacy {
    /// Unix mode 0700 was applied to the run, staging, and output directories.
    UnixOwnerOnly0700,
    /// Windows inherited the ACL of the examiner-selected parent directory.
    /// This is isolated per run but is not an independent ACL-hardening claim.
    InheritedPlatformAcl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedRunDirectory {
    pub root: PathBuf,
    pub staging: PathBuf,
    pub output: PathBuf,
    pub stdout_capture: PathBuf,
    pub stderr_capture: PathBuf,
    pub privacy: RunDirectoryPrivacy,
}

impl PreparedRunDirectory {
    fn validate(&self) -> Result<()> {
        for (label, path) in [
            ("run root", &self.root),
            ("staging directory", &self.staging),
            ("output directory", &self.output),
            ("stdout capture", &self.stdout_capture),
            ("stderr capture", &self.stderr_capture),
        ] {
            if !path.is_absolute() {
                bail!("prepared {label} path must be absolute");
            }
        }
        if self.staging.parent() != Some(self.root.as_path())
            || self.output.parent() != Some(self.root.as_path())
            || self.stdout_capture.parent() != Some(self.root.as_path())
            || self.stderr_capture.parent() != Some(self.root.as_path())
        {
            bail!("prepared run paths must be direct children of the run root");
        }
        if !self.root.is_dir() || !self.staging.is_dir() || !self.output.is_dir() {
            bail!("prepared run directory is incomplete or no longer available");
        }
        Ok(())
    }
}

/// Creates a fresh run directory and refuses to reuse an existing one.
pub fn prepare_run_directory(base: &Path, run_id: &str) -> Result<PreparedRunDirectory> {
    if !base.is_absolute() {
        bail!("parser run base directory must be absolute");
    }
    validate_run_id(run_id)?;
    fs::create_dir_all(base)
        .with_context(|| format!("creating parser run base directory {}", base.display()))?;
    let root = base.join(run_id);
    create_private_directory(&root).with_context(|| {
        format!(
            "creating fresh parser run directory {}; existing directories are never reused",
            root.display()
        )
    })?;
    let staging = root.join("staging");
    let output = root.join("output");
    create_private_directory(&staging)
        .with_context(|| format!("creating parser staging directory {}", staging.display()))?;
    create_private_directory(&output)
        .with_context(|| format!("creating parser output directory {}", output.display()))?;

    #[cfg(unix)]
    let privacy = RunDirectoryPrivacy::UnixOwnerOnly0700;

    #[cfg(not(unix))]
    let privacy = RunDirectoryPrivacy::InheritedPlatformAcl;

    Ok(PreparedRunDirectory {
        stdout_capture: root.join("stdout.raw"),
        stderr_capture: root.join("stderr.raw"),
        root,
        staging,
        output,
        privacy,
    })
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageFileRequest {
    pub logical_name: String,
    pub source_path: PathBuf,
    /// Exact expected hash recorded before this processing run.
    pub expected_sha256: String,
    /// Single filename to create inside the private staging directory.
    pub staged_name: String,
}

/// Copies a source into the private run directory without modifying the source
/// and verifies the bytes while they are copied.
pub fn stage_input_copy(
    prepared: &PreparedRunDirectory,
    request: &StageFileRequest,
) -> Result<StagedInput> {
    prepared.validate()?;
    validate_nonempty("staged input logical name", &request.logical_name)?;
    validate_sha256("expected staged input SHA-256", &request.expected_sha256)?;
    if !request.source_path.is_absolute() || !request.source_path.is_file() {
        bail!("staged input source must be an existing absolute file path");
    }
    validate_single_filename(&request.staged_name)?;
    let destination = prepared.staging.join(&request.staged_name);
    let mut source = File::open(&request.source_path)
        .with_context(|| format!("opening parser input {}", request.source_path.display()))?;
    let mut staged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .with_context(|| format!("creating staged parser input {}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .with_context(|| format!("reading parser input {}", request.source_path.display()))?;
        if read == 0 {
            break;
        }
        staged
            .write_all(&buffer[..read])
            .with_context(|| format!("writing staged parser input {}", destination.display()))?;
        hasher.update(&buffer[..read]);
        size_bytes = size_bytes.saturating_add(read as u64);
    }
    staged
        .sync_all()
        .with_context(|| format!("flushing staged parser input {}", destination.display()))?;
    let observed = format!("{:x}", hasher.finalize());
    if observed != request.expected_sha256 {
        drop(staged);
        let _ = fs::remove_file(&destination);
        bail!("staged parser input SHA-256 does not match the expected source hash");
    }
    Ok(StagedInput {
        logical_name: request.logical_name.clone(),
        staged_path: destination,
        source_sha256: observed.clone(),
        staged_sha256: observed,
        size_bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedToolInstallation {
    pub executable: ExecutableIdentity,
    pub companions: BTreeMap<String, ExecutableIdentity>,
}

/// Verifies the exact executable and every result-affecting companion before
/// launch. Missing, extra, symlinked, or mismatched companion paths are refused.
pub fn verify_tool_installation(
    lock: &ToolLock,
    companion_paths: &BTreeMap<String, PathBuf>,
) -> Result<VerifiedToolInstallation> {
    lock.validate()?;
    let executable = hash_locked_file(&lock.executable.path, "locked executable")?;
    lock.verify_observed_executable(&executable.path, &executable.sha256, executable.size_bytes)?;

    let expected_names = lock.companion_sha256.keys().collect::<BTreeSet<_>>();
    let supplied_names = companion_paths.keys().collect::<BTreeSet<_>>();
    if expected_names != supplied_names {
        bail!("configured companion paths do not exactly match the accepted tool lock");
    }
    let mut companions = BTreeMap::new();
    for (name, expected_sha256) in &lock.companion_sha256 {
        let path = companion_paths
            .get(name)
            .ok_or_else(|| anyhow!("missing locked companion path"))?;
        let identity = hash_locked_file(path, "locked companion")?;
        if identity.sha256 != *expected_sha256 {
            bail!("configured companion SHA-256 does not match the accepted tool lock");
        }
        companions.insert(name.clone(), identity);
    }
    Ok(VerifiedToolInstallation {
        executable,
        companions,
    })
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct RunnerRequest<'a> {
    pub lock: &'a ToolLock,
    pub command: &'a LockedCommand,
    pub companion_paths: &'a BTreeMap<String, PathBuf>,
    pub prepared: &'a PreparedRunDirectory,
    pub limits: &'a RunLimits,
    pub cancellation: &'a CancellationToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedStream {
    pub path: PathBuf,
    pub sha256: String,
    /// Bytes retained in the capture file. When `truncated` is true, this is a
    /// bounded prefix and the digest is explicitly the digest of that prefix.
    pub captured_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserRunExecution {
    pub run_directory: PreparedRunDirectory,
    pub installation: VerifiedToolInstallation,
    pub installation_stable_after_run: bool,
    pub minimal_environment_keys: Vec<String>,
    /// False until an OS firewall/sandbox implementation is added. The tool
    /// lock and adapter profile still prohibit network-enabled switches.
    pub os_network_isolation_enforced: bool,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub output_sha256: BTreeMap<String, String>,
    pub output_scan_complete: bool,
    pub outcome: BoundedRunOutcome,
}

/// Verifies and launches a locked parser. No shell is involved and the caller
/// cannot provide arbitrary environment variables.
pub fn execute_locked_parser(request: RunnerRequest<'_>) -> Result<ParserRunExecution> {
    request.prepared.validate()?;
    request.limits.validate()?;
    request.lock.validate_command(request.command)?;
    if request.command.working_directory != request.prepared.root {
        bail!("locked parser working directory must equal the fresh run directory");
    }
    ensure_directory_empty(&request.prepared.output)?;
    let installation = verify_tool_installation(request.lock, request.companion_paths)?;

    if request.cancellation.is_cancelled() {
        let stdout = create_empty_capture(&request.prepared.stdout_capture)?;
        let stderr = create_empty_capture(&request.prepared.stderr_capture)?;
        let outcome = BoundedRunOutcome {
            termination: RunTermination::Cancelled,
            process_started: false,
            exit_code: None,
            elapsed_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            output_file_count: 0,
            output_bytes: 0,
            imported_rows: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            termination_capability: TerminationCapability::DirectChildOnly,
            process_tree_termination_attempted: false,
            process_tree_terminated: false,
            limit_hit: None,
            diagnostics: vec!["parser run was cancelled before process launch".to_string()],
        };
        outcome.validate(request.limits)?;
        return Ok(ParserRunExecution {
            run_directory: request.prepared.clone(),
            installation,
            installation_stable_after_run: true,
            minimal_environment_keys: Vec::new(),
            os_network_isolation_enforced: false,
            stdout,
            stderr,
            output_sha256: BTreeMap::new(),
            output_scan_complete: true,
            outcome,
        });
    }

    let mut command = Command::new(&request.command.program);
    command
        .args(&request.command.argv)
        .current_dir(&request.command.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let minimal_environment_keys = apply_minimal_environment(&mut command, request.prepared);
    let termination_capability = configure_process_group(&mut command);

    let started = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let stdout = create_empty_capture(&request.prepared.stdout_capture)?;
            let stderr = create_empty_capture(&request.prepared.stderr_capture)?;
            let diagnostic = secret_safe_diagnostic("parser process could not be started", &error);
            return Ok(ParserRunExecution {
                run_directory: request.prepared.clone(),
                installation,
                installation_stable_after_run: true,
                minimal_environment_keys,
                os_network_isolation_enforced: false,
                stdout,
                stderr,
                output_sha256: BTreeMap::new(),
                output_scan_complete: true,
                outcome: BoundedRunOutcome {
                    termination: RunTermination::SpawnFailed,
                    process_started: false,
                    exit_code: None,
                    elapsed_ms: elapsed_ms(started.elapsed()),
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    output_file_count: 0,
                    output_bytes: 0,
                    imported_rows: 0,
                    stdout_truncated: false,
                    stderr_truncated: false,
                    termination_capability,
                    process_tree_termination_attempted: false,
                    process_tree_terminated: false,
                    limit_hit: None,
                    diagnostics: vec![diagnostic],
                },
            });
        }
    };

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("locked parser stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("locked parser stderr pipe was unavailable"))?;
    let stdout_limit_hit = Arc::new(AtomicBool::new(false));
    let stderr_limit_hit = Arc::new(AtomicBool::new(false));
    let stdout_thread = capture_stream(
        stdout,
        request.prepared.stdout_capture.clone(),
        request.limits.stdout_bytes,
        Arc::clone(&stdout_limit_hit),
    );
    let stderr_thread = capture_stream(
        stderr,
        request.prepared.stderr_capture.clone(),
        request.limits.stderr_bytes,
        Arc::clone(&stderr_limit_hit),
    );

    let mut forced_termination = None::<(RunTermination, Option<RunLimitKind>)>;
    let mut termination_attempted = false;
    let mut process_tree_terminated = false;
    let mut diagnostics = Vec::new();
    let exit_status = loop {
        if request.cancellation.is_cancelled() {
            forced_termination = Some((RunTermination::Cancelled, None));
        } else if stdout_limit_hit.load(Ordering::SeqCst) {
            forced_termination = Some((
                RunTermination::LimitExceeded,
                Some(RunLimitKind::StdoutBytes),
            ));
        } else if stderr_limit_hit.load(Ordering::SeqCst) {
            forced_termination = Some((
                RunTermination::LimitExceeded,
                Some(RunLimitKind::StderrBytes),
            ));
        } else if started.elapsed().as_millis() >= u128::from(request.limits.wall_time_ms) {
            forced_termination = Some((RunTermination::TimedOut, None));
        } else {
            match scan_output_usage(&request.prepared.output) {
                Ok(usage) if usage.file_count > request.limits.output_files => {
                    forced_termination = Some((
                        RunTermination::LimitExceeded,
                        Some(RunLimitKind::OutputFiles),
                    ));
                }
                Ok(usage) if usage.bytes > request.limits.output_bytes => {
                    forced_termination = Some((
                        RunTermination::LimitExceeded,
                        Some(RunLimitKind::OutputBytes),
                    ));
                }
                Ok(_) => {}
                Err(error) => {
                    forced_termination = Some((RunTermination::ExitFailure, None));
                    diagnostics.push(secret_safe_diagnostic(
                        "parser output directory could not be monitored",
                        &error,
                    ));
                }
            }
        }

        if forced_termination.is_some() {
            termination_attempted = true;
            let result = terminate_process(&mut child, termination_capability);
            process_tree_terminated = result.process_tree_terminated;
            if let Some(diagnostic) = result.diagnostic {
                diagnostics.push(diagnostic);
            }
            break child
                .wait()
                .context("waiting for interrupted locked parser")?;
        }
        if let Some(status) = child.try_wait().context("polling locked parser")? {
            break status;
        }
        thread::sleep(POLL_INTERVAL);
    };

    let stdout = join_capture(stdout_thread, "stdout")?;
    let stderr = join_capture(stderr_thread, "stderr")?;
    let final_usage = scan_output_usage(&request.prepared.output);
    let (output_file_count, output_bytes, output_scan_complete) = match final_usage {
        Ok(usage) => (usage.file_count, usage.bytes, true),
        Err(error) => {
            diagnostics.push(secret_safe_diagnostic(
                "parser output directory could not be inventoried",
                &error,
            ));
            (0, 0, false)
        }
    };

    if forced_termination.is_none() {
        if stdout.truncated {
            forced_termination = Some((
                RunTermination::LimitExceeded,
                Some(RunLimitKind::StdoutBytes),
            ));
        } else if stderr.truncated {
            forced_termination = Some((
                RunTermination::LimitExceeded,
                Some(RunLimitKind::StderrBytes),
            ));
        } else if output_file_count > request.limits.output_files {
            forced_termination = Some((
                RunTermination::LimitExceeded,
                Some(RunLimitKind::OutputFiles),
            ));
        } else if output_bytes > request.limits.output_bytes {
            forced_termination = Some((
                RunTermination::LimitExceeded,
                Some(RunLimitKind::OutputBytes),
            ));
        }
    }

    let mut installation_stable_after_run = true;
    if verify_tool_installation(request.lock, request.companion_paths).is_err() {
        installation_stable_after_run = false;
        diagnostics.push(
            "tool installation identity changed between pre-run and post-run verification"
                .to_string(),
        );
        if forced_termination.is_none() {
            forced_termination = Some((RunTermination::IntegrityFailure, None));
        }
    }

    let (output_sha256, output_hash_complete) =
        match hash_output_files(&request.prepared.output, request.limits) {
            Ok(hashes) => (hashes, true),
            Err(error) => {
                diagnostics.push(secret_safe_diagnostic(
                    "parser output hashes could not be completed",
                    &error,
                ));
                if forced_termination.is_none() {
                    forced_termination = Some((RunTermination::ExitFailure, None));
                }
                (BTreeMap::new(), false)
            }
        };

    let (termination, limit_hit) = forced_termination.unwrap_or_else(|| {
        if exit_status.success() {
            (RunTermination::Completed, None)
        } else {
            (RunTermination::ExitFailure, None)
        }
    });
    let outcome = BoundedRunOutcome {
        termination,
        process_started: true,
        exit_code: exit_status.code(),
        elapsed_ms: elapsed_ms(started.elapsed()),
        stdout_bytes: stdout.captured_bytes,
        stderr_bytes: stderr.captured_bytes,
        output_file_count,
        output_bytes,
        imported_rows: 0,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        termination_capability,
        process_tree_termination_attempted: termination_attempted,
        process_tree_terminated,
        limit_hit,
        diagnostics,
    };
    outcome.validate(request.limits)?;

    Ok(ParserRunExecution {
        run_directory: request.prepared.clone(),
        installation,
        installation_stable_after_run,
        minimal_environment_keys,
        os_network_isolation_enforced: false,
        stdout,
        stderr,
        output_sha256,
        output_scan_complete: output_scan_complete && output_hash_complete,
        outcome,
    })
}

fn capture_stream<R: Read + Send + 'static>(
    mut reader: R,
    path: PathBuf,
    limit: u64,
    limit_hit: Arc<AtomicBool>,
) -> JoinHandle<Result<CapturedStream>> {
    thread::spawn(move || {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating bounded stream capture {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut captured = 0_u64;
        let mut truncated = false;
        let mut buffer = vec![0_u8; CAPTURE_BUFFER_BYTES];
        loop {
            let read = reader
                .read(&mut buffer)
                .with_context(|| format!("reading parser stream for {}", path.display()))?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(captured);
            let retain = usize::try_from(remaining.min(read as u64)).unwrap_or(0);
            if retain > 0 {
                output.write_all(&buffer[..retain]).with_context(|| {
                    format!("writing bounded stream capture {}", path.display())
                })?;
                hasher.update(&buffer[..retain]);
                captured = captured.saturating_add(retain as u64);
            }
            if retain < read {
                truncated = true;
                limit_hit.store(true, Ordering::SeqCst);
            }
        }
        output
            .flush()
            .with_context(|| format!("flushing bounded stream capture {}", path.display()))?;
        Ok(CapturedStream {
            path,
            sha256: format!("{:x}", hasher.finalize()),
            captured_bytes: captured,
            truncated,
        })
    })
}

fn join_capture(
    handle: JoinHandle<Result<CapturedStream>>,
    stream_name: &str,
) -> Result<CapturedStream> {
    handle
        .join()
        .map_err(|_| anyhow!("{stream_name} capture worker panicked"))?
}

fn create_empty_capture(path: &Path) -> Result<CapturedStream> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating empty parser stream capture {}", path.display()))?;
    Ok(CapturedStream {
        path: path.to_path_buf(),
        sha256: format!("{:x}", Sha256::digest([])),
        captured_bytes: 0,
        truncated: false,
    })
}

#[derive(Debug, Clone, Copy)]
struct OutputUsage {
    file_count: u64,
    bytes: u64,
}

fn scan_output_usage(root: &Path) -> Result<OutputUsage> {
    let mut usage = OutputUsage {
        file_count: 0,
        bytes: 0,
    };
    walk_regular_output_files(root, |_, metadata| {
        usage.file_count = usage.file_count.saturating_add(1);
        usage.bytes = usage.bytes.saturating_add(metadata.len());
        Ok(())
    })?;
    Ok(usage)
}

fn hash_output_files(root: &Path, limits: &RunLimits) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    let mut total_bytes = 0_u64;
    walk_regular_output_files(root, |path, metadata| {
        if hashes.len() as u64 >= limits.output_files {
            bail!("parser output file count exceeded the hashing bound");
        }
        total_bytes = total_bytes.saturating_add(metadata.len());
        if total_bytes > limits.output_bytes {
            bail!("parser output bytes exceeded the hashing bound");
        }
        let relative = path
            .strip_prefix(root)
            .context("normalizing parser output path")?
            .to_string_lossy()
            .replace('\\', "/");
        hashes.insert(relative, hash_file(path)?.sha256);
        Ok(())
    })?;
    Ok(hashes)
}

fn walk_regular_output_files<F>(root: &Path, mut visit: F) -> Result<()>
where
    F: FnMut(&Path, &fs::Metadata) -> Result<()>,
{
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("reading parser output directory {}", directory.display()))?
        {
            let entry = entry.context("reading parser output directory entry")?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("reading parser output metadata {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                bail!("parser output may not contain symbolic links or reparse links");
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                visit(&path, &metadata)?;
            }
        }
    }
    Ok(())
}

fn hash_locked_file(path: &Path, label: &str) -> Result<ExecutableIdentity> {
    if !path.is_absolute() {
        bail!("{label} path must be absolute");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} must be a regular non-symlink file");
    }
    let mut identity = hash_file(path)?;
    identity.size_bytes = metadata.len();
    Ok(identity)
}

fn hash_file(path: &Path) -> Result<ExecutableIdentity> {
    let mut file =
        File::open(path).with_context(|| format!("opening file for SHA-256 {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hashing file {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size_bytes = size_bytes.saturating_add(read as u64);
    }
    Ok(ExecutableIdentity {
        path: path.to_path_buf(),
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes,
    })
}

fn apply_minimal_environment(
    command: &mut Command,
    prepared: &PreparedRunDirectory,
) -> Vec<String> {
    command.env_clear();
    let mut keys = Vec::new();
    #[cfg(windows)]
    {
        for key in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
                keys.push(key.to_string());
            }
        }
        command.env("TEMP", &prepared.root);
        command.env("TMP", &prepared.root);
        keys.extend(["TEMP".to_string(), "TMP".to_string()]);
    }
    #[cfg(not(windows))]
    {
        command.env("TMPDIR", &prepared.root);
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        command.env("TZ", "UTC");
        keys.extend([
            "TMPDIR".to_string(),
            "LANG".to_string(),
            "LC_ALL".to_string(),
            "TZ".to_string(),
        ]);
    }
    keys.sort();
    keys.dedup();
    keys
}

#[cfg(windows)]
fn configure_process_group(command: &mut Command) -> TerminationCapability {
    use std::os::windows::process::CommandExt;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    TerminationCapability::WindowsTaskkillTree
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) -> TerminationCapability {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    TerminationCapability::PosixProcessGroup
}

#[cfg(not(any(windows, unix)))]
fn configure_process_group(_command: &mut Command) -> TerminationCapability {
    TerminationCapability::DirectChildOnly
}

struct TerminationResult {
    process_tree_terminated: bool,
    diagnostic: Option<String>,
}

#[cfg(windows)]
fn terminate_process(child: &mut Child, _capability: TerminationCapability) -> TerminationResult {
    let taskkill = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32").join("taskkill.exe"));
    if let Some(taskkill) = taskkill.filter(|path| path.is_file()) {
        let status = Command::new(taskkill)
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok_and(|status| status.success()) {
            return TerminationResult {
                process_tree_terminated: true,
                diagnostic: None,
            };
        }
    }
    let direct = child.kill();
    TerminationResult {
        process_tree_terminated: false,
        diagnostic: Some(if direct.is_ok() {
            "Windows process-tree termination was unavailable; only the direct parser process was stopped"
                .to_string()
        } else {
            "Windows process-tree termination and direct-child termination both failed".to_string()
        }),
    }
}

#[cfg(unix)]
fn terminate_process(child: &mut Child, _capability: TerminationCapability) -> TerminationResult {
    let group = format!("-{}", child.id());
    let kill_program = [Path::new("/bin/kill"), Path::new("/usr/bin/kill")]
        .into_iter()
        .find(|path| path.is_file());
    if let Some(kill_program) = kill_program {
        let status = Command::new(kill_program)
            .args(["-KILL", "--", &group])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok_and(|status| status.success()) {
            return TerminationResult {
                process_tree_terminated: true,
                diagnostic: None,
            };
        }
    }
    let direct = child.kill();
    TerminationResult {
        process_tree_terminated: false,
        diagnostic: Some(if direct.is_ok() {
            "POSIX process-group termination was unavailable; only the direct parser process was stopped"
                .to_string()
        } else {
            "POSIX process-group termination and direct-child termination both failed".to_string()
        }),
    }
}

#[cfg(not(any(windows, unix)))]
fn terminate_process(child: &mut Child, _capability: TerminationCapability) -> TerminationResult {
    let direct = child.kill();
    TerminationResult {
        process_tree_terminated: false,
        diagnostic: Some(if direct.is_ok() {
            "this platform supports direct-child termination only".to_string()
        } else {
            "direct-child termination failed on this platform".to_string()
        }),
    }
}

fn ensure_directory_empty(path: &Path) -> Result<()> {
    if fs::read_dir(path)
        .with_context(|| format!("reading parser output directory {}", path.display()))?
        .next()
        .is_some()
    {
        bail!("fresh parser output directory must be empty before launch");
    }
    Ok(())
}

fn validate_run_id(value: &str) -> Result<()> {
    validate_nonempty("parser run id", value)?;
    if value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("parser run id contains unsupported path characters");
    }
    Ok(())
}

fn validate_single_filename(value: &str) -> Result<()> {
    validate_nonempty("staged filename", value)?;
    let path = Path::new(value);
    if matches!(value, "." | "..")
        || path.components().count() != 1
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("staged filename must be one normal path component");
    }
    Ok(())
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn secret_safe_diagnostic(prefix: &str, _error: &dyn std::fmt::Display) -> String {
    // OS and filesystem errors can contain arbitrary paths or other caller-
    // controlled text. Pattern-based secret detection is not sufficient to
    // safely persist that text in a run manifest.
    prefix.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct FixtureDirectory(PathBuf);

    impl FixtureDirectory {
        fn new(label: &str) -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "kdft-parser-runner-{label}-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn lock_for(executable: &Path, allowed_switches: &[&str]) -> ToolLock {
        let identity = hash_locked_file(executable, "test executable").unwrap();
        ToolLock {
            adapter_id: "fixture-parser-v1".to_string(),
            parser_name: "KDFT test harness fixture".to_string(),
            parser_version: "1".to_string(),
            source_repository: "local-test-fixture".to_string(),
            source_commit: "test-fixture".to_string(),
            executable: identity,
            companion_sha256: BTreeMap::new(),
            allowed_switches: allowed_switches
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            network_allowed: false,
        }
    }

    fn generous_limits() -> RunLimits {
        RunLimits {
            wall_time_ms: 30_000,
            stdout_bytes: 4 * 1024 * 1024,
            stderr_bytes: 4 * 1024 * 1024,
            output_files: 10,
            output_bytes: 4 * 1024 * 1024,
            imported_rows: 100,
        }
    }

    #[test]
    fn fresh_run_directory_refuses_reuse_and_stages_a_verified_copy() {
        let fixture = FixtureDirectory::new("stage");
        let source = fixture.0.join("source.bin");
        fs::write(&source, b"forensic fixture").unwrap();
        let source_identity = hash_file(&source).unwrap();
        let runs = fixture.0.join("runs");
        fs::create_dir(&runs).unwrap();
        let prepared = prepare_run_directory(&runs, "run-1").unwrap();
        assert!(prepare_run_directory(&runs, "run-1").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&prepared.root, &prepared.staging, &prepared.output] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
        let staged = stage_input_copy(
            &prepared,
            &StageFileRequest {
                logical_name: "primary".to_string(),
                source_path: source,
                expected_sha256: source_identity.sha256,
                staged_name: "source.bin".to_string(),
            },
        )
        .unwrap();
        staged.validate().unwrap();
        assert!(staged.staged_path.starts_with(&prepared.staging));
    }

    #[test]
    fn tool_verification_rejects_a_changed_companion() {
        let fixture = FixtureDirectory::new("companion");
        let executable = std::env::current_exe().unwrap();
        let companion = fixture.0.join("Maps.json");
        fs::write(&companion, b"locked maps").unwrap();
        let companion_hash = hash_file(&companion).unwrap().sha256;
        let mut lock = lock_for(&executable, &[]);
        lock.companion_sha256
            .insert("maps".to_string(), companion_hash);
        let paths = [("maps".to_string(), companion.clone())]
            .into_iter()
            .collect();
        verify_tool_installation(&lock, &paths).unwrap();
        fs::write(&companion, b"changed maps").unwrap();
        assert!(verify_tool_installation(&lock, &paths).is_err());
    }

    #[test]
    fn persisted_runner_diagnostics_do_not_echo_error_text() {
        let error = anyhow!("credential=unrecognized-secret-value");
        assert_eq!(
            secret_safe_diagnostic("parser failed", &error),
            "parser failed"
        );
    }

    #[test]
    fn runner_executes_only_the_locked_program_with_bounded_capture() {
        let fixture = FixtureDirectory::new("execute");
        let runs = fixture.0.join("runs");
        fs::create_dir(&runs).unwrap();
        let prepared = prepare_run_directory(&runs, "run-1").unwrap();
        let executable = std::env::current_exe().unwrap();
        let lock = lock_for(&executable, &["--list"]);
        let command = LockedCommand {
            program: executable,
            argv: vec!["--list".to_string()],
            working_directory: prepared.root.clone(),
        };
        let companions = BTreeMap::new();
        let cancellation = CancellationToken::new();
        let limits = generous_limits();
        let execution = execute_locked_parser(RunnerRequest {
            lock: &lock,
            command: &command,
            companion_paths: &companions,
            prepared: &prepared,
            limits: &limits,
            cancellation: &cancellation,
        })
        .unwrap();
        assert_eq!(execution.outcome.termination, RunTermination::Completed);
        assert_eq!(execution.outcome.exit_code, Some(0));
        assert!(execution.stdout.captured_bytes > 0);
        validate_sha256("stdout hash", &execution.stdout.sha256).unwrap();
        assert!(!execution.os_network_isolation_enforced);
        assert!(execution.output_scan_complete);
    }

    #[test]
    fn pre_cancelled_run_records_cancellation_without_launching() {
        let fixture = FixtureDirectory::new("cancel");
        let runs = fixture.0.join("runs");
        fs::create_dir(&runs).unwrap();
        let prepared = prepare_run_directory(&runs, "run-1").unwrap();
        let executable = std::env::current_exe().unwrap();
        let lock = lock_for(&executable, &["--ignored", "--exact"]);
        let command = LockedCommand {
            program: executable,
            argv: vec![
                "--ignored".to_string(),
                "--exact".to_string(),
                "parser_adapters::runner::tests::fixture_child_waits".to_string(),
            ],
            working_directory: prepared.root.clone(),
        };
        let companions = BTreeMap::new();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let limits = generous_limits();
        let execution = execute_locked_parser(RunnerRequest {
            lock: &lock,
            command: &command,
            companion_paths: &companions,
            prepared: &prepared,
            limits: &limits,
            cancellation: &cancellation,
        })
        .unwrap();
        assert_eq!(execution.outcome.termination, RunTermination::Cancelled);
        assert!(!execution.outcome.process_started);
        assert!(!execution.outcome.process_tree_termination_attempted);
    }

    #[test]
    fn timeout_attempts_process_tree_termination() {
        let fixture = FixtureDirectory::new("timeout");
        let runs = fixture.0.join("runs");
        fs::create_dir(&runs).unwrap();
        let prepared = prepare_run_directory(&runs, "run-1").unwrap();
        let executable = std::env::current_exe().unwrap();
        let lock = lock_for(&executable, &["--ignored", "--exact"]);
        let command = LockedCommand {
            program: executable,
            argv: vec![
                "--ignored".to_string(),
                "--exact".to_string(),
                "parser_adapters::runner::tests::fixture_child_waits".to_string(),
            ],
            working_directory: prepared.root.clone(),
        };
        let companions = BTreeMap::new();
        let cancellation = CancellationToken::new();
        let mut limits = generous_limits();
        limits.wall_time_ms = 200;
        let execution = execute_locked_parser(RunnerRequest {
            lock: &lock,
            command: &command,
            companion_paths: &companions,
            prepared: &prepared,
            limits: &limits,
            cancellation: &cancellation,
        })
        .unwrap();
        assert_eq!(execution.outcome.termination, RunTermination::TimedOut);
        assert!(execution.outcome.process_started);
        assert!(execution.outcome.process_tree_termination_attempted);
    }

    #[test]
    #[ignore = "runner-only child fixture"]
    fn fixture_child_waits() {
        thread::sleep(Duration::from_secs(10));
    }
}
