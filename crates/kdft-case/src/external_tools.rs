//! Optional, examiner-supplied forensic parser adapters.
//!
//! KDFT never invokes a shell, never downloads tools, and never updates tool
//! maps/plugins during evidence processing. A configured executable is hashed
//! and launched against a private working copy with bounded time and output.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DEFAULT_OUTPUT_LIMIT: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExternalToolRun {
    pub tool_path: String,
    pub tool_sha256: String,
    pub arguments: Vec<String>,
    pub exit_code: Option<i32>,
    pub status: String,
    pub elapsed_ms: u128,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub(crate) fn configured_tool(
    environment_variable: &str,
    candidate_names: &[&str],
) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(environment_variable).map(PathBuf::from) {
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            for name in candidate_names {
                for candidate in [parent.join(name), parent.join("tools").join(name)] {
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    let path_value = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path_value) {
        for name in candidate_names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("opening executable for hashing {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hashing executable {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn read_bounded(path: &Path, limit: u64) -> Result<(String, bool)> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading external parser output metadata {}", path.display()))?;
    let truncated = metadata.len() > limit;
    let file = fs::File::open(path)
        .with_context(|| format!("opening external parser output {}", path.display()))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len().min(limit)).unwrap_or(0));
    file.take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading external parser output {}", path.display()))?;
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

pub(crate) fn run_bounded<I, S>(
    tool_path: &Path,
    arguments: I,
    working_directory: &Path,
) -> Result<ExternalToolRun>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if !tool_path.is_file() {
        bail!(
            "configured external parser does not exist: {}",
            tool_path.display()
        );
    }
    fs::create_dir_all(working_directory).with_context(|| {
        format!(
            "creating external parser working directory {}",
            working_directory.display()
        )
    })?;
    let stdout_path = working_directory.join("kdft-external.stdout");
    let stderr_path = working_directory.join("kdft-external.stderr");
    let stdout_file = fs::File::create(&stdout_path)?;
    let stderr_file = fs::File::create(&stderr_path)?;
    let arguments = arguments
        .into_iter()
        .map(|value| value.as_ref().to_os_string())
        .collect::<Vec<OsString>>();
    let argument_text = arguments
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let started = Instant::now();
    let mut child = Command::new(tool_path)
        .args(&arguments)
        .current_dir(tool_path.parent().unwrap_or(working_directory))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .with_context(|| format!("starting external parser {}", tool_path.display()))?;
    let mut forced_status = None::<&str>;
    let exit = loop {
        if let Some(status) = child.try_wait().context("polling external parser")? {
            break status;
        }
        let output_bytes = fs::metadata(&stdout_path)
            .map(|value| value.len())
            .unwrap_or(0)
            + fs::metadata(&stderr_path)
                .map(|value| value.len())
                .unwrap_or(0);
        if output_bytes > DEFAULT_OUTPUT_LIMIT {
            forced_status = Some("output_limit");
            child
                .kill()
                .context("stopping external parser at output limit")?;
            break child
                .wait()
                .context("waiting for stopped external parser")?;
        }
        if started.elapsed() > DEFAULT_TIMEOUT {
            forced_status = Some("timeout");
            child.kill().context("stopping timed-out external parser")?;
            break child
                .wait()
                .context("waiting for timed-out external parser")?;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (stdout, stdout_truncated) = read_bounded(&stdout_path, DEFAULT_OUTPUT_LIMIT)?;
    let (stderr, stderr_truncated) = read_bounded(&stderr_path, DEFAULT_OUTPUT_LIMIT)?;
    let status = forced_status.map(ToString::to_string).unwrap_or_else(|| {
        if exit.success() {
            "completed"
        } else {
            "failed"
        }
        .to_string()
    });
    Ok(ExternalToolRun {
        tool_path: tool_path.display().to_string(),
        tool_sha256: sha256_file(tool_path)?,
        arguments: argument_text,
        exit_code: exit.code(),
        status,
        elapsed_ms: started.elapsed().as_millis(),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}
