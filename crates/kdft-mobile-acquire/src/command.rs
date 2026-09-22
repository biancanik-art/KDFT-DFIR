use std::ffi::OsStr;
use std::process::{Command, Output, Stdio};

use anyhow::{anyhow, Context, Result};

pub fn command_exists(name: &str) -> bool {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("where");
        c.arg(name);
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c")
            .arg(format!("command -v -- '{}'", name.replace('\'', "'\\''")));
        c
    };

    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn run_capture<I, S>(program: &str, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))
}

pub fn run_checked<I, S>(program: &str, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let out = run_capture(program, args)?;
    if !out.status.success() {
        return Err(anyhow!(
            "{} failed with status {:?}: {}",
            program,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out)
}

pub fn text_stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn format_command(program: &str, args: &[String]) -> String {
    let mut out = String::from(program);
    for arg in args {
        out.push(' ');
        if arg.contains(' ') {
            out.push('"');
            out.push_str(arg);
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}
