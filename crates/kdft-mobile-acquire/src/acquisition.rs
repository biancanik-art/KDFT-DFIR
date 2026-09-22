use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::Serialize;

use crate::android::{inspect_android, select_android_device};
use crate::command::{command_exists, format_command, run_capture};
use crate::hashing::hash_tree;
use crate::ios::{inspect_ios, select_ios_device};
use crate::models::{AcquisitionSummary, ActionRecord, DeviceInfo, ErrorRecord, Platform, Profile};

struct CasePaths {
    root: PathBuf,
    native: PathBuf,
    logs: PathBuf,
    actions: PathBuf,
    errors: PathBuf,
    manifest: PathBuf,
}

impl CasePaths {
    fn create(base: &Path, case_id: &str, evidence_id: &str) -> Result<Self> {
        let root = base.join(case_id).join(evidence_id);
        let native = root.join("native");
        let logs = root.join("logs");
        fs::create_dir_all(&native)?;
        fs::create_dir_all(&logs)?;
        Ok(Self {
            actions: root.join("actions.jsonl"),
            errors: root.join("errors.jsonl"),
            manifest: root.join("hashes.sha256"),
            root,
            native,
            logs,
        })
    }
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn log_action(
    paths: &CasePaths,
    action: &str,
    command: Option<String>,
    status: &str,
    detail: Option<String>,
) -> Result<()> {
    append_jsonl(
        &paths.actions,
        &ActionRecord {
            timestamp_utc: Utc::now().to_rfc3339(),
            action,
            command,
            status,
            detail,
        },
    )
}

fn log_error(paths: &CasePaths, stage: &str, err: &anyhow::Error) {
    let _ = append_jsonl(
        &paths.errors,
        &ErrorRecord {
            timestamp_utc: Utc::now().to_rfc3339(),
            stage,
            error: format!("{err:#}"),
        },
    );
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn capture_to_file(
    paths: &CasePaths,
    stage: &str,
    program: &str,
    args: &[String],
    destination: &Path,
) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let display = format_command(program, args);
    log_action(paths, stage, Some(display.clone()), "started", None)?;
    let result = run_capture(program, args.iter().map(String::as_str));
    match result {
        Ok(output) => {
            let mut file = File::create(destination)?;
            file.write_all(&output.stdout)?;
            if !output.stderr.is_empty() {
                file.write_all(b"\n--- STDERR ---\n")?;
                file.write_all(&output.stderr)?;
            }
            if output.status.success() {
                log_action(
                    paths,
                    stage,
                    Some(display),
                    "completed",
                    Some(format!("wrote {}", destination.display())),
                )?;
                Ok(())
            } else {
                let err = anyhow!("{program} exited with {:?}", output.status.code());
                log_error(paths, stage, &err);
                log_action(paths, stage, Some(display), "failed", Some(format!("{err:#}")))?;
                Err(err)
            }
        }
        Err(err) => {
            log_error(paths, stage, &err);
            log_action(paths, stage, Some(display), "failed", Some(format!("{err:#}")))?;
            Err(err)
        }
    }
}

fn run_logged(
    paths: &CasePaths,
    stage: &str,
    program: &str,
    args: &[String],
) -> Result<()> {
    let stdout_path = paths.logs.join(format!("{stage}.stdout.log"));
    let stderr_path = paths.logs.join(format!("{stage}.stderr.log"));
    let stdout = File::create(stdout_path)?;
    let stderr = File::create(stderr_path)?;
    let display = format_command(program, args);
    log_action(paths, stage, Some(display.clone()), "started", None)?;

    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .with_context(|| format!("failed to launch {program}"))?;

    if status.success() {
        log_action(paths, stage, Some(display), "completed", None)?;
        Ok(())
    } else {
        let err = anyhow!("{program} failed with status {:?}", status.code());
        log_error(paths, stage, &err);
        log_action(paths, stage, Some(display), "failed", Some(format!("{err:#}")))?;
        Err(err)
    }
}

fn finalize(
    paths: &CasePaths,
    started: chrono::DateTime<Utc>,
    case_id: &str,
    evidence_id: &str,
    examiner: &str,
    platform: Platform,
    profile: Profile,
    device_identifier: String,
    warnings: Vec<String>,
) -> Result<()> {
    let before_summary = hash_tree(&paths.root, &paths.manifest)?;
    let summary = AcquisitionSummary {
        tool: "KDFT Mobile Acquire".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        case_id: case_id.into(),
        evidence_id: evidence_id.into(),
        examiner: examiner.into(),
        platform,
        profile,
        device_identifier,
        started_utc: started.to_rfc3339(),
        ended_utc: Utc::now().to_rfc3339(),
        status: if warnings.is_empty() {
            "completed".into()
        } else {
            "completed_with_warnings".into()
        },
        output_directory: paths.root.display().to_string(),
        files_hashed: before_summary + 1,
        warnings,
    };
    write_json(&paths.root.join("acquisition.json"), &summary)?;
    let final_count = hash_tree(&paths.root, &paths.manifest)?;
    println!("Acquisition complete: {}", paths.root.display());
    println!("Files hashed: {final_count}");
    Ok(())
}

pub fn acquire_android(
    requested: Option<&str>,
    profile: Profile,
    case_id: &str,
    evidence_id: &str,
    examiner: &str,
    base: &Path,
) -> Result<()> {
    let serial = select_android_device(requested)?;
    let info = inspect_android(&serial)?;
    if info.pairing_or_adb_authorized != Some(true) {
        bail!("ADB is not authorized; acquisition will not attempt to change device trust/state");
    }

    let paths = CasePaths::create(base, case_id, evidence_id)?;
    let started = Utc::now();
    write_json(&paths.root.join("device.json"), &info)?;
    log_action(&paths, "acquisition", None, "started", Some(format!("android serial={serial} profile={profile:?}")))?;

    let android = paths.native.join("android");
    fs::create_dir_all(&android)?;
    let mut warnings = Vec::new();
    let adb_args = |tail: &[&str]| -> Vec<String> {
        let mut args = vec!["-s".into(), serial.clone()];
        args.extend(tail.iter().map(|s| (*s).to_string()));
        args
    };

    let collectors = [
        ("getprop", vec!["shell", "getprop"], "getprop.txt"),
        ("packages", vec!["shell", "pm", "list", "packages", "-f"], "packages.txt"),
        ("mounts", vec!["shell", "mount"], "mounts.txt"),
        ("df", vec!["shell", "df", "-h"], "df.txt"),
        ("users", vec!["shell", "dumpsys", "user"], "dumpsys_user.txt"),
        ("dumpsys", vec!["shell", "dumpsys"], "dumpsys.txt"),
        ("logcat", vec!["logcat", "-d", "-v", "threadtime"], "logcat.txt"),
    ];

    for (stage, tail, filename) in collectors {
        let args = adb_args(&tail);
        if let Err(err) = capture_to_file(&paths, stage, "adb", &args, &android.join(filename)) {
            warnings.push(format!("{stage}: {err:#}"));
        }
    }

    let bugreport = android.join("bugreport.zip");
    let bugreport_s = bugreport.to_string_lossy().to_string();
    let args = adb_args(&["bugreport", bugreport_s.as_str()]);
    if let Err(err) = run_logged(&paths, "bugreport", "adb", &args) {
        warnings.push(format!("bugreport: {err:#}"));
    }

    if matches!(profile, Profile::Logical) {
        let shared = android.join("shared-storage");
        fs::create_dir_all(&shared)?;
        let shared_s = shared.to_string_lossy().to_string();
        let args = adb_args(&["pull", "/sdcard/", shared_s.as_str()]);
        if let Err(err) = run_logged(&paths, "shared_storage_pull", "adb", &args) {
            warnings.push(format!("shared storage pull: {err:#}"));
        }
    }

    log_action(&paths, "acquisition", None, "collection_complete", None)?;
    finalize(
        &paths,
        started,
        case_id,
        evidence_id,
        examiner,
        Platform::Android,
        profile,
        serial,
        warnings,
    )
}

pub fn acquire_ios(
    requested: Option<&str>,
    profile: Profile,
    case_id: &str,
    evidence_id: &str,
    examiner: &str,
    base: &Path,
) -> Result<()> {
    let udid = select_ios_device(requested)?;
    let info: DeviceInfo = inspect_ios(&udid)?;
    let paths = CasePaths::create(base, case_id, evidence_id)?;
    let started = Utc::now();
    write_json(&paths.root.join("device.json"), &info)?;
    log_action(&paths, "acquisition", None, "started", Some(format!("ios udid={udid} profile={profile:?}")))?;

    let ios = paths.native.join("ios");
    fs::create_dir_all(&ios)?;
    let mut warnings = Vec::new();

    let info_args = vec!["-u".into(), udid.clone()];
    if let Err(err) = capture_to_file(&paths, "ideviceinfo", "ideviceinfo", &info_args, &ios.join("ideviceinfo.txt")) {
        warnings.push(format!("ideviceinfo: {err:#}"));
    }

    if command_exists("idevicepair") {
        let args = vec!["-u".into(), udid.clone(), "validate".into()];
        if let Err(err) = capture_to_file(&paths, "pairing_validate", "idevicepair", &args, &ios.join("pairing_validate.txt")) {
            warnings.push(format!("pairing validate: {err:#}"));
        }
    }

    if command_exists("idevicecrashreport") {
        let crash_dir = ios.join("crash-reports");
        fs::create_dir_all(&crash_dir)?;
        let args = vec![
            "-u".into(),
            udid.clone(),
            "-k".into(),
            crash_dir.to_string_lossy().to_string(),
        ];
        if let Err(err) = run_logged(&paths, "crash_reports_copy", "idevicecrashreport", &args) {
            warnings.push(format!("crash reports: {err:#}"));
        }
    }

    if matches!(profile, Profile::Logical) {
        if !command_exists("idevicebackup2") {
            bail!("idevicebackup2 not found in PATH; cannot perform native logical backup");
        }
        let backup_dir = ios.join("mobilebackup2");
        fs::create_dir_all(&backup_dir)?;
        let args = vec![
            "-u".into(),
            udid.clone(),
            "backup".into(),
            "--full".into(),
            backup_dir.to_string_lossy().to_string(),
        ];
        if let Err(err) = run_logged(&paths, "mobilebackup2_full", "idevicebackup2", &args) {
            warnings.push(format!("MobileBackup2 full backup: {err:#}"));
        }
    }

    log_action(&paths, "acquisition", None, "collection_complete", None)?;
    finalize(
        &paths,
        started,
        case_id,
        evidence_id,
        examiner,
        Platform::Ios,
        profile,
        udid,
        warnings,
    )
}
