use anyhow::{anyhow, bail, Result};

use crate::command::{command_exists, run_checked, text_stdout};
use crate::models::{DeviceInfo, Platform};

pub fn list_android_devices() -> Result<Vec<(String, String)>> {
    if !command_exists("adb") {
        bail!("adb not found in PATH. Install Android Platform Tools first.");
    }

    let out = run_checked("adb", ["devices", "-l"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut devices = Vec::new();

    for line in text.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let serial = match parts.next() {
            Some(v) => v.to_string(),
            None => continue,
        };
        let state = parts.next().unwrap_or("unknown").to_string();
        devices.push((serial, state));
    }

    Ok(devices)
}

pub fn select_android_device(requested: Option<&str>) -> Result<String> {
    let devices = list_android_devices()?;

    if let Some(serial) = requested {
        if devices.iter().any(|(s, _)| s == serial) {
            return Ok(serial.to_string());
        }
        bail!("Android device {serial} not found");
    }

    let authorized: Vec<_> = devices.iter().filter(|(_, state)| state == "device").collect();
    match authorized.len() {
        0 => {
            if devices.iter().any(|(_, state)| state == "unauthorized") {
                bail!("Android device is present but ADB is unauthorized. Do not reboot it; unlock only if authorized by your acquisition procedure and approve this workstation if appropriate.");
            }
            bail!("No authorized Android device found")
        }
        1 => Ok(authorized[0].0.clone()),
        _ => bail!("Multiple Android devices are connected; pass --device <serial>"),
    }
}

fn adb_shell(serial: &str, args: &[&str]) -> Option<String> {
    let mut all = vec!["-s", serial, "shell"];
    all.extend_from_slice(args);
    let out = run_checked("adb", all).ok()?;
    Some(text_stdout(&out))
}

fn getprop(serial: &str, key: &str) -> Option<String> {
    adb_shell(serial, &["getprop", key]).filter(|v| !v.is_empty())
}

pub fn inspect_android(serial: &str) -> Result<DeviceInfo> {
    let devices = list_android_devices()?;
    let state = devices
        .iter()
        .find(|(s, _)| s == serial)
        .map(|(_, st)| st.as_str())
        .ok_or_else(|| anyhow!("device disappeared during probe"))?;

    let authorized = state == "device";
    let ce_unlocked = if authorized {
        adb_shell(serial, &["cmd", "user", "is-user-unlocked", "0"])
            .map(|v| v.eq_ignore_ascii_case("true"))
    } else {
        None
    };

    let root = if authorized {
        adb_shell(serial, &["id"]).map(|v| v.contains("uid=0(root)"))
    } else {
        None
    };

    let bootloader_locked = if authorized {
        getprop(serial, "ro.boot.flash.locked").map(|v| v == "1")
    } else {
        None
    };

    let mut notes = Vec::new();
    if !authorized {
        notes.push(format!("ADB state is {state}"));
    }
    match ce_unlocked {
        Some(true) => notes.push("Android user 0 reports unlocked since boot; credential-encrypted storage may be available to permitted services.".into()),
        Some(false) => notes.push("Android user 0 reports not unlocked; treat as Direct Boot/BFU-limited and avoid rebooting or state-changing actions.".into()),
        None => {}
    }

    Ok(DeviceInfo {
        platform: Platform::Android,
        identifier: serial.to_string(),
        manufacturer: authorized.then(|| getprop(serial, "ro.product.manufacturer")).flatten(),
        model: authorized.then(|| getprop(serial, "ro.product.model")).flatten(),
        os_version: authorized.then(|| getprop(serial, "ro.build.version.release")).flatten(),
        build: authorized.then(|| getprop(serial, "ro.build.fingerprint")).flatten(),
        serial_number: Some(serial.to_string()),
        pairing_or_adb_authorized: Some(authorized),
        ce_unlocked_since_boot: ce_unlocked,
        root_or_jailbreak_detected: root,
        bootloader_locked,
        notes,
    })
}

pub fn probe_android(requested: Option<&str>) -> Result<()> {
    let devices = list_android_devices()?;
    if devices.is_empty() {
        println!("No Android devices detected by adb.");
        return Ok(());
    }

    for (serial, state) in devices {
        if let Some(wanted) = requested {
            if wanted != serial {
                continue;
            }
        }
        println!("{serial}: adb_state={state}");
        if state == "device" {
            let info = inspect_android(&serial)?;
            println!("  model={:?}", info.model);
            println!("  os={:?}", info.os_version);
            println!("  ce_unlocked_since_boot={:?}", info.ce_unlocked_since_boot);
            println!("  root_detected={:?}", info.root_or_jailbreak_detected);
            println!("  quick=available");
            println!("  logical=available (shared storage only; app-private scope depends on OS permissions)");
        } else {
            println!("  acquisition=unavailable until the existing ADB trust/state allows access");
        }
    }
    Ok(())
}
