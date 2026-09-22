use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::command::{command_exists, run_capture, run_checked};
use crate::models::{DeviceInfo, Platform};

pub fn list_ios_devices() -> Result<Vec<String>> {
    if !command_exists("idevice_id") {
        bail!("idevice_id not found in PATH. Install current libimobiledevice tools first.");
    }
    let out = run_checked("idevice_id", ["-l"])?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub fn select_ios_device(requested: Option<&str>) -> Result<String> {
    let devices = list_ios_devices()?;
    if let Some(udid) = requested {
        if devices.iter().any(|d| d == udid) {
            return Ok(udid.to_string());
        }
        bail!("iOS device {udid} not found");
    }

    match devices.len() {
        0 => bail!("No iOS device detected through usbmux/libimobiledevice"),
        1 => Ok(devices[0].clone()),
        _ => bail!("Multiple iOS devices are connected; pass --device <UDID>"),
    }
}

fn parse_ideviceinfo(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

pub fn inspect_ios(udid: &str) -> Result<DeviceInfo> {
    if !command_exists("ideviceinfo") {
        bail!("ideviceinfo not found in PATH");
    }

    let info_out = run_capture("ideviceinfo", ["-u", udid])?;
    let info_ok = info_out.status.success();
    let info_text = String::from_utf8_lossy(&info_out.stdout).to_string();
    let map = parse_ideviceinfo(&info_text);

    let pairing_valid = if command_exists("idevicepair") {
        run_capture("idevicepair", ["-u", udid, "validate"])
            .map(|o| o.status.success())
            .ok()
    } else {
        None
    };

    let mut notes = Vec::new();
    if !info_ok {
        notes.push("Device enumerates through usbmux, but ideviceinfo handshake failed. This can indicate locked/unpaired/restricted service access; state is not inferred as AFU or BFU from this alone.".into());
    }
    if pairing_valid == Some(true) {
        notes.push("Existing host pairing validates.".into());
    }
    notes.push("This MVP does not infer iOS AFU/BFU solely from lockdownd service availability.".into());

    Ok(DeviceInfo {
        platform: Platform::Ios,
        identifier: udid.to_string(),
        manufacturer: Some("Apple".into()),
        model: map
            .get("ProductType")
            .cloned()
            .or_else(|| map.get("DeviceName").cloned()),
        os_version: map.get("ProductVersion").cloned(),
        build: map.get("BuildVersion").cloned(),
        serial_number: map.get("SerialNumber").cloned(),
        pairing_or_adb_authorized: pairing_valid,
        ce_unlocked_since_boot: None,
        root_or_jailbreak_detected: None,
        bootloader_locked: None,
        notes,
    })
}

pub fn probe_ios(requested: Option<&str>) -> Result<()> {
    let devices = list_ios_devices()?;
    if devices.is_empty() {
        println!("No iOS devices detected through libimobiledevice.");
        return Ok(());
    }

    for udid in devices {
        if let Some(wanted) = requested {
            if wanted != udid {
                continue;
            }
        }
        let info = inspect_ios(&udid)?;
        println!("{udid}");
        println!("  model={:?}", info.model);
        println!("  os={:?}", info.os_version);
        println!("  pairing_valid={:?}", info.pairing_or_adb_authorized);
        println!("  quick=available when lockdownd/paired services allow it");
        println!("  logical=available when MobileBackup2 service is permitted");
    }
    Ok(())
}
