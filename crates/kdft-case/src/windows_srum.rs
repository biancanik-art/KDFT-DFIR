//! Bounded parser for Windows System Resource Usage Monitor (`SRUDB.dat`) ESE databases.
//!
//! SRUM records long-term system resource usage: application executions, network bandwidth
//! (bytes sent / received per process), network connectivity durations, and energy usage.
//! It is a premier forensic artifact for investigating data exfiltration, malware beaconing,
//! and user activity.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const MAX_SRUM_SOURCE_BYTES: u64 = 512 * 1024 * 1024; // 512 MB safety bound

/// A parsed record from the SRUM database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrumRecord {
    pub srum_table: String,
    pub application: String,
    pub application_raw: Option<String>,
    pub user_sid: Option<String>,
    pub timestamp_utc: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
    pub focus_time_ms: Option<u64>,
    pub user_input_time_ms: Option<u64>,
    pub connected_time_seconds: Option<u64>,
    pub network_profile_id: Option<i32>,
    pub energy_consumed: Option<u64>,
    pub charge_level: Option<u64>,
}

/// Overall results of parsing an `SRUDB.dat` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrumParseResult {
    pub records: Vec<SrumRecord>,
    pub total_records: usize,
    pub network_usage_count: usize,
    pub app_timeline_count: usize,
    pub network_connectivity_count: usize,
    pub energy_usage_count: usize,
    pub parse_errors: Vec<String>,
}

/// Decodes binary Windows SID bytes into standard string representation (`S-1-5-21-...`).
pub fn decode_sid_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let sub_auth_count = bytes[1] as usize;
    if bytes.len() < 8 + sub_auth_count * 4 {
        return None;
    }

    let mut auth: u64 = 0;
    for b in &bytes[2..8] {
        auth = (auth << 8) | (*b as u64);
    }

    let mut sub_auths = Vec::with_capacity(sub_auth_count);
    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        let sub = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?);
        sub_auths.push(sub);
    }

    let mut s = format!("S-{revision}-{auth}");
    for sub in sub_auths {
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

/// Cleans raw SRUM application identifiers (e.g. `!!app.exe!timestamp!hash![Service]` or device paths).
pub fn clean_srum_app_name(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return "Unknown Application".to_string();
    }

    // Handle SRUM binary SID bytes in IdMap
    if s.as_bytes().starts_with(&[1]) {
        if let Some(sid) = decode_sid_bytes(s.as_bytes()) {
            return sid;
        }
    }

    // Handle !!<binary>!... patterns
    if s.starts_with("!!") {
        let trimmed = &s[2..];
        let parts: Vec<&str> = trimmed.split('!').collect();
        if let Some(binary) = parts.first() {
            if !binary.is_empty() {
                // If there is a trailing service name like [Service]
                if let Some(service) = parts.iter().find(|p| p.starts_with('[') && p.ends_with(']')) {
                    return format!("{binary} {service}");
                }
                return binary.to_string();
            }
        }
    }

    // Handle \device\harddiskvolume<N>\
    if s.to_ascii_lowercase().starts_with("\\device\\harddiskvolume") {
        if let Some(idx) = s[22..].find('\\') {
            let after_vol = &s[22 + idx + 1..];
            return format!("C:\\{after_vol}");
        }
    }

    s.to_string()
}

/// Parses an `SRUDB.dat` ESE database file.
pub fn parse_srum_database(db_path: &Path) -> Result<SrumParseResult> {
    let metadata = fs::metadata(db_path)
        .with_context(|| format!("reading SRUM database metadata {}", db_path.display()))?;
    let file_size = metadata.len();
    if file_size > MAX_SRUM_SOURCE_BYTES {
        bail!(
            "SRUDB.dat source is {} bytes; safety limit is {} bytes",
            file_size,
            MAX_SRUM_SOURCE_BYTES
        );
    }

    let mut result = SrumParseResult::default();

    // 1. Build ID Map lookup
    let id_map: HashMap<i32, String> = match srum_parser::parse_id_map(db_path) {
        Ok(entries) => entries
            .into_iter()
            .map(|entry| (entry.id, clean_srum_app_name(&entry.name)))
            .collect(),
        Err(err) => {
            result
                .parse_errors
                .push(format!("reading SRUM IdMap: {err:#}"));
            HashMap::new()
        }
    };

    let lookup_id = |id: i32| -> String {
        id_map
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("ID #{id}"))
    };

    let lookup_user = |id: i32| -> Option<String> {
        id_map.get(&id).cloned().filter(|name| name.starts_with("S-1-"))
    };

    let format_ts = |ts: &dyn std::fmt::Display| -> Option<String> {
        let s = ts.to_string();
        if s.starts_with("1601") || s.starts_with("1899") || s.starts_with("1900") || s.is_empty() {
            None
        } else {
            Some(s)
        }
    };

    // 2. Parse Network Usage (bytes sent / received)
    match srum_parser::parse_network_usage(db_path) {
        Ok(records) => {
            for rec in records {
                let app_name = lookup_id(rec.app_id);
                let user_sid = lookup_user(rec.user_id);
                let timestamp_utc = format_ts(&rec.timestamp);

                result.records.push(SrumRecord {
                    srum_table: "network_usage".to_string(),
                    application: app_name,
                    application_raw: Some(format!("app_id: {}", rec.app_id)),
                    user_sid,
                    timestamp_utc,
                    bytes_sent: Some(rec.bytes_sent),
                    bytes_recv: Some(rec.bytes_recv),
                    focus_time_ms: None,
                    user_input_time_ms: None,
                    connected_time_seconds: None,
                    network_profile_id: None,
                    energy_consumed: None,
                    charge_level: None,
                });
                result.network_usage_count += 1;
                result.total_records += 1;
            }
        }
        Err(err) => {
            result
                .parse_errors
                .push(format!("reading SRUM Network Usage: {err:#}"));
        }
    }

    // 3. Parse Network Connectivity
    match srum_parser::parse_network_connectivity(db_path) {
        Ok(records) => {
            for rec in records {
                let app_name = lookup_id(rec.app_id);
                let timestamp_utc = format_ts(&rec.timestamp);

                result.records.push(SrumRecord {
                    srum_table: "network_connectivity".to_string(),
                    application: app_name,
                    application_raw: Some(format!("app_id: {}", rec.app_id)),
                    user_sid: None,
                    timestamp_utc,
                    bytes_sent: None,
                    bytes_recv: None,
                    focus_time_ms: None,
                    user_input_time_ms: None,
                    connected_time_seconds: Some(rec.connected_time),
                    network_profile_id: Some(rec.profile_id),
                    energy_consumed: None,
                    charge_level: None,
                });
                result.network_connectivity_count += 1;
                result.total_records += 1;
            }
        }
        Err(err) => {
            result
                .parse_errors
                .push(format!("reading SRUM Network Connectivity: {err:#}"));
        }
    }

    // 4. Parse Application Timeline
    match srum_parser::parse_app_timeline(db_path) {
        Ok(records) => {
            for rec in records {
                let app_name = lookup_id(rec.app_id);
                let user_sid = lookup_user(rec.user_id);
                let timestamp_utc = format_ts(&rec.timestamp);

                result.records.push(SrumRecord {
                    srum_table: "app_timeline".to_string(),
                    application: app_name,
                    application_raw: Some(format!("app_id: {}", rec.app_id)),
                    user_sid,
                    timestamp_utc,
                    bytes_sent: None,
                    bytes_recv: None,
                    focus_time_ms: Some(rec.focus_time_ms as u64),
                    user_input_time_ms: Some(rec.user_input_time_ms as u64),
                    connected_time_seconds: None,
                    network_profile_id: None,
                    energy_consumed: None,
                    charge_level: None,
                });
                result.app_timeline_count += 1;
                result.total_records += 1;
            }
        }
        Err(err) => {
            result
                .parse_errors
                .push(format!("reading SRUM App Timeline: {err:#}"));
        }
    }

    // 5. Parse Energy Usage
    match srum_parser::parse_energy_usage(db_path) {
        Ok(records) => {
            for rec in records {
                let app_name = lookup_id(rec.app_id);
                let timestamp_utc = format_ts(&rec.timestamp);

                result.records.push(SrumRecord {
                    srum_table: "energy_usage".to_string(),
                    application: app_name,
                    application_raw: Some(format!("app_id: {}", rec.app_id)),
                    user_sid: None,
                    timestamp_utc,
                    bytes_sent: None,
                    bytes_recv: None,
                    focus_time_ms: None,
                    user_input_time_ms: None,
                    connected_time_seconds: None,
                    network_profile_id: None,
                    energy_consumed: Some(rec.energy_consumed),
                    charge_level: Some(rec.charge_level),
                });
                result.energy_usage_count += 1;
                result.total_records += 1;
            }
        }
        Err(err) => {
            result
                .parse_errors
                .push(format!("reading SRUM Energy Usage: {err:#}"));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_sid_bytes() {
        // S-1-5-18 (Local System)
        // Revision: 1, SubAuthCount: 1, Authority: 5, SubAuth: 18
        let bytes: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let sid = decode_sid_bytes(&bytes);
        assert_eq!(sid.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn test_clean_srum_app_name() {
        let raw1 = "!!svchost.exe!2037/07/18:06:45:20!15eca![NetworkService] [Dnscache]";
        assert_eq!(clean_srum_app_name(raw1), "svchost.exe [NetworkService] [Dnscache]");

        let raw2 = "!!MsMpEng.exe!1993/01/18:16:54:13!27311!";
        assert_eq!(clean_srum_app_name(raw2), "MsMpEng.exe");

        let raw3 = "\\device\\harddiskvolume2\\windows\\system32\\cmd.exe";
        assert_eq!(clean_srum_app_name(raw3), "C:\\windows\\system32\\cmd.exe");
    }
}
