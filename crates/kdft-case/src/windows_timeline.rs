//! Bounded parser for Windows 10 and 11 Timeline (`ActivitiesCache.db`) SQLite databases.
//!
//! Windows Timeline records user engagements, opened files, launched apps, web navigation,
//! and clipboard actions. Activities provide high-fidelity DFIR attribution for user focus,
//! execution duration, and cloud/cross-device activity.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const MAX_TIMELINE_SOURCE_BYTES: u64 = 256 * 1024 * 1024; // 256 MB safety bound

/// A parsed record from the Windows Timeline `Activity` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineActivityRecord {
    pub activity_id: String,
    pub app_id_raw: String,
    pub application: Option<String>,
    pub app_platform: Option<String>,
    pub app_activity_id: Option<String>,
    pub activity_type: i64,
    pub activity_type_name: String,
    pub activity_status: i64,
    pub parent_activity_id: Option<String>,
    pub tag: Option<String>,
    pub group: Option<String>,
    pub match_id: Option<String>,
    pub start_time_utc: Option<String>,
    pub end_time_utc: Option<String>,
    pub last_modified_utc: Option<String>,
    pub expiration_time_utc: Option<String>,
    pub display_text: Option<String>,
    pub app_display_name: Option<String>,
    pub description: Option<String>,
    pub activation_uri: Option<String>,
    pub content_url: Option<String>,
    pub active_duration_seconds: Option<i64>,
    pub user_timezone: Option<String>,
    pub reporting_app: Option<String>,
    pub clipboard_text: Option<String>,
    pub payload_json: Option<serde_json::Value>,
    pub package_name: Option<String>,
}

/// Overall results of parsing an `ActivitiesCache.db` file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimelineParseResult {
    pub records: Vec<TimelineActivityRecord>,
    pub total_activities: usize,
    pub type_counts: HashMap<i64, usize>,
    pub parse_errors: Vec<String>,
}

/// Parses an `ActivitiesCache.db` database from a local path.
pub fn parse_timeline_database(db_path: &Path) -> Result<TimelineParseResult> {
    let metadata = fs::metadata(db_path)
        .with_context(|| format!("reading Timeline database metadata {}", db_path.display()))?;
    let file_size = metadata.len();
    if file_size > MAX_TIMELINE_SOURCE_BYTES {
        bail!(
            "ActivitiesCache.db source is {} bytes; safety limit is {} bytes",
            file_size,
            MAX_TIMELINE_SOURCE_BYTES
        );
    }

    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("opening Timeline database {}", db_path.display()))?;

    // Check whether the Activity table exists
    let has_activity_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='Activity'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !has_activity_table {
        return Ok(TimelineParseResult {
            records: Vec::new(),
            total_activities: 0,
            type_counts: HashMap::new(),
            parse_errors: vec!["Activity table not found in SQLite database".to_string()],
        });
    }

    // Optional package metadata mapping from Activity_PackageId
    let package_map = read_package_mappings(&conn);

    let mut stmt = conn
        .prepare(
            "SELECT hex(Id), COALESCE(AppId, ''), AppActivityId, ActivityType, ActivityStatus,
                    hex(ParentActivityId), Tag, \"Group\", MatchId,
                    StartTime, EndTime, LastModifiedTime, ExpirationTime,
                    Payload, ClipboardPayload
             FROM Activity
             ORDER BY StartTime ASC, Id ASC",
        )
        .context("preparing Timeline Activity query")?;

    let mut rows = stmt
        .query([])
        .context("executing Timeline Activity query")?;

    let mut result = TimelineParseResult::default();

    while let Some(row) = rows.next().context("reading Activity row")? {
        let raw_id: String = row.get(0).unwrap_or_default();
        let app_id_raw: String = row.get(1).unwrap_or_default();
        let app_activity_id: Option<String> = row.get(2).ok();
        let activity_type: i64 = row.get(3).unwrap_or(0);
        let activity_status: i64 = row.get(4).unwrap_or(0);
        let raw_parent: Option<String> = row.get(5).ok();
        let tag: Option<String> = row.get(6).ok();
        let group: Option<String> = row.get(7).ok();
        let match_id: Option<String> = row.get(8).ok();
        let start_val: Option<rusqlite::types::Value> = row.get(9).ok();
        let end_val: Option<rusqlite::types::Value> = row.get(10).ok();
        let last_mod_val: Option<rusqlite::types::Value> = row.get(11).ok();
        let exp_val: Option<rusqlite::types::Value> = row.get(12).ok();
        let payload_blob: Option<Vec<u8>> = row.get(13).ok();
        let clipboard_blob: Option<Vec<u8>> = row.get(14).ok();

        let activity_id = format_canonical_guid(&raw_id);
        let parent_activity_id = raw_parent
            .filter(|s| !s.is_empty())
            .map(|s| format_canonical_guid(&s));

        let (application, app_platform) = parse_app_id(&app_id_raw);
        let activity_type_name = activity_type_to_name(activity_type);

        let start_time_utc = start_val.as_ref().and_then(parse_timeline_datetime);
        let end_time_utc = end_val.as_ref().and_then(parse_timeline_datetime);
        let last_modified_utc = last_mod_val.as_ref().and_then(parse_timeline_datetime);
        let expiration_time_utc = exp_val.as_ref().and_then(parse_timeline_datetime);

        // Decode Payload JSON and fields
        let (
            payload_json,
            display_text,
            app_display_name,
            description,
            activation_uri,
            content_url,
            mut active_duration_seconds,
            user_timezone,
            reporting_app,
        ) = parse_payload(payload_blob.as_deref());

        // For Type 6 (UserEngaged), if duration was not in JSON, calculate from (end - start)
        if activity_type == 6 && active_duration_seconds.is_none() {
            if let (Some(rusqlite::types::Value::Integer(s)), Some(rusqlite::types::Value::Integer(e))) =
                (&start_val, &end_val)
            {
                if *e > *s && *s > 0 {
                    active_duration_seconds = Some(*e - *s);
                }
            }
        }

        // Decode Clipboard text if present
        let clipboard_text = clipboard_blob.as_deref().and_then(|bytes| {
            if bytes.is_empty() {
                None
            } else {
                String::from_utf8(bytes.to_vec()).ok()
            }
        });

        let package_name = package_map.get(&raw_id).map(|(_, pkg)| pkg.clone());

        *result.type_counts.entry(activity_type).or_insert(0) += 1;
        result.total_activities += 1;

        result.records.push(TimelineActivityRecord {
            activity_id,
            app_id_raw,
            application,
            app_platform,
            app_activity_id,
            activity_type,
            activity_type_name,
            activity_status,
            parent_activity_id,
            tag,
            group,
            match_id,
            start_time_utc,
            end_time_utc,
            last_modified_utc,
            expiration_time_utc,
            display_text,
            app_display_name,
            description,
            activation_uri,
            content_url,
            active_duration_seconds,
            user_timezone,
            reporting_app,
            clipboard_text,
            payload_json,
            package_name,
        });
    }

    Ok(result)
}

fn read_package_mappings(conn: &Connection) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    let has_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='Activity_PackageId'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if has_table {
        if let Ok(mut stmt) =
            conn.prepare("SELECT hex(ActivityId), Platform, PackageName FROM Activity_PackageId")
        {
            if let Ok(mut rows) = stmt.query([]) {
                while let Ok(Some(row)) = rows.next() {
                    let act_id: String = row.get(0).unwrap_or_default();
                    let platform: String = row.get(1).unwrap_or_default();
                    let pkg_name: String = row.get(2).unwrap_or_default();
                    if !act_id.is_empty() {
                        map.insert(act_id, (platform, pkg_name));
                    }
                }
            }
        }
    }
    map
}

/// Formats a 32-character uppercase hex string into canonical 8-4-4-4-12 GUID format.
pub fn format_canonical_guid(hex_str: &str) -> String {
    let s = hex_str.trim();
    if s.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &s[0..8],
            &s[8..12],
            &s[12..16],
            &s[16..20],
            &s[20..32]
        )
    } else {
        s.to_string()
    }
}

/// Maps Windows ActivityType numeric values to descriptive names.
pub fn activity_type_to_name(act_type: i64) -> String {
    match act_type {
        5 => "User Engagement (App Launch)".to_string(),
        6 => "User Engagement (Active Duration)".to_string(),
        10 => "User Session".to_string(),
        11 => "Device Settings / Sync".to_string(),
        12 => "System Notification".to_string(),
        15 => "Device Connectivity".to_string(),
        16 => "Clipboard".to_string(),
        other => format!("Type {other}"),
    }
}

/// Resolves known Windows folder GUIDs embedded in application paths.
pub fn resolve_known_folder_guid(path: &str) -> String {
    let mut resolved = path.to_string();
    const GUID_REPLACEMENTS: &[(&str, &str)] = &[
        ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "C:\\Windows\\System32"),
        ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "C:\\Windows\\SysWOW64"),
        ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "C:\\Program Files (x86)"),
        ("{6D809377-6AF0-444B-8957-A3773F02200E}", "C:\\Program Files"),
        ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "C:\\Windows"),
        ("{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}", "C:\\ProgramData"),
        ("{3EB685FD-984F-4E40-AC96-E7865239C0F2}", "AppData\\Roaming"),
        ("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "AppData\\Local"),
    ];

    for (guid, replacement) in GUID_REPLACEMENTS {
        if resolved.contains(guid) {
            resolved = resolved.replace(guid, replacement);
        }
    }
    resolved
}

/// Parses the raw `AppId` column, which may be a JSON array of objects or a plain string.
pub fn parse_app_id(raw: &str) -> (Option<String>, Option<String>) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (None, None);
    }

    if raw.starts_with('[') {
        if let Ok(array) = serde_json::from_str::<Vec<serde_json::Value>>(raw) {
            let mut application = None;
            let mut platform = None;

            for item in array {
                if let Some(app) = item.get("application").and_then(|v| v.as_str()) {
                    let trimmed = app.trim();
                    if !trimmed.is_empty() && application.is_none() {
                        application = Some(resolve_known_folder_guid(trimmed));
                        platform = item
                            .get("platform")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                    }
                }
            }
            return (application, platform);
        }
    }

    (Some(resolve_known_folder_guid(raw)), None)
}

type ParsedPayload = (
    Option<serde_json::Value>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

fn parse_payload(payload_bytes: Option<&[u8]>) -> ParsedPayload {
    let bytes = match payload_bytes {
        Some(b) if !b.is_empty() => b,
        _ => return (None, None, None, None, None, None, None, None, None),
    };

    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.trim(),
        Err(_) => return (None, None, None, None, None, None, None, None, None),
    };

    if !text.starts_with('{') {
        return (None, None, None, None, None, None, None, None, None);
    }

    let json: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return (None, None, None, None, None, None, None, None, None),
    };

    let display_text = json
        .get("displayText")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let app_display_name = json
        .get("appDisplayName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let description = json
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let activation_uri = json
        .get("activationUri")
        .or_else(|| json.get("activationUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let content_url = json
        .get("contentUrl")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let active_duration_seconds = json
        .get("activeDurationSeconds")
        .and_then(|v| v.as_i64());
    let user_timezone = json
        .get("userTimezone")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let reporting_app = json
        .get("reportingApp")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    (
        Some(json),
        display_text,
        app_display_name,
        description,
        activation_uri,
        content_url,
        active_duration_seconds,
        user_timezone,
        reporting_app,
    )
}

/// Parses an SQLite DATETIME value from Timeline (Unix epoch seconds, ms, or ISO string).
pub fn parse_timeline_datetime(val: &rusqlite::types::Value) -> Option<String> {
    match val {
        rusqlite::types::Value::Integer(n) => {
            let n = *n;
            if n <= 0 {
                return None;
            }
            // Check if Windows FILETIME (> 100_000_000_000_000_000, 100ns since 1601)
            if n > 100_000_000_000_000_000 {
                const FILETIME_UNIX_EPOCH_100NS: i64 = 116_444_736_000_000_000;
                let nanos_100 = n.checked_sub(FILETIME_UNIX_EPOCH_100NS)?;
                let secs = nanos_100 / 10_000_000;
                let subsec_nanos = ((nanos_100 % 10_000_000) * 100) as u32;
                DateTime::<Utc>::from_timestamp(secs, subsec_nanos)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            } else if n > 10_000_000_000 {
                // Milliseconds epoch
                let secs = n / 1000;
                let millis = (n % 1000) as u32;
                DateTime::<Utc>::from_timestamp(secs, millis * 1_000_000)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            } else {
                // Seconds epoch
                DateTime::<Utc>::from_timestamp(n, 0)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            }
        }
        rusqlite::types::Value::Text(s) => {
            let s = s.trim();
            if s.is_empty() || s == "0" {
                return None;
            }
            if let Ok(num) = s.parse::<i64>() {
                return parse_timeline_datetime(&rusqlite::types::Value::Integer(num));
            }
            Some(s.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_canonical_guid() {
        let raw = "80A055DE84A3072E764979934E3C657E";
        let guid = format_canonical_guid(raw);
        assert_eq!(guid, "80A055DE-84A3-072E-7649-79934E3C657E");
    }

    #[test]
    fn test_resolve_known_folder_guid() {
        let path = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe";
        let resolved = resolve_known_folder_guid(path);
        assert_eq!(resolved, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn test_parse_app_id_json_array() {
        let raw = r#"[{"application":"Microsoft.Windows.Explorer","platform":"windows_win32"},{"application":"Microsoft.Windows.Explorer","platform":"packageId"}]"#;
        let (app, platform) = parse_app_id(raw);
        assert_eq!(app.as_deref(), Some("Microsoft.Windows.Explorer"));
        assert_eq!(platform.as_deref(), Some("windows_win32"));
    }

    #[test]
    fn test_parse_app_id_with_guid() {
        let raw = r#"[{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe","platform":"windows_win32"}]"#;
        let (app, _) = parse_app_id(raw);
        assert_eq!(app.as_deref(), Some("C:\\Windows\\System32\\cmd.exe"));
    }

    #[test]
    fn test_parse_timeline_datetime_seconds() {
        let val = rusqlite::types::Value::Integer(1787401630);
        let dt = parse_timeline_datetime(&val);
        assert!(dt.is_some());
        assert!(dt.unwrap().starts_with("2026-"));
    }

    #[test]
    fn test_parse_payload_json() {
        let payload = br#"{"displayText":"Command Prompt","activationUri":"ms-shellactivity:","appDisplayName":"Command Prompt","backgroundColor":"black"}"#;
        let (_, display, app, _, uri, _, _, _, _) = parse_payload(Some(payload));
        assert_eq!(display.as_deref(), Some("Command Prompt"));
        assert_eq!(app.as_deref(), Some("Command Prompt"));
        assert_eq!(uri.as_deref(), Some("ms-shellactivity:"));
    }

    #[test]
    fn test_parse_payload_user_engaged() {
        let payload = br#"{"type":"UserEngaged","reportingApp":"ShellActivityMonitor","activeDurationSeconds":290,"userTimezone":"America/Los_Angeles"}"#;
        let (_, _, _, _, _, _, duration, tz, reporting) = parse_payload(Some(payload));
        assert_eq!(duration, Some(290));
        assert_eq!(tz.as_deref(), Some("America/Los_Angeles"));
        assert_eq!(reporting.as_deref(), Some("ShellActivityMonitor"));
    }

    #[test]
    fn test_parse_timeline_in_memory_db() {
        let temp_dir = std::env::temp_dir().join(format!("kdft-timeline-test-{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let db_file = temp_dir.join("ActivitiesCache.db");

        {
            let conn = Connection::open(&db_file).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE Activity (
                    Id BLOB PRIMARY KEY NOT NULL,
                    AppId TEXT NOT NULL,
                    PackageIdHash TEXT,
                    AppActivityId TEXT,
                    ActivityType INT NOT NULL,
                    ActivityStatus INT NOT NULL,
                    ParentActivityId BLOB,
                    Tag TEXT,
                    "Group" TEXT,
                    MatchId TEXT,
                    LastModifiedTime DATETIME NOT NULL,
                    ExpirationTime DATETIME,
                    Payload BLOB,
                    Priority INT,
                    IsLocalOnly INT,
                    PlatformDeviceId TEXT,
                    CreatedInCloud DATETIME,
                    StartTime DATETIME,
                    EndTime DATETIME,
                    LastModifiedOnClient DATETIME,
                    ClipboardPayload BLOB
                );

                CREATE TABLE Activity_PackageId (
                    ActivityId BLOB NOT NULL,
                    Platform TEXT NOT NULL,
                    PackageName TEXT NOT NULL,
                    ExpirationTime DATETIME NOT NULL
                );

                INSERT INTO Activity (
                    Id, AppId, AppActivityId, ActivityType, ActivityStatus,
                    StartTime, EndTime, LastModifiedTime, Payload
                ) VALUES (
                    X'80A055DE84A3072E764979934E3C657E',
                    '[{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe","platform":"windows_win32"}]',
                    'ACT123',
                    5,
                    1,
                    1787401630,
                    0,
                    1787401630,
                    CAST('{"displayText":"Command Prompt","appDisplayName":"cmd.exe"}' AS BLOB)
                );
                "#,
            )
            .unwrap();
        }

        let parsed = parse_timeline_database(&db_file).unwrap();
        assert_eq!(parsed.total_activities, 1);
        assert_eq!(parsed.records.len(), 1);

        let rec = &parsed.records[0];
        assert_eq!(rec.activity_id, "80A055DE-84A3-072E-7649-79934E3C657E");
        assert_eq!(rec.application.as_deref(), Some("C:\\Windows\\System32\\cmd.exe"));
        assert_eq!(rec.display_text.as_deref(), Some("Command Prompt"));
        assert_eq!(rec.activity_type, 5);
        assert_eq!(rec.activity_type_name, "User Engagement (App Launch)");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
