use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

/// Chromium history `visit_source` integer to a stable human label.
///
/// This is the raw source value from the `visit_source` table and older
/// Chromium schemas; it is preserved for transparency but must not be used
/// alone to decide whether a visit is remote/synced. Use
/// [`chromium_visit_origin`] for the truthful origin classification.
pub fn chromium_visit_source_label(source: Option<i64>) -> String {
    match source {
        None => "not_recorded".to_string(),
        Some(0) => "synced".to_string(),
        Some(1) => "browsed(local)".to_string(),
        Some(2) => "extension".to_string(),
        Some(3) => "firefox_imported".to_string(),
        Some(4) => "ie_imported".to_string(),
        Some(5) => "safari_imported".to_string(),
        Some(value) => format!("unknown ({value})"),
    }
}

/// Truthful origin classification for a Chromium history visit.
///
/// Rules, in order:
/// 1. If a non-empty `originator_cache_guid` is present, the visit is
///    `remote_synced` (a modern Chromium Sync-originated visit). The GUID is
///    an opaque Sync client/cache identifier, not a hardware identity.
/// 2. Otherwise, if `visit_source` is `Some(0)` (synced) but the GUID is
///    absent, the visit is `synced_origin_unresolved`.
/// 3. If `visit_source` is missing entirely, origin remains unresolved.
///    Modern schemas can omit the legacy source row, so absence must not be
///    labelled as local evidence.
/// 4. Known non-local source values produce their own classes:
///    `extension`, `imported`.
/// 5. `is_known_to_sync` is never enough on its own to classify a visit as
///    remote.
pub fn chromium_visit_origin(
    originator_cache_guid: Option<&str>,
    visit_source: Option<i64>,
    is_known_to_sync: Option<i64>,
) -> &'static str {
    let has_nonempty_guid = originator_cache_guid
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if has_nonempty_guid {
        return "remote_synced";
    }
    match visit_source {
        Some(0) => "synced_origin_unresolved",
        Some(1) => "local_browsed",
        Some(2) => "extension",
        Some(3) | Some(4) | Some(5) => "imported",
        Some(_) => "unknown",
        // is_known_to_sync alone means the record participates in sync; it
        // does not identify which client originally generated the visit.
        None if is_known_to_sync == Some(1) => "sync_eligible_origin_unresolved",
        None => "origin_unresolved",
    }
}

/// Shortened originator Sync client/cache GUID for compact UI columns.
///
/// Returns the first eight characters of the GUID, or an empty string when the
/// GUID is missing or empty. The full GUID must be consulted for any forensic
/// claim.
pub fn chromium_originator_sync_guid_short(originator_cache_guid: Option<&str>) -> String {
    originator_cache_guid
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(8).collect())
        .unwrap_or_default()
}

/// Full originator Sync client/cache GUID for detailed views and exports.
pub fn chromium_originator_sync_guid_full(originator_cache_guid: Option<&str>) -> String {
    originator_cache_guid
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_default()
}

/// Human-readable note explaining that the originator GUID is opaque and that
/// a friendly device name is only available when an acquired DeviceInfo record
/// maps it.
pub fn chromium_originator_sync_guid_note() -> &'static str {
    "Opaque Chromium Sync client cache GUID; not a hardware/device identity. A friendly device name requires separately acquired Sync DeviceInfo that maps this GUID."
}

/// Returns a profile label only for Chromium's conventional on-disk profile
/// directory names. Examiner collection folders must never be attributed to
/// the subject as a browser profile.
pub fn chromium_profile_label(history_path: &Path) -> Option<String> {
    let label = history_path.parent()?.file_name()?.to_str()?.trim();
    let lower = label.to_ascii_lowercase();
    let conventional = matches!(
        lower.as_str(),
        "default" | "guest profile" | "system profile"
    ) || lower.strip_prefix("profile ").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    });
    conventional.then(|| label.to_string())
}

pub fn chromium_transition_type(transition: i64) -> &'static str {
    match transition & 0xff {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "unknown",
    }
}

pub fn chromium_transition_qualifiers(transition: i64) -> Vec<&'static str> {
    const QUALIFIERS: &[(i64, &str)] = &[
        (0x0080_0000, "blocked"),
        (0x0100_0000, "forward_back"),
        (0x0200_0000, "from_address_bar"),
        (0x0400_0000, "home_page"),
        (0x0800_0000, "from_api"),
        (0x1000_0000, "chain_start"),
        (0x2000_0000, "chain_end"),
        (0x4000_0000, "client_redirect"),
        (0x8000_0000, "server_redirect"),
    ];
    QUALIFIERS
        .iter()
        .filter_map(|(mask, label)| (transition & mask != 0).then_some(*label))
        .collect()
}

pub fn chromium_download_state_label(state: i64) -> String {
    match state {
        0 => "in_progress".to_string(),
        1 => "complete".to_string(),
        2 => "cancelled".to_string(),
        3 => "obsolete_bug_140687".to_string(),
        4 => "interrupted".to_string(),
        value => format!("unknown ({value})"),
    }
}

pub fn chromium_download_danger_type_label(danger_type: i64) -> String {
    match danger_type {
        0 => "not_dangerous".to_string(),
        1 => "dangerous_file".to_string(),
        2 => "dangerous_url".to_string(),
        3 => "dangerous_content".to_string(),
        4 => "maybe_dangerous_content".to_string(),
        5 => "uncommon_content".to_string(),
        6 => "user_validated".to_string(),
        7 => "dangerous_host".to_string(),
        8 => "potentially_unwanted".to_string(),
        value => format!("unknown ({value})"),
    }
}

pub fn chromium_download_interrupt_reason_label(reason: i64) -> String {
    match reason {
        0 => "none".to_string(),
        1 => "file_failed".to_string(),
        2 => "file_access_denied".to_string(),
        3 => "file_no_space".to_string(),
        5 => "file_name_too_long".to_string(),
        6 => "file_too_large".to_string(),
        7 => "file_virus_infected".to_string(),
        10 => "file_transient_error".to_string(),
        11 => "file_blocked".to_string(),
        12 => "file_security_check_failed".to_string(),
        13 => "file_too_short".to_string(),
        14 => "file_hash_mismatch".to_string(),
        15 => "file_same_as_source".to_string(),
        20 => "network_failed".to_string(),
        21 => "network_timeout".to_string(),
        22 => "network_disconnected".to_string(),
        23 => "network_server_down".to_string(),
        24 => "network_invalid_request".to_string(),
        30 => "server_failed".to_string(),
        31 => "server_no_range".to_string(),
        33 => "server_bad_content".to_string(),
        34 => "server_unauthorized".to_string(),
        35 => "server_cert_problem".to_string(),
        36 => "server_forbidden".to_string(),
        37 => "server_unreachable".to_string(),
        38 => "server_content_length_mismatch".to_string(),
        40 => "user_canceled".to_string(),
        41 => "user_shutdown".to_string(),
        50 => "crash".to_string(),
        value => format!("unknown ({value})"),
    }
}

/// Best-effort schema-based detection of a Chromium History SQLite file.
///
/// Unlike [`crate::detect_browser_database`], this only accepts Chromium
/// (`urls` + `visits`) and it accepts a candidate path directly, so a renamed
/// copied History file can be discovered by scanning a profile directory.
pub fn is_chromium_history_database(path: &std::path::Path) -> bool {
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

    let mut header = [0_u8; SQLITE_HEADER.len()];
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    if file.read_exact(&mut header).is_err() || &header != SQLITE_HEADER {
        return false;
    }

    // Never let SQLite touch the examiner-selected artifact while sniffing its
    // schema. Even a read-only WAL connection can create/update shared-memory
    // sidecars. The parent module's snapshot helper fingerprints and copies the
    // complete SQLite generation before this disposable copy is opened.
    let (conn, _snapshot) = match crate::open_sqlite_copy_read_only(path) {
        Ok(snapshot) => snapshot,
        Err(_) => return false,
    };
    if conn
        .busy_timeout(std::time::Duration::from_millis(250))
        .is_err()
    {
        return false;
    }
    let mut names = HashSet::new();
    let mut stmt = match conn.prepare(
        "SELECT lower(name) FROM sqlite_master WHERE type = 'table' AND lower(name) IN ('urls', 'visits')",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return false,
    };
    let rows = stmt.query_map([], |row| row.get::<_, String>(0));
    let rows = match rows {
        Ok(rows) => rows,
        Err(_) => return false,
    };
    for name in rows.flatten() {
        names.insert(name);
    }
    names.contains("urls") && names.contains("visits")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visit_origin_classification_is_truthful() {
        // Modern sync: non-empty GUID wins regardless of other fields.
        assert_eq!(
            chromium_visit_origin(Some("guid-abc"), Some(1), Some(0)),
            "remote_synced"
        );
        assert_eq!(
            chromium_visit_origin(Some("guid-abc"), Some(0), Some(1)),
            "remote_synced"
        );
        // Empty or whitespace GUID does not promote to remote.
        assert_eq!(
            chromium_visit_origin(Some(""), Some(0), Some(1)),
            "synced_origin_unresolved"
        );
        assert_eq!(
            chromium_visit_origin(Some("   "), Some(0), Some(1)),
            "synced_origin_unresolved"
        );
        // A synced source without an originator GUID has unresolved origin.
        assert_eq!(
            chromium_visit_origin(None, Some(0), Some(0)),
            "synced_origin_unresolved"
        );
        // Missing visit_source does not establish local or remote origin.
        assert_eq!(
            chromium_visit_origin(None, None, Some(1)),
            "sync_eligible_origin_unresolved"
        );
        assert_eq!(
            chromium_visit_origin(None, None, Some(0)),
            "origin_unresolved"
        );
        // Explicit local browsed source.
        assert_eq!(
            chromium_visit_origin(None, Some(1), Some(0)),
            "local_browsed"
        );
        // Extension and imported classes.
        assert_eq!(chromium_visit_origin(None, Some(2), None), "extension");
        assert_eq!(chromium_visit_origin(None, Some(3), None), "imported");
        assert_eq!(chromium_visit_origin(None, Some(4), None), "imported");
        assert_eq!(chromium_visit_origin(None, Some(5), None), "imported");
        // Unknown source value.
        assert_eq!(chromium_visit_origin(None, Some(99), None), "unknown");
    }

    #[test]
    fn originator_sync_guid_helpers_handle_missing_and_long_guids() {
        assert_eq!(chromium_originator_sync_guid_short(None), "");
        assert_eq!(chromium_originator_sync_guid_full(None), "");
        assert_eq!(chromium_originator_sync_guid_short(Some("")), "");
        assert_eq!(chromium_originator_sync_guid_short(Some("   ")), "");
        assert_eq!(
            chromium_originator_sync_guid_short(Some("abcdef123456")),
            "abcdef12"
        );
        assert_eq!(
            chromium_originator_sync_guid_full(Some("abcdef123456")),
            "abcdef123456"
        );
    }

    #[test]
    fn profile_label_rejects_examiner_collection_folders() {
        assert_eq!(
            chromium_profile_label(Path::new("/Users/alice/Library/Edge/Default/History"))
                .as_deref(),
            Some("Default")
        );
        assert_eq!(
            chromium_profile_label(Path::new("C:/Cases/Profile 12/History")).as_deref(),
            Some("Profile 12")
        );
        assert_eq!(
            chromium_profile_label(Path::new("/Users/examiner/Downloads/History copy")),
            None
        );
        assert_eq!(
            chromium_profile_label(Path::new("C:/Cases/Triage/History")),
            None
        );
    }
}
