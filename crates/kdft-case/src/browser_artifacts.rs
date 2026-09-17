//! Browser artifact extraction, parsing, and forensic profile analysis.
//!
//! Provides read-only streaming, decoding, and forensic normalization of
//! Chromium, Firefox, and Safari profile artifacts (visits, URLs, downloads,
//! searches, bookmarks, logins, preferences, and cookies).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

use super::{
    active_case_id, add_entry_category, audit_actor, ensure_evidence_source, ext4_list_dir,
    host_from_url, json_has_display_value, merge_json_object, open_existing_case, progress,
    recover_filesystem_entry_in_session, relink_bookmark_items_tx, sanitize_logical_segment,
    sha256_hex, source_artifact_metadata, source_path_exact_from_metadata, stable_path_string,
    trim_optional_string, unlimited_if_zero, upsert_filesystem_entry, BrowserHistoryImportResult,
    EvidenceReadSession, Ext4ImageReader, ExtChild, ImportBrowserArtifactsIntoEvidenceOptions,
    ImportBrowserHistoryOptions, RecoverEntryOptions, TempFileGuard,
};

pub fn import_chromium_history(
    case_path: &Path,
    options: ImportBrowserHistoryOptions,
) -> Result<BrowserHistoryImportResult> {
    import_browser_history_for_family(case_path, BrowserFamily::Chromium, options)
}

pub fn import_firefox_history(
    case_path: &Path,
    options: ImportBrowserHistoryOptions,
) -> Result<BrowserHistoryImportResult> {
    import_browser_history_for_family(case_path, BrowserFamily::Firefox, options)
}

pub fn import_safari_history(
    case_path: &Path,
    options: ImportBrowserHistoryOptions,
) -> Result<BrowserHistoryImportResult> {
    import_browser_history_for_family(case_path, BrowserFamily::Safari, options)
}

pub fn import_browser_history(
    case_path: &Path,
    options: ImportBrowserHistoryOptions,
) -> Result<BrowserHistoryImportResult> {
    let family = detect_browser_family(&options.history_path)?;
    import_browser_history_for_family(case_path, family, options)
}

pub fn import_browser_history_for_family(
    case_path: &Path,
    family: BrowserFamily,
    options: ImportBrowserHistoryOptions,
) -> Result<BrowserHistoryImportResult> {
    let import_data = collect_browser_history_import_for_family(
        &options.history_path,
        options.max_visits,
        family,
    )?;
    persist_browser_history_import(case_path, options.evidence_name, import_data)
}

pub fn collect_browser_history_import(
    history_path: &Path,
    max_visits: usize,
) -> Result<BrowserHistoryImportData> {
    let family = detect_browser_family(history_path)?;
    collect_browser_history_import_for_family(history_path, max_visits, family)
}

pub fn collect_browser_history_import_for_family(
    history_path: &Path,
    max_visits: usize,
    family: BrowserFamily,
) -> Result<BrowserHistoryImportData> {
    let max_visits = unlimited_if_zero(max_visits);
    let import_data = match family {
        BrowserFamily::Chromium => collect_chromium_history_import(history_path, max_visits)?,
        BrowserFamily::Firefox => collect_firefox_history_import(history_path, max_visits)?,
        BrowserFamily::Safari => collect_safari_history_import(history_path, max_visits)?,
    };
    Ok(import_data)
}

pub fn persist_browser_history_import(
    case_path: &Path,
    evidence_name: Option<String>,
    import_data: BrowserHistoryImportData,
) -> Result<BrowserHistoryImportResult> {
    let source_metadata = fs::metadata(&import_data.primary_db_path).with_context(|| {
        format!(
            "reading history database {}",
            import_data.primary_db_path.display()
        )
    })?;
    let display_name = trim_optional_string(evidence_name)
        .unwrap_or_else(|| import_data.default_display_name.clone());
    let counts = import_data.records.counts;
    let visit_limit_reached = import_data.total_visits > counts.visits;
    let artifact_limit_reached = import_data.examiner_artifact_limit_reached;
    let parser_errors_present = import_data.parse_error_count > 0;
    let truncated = visit_limit_reached || artifact_limit_reached || parser_errors_present;
    let mut truncation_reasons = Vec::with_capacity(3);
    if visit_limit_reached {
        truncation_reasons.push("examiner visit limit reached");
    }
    if artifact_limit_reached {
        truncation_reasons.push("examiner per-artifact row limit reached");
    }
    if parser_errors_present {
        truncation_reasons.push("one or more browser artifact tables could not be parsed");
    }
    let truncation_reason = (!truncation_reasons.is_empty()).then(|| truncation_reasons.join("; "));
    let entries_indexed = counts.total();
    let visits_indexed = counts.visits;
    let bookmarks_indexed = counts.bookmarks;
    let preferences_indexed = counts.preferences;
    let parse_error_count = i64::try_from(import_data.parse_error_count).unwrap_or(i64::MAX);

    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let evidence_id = upsert_browser_history_evidence(
        &tx,
        case_id,
        &import_data.source_path,
        &display_name,
        import_data.family,
        i64::try_from(source_metadata.len()).context("history database size exceeds i64")?,
    )?;
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'browser_history_import', 'running', ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![case_id, evidence_id, import_data.parameters_json],
    )?;
    let job_id = tx.last_insert_rowid();

    tx.execute(
        "DELETE FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
        params![case_id, evidence_id],
    )?;
    import_data.records.for_each_record(|record| {
        let metadata_json: serde_json::Value = serde_json::from_str(&record.metadata_json)
            .with_context(|| format!("parsing browser metadata for {}", record.logical_path))?;
        let metadata_json = metadata_json.to_string();
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            &record.logical_path,
            &record.display_name,
            "record",
            None,
            &metadata_json,
            job_id,
        )?;
        Ok(())
    })?;
    relink_bookmark_items_tx(&tx, case_id, evidence_id)?;
    let status = if truncated { "truncated" } else { "completed" };
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?1,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             error = ?2,
             parameters_json = json_set(parameters_json, '$.entries_indexed', ?3)
         WHERE id = ?4",
        params![
            status,
            truncation_reason,
            i64::try_from(entries_indexed).unwrap_or(i64::MAX),
            job_id
        ],
    )?;
    tx.execute(
        "UPDATE evidence_sources
         SET indexed_at = CASE WHEN ?3 = 0
             THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             ELSE NULL
         END
         WHERE id = ?1 AND case_id = ?2",
        params![evidence_id, case_id, if truncated { 1 } else { 0 }],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'browser_history.import', ?2, 'evidence', ?3,
                 json_object('job_id', ?4, 'entries_indexed', ?5, 'truncated', ?6,
                             'status', ?7, 'truncation_reason', ?8, 'source_path', ?9,
                             'parse_errors', ?10))",
        params![
            case_id,
            actor,
            evidence_id,
            job_id,
            entries_indexed as i64,
            if truncated { 1 } else { 0 },
            status,
            truncation_reason,
            import_data.source_path,
            parse_error_count,
        ],
    )?;
    tx.commit()?;

    Ok(BrowserHistoryImportResult {
        evidence_id,
        job_id,
        source_path: import_data.source_path,
        entries_indexed,
        visits_indexed,
        bookmarks_indexed,
        preferences_indexed,
        truncated,
        visit_limit_reached,
        artifact_limit_reached,
        limited_artifact_kinds: import_data.limited_artifact_kinds,
        status: status.to_string(),
        parse_error_count: import_data.parse_error_count,
        parse_error_samples_omitted: import_data
            .parse_error_count
            .saturating_sub(import_data.parse_errors.len() as u64),
        parse_errors: import_data.parse_errors,
    })
}

pub fn import_browser_artifacts_into_evidence(
    case_path: &Path,
    options: ImportBrowserArtifactsIntoEvidenceOptions,
) -> Result<BrowserHistoryImportResult> {
    let import_data = collect_browser_history_import(&options.history_path, options.max_visits)?;
    persist_browser_artifacts_into_evidence(case_path, options, import_data)
}

pub fn persist_browser_artifacts_into_evidence(
    case_path: &Path,
    options: ImportBrowserArtifactsIntoEvidenceOptions,
    import_data: BrowserHistoryImportData,
) -> Result<BrowserHistoryImportResult> {
    let counts = import_data.records.counts;
    let visit_limit_reached = import_data.total_visits > counts.visits;
    let artifact_limit_reached = import_data.examiner_artifact_limit_reached;
    let parser_errors_present = import_data.parse_error_count > 0;
    let truncated = visit_limit_reached || artifact_limit_reached || parser_errors_present;
    let mut truncation_reasons = Vec::with_capacity(3);
    if visit_limit_reached {
        truncation_reasons.push("examiner visit limit reached");
    }
    if artifact_limit_reached {
        truncation_reasons.push("examiner per-artifact row limit reached");
    }
    if parser_errors_present {
        truncation_reasons.push("one or more browser artifact tables could not be parsed");
    }
    let truncation_reason = (!truncation_reasons.is_empty()).then(|| truncation_reasons.join("; "));
    let visits_indexed = counts.visits;
    let bookmarks_indexed = counts.bookmarks;
    let preferences_indexed = counts.preferences;
    let parse_error_count = i64::try_from(import_data.parse_error_count).unwrap_or(i64::MAX);
    let derivation_key = browser_profile_derivation_key(
        &options.source_profile_path,
        options.volume_index_zero_based,
    );
    let logical_prefix = browser_profile_logical_prefix(
        &options.source_profile_path,
        options.volume_index_zero_based,
        &derivation_key,
    );

    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, options.evidence_id)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    let source_files = load_indexed_browser_source_files(
        &tx,
        case_id,
        options.evidence_id,
        &options.source_profile_path,
        options.volume_index_zero_based,
    )?;
    let mut parameters: serde_json::Value = serde_json::from_str(&import_data.parameters_json)
        .context("parsing browser import job parameters")?;
    if let Some(object) = parameters.as_object_mut() {
        object.insert(
            "derived_into_evidence_id".to_string(),
            serde_json::json!(options.evidence_id),
        );
        object.insert(
            "browser_derivation_key".to_string(),
            serde_json::json!(derivation_key),
        );
        object.insert(
            "source_profile_path".to_string(),
            serde_json::json!(options.source_profile_path),
        );
        object.insert(
            "volume_index_zero_based".to_string(),
            serde_json::json!(options.volume_index_zero_based),
        );
    }
    tx.execute(
        "INSERT INTO evidence_jobs(case_id, evidence_id, job_type, status, parameters_json, started_at)
         VALUES (?1, ?2, 'browser_history_import', 'running', ?3,
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![case_id, options.evidence_id, parameters.to_string()],
    )?;
    let job_id = tx.last_insert_rowid();

    // One profile is one replaceable derived dataset. This makes both a
    // repeated parser run and a full evidence reprocess idempotent.
    tx.execute(
        "DELETE FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND json_extract(metadata_json, '$.browser_derivation_key') = ?3",
        params![case_id, options.evidence_id, derivation_key],
    )?;
    let context = BrowserDerivedImportContext {
        evidence_id: options.evidence_id,
        derivation_key: &derivation_key,
        logical_prefix: &logical_prefix,
        source_profile_path: &options.source_profile_path,
        volume_index_zero_based: options.volume_index_zero_based,
        staging_path: &options.history_path,
        source_files: &source_files,
    };
    let entries_indexed = insert_browser_history_records_into_evidence(
        &tx,
        case_id,
        options.evidence_id,
        job_id,
        &import_data,
        Some(&context),
    )?;
    let _retired_staging_paths = if let Some(legacy_name) = options
        .legacy_evidence_name
        .as_deref()
        .filter(|name| name.contains("(auto-parsed from "))
    {
        retire_legacy_browser_evidence(
            &tx,
            case_id,
            options.evidence_id,
            legacy_name,
            &logical_prefix,
        )?
    } else {
        Vec::new()
    };
    relink_bookmark_items_tx(&tx, case_id, options.evidence_id)?;

    let status = if truncated { "truncated" } else { "completed" };
    tx.execute(
        "UPDATE evidence_jobs
         SET status = ?1,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
             error = ?2,
             parameters_json = json_set(parameters_json, '$.entries_indexed', ?3)
         WHERE id = ?4",
        params![
            status,
            truncation_reason,
            i64::try_from(entries_indexed).unwrap_or(i64::MAX),
            job_id,
        ],
    )?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'browser_history.derive', ?2, 'evidence', ?3,
                 json_object('job_id', ?4, 'entries_indexed', ?5, 'truncated', ?6,
                             'status', ?7, 'source_profile_path', ?8,
                             'browser_derivation_key', ?9, 'parse_errors', ?10))",
        params![
            case_id,
            actor,
            options.evidence_id,
            job_id,
            i64::try_from(entries_indexed).unwrap_or(i64::MAX),
            if truncated { 1 } else { 0 },
            status,
            options.source_profile_path,
            derivation_key,
            parse_error_count,
        ],
    )?;
    tx.commit()?;

    Ok(BrowserHistoryImportResult {
        evidence_id: options.evidence_id,
        job_id,
        source_path: options.source_profile_path,
        entries_indexed,
        visits_indexed,
        bookmarks_indexed,
        preferences_indexed,
        truncated,
        visit_limit_reached,
        artifact_limit_reached,
        limited_artifact_kinds: import_data.limited_artifact_kinds,
        status: status.to_string(),
        parse_error_count: import_data.parse_error_count,
        parse_error_samples_omitted: import_data
            .parse_error_count
            .saturating_sub(import_data.parse_errors.len() as u64),
        parse_errors: import_data.parse_errors,
    })
}

pub fn browser_profile_derivation_key(
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
) -> String {
    let normalized = source_profile_path
        .replace('\\', "/")
        .trim_matches('/')
        .to_string();
    format!(
        "browser-profile:v1:{}:{normalized}",
        volume_index_zero_based
            .map(|value| value.to_string())
            .unwrap_or_else(|| "local".to_string())
    )
}

pub fn browser_profile_logical_prefix(
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
    derivation_key: &str,
) -> String {
    let profile_name = source_profile_path
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("profile");
    let digest = sha256_hex(derivation_key.as_bytes());
    let volume = volume_index_zero_based
        .map(|value| format!("vol-{value}-"))
        .unwrap_or_default();
    format!(
        "/Parsed Artifacts/Browser/{volume}{}-{}",
        sanitize_logical_segment(profile_name),
        &digest[..12]
    )
}

pub fn retire_legacy_browser_evidence(
    conn: &Connection,
    case_id: i64,
    parent_evidence_id: i64,
    legacy_display_name: &str,
    logical_prefix: &str,
) -> Result<Vec<PathBuf>> {
    let mut stmt = conn.prepare(
        "SELECT id, source_path FROM evidence_sources
         WHERE case_id = ?1 AND id <> ?2 AND source_kind = 'browser_history'
           AND display_name = ?3 AND attach_status <> 'superseded'
         ORDER BY id",
    )?;
    let legacy_ids = stmt
        .query_map(
            params![case_id, parent_evidence_id, legacy_display_name],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    PathBuf::from(row.get::<_, String>(1)?),
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(stmt);

    for (legacy_id, _) in &legacy_ids {
        let prefix_expression = "CASE
            WHEN logical_path LIKE '/Browser Activities/%'
            THEN ?3 || logical_path
            ELSE logical_path END";
        conn.execute(
            &format!(
                "UPDATE bookmark_items
                 SET evidence_id = ?1,
                     entry_id = NULL,
                     logical_path = {prefix_expression},
                     item_ref_json = CASE WHEN json_valid(item_ref_json)
                         THEN json_set(item_ref_json,
                              '$.evidence_id', ?1,
                              '$.entry_id', NULL,
                              '$.logical_path', {prefix_expression})
                         ELSE item_ref_json END
                 WHERE evidence_id = ?2"
            ),
            params![parent_evidence_id, legacy_id, logical_prefix],
        )?;
        conn.execute(
            "DELETE FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2",
            params![case_id, legacy_id],
        )?;
        conn.execute(
            "UPDATE evidence_sources
             SET source_kind = 'derived_browser_history_superseded',
                 attach_status = 'superseded',
                 notes = trim(COALESCE(notes || '; ', '') ||
                     'Superseded by idempotent browser artifacts attached to parent evidence ' || ?3)
             WHERE case_id = ?1 AND id = ?2",
            params![case_id, legacy_id, parent_evidence_id],
        )?;
    }
    Ok(legacy_ids.into_iter().map(|(_, path)| path).collect())
}

/// Maps a browser-history record's (family, artifact_kind) to the specific
/// companion filename inside the profile folder that actually holds it -
/// browser profiles are made of several distinct database files (history,
/// logins, cookies, form history are NOT all in one file), so "the source
/// file" is not a single answer for a given profile, only for a given
/// artifact kind within it.
pub fn browser_history_source_filename(family: &str, artifact_kind: &str) -> Option<&'static str> {
    match (family, artifact_kind) {
        ("firefox", "browser_history_visit")
        | ("firefox", "browser_url")
        | ("firefox", "browser_download")
        | ("firefox", "browser_bookmark") => Some("places.sqlite"),
        ("firefox", "browser_login") => Some("logins.json"),
        ("firefox", "browser_cookie") => Some("cookies.sqlite"),
        ("firefox", "browser_search_term") => Some("formhistory.sqlite"),
        ("firefox", "browser_preference") => Some("prefs.js"),
        ("chromium", "browser_history_visit")
        | ("chromium", "browser_url")
        | ("chromium", "browser_download")
        | ("chromium", "browser_search_term") => Some("History"),
        ("chromium", "browser_bookmark") => Some("Bookmarks"),
        ("chromium", "browser_login") => Some("Login Data"),
        ("chromium", "browser_cookie") => Some("Cookies"),
        ("chromium", "browser_preference") => Some("Preferences"),
        ("chromium", "browser_omnibox_shortcut") => Some("Shortcuts"),
        ("chromium", "browser_autofill") => Some("Web Data"),
        ("safari", _) => Some("History.db"),
        _ => None,
    }
}

pub struct ChromiumProfilePaths {
    profile_dir: PathBuf,
    history_path: PathBuf,
    bookmarks_path: PathBuf,
    preferences_path: PathBuf,
    shortcuts_path: PathBuf,
    web_data_path: PathBuf,
}

pub struct FirefoxProfilePaths {
    profile_dir: PathBuf,
    places_path: PathBuf,
    downloads_path: PathBuf,
    formhistory_path: PathBuf,
    cookies_path: PathBuf,
    logins_path: PathBuf,
}

pub struct SafariProfilePaths {
    profile_dir: PathBuf,
    history_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserFamily {
    Chromium,
    Firefox,
    Safari,
}

impl BrowserFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Chromium => "Chromium",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari",
        }
    }
}

/// Returned by [`add_evidence`] when a regular file is a supported browser
/// history database. Callers should route the file's parent directory through
/// the browser-history import flow instead of attaching the database as an
/// ordinary file or disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserDatabaseDetected {
    pub family: BrowserFamily,
}

impl std::fmt::Display for BrowserDatabaseDetected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "detected {} browser history database",
            self.family.label()
        )
    }
}

impl std::error::Error for BrowserDatabaseDetected {}

pub const BROWSER_IMPORT_ERROR_SAMPLE_LIMIT: usize = 32;
// No implicit forensic-coverage caps. Deployments may opt into a positive
// per-object safeguard through the documented environment variables; when
// they do, any omission is counted and the import is marked truncated.
pub const DEFAULT_CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS: usize = usize::MAX;
pub const CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS_ENV: &str = "KDFT_CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS";
pub const DEFAULT_CHROMIUM_PREFERENCES_MAX_BYTES: u64 = u64::MAX;
pub const CHROMIUM_PREFERENCES_MAX_BYTES_ENV: &str = "KDFT_CHROMIUM_PREFERENCES_MAX_BYTES";

pub fn configured_positive_usize(name: &str, default_value: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_value)
}

pub fn configured_positive_u64(name: &str, default_value: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_value)
}

pub fn configured_chromium_download_url_chain_limit() -> usize {
    configured_positive_usize(
        CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS_ENV,
        DEFAULT_CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS,
    )
}

pub fn configured_chromium_preferences_max_bytes() -> u64 {
    configured_positive_u64(
        CHROMIUM_PREFERENCES_MAX_BYTES_ENV,
        DEFAULT_CHROMIUM_PREFERENCES_MAX_BYTES,
    )
}

#[derive(Debug, Clone, Copy)]
pub enum BrowserRecordKind {
    Visit,
    Bookmark,
    Preference,
    Url,
    Search,
    Omnibox,
    Autofill,
    Download,
    Login,
    Cookie,
}

impl BrowserRecordKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Visit => "visit",
            Self::Bookmark => "bookmark",
            Self::Preference => "preference",
            Self::Url => "url",
            Self::Search => "search",
            Self::Omnibox => "omnibox",
            Self::Autofill => "autofill",
            Self::Download => "download",
            Self::Login => "login",
            Self::Cookie => "cookie",
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BrowserRecordCounts {
    pub visits: usize,
    pub bookmarks: usize,
    pub preferences: usize,
    pub urls: usize,
    pub searches: usize,
    pub omnibox: usize,
    pub autofill: usize,
    pub downloads: usize,
    pub logins: usize,
    pub cookies: usize,
}

impl BrowserRecordCounts {
    pub fn increment(&mut self, kind: BrowserRecordKind) {
        let count = match kind {
            BrowserRecordKind::Visit => &mut self.visits,
            BrowserRecordKind::Bookmark => &mut self.bookmarks,
            BrowserRecordKind::Preference => &mut self.preferences,
            BrowserRecordKind::Url => &mut self.urls,
            BrowserRecordKind::Search => &mut self.searches,
            BrowserRecordKind::Omnibox => &mut self.omnibox,
            BrowserRecordKind::Autofill => &mut self.autofill,
            BrowserRecordKind::Download => &mut self.downloads,
            BrowserRecordKind::Login => &mut self.logins,
            BrowserRecordKind::Cookie => &mut self.cookies,
        };
        *count = count.saturating_add(1);
    }

    pub fn total(self) -> usize {
        self.visits
            .saturating_add(self.bookmarks)
            .saturating_add(self.preferences)
            .saturating_add(self.urls)
            .saturating_add(self.searches)
            .saturating_add(self.omnibox)
            .saturating_add(self.autofill)
            .saturating_add(self.downloads)
            .saturating_add(self.logins)
            .saturating_add(self.cookies)
    }
}

#[derive(Default)]
pub struct BrowserImportDiagnostics {
    pub(crate) samples: Vec<String>,
    pub(crate) total: u64,
}

impl BrowserImportDiagnostics {
    pub(crate) fn record(&mut self, message: String) {
        self.total = self.total.saturating_add(1);
        progress::progress_diagnostic(
            progress::JobDiagnosticKind::ParserDiagnostic,
            message.clone(),
        );
        if self.samples.len() < BROWSER_IMPORT_ERROR_SAMPLE_LIMIT {
            self.samples.push(message);
        }
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.total = self.total.saturating_add(other.total);
        let remaining = BROWSER_IMPORT_ERROR_SAMPLE_LIMIT.saturating_sub(self.samples.len());
        self.samples
            .extend(other.samples.into_iter().take(remaining));
    }
}

/// Disk-backed record sink used by all browser collectors. Producers emit one
/// record at a time, and persistence reads one record at a time, so an
/// unlimited import has constant retained record memory instead of ten
/// unbounded vectors. The temporary SQLite database is transactionally filled
/// and removed automatically after the case transaction consumes it.
pub struct BrowserRecordSpool {
    conn: Connection,
    _guard: TempFileGuard,
    pub(crate) counts: BrowserRecordCounts,
    collecting: bool,
}

pub fn reserve_unique_browser_spool_path(prefix: &str, source_hint: &Path) -> Result<PathBuf> {
    static NEXT_SPOOL_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let source_name = source_hint
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("browser-source");
    for _ in 0..128 {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let nonce = NEXT_SPOOL_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{timestamp}-{nonce}-{}.sqlite",
            std::process::id(),
            sanitize_logical_segment(source_name)
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                drop(file);
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reserving browser spool {}", path.display()));
            }
        }
    }
    bail!("could not reserve a unique browser spool after 128 attempts")
}

impl BrowserRecordSpool {
    pub(crate) fn new(source_hint: &Path) -> Result<Self> {
        let path = reserve_unique_browser_spool_path("kdft-browser-records", source_hint)?;
        let guard = TempFileGuard::new(path.clone());
        let conn = Connection::open(&path)
            .with_context(|| format!("creating browser record spool {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA temp_store = MEMORY;
             CREATE TABLE browser_records(
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 record_kind TEXT NOT NULL,
                 logical_path TEXT NOT NULL,
                 display_name TEXT NOT NULL,
                 metadata_json TEXT NOT NULL
             );
             BEGIN IMMEDIATE;",
        )
        .context("initializing browser record spool")?;
        Ok(Self {
            conn,
            _guard: guard,
            counts: BrowserRecordCounts::default(),
            collecting: true,
        })
    }

    pub(crate) fn push(&mut self, kind: BrowserRecordKind, record: BrowserActivityRecord) -> Result<()> {
        let logical_path = record.logical_path;
        {
            let mut stmt = self.conn.prepare_cached(
                "INSERT INTO browser_records(record_kind, logical_path, display_name, metadata_json)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            stmt.execute(params![
                kind.as_str(),
                &logical_path,
                record.display_name,
                record.metadata_json
            ])?;
        }
        self.counts.increment(kind);
        progress::progress_database_entry(logical_path);
        Ok(())
    }

    pub(crate) fn seal(&mut self) -> Result<()> {
        if self.collecting {
            self.conn
                .execute_batch("COMMIT")
                .context("committing browser record spool")?;
            self.collecting = false;
        }
        Ok(())
    }

    pub(crate) fn for_each_record(
        &self,
        mut consume: impl FnMut(BrowserActivityRecord) -> Result<()>,
    ) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "SELECT logical_path, display_name, metadata_json
             FROM browser_records ORDER BY sequence",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            consume(BrowserActivityRecord {
                logical_path: row.get(0)?,
                display_name: row.get(1)?,
                metadata_json: row.get(2)?,
            })?;
        }
        Ok(())
    }
}

pub struct BrowserHistoryImportData {
    pub(crate) family: BrowserFamily,
    pub(crate) source_path: String,
    pub(crate) primary_db_path: PathBuf,
    pub(crate) default_display_name: String,
    pub(crate) parameters_json: String,
    pub(crate) records: BrowserRecordSpool,
    pub(crate) total_visits: usize,
    pub(crate) examiner_artifact_limit_reached: bool,
    pub(crate) limited_artifact_kinds: Vec<String>,
    /// Reader failures disclosed per artifact class ("cookies: no such
    /// column ..."). Persisted with the import so a parse failure is never
    /// presented as an artifact-free profile.
    pub(crate) parse_errors: Vec<String>,
    pub(crate) parse_error_count: u64,
}

impl BrowserHistoryImportData {
    pub(crate) fn add_diagnostics(&mut self, diagnostics: BrowserImportDiagnostics) -> Result<()> {
        self.parse_error_count = self.parse_error_count.saturating_add(diagnostics.total);
        let remaining = BROWSER_IMPORT_ERROR_SAMPLE_LIMIT.saturating_sub(self.parse_errors.len());
        self.parse_errors
            .extend(diagnostics.samples.into_iter().take(remaining));
        let mut parameters: serde_json::Value = serde_json::from_str(&self.parameters_json)
            .context("parsing browser import parameters for diagnostics")?;
        if let Some(object) = parameters.as_object_mut() {
            object.insert(
                "parse_errors".to_string(),
                serde_json::json!(self.parse_errors),
            );
            object.insert(
                "parse_error_count".to_string(),
                serde_json::json!(self.parse_error_count),
            );
            object.insert(
                "parse_error_samples_omitted".to_string(),
                serde_json::json!(self
                    .parse_error_count
                    .saturating_sub(self.parse_errors.len() as u64)),
            );
        }
        self.parameters_json = parameters.to_string();
        Ok(())
    }
}

pub struct BrowserActivityRecord {
    pub(crate) logical_path: String,
    pub(crate) display_name: String,
    pub(crate) metadata_json: String,
}

/// Adapter that lets the existing row-to-record builders retain their simple
/// `push` shape while forwarding each record immediately to a bounded sink.
/// The first sink error is retained and returned after the SQLite row iterator
/// is dropped; no record vector is accumulated.
pub struct BrowserRecordEmitter<'a> {
    emit: &'a mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
    emitted: usize,
    error: Option<anyhow::Error>,
}

impl<'a> BrowserRecordEmitter<'a> {
    pub(crate) fn new(emit: &'a mut dyn FnMut(BrowserActivityRecord) -> Result<()>) -> Self {
        Self {
            emit,
            emitted: 0,
            error: None,
        }
    }

    pub(crate) fn push(&mut self, record: BrowserActivityRecord) {
        if self.error.is_some() {
            return;
        }
        match (self.emit)(record) {
            Ok(()) => self.emitted = self.emitted.saturating_add(1),
            Err(error) => self.error = Some(error),
        }
    }

    pub(crate) fn finish(self) -> Result<usize> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.emitted),
        }
    }
}

pub struct ChromiumHistoryRow {
    visit_id: i64,
    url_id: i64,
    url: String,
    title: Option<String>,
    visit_time: i64,
    last_visit_time: Option<i64>,
    visit_count: Option<i64>,
    typed_count: Option<i64>,
    transition: Option<i64>,
    visit_duration: Option<i64>,
    hidden: Option<i64>,
    from_visit_id: Option<i64>,
    referrer_url: Option<String>,
    referrer_visit_time: Option<i64>,
    opener_visit_id: Option<i64>,
    opener_url: Option<String>,
    external_referrer_url: Option<String>,
    visit_source: Option<i64>,
}

impl ChromiumHistoryRow {
    fn display_name(&self) -> String {
        self.title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.url)
            .chars()
            .take(180)
            .collect()
    }

    fn logical_path(&self) -> String {
        let host = sanitize_logical_segment(&host_from_url(&self.url));
        format!(
            "/Browser Activities/Visits/{}/{}-{}.record",
            host, self.visit_time, self.visit_id
        )
    }
}

pub struct ChromiumDownloadRow {
    id: i64,
    current_path: Option<String>,
    target_path: Option<String>,
    full_path: Option<String>,
    legacy_url: Option<String>,
    start_time: Option<i64>,
    end_time: Option<i64>,
    received_bytes: Option<i64>,
    total_bytes: Option<i64>,
    state: Option<i64>,
    danger_type: Option<i64>,
    interrupt_reason: Option<i64>,
    referrer: Option<String>,
    tab_url: Option<String>,
    mime_type: Option<String>,
    guid: Option<String>,
    site_url: Option<String>,
    tab_referrer_url: Option<String>,
    original_mime_type: Option<String>,
    last_access_time: Option<i64>,
    opened: Option<i64>,
    hash_hex: Option<String>,
}

pub struct FirefoxHistoryRow {
    visit_id: i64,
    place_id: i64,
    url: String,
    title: Option<String>,
    visit_date: Option<i64>,
    visit_type: Option<i64>,
    visit_count: Option<i64>,
    typed: Option<i64>,
    last_visit_date: Option<i64>,
    frecency: Option<i64>,
}

impl FirefoxHistoryRow {
    fn display_name(&self) -> String {
        self.title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.url)
            .chars()
            .take(180)
            .collect()
    }

    fn logical_path(&self) -> String {
        let host = sanitize_logical_segment(&host_from_url(&self.url));
        format!(
            "/Browser Activities/Visits/{}/{}-{}.record",
            host,
            self.visit_date.unwrap_or_default(),
            self.visit_id
        )
    }
}

pub struct SafariHistoryRow {
    visit_id: i64,
    history_item_id: i64,
    url: String,
    title: Option<String>,
    visit_time: Option<f64>,
    visit_count: Option<i64>,
    domain_expansion: Option<String>,
}

impl SafariHistoryRow {
    fn display_name(&self) -> String {
        self.title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.url)
            .chars()
            .take(180)
            .collect()
    }

    fn logical_path(&self) -> String {
        let host = sanitize_logical_segment(&host_from_url(&self.url));
        let visit_time = self.visit_time.unwrap_or_default();
        format!(
            "/Browser Activities/Visits/{}/{}-{}.record",
            host, visit_time, self.visit_id
        )
    }
}


pub fn stream_chromium_history_records(
    history_path: &Path,
    max_visits: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<(usize, usize)> {
    let (conn, _copy_guard) = open_sqlite_copy_read_only(history_path)?;
    let total_visits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM visits v JOIN urls u ON u.id = v.url",
            [],
            |row| row.get(0),
        )
        .context("counting Chromium history visits")?;
    let last_visit_time = sql_column_or_null(&conn, "urls", "u.", "last_visit_time")?;
    let visit_count = sql_column_or_null(&conn, "urls", "u.", "visit_count")?;
    let typed_count = sql_column_or_null(&conn, "urls", "u.", "typed_count")?;
    let transition = sql_column_or_null(&conn, "visits", "v.", "transition")?;
    let visit_duration = sql_column_or_null(&conn, "visits", "v.", "visit_duration")?;
    let hidden = sql_column_or_null(&conn, "urls", "u.", "hidden")?;
    let from_visit = sql_column_or_null(&conn, "visits", "v.", "from_visit")?;
    let opener_visit = sql_column_or_null(&conn, "visits", "v.", "opener_visit")?;
    let external_referrer_url = sql_column_or_null(&conn, "visits", "v.", "external_referrer_url")?;
    let (visit_source, visit_source_join) = if sqlite_table_exists(&conn, "visit_source")? {
        (
            sql_column_or_null(&conn, "visit_source", "vs.", "source")?,
            "LEFT JOIN visit_source vs ON vs.id = v.id",
        )
    } else {
        ("NULL".to_string(), "")
    };
    // Resolve referrer and opener rows before applying LIMIT. A capped import
    // can therefore still explain a retained visit whose predecessor is older
    // than the cap instead of presenting a broken navigation chain.
    let sql = format!(
        "SELECT v.id, v.url, u.url, u.title, v.visit_time, {last_visit_time},
                {visit_count}, {typed_count}, {transition}, {visit_duration}, {hidden},
                {from_visit}, ref_url.url, ref_visit.visit_time,
                {opener_visit}, opener_url.url, {external_referrer_url}, {visit_source}
         FROM visits v
         JOIN urls u ON u.id = v.url
         LEFT JOIN visits ref_visit ON ref_visit.id = {from_visit}
         LEFT JOIN urls ref_url ON ref_url.id = ref_visit.url
         LEFT JOIN visits opener ON opener.id = {opener_visit}
         LEFT JOIN urls opener_url ON opener_url.id = opener.url
         {visit_source_join}
         ORDER BY v.visit_time DESC, v.id DESC
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_visits)], |row| {
        Ok(ChromiumHistoryRow {
            visit_id: row.get(0)?,
            url_id: row.get(1)?,
            url: row.get(2)?,
            title: row.get(3)?,
            visit_time: row.get(4)?,
            last_visit_time: row.get(5)?,
            visit_count: row.get(6)?,
            typed_count: row.get(7)?,
            transition: row.get(8)?,
            visit_duration: row.get(9)?,
            hidden: row.get(10)?,
            from_visit_id: nonzero_optional_i64(row.get(11)?),
            referrer_url: row.get(12)?,
            referrer_visit_time: row.get(13)?,
            opener_visit_id: nonzero_optional_i64(row.get(14)?),
            opener_url: row.get(15)?,
            external_referrer_url: row.get(16)?,
            visit_source: row.get(17)?,
        })
    })?;
    let source_metadata = source_artifact_metadata(history_path, "History");
    let mut emitted = 0_usize;
    for row in rows {
        let row = row.context("reading Chromium history visit")?;
        emit(browser_history_visit_record(&row, &source_metadata))?;
        emitted = emitted.saturating_add(1);
    }
    Ok((emitted, usize::try_from(total_visits).unwrap_or(usize::MAX)))
}

pub fn browser_history_visit_record(
    row: &ChromiumHistoryRow,
    source_metadata: &serde_json::Value,
) -> BrowserActivityRecord {
    BrowserActivityRecord {
        logical_path: row.logical_path(),
        display_name: row.display_name(),
        metadata_json: browser_history_metadata_json(row, source_metadata),
    }
}

pub(crate) fn open_sqlite_copy_read_only(path: &Path) -> Result<(Connection, TempFileGuard)> {
    let guard = copy_sqlite_database_to_temp(path)?;
    // The evidence is copied first. Open the disposable copy read/write so
    // SQLite can recover a hot rollback journal or checkpoint a copied WAL;
    // the original forensic artifact and its sidecars remain untouched.
    let conn = Connection::open_with_flags(&guard.path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("opening browser database copy {}", guard.path.display()))?;
    Ok((conn, guard))
}

/// Detect a supported browser history database by SQLite header and schema.
///
/// This is deliberately a best-effort attach-time sniff: inaccessible,
/// locked, truncated, and corrupt files are reported as `Ok(None)` so a failed
/// probe can never prevent the caller from attaching the file normally.
pub fn detect_browser_database(path: &Path) -> Result<Option<BrowserFamily>> {
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

    let mut header = [0_u8; SQLITE_HEADER.len()];
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    if file.read_exact(&mut header).is_err() || &header != SQLITE_HEADER {
        return Ok(None);
    }

    let (conn, _guard) = match open_sqlite_copy_read_only(path) {
        Ok(opened) => opened,
        Err(_) => return Ok(None),
    };
    let mut stmt = match conn.prepare(
        "SELECT lower(name)
         FROM sqlite_master
         WHERE type = 'table'
           AND lower(name) IN (
               'urls', 'visits', 'moz_places', 'history_visits', 'history_items'
           )",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return Ok(None),
    };
    let names = match stmt.query_map([], |row| row.get::<_, String>(0)) {
        Ok(rows) => {
            let mut names = HashSet::new();
            for row in rows {
                let Ok(name) = row else {
                    return Ok(None);
                };
                names.insert(name);
            }
            names
        }
        Err(_) => return Ok(None),
    };

    let mut matches = Vec::new();
    if names.contains("urls") && names.contains("visits") {
        matches.push(BrowserFamily::Chromium);
    }
    if names.contains("moz_places") {
        matches.push(BrowserFamily::Firefox);
    }
    if names.contains("history_visits") || names.contains("history_items") {
        matches.push(BrowserFamily::Safari);
    }
    Ok(match matches.as_slice() {
        [family] => Some(*family),
        _ => None,
    })
}

pub(crate) fn copy_sqlite_database_to_temp(path: &Path) -> Result<TempFileGuard> {
    static NEXT_HISTORY_COPY_NONCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);
    let (copy_path, mut output) = (0..128)
        .find_map(|_| {
            let nonce = NEXT_HISTORY_COPY_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let candidate = temp_history_copy_path(path, nonce);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => Some(Ok((candidate, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error).with_context(|| {
                    format!("reserving browser database copy {}", candidate.display())
                })),
            }
        })
        .transpose()?
        .ok_or_else(|| anyhow!("could not reserve a unique browser database copy"))?;
    let mut guard = TempFileGuard::new(copy_path);
    let mut input = fs::File::open(path)
        .with_context(|| format!("opening browser database {}", path.display()))?;
    io::copy(&mut input, &mut output).with_context(|| {
        format!(
            "copying browser database {} to {}",
            path.display(),
            guard.path.display()
        )
    })?;
    output
        .flush()
        .with_context(|| format!("flushing browser database copy {}", guard.path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("syncing browser database copy {}", guard.path.display()))?;
    drop(output);
    let dest_db = guard.path.clone();
    copy_sqlite_sidecar_if_present(path, &dest_db, "-wal", &mut guard)?;
    copy_sqlite_sidecar_if_present(path, &dest_db, "-shm", &mut guard)?;
    copy_sqlite_sidecar_if_present(path, &dest_db, "-journal", &mut guard)?;
    Ok(guard)
}

pub(crate) fn copy_sqlite_sidecar_if_present(
    source_db: &Path,
    dest_db: &Path,
    suffix: &str,
    guard: &mut TempFileGuard,
) -> Result<()> {
    let source_sidecar = sqlite_sidecar_path(source_db, suffix);
    let metadata = match fs::metadata(&source_sidecar) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading SQLite sidecar {}", source_sidecar.display()))
        }
    };
    if !metadata.is_file() {
        return Ok(());
    }

    let dest_sidecar = sqlite_sidecar_path(dest_db, suffix);
    let mut source = match fs::File::open(&source_sidecar) {
        Ok(source) => source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening SQLite sidecar {}", source_sidecar.display()))
        }
    };
    let mut destination = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dest_sidecar)
    {
        Ok(destination) => destination,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "creating SQLite sidecar copy without replacing {}",
                    dest_sidecar.display()
                )
            });
        }
    };
    guard.add_sidecar(dest_sidecar.clone());
    match io::copy(&mut source, &mut destination) {
        Ok(_) => {
            destination.flush().with_context(|| {
                format!("flushing SQLite sidecar copy {}", dest_sidecar.display())
            })?;
            destination.sync_all().with_context(|| {
                format!("syncing SQLite sidecar copy {}", dest_sidecar.display())
            })?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "copying SQLite sidecar {} to {}",
                source_sidecar.display(),
                dest_sidecar.display()
            )
        }),
    }
}

pub fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

pub fn history_limit_json(max_rows: usize) -> serde_json::Value {
    if max_rows == usize::MAX {
        serde_json::Value::String("unlimited".to_string())
    } else {
        serde_json::json!(max_rows)
    }
}

pub fn byte_limit_json(max_bytes: u64) -> serde_json::Value {
    if max_bytes == u64::MAX {
        serde_json::Value::String("unlimited".to_string())
    } else {
        serde_json::json!(max_bytes)
    }
}

pub fn sqlite_limit_param(max_rows: usize) -> i64 {
    if max_rows == usize::MAX {
        -1
    } else {
        i64::try_from(max_rows).unwrap_or(i64::MAX)
    }
}

pub fn browser_limit_probe(max_rows: usize) -> usize {
    if max_rows == usize::MAX {
        usize::MAX
    } else {
        max_rows.saturating_add(1)
    }
}

pub fn sqlite_table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_master
            WHERE type IN ('table', 'view') AND name = ?1
            LIMIT 1
        )",
        params![table_name],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .context("checking SQLite schema table")
}

pub fn sqlite_column_exists(conn: &Connection, table_name: &str, column_name: &str) -> Result<bool> {
    let escaped = table_name.replace('\'', "''");
    let pragma = format!("PRAGMA table_info('{escaped}')");
    let mut stmt = conn.prepare(&pragma)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row?.eq_ignore_ascii_case(column_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// SQL expression for a browser-schema column that older database
/// generations may not have (for example Firefox 3.0-era places.sqlite has no
/// moz_places.last_visit_date and 2008-era formhistory.sqlite has only
/// id/fieldname/value). Missing columns select NULL so era-specific databases
/// still parse instead of failing the whole reader.
pub fn sql_column_or_null(
    conn: &Connection,
    table_name: &str,
    prefix: &str,
    column_name: &str,
) -> Result<String> {
    Ok(if sqlite_column_exists(conn, table_name, column_name)? {
        format!("{prefix}{column_name}")
    } else {
        "NULL".to_string()
    })
}

pub fn collect_browser_record_stream(
    label: &str,
    kind: BrowserRecordKind,
    spool: &mut BrowserRecordSpool,
    diagnostics: &mut BrowserImportDiagnostics,
    chromium_profile_path: Option<&str>,
    output_limit: usize,
    produce: impl FnOnce(&mut dyn FnMut(BrowserActivityRecord) -> Result<()>) -> Result<usize>,
) -> bool {
    let mut observed = 0_usize;
    let mut emit = |mut record: BrowserActivityRecord| -> Result<()> {
        observed = observed.saturating_add(1);
        if observed > output_limit {
            return Ok(());
        }
        if let Some(profile_path) = chromium_profile_path {
            apply_chromium_browser_brand_to_record(&mut record, profile_path)?;
        }
        spool.push(kind, record)
    };
    match produce(&mut emit) {
        Ok(produced) => produced.max(observed) > output_limit,
        Err(error) => {
            diagnostics.record(format!("{label}: {error:#}"));
            false
        }
    }
}

pub fn collect_browser_visit_stream(
    label: &str,
    spool: &mut BrowserRecordSpool,
    diagnostics: &mut BrowserImportDiagnostics,
    chromium_profile_path: Option<&str>,
    produce: impl FnOnce(&mut dyn FnMut(BrowserActivityRecord) -> Result<()>) -> Result<(usize, usize)>,
) -> usize {
    let mut emit = |mut record: BrowserActivityRecord| -> Result<()> {
        if let Some(profile_path) = chromium_profile_path {
            apply_chromium_browser_brand_to_record(&mut record, profile_path)?;
        }
        spool.push(BrowserRecordKind::Visit, record)
    };
    match produce(&mut emit) {
        Ok((_, total_visits)) => total_visits,
        Err(error) => {
            diagnostics.record(format!("{label}: {error:#}"));
            0
        }
    }
}

pub fn chromium_browser_brand(profile_path: &str) -> Option<&'static str> {
    let normalized = profile_path.replace('\\', "/").to_ascii_lowercase();
    if normalized.contains("google/chrome") || normalized.contains("google-chrome") {
        Some("chrome")
    } else if normalized.contains("microsoft/edge") || normalized.contains("microsoft-edge") {
        Some("edge")
    } else if normalized.contains("bravesoftware") || normalized.contains("brave-browser") {
        Some("brave")
    } else if normalized.contains("opera") {
        Some("opera")
    } else if normalized.contains("chromium") {
        Some("chromium")
    } else {
        None
    }
}

pub fn apply_chromium_browser_brand_to_record(
    record: &mut BrowserActivityRecord,
    profile_path: &str,
) -> Result<()> {
    let browser_brand = chromium_browser_brand(profile_path);
    let mut metadata: serde_json::Value = serde_json::from_str(&record.metadata_json)
        .with_context(|| format!("parsing Chromium record {}", record.logical_path))?;
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "browser_brand".to_string(),
            serde_json::json!(browser_brand),
        );
    }
    record.metadata_json = metadata.to_string();
    Ok(())
}

pub fn collect_chromium_history_import(
    input_path: &Path,
    max_visits: usize,
) -> Result<BrowserHistoryImportData> {
    collect_chromium_history_import_with_protections(
        input_path,
        max_visits,
        configured_chromium_download_url_chain_limit(),
        configured_chromium_preferences_max_bytes(),
    )
}

pub fn collect_chromium_history_import_with_protections(
    input_path: &Path,
    max_visits: usize,
    max_download_url_chain_urls: usize,
    max_preferences_bytes: u64,
) -> Result<BrowserHistoryImportData> {
    let profile_paths = chromium_profile_paths(input_path)?;
    let profile_path = profile_paths.profile_dir.to_string_lossy().into_owned();
    let mut records = BrowserRecordSpool::new(&profile_paths.history_path)?;
    let mut diagnostics = BrowserImportDiagnostics::default();
    let mut limited_artifact_kinds = Vec::new();
    let total_visits = collect_browser_visit_stream(
        "history visits",
        &mut records,
        &mut diagnostics,
        Some(&profile_path),
        |emit| stream_chromium_history_records(&profile_paths.history_path, max_visits, emit),
    );
    collect_browser_record_stream(
        "bookmarks",
        BrowserRecordKind::Bookmark,
        &mut records,
        &mut diagnostics,
        Some(&profile_path),
        usize::MAX,
        |emit| stream_chromium_bookmark_records(&profile_paths.bookmarks_path, emit),
    );
    collect_browser_record_stream(
        "preferences",
        BrowserRecordKind::Preference,
        &mut records,
        &mut diagnostics,
        Some(&profile_path),
        usize::MAX,
        |emit| {
            stream_chromium_preference_records(
                &profile_paths.preferences_path,
                max_preferences_bytes,
                emit,
            )
        },
    );
    for (label, kind, path_kind) in [
        ("urls", BrowserRecordKind::Url, 0_u8),
        ("search terms", BrowserRecordKind::Search, 1),
        ("omnibox shortcuts", BrowserRecordKind::Omnibox, 2),
        ("autofill", BrowserRecordKind::Autofill, 3),
        ("logins", BrowserRecordKind::Login, 4),
        ("cookies", BrowserRecordKind::Cookie, 5),
    ] {
        if collect_browser_record_stream(
            label,
            kind,
            &mut records,
            &mut diagnostics,
            Some(&profile_path),
            max_visits,
            |emit| match path_kind {
                0 => stream_chromium_url_records(
                    &profile_paths.history_path,
                    browser_limit_probe(max_visits),
                    emit,
                ),
                1 => stream_chromium_search_records(
                    &profile_paths.history_path,
                    browser_limit_probe(max_visits),
                    emit,
                ),
                2 => stream_chromium_omnibox_shortcut_records(
                    &profile_paths.shortcuts_path,
                    browser_limit_probe(max_visits),
                    emit,
                ),
                3 => stream_chromium_autofill_records(
                    &profile_paths.web_data_path,
                    browser_limit_probe(max_visits),
                    emit,
                ),
                4 => stream_chromium_login_records(
                    &profile_paths.profile_dir,
                    browser_limit_probe(max_visits),
                    emit,
                ),
                _ => stream_chromium_cookie_records(
                    &profile_paths.profile_dir,
                    browser_limit_probe(max_visits),
                    emit,
                ),
            },
        ) {
            limited_artifact_kinds.push(label.to_string());
        }
    }
    let mut download_diagnostics = BrowserImportDiagnostics::default();
    if collect_browser_record_stream(
        "downloads",
        BrowserRecordKind::Download,
        &mut records,
        &mut diagnostics,
        Some(&profile_path),
        max_visits,
        |emit| {
            stream_chromium_download_records(
                &profile_paths.history_path,
                browser_limit_probe(max_visits),
                max_download_url_chain_urls,
                &mut download_diagnostics,
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("downloads".to_string());
    }
    diagnostics.merge(download_diagnostics);
    records.seal()?;
    let parse_errors = diagnostics.samples;
    let parse_error_count = diagnostics.total;
    let source_path = stable_path_string(&profile_paths.profile_dir);
    let parameters_json = serde_json::json!({
        "browser_family": BrowserFamily::Chromium.as_str(),
        "history_path": source_path,
        "profile_dir": profile_paths.profile_dir.to_string_lossy(),
        "history_db": profile_paths.history_path.to_string_lossy(),
        "bookmarks_file": profile_paths.bookmarks_path.to_string_lossy(),
        "preferences_file": profile_paths.preferences_path.to_string_lossy(),
        "preferences_protective_max_bytes": byte_limit_json(max_preferences_bytes),
        "preferences_protective_max_bytes_configuration": CHROMIUM_PREFERENCES_MAX_BYTES_ENV,
        "download_url_chain_protective_max_urls": history_limit_json(max_download_url_chain_urls),
        "download_url_chain_protective_max_urls_configuration": CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS_ENV,
        "shortcuts_file": profile_paths.shortcuts_path.to_string_lossy(),
        "web_data_file": profile_paths.web_data_path.to_string_lossy(),
        "max_visits": history_limit_json(max_visits),
        "max_visits_scope": "visits and each row-oriented browser artifact class; bookmarks and selected preference fields are not row-capped",
        "artifact_limit_reached": !limited_artifact_kinds.is_empty(),
        "limited_artifact_kinds": &limited_artifact_kinds,
        "parse_errors": parse_errors,
        "parse_error_count": parse_error_count,
        "parse_error_samples_omitted": parse_error_count.saturating_sub(parse_errors.len() as u64)
    })
    .to_string();
    Ok(BrowserHistoryImportData {
        family: BrowserFamily::Chromium,
        source_path,
        primary_db_path: profile_paths.history_path.clone(),
        default_display_name: default_browser_history_display_name(
            BrowserFamily::Chromium,
            &profile_paths.profile_dir,
        ),
        parameters_json,
        records,
        total_visits,
        examiner_artifact_limit_reached: !limited_artifact_kinds.is_empty(),
        limited_artifact_kinds,
        parse_error_count,
        parse_errors,
    })
}

pub fn collect_firefox_history_import(
    input_path: &Path,
    max_visits: usize,
) -> Result<BrowserHistoryImportData> {
    let profile_paths = firefox_profile_paths(input_path)?;
    let mut records = BrowserRecordSpool::new(&profile_paths.places_path)?;
    let mut diagnostics = BrowserImportDiagnostics::default();
    let mut limited_artifact_kinds = Vec::new();
    let total_visits = collect_browser_visit_stream(
        "history visits",
        &mut records,
        &mut diagnostics,
        None,
        |emit| stream_firefox_history_records(&profile_paths.places_path, max_visits, emit),
    );
    if collect_browser_record_stream(
        "bookmarks",
        BrowserRecordKind::Bookmark,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_bookmark_records(
                &profile_paths.places_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("bookmarks".to_string());
    }
    if collect_browser_record_stream(
        "urls",
        BrowserRecordKind::Url,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_url_records(
                &profile_paths.places_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("urls".to_string());
    }
    if collect_browser_record_stream(
        "search terms",
        BrowserRecordKind::Search,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_search_records(
                &profile_paths.formhistory_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("search terms".to_string());
    }
    if collect_browser_record_stream(
        "downloads",
        BrowserRecordKind::Download,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_download_records(
                &profile_paths.places_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("downloads".to_string());
    }
    if collect_browser_record_stream(
        "downloads (downloads.sqlite)",
        BrowserRecordKind::Download,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_downloads_sqlite_records(
                &profile_paths.downloads_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("downloads (downloads.sqlite)".to_string());
    }
    if collect_browser_record_stream(
        "logins",
        BrowserRecordKind::Login,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_login_records(
                &profile_paths.logins_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("logins".to_string());
    }
    if collect_browser_record_stream(
        "cookies",
        BrowserRecordKind::Cookie,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_firefox_cookie_records(
                &profile_paths.cookies_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("cookies".to_string());
    }
    records.seal()?;
    let parse_errors = diagnostics.samples;
    let parse_error_count = diagnostics.total;
    let source_path = stable_path_string(&profile_paths.profile_dir);
    let parameters_json = serde_json::json!({
        "browser_family": BrowserFamily::Firefox.as_str(),
        "history_path": source_path,
        "profile_dir": profile_paths.profile_dir.to_string_lossy(),
        "places_file": profile_paths.places_path.to_string_lossy(),
        "downloads_file": profile_paths.downloads_path.to_string_lossy(),
        "formhistory_file": profile_paths.formhistory_path.to_string_lossy(),
        "cookies_file": profile_paths.cookies_path.to_string_lossy(),
        "logins_file": profile_paths.logins_path.to_string_lossy(),
        "max_visits": history_limit_json(max_visits),
        "max_visits_scope": "visits and each row-oriented browser artifact class",
        "artifact_limit_reached": !limited_artifact_kinds.is_empty(),
        "limited_artifact_kinds": &limited_artifact_kinds,
        "parse_errors": parse_errors,
        "parse_error_count": parse_error_count,
        "parse_error_samples_omitted": parse_error_count.saturating_sub(parse_errors.len() as u64)
    })
    .to_string();
    Ok(BrowserHistoryImportData {
        family: BrowserFamily::Firefox,
        source_path,
        primary_db_path: profile_paths.places_path.clone(),
        default_display_name: default_browser_history_display_name(
            BrowserFamily::Firefox,
            &profile_paths.profile_dir,
        ),
        parameters_json,
        records,
        total_visits,
        examiner_artifact_limit_reached: !limited_artifact_kinds.is_empty(),
        limited_artifact_kinds,
        parse_error_count,
        parse_errors,
    })
}

pub fn collect_safari_history_import(
    input_path: &Path,
    max_visits: usize,
) -> Result<BrowserHistoryImportData> {
    let profile_paths = safari_profile_paths(input_path)?;
    let mut records = BrowserRecordSpool::new(&profile_paths.history_path)?;
    let mut diagnostics = BrowserImportDiagnostics::default();
    let mut limited_artifact_kinds = Vec::new();
    let total_visits = collect_browser_visit_stream(
        "history visits",
        &mut records,
        &mut diagnostics,
        None,
        |emit| stream_safari_history_records(&profile_paths.history_path, max_visits, emit),
    );
    if collect_browser_record_stream(
        "urls",
        BrowserRecordKind::Url,
        &mut records,
        &mut diagnostics,
        None,
        max_visits,
        |emit| {
            stream_safari_url_records(
                &profile_paths.history_path,
                browser_limit_probe(max_visits),
                emit,
            )
        },
    ) {
        limited_artifact_kinds.push("urls".to_string());
    }
    records.seal()?;
    let parse_errors = diagnostics.samples;
    let parse_error_count = diagnostics.total;
    let source_path = stable_path_string(&profile_paths.profile_dir);
    let parameters_json = serde_json::json!({
        "browser_family": BrowserFamily::Safari.as_str(),
        "history_path": source_path,
        "profile_dir": profile_paths.profile_dir.to_string_lossy(),
        "history_db": profile_paths.history_path.to_string_lossy(),
        "unsupported_artifacts": ["bookmarks_plist", "downloads_plist"],
        "max_visits": history_limit_json(max_visits),
        "max_visits_scope": "visits and each row-oriented browser artifact class",
        "artifact_limit_reached": !limited_artifact_kinds.is_empty(),
        "limited_artifact_kinds": &limited_artifact_kinds,
        "parse_errors": parse_errors,
        "parse_error_count": parse_error_count,
        "parse_error_samples_omitted": parse_error_count.saturating_sub(parse_errors.len() as u64)
    })
    .to_string();
    Ok(BrowserHistoryImportData {
        family: BrowserFamily::Safari,
        source_path,
        primary_db_path: profile_paths.history_path.clone(),
        default_display_name: default_browser_history_display_name(
            BrowserFamily::Safari,
            &profile_paths.profile_dir,
        ),
        parameters_json,
        records,
        total_visits,
        examiner_artifact_limit_reached: !limited_artifact_kinds.is_empty(),
        limited_artifact_kinds,
        parse_error_count,
        parse_errors,
    })
}

/// Unique URL rows from the Chromium `urls` table ("URLs" DFIR category, distinct from
/// per-event "Visits").
pub fn stream_chromium_url_records(
    history_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    let source_metadata = source_artifact_metadata(history_path, "History");
    let mut stmt = conn.prepare(
        "SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden
         FROM urls ORDER BY last_visit_time DESC, id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        let id: i64 = row.get(0)?;
        let url: String = row.get(1)?;
        let title: Option<String> = row.get(2)?;
        let visit_count: Option<i64> = row.get(3)?;
        let typed_count: Option<i64> = row.get(4)?;
        let last_visit_time: Option<i64> = row.get(5)?;
        let hidden: Option<i64> = row.get(6)?;
        Ok((
            id,
            url,
            title,
            visit_count,
            typed_count,
            last_visit_time,
            hidden,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (id, url, title, visit_count, typed_count, last_visit_time, hidden) = row?;
        let host = host_from_url(&url);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_url",
            "browser_family": "chromium",
            "url_id": id,
            "url": url,
            "title": title,
            "host": host,
            "visit_count": visit_count,
            "typed_count": typed_count,
            "last_visit_time_chrome": last_visit_time,
            "last_visit_time_utc": optional_chrome_time_to_rfc3339(last_visit_time),
            "hidden": hidden.map(|value| value != 0),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let display_name = title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&url)
            .chars()
            .take(180)
            .collect::<String>();
        let logical_path = format!(
            "/Browser Activities/URLs/{}/{}.record",
            sanitize_logical_segment(&host),
            id
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Search terms typed in the browser (Chromium `keyword_search_terms`).
pub fn stream_chromium_search_records(
    history_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    if !sqlite_table_exists(&conn, "keyword_search_terms")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(history_path, "History");
    let keyword_id = sql_column_or_null(&conn, "keyword_search_terms", "k.", "keyword_id")?;
    let normalized_term =
        sql_column_or_null(&conn, "keyword_search_terms", "k.", "normalized_term")?;
    let lower_term = sql_column_or_null(&conn, "keyword_search_terms", "k.", "lower_term")?;
    let sql = format!(
        "SELECT {keyword_id}, k.url_id, k.term, {normalized_term}, {lower_term},
                u.url, u.last_visit_time, k.rowid,
                ROW_NUMBER() OVER (
                    PARTITION BY k.term, k.url_id
                    ORDER BY k.rowid
                )
         FROM keyword_search_terms k
         JOIN urls u ON u.id = k.url_id
         ORDER BY u.last_visit_time DESC, k.url_id DESC, {keyword_id} DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        let keyword_id: Option<i64> = row.get(0)?;
        let url_id: i64 = row.get(1)?;
        let term: String = row.get(2)?;
        let normalized_term: Option<String> = row.get(3)?;
        let lower_term: Option<String> = row.get(4)?;
        let url: String = row.get(5)?;
        let last_visit_time: Option<i64> = row.get(6)?;
        let source_rowid: i64 = row.get(7)?;
        let logical_path_rank: i64 = row.get(8)?;
        Ok((
            keyword_id,
            url_id,
            term,
            normalized_term,
            lower_term,
            url,
            last_visit_time,
            source_rowid,
            logical_path_rank,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (
            keyword_id,
            url_id,
            term,
            normalized_term,
            lower_term,
            url,
            last_visit_time,
            source_rowid,
            logical_path_rank,
        ) = row?;
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_search_term",
            "browser_family": "chromium",
            "keyword_id": keyword_id,
            "url_id": url_id,
            "search_term": term,
            "normalized_term": normalized_term,
            "lower_term": lower_term,
            "url": url,
            "host": host_from_url(&url),
            "last_visit_time_chrome": last_visit_time,
            "last_visit_time_utc": optional_chrome_time_to_rfc3339(last_visit_time),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let base_logical_path = format!(
            "/Browser Activities/Searches/{}-{}.record",
            sanitize_logical_segment(term.chars().take(60).collect::<String>().as_str()),
            url_id
        );
        let logical_path = if logical_path_rank == 1 {
            base_logical_path
        } else {
            format!(
                "/Browser Activities/Searches/{}-{}-{}-{}.record",
                sanitize_logical_segment(term.chars().take(60).collect::<String>().as_str()),
                keyword_id.unwrap_or_default(),
                url_id,
                source_rowid,
            )
        };
        let display_name: String = format!("Search: {term}").chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Exact omnibox text retained by Chromium's `Shortcuts` database.
pub fn stream_chromium_omnibox_shortcut_records(
    shortcuts_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !shortcuts_path.is_file() {
        return Ok(0);
    }
    let (conn, _guard) = open_sqlite_copy_read_only(shortcuts_path)?;
    // Chromium's production table name is `omni_box_shortcuts`. Accept the
    // compact spelling too because some downstream Chromium-family builds and
    // older exported fixtures use it.
    let table_name = if sqlite_table_exists(&conn, "omni_box_shortcuts")? {
        "omni_box_shortcuts"
    } else if sqlite_table_exists(&conn, "omnibox_shortcuts")? {
        "omnibox_shortcuts"
    } else {
        return Ok(0);
    };
    let source_metadata = source_artifact_metadata(shortcuts_path, "Shortcuts");
    let id = if sqlite_column_exists(&conn, table_name, "id")? {
        "CAST(s.id AS TEXT)".to_string()
    } else {
        "CAST(s.rowid AS TEXT)".to_string()
    };
    let text = sql_column_or_null(&conn, table_name, "s.", "text")?;
    let fill_into_edit = sql_column_or_null(&conn, table_name, "s.", "fill_into_edit")?;
    let url = sql_column_or_null(&conn, table_name, "s.", "url")?;
    let contents = sql_column_or_null(&conn, table_name, "s.", "contents")?;
    let description = sql_column_or_null(&conn, table_name, "s.", "description")?;
    let shortcut_type = sql_column_or_null(&conn, table_name, "s.", "type")?;
    let keyword = sql_column_or_null(&conn, table_name, "s.", "keyword")?;
    let last_access_time = sql_column_or_null(&conn, table_name, "s.", "last_access_time")?;
    let number_of_hits = sql_column_or_null(&conn, table_name, "s.", "number_of_hits")?;
    let sql = format!(
        "SELECT {id}, {text}, {fill_into_edit}, {url}, {contents}, {description},
                {shortcut_type}, {keyword}, {last_access_time}, {number_of_hits}
         FROM {table_name} s
         ORDER BY {last_access_time} DESC, {id} DESC
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<i64>>(9)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (
            id,
            text,
            fill_into_edit,
            url,
            contents,
            description,
            shortcut_type,
            keyword,
            last_access_time,
            number_of_hits,
        ) = row?;
        let path_text = text.as_deref().unwrap_or("");
        let display_text = text
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .or(url.as_deref())
            .unwrap_or(&id);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_omnibox_shortcut",
            "browser_family": "chromium",
            "shortcut_id": id,
            "id": id,
            "text": text,
            "fill_into_edit": fill_into_edit,
            "url": url,
            "contents": contents,
            "description": description,
            "type": shortcut_type,
            "keyword": keyword,
            "last_access_time_chrome": last_access_time,
            "last_access_time_utc": optional_chrome_time_to_rfc3339(last_access_time),
            "last_access_utc": optional_chrome_time_to_rfc3339(last_access_time),
            "number_of_hits": number_of_hits,
            "search_text": format!("{} {} {} {}", path_text, fill_into_edit.as_deref().unwrap_or(""), contents.as_deref().unwrap_or(""), description.as_deref().unwrap_or("")),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Omnibox/{}-{}.record",
            sanitize_logical_segment(&id),
            sanitize_logical_segment(&path_text.chars().take(60).collect::<String>())
        );
        let display_name: String = format!("Omnibox: {display_text}")
            .chars()
            .take(180)
            .collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Plain-text form entries from Chromium's `Web Data` database. Credit-card
/// and encrypted tables are deliberately outside this reader.
pub fn stream_chromium_autofill_records(
    web_data_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !web_data_path.is_file() {
        return Ok(0);
    }
    let (conn, _guard) = open_sqlite_copy_read_only(web_data_path)?;
    if !sqlite_table_exists(&conn, "autofill")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(web_data_path, "Web Data");
    let name = sql_column_or_null(&conn, "autofill", "a.", "name")?;
    let value = sql_column_or_null(&conn, "autofill", "a.", "value")?;
    let has_count = sqlite_column_exists(&conn, "autofill", "count")?;
    let has_date_created = sqlite_column_exists(&conn, "autofill", "date_created")?;
    let has_date_last_used = sqlite_column_exists(&conn, "autofill", "date_last_used")?;
    let has_legacy_dates = sqlite_column_exists(&conn, "autofill", "pair_id")?
        && sqlite_table_exists(&conn, "autofill_dates")?
        && sqlite_column_exists(&conn, "autofill_dates", "pair_id")?
        && sqlite_column_exists(&conn, "autofill_dates", "date_created")?;
    let legacy_join = if has_legacy_dates {
        "LEFT JOIN (
             SELECT pair_id, MIN(NULLIF(date_created, 0)) AS first_date,
                    MAX(NULLIF(date_created, 0)) AS last_date,
                    COUNT(NULLIF(date_created, 0)) AS use_count
             FROM autofill_dates GROUP BY pair_id
         ) ad ON ad.pair_id = a.pair_id"
    } else {
        ""
    };
    let date_created = if has_date_created {
        "a.date_created"
    } else if has_legacy_dates {
        "ad.first_date"
    } else {
        "NULL"
    };
    let count = if has_count {
        "a.count"
    } else if has_legacy_dates {
        "ad.use_count"
    } else {
        "NULL"
    };
    let date_last_used = if has_date_last_used {
        "a.date_last_used"
    } else if has_legacy_dates {
        "ad.last_date"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT a.rowid, {name}, {value}, {count}, {date_created}, {date_last_used}
         FROM autofill a
         {legacy_join}
         ORDER BY {date_last_used} DESC, a.rowid DESC
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (rowid, name, value, count, date_created, date_last_used) = row?;
        let date_created_utc = nonzero_optional_i64(date_created).and_then(unix_seconds_to_rfc3339);
        let date_last_used_utc =
            nonzero_optional_i64(date_last_used).and_then(unix_seconds_to_rfc3339);
        let path_name = name.as_deref().unwrap_or("");
        let display_field = name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("unnamed field");
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_autofill",
            "browser_family": "chromium",
            "rowid": rowid,
            "name": name,
            "value": value,
            "count": count,
            "date_created": date_created,
            "date_created_unix_seconds": date_created,
            "date_created_utc": date_created_utc,
            "date_last_used": date_last_used,
            "date_last_used_unix_seconds": date_last_used,
            "date_last_used_utc": date_last_used_utc,
            "search_text": format!("{} {}", path_name, value.as_deref().unwrap_or("")),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Autofill/{}-{}.record",
            rowid,
            sanitize_logical_segment(&path_name.chars().take(60).collect::<String>())
        );
        let display_name: String = format!("Autofill: {display_field}")
            .chars()
            .take(180)
            .collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Download records from the Chromium `downloads` table.
pub fn stream_chromium_download_records(
    history_path: &Path,
    max_rows: usize,
    max_url_chain_urls: usize,
    diagnostics: &mut BrowserImportDiagnostics,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    if !sqlite_table_exists(&conn, "downloads")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(history_path, "History");
    let current_path = sql_column_or_null(&conn, "downloads", "d.", "current_path")?;
    let target_path = sql_column_or_null(&conn, "downloads", "d.", "target_path")?;
    let full_path = sql_column_or_null(&conn, "downloads", "d.", "full_path")?;
    let legacy_url = sql_column_or_null(&conn, "downloads", "d.", "url")?;
    let start_time = sql_column_or_null(&conn, "downloads", "d.", "start_time")?;
    let end_time = sql_column_or_null(&conn, "downloads", "d.", "end_time")?;
    let received_bytes = sql_column_or_null(&conn, "downloads", "d.", "received_bytes")?;
    let total_bytes = sql_column_or_null(&conn, "downloads", "d.", "total_bytes")?;
    let state = sql_column_or_null(&conn, "downloads", "d.", "state")?;
    let danger_type = sql_column_or_null(&conn, "downloads", "d.", "danger_type")?;
    let interrupt_reason = sql_column_or_null(&conn, "downloads", "d.", "interrupt_reason")?;
    let referrer = sql_column_or_null(&conn, "downloads", "d.", "referrer")?;
    let tab_url = sql_column_or_null(&conn, "downloads", "d.", "tab_url")?;
    let mime_type = sql_column_or_null(&conn, "downloads", "d.", "mime_type")?;
    let guid = sql_column_or_null(&conn, "downloads", "d.", "guid")?;
    let site_url = sql_column_or_null(&conn, "downloads", "d.", "site_url")?;
    let tab_referrer_url = sql_column_or_null(&conn, "downloads", "d.", "tab_referrer_url")?;
    let original_mime_type = sql_column_or_null(&conn, "downloads", "d.", "original_mime_type")?;
    let last_access_time = sql_column_or_null(&conn, "downloads", "d.", "last_access_time")?;
    let opened = sql_column_or_null(&conn, "downloads", "d.", "opened")?;
    let hash_hex = if sqlite_column_exists(&conn, "downloads", "hash")? {
        "CASE WHEN d.hash IS NULL OR length(d.hash) = 0
              THEN NULL ELSE lower(hex(d.hash)) END"
            .to_string()
    } else {
        "NULL".to_string()
    };
    let sql = format!(
        "SELECT d.id, {current_path}, {target_path}, {full_path}, {legacy_url},
                {start_time}, {end_time}, {received_bytes}, {total_bytes}, {state},
                {danger_type}, {interrupt_reason}, {referrer}, {tab_url}, {mime_type},
                {guid}, {site_url}, {tab_referrer_url}, {original_mime_type},
                {last_access_time}, {opened}, {hash_hex}
         FROM downloads d
         ORDER BY {start_time} DESC, d.id DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok(ChromiumDownloadRow {
            id: row.get(0)?,
            current_path: row.get(1)?,
            target_path: row.get(2)?,
            full_path: row.get(3)?,
            legacy_url: row.get(4)?,
            start_time: row.get(5)?,
            end_time: row.get(6)?,
            received_bytes: row.get(7)?,
            total_bytes: row.get(8)?,
            state: row.get(9)?,
            danger_type: row.get(10)?,
            interrupt_reason: row.get(11)?,
            referrer: row.get(12)?,
            tab_url: row.get(13)?,
            mime_type: row.get(14)?,
            guid: row.get(15)?,
            site_url: row.get(16)?,
            tab_referrer_url: row.get(17)?,
            original_mime_type: row.get(18)?,
            last_access_time: row.get(19)?,
            opened: row.get(20)?,
            hash_hex: row.get(21)?,
        })
    })?;
    let mut chain_stmt = if sqlite_table_exists(&conn, "downloads_url_chains")? {
        Some(conn.prepare(
            "SELECT url FROM downloads_url_chains
             WHERE id = ?1 AND url IS NOT NULL
             ORDER BY chain_index ASC LIMIT ?2",
        )?)
    } else {
        None
    };
    let mut chain_count_stmt = if sqlite_table_exists(&conn, "downloads_url_chains")? {
        Some(conn.prepare("SELECT COUNT(url) FROM downloads_url_chains WHERE id = ?1")?)
    } else {
        None
    };
    let mut chain_endpoints_stmt = if sqlite_table_exists(&conn, "downloads_url_chains")? {
        Some(conn.prepare(
            "SELECT
                (SELECT url FROM downloads_url_chains
                 WHERE id = ?1 AND url IS NOT NULL
                 ORDER BY chain_index ASC LIMIT 1),
                (SELECT url FROM downloads_url_chains
                 WHERE id = ?1 AND url IS NOT NULL
                 ORDER BY chain_index DESC LIMIT 1)",
        )?)
    } else {
        None
    };
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let row = row.context("reading Chromium download")?;
        let id = row.id;
        let effective_target_path = row.target_path.clone().or_else(|| row.full_path.clone());
        let file_name = row
            .target_path
            .as_deref()
            .or(row.current_path.as_deref())
            .or(row.full_path.as_deref())
            .map(|value| {
                value
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(value)
                    .to_string()
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("download-{id}"));
        let mut url_chain = Vec::new();
        let url_chain_total = match chain_count_stmt.as_mut() {
            Some(count_stmt) => usize::try_from(
                count_stmt.query_row(params![id], |count_row| count_row.get::<_, i64>(0))?,
            )
            .unwrap_or(usize::MAX),
            None => 0,
        };
        if let Some(chain_stmt) = chain_stmt.as_mut() {
            let urls = chain_stmt.query_map(
                params![id, i64::try_from(max_url_chain_urls).unwrap_or(i64::MAX)],
                |chain_row| chain_row.get::<_, Option<String>>(0),
            )?;
            for url in urls {
                if let Some(url) = url.context("reading Chromium download URL chain")? {
                    url_chain.push(url);
                }
            }
        }
        let url_chain_omitted = url_chain_total.saturating_sub(url_chain.len());
        if url_chain_omitted > 0 {
            diagnostics.record(format!(
                "downloads URL chain {id}: retained {} of {url_chain_total} URLs; omitted {url_chain_omitted} at the configured protective bound {CHROMIUM_DOWNLOAD_URL_CHAIN_MAX_URLS_ENV}={max_url_chain_urls}",
                url_chain.len(),
            ));
        }
        let (original_url, final_chain_url) = match chain_endpoints_stmt.as_mut() {
            Some(endpoint_stmt) => endpoint_stmt.query_row(params![id], |endpoint_row| {
                Ok((
                    endpoint_row.get::<_, Option<String>>(0)?,
                    endpoint_row.get::<_, Option<String>>(1)?,
                ))
            })?,
            None => (None, None),
        };
        let download_url = final_chain_url.or_else(|| row.legacy_url.clone());
        let duration_microseconds =
            chromium_download_duration_microseconds(row.start_time, row.end_time);
        let duration_seconds = duration_microseconds.map(|value| value as f64 / 1_000_000.0);
        let duration_human = duration_microseconds.map(duration_human_from_microseconds);
        let start_time_unix_seconds = row
            .start_time
            .filter(|value| chromium_download_time_is_unix_seconds(*value));
        let end_time_unix_seconds = row
            .end_time
            .filter(|value| chromium_download_time_is_unix_seconds(*value));
        let start_time_chrome = row
            .start_time
            .filter(|value| *value != 0 && !chromium_download_time_is_unix_seconds(*value));
        let end_time_chrome = row
            .end_time
            .filter(|value| *value != 0 && !chromium_download_time_is_unix_seconds(*value));
        let download_time_basis =
            if start_time_unix_seconds.is_some() || end_time_unix_seconds.is_some() {
                Some("unix_seconds_legacy")
            } else if start_time_chrome.is_some() || end_time_chrome.is_some() {
                Some("chrome_epoch_microseconds")
            } else {
                None
            };
        let percent_complete = row
            .total_bytes
            .filter(|value| *value > 0)
            .and_then(|total| {
                row.received_bytes
                    .map(|received| received as f64 / total as f64 * 100.0)
            });
        let state_label = row.state.map(chromium_download_state_label);
        let danger_type_label = row.danger_type.map(chromium_download_danger_type_label);
        let interrupt_reason_label = row
            .interrupt_reason
            .map(chromium_download_interrupt_reason_label);
        let outcome_summary = chromium_download_outcome_summary(
            &row,
            state_label.as_deref(),
            interrupt_reason_label.as_deref(),
            duration_human.as_deref(),
            percent_complete,
        );
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_download",
            "browser_family": "chromium",
            "download_id": id,
            "file_name": file_name,
            "target_path": effective_target_path,
            "current_path": row.current_path,
            "full_path": row.full_path,
            "url": row.legacy_url,
            "start_time_raw": row.start_time,
            "start_time_chrome": start_time_chrome,
            "start_time_unix_seconds": start_time_unix_seconds,
            "start_time_utc": chromium_download_time_to_rfc3339(row.start_time),
            "end_time_raw": row.end_time,
            "end_time_chrome": end_time_chrome,
            "end_time_unix_seconds": end_time_unix_seconds,
            "end_time_utc": chromium_download_time_to_rfc3339(row.end_time),
            "download_time_basis": download_time_basis,
            "last_access_time_chrome": row.last_access_time,
            "last_access_time_utc": optional_chrome_time_to_rfc3339(row.last_access_time),
            "last_access_utc": optional_chrome_time_to_rfc3339(row.last_access_time),
        });
        let download_details = serde_json::json!({
            "duration_microseconds": duration_microseconds,
            "duration_seconds": duration_seconds,
            "duration_human": duration_human,
            "received_bytes": row.received_bytes,
            "total_bytes": row.total_bytes,
            "percent_complete": percent_complete,
            "state": row.state,
            "state_label": state_label,
            "danger_type": row.danger_type,
            "danger_type_label": danger_type_label,
            "interrupt_reason": row.interrupt_reason,
            "interrupt_reason_label": interrupt_reason_label,
            "referrer": row.referrer,
            "site_url": row.site_url,
            "tab_url": row.tab_url,
            "tab_referrer_url": row.tab_referrer_url,
            "mime_type": row.mime_type,
            "original_mime_type": row.original_mime_type,
            "guid": row.guid,
            "opened": row.opened.map(|value| value != 0),
            "hash": row.hash_hex,
            "hash_hex": row.hash_hex,
            "url_chain": url_chain,
            "url_chain_total": url_chain_total,
            "url_chain_omitted": url_chain_omitted,
            "url_chain_complete": url_chain_omitted == 0,
            "original_url": original_url,
            "download_url": download_url,
            "outcome_summary": outcome_summary,
        });
        merge_json_object(&mut metadata, &download_details);
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Downloads/{}-{}.record",
            id,
            sanitize_logical_segment(&file_name)
        );
        let display_name: String = file_name.chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Saved website credentials from `Login Data`. Encrypted password bytes are
/// retained as labelled ciphertext so the examiner can export the complete
/// record or use an authorized external decryptor without KDFT pretending that
/// DPAPI/application encryption was decoded.
pub fn stream_chromium_login_records(
    profile_dir: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let login_path = profile_dir.join("Login Data");
    if !login_path.is_file() {
        return Ok(0);
    }
    let (conn, _guard) = open_sqlite_copy_read_only(&login_path)?;
    let source_metadata = source_artifact_metadata(&login_path, "Login Data");
    let password_value = sql_column_or_null(&conn, "logins", "", "password_value")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT origin_url, action_url, username_value, date_created, date_last_used, times_used,
                hex({password_value})
         FROM logins ORDER BY date_created DESC LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        let origin_url: Option<String> = row.get(0)?;
        let action_url: Option<String> = row.get(1)?;
        let username: Option<String> = row.get(2)?;
        let date_created: Option<i64> = row.get(3)?;
        let date_last_used: Option<i64> = row.get(4)?;
        let times_used: Option<i64> = row.get(5)?;
        let password_ciphertext_hex: Option<String> = row.get(6)?;
        Ok((
            origin_url,
            action_url,
            username,
            date_created,
            date_last_used,
            times_used,
            password_ciphertext_hex,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for (index, row) in rows.enumerate() {
        let (
            origin_url,
            action_url,
            username,
            date_created,
            date_last_used,
            times_used,
            password_ciphertext_hex,
        ) = row?;
        let password_ciphertext_hex = password_ciphertext_hex.filter(|value| !value.is_empty());
        let password_ciphertext_bytes = password_ciphertext_hex
            .as_ref()
            .map(|value| value.len().saturating_div(2));
        let origin = origin_url.clone().unwrap_or_default();
        let host = host_from_url(&origin);
        let user_label = username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("(no username)");
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_login",
            "browser_family": "chromium",
            "origin_url": origin_url,
            "action_url": action_url,
            "username": username,
            "host": host,
            "date_created_chrome": date_created,
            "date_created_utc": optional_chrome_time_to_rfc3339(date_created),
            "date_last_used_chrome": date_last_used,
            "date_last_used_utc": optional_chrome_time_to_rfc3339(date_last_used),
            "times_used": times_used,
            "password_ciphertext_hex": password_ciphertext_hex,
            "password_ciphertext_bytes": password_ciphertext_bytes,
            "sensitive_value_present": password_ciphertext_bytes.unwrap_or_default() > 0,
            "password_note": "encrypted password retained as ciphertext; not decrypted",
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Logins/{}/{}-{}.record",
            sanitize_logical_segment(&host),
            sanitize_logical_segment(user_label),
            index
        );
        let display_name: String = format!("{user_label} @ {host}").chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Cookie records from the Chromium cookie store (`Network\Cookies` or legacy `Cookies`).
/// Plaintext values already present in the database are retained as sensitive evidence;
/// encrypted values are counted but are never mislabeled as decoded plaintext.
pub fn stream_chromium_cookie_records(
    profile_dir: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let network_path = profile_dir.join("Network").join("Cookies");
    let legacy_path = profile_dir.join("Cookies");
    let cookie_path = if network_path.is_file() {
        network_path
    } else if legacy_path.is_file() {
        legacy_path
    } else {
        return Ok(0);
    };
    let (conn, _guard) = open_sqlite_copy_read_only(&cookie_path)?;
    let source_metadata = source_artifact_metadata(&cookie_path, "Cookies");
    let plaintext_value = sql_column_or_null(&conn, "cookies", "", "value")?;
    let encrypted_length = if sqlite_column_exists(&conn, "cookies", "encrypted_value")? {
        "length(encrypted_value)".to_string()
    } else {
        "NULL".to_string()
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT host_key, name, path, creation_utc, expires_utc, last_access_utc,
                is_secure, is_httponly, {plaintext_value}, {encrypted_length}
         FROM cookies ORDER BY creation_utc DESC LIMIT ?1"
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        let host_key: String = row.get(0)?;
        let name: String = row.get(1)?;
        let path: Option<String> = row.get(2)?;
        let creation: Option<i64> = row.get(3)?;
        let expires: Option<i64> = row.get(4)?;
        let last_access: Option<i64> = row.get(5)?;
        let is_secure: Option<i64> = row.get(6)?;
        let is_httponly: Option<i64> = row.get(7)?;
        let plaintext_value: Option<String> = row.get(8)?;
        let encrypted_value_bytes: Option<i64> = row.get(9)?;
        Ok((
            host_key,
            name,
            path,
            creation,
            expires,
            last_access,
            is_secure,
            is_httponly,
            plaintext_value,
            encrypted_value_bytes,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (
            host_key,
            name,
            path,
            creation,
            expires,
            last_access,
            is_secure,
            is_httponly,
            plaintext_value,
            encrypted_value_bytes,
        ) = row?;
        let plaintext_value = plaintext_value.filter(|value| !value.is_empty());
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_cookie",
            "browser_family": "chromium",
            "host": host_key,
            "cookie_name": name,
            "cookie_path": path,
            "creation_chrome": creation,
            "creation_utc": optional_chrome_time_to_rfc3339(creation),
            "expires_chrome": expires,
            "expires_utc": optional_chrome_time_to_rfc3339(expires),
            "last_access_chrome": last_access,
            "last_access_utc": optional_chrome_time_to_rfc3339(last_access),
            "is_secure": is_secure.map(|value| value != 0),
            "is_httponly": is_httponly.map(|value| value != 0),
            "cookie_value_plaintext": plaintext_value,
            "cookie_value_encrypted_bytes": encrypted_value_bytes,
            "sensitive_value_present": plaintext_value.is_some() || encrypted_value_bytes.unwrap_or(0) > 0,
            "value_note": if plaintext_value.is_some() { "plaintext cookie/session value retained as sensitive evidence" } else { "encrypted cookie value not decoded" },
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Cookies/{}/{}-{}.record",
            sanitize_logical_segment(&host_key),
            sanitize_logical_segment(&name),
            creation.unwrap_or_default()
        );
        let display_name: String = format!("{name} ({host_key})").chars().take(180).collect();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub struct ChromiumBookmarkNodeSpool {
    conn: Connection,
    _guard: TempFileGuard,
    next_node_id: i64,
    collecting: bool,
}

pub struct SpooledChromiumBookmark {
    name: Option<String>,
    url: Option<String>,
    guid: Option<String>,
    date_added: Option<i64>,
    date_last_used: Option<i64>,
    folder_path: Vec<String>,
}

impl ChromiumBookmarkNodeSpool {
    pub(crate) fn new(source_hint: &Path) -> Result<Self> {
        let path = reserve_unique_browser_spool_path("kdft-chromium-bookmarks", source_hint)?;
        let guard = TempFileGuard::new(path.clone());
        let conn = Connection::open(&path)
            .with_context(|| format!("creating Chromium bookmark spool {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             CREATE TABLE bookmark_nodes(
                 node_id INTEGER PRIMARY KEY,
                 parent_id INTEGER,
                 node_type TEXT NOT NULL,
                 name TEXT,
                 url TEXT,
                 guid TEXT,
                 date_added INTEGER,
                 date_last_used INTEGER
             );
             CREATE INDEX bookmark_nodes_parent ON bookmark_nodes(parent_id);
             BEGIN IMMEDIATE;",
        )?;
        Ok(Self {
            conn,
            _guard: guard,
            next_node_id: 1,
            collecting: true,
        })
    }

    fn allocate_node_id(&mut self) -> i64 {
        let node_id = self.next_node_id;
        self.next_node_id = self.next_node_id.saturating_add(1);
        node_id
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_node(
        &mut self,
        node_id: i64,
        parent_id: Option<i64>,
        node_type: &str,
        name: Option<String>,
        url: Option<String>,
        guid: Option<String>,
        date_added: Option<i64>,
        date_last_used: Option<i64>,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO bookmark_nodes(
                node_id, parent_id, node_type, name, url, guid,
                date_added, date_last_used
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                node_id,
                parent_id,
                node_type,
                name,
                url,
                guid,
                date_added,
                date_last_used
            ])?;
        Ok(())
    }

    fn insert_root(&mut self, label: &str) -> Result<i64> {
        let node_id = self.allocate_node_id();
        self.insert_node(
            node_id,
            None,
            "folder",
            Some(label.to_string()),
            None,
            None,
            None,
            None,
        )?;
        Ok(node_id)
    }

    pub(crate) fn seal(&mut self) -> Result<()> {
        if self.collecting {
            self.conn.execute_batch("COMMIT")?;
            self.collecting = false;
        }
        Ok(())
    }

    fn for_each_bookmark(
        &self,
        mut consume: impl FnMut(SpooledChromiumBookmark) -> Result<()>,
    ) -> Result<usize> {
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE ancestry(
                 bookmark_id, node_id, parent_id, name, depth
             ) AS (
                 SELECT child.node_id, parent.node_id, parent.parent_id,
                        parent.name, 0
                 FROM bookmark_nodes child
                 JOIN bookmark_nodes parent ON parent.node_id = child.parent_id
                 WHERE child.node_type = 'url'
                 UNION ALL
                 SELECT ancestry.bookmark_id, parent.node_id, parent.parent_id,
                        parent.name, ancestry.depth + 1
                 FROM ancestry
                 JOIN bookmark_nodes parent ON parent.node_id = ancestry.parent_id
             )
             SELECT bookmark.node_id, bookmark.name, bookmark.url, bookmark.guid,
                    bookmark.date_added, bookmark.date_last_used, ancestry.name
             FROM bookmark_nodes bookmark
             LEFT JOIN ancestry ON ancestry.bookmark_id = bookmark.node_id
             WHERE bookmark.node_type = 'url'
             ORDER BY bookmark.node_id, ancestry.depth DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut count = 0_usize;
        let mut current: Option<(i64, SpooledChromiumBookmark)> = None;
        while let Some(row) = rows.next()? {
            let node_id = row.get::<_, i64>(0)?;
            if current
                .as_ref()
                .is_some_and(|(current_id, _)| *current_id != node_id)
            {
                if let Some((_, bookmark)) = current.take() {
                    consume(bookmark)?;
                    count = count.saturating_add(1);
                }
            }
            if current.is_none() {
                current = Some((
                    node_id,
                    SpooledChromiumBookmark {
                        name: row.get(1)?,
                        url: row.get(2)?,
                        guid: row.get(3)?,
                        date_added: row.get(4)?,
                        date_last_used: row.get(5)?,
                        folder_path: Vec::new(),
                    },
                ));
            }
            if let Some(folder_name) = row.get::<_, Option<String>>(6)? {
                let folder_name = folder_name.trim();
                if !folder_name.is_empty() {
                    if let Some((_, bookmark)) = current.as_mut() {
                        let folder_path = &mut bookmark.folder_path;
                        if folder_path.last().is_none_or(|last| last != folder_name) {
                            folder_path.push(folder_name.to_string());
                        }
                    }
                }
            }
        }
        if let Some((_, bookmark)) = current {
            consume(bookmark)?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

pub struct ChromiumBookmarksDocumentSeed<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
}

impl<'de> DeserializeSeed<'de> for ChromiumBookmarksDocumentSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ChromiumBookmarksDocumentVisitor { spool: self.spool })
    }
}

pub struct ChromiumBookmarksDocumentVisitor<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
}

impl<'de> Visitor<'de> for ChromiumBookmarksDocumentVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Chromium Bookmarks JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "roots" {
                map.next_value_seed(ChromiumBookmarkRootsSeed {
                    spool: &mut *self.spool,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

pub struct ChromiumBookmarkRootsSeed<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
}

impl<'de> DeserializeSeed<'de> for ChromiumBookmarkRootsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ChromiumBookmarkRootsVisitor { spool: self.spool })
    }
}

pub struct ChromiumBookmarkRootsVisitor<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
}

impl<'de> Visitor<'de> for ChromiumBookmarkRootsVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the Chromium bookmark roots object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(root_name) = map.next_key::<String>()? {
            let parent_id = self
                .spool
                .insert_root(chromium_bookmark_root_label(&root_name))
                .map_err(|error| serde::de::Error::custom(format!("{error:#}")))?;
            map.next_value_seed(ChromiumBookmarkNodeSeed {
                spool: &mut *self.spool,
                parent_id: Some(parent_id),
            })?;
        }
        Ok(())
    }
}

pub struct ChromiumBookmarkNodeSeed<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
    parent_id: Option<i64>,
}

impl<'de> DeserializeSeed<'de> for ChromiumBookmarkNodeSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let node_id = self.spool.allocate_node_id();
        deserializer.deserialize_map(ChromiumBookmarkNodeVisitor {
            spool: self.spool,
            node_id,
            parent_id: self.parent_id,
        })
    }
}

pub struct ChromiumBookmarkNodeVisitor<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
    node_id: i64,
    parent_id: Option<i64>,
}

#[derive(Default)]
pub struct JsonOptionalString(Option<String>);

impl<'de> Deserialize<'de> for JsonOptionalString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(Self(value.as_str().map(str::to_string)))
    }
}

pub fn deserialize_optional_json_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(JsonOptionalString::deserialize(deserializer)?.0)
}

pub struct JsonChromeTime(Option<i64>);

impl<'de> Deserialize<'de> for JsonChromeTime {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(JsonChromeTime(match value {
            serde_json::Value::Number(value) => value.as_i64(),
            serde_json::Value::String(value) => value.parse::<i64>().ok(),
            _ => None,
        }))
    }
}

impl<'de> Visitor<'de> for ChromiumBookmarkNodeVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Chromium bookmark node")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut node_type = None;
        let mut name = None;
        let mut url = None;
        let mut guid = None;
        let mut date_added = None;
        let mut date_last_used = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "type" => node_type = map.next_value::<JsonOptionalString>()?.0,
                "name" => name = map.next_value::<JsonOptionalString>()?.0,
                "url" => url = map.next_value::<JsonOptionalString>()?.0,
                "guid" => guid = map.next_value::<JsonOptionalString>()?.0,
                "date_added" => {
                    date_added = map.next_value::<JsonChromeTime>()?.0;
                }
                "date_last_used" => {
                    date_last_used = map.next_value::<JsonChromeTime>()?.0;
                }
                "children" => {
                    map.next_value_seed(ChromiumBookmarkChildrenSeed {
                        spool: &mut *self.spool,
                        parent_id: self.node_id,
                    })?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        self.spool
            .insert_node(
                self.node_id,
                self.parent_id,
                node_type.as_deref().unwrap_or(""),
                name,
                url,
                guid,
                date_added,
                date_last_used,
            )
            .map_err(|error| serde::de::Error::custom(format!("{error:#}")))?;
        Ok(())
    }
}

pub struct ChromiumBookmarkChildrenSeed<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
    parent_id: i64,
}

impl<'de> DeserializeSeed<'de> for ChromiumBookmarkChildrenSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(ChromiumBookmarkChildrenVisitor {
            spool: self.spool,
            parent_id: self.parent_id,
        })
    }
}

pub struct ChromiumBookmarkChildrenVisitor<'a> {
    spool: &'a mut ChromiumBookmarkNodeSpool,
    parent_id: i64,
}

impl<'de> Visitor<'de> for ChromiumBookmarkChildrenVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Chromium bookmark children array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(ChromiumBookmarkNodeSeed {
                spool: &mut *self.spool,
                parent_id: Some(self.parent_id),
            })?
            .is_some()
        {}
        Ok(())
    }
}

pub fn stream_chromium_bookmark_records(
    bookmarks_path: &Path,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !bookmarks_path.is_file() {
        return Ok(0);
    }
    let reader = io::BufReader::new(fs::File::open(bookmarks_path).with_context(|| {
        format!(
            "opening Chromium Bookmarks file {}",
            bookmarks_path.display()
        )
    })?);
    let mut bookmark_spool = ChromiumBookmarkNodeSpool::new(bookmarks_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    ChromiumBookmarksDocumentSeed {
        spool: &mut bookmark_spool,
    }
    .deserialize(&mut deserializer)
    .with_context(|| {
        format!(
            "parsing Chromium Bookmarks file {}",
            bookmarks_path.display()
        )
    })?;
    deserializer.end().with_context(|| {
        format!(
            "checking trailing JSON in Chromium Bookmarks file {}",
            bookmarks_path.display()
        )
    })?;
    bookmark_spool.seal()?;
    let source_metadata = source_artifact_metadata(bookmarks_path, "Bookmarks");
    let mut records = BrowserRecordEmitter::new(emit);
    bookmark_spool.for_each_bookmark(|bookmark| {
        let name_value = bookmark.name.unwrap_or_else(|| "Bookmark".to_string());
        let name = name_value.trim();
        let url_value = bookmark.url.unwrap_or_default();
        let url = url_value.as_str();
        let folder_display = bookmark.folder_path.join("/");
        let logical_folder = bookmark
            .folder_path
            .iter()
            .map(|part| sanitize_logical_segment(part))
            .collect::<Vec<_>>()
            .join("/");
        let unique = bookmark
            .guid
            .as_deref()
            .map(sanitize_logical_segment)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| sanitize_logical_segment(&format!("{name}-{url}")));
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_bookmark",
            "browser_family": "chromium",
            "name": name,
            "url": url,
            "host": host_from_url(url),
            "folder": folder_display,
            "guid": bookmark.guid,
            "date_added_chrome": bookmark.date_added,
            "date_added_utc": optional_chrome_time_to_rfc3339(bookmark.date_added),
            "date_last_used_chrome": bookmark.date_last_used,
            "date_last_used_utc": optional_chrome_time_to_rfc3339(bookmark.date_last_used),
            "search_text": format!("{name} {url} {} {folder_display}", host_from_url(url)),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Bookmarks/{}/{}.record",
            logical_folder, unique
        );
        add_entry_category(&mut metadata, &logical_path, name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name: if name.is_empty() {
                url.chars().take(180).collect()
            } else {
                name.chars().take(180).collect()
            },
            metadata_json: metadata.to_string(),
        });
        Ok(())
    })?;
    records.finish()
}

pub fn stream_chromium_preference_records(
    preferences_path: &Path,
    max_bytes: u64,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !preferences_path.is_file() {
        return Ok(0);
    }
    let value = read_json_value_with_byte_bound(
        preferences_path,
        "Chromium Preferences",
        max_bytes,
        CHROMIUM_PREFERENCES_MAX_BYTES_ENV,
    )?;
    let source_metadata = source_artifact_metadata(preferences_path, "Preferences");
    let mut records = BrowserRecordEmitter::new(emit);
    push_preference_record(
        &mut records,
        "Profile",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "profile",
            "name": json_path(&value, &["profile", "name"]).cloned(),
            "avatar_index": json_path(&value, &["profile", "avatar_index"]).cloned(),
            "created_by_version": json_path(&value, &["profile", "created_by_version"]).cloned(),
            "last_used": json_path(&value, &["profile", "last_used"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Startup",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "startup",
            "restore_on_startup": json_path(&value, &["session", "restore_on_startup"]).cloned(),
            "startup_urls": json_path(&value, &["session", "startup_urls"]).cloned(),
            "homepage": json_path(&value, &["homepage"]).cloned(),
            "homepage_is_newtabpage": json_path(&value, &["homepage_is_newtabpage"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Search",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "search",
            "default_search_provider": json_path(&value, &["default_search_provider"]).cloned(),
            "default_search_provider_data": json_path(&value, &["default_search_provider_data", "template_url_data"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Downloads",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "downloads",
            "download_default_directory": json_path(&value, &["download", "default_directory"]).cloned(),
            "prompt_for_download": json_path(&value, &["download", "prompt_for_download"]).cloned(),
        }),
        &source_metadata,
    );
    push_preference_record(
        &mut records,
        "Privacy And Safety",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "privacy_safety",
            "safe_browsing": json_path(&value, &["safebrowsing"]).cloned(),
            "credentials_enable_service": json_path(&value, &["credentials_enable_service"]).cloned(),
            "profile_password_manager_enabled": json_path(&value, &["profile", "password_manager_enabled"]).cloned(),
            "autofill": json_path(&value, &["autofill"]).cloned(),
        }),
        &source_metadata,
    );
    let extensions_count = json_path(&value, &["extensions", "settings"])
        .and_then(|value| value.as_object())
        .map(|value| value.len())
        .unwrap_or(0);
    push_preference_record(
        &mut records,
        "Extensions",
        serde_json::json!({
            "artifact_kind": "browser_preference",
            "category": "extensions",
            "extension_count": extensions_count,
            "extensions_settings": json_path(&value, &["extensions", "settings"]).cloned(),
        }),
        &source_metadata,
    );
    records.finish()
}

/// Some preference records intentionally retain selected JSON subtrees in a
/// single case row. Until those subtrees are normalized into their own record
/// family, parsing the whole source is bounded explicitly. Crossing the bound
/// is a disclosed parser error (and therefore a truncated import), never a
/// false successful parse with silently omitted fields.
pub fn read_json_value_with_byte_bound(
    path: &Path,
    artifact_label: &str,
    max_bytes: u64,
    configuration_name: &str,
) -> Result<serde_json::Value> {
    let file = fs::File::open(path)
        .with_context(|| format!("opening {artifact_label} file {}", path.display()))?;
    let metadata_bytes = file.metadata().map(|metadata| metadata.len()).ok();
    let read_limit = max_bytes.saturating_add(1);
    let initial_capacity = usize::try_from(read_limit.min(8 * 1024 * 1024)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {artifact_label} file {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        let omitted = metadata_bytes.map(|total| total.saturating_sub(max_bytes));
        let omitted_text = omitted
            .map(|value| format!("{value} bytes"))
            .unwrap_or_else(|| "an unknown number of bytes".to_string());
        bail!(
            "{artifact_label} file {} exceeds configured protective bound {configuration_name}={max_bytes} bytes; metadata reports {} total bytes and {omitted_text} were not parsed",
            path.display(),
            metadata_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "an unknown".to_string()),
        );
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing {artifact_label} file {}", path.display()))
}

pub fn push_preference_record(
    records: &mut BrowserRecordEmitter<'_>,
    display_name: &str,
    mut metadata: serde_json::Value,
    source_metadata: &serde_json::Value,
) {
    let search_text = serde_json::to_string(&metadata).unwrap_or_default();
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "browser_family".to_string(),
            serde_json::Value::String("chromium".to_string()),
        );
        object.insert(
            "search_text".to_string(),
            serde_json::Value::String(search_text),
        );
    }
    merge_json_object(&mut metadata, source_metadata);
    let logical_path = format!(
        "/Browser Activities/Preferences/{}.record",
        sanitize_logical_segment(display_name)
    );
    add_entry_category(&mut metadata, &logical_path, display_name, "record");
    records.push(BrowserActivityRecord {
        logical_path,
        display_name: display_name.to_string(),
        metadata_json: metadata.to_string(),
    });
}

pub fn upsert_browser_history_evidence(
    conn: &Connection,
    case_id: i64,
    source_path: &str,
    display_name: &str,
    family: BrowserFamily,
    size_bytes: i64,
) -> Result<i64> {
    let notes = format!("Imported {} browser history", family.label());
    if let Some(existing_id) = conn
        .query_row(
            "SELECT id FROM evidence_sources WHERE case_id = ?1 AND source_path = ?2",
            params![case_id, source_path],
            |row| row.get(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE evidence_sources
             SET source_kind = 'browser_history',
                 display_name = ?1,
                 size_bytes = ?2,
                 read_file_system_requested = 0,
                 notes = ?3
             WHERE id = ?4 AND case_id = ?5",
            params![display_name, size_bytes, notes, existing_id, case_id],
        )?;
        return Ok(existing_id);
    }

    conn.execute(
        "INSERT INTO evidence_sources(
             case_id, source_kind, source_path, display_name, size_bytes,
             read_file_system_requested, notes
         ) VALUES (?1, 'browser_history', ?2, ?3, ?4, 0, ?5)",
        params![case_id, source_path, display_name, size_bytes, notes],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn browser_history_metadata_json(
    row: &ChromiumHistoryRow,
    source_metadata: &serde_json::Value,
) -> String {
    let transition = row.transition.unwrap_or_default();
    let transition_type = chromium_transition_type(transition);
    let transition_qualifiers = chromium_transition_qualifiers(transition);
    let is_redirect = transition_qualifiers
        .iter()
        .any(|value| matches!(*value, "client_redirect" | "server_redirect"));
    let typed_navigation = transition_type == "typed";
    let user_initiated_hint = typed_navigation
        || transition_type == "auto_bookmark"
        || transition_qualifiers
            .iter()
            .any(|value| matches!(*value, "from_address_bar" | "forward_back"));
    let visit_duration_seconds = row.visit_duration.map(|value| value as f64 / 1_000_000.0);
    let visit_duration_human = row.visit_duration.map(duration_human_from_microseconds);
    let mut metadata = serde_json::json!({
        "artifact_kind": "browser_history_visit",
        "browser_family": "chromium",
        "visit_id": row.visit_id,
        "url_id": row.url_id,
        "url": row.url,
        "title": row.title,
        "host": host_from_url(&row.url),
        "visit_time_chrome": row.visit_time,
        "visit_time_utc": optional_chrome_time_to_rfc3339(Some(row.visit_time)),
        "last_visit_time_chrome": row.last_visit_time,
        "last_visit_time_utc": optional_chrome_time_to_rfc3339(row.last_visit_time),
        "visit_count": row.visit_count,
        "typed_count": row.typed_count,
        "transition": transition,
        "transition_raw": row.transition,
        "transition_type": transition_type,
        "transition_qualifiers": transition_qualifiers,
        "is_redirect": is_redirect,
        "typed_navigation": typed_navigation,
        "user_initiated_hint": user_initiated_hint,
        "visit_duration_microseconds": row.visit_duration,
        "visit_duration_seconds": visit_duration_seconds,
        "visit_duration_human": visit_duration_human,
        "from_visit_id": row.from_visit_id,
        "referrer_url": row.referrer_url,
        "referrer_visit_time_chrome": row.referrer_visit_time,
        "referrer_visit_time_utc": optional_chrome_time_to_rfc3339(row.referrer_visit_time),
        "opener_visit_id": row.opener_visit_id,
        "opener_url": row.opener_url,
        "external_referrer_url": row.external_referrer_url,
        "visit_source": row.visit_source,
        "visit_source_label": chromium_visit_source_label(row.visit_source),
        "hidden": row.hidden.map(|value| value != 0),
        "search_text": format!("{} {} {}", row.url, row.title.as_deref().unwrap_or(""), host_from_url(&row.url)),
    });
    merge_json_object(&mut metadata, source_metadata);
    add_entry_category(
        &mut metadata,
        &row.logical_path(),
        row.title.as_deref().unwrap_or(&row.url),
        "record",
    );
    metadata.to_string()
}

pub fn stream_firefox_history_records(
    places_path: &Path,
    max_visits: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<(usize, usize)> {
    let (conn, _guard) = open_sqlite_copy_read_only(places_path)?;
    let has_visits = sqlite_table_exists(&conn, "moz_historyvisits")?;
    let has_places = sqlite_table_exists(&conn, "moz_places")?;
    if !has_visits || !has_places {
        bail!(
            "Firefox history schema is missing required table(s):{}{}",
            if has_places { "" } else { " moz_places" },
            if has_visits { "" } else { " moz_historyvisits" },
        );
    }
    let total_visits: i64 = conn.query_row(
        "SELECT COUNT(*) FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id",
        [],
        |row| row.get(0),
    )?;
    let visit_count = sql_column_or_null(&conn, "moz_places", "p.", "visit_count")?;
    let typed = sql_column_or_null(&conn, "moz_places", "p.", "typed")?;
    let last_visit_date = sql_column_or_null(&conn, "moz_places", "p.", "last_visit_date")?;
    let frecency = sql_column_or_null(&conn, "moz_places", "p.", "frecency")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT v.id, v.place_id, p.url, p.title, v.visit_date, v.visit_type,
                {visit_count}, {typed}, {last_visit_date}, {frecency}
         FROM moz_historyvisits v
         JOIN moz_places p ON p.id = v.place_id
         ORDER BY v.visit_date DESC, v.id DESC
         LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_visits)], |row| {
        Ok(FirefoxHistoryRow {
            visit_id: row.get(0)?,
            place_id: row.get(1)?,
            url: row.get(2)?,
            title: row.get(3)?,
            visit_date: row.get(4)?,
            visit_type: row.get(5)?,
            visit_count: row.get(6)?,
            typed: row.get(7)?,
            last_visit_date: row.get(8)?,
            frecency: row.get(9)?,
        })
    })?;
    let source_metadata = source_artifact_metadata(places_path, "places.sqlite");
    let mut emitted = 0_usize;
    for row in rows {
        let row = row.context("reading Firefox history visit")?;
        emit(firefox_history_visit_record(&row, &source_metadata))?;
        emitted = emitted.saturating_add(1);
    }
    Ok((emitted, usize::try_from(total_visits).unwrap_or(usize::MAX)))
}

pub fn firefox_history_visit_record(
    row: &FirefoxHistoryRow,
    source_metadata: &serde_json::Value,
) -> BrowserActivityRecord {
    let mut metadata = serde_json::json!({
        "artifact_kind": "browser_history_visit",
        "browser_family": "firefox",
        "visit_id": row.visit_id,
        "place_id": row.place_id,
        "url": row.url,
        "title": row.title,
        "host": host_from_url(&row.url),
        "visit_time_prtime": row.visit_date,
        "visit_time_utc": row.visit_date.and_then(unix_micros_to_rfc3339),
        "last_visit_time_prtime": row.last_visit_date,
        "last_visit_time_utc": row.last_visit_date.and_then(unix_micros_to_rfc3339),
        "visit_count": row.visit_count,
        "typed": row.typed.map(|value| value != 0),
        "visit_type": row.visit_type,
        "visit_type_label": row.visit_type.map(firefox_visit_type_label),
        "frecency": row.frecency,
        "search_text": format!("{} {} {}", row.url, row.title.as_deref().unwrap_or(""), host_from_url(&row.url)),
    });
    merge_json_object(&mut metadata, source_metadata);
    let logical_path = row.logical_path();
    let display_name = row.display_name();
    add_entry_category(&mut metadata, &logical_path, &display_name, "record");
    BrowserActivityRecord {
        logical_path,
        display_name,
        metadata_json: metadata.to_string(),
    }
}

pub fn stream_firefox_url_records(
    places_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(places_path)?;
    if !sqlite_table_exists(&conn, "moz_places")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(places_path, "places.sqlite");
    let visit_count = sql_column_or_null(&conn, "moz_places", "", "visit_count")?;
    let typed = sql_column_or_null(&conn, "moz_places", "", "typed")?;
    let last_visit_date = sql_column_or_null(&conn, "moz_places", "", "last_visit_date")?;
    let frecency = sql_column_or_null(&conn, "moz_places", "", "frecency")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT id, url, title, {visit_count}, {typed}, {last_visit_date}, {frecency}
         FROM moz_places
         ORDER BY COALESCE({last_visit_date}, 0) DESC, id DESC
         LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (id, url, title, visit_count, typed, last_visit_date, frecency) = row?;
        let host = host_from_url(&url);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_url",
            "browser_family": "firefox",
            "place_id": id,
            "url": url,
            "title": title,
            "host": host,
            "visit_count": visit_count,
            "typed": typed.map(|value| value != 0),
            "last_visit_time_prtime": last_visit_date,
            "last_visit_time_utc": last_visit_date.and_then(unix_micros_to_rfc3339),
            "frecency": frecency,
        });
        merge_json_object(&mut metadata, &source_metadata);
        let display_name = title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&url)
            .chars()
            .take(180)
            .collect::<String>();
        let logical_path = format!(
            "/Browser Activities/URLs/{}/{}.record",
            sanitize_logical_segment(&host),
            id
        );
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub fn stream_firefox_bookmark_records(
    places_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(places_path)?;
    if !sqlite_table_exists(&conn, "moz_bookmarks")? || !sqlite_table_exists(&conn, "moz_places")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(places_path, "places.sqlite");
    let mut stmt = conn.prepare(
        "SELECT b.id, b.fk, b.title, p.title, p.url, b.parent, parent.title,
                b.dateAdded, b.lastModified
         FROM moz_bookmarks b
         JOIN moz_places p ON p.id = b.fk
         LEFT JOIN moz_bookmarks parent ON parent.id = b.parent
         WHERE b.type = 1
         ORDER BY b.dateAdded DESC, b.id DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<i64>>(8)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (
            bookmark_id,
            place_id,
            bookmark_title,
            page_title,
            url,
            parent_id,
            parent_title,
            date_added,
            last_modified,
        ) = row?;
        let folder = parent_title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("Bookmarks");
        let name = bookmark_title
            .as_deref()
            .or(page_title.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&url);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_bookmark",
            "browser_family": "firefox",
            "bookmark_id": bookmark_id,
            "place_id": place_id,
            "name": bookmark_title,
            "page_title": page_title,
            "url": url,
            "host": host_from_url(&url),
            "parent_id": parent_id,
            "folder": folder,
            "date_added_prtime": date_added,
            "date_added_utc": date_added.and_then(unix_micros_to_rfc3339),
            "last_modified_prtime": last_modified,
            "last_modified_utc": last_modified.and_then(unix_micros_to_rfc3339),
            "search_text": format!("{name} {url} {} {folder}", host_from_url(&url)),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Bookmarks/{}/{}.record",
            sanitize_logical_segment(folder),
            bookmark_id
        );
        let display_name = name.chars().take(180).collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub fn stream_firefox_search_records(
    formhistory_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !formhistory_path.is_file() {
        return Ok(0);
    }
    let (conn, _guard) = open_sqlite_copy_read_only(formhistory_path)?;
    if !sqlite_table_exists(&conn, "moz_formhistory")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(formhistory_path, "formhistory.sqlite");
    let times_used = sql_column_or_null(&conn, "moz_formhistory", "", "timesUsed")?;
    let first_used = sql_column_or_null(&conn, "moz_formhistory", "", "firstUsed")?;
    let last_used = sql_column_or_null(&conn, "moz_formhistory", "", "lastUsed")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT id, fieldname, value, {times_used}, {first_used}, {last_used}
         FROM moz_formhistory
         WHERE fieldname = 'searchbar-history'
         ORDER BY COALESCE({last_used}, 0) DESC, id DESC
         LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (id, fieldname, value, times_used, first_used, last_used) = row?;
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_search_term",
            "browser_family": "firefox",
            "formhistory_id": id,
            "fieldname": fieldname,
            "search_term": value,
            "times_used": times_used,
            "first_used_prtime": first_used,
            "first_used_utc": first_used.and_then(unix_micros_to_rfc3339),
            "last_used_prtime": last_used,
            "last_used_utc": last_used.and_then(unix_micros_to_rfc3339),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Searches/{}-{}.record",
            sanitize_logical_segment(&value),
            id
        );
        let display_name = format!("Search: {value}")
            .chars()
            .take(180)
            .collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub fn stream_firefox_download_records(
    places_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(places_path)?;
    if !sqlite_table_exists(&conn, "moz_annos")?
        || !sqlite_table_exists(&conn, "moz_anno_attributes")?
        || !sqlite_table_exists(&conn, "moz_places")?
    {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(places_path, "places.sqlite");
    let mut stmt = conn.prepare(
        "SELECT a.id, a.place_id, aa.name, a.content, a.dateAdded, a.lastModified,
                p.url, p.title
         FROM moz_annos a
         JOIN moz_anno_attributes aa ON aa.id = a.anno_attribute_id
         JOIN moz_places p ON p.id = a.place_id
         WHERE aa.name IN ('downloads/destinationFileURI', 'downloads/metaData')
         ORDER BY a.dateAdded DESC, a.id DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (id, place_id, annotation_name, content, date_added, last_modified, source_url, title) =
            row?;
        let file_name = content
            .as_deref()
            .and_then(file_name_from_pathish)
            .unwrap_or_else(|| format!("download-{id}"));
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_download",
            "browser_family": "firefox",
            "annotation_id": id,
            "place_id": place_id,
            "annotation_name": annotation_name,
            "annotation_content": content,
            "file_name": file_name,
            "source_url": source_url,
            "title": title,
            "host": host_from_url(&source_url),
            "date_added_prtime": date_added,
            "date_added_utc": date_added.and_then(unix_micros_to_rfc3339),
            "last_modified_prtime": last_modified,
            "last_modified_utc": last_modified.and_then(unix_micros_to_rfc3339),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Downloads/{}-{}.record",
            id,
            sanitize_logical_segment(&file_name)
        );
        let display_name = file_name.chars().take(180).collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub fn stream_firefox_downloads_sqlite_records(
    downloads_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let downloads_metadata = match fs::metadata(downloads_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "reading Firefox downloads database {}",
                    downloads_path.display()
                )
            })
        }
    };
    if !downloads_metadata.is_file() {
        bail!(
            "Firefox downloads database path is not a file: {}",
            downloads_path.display()
        );
    }
    let (conn, _guard) = open_sqlite_copy_read_only(downloads_path)?;
    if !sqlite_table_exists(&conn, "moz_downloads")? {
        return Ok(0);
    }

    let guid = sql_column_or_null(&conn, "moz_downloads", "", "guid")?;
    let name = sql_column_or_null(&conn, "moz_downloads", "", "name")?;
    let source = sql_column_or_null(&conn, "moz_downloads", "", "source")?;
    let target = sql_column_or_null(&conn, "moz_downloads", "", "target")?;
    let temp_path = sql_column_or_null(&conn, "moz_downloads", "", "tempPath")?;
    let start_time = sql_column_or_null(&conn, "moz_downloads", "", "startTime")?;
    let end_time = sql_column_or_null(&conn, "moz_downloads", "", "endTime")?;
    let state = sql_column_or_null(&conn, "moz_downloads", "", "state")?;
    let referrer = sql_column_or_null(&conn, "moz_downloads", "", "referrer")?;
    let curr_bytes = sql_column_or_null(&conn, "moz_downloads", "", "currBytes")?;
    let max_bytes = sql_column_or_null(&conn, "moz_downloads", "", "maxBytes")?;
    let mime_type = sql_column_or_null(&conn, "moz_downloads", "", "mimeType")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT id, {guid}, {name}, {source}, {target}, {temp_path},
                {start_time}, {end_time}, {state}, {referrer},
                {curr_bytes}, {max_bytes}, {mime_type}
         FROM moz_downloads
         ORDER BY COALESCE({start_time}, 0) DESC, id DESC
         LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<i64>>(10)?,
            row.get::<_, Option<i64>>(11)?,
            row.get::<_, Option<String>>(12)?,
        ))
    })?;

    let source_metadata = source_artifact_metadata(downloads_path, "downloads.sqlite");
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (
            id,
            guid,
            name,
            source_url,
            target_uri,
            temp_path,
            start_time,
            end_time,
            state,
            referrer,
            curr_bytes,
            max_bytes,
            mime_type,
        ) = row?;
        let file_name = name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| target_uri.as_deref().and_then(file_name_from_pathish))
            .unwrap_or_else(|| format!("download-{id}"));
        let host = host_from_url(source_url.as_deref().unwrap_or(""));
        let state_label = state.map(firefox_download_state_label);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_download",
            "browser_family": "firefox",
            "download_id": id,
            "guid": guid,
            "file_name": file_name,
            "source_url": source_url,
            "target_uri": target_uri,
            "temp_path": temp_path,
            "referrer": referrer,
            "mime_type": mime_type,
            "curr_bytes": curr_bytes,
            "max_bytes": max_bytes,
            "state": state,
            "state_label": state_label,
            "host": host,
            "start_time_prtime": start_time,
            "start_time_utc": start_time.and_then(unix_micros_to_rfc3339),
            "end_time_prtime": end_time,
            "end_time_utc": end_time.and_then(unix_micros_to_rfc3339),
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Downloads/downloads-sqlite-{}-{}.record",
            id,
            sanitize_logical_segment(&file_name)
        );
        let display_name = file_name.chars().take(180).collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

/// Firefox `logins.json` is a top-level object containing a potentially large
/// `logins` array. Deserialize that array one element at a time into a
/// disk-backed sort spool so unlimited imports retain neither the whole JSON
/// document nor the whole login list in memory.
#[derive(Deserialize)]
pub struct FirefoxLoginInput {
    #[serde(default, deserialize_with = "deserialize_optional_json_string")]
    hostname: Option<String>,
    #[serde(
        rename = "httpRealm",
        default,
        deserialize_with = "deserialize_optional_json_string"
    )]
    http_realm: Option<String>,
    #[serde(rename = "timeCreated", default)]
    time_created: Option<JsonChromeTime>,
    #[serde(rename = "timeLastUsed", default)]
    time_last_used: Option<JsonChromeTime>,
    #[serde(rename = "timePasswordChanged", default)]
    time_password_changed: Option<JsonChromeTime>,
    #[serde(rename = "timesUsed", default)]
    times_used: Option<JsonChromeTime>,
    #[serde(
        rename = "encryptedUsername",
        default,
        deserialize_with = "deserialize_optional_json_string"
    )]
    encrypted_username: Option<String>,
    #[serde(
        rename = "encryptedPassword",
        default,
        deserialize_with = "deserialize_optional_json_string"
    )]
    encrypted_password: Option<String>,
}

pub struct FirefoxLoginSpoolRecord {
    hostname: Option<String>,
    http_realm: Option<String>,
    time_created: Option<i64>,
    time_last_used: Option<i64>,
    time_password_changed: Option<i64>,
    times_used: Option<i64>,
    encrypted_username: Option<String>,
    encrypted_password: Option<String>,
}

pub struct FirefoxLoginJsonSpool {
    conn: Connection,
    _guard: TempFileGuard,
    collecting: bool,
}

impl FirefoxLoginJsonSpool {
    pub(crate) fn new(source_hint: &Path) -> Result<Self> {
        let path = reserve_unique_browser_spool_path("kdft-firefox-logins", source_hint)?;
        let guard = TempFileGuard::new(path.clone());
        let conn = Connection::open(&path)
            .with_context(|| format!("creating Firefox login spool {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             CREATE TABLE firefox_logins(
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 sort_time INTEGER NOT NULL,
                 hostname TEXT,
                 http_realm TEXT,
                 time_created INTEGER,
                 time_last_used INTEGER,
                 time_password_changed INTEGER,
                 times_used INTEGER,
                 encrypted_username TEXT,
                 encrypted_password TEXT
             );
             BEGIN IMMEDIATE;",
        )?;
        Ok(Self {
            conn,
            _guard: guard,
            collecting: true,
        })
    }

    fn push(&mut self, login: FirefoxLoginInput) -> Result<()> {
        let time_created = login.time_created.and_then(|value| value.0);
        let time_last_used = login.time_last_used.and_then(|value| value.0);
        let time_password_changed = login.time_password_changed.and_then(|value| value.0);
        let times_used = login.times_used.and_then(|value| value.0);
        let sort_time = time_last_used.or(time_created).unwrap_or_default();
        self.conn
            .prepare_cached(
                "INSERT INTO firefox_logins(
                sort_time, hostname, http_realm, time_created, time_last_used,
                time_password_changed, times_used, encrypted_username, encrypted_password
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?
            .execute(params![
                sort_time,
                login.hostname,
                login.http_realm,
                time_created,
                time_last_used,
                time_password_changed,
                times_used,
                login.encrypted_username,
                login.encrypted_password,
            ])?;
        Ok(())
    }

    pub(crate) fn seal(&mut self) -> Result<()> {
        if self.collecting {
            self.conn.execute_batch("COMMIT")?;
            self.collecting = false;
        }
        Ok(())
    }

    fn for_each(
        &self,
        max_rows: usize,
        mut consume: impl FnMut(usize, FirefoxLoginSpoolRecord) -> Result<()>,
    ) -> Result<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT hostname, http_realm, time_created, time_last_used,
                    time_password_changed, times_used, encrypted_username, encrypted_password
             FROM firefox_logins
             ORDER BY sort_time DESC, sequence ASC LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![sqlite_limit_param(max_rows)])?;
        let mut index = 0_usize;
        while let Some(row) = rows.next()? {
            consume(
                index,
                FirefoxLoginSpoolRecord {
                    hostname: row.get(0)?,
                    http_realm: row.get(1)?,
                    time_created: row.get(2)?,
                    time_last_used: row.get(3)?,
                    time_password_changed: row.get(4)?,
                    times_used: row.get(5)?,
                    encrypted_username: row.get(6)?,
                    encrypted_password: row.get(7)?,
                },
            )?;
            index = index.saturating_add(1);
        }
        Ok(index)
    }
}

pub struct FirefoxLoginsRootSeed<'a> {
    spool: &'a mut FirefoxLoginJsonSpool,
}

impl<'de> DeserializeSeed<'de> for FirefoxLoginsRootSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(FirefoxLoginsRootVisitor { spool: self.spool })
    }
}

pub struct FirefoxLoginsRootVisitor<'a> {
    spool: &'a mut FirefoxLoginJsonSpool,
}

impl<'de> Visitor<'de> for FirefoxLoginsRootVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a Firefox logins JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "logins" {
                map.next_value_seed(FirefoxLoginsArraySeed {
                    spool: &mut *self.spool,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

pub struct FirefoxLoginsArraySeed<'a> {
    spool: &'a mut FirefoxLoginJsonSpool,
}

impl<'de> DeserializeSeed<'de> for FirefoxLoginsArraySeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(FirefoxLoginsArrayVisitor { spool: self.spool })
    }
}

pub struct FirefoxLoginsArrayVisitor<'a> {
    spool: &'a mut FirefoxLoginJsonSpool,
}

impl<'de> Visitor<'de> for FirefoxLoginsArrayVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the Firefox logins array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(login) = sequence.next_element::<FirefoxLoginInput>()? {
            self.spool
                .push(login)
                .map_err(|error| serde::de::Error::custom(format!("{error:#}")))?;
        }
        Ok(())
    }
}

pub fn stream_firefox_login_records(
    logins_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !logins_path.is_file() {
        return Ok(0);
    }
    let reader = io::BufReader::new(
        fs::File::open(logins_path)
            .with_context(|| format!("opening Firefox logins file {}", logins_path.display()))?,
    );
    let mut login_spool = FirefoxLoginJsonSpool::new(logins_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    FirefoxLoginsRootSeed {
        spool: &mut login_spool,
    }
    .deserialize(&mut deserializer)
    .with_context(|| format!("parsing Firefox logins file {}", logins_path.display()))?;
    deserializer.end().with_context(|| {
        format!(
            "checking trailing JSON in Firefox logins file {}",
            logins_path.display()
        )
    })?;
    login_spool.seal()?;
    let source_metadata = source_artifact_metadata(logins_path, "logins.json");
    let mut records = BrowserRecordEmitter::new(emit);
    login_spool.for_each(max_rows, |index, login| {
        let FirefoxLoginSpoolRecord {
            hostname,
            http_realm,
            time_created,
            time_last_used,
            time_password_changed,
            times_used,
            encrypted_username,
            encrypted_password,
        } = login;
        let sensitive_value_present = encrypted_username.is_some() || encrypted_password.is_some();
        let host_label = hostname.as_deref().unwrap_or("unknown-host");
        let host = host_from_url(host_label);
        let realm_label = http_realm
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("saved-login");
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_login",
            "browser_family": "firefox",
            "hostname": hostname,
            "http_realm": http_realm,
            "host": host,
            "time_created_ms": time_created,
            "time_created_utc": time_created.and_then(unix_millis_to_rfc3339),
            "time_last_used_ms": time_last_used,
            "time_last_used_utc": time_last_used.and_then(unix_millis_to_rfc3339),
            "time_password_changed_ms": time_password_changed,
            "time_password_changed_utc": time_password_changed.and_then(unix_millis_to_rfc3339),
            "times_used": times_used,
            "username_ciphertext": encrypted_username,
            "password_ciphertext": encrypted_password,
            "sensitive_value_present": sensitive_value_present,
            "password_note": "encrypted username/password retained as ciphertext; not decrypted",
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Logins/{}/{}-{}.record",
            sanitize_logical_segment(&host),
            sanitize_logical_segment(realm_label),
            index
        );
        let display_name = format!("{realm_label} @ {host}")
            .chars()
            .take(180)
            .collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
        Ok(())
    })?;
    records.finish()
}

pub fn stream_firefox_cookie_records(
    cookies_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    if !cookies_path.is_file() {
        return Ok(0);
    }
    let (conn, _guard) = open_sqlite_copy_read_only(cookies_path)?;
    if !sqlite_table_exists(&conn, "moz_cookies")? {
        return Ok(0);
    }
    let source_metadata = source_artifact_metadata(cookies_path, "cookies.sqlite");
    let creation_time = sql_column_or_null(&conn, "moz_cookies", "", "creationTime")?;
    let last_accessed = sql_column_or_null(&conn, "moz_cookies", "", "lastAccessed")?;
    let cookie_value = sql_column_or_null(&conn, "moz_cookies", "", "value")?;
    let mut stmt = conn.prepare(&format!(
        "SELECT id, host, name, path, {creation_time}, {last_accessed}, expiry, isSecure, isHttpOnly, {cookie_value}
         FROM moz_cookies
         ORDER BY COALESCE({creation_time}, 0) DESC, id DESC
         LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (
            id,
            host,
            name,
            path,
            creation,
            last_accessed,
            expiry,
            is_secure,
            is_httponly,
            cookie_value,
        ) = row?;
        let cookie_value = cookie_value.filter(|value| !value.is_empty());
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_cookie",
            "browser_family": "firefox",
            "cookie_id": id,
            "host": host,
            "cookie_name": name,
            "cookie_path": path,
            "creation_prtime": creation,
            "creation_utc": creation.and_then(unix_micros_to_rfc3339),
            "last_accessed_prtime": last_accessed,
            "last_accessed_utc": last_accessed.and_then(unix_micros_to_rfc3339),
            "expiry_unix": expiry,
            "expiry_utc": expiry.and_then(unix_seconds_to_rfc3339),
            "is_secure": is_secure.map(|value| value != 0),
            "is_httponly": is_httponly.map(|value| value != 0),
            "cookie_value_plaintext": cookie_value,
            "sensitive_value_present": cookie_value.is_some(),
            "value_note": if cookie_value.is_some() { "plaintext cookie/session value retained as sensitive evidence" } else { "cookie value empty" },
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/Cookies/{}/{}-{}.record",
            sanitize_logical_segment(&host),
            sanitize_logical_segment(&name),
            id
        );
        let display_name = format!("{name} ({host})")
            .chars()
            .take(180)
            .collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub fn stream_safari_history_records(
    history_path: &Path,
    max_visits: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<(usize, usize)> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    let has_visits = sqlite_table_exists(&conn, "history_visits")?;
    let has_items = sqlite_table_exists(&conn, "history_items")?;
    if !has_visits || !has_items {
        bail!(
            "Safari history schema is missing required table(s):{}{}",
            if has_items { "" } else { " history_items" },
            if has_visits { "" } else { " history_visits" },
        );
    }
    let total_visits: i64 = conn.query_row(
        "SELECT COUNT(*) FROM history_visits v JOIN history_items i ON i.id = v.history_item",
        [],
        |row| row.get(0),
    )?;
    let domain_select = if sqlite_column_exists(&conn, "history_items", "domain_expansion")? {
        "i.domain_expansion"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT v.id, v.history_item, i.url, v.title, v.visit_time, i.visit_count,
                {domain_select}
         FROM history_visits v
         JOIN history_items i ON i.id = v.history_item
         ORDER BY v.visit_time DESC, v.id DESC
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_visits)], |row| {
        Ok(SafariHistoryRow {
            visit_id: row.get(0)?,
            history_item_id: row.get(1)?,
            url: row.get(2)?,
            title: row.get(3)?,
            visit_time: row.get(4)?,
            visit_count: row.get(5)?,
            domain_expansion: row.get(6)?,
        })
    })?;
    let source_metadata = source_artifact_metadata(history_path, "History.db");
    let mut emitted = 0_usize;
    for row in rows {
        let row = row.context("reading Safari history visit")?;
        emit(safari_history_visit_record(&row, &source_metadata))?;
        emitted = emitted.saturating_add(1);
    }
    Ok((emitted, usize::try_from(total_visits).unwrap_or(usize::MAX)))
}

pub fn safari_history_visit_record(
    row: &SafariHistoryRow,
    source_metadata: &serde_json::Value,
) -> BrowserActivityRecord {
    let mut metadata = serde_json::json!({
        "artifact_kind": "browser_history_visit",
        "browser_family": "safari",
        "visit_id": row.visit_id,
        "history_item_id": row.history_item_id,
        "url": row.url,
        "title": row.title,
        "host": host_from_url(&row.url),
        "visit_time_safari": row.visit_time,
        "visit_time_utc": row.visit_time.and_then(safari_time_to_rfc3339),
        "visit_count": row.visit_count,
        "domain_expansion": row.domain_expansion,
        "search_text": format!("{} {} {}", row.url, row.title.as_deref().unwrap_or(""), host_from_url(&row.url)),
    });
    merge_json_object(&mut metadata, source_metadata);
    let logical_path = row.logical_path();
    let display_name = row.display_name();
    add_entry_category(&mut metadata, &logical_path, &display_name, "record");
    BrowserActivityRecord {
        logical_path,
        display_name,
        metadata_json: metadata.to_string(),
    }
}

pub fn stream_safari_url_records(
    history_path: &Path,
    max_rows: usize,
    emit: &mut dyn FnMut(BrowserActivityRecord) -> Result<()>,
) -> Result<usize> {
    let (conn, _guard) = open_sqlite_copy_read_only(history_path)?;
    if !sqlite_table_exists(&conn, "history_items")? {
        return Ok(0);
    }
    let domain_select = if sqlite_column_exists(&conn, "history_items", "domain_expansion")? {
        "domain_expansion"
    } else {
        "NULL"
    };
    let source_metadata = source_artifact_metadata(history_path, "History.db");
    let sql = format!(
        "SELECT id, url, visit_count, {domain_select}
         FROM history_items
         ORDER BY COALESCE(visit_count, 0) DESC, id DESC
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![sqlite_limit_param(max_rows)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut records = BrowserRecordEmitter::new(emit);
    for row in rows {
        let (id, url, visit_count, domain_expansion) = row?;
        let host = host_from_url(&url);
        let mut metadata = serde_json::json!({
            "artifact_kind": "browser_url",
            "browser_family": "safari",
            "history_item_id": id,
            "url": url,
            "host": host,
            "visit_count": visit_count,
            "domain_expansion": domain_expansion,
        });
        merge_json_object(&mut metadata, &source_metadata);
        let logical_path = format!(
            "/Browser Activities/URLs/{}/{}.record",
            sanitize_logical_segment(&host),
            id
        );
        let display_name = url.chars().take(180).collect::<String>();
        add_entry_category(&mut metadata, &logical_path, &display_name, "record");
        records.push(BrowserActivityRecord {
            logical_path,
            display_name,
            metadata_json: metadata.to_string(),
        });
    }
    records.finish()
}

pub fn file_name_from_pathish(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(['/', '\\']);
    let without_query = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let name = without_query
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(without_query)
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub fn firefox_visit_type_label(visit_type: i64) -> &'static str {
    match visit_type {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect_permanent",
        6 => "redirect_temporary",
        7 => "download",
        8 => "framed_link",
        9 => "reload",
        _ => "unknown",
    }
}

pub fn firefox_download_state_label(state: i64) -> String {
    match state {
        0 => "downloading".to_string(),
        1 => "finished".to_string(),
        2 => "failed".to_string(),
        3 => "canceled".to_string(),
        4 => "paused".to_string(),
        5 => "queued".to_string(),
        6 => "blocked-parental".to_string(),
        7 => "scanning".to_string(),
        8 => "dirty".to_string(),
        9 => "blocked-policy".to_string(),
        value => format!("unknown ({value})"),
    }
}

#[derive(Clone)]
pub struct IndexedBrowserSourceFile {
    entry_id: i64,
    exact_path: String,
    size_bytes: Option<i64>,
    metadata: serde_json::Value,
}

pub struct BrowserDerivedImportContext<'a> {
    evidence_id: i64,
    derivation_key: &'a str,
    logical_prefix: &'a str,
    source_profile_path: &'a str,
    volume_index_zero_based: Option<usize>,
    staging_path: &'a Path,
    source_files: &'a HashMap<String, IndexedBrowserSourceFile>,
}

pub fn normalized_browser_source_path(value: &str) -> String {
    value.replace('\\', "/").trim_matches('/').to_string()
}

pub fn join_browser_source_path(profile_path: &str, relative_path: &str) -> String {
    let profile = profile_path.replace('\\', "/");
    let relative = relative_path.replace('\\', "/");
    if profile.trim_matches('/').is_empty() {
        relative.trim_start_matches('/').to_string()
    } else {
        format!(
            "{}/{}",
            profile.trim_end_matches('/'),
            relative.trim_start_matches('/')
        )
    }
}

pub fn is_exact_browser_profile_relative_artifact(relative_path: &str) -> bool {
    let normalized = relative_path.replace('\\', "/");
    let normalized = normalized.trim_matches('/');
    if !normalized.contains('/') {
        return is_ext_browser_top_level_artifact(normalized);
    }
    normalized
        .strip_prefix("Network/")
        .filter(|name| !name.contains('/'))
        .is_some_and(is_ext_browser_network_artifact)
}

pub fn load_indexed_browser_source_files(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
) -> Result<HashMap<String, IndexedBrowserSourceFile>> {
    let profile_key = normalized_browser_source_path(source_profile_path);
    let mut stmt = conn.prepare(
        "SELECT id, size_bytes, metadata_json
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2 AND entry_kind = 'file'
           AND (
               name IN ('History', 'History.db', 'places.sqlite', 'downloads.sqlite',
                        'formhistory.sqlite', 'cookies.sqlite', 'logins.json', 'Login Data', 'Cookies',
                        'Bookmarks', 'Preferences', 'Shortcuts', 'Web Data')
               OR name LIKE 'History-%'
               OR name LIKE 'History.db-%'
               OR name LIKE 'places.sqlite-%'
               OR name LIKE 'downloads.sqlite-%'
               OR name LIKE 'formhistory.sqlite-%'
               OR name LIKE 'cookies.sqlite-%'
               OR name LIKE 'Login Data-%'
               OR name LIKE 'Cookies-%'
               OR name LIKE 'Shortcuts-%'
               OR name LIKE 'Web Data-%'
           )",
    )?;
    let rows = stmt.query_map(params![case_id, evidence_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut files = HashMap::new();
    for row in rows {
        let (entry_id, size_bytes, metadata_json) = row?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
            .with_context(|| format!("parsing browser source metadata for entry {entry_id}"))?;
        let source_volume = metadata
            .get("volume_index_zero_based")
            .and_then(|value| value.as_u64())
            .and_then(|value| usize::try_from(value).ok());
        if source_volume != volume_index_zero_based {
            continue;
        }
        let Some(exact_path) = source_path_exact_from_metadata(&metadata) else {
            continue;
        };
        let exact_key = normalized_browser_source_path(&exact_path);
        let relative = if profile_key.is_empty() {
            exact_key.as_str()
        } else if exact_key == profile_key {
            ""
        } else if let Some(relative) = exact_key.strip_prefix(&format!("{profile_key}/")) {
            relative
        } else {
            continue;
        };
        if !is_exact_browser_profile_relative_artifact(relative) {
            continue;
        }
        files.insert(
            exact_key,
            IndexedBrowserSourceFile {
                entry_id,
                exact_path,
                size_bytes,
                metadata,
            },
        );
    }
    Ok(files)
}

/// Exports only the indexed browser databases/configuration files that the
/// browser parser actually consumes, including SQLite sidecars. This avoids
/// staging an entire profile/cache tree and therefore has no unrelated
/// file-count, directory-count, or per-file-size omission cap.
pub fn export_indexed_browser_profile(
    case_path: &Path,
    evidence_id: i64,
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
    output_root: &Path,
) -> Result<usize> {
    let files = {
        let conn = open_existing_case(case_path)?;
        let case_id = active_case_id(&conn)?;
        ensure_evidence_source(&conn, case_id, evidence_id)?;
        load_indexed_browser_source_files(
            &conn,
            case_id,
            evidence_id,
            source_profile_path,
            volume_index_zero_based,
        )?
    };
    if files.is_empty() {
        bail!("no supported indexed browser files exist under profile {source_profile_path}");
    }
    let profile_key = normalized_browser_source_path(source_profile_path);
    let prefix = if profile_key.is_empty() {
        String::new()
    } else {
        format!("{profile_key}/")
    };
    let mut sources = files.into_values().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.exact_path.cmp(&right.exact_path));
    fs::create_dir_all(output_root)
        .with_context(|| format!("creating browser staging root {}", output_root.display()))?;
    let mut exported = 0_usize;
    let mut read_session = EvidenceReadSession::open(case_path)?;
    for source in sources {
        let exact_key = normalized_browser_source_path(&source.exact_path);
        let relative = if profile_key.is_empty() {
            exact_key.as_str()
        } else {
            exact_key.strip_prefix(&prefix).with_context(|| {
                format!(
                    "indexed browser file {} is not below profile {}",
                    source.exact_path, source_profile_path
                )
            })?
        };
        let mut output_path = output_root.to_path_buf();
        for component in relative.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                bail!(
                    "unsafe relative browser artifact path {:?} from {}",
                    relative,
                    source.exact_path
                );
            }
            output_path.push(component);
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating browser staging folder {}", parent.display()))?;
        }
        recover_filesystem_entry_in_session(
            &mut read_session,
            RecoverEntryOptions {
                entry_id: source.entry_id,
                output_path,
            },
        )
        .with_context(|| format!("staging browser source {}", source.exact_path))?;
        exported += 1;
    }
    Ok(exported)
}

pub fn browser_record_source_file<'a>(
    metadata: &serde_json::Value,
    context: &'a BrowserDerivedImportContext<'_>,
) -> (String, Option<&'a IndexedBrowserSourceFile>) {
    let artifact = metadata
        .get("source_artifact")
        .and_then(|value| value.as_str())
        .unwrap_or("browser source");
    let mut relative_candidates = vec![artifact.to_string()];
    if artifact.eq_ignore_ascii_case("Cookies") {
        relative_candidates.insert(0, "Network/Cookies".to_string());
    }
    for relative in &relative_candidates {
        let exact = join_browser_source_path(context.source_profile_path, relative);
        if let Some(source) = context
            .source_files
            .get(&normalized_browser_source_path(&exact))
        {
            return (source.exact_path.clone(), Some(source));
        }
    }
    (
        join_browser_source_path(context.source_profile_path, &relative_candidates[0]),
        None,
    )
}

pub fn first_metadata_value(metadata: &serde_json::Value, keys: &[&str]) -> Option<serde_json::Value> {
    keys.iter()
        .filter_map(|key| metadata.get(*key))
        .find(|value| json_has_display_value(Some(*value)))
        .cloned()
}

pub fn move_staging_source_metadata(object: &mut serde_json::Map<String, serde_json::Value>) {
    for (source, staging) in [
        ("source_artifact_path", "source_artifact_staging_path"),
        ("source_file_size_bytes", "staging_file_size_bytes"),
        ("source_file_created_utc", "staging_file_created_utc"),
        ("source_file_modified_utc", "staging_file_modified_utc"),
        ("source_file_accessed_utc", "staging_file_accessed_utc"),
    ] {
        if let Some(value) = object.remove(source) {
            object.insert(staging.to_string(), value);
        }
    }
    object.remove("source_file_time_basis");
}

pub fn apply_indexed_browser_source_metadata(
    object: &mut serde_json::Map<String, serde_json::Value>,
    source: &IndexedBrowserSourceFile,
) {
    object.insert(
        "source_entry_id".to_string(),
        serde_json::json!(source.entry_id),
    );
    object.insert(
        "source_file_time_basis".to_string(),
        serde_json::json!("original_evidence_filesystem"),
    );
    for (target, keys) in [
        (
            "source_file_created_utc",
            &[
                "ntfs_creation_time_utc",
                "ntfs_standard_creation_time_utc",
                "standard_information_created_utc",
                "created_utc",
                "fat_created",
            ][..],
        ),
        (
            "source_file_modified_utc",
            &[
                "ntfs_modification_time_utc",
                "ntfs_standard_modification_time_utc",
                "standard_information_modified_utc",
                "modified_utc",
                "fat_modified",
            ][..],
        ),
        (
            "source_file_accessed_utc",
            &[
                "ntfs_access_time_utc",
                "ntfs_standard_access_time_utc",
                "standard_information_accessed_utc",
                "accessed_utc",
                "fat_accessed",
            ][..],
        ),
        (
            "source_file_mft_modified_utc",
            &[
                "ntfs_mft_record_modification_time_utc",
                "ntfs_standard_mft_record_modification_time_utc",
                "standard_information_mft_modified_utc",
                "mft_modified_utc",
            ][..],
        ),
    ] {
        if let Some(value) = first_metadata_value(&source.metadata, keys) {
            object.insert(target.to_string(), value);
        }
    }
    if let Some(value) = first_metadata_value(&source.metadata, &["file_sha256"]) {
        object.insert("source_file_sha256".to_string(), value);
    }
    if let Some(value) = source.size_bytes {
        object.insert(
            "source_file_size_bytes".to_string(),
            serde_json::json!(value),
        );
    }
}

pub fn apply_browser_derived_provenance(
    metadata: &mut serde_json::Value,
    context: &BrowserDerivedImportContext<'_>,
) {
    let (source_exact_path, source_file) = browser_record_source_file(metadata, context);
    let Some(object) = metadata.as_object_mut() else {
        return;
    };
    move_staging_source_metadata(object);
    if object
        .get("browser_family")
        .and_then(|value| value.as_str())
        == Some("chromium")
    {
        object.insert(
            "browser_brand".to_string(),
            serde_json::json!(chromium_browser_brand(context.source_profile_path)),
        );
    }
    object.insert(
        "browser_derivation_key".to_string(),
        serde_json::json!(context.derivation_key),
    );
    object.insert(
        "source_evidence_id".to_string(),
        serde_json::json!(context.evidence_id),
    );
    object.insert("derived_artifact".to_string(), serde_json::json!(true));
    object.insert(
        "source_profile_path_exact".to_string(),
        serde_json::json!(context.source_profile_path),
    );
    object.insert(
        "volume_index_zero_based".to_string(),
        serde_json::json!(context.volume_index_zero_based),
    );
    object.insert(
        "browser_profile_staging_path".to_string(),
        serde_json::json!(context.staging_path.to_string_lossy()),
    );
    object.insert(
        "source_artifact_path".to_string(),
        serde_json::json!(source_exact_path),
    );
    object.insert(
        "source_artifact_path_exact".to_string(),
        serde_json::json!(source_exact_path),
    );
    object.insert(
        "source_path_exact".to_string(),
        serde_json::json!(source_exact_path),
    );

    if let Some(source) = source_file {
        apply_indexed_browser_source_metadata(object, source);
    } else {
        object.insert(
            "source_file_time_basis".to_string(),
            serde_json::json!("original_evidence_path_resolved_times_unavailable"),
        );
    }
}

/// Some browser artifacts (notably Chromium's `Network/Cookies`) are parsed
/// when their profile directory is visited, before the breadth-first EXT walk
/// has indexed the nested source file. Revisit only derived rows that still
/// lack a source entry after the walk, in bounded pages, and attach the exact
/// original entry/MACB provenance without changing any canonical path value.
pub fn relink_ext_browser_derived_provenance(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    partition_index_one_based: usize,
) -> Result<usize> {
    const PAGE_SIZE: i64 = 64;
    let volume_index_zero_based = partition_index_one_based.saturating_sub(1);
    let mut last_id = 0_i64;
    let mut relinked = 0_usize;

    loop {
        let page = {
            let mut stmt = conn.prepare(
                "SELECT id, metadata_json
                 FROM filesystem_entries
                 WHERE case_id = ?1 AND evidence_id = ?2 AND discovered_by_job_id = ?3
                   AND id > ?4
                   AND json_extract(metadata_json, '$.derived_artifact') = 1
                   AND json_extract(metadata_json, '$.source_entry_id') IS NULL
                   AND json_extract(metadata_json, '$.volume_index_zero_based') = ?5
                 ORDER BY id
                 LIMIT ?6",
            )?;
            let rows = stmt.query_map(
                params![
                    case_id,
                    evidence_id,
                    job_id,
                    last_id,
                    i64::try_from(volume_index_zero_based).unwrap_or(i64::MAX),
                    PAGE_SIZE,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        if page.is_empty() {
            break;
        }

        for (derived_id, metadata_json) in page {
            last_id = derived_id;
            let mut metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                .with_context(|| {
                    format!("parsing derived browser metadata for entry {derived_id}")
                })?;
            let Some(source_path) = metadata
                .get("source_artifact_path_exact")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            let source_path_with_slash = format!("/{}", source_path.trim_start_matches('/'));
            let source = conn
                .query_row(
                    "SELECT id, size_bytes, metadata_json
                     FROM filesystem_entries
                     WHERE case_id = ?1 AND evidence_id = ?2 AND discovered_by_job_id = ?3
                       AND entry_kind = 'file'
                       AND json_extract(metadata_json, '$.filesystem_parser') = 'ext4'
                       AND json_extract(metadata_json, '$.partition_index') = ?4
                       AND json_extract(metadata_json, '$.ext_path') IN (?5, ?6)
                     ORDER BY id DESC LIMIT 1",
                    params![
                        case_id,
                        evidence_id,
                        job_id,
                        i64::try_from(partition_index_one_based).unwrap_or(i64::MAX),
                        source_path,
                        source_path_with_slash,
                    ],
                    |row| {
                        let entry_id = row.get::<_, i64>(0)?;
                        let size_bytes = row.get::<_, Option<i64>>(1)?;
                        let source_metadata_json = row.get::<_, String>(2)?;
                        Ok((entry_id, size_bytes, source_metadata_json))
                    },
                )
                .optional()?;
            let Some((entry_id, size_bytes, source_metadata_json)) = source else {
                continue;
            };
            let source_metadata: serde_json::Value = serde_json::from_str(&source_metadata_json)
                .with_context(|| {
                    format!("parsing EXT browser source metadata for entry {entry_id}")
                })?;
            let source = IndexedBrowserSourceFile {
                entry_id,
                exact_path: source_path_with_slash,
                size_bytes,
                metadata: source_metadata,
            };
            let Some(object) = metadata.as_object_mut() else {
                continue;
            };
            apply_indexed_browser_source_metadata(object, &source);
            conn.execute(
                "UPDATE filesystem_entries SET metadata_json = ?1 WHERE id = ?2",
                params![metadata.to_string(), derived_id],
            )?;
            relinked = relinked.saturating_add(1);
        }
    }
    Ok(relinked)
}

/// Inserts a browser-history parse result's records directly into an
/// ALREADY-EXISTING evidence source (not a new one) - shares the insert loop
/// shape with `persist_browser_history_import`, but that function always
/// creates/reuses its own dedicated `browser_history` evidence row via
/// `upsert_browser_history_evidence`, which is wrong for auto-detected
/// profiles found mid-walk: those belong under the SAME evidence_id as the
/// disk image they were found on, so the examiner sees them as part of one
/// unified case view (via the case-wide Categories fix), not as a mystery
/// second evidence source they have to go find.
pub fn insert_browser_history_records_into_evidence(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    import_data: &BrowserHistoryImportData,
    derived_context: Option<&BrowserDerivedImportContext<'_>>,
) -> Result<usize> {
    let mut inserted = 0_usize;
    import_data.records.for_each_record(|record| {
        let mut metadata_json: serde_json::Value = serde_json::from_str(&record.metadata_json)
            .with_context(|| format!("parsing browser metadata for {}", record.logical_path))?;
        let logical_path = if let Some(context) = derived_context {
            apply_browser_derived_provenance(&mut metadata_json, context);
            format!("{}{}", context.logical_prefix, record.logical_path)
        } else {
            record.logical_path.clone()
        };
        if let Some(object) = metadata_json.as_object_mut() {
            object.insert(
                "parsed_record_logical_path".to_string(),
                serde_json::json!(record.logical_path),
            );
        }
        let metadata_json = metadata_json.to_string();
        upsert_filesystem_entry(
            conn,
            case_id,
            evidence_id,
            &logical_path,
            &record.display_name,
            "record",
            None,
            &metadata_json,
            job_id,
        )?;
        inserted += 1;
        Ok(())
    })?;
    Ok(inserted)
}

pub fn append_auto_browser_import_job_disclosure(
    conn: &Connection,
    job_id: i64,
    disclosure: serde_json::Value,
) -> Result<()> {
    let parameters_json: String = conn
        .query_row(
            "SELECT parameters_json FROM evidence_jobs WHERE id = ?1",
            params![job_id],
            |row| row.get(0),
        )
        .with_context(|| format!("reading filesystem-index job {job_id}"))?;
    let mut parameters: serde_json::Value = serde_json::from_str(&parameters_json)
        .with_context(|| format!("parsing filesystem-index job {job_id} parameters"))?;
    let object = parameters
        .as_object_mut()
        .ok_or_else(|| anyhow!("filesystem-index job {job_id} parameters are not an object"))?;
    let disclosures = object
        .entry("auto_browser_imports".to_string())
        .or_insert_with(|| serde_json::json!([]));
    if !disclosures.is_array() {
        *disclosures = serde_json::json!([]);
    }
    let disclosures = disclosures
        .as_array_mut()
        .ok_or_else(|| anyhow!("filesystem-index browser disclosure list is not an array"))?;
    disclosures.push(disclosure);
    let parse_error_count = disclosures
        .iter()
        .map(|item| {
            item.get("parse_error_count")
                .and_then(|value| value.as_u64())
                .or_else(|| {
                    item.get("parse_errors")
                        .and_then(|value| value.as_array())
                        .map(|errors| errors.len() as u64)
                })
                .unwrap_or(0)
        })
        .fold(0_u64, u64::saturating_add);
    object.insert(
        "browser_parse_error_count".to_string(),
        serde_json::json!(parse_error_count),
    );
    conn.execute(
        "UPDATE evidence_jobs SET parameters_json = ?1 WHERE id = ?2",
        params![parameters.to_string(), job_id],
    )?;
    Ok(())
}

/// Returns the structured EXT mid-walk browser import disclosures from the
/// latest filesystem-index job. The post-index browser stage uses this rather
/// than treating every EXT profile as a successful skip.
pub fn browser_auto_import_disclosures(
    case_path: &Path,
    evidence_id: i64,
) -> Result<Vec<serde_json::Value>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let parameters_json: Option<String> = conn
        .query_row(
            "SELECT parameters_json
             FROM evidence_jobs
             WHERE case_id = ?1 AND evidence_id = ?2
               AND job_type = 'filesystem_index'
             ORDER BY id DESC LIMIT 1",
            params![case_id, evidence_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(parameters_json) = parameters_json else {
        return Ok(Vec::new());
    };
    let parameters: serde_json::Value = serde_json::from_str(&parameters_json)
        .context("parsing auto browser import disclosures")?;
    Ok(parameters
        .get("auto_browser_imports")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default())
}

#[allow(clippy::too_many_arguments)]
pub fn persist_auto_browser_profile_import(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
    staging_path: &Path,
    import_data: &BrowserHistoryImportData,
) -> Result<usize> {
    const SAVEPOINT: &str = "kdft_auto_browser_profile_import";
    conn.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))?;
    let result = persist_auto_browser_profile_import_inner(
        conn,
        case_id,
        evidence_id,
        job_id,
        source_profile_path,
        volume_index_zero_based,
        staging_path,
        import_data,
    );
    match result {
        Ok(inserted) => {
            conn.execute_batch(&format!("RELEASE SAVEPOINT {SAVEPOINT}"))?;
            Ok(inserted)
        }
        Err(error) => {
            conn.execute_batch(&format!(
                "ROLLBACK TO SAVEPOINT {SAVEPOINT}; RELEASE SAVEPOINT {SAVEPOINT};"
            ))
            .context("rolling back failed EXT browser profile persistence")?;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn persist_auto_browser_profile_import_inner(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
    staging_path: &Path,
    import_data: &BrowserHistoryImportData,
) -> Result<usize> {
    let derivation_key =
        browser_profile_derivation_key(source_profile_path, volume_index_zero_based);
    let logical_prefix = browser_profile_logical_prefix(
        source_profile_path,
        volume_index_zero_based,
        &derivation_key,
    );
    let source_files = load_indexed_browser_source_files(
        conn,
        case_id,
        evidence_id,
        source_profile_path,
        volume_index_zero_based,
    )?;

    // A profile is a replaceable derived dataset even during the EXT walk.
    // The source filesystem entries do not carry this key and are untouched.
    conn.execute(
        "DELETE FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND json_extract(metadata_json, '$.browser_derivation_key') = ?3",
        params![case_id, evidence_id, derivation_key],
    )?;
    let context = BrowserDerivedImportContext {
        evidence_id,
        derivation_key: &derivation_key,
        logical_prefix: &logical_prefix,
        source_profile_path,
        volume_index_zero_based,
        staging_path,
        source_files: &source_files,
    };
    let inserted = insert_browser_history_records_into_evidence(
        conn,
        case_id,
        evidence_id,
        job_id,
        import_data,
        Some(&context),
    )?;
    append_auto_browser_import_job_disclosure(
        conn,
        job_id,
        serde_json::json!({
            "browser_derivation_key": derivation_key,
            "browser_family": import_data.family.as_str(),
            "source_profile_path": source_profile_path,
            "volume_index_zero_based": volume_index_zero_based,
            "staging_path": staging_path,
            "entries_indexed": inserted,
            "visits_indexed": import_data.records.counts.visits,
            "bookmarks_indexed": import_data.records.counts.bookmarks,
            "preferences_indexed": import_data.records.counts.preferences,
            "parse_errors": &import_data.parse_errors,
            "parse_error_count": import_data.parse_error_count,
            "parse_error_samples_omitted": import_data.parse_error_count.saturating_sub(import_data.parse_errors.len() as u64),
            "status": if import_data.parse_error_count == 0 {
                "completed"
            } else {
                "completed_with_errors"
            },
        }),
    )?;
    Ok(inserted)
}

pub fn auto_browser_profile_staging_root(
    imports_root: &Path,
    evidence_id: i64,
    profile_name: &str,
    derivation_key: &str,
    job_id: i64,
) -> PathBuf {
    let digest = sha256_hex(derivation_key.as_bytes());
    imports_root.join(format!(
        "evidence-{evidence_id}-{}-{}-job-{job_id}",
        sanitize_logical_segment(profile_name),
        &digest[..12]
    ))
}

pub fn ensure_directory_is_not_reparse(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {description} metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "{description} cannot be a symbolic link: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!(
                "{description} cannot be a reparse point: {}",
                path.display()
            );
        }
    }
    if !metadata.is_dir() {
        bail!("{description} is not a directory: {}", path.display());
    }
    Ok(())
}

pub const EXT_BROWSER_TOP_LEVEL_ARTIFACTS: &[&str] = &[
    "History",
    "History-wal",
    "History-shm",
    "History-journal",
    "Bookmarks",
    "Preferences",
    "Shortcuts",
    "Shortcuts-wal",
    "Shortcuts-shm",
    "Shortcuts-journal",
    "Web Data",
    "Web Data-wal",
    "Web Data-shm",
    "Web Data-journal",
    "Login Data",
    "Login Data-wal",
    "Login Data-shm",
    "Login Data-journal",
    "Cookies",
    "Cookies-wal",
    "Cookies-shm",
    "Cookies-journal",
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "places.sqlite-journal",
    "downloads.sqlite",
    "downloads.sqlite-wal",
    "downloads.sqlite-shm",
    "downloads.sqlite-journal",
    "formhistory.sqlite",
    "formhistory.sqlite-wal",
    "formhistory.sqlite-shm",
    "formhistory.sqlite-journal",
    "cookies.sqlite",
    "cookies.sqlite-wal",
    "cookies.sqlite-shm",
    "cookies.sqlite-journal",
    "logins.json",
    "History.db",
    "History.db-wal",
    "History.db-shm",
    "History.db-journal",
];

pub const EXT_BROWSER_NETWORK_ARTIFACTS: &[&str] =
    &["Cookies", "Cookies-wal", "Cookies-shm", "Cookies-journal"];

pub fn is_ext_browser_top_level_artifact(name: &str) -> bool {
    EXT_BROWSER_TOP_LEVEL_ARTIFACTS.contains(&name)
}

pub fn is_ext_browser_network_artifact(name: &str) -> bool {
    EXT_BROWSER_NETWORK_ARTIFACTS.contains(&name)
}

pub(crate) fn stage_ext_browser_file(
    image_fs: &ext4::SuperBlock<Ext4ImageReader>,
    inode_number: u32,
    source_path: &str,
    destination: &Path,
) -> Result<u64> {
    let inode = image_fs
        .load_inode(inode_number)
        .map_err(|error| anyhow!("loading inode for {source_path}: {error}"))?;
    let mut reader = image_fs
        .open(&inode)
        .map_err(|error| anyhow!("opening {source_path}: {error}"))?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating browser staging folder {}", parent.display()))?;
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("creating staged browser file {}", destination.display()))?;
    let copied = match io::copy(&mut reader, &mut output) {
        Ok(copied) => copied,
        Err(error) => {
            drop(output);
            let _ = fs::remove_file(destination);
            return Err(error).with_context(|| {
                format!(
                    "streaming EXT browser artifact {source_path} to {}",
                    destination.display()
                )
            });
        }
    };
    if let Err(error) = output.flush() {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(error)
            .with_context(|| format!("flushing staged browser file {}", destination.display()));
    }
    Ok(copied)
}

pub fn append_failed_auto_browser_disclosure(
    conn: &Connection,
    job_id: i64,
    derivation_key: &str,
    source_profile_path: &str,
    volume_index_zero_based: Option<usize>,
    diagnostics: &BrowserImportDiagnostics,
) -> Result<()> {
    append_auto_browser_import_job_disclosure(
        conn,
        job_id,
        serde_json::json!({
            "browser_derivation_key": derivation_key,
            "source_profile_path": source_profile_path,
            "volume_index_zero_based": volume_index_zero_based,
            "entries_indexed": 0,
            "parse_errors": diagnostics.samples,
            "parse_error_count": diagnostics.total,
            "parse_error_samples_omitted": diagnostics.total.saturating_sub(diagnostics.samples.len() as u64),
            "status": "failed",
        }),
    )
}

pub fn detect_staged_browser_family(staging_root: &Path) -> Result<Option<BrowserFamily>> {
    let mut detected_families = Vec::new();
    for marker in [
        staging_root.join("History"),
        staging_root.join("places.sqlite"),
    ]
    .into_iter()
    .filter(|path| path.is_file())
    {
        if let Some(family) = detect_browser_database(&marker)? {
            if !detected_families.contains(&family) {
                detected_families.push(family);
            }
        }
    }
    match detected_families.as_slice() {
        [family] => Ok(Some(*family)),
        [] => Ok(None),
        _ => bail!("multiple supported browser schemas were present"),
    }
}

/// Checks one just-listed EXT directory for the top-level marker file of a
/// Firefox (`places.sqlite`) or Chromium (`History`) browser profile. It
/// streams only exact parser-consumed artifacts and SQLite sidecars (including
/// modern `Network/Cookies`) to the persistent staging folder, then parses and
/// inserts records under the enclosing evidence id. Unrelated cache/profile
/// files are never staged. Optional staging and parser failures are retained
/// as bounded samples with exact counts and make the enclosing filesystem job
/// explicitly partial/truncated.
#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_auto_import_browser_profile(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    job_id: i64,
    image_fs: &ext4::SuperBlock<Ext4ImageReader>,
    ext_dir_path: &str,
    children: &[ExtChild],
    volume_index_zero_based: Option<usize>,
    indexed: &mut usize,
) -> Result<u64> {
    let has_firefox_marker = children
        .iter()
        .any(|child| !child.is_dir && child.name.eq_ignore_ascii_case("places.sqlite"));
    let has_chromium_marker = children
        .iter()
        .any(|child| !child.is_dir && child.name == "History");
    if !has_firefox_marker && !has_chromium_marker {
        return Ok(0);
    }
    let Some(case_path) = conn.path() else {
        return Ok(0);
    };
    let case_path = PathBuf::from(case_path);
    let case_stem = case_path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "case".to_string());
    let imports_root = case_path
        .parent()
        .map(|parent| parent.join(format!("{case_stem}-history-imports")))
        .unwrap_or_else(|| PathBuf::from(format!("{case_stem}-history-imports")));
    let profile_name = ext_dir_path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("profile");
    let derivation_key = browser_profile_derivation_key(ext_dir_path, volume_index_zero_based);
    let staging_root = auto_browser_profile_staging_root(
        &imports_root,
        evidence_id,
        profile_name,
        &derivation_key,
        job_id,
    );
    let mut staging_diagnostics = BrowserImportDiagnostics::default();
    let staging_created = (|| -> Result<()> {
        fs::create_dir_all(&imports_root)
            .with_context(|| format!("creating browser imports root {}", imports_root.display()))?;
        ensure_directory_is_not_reparse(&imports_root, "browser imports root")?;
        fs::create_dir(&staging_root)
            .with_context(|| format!("creating staging folder {}", staging_root.display()))?;
        Ok(())
    })();
    if let Err(error) = staging_created {
        staging_diagnostics.record(format!(
            "creating staging folder {}: {error}",
            staging_root.display()
        ));
        append_failed_auto_browser_disclosure(
            conn,
            job_id,
            &derivation_key,
            ext_dir_path,
            volume_index_zero_based,
            &staging_diagnostics,
        )?;
        return Ok(staging_diagnostics.total);
    }
    let mut staged_marker = false;
    for child in children {
        if child.is_dir || !is_ext_browser_top_level_artifact(&child.name) {
            continue;
        }
        let child_ext_path = if ext_dir_path == "/" {
            format!("/{}", child.name)
        } else {
            format!("{ext_dir_path}/{}", child.name)
        };
        if child.is_symlink {
            staging_diagnostics.record(format!(
                "staging {child_ext_path}: recognized browser artifact is a symlink; symlink targets are not followed by the EXT evidence reader"
            ));
            continue;
        }
        match stage_ext_browser_file(
            image_fs,
            child.inode_number,
            &child_ext_path,
            &staging_root.join(&child.name),
        ) {
            Ok(copied) => {
                staged_marker |=
                    child.name == "History" || child.name.eq_ignore_ascii_case("places.sqlite");
                if copied != child.size {
                    staging_diagnostics.record(format!(
                        "staging {child_ext_path}: expected {} bytes from EXT metadata but streamed {copied}",
                        child.size
                    ));
                }
            }
            Err(error) => {
                staging_diagnostics.record(format!("staging {child_ext_path}: {error:#}"));
            }
        }
    }
    // Modern Chromium stores Cookies under Network/. Stage only that parser
    // input and its SQLite sidecars; cache/storage trees are unrelated.
    if has_chromium_marker
        && children
            .iter()
            .any(|child| child.name == "Network" && child.is_symlink)
    {
        staging_diagnostics.record(format!(
            "staging {}/Network: recognized Chromium Network directory is a symlink; symlink targets are not followed by the EXT evidence reader",
            ext_dir_path.trim_end_matches('/'),
        ));
    }
    if has_chromium_marker
        && children
            .iter()
            .any(|child| child.is_dir && child.name == "Network")
    {
        let network_ext_path = format!("{}/Network", ext_dir_path.trim_end_matches('/'));
        match ext4_list_dir(image_fs, &network_ext_path) {
            Ok(network_children) => {
                for child in network_children {
                    if child.is_dir || !is_ext_browser_network_artifact(&child.name) {
                        continue;
                    }
                    let child_ext_path = format!("{network_ext_path}/{}", child.name);
                    if child.is_symlink {
                        staging_diagnostics.record(format!(
                            "staging {child_ext_path}: recognized browser artifact is a symlink; symlink targets are not followed by the EXT evidence reader"
                        ));
                        continue;
                    }
                    match stage_ext_browser_file(
                        image_fs,
                        child.inode_number,
                        &child_ext_path,
                        &staging_root.join("Network").join(&child.name),
                    ) {
                        Ok(copied) => {
                            if copied != child.size {
                                staging_diagnostics.record(format!(
                                    "staging {child_ext_path}: expected {} bytes from EXT metadata but streamed {copied}",
                                    child.size
                                ));
                            }
                        }
                        Err(error) => staging_diagnostics
                            .record(format!("staging {child_ext_path}: {error:#}")),
                    }
                }
            }
            Err(error) => staging_diagnostics.record(format!(
                "staging {network_ext_path}: could not list Network artifacts: {error:#}"
            )),
        }
    }
    if !staged_marker {
        if staging_diagnostics.total == 0 {
            staging_diagnostics.record(format!(
                "staging {ext_dir_path}: browser marker could not be staged"
            ));
        }
        append_failed_auto_browser_disclosure(
            conn,
            job_id,
            &derivation_key,
            ext_dir_path,
            volume_index_zero_based,
            &staging_diagnostics,
        )?;
        return Ok(staging_diagnostics.total);
    }
    let family = match detect_staged_browser_family(&staging_root) {
        Ok(Some(family)) => family,
        Ok(None) => {
            // A generic file called History is not itself evidence of a
            // browser profile. Keep it in the filesystem index, remove only
            // our staging copy, and do not inflate browser/error counts.
            return Ok(0);
        }
        Err(error) => {
            staging_diagnostics.record(format!(
                "detecting staged browser profile {ext_dir_path}: {error:#}"
            ));
            append_failed_auto_browser_disclosure(
                conn,
                job_id,
                &derivation_key,
                ext_dir_path,
                volume_index_zero_based,
                &staging_diagnostics,
            )?;
            return Ok(staging_diagnostics.total);
        }
    };
    // collect_*_history_import take an already-resolved row cap, not "0 means
    // unlimited" - that conversion normally happens in import_browser_history
    // (via unlimited_if_zero) before reaching these functions. Passing a bare
    // 0 through here silently asked for zero rows of everything, which is
    // exactly why this returned successfully but inserted nothing.
    let max_visits = unlimited_if_zero(0);
    let collected = match family {
        BrowserFamily::Chromium => collect_chromium_history_import(&staging_root, max_visits),
        BrowserFamily::Firefox => collect_firefox_history_import(&staging_root, max_visits),
        BrowserFamily::Safari => collect_safari_history_import(&staging_root, max_visits),
    };
    let mut import_data = match collected {
        Ok(import_data) => import_data,
        Err(error) => {
            staging_diagnostics.record(format!(
                "parsing staged browser profile {ext_dir_path}: {error:#}"
            ));
            append_failed_auto_browser_disclosure(
                conn,
                job_id,
                &derivation_key,
                ext_dir_path,
                volume_index_zero_based,
                &staging_diagnostics,
            )?;
            return Ok(staging_diagnostics.total);
        }
    };
    import_data.add_diagnostics(staging_diagnostics)?;
    let inserted = match persist_auto_browser_profile_import(
        conn,
        case_id,
        evidence_id,
        job_id,
        ext_dir_path,
        volume_index_zero_based,
        &staging_root,
        &import_data,
    ) {
        Ok(inserted) => inserted,
        Err(error) => {
            let mut persistence_diagnostics = BrowserImportDiagnostics {
                samples: import_data.parse_errors.clone(),
                total: import_data.parse_error_count,
            };
            persistence_diagnostics.record(format!(
                "persisting staged browser profile {ext_dir_path}: {error:#}"
            ));
            append_failed_auto_browser_disclosure(
                conn,
                job_id,
                &derivation_key,
                ext_dir_path,
                volume_index_zero_based,
                &persistence_diagnostics,
            )?;
            return Ok(persistence_diagnostics.total);
        }
    };
    *indexed += inserted;
    Ok(import_data.parse_error_count)
}

pub fn chromium_profile_paths(input_path: &Path) -> Result<ChromiumProfilePaths> {
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("reading browser profile path {}", input_path.display()))?;
    let profile_dir = if metadata.is_dir() {
        input_path.to_path_buf()
    } else if metadata.is_file() {
        input_path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "browser history file has no parent: {}",
                    input_path.display()
                )
            })?
    } else {
        bail!(
            "browser history/profile path is not a file or directory: {}",
            input_path.display()
        );
    };
    let history_path = if metadata.is_file() {
        input_path.to_path_buf()
    } else {
        profile_dir.join("History")
    };
    if !history_path.is_file() {
        bail!(
            "Chromium History database was not found: {}",
            history_path.display()
        );
    }
    Ok(ChromiumProfilePaths {
        bookmarks_path: profile_dir.join("Bookmarks"),
        preferences_path: profile_dir.join("Preferences"),
        shortcuts_path: profile_dir.join("Shortcuts"),
        web_data_path: profile_dir.join("Web Data"),
        profile_dir,
        history_path,
    })
}

pub fn firefox_profile_paths(input_path: &Path) -> Result<FirefoxProfilePaths> {
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("reading Firefox profile path {}", input_path.display()))?;
    let profile_dir = if metadata.is_dir() {
        input_path.to_path_buf()
    } else if metadata.is_file() {
        input_path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "Firefox places.sqlite file has no parent: {}",
                    input_path.display()
                )
            })?
    } else {
        bail!(
            "Firefox profile/history path is not a file or directory: {}",
            input_path.display()
        );
    };
    let places_path = if metadata.is_file() {
        input_path.to_path_buf()
    } else {
        profile_dir.join("places.sqlite")
    };
    if !places_path.is_file() {
        bail!(
            "Firefox places.sqlite database was not found: {}",
            places_path.display()
        );
    }
    Ok(FirefoxProfilePaths {
        downloads_path: profile_dir.join("downloads.sqlite"),
        formhistory_path: profile_dir.join("formhistory.sqlite"),
        cookies_path: profile_dir.join("cookies.sqlite"),
        logins_path: profile_dir.join("logins.json"),
        profile_dir,
        places_path,
    })
}

pub fn safari_profile_paths(input_path: &Path) -> Result<SafariProfilePaths> {
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("reading Safari history path {}", input_path.display()))?;
    let profile_dir = if metadata.is_dir() {
        input_path.to_path_buf()
    } else if metadata.is_file() {
        input_path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "Safari History.db file has no parent: {}",
                    input_path.display()
                )
            })?
    } else {
        bail!(
            "Safari history path is not a file or directory: {}",
            input_path.display()
        );
    };
    let history_path = if metadata.is_file() {
        input_path.to_path_buf()
    } else {
        profile_dir.join("History.db")
    };
    if !history_path.is_file() {
        bail!(
            "Safari History.db database was not found: {}",
            history_path.display()
        );
    }
    Ok(SafariProfilePaths {
        profile_dir,
        history_path,
    })
}

pub fn detect_browser_family(input_path: &Path) -> Result<BrowserFamily> {
    let metadata = fs::metadata(input_path)
        .with_context(|| format!("reading browser history path {}", input_path.display()))?;
    if metadata.is_dir() {
        let candidates = [
            (BrowserFamily::Chromium, input_path.join("History")),
            (BrowserFamily::Firefox, input_path.join("places.sqlite")),
            (BrowserFamily::Safari, input_path.join("History.db")),
        ];
        let matches = candidates
            .iter()
            .filter(|(_, path)| path.is_file())
            .map(|(family, path)| (*family, path.clone()))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [(family, _)] => Ok(*family),
            [] => bail!(
                "no supported browser history database was found in {}; point at a Chromium History, Firefox places.sqlite, or Safari History.db file",
                input_path.display()
            ),
            _ => {
                let names = matches
                    .iter()
                    .map(|(_, path)| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "ambiguous browser profile directory {}; multiple supported history databases were found ({names}); point at the specific DB file",
                    input_path.display()
                )
            }
        };
    }
    if !metadata.is_file() {
        bail!(
            "browser history/profile path is not a file or directory: {}",
            input_path.display()
        );
    }
    let file_name = input_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match file_name.as_str() {
        "history" => Ok(BrowserFamily::Chromium),
        "places.sqlite" => Ok(BrowserFamily::Firefox),
        "history.db" => Ok(BrowserFamily::Safari),
        _ => sniff_browser_family_from_sqlite(input_path),
    }
}

pub fn sniff_browser_family_from_sqlite(input_path: &Path) -> Result<BrowserFamily> {
    match detect_browser_database(input_path)? {
        Some(family) => Ok(family),
        None => bail!(
            "could not identify browser history database schema in {}; expected Firefox moz_places, Safari history_items/history_visits, or Chromium urls/visits tables",
            input_path.display()
        ),
    }
}

pub fn temp_history_copy_path(history_path: &Path, nonce: u64) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let source_name = history_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("History");
    std::env::temp_dir().join(format!(
        "kdft-history-{}-{stamp}-{nonce}-{}.sqlite",
        std::process::id(),
        sanitize_logical_segment(source_name)
    ))
}

pub fn default_browser_history_display_name(family: BrowserFamily, profile_dir: &Path) -> String {
    let profile = profile_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("Profile");
    format!("{} History - {profile}", family.label())
}

pub fn chrome_time_to_rfc3339(chrome_time: i64) -> Option<String> {
    const CHROME_TO_UNIX_EPOCH_MICROS: i64 = 11_644_473_600_i64 * 1_000_000;
    let unix_micros = chrome_time.checked_sub(CHROME_TO_UNIX_EPOCH_MICROS)?;
    let seconds = unix_micros.div_euclid(1_000_000);
    let nanos = unix_micros.rem_euclid(1_000_000) * 1_000;
    DateTime::<Utc>::from_timestamp(seconds, nanos as u32).map(|value| value.to_rfc3339())
}

pub fn nonzero_optional_i64(value: Option<i64>) -> Option<i64> {
    value.filter(|value| *value != 0)
}

pub fn optional_chrome_time_to_rfc3339(value: Option<i64>) -> Option<String> {
    nonzero_optional_i64(value).and_then(chrome_time_to_rfc3339)
}

pub fn chromium_download_time_is_unix_seconds(value: i64) -> bool {
    value != 0 && value.unsigned_abs() < 10_000_000_000
}

pub fn chromium_download_time_to_rfc3339(value: Option<i64>) -> Option<String> {
    let value = nonzero_optional_i64(value)?;
    if chromium_download_time_is_unix_seconds(value) {
        unix_seconds_to_rfc3339(value)
    } else {
        chrome_time_to_rfc3339(value)
    }
}

pub fn chromium_download_duration_microseconds(
    start_time: Option<i64>,
    end_time: Option<i64>,
) -> Option<i64> {
    let start = nonzero_optional_i64(start_time)?;
    let end = nonzero_optional_i64(end_time)?;
    let start_is_seconds = chromium_download_time_is_unix_seconds(start);
    if start_is_seconds != chromium_download_time_is_unix_seconds(end) {
        return None;
    }
    let duration = end.checked_sub(start)?;
    if duration < 0 {
        return None;
    }
    if start_is_seconds {
        duration.checked_mul(1_000_000)
    } else {
        Some(duration)
    }
}

pub fn duration_human_from_microseconds(microseconds: i64) -> String {
    let negative = microseconds < 0;
    let absolute = i128::from(microseconds).abs();
    let total_tenths = (absolute + 50_000) / 100_000;
    let hours = total_tenths / 36_000;
    let minutes = (total_tenths % 36_000) / 600;
    let seconds_tenths = total_tenths % 600;
    let seconds = seconds_tenths / 10;
    let tenths = seconds_tenths % 10;
    let sign = if negative { "-" } else { "" };
    if hours > 0 {
        format!("{sign}{hours}h {minutes}m {seconds}.{tenths}s")
    } else if minutes > 0 {
        format!("{sign}{minutes}m {seconds}.{tenths}s")
    } else {
        format!("{sign}{seconds}.{tenths}s")
    }
}

pub fn unix_micros_to_rfc3339(unix_micros: i64) -> Option<String> {
    let seconds = unix_micros.div_euclid(1_000_000);
    let nanos = unix_micros.rem_euclid(1_000_000) * 1_000;
    DateTime::<Utc>::from_timestamp(seconds, nanos as u32).map(|value| value.to_rfc3339())
}

pub fn unix_millis_to_rfc3339(unix_millis: i64) -> Option<String> {
    let seconds = unix_millis.div_euclid(1_000);
    let nanos = unix_millis.rem_euclid(1_000) * 1_000_000;
    DateTime::<Utc>::from_timestamp(seconds, nanos as u32).map(|value| value.to_rfc3339())
}

pub fn unix_seconds_to_rfc3339(unix_seconds: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(unix_seconds, 0).map(|value| value.to_rfc3339())
}

pub fn safari_time_to_rfc3339(safari_time: f64) -> Option<String> {
    const SAFARI_TO_UNIX_EPOCH_SECONDS: f64 = 978_307_200.0;
    if !safari_time.is_finite() {
        return None;
    }
    let unix_seconds = safari_time + SAFARI_TO_UNIX_EPOCH_SECONDS;
    if unix_seconds < i64::MIN as f64 || unix_seconds > i64::MAX as f64 {
        return None;
    }
    let mut seconds = unix_seconds.floor() as i64;
    let mut nanos = ((unix_seconds - seconds as f64) * 1_000_000_000.0).round() as i64;
    if nanos >= 1_000_000_000 {
        seconds = seconds.checked_add(1)?;
        nanos -= 1_000_000_000;
    }
    if nanos < 0 {
        seconds = seconds.checked_sub(1)?;
        nanos += 1_000_000_000;
    }
    DateTime::<Utc>::from_timestamp(seconds, nanos as u32).map(|value| value.to_rfc3339())
}

pub fn chromium_bookmark_root_label(root_name: &str) -> &'static str {
    match root_name {
        "bookmark_bar" => "Bookmarks Bar",
        "other" => "Other Bookmarks",
        "synced" => "Mobile Bookmarks",
        _ => "Bookmarks",
    }
}

pub fn json_path<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in path {
        current = current.get(*part)?;
    }
    Some(current)
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

pub fn chromium_visit_source_label(source: Option<i64>) -> String {
    match source {
        None => "local".to_string(),
        Some(0) => "synced".to_string(),
        Some(1) => "browsed(local)".to_string(),
        Some(2) => "extension".to_string(),
        Some(3) => "firefox_imported".to_string(),
        Some(4) => "ie_imported".to_string(),
        Some(5) => "safari_imported".to_string(),
        Some(value) => format!("unknown ({value})"),
    }
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

pub fn format_i64_grouped(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if value < 0 {
        grouped.push('-');
    }
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(character);
    }
    grouped
}

pub fn chromium_download_outcome_summary(
    row: &ChromiumDownloadRow,
    state_label: Option<&str>,
    interrupt_reason_label: Option<&str>,
    duration_human: Option<&str>,
    percent_complete: Option<f64>,
) -> Option<String> {
    if state_label.is_none()
        && row.received_bytes.is_none()
        && row.total_bytes.is_none()
        && duration_human.is_none()
        && interrupt_reason_label.is_none()
    {
        return None;
    }
    let mut summary = state_label.unwrap_or("download").to_string();
    match row.state {
        Some(4) => {
            match (row.received_bytes, row.total_bytes) {
                (Some(received), Some(total)) => {
                    summary.push_str(&format!(
                        " at {} of {} bytes",
                        format_i64_grouped(received),
                        format_i64_grouped(total)
                    ));
                    if let Some(percent) = percent_complete {
                        summary.push_str(&format!(" ({percent:.0}%)"));
                    }
                }
                (Some(received), None) => summary.push_str(&format!(
                    " after receiving {} bytes",
                    format_i64_grouped(received)
                )),
                (None, Some(total)) => summary.push_str(&format!(
                    " with {} bytes expected",
                    format_i64_grouped(total)
                )),
                (None, None) => {}
            }
            if let Some(duration) = duration_human {
                summary.push_str(&format!(" after {duration}"));
            }
            if let Some(reason) = interrupt_reason_label.filter(|value| *value != "none") {
                summary.push_str(&format!(" - {reason}"));
            }
        }
        Some(1) => {
            if let Some(bytes) = row.received_bytes.or(row.total_bytes) {
                summary.push_str(&format!(" - {} bytes", format_i64_grouped(bytes)));
            }
            if let Some(duration) = duration_human {
                summary.push_str(&format!(" in {duration}"));
            }
        }
        _ => {
            if let (Some(received), Some(total)) = (row.received_bytes, row.total_bytes) {
                summary.push_str(&format!(
                    " - {} of {} bytes",
                    format_i64_grouped(received),
                    format_i64_grouped(total)
                ));
            }
            if let Some(duration) = duration_human {
                summary.push_str(&format!(" after {duration}"));
            }
            if let Some(reason) = interrupt_reason_label.filter(|value| *value != "none") {
                summary.push_str(&format!(" - {reason}"));
            }
        }
    }
    Some(summary)
}

