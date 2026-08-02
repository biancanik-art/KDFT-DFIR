//! Structured Windows Registry artifact derivation from indexed hive sources.
//!
//! This pass is deliberately source-driven. It recognizes exact Registry
//! schemas (Amcache, UserAssist, BagMRU, and Run/RunOnce) and never promotes a
//! loose filename keyword into an execution, identity, or credential fact.

use anyhow::{bail, Context, Result};
use rusqlite::{params, TransactionBehavior};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    active_case_id, add_entry_category, audit_actor, collect_registry_hive_import,
    ensure_evidence_source, open_existing_case, recover_filesystem_entry_in_session,
    sanitize_logical_segment, upsert_filesystem_entry, EvidenceReadSession, RecoverEntryOptions,
    RegistryImportData, RegistryImportEntry,
};

const PARSER_NAME: &str = "kdft-windows-registry-artifacts-v1";
const ERROR_SAMPLE_LIMIT: usize = 32;
const TEMPORARY_DIRECTORY_ATTEMPTS: usize = 1_024;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Default, Serialize)]
pub struct WindowsRegistryArtifactParseResult {
    pub evidence_id: i64,
    pub hives_found: usize,
    pub hives_parsed: usize,
    pub amcache_records_indexed: usize,
    pub userassist_records_indexed: usize,
    pub shellbag_records_indexed: usize,
    pub startup_records_indexed: usize,
    pub shimcache_sources_seen: usize,
    pub shimcache_records_indexed: usize,
    pub srum_sources_seen: usize,
    pub srum_records_indexed: usize,
    pub parse_error_count: usize,
    pub parse_errors: Vec<String>,
    pub parse_errors_omitted: usize,
    pub limitations: Vec<String>,
    pub status: String,
}

#[derive(Debug)]
struct HiveCandidate {
    entry_id: i64,
    source_job_id: i64,
    logical_path: String,
    exact_path: String,
    name: String,
}

#[derive(Debug)]
struct DerivedRecord {
    logical_path: String,
    display_name: String,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
struct ValueObservation {
    key_path: String,
    key_last_write_utc: Option<String>,
    name: String,
    value_type: String,
    rendered: String,
    raw: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct DerivedCounts {
    amcache: usize,
    userassist: usize,
    shellbags: usize,
    startup: usize,
    shimcache_sources: usize,
}

pub fn parse_windows_registry_artifacts(
    case_path: &Path,
    evidence_id: i64,
) -> Result<WindowsRegistryArtifactParseResult> {
    let candidates = registry_candidates(case_path, evidence_id)?;
    let srum_sources_seen = count_srum_sources(case_path, evidence_id)?;
    super::progress::progress_set_unit("Windows Registry hives");
    super::progress::progress_set_total(Some(candidates.len() as u64));
    let mut result = WindowsRegistryArtifactParseResult {
        evidence_id,
        hives_found: candidates.len(),
        srum_sources_seen,
        limitations: vec![
            "Shimcache/AppCompatCache binary layouts are retained as source evidence but are not decoded by this version.".to_string(),
            "SRUDB.dat is an ESE database; this build identifies the source but does not claim decoded SRUM rows without a validated ESE decoder.".to_string(),
            "ShellBag item names use bounded shell-item string recovery when a complete typed-shell-item decoder is unavailable; the raw Registry value and decode method remain explicit.".to_string(),
        ],
        status: "completed".to_string(),
        ..WindowsRegistryArtifactParseResult::default()
    };
    let mut read_session = EvidenceReadSession::open(case_path)?;

    for candidate in &candidates {
        super::progress::progress_current(candidate.exact_path.clone());
        match parse_one_hive(case_path, &mut read_session, evidence_id, candidate) {
            Ok(counts) => {
                result.hives_parsed = result.hives_parsed.saturating_add(1);
                result.amcache_records_indexed = result
                    .amcache_records_indexed
                    .saturating_add(counts.amcache);
                result.userassist_records_indexed = result
                    .userassist_records_indexed
                    .saturating_add(counts.userassist);
                result.shellbag_records_indexed = result
                    .shellbag_records_indexed
                    .saturating_add(counts.shellbags);
                result.startup_records_indexed = result
                    .startup_records_indexed
                    .saturating_add(counts.startup);
                result.shimcache_sources_seen = result
                    .shimcache_sources_seen
                    .saturating_add(counts.shimcache_sources);
            }
            Err(error) => {
                result.parse_error_count = result.parse_error_count.saturating_add(1);
                if result.parse_errors.len() < ERROR_SAMPLE_LIMIT {
                    result
                        .parse_errors
                        .push(format!("{}: {error:#}", candidate.exact_path));
                } else {
                    result.parse_errors_omitted = result.parse_errors_omitted.saturating_add(1);
                }
                super::progress::progress_error(Some(candidate.exact_path.clone()));
                super::progress::progress_skip(Some(candidate.exact_path.clone()));
            }
        }
        super::progress::progress_advance(candidate.exact_path.clone());
    }
    result.status = if result.parse_error_count == 0 {
        "completed".to_string()
    } else {
        super::progress::progress_truncated(format!(
            "{} Windows Registry hive source(s) could not be parsed",
            result.parse_error_count
        ));
        "truncated".to_string()
    };
    persist_pass_audit(case_path, &result)?;
    Ok(result)
}

fn registry_candidates(case_path: &Path, evidence_id: i64) -> Result<Vec<HiveCandidate>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let mut statement = conn.prepare(
        "SELECT id, discovered_by_job_id, logical_path, name,
                COALESCE(
                    NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
                    NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
                    NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
                    NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
                    NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
                    logical_path
                )
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND entry_kind = 'file' AND is_deleted = 0
           AND lower(name) IN ('amcache.hve', 'ntuser.dat', 'usrclass.dat', 'system', 'software')
           AND COALESCE(json_extract(metadata_json, '$.windows_registry_derived'), 0) <> 1
         ORDER BY id",
    )?;
    let rows = statement.query_map(params![case_id, evidence_id], |row| {
        Ok(HiveCandidate {
            entry_id: row.get(0)?,
            source_job_id: row.get(1)?,
            logical_path: row.get(2)?,
            name: row.get(3)?,
            exact_path: row.get(4)?,
        })
    })?;
    let mut candidates = Vec::new();
    for row in rows {
        let candidate = row?;
        if is_supported_hive_path(&candidate.name, &candidate.exact_path) {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn is_supported_hive_path(name: &str, path: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let path = normalize_windows_path_for_matching(path);
    if is_winsxs_path(&path) {
        return false;
    }
    match name.as_str() {
        "amcache.hve" => path.contains("/windows/appcompat/programs/"),
        "system" | "software" => path.contains("/windows/system32/config/"),
        "ntuser.dat" | "usrclass.dat" => {
            path.contains("/users/") || path.contains("/documents and settings/")
        }
        _ => false,
    }
}

fn normalize_windows_path_for_matching(path: &str) -> String {
    let mut normalized = path.replace('\\', "/").to_ascii_lowercase();
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    normalized
}

fn is_srum_source_path(path: &str) -> bool {
    let path = normalize_windows_path_for_matching(path);
    !is_winsxs_path(&path) && path.contains("/windows/system32/sru/")
}

fn is_winsxs_path(path: &str) -> bool {
    normalize_windows_path_for_matching(path).contains("/windows/winsxs/")
}

fn count_srum_sources(case_path: &Path, evidence_id: i64) -> Result<usize> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let mut statement = conn.prepare(
        "SELECT COALESCE(
               NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
               NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
               logical_path
           )
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2 AND entry_kind = 'file'
           AND is_deleted = 0 AND lower(name) = 'srudb.dat'",
    )?;
    let rows = statement.query_map(params![case_id, evidence_id], |row| row.get::<_, String>(0))?;
    let mut count = 0_usize;
    for path in rows {
        if is_srum_source_path(&path?) {
            count = count
                .checked_add(1)
                .context("SRUM source count is too large")?;
        }
    }
    Ok(count)
}

fn parse_one_hive(
    case_path: &Path,
    read_session: &mut EvidenceReadSession,
    evidence_id: i64,
    candidate: &HiveCandidate,
) -> Result<DerivedCounts> {
    let (directory, staging_path) =
        reserve_staging_destination(candidate.entry_id, &candidate.name)?;
    let parsed = (|| -> Result<(Vec<DerivedRecord>, DerivedCounts)> {
        recover_filesystem_entry_in_session(
            read_session,
            RecoverEntryOptions {
                entry_id: candidate.entry_id,
                output_path: staging_path.clone(),
            },
        )
        .with_context(|| format!("recovering Registry hive {}", candidate.exact_path))?;
        let import = collect_registry_hive_import(&staging_path, &candidate.name, usize::MAX)
            .with_context(|| format!("parsing Registry hive {}", candidate.exact_path))?;
        Ok(derive_hive_records(candidate, &import))
    })();
    let file_cleanup = if staging_path.exists() {
        fs::remove_file(&staging_path)
    } else {
        Ok(())
    };
    let directory_cleanup = fs::remove_dir(&directory);
    let (records, counts) = parsed?;
    file_cleanup.with_context(|| format!("removing staged hive {}", staging_path.display()))?;
    directory_cleanup
        .with_context(|| format!("removing staged hive directory {}", directory.display()))?;
    replace_source_records(case_path, evidence_id, candidate, &records)?;
    Ok(counts)
}

fn reserve_staging_destination(entry_id: i64, name: &str) -> Result<(PathBuf, PathBuf)> {
    for _ in 0..TEMPORARY_DIRECTORY_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "kdft-windows-registry-{}-{entry_id}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&directory) {
            Ok(()) => {
                return Ok((
                    directory.clone(),
                    directory.join(sanitize_logical_segment(name)),
                ))
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("reserving Registry staging directory"),
        }
    }
    bail!("could not reserve a unique Registry staging directory")
}

fn derive_hive_records(
    candidate: &HiveCandidate,
    import: &RegistryImportData,
) -> (Vec<DerivedRecord>, DerivedCounts) {
    let observations = import
        .entries
        .iter()
        .filter_map(value_observation)
        .collect::<Vec<_>>();
    let hive = candidate.name.to_ascii_lowercase();
    let mut records = Vec::new();
    let mut counts = DerivedCounts::default();
    if hive == "amcache.hve" {
        let derived = derive_amcache(candidate, &observations);
        counts.amcache = derived.len();
        records.extend(derived);
    }
    if hive == "ntuser.dat" || hive == "usrclass.dat" {
        let derived = derive_userassist(candidate, &observations);
        counts.userassist = derived.len();
        records.extend(derived);
        let derived = derive_shellbags(candidate, &observations);
        counts.shellbags = derived.len();
        records.extend(derived);
    }
    if hive == "ntuser.dat" || hive == "software" {
        let derived = derive_startup_records(candidate, &observations);
        counts.startup = derived.len();
        records.extend(derived);
    }
    if hive == "system"
        && observations.iter().any(|value| {
            value
                .key_path
                .replace('\\', "/")
                .to_ascii_lowercase()
                .contains("/control/session manager/appcompatcache")
        })
    {
        counts.shimcache_sources = 1;
    }
    (records, counts)
}

fn value_observation(entry: &RegistryImportEntry) -> Option<ValueObservation> {
    if entry.metadata["artifact_kind"] != "registry_value" {
        return None;
    }
    Some(ValueObservation {
        key_path: entry.metadata["registry_key_path"].as_str()?.to_string(),
        key_last_write_utc: entry.metadata["registry_key_last_write_utc"]
            .as_str()
            .map(str::to_string),
        name: entry.metadata["registry_value_name"].as_str()?.to_string(),
        value_type: entry.metadata["registry_value_type"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        rendered: entry.metadata["registry_value_data"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        raw: entry.raw_value_bytes.clone(),
    })
}

fn derive_amcache(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    let mut keys: BTreeMap<String, Vec<&ValueObservation>> = BTreeMap::new();
    for observation in observations {
        let lower = observation.key_path.replace('\\', "/").to_ascii_lowercase();
        if lower.contains("/root/inventoryapplicationfile/")
            || lower.contains("/root/inventoryapplication/")
            || lower.contains("/root/file/")
            || lower.contains("/root/programs/")
        {
            keys.entry(observation.key_path.clone())
                .or_default()
                .push(observation);
        }
    }
    keys.into_iter()
        .enumerate()
        .map(|(ordinal, (key_path, values))| {
            let fields = values
                .iter()
                .map(|value| (value.name.clone(), value.rendered.clone()))
                .collect::<BTreeMap<_, _>>();
            let path = field_ci(
                &fields,
                &["LowerCaseLongPath", "LongPathHash", "Path", "15"],
            );
            let program_name = field_ci(&fields, &["Name", "ProductName", "0"]);
            let display_name = path.clone().or(program_name.clone()).unwrap_or_else(|| {
                key_path
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("Amcache record")
                    .to_string()
            });
            let artifact_time = values
                .first()
                .and_then(|value| value.key_last_write_utc.clone());
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/amcache/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&display_name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_amcache_record",
                "parser": PARSER_NAME,
                "amcache_key_path": key_path,
                "amcache_path": path,
                "amcache_name": program_name,
                "amcache_publisher": field_ci(&fields, &["Publisher"]),
                "amcache_version": field_ci(&fields, &["Version", "ProductVersion"]),
                "amcache_product_name": field_ci(&fields, &["ProductName"]),
                "amcache_sha1": field_ci(&fields, &["SHA1"]),
                "amcache_link_date": field_ci(&fields, &["LinkDate"]),
                "amcache_fields": fields,
                "artifact_time_utc": artifact_time,
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &display_name, "record");
            DerivedRecord {
                logical_path,
                display_name,
                metadata,
            }
        })
        .collect()
}

fn derive_userassist(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    observations
        .iter()
        .filter(|value| {
            let key = value.key_path.replace('\\', "/").to_ascii_lowercase();
            key.contains("/software/microsoft/windows/currentversion/explorer/userassist/")
                && key.ends_with("/count")
                && !value.name.eq_ignore_ascii_case("(default)")
        })
        .enumerate()
        .map(|(ordinal, value)| {
            let decoded_name = rot13(&value.name);
            let parsed = value.raw.as_deref().map(parse_userassist_binary).unwrap_or_default();
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/userassist/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&decoded_name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_userassist_record",
                "parser": PARSER_NAME,
                "userassist_encoded_name": value.name,
                "userassist_decoded_name": decoded_name,
                "userassist_registry_key": value.key_path,
                "userassist_value_type": value.value_type,
                "userassist_raw_preview": value.rendered,
                "userassist_run_count": parsed.run_count,
                "userassist_focus_count": parsed.focus_count,
                "userassist_focus_time_ms": parsed.focus_time_ms,
                "userassist_last_execution_utc": parsed.last_execution_utc,
                "userassist_binary_layout": parsed.layout,
                "artifact_time_utc": parsed.last_execution_utc.or_else(|| value.key_last_write_utc.clone()),
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &decoded_name, "record");
            DerivedRecord { logical_path, display_name: decoded_name, metadata }
        })
        .collect()
}

#[derive(Debug, Default)]
struct UserAssistBinary {
    run_count: Option<u32>,
    focus_count: Option<u32>,
    focus_time_ms: Option<u32>,
    last_execution_utc: Option<String>,
    layout: &'static str,
}

fn parse_userassist_binary(bytes: &[u8]) -> UserAssistBinary {
    if bytes.len() >= 72 {
        UserAssistBinary {
            run_count: le_u32(bytes, 4),
            focus_count: le_u32(bytes, 8),
            focus_time_ms: le_u32(bytes, 12),
            last_execution_utc: le_u64(bytes, 60).and_then(filetime_to_rfc3339),
            layout: "Windows 7+ 72-byte layout",
        }
    } else if bytes.len() >= 16 {
        UserAssistBinary {
            run_count: le_u32(bytes, 4),
            last_execution_utc: le_u64(bytes, 8).and_then(filetime_to_rfc3339),
            layout: "legacy 16-byte layout",
            ..UserAssistBinary::default()
        }
    } else {
        UserAssistBinary {
            layout: "unrecognized or unavailable",
            ..UserAssistBinary::default()
        }
    }
}

fn derive_shellbags(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    let mut by_key: BTreeMap<String, Vec<&ValueObservation>> = BTreeMap::new();
    for value in observations {
        let key = value.key_path.replace('\\', "/").to_ascii_lowercase();
        if key.contains("/shell/bagmru") {
            by_key
                .entry(value.key_path.clone())
                .or_default()
                .push(value);
        }
    }
    let mut decoded_nodes = HashMap::<String, String>::new();
    let mut items = Vec::new();
    for (key_path, values) in &by_key {
        for value in values {
            if value.name.parse::<u32>().is_ok() {
                let decoded = value
                    .raw
                    .as_deref()
                    .and_then(extract_shell_item_name)
                    .unwrap_or_else(|| format!("[shell item {}]", value.name));
                decoded_nodes.insert(
                    format!("{}\\{}", key_path.trim_end_matches('\\'), value.name)
                        .to_ascii_lowercase(),
                    decoded,
                );
            }
        }
    }
    for (key_path, values) in by_key {
        let mru_order = values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case("MRUListEx"))
            .and_then(|value| value.raw.as_deref())
            .map(parse_mru_list_ex)
            .unwrap_or_default();
        for value in values {
            let Ok(node_number) = value.name.parse::<u32>() else {
                continue;
            };
            let item_name = value
                .raw
                .as_deref()
                .and_then(extract_shell_item_name)
                .unwrap_or_else(|| format!("[shell item {node_number}]"));
            let parent = shellbag_parent_path(&key_path, &decoded_nodes);
            let resolved_path = if parent.is_empty() {
                item_name.clone()
            } else {
                format!("{parent}\\{item_name}")
            };
            items.push((
                key_path.clone(),
                value,
                item_name,
                resolved_path,
                mru_order.iter().position(|item| *item == node_number),
            ));
        }
    }
    items
        .into_iter()
        .enumerate()
        .map(|(ordinal, (key_path, value, item_name, resolved_path, mru_position))| {
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/shellbags/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&item_name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_shellbag_record",
                "parser": PARSER_NAME,
                "shellbag_registry_key": key_path,
                "shellbag_node_number": value.name,
                "shellbag_item_name": item_name,
                "shellbag_resolved_path": resolved_path,
                "shellbag_mru_position": mru_position,
                "shellbag_key_last_write_utc": value.key_last_write_utc,
                "artifact_time_utc": value.key_last_write_utc,
                "shellbag_raw_preview": value.rendered,
                "shellbag_name_decode_method": "bounded UTF-16LE/ASCII shell-item string recovery; validate against raw value",
                "shellbag_decode_confidence": "medium",
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &resolved_path, "record");
            DerivedRecord { logical_path, display_name: resolved_path, metadata }
        })
        .collect()
}

fn derive_startup_records(
    candidate: &HiveCandidate,
    observations: &[ValueObservation],
) -> Vec<DerivedRecord> {
    observations
        .iter()
        .filter(|value| is_startup_registry_key(&value.key_path))
        .filter(|value| !value.name.eq_ignore_ascii_case("(default)"))
        .enumerate()
        .map(|(ordinal, value)| {
            let display_name = format!("{}: {}", value.name, value.rendered);
            let logical_path = format!(
                "/Windows Artifacts/Registry/{}/startup/{ordinal:020}-{}.record",
                candidate.entry_id,
                sanitize_logical_segment(&value.name)
            );
            let mut metadata = serde_json::json!({
                "artifact_kind": "windows_startup_record",
                "parser": PARSER_NAME,
                "startup_value_name": value.name,
                "startup_command": value.rendered,
                "startup_registry_key": value.key_path,
                "startup_scope": if candidate.name.eq_ignore_ascii_case("ntuser.dat") { "user" } else { "machine" },
                "startup_key_last_write_utc": value.key_last_write_utc,
                "artifact_time_utc": value.key_last_write_utc,
                "structured_source": true,
            });
            source_metadata(&mut metadata, candidate);
            add_entry_category(&mut metadata, &logical_path, &display_name, "record");
            DerivedRecord { logical_path, display_name, metadata }
        })
        .collect()
}

fn is_startup_registry_key(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let path = format!("/{}", normalized.trim_start_matches('/'));
    path.ends_with("/software/microsoft/windows/currentversion/run")
        || path.ends_with("/software/microsoft/windows/currentversion/runonce")
        || path.ends_with("/software/microsoft/windows/currentversion/policies/explorer/run")
        || path.ends_with("/software/wow6432node/microsoft/windows/currentversion/run")
        || path.ends_with("/software/wow6432node/microsoft/windows/currentversion/runonce")
}

fn source_metadata(metadata: &mut serde_json::Value, candidate: &HiveCandidate) {
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "windows_registry_derived".to_string(),
            serde_json::json!(true),
        );
        object.insert(
            "windows_registry_source_entry_id".to_string(),
            serde_json::json!(candidate.entry_id),
        );
        object.insert(
            "source_entry_id".to_string(),
            serde_json::json!(candidate.entry_id),
        );
        object.insert(
            "source_artifact_path".to_string(),
            serde_json::json!(candidate.exact_path),
        );
        object.insert(
            "source_logical_path".to_string(),
            serde_json::json!(candidate.logical_path),
        );
        object.insert(
            "source_hive_name".to_string(),
            serde_json::json!(candidate.name),
        );
    }
}

fn replace_source_records(
    case_path: &Path,
    evidence_id: i64,
    candidate: &HiveCandidate,
    records: &[DerivedRecord],
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "DELETE FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND json_extract(metadata_json, '$.windows_registry_derived') = 1
           AND json_extract(metadata_json, '$.windows_registry_source_entry_id') = ?3",
        params![case_id, evidence_id, candidate.entry_id],
    )?;
    for record in records {
        upsert_filesystem_entry(
            &tx,
            case_id,
            evidence_id,
            &record.logical_path,
            &record.display_name,
            "record",
            None,
            &record.metadata.to_string(),
            candidate.source_job_id,
        )?;
        let derived_entry_id: i64 = tx.query_row(
            "SELECT id FROM filesystem_entries WHERE evidence_id = ?1 AND logical_path = ?2",
            params![evidence_id, record.logical_path],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO filesystem_entry_text_segments(
                 entry_id, parser_name, segment_index, part_name, content, content_encoding
             ) VALUES (?1, ?2, 0, 'record', ?3, 'utf-8')",
            params![
                derived_entry_id,
                PARSER_NAME,
                record.metadata.to_string().as_bytes()
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn persist_pass_audit(case_path: &Path, result: &WindowsRegistryArtifactParseResult) -> Result<()> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let actor = audit_actor(&conn, case_id)?;
    conn.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.windows_registry_artifact_parse', ?2, 'evidence', ?3, ?4)",
        params![
            case_id,
            actor,
            result.evidence_id,
            serde_json::to_string(result)?
        ],
    )?;
    Ok(())
}

fn field_ci(fields: &BTreeMap<String, String>, wanted: &[&str]) -> Option<String> {
    wanted.iter().find_map(|wanted| {
        fields
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.clone())
            .filter(|value| !value.trim().is_empty())
    })
}

fn rot13(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            'a'..='m' | 'A'..='M' => char::from_u32(character as u32 + 13).unwrap_or(character),
            'n'..='z' | 'N'..='Z' => char::from_u32(character as u32 - 13).unwrap_or(character),
            _ => character,
        })
        .collect()
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    i64::try_from(filetime)
        .ok()
        .and_then(super::pst_filetime_to_rfc3339)
}

fn parse_mru_list_ex(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .take_while(|value| *value != u32::MAX)
        .collect()
}

fn extract_shell_item_name(bytes: &[u8]) -> Option<String> {
    let mut candidates = Vec::<String>::new();
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        let start = offset;
        let mut units = Vec::new();
        while offset + 1 < bytes.len() {
            let unit = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            if unit == 0 {
                break;
            }
            if unit < 0x20 || (0x7f..0xa0).contains(&unit) {
                units.clear();
                break;
            }
            units.push(unit);
            offset += 2;
        }
        if units.len() >= 3 {
            if let Ok(value) = String::from_utf16(&units) {
                candidates.push(value);
            }
        }
        offset = start.saturating_add(2);
    }
    let mut ascii = String::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            ascii.push(*byte as char);
        } else {
            if ascii.len() >= 4 {
                candidates.push(std::mem::take(&mut ascii));
            }
            ascii.clear();
        }
    }
    if ascii.len() >= 4 {
        candidates.push(ascii);
    }
    candidates
        .into_iter()
        .map(|value| value.trim_matches('\0').trim().to_string())
        .filter(|value| {
            value.len() >= 3 && !value.chars().all(|character| character.is_ascii_hexdigit())
        })
        .max_by_key(|value| value.chars().count())
}

fn shellbag_parent_path(key_path: &str, decoded_nodes: &HashMap<String, String>) -> String {
    let lower = key_path.to_ascii_lowercase();
    let Some(index) = lower.find("bagmru") else {
        return String::new();
    };
    let root_end = index + "bagmru".len();
    let root = &key_path[..root_end];
    let suffix = key_path[root_end..].trim_matches(['\\', '/']);
    if suffix.is_empty() {
        return String::new();
    }
    let mut key = root.to_string();
    let mut names = Vec::new();
    for segment in suffix
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
    {
        key.push('\\');
        key.push_str(segment);
        names.push(
            decoded_nodes
                .get(&key.to_ascii_lowercase())
                .cloned()
                .unwrap_or_else(|| format!("[node {segment}]")),
        );
    }
    names.join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_hive_paths_accept_root_relative_and_windows_separators() {
        assert!(is_supported_hive_path(
            "SYSTEM",
            "Windows/System32/config/SYSTEM"
        ));
        assert!(is_supported_hive_path(
            "SOFTWARE",
            "/Windows/System32/config/SOFTWARE"
        ));
        assert!(is_supported_hive_path(
            "Amcache.hve",
            r"Windows\appcompat\Programs\Amcache.hve"
        ));
        assert!(is_supported_hive_path(
            "NTUSER.DAT",
            r"Users\Alice\NTUSER.DAT"
        ));
        assert!(is_supported_hive_path(
            "UsrClass.dat",
            "/Documents and Settings/Alice/UsrClass.dat"
        ));
        assert!(!is_supported_hive_path(
            "SYSTEM",
            "Windows/System32/Tasks/SYSTEM"
        ));
        assert!(!is_supported_hive_path(
            "SYSTEM",
            "Windows/WinSxS/component/Windows/System32/config/SYSTEM"
        ));
        assert!(!is_supported_hive_path(
            "Amcache.hve",
            r"Windows\WinSxS\component\Windows\appcompat\Programs\Amcache.hve"
        ));
    }

    #[test]
    fn srum_paths_accept_root_relative_and_windows_separators() {
        assert!(is_srum_source_path("Windows/System32/sru/SRUDB.dat"));
        assert!(is_srum_source_path("/Windows/System32/sru/SRUDB.dat"));
        assert!(is_srum_source_path(r"Windows\System32\sru\SRUDB.dat"));
        assert!(!is_srum_source_path("Windows/System32/config/SRUDB.dat"));
        assert!(!is_srum_source_path(
            "Windows/WinSxS/component/Windows/System32/sru/SRUDB.dat"
        ));
    }

    #[test]
    fn userassist_rot13_and_layout_are_decoded() {
        assert_eq!(rot13("Pnyp"), "Calc");
        let mut bytes = vec![0_u8; 72];
        bytes[4..8].copy_from_slice(&7_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1500_u32.to_le_bytes());
        let parsed = parse_userassist_binary(&bytes);
        assert_eq!(parsed.run_count, Some(7));
        assert_eq!(parsed.focus_count, Some(2));
        assert_eq!(parsed.focus_time_ms, Some(1500));
        assert_eq!(parsed.layout, "Windows 7+ 72-byte layout");
    }

    #[test]
    fn mru_list_stops_at_terminator() {
        let bytes = [
            2_u32.to_le_bytes(),
            7_u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
        ]
        .concat();
        assert_eq!(parse_mru_list_ex(&bytes), vec![2, 7]);
    }

    #[test]
    fn startup_key_matching_is_exact() {
        assert!(is_startup_registry_key(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ));
        assert!(!is_startup_registry_key("Software\\Vendor\\StartupStrings"));
    }
}
