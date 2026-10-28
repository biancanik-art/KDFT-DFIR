use crate::protocol::{
    ArtifactCoordinate, ArtifactDetail, ArtifactDetailCompleteness, ArtifactDetailField,
    ArtifactDetailQuery, ArtifactHash, ArtifactMetadataState, ArtifactProvenanceField,
    ArtifactSectionAvailability, ArtifactTimestamp, ArtifactValueAvailability, CoverageState,
};
use anyhow::{anyhow, Context, Result};
use rusqlite::{params, OptionalExtension, Transaction};
use serde_json::{Map, Value};

pub const MAX_ARTIFACT_METADATA_BYTES: usize = 64 * 1_024;
pub const MAX_ARTIFACT_DETAIL_TEXT_CHARS: usize = 2_048;
pub const MAX_ARTIFACT_DETAIL_PATH_CHARS: usize = 4_096;
pub const MAX_ARTIFACT_DETAIL_FIELDS: usize = 96;
pub const MAX_ARTIFACT_DETAIL_TIMESTAMPS: usize = 32;
pub const MAX_ARTIFACT_DETAIL_HASHES: usize = 16;
pub const MAX_ARTIFACT_DETAIL_COORDINATES: usize = 32;
pub const MAX_ARTIFACT_DETAIL_PROVENANCE: usize = 32;
pub const MAX_ARTIFACT_DETAIL_WARNINGS: usize = 16;
pub const MAX_ARTIFACT_DETAIL_DIAGNOSTICS: usize = 8;

#[derive(Debug)]
struct DetailRow {
    case_id: i64,
    entry_id: i64,
    evidence_id: i64,
    parent_id: Option<i64>,
    source_job_id: Option<i64>,
    logical_path: String,
    logical_path_truncated: bool,
    display_name: String,
    display_name_truncated: bool,
    entry_kind: String,
    size_bytes: Option<i64>,
    is_deleted: bool,
    bounded_metadata_json: Option<String>,
    metadata_bytes: Option<i64>,
    source_path: String,
    source_path_truncated: bool,
    evidence_display_name: String,
    evidence_display_name_truncated: bool,
    source_kind: String,
    source_kind_truncated: bool,
    evidence_sha256_hex: Option<String>,
    evidence_hashed_at: Option<String>,
    evidence_sha256_scope: Option<String>,
    evidence_attached_at: Option<String>,
    evidence_indexed_at: Option<String>,
    source_job_type: Option<String>,
    source_job_type_truncated: bool,
    source_job_status: Option<String>,
    source_job_status_truncated: bool,
    source_job_started_at: Option<String>,
    source_job_finished_at: Option<String>,
    source_job_has_error: bool,
    parser_schema_version: Option<String>,
    parser_schema_version_truncated: bool,
    entry_kind_truncated: bool,
}

#[derive(Debug)]
struct ParsedMetadata {
    state: ArtifactMetadataState,
    object: Option<Map<String, Value>>,
}

#[derive(Debug, Default)]
struct HashProjectionState {
    invalid_reason: Option<String>,
}

impl HashProjectionState {
    fn invalid(&mut self, reason: &str) {
        if self.invalid_reason.is_none() {
            self.invalid_reason = Some(bound_text(reason).0);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CoordinateSpec {
    key: &'static str,
    label: &'static str,
    namespace: &'static str,
    basis_key: Option<&'static str>,
    scope_key: Option<&'static str>,
    exact_key: Option<&'static str>,
    legacy_physical_name: bool,
}

/// Reads one exact canonical entry. The caller supplies the generation read in
/// the same transaction and is responsible for rejecting a stale generation
/// before calling this function.
pub(crate) fn read_artifact_detail(
    tx: &Transaction<'_>,
    query: &ArtifactDetailQuery,
    generation: i64,
) -> Result<ArtifactDetail> {
    let row = read_detail_row(tx, query.entry_id)?
        .ok_or_else(|| anyhow!("artifact detail entry {} was not found", query.entry_id))?;
    let mut warnings = BoundedStrings::new(MAX_ARTIFACT_DETAIL_WARNINGS);
    let metadata = parse_metadata(&row, &mut warnings);

    let mut fields = Vec::new();
    let mut fields_omitted = 0;
    let mut timestamps = Vec::new();
    let mut timestamps_omitted = 0;
    let mut hashes = Vec::new();
    let mut hashes_omitted = 0;
    let mut hash_projection = HashProjectionState::default();
    let mut invalid_timestamp_recorded = false;
    let mut coordinates = Vec::new();
    let mut coordinates_omitted = 0;
    let mut provenance = Vec::new();
    let mut provenance_omitted = 0;

    if let Some(object) = metadata.object.as_ref() {
        project_fields(object, &mut fields, &mut fields_omitted);
        project_metadata_timestamps(
            object,
            &mut timestamps,
            &mut timestamps_omitted,
            &mut invalid_timestamp_recorded,
            &mut warnings,
        );
        project_file_hash(
            object,
            &mut hashes,
            &mut hashes_omitted,
            &mut hash_projection,
            &mut warnings,
        );
        project_coordinates(
            object,
            &mut coordinates,
            &mut coordinates_omitted,
            &mut warnings,
        );
        project_metadata_provenance(object, &mut provenance, &mut provenance_omitted);
    }

    project_database_timestamps(&row, &mut timestamps, &mut timestamps_omitted);
    project_evidence_hash(
        &row,
        &mut hashes,
        &mut hashes_omitted,
        &mut hash_projection,
        &mut warnings,
    );
    project_database_provenance(&row, &mut provenance, &mut provenance_omitted);

    let (artifact_kind, artifact_kind_truncated) = metadata
        .object
        .as_ref()
        .and_then(|object| bounded_string_value_with_flag(object.get("artifact_kind")))
        .map_or((None, false), |(value, truncated)| (Some(value), truncated));
    let parser_name = metadata
        .object
        .as_ref()
        .and_then(|object| bounded_string_value(object.get("parser_name")));
    let parser_version = metadata
        .object
        .as_ref()
        .and_then(|object| bounded_string_value(object.get("parser_version")));
    if let Some(parser_name) = parser_name {
        push_provenance(
            &mut provenance,
            &mut provenance_omitted,
            "parser_name",
            "Parser name",
            parser_name,
            "filesystem_entries.metadata_json.parser_name",
        );
    }
    if let Some(parser_version) = parser_version {
        push_provenance(
            &mut provenance,
            &mut provenance_omitted,
            "parser_version",
            "Parser version",
            parser_version,
            "filesystem_entries.metadata_json.parser_version",
        );
    }

    let hashes_status = if let Some(reason) = hash_projection.invalid_reason {
        ArtifactSectionAvailability {
            state: ArtifactValueAvailability::Invalid,
            reason: Some(reason),
            omitted_count: hashes_omitted,
        }
    } else if hashes.is_empty() {
        let reason = metadata
            .object
            .as_ref()
            .and_then(|object| bounded_string_value(object.get("file_sha256_skipped")))
            .map(|reason| format!("Entry hash was skipped: {reason}"))
            .unwrap_or_else(|| {
                "No eligible scoped hash is recorded for this entry or evidence.".to_string()
            });
        ArtifactSectionAvailability {
            state: if metadata.state == ArtifactMetadataState::Oversized {
                ArtifactValueAvailability::WithheldOversized
            } else {
                ArtifactValueAvailability::NotRecorded
            },
            reason: Some(bound_text(&reason).0),
            omitted_count: hashes_omitted,
        }
    } else {
        ArtifactSectionAvailability {
            state: ArtifactValueAvailability::Recorded,
            reason: None,
            omitted_count: hashes_omitted,
        }
    };

    let timestamps_status = if invalid_timestamp_recorded {
        ArtifactSectionAvailability {
            state: ArtifactValueAvailability::Invalid,
            reason: Some(
                "At least one allowlisted timestamp is persisted with a non-string value and was withheld."
                    .to_string(),
            ),
            omitted_count: timestamps_omitted,
        }
    } else if timestamps.is_empty() {
        let (state, reason) = match metadata.state {
            ArtifactMetadataState::Oversized => (
                ArtifactValueAvailability::WithheldOversized,
                "Metadata exceeds the Inspector parsing bound; metadata timestamps were not read.",
            ),
            ArtifactMetadataState::Malformed => (
                ArtifactValueAvailability::Invalid,
                "Metadata is malformed; metadata timestamps were not decoded.",
            ),
            _ => (
                ArtifactValueAvailability::NotRecorded,
                "No allowlisted timestamp is recorded for this entry or its source records.",
            ),
        };
        ArtifactSectionAvailability {
            state,
            reason: Some(reason.to_string()),
            omitted_count: timestamps_omitted,
        }
    } else {
        ArtifactSectionAvailability {
            state: ArtifactValueAvailability::Recorded,
            reason: None,
            omitted_count: timestamps_omitted,
        }
    };

    let coordinates_status = if coordinates
        .iter()
        .any(|coordinate| coordinate.availability == ArtifactValueAvailability::Recorded)
    {
        ArtifactSectionAvailability {
            state: ArtifactValueAvailability::Recorded,
            reason: Some(
                "Coordinates are parser-recorded projections and were not revalidated against raw evidence during Inspector display."
                    .to_string(),
            ),
            omitted_count: coordinates_omitted,
        }
    } else {
        let (state, reason) = match metadata.state {
            ArtifactMetadataState::Oversized => (
                ArtifactValueAvailability::WithheldOversized,
                "Metadata exceeds the Inspector parsing bound; no coordinate was read.",
            ),
            ArtifactMetadataState::Malformed => (
                ArtifactValueAvailability::Invalid,
                "Metadata is malformed; no coordinate could be decoded.",
            ),
            _ => (
                ArtifactValueAvailability::NotRecorded,
                "No allowlisted source coordinate is recorded for this entry; zero was not substituted.",
            ),
        };
        ArtifactSectionAvailability {
            state,
            reason: Some(reason.to_string()),
            omitted_count: coordinates_omitted,
        }
    };

    let completeness = detail_completeness(&row, metadata.state);
    let (warnings, warnings_omitted) = warnings.finish();
    Ok(ArtifactDetail {
        generation,
        case_id: row.case_id,
        entry_id: row.entry_id,
        evidence_id: row.evidence_id,
        parent_id: row.parent_id,
        source_job_id: row.source_job_id,
        source_job_type: row.source_job_type,
        source_job_type_truncated: row.source_job_type_truncated,
        source_job_status: row.source_job_status,
        source_job_status_truncated: row.source_job_status_truncated,
        parser_schema_version: row.parser_schema_version,
        parser_schema_version_truncated: row.parser_schema_version_truncated,
        logical_path: row.logical_path,
        logical_path_truncated: row.logical_path_truncated,
        source_path: row.source_path,
        source_path_truncated: row.source_path_truncated,
        display_name: row.display_name,
        display_name_truncated: row.display_name_truncated,
        evidence_display_name: row.evidence_display_name,
        evidence_display_name_truncated: row.evidence_display_name_truncated,
        source_kind: row.source_kind,
        source_kind_truncated: row.source_kind_truncated,
        entry_kind: row.entry_kind,
        entry_kind_truncated: row.entry_kind_truncated,
        artifact_kind,
        artifact_kind_truncated,
        size_bytes: row.size_bytes,
        is_deleted: row.is_deleted,
        metadata_state: metadata.state,
        fields,
        fields_omitted,
        timestamps,
        timestamps_omitted,
        timestamps_status,
        hashes,
        hashes_status,
        coordinates,
        coordinates_status,
        provenance,
        provenance_omitted,
        completeness,
        warnings,
        warnings_omitted,
    })
}

fn read_detail_row(tx: &Transaction<'_>, entry_id: i64) -> Result<Option<DetailRow>> {
    let path_chars = i64::try_from(MAX_ARTIFACT_DETAIL_PATH_CHARS).unwrap_or(i64::MAX);
    let text_chars = i64::try_from(MAX_ARTIFACT_DETAIL_TEXT_CHARS).unwrap_or(i64::MAX);
    let metadata_bytes = i64::try_from(MAX_ARTIFACT_METADATA_BYTES).unwrap_or(i64::MAX);
    tx.query_row(
        "SELECT fe.case_id AS case_id, fe.id AS entry_id,
                fe.evidence_id AS evidence_id, fe.parent_id AS parent_id,
                fe.discovered_by_job_id AS source_job_id,
                COALESCE(substr(fe.logical_path, 1, ?2), '') AS logical_path_preview,
                COALESCE(length(fe.logical_path) > ?2, 0) AS logical_path_truncated,
                COALESCE(substr(fe.name, 1, ?3), '') AS entry_name_preview,
                COALESCE(length(fe.name) > ?3, 0) AS entry_name_truncated,
                COALESCE(substr(fe.entry_kind, 1, ?3), '') AS entry_kind_preview,
                COALESCE(length(fe.entry_kind) > ?3, 0) AS entry_kind_truncated,
                fe.size_bytes AS size_bytes, fe.is_deleted AS is_deleted,
                CASE
                    WHEN fe.metadata_json IS NULL THEN NULL
                    WHEN length(CAST(fe.metadata_json AS BLOB)) <= ?4
                    THEN substr(fe.metadata_json, 1, ?4)
                    ELSE NULL
                END AS bounded_metadata_json,
                CASE WHEN fe.metadata_json IS NULL THEN NULL
                     ELSE length(CAST(fe.metadata_json AS BLOB)) END AS metadata_bytes,
                COALESCE(substr(es.source_path, 1, ?2), '') AS source_path_preview,
                COALESCE(length(es.source_path) > ?2, 0) AS source_path_truncated,
                COALESCE(substr(es.display_name, 1, ?3), '') AS evidence_name_preview,
                COALESCE(length(es.display_name) > ?3, 0) AS evidence_name_truncated,
                COALESCE(substr(es.source_kind, 1, ?3), '') AS source_kind_preview,
                COALESCE(length(es.source_kind) > ?3, 0) AS source_kind_truncated,
                substr(es.sha256_hex, 1, ?3) AS evidence_sha256_hex,
                substr(es.hashed_at, 1, ?3) AS evidence_hashed_at,
                substr(es.sha256_scope, 1, ?3) AS evidence_sha256_scope,
                substr(es.attached_at, 1, ?3) AS evidence_attached_at,
                substr(es.indexed_at, 1, ?3) AS evidence_indexed_at,
                substr(ej.job_type, 1, ?3) AS source_job_type,
                COALESCE(length(ej.job_type) > ?3, 0) AS source_job_type_truncated,
                substr(ej.status, 1, ?3) AS source_job_status,
                COALESCE(length(ej.status) > ?3, 0) AS source_job_status_truncated,
                substr(ej.started_at, 1, ?3) AS source_job_started_at,
                substr(ej.finished_at, 1, ?3) AS source_job_finished_at,
                CASE WHEN ej.error IS NULL OR ej.error = '' THEN 0 ELSE 1 END AS source_job_has_error,
                substr(ej.parser_schema_version, 1, ?3) AS parser_schema_version,
                COALESCE(length(ej.parser_schema_version) > ?3, 0) AS parser_schema_version_truncated
         FROM filesystem_entries fe
         JOIN evidence_sources es
           ON es.id = fe.evidence_id AND es.case_id = fe.case_id
         LEFT JOIN evidence_jobs ej
           ON ej.id = fe.discovered_by_job_id
          AND ej.case_id = fe.case_id
          AND (ej.evidence_id IS NULL OR ej.evidence_id = fe.evidence_id)
         WHERE fe.id = ?1
         LIMIT 1",
        params![entry_id, path_chars, text_chars, metadata_bytes],
        |row| {
            Ok(DetailRow {
                case_id: row.get("case_id")?,
                entry_id: row.get("entry_id")?,
                evidence_id: row.get("evidence_id")?,
                parent_id: row.get("parent_id")?,
                source_job_id: row.get("source_job_id")?,
                logical_path: row.get("logical_path_preview")?,
                logical_path_truncated: row.get::<_, i64>("logical_path_truncated")? != 0,
                display_name: row.get("entry_name_preview")?,
                display_name_truncated: row.get::<_, i64>("entry_name_truncated")? != 0,
                entry_kind: row.get("entry_kind_preview")?,
                entry_kind_truncated: row.get::<_, i64>("entry_kind_truncated")? != 0,
                size_bytes: row.get("size_bytes")?,
                is_deleted: row.get::<_, i64>("is_deleted")? != 0,
                bounded_metadata_json: row.get("bounded_metadata_json")?,
                metadata_bytes: row.get("metadata_bytes")?,
                source_path: row.get("source_path_preview")?,
                source_path_truncated: row.get::<_, i64>("source_path_truncated")? != 0,
                evidence_display_name: row.get("evidence_name_preview")?,
                evidence_display_name_truncated: row.get::<_, i64>("evidence_name_truncated")? != 0,
                source_kind: row.get("source_kind_preview")?,
                source_kind_truncated: row.get::<_, i64>("source_kind_truncated")? != 0,
                evidence_sha256_hex: row.get("evidence_sha256_hex")?,
                evidence_hashed_at: row.get("evidence_hashed_at")?,
                evidence_sha256_scope: row.get("evidence_sha256_scope")?,
                evidence_attached_at: row.get("evidence_attached_at")?,
                evidence_indexed_at: row.get("evidence_indexed_at")?,
                source_job_type: row.get("source_job_type")?,
                source_job_type_truncated: row.get::<_, i64>("source_job_type_truncated")? != 0,
                source_job_status: row.get("source_job_status")?,
                source_job_status_truncated: row.get::<_, i64>("source_job_status_truncated")? != 0,
                source_job_started_at: row.get("source_job_started_at")?,
                source_job_finished_at: row.get("source_job_finished_at")?,
                source_job_has_error: row.get::<_, i64>("source_job_has_error")? != 0,
                parser_schema_version: row.get("parser_schema_version")?,
                parser_schema_version_truncated: row.get::<_, i64>("parser_schema_version_truncated")? != 0,
            })
        },
    )
    .optional()
    .context("reading exact bounded artifact detail")
}

fn parse_metadata(row: &DetailRow, warnings: &mut BoundedStrings) -> ParsedMetadata {
    let Some(byte_len) = row.metadata_bytes else {
        return ParsedMetadata {
            state: ArtifactMetadataState::Absent,
            object: None,
        };
    };
    if byte_len > i64::try_from(MAX_ARTIFACT_METADATA_BYTES).unwrap_or(i64::MAX) {
        warnings.push(format!(
            "Metadata is {byte_len} bytes and exceeds the {MAX_ARTIFACT_METADATA_BYTES}-byte Inspector bound; it was not parsed."
        ));
        return ParsedMetadata {
            state: ArtifactMetadataState::Oversized,
            object: None,
        };
    }
    let Some(raw) = row.bounded_metadata_json.as_deref() else {
        warnings.push("Metadata length was recorded but the bounded projection is unavailable.");
        return ParsedMetadata {
            state: ArtifactMetadataState::Malformed,
            object: None,
        };
    };
    if raw.trim().is_empty() {
        return ParsedMetadata {
            state: ArtifactMetadataState::Empty,
            object: None,
        };
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(object)) if object.is_empty() => ParsedMetadata {
            state: ArtifactMetadataState::Empty,
            object: Some(object),
        },
        Ok(Value::Object(object)) => ParsedMetadata {
            state: ArtifactMetadataState::Parsed,
            object: Some(object),
        },
        Ok(_) => {
            warnings.push("Metadata is valid JSON but is not an object; no fields were projected.");
            ParsedMetadata {
                state: ArtifactMetadataState::Malformed,
                object: None,
            }
        }
        Err(_) => {
            warnings.push("Metadata JSON is malformed; no fields were projected.");
            ParsedMetadata {
                state: ArtifactMetadataState::Malformed,
                object: None,
            }
        }
    }
}

fn project_fields(
    object: &Map<String, Value>,
    output: &mut Vec<ArtifactDetailField>,
    omitted: &mut usize,
) {
    const FIELD_SPECS: &[(&str, &str)] = &[
        ("analysis_category", "Analysis category"),
        ("category", "Category"),
        ("category_sub", "Category subdivision"),
        ("category_detail", "Category detail"),
        ("artifact_kind", "Artifact kind"),
        ("record_key", "Record key"),
        ("source_artifact", "Source artifact"),
        ("url", "URL"),
        ("title", "Title"),
        ("host", "Host"),
        ("domain", "Domain"),
        ("search_term", "Search term"),
        ("target_path", "Target path"),
        ("current_path", "Current path"),
        ("application_name", "Application name"),
        ("application_path", "Application path"),
        ("event_id", "Event ID"),
        ("channel", "Channel"),
        ("provider", "Provider"),
        ("computer", "Computer"),
        ("user", "User"),
        ("username", "Username"),
        ("sid", "SID"),
        ("registry_key_path", "Registry key path"),
        ("registry_value_name", "Registry value name"),
        ("registry_value_type", "Registry value type"),
        ("file_system", "File system"),
        ("filesystem_parser", "Filesystem parser"),
        ("ntfs_file_record_number", "NTFS file record number"),
        ("mft_record_number", "MFT record number"),
        ("ext_inode_number", "EXT inode number"),
        ("record_index", "Record index"),
        ("entry_type", "Entry type"),
        ("visit_source", "Visit source"),
        ("visit_source_label", "Visit source label"),
        ("visit_origin", "Visit origin"),
        ("browser_profile", "Browser profile"),
        ("is_known_to_sync", "Known to Chromium Sync"),
        ("originator_sync_guid_full", "Originating Sync client GUID"),
        (
            "originator_sync_guid_note",
            "Originating Sync client GUID meaning",
        ),
        ("source_profile_path_exact", "Source browser profile path"),
        ("source_artifact_path_exact", "Source artifact path (exact)"),
        ("source_artifact_path", "Source artifact path"),
        ("hidden", "Hidden"),
        ("shimcache_path", "Shimcache path"),
        ("shimcache_execution_flag", "Shimcache execution flag"),
        (
            "shimcache_execution_flag_semantics",
            "Shimcache execution flag semantics",
        ),
        ("shimcache_layout_label", "Shimcache layout"),
        ("shimcache_registry_key", "Shimcache Registry key"),
        ("shimcache_registry_value", "Shimcache Registry value"),
        ("userassist_decoded_name", "UserAssist decoded name"),
        ("userassist_encoded_name", "UserAssist raw value name"),
        ("userassist_run_count", "UserAssist run count"),
        ("userassist_focus_count", "UserAssist focus count"),
        ("userassist_focus_time_ms", "UserAssist focus time (ms)"),
        ("userassist_binary_layout", "UserAssist binary layout"),
        ("amcache_path", "Amcache path"),
        ("amcache_name", "Amcache program name"),
        ("amcache_publisher", "Amcache publisher"),
        ("amcache_product_name", "Amcache product name"),
        ("amcache_version", "Amcache version"),
        ("amcache_sha1", "Amcache SHA-1"),
        ("amcache_key_path", "Amcache key path"),
        ("usn", "USN"),
        ("usn_reason", "USN reason"),
        ("usn_reason_flags", "USN reason flags"),
        ("usn_source_info", "USN source info"),
        ("usn_file_name", "USN file name"),
        ("usn_file_reference_number", "USN file reference number"),
        (
            "usn_parent_file_reference_number",
            "USN parent file reference number",
        ),
        ("shell_link_target_path", "Shell link target path"),
        ("shell_link_relative_path", "Shell link relative path"),
        ("shell_link_working_dir", "Shell link working directory"),
        ("shell_link_arguments", "Shell link arguments"),
        ("prefetch_executable_name", "Prefetch executable name"),
        ("prefetch_run_count", "Prefetch run count"),
        ("prefetch_hash", "Prefetch hash"),
    ];
    for (name, label) in FIELD_SPECS {
        let Some(value) = object.get(*name).and_then(scalar_text) else {
            continue;
        };
        let (value, value_truncated) = bound_text(&value);
        push_limited(
            output,
            omitted,
            MAX_ARTIFACT_DETAIL_FIELDS,
            ArtifactDetailField {
                name: (*name).to_string(),
                label: (*label).to_string(),
                value,
                value_truncated,
                source: format!("filesystem_entries.metadata_json.{name}"),
            },
        );
    }
}

fn project_metadata_timestamps(
    object: &Map<String, Value>,
    output: &mut Vec<ArtifactTimestamp>,
    omitted: &mut usize,
    invalid_recorded: &mut bool,
    warnings: &mut BoundedStrings,
) {
    const TIMESTAMP_SPECS: &[(&str, &str, Option<&str>, Option<&str>)] = &[
        (
            "artifact_time_utc",
            "Artifact time",
            Some("artifact_time_basis"),
            Some("UTC"),
        ),
        (
            "created_utc",
            "Created",
            Some("created_time_basis"),
            Some("UTC"),
        ),
        (
            "modified_utc",
            "Modified",
            Some("modified_time_basis"),
            Some("UTC"),
        ),
        (
            "accessed_utc",
            "Accessed",
            Some("accessed_time_basis"),
            Some("UTC"),
        ),
        (
            "mft_modified_utc",
            "MFT modified",
            Some("mft_modified_time_basis"),
            Some("UTC"),
        ),
        (
            "deleted_utc",
            "Deleted",
            Some("deleted_time_basis"),
            Some("UTC"),
        ),
        (
            "visit_time_utc",
            "Visit time",
            Some("visit_time_basis"),
            Some("UTC"),
        ),
        (
            "download_start_utc",
            "Download start",
            Some("download_start_time_basis"),
            Some("UTC"),
        ),
        (
            "download_end_utc",
            "Download end",
            Some("download_end_time_basis"),
            Some("UTC"),
        ),
        (
            "registry_key_last_write_utc",
            "Registry key last write",
            Some("registry_time_basis"),
            Some("UTC"),
        ),
        (
            "ntfs_mft_record_modification_time_utc",
            "NTFS MFT record modification",
            Some("ntfs_time_basis"),
            Some("UTC"),
        ),
        (
            "shimcache_file_last_modified_utc",
            "Shimcache cached file modified",
            Some("shimcache_time_semantics"),
            Some("UTC"),
        ),
        (
            "userassist_last_execution_utc",
            "UserAssist last execution",
            None,
            Some("UTC"),
        ),
        (
            "prefetch_last_run_utc",
            "Prefetch last run",
            Some("artifact_time_semantics"),
            Some("UTC"),
        ),
        (
            "shell_link_target_creation_utc",
            "Shell link target created",
            None,
            Some("UTC"),
        ),
        (
            "shell_link_target_modification_utc",
            "Shell link target modified",
            None,
            Some("UTC"),
        ),
        (
            "shell_link_target_access_utc",
            "Shell link target accessed",
            None,
            Some("UTC"),
        ),
        ("usn_timestamp_utc", "USN timestamp", None, Some("UTC")),
    ];
    for (key, label, basis_key, timezone) in TIMESTAMP_SPECS {
        let Some(raw) = object.get(*key) else {
            continue;
        };
        let Some(raw_value) = raw.as_str() else {
            *invalid_recorded = true;
            warnings.push(format!(
                "Timestamp {key} is persisted with a non-string value and was withheld."
            ));
            continue;
        };
        let (raw_value, value_truncated) = bound_text(raw_value);
        let (basis, basis_truncated) = basis_key
            .and_then(|key| bounded_string_value_with_flag(object.get(key)))
            .map_or((None, false), |(value, truncated)| (Some(value), truncated));
        push_limited(
            output,
            omitted,
            MAX_ARTIFACT_DETAIL_TIMESTAMPS,
            ArtifactTimestamp {
                semantic_field: (*key).to_string(),
                label: (*label).to_string(),
                raw_value,
                value_truncated,
                basis,
                basis_truncated,
                timezone: timezone.map(str::to_string),
                source: format!("filesystem_entries.metadata_json.{key}"),
            },
        );
    }
}

fn project_database_timestamps(
    row: &DetailRow,
    output: &mut Vec<ArtifactTimestamp>,
    omitted: &mut usize,
) {
    for (field, label, value, source) in [
        (
            "evidence_attached_at",
            "Evidence attached",
            row.evidence_attached_at.as_deref(),
            "evidence_sources.attached_at",
        ),
        (
            "evidence_indexed_at",
            "Evidence indexed",
            row.evidence_indexed_at.as_deref(),
            "evidence_sources.indexed_at",
        ),
        (
            "source_job_started_at",
            "Source job started",
            row.source_job_started_at.as_deref(),
            "evidence_jobs.started_at",
        ),
        (
            "source_job_finished_at",
            "Source job finished",
            row.source_job_finished_at.as_deref(),
            "evidence_jobs.finished_at",
        ),
    ] {
        let Some(value) = value else { continue };
        let (raw_value, value_truncated) = bound_text(value);
        push_limited(
            output,
            omitted,
            MAX_ARTIFACT_DETAIL_TIMESTAMPS,
            ArtifactTimestamp {
                semantic_field: field.to_string(),
                label: label.to_string(),
                raw_value,
                value_truncated,
                basis: Some(source.to_string()),
                basis_truncated: false,
                // KDFT writes these database fields in canonical UTC. The raw
                // value remains available so the UI performs no conversion.
                timezone: Some("UTC".to_string()),
                source: source.to_string(),
            },
        );
    }
}

fn project_evidence_hash(
    row: &DetailRow,
    output: &mut Vec<ArtifactHash>,
    omitted: &mut usize,
    projection: &mut HashProjectionState,
    warnings: &mut BoundedStrings,
) {
    let Some(value) = row.evidence_sha256_hex.as_deref() else {
        return;
    };
    if !is_sha256_hex(value) {
        projection.invalid("A persisted evidence SHA-256 is malformed and was withheld.");
        warnings.push("The persisted evidence SHA-256 is not a 64-character hexadecimal digest and was withheld.");
        return;
    }
    let (scope, scope_truncated) = row
        .evidence_sha256_scope
        .as_deref()
        .map(bound_text)
        .map_or((None, false), |(value, truncated)| (Some(value), truncated));
    let (scope_availability, label) = match scope.as_deref() {
        Some("file") => (ArtifactValueAvailability::Recorded, "Evidence file SHA-256"),
        Some("logical_media") => (
            ArtifactValueAvailability::Recorded,
            "Decoded logical-media SHA-256",
        ),
        Some(_) => {
            projection.invalid("A persisted evidence SHA-256 has an undefined scope.");
            warnings.push("The persisted evidence SHA-256 has an undefined scope; it must not be treated as an acquisition-container hash.");
            (
                ArtifactValueAvailability::Invalid,
                "Evidence SHA-256 (scope invalid)",
            )
        }
        None => {
            projection.invalid("A persisted evidence SHA-256 has no recorded scope.");
            warnings.push("The persisted evidence SHA-256 has no recorded scope; it must not be treated as an acquisition-container hash.");
            (
                ArtifactValueAvailability::Invalid,
                "Evidence SHA-256 (scope unavailable)",
            )
        }
    };
    let (value, value_truncated) = bound_text(value);
    push_limited(
        output,
        omitted,
        MAX_ARTIFACT_DETAIL_HASHES,
        ArtifactHash {
            algorithm: "SHA-256".to_string(),
            label: label.to_string(),
            value,
            value_truncated,
            scope,
            scope_truncated,
            scope_availability,
            hashed_at: row
                .evidence_hashed_at
                .as_deref()
                .map(bound_text)
                .map(|v| v.0),
            hashed_at_truncated: row
                .evidence_hashed_at
                .as_deref()
                .map(bound_text)
                .map(|v| v.1)
                .unwrap_or(false),
            source: "evidence_sources.sha256_hex".to_string(),
        },
    );
}

fn project_file_hash(
    object: &Map<String, Value>,
    output: &mut Vec<ArtifactHash>,
    omitted: &mut usize,
    projection: &mut HashProjectionState,
    warnings: &mut BoundedStrings,
) {
    let Some(value) = object.get("file_sha256").and_then(Value::as_str) else {
        return;
    };
    let input = object.get("file_sha256_input").and_then(Value::as_str);
    if input != Some("complete reconstructed file content") || !is_sha256_hex(value) {
        projection.invalid(
            "A persisted file_sha256 lacks a valid digest or complete reconstructed-file input proof.",
        );
        warnings.push("A metadata file_sha256 was withheld because its digest or complete reconstructed-file input proof is invalid.");
        return;
    }
    let (value, value_truncated) = bound_text(value);
    push_limited(
        output,
        omitted,
        MAX_ARTIFACT_DETAIL_HASHES,
        ArtifactHash {
            algorithm: "SHA-256".to_string(),
            label: "Complete reconstructed file SHA-256".to_string(),
            value,
            value_truncated,
            scope: Some("complete reconstructed file content".to_string()),
            scope_truncated: false,
            scope_availability: ArtifactValueAvailability::Recorded,
            hashed_at: object
                .get("file_sha256_at")
                .and_then(Value::as_str)
                .map(bound_text)
                .map(|v| v.0),
            hashed_at_truncated: object
                .get("file_sha256_at")
                .and_then(Value::as_str)
                .map(bound_text)
                .map(|v| v.1)
                .unwrap_or(false),
            source: "filesystem_entries.metadata_json.file_sha256".to_string(),
        },
    );
}

fn project_coordinates(
    object: &Map<String, Value>,
    output: &mut Vec<ArtifactCoordinate>,
    omitted: &mut usize,
    warnings: &mut BoundedStrings,
) {
    const COORDINATES: &[CoordinateSpec] = &[
        CoordinateSpec {
            key: "partition_start_offset",
            label: "Partition start offset",
            namespace: "decoded_evidence_media",
            basis_key: Some("physical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("partition_start_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "partition_size_bytes",
            label: "Partition size",
            namespace: "decoded_evidence_media",
            basis_key: Some("physical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("partition_size_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "file_data_decoded_media_offset",
            label: "File data decoded-media offset",
            namespace: "decoded_evidence_media",
            basis_key: Some("physical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("file_data_exact_start"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "file_data_physical_offset",
            label: "Legacy parser-recorded file data physical offset",
            namespace: "parser_recorded_legacy_physical",
            basis_key: Some("physical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("file_data_exact_start"),
            legacy_physical_name: true,
        },
        CoordinateSpec {
            key: "file_data_file_offset",
            label: "File-relative data offset",
            namespace: "logical_file_relative",
            basis_key: Some("file_data_file_offset_basis"),
            scope_key: Some("file_data_file_offset_scope"),
            exact_key: Some("file_data_file_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "file_data_logical_offset",
            label: "Filesystem-volume logical data offset",
            namespace: "filesystem_volume_relative",
            basis_key: Some("file_data_logical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("file_data_exact_start"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "file_data_contiguous_bytes",
            label: "Contiguous data extent",
            namespace: "filesystem_volume_relative",
            basis_key: Some("file_data_logical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("file_data_contiguous_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "mft_record_logical_offset",
            label: "MFT record logical offset",
            namespace: "filesystem_volume_relative",
            basis_key: Some("mft_record_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("mft_record_exact_start"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "mft_record_physical_offset",
            label: "Legacy parser-recorded MFT record physical offset",
            namespace: "parser_recorded_legacy_physical",
            basis_key: Some("physical_offset_basis"),
            scope_key: Some("offset_coordinate_system"),
            exact_key: Some("mft_record_exact_start"),
            legacy_physical_name: true,
        },
        CoordinateSpec {
            key: "registry_key_offset",
            label: "Registry key file-relative offset",
            namespace: "registry_hive_file_relative",
            basis_key: Some("registry_key_offset_basis"),
            scope_key: Some("registry_hive_path"),
            exact_key: Some("registry_key_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "registry_key_file_relative_offset",
            label: "Registry key file-relative offset",
            namespace: "registry_hive_file_relative",
            basis_key: Some("registry_key_offset_basis"),
            scope_key: Some("registry_hive_path"),
            exact_key: Some("registry_key_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "registry_value_offset",
            label: "Registry value file-relative offset",
            namespace: "registry_hive_file_relative",
            basis_key: Some("registry_value_offset_basis"),
            scope_key: Some("registry_hive_path"),
            exact_key: Some("registry_value_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "registry_value_file_relative_offset",
            label: "Registry value file-relative offset",
            namespace: "registry_hive_file_relative",
            basis_key: Some("registry_value_offset_basis"),
            scope_key: Some("registry_hive_path"),
            exact_key: Some("registry_value_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "shimcache_record_file_relative_offset",
            label: "Shimcache record file-relative offset",
            namespace: "registry_hive_file_relative",
            basis_key: Some("shimcache_record_offset_basis"),
            scope_key: Some("registry_hive_path"),
            exact_key: Some("shimcache_record_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "container_physical_offset",
            label: "Acquisition container offset",
            namespace: "acquisition_container",
            basis_key: Some("container_offset_basis"),
            scope_key: Some("container_offset_scope"),
            exact_key: Some("container_offset_exact"),
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "shimcache_record_value_relative_offset",
            label: "Shimcache record value-relative offset",
            namespace: "registry_value_relative",
            basis_key: Some("shimcache_offset_basis"),
            scope_key: Some("shimcache_registry_key"),
            exact_key: None,
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "shimcache_path_value_relative_offset",
            label: "Shimcache path value-relative offset",
            namespace: "registry_value_relative",
            basis_key: Some("shimcache_offset_basis"),
            scope_key: Some("shimcache_registry_key"),
            exact_key: None,
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "source_stream_offset",
            label: "Source journal stream-relative offset",
            namespace: "journal_stream_relative",
            basis_key: Some("source_stream_offset_basis"),
            scope_key: Some("source_logical_path_exact"),
            exact_key: None,
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "source_file_record_offset",
            label: "Database source file record offset",
            namespace: "database_file_relative",
            basis_key: Some("srum_offset_basis"),
            scope_key: Some("source_path_exact"),
            exact_key: None,
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "source_file_page_offset",
            label: "Database source file page offset",
            namespace: "database_file_relative",
            basis_key: Some("srum_offset_basis"),
            scope_key: Some("source_path_exact"),
            exact_key: None,
            legacy_physical_name: false,
        },
        CoordinateSpec {
            key: "source_file_page_value_offset",
            label: "Database source file page value offset",
            namespace: "database_file_relative",
            basis_key: Some("srum_offset_basis"),
            scope_key: Some("source_path_exact"),
            exact_key: None,
            legacy_physical_name: false,
        },
    ];
    for spec in COORDINATES {
        let Some(raw) = object.get(spec.key) else {
            continue;
        };
        let (availability, value, value_truncated) = match raw {
            Value::Null => (ArtifactValueAvailability::RecordedNull, None, false),
            Value::Number(number) => match number.as_u64() {
                Some(number) => (
                    ArtifactValueAvailability::Recorded,
                    Some(number.to_string()),
                    false,
                ),
                None => (
                    ArtifactValueAvailability::Invalid,
                    Some(bound_text(&number.to_string()).0),
                    false,
                ),
            },
            other => {
                let raw = scalar_text(other).unwrap_or_else(|| "non-scalar JSON value".to_string());
                let (raw, truncated) = bound_text(&raw);
                (ArtifactValueAvailability::Invalid, Some(raw), truncated)
            }
        };
        let exact = spec
            .exact_key
            .and_then(|key| object.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (basis, basis_truncated) = spec
            .basis_key
            .and_then(|key| bounded_string_value_with_flag(object.get(key)))
            .map_or((None, false), |(value, truncated)| (Some(value), truncated));
        let (scope, scope_truncated) = spec
            .scope_key
            .and_then(|key| bounded_string_value_with_flag(object.get(key)))
            .map_or((None, false), |(value, truncated)| (Some(value), truncated));
        let bitlocker_plaintext_logical =
            scope.as_deref() == Some("decrypted_bitlocker_volume_logical_bytes");
        let warning = match availability {
            ArtifactValueAvailability::RecordedNull => Some(
                "The database records this coordinate as null; zero was not substituted."
                    .to_string(),
            ),
            ArtifactValueAvailability::Invalid => Some(
                "The recorded coordinate is not a non-negative integer byte value; it was not coerced to zero."
                    .to_string(),
            ),
            ArtifactValueAvailability::Recorded if bitlocker_plaintext_logical => Some(
                if spec.legacy_physical_name {
                    "Plaintext logical offset in a decrypted BitLocker volume: it must not be added to the encrypted partition start, no decoded-media/physical mapping is asserted, and the legacy field name is not an E01 segment/container offset."
                } else {
                    "Plaintext logical offset in a decrypted BitLocker volume: it must not be added to the encrypted partition start and no decoded-media/physical mapping is asserted."
                }
                .to_string(),
            ),
            ArtifactValueAvailability::Recorded if spec.legacy_physical_name => Some(
                "Legacy parser field name only: this is not asserted to be an E01 segment/container-file physical offset and was not revalidated."
                    .to_string(),
            ),
            ArtifactValueAvailability::Recorded => Some(
                "Parser-recorded coordinate; not revalidated against raw evidence during Inspector display."
                    .to_string(),
            ),
            _ => None,
        };
        if availability == ArtifactValueAvailability::Invalid {
            warnings.push(format!(
                "Coordinate {} has an invalid persisted type or value and was not coerced.",
                spec.key
            ));
        }
        push_limited(
            output,
            omitted,
            MAX_ARTIFACT_DETAIL_COORDINATES,
            ArtifactCoordinate {
                name: spec.key.to_string(),
                label: spec.label.to_string(),
                namespace: spec.namespace.to_string(),
                availability,
                value,
                value_truncated,
                exact,
                unit: Some("bytes".to_string()),
                basis,
                basis_truncated,
                scope,
                scope_truncated,
                warning,
            },
        );
    }
}

fn project_metadata_provenance(
    object: &Map<String, Value>,
    output: &mut Vec<ArtifactProvenanceField>,
    omitted: &mut usize,
) {
    const PROVENANCE: &[(&str, &str)] = &[
        ("source_path_exact", "Exact source path"),
        ("local_relative_path", "Local relative path"),
        ("source_artifact", "Source artifact"),
        ("source_entry_id", "Source entry ID"),
        ("source_file_id", "Source file ID"),
        ("filesystem_parser", "Filesystem parser"),
        ("registry_hive_role", "Registry hive role"),
        ("registry_hive_path", "Registry hive path"),
        ("virtual_filesystem", "Virtual filesystem"),
        ("recovery_read", "Recovery read"),
        ("source_logical_path_exact", "Exact source logical path"),
        ("source_stream_offset_basis", "Source stream offset basis"),
        ("path_claim", "Path claim"),
        ("rename_pairing_claim", "Rename pairing claim"),
        ("parser", "Parser"),
        ("structured_source", "Structured source"),
    ];
    for (name, label) in PROVENANCE {
        let Some(value) = object.get(*name).and_then(scalar_text) else {
            continue;
        };
        push_provenance(
            output,
            omitted,
            name,
            label,
            value,
            &format!("filesystem_entries.metadata_json.{name}"),
        );
    }
}

fn project_database_provenance(
    row: &DetailRow,
    output: &mut Vec<ArtifactProvenanceField>,
    omitted: &mut usize,
) {
    for (name, label, value, source) in [
        (
            "case_id",
            "Case ID",
            Some(row.case_id.to_string()),
            "filesystem_entries.case_id",
        ),
        (
            "entry_id",
            "Entry ID",
            Some(row.entry_id.to_string()),
            "filesystem_entries.id",
        ),
        (
            "evidence_id",
            "Evidence ID",
            Some(row.evidence_id.to_string()),
            "filesystem_entries.evidence_id",
        ),
        (
            "source_job_id",
            "Source job ID",
            row.source_job_id.map(|value| value.to_string()),
            "filesystem_entries.discovered_by_job_id",
        ),
        (
            "source_job_type",
            "Source job type",
            row.source_job_type.clone(),
            "evidence_jobs.job_type",
        ),
        (
            "source_job_status",
            "Source job status",
            row.source_job_status.clone(),
            "evidence_jobs.status",
        ),
        (
            "parser_schema_version",
            "Parser schema version",
            row.parser_schema_version.clone(),
            "evidence_jobs.parser_schema_version",
        ),
    ] {
        let Some(value) = value else { continue };
        push_provenance(output, omitted, name, label, value, source);
    }
}

fn detail_completeness(
    row: &DetailRow,
    metadata_state: ArtifactMetadataState,
) -> ArtifactDetailCompleteness {
    let mut diagnostics = BoundedStrings::new(MAX_ARTIFACT_DETAIL_DIAGNOSTICS);
    if row.source_job_has_error {
        diagnostics.push(
            "The source job has a recorded diagnostic; its unbounded error text was not loaded.",
        );
    }
    match metadata_state {
        ArtifactMetadataState::Oversized => diagnostics.push(
            "Metadata exceeded the Inspector parsing bound, so allowlisted detail fields are unavailable.",
        ),
        ArtifactMetadataState::Malformed => diagnostics.push(
            "Metadata is malformed, so allowlisted detail fields are unavailable.",
        ),
        _ => {}
    }
    let (state, detail) = match row.source_job_status.as_deref() {
        Some("queued" | "running") => (
            CoverageState::InProgress,
            "The source job is still active; no explicit artifact coverage record proves completeness.",
        ),
        Some("failed") => (
            CoverageState::Failed,
            "The source job failed; this artifact projection is not proof of complete processing.",
        ),
        Some("completed") => (
            CoverageState::Partial,
            "The source job completed, but no explicit artifact coverage record proves complete processing.",
        ),
        Some(_) => (
            CoverageState::Partial,
            "The source job status is limited or non-final; complete processing is not proven.",
        ),
        None => (
            CoverageState::Unknown,
            "No source job is linked to this entry; processing completeness is unknown.",
        ),
    };
    let (diagnostics, diagnostics_omitted) = diagnostics.finish();
    ArtifactDetailCompleteness {
        state,
        is_complete: false,
        detail: detail.to_string(),
        diagnostics,
        diagnostics_omitted,
    }
}

fn push_provenance(
    output: &mut Vec<ArtifactProvenanceField>,
    omitted: &mut usize,
    name: &str,
    label: &str,
    value: String,
    source: &str,
) {
    let (value, value_truncated) = bound_text(&value);
    push_limited(
        output,
        omitted,
        MAX_ARTIFACT_DETAIL_PROVENANCE,
        ArtifactProvenanceField {
            name: name.to_string(),
            label: label.to_string(),
            value,
            value_truncated,
            source: source.to_string(),
        },
    );
}

fn push_limited<T>(output: &mut Vec<T>, omitted: &mut usize, limit: usize, value: T) {
    if output.len() < limit {
        output.push(value);
    } else {
        *omitted += 1;
    }
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn bounded_string_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(bound_text)
        .map(|value| value.0)
}

fn bounded_string_value_with_flag(value: Option<&Value>) -> Option<(String, bool)> {
    value.and_then(Value::as_str).map(bound_text)
}

fn bound_text(value: &str) -> (String, bool) {
    let mut chars = value.chars();
    let bounded: String = chars
        .by_ref()
        .take(MAX_ARTIFACT_DETAIL_TEXT_CHARS)
        .collect();
    (bounded, chars.next().is_some())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug)]
struct BoundedStrings {
    values: Vec<String>,
    limit: usize,
    omitted: usize,
}

impl BoundedStrings {
    fn new(limit: usize) -> Self {
        Self {
            values: Vec::new(),
            limit,
            omitted: 0,
        }
    }

    fn push(&mut self, value: impl Into<String>) {
        let (value, _) = bound_text(&value.into());
        if self.values.len() < self.limit {
            self.values.push(value);
        } else {
            self.omitted += 1;
        }
    }

    fn finish(self) -> (Vec<String>, usize) {
        (self.values, self.omitted)
    }
}
