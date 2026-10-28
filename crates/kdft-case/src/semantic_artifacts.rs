//! Normalized semantic artifact storage.
//!
//! `filesystem_entries` remains the canonical inventory of source containers.
//! This module stores records *parsed from* those containers (for example one
//! EVTX event, browser visit, or registry value) without pretending that the
//! source file and the parsed artifact are the same thing.  Every artifact is
//! tied to a parser execution, may have multiple precisely-labelled source
//! coordinates, and may participate in multiple indexed taxonomy categories.

use super::{active_case_id, open_existing_case, schema_version_applied};
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::path::Path;

const SEMANTIC_ARTIFACT_SCHEMA_VERSION: i64 = 2;

/// The address space in which `offset_bytes` and `length_bytes` are expressed.
///
/// These stable values are evidence provenance, not presentation labels.  In
/// particular, decrypted BitLocker plaintext is deliberately distinct from
/// physical media bytes: adding the encrypted partition start does not create
/// a valid physical offset into ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCoordinateSystem {
    PhysicalMediaBytes,
    PartitionLogicalBytes,
    DecryptedBitlockerVolumeLogicalBytes,
    FilesystemFileBytes,
    FilesystemRecord,
    RegistryHiveBytes,
    EvtxFileBytes,
    SqliteDatabaseBytes,
    SqliteRow,
}

impl SourceCoordinateSystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PhysicalMediaBytes => "physical_media_bytes",
            Self::PartitionLogicalBytes => "partition_logical_bytes",
            Self::DecryptedBitlockerVolumeLogicalBytes => {
                "decrypted_bitlocker_volume_logical_bytes"
            }
            Self::FilesystemFileBytes => "filesystem_file_bytes",
            Self::FilesystemRecord => "filesystem_record",
            Self::RegistryHiveBytes => "registry_hive_bytes",
            Self::EvtxFileBytes => "evtx_file_bytes",
            Self::SqliteDatabaseBytes => "sqlite_database_bytes",
            Self::SqliteRow => "sqlite_row",
        }
    }

    fn from_db(value: &str) -> Result<Self> {
        match value {
            "physical_media_bytes" => Ok(Self::PhysicalMediaBytes),
            "partition_logical_bytes" => Ok(Self::PartitionLogicalBytes),
            "decrypted_bitlocker_volume_logical_bytes" => {
                Ok(Self::DecryptedBitlockerVolumeLogicalBytes)
            }
            "filesystem_file_bytes" => Ok(Self::FilesystemFileBytes),
            "filesystem_record" => Ok(Self::FilesystemRecord),
            "registry_hive_bytes" => Ok(Self::RegistryHiveBytes),
            "evtx_file_bytes" => Ok(Self::EvtxFileBytes),
            "sqlite_database_bytes" => Ok(Self::SqliteDatabaseBytes),
            "sqlite_row" => Ok(Self::SqliteRow),
            other => bail!("unsupported semantic artifact coordinate system: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserImplementationKind {
    BuiltIn,
    ExternalTool,
}

impl ParserImplementationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::ExternalTool => "external_tool",
        }
    }

    fn from_db(value: &str) -> Result<Self> {
        match value {
            "built_in" => Ok(Self::BuiltIn),
            "external_tool" => Ok(Self::ExternalTool),
            other => bail!("unsupported parser implementation kind: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserExecutionStatus {
    Running,
    Completed,
    CompletedWithDiagnostics,
    Failed,
    Cancelled,
}

impl ParserExecutionStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::CompletedWithDiagnostics => "completed_with_diagnostics",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn from_db(value: &str) -> Result<Self> {
        match value {
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "completed_with_diagnostics" => Ok(Self::CompletedWithDiagnostics),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => bail!("unsupported parser execution status: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactConfidence {
    Low,
    Medium,
    High,
    Verified,
}

impl ArtifactConfidence {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Verified => "verified",
        }
    }

    fn from_db(value: &str) -> Result<Self> {
        match value {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "verified" => Ok(Self::Verified),
            other => bail!("unsupported artifact classification confidence: {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewParserExecution {
    pub evidence_id: i64,
    pub evidence_job_id: Option<i64>,
    pub parser_name: String,
    pub parser_version: String,
    pub parser_schema_version: String,
    pub implementation_kind: ParserImplementationKind,
    /// Hash of the exact external executable/package when available.
    pub implementation_sha256: Option<String>,
    /// Reproducibility settings only. Callers must remove passwords, recovery
    /// keys, tokens, cookies, and other secrets before persistence.
    pub configuration_json: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserExecution {
    pub id: i64,
    pub case_id: i64,
    pub evidence_id: i64,
    pub evidence_job_id: Option<i64>,
    pub parser_name: String,
    pub parser_version: String,
    pub parser_schema_version: String,
    pub implementation_kind: ParserImplementationKind,
    pub implementation_sha256: Option<String>,
    pub configuration_json: JsonValue,
    pub status: ParserExecutionStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub diagnostics_json: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSourceCoordinate {
    /// `primary`, `supporting`, or another parser-defined role.
    pub role: String,
    /// Filesystem container from which the semantic record was parsed.
    pub source_entry_id: Option<i64>,
    pub coordinate_system: SourceCoordinateSystem,
    /// Examiner-facing source path retained even if an index generation is
    /// later replaced and `source_entry_id` becomes NULL.
    pub source_path: Option<String>,
    pub partition_index: Option<i64>,
    pub volume_index: Option<i64>,
    /// Context for partition-relative spaces. For decrypted BitLocker this is
    /// the encrypted partition's physical start and MUST NOT be added to the
    /// plaintext logical offset to claim a ciphertext/media offset.
    pub partition_start_offset_bytes: Option<i64>,
    pub offset_bytes: Option<i64>,
    pub length_bytes: Option<i64>,
    /// Native record identity (EVTX record ID, registry cell, SQLite row, ...).
    pub record_identifier: Option<String>,
    pub source_sha256: Option<String>,
    pub provenance_json: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewArtifactCategoryMembership {
    /// Stable taxonomy key, for example `web_activity.visits`.
    pub category_key: String,
    pub category_display_name: String,
    pub parent_category_key: Option<String>,
    pub parent_category_display_name: Option<String>,
    pub confidence: ArtifactConfidence,
    pub classification_basis: String,
    pub classifier_name: String,
    pub classifier_version: String,
}

#[derive(Debug, Clone)]
pub struct NewSemanticArtifact {
    pub evidence_id: i64,
    pub parser_execution_id: i64,
    /// Stable semantic kind such as `windows_event_log_record`.
    pub artifact_kind: String,
    /// Parser-scoped stable record identity. It is not a display name.
    pub record_key: String,
    pub display_name: String,
    pub artifact_time_utc: Option<String>,
    pub attributes_json: JsonValue,
    pub source_coordinates: Vec<ArtifactSourceCoordinate>,
    pub category_memberships: Vec<NewArtifactCategoryMembership>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactCategoryMembership {
    pub category_key: String,
    pub category_display_name: String,
    pub parent_category_key: Option<String>,
    pub confidence: ArtifactConfidence,
    pub classification_basis: String,
    pub classifier_name: String,
    pub classifier_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticArtifact {
    pub id: i64,
    pub case_id: i64,
    pub evidence_id: i64,
    pub parser_execution_id: i64,
    pub artifact_kind: String,
    pub record_key: String,
    pub display_name: String,
    pub artifact_time_utc: Option<String>,
    pub attributes_json: JsonValue,
    pub created_at: String,
    pub source_coordinates: Vec<ArtifactSourceCoordinate>,
    pub category_memberships: Vec<ArtifactCategoryMembership>,
}

#[derive(Debug, Clone, Default)]
pub struct SemanticArtifactQuery {
    pub evidence_id: Option<i64>,
    pub artifact_kind: Option<String>,
    pub category_key: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticCategoryCount {
    pub category_key: String,
    pub category_display_name: String,
    pub artifact_count: i64,
}

/// Idempotent additive migration for both new and pre-existing KDFT cases.
pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    if schema_version_applied(conn, SEMANTIC_ARTIFACT_SCHEMA_VERSION)? {
        return Ok(());
    }

    let migration = conn.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS parser_executions (
             id INTEGER PRIMARY KEY,
             case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
             evidence_id INTEGER NOT NULL REFERENCES evidence_sources(id) ON DELETE CASCADE,
             evidence_job_id INTEGER REFERENCES evidence_jobs(id) ON DELETE SET NULL,
             parser_name TEXT NOT NULL,
             parser_version TEXT NOT NULL,
             parser_schema_version TEXT NOT NULL,
             implementation_kind TEXT NOT NULL
                 CHECK (implementation_kind IN ('built_in', 'external_tool')),
             implementation_sha256 TEXT,
             configuration_json TEXT NOT NULL DEFAULT '{}',
             status TEXT NOT NULL DEFAULT 'running'
                 CHECK (status IN ('running', 'completed', 'completed_with_diagnostics', 'failed', 'cancelled')),
             started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             finished_at TEXT,
             diagnostics_json TEXT NOT NULL DEFAULT '{}'
         );
         CREATE INDEX IF NOT EXISTS ix_parser_executions_case_evidence_status
             ON parser_executions(case_id, evidence_id, status, id);
         CREATE INDEX IF NOT EXISTS ix_parser_executions_job
             ON parser_executions(evidence_job_id);

         CREATE TABLE IF NOT EXISTS semantic_artifacts (
             id INTEGER PRIMARY KEY,
             case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
             evidence_id INTEGER NOT NULL REFERENCES evidence_sources(id) ON DELETE CASCADE,
             parser_execution_id INTEGER NOT NULL REFERENCES parser_executions(id) ON DELETE RESTRICT,
             artifact_kind TEXT NOT NULL,
             record_key TEXT NOT NULL,
             display_name TEXT NOT NULL,
             artifact_time_utc TEXT,
             attributes_json TEXT NOT NULL DEFAULT '{}',
             created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             UNIQUE(parser_execution_id, artifact_kind, record_key)
         );
         CREATE INDEX IF NOT EXISTS ix_semantic_artifacts_case_evidence_id
             ON semantic_artifacts(case_id, evidence_id, id);
         CREATE INDEX IF NOT EXISTS ix_semantic_artifacts_evidence_kind_id
             ON semantic_artifacts(evidence_id, artifact_kind, id);
         CREATE INDEX IF NOT EXISTS ix_semantic_artifacts_parser_execution
             ON semantic_artifacts(parser_execution_id, id);
         CREATE INDEX IF NOT EXISTS ix_semantic_artifacts_time
             ON semantic_artifacts(artifact_time_utc, id);

         CREATE TABLE IF NOT EXISTS artifact_source_coordinates (
             id INTEGER PRIMARY KEY,
             artifact_id INTEGER NOT NULL REFERENCES semantic_artifacts(id) ON DELETE CASCADE,
             role TEXT NOT NULL,
             source_entry_id INTEGER REFERENCES filesystem_entries(id) ON DELETE SET NULL,
             coordinate_system TEXT NOT NULL,
             source_path TEXT,
             partition_index INTEGER CHECK (partition_index IS NULL OR partition_index >= 0),
             volume_index INTEGER CHECK (volume_index IS NULL OR volume_index >= 0),
             partition_start_offset_bytes INTEGER
                 CHECK (partition_start_offset_bytes IS NULL OR partition_start_offset_bytes >= 0),
             offset_bytes INTEGER CHECK (offset_bytes IS NULL OR offset_bytes >= 0),
             length_bytes INTEGER CHECK (length_bytes IS NULL OR length_bytes >= 0),
             record_identifier TEXT,
             source_sha256 TEXT,
             provenance_json TEXT NOT NULL DEFAULT '{}'
         );
         CREATE INDEX IF NOT EXISTS ix_artifact_source_coordinates_artifact
             ON artifact_source_coordinates(artifact_id, id);
         CREATE INDEX IF NOT EXISTS ix_artifact_source_coordinates_entry_artifact
             ON artifact_source_coordinates(source_entry_id, artifact_id)
             WHERE source_entry_id IS NOT NULL;
         CREATE INDEX IF NOT EXISTS ix_artifact_source_coordinates_space_offset
             ON artifact_source_coordinates(coordinate_system, offset_bytes, artifact_id);

         CREATE TABLE IF NOT EXISTS semantic_categories (
             id INTEGER PRIMARY KEY,
             case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
             category_key TEXT NOT NULL,
             display_name TEXT NOT NULL,
             parent_id INTEGER REFERENCES semantic_categories(id) ON DELETE RESTRICT
         );
         CREATE UNIQUE INDEX IF NOT EXISTS ux_semantic_categories_case_key
             ON semantic_categories(case_id, category_key);
         CREATE INDEX IF NOT EXISTS ix_semantic_categories_parent
             ON semantic_categories(parent_id, id);

         CREATE TABLE IF NOT EXISTS artifact_category_memberships (
             artifact_id INTEGER NOT NULL REFERENCES semantic_artifacts(id) ON DELETE CASCADE,
             category_id INTEGER NOT NULL REFERENCES semantic_categories(id) ON DELETE RESTRICT,
             confidence TEXT NOT NULL
                 CHECK (confidence IN ('low', 'medium', 'high', 'verified')),
             classification_basis TEXT NOT NULL,
             classifier_name TEXT NOT NULL,
             classifier_version TEXT NOT NULL,
             classified_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
             PRIMARY KEY(artifact_id, category_id)
         );
         CREATE INDEX IF NOT EXISTS ix_artifact_category_memberships_category_artifact
             ON artifact_category_memberships(category_id, artifact_id);

         INSERT OR IGNORE INTO schema_migrations(version) VALUES (2);
         COMMIT;",
    );
    if let Err(error) = migration {
        let _ = conn.execute_batch("ROLLBACK;");
        return Err(error).context("creating normalized semantic artifact storage");
    }
    Ok(())
}

pub fn begin_parser_execution(case_path: &Path, input: NewParserExecution) -> Result<i64> {
    validate_nonempty("parser name", &input.parser_name)?;
    validate_nonempty("parser version", &input.parser_version)?;
    validate_nonempty("parser schema version", &input.parser_schema_version)?;
    reject_sensitive_configuration_fields(&input.configuration_json, "$")?;
    let configuration_json = serde_json::to_string(&input.configuration_json)
        .context("serializing parser execution configuration")?;
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let evidence_exists = conn
        .query_row(
            "SELECT 1 FROM evidence_sources WHERE id = ?1 AND case_id = ?2",
            params![input.evidence_id, case_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !evidence_exists {
        bail!(
            "evidence {} does not belong to this case",
            input.evidence_id
        );
    }
    if let Some(job_id) = input.evidence_job_id {
        let job_matches = conn
            .query_row(
                "SELECT 1 FROM evidence_jobs
                 WHERE id = ?1 AND case_id = ?2 AND evidence_id = ?3",
                params![job_id, case_id, input.evidence_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !job_matches {
            bail!(
                "evidence job {job_id} does not belong to evidence {}",
                input.evidence_id
            );
        }
    }
    conn.execute(
        "INSERT INTO parser_executions(
             case_id, evidence_id, evidence_job_id, parser_name, parser_version,
             parser_schema_version, implementation_kind, implementation_sha256,
             configuration_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            case_id,
            input.evidence_id,
            input.evidence_job_id,
            input.parser_name.trim(),
            input.parser_version.trim(),
            input.parser_schema_version.trim(),
            input.implementation_kind.as_str(),
            trim_optional(input.implementation_sha256),
            configuration_json,
        ],
    )
    .context("recording parser execution provenance")?;
    Ok(conn.last_insert_rowid())
}

pub fn finish_parser_execution(
    case_path: &Path,
    parser_execution_id: i64,
    status: ParserExecutionStatus,
    diagnostics_json: JsonValue,
) -> Result<()> {
    if status == ParserExecutionStatus::Running {
        bail!("a parser execution cannot be finished with running status");
    }
    let diagnostics_json =
        serde_json::to_string(&diagnostics_json).context("serializing parser diagnostics")?;
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let updated = conn.execute(
        "UPDATE parser_executions
         SET status = ?1,
             diagnostics_json = ?2,
             finished_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?3 AND case_id = ?4",
        params![
            status.as_str(),
            diagnostics_json,
            parser_execution_id,
            case_id
        ],
    )?;
    if updated != 1 {
        bail!("parser execution {parser_execution_id} was not found in this case");
    }
    Ok(())
}

pub fn get_parser_execution(case_path: &Path, parser_execution_id: i64) -> Result<ParserExecution> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    conn.query_row(
        "SELECT id, case_id, evidence_id, evidence_job_id, parser_name,
                parser_version, parser_schema_version, implementation_kind,
                implementation_sha256, configuration_json, status, started_at,
                finished_at, diagnostics_json
         FROM parser_executions WHERE id = ?1 AND case_id = ?2",
        params![parser_execution_id, case_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,
            ))
        },
    )
    .optional()?
    .ok_or_else(|| anyhow!("parser execution {parser_execution_id} was not found"))
    .and_then(
        |(
            id,
            case_id,
            evidence_id,
            evidence_job_id,
            parser_name,
            parser_version,
            parser_schema_version,
            implementation_kind,
            implementation_sha256,
            configuration_json,
            status,
            started_at,
            finished_at,
            diagnostics_json,
        )| {
            Ok(ParserExecution {
                id,
                case_id,
                evidence_id,
                evidence_job_id,
                parser_name,
                parser_version,
                parser_schema_version,
                implementation_kind: ParserImplementationKind::from_db(&implementation_kind)?,
                implementation_sha256,
                configuration_json: parse_json(&configuration_json, "parser configuration")?,
                status: ParserExecutionStatus::from_db(&status)?,
                started_at,
                finished_at,
                diagnostics_json: parse_json(&diagnostics_json, "parser diagnostics")?,
            })
        },
    )
}

pub fn insert_semantic_artifact(case_path: &Path, input: NewSemanticArtifact) -> Result<i64> {
    validate_nonempty("artifact kind", &input.artifact_kind)?;
    validate_nonempty("artifact record key", &input.record_key)?;
    validate_nonempty("artifact display name", &input.display_name)?;
    for coordinate in &input.source_coordinates {
        validate_coordinate(coordinate)?;
    }
    for membership in &input.category_memberships {
        validate_membership(membership)?;
    }
    let attributes_json =
        serde_json::to_string(&input.attributes_json).context("serializing artifact attributes")?;

    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction()?;
    let execution_evidence_id = tx
        .query_row(
            "SELECT evidence_id FROM parser_executions
             WHERE id = ?1 AND case_id = ?2",
            params![input.parser_execution_id, case_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| {
            anyhow!(
                "parser execution {} was not found",
                input.parser_execution_id
            )
        })?;
    if execution_evidence_id != input.evidence_id {
        bail!(
            "parser execution {} belongs to evidence {}, not evidence {}",
            input.parser_execution_id,
            execution_evidence_id,
            input.evidence_id
        );
    }

    tx.execute(
        "INSERT INTO semantic_artifacts(
             case_id, evidence_id, parser_execution_id, artifact_kind,
             record_key, display_name, artifact_time_utc, attributes_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            case_id,
            input.evidence_id,
            input.parser_execution_id,
            input.artifact_kind.trim(),
            input.record_key.trim(),
            input.display_name.trim(),
            trim_optional(input.artifact_time_utc),
            attributes_json,
        ],
    )
    .context("inserting semantic artifact")?;
    let artifact_id = tx.last_insert_rowid();

    for coordinate in input.source_coordinates {
        if let Some(source_entry_id) = coordinate.source_entry_id {
            let source_evidence_id = tx
                .query_row(
                    "SELECT evidence_id FROM filesystem_entries
                     WHERE id = ?1 AND case_id = ?2",
                    params![source_entry_id, case_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or_else(|| {
                    anyhow!("source filesystem entry {source_entry_id} was not found")
                })?;
            if source_evidence_id != input.evidence_id {
                bail!(
                    "source filesystem entry {source_entry_id} belongs to evidence \
                     {source_evidence_id}, not evidence {}",
                    input.evidence_id
                );
            }
        }
        tx.execute(
            "INSERT INTO artifact_source_coordinates(
                 artifact_id, role, source_entry_id, coordinate_system,
                 source_path, partition_index, volume_index,
                 partition_start_offset_bytes, offset_bytes, length_bytes,
                 record_identifier, source_sha256, provenance_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                artifact_id,
                coordinate.role.trim(),
                coordinate.source_entry_id,
                coordinate.coordinate_system.as_str(),
                trim_optional(coordinate.source_path),
                coordinate.partition_index,
                coordinate.volume_index,
                coordinate.partition_start_offset_bytes,
                coordinate.offset_bytes,
                coordinate.length_bytes,
                trim_optional(coordinate.record_identifier),
                trim_optional(coordinate.source_sha256),
                serde_json::to_string(&coordinate.provenance_json)?,
            ],
        )
        .context("inserting artifact source coordinate")?;
    }

    for membership in input.category_memberships {
        let parent_id = match (
            membership.parent_category_key.as_deref(),
            membership.parent_category_display_name.as_deref(),
        ) {
            (Some(key), Some(display_name)) => {
                Some(ensure_category(&tx, case_id, key, display_name, None)?)
            }
            (None, None) => None,
            _ => bail!("parent category key and display name must be supplied together"),
        };
        let category_id = ensure_category(
            &tx,
            case_id,
            &membership.category_key,
            &membership.category_display_name,
            parent_id,
        )?;
        tx.execute(
            "INSERT INTO artifact_category_memberships(
                 artifact_id, category_id, confidence, classification_basis,
                 classifier_name, classifier_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                artifact_id,
                category_id,
                membership.confidence.as_str(),
                membership.classification_basis.trim(),
                membership.classifier_name.trim(),
                membership.classifier_version.trim(),
            ],
        )
        .context("inserting artifact category membership")?;
    }
    tx.commit()?;
    Ok(artifact_id)
}

pub fn list_semantic_artifacts(
    case_path: &Path,
    query: &SemanticArtifactQuery,
) -> Result<Vec<SemanticArtifact>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (sql, parameters) = artifact_select_sql(case_id, query);
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params_from_iter(parameters.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(
                id,
                case_id,
                evidence_id,
                parser_execution_id,
                artifact_kind,
                record_key,
                display_name,
                artifact_time_utc,
                attributes_json,
                created_at,
            )| {
                Ok(SemanticArtifact {
                    id,
                    case_id,
                    evidence_id,
                    parser_execution_id,
                    artifact_kind,
                    record_key,
                    display_name,
                    artifact_time_utc,
                    attributes_json: parse_json(&attributes_json, "artifact attributes")?,
                    created_at,
                    source_coordinates: load_coordinates(&conn, id)?,
                    category_memberships: load_memberships(&conn, id)?,
                })
            },
        )
        .collect()
}

pub fn count_semantic_artifacts(case_path: &Path, evidence_id: Option<i64>) -> Result<i64> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    match evidence_id {
        Some(evidence_id) => conn
            .query_row(
                "SELECT COUNT(*) FROM semantic_artifacts
                 WHERE case_id = ?1 AND evidence_id = ?2",
                params![case_id, evidence_id],
                |row| row.get(0),
            )
            .context("counting semantic artifacts for evidence"),
        None => conn
            .query_row(
                "SELECT COUNT(*) FROM semantic_artifacts WHERE case_id = ?1",
                params![case_id],
                |row| row.get(0),
            )
            .context("counting semantic artifacts"),
    }
}

/// Counts distinct source filesystem entries, not parsed records. This is the
/// container count shown separately from [`count_semantic_artifacts`].
pub fn count_artifact_source_containers(case_path: &Path, evidence_id: Option<i64>) -> Result<i64> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    match evidence_id {
        Some(evidence_id) => conn
            .query_row(
                "SELECT COUNT(DISTINCT s.source_entry_id)
                 FROM artifact_source_coordinates s
                 JOIN semantic_artifacts a ON a.id = s.artifact_id
                 WHERE a.case_id = ?1 AND a.evidence_id = ?2
                   AND s.source_entry_id IS NOT NULL",
                params![case_id, evidence_id],
                |row| row.get(0),
            )
            .context("counting semantic artifact source containers"),
        None => conn
            .query_row(
                "SELECT COUNT(DISTINCT s.source_entry_id)
                 FROM artifact_source_coordinates s
                 JOIN semantic_artifacts a ON a.id = s.artifact_id
                 WHERE a.case_id = ?1 AND s.source_entry_id IS NOT NULL",
                params![case_id],
                |row| row.get(0),
            )
            .context("counting semantic artifact source containers"),
    }
}

pub fn semantic_category_counts(
    case_path: &Path,
    evidence_id: Option<i64>,
) -> Result<Vec<SemanticCategoryCount>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (sql, parameters) = if let Some(evidence_id) = evidence_id {
        (
            "SELECT c.category_key, c.display_name, COUNT(*)
             FROM semantic_categories c
             JOIN artifact_category_memberships m ON m.category_id = c.id
             JOIN semantic_artifacts a ON a.id = m.artifact_id
             WHERE c.case_id = ?1 AND a.evidence_id = ?2
             GROUP BY c.id, c.category_key, c.display_name
             ORDER BY c.category_key",
            vec![SqlValue::Integer(case_id), SqlValue::Integer(evidence_id)],
        )
    } else {
        (
            "SELECT c.category_key, c.display_name, COUNT(*)
             FROM semantic_categories c
             JOIN artifact_category_memberships m ON m.category_id = c.id
             JOIN semantic_artifacts a ON a.id = m.artifact_id
             WHERE c.case_id = ?1
             GROUP BY c.id, c.category_key, c.display_name
             ORDER BY c.category_key",
            vec![SqlValue::Integer(case_id)],
        )
    };
    let mut stmt = conn.prepare(sql)?;
    let counts = stmt
        .query_map(params_from_iter(parameters.iter()), |row| {
            Ok(SemanticCategoryCount {
                category_key: row.get(0)?,
                category_display_name: row.get(1)?,
                artifact_count: row.get(2)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("reading semantic artifact category counts")?;
    Ok(counts)
}

fn artifact_select_sql(case_id: i64, query: &SemanticArtifactQuery) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        "SELECT a.id, a.case_id, a.evidence_id, a.parser_execution_id,
                a.artifact_kind, a.record_key, a.display_name,
                a.artifact_time_utc, a.attributes_json, a.created_at
         FROM semantic_artifacts a",
    );
    if query.category_key.is_some() {
        sql.push_str(
            " JOIN artifact_category_memberships m ON m.artifact_id = a.id
              JOIN semantic_categories c ON c.id = m.category_id",
        );
    }
    sql.push_str(" WHERE a.case_id = ?");
    let mut values = vec![SqlValue::Integer(case_id)];
    if let Some(evidence_id) = query.evidence_id {
        sql.push_str(" AND a.evidence_id = ?");
        values.push(SqlValue::Integer(evidence_id));
    }
    if let Some(artifact_kind) = query.artifact_kind.as_deref() {
        sql.push_str(" AND a.artifact_kind = ?");
        values.push(SqlValue::Text(artifact_kind.to_string()));
    }
    if let Some(category_key) = query.category_key.as_deref() {
        sql.push_str(" AND c.case_id = ? AND c.category_key = ?");
        values.push(SqlValue::Integer(case_id));
        values.push(SqlValue::Text(category_key.to_string()));
    }
    sql.push_str(" ORDER BY a.id LIMIT ? OFFSET ?");
    values.push(SqlValue::Integer(query.limit.clamp(1, 10_000) as i64));
    values.push(SqlValue::Integer(query.offset as i64));
    (sql, values)
}

fn load_coordinates(conn: &Connection, artifact_id: i64) -> Result<Vec<ArtifactSourceCoordinate>> {
    let mut stmt = conn.prepare(
        "SELECT role, source_entry_id, coordinate_system, source_path,
                partition_index, volume_index, partition_start_offset_bytes,
                offset_bytes, length_bytes, record_identifier, source_sha256,
                provenance_json
         FROM artifact_source_coordinates
         WHERE artifact_id = ?1 ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![artifact_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, String>(11)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(
                role,
                source_entry_id,
                coordinate_system,
                source_path,
                partition_index,
                volume_index,
                partition_start_offset_bytes,
                offset_bytes,
                length_bytes,
                record_identifier,
                source_sha256,
                provenance_json,
            )| {
                Ok(ArtifactSourceCoordinate {
                    role,
                    source_entry_id,
                    coordinate_system: SourceCoordinateSystem::from_db(&coordinate_system)?,
                    source_path,
                    partition_index,
                    volume_index,
                    partition_start_offset_bytes,
                    offset_bytes,
                    length_bytes,
                    record_identifier,
                    source_sha256,
                    provenance_json: parse_json(&provenance_json, "coordinate provenance")?,
                })
            },
        )
        .collect()
}

fn load_memberships(
    conn: &Connection,
    artifact_id: i64,
) -> Result<Vec<ArtifactCategoryMembership>> {
    let mut stmt = conn.prepare(
        "SELECT c.category_key, c.display_name, p.category_key,
                m.confidence, m.classification_basis, m.classifier_name,
                m.classifier_version
         FROM artifact_category_memberships m
         JOIN semantic_categories c ON c.id = m.category_id
         LEFT JOIN semantic_categories p ON p.id = c.parent_id
         WHERE m.artifact_id = ?1 ORDER BY c.category_key",
    )?;
    let rows = stmt
        .query_map(params![artifact_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(
                category_key,
                category_display_name,
                parent_category_key,
                confidence,
                classification_basis,
                classifier_name,
                classifier_version,
            )| {
                Ok(ArtifactCategoryMembership {
                    category_key,
                    category_display_name,
                    parent_category_key,
                    confidence: ArtifactConfidence::from_db(&confidence)?,
                    classification_basis,
                    classifier_name,
                    classifier_version,
                })
            },
        )
        .collect()
}

fn ensure_category(
    conn: &Connection,
    case_id: i64,
    key: &str,
    display_name: &str,
    parent_id: Option<i64>,
) -> Result<i64> {
    validate_nonempty("category key", key)?;
    validate_nonempty("category display name", display_name)?;
    conn.execute(
        "INSERT INTO semantic_categories(case_id, category_key, display_name, parent_id)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(case_id, category_key) DO NOTHING",
        params![case_id, key.trim(), display_name.trim(), parent_id],
    )?;
    let (id, stored_display, stored_parent): (i64, String, Option<i64>) = conn.query_row(
        "SELECT id, display_name, parent_id FROM semantic_categories
         WHERE case_id = ?1 AND category_key = ?2",
        params![case_id, key.trim()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if stored_display != display_name.trim() || stored_parent != parent_id {
        bail!(
            "category key {} already exists with a different display name or parent",
            key.trim()
        );
    }
    Ok(id)
}

fn validate_coordinate(coordinate: &ArtifactSourceCoordinate) -> Result<()> {
    validate_nonempty("artifact coordinate role", &coordinate.role)?;
    for (field, value) in [
        ("partition index", coordinate.partition_index),
        ("volume index", coordinate.volume_index),
        (
            "partition start offset",
            coordinate.partition_start_offset_bytes,
        ),
        ("source offset", coordinate.offset_bytes),
        ("source length", coordinate.length_bytes),
    ] {
        if value.is_some_and(|value| value < 0) {
            bail!("{field} cannot be negative");
        }
    }
    if coordinate.offset_bytes.is_some() && coordinate.length_bytes.is_none() {
        bail!("a byte coordinate with an offset must include its length");
    }
    Ok(())
}

fn validate_membership(membership: &NewArtifactCategoryMembership) -> Result<()> {
    validate_nonempty("category key", &membership.category_key)?;
    validate_nonempty("category display name", &membership.category_display_name)?;
    validate_nonempty("classification basis", &membership.classification_basis)?;
    validate_nonempty("classifier name", &membership.classifier_name)?;
    validate_nonempty("classifier version", &membership.classifier_version)?;
    if membership.parent_category_key.is_some() != membership.parent_category_display_name.is_some()
    {
        bail!("parent category key and display name must be supplied together");
    }
    Ok(())
}

fn validate_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} cannot be empty");
    }
    Ok(())
}

fn reject_sensitive_configuration_fields(value: &JsonValue, path: &str) -> Result<()> {
    match value {
        JsonValue::Object(fields) => {
            for (key, child) in fields {
                let normalized = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if matches!(
                    normalized.as_str(),
                    "bitlockerrecoverykey"
                        | "recoverypassword"
                        | "password"
                        | "passwd"
                        | "accesstoken"
                        | "refreshtoken"
                        | "authorization"
                        | "clientsecret"
                        | "secretvalue"
                ) {
                    bail!(
                        "parser configuration contains prohibited sensitive field {path}.{key}; \
                         persist only non-secret reproducibility settings"
                    );
                }
                reject_sensitive_configuration_fields(child, &format!("{path}.{key}"))?;
            }
        }
        JsonValue::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_sensitive_configuration_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

fn parse_json(value: &str, label: &str) -> Result<JsonValue> {
    serde_json::from_str(value).with_context(|| format!("parsing stored {label}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_case, CreateCaseOptions, INITIAL_SCHEMA, KDFT_APPLICATION_ID};
    use rusqlite::Connection;
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};

    struct Fixture {
        case_path: PathBuf,
        evidence_id: i64,
        source_entry_id: i64,
        parser_execution_id: i64,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.case_path);
            let _ = fs::remove_file(self.case_path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(self.case_path.with_extension("sqlite-shm"));
        }
    }

    fn temporary_case_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kdft-semantic-{label}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn case_options() -> CreateCaseOptions {
        CreateCaseOptions {
            name: "semantic artifact test".to_string(),
            examiner_name: None,
            case_number: None,
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        }
    }

    fn fixture(label: &str) -> Result<Fixture> {
        let case_path = temporary_case_path(label);
        create_case(&case_path, case_options())?;
        let conn = open_existing_case(&case_path)?;
        conn.execute(
            "INSERT INTO evidence_sources(
                 case_id, source_kind, source_path, display_name
             ) VALUES (1, 'image', 'fixture.E01', 'fixture.E01')",
            [],
        )?;
        let evidence_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind
             ) VALUES (1, ?1, '/Windows/System32/winevt/Logs/Security.evtx',
                       'Security.evtx', 'file')",
            params![evidence_id],
        )?;
        let source_entry_id = conn.last_insert_rowid();
        drop(conn);
        let parser_execution_id = begin_parser_execution(
            &case_path,
            NewParserExecution {
                evidence_id,
                evidence_job_id: None,
                parser_name: "evtx".to_string(),
                parser_version: "0.12.2".to_string(),
                parser_schema_version: "windows-event-v1".to_string(),
                implementation_kind: ParserImplementationKind::BuiltIn,
                implementation_sha256: None,
                configuration_json: json!({"recover_deleted": true}),
            },
        )?;
        Ok(Fixture {
            case_path,
            evidence_id,
            source_entry_id,
            parser_execution_id,
        })
    }

    fn event_artifact(fixture: &Fixture, record_id: i64) -> NewSemanticArtifact {
        NewSemanticArtifact {
            evidence_id: fixture.evidence_id,
            parser_execution_id: fixture.parser_execution_id,
            artifact_kind: "windows_event_log_record".to_string(),
            record_key: format!("Security.evtx:{record_id}"),
            display_name: format!("Security event {record_id}"),
            artifact_time_utc: Some("2026-10-15T12:00:00.000Z".to_string()),
            attributes_json: json!({"event_id": 4624, "record_id": record_id}),
            source_coordinates: vec![ArtifactSourceCoordinate {
                role: "primary".to_string(),
                source_entry_id: Some(fixture.source_entry_id),
                coordinate_system: SourceCoordinateSystem::EvtxFileBytes,
                source_path: Some("/Windows/System32/winevt/Logs/Security.evtx".to_string()),
                partition_index: Some(3),
                volume_index: None,
                partition_start_offset_bytes: Some(1_048_576),
                offset_bytes: Some(4_096 + record_id * 512),
                length_bytes: Some(512),
                record_identifier: Some(record_id.to_string()),
                source_sha256: None,
                provenance_json: json!({"chunk_number": 1}),
            }],
            category_memberships: vec![NewArtifactCategoryMembership {
                category_key: "operating_system.event_logs.records".to_string(),
                category_display_name: "Windows Event Log Records".to_string(),
                parent_category_key: Some("operating_system.event_logs".to_string()),
                parent_category_display_name: Some("Event and Diagnostic Logs".to_string()),
                confidence: ArtifactConfidence::Verified,
                classification_basis: "structurally decoded EVTX record".to_string(),
                classifier_name: "kdft-event-taxonomy".to_string(),
                classifier_version: "1".to_string(),
            }],
        }
    }

    #[test]
    fn existing_v1_case_is_migrated_without_changing_legacy_entries() -> Result<()> {
        let case_path = temporary_case_path("migration");
        {
            let conn = Connection::open(&case_path)?;
            conn.execute_batch(INITIAL_SCHEMA)?;
            conn.pragma_update(None, "application_id", KDFT_APPLICATION_ID)?;
            conn.execute("INSERT INTO cases(id, name) VALUES (1, 'legacy')", [])?;
            conn.execute("INSERT INTO case_options(case_id) VALUES (1)", [])?;
            conn.execute(
                "INSERT INTO evidence_sources(
                     id, case_id, source_kind, source_path, display_name
                 ) VALUES (1, 1, 'file', 'legacy.bin', 'legacy.bin')",
                [],
            )?;
            conn.execute(
                "INSERT INTO filesystem_entries(
                     id, case_id, evidence_id, logical_path, name, entry_kind
                 ) VALUES (7, 1, 1, '/legacy.bin', 'legacy.bin', 'file')",
                [],
            )?;
        }
        {
            let conn = open_existing_case(&case_path)?;
            assert!(schema_version_applied(
                &conn,
                SEMANTIC_ARTIFACT_SCHEMA_VERSION
            )?);
            let legacy_name: String = conn.query_row(
                "SELECT name FROM filesystem_entries WHERE id = 7",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(legacy_name, "legacy.bin");
            let table_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                     'parser_executions', 'semantic_artifacts',
                     'artifact_source_coordinates', 'semantic_categories',
                     'artifact_category_memberships'
                 )",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(table_count, 5);
        }
        fs::remove_file(&case_path)?;
        Ok(())
    }

    #[test]
    fn semantic_artifact_counts_are_distinct_from_source_container_counts() -> Result<()> {
        let fixture = fixture("counts")?;
        insert_semantic_artifact(&fixture.case_path, event_artifact(&fixture, 41))?;
        insert_semantic_artifact(&fixture.case_path, event_artifact(&fixture, 42))?;

        assert_eq!(
            count_semantic_artifacts(&fixture.case_path, Some(fixture.evidence_id))?,
            2
        );
        assert_eq!(
            count_artifact_source_containers(&fixture.case_path, Some(fixture.evidence_id))?,
            1
        );

        let artifacts = list_semantic_artifacts(
            &fixture.case_path,
            &SemanticArtifactQuery {
                evidence_id: Some(fixture.evidence_id),
                limit: 10,
                ..Default::default()
            },
        )?;
        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            artifacts[0].source_coordinates[0]
                .coordinate_system
                .as_str(),
            "evtx_file_bytes"
        );
        Ok(())
    }

    #[test]
    fn decrypted_bitlocker_coordinate_label_round_trips_exactly() -> Result<()> {
        let fixture = fixture("bitlocker-coordinate")?;
        let mut artifact = event_artifact(&fixture, 99);
        artifact.source_coordinates[0].coordinate_system =
            SourceCoordinateSystem::DecryptedBitlockerVolumeLogicalBytes;
        artifact.source_coordinates[0].volume_index = Some(2);
        artifact.source_coordinates[0].partition_start_offset_bytes = Some(1_073_741_824);
        artifact.source_coordinates[0].offset_bytes = Some(65_536);
        insert_semantic_artifact(&fixture.case_path, artifact)?;

        let conn = open_existing_case(&fixture.case_path)?;
        let stored: String = conn.query_row(
            "SELECT coordinate_system FROM artifact_source_coordinates",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(stored, "decrypted_bitlocker_volume_logical_bytes");
        drop(conn);
        let loaded = list_semantic_artifacts(
            &fixture.case_path,
            &SemanticArtifactQuery {
                limit: 10,
                ..Default::default()
            },
        )?;
        assert_eq!(
            loaded[0].source_coordinates[0].coordinate_system,
            SourceCoordinateSystem::DecryptedBitlockerVolumeLogicalBytes
        );
        assert_eq!(loaded[0].source_coordinates[0].offset_bytes, Some(65_536));
        assert_eq!(
            loaded[0].source_coordinates[0].partition_start_offset_bytes,
            Some(1_073_741_824)
        );
        Ok(())
    }

    #[test]
    fn category_queries_use_normalized_indexed_predicates() -> Result<()> {
        let fixture = fixture("category-index")?;
        insert_semantic_artifact(&fixture.case_path, event_artifact(&fixture, 1))?;
        let query = SemanticArtifactQuery {
            category_key: Some("operating_system.event_logs.records".to_string()),
            limit: 100,
            ..Default::default()
        };
        let artifacts = list_semantic_artifacts(&fixture.case_path, &query)?;
        assert_eq!(artifacts.len(), 1);

        let conn = open_existing_case(&fixture.case_path)?;
        let (sql, values) = artifact_select_sql(1, &query);
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let mut stmt = conn.prepare(&explain)?;
        let details = stmt
            .query_map(params_from_iter(values.iter()), |row| {
                row.get::<_, String>(3)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n");
        assert!(
            details.contains("ux_semantic_categories_case_key"),
            "category key predicate did not use its index:\n{details}"
        );
        assert!(
            details.contains("ix_artifact_category_memberships_category_artifact"),
            "category membership predicate did not use its index:\n{details}"
        );
        Ok(())
    }

    #[test]
    fn parser_execution_provenance_is_durable_and_status_is_explicit() -> Result<()> {
        let fixture = fixture("parser-provenance")?;
        finish_parser_execution(
            &fixture.case_path,
            fixture.parser_execution_id,
            ParserExecutionStatus::CompletedWithDiagnostics,
            json!({"omitted_records": 2}),
        )?;
        let execution = get_parser_execution(&fixture.case_path, fixture.parser_execution_id)?;
        assert_eq!(execution.parser_name, "evtx");
        assert_eq!(execution.parser_version, "0.12.2");
        assert_eq!(
            execution.status,
            ParserExecutionStatus::CompletedWithDiagnostics
        );
        assert_eq!(execution.diagnostics_json["omitted_records"], 2);
        assert!(execution.finished_at.is_some());
        Ok(())
    }

    #[test]
    fn parser_provenance_rejects_recovery_keys_and_other_secret_fields() -> Result<()> {
        let fixture = fixture("parser-secrets")?;
        let error = begin_parser_execution(
            &fixture.case_path,
            NewParserExecution {
                evidence_id: fixture.evidence_id,
                evidence_job_id: None,
                parser_name: "bitlocker-parser".to_string(),
                parser_version: "1".to_string(),
                parser_schema_version: "1".to_string(),
                implementation_kind: ParserImplementationKind::BuiltIn,
                implementation_sha256: None,
                configuration_json: json!({
                    "mode": "memory_only",
                    "bitlocker_recovery_key": "redacted-test-value"
                }),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("prohibited sensitive field"));
        let conn = open_existing_case(&fixture.case_path)?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM parser_executions WHERE parser_name = 'bitlocker-parser'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[allow(dead_code)]
    fn _assert_path_is_used(_: &Path) {}
}
