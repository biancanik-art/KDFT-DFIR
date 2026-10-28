use crate::artifact_detail::read_artifact_detail;
use crate::protocol::{
    ArtifactDetail, ArtifactDetailQuery, BackendCommand, BackendResponse, CaseSummary,
    CoverageBanner, CoverageState, EntryCursor, EntryPage, EntryPageQuery, EntrySummary,
    JobCoverage,
};
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_PAGE_SIZE: u32 = 200;
pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const MAX_IPC_COMMAND_BYTES: usize = 64 * 1_024;
const SQLITE_CACHE_KIB: i64 = 8 * 1_024;

/// Direct, read-only backend used by the standalone shell.
///
/// It stores only the case path. Each command gets a short-lived SQLite read
/// snapshot, which avoids a GUI-lifetime connection and prevents accidental
/// retention of large result sets.
#[derive(Debug, Clone)]
pub struct DesktopBackend {
    case_path: PathBuf,
}

impl DesktopBackend {
    pub fn open(case_path: impl AsRef<Path>) -> Result<Self> {
        let case_path = case_path.as_ref();
        if !case_path.is_file() {
            bail!(
                "case database is not a regular file: {}",
                case_path.display()
            );
        }
        let backend = Self {
            case_path: case_path.to_path_buf(),
        };
        let conn = backend.open_read_only()?;
        require_case_schema(&conn)?;
        Ok(backend)
    }

    pub fn dispatch(&self, command: BackendCommand) -> BackendResponse {
        let result = match command {
            BackendCommand::CaseSummary => self
                .case_summary()
                .map(|summary| BackendResponse::CaseSummary { summary }),
            BackendCommand::Coverage { evidence_id } => self
                .coverage(evidence_id)
                .map(|coverage| BackendResponse::Coverage { coverage }),
            BackendCommand::EntryPage { query } => self
                .entry_page(query)
                .map(|page| BackendResponse::EntryPage { page }),
            BackendCommand::ArtifactDetail { query } => {
                self.artifact_detail(query)
                    .map(|detail| BackendResponse::ArtifactDetail {
                        detail: Box::new(detail),
                    })
            }
        };

        result.unwrap_or_else(|error| BackendResponse::Error {
            code: error_code(&error).to_string(),
            message: error.to_string(),
        })
    }

    /// Path of the currently opened case database.
    ///
    /// The native shell uses this only for examiner-facing status. The backend
    /// still opens a fresh, read-only connection for each bounded command.
    pub fn case_path(&self) -> &Path {
        &self.case_path
    }

    /// Compatibility adapter for bounded native command JSON. It parses one
    /// command and emits one bounded response; it never starts a listener.
    pub fn dispatch_json(&self, command_json: &str) -> String {
        let response = if command_json.len() > MAX_IPC_COMMAND_BYTES {
            BackendResponse::Error {
                code: "command_too_large".to_string(),
                message: format!(
                    "desktop command exceeds the {MAX_IPC_COMMAND_BYTES}-byte safety limit"
                ),
            }
        } else {
            match serde_json::from_str::<BackendCommand>(command_json) {
                Ok(command) => self.dispatch(command),
                Err(error) => BackendResponse::Error {
                    code: "invalid_command".to_string(),
                    message: error.to_string(),
                },
            }
        };
        serde_json::to_string(&response).unwrap_or_else(|_| {
            r#"{"response":"error","code":"serialization_failed","message":"response serialization failed"}"#.to_string()
        })
    }

    fn case_summary(&self) -> Result<CaseSummary> {
        let mut conn = self.open_read_only()?;
        let tx = conn
            .transaction()
            .context("starting stable case-summary snapshot")?;
        let generation = case_generation_tx(&tx)?;
        let summary = tx
            .query_row(
                "SELECT c.id, c.name, c.examiner_name, c.case_number,
                    COALESCE(o.timezone, 'UTC'), c.created_at
             FROM cases c
             LEFT JOIN case_options o ON o.case_id = c.id
             ORDER BY c.id
             LIMIT 1",
                [],
                |row| {
                    Ok(CaseSummary {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        examiner_name: row.get(2)?,
                        case_number: row.get(3)?,
                        timezone: row.get(4)?,
                        created_at: row.get(5)?,
                        generation,
                    })
                },
            )
            .context("reading case summary")?;
        tx.commit().context("closing case-summary snapshot")?;
        Ok(summary)
    }

    fn coverage(&self, evidence_id: Option<i64>) -> Result<CoverageBanner> {
        let conn = self.open_read_only()?;
        latest_job_coverage(&conn, evidence_id)
    }

    fn entry_page(&self, query: EntryPageQuery) -> Result<EntryPage> {
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
        if limit == 0 || limit > MAX_PAGE_SIZE {
            bail!("page limit must be between 1 and {MAX_PAGE_SIZE}");
        }
        let after_id = query.cursor.as_ref().map_or(0, |cursor| cursor.after_id);
        if after_id < 0 {
            bail!("entry cursor cannot be negative");
        }

        let mut conn = self.open_read_only()?;
        let tx = conn
            .transaction()
            .context("starting stable case read snapshot")?;
        let generation = case_generation_tx(&tx)?;
        if let Some(cursor) = query.cursor.as_ref() {
            if cursor.generation != generation {
                return Err(anyhow!(
                    "stale page cursor: case generation changed from {} to {}; restart the query",
                    cursor.generation,
                    generation
                ));
            }
        }

        let mut items = read_entry_page(&tx, query.evidence_id, after_id, i64::from(limit) + 1)?;
        let has_more = items.len() > limit as usize;
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            items.last().map(|item| EntryCursor {
                after_id: item.id,
                generation,
            })
        } else {
            None
        };
        let coverage = latest_job_coverage_tx(&tx, query.evidence_id)?;
        tx.commit().context("closing stable case read snapshot")?;

        Ok(EntryPage {
            items,
            next_cursor,
            generation,
            coverage,
        })
    }

    /// Reads one exact entry and its bounded Inspector projection from one
    /// read-only SQLite snapshot. No raw evidence bytes or arbitrary metadata
    /// blobs are opened by this command.
    pub fn artifact_detail(&self, query: ArtifactDetailQuery) -> Result<ArtifactDetail> {
        if query.entry_id <= 0 {
            bail!("artifact detail entry ID must be positive");
        }
        if query.expected_generation < 0 {
            bail!("artifact detail generation cannot be negative");
        }

        let mut conn = self.open_read_only()?;
        let tx = conn
            .transaction()
            .context("starting stable artifact-detail snapshot")?;
        let generation = case_generation_tx(&tx)?;
        if query.expected_generation != generation {
            return Err(anyhow!(
                "stale artifact detail: case generation changed from {} to {}; reselect the entry",
                query.expected_generation,
                generation
            ));
        }
        let detail = read_artifact_detail(&tx, &query, generation)?;
        tx.commit().context("closing artifact-detail snapshot")?;
        Ok(detail)
    }

    fn open_read_only(&self) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            &self.case_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening case read-only: {}", self.case_path.display()))?;
        conn.busy_timeout(Duration::from_secs(2))?;
        conn.pragma_update(None, "query_only", true)?;
        conn.pragma_update(None, "cache_size", -SQLITE_CACHE_KIB)?;
        // Large mappings make address-space use look like retained RAM on
        // examiner workstations. Explicit reads keep the memory envelope
        // predictable; the OS page cache still serves repeated access.
        conn.pragma_update(None, "mmap_size", 0_i64)?;
        Ok(conn)
    }
}

fn require_case_schema(conn: &Connection) -> Result<()> {
    let cases: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'cases'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let entries: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name = 'filesystem_entries'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if cases.is_none() || entries.is_none() {
        bail!("file is not a supported KDFT case database");
    }
    Ok(())
}

fn case_generation_tx(tx: &Transaction<'_>) -> Result<i64> {
    tx.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
        row.get(0)
    })
    .context("reading case mutation generation")
}

fn read_entry_page(
    tx: &Transaction<'_>,
    evidence_id: Option<i64>,
    after_id: i64,
    fetch_limit: i64,
) -> Result<Vec<EntrySummary>> {
    let mut statement = tx.prepare_cached(
        "SELECT id, evidence_id, parent_id, logical_path, name, entry_kind,
                size_bytes, is_deleted, discovered_by_job_id
         FROM filesystem_entries
         WHERE id > ?1 AND (?2 IS NULL OR evidence_id = ?2)
         ORDER BY id
         LIMIT ?3",
    )?;
    let rows = statement.query_map(params![after_id, evidence_id, fetch_limit], |row| {
        Ok(EntrySummary {
            id: row.get(0)?,
            evidence_id: row.get(1)?,
            parent_id: row.get(2)?,
            logical_path: row.get(3)?,
            name: row.get(4)?,
            entry_kind: row.get(5)?,
            size_bytes: row.get(6)?,
            is_deleted: row.get::<_, i64>(7)? != 0,
            discovered_by_job_id: row.get(8)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading bounded entry page")
}

fn latest_job_coverage(conn: &Connection, evidence_id: Option<i64>) -> Result<CoverageBanner> {
    let mut statement = conn.prepare_cached(latest_jobs_sql())?;
    let jobs = map_job_rows(statement.query_map(params![evidence_id], map_job)?)?;
    Ok(summarize_coverage(jobs))
}

fn latest_job_coverage_tx(
    tx: &Transaction<'_>,
    evidence_id: Option<i64>,
) -> Result<CoverageBanner> {
    let mut statement = tx.prepare_cached(latest_jobs_sql())?;
    let jobs = map_job_rows(statement.query_map(params![evidence_id], map_job)?)?;
    Ok(summarize_coverage(jobs))
}

fn latest_jobs_sql() -> &'static str {
    "WITH ranked AS (
         SELECT id, evidence_id, job_type, status, started_at, finished_at,
                CASE WHEN error IS NULL OR error = '' THEN 0 ELSE 1 END AS has_error,
                ROW_NUMBER() OVER (
                    PARTITION BY COALESCE(evidence_id, -1), job_type ORDER BY id DESC
                ) AS rank
         FROM evidence_jobs
         WHERE (?1 IS NULL OR evidence_id = ?1)
     )
     SELECT id, evidence_id, job_type, status, started_at, finished_at, has_error
     FROM ranked
     WHERE rank = 1
     ORDER BY COALESCE(evidence_id, -1), job_type"
}

fn map_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobCoverage> {
    Ok(JobCoverage {
        id: row.get(0)?,
        evidence_id: row.get(1)?,
        job_type: row.get(2)?,
        status: row.get(3)?,
        started_at: row.get(4)?,
        finished_at: row.get(5)?,
        has_error: row.get::<_, i64>(6)? != 0,
    })
}

fn map_job_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<JobCoverage>>,
) -> Result<Vec<JobCoverage>> {
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("reading processor coverage")
}

fn summarize_coverage(jobs: Vec<JobCoverage>) -> CoverageBanner {
    if jobs.is_empty() {
        return CoverageBanner {
            state: CoverageState::NotProcessed,
            is_complete: false,
            title: "Results are not complete".to_string(),
            detail: "No processing job is recorded for this scope.".to_string(),
            jobs,
        };
    }

    let mut complete = 0_usize;
    let mut in_progress = 0_usize;
    let mut partial = 0_usize;
    let mut failed = 0_usize;
    for job in &jobs {
        match job.status.as_str() {
            "completed" if !job.has_error => complete += 1,
            "queued" | "running" => in_progress += 1,
            "failed" => failed += 1,
            _ => partial += 1,
        }
    }

    let (state, title, is_complete) = if in_progress > 0 {
        (
            CoverageState::InProgress,
            "Results are still being produced",
            false,
        )
    } else if failed > 0 && complete == 0 && partial == 0 {
        (CoverageState::Failed, "Results are not complete", false)
    } else if failed > 0 || partial > 0 {
        (CoverageState::Partial, "Results are partial", false)
    } else {
        // A set of successful jobs is not proof that every processor required
        // by the examiner's plan ran. Until the normalized parser-execution
        // store exposes a signed/immutable coverage plan, stay conservative.
        (
            CoverageState::Partial,
            "Recorded jobs completed; full scope is not proven",
            false,
        )
    };
    CoverageBanner {
        state,
        is_complete,
        title: title.to_string(),
        detail: format!(
            "Latest jobs in scope: {complete} complete, {in_progress} active, {partial} partial or limited, {failed} failed."
        ),
        jobs,
    }
}

fn error_code(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    if text.starts_with("stale page cursor") {
        "stale_cursor"
    } else if text.starts_with("stale artifact detail") {
        "stale_artifact_detail"
    } else if text.starts_with("artifact detail entry") && text.ends_with("was not found") {
        "artifact_not_found"
    } else if text.starts_with("artifact detail entry ID")
        || text.starts_with("artifact detail generation")
    {
        "invalid_artifact_detail"
    } else if text.starts_with("page limit") || text.starts_with("entry cursor") {
        "invalid_page"
    } else {
        "backend_error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactMetadataState, ArtifactValueAvailability, MAX_ARTIFACT_METADATA_BYTES};
    use rusqlite::{params, Connection};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture_path(label: &str) -> PathBuf {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "kdft-desktop-core-{label}-{}-{serial}.sqlite",
            std::process::id()
        ))
    }

    fn fixture() -> Result<PathBuf> {
        let path = fixture_path("case");
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "CREATE TABLE cases(
                 id INTEGER PRIMARY KEY, name TEXT NOT NULL, examiner_name TEXT,
                 case_number TEXT, created_at TEXT NOT NULL
             );
             CREATE TABLE case_options(case_id INTEGER PRIMARY KEY, timezone TEXT NOT NULL);
             CREATE TABLE audit_events(id INTEGER PRIMARY KEY);
             CREATE TABLE evidence_sources(
                 id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL,
                 source_kind TEXT NOT NULL, source_path TEXT NOT NULL,
                 display_name TEXT NOT NULL, attached_at TEXT, indexed_at TEXT,
                 sha256_hex TEXT, hashed_at TEXT, sha256_scope TEXT
             );
             CREATE TABLE evidence_jobs(
                 id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, evidence_id INTEGER,
                 job_type TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT,
                 finished_at TEXT, error TEXT, parser_schema_version TEXT
             );
             CREATE TABLE filesystem_entries(
                 id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL,
                 evidence_id INTEGER NOT NULL, parent_id INTEGER,
                 logical_path TEXT NOT NULL, name TEXT NOT NULL,
                 entry_kind TEXT NOT NULL, size_bytes INTEGER,
                 is_deleted INTEGER NOT NULL, discovered_by_job_id INTEGER,
                 content_head BLOB, metadata_json TEXT
             );
             INSERT INTO cases VALUES(1, 'Fixture', 'Examiner', 'CASE-1', '2026-10-16T00:00:00Z');
             INSERT INTO case_options VALUES(1, 'UTC');
             INSERT INTO audit_events VALUES(7);
             INSERT INTO evidence_sources VALUES(
                 1, 1, 'image', 'C:/fixtures/source.E01', 'Synthetic image',
                 '2026-10-16T00:00:00Z', '2026-10-16T00:10:00Z',
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                 '2026-10-16T00:11:00Z', 'logical_media'
             );
             INSERT INTO evidence_jobs VALUES(
                 10, 1, 1, 'filesystem_index', 'truncated',
                 '2026-10-16T00:00:00Z', '2026-10-16T00:10:00Z', NULL,
                 'filesystem-v1'
             );
             INSERT INTO filesystem_entries VALUES(
                 1, 1, 1, NULL, '/one', 'one', 'file', 10, 0, 10,
                 zeroblob(1048576),
                 '{\"artifact_kind\":\"fixture_record\",\"title\":\"Bounded fixture\",\"created_utc\":\"2026-10-15T23:59:00Z\",\"file_data_decoded_media_offset\":4096,\"file_data_physical_offset\":8192,\"file_data_exact_start\":true,\"physical_offset_basis\":\"recorded decoded-media basis\",\"offset_coordinate_system\":\"decoded_evidence_media_bytes\",\"parser_name\":\"fixture-parser\",\"parser_version\":\"1.2\",\"file_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"file_sha256_input\":\"complete reconstructed file content\",\"file_sha256_at\":\"2026-10-16T00:09:00Z\"}'
             );
             INSERT INTO filesystem_entries VALUES(
                 2, 1, 1, NULL, '/two', 'two', 'file', 20, 0, 10, NULL, '{}'
             );
             INSERT INTO filesystem_entries VALUES(
                 3, 1, 1, NULL, '/three', 'three', 'file', 30, 1, 10, NULL, '{}'
             );",
        )?;
        drop(conn);
        Ok(path)
    }

    #[test]
    fn pages_are_bounded_and_cursors_do_not_repeat_rows() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let first = backend.entry_page(EntryPageQuery {
            evidence_id: Some(1),
            cursor: None,
            limit: Some(2),
        })?;
        assert_eq!(
            first.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(first.coverage.state, CoverageState::Partial);
        assert!(!first.coverage.is_complete);

        let second = backend.entry_page(EntryPageQuery {
            evidence_id: Some(1),
            cursor: first.next_cursor,
            limit: Some(2),
        })?;
        assert_eq!(
            second.items.iter().map(|item| item.id).collect::<Vec<_>>(),
            [3]
        );
        assert!(second.next_cursor.is_none());
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn stale_cursor_is_rejected_instead_of_mixing_generations() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let error = backend
            .entry_page(EntryPageQuery {
                evidence_id: None,
                cursor: Some(EntryCursor {
                    after_id: 1,
                    generation: 6,
                }),
                limit: Some(1),
            })
            .expect_err("stale cursor must fail");
        assert!(error.to_string().contains("stale page cursor"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn artifact_detail_selects_one_exact_id_without_loading_raw_content() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let detail = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 1,
            expected_generation: 7,
        })?;

        assert_eq!(detail.entry_id, 1);
        assert_eq!(detail.evidence_id, 1);
        assert_eq!(detail.display_name, "one");
        assert_eq!(detail.logical_path, "/one");
        assert_eq!(detail.artifact_kind.as_deref(), Some("fixture_record"));
        assert_eq!(detail.metadata_state, ArtifactMetadataState::Parsed);
        assert!(detail
            .fields
            .iter()
            .any(|field| field.name == "title" && field.value == "Bounded fixture"));
        let decoded = detail
            .coordinates
            .iter()
            .find(|coordinate| coordinate.name == "file_data_decoded_media_offset")
            .expect("decoded-media coordinate");
        assert_eq!(decoded.namespace, "decoded_evidence_media");
        assert_eq!(decoded.value.as_deref(), Some("4096"));
        assert!(decoded.exact);
        let legacy = detail
            .coordinates
            .iter()
            .find(|coordinate| coordinate.name == "file_data_physical_offset")
            .expect("legacy coordinate");
        assert!(legacy
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("not asserted to be an E01")));
        assert!(detail
            .hashes
            .iter()
            .any(|hash| hash.label == "Decoded logical-media SHA-256"));
        assert!(detail
            .hashes
            .iter()
            .any(|hash| hash.label == "Complete reconstructed file SHA-256"));
        assert!(!detail.completeness.is_complete);
        assert_eq!(detail.completeness.state, CoverageState::Partial);
        let json = serde_json::to_string(&detail)?;
        assert!(!json.contains("metadata deliberately not projected"));
        assert!(!json.contains("content_head"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn chromium_history_origin_and_profile_provenance_are_visible_in_inspector() -> Result<()> {
        let path = fixture()?;
        let conn = Connection::open(&path)?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = ?1
             WHERE id = 2",
            [serde_json::json!({
                "artifact_kind": "browser_history_visit",
                "url": "https://example.test/",
                "visit_source": 0,
                "visit_source_label": "synced",
                "visit_origin": "remote_synced",
                "browser_profile": "Default",
                "is_known_to_sync": 1,
                "originator_sync_guid_full": "client-guid-1234",
                "originator_sync_guid_note": "Opaque Chromium Sync client cache GUID; not a hardware/device identity.",
                "source_profile_path_exact": "Users/alice/AppData/Local/Google/Chrome/User Data/Default",
                "source_artifact_path_exact": "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History"
            })
            .to_string()],
        )?;
        drop(conn);

        let backend = DesktopBackend::open(&path)?;
        let detail = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 2,
            expected_generation: 7,
        })?;
        let field = |name: &str| {
            detail
                .fields
                .iter()
                .find(|field| field.name == name)
                .map(|field| field.value.as_str())
        };

        assert_eq!(field("visit_origin"), Some("remote_synced"));
        assert_eq!(field("browser_profile"), Some("Default"));
        assert_eq!(field("originator_sync_guid_full"), Some("client-guid-1234"));
        assert_eq!(
            field("source_profile_path_exact"),
            Some("Users/alice/AppData/Local/Google/Chrome/User Data/Default")
        );
        assert!(field("originator_sync_guid_note")
            .is_some_and(|note| note.contains("not a hardware/device identity")));

        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn artifact_detail_rejects_invalid_missing_and_stale_selections() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let invalid = backend
            .artifact_detail(ArtifactDetailQuery {
                entry_id: 0,
                expected_generation: 7,
            })
            .expect_err("non-positive ID must fail");
        assert!(invalid.to_string().contains("must be positive"));

        let missing = backend
            .artifact_detail(ArtifactDetailQuery {
                entry_id: 999,
                expected_generation: 7,
            })
            .expect_err("missing exact ID must fail");
        assert!(missing.to_string().contains("was not found"));

        let stale = backend
            .artifact_detail(ArtifactDetailQuery {
                entry_id: 1,
                expected_generation: 6,
            })
            .expect_err("stale generation must fail");
        assert!(stale.to_string().contains("stale artifact detail"));
        let response = backend.dispatch(BackendCommand::ArtifactDetail {
            query: ArtifactDetailQuery {
                entry_id: 1,
                expected_generation: 6,
            },
        });
        assert!(matches!(
            response,
            BackendResponse::Error { ref code, .. } if code == "stale_artifact_detail"
        ));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn oversized_metadata_is_not_materialized_or_parsed() -> Result<()> {
        let path = fixture()?;
        let oversized = format!(
            "{{\"title\":\"{}\",\"file_data_decoded_media_offset\":0}}",
            "x".repeat(MAX_ARTIFACT_METADATA_BYTES + 128)
        );
        let conn = Connection::open(&path)?;
        conn.execute(
            "UPDATE filesystem_entries SET metadata_json = ?1 WHERE id = 1",
            params![oversized],
        )?;
        drop(conn);

        let backend = DesktopBackend::open(&path)?;
        let detail = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 1,
            expected_generation: 7,
        })?;
        assert_eq!(detail.metadata_state, ArtifactMetadataState::Oversized);
        assert!(detail.fields.is_empty());
        assert!(detail.coordinates.is_empty());
        assert_eq!(
            detail.coordinates_status.state,
            ArtifactValueAvailability::WithheldOversized
        );
        let encoded = serde_json::to_vec(&detail)?;
        assert!(encoded.len() < 100_000);
        assert!(!encoded
            .windows(64)
            .any(|window| window
                == b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn unavailable_null_and_invalid_coordinates_never_become_zero() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let absent = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 2,
            expected_generation: 7,
        })?;
        assert!(absent.coordinates.is_empty());
        assert_eq!(
            absent.coordinates_status.state,
            ArtifactValueAvailability::NotRecorded
        );

        let conn = Connection::open(&path)?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = '{\"file_data_decoded_media_offset\":null,\"registry_key_offset\":-1}'
             WHERE id = 2",
            [],
        )?;
        drop(conn);
        let projected = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 2,
            expected_generation: 7,
        })?;
        let null_coordinate = projected
            .coordinates
            .iter()
            .find(|coordinate| coordinate.name == "file_data_decoded_media_offset")
            .expect("recorded null coordinate");
        assert_eq!(
            null_coordinate.availability,
            ArtifactValueAvailability::RecordedNull
        );
        assert!(null_coordinate.value.is_none());
        let invalid_coordinate = projected
            .coordinates
            .iter()
            .find(|coordinate| coordinate.name == "registry_key_offset")
            .expect("invalid coordinate");
        assert_eq!(
            invalid_coordinate.availability,
            ArtifactValueAvailability::Invalid
        );
        assert_eq!(invalid_coordinate.value.as_deref(), Some("-1"));
        assert!(!projected
            .coordinates
            .iter()
            .any(|coordinate| coordinate.value.as_deref() == Some("0")));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn decrypted_bitlocker_logical_coordinate_forbids_offset_arithmetic() -> Result<()> {
        let path = fixture()?;
        let conn = Connection::open(&path)?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = '{\"file_data_logical_offset\":512,\"offset_coordinate_system\":\"decrypted_bitlocker_volume_logical_bytes\"}'
             WHERE id = 2",
            [],
        )?;
        drop(conn);
        let backend = DesktopBackend::open(&path)?;
        let detail = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 2,
            expected_generation: 7,
        })?;
        let coordinate = detail
            .coordinates
            .iter()
            .find(|coordinate| coordinate.name == "file_data_logical_offset")
            .expect("BitLocker logical coordinate");
        let warning = coordinate.warning.as_deref().unwrap_or_default();
        assert!(warning.contains("must not be added to the encrypted partition start"));
        assert!(warning.contains("no decoded-media/physical mapping is asserted"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn malformed_hash_scope_and_timestamp_are_explicitly_invalid() -> Result<()> {
        let path = fixture()?;
        let conn = Connection::open(&path)?;
        conn.execute(
            "UPDATE evidence_sources SET sha256_scope = 'undefined_scope' WHERE id = 1",
            [],
        )?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = '{\"created_utc\":123,\"file_sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"file_sha256_input\":\"partial prefix\"}'
             WHERE id = 1",
            [],
        )?;
        drop(conn);
        let backend = DesktopBackend::open(&path)?;
        let detail = backend.artifact_detail(ArtifactDetailQuery {
            entry_id: 1,
            expected_generation: 7,
        })?;
        assert_eq!(
            detail.hashes_status.state,
            ArtifactValueAvailability::Invalid
        );
        assert!(detail
            .hashes
            .iter()
            .any(|hash| hash.scope_availability == ArtifactValueAvailability::Invalid));
        assert!(!detail
            .hashes
            .iter()
            .any(|hash| hash.label == "Complete reconstructed file SHA-256"));
        assert_eq!(
            detail.timestamps_status.state,
            ArtifactValueAvailability::Invalid
        );
        assert!(!detail
            .timestamps
            .iter()
            .any(|timestamp| timestamp.semantic_field == "created_utc"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn read_only_backend_cannot_modify_the_case() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let conn = backend.open_read_only()?;
        assert!(conn.execute("DELETE FROM filesystem_entries", []).is_err());
        drop(conn);
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn invalid_or_unbounded_page_size_is_rejected() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        for limit in [0, MAX_PAGE_SIZE + 1] {
            let error = backend
                .entry_page(EntryPageQuery {
                    evidence_id: None,
                    cursor: None,
                    limit: Some(limit),
                })
                .expect_err("invalid limit must fail");
            assert!(error.to_string().contains("page limit"));
        }
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn completed_jobs_do_not_claim_complete_examination_without_a_coverage_plan() {
        let banner = summarize_coverage(vec![JobCoverage {
            id: 1,
            evidence_id: Some(1),
            job_type: "filesystem_index".to_string(),
            status: "completed".to_string(),
            started_at: None,
            finished_at: None,
            has_error: false,
        }]);
        assert_eq!(banner.state, CoverageState::Partial);
        assert!(!banner.is_complete);
        assert!(banner.title.contains("not proven"));
    }

    #[test]
    fn direct_json_dispatch_never_requires_http() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let response = backend.dispatch_json(r#"{"command":"case_summary"}"#);
        assert!(response.contains(r#""response":"case_summary""#));
        assert!(response.contains(r#""name":"Fixture""#));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn ipc_command_size_is_bounded_before_json_parsing() -> Result<()> {
        let path = fixture()?;
        let backend = DesktopBackend::open(&path)?;
        let response = backend.dispatch_json(&"x".repeat(MAX_IPC_COMMAND_BYTES + 1));
        assert!(response.contains(r#""code":"command_too_large""#));
        fs::remove_file(path)?;
        Ok(())
    }
}
