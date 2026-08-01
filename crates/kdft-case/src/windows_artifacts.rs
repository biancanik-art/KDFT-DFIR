//! Post-index parsing for Windows execution and activity artifacts recovered from indexed evidence.
//!
//! Candidate discovery is snapshot-based (`COUNT(*)` plus `MAX(id)`) and keyset-paged. The pass
//! never imposes a default candidate or record coverage cap. Each source is recovered by itself,
//! parsed into a source-scoped SQLite transaction, and then discarded. A successful attempt
//! atomically replaces only rows derived from that source. A failed attempt rolls the replacement
//! transaction back before a separate last-attempt diagnostic is committed, preserving the last
//! known-good derived rows and searchable text segments.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::jumplist::{
    self, DestListMetadata, JumpListContainerKind, JumpListDiagnostic, JumpListLnkMetadata,
    JumpListParseOptions, JumpListSink, JumpListTerminalStatus,
};
use super::lnk::{LnkParseResult, LnkParser, LnkParserOptions, LnkStatus};
use super::prefetch::{PrefetchParser, PrefetchParserOptions, PrefetchStatus};
use super::usn::{
    self, UsnFileReference, UsnParseOptions, UsnRecord, UsnSink, UsnTerminalStatus, UsnVersion,
};
use super::{
    active_case_id, add_entry_category, audit_actor, ensure_evidence_source, evtx_channel_hint,
    evtx_import_entry_from_record, open_existing_case, recover_filesystem_entry_in_session,
    sanitize_logical_segment, source_path_exact_from_metadata, EvidenceReadSession, EvtxParser,
    EvtxParserSettings, RecoverEntryOptions, RecoverEntryResult,
};

const WINDOWS_ARTIFACT_PARSER_NAME: &str = "kdft-windows-artifacts-v1";
const WINDOWS_ARTIFACT_TEXT_PARSER_NAME: &str = "kdft-windows-artifacts-v1";
const CANDIDATE_PAGE_SIZE: i64 = 128;
const DIAGNOSTIC_SAMPLE_LIMIT: usize = 32;
const DIAGNOSTIC_TEXT_BYTES: usize = 2_048;
const TEMPORARY_FILE_CREATE_ATTEMPTS: usize = 1_024;
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const CANDIDATE_FILTER_SQL: &str = r#"
    AND entry_kind = 'file'
    AND COALESCE(json_extract(metadata_json, '$.windows_artifact_derived'), 0) <> 1
    AND (
        lower(name) LIKE '%.lnk'
        OR lower(name) LIKE '%.pf'
        OR lower(name) LIKE '%.evtx'
        OR lower(name) LIKE '%.automaticdestinations-ms'
        OR lower(name) LIKE '%.customdestinations-ms'
        OR lower(name) = '$usnjrnl:$j'
        OR (
            lower(COALESCE(json_extract(metadata_json, '$.ntfs_base_name'), '')) = '$usnjrnl'
            AND lower(COALESCE(json_extract(metadata_json, '$.ntfs_data_stream_name'), '')) = '$j'
        )
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%.lnk'
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%.pf'
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%.evtx'
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%.automaticdestinations-ms'
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%.customdestinations-ms'
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%/$usnjrnl:$j'
        OR lower(replace(COALESCE(
            NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
            NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
            NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
            NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
            NULLIF(json_extract(metadata_json, '$.local_relative_path'), ''),
            logical_path
        ), '\', '/')) LIKE '%/windows/system32/tasks/%'
    )
"#;

// A completed source is an immutable checkpoint for this parser version. Re-running the same
// processor therefore resumes at sources without a committed terminal result instead of deleting
// and regenerating already committed parsed or explicitly-partial records. Re-indexing the
// filesystem deliberately rebuilds the source rows and is the explicit way to force a complete
// parser rerun.
const PENDING_CANDIDATE_FILTER_SQL: &str = r#"
    AND NOT (
        COALESCE(json_extract(
            metadata_json,
            '$.windows_artifact_parser_committed.parser_name'
        ), '') = 'kdft-windows-artifacts-v1'
        AND COALESCE(json_extract(
            metadata_json,
            '$.windows_artifact_parser_committed.status'
        ), '') IN ('parsed', 'partial')
    )
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsArtifactKind {
    ShellLink,
    Prefetch,
    Evtx,
    AutomaticJumpList,
    CustomJumpList,
    UsnJournal,
    ScheduledTask,
}

impl WindowsArtifactKind {
    fn key(self) -> &'static str {
        match self {
            Self::ShellLink => "lnk",
            Self::Prefetch => "prefetch",
            Self::Evtx => "evtx",
            Self::AutomaticJumpList => "automatic_jumplist",
            Self::CustomJumpList => "custom_jumplist",
            Self::UsnJournal => "usn",
            Self::ScheduledTask => "scheduled_task",
        }
    }

    fn staging_suffix(self) -> &'static str {
        match self {
            Self::ShellLink => "lnk",
            Self::Prefetch => "pf",
            Self::Evtx => "evtx",
            Self::AutomaticJumpList => "automaticDestinations-ms",
            Self::CustomJumpList => "customDestinations-ms",
            Self::UsnJournal => "usn-journal",
            Self::ScheduledTask => "task.xml",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WindowsArtifactKindCounts {
    pub candidates_seen: u64,
    pub parsed_sources: u64,
    pub partial_sources: u64,
    pub failed_sources: u64,
    pub derived_entries: u64,
    pub text_segments: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsArtifactDiagnostic {
    pub source_entry_id: Option<i64>,
    pub source_kind: Option<String>,
    pub source_path_exact: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowsArtifactParseResult {
    pub evidence_id: i64,
    pub supported_source_count: u64,
    pub up_to_date_sources_skipped: u64,
    pub reused_partial_sources: u64,
    pub snapshot_candidate_count: u64,
    pub snapshot_max_entry_id: Option<i64>,
    pub candidates_seen: u64,
    pub parsed_sources: u64,
    pub partial_sources: u64,
    pub failed_sources: u64,
    pub derived_entries: u64,
    pub text_segments: u64,
    pub per_kind: BTreeMap<String, WindowsArtifactKindCounts>,
    pub diagnostic_count: u64,
    pub diagnostics: Vec<WindowsArtifactDiagnostic>,
    pub diagnostics_omitted: u64,
    pub snapshot_stable: bool,
    pub default_coverage_cap: Option<u64>,
    pub supported_scope_complete: bool,
    pub safety_bounds: serde_json::Value,
    pub status: String,
}

#[derive(Debug, Clone, Copy)]
struct CandidateSnapshot {
    supported_count: u64,
    reused_partial_count: u64,
    reuse_committed: bool,
    count: u64,
    max_entry_id: Option<i64>,
}

#[derive(Debug, Clone)]
struct WindowsArtifactCandidate {
    entry_id: i64,
    evidence_id: i64,
    source_job_id: Option<i64>,
    logical_path: String,
    name: String,
    source_path_exact: String,
    is_deleted: bool,
    kind: WindowsArtifactKind,
}

#[derive(Debug, Default)]
struct DiagnosticAccumulator {
    total: u64,
    samples: Vec<WindowsArtifactDiagnostic>,
    omitted: u64,
}

impl DiagnosticAccumulator {
    fn push(&mut self, diagnostic: WindowsArtifactDiagnostic) {
        self.total = self.total.saturating_add(1);
        let message = match diagnostic.source_path_exact.as_deref() {
            Some(path) => format!("{path}: {}", diagnostic.message),
            None => diagnostic.message.clone(),
        };
        super::progress::progress_diagnostic(
            super::progress::JobDiagnosticKind::ParserDiagnostic,
            message,
        );
        if self.samples.len() < DIAGNOSTIC_SAMPLE_LIMIT {
            self.samples.push(diagnostic);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    fn absorb_exact(
        &mut self,
        exact_total: u64,
        source_entry_id: i64,
        kind: WindowsArtifactKind,
        source_path_exact: &str,
        samples: impl IntoIterator<Item = String>,
    ) {
        let mut represented = 0_u64;
        for message in samples {
            represented = represented.saturating_add(1);
            if represented > exact_total {
                break;
            }
            self.push(source_diagnostic(
                source_entry_id,
                kind,
                source_path_exact,
                message,
            ));
        }
        let unrepresented = exact_total.saturating_sub(represented.min(exact_total));
        self.total = self.total.saturating_add(unrepresented);
        self.omitted = self.omitted.saturating_add(unrepresented);
    }

    fn merge(&mut self, other: &Self) {
        let available = DIAGNOSTIC_SAMPLE_LIMIT.saturating_sub(self.samples.len());
        let retained = other.samples.len().min(available);
        self.samples
            .extend(other.samples.iter().take(retained).cloned());
        self.total = self.total.saturating_add(other.total);
        self.omitted = self
            .omitted
            .saturating_add(other.total.saturating_sub(retained as u64));
    }
}

#[derive(Debug)]
struct SourceParseSummary {
    partial: bool,
    derived_entries: u64,
    text_segments: u64,
    diagnostics: DiagnosticAccumulator,
    details: serde_json::Value,
}

#[derive(Debug)]
struct StagedSourceOutcome {
    parsed: SourceParseSummary,
    cleanup_warning: Option<String>,
}

#[derive(Debug)]
struct SourceAttemptFailure {
    message: String,
    diagnostic_count: u64,
    diagnostic_samples: Vec<String>,
    diagnostics_omitted: u64,
    details: serde_json::Value,
}

impl SourceAttemptFailure {
    fn new(
        message: impl Into<String>,
        inner_diagnostic_count: u64,
        inner_samples: impl IntoIterator<Item = String>,
        details: serde_json::Value,
    ) -> Self {
        let message = bounded_text(&message.into(), DIAGNOSTIC_TEXT_BYTES);
        let diagnostic_count = inner_diagnostic_count.saturating_add(1);
        let mut diagnostic_samples = Vec::with_capacity(DIAGNOSTIC_SAMPLE_LIMIT);
        diagnostic_samples.push(message.clone());
        let retained_inner_limit = usize::try_from(inner_diagnostic_count)
            .unwrap_or(usize::MAX)
            .min(DIAGNOSTIC_SAMPLE_LIMIT.saturating_sub(1));
        for sample in inner_samples.into_iter().take(retained_inner_limit) {
            diagnostic_samples.push(bounded_text(&sample, DIAGNOSTIC_TEXT_BYTES));
        }
        let diagnostics_omitted = diagnostic_count.saturating_sub(diagnostic_samples.len() as u64);
        Self {
            message,
            diagnostic_count,
            diagnostic_samples,
            diagnostics_omitted,
            details,
        }
    }
}

impl std::fmt::Display for SourceAttemptFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SourceAttemptFailure {}

fn diagnostics_for_failed_attempt(
    candidate: &WindowsArtifactCandidate,
    error: &anyhow::Error,
    fallback_message: &str,
) -> DiagnosticAccumulator {
    let mut diagnostics = DiagnosticAccumulator::default();
    if let Some(failure) = error.downcast_ref::<SourceAttemptFailure>() {
        debug_assert_eq!(
            failure.diagnostic_count,
            (failure.diagnostic_samples.len() as u64).saturating_add(failure.diagnostics_omitted)
        );
        diagnostics.absorb_exact(
            failure.diagnostic_count,
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            failure.diagnostic_samples.iter().cloned(),
        );
    } else {
        diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            fallback_message.to_string(),
        ));
    }
    diagnostics
}

/// Parse supported recoverable Windows artifacts already present in one evidence index.
///
/// The genuine candidate denominator is captured once. Rows are then read in bounded keyset pages
/// up to that maximum id, preventing both an unbounded candidate vector and inclusion of derived
/// rows created by this pass.
pub fn parse_windows_artifacts(
    case_path: &Path,
    evidence_id: i64,
) -> Result<WindowsArtifactParseResult> {
    let snapshot = candidate_snapshot(case_path, evidence_id)?;
    super::progress::progress_set_unit("Windows artifact sources");
    super::progress::progress_set_total(Some(snapshot.count));

    let mut result = WindowsArtifactParseResult {
        evidence_id,
        supported_source_count: snapshot.supported_count,
        up_to_date_sources_skipped: snapshot.supported_count.saturating_sub(snapshot.count),
        reused_partial_sources: snapshot.reused_partial_count,
        snapshot_candidate_count: snapshot.count,
        snapshot_max_entry_id: snapshot.max_entry_id,
        candidates_seen: 0,
        parsed_sources: 0,
        partial_sources: 0,
        failed_sources: 0,
        derived_entries: 0,
        text_segments: 0,
        per_kind: BTreeMap::new(),
        diagnostic_count: 0,
        diagnostics: Vec::new(),
        diagnostics_omitted: 0,
        snapshot_stable: true,
        default_coverage_cap: None,
        supported_scope_complete: true,
        safety_bounds: pass_safety_bounds(),
        status: "completed".to_string(),
    };
    let mut diagnostics = DiagnosticAccumulator::default();
    let mut after_entry_id = i64::MIN;
    // Keep the decoded evidence container and its EWF chunk cache alive for
    // the complete pass. Previously every LNK/Prefetch/EVTX recovery rebuilt
    // the E01 chunk table, and large files repeated that work per 64 KiB.
    let mut read_session = EvidenceReadSession::open(case_path)?;

    if let Some(max_entry_id) = snapshot.max_entry_id {
        loop {
            let candidates = candidate_page(
                case_path,
                evidence_id,
                after_entry_id,
                max_entry_id,
                CANDIDATE_PAGE_SIZE,
                snapshot.reuse_committed,
            )?;
            if candidates.is_empty() {
                break;
            }
            for candidate in candidates {
                after_entry_id = candidate.entry_id;
                result.candidates_seen = result.candidates_seen.saturating_add(1);
                let kind_key = candidate.kind.key().to_string();
                let kind_counts = result.per_kind.entry(kind_key).or_default();
                kind_counts.candidates_seen = kind_counts.candidates_seen.saturating_add(1);
                super::progress::progress_current(candidate.source_path_exact.clone());

                match parse_one_source(case_path, &mut read_session, &candidate) {
                    Ok(outcome) => {
                        let summary = outcome.parsed;
                        result.parsed_sources = result.parsed_sources.saturating_add(1);
                        kind_counts.parsed_sources = kind_counts.parsed_sources.saturating_add(1);
                        result.derived_entries = result
                            .derived_entries
                            .saturating_add(summary.derived_entries);
                        result.text_segments =
                            result.text_segments.saturating_add(summary.text_segments);
                        kind_counts.derived_entries = kind_counts
                            .derived_entries
                            .saturating_add(summary.derived_entries);
                        kind_counts.text_segments = kind_counts
                            .text_segments
                            .saturating_add(summary.text_segments);
                        if summary.partial {
                            result.partial_sources = result.partial_sources.saturating_add(1);
                            kind_counts.partial_sources =
                                kind_counts.partial_sources.saturating_add(1);
                            super::progress::progress_truncated(format!(
                                "{} source {} was parsed with explicitly disclosed partial coverage",
                                candidate.kind.key(), candidate.source_path_exact
                            ));
                        }
                        diagnostics.merge(&summary.diagnostics);
                        if let Some(warning) = outcome.cleanup_warning {
                            diagnostics.push(source_diagnostic(
                                candidate.entry_id,
                                candidate.kind,
                                &candidate.source_path_exact,
                                warning,
                            ));
                        }
                    }
                    Err(error) => {
                        let message = format!(
                            "{} (entry {}): {error:#}",
                            candidate.source_path_exact, candidate.entry_id
                        );
                        let failure_diagnostics =
                            diagnostics_for_failed_attempt(&candidate, &error, &message);
                        persist_failed_attempt(
                            case_path,
                            &candidate,
                            &error,
                            &failure_diagnostics,
                        )?;
                        result.failed_sources = result.failed_sources.saturating_add(1);
                        kind_counts.failed_sources = kind_counts.failed_sources.saturating_add(1);
                        diagnostics.merge(&failure_diagnostics);
                        super::progress::progress_error(Some(candidate.source_path_exact.clone()));
                        super::progress::progress_skip(Some(candidate.source_path_exact.clone()));
                        super::progress::progress_truncated(format!(
                            "{} source {} failed; the prior committed derived rows were preserved",
                            candidate.kind.key(),
                            candidate.source_path_exact
                        ));
                    }
                }
                super::progress::progress_advance(candidate.source_path_exact.clone());
            }
        }
    }

    if result.candidates_seen != snapshot.count {
        result.snapshot_stable = false;
        diagnostics.push(WindowsArtifactDiagnostic {
            source_entry_id: None,
            source_kind: None,
            source_path_exact: None,
            message: bounded_text(
                &format!(
                    "Windows artifact snapshot contained {} candidate(s), but bounded keyset paging observed {}; the evidence index changed during parsing",
                    snapshot.count, result.candidates_seen
                ),
                DIAGNOSTIC_TEXT_BYTES,
            ),
        });
    }

    result.diagnostic_count = diagnostics.total;
    result.diagnostics = diagnostics.samples;
    result.diagnostics_omitted = diagnostics.omitted;
    result.supported_scope_complete = result.snapshot_stable
        && result.partial_sources == 0
        && result.reused_partial_sources == 0
        && result.failed_sources == 0
        && result.diagnostic_count == 0;
    result.status = if result.supported_scope_complete {
        "completed".to_string()
    } else {
        "truncated".to_string()
    };
    persist_pass_audit(case_path, &result)?;
    Ok(result)
}

fn candidate_snapshot(case_path: &Path, evidence_id: i64) -> Result<CandidateSnapshot> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, evidence_id)?;
    let source_kind: String = conn.query_row(
        "SELECT source_kind FROM evidence_sources WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
        |row| row.get(0),
    )?;
    candidate_snapshot_conn(&conn, case_id, evidence_id, source_kind == "image")
}

fn candidate_snapshot_conn(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    reuse_committed: bool,
) -> Result<CandidateSnapshot> {
    let supported_sql = format!(
        "SELECT COUNT(*) FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2 {CANDIDATE_FILTER_SQL}"
    );
    let supported_count: i64 =
        conn.query_row(&supported_sql, params![case_id, evidence_id], |row| {
            row.get(0)
        })?;
    let supported_count = u64::try_from(supported_count)
        .context("Windows artifact supported source count is negative")?;
    let reused_partial_sql = format!(
        "SELECT COUNT(*) FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2 {CANDIDATE_FILTER_SQL}
           AND json_extract(metadata_json, '$.windows_artifact_parser_committed.parser_name') = ?3
           AND json_extract(metadata_json, '$.windows_artifact_parser_committed.status') = 'partial'"
    );
    let reused_partial_count: i64 = if reuse_committed {
        conn.query_row(
            &reused_partial_sql,
            params![case_id, evidence_id, WINDOWS_ARTIFACT_PARSER_NAME],
            |row| row.get(0),
        )?
    } else {
        0
    };
    let reused_partial_count = u64::try_from(reused_partial_count)
        .context("Windows artifact reused partial source count is negative")?;
    let pending_filter = if reuse_committed {
        PENDING_CANDIDATE_FILTER_SQL
    } else {
        ""
    };
    let sql = format!(
        "SELECT COUNT(*), MAX(id) FROM filesystem_entries WHERE case_id = ?1 AND evidence_id = ?2 {CANDIDATE_FILTER_SQL} {pending_filter}"
    );
    let (count, max_entry_id): (i64, Option<i64>) =
        conn.query_row(&sql, params![case_id, evidence_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let count = u64::try_from(count).context("Windows artifact candidate count is negative")?;
    if (count == 0) != max_entry_id.is_none() {
        bail!("Windows artifact candidate count and maximum entry id are inconsistent");
    }
    Ok(CandidateSnapshot {
        supported_count,
        reused_partial_count,
        reuse_committed,
        count,
        max_entry_id,
    })
}

fn candidate_page(
    case_path: &Path,
    evidence_id: i64,
    after_entry_id: i64,
    max_entry_id: i64,
    page_size: i64,
    reuse_committed: bool,
) -> Result<Vec<WindowsArtifactCandidate>> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    candidate_page_conn(
        &conn,
        case_id,
        evidence_id,
        after_entry_id,
        max_entry_id,
        page_size,
        reuse_committed,
    )
}

fn candidate_page_conn(
    conn: &Connection,
    case_id: i64,
    evidence_id: i64,
    after_entry_id: i64,
    max_entry_id: i64,
    page_size: i64,
    reuse_committed: bool,
) -> Result<Vec<WindowsArtifactCandidate>> {
    if page_size <= 0 || page_size > CANDIDATE_PAGE_SIZE {
        bail!("Windows artifact candidate page size must be in 1..={CANDIDATE_PAGE_SIZE}");
    }
    let pending_filter = if reuse_committed {
        PENDING_CANDIDATE_FILTER_SQL
    } else {
        ""
    };
    let sql = format!(
        "SELECT id, discovered_by_job_id, logical_path, name, metadata_json, is_deleted
         FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND id > ?3 AND id <= ?4
           {CANDIDATE_FILTER_SQL}
           {pending_filter}
         ORDER BY id
         LIMIT ?5"
    );
    let raw_rows = {
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                case_id,
                evidence_id,
                after_entry_id,
                max_entry_id,
                page_size
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };

    raw_rows
        .into_iter()
        .map(
            |(entry_id, source_job_id, logical_path, name, metadata_text, is_deleted)| {
                let metadata: serde_json::Value = serde_json::from_str(&metadata_text)
                    .with_context(|| format!("parsing metadata for source entry {entry_id}"))?;
                let source_path_exact = source_path_exact_from_metadata(&metadata)
                    .unwrap_or_else(|| logical_path.clone());
                let kind = classify_windows_source(&name, &source_path_exact, &metadata)
                    .with_context(|| {
                        format!(
                            "candidate query selected unsupported source entry {entry_id}: {source_path_exact}"
                        )
                    })?;
                Ok(WindowsArtifactCandidate {
                    entry_id,
                    evidence_id,
                    source_job_id,
                    logical_path,
                    name,
                    source_path_exact,
                    is_deleted,
                    kind,
                })
            },
        )
        .collect()
}

fn classify_windows_source(
    name: &str,
    source_path_exact: &str,
    metadata: &serde_json::Value,
) -> Option<WindowsArtifactKind> {
    let name = name.to_ascii_lowercase();
    let path = source_path_exact.replace('\\', "/").to_ascii_lowercase();
    let base_name = metadata
        .get("ntfs_base_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let stream_name = metadata
        .get("ntfs_data_stream_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();

    if path.contains("/windows/system32/tasks/") {
        Some(WindowsArtifactKind::ScheduledTask)
    } else if name.ends_with(".automaticdestinations-ms")
        || path.ends_with(".automaticdestinations-ms")
    {
        Some(WindowsArtifactKind::AutomaticJumpList)
    } else if name.ends_with(".customdestinations-ms") || path.ends_with(".customdestinations-ms") {
        Some(WindowsArtifactKind::CustomJumpList)
    } else if name.ends_with(".lnk") || path.ends_with(".lnk") {
        Some(WindowsArtifactKind::ShellLink)
    } else if name.ends_with(".pf") || path.ends_with(".pf") {
        Some(WindowsArtifactKind::Prefetch)
    } else if name.ends_with(".evtx") || path.ends_with(".evtx") {
        Some(WindowsArtifactKind::Evtx)
    } else if name == "$usnjrnl:$j"
        || path.ends_with("/$usnjrnl:$j")
        || (base_name == "$usnjrnl" && stream_name == "$j")
    {
        Some(WindowsArtifactKind::UsnJournal)
    } else {
        None
    }
}

fn pass_safety_bounds() -> serde_json::Value {
    let lnk = LnkParserOptions::default();
    // Use Default rather than listing fields so the parser's MAM decompression safety extensions
    // remain source compatible while their exact active values are recorded by parser output.
    let prefetch = PrefetchParserOptions::default();
    let usn = UsnParseOptions::default();
    let jump = JumpListParseOptions::default();
    serde_json::json!({
        "default_coverage_cap": null,
        "candidate_snapshot": "exact COUNT(*) plus MAX(id) over the supported source predicate",
        "resume_checkpoint": "sources successfully committed by this parser version are skipped; partial and failed sources remain pending; filesystem re-indexing forces a complete rerun",
        "candidate_page_rows": CANDIDATE_PAGE_SIZE,
        "source_recovery": "one indexed source at a time, including deleted entries when their indexed recovery metadata remains usable; no source-size coverage cap",
        "lnk_max_file_size_bytes": lnk.max_file_size,
        "prefetch_max_file_size_bytes": prefetch.max_file_size,
        "prefetch_max_decompressed_size_bytes": prefetch.max_decompressed_size,
        "evtx": "records streamed one at a time with no record-count cap",
        "usn_max_record_bytes": usn.max_record_bytes,
        "usn_max_filename_bytes": usn.max_filename_bytes,
        "usn_diagnostic_sample_limit": usn.diagnostic_sample_limit,
        "jumplist_io_buffer_bytes": jump.io_buffer_bytes,
        "jumplist_diagnostic_sample_limit": jump.diagnostic_sample_limit,
        "jumplist_embedded_lnk_spooling": "one embedded LNK temporary file at a time",
        "scheduled_task_max_source_bytes": 16 * 1024 * 1024,
        "pass_diagnostic_sample_limit": DIAGNOSTIC_SAMPLE_LIMIT,
    })
}

fn source_supported_scope(kind: WindowsArtifactKind) -> &'static str {
    match kind {
        WindowsArtifactKind::ShellLink => {
            "One indexed, recoverable Shell Link source parsed by the bounded KDFT LNK parser; unsupported or malformed structures are disclosed by status and exact warning counters"
        }
        WindowsArtifactKind::Prefetch => {
            "One indexed, recoverable Windows Prefetch source parsed by the bounded KDFT Prefetch parser; parser-declared compression/version limitations remain explicit"
        }
        WindowsArtifactKind::Evtx => {
            "All records yielded by evtx 0.12.2 are streamed; unreadable records are counted exactly and sampled diagnostics are bounded; ETL and provider message-template expansion are outside scope"
        }
        WindowsArtifactKind::AutomaticJumpList => {
            "Indexed, recoverable CFB streams and DestList summary supported by the KDFT AutomaticDestinations parser; every emitted embedded LNK is parsed through one bounded temporary spool"
        }
        WindowsArtifactKind::CustomJumpList => {
            "All signatures found by the KDFT CustomDestinations streaming parser; heuristic boundaries and damaged/omitted payloads are explicitly partial"
        }
        WindowsArtifactKind::UsnJournal => {
            "The complete recovered $UsnJrnl:$J byte stream is parsed incrementally for USN V2/V3; unsupported V4/unknown versions and damaged records are counted explicitly"
        }
        WindowsArtifactKind::ScheduledTask => {
            "One indexed, recoverable Windows Task Scheduler XML definition; registration, principals, settings, triggers, and actions are decoded without executing the task"
        }
    }
}

fn parse_one_source(
    case_path: &Path,
    read_session: &mut EvidenceReadSession,
    candidate: &WindowsArtifactCandidate,
) -> Result<StagedSourceOutcome> {
    let (staging_directory, staging_path) = create_unique_recovery_destination(
        "kdft-windows-source",
        candidate.entry_id,
        candidate.kind.staging_suffix(),
    )?;
    let parsed = (|| -> Result<SourceParseSummary> {
        let recovery = recover_filesystem_entry_in_session(
            read_session,
            RecoverEntryOptions {
                entry_id: candidate.entry_id,
                output_path: staging_path.clone(),
            },
        )
        .with_context(|| {
            format!(
                "recovering {} source {}",
                candidate.kind.key(),
                candidate.source_path_exact
            )
        })?;
        replace_source_transaction(case_path, candidate, &staging_path, &recovery).with_context(
            || {
                format!(
                    "parsing recovered source after status {:?} wrote {} of {} byte(s)",
                    recovery.status, recovery.bytes_written, recovery.total_size
                )
            },
        )
    })();

    let file_cleanup = if staging_path.exists() {
        fs::remove_file(&staging_path).with_context(|| {
            format!(
                "removing temporary {} source {}",
                candidate.kind.key(),
                staging_path.display()
            )
        })
    } else {
        Ok(())
    };
    let directory_cleanup = fs::remove_dir(&staging_directory).with_context(|| {
        format!(
            "removing temporary {} source directory {}",
            candidate.kind.key(),
            staging_directory.display()
        )
    });
    let cleanup = file_cleanup.and(directory_cleanup);

    match (parsed, cleanup) {
        (Ok(parsed), Ok(())) => Ok(StagedSourceOutcome {
            parsed,
            cleanup_warning: None,
        }),
        (Ok(parsed), Err(cleanup_error)) => Ok(StagedSourceOutcome {
            parsed,
            cleanup_warning: Some(format!(
                "{} parsed successfully, but its temporary source could not be removed: {cleanup_error:#}",
                candidate.source_path_exact
            )),
        }),
        (Err(parse_error), Ok(())) => Err(parse_error),
        (Err(parse_error), Err(cleanup_error)) => Err(parse_error.context(format!(
            "temporary source cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

/// Reserve a private, collision-safe directory and return a destination path
/// that does not yet exist. Recovery uses `AtomicOutput`, so pre-creating the
/// destination would correctly be treated as an overwrite attempt.
fn create_unique_recovery_destination(
    prefix: &str,
    entry_id: i64,
    suffix: &str,
) -> Result<(PathBuf, PathBuf)> {
    let temporary_root = std::env::temp_dir();
    for _ in 0..TEMPORARY_FILE_CREATE_ATTEMPTS {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = temporary_root.join(format!(
            "{prefix}-{}-{entry_id}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&directory) {
            Ok(()) => {
                let destination = directory.join(format!("source.{suffix}"));
                return Ok((directory, destination));
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "creating collision-safe temporary directory {}",
                        directory.display()
                    )
                });
            }
        }
    }
    bail!(
        "could not reserve a collision-safe temporary directory after {} attempts",
        TEMPORARY_FILE_CREATE_ATTEMPTS
    )
}

fn replace_source_transaction(
    case_path: &Path,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
    recovery: &RecoverEntryResult,
) -> Result<SourceParseSummary> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    ensure_evidence_source(&conn, case_id, candidate.evidence_id)?;
    let actor = audit_actor(&conn, case_id)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (previous_entries, previous_segments) = source_derived_counts(&tx, candidate.entry_id)?;
    delete_source_derived(&tx, case_id, candidate.evidence_id, candidate.entry_id)?;

    let mut summary = match candidate.kind {
        WindowsArtifactKind::ShellLink => parse_lnk_source(&tx, candidate, staging_path)?,
        WindowsArtifactKind::Prefetch => parse_prefetch_source(&tx, candidate, staging_path)?,
        WindowsArtifactKind::Evtx => parse_evtx_source(&tx, candidate, staging_path)?,
        WindowsArtifactKind::AutomaticJumpList | WindowsArtifactKind::CustomJumpList => {
            parse_jumplist_source(&tx, candidate, staging_path)?
        }
        WindowsArtifactKind::UsnJournal => parse_usn_source(&tx, candidate, staging_path)?,
        WindowsArtifactKind::ScheduledTask => {
            parse_scheduled_task_source(&tx, candidate, staging_path)?
        }
    };

    let recovery_complete =
        recovery.status == "completed" && recovery.bytes_written == recovery.total_size;
    if !recovery_complete {
        summary.partial = true;
        summary.diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            format!(
                "source recovery returned status {:?} after writing {} of {} byte(s)",
                recovery.status, recovery.bytes_written, recovery.total_size
            ),
        ));
    }
    let details = summary
        .details
        .as_object_mut()
        .context("Windows artifact source details must be a JSON object")?;
    details.insert(
        "source_recovery".to_string(),
        serde_json::json!({
            "status": recovery.status,
            "bytes_written": recovery.bytes_written,
            "total_size": recovery.total_size,
            "complete": recovery_complete,
            "source_is_deleted": candidate.is_deleted,
        }),
    );

    let committed = committed_source_metadata(candidate, &summary);
    let updated = tx.execute(
        "UPDATE filesystem_entries
         SET metadata_json = json_set(
             metadata_json,
             '$.windows_artifact_parser_committed', json(?2),
             '$.windows_artifact_parser_last_attempt', json(?2)
         )
         WHERE case_id = ?3 AND evidence_id = ?4 AND id = ?1",
        params![
            candidate.entry_id,
            committed.to_string(),
            case_id,
            candidate.evidence_id
        ],
    )?;
    if updated != 1 {
        bail!(
            "Windows artifact source entry {} disappeared before replacement commit",
            candidate.entry_id
        );
    }
    let audit_details = serde_json::json!({
        "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
        "source_entry_id": candidate.entry_id,
        "source_kind": candidate.kind,
        "source_name_exact": candidate.name,
        "source_logical_path_exact": candidate.logical_path,
        "source_path_exact": candidate.source_path_exact,
        "source_is_deleted": candidate.is_deleted,
        "previous_derived_entries_replaced": previous_entries,
        "previous_text_segments_replaced": previous_segments,
        "derived_entries": summary.derived_entries,
        "text_segments": summary.text_segments,
        "partial": summary.partial,
        "diagnostic_count": summary.diagnostics.total,
        "diagnostics_omitted": summary.diagnostics.omitted,
        "replacement_committed": true,
    });
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.windows_artifact_source_replaced', ?2,
                 'filesystem_entry', ?3, ?4)",
        params![
            case_id,
            actor,
            candidate.entry_id,
            audit_details.to_string()
        ],
    )?;
    tx.commit()?;
    Ok(summary)
}

fn create_unique_temporary_file(
    prefix: &str,
    entry_id: i64,
    suffix: &str,
) -> Result<(PathBuf, File)> {
    let temporary_root = std::env::temp_dir();
    for _ in 0..TEMPORARY_FILE_CREATE_ATTEMPTS {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = temporary_root.join(format!(
            "{prefix}-{}-{entry_id}-{sequence}.{suffix}",
            std::process::id()
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("creating collision-safe temporary file {}", path.display())
                });
            }
        }
    }
    bail!(
        "could not reserve a collision-safe temporary file after {} attempts",
        TEMPORARY_FILE_CREATE_ATTEMPTS
    )
}

fn parse_scheduled_task_source(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
) -> Result<SourceParseSummary> {
    const MAX_TASK_BYTES: u64 = 16 * 1024 * 1024;
    let source_size = fs::metadata(staging_path)
        .with_context(|| {
            format!(
                "reading staged scheduled-task metadata {}",
                candidate.source_path_exact
            )
        })?
        .len();
    if source_size > MAX_TASK_BYTES {
        bail!(
            "scheduled-task XML source is {} bytes; safety limit is {} bytes",
            source_size,
            MAX_TASK_BYTES
        );
    }
    let file = File::open(staging_path).with_context(|| {
        format!(
            "opening staged scheduled task {}",
            candidate.source_path_exact
        )
    })?;
    let parsed =
        super::scheduled_task::parse_scheduled_task(BufReader::new(file)).with_context(|| {
            format!(
                "parsing Windows scheduled task {}",
                candidate.source_path_exact
            )
        })?;
    let task_uri = parsed.registration.get("uri").cloned();
    let author = parsed.registration.get("author").cloned();
    let registration_date = parsed.registration.get("date").cloned();
    let principal_user = parsed
        .principals
        .iter()
        .find_map(|principal| principal.get("userid").or_else(|| principal.get("groupid")))
        .cloned();
    let principal_logon_type = parsed
        .principals
        .iter()
        .find_map(|principal| principal.get("logontype"))
        .cloned();
    let primary_exec = parsed
        .actions
        .iter()
        .find(|action| action.get("type").is_some_and(|kind| kind == "exec"));
    let action_command = primary_exec
        .and_then(|action| action.get("command"))
        .cloned();
    let action_arguments = primary_exec
        .and_then(|action| action.get("arguments"))
        .cloned();
    let display_name = task_uri
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| candidate.name.clone());
    let logical_path = derived_logical_path(candidate, "scheduled-task", 1, &display_name);
    let metadata = serde_json::json!({
        "artifact_kind": "windows_scheduled_task",
        "parser": WINDOWS_ARTIFACT_PARSER_NAME,
        "supported_scope": source_supported_scope(candidate.kind),
        "task_uri": task_uri,
        "task_author": author,
        "task_registration_date": registration_date,
        "artifact_time_utc": parsed.registration.get("date"),
        "task_principal": principal_user,
        "task_logon_type": principal_logon_type,
        "task_enabled": parsed.settings.get("enabled"),
        "task_hidden": parsed.settings.get("hidden"),
        "task_action_command": action_command,
        "task_action_arguments": action_arguments,
        "task_version": parsed.task_version,
        "task_registration": parsed.registration,
        "task_principals": parsed.principals,
        "task_settings": parsed.settings,
        "task_triggers": parsed.triggers,
        "task_actions": parsed.actions,
    });
    let search_text = serde_json::to_string(&metadata)
        .context("serializing scheduled-task searchable metadata")?;
    insert_derived_entry(
        tx,
        candidate,
        &logical_path,
        &display_name,
        "record",
        metadata,
        &search_text,
    )?;
    Ok(SourceParseSummary {
        partial: false,
        derived_entries: 1,
        text_segments: 1,
        diagnostics: DiagnosticAccumulator::default(),
        details: serde_json::json!({
            "task_source_bytes": source_size,
            "task_principal_count": parsed.principals.len(),
            "task_trigger_count": parsed.triggers.len(),
            "task_action_count": parsed.actions.len(),
            "task_default_coverage_cap": null,
        }),
    })
}

fn parse_lnk_source(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
) -> Result<SourceParseSummary> {
    let mut file = File::open(staging_path)
        .with_context(|| format!("opening staged LNK {}", candidate.source_path_exact))?;
    let options = LnkParserOptions::default();
    let parsed = LnkParser::parse_reader(&mut file, &options);
    let exact_warning_count =
        (parsed.warnings.len() as u64).saturating_add(parsed.warnings_omitted);
    if parsed.status == LnkStatus::Failed {
        let message = format!(
            "LNK parser rejected source: {}",
            parsed
                .warnings
                .first()
                .map(String::as_str)
                .unwrap_or("unknown parser failure")
        );
        return Err(anyhow::Error::new(SourceAttemptFailure::new(
            message,
            exact_warning_count,
            parsed.warnings.iter().cloned(),
            serde_json::json!({
                "lnk_status": lnk_status_name(parsed.status),
                "lnk_is_valid": parsed.is_valid,
                "lnk_warning_count": exact_warning_count,
                "lnk_warnings_omitted": parsed.warnings_omitted,
                "lnk_extra_blocks_omitted": parsed.extra_blocks_omitted,
            }),
        )));
    }

    let mut diagnostics = DiagnosticAccumulator::default();
    diagnostics.absorb_exact(
        exact_warning_count,
        candidate.entry_id,
        candidate.kind,
        &candidate.source_path_exact,
        parsed.warnings.iter().cloned(),
    );
    let partial = parsed.status == LnkStatus::Partial || !parsed.is_valid;
    if partial && diagnostics.total == 0 {
        diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            "LNK parser reported partial coverage without a retained warning".to_string(),
        ));
    }

    let parsed_json = serde_json::to_value(&parsed).context("serializing LNK parse result")?;
    let search_text = serde_json::to_string(&parsed).context("rendering searchable LNK text")?;
    let metadata = serde_json::json!({
        "artifact_kind": "windows_shell_link_record",
        "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
        "parser_status": if partial { "partial" } else { "parsed" },
        "supported_scope_complete": !partial,
        "supported_scope": source_supported_scope(candidate.kind),
        "safety_bounds": { "max_file_size_bytes": options.max_file_size },
        "lnk": parsed_json,
    });
    let logical_path = derived_logical_path(candidate, "lnk", 1, "shortcut");
    insert_derived_entry(
        tx,
        candidate,
        &logical_path,
        &format!("{} parsed Shell Link", candidate.name),
        "record",
        metadata,
        &search_text,
    )?;

    Ok(SourceParseSummary {
        partial,
        derived_entries: 1,
        text_segments: 1,
        diagnostics,
        details: serde_json::json!({
            "lnk_status": lnk_status_name(parsed.status),
            "lnk_is_valid": parsed.is_valid,
            "lnk_warning_count": exact_warning_count,
            "lnk_warnings_omitted": parsed.warnings_omitted,
            "lnk_extra_blocks_omitted": parsed.extra_blocks_omitted,
        }),
    })
}

fn parse_prefetch_source(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
) -> Result<SourceParseSummary> {
    let mut file = File::open(staging_path)
        .with_context(|| format!("opening staged Prefetch {}", candidate.source_path_exact))?;
    // Default construction deliberately tolerates additional parser safety fields (for example
    // bounded MAM decompression settings) without this adapter silently overriding them.
    let options = PrefetchParserOptions::default();
    let parsed = PrefetchParser::parse_reader(&mut file, &options);
    let exact_warning_count =
        (parsed.warnings.len() as u64).saturating_add(parsed.warnings_omitted);
    // Header-bearing structural damage still contains useful execution metadata. Preserve it as
    // an explicitly partial result; only a result without a parseable Prefetch payload is fatal.
    if parsed.header.is_none() {
        let message = format!(
            "Prefetch parser produced no parseable payload with status {}: {}",
            prefetch_status_name(&parsed.status),
            parsed
                .warnings
                .first()
                .map(String::as_str)
                .unwrap_or("no diagnostic")
        );
        return Err(anyhow::Error::new(SourceAttemptFailure::new(
            message,
            exact_warning_count,
            parsed.warnings.iter().cloned(),
            serde_json::json!({
                "prefetch_status": prefetch_status_name(&parsed.status),
                "prefetch_is_complete": parsed.is_complete,
                "prefetch_is_mam_compressed": parsed.is_mam_compressed,
                "prefetch_mam_uncompressed_size": parsed.mam_uncompressed_size,
                "prefetch_warning_count": exact_warning_count,
                "prefetch_warnings_omitted": parsed.warnings_omitted,
                "prefetch_parseable_payload": false,
            }),
        )));
    }

    let mut diagnostics = DiagnosticAccumulator::default();
    diagnostics.absorb_exact(
        exact_warning_count,
        candidate.entry_id,
        candidate.kind,
        &candidate.source_path_exact,
        parsed.warnings.iter().cloned(),
    );
    let partial = !matches!(parsed.status, PrefetchStatus::Success) || !parsed.is_complete;
    if partial && diagnostics.total == 0 {
        diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            format!(
                "Prefetch parser reported {} with incomplete supported scope",
                prefetch_status_name(&parsed.status)
            ),
        ));
    }

    let parsed_json = serde_json::to_value(&parsed).context("serializing Prefetch parse result")?;
    let search_text =
        serde_json::to_string(&parsed).context("rendering searchable Prefetch text")?;
    let metadata = serde_json::json!({
        "artifact_kind": "windows_prefetch_record",
        "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
        "parser_status": if partial { "partial" } else { "parsed" },
        "supported_scope_complete": !partial,
        "supported_scope": source_supported_scope(candidate.kind),
        "safety_bounds": {
            "max_file_size_bytes": options.max_file_size,
            "max_decompressed_size_bytes": options.max_decompressed_size,
        },
        "prefetch": parsed_json,
    });
    let logical_path = derived_logical_path(candidate, "prefetch", 1, "execution");
    let display_name = parsed
        .header
        .as_ref()
        .map(|header| format!("{} Prefetch execution", header.executable_name))
        .unwrap_or_else(|| format!("{} parsed Prefetch", candidate.name));
    insert_derived_entry(
        tx,
        candidate,
        &logical_path,
        &display_name,
        "record",
        metadata,
        &search_text,
    )?;

    Ok(SourceParseSummary {
        partial,
        derived_entries: 1,
        text_segments: 1,
        diagnostics,
        details: serde_json::json!({
            "prefetch_status": prefetch_status_name(&parsed.status),
            "prefetch_is_complete": parsed.is_complete,
            "prefetch_warning_count": exact_warning_count,
            "prefetch_warnings_omitted": parsed.warnings_omitted,
            "prefetch_total_referenced_files": parsed.total_referenced_files,
            "prefetch_total_volumes": parsed.total_volumes,
        }),
    })
}

fn parse_evtx_source(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
) -> Result<SourceParseSummary> {
    let mut parser = EvtxParser::from_path(staging_path)
        .with_context(|| format!("opening staged EVTX {}", candidate.source_path_exact))?
        .with_configuration(EvtxParserSettings::new().indent(false));
    let root = format!("/Windows Artifacts/{}/evtx", candidate.entry_id);
    let channel_hint = evtx_channel_hint(&candidate.name);
    let mut records_seen = 0_u64;
    let mut recognized_records = 0_u64;
    let mut partial_records = 0_u64;
    let mut failed_records = 0_u64;
    let mut derived_entries = 0_u64;
    let mut text_segments = 0_u64;
    let mut diagnostics = DiagnosticAccumulator::default();

    for record in parser.records_json_value() {
        records_seen = records_seen.saturating_add(1);
        match record {
            Ok(record) => {
                let rendered_json = record.data.clone();
                let ordinal =
                    usize::try_from(records_seen).context("EVTX record ordinal exceeds usize")?;
                let mut entry = evtx_import_entry_from_record(
                    record,
                    &root,
                    &candidate.name,
                    &candidate.source_path_exact,
                    channel_hint.as_deref(),
                    ordinal,
                )?;
                let record_partial = [
                    "evtx_event_id",
                    "evtx_provider",
                    "evtx_channel",
                    "evtx_computer",
                ]
                .iter()
                .any(|key| entry.metadata.get(*key).is_none());
                if record_partial {
                    partial_records = partial_records.saturating_add(1);
                    entry.metadata["evtx_parser_status"] = serde_json::json!("partial");
                    entry.metadata["supported_scope_complete"] = serde_json::json!(false);
                } else {
                    recognized_records = recognized_records.saturating_add(1);
                    entry.metadata["supported_scope_complete"] = serde_json::json!(true);
                }
                // The complete rendered event remains in the searchable text segment below.
                // Duplicating the same JSON inside metadata doubled the dominant storage cost on
                // large event-log sets (hundreds of thousands of records) without adding evidence.
                entry.metadata["evtx_rendered_json_storage"] = serde_json::json!(
                    "filesystem_entry_text_segments: kdft-windows-artifacts-v1/record"
                );
                entry.metadata["supported_scope"] =
                    serde_json::json!(source_supported_scope(candidate.kind));
                entry.metadata["safety_bounds"] = serde_json::json!({
                    "record_count_cap": null,
                    "materialization": "one evtx-rendered event JSON value at a time"
                });
                let search_text = serde_json::to_string(&rendered_json)
                    .context("rendering searchable EVTX event JSON")?;
                insert_derived_entry(
                    tx,
                    candidate,
                    &entry.logical_path,
                    &entry.display_name,
                    entry.entry_kind,
                    entry.metadata,
                    &search_text,
                )?;
                derived_entries = derived_entries.saturating_add(1);
                text_segments = text_segments.saturating_add(1);
            }
            Err(error) => {
                failed_records = failed_records.saturating_add(1);
                diagnostics.push(source_diagnostic(
                    candidate.entry_id,
                    candidate.kind,
                    &candidate.source_path_exact,
                    format!("EVTX record {records_seen} could not be decoded: {error}"),
                ));
            }
        }
    }

    if partial_records > 0 {
        diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            format!(
                "{partial_records} EVTX record(s) were emitted with one or more canonical system fields absent"
            ),
        ));
    }
    let partial = partial_records > 0 || failed_records > 0;
    Ok(SourceParseSummary {
        partial,
        derived_entries,
        text_segments,
        diagnostics,
        details: serde_json::json!({
            "evtx_records_seen": records_seen,
            "evtx_records_indexed": derived_entries,
            "evtx_recognized_records": recognized_records,
            "evtx_partial_records": partial_records,
            "evtx_failed_records": failed_records,
            "evtx_empty_valid_log": records_seen == 0,
            "evtx_record_count_cap": null,
        }),
    })
}

struct SqliteUsnSink<'connection, 'transaction> {
    tx: &'connection Transaction<'transaction>,
    candidate: &'connection WindowsArtifactCandidate,
    ordinal: u64,
    derived_entries: u64,
    text_segments: u64,
}

impl UsnSink for SqliteUsnSink<'_, '_> {
    type Error = anyhow::Error;

    fn record(&mut self, record: &UsnRecord) -> Result<(), Self::Error> {
        self.ordinal = self.ordinal.saturating_add(1);
        let record_json = usn_record_json(record);
        let metadata = serde_json::json!({
            "artifact_kind": "windows_usn_record",
            "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
            "parser_status": "parsed",
            "supported_scope_complete": true,
            "supported_scope": source_supported_scope(self.candidate.kind),
            "safety_bounds": {
                "record_count_cap": null,
                "materialization": "one bounded USN record at a time"
            },
            "usn_record": record_json,
        });
        let logical_path = derived_logical_path(
            self.candidate,
            "usn",
            self.ordinal,
            &format!("{}", record.usn),
        );
        let search_text =
            serde_json::to_string(&record_json).context("rendering searchable USN record")?;
        insert_derived_entry(
            self.tx,
            self.candidate,
            &logical_path,
            &record.file_name,
            "record",
            metadata,
            &search_text,
        )?;
        self.derived_entries = self.derived_entries.saturating_add(1);
        self.text_segments = self.text_segments.saturating_add(1);
        Ok(())
    }
}

fn parse_usn_source(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
) -> Result<SourceParseSummary> {
    let file = File::open(staging_path)
        .with_context(|| format!("opening staged USN journal {}", candidate.source_path_exact))?;
    let options = UsnParseOptions::default();
    let mut sink = SqliteUsnSink {
        tx,
        candidate,
        ordinal: 0,
        derived_entries: 0,
        text_segments: 0,
    };
    let parsed = usn::parse_usn_journal(file, &mut sink, &options).map_err(|error| {
        let message = format!(
            "USN parser failed at byte {} after seeing {} record(s), parsing {}, and emitting {}: {}",
            error.offset,
            error.stats.records_seen,
            error.stats.records_parsed,
            error.stats.records_emitted,
            error
        );
        let diagnostic_samples = error
            .stats
            .diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "USN {:?} diagnostic at byte {}: {}",
                    diagnostic.kind, diagnostic.offset, diagnostic.message
                )
            })
            .collect::<Vec<_>>();
        let details = serde_json::json!({
            "usn_status": usn_status_name(error.status),
            "usn_error_kind": format!("{:?}", error.kind),
            "usn_error_offset": error.offset,
            "usn_bytes_read": error.stats.bytes_read,
            "usn_records_seen": error.stats.records_seen,
            "usn_records_parsed": error.stats.records_parsed,
            "usn_records_emitted_before_rollback": error.stats.records_emitted,
            "usn_diagnostic_count": error.stats.diagnostic_count,
            "usn_diagnostics_omitted": error.stats.diagnostics_omitted,
        });
        anyhow::Error::new(SourceAttemptFailure::new(
            message,
            error.stats.diagnostic_count,
            diagnostic_samples,
            details,
        ))
    })?;
    if parsed.stats.records_emitted != sink.derived_entries {
        bail!(
            "USN parser reported {} emitted record(s), but SQLite inserted {}",
            parsed.stats.records_emitted,
            sink.derived_entries
        );
    }
    let derived_entries = sink.derived_entries;
    let text_segments = sink.text_segments;
    let mut diagnostics = DiagnosticAccumulator::default();
    diagnostics.absorb_exact(
        parsed.stats.diagnostic_count,
        candidate.entry_id,
        candidate.kind,
        &candidate.source_path_exact,
        parsed.stats.diagnostics.iter().map(|diagnostic| {
            format!(
                "USN {:?} diagnostic at byte {}: {}",
                diagnostic.kind, diagnostic.offset, diagnostic.message
            )
        }),
    );
    let partial = parsed.status == UsnTerminalStatus::Partial;
    if partial && diagnostics.total == 0 {
        diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            "USN parser reported partial coverage without a retained diagnostic".to_string(),
        ));
    }
    Ok(SourceParseSummary {
        partial,
        derived_entries,
        text_segments,
        diagnostics,
        details: serde_json::json!({
            "usn_status": usn_status_name(parsed.status),
            "usn_bytes_read": parsed.stats.bytes_read,
            "usn_sparse_zero_bytes_skipped": parsed.stats.sparse_zero_bytes_skipped,
            "usn_records_seen": parsed.stats.records_seen,
            "usn_records_parsed": parsed.stats.records_parsed,
            "usn_records_emitted": parsed.stats.records_emitted,
            "usn_v2_records": parsed.stats.v2_records,
            "usn_v3_records": parsed.stats.v3_records,
            "usn_unsupported_v4_records": parsed.stats.unsupported_v4_records,
            "usn_unknown_version_records": parsed.stats.unknown_version_records,
            "usn_corrupt_records": parsed.stats.corrupt_records,
            "usn_truncated_records": parsed.stats.truncated_records,
            "usn_oversized_records": parsed.stats.oversized_records,
            "usn_diagnostic_count": parsed.stats.diagnostic_count,
            "usn_diagnostics_omitted": parsed.stats.diagnostics_omitted,
            "usn_record_count_cap": null,
            "usn_max_record_bytes": options.max_record_bytes,
            "usn_max_filename_bytes": options.max_filename_bytes,
        }),
    })
}

struct ActiveEmbeddedLnk {
    metadata: JumpListLnkMetadata,
    path: PathBuf,
    file: File,
    bytes_written: u64,
}

struct SqliteJumpListSink<'connection, 'transaction> {
    tx: &'connection Transaction<'transaction>,
    candidate: &'connection WindowsArtifactCandidate,
    active: Option<ActiveEmbeddedLnk>,
    completed_lnk_streams: u64,
    derived_entries: u64,
    text_segments: u64,
    partial_embedded_lnks: u64,
    dest_list: Option<DestListMetadata>,
}

impl SqliteJumpListSink<'_, '_> {
    fn remove_spool(path: &Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path).with_context(|| {
                format!(
                    "removing temporary embedded Jump List LNK {}",
                    path.display()
                )
            })?;
        }
        Ok(())
    }

    fn persist_embedded_lnk(
        &mut self,
        metadata: JumpListLnkMetadata,
        parsed: LnkParseResult,
    ) -> Result<()> {
        self.completed_lnk_streams = self.completed_lnk_streams.saturating_add(1);
        let lnk_partial = parsed.status != LnkStatus::Recognized || !parsed.is_valid;
        if lnk_partial {
            self.partial_embedded_lnks = self.partial_embedded_lnks.saturating_add(1);
        }
        let parsed_json = serde_json::to_value(&parsed)
            .context("serializing embedded Jump List LNK parse result")?;
        let lnk_metadata = jump_lnk_metadata_json(&metadata);
        let combined = serde_json::json!({
            "embedded_lnk": lnk_metadata,
            "lnk": parsed_json,
        });
        let metadata_json = serde_json::json!({
            "artifact_kind": "windows_jumplist_lnk_record",
            "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
            "parser_status": if lnk_partial { "partial" } else { "parsed" },
            "supported_scope_complete": !lnk_partial,
            "supported_scope": source_supported_scope(self.candidate.kind),
            "safety_bounds": {
                "embedded_lnk_max_file_size_bytes": LnkParserOptions::default().max_file_size,
                "embedded_lnk_spools_concurrent": 1
            },
            "jumplist": combined,
        });
        let logical_path = derived_logical_path(
            self.candidate,
            "jumplist",
            self.completed_lnk_streams,
            &metadata.label,
        );
        let search_text =
            serde_json::to_string(&combined).context("rendering searchable Jump List LNK text")?;
        insert_derived_entry(
            self.tx,
            self.candidate,
            &logical_path,
            &metadata.label,
            "record",
            metadata_json,
            &search_text,
        )?;
        self.derived_entries = self.derived_entries.saturating_add(1);
        self.text_segments = self.text_segments.saturating_add(1);
        Ok(())
    }
}

impl JumpListSink for SqliteJumpListSink<'_, '_> {
    type Error = anyhow::Error;

    fn begin_lnk(&mut self, metadata: &JumpListLnkMetadata) -> Result<(), Self::Error> {
        if self.active.is_some() {
            bail!("Jump List sink received begin_lnk while another embedded LNK spool is active");
        }
        let (path, file) = create_unique_temporary_file(
            "kdft-jumplist-lnk",
            self.candidate.entry_id,
            &format!("{}.lnk", self.completed_lnk_streams.saturating_add(1)),
        )?;
        self.active = Some(ActiveEmbeddedLnk {
            metadata: metadata.clone(),
            path,
            file,
            bytes_written: 0,
        });
        Ok(())
    }

    fn lnk_chunk(
        &mut self,
        metadata: &JumpListLnkMetadata,
        logical_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let active = self
            .active
            .as_mut()
            .context("Jump List sink received bytes without an active LNK spool")?;
        if &active.metadata != metadata {
            bail!("Jump List sink metadata changed while streaming one embedded LNK");
        }
        if logical_offset != active.bytes_written {
            bail!(
                "Jump List embedded LNK chunk offset {} is not contiguous with {} bytes already written",
                logical_offset,
                active.bytes_written
            );
        }
        active.file.write_all(bytes)?;
        active.bytes_written = active
            .bytes_written
            .checked_add(bytes.len() as u64)
            .context("embedded Jump List LNK byte count overflow")?;
        if active.bytes_written > metadata.declared_size {
            bail!(
                "Jump List embedded LNK exceeded declared size {}",
                metadata.declared_size
            );
        }
        Ok(())
    }

    fn end_lnk(
        &mut self,
        metadata: &JumpListLnkMetadata,
        complete: bool,
    ) -> Result<(), Self::Error> {
        let mut active = self
            .active
            .take()
            .context("Jump List sink received end_lnk without an active spool")?;
        if &active.metadata != metadata {
            bail!("Jump List sink metadata changed before end_lnk");
        }
        active.file.flush()?;
        drop(active.file);
        if !complete || active.bytes_written != metadata.declared_size {
            Self::remove_spool(&active.path)?;
            self.partial_embedded_lnks = self.partial_embedded_lnks.saturating_add(1);
            return Ok(());
        }

        let parsed_result = (|| -> Result<LnkParseResult> {
            let mut file = File::open(&active.path).with_context(|| {
                format!("reopening embedded Jump List LNK {}", active.path.display())
            })?;
            Ok(LnkParser::parse_reader(
                &mut file,
                &LnkParserOptions::default(),
            ))
        })();
        let cleanup_result = Self::remove_spool(&active.path);
        let parsed = parsed_result?;
        cleanup_result?;
        self.persist_embedded_lnk(metadata.clone(), parsed)
    }

    fn dest_list(&mut self, metadata: &DestListMetadata) -> Result<(), Self::Error> {
        self.dest_list = Some(metadata.clone());
        Ok(())
    }

    fn corrupt_stream(&mut self, _diagnostic: &JumpListDiagnostic) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Drop for SqliteJumpListSink<'_, '_> {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            drop(active.file);
            let _ = fs::remove_file(active.path);
        }
    }
}

fn parse_jumplist_source(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    staging_path: &Path,
) -> Result<SourceParseSummary> {
    let mut file = File::open(staging_path)
        .with_context(|| format!("opening staged Jump List {}", candidate.source_path_exact))?;
    let options = JumpListParseOptions::default();
    let mut sink = SqliteJumpListSink {
        tx,
        candidate,
        active: None,
        completed_lnk_streams: 0,
        derived_entries: 0,
        text_segments: 0,
        partial_embedded_lnks: 0,
        dest_list: None,
    };
    let parsed = match candidate.kind {
        WindowsArtifactKind::AutomaticJumpList => {
            jumplist::parse_automatic_destinations(&mut file, &mut sink, &options)
        }
        WindowsArtifactKind::CustomJumpList => {
            jumplist::parse_custom_destinations(&mut file, &mut sink, &options)
        }
        _ => bail!(
            "non-Jump List candidate {} reached the Jump List parser",
            candidate.source_path_exact
        ),
    }
    .map_err(|error| {
        let message = format!(
            "Jump List parser failed with {:?} at {:?} after seeing {} LNK candidate(s) and emitting {}: {}",
            error.kind,
            error.offset,
            error.stats.lnk_candidates,
            error.stats.lnk_streams_emitted,
            error
        );
        let diagnostic_samples = error
            .stats
            .diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "Jump List {:?} diagnostic for {:?} at {:?}: {}",
                    diagnostic.kind, diagnostic.label, diagnostic.offset, diagnostic.message
                )
            })
            .collect::<Vec<_>>();
        let details = serde_json::json!({
            "jumplist_status": jumplist_status_name(error.status),
            "jumplist_error_kind": format!("{:?}", error.kind),
            "jumplist_error_offset": error.offset,
            "jumplist_file_size": error.stats.file_size,
            "jumplist_bytes_read": error.stats.bytes_read,
            "jumplist_lnk_candidates": error.stats.lnk_candidates,
            "jumplist_lnk_streams_emitted_before_rollback": error.stats.lnk_streams_emitted,
            "jumplist_incomplete_streams": error.stats.incomplete_streams,
            "jumplist_omitted_lnk_streams": error.stats.omitted_lnk_streams,
            "jumplist_omitted_lnk_bytes": error.stats.omitted_lnk_bytes,
            "jumplist_diagnostic_count": error.stats.diagnostic_count,
            "jumplist_diagnostics_omitted": error.stats.diagnostics_omitted,
        });
        anyhow::Error::new(SourceAttemptFailure::new(
            message,
            error.stats.diagnostic_count,
            diagnostic_samples,
            details,
        ))
    })?;
    if sink.active.is_some() {
        bail!("Jump List parser returned with an embedded LNK spool still active");
    }
    // The parser increments `lnk_streams_emitted` only after `end_lnk(..., true)` succeeds.
    // Likewise, the sink increments this counter only after persisting that complete stream;
    // `end_lnk(..., false)` records disclosed partial coverage without making the source fail.
    if parsed.stats.lnk_streams_emitted != sink.completed_lnk_streams {
        bail!(
            "Jump List parser reported {} emitted LNK stream(s), but SQLite processed {}",
            parsed.stats.lnk_streams_emitted,
            sink.completed_lnk_streams
        );
    }
    let derived_entries = sink.derived_entries;
    let text_segments = sink.text_segments;
    let partial_embedded_lnks = sink.partial_embedded_lnks;
    let dest_list = sink.dest_list.as_ref().map(dest_list_metadata_json);
    drop(sink);

    let mut diagnostics = DiagnosticAccumulator::default();
    diagnostics.absorb_exact(
        parsed.stats.diagnostic_count,
        candidate.entry_id,
        candidate.kind,
        &candidate.source_path_exact,
        parsed.stats.diagnostics.iter().map(|diagnostic| {
            format!(
                "Jump List {:?} diagnostic for {:?} at {:?}: {}",
                diagnostic.kind, diagnostic.label, diagnostic.offset, diagnostic.message
            )
        }),
    );
    let partial = parsed.status == JumpListTerminalStatus::Partial || partial_embedded_lnks > 0;
    if partial && diagnostics.total == 0 {
        diagnostics.push(source_diagnostic(
            candidate.entry_id,
            candidate.kind,
            &candidate.source_path_exact,
            "Jump List parser reported partial coverage without a retained diagnostic".to_string(),
        ));
    }
    Ok(SourceParseSummary {
        partial,
        derived_entries,
        text_segments,
        diagnostics,
        details: serde_json::json!({
            "jumplist_status": jumplist_status_name(parsed.status),
            "jumplist_container": candidate.kind,
            "jumplist_file_size": parsed.stats.file_size,
            "jumplist_bytes_read": parsed.stats.bytes_read,
            "jumplist_sector_size": parsed.stats.sector_size,
            "jumplist_sector_count": parsed.stats.sector_count,
            "jumplist_directory_streams": parsed.stats.directory_streams,
            "jumplist_lnk_candidates": parsed.stats.lnk_candidates,
            "jumplist_lnk_streams_emitted": parsed.stats.lnk_streams_emitted,
            "jumplist_lnk_bytes_emitted": parsed.stats.lnk_bytes_emitted,
            "jumplist_dest_list_streams": parsed.stats.dest_list_streams,
            "jumplist_corrupt_streams": parsed.stats.corrupt_streams,
            "jumplist_incomplete_streams": parsed.stats.incomplete_streams,
            "jumplist_omitted_lnk_streams": parsed.stats.omitted_lnk_streams,
            "jumplist_omitted_lnk_bytes": parsed.stats.omitted_lnk_bytes,
            "jumplist_missing_dest_list": parsed.stats.missing_dest_list,
            "jumplist_heuristic_custom_boundaries": parsed.stats.heuristic_custom_boundaries,
            "jumplist_partial_embedded_lnks": partial_embedded_lnks,
            "jumplist_diagnostic_count": parsed.stats.diagnostic_count,
            "jumplist_diagnostics_omitted": parsed.stats.diagnostics_omitted,
            "jumplist_dest_list": dest_list,
            "jumplist_limitations": parsed.limitations,
            "jumplist_record_count_cap": null,
            "jumplist_io_buffer_bytes": options.io_buffer_bytes,
            "jumplist_embedded_lnk_spools_concurrent": 1,
        }),
    })
}

fn derived_logical_path(
    candidate: &WindowsArtifactCandidate,
    kind: &str,
    ordinal: u64,
    label: &str,
) -> String {
    format!(
        "/Windows Artifacts/{}/{}/{ordinal:020}-{}.record",
        candidate.entry_id,
        kind,
        sanitize_logical_segment(label)
    )
}

fn insert_derived_entry(
    tx: &Transaction<'_>,
    candidate: &WindowsArtifactCandidate,
    logical_path: &str,
    display_name: &str,
    entry_kind: &str,
    mut metadata: serde_json::Value,
    search_text: &str,
) -> Result<i64> {
    let object = metadata
        .as_object_mut()
        .context("Windows artifact derived metadata must be a JSON object")?;
    object.insert(
        "windows_artifact_derived".to_string(),
        serde_json::json!(true),
    );
    object.insert(
        "windows_artifact_source_entry_id".to_string(),
        serde_json::json!(candidate.entry_id),
    );
    object.insert(
        "source_entry_id".to_string(),
        serde_json::json!(candidate.entry_id),
    );
    object.insert("source_kind".to_string(), serde_json::json!(candidate.kind));
    object.insert(
        "source_name_exact".to_string(),
        serde_json::json!(candidate.name),
    );
    object.insert(
        "source_logical_path_exact".to_string(),
        serde_json::json!(candidate.logical_path),
    );
    object.insert(
        "source_path_exact".to_string(),
        serde_json::json!(candidate.source_path_exact),
    );
    object.insert(
        "source_is_deleted".to_string(),
        serde_json::json!(candidate.is_deleted),
    );
    add_entry_category(&mut metadata, logical_path, display_name, entry_kind);
    tx.prepare_cached(
        "INSERT INTO filesystem_entries(
             case_id, evidence_id, parent_id, logical_path, name, entry_kind,
             size_bytes, is_deleted, metadata_json, content_head, discovered_by_job_id
         ) VALUES (
             (SELECT case_id FROM filesystem_entries WHERE id = ?1),
             ?2, NULL, ?3, ?4, ?5, NULL, 0, ?6, NULL, ?7
         )",
    )?
    .execute(params![
        candidate.entry_id,
        candidate.evidence_id,
        logical_path,
        display_name,
        entry_kind,
        metadata.to_string(),
        candidate.source_job_id
    ])?;
    let entry_id = tx.last_insert_rowid();
    tx.prepare_cached(
        "INSERT INTO filesystem_entry_text_segments(
             entry_id, parser_name, segment_index, part_name, content, content_encoding
         ) VALUES (?1, ?2, 0, 'record', ?3, 'utf-8')",
    )?
    .execute(params![
        entry_id,
        WINDOWS_ARTIFACT_TEXT_PARSER_NAME,
        search_text.as_bytes()
    ])?;
    Ok(entry_id)
}

fn source_derived_counts(tx: &Transaction<'_>, source_entry_id: i64) -> Result<(u64, u64)> {
    let entries: i64 = tx.query_row(
        "SELECT COUNT(*) FROM filesystem_entries
         WHERE json_extract(metadata_json, '$.windows_artifact_derived') = 1
           AND json_extract(metadata_json, '$.windows_artifact_source_entry_id') = ?1",
        [source_entry_id],
        |row| row.get(0),
    )?;
    let segments: i64 = tx.query_row(
        "SELECT COUNT(*)
         FROM filesystem_entry_text_segments segment
         JOIN filesystem_entries entry ON entry.id = segment.entry_id
         WHERE json_extract(entry.metadata_json, '$.windows_artifact_derived') = 1
           AND json_extract(entry.metadata_json, '$.windows_artifact_source_entry_id') = ?1",
        [source_entry_id],
        |row| row.get(0),
    )?;
    Ok((
        u64::try_from(entries).context("negative Windows artifact derived entry count")?,
        u64::try_from(segments).context("negative Windows artifact segment count")?,
    ))
}

fn delete_source_derived(
    tx: &Transaction<'_>,
    case_id: i64,
    evidence_id: i64,
    source_entry_id: i64,
) -> Result<()> {
    tx.execute(
        "DELETE FROM filesystem_entries
         WHERE case_id = ?1 AND evidence_id = ?2
           AND json_extract(metadata_json, '$.windows_artifact_derived') = 1
           AND json_extract(metadata_json, '$.windows_artifact_source_entry_id') = ?3",
        params![case_id, evidence_id, source_entry_id],
    )?;
    Ok(())
}

fn committed_source_metadata(
    candidate: &WindowsArtifactCandidate,
    summary: &SourceParseSummary,
) -> serde_json::Value {
    serde_json::json!({
        "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
        "source_kind": candidate.kind,
        "source_entry_id": candidate.entry_id,
        "source_name_exact": candidate.name,
        "source_logical_path_exact": candidate.logical_path,
        "source_path_exact": candidate.source_path_exact,
        "source_is_deleted": candidate.is_deleted,
        "status": if summary.partial { "partial" } else { "parsed" },
        "supported_scope_complete": !summary.partial,
        "supported_scope": source_supported_scope(candidate.kind),
        "default_coverage_cap": null,
        "safety_bounds": pass_safety_bounds(),
        "derived_entries": summary.derived_entries,
        "text_segments": summary.text_segments,
        "diagnostic_count": summary.diagnostics.total,
        "diagnostics": summary.diagnostics.samples,
        "diagnostics_omitted": summary.diagnostics.omitted,
        "replacement_committed": true,
        "replacement_rolled_back": false,
        "previous_committed_results_preserved": false,
        "details": summary.details,
    })
}

fn persist_failed_attempt(
    case_path: &Path,
    candidate: &WindowsArtifactCandidate,
    error: &anyhow::Error,
    diagnostics: &DiagnosticAccumulator,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let actor = audit_actor(&conn, case_id)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (previous_entries, previous_segments) = source_derived_counts(&tx, candidate.entry_id)?;
    let parser_failure_details = error
        .downcast_ref::<SourceAttemptFailure>()
        .map(|failure| failure.details.clone())
        .unwrap_or_else(|| serde_json::json!({}));
    let failure = failure_attempt_metadata(
        candidate,
        &format!("{error:#}"),
        previous_entries,
        previous_segments,
        diagnostics,
        parser_failure_details,
    );
    update_source_last_attempt(&tx, case_id, candidate, &failure)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.windows_artifact_source_parse_failed', ?2,
                 'filesystem_entry', ?3, ?4)",
        params![case_id, actor, candidate.entry_id, failure.to_string()],
    )?;
    tx.commit()?;
    Ok(())
}

fn failure_attempt_metadata(
    candidate: &WindowsArtifactCandidate,
    message: &str,
    previous_entries: u64,
    previous_segments: u64,
    diagnostics: &DiagnosticAccumulator,
    parser_failure_details: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
        "source_kind": candidate.kind,
        "source_entry_id": candidate.entry_id,
        "source_name_exact": candidate.name,
        "source_logical_path_exact": candidate.logical_path,
        "source_path_exact": candidate.source_path_exact,
        "source_is_deleted": candidate.is_deleted,
        "status": "failed",
        "error": bounded_text(message, DIAGNOSTIC_TEXT_BYTES),
        "supported_scope_complete": false,
        "supported_scope": source_supported_scope(candidate.kind),
        "default_coverage_cap": null,
        "safety_bounds": pass_safety_bounds(),
        "derived_entries": 0,
        "text_segments": 0,
        "diagnostic_count": diagnostics.total,
        "diagnostics": diagnostics.samples,
        "diagnostics_omitted": diagnostics.omitted,
        "replacement_committed": false,
        "replacement_rolled_back": true,
        "previous_committed_results_preserved": true,
        "previous_derived_entries_retained": previous_entries,
        "previous_text_segments_retained": previous_segments,
        "parser_failure_details": parser_failure_details,
    })
}

fn update_source_last_attempt(
    tx: &Transaction<'_>,
    case_id: i64,
    candidate: &WindowsArtifactCandidate,
    attempt: &serde_json::Value,
) -> Result<()> {
    let updated = tx.execute(
        "UPDATE filesystem_entries
         SET metadata_json = json_set(
             metadata_json,
             '$.windows_artifact_parser_last_attempt', json(?2)
         )
         WHERE case_id = ?3 AND evidence_id = ?4 AND id = ?1",
        params![
            candidate.entry_id,
            attempt.to_string(),
            case_id,
            candidate.evidence_id
        ],
    )?;
    if updated != 1 {
        bail!(
            "Windows artifact source entry {} disappeared before failure diagnostic could be persisted",
            candidate.entry_id
        );
    }
    Ok(())
}

fn persist_pass_audit(case_path: &Path, result: &WindowsArtifactParseResult) -> Result<()> {
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let actor = audit_actor(&conn, case_id)?;
    let details = serde_json::to_string(result)
        .context("serializing Windows artifact parse result for audit")?;
    conn.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'evidence.windows_artifact_parse', ?2, 'evidence', ?3, ?4)",
        params![case_id, actor, result.evidence_id, details],
    )?;
    Ok(())
}

fn source_diagnostic(
    entry_id: i64,
    kind: WindowsArtifactKind,
    source_path_exact: &str,
    message: String,
) -> WindowsArtifactDiagnostic {
    WindowsArtifactDiagnostic {
        source_entry_id: Some(entry_id),
        source_kind: Some(kind.key().to_string()),
        source_path_exact: Some(source_path_exact.to_string()),
        message: bounded_text(&message, DIAGNOSTIC_TEXT_BYTES),
    }
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn lnk_status_name(status: LnkStatus) -> &'static str {
    match status {
        LnkStatus::Recognized => "recognized",
        LnkStatus::Partial => "partial",
        LnkStatus::Failed => "failed",
    }
}

fn prefetch_status_name(status: &PrefetchStatus) -> String {
    match status {
        PrefetchStatus::Success => "success".to_string(),
        PrefetchStatus::Partial => "partial".to_string(),
        PrefetchStatus::MamCompressedNotDecompressed => {
            "mam_compressed_not_decompressed".to_string()
        }
        PrefetchStatus::MamDecompressionFailed => "mam_decompression_failed".to_string(),
        PrefetchStatus::ResourceLimitExceeded => "resource_limit_exceeded".to_string(),
        PrefetchStatus::UnsupportedVersion(version) => format!("unsupported_version_{version}"),
        PrefetchStatus::InvalidSignature => "invalid_signature".to_string(),
        PrefetchStatus::CorruptHeader => "corrupt_header".to_string(),
        PrefetchStatus::CorruptSectionOffsets => "corrupt_section_offsets".to_string(),
    }
}

fn usn_status_name(status: UsnTerminalStatus) -> &'static str {
    match status {
        UsnTerminalStatus::Recognized => "recognized",
        UsnTerminalStatus::Partial => "partial",
        UsnTerminalStatus::Failed => "failed",
    }
}

fn jumplist_status_name(status: JumpListTerminalStatus) -> &'static str {
    match status {
        JumpListTerminalStatus::Recognized => "recognized",
        JumpListTerminalStatus::Partial => "partial",
        JumpListTerminalStatus::Failed => "failed",
    }
}

fn usn_reference_json(reference: UsnFileReference) -> serde_json::Value {
    match reference {
        UsnFileReference::V2 {
            raw,
            entry,
            sequence,
        } => serde_json::json!({
            "version": "v2",
            "raw": raw,
            "entry": entry,
            "sequence": sequence,
        }),
        UsnFileReference::V3 { low, high } => serde_json::json!({
            "version": "v3",
            "low": low,
            "high": high,
        }),
    }
}

fn usn_record_json(record: &UsnRecord) -> serde_json::Value {
    serde_json::json!({
        "version": match record.version { UsnVersion::V2 => "v2", UsnVersion::V3 => "v3" },
        "major_version": record.major_version,
        "minor_version": record.minor_version,
        "record_length": record.record_length,
        "file_reference": usn_reference_json(record.file_reference),
        "parent_reference": usn_reference_json(record.parent_reference),
        "usn": record.usn,
        "timestamp_filetime": record.timestamp_filetime,
        "timestamp_utc": record.timestamp_utc,
        "reason": record.reason,
        "reason_flags": record.reason_flags,
        "unknown_reason_bits": record.unknown_reason_bits,
        "source_info": record.source_info,
        "security_id": record.security_id,
        "file_attributes": record.file_attributes,
        "file_name": record.file_name,
        "byte_offset": record.byte_offset,
    })
}

fn jump_lnk_metadata_json(metadata: &JumpListLnkMetadata) -> serde_json::Value {
    serde_json::json!({
        "container": match metadata.container {
            JumpListContainerKind::AutomaticDestinations => "automatic_destinations",
            JumpListContainerKind::CustomDestinations => "custom_destinations",
        },
        "label": metadata.label,
        "declared_size": metadata.declared_size,
        "source_offset": metadata.source_offset,
        "stored_in_mini_stream": metadata.stored_in_mini_stream,
        "created_filetime": metadata.created_filetime,
        "created_utc": metadata.created_utc,
        "modified_filetime": metadata.modified_filetime,
        "modified_utc": metadata.modified_utc,
    })
}

fn dest_list_metadata_json(metadata: &DestListMetadata) -> serde_json::Value {
    serde_json::json!({
        "declared_size": metadata.declared_size,
        "header_bytes_read": metadata.header_bytes_read,
        "version": metadata.version,
        "entry_count": metadata.entry_count,
        "pinned_entry_count": metadata.pinned_entry_count,
        "unknown_header_dword": metadata.unknown_header_dword,
        "last_entry_id": metadata.last_entry_id,
        "action_count": metadata.action_count,
        "created_filetime": metadata.created_filetime,
        "created_utc": metadata.created_utc,
        "modified_filetime": metadata.modified_filetime,
        "modified_utc": metadata.modified_utc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> Result<Connection> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE filesystem_entries (
                 id INTEGER PRIMARY KEY,
                 case_id INTEGER NOT NULL,
                 evidence_id INTEGER NOT NULL,
                 parent_id INTEGER REFERENCES filesystem_entries(id) ON DELETE SET NULL,
                 logical_path TEXT NOT NULL,
                 name TEXT NOT NULL,
                 entry_kind TEXT NOT NULL,
                 size_bytes INTEGER,
                 is_deleted INTEGER NOT NULL DEFAULT 0,
                 metadata_json TEXT NOT NULL DEFAULT '{}',
                 content_head BLOB,
                 discovered_by_job_id INTEGER,
                 UNIQUE(evidence_id, logical_path)
             );
             CREATE TABLE filesystem_entry_text_segments (
                 entry_id INTEGER NOT NULL REFERENCES filesystem_entries(id) ON DELETE CASCADE,
                 parser_name TEXT NOT NULL,
                 segment_index INTEGER NOT NULL,
                 part_name TEXT NOT NULL,
                 content BLOB NOT NULL,
                 content_encoding TEXT NOT NULL,
                 PRIMARY KEY(entry_id, parser_name, segment_index)
             );",
        )?;
        Ok(conn)
    }

    fn insert_source(
        conn: &Connection,
        id: i64,
        logical_path: &str,
        name: &str,
        metadata: serde_json::Value,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO filesystem_entries(
                 id, case_id, evidence_id, logical_path, name, entry_kind,
                 is_deleted, metadata_json
             ) VALUES (?1, 1, 7, ?2, ?3, 'file', 0, ?4)",
            params![id, logical_path, name, metadata.to_string()],
        )?;
        Ok(())
    }

    fn candidate(
        entry_id: i64,
        logical_path: &str,
        name: &str,
        source_path_exact: &str,
        kind: WindowsArtifactKind,
    ) -> WindowsArtifactCandidate {
        WindowsArtifactCandidate {
            entry_id,
            evidence_id: 7,
            source_job_id: None,
            logical_path: logical_path.to_string(),
            name: name.to_string(),
            source_path_exact: source_path_exact.to_string(),
            is_deleted: false,
            kind,
        }
    }

    #[test]
    fn classification_is_exact_and_case_insensitive() {
        let empty = serde_json::json!({});
        assert_eq!(
            classify_windows_source("Target.LNK", "C:\\Users\\Alice\\Target.LNK", &empty),
            Some(WindowsArtifactKind::ShellLink)
        );
        assert_eq!(
            classify_windows_source("APP.PF", "C:\\Windows\\Prefetch\\APP.PF", &empty),
            Some(WindowsArtifactKind::Prefetch)
        );
        assert_eq!(
            classify_windows_source("Security.EVTX", "Security.EVTX", &empty),
            Some(WindowsArtifactKind::Evtx)
        );
        assert_eq!(
            classify_windows_source(
                "1b4dd67f29cb1962.automaticDestinations-ms",
                "Recent/AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms",
                &empty,
            ),
            Some(WindowsArtifactKind::AutomaticJumpList)
        );
        assert_eq!(
            classify_windows_source(
                "1b4dd67f29cb1962.customDestinations-ms",
                "Recent/CustomDestinations/1b4dd67f29cb1962.customDestinations-ms",
                &empty,
            ),
            Some(WindowsArtifactKind::CustomJumpList)
        );
        assert_eq!(
            classify_windows_source(
                "$UsnJrnl:$J",
                "C:\\$Extend\\$UsnJrnl:$J",
                &serde_json::json!({
                    "ntfs_base_name": "$UsnJrnl",
                    "ntfs_data_stream_name": "$J"
                }),
            ),
            Some(WindowsArtifactKind::UsnJournal)
        );
        assert_eq!(
            classify_windows_source("not-a-link.txt", "C:\\Temp\\not-a-link.txt", &empty),
            None
        );
        assert_eq!(
            classify_windows_source("fake.lnk.txt", "C:\\Temp\\fake.lnk.txt", &empty),
            None
        );
        assert_eq!(
            classify_windows_source(
                "Collect inventory",
                "C:\\Windows\\System32\\Tasks\\KDFT\\Collect inventory",
                &empty,
            ),
            Some(WindowsArtifactKind::ScheduledTask)
        );
    }

    #[test]
    fn recovery_destination_is_reserved_but_does_not_exist() -> Result<()> {
        let (directory, destination) =
            create_unique_recovery_destination("kdft-recovery-test", 41, "xml")?;
        assert!(directory.is_dir());
        assert!(!destination.exists());
        fs::remove_dir(directory)?;
        Ok(())
    }

    #[test]
    fn count_max_snapshot_and_bounded_keyset_pages_exclude_later_rows() -> Result<()> {
        let conn = test_connection()?;
        insert_source(
            &conn,
            1,
            "/image/Target.LNK",
            "Target.LNK",
            serde_json::json!({"source_path_exact": "Users\\Alice\\Target.LNK"}),
        )?;
        insert_source(
            &conn,
            2,
            "/image/prefetch-source",
            "prefetch-source",
            serde_json::json!({"ntfs_path": "Windows\\Prefetch\\APP.PF"}),
        )?;
        insert_source(
            &conn,
            3,
            "/image/usn-stream",
            "$UsnJrnl:$J",
            serde_json::json!({
                "ntfs_base_name": "$UsnJrnl",
                "ntfs_data_stream_name": "$J",
                "ntfs_path": "$Extend\\$UsnJrnl:$J"
            }),
        )?;
        insert_source(
            &conn,
            4,
            "/image/readme.txt",
            "readme.txt",
            serde_json::json!({}),
        )?;
        insert_source(
            &conn,
            6,
            "/image/already-parsed.lnk",
            "already-parsed.lnk",
            serde_json::json!({
                "source_path_exact": "Users\\Alice\\already-parsed.lnk",
                "windows_artifact_parser_committed": {
                    "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
                    "status": "parsed",
                    "supported_scope_complete": true
                }
            }),
        )?;
        insert_source(
            &conn,
            7,
            "/image/already-partial.lnk",
            "already-partial.lnk",
            serde_json::json!({
                "source_path_exact": "Users\\Alice\\already-partial.lnk",
                "windows_artifact_parser_committed": {
                    "parser_name": WINDOWS_ARTIFACT_PARSER_NAME,
                    "status": "partial",
                    "supported_scope_complete": false
                }
            }),
        )?;
        conn.execute(
            "UPDATE filesystem_entries SET is_deleted = 1 WHERE id = 3",
            [],
        )?;

        let snapshot = candidate_snapshot_conn(&conn, 1, 7, true)?;
        assert_eq!(snapshot.supported_count, 5);
        assert_eq!(snapshot.reused_partial_count, 1);
        assert_eq!(snapshot.count, 3);
        assert_eq!(snapshot.max_entry_id, Some(3));

        insert_source(
            &conn,
            5,
            "/image/later.evtx",
            "later.evtx",
            serde_json::json!({"source_path_exact": "Windows/System32/winevt/Logs/later.evtx"}),
        )?;
        let first = candidate_page_conn(&conn, 1, 7, i64::MIN, 3, 2, true)?;
        assert_eq!(
            first.iter().map(|item| item.entry_id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(first[1].source_path_exact, "Windows\\Prefetch\\APP.PF");
        let second = candidate_page_conn(&conn, 1, 7, 2, 3, 2, true)?;
        assert_eq!(
            second.iter().map(|item| item.entry_id).collect::<Vec<_>>(),
            vec![3]
        );
        assert!(
            second[0].is_deleted,
            "recoverable deleted Windows artifacts must remain candidates"
        );
        Ok(())
    }

    #[test]
    fn header_bearing_corrupt_prefetch_is_persisted_as_partial() -> Result<()> {
        let mut conn = test_connection()?;
        insert_source(
            &conn,
            9,
            "/image/Windows/Prefetch/EDITOR.PF",
            "EDITOR.PF",
            serde_json::json!({"ntfs_path": "Windows\\Prefetch\\EDITOR.PF"}),
        )?;
        let candidate = candidate(
            9,
            "/image/Windows/Prefetch/EDITOR.PF",
            "EDITOR.PF",
            "Windows\\Prefetch\\EDITOR.PF",
            WindowsArtifactKind::Prefetch,
        );
        let (path, mut staged) = create_unique_temporary_file("kdft-windows-test", 9, "pf")?;
        let mut bytes = vec![0_u8; 304];
        bytes[0..4].copy_from_slice(&26_u32.to_le_bytes());
        bytes[4..8].copy_from_slice(b"SCCA");
        bytes[12..16].copy_from_slice(&304_u32.to_le_bytes());
        for (index, unit) in "EDITOR.EXE".encode_utf16().enumerate() {
            let offset = 16 + index * 2;
            bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        // Section C advertises a range beyond EOF. The Prefetch header remains useful.
        bytes[100..104].copy_from_slice(&500_u32.to_le_bytes());
        bytes[104..108].copy_from_slice(&2_u32.to_le_bytes());
        staged.write_all(&bytes)?;
        staged.flush()?;
        drop(staged);

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let summary = parse_prefetch_source(&tx, &candidate, &path)?;
        assert!(summary.partial);
        assert_eq!(summary.derived_entries, 1);
        tx.commit()?;
        fs::remove_file(path)?;

        let (status, executable): (String, String) = conn.query_row(
            "SELECT json_extract(metadata_json, '$.prefetch.status'),
                    json_extract(metadata_json, '$.prefetch.header.executable_name')
             FROM filesystem_entries
             WHERE json_extract(metadata_json, '$.windows_artifact_derived') = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(status, "CorruptSectionOffsets");
        assert_eq!(executable, "EDITOR.EXE");
        Ok(())
    }

    #[test]
    fn incomplete_jumplist_lnk_is_disclosed_without_counting_as_emitted() -> Result<()> {
        let mut conn = test_connection()?;
        insert_source(
            &conn,
            8,
            "/image/Recent/sample.customDestinations-ms",
            "sample.customDestinations-ms",
            serde_json::json!({}),
        )?;
        let candidate = candidate(
            8,
            "/image/Recent/sample.customDestinations-ms",
            "sample.customDestinations-ms",
            "Recent\\sample.customDestinations-ms",
            WindowsArtifactKind::CustomJumpList,
        );
        let metadata = JumpListLnkMetadata {
            container: JumpListContainerKind::CustomDestinations,
            label: "incomplete".to_string(),
            declared_size: 16,
            source_offset: 64,
            stored_in_mini_stream: false,
            created_filetime: None,
            created_utc: None,
            modified_filetime: None,
            modified_utc: None,
        };
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut sink = SqliteJumpListSink {
            tx: &tx,
            candidate: &candidate,
            active: None,
            completed_lnk_streams: 0,
            derived_entries: 0,
            text_segments: 0,
            partial_embedded_lnks: 0,
            dest_list: None,
        };
        sink.begin_lnk(&metadata)?;
        sink.lnk_chunk(&metadata, 0, &[1, 2, 3, 4])?;
        sink.end_lnk(&metadata, false)?;
        assert!(sink.active.is_none());
        assert_eq!(sink.completed_lnk_streams, 0);
        assert_eq!(sink.derived_entries, 0);
        assert_eq!(sink.partial_embedded_lnks, 1);
        drop(sink);
        tx.rollback()?;
        Ok(())
    }

    #[test]
    fn parsed_lnk_persists_exact_source_values_and_searchable_segment() -> Result<()> {
        let mut conn = test_connection()?;
        let canonical = "Users\\Alice\\Recent\\Résumé Target.LNK";
        insert_source(
            &conn,
            10,
            "/image/Users/Alice/Recent/Résumé Target.LNK",
            "Résumé Target.LNK",
            serde_json::json!({"ntfs_path": canonical}),
        )?;
        let candidate = candidate(
            10,
            "/image/Users/Alice/Recent/Résumé Target.LNK",
            "Résumé Target.LNK",
            canonical,
            WindowsArtifactKind::ShellLink,
        );
        let (path, mut staged) = create_unique_temporary_file("kdft-windows-test", 10, "lnk")?;
        let mut bytes = vec![0_u8; 128];
        bytes[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        bytes[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        bytes[20..24].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&1024_u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&1_u32.to_le_bytes());
        staged.write_all(&bytes)?;
        staged.flush()?;
        drop(staged);

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let summary = parse_lnk_source(&tx, &candidate, &path)?;
        assert!(!summary.partial);
        tx.commit()?;
        fs::remove_file(path)?;

        let (source_name, source_path): (String, String) = conn.query_row(
            "SELECT json_extract(metadata_json, '$.source_name_exact'),
                    json_extract(metadata_json, '$.source_path_exact')
             FROM filesystem_entries
             WHERE json_extract(metadata_json, '$.windows_artifact_derived') = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(source_name, "Résumé Target.LNK");
        assert_eq!(source_path, canonical);
        let searchable: Vec<u8> = conn.query_row(
            "SELECT content FROM filesystem_entry_text_segments",
            [],
            |row| row.get(0),
        )?;
        let searchable = String::from_utf8(searchable)?;
        assert!(searchable.contains("link_clsid"));
        assert!(searchable.contains("00021401-0000-0000-C000-000000000046"));
        Ok(())
    }

    #[test]
    fn failed_replacement_rolls_back_and_separate_attempt_preserves_prior_rows() -> Result<()> {
        let mut conn = test_connection()?;
        let canonical = "$Extend\\$UsnJrnl:$J";
        insert_source(
            &conn,
            20,
            "/image/usn-stream",
            "$UsnJrnl:$J",
            serde_json::json!({
                "ntfs_path": canonical,
                "windows_artifact_parser_committed": {"status": "parsed", "generation": 1}
            }),
        )?;
        let candidate = candidate(
            20,
            "/image/usn-stream",
            "$UsnJrnl:$J",
            canonical,
            WindowsArtifactKind::UsnJournal,
        );
        {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            insert_derived_entry(
                &tx,
                &candidate,
                "/Windows Artifacts/20/usn/00000000000000000001-old.record",
                "old.txt",
                "record",
                serde_json::json!({"artifact_kind": "windows_usn_record", "generation": 1}),
                "old searchable record",
            )?;
            tx.commit()?;
        }
        let old_entry_id: i64 = conn.query_row(
            "SELECT id FROM filesystem_entries
             WHERE json_extract(metadata_json, '$.windows_artifact_derived') = 1",
            [],
            |row| row.get(0),
        )?;

        {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            delete_source_derived(&tx, 1, 7, 20)?;
            assert_eq!(source_derived_counts(&tx, 20)?, (0, 0));
            tx.rollback()?;
        }
        {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut diagnostics = DiagnosticAccumulator::default();
            diagnostics.push(source_diagnostic(
                candidate.entry_id,
                candidate.kind,
                &candidate.source_path_exact,
                "synthetic parser failure".to_string(),
            ));
            let failure = failure_attempt_metadata(
                &candidate,
                "synthetic parser failure",
                1,
                1,
                &diagnostics,
                serde_json::json!({"synthetic": true}),
            );
            update_source_last_attempt(&tx, 1, &candidate, &failure)?;
            tx.commit()?;
        }

        let retained_entry_id: i64 = conn.query_row(
            "SELECT id FROM filesystem_entries
             WHERE json_extract(metadata_json, '$.windows_artifact_derived') = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(retained_entry_id, old_entry_id);
        let retained_text: Vec<u8> = conn.query_row(
            "SELECT content FROM filesystem_entry_text_segments WHERE entry_id = ?1",
            [old_entry_id],
            |row| row.get(0),
        )?;
        assert_eq!(retained_text, b"old searchable record");
        let (name, logical_path, metadata_text): (String, String, String) = conn.query_row(
            "SELECT name, logical_path, metadata_json FROM filesystem_entries WHERE id = 20",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(name, "$UsnJrnl:$J");
        assert_eq!(logical_path, "/image/usn-stream");
        let metadata: serde_json::Value = serde_json::from_str(&metadata_text)?;
        assert_eq!(
            metadata["windows_artifact_parser_committed"]["generation"],
            1
        );
        assert_eq!(
            metadata["windows_artifact_parser_last_attempt"]["status"],
            "failed"
        );
        assert_eq!(
            metadata["windows_artifact_parser_last_attempt"]
                ["previous_committed_results_preserved"],
            true
        );
        Ok(())
    }
}
