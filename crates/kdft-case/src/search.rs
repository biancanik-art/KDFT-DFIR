//! Deep and raw disk forensic search capabilities.
//!
//! Provides examiner-bounded forensic searching across indexed metadata,
//! captured entry text/content, and whole raw physical/logical image streams.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::{
    active_case_id, audit_actor, ensure_evidence_source, list_image_volumes, open_disk_image,
    open_existing_case, source_path_exact_from_metadata, DeepSearchCoverage, DeepSearchCursor,
    DeepSearchOptions, DeepSearchPage, DeepSearchResult, LiveVolume, CONTENT_INDEX_BYTES,
    SEARCH_RESPONSE_PAGE_MAX,
};

pub fn deep_search(case_path: &Path, options: DeepSearchOptions) -> Result<Vec<DeepSearchResult>> {
    let query = options.query.trim();
    if query.is_empty() {
        bail!("search query cannot be empty");
    }
    // This remains an examiner-requested response bound, not an ingestion cap.
    // Do not silently reduce a larger request; callers that need small pages
    // already send a small value.
    let max_results = options.max_results.max(1);
    // File content search only ever has CONTENT_INDEX_BYTES available per file
    // (content_head, captured once at "Read File System" time) - clamping here
    // to the real ceiling instead of a much larger one keeps the "Max file
    // bytes" field honest about what it can actually do, instead of silently
    // accepting a bigger number that can never matter. For matches beyond a
    // file's first CONTENT_INDEX_BYTES, anywhere on disk including unallocated
    // space and slack, use raw_disk_search instead.
    let max_file_bytes = options.max_file_bytes.clamp(1, CONTENT_INDEX_BYTES as u64);
    let query_lower = query.to_ascii_lowercase();
    let scope = SearchScope::new(options.category.as_deref(), options.file_types.as_deref())?;

    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    if let Some(evidence_id) = options.evidence_id {
        ensure_evidence_source(&conn, case_id, evidence_id)?;
    }

    // Byte-pattern mode: `hex:FF D8 FF` scans indexed content and reports
    // byte offsets. Path/metadata text search does not apply to raw bytes.
    if let Some(pattern_text) = strip_hex_query_prefix(query) {
        let needle = parse_hex_pattern(pattern_text)?;
        let mut results = Vec::new();
        content_hex_search_results(
            &conn,
            case_id,
            options.evidence_id,
            &needle,
            max_file_bytes,
            max_results,
            &scope,
            &mut results,
        )?;
        return Ok(results);
    }

    let mut results = path_search_results(
        &conn,
        case_id,
        options.evidence_id,
        query,
        &query_lower,
        max_results,
        &scope,
    )?;
    if options.include_content && results.len() < max_results {
        parsed_text_search_results(
            &conn,
            case_id,
            options.evidence_id,
            query,
            max_results,
            &scope,
            &mut results,
        )?;
    }
    if options.include_content && results.len() < max_results {
        content_search_results(
            &conn,
            case_id,
            options.evidence_id,
            query,
            max_file_bytes,
            max_results,
            &scope,
            &mut results,
        )?;
    }
    Ok(results)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeepSearchPhase {
    Path,
    ParsedContent,
    Content,
    HexContent,
}

impl DeepSearchPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::ParsedContent => "parsed_content",
            Self::Content => "content",
            Self::HexContent => "hex_content",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "path" => Ok(Self::Path),
            "parsed_content" => Ok(Self::ParsedContent),
            "content" => Ok(Self::Content),
            "hex_content" => Ok(Self::HexContent),
            _ => bail!("invalid Deep Search continuation phase"),
        }
    }
}

#[derive(Debug, Clone)]
struct DeepSearchKey {
    evidence_id: i64,
    logical_path: String,
    entry_id: i64,
}

impl DeepSearchKey {
    fn from_result(result: &DeepSearchResult) -> Self {
        Self {
            evidence_id: result.evidence_id,
            logical_path: result.internal_path_key.clone(),
            entry_id: result.entry_id,
        }
    }
}

struct DeepSearchPhaseBatch {
    results: Vec<DeepSearchResult>,
    exhausted: bool,
}

fn deep_search_coverage() -> DeepSearchCoverage {
    DeepSearchCoverage {
        indexed_entry_scope: "all matching indexed entries across the complete cursor sequence",
        generic_file_content_bytes_per_file: CONTENT_INDEX_BYTES,
        parser_derived_text_scope: "all text segments emitted and persisted by supported structured parsers; parser-declared unsupported parts are not searched",
        raw_evidence_bytes_included: false,
    }
}

fn deep_search_scope_token(options: &DeepSearchOptions, max_file_bytes: u64) -> Result<String> {
    serde_json::to_string(&(
        options.query.trim(),
        options.evidence_id,
        options.include_content,
        max_file_bytes,
        options.category.as_deref(),
        options.file_types.as_deref(),
    ))
    .context("serializing Deep Search continuation scope")
}

fn deep_search_cursor(
    phase: DeepSearchPhase,
    key: Option<&DeepSearchKey>,
    scope_token: &str,
) -> DeepSearchCursor {
    DeepSearchCursor {
        phase: phase.as_str().to_string(),
        evidence_id: key.map(|value| value.evidence_id),
        logical_path: key.map(|value| value.logical_path.clone()),
        entry_id: key.map(|value| value.entry_id),
        scope_token: scope_token.to_string(),
    }
}

fn deep_search_cursor_key(cursor: &DeepSearchCursor) -> Result<Option<DeepSearchKey>> {
    match (
        cursor.evidence_id,
        cursor.logical_path.as_ref(),
        cursor.entry_id,
    ) {
        (None, None, None) => Ok(None),
        (Some(evidence_id), Some(logical_path), Some(entry_id)) => Ok(Some(DeepSearchKey {
            evidence_id,
            logical_path: logical_path.clone(),
            entry_id,
        })),
        _ => bail!("invalid Deep Search continuation key"),
    }
}

fn first_deep_search_phase(hex_mode: bool) -> DeepSearchPhase {
    if hex_mode {
        DeepSearchPhase::HexContent
    } else {
        DeepSearchPhase::Path
    }
}

fn next_deep_search_phase(
    phase: DeepSearchPhase,
    include_content: bool,
) -> Option<DeepSearchPhase> {
    match phase {
        DeepSearchPhase::Path if include_content => Some(DeepSearchPhase::ParsedContent),
        DeepSearchPhase::Path => None,
        DeepSearchPhase::ParsedContent => Some(DeepSearchPhase::Content),
        DeepSearchPhase::Content | DeepSearchPhase::HexContent => None,
    }
}

/// Bounded, lossless Deep Search pagination. Each response holds at most
/// `page_size` results, while the continuation advances through every matching
/// indexed row. No result-count ceiling is applied to the search itself.
pub fn deep_search_page(
    case_path: &Path,
    options: DeepSearchOptions,
    cursor: Option<DeepSearchCursor>,
    page_size: usize,
) -> Result<DeepSearchPage> {
    let query = options.query.trim();
    if query.is_empty() {
        bail!("search query cannot be empty");
    }
    if page_size == 0 {
        bail!("Deep Search page size must be at least 1");
    }
    if page_size > SEARCH_RESPONSE_PAGE_MAX {
        bail!(
            "Deep Search page size {page_size} exceeds the protective response maximum of {SEARCH_RESPONSE_PAGE_MAX}; this bounds one response only, and cursors preserve complete search coverage"
        );
    }
    let lookahead = page_size
        .checked_add(1)
        .context("Deep Search page size is too large")?;
    i64::try_from(lookahead).context("Deep Search page size exceeds SQLite's supported range")?;
    let max_file_bytes = options.max_file_bytes.clamp(1, CONTENT_INDEX_BYTES as u64);
    let scope_token = deep_search_scope_token(&options, max_file_bytes)?;
    let hex_needle = strip_hex_query_prefix(query)
        .map(parse_hex_pattern)
        .transpose()?;
    let hex_mode = hex_needle.is_some();

    let (mut phase, mut after) = if let Some(cursor) = cursor.as_ref() {
        if cursor.scope_token != scope_token {
            bail!("Deep Search continuation does not match this query or scope");
        }
        let phase = DeepSearchPhase::parse(&cursor.phase)?;
        let allowed = if hex_mode {
            phase == DeepSearchPhase::HexContent
        } else if options.include_content {
            matches!(
                phase,
                DeepSearchPhase::Path | DeepSearchPhase::ParsedContent | DeepSearchPhase::Content
            )
        } else {
            phase == DeepSearchPhase::Path
        };
        if !allowed {
            bail!("Deep Search continuation phase does not match this search mode");
        }
        (phase, deep_search_cursor_key(cursor)?)
    } else {
        (first_deep_search_phase(hex_mode), None)
    };

    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    if let Some(evidence_id) = options.evidence_id {
        ensure_evidence_source(&conn, case_id, evidence_id)?;
    }
    let scope = SearchScope::new(options.category.as_deref(), options.file_types.as_deref())?;
    let query_lower = query.to_ascii_lowercase();
    let mut results = Vec::new();

    loop {
        let remaining = page_size.saturating_sub(results.len());
        if remaining == 0 {
            return Ok(DeepSearchPage {
                results,
                next_cursor: Some(deep_search_cursor(phase, after.as_ref(), &scope_token)),
                complete: false,
                page_size,
                coverage: deep_search_coverage(),
            });
        }
        let phase_limit = remaining
            .checked_add(1)
            .context("Deep Search page size is too large")?;
        let batch = match phase {
            DeepSearchPhase::Path => path_search_page_results(
                &conn,
                case_id,
                options.evidence_id,
                query,
                &query_lower,
                &scope,
                after.as_ref(),
                phase_limit,
            )?,
            DeepSearchPhase::ParsedContent => parsed_text_search_page_results(
                &conn,
                case_id,
                options.evidence_id,
                query,
                &query_lower,
                &scope,
                after.as_ref(),
                phase_limit,
            )?,
            DeepSearchPhase::Content => content_search_page_results(
                &conn,
                case_id,
                options.evidence_id,
                query,
                max_file_bytes,
                &scope,
                after.as_ref(),
                phase_limit,
            )?,
            DeepSearchPhase::HexContent => content_hex_search_page_results(
                &conn,
                case_id,
                options.evidence_id,
                hex_needle
                    .as_deref()
                    .context("missing hex search pattern")?,
                max_file_bytes,
                &scope,
                after.as_ref(),
                phase_limit,
            )?,
        };

        if batch.results.len() > remaining {
            results.extend(batch.results.into_iter().take(remaining));
            let last_key = results.last().map(DeepSearchKey::from_result);
            return Ok(DeepSearchPage {
                results,
                next_cursor: Some(deep_search_cursor(phase, last_key.as_ref(), &scope_token)),
                complete: false,
                page_size,
                coverage: deep_search_coverage(),
            });
        }
        results.extend(batch.results);
        debug_assert!(batch.exhausted);
        let Some(next_phase) = next_deep_search_phase(phase, options.include_content) else {
            return Ok(DeepSearchPage {
                results,
                next_cursor: None,
                complete: true,
                page_size,
                coverage: deep_search_coverage(),
            });
        };
        phase = next_phase;
        after = None;
        if results.len() == page_size {
            let continuation = deep_search_cursor(phase, None, &scope_token);
            // Do one bounded lookahead at a phase boundary. Without this, an
            // exact-size final path page could claim "more available" merely
            // because content phases exist, then yield an empty last page.
            let probe =
                deep_search_page(case_path, options.clone(), Some(continuation.clone()), 1)?;
            if probe.complete && probe.results.is_empty() {
                return Ok(DeepSearchPage {
                    results,
                    next_cursor: None,
                    complete: true,
                    page_size,
                    coverage: deep_search_coverage(),
                });
            }
            return Ok(DeepSearchPage {
                results,
                next_cursor: Some(continuation),
                complete: false,
                page_size,
                coverage: deep_search_coverage(),
            });
        }
    }
}

fn page_cursor_parts(after: Option<&DeepSearchKey>) -> (Option<i64>, Option<&str>, Option<i64>) {
    match after {
        Some(key) => (
            Some(key.evidence_id),
            Some(key.logical_path.as_str()),
            Some(key.entry_id),
        ),
        None => (None, None, None),
    }
}

#[allow(clippy::too_many_arguments)]
fn path_search_page_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    query_lower: &str,
    scope: &SearchScope,
    after: Option<&DeepSearchKey>,
    limit: usize,
) -> Result<DeepSearchPhaseBatch> {
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND (instr(lower(fe.logical_path), ?3) > 0
                OR instr(lower(fe.name), ?3) > 0
                OR instr(lower(fe.metadata_json), ?3) > 0)
           AND (?4 IS NULL OR fe.evidence_id > ?4
                OR (fe.evidence_id = ?4 AND fe.logical_path > ?5)
                OR (fe.evidence_id = ?4 AND fe.logical_path = ?5 AND fe.id > ?6)){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id
         LIMIT ?7",
        scope.sql_clause
    ))?;
    let (after_evidence, after_path, after_entry) = page_cursor_parts(after);
    let rows = stmt.query_map(
        params![
            case_id,
            evidence_id,
            query_lower,
            after_evidence,
            after_path,
            after_entry,
            i64::try_from(limit).unwrap_or(i64::MAX)
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    )?;
    let mut results = Vec::new();
    for row in rows {
        let (entry_id, evidence_id, logical_path, name, entry_kind, metadata_json) =
            row.context("reading paged indexed-path result")?;
        let source_path_exact = serde_json::from_str::<serde_json::Value>(&metadata_json)
            .ok()
            .and_then(|metadata| source_path_exact_from_metadata(&metadata));
        let matched_path_or_name = logical_path.to_ascii_lowercase().contains(query_lower)
            || name.to_ascii_lowercase().contains(query_lower);
        let (match_kind, preview) = if matched_path_or_name {
            (
                "path".to_string(),
                source_path_exact
                    .clone()
                    .or_else(|| Some(logical_path.clone())),
            )
        } else if let Some(offset) = metadata_json.to_ascii_lowercase().find(query_lower) {
            (
                "metadata".to_string(),
                Some(content_preview(&metadata_json, offset, query.len())),
            )
        } else {
            (
                "path".to_string(),
                source_path_exact
                    .clone()
                    .or_else(|| Some(logical_path.clone())),
            )
        };
        results.push(DeepSearchResult {
            evidence_id,
            entry_id,
            internal_path_key: logical_path.clone(),
            logical_path,
            source_path_exact,
            display_name: name,
            entry_kind,
            match_kind,
            selection_offset: None,
            selection_length: None,
            data_preview: preview,
        });
    }
    let exhausted = results.len() < limit;
    Ok(DeepSearchPhaseBatch { results, exhausted })
}

#[allow(clippy::too_many_arguments)]
fn parsed_text_search_page_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    query_lower: &str,
    scope: &SearchScope,
    after: Option<&DeepSearchKey>,
    limit: usize,
) -> Result<DeepSearchPhaseBatch> {
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind,
                fe.metadata_json, segments.part_name, segments.content
         FROM filesystem_entry_text_segments segments
         JOIN filesystem_entries fe ON fe.id = segments.entry_id
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind IN ('file', 'record')
           AND NOT (instr(lower(fe.logical_path), ?3) > 0
                    OR instr(lower(fe.name), ?3) > 0
                    OR instr(lower(fe.metadata_json), ?3) > 0)
           AND (?4 IS NULL OR fe.evidence_id > ?4
                OR (fe.evidence_id = ?4 AND fe.logical_path > ?5)
                OR (fe.evidence_id = ?4 AND fe.logical_path = ?5 AND fe.id > ?6)){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id,
                  segments.parser_name, segments.segment_index",
        scope.sql_clause
    ))?;
    let (after_evidence, after_path, after_entry) = page_cursor_parts(after);
    let rows = stmt.query_map(
        params![
            case_id,
            evidence_id,
            query_lower,
            after_evidence,
            after_path,
            after_entry
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        },
    )?;
    let mut results = Vec::new();
    let mut matched_entry = None;
    let mut previous_entry_id = None;
    let mut previous_part = String::new();
    let mut previous_tail = Vec::new();
    let mut exhausted = true;
    for row in rows {
        let (
            entry_id,
            evidence_id,
            logical_path,
            display_name,
            entry_kind,
            metadata_json,
            part_name,
            segment_content,
        ) = row.context("reading paged parser-derived search candidate")?;
        if previous_entry_id != Some(entry_id) {
            previous_entry_id = Some(entry_id);
            matched_entry = None;
            previous_part.clear();
            previous_tail.clear();
        }
        if matched_entry == Some(entry_id) {
            continue;
        }
        let mut searchable =
            Vec::with_capacity(previous_tail.len().saturating_add(segment_content.len()));
        if previous_part == part_name {
            searchable.extend_from_slice(&previous_tail);
        }
        searchable.extend_from_slice(&segment_content);
        if let Some(hit) = content_search_hit(&searchable, query) {
            results.push(DeepSearchResult {
                evidence_id,
                entry_id,
                internal_path_key: logical_path.clone(),
                logical_path,
                source_path_exact: serde_json::from_str::<serde_json::Value>(&metadata_json)
                    .ok()
                    .and_then(|metadata| source_path_exact_from_metadata(&metadata)),
                display_name,
                entry_kind,
                match_kind: "parsed_content".to_string(),
                selection_offset: None,
                selection_length: None,
                data_preview: Some(format!("{}: {}", part_name, hit.data_preview)),
            });
            matched_entry = Some(entry_id);
            if results.len() >= limit {
                exhausted = false;
                break;
            }
            continue;
        }
        previous_part = part_name;
        previous_tail = byte_tail(&searchable, content_search_overlap_bytes(query));
    }
    Ok(DeepSearchPhaseBatch { results, exhausted })
}

#[allow(clippy::too_many_arguments)]
fn content_search_page_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    max_file_bytes: u64,
    scope: &SearchScope,
    after: Option<&DeepSearchKey>,
    limit: usize,
) -> Result<DeepSearchPhaseBatch> {
    let query_lower = query.to_ascii_lowercase();
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind,
                fe.content_head, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind = 'file'
           AND NOT (instr(lower(fe.logical_path), ?3) > 0
                    OR instr(lower(fe.name), ?3) > 0
                    OR instr(lower(fe.metadata_json), ?3) > 0)
           AND (?4 IS NULL OR fe.evidence_id > ?4
                OR (fe.evidence_id = ?4 AND fe.logical_path > ?5)
                OR (fe.evidence_id = ?4 AND fe.logical_path = ?5 AND fe.id > ?6)){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id",
        scope.sql_clause
    ))?;
    let (after_evidence, after_path, after_entry) = page_cursor_parts(after);
    let rows = stmt.query_map(
        params![
            case_id,
            evidence_id,
            query_lower,
            after_evidence,
            after_path,
            after_entry
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, String>(6)?,
            ))
        },
    )?;
    let mut parsed_match_stmt = conn.prepare(
        "SELECT part_name, content
         FROM filesystem_entry_text_segments
         WHERE entry_id = ?1
         ORDER BY parser_name, segment_index",
    )?;
    let mut results = Vec::new();
    let mut exhausted = true;
    for row in rows {
        let (
            entry_id,
            evidence_id,
            logical_path,
            display_name,
            entry_kind,
            content_head,
            metadata_json,
        ) = row.context("reading paged content-search candidate")?;
        let Some(content_head) = content_head else {
            continue;
        };
        let read_len = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .min(content_head.len());
        if let Some(hit) = content_search_hit(&content_head[..read_len], query) {
            if parsed_text_entry_matches(&mut parsed_match_stmt, entry_id, query)? {
                continue;
            }
            push_content_search_result(
                evidence_id,
                entry_id,
                &logical_path,
                &display_name,
                &entry_kind,
                serde_json::from_str::<serde_json::Value>(&metadata_json)
                    .ok()
                    .and_then(|metadata| source_path_exact_from_metadata(&metadata)),
                hit,
                &mut results,
            );
            if results.len() >= limit {
                exhausted = false;
                break;
            }
        }
    }
    Ok(DeepSearchPhaseBatch { results, exhausted })
}

fn parsed_text_entry_matches(
    stmt: &mut rusqlite::Statement<'_>,
    entry_id: i64,
    query: &str,
) -> Result<bool> {
    let rows = stmt.query_map([entry_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut previous_part = String::new();
    let mut previous_tail = Vec::new();
    for row in rows {
        let (part_name, content) = row.context("reading parser text for search precedence")?;
        let mut searchable = Vec::with_capacity(previous_tail.len().saturating_add(content.len()));
        if previous_part == part_name {
            searchable.extend_from_slice(&previous_tail);
        }
        searchable.extend_from_slice(&content);
        if content_search_hit(&searchable, query).is_some() {
            return Ok(true);
        }
        previous_part = part_name;
        previous_tail = byte_tail(&searchable, content_search_overlap_bytes(query));
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn content_hex_search_page_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    needle: &[u8],
    max_file_bytes: u64,
    scope: &SearchScope,
    after: Option<&DeepSearchKey>,
    limit: usize,
) -> Result<DeepSearchPhaseBatch> {
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind,
                fe.content_head, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind = 'file'
           AND fe.content_head IS NOT NULL
           AND (?3 IS NULL OR fe.evidence_id > ?3
                OR (fe.evidence_id = ?3 AND fe.logical_path > ?4)
                OR (fe.evidence_id = ?3 AND fe.logical_path = ?4 AND fe.id > ?5)){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id",
        scope.sql_clause
    ))?;
    let (after_evidence, after_path, after_entry) = page_cursor_parts(after);
    let rows = stmt.query_map(
        params![
            case_id,
            evidence_id,
            after_evidence,
            after_path,
            after_entry
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, String>(6)?,
            ))
        },
    )?;
    let mut results = Vec::new();
    let mut exhausted = true;
    for row in rows {
        let (entry_id, evidence_id, logical_path, display_name, entry_kind, content, metadata) =
            row.context("reading paged hex-search candidate")?;
        let read_len = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .min(content.len());
        if let Some(offset) = find_bytes(&content[..read_len], needle) {
            results.push(DeepSearchResult {
                evidence_id,
                entry_id,
                internal_path_key: logical_path.clone(),
                logical_path,
                source_path_exact: serde_json::from_str::<serde_json::Value>(&metadata)
                    .ok()
                    .and_then(|value| source_path_exact_from_metadata(&value)),
                display_name,
                entry_kind,
                match_kind: "content".to_string(),
                selection_offset: Some(offset as i64),
                selection_length: Some(needle.len() as i64),
                data_preview: Some(hex_match_preview(
                    &content[..read_len],
                    offset,
                    needle.len(),
                )),
            });
            if results.len() >= limit {
                exhausted = false;
                break;
            }
        }
    }
    Ok(DeepSearchPhaseBatch { results, exhausted })
}

fn parsed_text_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    max_results: usize,
    scope: &SearchScope,
    results: &mut Vec<DeepSearchResult>,
) -> Result<()> {
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind,
                fe.metadata_json, segments.part_name, segments.content
         FROM filesystem_entry_text_segments segments
         JOIN filesystem_entries fe ON fe.id = segments.entry_id
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind IN ('file', 'record'){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id,
                  segments.parser_name, segments.segment_index",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(params![case_id, evidence_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, Vec<u8>>(7)?,
        ))
    })?;

    let already_matched = results
        .iter()
        .map(|result| result.entry_id)
        .collect::<HashSet<_>>();
    let mut parsed_matched = HashSet::new();
    let mut previous_entry_id = None;
    let mut previous_part = String::new();
    let mut previous_tail = Vec::new();
    for row in rows {
        if results.len() >= max_results {
            break;
        }
        let (
            entry_id,
            evidence_id,
            logical_path,
            display_name,
            entry_kind,
            metadata_json,
            part_name,
            segment_content,
        ) = row.context("reading parser-derived text search candidate")?;
        if previous_entry_id != Some(entry_id) {
            previous_entry_id = Some(entry_id);
            previous_part.clear();
            previous_tail.clear();
        }
        if already_matched.contains(&entry_id) || parsed_matched.contains(&entry_id) {
            continue;
        }

        let mut searchable =
            Vec::with_capacity(previous_tail.len().saturating_add(segment_content.len()));
        if previous_part == part_name {
            searchable.extend_from_slice(&previous_tail);
        }
        searchable.extend_from_slice(&segment_content);
        if let Some(hit) = content_search_hit(&searchable, query) {
            let preview = format!("{}: {}", part_name, hit.data_preview);
            results.push(DeepSearchResult {
                evidence_id,
                entry_id,
                internal_path_key: logical_path.clone(),
                logical_path,
                source_path_exact: serde_json::from_str::<serde_json::Value>(&metadata_json)
                    .ok()
                    .and_then(|metadata| source_path_exact_from_metadata(&metadata)),
                display_name,
                entry_kind,
                match_kind: "parsed_content".to_string(),
                // Parsed XML character positions are not byte offsets in the
                // original DOCX ZIP. Never present them as source offsets.
                selection_offset: None,
                selection_length: None,
                data_preview: Some(preview),
            });
            parsed_matched.insert(entry_id);
            continue;
        }

        previous_part = part_name;
        let tail_bytes = content_search_overlap_bytes(query);
        previous_tail = byte_tail(&searchable, tail_bytes);
    }
    Ok(())
}

fn byte_tail(bytes: &[u8], max_bytes: usize) -> Vec<u8> {
    bytes[bytes.len().saturating_sub(max_bytes)..].to_vec()
}

fn content_search_overlap_bytes(query: &str) -> usize {
    let exact_bytes = parse_hex_search_query(query).map_or(0, |bytes| bytes.len());
    let utf8_bytes = query.len();
    let utf16_bytes = query.encode_utf16().count().saturating_mul(2);
    exact_bytes
        .max(utf8_bytes)
        .max(utf16_bytes)
        .saturating_sub(1)
}

/// Category/file-type restriction for Deep Search, compiled once into an SQL
/// clause so LIMIT-bounded queries never drop in-scope hits behind
/// out-of-scope rows.
struct SearchScope {
    sql_clause: String,
}

impl SearchScope {
    fn new(category: Option<&str>, file_types: Option<&[String]>) -> Result<Self> {
        let mut sql_clause = " AND coalesce(json_extract(fe.metadata_json,'$.artifact_kind'),'') NOT IN ('filesystem_parser_error','filesystem_parser_summary')".to_string();
        if let Some(category) = category.map(str::trim).filter(|value| !value.is_empty()) {
            let literal = category.to_ascii_lowercase().replace('\'', "''");
            sql_clause.push_str(&format!(
                " AND instr(lower(\
                 coalesce(json_extract(fe.metadata_json,'$.category_main'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.category_sub'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.category_detail'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.analysis_category'),'') || ' ' || \
                 coalesce(json_extract(fe.metadata_json,'$.category_tags'),'')\
                ), '{literal}') > 0"
            ));
        }
        if let Some(types) = file_types {
            let mut likes = Vec::new();
            for raw in types {
                let ext = raw.trim().trim_start_matches('.').to_ascii_lowercase();
                if ext.is_empty() {
                    continue;
                }
                if !ext
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_')
                {
                    bail!("file type filter contains unsupported characters: {raw}");
                }
                likes.push(format!("lower(fe.name) LIKE '%.{ext}'"));
            }
            if !likes.is_empty() {
                sql_clause.push_str(&format!(" AND ({})", likes.join(" OR ")));
            }
        }
        Ok(Self { sql_clause })
    }
}

pub fn strip_hex_query_prefix(query: &str) -> Option<&str> {
    let (prefix, rest) = query.split_at_checked(4)?;
    prefix.eq_ignore_ascii_case("hex:").then_some(rest)
}

/// Parses `FF D8 FF`, `ff,d8,ff`, `0xFFD8FF`, `FF-D8-FF` style byte patterns.
pub fn parse_hex_pattern(text: &str) -> Result<Vec<u8>> {
    let cleaned = text.replace("0x", "").replace("0X", "");
    let cleaned: String = cleaned
        .chars()
        .filter(|ch| !ch.is_whitespace() && !matches!(ch, ',' | '-' | ':'))
        .collect();
    if cleaned.is_empty() {
        bail!("hex search needs at least one byte, e.g. hex:FF D8 FF");
    }
    if !cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("hex pattern may only contain hex digits and space/comma/dash separators");
    }
    if !cleaned.len().is_multiple_of(2) {
        bail!("hex pattern must contain whole bytes (an even number of hex digits)");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).context("parsing hex byte"))
        .collect()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex_match_preview(bytes: &[u8], offset: usize, length: usize) -> String {
    let start = offset.saturating_sub(8);
    let end = offset
        .saturating_add(length)
        .saturating_add(8)
        .min(bytes.len());
    bytes[start..end]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ascii_match_preview(bytes: &[u8], offset: usize, length: usize) -> String {
    let start = offset.saturating_sub(8);
    let end = offset
        .saturating_add(length)
        .saturating_add(8)
        .min(bytes.len());
    bytes[start..end]
        .iter()
        .map(|byte| match byte {
            0x20..=0x7E => char::from(*byte),
            _ => '.',
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct RawDiskSearchOptions {
    pub evidence_id: i64,
    pub query: String,
    pub max_results: usize,
    /// Bytes to scan before stopping, starting from the beginning of the
    /// evidence source. 0 means unlimited (scan the whole evidence) - same
    /// "0 = no cap" convention used by Timeline/recursive-bookmark limits
    /// elsewhere, so the examiner has to explicitly opt into a full scan.
    pub max_scan_bytes: u64,
}

/// Continuation for a bounded raw-search result page.  `encoding` is part of
/// the ordering key because ASCII and UTF-16 matches can begin at the same
/// absolute byte offset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawSearchCursor {
    pub evidence_id: i64,
    pub query: String,
    pub max_scan_bytes: u64,
    pub offset: u64,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawSearchHit {
    pub offset: u64,
    pub length: usize,
    pub encoding: String,
    pub data_preview: String,
    pub ascii_preview: String,
    pub sector: u64,
    /// Deprecated zero-based compatibility alias.
    pub partition_index: Option<usize>,
    pub volume_index_zero_based: Option<usize>,
    pub partition_number_one_based: Option<usize>,
    pub volume_name: Option<String>,
    pub partition_start_offset: Option<u64>,
    pub filesystem: Option<String>,
    pub region: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawSearchResult {
    pub evidence_id: i64,
    pub evidence_display_name: String,
    pub source_path: String,
    pub evidence_sha256_hex: Option<String>,
    pub evidence_hashed_at: Option<String>,
    pub sector_size: u64,
    pub searched_at: String,
    pub actor: String,
    pub query: String,
    pub encodings: Vec<String>,
    pub scan_start: u64,
    pub max_scan_bytes: u64,
    pub max_results: usize,
    pub total_size: u64,
    pub bytes_scanned: u64,
    pub stop_reason: RawSearchStopReason,
    pub read_error: Option<String>,
    /// Present when another bounded response page is available. Resuming this
    /// cursor resumes from the overlap needed to preserve cross-chunk and
    /// same-offset matches.
    pub next_cursor: Option<RawSearchCursor>,
    /// True only after the search reached end-of-evidence. A configured byte
    /// budget remains explicitly incomplete (`stop_reason = byte_limit`).
    pub complete: bool,
    pub coverage: RawSearchCoverage,
    /// Compatibility derivative: false only for a complete EOF scan.
    pub truncated: bool,
    pub hits: Vec<RawSearchHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawSearchCoverage {
    pub source_scope: &'static str,
    pub hit_attribution: &'static str,
    pub folder_evidence_supported: bool,
}

fn raw_search_coverage(source_kind: &str) -> RawSearchCoverage {
    if source_kind == "file" {
        RawSearchCoverage {
            source_scope: "attached file byte stream from offset zero through EOF (or an explicitly reported examiner byte budget)",
            hit_attribution: "absolute offset within the attached file source; no partition or filesystem-file ownership is inferred",
            folder_evidence_supported: false,
        }
    } else {
        RawSearchCoverage {
            source_scope: "decoded image byte stream from offset zero through EOF (or an explicitly reported examiner byte budget), including partition gaps, unallocated space, and slack",
            hit_attribution: "absolute decoded-media offset and containing volume when known; ownership by a parsed filesystem file is not inferred",
            folder_evidence_supported: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawSearchStopReason {
    Eof,
    ByteLimit,
    ResultLimit,
    Cancelled,
    ReadError,
}

impl RawSearchStopReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eof => "eof",
            Self::ByteLimit => "byte_limit",
            Self::ResultLimit => "result_limit",
            Self::Cancelled => "cancelled",
            Self::ReadError => "read_error",
        }
    }

    fn is_partial(self) -> bool {
        self != Self::Eof
    }
}

pub const RAW_SEARCH_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const RAW_SEARCH_SECTOR_SIZE: u64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHitLocation {
    pub partition_index: Option<usize>,
    pub volume_index_zero_based: Option<usize>,
    pub partition_number_one_based: Option<usize>,
    pub volume_name: Option<String>,
    pub partition_start_offset: Option<u64>,
    pub filesystem: Option<String>,
    pub region: String,
}

pub fn raw_search_sector(offset: u64, sector_size: u64) -> u64 {
    offset / sector_size
}

pub fn classify_raw_hit_location(
    source_kind: &str,
    offset: u64,
    volumes: &[LiveVolume],
) -> RawHitLocation {
    if source_kind == "file" {
        return RawHitLocation {
            partition_index: None,
            volume_index_zero_based: None,
            partition_number_one_based: None,
            volume_name: None,
            partition_start_offset: None,
            filesystem: None,
            region: "not-applicable (file evidence)".to_string(),
        };
    }

    for volume in volumes {
        let volume_end = volume.start_offset.saturating_add(volume.size_bytes);
        if offset >= volume.start_offset && offset < volume_end {
            return RawHitLocation {
                partition_index: Some(volume.volume_index_zero_based),
                volume_index_zero_based: Some(volume.volume_index_zero_based),
                partition_number_one_based: volume.partition_number_one_based,
                volume_name: Some(volume.name.clone()),
                partition_start_offset: Some(volume.start_offset),
                filesystem: Some(volume.filesystem.clone()),
                region: "in-partition".to_string(),
            };
        }
    }

    RawHitLocation {
        partition_index: None,
        volume_index_zero_based: None,
        partition_number_one_based: None,
        volume_name: None,
        partition_start_offset: None,
        filesystem: None,
        region: "partition-gap/unpartitioned".to_string(),
    }
}

fn raw_search_encodings(query: &str) -> Vec<String> {
    if strip_hex_query_prefix(query).is_some() {
        vec!["hex".to_string()]
    } else {
        vec![
            "ascii".to_string(),
            "utf16le".to_string(),
            "utf16be".to_string(),
        ]
    }
}

/// Scans an evidence source's raw bytes directly, independent of any parsed
/// file system - the same read path `hash_evidence` already uses to stream
/// the whole decoded image/file for hashing, reused here for keyword/hex
/// scanning instead. Because this walks bytes rather than filesystem_entries
/// rows, it naturally covers unallocated space and file slack along with
/// allocated files - there is no "kind" of on-disk region it skips, unlike
/// `deep_search`'s content_head index which deliberately excludes those (see
/// `should_index_content_head`). `max_scan_bytes = 0` scans to EOF; a nonzero
/// examiner-selected byte budget is reported as incomplete when it controls.
pub fn raw_disk_search(case_path: &Path, options: RawDiskSearchOptions) -> Result<RawSearchResult> {
    raw_disk_search_page(case_path, options, None)
}

/// Returns one bounded page of a whole-evidence byte search. A result-limit
/// stop always includes a resumable cursor; callers can keep requesting pages
/// until `complete` is true without omitting matches or retaining an
/// unbounded hit vector.
pub fn raw_disk_search_page(
    case_path: &Path,
    options: RawDiskSearchOptions,
    cursor: Option<RawSearchCursor>,
) -> Result<RawSearchResult> {
    let query = options.query.trim();
    if query.is_empty() {
        bail!("search query cannot be empty");
    }
    // Honor the examiner-requested response bound instead of silently
    // reducing it. The stop reason remains explicit when that bound controls.
    if options.max_results == 0 {
        bail!("raw search page size must be at least 1");
    }
    if options.max_results > SEARCH_RESPONSE_PAGE_MAX {
        bail!(
            "raw search page size {} exceeds the protective response maximum of {SEARCH_RESPONSE_PAGE_MAX}; this bounds one response only, and cursors preserve complete search coverage",
            options.max_results
        );
    }
    let max_results = options.max_results;
    let result_lookahead = max_results
        .checked_add(1)
        .context("raw search page size is too large")?;
    let max_scan_bytes = if options.max_scan_bytes == 0 {
        u64::MAX
    } else {
        options.max_scan_bytes
    };

    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let (
        source_kind,
        source_path,
        evidence_display_name,
        evidence_sha256_hex,
        evidence_hashed_at,
    ): (String, String, String, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT source_kind, source_path, display_name, sha256_hex, hashed_at
             FROM evidence_sources
             WHERE case_id = ?1 AND id = ?2",
            params![case_id, options.evidence_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .context("evidence source not found")?;
    let actor = audit_actor(&conn, case_id)?;
    let encodings = raw_search_encodings(query);
    if let Some(cursor) = cursor.as_ref() {
        if cursor.evidence_id != options.evidence_id
            || cursor.query != query
            || cursor.max_scan_bytes != options.max_scan_bytes
        {
            bail!("raw search continuation does not match this evidence, query, or scan range");
        }
        if !encodings
            .iter()
            .any(|encoding| encoding == &cursor.encoding)
        {
            bail!("raw search continuation encoding does not match this query");
        }
    }
    let volumes = if source_kind == "image" {
        list_image_volumes(Path::new(&source_path))
            .context("mapping image volumes for raw search")?
    } else {
        Vec::new()
    };

    let (mut reader, total_size): (Box<dyn disk_forensic::container::ReadSeek>, u64) =
        match source_kind.as_str() {
            "image" => {
                let opened = open_disk_image(Path::new(&source_path))?;
                (opened.reader, opened.decoded_size)
            }
            "file" => {
                let metadata = fs::metadata(&source_path)
                    .with_context(|| format!("reading evidence metadata {source_path}"))?;
                if !metadata.is_file() {
                    bail!("raw disk search supports image and file evidence; this evidence path is not a file");
                }
                let file = fs::File::open(&source_path)
                    .with_context(|| format!("opening evidence {source_path}"))?;
                (Box::new(file), metadata.len())
            }
            _ => bail!(
                "raw disk search supports image and file evidence; {source_kind} evidence has no single raw byte stream to scan"
            ),
        };

    let hex_needle = strip_hex_query_prefix(query)
        .map(parse_hex_pattern)
        .transpose()?;
    let utf16_units: Vec<u16> = if hex_needle.is_some() {
        Vec::new()
    } else {
        query.encode_utf16().collect()
    };
    let ascii_needle: &[u8] = if hex_needle.is_some() {
        &[]
    } else {
        query.as_bytes()
    };
    let max_needle_len = hex_needle
        .as_ref()
        .map(Vec::len)
        .unwrap_or(0)
        .max(ascii_needle.len())
        .max(utf16_units.len().saturating_mul(2));
    if max_needle_len == 0 {
        bail!("search query has no matchable bytes");
    }
    let overlap = max_needle_len.saturating_sub(1);
    let scan_end = total_size.min(max_scan_bytes);
    let scan_start = cursor
        .as_ref()
        .map(|value| value.offset.saturating_sub(overlap as u64))
        .unwrap_or(0)
        .min(scan_end);
    reader
        .seek(SeekFrom::Start(scan_start))
        .context("seeking to raw search continuation")?;
    let mut hits: Vec<RawSearchHit> = Vec::new();
    let mut bytes_scanned = 0_u64;
    // EA-009: track WHY the scan stopped (not just a truncated bool) so the
    // examiner is told whether more matches may exist (result cap or byte
    // budget) versus a complete scan to end-of-evidence.
    let mut window: Vec<u8> = Vec::new();
    let mut window_start = scan_start;
    let mut read_position = scan_start;
    let mut buffer = vec![0_u8; RAW_SEARCH_CHUNK_BYTES];

    let stop_reason = loop {
        let want = usize::try_from(scan_end.saturating_sub(read_position))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = if want == 0 {
            0
        } else {
            reader
                .read(&mut buffer[..want])
                .context("reading evidence for raw search")?
        };
        if read > 0 {
            bytes_scanned = bytes_scanned.saturating_add(read as u64);
            read_position = read_position.saturating_add(read as u64);
            window.extend_from_slice(&buffer[..read]);
        }
        let terminal = read == 0 || read_position >= scan_end;
        let safe_len = if terminal {
            window.len()
        } else {
            window.len().saturating_sub(overlap)
        };
        if safe_len > 0 {
            let remaining_lookahead = result_lookahead.saturating_sub(hits.len()).max(1);
            let candidates = scan_raw_matches(
                &window,
                window_start,
                safe_len,
                hex_needle.as_deref(),
                ascii_needle,
                &utf16_units,
                remaining_lookahead,
                cursor.as_ref(),
            );
            for hit in candidates {
                if cursor
                    .as_ref()
                    .is_some_and(|after| !raw_hit_follows_cursor(&hit, after))
                {
                    continue;
                }
                hits.push(hit);
                if hits.len() >= result_lookahead {
                    break;
                }
            }
        }
        if hits.len() >= result_lookahead {
            break RawSearchStopReason::ResultLimit;
        }
        if terminal {
            break if scan_end < total_size {
                RawSearchStopReason::ByteLimit
            } else {
                RawSearchStopReason::Eof
            };
        }
        window_start += safe_len as u64;
        window.drain(0..safe_len);
    };
    if hits.len() > max_results {
        hits.truncate(max_results);
    }
    let next_cursor = (stop_reason == RawSearchStopReason::ResultLimit)
        .then(|| hits.last())
        .flatten()
        .map(|hit| RawSearchCursor {
            evidence_id: options.evidence_id,
            query: query.to_string(),
            max_scan_bytes: options.max_scan_bytes,
            offset: hit.offset,
            encoding: hit.encoding.clone(),
        });
    let truncated = stop_reason.is_partial();
    for hit in &mut hits {
        let location = classify_raw_hit_location(&source_kind, hit.offset, &volumes);
        hit.sector = raw_search_sector(hit.offset, RAW_SEARCH_SECTOR_SIZE);
        hit.partition_index = location.partition_index;
        hit.volume_index_zero_based = location.volume_index_zero_based;
        hit.partition_number_one_based = location.partition_number_one_based;
        hit.volume_name = location.volume_name;
        hit.partition_start_offset = location.partition_start_offset;
        hit.filesystem = location.filesystem;
        hit.region = location.region;
    }

    let searched_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let encodings_json =
        serde_json::to_string(&encodings).context("serializing raw search encodings")?;
    conn.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'raw_search.run', ?2, 'evidence', ?3,
                 json_object('query', ?4,
                             'encodings', json(?5),
                             'bytes_scanned', ?6,
                             'total_size', ?7,
                             'hit_count', ?8,
                             'truncated', CASE WHEN ?9 != 0 THEN json('true') ELSE json('false') END,
                             'max_scan_bytes', ?10,
                             'sector_size', ?11,
                             'evidence_sha256_hex', ?12,
                             'stop_reason', ?13,
                             'scan_start', ?14,
                             'continuation_available', CASE WHEN ?15 != 0 THEN json('true') ELSE json('false') END))",
        params![
            case_id,
            actor.as_str(),
            options.evidence_id,
            query,
            encodings_json,
            i64::try_from(bytes_scanned).unwrap_or(i64::MAX),
            i64::try_from(total_size).unwrap_or(i64::MAX),
            i64::try_from(hits.len()).unwrap_or(i64::MAX),
            if truncated { 1 } else { 0 },
            i64::try_from(options.max_scan_bytes).unwrap_or(i64::MAX),
            i64::try_from(RAW_SEARCH_SECTOR_SIZE).unwrap_or(i64::MAX),
            evidence_sha256_hex.as_deref(),
            stop_reason.as_str(),
            i64::try_from(scan_start).unwrap_or(i64::MAX),
            if next_cursor.is_some() { 1 } else { 0 },
        ],
    )?;

    Ok(RawSearchResult {
        evidence_id: options.evidence_id,
        evidence_display_name,
        source_path,
        evidence_sha256_hex,
        evidence_hashed_at,
        sector_size: RAW_SEARCH_SECTOR_SIZE,
        searched_at,
        actor,
        query: query.to_string(),
        encodings,
        scan_start,
        max_scan_bytes: options.max_scan_bytes,
        max_results,
        total_size,
        bytes_scanned,
        stop_reason,
        read_error: None,
        next_cursor,
        complete: stop_reason == RawSearchStopReason::Eof,
        coverage: raw_search_coverage(&source_kind),
        truncated,
        hits,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_raw_matches(
    window: &[u8],
    window_start: u64,
    start_limit: usize,
    hex_needle: Option<&[u8]>,
    ascii_needle: &[u8],
    utf16_units: &[u16],
    max_results: usize,
    after: Option<&RawSearchCursor>,
) -> Vec<RawSearchHit> {
    let mut hits = Vec::new();
    if let Some(needle) = hex_needle {
        scan_one_raw_encoding(
            window,
            window_start,
            start_limit,
            needle.len(),
            "hex",
            max_results,
            after,
            &mut hits,
            |hay| find_bytes(hay, needle),
        );
        return hits;
    }
    if !ascii_needle.is_empty() {
        let mut encoding_hits = Vec::new();
        scan_one_raw_encoding(
            window,
            window_start,
            start_limit,
            ascii_needle.len(),
            "ascii",
            max_results,
            after,
            &mut encoding_hits,
            |hay| find_ascii_case_insensitive_bytes(hay, ascii_needle),
        );
        hits.extend(encoding_hits);
    }
    if !utf16_units.is_empty() {
        let byte_len = utf16_units.len().saturating_mul(2);
        let mut encoding_hits = Vec::new();
        scan_one_raw_encoding(
            window,
            window_start,
            start_limit,
            byte_len,
            "utf16le",
            max_results,
            after,
            &mut encoding_hits,
            |hay| find_utf16_ascii_case_insensitive_bytes(hay, utf16_units, true),
        );
        hits.extend(encoding_hits);
        let mut encoding_hits = Vec::new();
        scan_one_raw_encoding(
            window,
            window_start,
            start_limit,
            byte_len,
            "utf16be",
            max_results,
            after,
            &mut encoding_hits,
            |hay| find_utf16_ascii_case_insensitive_bytes(hay, utf16_units, false),
        );
        hits.extend(encoding_hits);
    }
    hits.sort_by(|left, right| {
        left.offset
            .cmp(&right.offset)
            .then_with(|| {
                raw_encoding_rank(&left.encoding).cmp(&raw_encoding_rank(&right.encoding))
            })
            .then_with(|| left.encoding.cmp(&right.encoding))
    });
    hits.truncate(max_results);
    hits
}

fn raw_encoding_rank(encoding: &str) -> u8 {
    match encoding {
        "hex" | "ascii" => 0,
        "utf16le" => 1,
        "utf16be" => 2,
        _ => u8::MAX,
    }
}

fn raw_hit_follows_cursor(hit: &RawSearchHit, cursor: &RawSearchCursor) -> bool {
    hit.offset > cursor.offset
        || (hit.offset == cursor.offset
            && (raw_encoding_rank(&hit.encoding), hit.encoding.as_str())
                > (
                    raw_encoding_rank(&cursor.encoding),
                    cursor.encoding.as_str(),
                ))
}

#[allow(clippy::too_many_arguments)]
fn scan_one_raw_encoding(
    window: &[u8],
    window_start: u64,
    start_limit: usize,
    needle_len: usize,
    encoding: &'static str,
    max_results: usize,
    after: Option<&RawSearchCursor>,
    hits: &mut Vec<RawSearchHit>,
    finder: impl Fn(&[u8]) -> Option<usize>,
) {
    if needle_len == 0 {
        return;
    }
    let mut pos = 0_usize;
    while pos < start_limit && pos + needle_len <= window.len() && hits.len() < max_results {
        let Some(relative) = finder(&window[pos..]) else {
            break;
        };
        let match_start = pos + relative;
        if match_start >= start_limit {
            break;
        }
        let hit = RawSearchHit {
            offset: window_start + match_start as u64,
            length: needle_len,
            encoding: encoding.to_string(),
            data_preview: hex_match_preview(window, match_start, needle_len),
            ascii_preview: ascii_match_preview(window, match_start, needle_len),
            sector: raw_search_sector(window_start + match_start as u64, RAW_SEARCH_SECTOR_SIZE),
            partition_index: None,
            volume_index_zero_based: None,
            partition_number_one_based: None,
            volume_name: None,
            partition_start_offset: None,
            filesystem: None,
            region: String::new(),
        };
        if after.is_none_or(|cursor| raw_hit_follows_cursor(&hit, cursor)) {
            hits.push(hit);
        }
        pos = match_start + 1;
    }
}

struct ContentSearchHit {
    offset: usize,
    length: usize,
    data_preview: String,
}

fn path_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    query_lower: &str,
    max_results: usize,
    scope: &SearchScope,
) -> Result<Vec<DeepSearchResult>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND (
                instr(lower(fe.logical_path), ?3) > 0
                OR instr(lower(fe.name), ?3) > 0
                OR instr(lower(fe.metadata_json), ?3) > 0
           ){}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id
         LIMIT ?4",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(
        params![case_id, evidence_id, query_lower, max_results as i64],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    )?;
    let results = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("searching indexed paths")?
        .into_iter()
        .map(
            |(entry_id, evidence_id, logical_path, name, entry_kind, metadata_json)| {
                let source_path_exact = serde_json::from_str::<serde_json::Value>(&metadata_json)
                    .ok()
                    .and_then(|metadata| source_path_exact_from_metadata(&metadata));
                // A hit can come from the path/name text or from parsed metadata (e.g. an email
                // subject/body a parser extracted). Report which one actually matched instead of
                // always labeling it "path", and show the real matching text for metadata hits
                // instead of just repeating the file path.
                let matched_path_or_name = logical_path.to_ascii_lowercase().contains(query_lower)
                    || name.to_ascii_lowercase().contains(query_lower);
                if matched_path_or_name {
                    return DeepSearchResult {
                        evidence_id,
                        entry_id,
                        internal_path_key: logical_path.clone(),
                        logical_path: logical_path.clone(),
                        source_path_exact: source_path_exact.clone(),
                        display_name: name,
                        entry_kind,
                        match_kind: "path".to_string(),
                        selection_offset: None,
                        selection_length: None,
                        data_preview: source_path_exact.or(Some(logical_path)),
                    };
                }
                if let Some(offset) = metadata_json.to_ascii_lowercase().find(query_lower) {
                    return DeepSearchResult {
                        evidence_id,
                        entry_id,
                        internal_path_key: logical_path.clone(),
                        logical_path,
                        source_path_exact,
                        display_name: name,
                        entry_kind,
                        match_kind: "metadata".to_string(),
                        selection_offset: None,
                        selection_length: None,
                        data_preview: Some(content_preview(&metadata_json, offset, query.len())),
                    };
                }
                // The SQL WHERE clause guarantees one of the three fields matched; fall back to a
                // path-style result if the classification above somehow finds none (should not
                // happen in practice).
                DeepSearchResult {
                    evidence_id,
                    entry_id,
                    internal_path_key: logical_path.clone(),
                    logical_path: logical_path.clone(),
                    source_path_exact: source_path_exact.clone(),
                    display_name: name,
                    entry_kind,
                    match_kind: "path".to_string(),
                    selection_offset: None,
                    selection_length: None,
                    data_preview: source_path_exact.or(Some(logical_path)),
                }
            },
        )
        .collect();
    Ok(results)
}

fn content_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    query: &str,
    max_file_bytes: u64,
    max_results: usize,
    scope: &SearchScope,
    results: &mut Vec<DeepSearchResult>,
) -> Result<()> {
    // Content Deep Search is an index lookup over the first CONTENT_INDEX_BYTES of each processed
    // non-media file. Matches beyond that window, media files, and entries from existing cases that
    // have not been reprocessed are not indexed and therefore keep content_head NULL.
    // Examine every indexed file in scope while streaming rows to bound memory.
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind,
                fe.content_head, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind = 'file'{}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(params![case_id, evidence_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<Vec<u8>>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let already_matched = results
        .iter()
        .map(|result| result.entry_id)
        .collect::<HashSet<_>>();
    for row in rows {
        if results.len() >= max_results {
            break;
        }
        let (
            entry_id,
            evidence_id,
            logical_path,
            display_name,
            entry_kind,
            content_head,
            metadata_json,
        ) = row.context("reading content search candidate")?;
        if already_matched.contains(&entry_id) {
            continue;
        }
        let Some(content_head) = content_head else {
            continue;
        };
        let read_len = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .min(content_head.len());
        let bytes = &content_head[..read_len];
        if let Some(hit) = content_search_hit(bytes, query) {
            push_content_search_result(
                evidence_id,
                entry_id,
                &logical_path,
                &display_name,
                &entry_kind,
                serde_json::from_str::<serde_json::Value>(&metadata_json)
                    .ok()
                    .and_then(|metadata| source_path_exact_from_metadata(&metadata)),
                hit,
                results,
            );
        }
    }
    Ok(())
}

/// Byte-pattern Deep Search over the same indexed content windows the text
/// content search uses. Reports the byte offset and length of each match.
#[allow(clippy::too_many_arguments)]
fn content_hex_search_results(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    needle: &[u8],
    max_file_bytes: u64,
    max_results: usize,
    scope: &SearchScope,
    results: &mut Vec<DeepSearchResult>,
) -> Result<()> {
    // Examine every content-indexed file in scope while streaming rows to
    // bound memory.
    let mut stmt = conn.prepare(&format!(
        "SELECT fe.id, fe.evidence_id, fe.logical_path, fe.name, fe.entry_kind,
                fe.content_head, fe.metadata_json
         FROM filesystem_entries fe
         WHERE fe.case_id = ?1
           AND (?2 IS NULL OR fe.evidence_id = ?2)
           AND fe.entry_kind = 'file'
           AND fe.content_head IS NOT NULL{}
         ORDER BY fe.evidence_id, fe.logical_path, fe.id",
        scope.sql_clause
    ))?;
    let rows = stmt.query_map(params![case_id, evidence_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<Vec<u8>>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        if results.len() >= max_results {
            break;
        }
        let (
            entry_id,
            evidence_id,
            logical_path,
            display_name,
            entry_kind,
            content_head,
            metadata_json,
        ) = row.context("reading hex search candidate")?;
        let Some(content_head) = content_head else {
            continue;
        };
        let read_len = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .min(content_head.len());
        let bytes = &content_head[..read_len];
        if let Some(offset) = find_bytes(bytes, needle) {
            results.push(DeepSearchResult {
                evidence_id,
                entry_id,
                internal_path_key: logical_path.clone(),
                logical_path,
                source_path_exact: serde_json::from_str::<serde_json::Value>(&metadata_json)
                    .ok()
                    .and_then(|metadata| source_path_exact_from_metadata(&metadata)),
                display_name,
                entry_kind,
                match_kind: "content".to_string(),
                selection_offset: Some(offset as i64),
                selection_length: Some(needle.len() as i64),
                data_preview: Some(hex_match_preview(bytes, offset, needle.len())),
            });
        }
    }
    Ok(())
}

fn content_search_hit(bytes: &[u8], query: &str) -> Option<ContentSearchHit> {
    let content_match = find_content_search_match(bytes, query)?;
    Some(ContentSearchHit {
        offset: content_match.offset,
        length: content_match.length,
        data_preview: content_byte_preview(bytes, content_match.offset, content_match.length),
    })
}

fn push_content_search_result(
    evidence_id: i64,
    entry_id: i64,
    logical_path: &str,
    display_name: &str,
    entry_kind: &str,
    source_path_exact: Option<String>,
    hit: ContentSearchHit,
    results: &mut Vec<DeepSearchResult>,
) {
    results.push(DeepSearchResult {
        evidence_id,
        entry_id,
        internal_path_key: logical_path.to_string(),
        logical_path: logical_path.to_string(),
        source_path_exact,
        display_name: display_name.to_string(),
        entry_kind: entry_kind.to_string(),
        match_kind: "content".to_string(),
        selection_offset: Some(hit.offset as i64),
        selection_length: Some(hit.length as i64),
        data_preview: Some(hit.data_preview),
    });
}

struct ContentSearchMatch {
    offset: usize,
    length: usize,
}

fn find_content_search_match(bytes: &[u8], query: &str) -> Option<ContentSearchMatch> {
    if let Some(hex_bytes) = parse_hex_search_query(query) {
        return find_exact_bytes(bytes, &hex_bytes).map(|offset| ContentSearchMatch {
            offset,
            length: hex_bytes.len(),
        });
    }

    let mut best: Option<ContentSearchMatch> = None;
    let query_bytes = query.as_bytes();
    maybe_keep_earliest_match(
        &mut best,
        find_ascii_case_insensitive_bytes(bytes, query_bytes),
        query_bytes.len(),
    );

    let utf16_units = query.encode_utf16().collect::<Vec<_>>();
    let utf16_len = utf16_units.len().saturating_mul(2);
    let le_offset = find_utf16_ascii_case_insensitive_bytes(bytes, &utf16_units, true);
    let mut be_offset = find_utf16_ascii_case_insensitive_bytes(bytes, &utf16_units, false);
    // For ASCII text, a UTF-16LE string at offset N preceded by a 0x00 byte also scans as a
    // valid UTF-16BE match at N-1 (its 1-byte shadow). Windows/NTFS evidence is UTF-16LE in
    // practice, so when the BE candidate is exactly the shadow of the LE candidate, keep LE.
    if let (Some(le), Some(be)) = (le_offset, be_offset) {
        if be + 1 == le {
            be_offset = None;
        }
    }
    maybe_keep_earliest_match(&mut best, le_offset, utf16_len);
    maybe_keep_earliest_match(&mut best, be_offset, utf16_len);

    best
}

fn maybe_keep_earliest_match(
    best: &mut Option<ContentSearchMatch>,
    offset: Option<usize>,
    length: usize,
) {
    let Some(offset) = offset else {
        return;
    };
    if length == 0 {
        return;
    }
    if best.as_ref().is_none_or(|current| offset < current.offset) {
        *best = Some(ContentSearchMatch { offset, length });
    }
}

fn parse_hex_search_query(query: &str) -> Option<Vec<u8>> {
    let trimmed = query.trim();
    let lower = trimmed.to_ascii_lowercase();
    let raw = if lower.starts_with("hex:") {
        &trimmed[4..]
    } else if lower.starts_with("bytes:") {
        &trimmed[6..]
    } else if lower.starts_with("0x") {
        &trimmed[2..]
    } else {
        return None;
    };
    let compact = raw
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '_' && *ch != '-')
        .collect::<String>();
    if compact.is_empty()
        || compact.len() % 2 != 0
        || !compact.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for index in (0..compact.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&compact[index..index + 2], 16).ok()?);
    }
    Some(bytes)
}

pub fn find_exact_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn find_ascii_case_insensitive_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| ascii_fold_byte(*left) == ascii_fold_byte(*right))
    })
}

pub fn find_utf16_ascii_case_insensitive_bytes(
    haystack: &[u8],
    needle: &[u16],
    little_endian: bool,
) -> Option<usize> {
    let byte_len = needle.len().checked_mul(2)?;
    if byte_len == 0 || byte_len > haystack.len() {
        return None;
    }
    // Check every byte offset, not only even ones: on-disk UTF-16 text carries no alignment
    // guarantee (strings after odd-length prefixes, in slack, or in unallocated space).
    for offset in 0..=haystack.len() - byte_len {
        let mut matched = true;
        for (index, expected) in needle.iter().enumerate() {
            let position = offset + (index * 2);
            let actual = if little_endian {
                u16::from_le_bytes([haystack[position], haystack[position + 1]])
            } else {
                u16::from_be_bytes([haystack[position], haystack[position + 1]])
            };
            if ascii_fold_u16(actual) != ascii_fold_u16(*expected) {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(offset);
        }
    }
    None
}

fn ascii_fold_byte(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte.to_ascii_lowercase()
    } else {
        byte
    }
}

fn ascii_fold_u16(value: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&value) {
        value + 32
    } else {
        value
    }
}

fn content_byte_preview(bytes: &[u8], offset: usize, length: usize) -> String {
    let start = offset.saturating_sub(64);
    let end = offset
        .saturating_add(length)
        .saturating_add(96)
        .min(bytes.len());
    let mut preview = String::new();
    if start > 0 {
        preview.push_str("...");
    }
    preview.push_str(&printable_ascii_preview(&bytes[start..end]));
    if end < bytes.len() {
        preview.push_str("...");
    }

    let matched_end = offset.saturating_add(length).min(bytes.len());
    let matched_hex = bytes[offset..matched_end]
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    if !matched_hex.is_empty() {
        preview.push_str(" | hex ");
        preview.push_str(&matched_hex);
        if matched_end.saturating_sub(offset) > 32 {
            preview.push_str(" ...");
        }
    }
    preview
}

fn printable_ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if (32..=126).contains(byte) {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

fn content_preview(text: &str, offset: usize, length: usize) -> String {
    let mut start = offset.saturating_sub(80);
    let mut end = (offset + length + 120).min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    let mut preview = String::new();
    if start > 0 {
        preview.push_str("...");
    }
    preview.push_str(text[start..end].trim());
    if end < text.len() {
        preview.push_str("...");
    }
    preview
}

