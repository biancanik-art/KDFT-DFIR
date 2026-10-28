#![forbid(unsafe_code)]

//! Native Deep Search service.
//!
//! Provides paginated full-text and pattern search across metadata, logical paths,
//! captured content, and parser-derived text with explicit coverage disclosures.

use anyhow::{bail, Result};
use kdft_case::{
    deep_search_page, DeepSearchCursor, DeepSearchOptions, DeepSearchPage, SearchMatchMode,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_SEARCH_PAGE_SIZE: usize = 100;
pub const MAX_SEARCH_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NativeMatchMode {
    #[default]
    Contains,
    Exact,
    WholeWord,
}

impl From<NativeMatchMode> for SearchMatchMode {
    fn from(m: NativeMatchMode) -> Self {
        match m {
            NativeMatchMode::Contains => SearchMatchMode::Contains,
            NativeMatchMode::Exact => SearchMatchMode::Exact,
            NativeMatchMode::WholeWord => SearchMatchMode::WholeWord,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSearchQuery {
    pub case_path: PathBuf,
    pub query: String,
    pub match_mode: NativeMatchMode,
    pub evidence_id: Option<i64>,
    pub include_content: bool,
    pub category: Option<String>,
    pub file_types: Option<Vec<String>>,
    pub cursor: Option<DeepSearchCursor>,
    pub page_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSearchResponse {
    pub results: Vec<DeepSearchResultSummary>,
    pub next_cursor: Option<DeepSearchCursor>,
    pub has_more: bool,
    pub coverage_statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepSearchResultSummary {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub display_name: String,
    /// Collision-safe indexed path used for byte access and navigation.
    pub logical_path: String,
    /// Parser-native source path used for examiner-facing presentation.
    pub source_path_exact: Option<String>,
    pub entry_kind: String,
    pub size_bytes: Option<u64>,
    pub match_field: String,
    pub match_snippet: String,
    /// Logical-file byte offset. Present only when the search engine can
    /// truthfully bind the match to bytes in the original logical file.
    pub byte_offset: Option<u64>,
    pub byte_length: Option<u64>,
}

impl DeepSearchResultSummary {
    pub fn display_path(&self) -> &str {
        self.source_path_exact
            .as_deref()
            .unwrap_or(&self.logical_path)
    }

    pub fn has_file_byte_match(&self) -> bool {
        self.match_field == "content" && self.byte_offset.is_some()
    }
}

pub struct NativeSearchService;

impl NativeSearchService {
    /// Executes one paginated Deep Search pass.
    pub fn search_page(query: &NativeSearchQuery) -> Result<NativeSearchResponse> {
        let trimmed = query.query.trim();
        if trimmed.is_empty() {
            bail!("Search query cannot be empty");
        }

        let page_size = query.page_size.clamp(1, MAX_SEARCH_PAGE_SIZE);

        let options = DeepSearchOptions {
            query: trimmed.to_string(),
            evidence_id: query.evidence_id,
            include_content: query.include_content,
            max_results: page_size,
            max_file_bytes: 64 * 1024,
            category: query.category.clone(),
            file_types: query.file_types.clone(),
            match_mode: Some(query.match_mode.into()),
        };

        let page: DeepSearchPage =
            deep_search_page(&query.case_path, options, query.cursor.clone(), page_size)?;

        let has_more = page.next_cursor.is_some();
        let results = page.results.into_iter().map(summarize_result).collect();

        let (entry_count, content_head_count, parsed_segment_count) =
            content_coverage_counts(&query.case_path, query.evidence_id)?;
        let coverage = if query.include_content
            && content_head_count == 0
            && parsed_segment_count == 0
        {
            format!(
                "Indexed filenames and paths only for this scope ({entry_count} entries): no captured file content or parsed text is present. Reprocess with content capture enabled to search file contents. Raw-byte disk sectors are not searched."
            )
        } else if query.include_content {
            format!(
                "Indexed filenames and paths across {entry_count} entries, {content_head_count} captured content heads (up to 64 KB each), and {parsed_segment_count} parsed text segments. Unindexed raw-byte disk sectors are not searched."
            )
        } else {
            format!(
                "Indexed filenames and directory paths only across {entry_count} entries. Content search disabled."
            )
        };

        Ok(NativeSearchResponse {
            results,
            next_cursor: page.next_cursor,
            has_more,
            coverage_statement: coverage,
        })
    }
}

fn summarize_result(r: kdft_case::DeepSearchResult) -> DeepSearchResultSummary {
    let is_file_byte_match = r.match_kind == "content";
    DeepSearchResultSummary {
        entry_id: r.entry_id,
        evidence_id: r.evidence_id,
        display_name: r.display_name,
        logical_path: r.internal_path_key,
        source_path_exact: r.source_path_exact,
        entry_kind: r.entry_kind,
        size_bytes: None,
        match_field: r.match_kind,
        match_snippet: r.data_preview.unwrap_or_default(),
        byte_offset: is_file_byte_match
            .then(|| r.selection_offset.map(|o| o.max(0) as u64))
            .flatten(),
        byte_length: is_file_byte_match
            .then(|| r.selection_length.map(|length| length.max(0) as u64))
            .flatten(),
    }
}

fn content_coverage_counts(
    case_path: &std::path::Path,
    evidence_id: Option<i64>,
) -> Result<(i64, i64, i64)> {
    let conn = Connection::open_with_flags(case_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (entry_count, content_head_count) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN content_head IS NOT NULL THEN 1 ELSE 0 END), 0)
           FROM filesystem_entries
          WHERE (?1 IS NULL OR evidence_id = ?1)",
        [evidence_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let parsed_segment_count = conn.query_row(
        "SELECT COUNT(*)
           FROM filesystem_entry_text_segments s
           JOIN filesystem_entries e ON e.id = s.entry_id
          WHERE (?1 IS NULL OR e.evidence_id = ?1)",
        [evidence_id],
        |row| row.get(0),
    )?;
    Ok((entry_count, content_head_count, parsed_segment_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_match_mode_conversion() {
        let mode: SearchMatchMode = NativeMatchMode::Exact.into();
        assert_eq!(mode, SearchMatchMode::Exact);
    }

    #[test]
    fn summary_preserves_source_path_and_truthful_file_byte_selection() {
        let summary = summarize_result(kdft_case::DeepSearchResult {
            evidence_id: 9,
            entry_id: 17,
            logical_path: "/internal/collision-safe-key".to_string(),
            internal_path_key: "/internal/collision-safe-key".to_string(),
            source_path_exact: Some("C:\\Evidence\\transfer.bin".to_string()),
            display_name: "transfer.bin".to_string(),
            entry_kind: "file".to_string(),
            match_kind: "content".to_string(),
            selection_offset: Some(767),
            selection_length: Some(8),
            data_preview: Some("transfer".to_string()),
            parsed_segment_kind: None,
            parsed_segment_provenance: None,
            record_context: None,
        });

        assert_eq!(summary.display_path(), "C:\\Evidence\\transfer.bin");
        assert_eq!(summary.logical_path, "/internal/collision-safe-key");
        assert_eq!(summary.byte_offset, Some(767));
        assert_eq!(summary.byte_length, Some(8));
        assert!(summary.has_file_byte_match());
    }

    #[test]
    fn parsed_text_hit_does_not_fabricate_original_file_byte_offset() {
        let summary = summarize_result(kdft_case::DeepSearchResult {
            evidence_id: 9,
            entry_id: 18,
            logical_path: "/internal/document".to_string(),
            internal_path_key: "/internal/document".to_string(),
            source_path_exact: None,
            display_name: "document.docx".to_string(),
            entry_kind: "file".to_string(),
            match_kind: "parsed_content".to_string(),
            selection_offset: Some(123),
            selection_length: Some(8),
            data_preview: Some("word/document.xml: transfer".to_string()),
            parsed_segment_kind: Some("visible_text".to_string()),
            parsed_segment_provenance: None,
            record_context: None,
        });

        assert_eq!(summary.byte_offset, None);
        assert_eq!(summary.byte_length, None);
        assert!(!summary.has_file_byte_match());
    }
}
