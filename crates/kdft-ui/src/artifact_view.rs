//! Read-only artifact/category view model for the local workbench.
//!
//! This module deliberately contains no HTTP connection state. It translates
//! the workbench's category query contract into the typed `kdft-case` paging
//! API and owns the small UI-side count cache. Keeping that boundary separate
//! makes it possible to replace JSON-derived category scans with normalized,
//! indexed artifact tables without changing the route dispatcher or browser
//! contract.

use anyhow::{Context, Result};
use kdft_case::{
    case_mutation_generation, category_entry_counts, list_entries_by_category_filtered,
    max_filesystem_entry_id, CategoryCount, CategoryEntryCursor, CategoryEntryFilters,
    CategoryEntryPage,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub(crate) const DEFAULT_CATEGORY_PAGE_LIMIT: usize = 1_000;

/// Typed representation of `/api/entries/category` query parameters.
///
/// `after` is a stable `(logical_path, id)` keyset cursor. `offset` remains in
/// the contract for compatibility with older clients, but new callers should
/// use the cursor so insertions cannot make an examiner skip or repeat rows.
#[derive(Debug)]
pub(crate) struct CategoryBrowseRequest {
    pub(crate) case_path: PathBuf,
    pub(crate) evidence_id: Option<i64>,
    pub(crate) main: String,
    pub(crate) sub: Option<String>,
    pub(crate) filters: CategoryEntryFilters,
    pub(crate) after: Option<CategoryEntryCursor>,
    pub(crate) limit: usize,
    pub(crate) offset: usize,
}

impl CategoryBrowseRequest {
    pub(crate) fn from_query(query: &HashMap<String, String>) -> Result<Self> {
        let case_path = query
            .get("case_path")
            .map(String::as_str)
            .context("case_path query parameter is required")
            .and_then(|value| super::request_path(value, "case_path"))?;
        let evidence_id = query
            .get("evidence_id")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<i64>()
                    .context("evidence_id must be an integer")
            })
            .transpose()?;
        let main = query.get("main").cloned().unwrap_or_default();
        let sub = query.get("sub").cloned();
        let limit = super::query_usize(query, "limit")?.unwrap_or(DEFAULT_CATEGORY_PAGE_LIMIT);
        let offset = super::query_usize(query, "offset")?.unwrap_or(0);
        let after = query
            .get("after_path")
            .map(|logical_path| -> Result<CategoryEntryCursor> {
                let id = query
                    .get("after_id")
                    .context("after_id is required with after_path")?
                    .parse::<i64>()
                    .context("after_id must be an integer")?;
                Ok(CategoryEntryCursor {
                    logical_path: logical_path.clone(),
                    id,
                    snapshot_generation: query.get("after_generation").cloned(),
                })
            })
            .transpose()?;
        let filters = CategoryEntryFilters {
            name: query.get("filter_name").cloned(),
            extension: query.get("filter_extension").cloned(),
            entry_type: query.get("filter_type").cloned(),
            flags: query.get("filter_flags").cloned(),
            sha256: query.get("filter_sha256").cloned(),
            from_utc: query.get("from_utc").cloned(),
            to_utc: query.get("to_utc").cloned(),
        };
        Ok(Self {
            case_path,
            evidence_id,
            main,
            sub,
            filters,
            after,
            limit,
            offset,
        })
    }
}

pub(crate) fn list_category_page(query: &HashMap<String, String>) -> Result<CategoryEntryPage> {
    let request = CategoryBrowseRequest::from_query(query)?;
    list_entries_by_category_filtered(
        &request.case_path,
        request.evidence_id,
        &request.main,
        request.sub.as_deref(),
        &request.filters,
        request.after.as_ref(),
        request.limit,
        request.offset,
    )
}

struct CategoryCountCacheEntry {
    entry_count: i64,
    max_entry_id: i64,
    mutation_generation: i64,
    counts: Vec<CategoryCount>,
}

static CATEGORY_COUNT_CACHE: OnceLock<Mutex<HashMap<PathBuf, CategoryCountCacheEntry>>> =
    OnceLock::new();

/// Returns exact taxonomy counts, cached only while all case-generation
/// witnesses remain unchanged. In-place recategorization invalidates the cache
/// through `case_mutation_generation`, even when the row count and max id stay
/// constant.
pub(crate) fn cached_category_counts(
    case_path: &Path,
    entry_count: i64,
) -> Result<Vec<CategoryCount>> {
    let cache = CATEGORY_COUNT_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let max_entry_id = max_filesystem_entry_id(case_path)?;
    let mutation_generation = case_mutation_generation(case_path)?;
    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.get(case_path) {
            if entry.entry_count == entry_count
                && entry.max_entry_id == max_entry_id
                && entry.mutation_generation == mutation_generation
            {
                return Ok(entry.counts.clone());
            }
        }
    }
    let counts = category_entry_counts(case_path)?;
    if let Ok(mut guard) = cache.lock() {
        guard.insert(
            case_path.to_path_buf(),
            CategoryCountCacheEntry {
                entry_count,
                max_entry_id,
                mutation_generation,
                counts: counts.clone(),
            },
        );
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::{CategoryBrowseRequest, DEFAULT_CATEGORY_PAGE_LIMIT};
    use std::collections::HashMap;

    fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn category_query_preserves_taxonomy_filters_and_cursor() -> anyhow::Result<()> {
        let parsed = CategoryBrowseRequest::from_query(&query(&[
            ("case_path", "case.kdft.sqlite"),
            ("evidence_id", " 42 "),
            ("main", "Operating System"),
            ("sub", "Event log records"),
            ("filter_name", "logon"),
            ("filter_extension", "evtx"),
            ("filter_type", "record"),
            ("filter_flags", "parsed"),
            ("filter_sha256", "abc123"),
            ("from_utc", "2026-10-01T00:00:00Z"),
            ("to_utc", "2026-10-02T00:00:00Z"),
            (
                "after_path",
                "/Windows/System32/winevt/Logs/Security.evtx/4624",
            ),
            ("after_id", "9001"),
            ("after_generation", "audit-42"),
            ("limit", "250"),
            ("offset", "10"),
        ]))?;

        assert_eq!(parsed.evidence_id, Some(42));
        assert_eq!(parsed.main, "Operating System");
        assert_eq!(parsed.sub.as_deref(), Some("Event log records"));
        assert_eq!(parsed.filters.name.as_deref(), Some("logon"));
        assert_eq!(parsed.filters.extension.as_deref(), Some("evtx"));
        assert_eq!(parsed.filters.entry_type.as_deref(), Some("record"));
        assert_eq!(parsed.filters.flags.as_deref(), Some("parsed"));
        assert_eq!(parsed.filters.sha256.as_deref(), Some("abc123"));
        assert_eq!(
            parsed.filters.from_utc.as_deref(),
            Some("2026-10-01T00:00:00Z")
        );
        assert_eq!(
            parsed.filters.to_utc.as_deref(),
            Some("2026-10-02T00:00:00Z")
        );
        let cursor = parsed.after.expect("cursor");
        assert_eq!(
            cursor.logical_path,
            "/Windows/System32/winevt/Logs/Security.evtx/4624"
        );
        assert_eq!(cursor.id, 9001);
        assert_eq!(cursor.snapshot_generation.as_deref(), Some("audit-42"));
        assert_eq!(parsed.limit, 250);
        assert_eq!(parsed.offset, 10);
        Ok(())
    }

    #[test]
    fn category_query_defaults_to_first_thousand_rows() -> anyhow::Result<()> {
        let parsed =
            CategoryBrowseRequest::from_query(&query(&[("case_path", "case.kdft.sqlite")]))?;

        assert_eq!(parsed.evidence_id, None);
        assert_eq!(parsed.main, "");
        assert_eq!(parsed.limit, DEFAULT_CATEGORY_PAGE_LIMIT);
        assert_eq!(parsed.offset, 0);
        assert_eq!(parsed.after, None);
        Ok(())
    }

    #[test]
    fn category_query_rejects_half_of_a_keyset_cursor() {
        let error = CategoryBrowseRequest::from_query(&query(&[
            ("case_path", "case.kdft.sqlite"),
            ("after_path", "/artifact/path"),
        ]))
        .expect_err("after_path without after_id must fail");

        assert!(error.to_string().contains("after_id is required"));
    }

    #[test]
    fn category_query_rejects_non_numeric_evidence_scope() {
        let error = CategoryBrowseRequest::from_query(&query(&[
            ("case_path", "case.kdft.sqlite"),
            ("evidence_id", "all"),
        ]))
        .expect_err("non-numeric evidence id must fail");

        assert!(error.to_string().contains("evidence_id must be an integer"));
    }
}
