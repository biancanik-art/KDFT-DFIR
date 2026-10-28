use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkFolderSummary {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub name: String,
    pub folder_comment: Option<String>,
    pub show_in_report: bool,
    pub report_order: i64,
    pub created_at: String,
    pub bookmark_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkSummary {
    pub id: i64,
    pub folder_id: i64,
    pub folder_name: String,
    pub bookmark_type: String,
    pub data_type: Option<String>,
    pub title: String,
    pub examiner_comment: Option<String>,
    pub in_report: bool,
    pub created_at: String,
    pub item_count: usize,
    #[serde(default)]
    pub is_incomplete: bool,
    #[serde(default)]
    pub checkpoint: Option<kdft_case::LiveTraversalCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkCursor {
    pub after_id: i64,
    pub snapshot_generation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkItemSummary {
    pub id: i64,
    pub bookmark_id: i64,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub item_order: i64,
    pub display_name: String,
    pub logical_path: String,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub preview_truncated: bool,
    pub ref_truncated: bool,
    #[serde(default)]
    pub ref_status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkItemDetail {
    pub id: i64,
    pub bookmark_id: i64,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub item_order: i64,
    pub display_name: String,
    pub logical_path: String,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub preview_truncated: bool,
    #[serde(default)]
    pub preview_bytes: usize,
    #[serde(default)]
    pub preview_status: String,
    pub item_ref_json: serde_json::Value,
    pub ref_truncated: bool,
    #[serde(default)]
    pub ref_bytes: usize,
    #[serde(default)]
    pub ref_status: String,
    pub created_at: String,
    pub case_generation: i64,
}

pub const DEFAULT_BOOKMARK_PAGE_SIZE: usize = 100;
pub const MAX_BOOKMARK_PAGE_SIZE: usize = 1_000;
pub const MAX_BOOKMARK_PREVIEW_CHARS: usize = 256;
pub const MAX_ITEM_DETAIL_PREVIEW_BYTES: usize = 64 * 1024;
pub const MAX_ITEM_DETAIL_REF_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkFoldersPage {
    pub folders: Vec<BookmarkFolderSummary>,
    pub total: usize,
    pub snapshot_generation: i64,
    pub next_cursor: Option<BookmarkCursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarksPage {
    pub bookmarks: Vec<BookmarkSummary>,
    pub total: usize,
    pub snapshot_generation: i64,
    pub next_cursor: Option<BookmarkCursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BookmarkItemsPage {
    pub items: Vec<BookmarkItemSummary>,
    pub total: usize,
    pub snapshot_generation: i64,
    pub next_cursor: Option<BookmarkCursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBookmarkFolderRequest {
    pub case_path: PathBuf,
    pub parent_id: Option<i64>,
    pub name: String,
    pub folder_comment: Option<String>,
    pub show_in_report: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBookmarkFolderResult {
    pub folder_id: i64,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBookmarkRequest {
    pub case_path: PathBuf,
    pub folder_name: String,
    pub title: String,
    pub bookmark_type: kdft_case::BookmarkType,
    pub data_type: Option<String>,
    pub examiner_comment: Option<String>,
    pub evidence_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub display_name: Option<String>,
    pub logical_path: Option<String>,
    pub selection_offset: Option<i64>,
    pub selection_length: Option<i64>,
    pub data_preview: Option<String>,
    pub item_ref_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBookmarkResult {
    pub folder_id: i64,
    pub bookmark_id: i64,
    pub item_id: Option<i64>,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncompleteBookmarkSummary {
    pub bookmark_id: i64,
    pub folder_id: i64,
    pub folder_name: String,
    pub title: String,
    pub bookmark_type: String,
    pub data_type: Option<String>,
    pub is_live: bool,
    pub evidence_id: i64,
    pub volume_index: usize,
    pub path: String,
    pub items_added: i64,
    pub total_candidates: i64,
    pub checkpoint: kdft_case::LiveTraversalCheckpoint,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveFolderBookmarkRequest {
    pub case_path: PathBuf,
    pub evidence_id: i64,
    pub volume_index: usize,
    pub path: String,
    pub is_live: bool,
    pub max_entries: usize,
    pub folder_name: String,
    pub title: Option<String>,
    pub examiner_comment: Option<String>,
    #[serde(default)]
    pub bitlocker_password: Option<String>,
    #[serde(default)]
    pub bitlocker_recovery_key: Option<String>,
    #[serde(default)]
    pub checkpoint: Option<kdft_case::LiveTraversalCheckpoint>,
    #[serde(default)]
    pub bookmark_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveFolderBookmarkResult {
    pub folder_id: i64,
    pub bookmark_id: i64,
    pub items_added: i64,
    pub total_candidates: i64,
    pub truncated: bool,
    pub skipped_count: u64,
    pub file_limit: Option<usize>,
    pub checkpoint: Option<kdft_case::LiveTraversalCheckpoint>,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveBookmarkResult {
    pub bookmark_id: i64,
    pub items_removed: i64,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveBookmarkItemResult {
    pub item_id: i64,
    pub bookmark_id: i64,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveBookmarkFolderResult {
    pub folder_id: i64,
    pub name: String,
    pub case_generation: Option<i64>,
    pub post_commit_warnings: Vec<String>,
}

pub struct NativeBookmarkService;

impl NativeBookmarkService {
    pub fn create_folder(
        request: CreateBookmarkFolderRequest,
    ) -> Result<CreateBookmarkFolderResult> {
        let name = request.name.trim();
        if name.is_empty() {
            bail!("Folder name cannot be empty");
        }
        let folder_id = kdft_case::create_bookmark_folder(
            &request.case_path,
            request.parent_id,
            name,
            request.folder_comment.as_deref(),
            request.show_in_report,
        )?;
        let (case_generation, warnings) = match read_case_generation(&request.case_path) {
            Ok(gen) => (Some(gen), Vec::new()),
            Err(err) => (
                None,
                vec![format!(
                    "Bookmark folder committed successfully, but the case generation could not be refreshed: {err}"
                )],
            ),
        };
        Ok(CreateBookmarkFolderResult {
            folder_id,
            case_generation,
            post_commit_warnings: warnings,
        })
    }

    pub fn list_folders_page(
        case_path: &Path,
        cursor: Option<BookmarkCursor>,
        limit: usize,
    ) -> Result<BookmarkFoldersPage> {
        if limit == 0 || limit > MAX_BOOKMARK_PAGE_SIZE {
            bail!("page limit must be between 1 and {MAX_BOOKMARK_PAGE_SIZE}");
        }
        let mut conn = open_ro_conn(case_path)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let snapshot_generation: i64 =
            tx.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
                row.get(0)
            })?;
        if let Some(ref c) = cursor {
            if c.snapshot_generation != snapshot_generation {
                bail!(
                    "stale bookmark cursor: case generation changed from {} to {}; restart the query",
                    c.snapshot_generation,
                    snapshot_generation
                );
            }
            if c.after_id < 0 {
                bail!("cursor after_id cannot be negative");
            }
        }
        let after_id = cursor.as_ref().map_or(0, |c| c.after_id);
        let case_id: i64 = tx.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
            row.get(0)
        })?;
        let total_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM bookmark_folders WHERE case_id = ?1",
            params![case_id],
            |row| row.get(0),
        )?;
        let total = usize::try_from(total_count).unwrap_or(0);
        let sql_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);

        let mut stmt = tx.prepare(
            "SELECT f.id, f.parent_id, f.name, f.folder_comment, f.show_in_report, f.report_order, f.created_at,
                    (SELECT COUNT(*) FROM bookmarks b WHERE b.folder_id = f.id) AS bookmark_count
             FROM bookmark_folders f
             WHERE f.case_id = ?1 AND f.id > ?2
             ORDER BY f.id ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![case_id, after_id, sql_limit], |row| {
            Ok(BookmarkFolderSummary {
                id: row.get(0)?,
                parent_id: row.get(1)?,
                name: row.get(2)?,
                folder_comment: row.get(3)?,
                show_in_report: row.get::<_, i64>(4)? != 0,
                report_order: row.get(5)?,
                created_at: row.get(6)?,
                bookmark_count: row.get::<_, i64>(7)? as usize,
            })
        })?;
        let mut folders = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        let has_more = folders.len() > limit;
        if has_more {
            folders.pop();
        }
        let next_cursor = if has_more {
            folders.last().map(|f| BookmarkCursor {
                after_id: f.id,
                snapshot_generation,
            })
        } else {
            None
        };
        Ok(BookmarkFoldersPage {
            folders,
            total,
            snapshot_generation,
            next_cursor,
            has_more,
        })
    }

    pub fn list_bookmarks_page(
        case_path: &Path,
        folder_id: Option<i64>,
        cursor: Option<BookmarkCursor>,
        limit: usize,
    ) -> Result<BookmarksPage> {
        if limit == 0 || limit > MAX_BOOKMARK_PAGE_SIZE {
            bail!("page limit must be between 1 and {MAX_BOOKMARK_PAGE_SIZE}");
        }
        let mut conn = open_ro_conn(case_path)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let snapshot_generation: i64 =
            tx.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
                row.get(0)
            })?;
        if let Some(ref c) = cursor {
            if c.snapshot_generation != snapshot_generation {
                bail!(
                    "stale bookmark cursor: case generation changed from {} to {}; restart the query",
                    c.snapshot_generation,
                    snapshot_generation
                );
            }
            if c.after_id < 0 {
                bail!("cursor after_id cannot be negative");
            }
        }
        let after_id = cursor.as_ref().map_or(0, |c| c.after_id);
        let case_id: i64 = tx.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
            row.get(0)
        })?;
        let total_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM bookmarks b WHERE b.case_id = ?1 AND (?2 IS NULL OR b.folder_id = ?2)",
            params![case_id, folder_id],
            |row| row.get(0),
        )?;
        let total = usize::try_from(total_count).unwrap_or(0);
        let sql_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);

        let mut stmt = tx.prepare(
            "SELECT b.id, b.folder_id, f.name, b.bookmark_type, b.data_type, b.title,
                    b.examiner_comment, b.in_report, b.created_at,
                    (SELECT COUNT(*) FROM bookmark_items bi WHERE bi.bookmark_id = b.id) AS item_count,
                    json_extract(b.source_ref_json, '$.checkpoint') AS checkpoint_json
             FROM bookmarks b
             JOIN bookmark_folders f ON f.id = b.folder_id
             WHERE b.case_id = ?1 AND (?2 IS NULL OR b.folder_id = ?2) AND b.id > ?3
             ORDER BY b.id ASC
             LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![case_id, folder_id, after_id, sql_limit], |row| {
            let cp_str: Option<String> = row.get(10)?;
            let checkpoint: Option<kdft_case::LiveTraversalCheckpoint> =
                cp_str.as_deref().and_then(|s| serde_json::from_str(s).ok());
            let is_incomplete = checkpoint.as_ref().map(|c| !c.completed).unwrap_or(false);
            Ok(BookmarkSummary {
                id: row.get(0)?,
                folder_id: row.get(1)?,
                folder_name: row.get(2)?,
                bookmark_type: row.get(3)?,
                data_type: row.get(4)?,
                title: row
                    .get::<_, Option<String>>(5)?
                    .unwrap_or_else(|| "Untitled bookmark".to_string()),
                examiner_comment: row.get(6)?,
                in_report: row.get::<_, i64>(7)? != 0,
                created_at: row.get(8)?,
                item_count: row.get::<_, i64>(9)? as usize,
                is_incomplete,
                checkpoint,
            })
        })?;
        let mut bookmarks = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        let has_more = bookmarks.len() > limit;
        if has_more {
            bookmarks.pop();
        }
        let next_cursor = if has_more {
            bookmarks.last().map(|b| BookmarkCursor {
                after_id: b.id,
                snapshot_generation,
            })
        } else {
            None
        };
        Ok(BookmarksPage {
            bookmarks,
            total,
            snapshot_generation,
            next_cursor,
            has_more,
        })
    }

    pub fn list_bookmark_items_page(
        case_path: &Path,
        bookmark_id: Option<i64>,
        cursor: Option<BookmarkCursor>,
        limit: usize,
    ) -> Result<BookmarkItemsPage> {
        if limit == 0 || limit > MAX_BOOKMARK_PAGE_SIZE {
            bail!("page limit must be between 1 and {MAX_BOOKMARK_PAGE_SIZE}");
        }
        let mut conn = open_ro_conn(case_path)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let snapshot_generation: i64 =
            tx.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
                row.get(0)
            })?;
        if let Some(ref c) = cursor {
            if c.snapshot_generation != snapshot_generation {
                bail!(
                    "stale bookmark cursor: case generation changed from {} to {}; restart the query",
                    c.snapshot_generation,
                    snapshot_generation
                );
            }
            if c.after_id < 0 {
                bail!("cursor after_id cannot be negative");
            }
        }
        let after_id = cursor.as_ref().map_or(0, |c| c.after_id);
        let case_id: i64 = tx.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
            row.get(0)
        })?;
        let total_count: i64 = tx.query_row(
            "SELECT COUNT(*)
             FROM bookmark_items bi
             JOIN bookmarks b ON b.id = bi.bookmark_id
             WHERE b.case_id = ?1 AND (?2 IS NULL OR bi.bookmark_id = ?2)",
            params![case_id, bookmark_id],
            |row| row.get(0),
        )?;
        let total = usize::try_from(total_count).unwrap_or(0);
        let sql_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);

        let mut stmt = tx.prepare(
            "SELECT bi.id, bi.bookmark_id, bi.evidence_id, bi.entry_id, bi.item_order,
                    bi.display_name, bi.logical_path, bi.selection_offset, bi.selection_length,
                    SUBSTR(bi.data_preview, 1, 256) AS data_preview,
                    (LENGTH(COALESCE(bi.data_preview, '')) > 256) AS preview_truncated,
                    (LENGTH(COALESCE(bi.item_ref_json, '')) > 256) AS ref_truncated,
                    bi.created_at
             FROM bookmark_items bi
             JOIN bookmarks b ON b.id = bi.bookmark_id
             WHERE b.case_id = ?1 AND (?2 IS NULL OR bi.bookmark_id = ?2) AND bi.id > ?3
             ORDER BY bi.id ASC
             LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![case_id, bookmark_id, after_id, sql_limit], |row| {
            Ok(BookmarkItemSummary {
                id: row.get(0)?,
                bookmark_id: row.get(1)?,
                evidence_id: row.get(2)?,
                entry_id: row.get(3)?,
                item_order: row.get(4)?,
                display_name: row
                    .get::<_, Option<String>>(5)?
                    .unwrap_or_else(|| "Unnamed item".to_string()),
                logical_path: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                selection_offset: row.get(7)?,
                selection_length: row.get(8)?,
                data_preview: row.get(9)?,
                preview_truncated: row.get::<_, i64>(10)? != 0,
                ref_truncated: row.get::<_, i64>(11)? != 0,
                ref_status: "omitted from list projection".to_string(),
                created_at: row.get(12)?,
            })
        })?;
        let mut items = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        let has_more = items.len() > limit;
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            items.last().map(|it| BookmarkCursor {
                after_id: it.id,
                snapshot_generation,
            })
        } else {
            None
        };
        Ok(BookmarkItemsPage {
            items,
            total,
            snapshot_generation,
            next_cursor,
            has_more,
        })
    }

    pub fn get_bookmark_item_detail(
        case_path: &Path,
        item_id: i64,
        expected_generation: Option<i64>,
    ) -> Result<BookmarkItemDetail> {
        let mut conn = open_ro_conn(case_path)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let generation: i64 =
            tx.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
                row.get(0)
            })?;
        if let Some(expected) = expected_generation {
            if expected != generation {
                bail!(
                    "stale bookmark item detail: case generation changed from {expected} to {generation}; reselect the item"
                );
            }
        }
        let preview_limit = i64::try_from(MAX_ITEM_DETAIL_PREVIEW_BYTES).unwrap_or(i64::MAX);
        let ref_limit = i64::try_from(MAX_ITEM_DETAIL_REF_BYTES).unwrap_or(i64::MAX);

        let mut stmt = tx.prepare(
            "SELECT id, bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path,
                    selection_offset, selection_length,
                    CASE WHEN data_preview IS NULL THEN NULL ELSE SUBSTR(data_preview, 1, ?2) END AS data_preview_projected,
                    CASE WHEN data_preview IS NULL THEN NULL ELSE LENGTH(CAST(data_preview AS BLOB)) END AS data_preview_bytes,
                    CASE WHEN item_ref_json IS NULL THEN NULL ELSE SUBSTR(item_ref_json, 1, ?3) END AS item_ref_json_projected,
                    CASE WHEN item_ref_json IS NULL THEN NULL ELSE LENGTH(CAST(item_ref_json AS BLOB)) END AS item_ref_json_bytes,
                    created_at
             FROM bookmark_items
             WHERE id = ?1",
        )?;
        let mut row_iter = stmt.query(params![item_id, preview_limit, ref_limit])?;
        let row = match row_iter.next()? {
            Some(row) => row,
            None => bail!("bookmark item {item_id} not found"),
        };

        let raw_preview: Option<String> = row.get(9)?;
        let raw_preview_bytes: Option<i64> = row.get(10)?;
        let preview_bytes = raw_preview_bytes.unwrap_or(0).max(0) as usize;
        let (data_preview, preview_truncated, preview_status) = match raw_preview {
            Some(p) => {
                if preview_bytes > MAX_ITEM_DETAIL_PREVIEW_BYTES {
                    let mut end = MAX_ITEM_DETAIL_PREVIEW_BYTES.min(p.len());
                    while end > 0 && !p.is_char_boundary(end) {
                        end -= 1;
                    }
                    (
                        Some(p[..end].to_string()),
                        true,
                        "truncated in detail projection".to_string(),
                    )
                } else {
                    (Some(p), false, "available".to_string())
                }
            }
            None => (None, false, "available".to_string()),
        };

        let raw_ref: Option<String> = row.get(11)?;
        let raw_ref_bytes: Option<i64> = row.get(12)?;
        let ref_bytes = raw_ref_bytes.unwrap_or(0).max(0) as usize;
        let (item_ref_json, ref_truncated, ref_status) = match raw_ref {
            Some(r) => {
                if ref_bytes > MAX_ITEM_DETAIL_REF_BYTES {
                    let char_limit = r
                        .char_indices()
                        .map(|(i, _)| i)
                        .take(512)
                        .last()
                        .unwrap_or(0);
                    (
                        serde_json::json!({
                            "_truncated": true,
                            "status": "truncated in detail projection",
                            "_projection": "truncated in detail projection",
                            "byte_length": ref_bytes,
                            "preview": format!("{}...", &r[..char_limit])
                        }),
                        true,
                        "truncated in detail projection".to_string(),
                    )
                } else {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&r).unwrap_or_else(|_| serde_json::json!({}));
                    (parsed, false, "available".to_string())
                }
            }
            None => (serde_json::json!({}), false, "available".to_string()),
        };

        Ok(BookmarkItemDetail {
            id: row.get(0)?,
            bookmark_id: row.get(1)?,
            evidence_id: row.get(2)?,
            entry_id: row.get(3)?,
            item_order: row.get(4)?,
            display_name: row
                .get::<_, Option<String>>(5)?
                .unwrap_or_else(|| "Unnamed item".to_string()),
            logical_path: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
            selection_offset: row.get(7)?,
            selection_length: row.get(8)?,
            data_preview,
            preview_truncated,
            preview_bytes,
            preview_status,
            item_ref_json,
            ref_truncated,
            ref_bytes,
            ref_status,
            created_at: row.get(13)?,
            case_generation: generation,
        })
    }

    pub fn list_incomplete_recursive_bookmarks(
        case_path: &Path,
    ) -> Result<Vec<IncompleteBookmarkSummary>> {
        let conn = open_ro_conn(case_path)?;
        let case_id: i64 =
            conn.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
                row.get(0)
            })?;
        let mut stmt = conn.prepare(
            "SELECT b.id, b.folder_id, f.name, b.title, b.bookmark_type, b.data_type, b.source_ref_json, b.created_at
             FROM bookmarks b
             JOIN bookmark_folders f ON f.id = b.folder_id
             WHERE b.case_id = ?1
               AND json_extract(b.source_ref_json, '$.checkpoint') IS NOT NULL
             ORDER BY b.id DESC",
        )?;
        let rows = stmt.query_map(params![case_id], |row| {
            let bookmark_id: i64 = row.get(0)?;
            let folder_id: i64 = row.get(1)?;
            let folder_name: String = row.get(2)?;
            let title: String = row.get::<_, Option<String>>(3)?.unwrap_or_default();
            let bookmark_type: String = row.get(4)?;
            let data_type: Option<String> = row.get(5)?;
            let raw_source_ref: String = row.get::<_, Option<String>>(6)?.unwrap_or_default();
            let created_at: String = row.get(7)?;

            let val: serde_json::Value =
                serde_json::from_str(&raw_source_ref).unwrap_or(serde_json::Value::Null);
            let checkpoint_val = val.get("checkpoint");
            let checkpoint: Option<kdft_case::LiveTraversalCheckpoint> =
                checkpoint_val.and_then(|v| serde_json::from_value(v.clone()).ok());

            let cp = match checkpoint {
                Some(cp) if !cp.completed => cp,
                _ => return Ok(None),
            };

            let evidence_id = val.get("evidence_id").and_then(|v| v.as_i64()).unwrap_or(0);
            let volume_index = val
                .get("volume_index")
                .or_else(|| val.get("volume"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let path = val
                .get("logical_path")
                .or_else(|| val.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let is_live = val
                .get("is_live")
                .and_then(|v| v.as_bool())
                .unwrap_or_else(|| {
                    data_type
                        .as_deref()
                        .map(|dt| dt.contains("Live") || dt.contains("live"))
                        .unwrap_or(false)
                });

            Ok(Some(IncompleteBookmarkSummary {
                bookmark_id,
                folder_id,
                folder_name,
                title,
                bookmark_type,
                data_type,
                is_live,
                evidence_id,
                volume_index,
                path,
                items_added: cp.items_added,
                total_candidates: cp.total_candidates,
                checkpoint: cp,
                created_at,
            }))
        })?;

        let mut result = Vec::new();
        for r in rows {
            if let Some(summary) = r? {
                result.push(summary);
            }
        }
        Ok(result)
    }

    pub fn get_incomplete_recursive_bookmark(
        case_path: &Path,
        bookmark_id: i64,
    ) -> Result<Option<IncompleteBookmarkSummary>> {
        let conn = open_ro_conn(case_path)?;
        let mut stmt = conn.prepare(
            "SELECT b.id, b.folder_id, f.name, b.title, b.bookmark_type, b.data_type, b.source_ref_json, b.created_at
             FROM bookmarks b
             JOIN bookmark_folders f ON f.id = b.folder_id
             WHERE b.id = ?1",
        )?;
        let mut rows = stmt.query(params![bookmark_id])?;
        let row = match rows.next()? {
            Some(row) => row,
            None => return Ok(None),
        };

        let bookmark_id: i64 = row.get(0)?;
        let folder_id: i64 = row.get(1)?;
        let folder_name: String = row.get(2)?;
        let title: String = row.get::<_, Option<String>>(3)?.unwrap_or_default();
        let bookmark_type: String = row.get(4)?;
        let data_type: Option<String> = row.get(5)?;
        let raw_source_ref: String = row.get::<_, Option<String>>(6)?.unwrap_or_default();
        let created_at: String = row.get(7)?;

        let val: serde_json::Value =
            serde_json::from_str(&raw_source_ref).unwrap_or(serde_json::Value::Null);
        let checkpoint_val = val.get("checkpoint");
        let checkpoint: Option<kdft_case::LiveTraversalCheckpoint> =
            checkpoint_val.and_then(|v| serde_json::from_value(v.clone()).ok());

        let cp = match checkpoint {
            Some(cp) if !cp.completed => cp,
            _ => return Ok(None),
        };

        let evidence_id = val.get("evidence_id").and_then(|v| v.as_i64()).unwrap_or(0);
        let volume_index = val
            .get("volume_index")
            .or_else(|| val.get("volume"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let path = val
            .get("logical_path")
            .or_else(|| val.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .to_string();
        let is_live = val
            .get("is_live")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| {
                data_type
                    .as_deref()
                    .map(|dt| dt.contains("Live") || dt.contains("live"))
                    .unwrap_or(false)
            });

        Ok(Some(IncompleteBookmarkSummary {
            bookmark_id,
            folder_id,
            folder_name,
            title,
            bookmark_type,
            data_type,
            is_live,
            evidence_id,
            volume_index,
            path,
            items_added: cp.items_added,
            total_candidates: cp.total_candidates,
            checkpoint: cp,
            created_at,
        }))
    }

    pub fn create_bookmark(request: CreateBookmarkRequest) -> Result<CreateBookmarkResult> {
        let case_path = &request.case_path;
        let folder_name = if request.folder_name.trim().is_empty() {
            "Findings"
        } else {
            request.folder_name.trim()
        };
        let title = if request.title.trim().is_empty() {
            "Bookmarked evidence".to_string()
        } else {
            request.title.trim().to_string()
        };
        let bookmark_type = request.bookmark_type;

        let item_ref_json = request
            .item_ref_json
            .unwrap_or_else(|| serde_json::json!({}));
        let source_ref_json = serde_json::json!({
            "evidence_id": request.evidence_id,
            "entry_id": request.entry_id,
            "logical_path": request.logical_path,
        });
        let content_ref_json = serde_json::json!({
            "selection_offset": request.selection_offset,
            "selection_length": request.selection_length,
            "preview": request.data_preview,
        });

        let result = kdft_case::create_bookmark_with_items(
            case_path,
            folder_name,
            kdft_case::CreateBookmarkOptions {
                folder_id: 0,
                bookmark_type,
                data_type: request.data_type,
                title: Some(title),
                examiner_comment: request.examiner_comment,
                in_report: true,
                source_ref_json,
                content_ref_json,
            },
            vec![kdft_case::CreateBookmarkItemOptions {
                bookmark_id: 0,
                evidence_id: request.evidence_id,
                entry_id: request.entry_id,
                item_order: None,
                display_name: request.display_name,
                logical_path: request.logical_path,
                selection_offset: request.selection_offset,
                selection_length: request.selection_length,
                data_preview: request.data_preview,
                item_ref_json,
            }],
        )?;

        let item_id = result.items.first().map(|i| i.id);

        let (case_generation, warnings) = match read_case_generation(case_path) {
            Ok(gen) => (Some(gen), Vec::new()),
            Err(err) => (
                None,
                vec![format!(
                    "Bookmark committed successfully, but the case generation could not be refreshed: {err}"
                )],
            ),
        };

        Ok(CreateBookmarkResult {
            folder_id: result.folder_id,
            bookmark_id: result.bookmark_id,
            item_id,
            case_generation,
            post_commit_warnings: warnings,
        })
    }

    pub fn bookmark_folder_recursive(
        request: RecursiveFolderBookmarkRequest,
    ) -> Result<RecursiveFolderBookmarkResult> {
        let case_path = &request.case_path;
        let (folder_id, bookmark_id) = if let Some(existing_id) = request.bookmark_id {
            let conn = open_ro_conn(case_path)?;
            let f_id: i64 = conn
                .query_row(
                    "SELECT folder_id FROM bookmarks WHERE id = ?1",
                    params![existing_id],
                    |row| row.get(0),
                )
                .with_context(|| format!("Bookmark #{existing_id} not found"))?;
            (f_id, existing_id)
        } else {
            let folder_name = if request.folder_name.trim().is_empty() {
                "Evidence Folders"
            } else {
                request.folder_name.trim()
            };
            let folder_id = ensure_report_folder(case_path, folder_name)?;
            let title = request.title.unwrap_or_else(|| {
                let p = if request.path.trim().is_empty() {
                    "/"
                } else {
                    request.path.trim()
                };
                format!("Folder (recursive): {p}")
            });

            let bookmark_id = kdft_case::create_bookmark(
                case_path,
                kdft_case::CreateBookmarkOptions {
                    folder_id,
                    bookmark_type: kdft_case::BookmarkType::FolderInfo,
                    data_type: Some(if request.is_live {
                        "Live folder (recursive)".to_string()
                    } else {
                        "Evidence Folder (recursive)".to_string()
                    }),
                    title: Some(title),
                    examiner_comment: request.examiner_comment,
                    in_report: true,
                    source_ref_json: serde_json::json!({
                        "evidence_id": request.evidence_id,
                        "logical_path": request.path,
                        "is_live": request.is_live,
                        "volume_index": request.volume_index,
                    }),
                    content_ref_json: serde_json::json!({}),
                },
            )?;
            (folder_id, bookmark_id)
        };

        let rec_res = if request.is_live {
            let (source_kind, source_path) =
                read_evidence_source_info(case_path, request.evidence_id)?;
            let (volume_name, filesystem) = match source_kind.as_str() {
                "image" => {
                    let img_path = Path::new(&source_path);
                    let volumes = kdft_case::list_image_volumes(img_path)?;
                    let volume = volumes.get(request.volume_index).with_context(|| {
                        format!("volume index {} out of range", request.volume_index)
                    })?;
                    (volume.name.clone(), volume.filesystem.clone())
                }
                "folder" => (String::new(), "LOCAL".to_string()),
                other => bail!("recursive live bookmarking is not available for {other} evidence"),
            };

            let bitlocker_credential = if let Some(ref pass) = request.bitlocker_password {
                Some(kdft_case::BitLockerUnlockCredential::Password(
                    pass.as_str(),
                ))
            } else {
                request
                    .bitlocker_recovery_key
                    .as_ref()
                    .map(|key| kdft_case::BitLockerUnlockCredential::RecoveryKey(key.as_str()))
            };

            kdft_case::stream_bookmark_live_folder(kdft_case::StreamBookmarkLiveFolderOptions {
                case_path,
                bookmark_id,
                evidence_id: request.evidence_id,
                source_kind: &source_kind,
                source_path: &source_path,
                volume_index: request.volume_index,
                volume_name: &volume_name,
                filesystem: &filesystem,
                dir_path: &request.path,
                max_entries: request.max_entries,
                checkpoint: request.checkpoint,
                bitlocker_credential,
            })?
        } else {
            kdft_case::bookmark_indexed_folder_recursive(
                case_path,
                bookmark_id,
                request.evidence_id,
                &request.path,
                request.max_entries,
            )?
        };

        let (case_generation, warnings) = match read_case_generation(case_path) {
            Ok(gen) => (Some(gen), Vec::new()),
            Err(err) => (
                None,
                vec![format!(
                    "Recursive bookmark committed successfully, but the case generation could not be refreshed: {err}"
                )],
            ),
        };

        Ok(RecursiveFolderBookmarkResult {
            folder_id,
            bookmark_id,
            items_added: rec_res.items_added,
            total_candidates: rec_res.total_candidates,
            truncated: rec_res.truncated,
            skipped_count: rec_res.skipped_count,
            file_limit: rec_res.file_limit,
            checkpoint: rec_res.checkpoint,
            case_generation,
            post_commit_warnings: warnings,
        })
    }

    pub fn remove_bookmark(case_path: &Path, bookmark_id: i64) -> Result<RemoveBookmarkResult> {
        let res = kdft_case::remove_bookmark(case_path, bookmark_id)?;
        let (case_generation, warnings) = match read_case_generation(case_path) {
            Ok(gen) => (Some(gen), Vec::new()),
            Err(err) => (
                None,
                vec![format!(
                    "Bookmark removed successfully, but the case generation could not be refreshed: {err}"
                )],
            ),
        };
        Ok(RemoveBookmarkResult {
            bookmark_id: res.bookmark_id,
            items_removed: res.removed_items,
            case_generation,
            post_commit_warnings: warnings,
        })
    }

    pub fn remove_bookmark_item(
        case_path: &Path,
        item_id: i64,
    ) -> Result<RemoveBookmarkItemResult> {
        let res = kdft_case::remove_bookmark_item(case_path, item_id)?;
        let (case_generation, warnings) = match read_case_generation(case_path) {
            Ok(gen) => (Some(gen), Vec::new()),
            Err(err) => (
                None,
                vec![format!(
                    "Bookmark item removed successfully, but the case generation could not be refreshed: {err}"
                )],
            ),
        };
        Ok(RemoveBookmarkItemResult {
            item_id: res.item_id,
            bookmark_id: res.bookmark_id,
            case_generation,
            post_commit_warnings: warnings,
        })
    }

    pub fn remove_bookmark_folder(
        case_path: &Path,
        folder_id: i64,
    ) -> Result<RemoveBookmarkFolderResult> {
        let res = kdft_case::remove_bookmark_folder(case_path, folder_id)?;
        let (case_generation, warnings) = match read_case_generation(case_path) {
            Ok(gen) => (Some(gen), Vec::new()),
            Err(err) => (
                None,
                vec![format!(
                    "Bookmark folder removed successfully, but the case generation could not be refreshed: {err}"
                )],
            ),
        };
        Ok(RemoveBookmarkFolderResult {
            folder_id: res.folder_id,
            name: res.name,
            case_generation,
            post_commit_warnings: warnings,
        })
    }
}

fn open_ro_conn(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn read_case_generation(case_path: &Path) -> Result<i64> {
    let conn = open_ro_conn(case_path)?;
    let generation: i64 =
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |row| {
            row.get(0)
        })?;
    Ok(generation)
}

fn ensure_report_folder(case_path: &Path, folder_name: &str) -> Result<i64> {
    let folders = kdft_case::list_bookmark_folders(case_path)?;
    if let Some(folder) = folders
        .iter()
        .find(|f| f.parent_id.is_none() && f.name == folder_name)
    {
        return Ok(folder.id);
    }
    kdft_case::create_bookmark_folder(case_path, None, folder_name, None, true)
}

fn read_evidence_source_info(case_path: &Path, evidence_id: i64) -> Result<(String, String)> {
    let conn = open_ro_conn(case_path)?;
    let case_id: i64 = conn.query_row("SELECT id FROM cases ORDER BY id LIMIT 1", [], |row| {
        row.get(0)
    })?;
    conn.query_row(
        "SELECT source_kind, source_path FROM evidence_sources WHERE case_id = ?1 AND id = ?2",
        params![case_id, evidence_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .with_context(|| format!("evidence source {evidence_id} not found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{CreateCaseRequest, NativeWorkflowService};
    use std::collections::HashSet;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn setup_bookmark_case() -> PathBuf {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kdft-bookmark-test-{}-{serial}.sqlite",
            std::process::id()
        ));
        let request = CreateCaseRequest {
            case_path: path.clone(),
            name: "Bookmark Fixture".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("CASE-BM".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        };
        NativeWorkflowService::create_case(request).expect("create test case");

        // Insert synthetic evidence and filesystem entries
        let conn = Connection::open(&path).expect("open db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name)
             VALUES(1, 1, 'image', 'C:/test/evidence.E01', 'Test Image')",
            [],
        )
        .expect("insert evidence");

        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
             VALUES(100, 1, 1, '/evidence/folder', 'folder', 'directory', 0, 0)",
            [],
        ).expect("insert dir entry");

        for i in 1..=5 {
            conn.execute(
                "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
                 VALUES(?1, 1, 1, ?2, ?3, 'file', 100, 0)",
                params![i, format!("/evidence/folder/item-{i}.dat"), format!("item-{i}.dat")],
            ).expect("insert entry");
        }

        path
    }

    #[test]
    fn bookmark_exact_identity_and_persistence() {
        let case_path = setup_bookmark_case();

        let req = CreateBookmarkRequest {
            case_path: case_path.clone(),
            folder_name: "Key Findings".to_string(),
            title: "Crucial Evidence Entry".to_string(),
            bookmark_type: kdft_case::BookmarkType::NotableFile,
            data_type: Some("Executable".to_string()),
            examiner_comment: Some("Found in user directory".to_string()),
            evidence_id: Some(1),
            entry_id: Some(1),
            display_name: Some("item-1.dat".to_string()),
            logical_path: Some("/evidence/folder/item-1.dat".to_string()),
            selection_offset: Some(512),
            selection_length: Some(128),
            data_preview: Some("MZ...".to_string()),
            item_ref_json: Some(serde_json::json!({"hash": "abc"})),
        };

        let result = NativeBookmarkService::create_bookmark(req).expect("create bookmark");
        assert!(result.bookmark_id > 0);
        assert!(result.post_commit_warnings.is_empty());

        let folders = NativeBookmarkService::list_folders_page(&case_path, None, 100)
            .expect("list folders")
            .folders;
        assert!(folders
            .iter()
            .any(|f| f.name == "Key Findings" && f.bookmark_count == 1));

        let bookmarks = NativeBookmarkService::list_bookmarks_page(
            &case_path,
            Some(result.folder_id),
            None,
            100,
        )
        .expect("list bookmarks")
        .bookmarks;
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].title, "Crucial Evidence Entry");
        assert_eq!(bookmarks[0].item_count, 1);

        let items = NativeBookmarkService::list_bookmark_items_page(
            &case_path,
            Some(result.bookmark_id),
            None,
            100,
        )
        .expect("list items")
        .items;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].entry_id, Some(1));
        assert_eq!(items[0].logical_path, "/evidence/folder/item-1.dat");
        assert_eq!(items[0].display_name, "item-1.dat");

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn recursive_folder_bookmarking_reports_limits_and_truncation() {
        let case_path = setup_bookmark_case();

        let req = RecursiveFolderBookmarkRequest {
            case_path: case_path.clone(),
            evidence_id: 1,
            volume_index: 0,
            path: "/evidence/folder".to_string(),
            is_live: false,
            max_entries: 2, // Explicit limit
            folder_name: "Recursive Tests".to_string(),
            title: Some("Bounded Folder".to_string()),
            examiner_comment: None,
            bitlocker_password: None,
            bitlocker_recovery_key: None,
            checkpoint: None,
            bookmark_id: None,
        };

        let result =
            NativeBookmarkService::bookmark_folder_recursive(req).expect("recursive bookmark");
        assert_eq!(result.items_added, 2);
        assert_eq!(result.total_candidates, 5);
        assert!(result.truncated);
        assert_eq!(result.file_limit, Some(2));

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn bookmark_folder_removal_refuses_non_empty_folder() {
        let case_path = setup_bookmark_case();

        let req = CreateBookmarkRequest {
            case_path: case_path.clone(),
            folder_name: "Protected Folder".to_string(),
            title: "Test Bookmark".to_string(),
            bookmark_type: kdft_case::BookmarkType::NotableFile,
            data_type: None,
            examiner_comment: None,
            evidence_id: Some(1),
            entry_id: Some(1),
            display_name: Some("item.bin".to_string()),
            logical_path: Some("/item.bin".to_string()),
            selection_offset: None,
            selection_length: None,
            data_preview: None,
            item_ref_json: None,
        };

        let result = NativeBookmarkService::create_bookmark(req).expect("create bookmark");

        // Attempting to remove folder while it contains bookmarks must fail
        let err = NativeBookmarkService::remove_bookmark_folder(&case_path, result.folder_id)
            .expect_err("non-empty folder removal must fail");
        assert!(err.to_string().contains("still contains 1 bookmark"));

        // Remove bookmark first
        let rem_b = NativeBookmarkService::remove_bookmark(&case_path, result.bookmark_id)
            .expect("remove bookmark");
        assert_eq!(rem_b.bookmark_id, result.bookmark_id);

        // Now remove folder succeeds
        let rem_f = NativeBookmarkService::remove_bookmark_folder(&case_path, result.folder_id)
            .expect("remove folder now succeeds");
        assert_eq!(rem_f.folder_id, result.folder_id);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn continuation_reaches_over_1000_bookmarks_page_by_page() {
        let case_path = setup_bookmark_case();
        let folder_id =
            kdft_case::create_bookmark_folder(&case_path, None, "Continuation Folder", None, true)
                .expect("create folder");

        let conn = Connection::open(&case_path).expect("open db");
        let tx = conn.unchecked_transaction().expect("start tx");
        for i in 1..=1050 {
            tx.execute(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', ?2, NULL, 1, '{}', '{}')",
                params![folder_id, format!("Continuation Bookmark {i:04}")],
            )
            .expect("insert bookmark");
        }
        tx.commit().expect("commit");
        drop(conn);

        let mut cursor = None;
        let mut seen_ids = HashSet::new();
        let mut page_count = 0;
        loop {
            let page = NativeBookmarkService::list_bookmarks_page(
                &case_path,
                Some(folder_id),
                cursor,
                100,
            )
            .expect("list bookmarks page");

            assert_eq!(page.total, 1050);
            page_count += 1;

            for b in &page.bookmarks {
                assert!(seen_ids.insert(b.id), "duplicate bookmark ID: {}", b.id);
            }

            if let Some(next) = page.next_cursor {
                assert!(page.has_more);
                cursor = Some(next);
            } else {
                assert!(!page.has_more);
                break;
            }
        }

        assert_eq!(seen_ids.len(), 1050);
        assert_eq!(page_count, 11);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn continuation_reaches_over_1000_bookmark_items_page_by_page() {
        let case_path = setup_bookmark_case();
        let folder_id =
            kdft_case::create_bookmark_folder(&case_path, None, "Continuation Folder", None, true)
                .expect("create folder");

        let conn = Connection::open(&case_path).expect("open db");
        let bookmark_id: i64 = conn
            .query_row(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', 'Large Item Bookmark', NULL, 1, '{}', '{}')
                 RETURNING id",
                params![folder_id],
                |row| row.get(0),
            )
            .expect("insert bookmark");

        let tx = conn.unchecked_transaction().expect("start tx");
        for i in 1..=1050 {
            tx.execute(
                "INSERT INTO bookmark_items(bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path, selection_offset, selection_length, data_preview, item_ref_json)
                 VALUES(?1, 1, NULL, ?2, ?3, ?4, NULL, NULL, NULL, '{}')",
                params![
                    bookmark_id,
                    i,
                    format!("item_{i:04}.bin"),
                    format!("/folder/item_{i:04}.bin")
                ],
            )
            .expect("insert item");
        }
        tx.commit().expect("commit");
        drop(conn);

        let mut cursor = None;
        let mut seen_ids = HashSet::new();
        let mut page_count = 0;
        loop {
            let page = NativeBookmarkService::list_bookmark_items_page(
                &case_path,
                Some(bookmark_id),
                cursor,
                100,
            )
            .expect("list bookmark items page");

            assert_eq!(page.total, 1050);
            page_count += 1;

            for it in &page.items {
                assert!(seen_ids.insert(it.id), "duplicate item ID: {}", it.id);
            }

            if let Some(next) = page.next_cursor {
                assert!(page.has_more);
                cursor = Some(next);
            } else {
                assert!(!page.has_more);
                break;
            }
        }

        assert_eq!(seen_ids.len(), 1050);
        assert_eq!(page_count, 11);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn continuation_reaches_over_1000_bookmark_folders_page_by_page() {
        let case_path = setup_bookmark_case();

        let conn = Connection::open(&case_path).expect("open db");
        let tx = conn.unchecked_transaction().expect("start tx");
        for i in 1..=1050 {
            tx.execute(
                "INSERT INTO bookmark_folders(case_id, parent_id, name, folder_comment, show_in_report, report_order)
                 VALUES(1, NULL, ?1, NULL, 1, ?2)",
                params![format!("Folder {i:04}"), i],
            )
            .expect("insert folder");
        }
        tx.commit().expect("commit");
        drop(conn);

        let mut cursor = None;
        let mut seen_ids = HashSet::new();
        let mut page_count = 0;
        loop {
            let page = NativeBookmarkService::list_folders_page(&case_path, cursor, 100)
                .expect("list folders page");

            assert!(page.total >= 1050);
            page_count += 1;

            for f in &page.folders {
                assert!(seen_ids.insert(f.id), "duplicate folder ID: {}", f.id);
            }

            if let Some(next) = page.next_cursor {
                assert!(page.has_more);
                cursor = Some(next);
            } else {
                assert!(!page.has_more);
                break;
            }
        }

        assert!(seen_ids.len() >= 1050);
        assert!(page_count >= 11);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn recursive_bookmarking_batches_and_pages_over_1000_candidates() {
        let case_path = setup_bookmark_case();

        let conn = Connection::open(&case_path).expect("open db");
        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
             VALUES(9999, 1, 1, '/evidence/large_folder', 'large_folder', 'directory', 0, 0)",
            [],
        )
        .expect("insert dir entry");

        let tx = conn.unchecked_transaction().expect("start tx");
        for i in 1..=1200 {
            tx.execute(
                "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
                 VALUES(?1, 1, 1, ?2, ?3, 'file', 100, 0)",
                params![
                    10000 + i,
                    format!("/evidence/large_folder/file_{i:04}.dat"),
                    format!("file_{i:04}.dat")
                ],
            )
            .expect("insert entry");
        }
        tx.commit().expect("commit");
        drop(conn);

        // Run 1: Limited to 500 entries (cancellable / bounded)
        let req1 = RecursiveFolderBookmarkRequest {
            case_path: case_path.clone(),
            evidence_id: 1,
            volume_index: 0,
            path: "/evidence/large_folder".to_string(),
            is_live: false,
            max_entries: 500,
            folder_name: "Large Recursive Batch".to_string(),
            title: Some("Batch Test 1200".to_string()),
            examiner_comment: None,
            bitlocker_password: None,
            bitlocker_recovery_key: None,
            checkpoint: None,
            bookmark_id: None,
        };
        let res1 = NativeBookmarkService::bookmark_folder_recursive(req1).expect("recursive run 1");
        assert_eq!(res1.items_added, 500);
        assert_eq!(res1.total_candidates, 1200);
        assert!(res1.truncated);

        // Run 2: Resume the existing bookmark to completion (max_entries: 0)
        let res2 = kdft_case::bookmark_indexed_folder_recursive(
            &case_path,
            res1.bookmark_id,
            1,
            "/evidence/large_folder",
            0,
        )
        .expect("recursive run 2 resumption");
        assert_eq!(res2.items_added, 700);
        assert_eq!(res2.total_candidates, 1200);
        assert!(!res2.truncated);
        assert_eq!(res2.bookmark_id, res1.bookmark_id);

        // Continuation test across all 1200 items in the resulting bookmark
        let mut cursor = None;
        let mut seen_ids = HashSet::new();
        let mut page_count = 0;
        loop {
            let page = NativeBookmarkService::list_bookmark_items_page(
                &case_path,
                Some(res1.bookmark_id),
                cursor,
                100,
            )
            .expect("list items page");

            assert_eq!(page.total, 1200);
            page_count += 1;

            for it in &page.items {
                assert!(seen_ids.insert(it.id), "duplicate item ID: {}", it.id);
            }

            if let Some(next) = page.next_cursor {
                assert!(page.has_more);
                cursor = Some(next);
            } else {
                assert!(!page.has_more);
                break;
            }
        }

        assert_eq!(seen_ids.len(), 1200);
        assert_eq!(page_count, 12);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn cancellation_occurs_during_live_traversal() {
        let case_path = setup_bookmark_case();
        let temp_dir = std::env::temp_dir().join(format!(
            "kdft-cancel-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(temp_dir.join("sub1")).unwrap();
        fs::create_dir_all(temp_dir.join("sub2")).unwrap();
        for i in 1..=20 {
            fs::write(temp_dir.join(format!("sub1/file_{i}.txt")), b"sample").unwrap();
        }
        for i in 1..=20 {
            fs::write(temp_dir.join(format!("sub2/file_{i}.txt")), b"sample").unwrap();
        }

        let conn = Connection::open(&case_path).expect("open db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name)
             VALUES(99, 1, 'folder', ?1, 'Local Source')",
            params![temp_dir.to_str().unwrap()],
        )
        .expect("insert evidence source");
        drop(conn);

        let folder_id = ensure_report_folder(&case_path, "Cancel Folder").expect("folder");
        let bookmark_id = kdft_case::create_bookmark(
            &case_path,
            kdft_case::CreateBookmarkOptions {
                folder_id,
                bookmark_type: kdft_case::BookmarkType::FolderInfo,
                data_type: None,
                title: Some("Cancel Test".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )
        .expect("bookmark");

        let tracker = kdft_case::progress::JobProgressTracker::new("cancel-test", "test", None);
        tracker.request_cancellation();

        let result = kdft_case::progress::with_job_progress(&tracker, || {
            kdft_case::stream_bookmark_live_folder(kdft_case::StreamBookmarkLiveFolderOptions {
                case_path: &case_path,
                bookmark_id,
                evidence_id: 99,
                source_kind: "folder",
                source_path: temp_dir.to_str().unwrap(),
                volume_index: 0,
                volume_name: "",
                filesystem: "LOCAL",
                dir_path: "/",
                max_entries: 0,
                checkpoint: None,
                bitlocker_credential: None,
            })
        })
        .expect("streaming bookmark");

        assert!(result.checkpoint.is_some());
        let cp = result.checkpoint.unwrap();
        assert!(!cp.completed, "expected cancellation during live traversal");
        assert!(
            cp.items_added < 40,
            "cancellation did not stop traversal: added {}",
            cp.items_added
        );

        let _ = fs::remove_dir_all(temp_dir);
        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn resume_reaches_every_item_without_duplicates() {
        let case_path = setup_bookmark_case();
        let temp_dir = std::env::temp_dir().join(format!(
            "kdft-resume-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(temp_dir.join("sub1")).unwrap();
        fs::create_dir_all(temp_dir.join("sub2")).unwrap();
        fs::create_dir_all(temp_dir.join("sub3")).unwrap();

        for i in 1..=5 {
            fs::write(temp_dir.join(format!("sub1/f1_{i}.txt")), b"content").unwrap();
            fs::write(temp_dir.join(format!("sub2/f2_{i}.txt")), b"content").unwrap();
            fs::write(temp_dir.join(format!("sub3/f3_{i}.txt")), b"content").unwrap();
        }

        let conn = Connection::open(&case_path).expect("open db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name)
             VALUES(98, 1, 'folder', ?1, 'Resume Local Source')",
            params![temp_dir.to_str().unwrap()],
        )
        .expect("insert evidence source");
        drop(conn);

        let folder_id = ensure_report_folder(&case_path, "Resume Folder").expect("folder");
        let bookmark_id = kdft_case::create_bookmark(
            &case_path,
            kdft_case::CreateBookmarkOptions {
                folder_id,
                bookmark_type: kdft_case::BookmarkType::FolderInfo,
                data_type: None,
                title: Some("Resume Test".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )
        .expect("bookmark");

        // Step 1: Bounded traversal of 5 items
        let res1 =
            kdft_case::stream_bookmark_live_folder(kdft_case::StreamBookmarkLiveFolderOptions {
                case_path: &case_path,
                bookmark_id,
                evidence_id: 98,
                source_kind: "folder",
                source_path: temp_dir.to_str().unwrap(),
                volume_index: 0,
                volume_name: "",
                filesystem: "LOCAL",
                dir_path: "/",
                max_entries: 5,
                checkpoint: None,
                bitlocker_credential: None,
            })
            .expect("run 1");

        assert_eq!(res1.items_added, 5);
        assert!(res1.truncated);
        let cp1 = res1.checkpoint.expect("checkpoint 1");
        assert!(!cp1.completed);

        // Step 2: Resume with checkpoint 1 to completion (max_entries: 0)
        let res2 =
            kdft_case::stream_bookmark_live_folder(kdft_case::StreamBookmarkLiveFolderOptions {
                case_path: &case_path,
                bookmark_id,
                evidence_id: 98,
                source_kind: "folder",
                source_path: temp_dir.to_str().unwrap(),
                volume_index: 0,
                volume_name: "",
                filesystem: "LOCAL",
                dir_path: "/",
                max_entries: 0,
                checkpoint: Some(cp1),
                bitlocker_credential: None,
            })
            .expect("run 2");

        assert_eq!(res2.items_added, 15);
        assert!(!res2.truncated);
        let cp2 = res2.checkpoint.expect("checkpoint 2");
        assert!(cp2.completed);

        // Verify all 15 items are in the bookmark with NO duplicates
        let page = NativeBookmarkService::list_bookmark_items_page(
            &case_path,
            Some(bookmark_id),
            None,
            100,
        )
        .expect("items");
        assert_eq!(page.items.len(), 15);
        let mut paths = HashSet::new();
        for item in &page.items {
            assert!(
                paths.insert(item.logical_path.clone()),
                "duplicate item: {}",
                item.logical_path
            );
        }
        assert_eq!(paths.len(), 15);

        let _ = fs::remove_dir_all(temp_dir);
        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn traversal_memory_remains_bounded_beyond_10_000_candidates() {
        let case_path = setup_bookmark_case();
        let temp_dir = std::env::temp_dir().join(format!(
            "kdft-scale-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));

        // Create 11 subdirectories with 1,000 files each = 11,000 files
        for dir_idx in 0..11 {
            let sub = temp_dir.join(format!("dir_{dir_idx:02}"));
            fs::create_dir_all(&sub).unwrap();
            for file_idx in 0..1000 {
                fs::write(sub.join(format!("f_{file_idx:04}.txt")), b"x").unwrap();
            }
        }

        let conn = Connection::open(&case_path).expect("open db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name)
             VALUES(97, 1, 'folder', ?1, 'Scale Source')",
            params![temp_dir.to_str().unwrap()],
        )
        .expect("insert evidence source");
        drop(conn);

        let folder_id = ensure_report_folder(&case_path, "Scale Folder").expect("folder");
        let bookmark_id = kdft_case::create_bookmark(
            &case_path,
            kdft_case::CreateBookmarkOptions {
                folder_id,
                bookmark_type: kdft_case::BookmarkType::FolderInfo,
                data_type: None,
                title: Some("Scale 11k Test".to_string()),
                examiner_comment: None,
                in_report: true,
                source_ref_json: serde_json::json!({}),
                content_ref_json: serde_json::json!({}),
            },
        )
        .expect("bookmark");

        let res =
            kdft_case::stream_bookmark_live_folder(kdft_case::StreamBookmarkLiveFolderOptions {
                case_path: &case_path,
                bookmark_id,
                evidence_id: 97,
                source_kind: "folder",
                source_path: temp_dir.to_str().unwrap(),
                volume_index: 0,
                volume_name: "",
                filesystem: "LOCAL",
                dir_path: "/",
                max_entries: 0,
                checkpoint: None,
                bitlocker_credential: None,
            })
            .expect("streaming 11k items");

        assert_eq!(res.items_added, 11000);
        assert_eq!(res.total_candidates, 11000);
        assert!(!res.truncated);
        let cp = res.checkpoint.expect("checkpoint");
        assert!(cp.completed);

        let _ = fs::remove_dir_all(temp_dir);
        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn stale_bookmark_cursors_are_rejected_after_mutation() {
        let case_path = setup_bookmark_case();
        let folder_id =
            kdft_case::create_bookmark_folder(&case_path, None, "Stale Cursor Folder", None, true)
                .expect("create folder");

        // Insert 20 bookmarks
        let conn = Connection::open(&case_path).expect("open db");
        for i in 1..=20 {
            conn.execute(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', ?2, NULL, 1, '{}', '{}')",
                params![folder_id, format!("Stale BM {i:02}")],
            )
            .expect("insert bm");
        }
        drop(conn);

        // Fetch page 1 with limit 5 -> gets a next_cursor
        let p1 = NativeBookmarkService::list_bookmarks_page(&case_path, Some(folder_id), None, 5)
            .expect("page 1");
        assert!(p1.has_more);
        let cursor = p1.next_cursor.expect("next cursor");

        // Cursor works right now
        let p2 = NativeBookmarkService::list_bookmarks_page(
            &case_path,
            Some(folder_id),
            Some(cursor.clone()),
            5,
        )
        .expect("page 2");
        assert_eq!(p2.bookmarks.len(), 5);

        // Perform a case mutation (recording an audit event, advancing generation)
        let _new_bm = NativeBookmarkService::create_bookmark(CreateBookmarkRequest {
            case_path: case_path.clone(),
            folder_name: "Stale Cursor Folder".to_string(),
            title: "Mutating Bookmark".to_string(),
            bookmark_type: kdft_case::BookmarkType::NotableFile,
            data_type: None,
            examiner_comment: None,
            evidence_id: None,
            entry_id: None,
            display_name: None,
            logical_path: None,
            selection_offset: None,
            selection_length: None,
            data_preview: None,
            item_ref_json: None,
        })
        .expect("create mutation");

        // Now using the old cursor must fail with a stale cursor error
        let err = NativeBookmarkService::list_bookmarks_page(
            &case_path,
            Some(folder_id),
            Some(cursor),
            5,
        )
        .expect_err("stale cursor must be rejected after mutation");
        assert!(
            err.to_string().contains("stale bookmark cursor")
                || err.to_string().contains("case generation changed"),
            "unexpected err: {err}"
        );

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn concurrent_bookmark_mutation_cannot_mix_generation_n_with_page_rows_from_generation_n_plus_1(
    ) {
        let case_path = setup_bookmark_case();
        let folder_id =
            kdft_case::create_bookmark_folder(&case_path, None, "Concurrent Folder", None, true)
                .expect("create folder");

        // Insert initial bookmarks at Generation N
        let conn = Connection::open(&case_path).expect("open db");
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', ?2, NULL, 1, '{}', '{}')",
                params![folder_id, format!("Initial BM {i:02}")],
            )
            .expect("insert bm");
        }
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES(1, 'bookmark.create', 'examiner', 'bookmark', 1, '{}')",
            [],
        )
        .expect("audit event N");
        let initial_gen: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |r| {
                r.get(0)
            })
            .expect("gen N");
        drop(conn);

        // Fetch page 1 with limit 2 at Generation N
        let p1 = NativeBookmarkService::list_bookmarks_page(&case_path, Some(folder_id), None, 2)
            .expect("page 1");
        assert_eq!(p1.snapshot_generation, initial_gen);
        assert_eq!(p1.bookmarks.len(), 2);
        let cursor_n = p1.next_cursor.expect("cursor at gen N");
        assert_eq!(cursor_n.snapshot_generation, initial_gen);

        // Concurrently mutate the case on a separate connection, advancing generation to N+1
        let conn = Connection::open(&case_path).expect("open db");
        for i in 6..=10 {
            conn.execute(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', ?2, NULL, 1, '{}', '{}')",
                params![folder_id, format!("Mutated BM {i:02}")],
            )
            .expect("insert mutated bm");
        }
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES(1, 'bookmark.create', 'examiner', 'bookmark', 6, '{}')",
            [],
        )
        .expect("audit event N+1");
        let next_gen: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM audit_events", [], |r| {
                r.get(0)
            })
            .expect("gen N+1");
        assert!(next_gen > initial_gen);
        drop(conn);

        // Attempting to query next page with cursor from Generation N MUST be rejected.
        // It cannot fetch or mix rows from Generation N+1.
        let err = NativeBookmarkService::list_bookmarks_page(
            &case_path,
            Some(folder_id),
            Some(cursor_n),
            2,
        )
        .expect_err("using cursor from gen N after gen N+1 mutation must fail");

        let err_msg = err.to_string();
        assert!(
            err_msg.contains("stale bookmark cursor")
                && err_msg.contains(&format!(
                    "case generation changed from {initial_gen} to {next_gen}"
                )),
            "unexpected error message: {err_msg}"
        );

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn oversized_preview_json_values_are_not_materialized_in_list_pages() {
        let case_path = setup_bookmark_case();
        let folder_id =
            kdft_case::create_bookmark_folder(&case_path, None, "Projection Folder", None, true)
                .expect("create folder");

        let conn = Connection::open(&case_path).expect("open db");
        let bookmark_id: i64 = conn
            .query_row(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', 'Oversized Projection BM', NULL, 1, '{}', '{}')
                 RETURNING id",
                params![folder_id],
                |row| row.get(0),
            )
            .expect("insert bm");

        // Insert an item with 2,000,000-byte preview and 2,000,000-byte JSON
        let huge_preview = "A".repeat(2 * 1024 * 1024);
        let huge_json = format!("{{\"payload\": \"{}\"}}", "X".repeat(2 * 1024 * 1024));
        let item_id: i64 = conn
            .query_row(
                "INSERT INTO bookmark_items(bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path, selection_offset, selection_length, data_preview, item_ref_json)
                 VALUES(?1, 1, 100, 1, 'huge_item.bin', '/evidence/folder/huge_item.bin', 0, 10000, ?2, ?3)
                 RETURNING id",
                params![bookmark_id, huge_preview, huge_json],
                |row| row.get(0),
            )
            .expect("insert huge item");
        drop(conn);

        // List page query: verify data_preview is bounded to MAX_BOOKMARK_PREVIEW_CHARS and item_ref_json is omitted
        let list_page = NativeBookmarkService::list_bookmark_items_page(
            &case_path,
            Some(bookmark_id),
            None,
            10,
        )
        .expect("list page");
        assert_eq!(list_page.items.len(), 1);
        let item = &list_page.items[0];
        assert_eq!(item.id, item_id);
        let preview = item.data_preview.as_ref().expect("data preview");
        assert_eq!(preview.chars().count(), MAX_BOOKMARK_PREVIEW_CHARS);
        assert!(item.preview_truncated, "preview should be marked truncated");
        assert!(item.ref_truncated, "ref should be marked truncated");
        assert_eq!(item.ref_status, "omitted from list projection");

        // Item detail query: detail byte ceiling enforced via SQL substring before materialization
        let detail = NativeBookmarkService::get_bookmark_item_detail(&case_path, item_id, None)
            .expect("item detail");
        assert_eq!(detail.id, item_id);
        assert!(detail.preview_truncated); // 2 MB > 64KB
        assert_eq!(detail.preview_bytes, 2 * 1024 * 1024);
        assert_eq!(detail.preview_status, "truncated in detail projection");
        assert!(detail.data_preview.as_ref().unwrap().len() <= MAX_ITEM_DETAIL_PREVIEW_BYTES);

        assert!(detail.ref_truncated); // 2 MB > 256KB
        assert_eq!(detail.ref_bytes, huge_json.len());
        assert_eq!(detail.ref_status, "truncated in detail projection");
        assert_eq!(detail.item_ref_json["_truncated"], true);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn invalid_and_oversized_page_sizes_return_errors() {
        let case_path = setup_bookmark_case();

        // 0 is rejected (not silently clamped)
        assert!(NativeBookmarkService::list_folders_page(&case_path, None, 0).is_err());
        assert!(NativeBookmarkService::list_bookmarks_page(&case_path, None, None, 0).is_err());
        assert!(
            NativeBookmarkService::list_bookmark_items_page(&case_path, None, None, 0).is_err()
        );

        // Above MAX_BOOKMARK_PAGE_SIZE (1,000) is rejected (not silently clamped)
        assert!(NativeBookmarkService::list_folders_page(&case_path, None, 1_001).is_err());
        assert!(NativeBookmarkService::list_bookmarks_page(&case_path, None, None, 1_001).is_err());
        assert!(
            NativeBookmarkService::list_bookmark_items_page(&case_path, None, None, 1_001).is_err()
        );

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn no_api_silently_returns_only_the_first_1_000_records() {
        let case_path = setup_bookmark_case();
        let folder_id =
            kdft_case::create_bookmark_folder(&case_path, None, "1050 Folder", None, true)
                .expect("create folder");

        let conn = Connection::open(&case_path).expect("open db");
        let bookmark_id: i64 = conn
            .query_row(
                "INSERT INTO bookmarks(case_id, folder_id, bookmark_type, data_type, title, examiner_comment, in_report, source_ref_json, content_ref_json)
                 VALUES(1, ?1, 'notable_file', 'file', '1050 Items BM', NULL, 1, '{}', '{}')
                 RETURNING id",
                params![folder_id],
                |row| row.get(0),
            )
            .expect("insert bm");

        let tx = conn.unchecked_transaction().expect("start tx");
        for i in 1..=1050 {
            tx.execute(
                "INSERT INTO bookmark_items(bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path, selection_offset, selection_length, data_preview, item_ref_json)
                 VALUES(?1, 1, NULL, ?2, ?3, ?4, NULL, NULL, NULL, '{}')",
                params![
                    bookmark_id,
                    i,
                    format!("rec_{i:04}.bin"),
                    format!("/path/rec_{i:04}.bin")
                ],
            )
            .expect("insert item");
        }
        tx.commit().expect("commit");
        drop(conn);

        // Fetching with limit 1,000 must NOT silently discard the remaining 50 records.
        // It must set has_more == true and provide next_cursor to continue.
        let page1 = NativeBookmarkService::list_bookmark_items_page(
            &case_path,
            Some(bookmark_id),
            None,
            1000,
        )
        .expect("page 1");
        assert_eq!(page1.items.len(), 1000);
        assert!(
            page1.has_more,
            "must not silently truncate to 1,000 records without continuation"
        );
        assert!(page1.next_cursor.is_some());

        let page2 = NativeBookmarkService::list_bookmark_items_page(
            &case_path,
            Some(bookmark_id),
            page1.next_cursor,
            1000,
        )
        .expect("page 2");
        assert_eq!(page2.items.len(), 50);
        assert!(!page2.has_more);

        let _ = fs::remove_file(case_path);
    }

    #[test]
    fn bitlocker_credentials_never_enter_checkpoint_bookmark_json_or_audit_logs() {
        const DUMMY_SECRET: &str = "super-secret-bitlocker-pass-xyz987";
        let case_path = setup_bookmark_case();
        let _folder_id =
            ensure_report_folder(&case_path, "BitLocker Security Test").expect("folder");

        let temp_dir = std::env::temp_dir().join(format!(
            "kdft-bitlocker-sec-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join("sample.txt"), b"test").unwrap();

        let conn = Connection::open(&case_path).expect("open db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name)
             VALUES(95, 1, 'folder', ?1, 'BitLocker Security Source')",
            params![temp_dir.to_str().unwrap()],
        )
        .expect("insert evidence source");
        drop(conn);

        // Run recursive bookmark with transient bitlocker credentials
        let req = RecursiveFolderBookmarkRequest {
            case_path: case_path.clone(),
            evidence_id: 95,
            volume_index: 0,
            path: "/".to_string(),
            is_live: true,
            max_entries: 0,
            folder_name: "BitLocker Security Test".to_string(),
            title: Some("Credential Sanitization Bookmark".to_string()),
            examiner_comment: Some("Testing credential exclusion".to_string()),
            bitlocker_password: Some(DUMMY_SECRET.to_string()),
            bitlocker_recovery_key: Some(format!("recovery-{DUMMY_SECRET}")),
            checkpoint: None,
            bookmark_id: None,
        };

        let result = NativeBookmarkService::bookmark_folder_recursive(req)
            .expect("bookmark folder recursive");

        // 1. Verify checkpoint JSON never contains secret
        let cp = result.checkpoint.expect("checkpoint");
        let cp_json = serde_json::to_string(&cp).unwrap();
        assert!(
            !cp_json.contains(DUMMY_SECRET),
            "Checkpoint JSON leaked secret: {}",
            cp_json
        );

        // 2. Verify DB checkpoint never contains secret
        let stored_cp =
            kdft_case::get_bookmark_traversal_checkpoint(&case_path, result.bookmark_id)
                .expect("stored cp")
                .expect("cp found");
        let stored_cp_json = serde_json::to_string(&stored_cp).unwrap();
        assert!(
            !stored_cp_json.contains(DUMMY_SECRET),
            "Stored checkpoint leaked secret"
        );

        // 3. Verify bookmark rows (source_ref_json, content_ref_json) never contain secret
        let conn = Connection::open(&case_path).expect("open db");
        let (source_ref, content_ref): (String, String) = conn
            .query_row(
                "SELECT source_ref_json, content_ref_json FROM bookmarks WHERE id = ?1",
                params![result.bookmark_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read bm refs");
        assert!(
            !source_ref.contains(DUMMY_SECRET),
            "Bookmark source_ref_json leaked secret: {}",
            source_ref
        );
        assert!(
            !content_ref.contains(DUMMY_SECRET),
            "Bookmark content_ref_json leaked secret: {}",
            content_ref
        );

        // 4. Verify audit_events never contain secret
        let mut stmt = conn
            .prepare("SELECT details_json FROM audit_events")
            .expect("audit stmt");
        let rows = stmt
            .query_map([], |row| row.get::<_, Option<String>>(0))
            .expect("query");
        for r in rows {
            if let Ok(Some(det)) = r {
                assert!(
                    !det.contains(DUMMY_SECRET),
                    "Audit event leaked secret: {}",
                    det
                );
            }
        }
        drop(stmt);
        drop(conn);

        let _ = fs::remove_dir_all(temp_dir);
        let _ = fs::remove_file(case_path);
    }
}
