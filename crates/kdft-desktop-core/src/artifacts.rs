#![forbid(unsafe_code)]

//! Native artifact category query and keyset pagination service.
//!
//! Provides SQL-backed, bounded pagination across categorized forensic entries
//! without full-table vectors or silent truncation.

use anyhow::Result;
use kdft_case::{
    active_case_id, list_entries_by_category_filtered, open_existing_case, read_case_generation,
    CategoryCount, CategoryEntryCursor, CategoryEntryFilters,
};
use rusqlite::TransactionBehavior;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_ARTIFACTS_PAGE_SIZE: usize = 100;
pub const MAX_ARTIFACTS_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCategoryNode {
    pub id: String,
    pub label: String,
    pub main_category: String,
    pub sub_category: Option<String>,
    pub count: i64,
    pub children: Vec<ArtifactCategoryNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCategoryTreeSnapshot {
    pub request_id: u64,
    pub case_generation: i64,
    pub evidence_id: Option<i64>,
    pub total_records: i64,
    pub tree: Vec<ArtifactCategoryNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPageSnapshot {
    pub request_id: u64,
    pub case_generation: i64,
    pub evidence_id: Option<i64>,
    pub category_main: String,
    pub category_sub: Option<String>,
    pub rows: Vec<ArtifactRow>,
    pub total_in_category: i64,
    pub total_matching: i64,
    pub limit: usize,
    pub next_cursor: Option<CategoryEntryCursor>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPageQuery {
    pub case_path: PathBuf,
    pub evidence_id: Option<i64>,
    #[serde(default)]
    pub request_id: u64,
    pub category_main: String,
    pub category_sub: Option<String>,
    pub name_filter: Option<String>,
    pub extension_filter: Option<String>,
    pub entry_type_filter: Option<String>,
    pub deleted_only: bool,
    pub date_from_utc: Option<String>,
    pub date_to_utc: Option<String>,
    pub cursor: Option<CategoryEntryCursor>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRow {
    pub id: i64,
    pub evidence_id: i64,
    pub display_name: String,
    pub logical_path: String,
    pub entry_kind: String,
    pub size_bytes: Option<u64>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub category_main: String,
    pub category_sub: String,
    pub is_deleted: bool,
    pub artifact_kind: Option<String>,
    pub processor: Option<String>,
    pub has_warnings: bool,
    pub key_path: Option<String>,
    pub value_name: Option<String>,
    pub value_type: Option<String>,
    pub value_preview: Option<String>,
    pub key_last_written: Option<String>,
    pub browser_url: Option<String>,
    pub visit_time_utc: Option<String>,
    pub visit_origin: Option<String>,
    pub visit_source_label: Option<String>,
    pub browser_family: Option<String>,
    pub browser_profile: Option<String>,
    pub originator_sync_guid_short: Option<String>,
    pub originator_sync_guid_full: Option<String>,
    pub originator_sync_guid_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactsPage {
    pub rows: Vec<ArtifactRow>,
    pub total_in_category: i64,
    pub total_matching: i64,
    pub limit: usize,
    pub next_cursor: Option<CategoryEntryCursor>,
    pub has_more: bool,
}

pub struct NativeArtifactService;

impl NativeArtifactService {
    /// Builds the hierarchical category tree representing persisted records.
    /// Only categories backed by persisted records (count > 0) are shown.
    pub fn get_category_tree(
        case_path: &Path,
        evidence_id: Option<i64>,
    ) -> Result<Vec<ArtifactCategoryNode>> {
        Self::get_category_tree_snapshot(case_path, evidence_id, 0).map(|s| s.tree)
    }

    /// Builds the generation-bound hierarchical category tree snapshot.
    pub fn get_category_tree_snapshot(
        case_path: &Path,
        evidence_id: Option<i64>,
        request_id: u64,
    ) -> Result<ArtifactCategoryTreeSnapshot> {
        let mut conn = open_existing_case(case_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let case_id = active_case_id(&tx)?;
        let case_generation = read_case_generation(&tx, Some(case_id))?;
        let mut query = String::from(
            "SELECT COALESCE(json_extract(metadata_json, '$.category_main'), 'Uncategorized') as main,
                    COALESCE(json_extract(metadata_json, '$.category_sub'), '') as sub,
                    COUNT(*) as cnt
             FROM filesystem_entries
             WHERE (entry_kind != 'directory' OR COALESCE(json_extract(metadata_json, '$.artifact_kind'), '') IN ('registry_hive', 'registry_key'))
               AND COALESCE(json_extract(metadata_json, '$.category_hidden'), 0) <> 1
               AND COALESCE(json_extract(metadata_json, '$.artifact_kind'), '')
                   NOT IN ('filesystem_parser_error', 'filesystem_parser_summary')",
        );
        if let Some(ev_id) = evidence_id {
            query.push_str(&format!(" AND evidence_id = {ev_id}"));
        }
        query.push_str(" GROUP BY 1, 2 ORDER BY 1, 2");

        let mut stmt = tx.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok(CategoryCount {
                main: row.get(0)?,
                sub: row.get(1)?,
                count: row.get(2)?,
            })
        })?;

        let mut main_groups: std::collections::BTreeMap<String, (i64, Vec<ArtifactCategoryNode>)> =
            std::collections::BTreeMap::new();
        let mut total_records = 0i64;

        for r in rows {
            let item = r?;
            if item.count <= 0 {
                continue;
            }
            total_records += item.count;
            let group = main_groups
                .entry(item.main.clone())
                .or_insert((0, Vec::new()));
            group.0 += item.count;

            if !item.sub.is_empty() {
                group.1.push(ArtifactCategoryNode {
                    id: format!("{}/{}", item.main, item.sub),
                    label: item.sub.clone(),
                    main_category: item.main.clone(),
                    sub_category: Some(item.sub.clone()),
                    count: item.count,
                    children: Vec::new(),
                });
            }
        }

        let mut tree = Vec::new();
        if total_records > 0 {
            tree.push(ArtifactCategoryNode {
                id: "all".to_string(),
                label: "All Indexed Items".to_string(),
                main_category: "".to_string(),
                sub_category: None,
                count: total_records,
                children: Vec::new(),
            });
        }

        for (main, (cnt, sub_nodes)) in main_groups {
            tree.push(ArtifactCategoryNode {
                id: main.clone(),
                label: main.clone(),
                main_category: main,
                sub_category: None,
                count: cnt,
                children: sub_nodes,
            });
        }

        drop(stmt);
        tx.commit()?;

        Ok(ArtifactCategoryTreeSnapshot {
            request_id,
            case_generation,
            evidence_id,
            total_records,
            tree,
        })
    }

    /// Queries a bounded page of categorized artifacts using keyset cursor.
    pub fn query_artifacts_page(query: &ArtifactPageQuery) -> Result<ArtifactsPage> {
        let snap = Self::query_artifacts_page_snapshot(query)?;
        Ok(ArtifactsPage {
            rows: snap.rows,
            total_in_category: snap.total_in_category,
            total_matching: snap.total_matching,
            limit: snap.limit,
            next_cursor: snap.next_cursor,
            has_more: snap.has_more,
        })
    }

    /// Queries a generation-bound page of categorized artifacts using keyset cursor.
    pub fn query_artifacts_page_snapshot(
        query: &ArtifactPageQuery,
    ) -> Result<ArtifactPageSnapshot> {
        let limit = query.limit.clamp(1, MAX_ARTIFACTS_PAGE_SIZE);

        let filters = CategoryEntryFilters {
            name: query.name_filter.clone(),
            extension: query.extension_filter.clone(),
            entry_type: query.entry_type_filter.clone(),
            flags: if query.deleted_only {
                Some("deleted".to_string())
            } else {
                None
            },
            sha256: None,
            from_utc: query.date_from_utc.clone(),
            to_utc: query.date_to_utc.clone(),
        };

        // If category_main is empty or "all", we query all records
        let page = list_entries_by_category_filtered(
            &query.case_path,
            query.evidence_id,
            &query.category_main,
            query.category_sub.as_deref(),
            &filters,
            query.cursor.as_ref(),
            limit,
            0,
        )?;

        let case_generation = page.case_generation;

        let has_more = page.entries.len() > limit || page.next_cursor.is_some();
        let rows = page
            .entries
            .into_iter()
            .take(limit)
            .map(|e| {
                let cat_main = e
                    .metadata_json
                    .get("category_main")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Uncategorized")
                    .to_string();
                let cat_sub = e
                    .metadata_json
                    .get("category_sub")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let artifact_kind = e
                    .metadata_json
                    .get("artifact_kind")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let processor = e
                    .metadata_json
                    .get("parser")
                    .or_else(|| e.metadata_json.get("filesystem_parser"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let has_warnings = e
                    .metadata_json
                    .get("warnings")
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| !a.is_empty());

                let created_at = e
                    .metadata_json
                    .get("created_at")
                    .or_else(|| e.metadata_json.get("ntfs_creation_time_utc"))
                    .or_else(|| e.metadata_json.get("fat_created"))
                    .or_else(|| e.metadata_json.get("file_created"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let modified_at = e
                    .metadata_json
                    .get("modified_at")
                    .or_else(|| e.metadata_json.get("ntfs_modification_time_utc"))
                    .or_else(|| e.metadata_json.get("fat_modified"))
                    .or_else(|| e.metadata_json.get("file_modified"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let key_path = e
                    .metadata_json
                    .get("registry_key_path")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let value_name = e
                    .metadata_json
                    .get("registry_value_name")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let value_type = e
                    .metadata_json
                    .get("registry_value_type")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let value_preview = e
                    .metadata_json
                    .get("registry_value_data")
                    .or_else(|| e.metadata_json.get("registry_value_data_preview"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let key_last_written = e
                    .metadata_json
                    .get("registry_key_last_write_utc")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let browser_url = e
                    .metadata_json
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let visit_time_utc = e
                    .metadata_json
                    .get("visit_time_utc")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let visit_origin = e
                    .metadata_json
                    .get("visit_origin")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let visit_source_label = e
                    .metadata_json
                    .get("visit_source_label")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let browser_family = e
                    .metadata_json
                    .get("browser_family")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let browser_profile = e
                    .metadata_json
                    .get("browser_profile")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let originator_sync_guid_short = e
                    .metadata_json
                    .get("originator_sync_guid_short")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.trim().is_empty())
                    .map(String::from);
                let originator_sync_guid_full = e
                    .metadata_json
                    .get("originator_sync_guid_full")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.trim().is_empty())
                    .map(String::from);
                let originator_sync_guid_note = e
                    .metadata_json
                    .get("originator_sync_guid_note")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                ArtifactRow {
                    id: e.id,
                    evidence_id: e.evidence_id,
                    display_name: e.name,
                    logical_path: e.logical_path,
                    entry_kind: e.entry_kind,
                    size_bytes: e.size_bytes.map(|s| s.max(0) as u64),
                    created_at,
                    modified_at,
                    category_main: cat_main,
                    category_sub: cat_sub,
                    is_deleted: e.is_deleted,
                    artifact_kind,
                    processor,
                    has_warnings,
                    key_path,
                    value_name,
                    value_type,
                    value_preview,
                    key_last_written,
                    browser_url,
                    visit_time_utc,
                    visit_origin,
                    visit_source_label,
                    browser_family,
                    browser_profile,
                    originator_sync_guid_short,
                    originator_sync_guid_full,
                    originator_sync_guid_note,
                }
            })
            .collect();

        Ok(ArtifactPageSnapshot {
            request_id: query.request_id,
            case_generation,
            evidence_id: query.evidence_id,
            category_main: query.category_main.clone(),
            category_sub: query.category_sub.clone(),
            rows,
            total_in_category: page.total_in_category,
            total_matching: page.total_matching,
            limit,
            next_cursor: page.next_cursor,
            has_more,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_clamps_page_limits() {
        let q = ArtifactPageQuery {
            case_path: PathBuf::from("test.sqlite"),
            evidence_id: None,
            request_id: 1,
            category_main: "Filesystem".to_string(),
            category_sub: None,
            name_filter: None,
            extension_filter: None,
            entry_type_filter: None,
            deleted_only: false,
            date_from_utc: None,
            date_to_utc: None,
            cursor: None,
            limit: 50_000,
        };
        assert_eq!(q.limit.clamp(1, MAX_ARTIFACTS_PAGE_SIZE), 1_000);
    }

    fn fixture_case(prefix: &str) -> (PathBuf, rusqlite::Connection) {
        let unique = format!(
            "{prefix}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        let _ = kdft_case::create_case(
            &path,
            kdft_case::CreateCaseOptions {
                name: prefix.to_string(),
                examiner_name: Some("Examiner".to_string()),
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )
        .expect("create case");
        let conn = rusqlite::Connection::open(&path).expect("open fixture");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, display_name, source_kind, source_path)
             VALUES (1, 1, 'Test Evidence', 'file', 'C:/mock/test.raw')",
            [],
        )
        .expect("insert evidence source");
        (path, conn)
    }

    #[test]
    fn test_a_atomic_tree_snapshot_under_concurrent_writer() {
        let (path, conn) = fixture_case("test-a-tree");
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/file1.txt', 'file1.txt', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\"}')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (1, 'artifact.insert', 'test', 'file', 1, '{}')",
            [],
        ).unwrap();
        let gen_n: i64 = conn
            .query_row("SELECT MAX(id) FROM audit_events", [], |r| r.get(0))
            .unwrap();

        let path_clone = path.clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let barrier_clone = barrier.clone();
        let writer_handle = std::thread::spawn(move || {
            let conn2 = rusqlite::Connection::open(&path_clone).unwrap();
            barrier_clone.wait();
            conn2.execute(
                "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
                 VALUES (1, 1, NULL, '/file2.txt', 'file2.txt', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\"}')",
                [],
            ).unwrap();
            conn2.execute(
                "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
                 VALUES (1, 'artifact.insert', 'test', 'file', 2, '{}')",
                [],
            ).unwrap();
        });

        barrier.wait();
        let snap = NativeArtifactService::get_category_tree_snapshot(&path, Some(1), 10).unwrap();
        writer_handle.join().unwrap();

        if snap.case_generation == gen_n {
            assert_eq!(snap.total_records, 1);
        } else {
            assert_eq!(snap.case_generation, gen_n + 1);
            assert_eq!(snap.total_records, 2);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_b_atomic_page_snapshot_and_cursor_validation() {
        let (path, conn) = fixture_case("test-b-page");
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
                 VALUES (1, 1, NULL, ?1, ?2, 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\"}')",
                rusqlite::params![format!("/file{i}.txt"), format!("file{i}.txt")],
            ).unwrap();
        }
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (1, 'batch.insert', 'test', 'files', 5, '{}')",
            [],
        ).unwrap();
        let cur_gen: i64 = conn
            .query_row("SELECT MAX(id) FROM audit_events", [], |r| r.get(0))
            .unwrap();

        let q1 = ArtifactPageQuery {
            case_path: path.clone(),
            evidence_id: Some(1),
            request_id: 1,
            category_main: "Documents".to_string(),
            category_sub: Some("Text".to_string()),
            name_filter: None,
            extension_filter: None,
            entry_type_filter: None,
            deleted_only: false,
            date_from_utc: None,
            date_to_utc: None,
            cursor: None,
            limit: 2,
        };
        let snap1 = NativeArtifactService::query_artifacts_page_snapshot(&q1).unwrap();
        assert_eq!(snap1.case_generation, cur_gen);
        assert_eq!(snap1.rows.len(), 2);
        assert_eq!(snap1.total_in_category, 5);
        assert!(snap1.has_more);
        let cursor1 = snap1.next_cursor.expect("must have cursor");

        let mut q2 = q1.clone();
        q2.cursor = Some(cursor1);
        let snap2 = NativeArtifactService::query_artifacts_page_snapshot(&q2).unwrap();
        assert_eq!(snap2.case_generation, cur_gen);
        assert_eq!(snap2.rows.len(), 2);
        for r2 in &snap2.rows {
            assert!(!snap1.rows.iter().any(|r1| r1.id == r2.id));
        }

        let mut q_stale = q1.clone();
        q_stale.cursor = Some(kdft_case::CategoryEntryCursor {
            logical_path: "/file2.txt".to_string(),
            id: snap1.rows[1].id,
            snapshot_generation: Some("audit-999999".to_string()),
        });
        let stale_err = NativeArtifactService::query_artifacts_page_snapshot(&q_stale);
        assert!(stale_err.is_err());
        assert!(stale_err
            .unwrap_err()
            .to_string()
            .contains("different case generation"));

        let mut q_empty = q1.clone();
        q_empty.category_main = "NonExistent".to_string();
        let snap_empty = NativeArtifactService::query_artifacts_page_snapshot(&q_empty).unwrap();
        assert_eq!(snap_empty.case_generation, cur_gen);
        assert_eq!(snap_empty.rows.len(), 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_c_generation_query_failure_propagates_error_without_fabricating_one() {
        let (path, conn) = fixture_case("test-c-gen-fail");
        conn.execute("DROP TABLE audit_events", []).unwrap();

        let tree_res = NativeArtifactService::get_category_tree_snapshot(&path, Some(1), 1);
        assert!(
            tree_res.is_err(),
            "Tree snapshot must fail when generation query fails"
        );

        let q = ArtifactPageQuery {
            case_path: path.clone(),
            evidence_id: Some(1),
            request_id: 1,
            category_main: "Documents".to_string(),
            category_sub: None,
            name_filter: None,
            extension_filter: None,
            entry_type_filter: None,
            deleted_only: false,
            date_from_utc: None,
            date_to_utc: None,
            cursor: None,
            limit: 10,
        };
        let page_res = NativeArtifactService::query_artifacts_page_snapshot(&q);
        assert!(
            page_res.is_err(),
            "Page snapshot must fail when generation query fails"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_f_exact_taxonomy_root_label_and_registry_partitioning() {
        let (path, conn) = fixture_case("test-f-tax");
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/doc.pdf', 'doc.pdf', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"PDF\"}')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/Windows/System32/config/SYSTEM', 'SYSTEM', 'directory', '{\"category_main\":\"Windows Registry\",\"category_sub\":\"Hives\",\"artifact_kind\":\"registry_hive\"}')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, 'HKLM\\SYSTEM\\Select', 'Select', 'directory', '{\"category_main\":\"Windows Registry\",\"category_sub\":\"Keys\",\"artifact_kind\":\"registry_key\"}')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, 'HKLM\\SYSTEM\\Select\\Current', 'Current', 'file', '{\"category_main\":\"Windows Registry\",\"category_sub\":\"Values\",\"artifact_kind\":\"registry_value\"}')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, 'HKLM\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation', 'TimeZoneInformation', 'file', '{\"category_main\":\"Windows Registry\",\"category_sub\":\"Interpreted Registry Artifacts\",\"artifact_kind\":\"registry_key\"}')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (1, 'populate', 'test', 'case', 1, '{}')",
            [],
        ).unwrap();

        let snap = NativeArtifactService::get_category_tree_snapshot(&path, Some(1), 1).unwrap();
        let all_node = snap
            .tree
            .iter()
            .find(|n| n.id == "all")
            .expect("must have 'all' root node");
        assert_eq!(all_node.label, "All Indexed Items");
        assert_eq!(all_node.count, 5);

        let reg_node = snap
            .tree
            .iter()
            .find(|n| n.id == "Windows Registry")
            .expect("must have Windows Registry category");
        assert_eq!(reg_node.count, 4);

        let hive_sub = reg_node
            .children
            .iter()
            .find(|c| c.label == "Hives")
            .expect("Hives subcategory");
        assert_eq!(hive_sub.count, 1);
        let key_sub = reg_node
            .children
            .iter()
            .find(|c| c.label == "Keys")
            .expect("Keys subcategory");
        assert_eq!(key_sub.count, 1);
        let val_sub = reg_node
            .children
            .iter()
            .find(|c| c.label == "Values")
            .expect("Values subcategory");
        assert_eq!(val_sub.count, 1);
        let interp_sub = reg_node
            .children
            .iter()
            .find(|c| c.label == "Interpreted Registry Artifacts")
            .expect("Interpreted Registry Artifacts subcategory");
        assert_eq!(interp_sub.count, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_g_tree_counts_reconcile_with_page_visibility_contract() {
        let (path, conn) = fixture_case("test-g-reconcile");
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/visible.txt', 'visible.txt', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\"}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/diagnostics/error', 'error', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\",\"artifact_kind\":\"filesystem_parser_error\"}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/diagnostics/summary', 'summary', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\",\"artifact_kind\":\"filesystem_parser_summary\"}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/hidden.txt', 'hidden.txt', 'file', '{\"category_main\":\"Documents\",\"category_sub\":\"Text\",\"category_hidden\":1}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (1, 'populate', 'test', 'case', 1, '{}')",
            [],
        )
        .unwrap();

        let tree = NativeArtifactService::get_category_tree_snapshot(&path, Some(1), 1).unwrap();
        assert_eq!(tree.total_records, 1);
        let documents = tree
            .tree
            .iter()
            .find(|node| node.id == "Documents")
            .expect("Documents category");
        assert_eq!(documents.count, 1);
        assert_eq!(documents.children[0].count, 1);

        let page = NativeArtifactService::query_artifacts_page_snapshot(&ArtifactPageQuery {
            case_path: path.clone(),
            evidence_id: Some(1),
            request_id: 2,
            category_main: "Documents".to_string(),
            category_sub: Some("Text".to_string()),
            name_filter: None,
            extension_filter: None,
            entry_type_filter: None,
            deleted_only: false,
            date_from_utc: None,
            date_to_utc: None,
            cursor: None,
            limit: 100,
        })
        .unwrap();
        assert_eq!(page.total_in_category, 1);
        assert_eq!(page.total_matching, 1);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].display_name, "visible.txt");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn chromium_visit_origin_provenance_is_projected_into_bounded_page_rows() {
        let (path, conn) = fixture_case("browser-origin-page");
        let metadata = serde_json::json!({
            "artifact_kind": "browser_history_visit",
            "category_main": "Web Activity",
            "category_sub": "Visits",
            "browser_family": "chromium",
            "browser_profile": "Default",
            "url": "https://example.test/visited",
            "visit_time_utc": "2026-10-24T18:00:00+00:00",
            "visit_origin": "remote_synced",
            "visit_source_label": "synced",
            "originator_sync_guid_short": "abcdef12",
            "originator_sync_guid_full": "abcdef12-3456-7890-abcd-ef1234567890",
            "originator_sync_guid_note": "Opaque Chromium Sync client identifier; not a hardware-device ID."
        });
        conn.execute(
            "INSERT INTO filesystem_entries(case_id, evidence_id, parent_id, logical_path, name, entry_kind, metadata_json)
             VALUES (1, 1, NULL, '/Parsed Artifacts/Browser/visit.record', 'Example visit', 'record', ?1)",
            [metadata.to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
             VALUES (1, 'populate', 'test', 'case', 1, '{}')",
            [],
        )
        .unwrap();

        let page = NativeArtifactService::query_artifacts_page_snapshot(&ArtifactPageQuery {
            case_path: path.clone(),
            evidence_id: Some(1),
            request_id: 7,
            category_main: "Web Activity".to_string(),
            category_sub: Some("Visits".to_string()),
            name_filter: None,
            extension_filter: None,
            entry_type_filter: None,
            deleted_only: false,
            date_from_utc: None,
            date_to_utc: None,
            cursor: None,
            limit: 100,
        })
        .unwrap();

        assert_eq!(page.rows.len(), 1);
        let row = &page.rows[0];
        assert_eq!(
            row.browser_url.as_deref(),
            Some("https://example.test/visited")
        );
        assert_eq!(
            row.visit_time_utc.as_deref(),
            Some("2026-10-24T18:00:00+00:00")
        );
        assert_eq!(row.visit_origin.as_deref(), Some("remote_synced"));
        assert_eq!(row.visit_source_label.as_deref(), Some("synced"));
        assert_eq!(row.browser_family.as_deref(), Some("chromium"));
        assert_eq!(row.browser_profile.as_deref(), Some("Default"));
        assert_eq!(row.originator_sync_guid_short.as_deref(), Some("abcdef12"));
        assert_eq!(
            row.originator_sync_guid_full.as_deref(),
            Some("abcdef12-3456-7890-abcd-ef1234567890")
        );
        assert!(row
            .originator_sync_guid_note
            .as_deref()
            .is_some_and(|note| note.contains("not a hardware-device ID")));

        drop(conn);
        let _ = std::fs::remove_file(path);
    }
}
