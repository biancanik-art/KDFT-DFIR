#![forbid(unsafe_code)]

//! Native Timeline service.
//!
//! Extracts, unifies, and normalizes persisted timestamps into a coherent,
//! paginated forensic event stream without conflating distinct temporal semantics.

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_TIMELINE_PAGE_SIZE: usize = 100;
pub const MAX_TIMELINE_PAGE_SIZE: usize = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub entry_id: i64,
    pub evidence_id: i64,
    pub timestamp_utc: String,
    pub timestamp_type: String,
    pub basis: String,
    /// Distinguishes raw filesystem timestamps from decoded parser output.
    pub event_origin: String,
    pub artifact_kind: String,
    pub display_name: String,
    pub logical_path: String,
    pub category: String,
    pub is_deleted: bool,
    pub is_bookmarked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineQuery {
    pub case_path: PathBuf,
    pub evidence_id: Option<i64>,
    pub from_utc: Option<String>,
    pub to_utc: Option<String>,
    pub category_filter: Option<String>,
    pub timestamp_type_filter: Option<String>,
    pub text_filter: Option<String>,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePage {
    pub events: Vec<TimelineEvent>,
    pub total_matching: usize,
    pub page: usize,
    pub has_more: bool,
}

pub struct NativeTimelineService;

impl NativeTimelineService {
    /// Queries unified timeline events for the case.
    pub fn query_timeline(query: &TimelineQuery) -> Result<TimelinePage> {
        let page_size = query.page_size.clamp(1, MAX_TIMELINE_PAGE_SIZE);
        let offset = query.page * page_size;

        let conn = Connection::open(&query.case_path)?;

        let mut bookmarked_set = std::collections::HashSet::new();
        if let Ok(mut stmt) =
            conn.prepare("SELECT entry_id FROM bookmark_items WHERE entry_id IS NOT NULL")
        {
            if let Ok(rows) = stmt.query_map([], |r| r.get::<_, i64>(0)) {
                for id in rows.flatten() {
                    bookmarked_set.insert(id);
                }
            }
        }

        let cat_param = like_filter(query.category_filter.as_deref());
        let text_param = like_filter(query.text_filter.as_deref());
        let type_param = like_filter(query.timestamp_type_filter.as_deref());
        let from_param = normalize_utc_boundary(query.from_utc.as_deref(), false)?;
        let to_param = normalize_utc_boundary(query.to_utc.as_deref(), true)?;

        let count_sql = format!(
            "{} SELECT COUNT(*) FROM filtered_events",
            timeline_events_cte()
        );
        let total_matching: usize = conn.query_row(
            &count_sql,
            rusqlite::named_params! {
                ":evidence_id": query.evidence_id,
                ":text_param": text_param,
                ":cat_param": cat_param,
                ":type_param": type_param,
                ":from_param": from_param,
                ":to_param": to_param,
            },
            |row| row.get(0),
        )?;

        let page_sql = format!(
            "{} SELECT entry_id, evidence_id, timestamp_utc, timestamp_type, basis,
                       event_origin, artifact_kind, display_name, logical_path, category, is_deleted
                  FROM filtered_events
                 ORDER BY julianday(timestamp_utc) DESC, timestamp_utc DESC, entry_id ASC
                 LIMIT :limit OFFSET :offset",
            timeline_events_cte()
        );
        let mut stmt = conn.prepare(&page_sql)?;
        let rows = stmt.query_map(
            rusqlite::named_params! {
                ":evidence_id": query.evidence_id,
                ":text_param": text_param,
                ":cat_param": cat_param,
                ":type_param": type_param,
                ":from_param": from_param,
                ":to_param": to_param,
                ":limit": page_size as i64,
                ":offset": offset as i64,
            },
            |row| {
                Ok(TimelineEvent {
                    entry_id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    timestamp_utc: row.get(2)?,
                    timestamp_type: row.get(3)?,
                    basis: row.get(4)?,
                    event_origin: row.get(5)?,
                    artifact_kind: row.get(6)?,
                    display_name: row.get(7)?,
                    logical_path: row.get(8)?,
                    category: row.get(9)?,
                    is_deleted: row.get::<_, i64>(10)? != 0,
                    is_bookmarked: false,
                })
            },
        )?;
        let mut events = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        for event in &mut events {
            event.is_bookmarked = bookmarked_set.contains(&event.entry_id);
        }

        let has_more = offset.saturating_add(events.len()) < total_matching;

        Ok(TimelinePage {
            events,
            total_matching,
            page: query.page,
            has_more,
        })
    }
}

fn like_filter(value: Option<&str>) -> Option<String> {
    let trimmed = value.unwrap_or("").trim();
    (!trimmed.is_empty()).then(|| format!("%{}%", trimmed.to_lowercase()))
}

/// Normalize examiner input to an inclusive UTC boundary. Supported forms:
/// YYYY, YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS[.fraction]], and RFC 3339.
pub fn normalize_utc_boundary(value: Option<&str>, end_boundary: bool) -> Result<Option<String>> {
    let raw = value.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(None);
    }

    let utc = if raw.len() == 4 && raw.bytes().all(|byte| byte.is_ascii_digit()) {
        let year: i32 = raw.parse()?;
        let date = if end_boundary {
            NaiveDate::from_ymd_opt(year, 12, 31)
        } else {
            NaiveDate::from_ymd_opt(year, 1, 1)
        }
        .ok_or_else(|| anyhow::anyhow!("year is outside the supported UTC range"))?;
        let naive = if end_boundary {
            date.and_hms_nano_opt(23, 59, 59, 999_999_999)
        } else {
            date.and_hms_opt(0, 0, 0)
        }
        .ok_or_else(|| anyhow!("UTC day boundary is outside the supported range"))?;
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    } else if let Ok(value) = DateTime::parse_from_rfc3339(raw) {
        value.with_timezone(&Utc)
    } else if let Ok(date) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
        let naive = if end_boundary {
            date.and_hms_nano_opt(23, 59, 59, 999_999_999)
        } else {
            date.and_hms_opt(0, 0, 0)
        }
        .ok_or_else(|| anyhow!("UTC day boundary is outside the supported range"))?;
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    } else {
        let without_z = raw.strip_suffix('Z').unwrap_or(raw);
        let formats = [
            "%Y-%m-%dT%H:%M:%S%.f",
            "%Y-%m-%d %H:%M:%S%.f",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M",
        ];
        let naive = formats
            .iter()
            .find_map(|format| NaiveDateTime::parse_from_str(without_z, format).ok());
        let Some(naive) = naive else {
            bail!(
                "Invalid UTC date/time '{raw}'. Use YYYY, YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, or RFC 3339 such as 2026-10-27T14:32:05.123456Z."
            );
        };
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    };

    Ok(Some(utc.to_rfc3339_opts(SecondsFormat::Nanos, true)))
}

fn timeline_events_cte() -> &'static str {
    r#"WITH base AS (
           SELECT id AS entry_id, evidence_id, logical_path, name AS display_name,
                  is_deleted,
                  CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END AS metadata_json,
                  COALESCE(
                      NULLIF(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.artifact_kind'), ''),
                      'filesystem_entry'
                  ) AS artifact_kind,
                  COALESCE(
                      NULLIF(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.category_main'), ''),
                      'Filesystem'
                  ) AS base_category
             FROM filesystem_entries
            WHERE (:evidence_id IS NULL OR evidence_id = :evidence_id)
              AND (:text_param IS NULL
                   OR lower(name) LIKE :text_param
                   OR lower(logical_path) LIKE :text_param
                   OR lower(COALESCE(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.source_artifact_path'), '')) LIKE :text_param
                   OR lower(COALESCE(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.source_artifact_path_exact'), '')) LIKE :text_param
                   OR lower(COALESCE(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.windows_registry_source_exact_path'), '')) LIKE :text_param
                   OR lower(COALESCE(json_extract(CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END, '$.registry_key_path'), '')) LIKE :text_param)
       ), raw_events AS (
           SELECT entry_id, evidence_id,
                  COALESCE(
                      json_extract(metadata_json, '$.created_at'),
                      json_extract(metadata_json, '$.ntfs_creation_time_utc'),
                      json_extract(metadata_json, '$.fat_created'),
                      json_extract(metadata_json, '$.file_created')
                  ) AS timestamp_utc,
                  'Created' AS timestamp_type,
                  'Filesystem creation time (UTC)' AS basis,
                  'Raw filesystem metadata' AS event_origin,
                  artifact_kind,
                  display_name, logical_path, base_category AS category, is_deleted
             FROM base
           UNION ALL
           SELECT entry_id, evidence_id,
                  COALESCE(
                      json_extract(metadata_json, '$.modified_at'),
                      json_extract(metadata_json, '$.ntfs_modification_time_utc'),
                      json_extract(metadata_json, '$.fat_modified'),
                      json_extract(metadata_json, '$.file_modified')
                  ),
                  'Modified', 'Filesystem last written/modified time (UTC)',
                  'Raw filesystem metadata', artifact_kind,
                  display_name, logical_path, base_category, is_deleted
             FROM base
           UNION ALL
           SELECT entry_id, evidence_id, json_extract(metadata_json, '$.visit_time'),
                  'Browser Visit', 'Browser history visit timestamp',
                  'Parsed browser artifact', artifact_kind,
                  display_name, logical_path, 'Browser Activity', is_deleted
             FROM base
           UNION ALL
           SELECT entry_id, evidence_id, json_extract(metadata_json, '$.time_created'),
                  'Event Log', 'EVTX System.TimeCreated',
                  'Parsed event-log artifact', artifact_kind,
                  display_name, logical_path, 'Windows Event Logs', is_deleted
             FROM base
           UNION ALL
           SELECT entry_id, evidence_id,
                  json_extract(metadata_json, '$.registry_key_last_write_utc'),
                  'Registry Last Write',
                  'Parsed Registry key LastWrite timestamp (UTC); Registry values do not have an individual modification timestamp',
                  'Parsed Registry artifact', artifact_kind,
                  display_name, logical_path, 'Windows Registry', is_deleted
             FROM base
            WHERE artifact_kind = 'registry_key'
       ), events AS (
           SELECT * FROM raw_events
            WHERE timestamp_utc IS NOT NULL
              AND trim(CAST(timestamp_utc AS TEXT)) <> ''
              AND julianday(timestamp_utc) IS NOT NULL
       ), filtered_events AS (
           SELECT * FROM events
            WHERE (:cat_param IS NULL OR lower(category) LIKE :cat_param)
              AND (:type_param IS NULL OR lower(timestamp_type) LIKE :type_param)
              AND (:from_param IS NULL OR julianday(timestamp_utc) >= julianday(:from_param))
              AND (:to_param IS NULL OR julianday(timestamp_utc) <= julianday(:to_param))
       )"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_ID: AtomicU64 = AtomicU64::new(1);

    fn timeline_test_db() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kdft-timeline-{}-{}.sqlite",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE filesystem_entries(
                 id INTEGER PRIMARY KEY,
                 evidence_id INTEGER NOT NULL,
                 logical_path TEXT NOT NULL,
                 name TEXT NOT NULL,
                 is_deleted INTEGER NOT NULL DEFAULT 0,
                 metadata_json TEXT NOT NULL
             );
             CREATE TABLE bookmark_items(entry_id INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries VALUES(1, 7, '/transfer.txt', 'transfer.txt', 0, ?1)",
            [serde_json::json!({
                "category_main": "Documents and Office",
                "created_at": "2025-02-03T04:05:06Z",
                "modified_at": "2026-03-04T05:06:07.123456Z"
            })
            .to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries VALUES(2, 7, '/transfer-no-time.txt', 'transfer-no-time.txt', 0, '{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries VALUES(3, 7, '/other.txt', 'other.txt', 0, ?1)",
            [serde_json::json!({"created_at": "2025-01-01T00:00:00Z"}).to_string()],
        )
        .unwrap();
        drop(conn);
        path
    }

    #[test]
    fn timeline_event_fields_are_distinct() {
        let ev = TimelineEvent {
            entry_id: 1,
            evidence_id: 2,
            timestamp_utc: "2026-10-19T00:00:00Z".to_string(),
            timestamp_type: "Created".to_string(),
            basis: "$STANDARD_INFORMATION".to_string(),
            event_origin: "Raw filesystem metadata".to_string(),
            artifact_kind: "filesystem_entry".to_string(),
            display_name: "test.txt".to_string(),
            logical_path: "/test.txt".to_string(),
            category: "Filesystem".to_string(),
            is_deleted: false,
            is_bookmarked: false,
        };
        assert_eq!(ev.timestamp_type, "Created");
        assert_eq!(ev.basis, "$STANDARD_INFORMATION");
    }

    #[test]
    fn utc_year_boundaries_are_inclusive() {
        assert_eq!(
            normalize_utc_boundary(Some("2025"), false).unwrap(),
            Some("2025-01-01T00:00:00.000000000Z".to_string())
        );
        assert_eq!(
            normalize_utc_boundary(Some("2026"), true).unwrap(),
            Some("2026-12-31T23:59:59.999999999Z".to_string())
        );
    }

    #[test]
    fn utc_precision_and_rfc3339_are_supported() {
        assert_eq!(
            normalize_utc_boundary(Some("2026-10-27 14:32:05.123456"), false).unwrap(),
            Some("2026-10-27T14:32:05.123456000Z".to_string())
        );
        assert_eq!(
            normalize_utc_boundary(Some("2026-10-27T16:32:05+02:00"), false).unwrap(),
            Some("2026-10-27T14:32:05.000000000Z".to_string())
        );
    }

    #[test]
    fn invalid_utc_filter_fails_closed_with_format_guidance() {
        let error = normalize_utc_boundary(Some("27/10/2026"), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("YYYY-MM-DD"));
        assert!(error.contains("RFC 3339"));
    }

    #[test]
    fn total_counts_timestamped_events_after_all_filters_and_pages_events() {
        let path = timeline_test_db();
        let mut query = TimelineQuery {
            case_path: path.clone(),
            evidence_id: Some(7),
            from_utc: Some("2025".to_string()),
            to_utc: Some("2026".to_string()),
            category_filter: Some("Documents and Office".to_string()),
            timestamp_type_filter: None,
            text_filter: Some("transfer".to_string()),
            page: 0,
            page_size: 1,
        };

        let first = NativeTimelineService::query_timeline(&query).unwrap();
        assert_eq!(first.total_matching, 2);
        assert_eq!(first.events.len(), 1);
        assert!(first.has_more);
        assert_eq!(first.events[0].timestamp_type, "Modified");

        query.page = 1;
        let second = NativeTimelineService::query_timeline(&query).unwrap();
        assert_eq!(second.total_matching, 2);
        assert_eq!(second.events.len(), 1);
        assert!(!second.has_more);
        assert_eq!(second.events[0].timestamp_type, "Created");

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn registry_source_search_returns_decoded_registry_last_write_events() {
        let path = timeline_test_db();
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO filesystem_entries VALUES(4, 7, '/Windows Artifacts/Registry/99/Hive/Software/Vendor', 'Vendor', 0, ?1)",
            [serde_json::json!({
                "artifact_kind": "registry_key",
                "category_main": "Windows Registry",
                "source_artifact_path": "/Users/Alice/NTUSER.DAT",
                "registry_key_path": "Software\\Vendor",
                "registry_key_last_write_utc": "2026-06-28T10:15:30Z"
            })
            .to_string()],
        )
        .unwrap();
        drop(conn);

        let page = NativeTimelineService::query_timeline(&TimelineQuery {
            case_path: path.clone(),
            evidence_id: Some(7),
            from_utc: None,
            to_utc: None,
            category_filter: Some("Windows Registry".to_string()),
            timestamp_type_filter: Some("Registry Last Write".to_string()),
            text_filter: Some("/Users/Alice/NTUSER.DAT".to_string()),
            page: 0,
            page_size: 100,
        })
        .unwrap();

        assert_eq!(page.total_matching, 1);
        assert_eq!(page.events[0].event_origin, "Parsed Registry artifact");
        assert_eq!(page.events[0].artifact_kind, "registry_key");
        assert_eq!(page.events[0].timestamp_type, "Registry Last Write");
        std::fs::remove_file(path).unwrap();
    }
}
