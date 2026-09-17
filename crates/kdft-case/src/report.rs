//! Report data generation and HTML rendering for case evidence and findings.
//!
//! Provides examiner-ready reporting with authentic digest verification,
//! hierarchical directory structures, bookmark folders, and detailed forensic
//! context for files, email messages, and browser activity.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use super::{
    acquisition_manifest_from_row, active_case_id, audit_actor, bookmark_item_from_raw, case_info,
    ensure_evidence_source, file_extension_of, filesystem_entry_from_raw, list_image_directory,
    list_image_volumes, open_existing_case, parse_stored_json, sha256_hex,
    source_path_exact_from_metadata, AcquisitionManifest, BookmarkItem, FilesystemEntry, LiveEntry,
    RawBookmarkItem, RawFilesystemEntry, RenderedReport, ReportBookmark, ReportData,
    ReportDirectoryTree, ReportEvidence, ReportFolder, ReportTreeLine,
};

pub fn report_data(case_path: &Path) -> Result<ReportData> {
    let case = case_info(case_path)?;
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;

    let mut folder_stmt = conn.prepare(
        "SELECT id, name, folder_comment, report_order
         FROM bookmark_folders
         WHERE case_id = ?1 AND show_in_report = 1
         ORDER BY report_order, name, id",
    )?;
    let folder_rows = folder_stmt.query_map(params![case_id], |row| {
        Ok(ReportFolder {
            id: row.get(0)?,
            name: row.get(1)?,
            folder_comment: row.get(2)?,
            report_order: row.get(3)?,
            bookmarks: Vec::new(),
        })
    })?;
    let mut folders = folder_rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report folders")?;

    for folder in &mut folders {
        folder.bookmarks = report_bookmarks_for_folder(&conn, case_id, folder.id)?;
    }

    let evidence = report_evidence_rows(&conn, case_id)?;

    Ok(ReportData {
        case,
        evidence,
        directory_trees: Vec::new(),
        folders,
    })
}

fn processing_status_is_incomplete(status: Option<&str>) -> bool {
    matches!(status, Some("truncated" | "failed" | "running"))
}

fn processing_requested_limit_label(limit: Option<i64>) -> String {
    match limit {
        Some(0) => "unlimited (examiner requested 0)".to_string(),
        Some(limit) => limit.to_string(),
        None => "not recorded".to_string(),
    }
}

pub fn processing_coverage_text(
    job_type: Option<&str>,
    status: Option<&str>,
    requested_limit: Option<i64>,
    entries_indexed: Option<i64>,
    reason: Option<&str>,
) -> String {
    let job_type = job_type.unwrap_or("indexing");
    let entries = entries_indexed
        .map(|count| count.to_string())
        .unwrap_or_else(|| "an unknown number of".to_string());
    let limit = processing_requested_limit_label(requested_limit);
    match status {
        None => "Not processed: no filesystem-index or browser-import job is recorded.".to_string(),
        Some("completed") => format!(
            "Complete indexing job: latest {job_type} completed with {entries} indexed entries and did not report truncation or failure. Requested limit: {limit}."
        ),
        Some("truncated") => format!(
            "PARTIAL INDEXING ONLY: latest {job_type} stopped after {entries} indexed entries. Requested limit: {limit}. Reason: {}. Findings from this index do not represent full source coverage.",
            reason.unwrap_or("processing reported truncation without a stored reason")
        ),
        Some("failed") => format!(
            "FAILED INDEXING: latest {job_type} failed; {entries} entries from that attempt were committed. Requested limit: {limit}. Reason: {}. Findings must not be treated as complete source coverage.",
            reason.unwrap_or("processing failed without a stored reason")
        ),
        Some("running") => format!(
            "PROCESSING INCOMPLETE: latest {job_type} is still marked running. Requested limit: {limit}. Current recorded entry count: {entries}. Findings must not be treated as complete source coverage."
        ),
        Some(other) => format!(
            "Processing coverage is unknown: latest {job_type} has unrecognized status '{other}', with {entries} recorded entries and requested limit {limit}."
        ),
    }
}

fn bookmark_item_processing_warning(
    item: &BookmarkItem,
    evidence: Option<&ReportEvidence>,
) -> Option<String> {
    item.entry_id?;
    let captured_status = item
        .item_ref_json
        .get("index_job_status")
        .and_then(|value| value.as_str());
    if let Some(status) = captured_status {
        return processing_status_is_incomplete(Some(status)).then(|| {
            item.item_ref_json
                .get("index_processing_coverage")
                .and_then(|value| value.as_str())
                .unwrap_or("This finding was derived from an incomplete indexing job and does not represent full source coverage.")
                .to_string()
        });
    }
    evidence
        .filter(|evidence| {
            processing_status_is_incomplete(evidence.latest_process_job_status.as_deref())
        })
        .map(|evidence| evidence.processing_coverage.clone())
}

fn report_evidence_rows(conn: &Connection, case_id: i64) -> Result<Vec<ReportEvidence>> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.display_name, e.source_kind, e.source_path, e.size_bytes,
                e.attached_at, e.indexed_at, e.notes,
                (SELECT COUNT(*) FROM filesystem_entries f
                 WHERE f.case_id = e.case_id AND f.evidence_id = e.id),
                e.sha256_hex, e.sha256_scope, e.acquisition_manifest_json,
                j.id, j.job_type, j.status,
                CAST(COALESCE(
                    json_extract(j.parameters_json, '$.max_entries'),
                    json_extract(j.parameters_json, '$.max_visits')
                ) AS INTEGER),
                COALESCE(
                    CAST(json_extract(j.parameters_json, '$.entries_indexed') AS INTEGER),
                    CASE WHEN j.id IS NOT NULL THEN (
                        SELECT COUNT(*) FROM filesystem_entries jf
                        WHERE jf.case_id = e.case_id
                          AND jf.evidence_id = e.id
                          AND jf.discovered_by_job_id = j.id
                    ) END
                ),
                j.error
         FROM evidence_sources e
         LEFT JOIN evidence_jobs j ON j.id = (
             SELECT latest.id FROM evidence_jobs latest
             WHERE latest.case_id = e.case_id
               AND latest.evidence_id = e.id
               AND latest.job_type = CASE WHEN e.source_kind = 'browser_history'
                   THEN 'browser_history_import' ELSE 'filesystem_index' END
             ORDER BY latest.id DESC
             LIMIT 1
         )
         WHERE e.case_id = ?1 AND e.attach_status <> 'superseded'
         ORDER BY e.id",
    )?;
    let rows = stmt.query_map(params![case_id], |row| {
        let source_path: String = row.get(3)?;
        let file_extension = Path::new(&source_path)
            .extension()
            .map(|ext| ext.to_string_lossy().to_lowercase());
        let latest_process_job_type: Option<String> = row.get(13)?;
        let latest_process_job_status: Option<String> = row.get(14)?;
        let requested_entry_limit: Option<i64> = row.get(15)?;
        let latest_process_entries_indexed: Option<i64> = row.get(16)?;
        let processing_truncation_reason: Option<String> = row.get(17)?;
        let processing_coverage = processing_coverage_text(
            latest_process_job_type.as_deref(),
            latest_process_job_status.as_deref(),
            requested_entry_limit,
            latest_process_entries_indexed,
            processing_truncation_reason.as_deref(),
        );
        Ok(ReportEvidence {
            id: row.get(0)?,
            display_name: row.get(1)?,
            source_kind: row.get(2)?,
            source_path,
            file_extension,
            size_bytes: row.get(4)?,
            sha256: row.get(9)?,
            sha256_scope: row.get(10)?,
            acquisition_manifest_json: acquisition_manifest_from_row(row, 11)?,
            attached_at: row.get(5)?,
            indexed_at: row.get(6)?,
            entries_indexed: row.get(8)?,
            latest_process_job_id: row.get(12)?,
            latest_process_job_type,
            latest_process_job_status,
            requested_entry_limit,
            latest_process_entries_indexed,
            processing_truncation_reason,
            processing_coverage,
            notes: row.get(7)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report evidence sources")
}

fn render_acquisition_manifest_html(html: &mut String, manifest: &AcquisitionManifest) {
    html.push_str("<dl class=\"activity-details\"><dt>Scheme</dt><dd>");
    html.push_str(&escape_html(&manifest.scheme));
    html.push_str("</dd><dt>Completeness</dt><dd>");
    html.push_str(if manifest.complete {
        "complete"
    } else {
        "partial"
    });
    html.push_str("</dd><dt>Segments</dt><dd>");
    html.push_str(&manifest.segment_count.to_string());
    html.push_str(" (total acquisition-file bytes: ");
    html.push_str(&manifest.total_size.to_string());
    html.push_str(")</dd>");
    for (index, segment) in manifest.segments.iter().enumerate() {
        html.push_str("<dt>Acquisition/container file ");
        html.push_str(&(index + 1).to_string());
        html.push_str("</dt><dd>");
        html.push_str(&escape_html(&segment.path));
        html.push_str(" &mdash; ");
        html.push_str(&segment.size.to_string());
        html.push_str(" bytes &mdash; SHA-256: <code>");
        html.push_str(&escape_html(&segment.sha256));
        html.push_str("</code></dd>");
    }
    html.push_str("<dt>Manifest note</dt><dd>");
    html.push_str(&escape_html(&manifest.note));
    html.push_str("</dd></dl>");
}

/// Report variant that also carries the full indexed directory structure of
/// each evidence source, bounded by `max_lines_per_evidence` tree lines.
pub fn report_data_with_directory_structure(
    case_path: &Path,
    max_lines_per_evidence: usize,
) -> Result<ReportData> {
    let mut report = report_data(case_path)?;
    let conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let mut trees = Vec::new();
    for evidence in &report.evidence {
        // Only the exact-source-path string is needed per row, so extract it
        // in SQL (mirroring source_path_exact_from_metadata's key priority)
        // instead of shipping and serde-parsing every row's full
        // metadata_json - that per-row parse dominated report export time on
        // six-figure-entry cases.
        // The report's Directory Structure shows the GENUINE source
        // filesystem hierarchy only. KDFT's own bookkeeping and derived rows
        // (partition/volume/container records, partition reports, carved
        // staging, unallocated pseudo-files) are tool output, not the disk's
        // directory structure, and used to leak synthetic roots like
        // "Carved/" into the source directory tree.
        let mut stmt = conn.prepare(
            "SELECT logical_path, name, entry_kind, size_bytes,
                    COALESCE(
                        NULLIF(json_extract(metadata_json, '$.source_path_exact'), ''),
                        NULLIF(json_extract(metadata_json, '$.ntfs_path'), ''),
                        NULLIF(json_extract(metadata_json, '$.fat_path'), ''),
                        NULLIF(json_extract(metadata_json, '$.ext_path'), ''),
                        NULLIF(json_extract(metadata_json, '$.local_relative_path'), '')
                    )
             FROM filesystem_entries
             WHERE case_id = ?1 AND evidence_id = ?2
               AND COALESCE(json_extract(metadata_json, '$.artifact_kind'), 'filesystem_entry')
                   IN ('filesystem_entry', 'deleted_file_record')",
        )?;
        let rows = stmt.query_map(params![case_id, evidence.id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let rows = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("listing directory structure entries")?;
        if rows.is_empty() {
            continue;
        }
        // BTreeMap keyed by path components yields depth-first, alphabetical
        // traversal and lets implied parent folders (paths with no directory
        // row of their own) appear in the tree.
        let mut nodes: BTreeMap<Vec<String>, (String, Option<i64>)> = BTreeMap::new();
        let total_entries = rows.len() as i64;
        for (logical_path, name, entry_kind, size_bytes, exact_path) in rows {
            let mut parts: Vec<String> = logical_path
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect();
            // Strip internal containers so report trees read source -> volume
            // -> folders.
            if parts.first().map(String::as_str) == Some("Image Analysis") {
                parts.remove(0);
                if matches!(
                    parts.first().map(String::as_str),
                    Some("Volumes") | Some("Partitions")
                ) {
                    parts.remove(0);
                }
                // The container folders themselves collapse away entirely.
                if parts.is_empty() {
                    continue;
                }
            }
            let exact_parts = exact_path
                .as_deref()
                .map(|path| {
                    path.split(['/', '\\'])
                        .filter(|part| !part.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .filter(|parts| !parts.is_empty());
            if let Some(exact_parts) = exact_parts {
                if logical_path.starts_with("/Image Analysis/Volumes/") && !parts.is_empty() {
                    let volume = parts[0].clone();
                    parts = std::iter::once(volume).chain(exact_parts).collect();
                } else {
                    parts = exact_parts;
                }
            }
            if parts.is_empty() {
                parts.push(name);
            }
            for ancestor_len in 1..parts.len() {
                nodes
                    .entry(parts[..ancestor_len].to_vec())
                    .or_insert_with(|| ("directory".to_string(), None));
            }
            // The report tree shows the directory structure only; individual
            // files would blow the report up on large evidence. Files still
            // contribute their implied ancestor folders above.
            if entry_kind == "directory" {
                nodes.insert(parts, (entry_kind, size_bytes));
            }
        }
        let mut truncated = false;
        let mut lines = Vec::new();
        for (parts, (entry_kind, size_bytes)) in &nodes {
            if lines.len() >= max_lines_per_evidence {
                truncated = true;
                break;
            }
            lines.push(ReportTreeLine {
                depth: parts.len() - 1,
                name: parts.last().cloned().unwrap_or_default(),
                entry_kind: entry_kind.clone(),
                size_bytes: *size_bytes,
            });
        }
        trees.push(ReportDirectoryTree {
            evidence_id: evidence.id,
            evidence_name: evidence.display_name.clone(),
            total_entries,
            truncated,
            lines,
        });
    }
    report.directory_trees = trees;
    Ok(report)
}

/// Records a report export in the case audit trail so a produced report can
/// later be re-verified against the case database. Two digests are stored
/// under explicit names: `content_prefix_sha256` is the digest
/// embedded in the report's integrity footer and covers only the bytes
/// preceding that footer; `report_file_sha256` is a standard SHA-256 over the
/// complete written report file, so ordinary `sha256sum`/`certutil`
/// verification matches it directly.
pub fn record_report_export(
    case_path: &Path,
    output_path: &str,
    content_prefix_sha256: &str,
    report_file_sha256: &str,
) -> Result<()> {
    let mut conn = open_existing_case(case_path)?;
    let case_id = active_case_id(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actor = audit_actor(&tx, case_id)?;
    tx.execute(
        "INSERT INTO audit_events(case_id, event_type, actor, object_type, object_id, details_json)
         VALUES (?1, 'report.export', ?2, 'report', ?1,
                 json_object('output_path', ?3,
                             'content_prefix_sha256', ?4,
                             'report_file_sha256', ?5))",
        params![
            case_id,
            actor,
            output_path,
            content_prefix_sha256,
            report_file_sha256
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn render_report_html(report: &ReportData) -> String {
    render_report(report).html
}

pub fn render_report(report: &ReportData) -> RenderedReport {
    let mut html = String::new();
    let evidence_by_id: HashMap<i64, &ReportEvidence> = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id, evidence))
        .collect();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>");
    html.push_str(&escape_html(&report.case.name));
    html.push_str("</title><style>");
    html.push_str("body{font-family:Segoe UI,Arial,sans-serif;margin:32px;line-height:1.4;color:#1f2933}h1{margin-bottom:0}h2{border-bottom:1px solid #cfd7df;padding-bottom:4px;margin-top:28px}article{margin:16px 0;padding:12px 0;border-bottom:1px solid #e6ebf0}.meta{color:#5b6773;font-size:0.9em}.comment{white-space:pre-wrap}.items{border-collapse:collapse;width:100%;margin-top:8px}.items th,.items td{border:1px solid #d9e1e8;padding:6px;text-align:left;vertical-align:top}.items th{background:#f3f6f8}.activity-details{margin:0}.activity-details dt{font-weight:600}.activity-details dd{margin:0 0 4px 0;overflow-wrap:anywhere}pre{white-space:pre-wrap;background:#f6f8fa;padding:8px;border:1px solid #d9e1e8}");
    html.push_str(".kdft-band{display:flex;justify-content:space-between;align-items:center;background:#0f3d3e;color:#eaf4f4;padding:10px 14px;border-radius:6px;font-size:0.9em}.kdft-band .kdft-logo{font-weight:800;letter-spacing:2px;font-size:1.2em}.dirtree{font-family:Consolas,monospace;font-size:0.85em;line-height:1.5;overflow-x:auto}.kdft-integrity{margin-top:32px;border-top:2px solid #0f3d3e;padding-top:8px;color:#5b6773;font-size:0.8em;overflow-wrap:anywhere}body::after{content:'KDFT';position:fixed;top:40%;left:20%;font-size:18vw;font-weight:900;color:rgba(15,61,62,0.05);transform:rotate(-28deg);pointer-events:none;z-index:0}");
    html.push_str(".processing-warning{border:2px solid #9f1239;background:#fff1f2;color:#881337;padding:12px 14px;margin:16px 0;font-weight:650;position:relative;z-index:1}.processing-partial{color:#9f1239;font-weight:700}");
    html.push_str(".kdft-toc{background:#f3f6f8;border:1px solid #d9e1e8;border-radius:6px;padding:10px 14px;margin-top:16px;display:flex;flex-wrap:wrap;gap:6px 14px;align-items:baseline;position:relative;z-index:1}.kdft-toc a{color:#0f3d3e;text-decoration:none;font-weight:600}.kdft-toc a:hover{text-decoration:underline}.kdft-back-to-top{display:inline-block;margin-top:6px;font-size:0.85em}");
    html.push_str(".bookmark-items{table-layout:fixed}.bookmark-items td{overflow-wrap:anywhere}.bookmark-items th:nth-child(1),.bookmark-items td:nth-child(1){width:4%}.bookmark-items th:nth-child(2),.bookmark-items td:nth-child(2){width:10%}.bookmark-items th:nth-child(3),.bookmark-items td:nth-child(3){width:13%}.bookmark-items th:nth-child(4),.bookmark-items td:nth-child(4){width:8%}.bookmark-items th:nth-child(5),.bookmark-items td:nth-child(5){width:39%}.bookmark-items th:nth-child(6),.bookmark-items td:nth-child(6){width:26%}");
    html.push_str("</style></head><body>");
    html.push_str("<div class=\"kdft-band\"><span class=\"kdft-logo\">KDFT</span><span>Kristiee's Digital Forensic Tool &middot; engine v");
    html.push_str(env!("CARGO_PKG_VERSION"));
    html.push_str("</span><span>Report generated ");
    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|now| DateTime::<Utc>::from_timestamp(now.as_secs() as i64, 0))
        .map(|now| now.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "unknown".to_string());
    html.push_str(&escape_html(&generated_at));
    html.push_str("</span></div>");
    html.push_str("<h1 id=\"top\">");
    html.push_str(&escape_html(&report.case.name));
    html.push_str("</h1>");
    html.push_str("<p class=\"meta\">");
    if let Some(case_number) = report
        .case
        .case_number
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        html.push_str("Case number: ");
        html.push_str(&escape_html(case_number));
        html.push_str(" | ");
    }
    if let Some(case_type) = report
        .case
        .case_type
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        html.push_str("Case type: ");
        html.push_str(&escape_html(case_type));
        html.push_str(" | ");
    }
    html.push_str("Examiner: ");
    html.push_str(&escape_html(
        report.case.examiner_name.as_deref().unwrap_or("unknown"),
    ));
    html.push_str(" | Created: ");
    html.push_str(&escape_html(&report.case.created_at));
    html.push_str("</p>");
    if let Some(description) = report
        .case
        .description
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        html.push_str("<p class=\"comment\">");
        html.push_str(&escape_html(description));
        html.push_str("</p>");
    }

    let incomplete_finding_evidence = report
        .folders
        .iter()
        .flat_map(|folder| &folder.bookmarks)
        .flat_map(|bookmark| &bookmark.items)
        .filter_map(|item| {
            let evidence = item
                .evidence_id
                .and_then(|evidence_id| evidence_by_id.get(&evidence_id).copied());
            bookmark_item_processing_warning(item, evidence)
                .is_some()
                .then_some(evidence)
                .flatten()
        })
        .map(|evidence| evidence.display_name.as_str())
        .collect::<HashSet<_>>();
    if !incomplete_finding_evidence.is_empty() {
        let mut names = incomplete_finding_evidence.into_iter().collect::<Vec<_>>();
        names.sort_unstable();
        html.push_str("<div class=\"processing-warning\">WARNING: This report contains findings derived from truncated, failed, or still-running indexing for: ");
        html.push_str(&escape_html(&names.join(", ")));
        html.push_str(". Those findings represent partial/uncertain coverage and must not be interpreted as a complete examination of the source.</div>");
    }

    html.push_str("<nav class=\"kdft-toc\"><strong>Jump to:</strong> <a href=\"#technical-details\">Technical Details</a>");
    for (index, tree) in report.directory_trees.iter().enumerate() {
        html.push_str(" <a href=\"#dirtree-");
        html.push_str(&index.to_string());
        html.push_str("\">Directory Structure - ");
        html.push_str(&escape_html(&tree.evidence_name));
        html.push_str("</a>");
    }
    for (index, folder) in report.folders.iter().enumerate() {
        html.push_str(" <a href=\"#folder-");
        html.push_str(&index.to_string());
        html.push_str("\">");
        html.push_str(&escape_html(&folder.name));
        html.push_str(" (");
        html.push_str(&folder.bookmarks.len().to_string());
        html.push_str(")</a>");
    }
    html.push_str("</nav>");

    html.push_str("<section id=\"technical-details\"><h2>Technical Details</h2>");
    html.push_str("<table class=\"items\"><tbody>");
    let case_rows = [
        ("Case name", Some(report.case.name.clone())),
        ("Case number", report.case.case_number.clone()),
        ("Case type", report.case.case_type.clone()),
        ("Examiner", report.case.examiner_name.clone()),
        ("Case created", Some(report.case.created_at.clone())),
        ("Timezone", Some(report.case.timezone.clone())),
        ("Report generated", Some(generated_at.clone())),
        (
            "Generated by",
            Some(format!(
                "KDFT (Kristiee's Digital Forensic Tool) v{}",
                env!("CARGO_PKG_VERSION")
            )),
        ),
    ];
    for (label, value) in case_rows {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            html.push_str("<tr><th>");
            html.push_str(&escape_html(label));
            html.push_str("</th><td>");
            html.push_str(&escape_html(&value));
            html.push_str("</td></tr>");
        }
    }
    html.push_str("</tbody></table>");

    if !report.evidence.is_empty() {
        html.push_str("<h2>Evidence Sources</h2><table class=\"items\"><thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Extension</th><th>Size</th><th>SHA-256 (decoded media for images; evidence file for files)</th><th>Acquisition/container file manifest</th><th>Latest processing status</th><th>Requested limit</th><th>Latest job indexed entries</th><th>Coverage / truncation reason</th><th>Location</th><th>Attached</th><th>Current indexed entries</th></tr></thead><tbody>");
        for evidence in &report.evidence {
            html.push_str("<tr><td>");
            html.push_str(&evidence.id.to_string());
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.display_name));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.source_kind));
            html.push_str("</td><td>");
            html.push_str(&escape_html(
                evidence.file_extension.as_deref().unwrap_or(""),
            ));
            html.push_str("</td><td>");
            match evidence.size_bytes {
                Some(size) => html.push_str(&escape_html(&format_size_bytes(size))),
                None => html.push_str("unknown"),
            }
            html.push_str("</td><td>");
            match evidence.sha256.as_deref() {
                Some(hash) => html.push_str(&escape_html(hash)),
                None => html.push_str("<span class=\"meta\">not computed</span>"),
            }
            html.push_str("</td><td>");
            match evidence.acquisition_manifest_json.as_ref() {
                Some(manifest) => render_acquisition_manifest_html(&mut html, manifest),
                None if evidence.source_kind == "image" => html.push_str(
                    "<span class=\"meta\">not computed; run the evidence hash job to create the acquisition-file manifest</span>",
                ),
                None => html.push_str("<span class=\"meta\">not applicable</span>"),
            }
            html.push_str("</td><td>");
            match evidence.latest_process_job_status.as_deref() {
                Some(status) => html.push_str(&escape_html(status)),
                None => html.push_str("<span class=\"meta\">not processed</span>"),
            }
            html.push_str("</td><td>");
            html.push_str(&escape_html(&processing_requested_limit_label(
                evidence.requested_entry_limit,
            )));
            html.push_str("</td><td>");
            match evidence.latest_process_entries_indexed {
                Some(count) => html.push_str(&count.to_string()),
                None => html.push_str("<span class=\"meta\">not recorded</span>"),
            }
            html.push_str("</td><td");
            if processing_status_is_incomplete(evidence.latest_process_job_status.as_deref()) {
                html.push_str(" class=\"processing-partial\"");
            }
            html.push('>');
            html.push_str(&escape_html(&evidence.processing_coverage));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.source_path));
            html.push_str("</td><td>");
            html.push_str(&escape_html(&evidence.attached_at));
            html.push_str("</td><td>");
            html.push_str(&evidence.entries_indexed.to_string());
            html.push_str("</td></tr>");
        }
        html.push_str("</tbody></table>");
    }
    html.push_str("</section>");

    for (dirtree_index, tree) in report.directory_trees.iter().enumerate() {
        html.push_str("<section id=\"dirtree-");
        html.push_str(&dirtree_index.to_string());
        html.push_str("\"><h2>Directory Structure - ");
        html.push_str(&escape_html(&tree.evidence_name));
        html.push_str("</h2><p class=\"meta\">");
        html.push_str(&tree.total_entries.to_string());
        html.push_str(" indexed entr");
        html.push_str(if tree.total_entries == 1 { "y" } else { "ies" });
        html.push_str(". Folder structure only; individual files are listed in bookmark sections.</p><pre class=\"dirtree\">");
        for line in &tree.lines {
            for _ in 0..line.depth {
                html.push_str("    ");
            }
            html.push_str(&escape_html(&line.name));
            if line.entry_kind == "directory" {
                html.push('/');
            } else if let Some(size) = line.size_bytes {
                html.push_str("  (");
                html.push_str(&escape_html(&format_size_bytes(size)));
                html.push(')');
            }
            html.push('\n');
        }
        html.push_str("</pre>");
        if tree.truncated {
            html.push_str("<p class=\"meta\">Directory listing truncated to ");
            html.push_str(&tree.lines.len().to_string());
            html.push_str(" lines.</p>");
        }
        html.push_str("<a class=\"kdft-back-to-top\" href=\"#top\">&uarr; Back to top</a>");
        html.push_str("</section>");
    }

    if report.folders.is_empty() {
        html.push_str("<p>No report-enabled bookmark folders.</p>");
    }

    for (folder_index, folder) in report.folders.iter().enumerate() {
        html.push_str("<section id=\"folder-");
        html.push_str(&folder_index.to_string());
        html.push_str("\"><h2>");
        html.push_str(&escape_html(&folder.name));
        html.push_str("</h2>");
        if let Some(comment) = &folder.folder_comment {
            html.push_str("<p class=\"comment\">");
            html.push_str(&escape_html(comment));
            html.push_str("</p>");
        }
        if folder.bookmarks.is_empty() {
            html.push_str("<p class=\"meta\">No report-enabled bookmarks in this folder.</p>");
        }
        for bookmark in &folder.bookmarks {
            html.push_str("<article><h3>");
            html.push_str(&escape_html(
                bookmark.title.as_deref().unwrap_or(&bookmark.bookmark_type),
            ));
            html.push_str("</h3><p class=\"meta\">Type: ");
            html.push_str(&escape_html(&bookmark.bookmark_type));
            if let Some(data_type) = &bookmark.data_type {
                html.push_str(" | Data type: ");
                html.push_str(&escape_html(data_type));
            }
            html.push_str(" | Created: ");
            html.push_str(&escape_html(&bookmark.created_at));
            html.push_str("</p>");
            if let Some(comment) = &bookmark.examiner_comment {
                html.push_str("<p class=\"comment\">");
                html.push_str(&escape_html(comment));
                html.push_str("</p>");
            }
            render_report_items_html(&mut html, &bookmark.items, &evidence_by_id);
            html.push_str("</article>");
        }
        html.push_str("<a class=\"kdft-back-to-top\" href=\"#top\">&uarr; Back to top</a>");
        html.push_str("</section>");
    }

    // The SHA-256 covers every report byte before the integrity footer, so an
    // exported file can be re-verified: hash the file content up to (not
    // including) the footer marker and compare, or match the hash against the
    // case database's report.export audit event.
    let sha256 = sha256_hex(html.as_bytes());
    html.push_str("<footer class=\"kdft-integrity\" data-kdft-sha256=\"");
    html.push_str(&sha256);
    html.push_str("\"><strong>KDFT report authenticity</strong> &mdash; generated by KDFT v");
    html.push_str(env!("CARGO_PKG_VERSION"));
    html.push_str(" on ");
    html.push_str(&escape_html(&generated_at));
    html.push_str(". SHA-256 of all report content preceding this footer: <code>");
    html.push_str(&sha256);
    html.push_str("</code>. To verify: hash the report file bytes up to (not including) the first occurrence of the marker <code>&lt;footer class=\"kdft-integrity\"</code> and compare with this value and with the <code>content_prefix_sha256</code> field of the report.export audit event stored in the case database. A standard SHA-256 over the complete report file is recorded separately in that audit event as <code>report_file_sha256</code>.</footer>");
    html.push_str("</body></html>");
    RenderedReport {
        html,
        content_prefix_sha256: sha256,
    }
}

fn format_size_bytes(size: i64) -> String {
    if size < 0 {
        return size.to_string();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {} ({size} bytes)", units[unit])
    }
}

pub fn report_bookmarks_for_folder(
    conn: &Connection,
    case_id: i64,
    folder_id: i64,
) -> Result<Vec<ReportBookmark>> {
    let mut stmt = conn.prepare(
        "SELECT id, folder_id, bookmark_type, data_type, title, examiner_comment,
                source_ref_json, content_ref_json, created_at
         FROM bookmarks
         WHERE folder_id = ?1 AND in_report = 1
         ORDER BY id",
    )?;
    let rows = stmt.query_map(params![folder_id], |row| {
        Ok(RawReportBookmark {
            id: row.get(0)?,
            folder_id: row.get(1)?,
            bookmark_type: row.get(2)?,
            data_type: row.get(3)?,
            title: row.get(4)?,
            examiner_comment: row.get(5)?,
            source_ref_json: row.get(6)?,
            content_ref_json: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    let raw_bookmarks = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report bookmarks")?;

    raw_bookmarks
        .into_iter()
        .map(|raw| {
            let source_ref_json =
                parse_stored_json(&raw.source_ref_json, "source_ref_json", raw.id)?;
            let content_ref_json =
                parse_stored_json(&raw.content_ref_json, "content_ref_json", raw.id)?;
            let mut bookmark = ReportBookmark {
                id: raw.id,
                folder_id: raw.folder_id,
                bookmark_type: raw.bookmark_type,
                data_type: raw.data_type,
                title: raw.title,
                examiner_comment: raw.examiner_comment,
                source_ref_json,
                content_ref_json,
                created_at: raw.created_at,
                items: report_items_for_bookmark(conn, case_id, raw.id)?,
            };
            expand_category_bookmark_items(conn, case_id, &mut bookmark)?;
            Ok(bookmark)
        })
        .collect()
}

struct RawReportBookmark {
    id: i64,
    folder_id: i64,
    bookmark_type: String,
    data_type: Option<String>,
    title: Option<String>,
    examiner_comment: Option<String>,
    source_ref_json: String,
    content_ref_json: String,
    created_at: String,
}

pub fn report_items_for_bookmark(
    conn: &Connection,
    case_id: i64,
    bookmark_id: i64,
) -> Result<Vec<BookmarkItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, bookmark_id, evidence_id, entry_id, item_order, display_name, logical_path,
                selection_offset, selection_length, data_preview, item_ref_json, created_at
         FROM bookmark_items
         WHERE bookmark_id = ?1
         ORDER BY item_order, id",
    )?;
    let rows = stmt.query_map(params![bookmark_id], |row| {
        Ok(RawBookmarkItem {
            id: row.get(0)?,
            bookmark_id: row.get(1)?,
            evidence_id: row.get(2)?,
            entry_id: row.get(3)?,
            item_order: row.get(4)?,
            display_name: row.get(5)?,
            logical_path: row.get(6)?,
            selection_offset: row.get(7)?,
            selection_length: row.get(8)?,
            data_preview: row.get(9)?,
            item_ref_json: row.get(10)?,
            created_at: row.get(11)?,
        })
    })?;
    let raw_items = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing report bookmark items")?;
    raw_items
        .into_iter()
        .map(|raw| {
            let mut item = bookmark_item_from_raw(raw)?;
            enrich_live_bookmark_item(conn, case_id, &mut item);
            Ok(item)
        })
        .collect()
}

pub const REPORT_CATEGORY_EXPANSION_LIMIT: usize = 1000;

fn enrich_live_bookmark_item(conn: &Connection, case_id: i64, item: &mut BookmarkItem) {
    if item.item_ref_json.get("metadata").is_some()
        && item.item_ref_json.get("size_bytes").is_some()
    {
        return;
    }
    let kind = item
        .item_ref_json
        .get("kind")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    if !matches!(kind.as_deref(), Some("live_file") | Some("live_dir")) {
        return;
    }
    let Some(evidence_id) = item.evidence_id.or_else(|| {
        item.item_ref_json
            .get("evidence_id")
            .and_then(|value| value.as_i64())
    }) else {
        return;
    };
    let Some(path) = item
        .item_ref_json
        .get("path")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item.item_ref_json
                .get("relative_path")
                .and_then(|value| value.as_str())
        })
        .map(str::to_string)
    else {
        return;
    };
    let volume = item
        .item_ref_json
        .get("volume")
        .and_then(|value| value.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);

    let source = conn
        .query_row(
            "SELECT source_kind, source_path, display_name
             FROM evidence_sources
             WHERE id = ?1 AND case_id = ?2",
            params![evidence_id, case_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .ok();
    let Some((source_kind, source_path, source_display_name)) = source else {
        return;
    };
    let mut volume_json = serde_json::Map::new();
    let live_entry = if source_kind == "image" {
        if let Ok(volumes) = list_image_volumes(Path::new(&source_path)) {
            if let Some(volume_info) = volumes.get(volume) {
                volume_json.insert(
                    "volume_name".to_string(),
                    serde_json::json!(volume_info.name),
                );
                volume_json.insert(
                    "volume_filesystem".to_string(),
                    serde_json::json!(volume_info.filesystem),
                );
                volume_json.insert(
                    "volume_start_offset".to_string(),
                    serde_json::json!(volume_info.start_offset),
                );
                volume_json.insert(
                    "volume_size_bytes".to_string(),
                    serde_json::json!(volume_info.size_bytes),
                );
            }
        }
        live_entry_for_image_path(Path::new(&source_path), volume, &path).ok()
    } else {
        None
    };

    let Some(object) = item.item_ref_json.as_object_mut() else {
        return;
    };
    object
        .entry("evidence_id".to_string())
        .or_insert_with(|| serde_json::json!(evidence_id));
    object.entry("entry_kind".to_string()).or_insert_with(|| {
        serde_json::json!(if kind.as_deref() == Some("live_dir") {
            "directory"
        } else {
            "file"
        })
    });
    if let Some(logical_path) = item.logical_path.as_deref() {
        object
            .entry("logical_path".to_string())
            .or_insert_with(|| serde_json::json!(logical_path));
    }
    object
        .entry("relative_path".to_string())
        .or_insert_with(|| serde_json::json!(path));
    if let Some(display_name) = item.display_name.as_deref() {
        object
            .entry("display_name".to_string())
            .or_insert_with(|| serde_json::json!(display_name));
    }
    object
        .entry("is_deleted".to_string())
        .or_insert_with(|| serde_json::json!(false));
    if kind.as_deref() == Some("live_file") {
        object
            .entry("file_extension".to_string())
            .or_insert_with(|| {
                serde_json::json!(file_extension_of(
                    item.display_name.as_deref().unwrap_or(&path)
                ))
            });
    }
    for (key, value) in &volume_json {
        object.entry(key.clone()).or_insert_with(|| value.clone());
    }
    if let Some(entry) = live_entry {
        object
            .entry("size_bytes".to_string())
            .or_insert_with(|| serde_json::json!(entry.size_bytes));
        object
            .entry("created_utc".to_string())
            .or_insert_with(|| serde_json::json!(entry.created_utc));
        object
            .entry("modified_utc".to_string())
            .or_insert_with(|| serde_json::json!(entry.modified_utc));
        object
            .entry("accessed_utc".to_string())
            .or_insert_with(|| serde_json::json!(entry.accessed_utc));
        object
            .entry("symlink".to_string())
            .or_insert_with(|| serde_json::json!(entry.symlink));
        object
            .entry("ntfs_file_record_number".to_string())
            .or_insert_with(|| serde_json::json!(entry.ntfs_file_record_number));
        object
            .entry("mft_record_logical_offset".to_string())
            .or_insert_with(|| serde_json::json!(entry.mft_record_logical_offset));
        object
            .entry("mft_record_physical_offset".to_string())
            .or_insert_with(|| serde_json::json!(entry.mft_record_physical_offset));
        object
            .entry("file_data_logical_offset".to_string())
            .or_insert_with(|| serde_json::json!(entry.file_data_logical_offset));
        object
            .entry("file_data_physical_offset".to_string())
            .or_insert_with(|| serde_json::json!(entry.file_data_physical_offset));
        object
            .entry("ntfs_mft_record_modification_time_utc".to_string())
            .or_insert_with(|| serde_json::json!(entry.ntfs_mft_record_modification_time_utc));
        if item
            .data_preview
            .as_deref()
            .filter(|value| !value.is_empty())
            .is_none()
        {
            item.data_preview = Some(live_entry_preview(kind.as_deref(), &entry));
        }
    }
    let metadata = object
        .entry("metadata".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if let Some(metadata) = metadata.as_object_mut() {
        metadata.insert("source_kind".to_string(), serde_json::json!(source_kind));
        metadata.insert("source_path".to_string(), serde_json::json!(source_path));
        metadata.insert(
            "source_display_name".to_string(),
            serde_json::json!(source_display_name),
        );
        metadata.insert("volume_index".to_string(), serde_json::json!(volume));
        for (key, value) in volume_json {
            metadata.entry(key).or_insert(value);
        }
    }
}

fn live_entry_for_image_path(source_path: &Path, volume: usize, path: &str) -> Result<LiveEntry> {
    let normalized = normalize_live_bookmark_path(path);
    let (parent, name) = split_live_parent_name(&normalized);
    let entries = list_image_directory(source_path, volume, &parent)?;
    entries
        .into_iter()
        .find(|entry| entry.name == name)
        .with_context(|| format!("live entry not found: {path}"))
}

fn normalize_live_bookmark_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn split_live_parent_name(path: &str) -> (String, String) {
    let trimmed = path.trim_end_matches('/');
    let Some(index) = trimmed.rfind('/') else {
        return ("/".to_string(), trimmed.to_string());
    };
    let parent = if index == 0 { "/" } else { &trimmed[..index] };
    let name = &trimmed[index + 1..];
    (parent.to_string(), name.to_string())
}

fn live_entry_preview(kind: Option<&str>, entry: &LiveEntry) -> String {
    let mut parts = Vec::new();
    parts.push(if kind == Some("live_dir") {
        "Live folder".to_string()
    } else {
        "Live file".to_string()
    });
    if let Some(size) = entry.size_bytes {
        parts.push(format_size_bytes(size));
    }
    if let Some(value) = entry.modified_utc.as_deref() {
        parts.push(format!("modified {value}"));
    }
    if let Some(value) = entry.created_utc.as_deref() {
        parts.push(format!("created {value}"));
    }
    if let Some(value) = entry.accessed_utc.as_deref() {
        parts.push(format!("accessed {value}"));
    }
    parts.join(" | ")
}

fn expand_category_bookmark_items(
    conn: &Connection,
    case_id: i64,
    bookmark: &mut ReportBookmark,
) -> Result<()> {
    let original_items = std::mem::take(&mut bookmark.items);
    let mut expanded_items = Vec::with_capacity(original_items.len());
    for mut item in original_items {
        let expansion = category_bookmark_expansion(conn, case_id, bookmark.id, &item)?;
        if let Some((summary, entries)) = expansion {
            item.data_preview = Some(summary);
            expanded_items.push(item);
            expanded_items.extend(entries);
        } else {
            expanded_items.push(item);
        }
    }
    bookmark.items = expanded_items;
    Ok(())
}

fn category_bookmark_expansion(
    conn: &Connection,
    case_id: i64,
    bookmark_id: i64,
    item: &BookmarkItem,
) -> Result<Option<(String, Vec<BookmarkItem>)>> {
    if item
        .item_ref_json
        .get("kind")
        .and_then(|value| value.as_str())
        != Some("category")
    {
        return Ok(None);
    }
    let key = item
        .item_ref_json
        .get("category_key")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let label = item
        .item_ref_json
        .get("category_label")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or({
            if key.is_empty() {
                "All Categories"
            } else {
                key
            }
        });
    let evidence_id = item
        .item_ref_json
        .get("evidence_id")
        .and_then(|value| value.as_i64())
        .or(item.evidence_id);
    let expansion = report_entries_for_category(conn, case_id, evidence_id, key)?;
    let total = expansion.total;
    let shown = expansion.entries.len();
    let omitted = total.saturating_sub(shown);
    let created_at = item.created_at.clone();
    let base_order = item.item_order;
    let synthetic_items = expansion
        .entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            report_category_entry_item(bookmark_id, base_order, index, &created_at, entry)
        })
        .collect::<Vec<_>>();
    let noun = if total == 1 { "entry" } else { "entries" };
    let summary = if omitted == 0 {
        format!("Indexed category: {label}. Expanded to {total} non-directory {noun}.")
    } else {
        format!(
            "Indexed category: {label}. Expanded to first {shown} of {total} non-directory {noun}; {omitted} omitted to keep the HTML report responsive."
        )
    };
    Ok(Some((summary, synthetic_items)))
}

struct ReportCategoryEntries {
    total: usize,
    entries: Vec<FilesystemEntry>,
}

fn report_entries_for_category(
    conn: &Connection,
    case_id: i64,
    evidence_id: Option<i64>,
    key: &str,
) -> Result<ReportCategoryEntries> {
    let (category_main, category_sub) = split_report_category_key(key);
    if let Some(evidence_id) = evidence_id {
        ensure_evidence_source(conn, case_id, evidence_id)?;
    }
    let total = conn
        .query_row(
            "SELECT COUNT(*)
             FROM filesystem_entries
             WHERE case_id = ?1
                AND (?2 IS NULL OR evidence_id = ?2)
                AND entry_kind != 'directory'
                AND COALESCE(json_extract(metadata_json, '$.category_hidden'), 0) <> 1
                AND COALESCE(json_extract(metadata_json, '$.artifact_kind'), '')
                    NOT IN ('filesystem_parser_error', 'filesystem_parser_summary')
                AND (?3 = '' OR COALESCE(json_extract(metadata_json, '$.category_main'), 'Uncategorized') = ?3)
               AND (?4 IS NULL OR COALESCE(json_extract(metadata_json, '$.category_sub'), '') = ?4)",
            params![case_id, evidence_id, category_main, category_sub.as_deref()],
            |row| row.get::<_, i64>(0),
        )
        .context("counting entries for report category expansion")?;
    let total = usize::try_from(total).unwrap_or(usize::MAX);
    let mut stmt = conn.prepare(
        "SELECT id, case_id, evidence_id, parent_id, logical_path, name, entry_kind,
                size_bytes, is_deleted, metadata_json, discovered_by_job_id
         FROM filesystem_entries
         WHERE case_id = ?1
           AND (?2 IS NULL OR evidence_id = ?2)
           AND entry_kind != 'directory'
           AND COALESCE(json_extract(metadata_json, '$.category_hidden'), 0) <> 1
           AND COALESCE(json_extract(metadata_json, '$.artifact_kind'), '')
               NOT IN ('filesystem_parser_error', 'filesystem_parser_summary')
           AND (?3 = '' OR COALESCE(json_extract(metadata_json, '$.category_main'), 'Uncategorized') = ?3)
           AND (?4 IS NULL OR COALESCE(json_extract(metadata_json, '$.category_sub'), '') = ?4)
         ORDER BY COALESCE(json_extract(metadata_json, '$.category_main'), 'Uncategorized'),
                  COALESCE(json_extract(metadata_json, '$.category_sub'), ''),
                  logical_path, id
         LIMIT ?5",
    )?;
    let rows = stmt.query_map(
        params![
            case_id,
            evidence_id,
            category_main,
            category_sub.as_deref(),
            i64::try_from(REPORT_CATEGORY_EXPANSION_LIMIT).unwrap_or(i64::MAX)
        ],
        |row| {
            Ok(RawFilesystemEntry {
                id: row.get(0)?,
                case_id: row.get(1)?,
                evidence_id: row.get(2)?,
                parent_id: row.get(3)?,
                logical_path: row.get(4)?,
                name: row.get(5)?,
                entry_kind: row.get(6)?,
                size_bytes: row.get(7)?,
                is_deleted: row.get::<_, i64>(8)? != 0,
                metadata_json: row.get(9)?,
                discovered_by_job_id: row.get(10)?,
            })
        },
    )?;
    let entries = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing entries for report category expansion")?
        .into_iter()
        .map(filesystem_entry_from_raw)
        .collect::<Result<Vec<_>>>()?;
    Ok(ReportCategoryEntries { total, entries })
}

fn split_report_category_key(key: &str) -> (String, Option<String>) {
    let mut parts = key.splitn(2, "|||");
    let main = parts.next().unwrap_or("").trim().to_string();
    let sub = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    (main, sub)
}

fn report_category_entry_item(
    bookmark_id: i64,
    base_order: i64,
    index: usize,
    created_at: &str,
    entry: FilesystemEntry,
) -> BookmarkItem {
    let item_ref_json = report_entry_item_ref_json(&entry);
    let display_name = report_entry_display_name(&entry);
    let internal_path_key = entry.internal_path_key.clone();
    let source_path_exact = entry.source_path_exact.clone();
    let item_order = base_order.saturating_add(i64::try_from(index + 1).unwrap_or(i64::MAX));
    BookmarkItem {
        id: -item_order,
        bookmark_id,
        evidence_id: Some(entry.evidence_id),
        entry_id: Some(entry.id),
        item_order,
        display_name: Some(display_name),
        logical_path: Some(entry.logical_path),
        internal_path_key: Some(internal_path_key),
        source_path_exact,
        selection_offset: None,
        selection_length: None,
        data_preview: report_entry_preview(&item_ref_json),
        item_ref_json,
        created_at: created_at.to_string(),
    }
}

pub fn report_entry_item_ref_json(entry: &FilesystemEntry) -> serde_json::Value {
    let mut metadata_for_report = entry.metadata_json.clone();
    if let Some(metadata_object) = metadata_for_report.as_object_mut() {
        metadata_object.remove("search_text");
    }
    let mut object = metadata_for_report
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    // search_text is a synthetic, often-large Deep Search index blob (concatenated
    // URL/title/host, or a full metadata dump for preferences) - internal plumbing, not
    // examiner-facing content, so it must not leak into the report.
    object.remove("search_text");
    let artifact_kind = object
        .get("artifact_kind")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    object.insert(
        "evidence_id".to_string(),
        serde_json::json!(entry.evidence_id),
    );
    object.insert("entry_id".to_string(), serde_json::json!(entry.id));
    object.insert(
        "index_job_id".to_string(),
        serde_json::json!(entry.discovered_by_job_id),
    );
    object.insert(
        "entry_kind".to_string(),
        serde_json::json!(entry.entry_kind),
    );
    object.insert(
        "logical_path".to_string(),
        serde_json::json!(entry.logical_path),
    );
    object.insert(
        "internal_path_key".to_string(),
        serde_json::json!(entry.internal_path_key),
    );
    object.insert(
        "source_path_exact".to_string(),
        serde_json::json!(entry.source_path_exact),
    );
    object.insert(
        "display_name".to_string(),
        serde_json::json!(report_entry_display_name(entry)),
    );
    object.insert(
        "size_bytes".to_string(),
        serde_json::json!(entry.size_bytes),
    );
    object.insert(
        "is_deleted".to_string(),
        serde_json::json!(entry.is_deleted),
    );
    object.insert("metadata".to_string(), metadata_for_report);
    if let Some(kind) = artifact_kind.filter(|kind| is_browser_activity_artifact_kind(kind)) {
        object.insert("kind".to_string(), serde_json::json!("browser_activity"));
        object.insert("activity_kind".to_string(), serde_json::json!(kind));
    } else {
        object.insert("kind".to_string(), serde_json::json!("category_entry"));
    }
    serde_json::Value::Object(object)
}

pub fn is_browser_activity_artifact_kind(kind: &str) -> bool {
    matches!(
        kind,
        "browser_history_visit"
            | "browser_url"
            | "browser_search_term"
            | "browser_omnibox_shortcut"
            | "browser_autofill"
            | "browser_download"
            | "browser_bookmark"
            | "browser_login"
            | "browser_cookie"
            | "browser_preference"
    )
}

pub fn report_entry_display_name(entry: &FilesystemEntry) -> String {
    if entry.name.trim().is_empty() {
        {
            entry
                .logical_path
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string()
        }
    } else {
        entry.name.clone()
    }
}

pub fn report_entry_preview(item_ref: &serde_json::Value) -> Option<String> {
    let preview_fields = [
        "visit_time_utc",
        "last_visit_time_utc",
        "last_access_time_utc",
        "last_used_utc",
        "date_added_utc",
        "start_time_utc",
        "url",
        "search_term",
        "text",
        "value",
        "outcome_summary",
        "target_path",
        "current_path",
        "username",
        "cookie_name",
        "category_detail",
        "category_sub",
    ];
    let parts = preview_fields
        .iter()
        .filter_map(|key| activity_value_string(item_ref, &[*key]))
        .take(4)
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join(" | "))
}

/// Report display form of an entry path: the indexer's synthetic containers
/// are stripped so paths read volume-first.
/// Stored logical paths are never rewritten; this is display-only.
pub fn display_entry_path(path: &str) -> String {
    for prefix in [
        "/Image Analysis/Volumes",
        "/Image Analysis/Partitions",
        "/Image Analysis",
    ] {
        if let Some(rest) = path.strip_prefix(prefix) {
            if rest.is_empty() {
                return "/".to_string();
            }
            if rest.starts_with('/') {
                return rest.to_string();
            }
        }
    }
    path.to_string()
}

pub fn bookmark_item_exact_source_path(item_ref: &serde_json::Value) -> Option<String> {
    source_path_exact_from_metadata(item_ref)
        .or_else(|| {
            item_ref
                .get("metadata")
                .and_then(source_path_exact_from_metadata)
        })
        .or_else(|| {
            matches!(
                item_ref.get("kind").and_then(|value| value.as_str()),
                Some("live_file" | "live_dir")
            )
            .then(|| {
                item_ref
                    .get("relative_path")
                    .or_else(|| item_ref.get("path"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
            .flatten()
        })
}

fn render_report_items_html(
    html: &mut String,
    items: &[BookmarkItem],
    evidence_by_id: &HashMap<i64, &ReportEvidence>,
) {
    if items.is_empty() {
        html.push_str("<p class=\"meta\">No bookmark items.</p>");
        return;
    }

    html.push_str("<table class=\"items bookmark-items\"><thead><tr><th>Position</th><th>Name</th><th>Source path / KDFT internal path</th><th>Selection</th><th>Artifact</th><th>Reference</th></tr></thead><tbody>");
    for (index, item) in items.iter().enumerate() {
        html.push_str("<tr><td>");
        html.push_str(&(index + 1).to_string());
        html.push_str("</td><td>");
        html.push_str(&escape_html(item.display_name.as_deref().unwrap_or("")));
        html.push_str("</td><td>");
        if let Some(source_path_exact) = bookmark_item_exact_source_path(&item.item_ref_json) {
            html.push_str("<strong>Exact source path:</strong> ");
            html.push_str(&escape_html(&source_path_exact));
            if let Some(internal_path) = item.logical_path.as_deref() {
                html.push_str("<br><span class=\"meta\">KDFT internal path: ");
                html.push_str(&escape_html(&display_entry_path(internal_path)));
                html.push_str("</span>");
            }
        } else if let Some(internal_path) = item.logical_path.as_deref() {
            html.push_str(
                "<span class=\"meta\">Exact source path unavailable; KDFT internal path: ",
            );
            html.push_str(&escape_html(&display_entry_path(internal_path)));
            html.push_str("</span>");
        }
        html.push_str("</td><td>");
        if let Some(offset) = item.selection_offset {
            html.push_str("offset ");
            html.push_str(&offset.to_string());
        }
        if let Some(length) = item.selection_length {
            if item.selection_offset.is_some() {
                html.push_str(", ");
            }
            html.push_str("length ");
            html.push_str(&length.to_string());
        }
        html.push_str("</td><td>");
        let evidence = item
            .evidence_id
            .and_then(|evidence_id| evidence_by_id.get(&evidence_id).copied());
        render_report_item_preview_html(html, item, evidence);
        html.push_str("</td><td>");
        render_report_item_reference_html(html, item);
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table>");
}

fn render_report_item_preview_html(
    html: &mut String,
    item: &BookmarkItem,
    evidence: Option<&ReportEvidence>,
) {
    if render_email_details_html(html, &item.item_ref_json) {
        // Email bookmarks still carry forensic context (MAC times, deleted/recovered state,
        // offsets, size, extension) when the item ref has it, so append it after the
        // email-specific fields instead of stopping here.
        render_forensic_context_details_html(html, item, evidence);
        return;
    }
    if render_browser_activity_details_html(html, &item.item_ref_json) {
        if let Some(preview) = item
            .data_preview
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            html.push_str("<p class=\"meta\">Preview: ");
            html.push_str(&escape_html(preview));
            html.push_str("</p>");
        }
        return;
    }
    if render_forensic_context_details_html(html, item, evidence) {
        if let Some(preview) = item
            .data_preview
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            html.push_str("<p class=\"meta\">Preview: ");
            html.push_str(&escape_html(preview));
            html.push_str("</p>");
        }
        return;
    }
    html.push_str(&escape_html(item.data_preview.as_deref().unwrap_or("")));
}

fn render_report_item_reference_html(html: &mut String, item: &BookmarkItem) {
    if email_artifact_kind(&item.item_ref_json).is_some() {
        html.push_str("<span class=\"meta\">email</span>");
        return;
    }
    if browser_activity_kind(&item.item_ref_json).is_some() {
        html.push_str("<span class=\"meta\">browser_activity</span>");
        return;
    }
    if item
        .item_ref_json
        .get("kind")
        .and_then(|value| value.as_str())
        == Some("search_result")
    {
        html.push_str("<span class=\"meta\">search_result</span>");
        return;
    }
    if item
        .item_ref_json
        .get("kind")
        .and_then(|value| value.as_str())
        == Some("highlighted_bytes")
    {
        html.push_str("<span class=\"meta\">highlighted_bytes</span>");
        return;
    }
    html.push_str("<pre>");
    let mut item_ref_value = item.item_ref_json.clone();
    if let Some(object) = item_ref_value.as_object_mut() {
        for key in ["logical_path", "path", "relative_path"] {
            if let Some(value) = object.get_mut(key) {
                if let Some(text) = value.as_str() {
                    *value = serde_json::Value::String(display_entry_path(text));
                }
            }
        }
    }
    let item_ref =
        serde_json::to_string_pretty(&item_ref_value).unwrap_or_else(|_| "{}".to_string());
    html.push_str(&escape_html(&item_ref));
    html.push_str("</pre>");
}

fn render_forensic_context_details_html(
    html: &mut String,
    item: &BookmarkItem,
    evidence: Option<&ReportEvidence>,
) -> bool {
    let item_ref = &item.item_ref_json;
    let kind = item_ref.get("kind").and_then(|value| value.as_str());
    let source = item_ref.get("source").and_then(|value| value.as_str());
    let is_raw_whole_disk_hit =
        kind == Some("highlighted_bytes") && source == Some("raw_image_whole_disk_scan");
    let has_context = matches!(
        kind,
        Some("search_result")
            | Some("filesystem_entry")
            | Some("filesystem_folder")
            | Some("live_file")
            | Some("live_dir")
            | Some("highlighted_bytes")
    ) || item_ref.get("mft_record_physical_offset").is_some()
        || item_ref.get("file_data_physical_offset").is_some()
        || item_ref.get("is_deleted").is_some()
        || item_ref.get("file_extension").is_some()
        || item_ref.get("size_bytes").is_some();
    if !has_context {
        return false;
    }
    html.push_str("<dl class=\"activity-details\"><dt>Artifact</dt><dd>");
    html.push_str(match kind {
        Some("highlighted_bytes") if is_raw_whole_disk_hit => "Whole-Disk Bitwise Hit",
        Some("highlighted_bytes") => "Highlighted Bytes",
        Some("live_file") => "Live Browse File",
        Some("live_dir") => "Live Browse Folder",
        Some("filesystem_folder") => "Filesystem Folder",
        Some("filesystem_entry") => "Filesystem Entry",
        Some("search_result") => "Forensic Finding",
        _ => "Forensic Finding",
    });
    html.push_str("</dd>");
    if let Some(path) = bookmark_item_exact_source_path(item_ref) {
        push_detail_value(html, "Source Path (exact)", &path);
    }
    if let Some(path) = item_ref
        .get("internal_path_key")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item_ref
                .get("logical_path")
                .and_then(|value| value.as_str())
        })
        .or(item.logical_path.as_deref())
    {
        push_detail_value(html, "KDFT Internal Path", &display_entry_path(path));
    }
    if let Some(value) = activity_value_string(
        item_ref,
        &[
            "evidence_source",
            "evidence_display_name",
            "source_evidence_name",
        ],
    )
    .or_else(|| evidence.map(|evidence| evidence.display_name.clone()))
    {
        push_detail_value(html, "Evidence Source", &value);
    }
    if let Some(value) = activity_value_string(item_ref, &["source_path", "evidence_source_path"])
        .or_else(|| evidence.map(|evidence| evidence.source_path.clone()))
    {
        push_detail_value(html, "Evidence Path", &value);
    }
    // EA-001 / EA-004: for an image source the stored evidence digest is the
    // DECODED logical-media hash, not a hash of the acquisition/container file,
    // so it must never be labeled "Acquisition SHA-256" - a verifier hashing the
    // supplied E01/VMDK/VDI file cannot reproduce it. And a finding's scan-time
    // identity is immutable: render only the hash captured in THIS finding's
    // item_ref and never backfill it from the current evidence row, so a later
    // hash job cannot silently rewrite an earlier finding's provenance.
    let evidence_source_kind = evidence.map(|evidence| evidence.source_kind.as_str());
    let media_hash_label = match evidence_source_kind {
        Some("image") => "Logical media SHA-256 (decoded image stream)",
        Some("file") => "SHA-256 (evidence file)",
        _ => "Evidence SHA-256",
    };
    let scan_time_hash =
        activity_value_string(item_ref, &["evidence_sha256_hex", "evidence_sha256"]);
    if let Some(value) = &scan_time_hash {
        push_detail_value(html, media_hash_label, value);
    } else if is_raw_whole_disk_hit {
        push_detail_value(
            html,
            media_hash_label,
            "evidence not hashed at search time - compute the hash before relying on these results in court",
        );
    }
    push_activity_detail(
        html,
        item_ref,
        "Evidence Hashed At",
        &["evidence_hashed_at"],
    );
    // A hash that is NOT part of this finding's captured provenance is shown as
    // a separate, clearly qualified line - never backfilled into the scan-time
    // slot above - so a later evidence hash cannot masquerade as scan-time
    // identity (EA-004).
    if scan_time_hash.is_none() {
        if let Some(current) = evidence.and_then(|evidence| evidence.sha256.clone()) {
            push_detail_value(
                html,
                &format!(
                    "{media_hash_label} (current evidence value, not captured with this finding)"
                ),
                &current,
            );
        }
    }
    // Acquisition/container hashes are a separate identity from the decoded
    // media hash above. Historical item references do not yet carry this
    // manifest, so qualify it as the current evidence manifest rather than
    // implying it was captured with the finding (EA-001/EA-004).
    if let Some(manifest) =
        evidence.and_then(|evidence| evidence.acquisition_manifest_json.as_ref())
    {
        push_detail_value(
            html,
            "Acquisition manifest (current evidence value)",
            &format!(
                "{}; {}; {} segment(s); {} acquisition-file bytes",
                manifest.scheme,
                if manifest.complete {
                    "complete"
                } else {
                    "partial"
                },
                manifest.segment_count,
                manifest.total_size
            ),
        );
        for (index, segment) in manifest.segments.iter().enumerate() {
            push_detail_value(
                html,
                &format!(
                    "Acquisition/container file SHA-256 (current evidence manifest, segment {})",
                    index + 1
                ),
                &format!(
                    "{} ΓÇö {} bytes ΓÇö {}",
                    segment.path, segment.size, segment.sha256
                ),
            );
        }
        push_detail_value(html, "Acquisition manifest note", &manifest.note);
    }
    if let Some(warning) = bookmark_item_processing_warning(item, evidence) {
        push_detail_value(html, "Processing Coverage Warning", &warning);
    }
    push_activity_detail(html, item_ref, "Index Job ID", &["index_job_id"]);
    push_activity_detail(html, item_ref, "Index Job Status", &["index_job_status"]);
    push_activity_detail(
        html,
        item_ref,
        "Requested Index Entry Limit",
        &["index_requested_entry_limit"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Index Entries Recorded",
        &["index_entries_indexed"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Index Truncation Reason",
        &["index_truncation_reason"],
    );
    push_activity_detail(html, item_ref, "Source", &["source"]);
    push_activity_detail(html, item_ref, "Display Name", &["display_name"]);
    push_activity_detail(html, item_ref, "Entry Kind", &["entry_kind"]);
    push_activity_detail(html, item_ref, "Filesystem", &["filesystem"]);
    push_activity_detail(html, item_ref, "Volume", &["volume", "volume_name"]);
    push_activity_detail(
        html,
        item_ref,
        "Volume Start Offset",
        &["volume_start_offset", "partition_start_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Volume Index (zero-based)",
        &["volume_index_zero_based"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Partition Number (one-based)",
        &["partition_number_one_based"],
    );
    if item_ref.get("volume_index_zero_based").is_none()
        && item_ref.get("partition_number_one_based").is_none()
    {
        push_activity_detail(
            html,
            item_ref,
            "Legacy Partition Field (ambiguous historical convention)",
            &["partition_index"],
        );
    }
    push_activity_detail(html, item_ref, "Region", &["region"]);
    push_activity_detail(html, item_ref, "Volume Size", &["volume_size_bytes"]);
    push_activity_detail(html, item_ref, "Extension", &["file_extension"]);
    push_activity_detail(html, item_ref, "Detected Type", &["detected_signature"]);
    push_activity_detail(html, item_ref, "Signature Status", &["signature_status"]);
    push_activity_detail(html, item_ref, "Size", &["size_bytes"]);
    push_activity_detail(html, item_ref, "Deleted", &["is_deleted"]);
    push_activity_detail(html, item_ref, "Match", &["match_kind"]);
    push_activity_detail(
        html,
        item_ref,
        "NTFS File Record",
        &["ntfs_file_record_number"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Finding Offset",
        &["finding_logical_offset", "selection_offset"],
    );
    push_dec_hex_detail(
        html,
        item_ref,
        "Byte Offset",
        &[
            "byte_offset",
            "offset",
            "selection_physical_offset_start",
            "selection_logical_offset_start",
        ],
    );
    push_dec_hex_detail(
        html,
        item_ref,
        "Byte Offset End",
        &[
            "selection_physical_offset_end",
            "selection_logical_offset_end",
        ],
    );
    push_activity_detail(
        html,
        item_ref,
        "Selection Length",
        &[
            "selection_length",
            "selection_length_bytes",
            "matched_length",
        ],
    );
    push_activity_detail(html, item_ref, "Sector", &["sector"]);
    push_activity_detail(html, item_ref, "Sector Size", &["sector_size"]);
    push_activity_detail(html, item_ref, "Encoding", &["encoding"]);
    push_activity_detail(
        html,
        item_ref,
        "Physical Offset Basis",
        &["physical_offset_basis"],
    );
    push_activity_detail(html, item_ref, "Storage Area", &["storage_area"]);
    push_activity_detail(
        html,
        item_ref,
        "MFT Record Logical Offset",
        &["mft_record_logical_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "MFT Record Physical Offset",
        &["mft_record_physical_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "File Data Logical Offset",
        &["file_data_logical_offset"],
    );
    push_activity_detail(
        html,
        item_ref,
        "File Data Physical Offset",
        &["file_data_physical_offset"],
    );
    push_activity_detail(html, item_ref, "In File Slack", &["is_file_slack"]);
    push_activity_detail(html, item_ref, "In Unallocated Space", &["is_unallocated"]);
    push_activity_detail(
        html,
        item_ref,
        "Hex Preview",
        &["hex_preview", "data_preview"],
    );
    push_activity_detail(html, item_ref, "ASCII Preview", &["ascii_preview"]);
    push_activity_detail(html, item_ref, "Search Query", &["query", "search_query"]);
    push_activity_detail(
        html,
        item_ref,
        "Search Encodings",
        &["encodings", "search_encodings"],
    );
    push_activity_detail(html, item_ref, "Search Started", &["searched_at"]);
    push_activity_detail(html, item_ref, "Search Examiner", &["actor", "examiner"]);
    push_activity_detail(html, item_ref, "Scan Start", &["scan_start"]);
    push_activity_detail(html, item_ref, "Max Scan Bytes", &["max_scan_bytes"]);
    push_activity_detail(html, item_ref, "Bytes Scanned", &["bytes_scanned"]);
    push_activity_detail(html, item_ref, "Evidence Total Size", &["total_size"]);
    push_time_detail(html, item_ref, "Created", ForensicTimeRole::Created);
    push_time_detail(html, item_ref, "Modified", ForensicTimeRole::Modified);
    push_time_detail(html, item_ref, "Accessed", ForensicTimeRole::Accessed);
    push_time_detail(
        html,
        item_ref,
        "MFT Modified",
        ForensicTimeRole::MftModified,
    );
    push_activity_detail(html, item_ref, "Symlink", &["symlink"]);
    if let Some(metadata) = item_ref.get("metadata") {
        push_activity_detail(html, metadata, "Source Path", &["source_path"]);
        push_activity_detail(html, metadata, "Source Kind", &["source_kind"]);
        push_activity_detail(html, metadata, "Recovery Source", &["recovery_source"]);
        push_activity_detail(html, metadata, "Recovery Status", &["recovery_status"]);
    }
    html.push_str("</dl>");
    true
}

fn render_email_details_html(html: &mut String, item_ref: &serde_json::Value) -> bool {
    let Some(kind) = email_artifact_kind(item_ref) else {
        return false;
    };
    html.push_str("<dl class=\"activity-details\"><dt>Artifact</dt><dd>");
    html.push_str(if kind == "email_store" {
        "Email Store"
    } else {
        "Email Message"
    });
    html.push_str("</dd>");
    push_activity_detail(html, item_ref, "Email Format", &["email_format"]);
    push_activity_detail(
        html,
        item_ref,
        "Email Parser",
        &["email_parser", "email_parser_status"],
    );
    push_activity_detail(html, item_ref, "From", &["email_from"]);
    push_activity_detail(html, item_ref, "To", &["email_to"]);
    push_activity_detail(html, item_ref, "Cc", &["email_cc"]);
    push_activity_detail(html, item_ref, "Bcc", &["email_bcc"]);
    push_activity_detail(
        html,
        item_ref,
        "Subject",
        &["email_subject", "display_name"],
    );
    push_activity_detail(html, item_ref, "Date", &["email_date"]);
    push_activity_detail(html, item_ref, "Message ID", &["email_message_id"]);
    push_activity_detail(html, item_ref, "Reply-To", &["email_reply_to"]);
    push_activity_detail(html, item_ref, "In Reply To", &["email_in_reply_to"]);
    push_activity_detail(html, item_ref, "Body Preview", &["email_body_preview"]);
    push_activity_detail(
        html,
        item_ref,
        "Attachment Names",
        &["email_attachment_names"],
    );
    push_activity_detail(html, item_ref, "PST Folder", &["pst_folder_path"]);
    push_activity_detail(html, item_ref, "PST Parser Scope", &["pst_parser_scope"]);
    push_activity_detail(
        html,
        item_ref,
        "PST Attachment Content",
        &["pst_attachment_content_extraction"],
    );
    push_activity_detail(
        html,
        item_ref,
        "PST Deleted Recovery",
        &["pst_deleted_recovery"],
    );
    push_activity_detail(html, item_ref, "Parser Error", &["email_parser_error"]);
    html.push_str("</dl>");
    true
}

fn email_artifact_kind(item_ref: &serde_json::Value) -> Option<&str> {
    let kind = item_ref
        .get("artifact_kind")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item_ref
                .get("metadata")
                .and_then(|value| value.get("artifact_kind"))
                .and_then(|value| value.as_str())
        })?;
    matches!(kind, "email_message" | "email_store").then_some(kind)
}

fn render_browser_activity_details_html(html: &mut String, item_ref: &serde_json::Value) -> bool {
    let Some(kind) = browser_activity_kind(item_ref) else {
        return false;
    };
    html.push_str("<dl class=\"activity-details\"><dt>Activity</dt><dd>");
    html.push_str(&escape_html(browser_activity_label(kind)));
    html.push_str("</dd>");
    match kind {
        "browser_history_visit" => {
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Title", &["title", "display_name"]);
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Visit Time", &["visit_time_utc"]);
            push_activity_detail(html, item_ref, "Last URL Visit", &["last_visit_time_utc"]);
            push_activity_detail(html, item_ref, "Transition", &["transition_type"]);
            push_activity_detail(
                html,
                item_ref,
                "Transition Qualifiers",
                &["transition_qualifiers"],
            );
            push_activity_detail(html, item_ref, "Referrer URL", &["referrer_url"]);
            push_activity_detail(
                html,
                item_ref,
                "Referrer Visit Time",
                &["referrer_visit_time_utc"],
            );
            push_activity_detail(html, item_ref, "Opener URL", &["opener_url"]);
            push_activity_detail(
                html,
                item_ref,
                "External Referrer",
                &["external_referrer_url"],
            );
            push_activity_detail(html, item_ref, "Visit Duration", &["visit_duration_human"]);
            push_activity_detail(html, item_ref, "Visit Source", &["visit_source_label"]);
            push_activity_detail(html, item_ref, "Visit Count", &["visit_count"]);
            push_activity_detail(html, item_ref, "Typed Count", &["typed_count"]);
            push_activity_detail(html, item_ref, "Visit ID", &["visit_id"]);
            push_activity_detail(html, item_ref, "URL ID", &["url_id"]);
            push_activity_detail(html, item_ref, "Place ID", &["place_id"]);
            push_activity_detail(html, item_ref, "History Item ID", &["history_item_id"]);
            push_activity_detail(html, item_ref, "Visit Type", &["visit_type_label"]);
            push_activity_detail(html, item_ref, "Chrome Visit Time", &["visit_time_chrome"]);
            push_activity_detail(
                html,
                item_ref,
                "Chrome Last URL Visit",
                &["last_visit_time_chrome"],
            );
            push_activity_detail(html, item_ref, "Firefox PRTime", &["visit_time_prtime"]);
            push_activity_detail(html, item_ref, "Safari Time", &["visit_time_safari"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_url" => {
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Title", &["title", "display_name"]);
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Last Visit", &["last_visit_time_utc"]);
            push_activity_detail(html, item_ref, "Visit Count", &["visit_count"]);
            push_activity_detail(html, item_ref, "Typed Count", &["typed_count"]);
            push_activity_detail(html, item_ref, "Typed", &["typed"]);
            push_activity_detail(html, item_ref, "Hidden", &["hidden"]);
            push_activity_detail(html, item_ref, "URL ID", &["url_id"]);
            push_activity_detail(html, item_ref, "Place ID", &["place_id"]);
            push_activity_detail(html, item_ref, "History Item ID", &["history_item_id"]);
            push_activity_detail(
                html,
                item_ref,
                "Chrome Last Visit",
                &["last_visit_time_chrome"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Firefox PRTime",
                &["last_visit_time_prtime"],
            );
            push_browser_source_details(html, item_ref);
        }
        "browser_search_term" => {
            push_activity_detail(html, item_ref, "Search Term", &["search_term"]);
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Last Visit", &["last_visit_time_utc"]);
            push_activity_detail(html, item_ref, "First Used", &["first_used_utc"]);
            push_activity_detail(html, item_ref, "Last Used", &["last_used_utc"]);
            push_activity_detail(html, item_ref, "Times Used", &["times_used"]);
            push_activity_detail(html, item_ref, "URL ID", &["url_id"]);
            push_activity_detail(html, item_ref, "Form History ID", &["formhistory_id"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_omnibox_shortcut" => {
            push_activity_detail(html, item_ref, "Typed Text", &["text"]);
            push_activity_detail(html, item_ref, "Fill Into Edit", &["fill_into_edit"]);
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Contents", &["contents"]);
            push_activity_detail(html, item_ref, "Description", &["description"]);
            push_activity_detail(html, item_ref, "Type", &["type"]);
            push_activity_detail(html, item_ref, "Keyword", &["keyword"]);
            push_activity_detail(html, item_ref, "Last Access", &["last_access_time_utc"]);
            push_activity_detail(html, item_ref, "Hits", &["number_of_hits"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_autofill" => {
            push_activity_detail(html, item_ref, "Form Field", &["name"]);
            push_activity_detail(html, item_ref, "Typed Value", &["value"]);
            push_activity_detail(html, item_ref, "Use Count", &["count"]);
            push_activity_detail(html, item_ref, "Created", &["date_created_utc"]);
            push_activity_detail(html, item_ref, "Last Used", &["date_last_used_utc"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_download" => {
            push_activity_detail(html, item_ref, "File Name", &["file_name", "display_name"]);
            push_activity_detail(html, item_ref, "Target Path", &["target_path"]);
            push_activity_detail(html, item_ref, "Current Path", &["current_path"]);
            push_activity_detail(html, item_ref, "Outcome", &["outcome_summary"]);
            push_activity_detail(html, item_ref, "Download URL", &["download_url"]);
            push_activity_detail(html, item_ref, "Original URL", &["original_url"]);
            push_activity_detail(html, item_ref, "URL Chain", &["url_chain"]);
            push_activity_detail(html, item_ref, "Source URL", &["source_url"]);
            push_activity_detail(html, item_ref, "Site URL", &["site_url"]);
            push_activity_detail(html, item_ref, "Tab URL", &["tab_url"]);
            push_activity_detail(html, item_ref, "Referrer", &["referrer"]);
            push_activity_detail(html, item_ref, "Tab Referrer", &["tab_referrer_url"]);
            push_activity_detail(
                html,
                item_ref,
                "Started",
                &["start_time_utc", "date_added_utc"],
            );
            push_activity_detail(html, item_ref, "Ended", &["end_time_utc"]);
            push_activity_detail(html, item_ref, "Received Bytes", &["received_bytes"]);
            push_activity_detail(html, item_ref, "Total Bytes", &["total_bytes"]);
            push_activity_detail(html, item_ref, "Percent Complete", &["percent_complete"]);
            push_activity_detail(html, item_ref, "Duration", &["duration_human"]);
            push_activity_detail(html, item_ref, "State", &["state_label", "state"]);
            push_activity_detail(
                html,
                item_ref,
                "Danger Type",
                &["danger_type_label", "danger_type"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Interrupt Reason",
                &["interrupt_reason_label", "interrupt_reason"],
            );
            push_activity_detail(html, item_ref, "MIME Type", &["mime_type"]);
            push_activity_detail(
                html,
                item_ref,
                "Original MIME Type",
                &["original_mime_type"],
            );
            push_activity_detail(html, item_ref, "GUID", &["guid"]);
            push_activity_detail(html, item_ref, "Opened", &["opened"]);
            push_activity_detail(html, item_ref, "Last Access", &["last_access_time_utc"]);
            push_activity_detail(html, item_ref, "Download Hash", &["hash_hex"]);
            push_activity_detail(html, item_ref, "Download ID", &["download_id"]);
            push_activity_detail(html, item_ref, "Annotation ID", &["annotation_id"]);
            push_activity_detail(html, item_ref, "Annotation Name", &["annotation_name"]);
            push_activity_detail(
                html,
                item_ref,
                "Annotation Content",
                &["annotation_content"],
            );
            push_browser_source_details(html, item_ref);
        }
        "browser_bookmark" => {
            push_activity_detail(html, item_ref, "Name", &["name", "display_name"]);
            push_activity_detail(html, item_ref, "URL", &["url"]);
            push_activity_detail(html, item_ref, "Folder", &["folder"]);
            push_activity_detail(html, item_ref, "Added", &["date_added_utc"]);
            push_activity_detail(html, item_ref, "Last Used", &["date_last_used_utc"]);
            push_activity_detail(html, item_ref, "Chrome Added", &["date_added_chrome"]);
            push_activity_detail(
                html,
                item_ref,
                "Chrome Last Used",
                &["date_last_used_chrome"],
            );
            push_activity_detail(html, item_ref, "GUID", &["guid"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_login" => {
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Origin URL", &["origin_url"]);
            push_activity_detail(html, item_ref, "Action URL", &["action_url"]);
            push_activity_detail(html, item_ref, "Hostname", &["hostname"]);
            push_activity_detail(html, item_ref, "Realm", &["http_realm"]);
            push_activity_detail(html, item_ref, "Username", &["username"]);
            push_activity_detail(
                html,
                item_ref,
                "Created",
                &["date_created_utc", "time_created_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Last Used",
                &["date_last_used_utc", "time_last_used_utc"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Password Changed",
                &["time_password_changed_utc"],
            );
            push_activity_detail(html, item_ref, "Times Used", &["times_used"]);
            push_activity_detail(
                html,
                item_ref,
                "Password Ciphertext",
                &["password_ciphertext", "password_ciphertext_hex"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Username Ciphertext",
                &["username_ciphertext"],
            );
            push_activity_detail(html, item_ref, "Password Note", &["password_note"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_cookie" => {
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Cookie Name", &["cookie_name"]);
            push_activity_detail(html, item_ref, "Cookie Path", &["cookie_path"]);
            push_activity_detail(html, item_ref, "Created", &["creation_utc"]);
            push_activity_detail(
                html,
                item_ref,
                "Last Access",
                &["last_access_utc", "last_accessed_utc"],
            );
            push_activity_detail(html, item_ref, "Expires", &["expires_utc", "expiry_utc"]);
            push_activity_detail(html, item_ref, "Secure", &["is_secure"]);
            push_activity_detail(html, item_ref, "HttpOnly", &["is_httponly"]);
            push_activity_detail(
                html,
                item_ref,
                "Cookie / Session Value",
                &["cookie_value_plaintext"],
            );
            push_activity_detail(
                html,
                item_ref,
                "Encrypted Value Bytes",
                &["cookie_value_encrypted_bytes"],
            );
            push_activity_detail(html, item_ref, "Value Note", &["value_note"]);
            push_browser_source_details(html, item_ref);
        }
        "browser_cache_entry" => {
            push_activity_detail(html, item_ref, "URL", &["url", "cache_key"]);
            push_activity_detail(html, item_ref, "Host", &["host"]);
            push_activity_detail(html, item_ref, "Created", &["created_utc", "creation_utc"]);
            push_activity_detail(html, item_ref, "HTTP Status", &["http_status_code"]);
            push_activity_detail(html, item_ref, "Status Line", &["http_status_line"]);
            push_activity_detail(html, item_ref, "Content Type", &["content_type"]);
            push_activity_detail(html, item_ref, "Content Encoding", &["content_encoding"]);
            push_activity_detail(html, item_ref, "Last Modified", &["last_modified"]);
            push_activity_detail(html, item_ref, "Expires", &["expires"]);
            push_activity_detail(html, item_ref, "Cache Control", &["cache_control"]);
            push_activity_detail(html, item_ref, "Body Bytes", &["cache_body_size_bytes"]);
            push_activity_detail(html, item_ref, "Cache State", &["cache_entry_state"]);
            push_activity_detail(
                html,
                item_ref,
                "Parser Scope",
                &["browser_cache_parser_scope"],
            );
            push_browser_source_details(html, item_ref);
        }
        "browser_preference" => {
            push_activity_detail(html, item_ref, "Category", &["category"]);
            push_activity_detail(html, item_ref, "Profile Name", &["name", "display_name"]);
            push_activity_detail(html, item_ref, "Startup URLs", &["startup_urls"]);
            push_activity_detail(html, item_ref, "Homepage", &["homepage"]);
            push_activity_detail(
                html,
                item_ref,
                "Download Directory",
                &["download_default_directory"],
            );
            push_activity_detail(html, item_ref, "Extensions", &["extension_count"]);
            push_activity_detail(
                html,
                item_ref,
                "Created By Version",
                &["created_by_version"],
            );
            push_activity_detail(html, item_ref, "Last Used", &["last_used"]);
            push_browser_source_details(html, item_ref);
        }
        _ => {
            push_activity_detail(html, item_ref, "Name", &["display_name", "name", "title"]);
            push_activity_detail(html, item_ref, "Path", &["logical_path"]);
        }
    }
    html.push_str("</dl>");
    true
}

fn push_browser_source_details(html: &mut String, item_ref: &serde_json::Value) {
    push_activity_detail(html, item_ref, "Source Artifact", &["source_artifact"]);
    push_activity_detail(
        html,
        item_ref,
        "Source Path",
        &["source_artifact_path_exact", "source_artifact_path"],
    );
    let basis = activity_value_string(item_ref, &["source_file_time_basis"])
        .unwrap_or_else(|| "basis_not_recorded".to_string());
    let prefix = match basis.as_str() {
        "original_evidence_filesystem" => "Original Source File",
        "local_source_filesystem" => "Imported Local Source File",
        "original_evidence_path_resolved_times_unavailable" => "Original Source File",
        _ => "Source File (timestamp basis not recorded)",
    };
    push_activity_detail(
        html,
        item_ref,
        &format!("{prefix} Created"),
        &["source_file_created_utc"],
    );
    push_activity_detail(
        html,
        item_ref,
        &format!("{prefix} Modified"),
        &["source_file_modified_utc"],
    );
    push_activity_detail(
        html,
        item_ref,
        &format!("{prefix} Accessed"),
        &["source_file_accessed_utc"],
    );
    push_activity_detail(
        html,
        item_ref,
        &format!("{prefix} MFT Modified"),
        &["source_file_mft_modified_utc"],
    );
    push_activity_detail(
        html,
        item_ref,
        &format!("{prefix} Size"),
        &["source_file_size_bytes"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Staging Copy Path (not evidence source path)",
        &["source_artifact_staging_path"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Staging Copy Created (not evidence MACB)",
        &["staging_file_created_utc"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Staging Copy Modified (not evidence MACB)",
        &["staging_file_modified_utc"],
    );
    push_activity_detail(
        html,
        item_ref,
        "Staging Copy Accessed (not evidence MACB)",
        &["staging_file_accessed_utc"],
    );
}

fn browser_activity_kind(item_ref: &serde_json::Value) -> Option<&str> {
    let explicit_browser_activity =
        item_ref.get("kind").and_then(|value| value.as_str()) == Some("browser_activity");
    let kind = item_ref
        .get("activity_kind")
        .and_then(|value| value.as_str())
        .or_else(|| {
            item_ref
                .get("metadata")
                .and_then(|value| value.get("artifact_kind"))
                .and_then(|value| value.as_str())
        })?;
    (explicit_browser_activity || kind.starts_with("browser_")).then_some(kind)
}

fn browser_activity_label(kind: &str) -> &'static str {
    match kind {
        "browser_history_visit" => "Visit",
        "browser_url" => "URL",
        "browser_search_term" => "Search",
        "browser_omnibox_shortcut" => "Omnibox Shortcut",
        "browser_autofill" => "Autofill",
        "browser_download" => "Download",
        "browser_bookmark" => "Bookmark",
        "browser_login" => "Saved Login",
        "browser_cookie" => "Cookie",
        "browser_cache_entry" => "Cache Entry",
        "browser_preference" => "Preference",
        _ => "Browser Activity",
    }
}

fn push_detail_value(html: &mut String, label: &str, value: &str) {
    if value.trim().is_empty() {
        return;
    }
    html.push_str("<dt>");
    html.push_str(&escape_html(label));
    html.push_str("</dt><dd>");
    html.push_str(&escape_html(value));
    html.push_str("</dd>");
}

fn push_dec_hex_detail(
    html: &mut String,
    item_ref: &serde_json::Value,
    label: &str,
    keys: &[&str],
) {
    if let Some(value) = activity_u64(item_ref, keys) {
        push_detail_value(html, label, &format!("{value} (0x{value:X})"));
    }
}

fn push_activity_detail(
    html: &mut String,
    item_ref: &serde_json::Value,
    label: &str,
    keys: &[&str],
) {
    if let Some(value) = activity_value_string(item_ref, keys) {
        push_detail_value(html, label, &value);
    }
}

#[derive(Clone, Copy)]
enum ForensicTimeRole {
    Created,
    Modified,
    Accessed,
    MftModified,
}

fn resolved_forensic_time(item_ref: &serde_json::Value, role: ForensicTimeRole) -> Option<String> {
    let metadata = item_ref.get("metadata").unwrap_or(item_ref);
    let keys = match role {
        ForensicTimeRole::Created => {
            report_display_time_keys(metadata, BrowserDisplayTimeRole::Created)
        }
        ForensicTimeRole::Modified => {
            report_display_time_keys(metadata, BrowserDisplayTimeRole::Modified)
        }
        ForensicTimeRole::Accessed => {
            report_display_time_keys(metadata, BrowserDisplayTimeRole::Accessed)
        }
        ForensicTimeRole::MftModified => vec![
            "ntfs_standard_mft_record_modification_time_utc",
            "standard_information_mft_modified_utc",
            "mft_modified_utc",
            "ntfs_mft_record_modification_time_utc",
            "file_name_mft_modified_utc",
        ],
    };
    activity_value_string(item_ref, &keys)
}

/// Resolve one MACB role across all authoritative top-level and nested
/// candidates, then emit exactly one row. Absence is reported only after the
/// complete candidate set has been checked.
fn push_time_detail(
    html: &mut String,
    item_ref: &serde_json::Value,
    label: &str,
    role: ForensicTimeRole,
) {
    html.push_str("<dt>");
    html.push_str(&escape_html(label));
    html.push_str("</dt><dd>");
    match resolved_forensic_time(item_ref, role) {
        Some(value) => html.push_str(&escape_html(&value)),
        None => html.push_str(
            "<span class=\"meta\">Not set on source filesystem (verified absent, not unchecked)</span>",
        ),
    }
    html.push_str("</dd>");
}

fn activity_value_string(item_ref: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = item_ref.get(*key).and_then(json_report_value) {
            return Some(value);
        }
        if let Some(value) = item_ref
            .get("metadata")
            .and_then(|metadata| metadata.get(*key))
            .and_then(json_report_value)
        {
            return Some(value);
        }
    }
    None
}

fn activity_u64(item_ref: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(value) = item_ref.get(*key).and_then(json_report_u64) {
            return Some(value);
        }
        if let Some(value) = item_ref
            .get("metadata")
            .and_then(|metadata| metadata.get(*key))
            .and_then(json_report_u64)
        {
            return Some(value);
        }
    }
    None
}

fn json_report_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(value) => value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|signed| u64::try_from(signed).ok())),
        serde_json::Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

fn json_report_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(value) => {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        serde_json::Value::Array(values) => {
            let parts = values
                .iter()
                .filter_map(json_report_value)
                .collect::<Vec<_>>();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(", "))
            }
        }
        serde_json::Value::Object(_) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[derive(Clone, Copy)]
enum BrowserDisplayTimeRole {
    Created,
    Accessed,
    Modified,
}

fn report_display_time_keys(
    _metadata: &serde_json::Value,
    role: BrowserDisplayTimeRole,
) -> Vec<&'static str> {
    generic_display_time_keys(role).to_vec()
}

fn generic_display_time_keys(role: BrowserDisplayTimeRole) -> &'static [&'static str] {
    match role {
        BrowserDisplayTimeRole::Created => &[
            "created_utc",
            "ntfs_standard_creation_time_utc",
            "standard_information_created_utc",
            "ntfs_creation_time_utc",
            "file_name_created_utc",
            "creation_utc",
            "fat_created",
        ],
        BrowserDisplayTimeRole::Accessed => &[
            "accessed_utc",
            "ntfs_standard_access_time_utc",
            "standard_information_accessed_utc",
            "ntfs_access_time_utc",
            "file_name_accessed_utc",
            "fat_accessed",
        ],
        BrowserDisplayTimeRole::Modified => &[
            "modified_utc",
            "ntfs_standard_modification_time_utc",
            "standard_information_modified_utc",
            "ntfs_modification_time_utc",
            "file_name_modified_utc",
            "fat_modified",
        ],
    }
}

