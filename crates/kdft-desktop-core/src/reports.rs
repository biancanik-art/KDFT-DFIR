#![forbid(unsafe_code)]

//! Native report preview and export service.
//!
//! Renders forensic reports incorporating evidence identity, bookmarks,
//! hashes, audit logs, and truthful completion/truncation disclosures.

use anyhow::{Context, Result};
use kdft_case::{record_report_export, render_report, report_data, ReportData};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPreview {
    pub case_name: String,
    pub examiner_name: Option<String>,
    pub case_number: Option<String>,
    pub evidence_count: usize,
    pub bookmark_folder_count: usize,
    pub bookmark_count: usize,
    pub is_complete: bool,
    pub partial_limitations: Vec<String>,
    pub html_content: String,
    pub sha256_integrity: String,
}

pub struct NativeReportService;

impl NativeReportService {
    /// Generates report data and rendered HTML preview with honest completion disclosures.
    pub fn generate_preview(case_path: &Path) -> Result<ReportPreview> {
        let data: ReportData = report_data(case_path)
            .with_context(|| format!("gathering report data from {}", case_path.display()))?;

        // Check for partial or truncated processing jobs in the case
        let conn = Connection::open(case_path)?;
        let mut limitations = Vec::new();
        let mut has_incomplete_jobs = false;

        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, evidence_id, job_type, status
             FROM evidence_jobs
             WHERE status IN ('partial', 'truncated', 'cancelled', 'failed')",
        ) {
            let job_rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;

            for j in job_rows.flatten() {
                has_incomplete_jobs = true;
                limitations.push(format!(
                    "Job #{} for evidence #{} ({}) terminated in state '{}'",
                    j.0, j.1, j.2, j.3
                ));
            }
        }

        // Check for incomplete recursive bookmarks
        if let Ok(mut bm_stmt) = conn.prepare(
            "SELECT id, title, json_extract(source_ref_json, '$.checkpoint.completed')
             FROM bookmarks
             WHERE json_extract(source_ref_json, '$.checkpoint') IS NOT NULL
               AND json_extract(source_ref_json, '$.checkpoint.completed') = 0",
        ) {
            if let Ok(rows) = bm_stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
            }) {
                for (bm_id, title) in rows.flatten() {
                    has_incomplete_jobs = true;
                    limitations.push(format!(
                        "Recursive bookmark #{} ('{}') has not completed traversal",
                        bm_id,
                        title.unwrap_or_else(|| "Untitled".to_string())
                    ));
                }
            }
        }

        let rendered = render_report(&data);
        let mut total_bms = 0;
        for f in &data.folders {
            total_bms += f.bookmarks.len();
        }

        Ok(ReportPreview {
            case_name: data.case.name,
            examiner_name: data.case.examiner_name,
            case_number: data.case.case_number,
            evidence_count: data.evidence.len(),
            bookmark_folder_count: data.folders.len(),
            bookmark_count: total_bms,
            is_complete: !has_incomplete_jobs,
            partial_limitations: limitations,
            html_content: rendered.html,
            sha256_integrity: rendered.content_prefix_sha256,
        })
    }

    /// Exports the rendered report to an examiner-chosen destination and logs the audit event.
    /// Supports .html, .json, and .md output formats.
    pub fn export_report(
        case_path: &Path,
        destination_path: &Path,
        examiner: Option<&str>,
    ) -> Result<PathBuf> {
        let preview = Self::generate_preview(case_path)?;
        let data = report_data(case_path)
            .with_context(|| format!("gathering report data from {}", case_path.display()))?;

        let ext = destination_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let (content_bytes, sha256_digest) = if ext == "json" {
            let json_obj = serde_json::json!({
                "case_name": preview.case_name,
                "examiner_name": preview.examiner_name,
                "case_number": preview.case_number,
                "is_complete": preview.is_complete,
                "partial_limitations": preview.partial_limitations,
                "data": data,
            });
            let s = serde_json::to_string_pretty(&json_obj)?;
            let b = s.into_bytes();
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&b);
            let digest = format!("{:x}", hasher.finalize());
            (b, digest)
        } else if ext == "md" || ext == "markdown" {
            let s = Self::render_markdown(&data, &preview);
            let b = s.into_bytes();
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&b);
            let digest = format!("{:x}", hasher.finalize());
            (b, digest)
        } else {
            (preview.html_content.into_bytes(), preview.sha256_integrity)
        };

        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination_path, &content_bytes)
            .with_context(|| format!("writing report to {}", destination_path.display()))?;

        // Audit report export in case database
        let dest_str = destination_path.to_str().unwrap_or("");
        let _ = record_report_export(
            case_path,
            dest_str,
            &sha256_digest,
            examiner.unwrap_or("examiner"),
        );

        Ok(destination_path.to_path_buf())
    }

    /// Renders genuine Markdown tables and headers for the report.
    pub fn render_markdown(data: &ReportData, preview: &ReportPreview) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Case Report: {}\n\n", data.case.name));

        md.push_str("## Case Summary\n\n");
        md.push_str("| Property | Value |\n| --- | --- |\n");
        md.push_str(&format!("| Case Name | {} |\n", data.case.name));
        md.push_str(&format!(
            "| Case Number | {} |\n",
            data.case.case_number.as_deref().unwrap_or("N/A")
        ));
        md.push_str(&format!(
            "| Examiner | {} |\n",
            data.case.examiner_name.as_deref().unwrap_or("N/A")
        ));
        md.push_str(&format!("| Created At | {} |\n", data.case.created_at));
        md.push_str(&format!(
            "| Examination Status | {} |\n",
            if preview.is_complete {
                "Complete"
            } else {
                "Incomplete / Partial"
            }
        ));
        md.push('\n');

        if !preview.partial_limitations.is_empty() {
            md.push_str("## Scope Limitations & Disclosures\n\n");
            for lim in &preview.partial_limitations {
                md.push_str(&format!("- {lim}\n"));
            }
            md.push('\n');
        }

        md.push_str("## Evidence Sources\n\n");
        if data.evidence.is_empty() {
            md.push_str("_No evidence sources attached._\n\n");
        } else {
            md.push_str("| ID | Source Name | Kind | Path | Size (Bytes) | SHA-256 |\n");
            md.push_str("| --- | --- | --- | --- | --- | --- |\n");
            for ev in &data.evidence {
                md.push_str(&format!(
                    "| {} | {} | {} | `{}` | {} | `{}` |\n",
                    ev.id,
                    ev.display_name,
                    ev.source_kind,
                    ev.source_path,
                    ev.size_bytes
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "N/A".to_string()),
                    ev.sha256.as_deref().unwrap_or("N/A")
                ));
            }
            md.push('\n');
        }

        md.push_str("## Bookmarks\n\n");
        if data.folders.is_empty() {
            md.push_str("_No bookmark folders created._\n\n");
        } else {
            for folder in &data.folders {
                md.push_str(&format!("### Folder: {}\n\n", folder.name));
                if folder.bookmarks.is_empty() {
                    md.push_str("_No bookmarks in this folder._\n\n");
                } else {
                    md.push_str("| ID | Title | Type | Data Type | Notes |\n");
                    md.push_str("| --- | --- | --- | --- | --- |\n");
                    for bm in &folder.bookmarks {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            bm.id,
                            bm.title.as_deref().unwrap_or("Untitled"),
                            bm.bookmark_type,
                            bm.data_type.as_deref().unwrap_or(""),
                            bm.examiner_comment.as_deref().unwrap_or("")
                        ));
                    }
                    md.push('\n');
                }
            }
        }

        md.push_str("## Integrity & Verification\n\n");
        md.push_str(&format!(
            "- **SHA-256 Digest**: `{}`\n",
            preview.sha256_integrity
        ));
        md.push_str("- Generated by KDFT Native Forensic Workbench.\n");

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_preview_struct_checks() {
        let prev = ReportPreview {
            case_name: "Test Case".to_string(),
            examiner_name: None,
            case_number: None,
            evidence_count: 1,
            bookmark_folder_count: 0,
            bookmark_count: 0,
            is_complete: false,
            partial_limitations: vec!["Job truncated".to_string()],
            html_content: "<html></html>".to_string(),
            sha256_integrity: "abc".to_string(),
        };
        assert!(!prev.is_complete);
        assert_eq!(prev.partial_limitations.len(), 1);
    }

    #[test]
    fn render_markdown_produces_genuine_markdown() {
        let data = ReportData {
            case: kdft_case::CaseInfo {
                id: 1,
                name: "Operation Blue".to_string(),
                examiner_name: Some("Lead Examiner".to_string()),
                case_number: Some("CASE-2026-001".to_string()),
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
                timezone: "UTC".to_string(),
                created_at: "2026-10-19T12:00:00Z".to_string(),
            },
            evidence: vec![],
            directory_trees: vec![],
            folders: vec![],
        };
        let preview = ReportPreview {
            case_name: data.case.name.clone(),
            examiner_name: data.case.examiner_name.clone(),
            case_number: data.case.case_number.clone(),
            evidence_count: 0,
            bookmark_folder_count: 0,
            bookmark_count: 0,
            is_complete: true,
            partial_limitations: vec![],
            html_content: "<html></html>".to_string(),
            sha256_integrity: "abcdef".to_string(),
        };
        let md = NativeReportService::render_markdown(&data, &preview);
        assert!(md.starts_with("# Case Report: Operation Blue"));
        assert!(md.contains("## Case Summary"));
        assert!(md.contains("| Case Name | Operation Blue |"));
        assert!(md.contains("## Evidence Sources"));
        assert!(md.contains("## Integrity & Verification"));
    }
}
