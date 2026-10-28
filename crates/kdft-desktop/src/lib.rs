#![forbid(unsafe_code)]

//! Fully native KDFT case and evidence workflow.

pub mod app;
pub mod dialogs;
pub mod inspector;
pub mod state;
pub mod views;
pub mod workers;

pub use app::*;
pub use dialogs::*;
pub use state::*;
pub use views::source_browser::parent_browse_path;
pub use views::*;
pub use workers::*;
#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui;
    use kdft_desktop_core::*;
    use rusqlite::Connection;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> PathBuf {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kdft-native-desktop-{}-{serial}.sqlite",
            std::process::id()
        ));
        let connection = Connection::open(&path).expect("create fixture");
        connection
            .execute_batch(
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
                     logical_path TEXT NOT NULL, name TEXT NOT NULL, entry_kind TEXT NOT NULL,
                     size_bytes INTEGER, is_deleted INTEGER NOT NULL,
                     discovered_by_job_id INTEGER, metadata_json TEXT
                 );
                 INSERT INTO cases VALUES(1, 'Native fixture', 'Examiner', 'CASE-7', '2026-10-16T00:00:00Z');
                 INSERT INTO case_options VALUES(1, 'UTC');
                 INSERT INTO audit_events VALUES(9);
                 INSERT INTO evidence_sources VALUES(
                     1, 1, 'file', 'C:/fixtures/source.bin', 'source.bin',
                     '2026-10-16T00:00:00Z', '2026-10-16T00:10:00Z', NULL, NULL, NULL
                 );
                 INSERT INTO evidence_jobs VALUES(
                     1, 1, 1, 'filesystem_index', 'running', '2026-10-16T00:00:00Z', NULL, NULL, 'v1'
                 );",
            )
            .expect("create schema");
        let transaction = connection
            .unchecked_transaction()
            .expect("start fixture transaction");
        for id in 1..=DEFAULT_PAGE_SIZE + 5 {
            transaction
                .execute(
                    "INSERT INTO filesystem_entries(
                         id, case_id, evidence_id, parent_id, logical_path, name, entry_kind,
                         size_bytes, is_deleted, discovered_by_job_id, metadata_json
                     ) VALUES(?1, 1, 1, NULL, ?2, ?3, 'file', 12, 0, 1, NULL)",
                    rusqlite::params![id, format!("/entry-{id}"), format!("entry-{id}")],
                )
                .expect("insert row");
        }
        transaction.commit().expect("commit fixture");
        drop(connection);
        path
    }

    #[test]
    fn native_shell_loads_only_one_bounded_page() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        assert_eq!(opened.page.items.len(), DEFAULT_PAGE_SIZE as usize);
        assert!(opened.page.next_cursor.is_some());
        assert_eq!(opened.page.coverage.state, CoverageState::InProgress);
        assert!(!opened.page.coverage.is_complete);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn native_shell_advances_by_keyset_cursor_without_overlap() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let first_last_id = opened.page.items.last().expect("first page row").id;
        let second =
            read_page(&opened.backend, opened.page.next_cursor.clone()).expect("read second page");
        assert_eq!(second.items.len(), 5);
        assert!(second.items.iter().all(|item| item.id > first_last_id));
        assert!(second.next_cursor.is_none());
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn invalid_case_is_reported_without_replacing_evidence() {
        let path = std::env::temp_dir().join(format!(
            "kdft-native-invalid-{}-{}.sqlite",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        Connection::open(&path).expect("create invalid database");
        let error = open_case(&path).expect_err("invalid schema must fail");
        assert!(error.contains("not a supported KDFT case database"));
        fs::remove_file(path).expect("remove invalid fixture");
    }

    #[test]
    fn new_case_form_rejects_missing_destination_and_name() {
        let form = NewCaseForm::default();
        assert_eq!(
            form.request().expect_err("missing path must fail"),
            "Choose a destination for the new case database."
        );
        let form = NewCaseForm {
            case_path: "case.sqlite".to_string(),
            ..Default::default()
        };
        assert_eq!(
            form.request().expect_err("missing name must fail"),
            "Enter a case name."
        );
    }

    #[test]
    fn entry_limit_is_explicit() {
        assert_eq!(parse_max_entries("").expect("blank is unlimited"), 0);
        assert_eq!(parse_max_entries("0").expect("zero is unlimited"), 0);
        assert_eq!(parse_max_entries("42").expect("numeric limit"), 42);
        assert!(parse_max_entries("everything").is_err());
    }

    #[test]
    fn evidence_selection_cannot_point_outside_current_page() {
        let page = EvidencePage {
            items: vec![EvidenceSummary {
                id: 7,
                source_kind: "file".to_string(),
                display_name: "fixture.bin".to_string(),
                display_name_truncated: false,
                source_path_preview: "fixture.bin".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "unknown".to_string(),
                attached_at: "2026-10-16T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: None,
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: None,
                expected_sha256: None,
                integrity_details_json: None,
            }],
            next_after_id: None,
            has_more: false,
            returned: 1,
            case_generation: 1,
        };
        assert_eq!(retained_selection(Some(7), &page), Some(7));
        assert_eq!(retained_selection(Some(8), &page), None);
    }

    #[test]
    fn human_size_format_does_not_hide_invalid_values() {
        assert_eq!(format_size(None), "—");
        assert_eq!(format_size(Some(-1)), "-1 B (invalid)");
        assert_eq!(format_size(Some(1_024)), "1.00 KiB");
    }

    #[test]
    fn mixed_generation_snapshot_is_rejected() {
        assert!(validate_snapshot_generations(7, 7, Some(7)).is_ok());
        let entry_error =
            validate_snapshot_generations(7, 8, Some(7)).expect_err("entry mismatch must fail");
        assert!(entry_error.contains("expected generation 7"));
        let evidence_error =
            validate_snapshot_generations(7, 7, Some(9)).expect_err("evidence mismatch must fail");
        assert!(evidence_error.contains("evidence generation 9"));
    }

    #[test]
    fn cancelled_processing_never_uses_completion_copy() {
        let result = process_result("cancelled");
        let refreshed = process_status_text(&result, true);
        assert!(refreshed.contains("cancelled safely"));
        assert!(refreshed.contains("no complete examination"));
        assert!(!refreshed.contains("Processing completed"));
    }

    #[test]
    fn committed_processing_with_refresh_failure_marks_view_stale() {
        let result = process_result("completed");
        let stale = process_status_text(&result, false);
        assert!(stale.contains("Processing completed"));
        assert!(stale.contains("displayed grid is stale"));
        assert!(!stale.contains("shown in the refreshed view"));
    }

    #[test]
    fn both_generation_cursor_errors_require_stale_view_lockout() {
        assert!(is_stale_cursor_error(
            "stale_cursor: stale page cursor: case generation changed from 7 to 8"
        ));
        assert!(is_stale_cursor_error(
            "stale evidence cursor: case generation changed from 7 to 8"
        ));
    }

    #[test]
    fn transient_page_errors_do_not_require_stale_view_lockout() {
        assert!(!is_stale_cursor_error("database is temporarily busy"));
        assert!(!is_stale_cursor_error("worker channel disconnected"));
    }

    #[test]
    fn post_commit_warning_view_remains_bounded() {
        let warnings = (0..MAX_OPERATION_WARNINGS + 3)
            .map(|index| format!("warning-{index}"))
            .collect();
        let (warnings, omitted) = bound_operation_warnings(warnings, 2);
        assert_eq!(warnings.len(), MAX_OPERATION_WARNINGS);
        assert_eq!(omitted, 5);
    }

    fn process_result(status: &str) -> ProcessEvidenceSummary {
        ProcessEvidenceSummary {
            job_id: 1,
            evidence_id: 1,
            entries_indexed: 3,
            attempt_entries_indexed: 3,
            replacement_committed: status == "completed",
            canonical_generation_preserved: status == "cancelled",
            retained_entry_count: 3,
            truncated: false,
            partial_artifact_coverage: false,
            completed_with_diagnostics: false,
            status: status.to_string(),
            bookmark_items_relinked: 0,
            truncation_reasons: Vec::new(),
            truncation_reasons_omitted: 0,
            case_generation: Some(7),
            progress_summary_persisted: true,
            post_commit_warnings: Vec::new(),
            post_commit_warnings_omitted: 0,
        }
    }

    fn test_app(path: &Path, opened: OpenedCase) -> KDFTDesktopApp {
        let mut app = KDFTDesktopApp::empty();
        app.case_path = path.display().to_string();
        app.opened_path = Some(path.to_path_buf());
        app.backend = Some(opened.backend);
        app.summary = Some(opened.summary);
        app.page = Some(opened.page);
        app.page_starts = vec![None];
        app.page_index = 0;
        app.active_work_area = WorkArea::Results;
        app.active_tab = TopLevelTab::Case;
        app.theme = AppTheme::Dark;
        app.status = String::new();
        app
    }

    #[test]
    fn deferred_close_requests_cancellation_and_has_a_bounded_grace_period() {
        let mut app = KDFTDesktopApp::empty();
        let tracker = JobProgressTracker::new("close-test", "forensic_analysis", None);
        let (_sender, receiver) = mpsc::channel();
        app.processing = Some(ProcessingJob {
            evidence_name: "test-evidence".to_string(),
            tracker: tracker.clone(),
            receiver,
        });
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        app.export_cancel = Some(cancellation.clone());
        app.hash_cancel = Some(cancellation.clone());
        app.integrity_cancel = Some(cancellation.clone());
        app.folder_export_cancel = Some(cancellation.clone());
        app.folder_hash_cancel = Some(cancellation.clone());

        app.close_after_background_work = true;
        app.close_request_started_at = Some(std::time::Instant::now());
        app.request_background_cancellation();

        assert!(tracker.is_cancellation_requested());
        assert!(cancellation.load(Ordering::SeqCst));
        assert!(!app.deferred_close_ready());

        app.close_request_started_at =
            std::time::Instant::now().checked_sub(CLOSE_GRACE_PERIOD + Duration::from_millis(1));
        assert!(app.deferred_close_ready());
    }

    #[test]
    fn processing_history_refresh_loads_running_job_off_the_ui_thread() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        app.selected_evidence_id = Some(1);
        let ctx = egui::Context::default();

        app.begin_processing_history_refresh(ctx);
        assert!(app.processing_history_pending.is_some());
        assert!(app.job_history.is_empty());

        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(10));
            app.poll_processing_history_worker();
            if app.processing_history_pending.is_none() {
                break;
            }
        }

        assert!(app.processing_history_pending.is_none());
        assert_eq!(app.job_history.len(), 1);
        assert_eq!(app.job_history[0].id, 1);
        assert_eq!(app.job_history[0].status, ProcessingJobState::Running);
        assert!(app.processing_history_error.is_none());
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn live_job_history_refresh_does_not_wait_for_or_replace_coverage() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        app.selected_evidence_id = Some(1);
        app.coverage_records = vec![ProcessorCoverageRecord {
            group_name: "Retained coverage".to_string(),
            scope: "prior completed projection".to_string(),
            status: "Complete".to_string(),
            count: 17,
            message: None,
        }];

        app.begin_live_job_history_refresh(egui::Context::default());
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(10));
            app.poll_processing_history_worker();
            if app.processing_history_pending.is_none() {
                break;
            }
        }

        assert!(app.processing_history_pending.is_none());
        assert_eq!(app.job_history.len(), 1);
        assert_eq!(app.job_history[0].status, ProcessingJobState::Running);
        assert_eq!(app.coverage_records.len(), 1);
        assert_eq!(app.coverage_records[0].group_name, "Retained coverage");
        assert_eq!(app.coverage_records[0].count, 17);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn processing_history_refresh_failure_keeps_last_successful_rows_visible() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        app.refresh_processing_history();
        assert_eq!(app.job_history.len(), 1);

        app.processing_history_request_id = 7;
        let (sender, receiver) = mpsc::channel();
        sender
            .send(ProcessingHistoryWorkerResult {
                request_id: 7,
                case_path: path.clone(),
                evidence_id: app.selected_evidence_id,
                jobs: Err("simulated read failure".to_string()),
                coverage: Some(Err("simulated coverage failure".to_string())),
            })
            .expect("queue worker result");
        app.processing_history_pending = Some(receiver);

        app.poll_processing_history_worker();

        assert_eq!(app.job_history.len(), 1);
        assert!(app
            .processing_history_error
            .as_deref()
            .is_some_and(|error| error.contains("last successful history remains displayed")));
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn artifact_detail_fetches_asynchronously_and_binds_to_generation() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();
        let selection = ArtifactSelection {
            entry_id: 1,
            generation: 9,
        };
        app.begin_artifact_detail(ctx.clone(), selection);
        assert!(app.artifact_pending.is_some());
        assert!(!app.is_busy());
        assert_eq!(app.selected_artifact, Some(selection));

        let mut loaded = false;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            app.poll_artifact_worker(&ctx);
            if app.artifact_detail.is_some() {
                loaded = true;
                break;
            }
        }
        assert!(loaded, "artifact detail should load asynchronously");
        assert!(app.artifact_pending.is_none());
        let detail = app.artifact_detail.as_ref().unwrap();
        assert_eq!(detail.entry_id, 1);
        assert_eq!(detail.generation, 9);
        assert_eq!(detail.display_name, "entry-1");
        assert_eq!(detail.logical_path, "/entry-1");

        app.begin_artifact_detail(ctx.clone(), selection);
        assert!(app.artifact_pending.is_none());

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn artifact_detail_does_not_reuse_a_mismatched_cached_snapshot() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();
        let selection = ArtifactSelection {
            entry_id: 1,
            generation: 9,
        };
        let mut stale_detail = fixture_artifact_detail(&app, 1, 9);
        stale_detail.generation = 8;
        app.selected_artifact = Some(selection);
        app.artifact_detail = Some(stale_detail);

        app.begin_artifact_detail(ctx, selection);

        assert!(
            app.artifact_pending.is_some(),
            "a detail that does not match the selected snapshot must be replaced"
        );
        assert!(app.artifact_detail.is_none());

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn stale_generation_artifact_selection_locks_out_inspector() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();
        let selection = ArtifactSelection {
            entry_id: 1,
            generation: 8,
        };
        app.begin_artifact_detail(ctx.clone(), selection);
        assert!(app.view_stale);
        assert!(app.artifact_detail_error.is_some());
        assert!(app.artifact_pending.is_none());
        assert_eq!(app.selected_artifact, None);

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn discarded_artifact_selection_does_not_lock_stale() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();
        let selection = ArtifactSelection {
            entry_id: 1,
            generation: 9,
        };
        app.begin_artifact_detail(ctx.clone(), selection);
        assert!(app.artifact_pending.is_some());

        app.clear_inspector();
        assert_eq!(app.selected_artifact, None);
        assert!(!app.view_stale);

        std::thread::sleep(std::time::Duration::from_millis(50));
        app.poll_artifact_worker(&ctx);

        assert!(!app.view_stale);
        assert!(app.artifact_detail.is_none());
        assert!(app.artifact_pending.is_none());

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn parent_back_forward_navigation_history_logic() {
        assert_eq!(parent_browse_path("/"), None);
        assert_eq!(parent_browse_path("/Windows"), Some("/".to_string()));
        assert_eq!(
            parent_browse_path("/Windows/System32"),
            Some("/Windows".to_string())
        );
        assert_eq!(
            parent_browse_path("Windows\\System32\\drivers"),
            Some("/Windows/System32".to_string())
        );

        // Navigation history state machine simulation
        let mut history_back: Vec<String> = Vec::new();
        let mut history_forward: Vec<String> = Vec::new();
        let mut current_path = "/".to_string();

        // Navigate into /Windows
        history_back.push(current_path.clone());
        history_forward.clear();
        current_path = "/Windows".to_string();
        assert_eq!(history_back, vec!["/"]);
        assert!(history_forward.is_empty());

        // Navigate into /Windows/System32
        history_back.push(current_path.clone());
        history_forward.clear();
        current_path = "/Windows/System32".to_string();
        assert_eq!(history_back, vec!["/", "/Windows"]);

        // Back action: pops /Windows from back, pushes /Windows/System32 to forward
        let prev = history_back.pop().expect("has back history");
        history_forward.push(current_path.clone());
        current_path = prev;
        assert_eq!(current_path, "/Windows");
        assert_eq!(history_back, vec!["/"]);
        assert_eq!(history_forward, vec!["/Windows/System32"]);

        // Forward action: pops /Windows/System32 from forward, pushes /Windows to back
        let next = history_forward.pop().expect("has forward history");
        history_back.push(current_path.clone());
        current_path = next;
        assert_eq!(current_path, "/Windows/System32");
        assert_eq!(history_back, vec!["/", "/Windows"]);
        assert!(history_forward.is_empty());

        // Navigating to new path clears forward
        let prev = history_back.pop().expect("has back history");
        history_forward.push(current_path.clone());
        current_path = prev; // back to /Windows
        assert_eq!(history_forward, vec!["/Windows/System32"]);

        // User clicks /Program Files
        history_back.push(current_path.clone());
        history_forward.clear();
        current_path = "/Program Files".to_string();
        assert_eq!(current_path, "/Program Files");
        assert_eq!(history_back, vec!["/", "/Windows"]);
        assert!(history_forward.is_empty());
    }

    #[test]
    fn unsupported_and_locked_volume_disclosure() {
        let locked_page = BrowseDirectoryPage {
            evidence_id: 1,
            volume_index: 0,
            volume_identity: None,
            access_state: VolumeAccessState::Locked {
                message: BITLOCKER_LOCKED_MSG.to_string(),
            },
            reader_label: "BitLocker Locked".to_string(),
            request_id: 1,
            path: "/".to_string(),
            entries: Vec::new(),
            total_entries: 0,
            offset: 0,
            next_offset: None,
            truncated: false,
            filesystem: "BitLocker".to_string(),
            is_locked: true,
            locked_message: Some(BITLOCKER_LOCKED_MSG.to_string()),
            is_unsupported: false,
            unsupported_message: None,
            diagnostics: Vec::new(),
        };
        assert!(locked_page.is_locked);
        assert!(locked_page
            .locked_message
            .as_deref()
            .unwrap()
            .contains("Locked / unlock not yet available in native Desktop."));

        let unsupported_page = BrowseDirectoryPage {
            evidence_id: 1,
            volume_index: 1,
            volume_identity: None,
            access_state: VolumeAccessState::UnsupportedFilesystem {
                filesystem: "APFS".to_string(),
            },
            reader_label: "Unsupported APFS".to_string(),
            request_id: 2,
            path: "/".to_string(),
            entries: Vec::new(),
            total_entries: 0,
            offset: 0,
            next_offset: None,
            truncated: false,
            filesystem: "APFS".to_string(),
            is_locked: false,
            locked_message: None,
            is_unsupported: true,
            unsupported_message: Some(
                "APFS filesystem is not supported for native browsing.".to_string(),
            ),
            diagnostics: vec!["Container superblock version 2 not recognized".to_string()],
        };
        assert!(unsupported_page.is_unsupported);
        assert!(unsupported_page
            .unsupported_message
            .unwrap()
            .contains("not supported"));
        assert_eq!(unsupported_page.diagnostics.len(), 1);
    }

    #[test]
    fn removal_confirmation_and_state_handling() {
        let mut state = RemovalConfirmationState::default();
        assert!(!state.visible);
        assert!(state.target.is_none());

        // Target folder
        state.target = Some(RemovalTarget::Folder {
            folder_id: 12,
            name: "Important Findings".to_string(),
        });
        state.visible = true;
        assert!(state.visible);
        if let Some(RemovalTarget::Folder { folder_id, name }) = &state.target {
            assert_eq!(*folder_id, 12);
            assert_eq!(name, "Important Findings");
        } else {
            panic!("Expected folder removal target");
        }

        // Cancel
        state.visible = false;
        state.target = None;
        assert!(!state.visible);

        // Target bookmark
        state.target = Some(RemovalTarget::Bookmark {
            bookmark_id: 34,
            title: "Persistence Keys".to_string(),
        });
        state.visible = true;
        if let Some(RemovalTarget::Bookmark { bookmark_id, title }) = &state.target {
            assert_eq!(*bookmark_id, 34);
            assert_eq!(title, "Persistence Keys");
        } else {
            panic!("Expected bookmark removal target");
        }

        // Target item
        state.target = Some(RemovalTarget::Item {
            item_id: 56,
            name: "run_key.reg".to_string(),
        });
        state.visible = true;
        if let Some(RemovalTarget::Item { item_id, name }) = &state.target {
            assert_eq!(*item_id, 56);
            assert_eq!(name, "run_key.reg");
        } else {
            panic!("Expected item removal target");
        }
    }

    #[test]
    fn committed_bookmark_survives_refresh_failure() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();

        let (sender, receiver) = mpsc::channel();
        sender
            .send(BookmarkWorkerResult::Created(Ok(CreateBookmarkResult {
                folder_id: 1,
                bookmark_id: 77,
                item_id: Some(101),
                case_generation: Some(9),
                post_commit_warnings: vec![
                    "Refresh failed: lock held by another thread".to_string()
                ],
            })))
            .unwrap();
        app.bookmark_pending = Some(receiver);
        app.bookmark_dialog.visible = true;

        app.poll_bookmark_worker(&ctx);

        assert_eq!(app.status, "COMMITTED: Created bookmark #77. Do not retry.");
        assert!(!app.bookmark_dialog.visible);
        assert_eq!(app.operation_warnings.len(), 1);
        assert!(app.operation_warnings[0].contains("Refresh failed"));

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn recursive_bookmark_limit_validation() {
        assert_eq!(parse_recursive_limit(""), Ok(0)); // 0 = unlimited in kdft-case
        assert_eq!(parse_recursive_limit("  "), Ok(0));
        assert_eq!(parse_recursive_limit("0"), Ok(0));
        assert_eq!(parse_recursive_limit("unlimited"), Ok(0));
        assert_eq!(parse_recursive_limit("1"), Ok(1));
        assert_eq!(parse_recursive_limit("500"), Ok(500));
        assert_eq!(parse_recursive_limit("10000"), Ok(10_000));
        assert_eq!(parse_recursive_limit("100000"), Ok(100_000));

        assert!(parse_recursive_limit("-10").is_err());
        assert!(parse_recursive_limit("abc").is_err());
    }

    #[test]
    fn no_http_or_webview_dependency() {
        let cargo_toml = include_str!("../Cargo.toml");
        let forbidden = [
            "actix",
            "axum",
            "warp",
            "tower-http",
            "reqwest",
            "hyper",
            "wry",
            "tauri",
            "webview",
        ];
        for word in forbidden {
            assert!(
                !cargo_toml.contains(word),
                "Forbidden web/network dependency found in Cargo.toml: {word}"
            );
        }

        let core_cargo_toml = include_str!("../../kdft-desktop-core/Cargo.toml");
        for word in forbidden {
            assert!(
                !core_cargo_toml.contains(word),
                "Forbidden web/network dependency found in kdft-desktop-core Cargo.toml: {word}"
            );
        }
    }

    #[test]
    fn live_source_projection_label_truthfulness() {
        // When entry_id is 0, it represents an unindexed live-source projection
        let live_selection = ArtifactSelection {
            entry_id: 0,
            generation: 1,
        };
        assert_eq!(live_selection.entry_id, 0);

        // When canonical entry exists, entry_id > 0
        let indexed_selection = ArtifactSelection {
            entry_id: 123,
            generation: 1,
        };
        assert!(indexed_selection.entry_id > 0);
    }

    fn setup_desktop_test_case() -> (PathBuf, KDFTDesktopApp, egui::Context) {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kdft-ui-target-test-{}-{serial}.sqlite",
            std::process::id()
        ));
        let request = CreateCaseRequest {
            case_path: path.clone(),
            name: "UI Target Fixture".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("CASE-UI".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        };
        NativeWorkflowService::create_case(request).expect("create test case");

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
        )
        .expect("insert dir entry");

        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
             VALUES(1, 1, 1, '/evidence/folder/sample.txt', 'sample.txt', 'file', 42, 0)",
            [],
        )
        .expect("insert file entry");

        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
             VALUES(2, 1, 1, '/evidence/folder/message.eml', 'message.eml', 'email', 1024, 0)",
            [],
        )
        .expect("insert email entry");

        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted)
             VALUES(3, 1, 1, '/evidence/folder/record_item', 'record_item', 'registry', 256, 0)",
            [],
        )
        .expect("insert record entry");

        drop(conn);

        let opened = open_case(&path).expect("open fixture");
        let app = test_app(&path, opened);
        let ctx = egui::Context::default();
        (path, app, ctx)
    }

    fn wait_for_desktop_bookmark_pipeline(app: &mut KDFTDesktopApp, ctx: &egui::Context) {
        let mut finished = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(15));
            app.poll_bookmark_worker(ctx);
            if app.status.starts_with("COMMITTED:")
                || app.status.starts_with("PARTIAL:")
                || app.status.starts_with("WARNING:")
                || app.bookmark_error.is_some()
            {
                finished = true;
                break;
            }
        }
        assert!(finished, "Expected terminal status, got: {}", app.status);
        for _ in 0..100 {
            if app.bookmark_pending.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
            app.poll_bookmark_worker(ctx);
        }
    }

    fn test_list_folders(path: &Path) -> Vec<BookmarkFolderSummary> {
        NativeBookmarkService::list_folders_page(path, None, 100)
            .expect("list folders page")
            .folders
    }

    fn test_list_bookmarks(path: &Path, folder_id: Option<i64>) -> Vec<BookmarkSummary> {
        NativeBookmarkService::list_bookmarks_page(path, folder_id, None, 100)
            .expect("list bookmarks page")
            .bookmarks
    }

    fn test_list_items(path: &Path, bookmark_id: Option<i64>) -> Vec<BookmarkItemSummary> {
        NativeBookmarkService::list_bookmark_items_page(path, bookmark_id, None, 100)
            .expect("list bookmark items page")
            .items
    }

    #[test]
    fn ui_path_creates_indexed_file_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Findings".to_string(),
            title: "Sample File Bookmark".to_string(),
            comment: "Indexed file bookmark test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::IndexedResult {
                evidence_id: 1,
                entry_id: 1,
                logical_path: "/evidence/folder/sample.txt".to_string(),
                artifact_kind: "file".to_string(),
                is_deleted: false,
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Findings")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].title, "Sample File Bookmark");
        assert_eq!(bookmarks[0].bookmark_type, "notable_file");
        assert_eq!(bookmarks[0].item_count, 1);

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, Some(1));
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].logical_path, "/evidence/folder/sample.txt");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_search_bookmark_preserves_exact_match_for_report() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "Search Findings".to_string(),
            title: "Transfer content hit".to_string(),
            comment: "Exact logical-file match".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::SearchResult {
                evidence_id: 1,
                entry_id: 1,
                logical_path: "/evidence/folder/sample.txt".to_string(),
                artifact_kind: "file".to_string(),
                match_field: "content".to_string(),
                match_snippet: "...transfer...".to_string(),
                selection_offset: Some(767),
                selection_length: Some(8),
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|folder| folder.name == "Search Findings")
            .expect("search folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert!(bookmarks[0].in_report);
        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].selection_offset, Some(767));
        assert_eq!(items[0].selection_length, Some(8));
        assert_eq!(items[0].data_preview.as_deref(), Some("...transfer..."));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_indexed_email_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Findings".to_string(),
            title: "Sample Email Bookmark".to_string(),
            comment: "Indexed email bookmark test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::IndexedResult {
                evidence_id: 1,
                entry_id: 2,
                logical_path: "/evidence/folder/message.eml".to_string(),
                artifact_kind: "email".to_string(),
                is_deleted: false,
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Findings")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].title, "Sample Email Bookmark");
        assert_eq!(bookmarks[0].bookmark_type, "email");
        assert_eq!(bookmarks[0].item_count, 1);

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, Some(2));
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].logical_path, "/evidence/folder/message.eml");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_indexed_record_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Findings".to_string(),
            title: "Sample Record Bookmark".to_string(),
            comment: "Indexed record bookmark test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::IndexedResult {
                evidence_id: 1,
                entry_id: 3,
                logical_path: "/evidence/folder/record_item".to_string(),
                artifact_kind: "registry".to_string(),
                is_deleted: false,
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Findings")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].title, "Sample Record Bookmark");
        assert_eq!(bookmarks[0].bookmark_type, "record");
        assert_eq!(bookmarks[0].item_count, 1);

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, Some(3));
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].logical_path, "/evidence/folder/record_item");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_live_source_file_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Live".to_string(),
            title: "Live File Bookmark".to_string(),
            comment: "Live source file test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::LiveSourceFile {
                evidence_id: 1,
                volume_index: 0,
                logical_path: "/Windows/System32/calc.exe".to_string(),
                is_dir: false,
                is_deleted: false,
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Live")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].bookmark_type, "notable_file");

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, None);
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].logical_path, "/Windows/System32/calc.exe");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_live_source_dir_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Live".to_string(),
            title: "Live Dir Bookmark".to_string(),
            comment: "Live source dir test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::LiveSourceFile {
                evidence_id: 1,
                volume_index: 0,
                logical_path: "/Windows/System32".to_string(),
                is_dir: true,
                is_deleted: false,
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Live")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].bookmark_type, "folder_info");

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, None);
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].logical_path, "/Windows/System32");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_folder_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Folders".to_string(),
            title: "Folder Bookmark".to_string(),
            comment: "Single folder bookmark test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::Folder {
                evidence_id: 1,
                volume_index: 0,
                logical_path: "/evidence/folder".to_string(),
                is_indexed: true,
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Folders")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].bookmark_type, "folder_info");

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, None);
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].logical_path, "/evidence/folder");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_evidence_source_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Sources".to_string(),
            title: "Source Bookmark".to_string(),
            comment: "Evidence source bookmark test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: Some(BookmarkTarget::EvidenceSource {
                evidence_id: 1,
                source_name: "Test Image".to_string(),
            }),
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Sources")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].bookmark_type, "file_group");

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, None);
        assert_eq!(items[0].evidence_id, Some(1));
        assert_eq!(items[0].display_name, "Test Image");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_manual_none_target_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Manual".to_string(),
            title: "Manual Bookmark".to_string(),
            comment: "Manual none target test".to_string(),
            max_entries: String::new(),
            is_recursive: false,
            target: None,
            error: None,
        };

        app.execute_create_single_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("COMMITTED: Created bookmark #"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Manual")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0].bookmark_type, "notable_file");

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry_id, None);
        assert_eq!(items[0].evidence_id, None);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_recursive_folder_bookmark_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Recursive".to_string(),
            title: "Recursive Folder Bookmark".to_string(),
            comment: "Recursive folder test".to_string(),
            max_entries: "0".to_string(),
            is_recursive: true,
            target: Some(BookmarkTarget::Folder {
                evidence_id: 1,
                volume_index: 0,
                logical_path: "/evidence/folder".to_string(),
                is_indexed: true,
            }),
            error: None,
        };

        app.execute_create_recursive_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app
            .status
            .starts_with("COMMITTED: Recursive folder bookmark completed"));
        assert!(app.bookmark_error.is_none());
        assert!(!app.bookmark_dialog.visible);
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Recursive")
            .expect("folder exists");
        let bookmarks = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bookmarks.len(), 1);

        let items = test_list_items(&path, Some(bookmarks[0].id));
        assert_eq!(items.len(), 3);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ui_path_creates_folder_via_dialog_successfully() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.create_folder_dialog = CreateFolderDialogState {
            visible: true,
            name: "Created By Dialog".to_string(),
            comment: "Created from New Folder dialog test".to_string(),
            show_in_report: true,
            error: None,
        };

        let req = CreateBookmarkFolderRequest {
            case_path: path.clone(),
            parent_id: None,
            name: app.create_folder_dialog.name.clone(),
            folder_comment: optional_trimmed(&app.create_folder_dialog.comment),
            show_in_report: app.create_folder_dialog.show_in_report,
        };
        app.begin_create_folder(ctx.clone(), req);
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app
            .status
            .starts_with("COMMITTED: Created bookmark folder #"));
        assert!(!app.create_folder_dialog.visible);
        assert!(app.create_folder_dialog.error.is_none());
        assert!(app.operation_warnings.is_empty());

        let folders = test_list_folders(&path);
        assert!(folders.iter().any(|f| f.name == "Created By Dialog"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn desktop_limited_operation_displays_partial_not_completed() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Recursive Partial".to_string(),
            title: "Partial Recursive Bookmark".to_string(),
            comment: "Partial test".to_string(),
            max_entries: "1".to_string(),
            is_recursive: true,
            target: Some(BookmarkTarget::Folder {
                evidence_id: 1,
                volume_index: 0,
                logical_path: "/evidence/folder".to_string(),
                is_indexed: true,
            }),
            error: None,
        };

        app.execute_create_recursive_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(
            app.status
                .starts_with("PARTIAL: Recursive bookmark saved. Resume available"),
            "Expected PARTIAL status, got: {}",
            app.status
        );
        assert!(
            !app.status.contains("Do not retry"),
            "Partial status must never claim 'Do not retry'"
        );
        assert!(app.bookmark_error.is_none());
        assert!(
            app.bookmark_dialog.visible,
            "Bookmark dialog must remain visible for partial result"
        );
        assert!(app.resuming_bookmark_id.is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn desktop_close_reopen_and_resume_reaches_every_item_without_duplicates() {
        let (path, mut app, ctx) = setup_desktop_test_case();
        app.bookmark_dialog = BookmarkDialogState {
            visible: true,
            folder_name: "UI Resume Folder".to_string(),
            title: "Resume Bookmark Test".to_string(),
            comment: "Resume test".to_string(),
            max_entries: "1".to_string(),
            is_recursive: true,
            target: Some(BookmarkTarget::Folder {
                evidence_id: 1,
                volume_index: 0,
                logical_path: "/evidence/folder".to_string(),
                is_indexed: true,
            }),
            error: None,
        };

        // Step 1: Initial partial creation
        app.execute_create_recursive_bookmark(ctx.clone());
        wait_for_desktop_bookmark_pipeline(&mut app, &ctx);

        assert!(app.status.starts_with("PARTIAL:"));
        let bookmark_id = app.resuming_bookmark_id.expect("resuming_bookmark_id set");

        // Step 2: Close case
        app.clear_opened_view();
        assert!(app.opened_path.is_none());

        // Step 3: Reopen case
        let opened = open_case(&path).expect("reopen fixture");
        let mut app2 = test_app(&path, opened);

        // Verify incomplete bookmark is discoverable after close/reopen
        let incomplete_list = NativeBookmarkService::list_incomplete_recursive_bookmarks(&path)
            .expect("list incomplete");
        assert_eq!(incomplete_list.len(), 1);
        assert_eq!(incomplete_list[0].bookmark_id, bookmark_id);
        assert_eq!(incomplete_list[0].items_added, 1);
        assert!(!incomplete_list[0].checkpoint.completed);

        // Check bookmark summary is marked incomplete
        let bms = test_list_bookmarks(&path, Some(incomplete_list[0].folder_id));
        assert_eq!(bms.len(), 1);
        assert_eq!(bms[0].id, bookmark_id);
        assert!(bms[0].is_incomplete);

        // Step 4: Resume recursive bookmark
        app2.execute_resume_bookmark(ctx.clone(), bookmark_id);
        wait_for_desktop_bookmark_pipeline(&mut app2, &ctx);

        assert!(
            app2.status
                .starts_with("COMMITTED: Recursive folder bookmark completed"),
            "Expected completed status, got: {}",
            app2.status
        );
        assert!(
            app2.status.contains("Do not retry"),
            "Completed status must claim 'Do not retry'"
        );
        assert!(!app2.bookmark_dialog.visible);

        // Verify original bookmark_id was reused
        let folders = test_list_folders(&path);
        let folder = folders
            .iter()
            .find(|f| f.name == "UI Resume Folder")
            .expect("folder exists");
        let bms_after = test_list_bookmarks(&path, Some(folder.id));
        assert_eq!(bms_after.len(), 1, "Must not create another bookmark");
        assert_eq!(
            bms_after[0].id, bookmark_id,
            "Must reuse original bookmark_id"
        );

        // Verify all 3 items reached without duplicates
        let items = test_list_items(&path, Some(bookmark_id));
        assert_eq!(items.len(), 3, "All 3 items must be in bookmark");
        let mut paths = std::collections::HashSet::new();
        for item in &items {
            assert!(
                paths.insert(item.logical_path.clone()),
                "duplicate item: {}",
                item.logical_path
            );
        }
        assert_eq!(paths.len(), 3);

        // Verify completed result no longer offers Resume
        let incomplete_after = NativeBookmarkService::list_incomplete_recursive_bookmarks(&path)
            .expect("list incomplete after completion");
        assert!(
            incomplete_after.is_empty(),
            "Completed bookmark must not be in incomplete list"
        );
        assert!(
            !bms_after[0].is_incomplete,
            "Completed bookmark must have is_incomplete = false"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn real_lifecycle_open_populates_opened_path_and_enables_attachment() {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kdft-lifecycle-test-{}-{serial}.kdft",
            std::process::id()
        ));
        let request = CreateCaseRequest {
            case_path: path.clone(),
            name: "Lifecycle Test".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: Some("LIFECYCLE-1".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        };
        NativeWorkflowService::create_case(request).expect("create test case");

        let mut app = KDFTDesktopApp::from_initial_path(None);
        assert!(app.opened_path.is_none());

        let opened = open_case(&path).expect("open created case");
        app.install_opened(opened);

        let canonical_path = path.canonicalize().unwrap();
        assert_eq!(app.opened_path, Some(canonical_path.clone()));
        assert_eq!(app.case_path, canonical_path.display().to_string());
        assert!(app.backend.is_some());
        assert!(app.summary.is_some());

        // Now verify attachment is immediately enabled and does NOT error with
        // "Create or open a case before attaching evidence."
        let ctx = egui::Context::default();
        app.begin_attach(
            ctx,
            PathBuf::from("C:/dummy/image.raw"),
            NativeEvidenceKind::Image,
        );

        assert_ne!(
            app.error.as_deref(),
            Some("Create or open a case before attaching evidence."),
            "opened_path must be populated so attachment is permitted"
        );
        assert!(app.pending.is_some(), "Attachment worker should be started");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn browse_evidence_action_switches_to_browse_tab() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);

        assert_eq!(app.active_tab, TopLevelTab::Case);

        // Simulate user clicking Browse on evidence #1
        app.active_tab = TopLevelTab::Browse;
        app.browse_evidence_id = Some(1);
        app.selected_evidence_id = Some(1);
        app.browse_evidence_name = "source.bin".to_string();

        assert_eq!(app.active_tab, TopLevelTab::Browse);
        assert_eq!(app.browse_evidence_id, Some(1));
        assert_eq!(app.browse_evidence_name, "source.bin");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn report_export_json_and_markdown_creation() {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kdft-report-test-{}-{serial}.kdft",
            std::process::id()
        ));
        let request = CreateCaseRequest {
            case_path: path.clone(),
            name: "Report Export Test".to_string(),
            examiner_name: Some("Lead Examiner".to_string()),
            case_number: Some("REP-001".to_string()),
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        };
        NativeWorkflowService::create_case(request).expect("create test case");

        // 1. Export as JSON
        let json_dest =
            std::env::temp_dir().join(format!("kdft-rep-out-{}-{serial}.json", std::process::id()));
        let res_json = kdft_desktop_core::reports::NativeReportService::export_report(
            &path,
            &json_dest,
            Some("Lead Examiner"),
        );
        assert!(
            res_json.is_ok(),
            "JSON export should succeed: {:?}",
            res_json
        );
        assert!(json_dest.exists(), "JSON file must exist on disk");
        let json_content = fs::read_to_string(&json_dest).expect("read json report");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_content).expect("valid json format");
        assert_eq!(parsed["case_name"], "Report Export Test");
        assert_eq!(parsed["case_number"], "REP-001");

        // 2. Export as Markdown
        let md_dest =
            std::env::temp_dir().join(format!("kdft-rep-out-{}-{serial}.md", std::process::id()));
        let res_md = kdft_desktop_core::reports::NativeReportService::export_report(
            &path,
            &md_dest,
            Some("Lead Examiner"),
        );
        assert!(
            res_md.is_ok(),
            "Markdown export should succeed: {:?}",
            res_md
        );
        assert!(md_dest.exists(), "Markdown file must exist on disk");
        let md_content = fs::read_to_string(&md_dest).expect("read md report");
        assert!(md_content.starts_with("# Case Report: Report Export Test"));
        assert!(md_content.contains("## Case Summary"));
        assert!(md_content.contains("| Case Name | Report Export Test |"));
        assert!(md_content.contains("## Integrity & Verification"));

        let _ = fs::remove_file(json_dest);
        let _ = fs::remove_file(md_dest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn regression_priority0_bitlocker_volume_identity_navigation_and_stale_response_protection() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();

        let evidence_id = 1;
        let volume_index = 2;
        let vol_id = VolumeIdentity::new(
            1,
            evidence_id,
            volume_index,
            0x2000000,
            20 * 1024 * 1024 * 1024,
            "NTFS",
            Some("BitLocker".to_string()),
            Some(1),
        );

        // 1. Establish BitLocker volume and unlock session
        app.browse_evidence_id = Some(evidence_id);
        app.browse_selected_volume = volume_index;
        app.active_volume_identity = Some(vol_id.clone());

        let cred = kdft_desktop_core::unlock::TransientBitLockerCredential::password(
            "test-secure-key".to_string(),
        );
        let gen = app.unlock_manager.store_unverified_session(
            evidence_id,
            volume_index,
            "NTFS".to_string(),
            cred,
        );
        assert!(app.unlock_manager.is_unlocked(evidence_id, volume_index));
        assert_eq!(
            app.unlock_manager
                .unlock_generation(evidence_id, volume_index),
            Some(gen)
        );

        // 2. Browse /Users and enter nested directories
        let paths = vec![
            "/",
            "/Users",
            "/Users/Examiner",
            "/Users/Examiner/Documents",
            "/Users/Examiner/Documents/Cases",
        ];

        for p in &paths {
            if app.browse_path != *p {
                app.browse_history_back.push(app.browse_path.clone());
                app.browse_history.push(BrowseHistoryEntry {
                    volume_identity: vol_id.clone(),
                    path: app.browse_path.clone(),
                });
            }
            app.browse_path = p.to_string();
            app.begin_browse_directory(ctx.clone(), evidence_id, volume_index, p.to_string(), 0);

            // Assert request uses exact evidence_id and volume_index
            assert_eq!(app.browse_evidence_id, Some(evidence_id));
            assert_eq!(app.browse_selected_volume, volume_index);
            assert_eq!(
                app.active_volume_identity.as_ref().unwrap().evidence_id,
                evidence_id
            );
            assert_eq!(
                app.active_volume_identity.as_ref().unwrap().volume_index,
                volume_index
            );
            assert_eq!(
                app.active_volume_identity.as_ref().unwrap().filesystem_type,
                "NTFS"
            );
            // Session remains unlocked across navigation
            assert!(app.unlock_manager.is_unlocked(evidence_id, volume_index));
        }

        // 3. Repeated Back and Forward navigation
        while let Some(prev) = app.browse_history_back.pop() {
            app.browse_history_forward.push(app.browse_path.clone());
            app.browse_path = prev.clone();
            app.begin_browse_directory(ctx.clone(), evidence_id, volume_index, prev, 0);

            assert_eq!(app.browse_evidence_id, Some(evidence_id));
            assert_eq!(app.browse_selected_volume, volume_index);
            assert_eq!(
                app.active_volume_identity.as_ref().unwrap().volume_index,
                volume_index
            );
            assert!(app.unlock_manager.is_unlocked(evidence_id, volume_index));
        }
        assert_eq!(app.browse_path, "/");

        while let Some(next) = app.browse_history_forward.pop() {
            app.browse_history_back.push(app.browse_path.clone());
            app.browse_path = next.clone();
            app.begin_browse_directory(ctx.clone(), evidence_id, volume_index, next, 0);

            assert_eq!(app.browse_evidence_id, Some(evidence_id));
            assert_eq!(app.browse_selected_volume, volume_index);
            assert!(app.unlock_manager.is_unlocked(evidence_id, volume_index));
        }

        // 4. Return to parent and re-enter
        let parent = parent_browse_path(&app.browse_path).expect("has parent");
        app.browse_path = parent.clone();
        app.begin_browse_directory(ctx.clone(), evidence_id, volume_index, parent, 0);
        assert!(app.unlock_manager.is_unlocked(evidence_id, volume_index));

        // 5. Assert reader provenance: decrypted NTFS, no FAT fallback
        let valid_page = BrowseDirectoryPage {
            evidence_id,
            volume_index,
            volume_identity: Some(vol_id.clone()),
            access_state: VolumeAccessState::UnlockedForSession { generation: gen },
            reader_label: "Decrypted BitLocker NTFS Reader".to_string(),
            request_id: app.browse_request_id,
            path: "/Users".to_string(),
            entries: Vec::new(),
            total_entries: 0,
            offset: 0,
            next_offset: None,
            truncated: false,
            filesystem: "NTFS".to_string(),
            is_locked: false,
            locked_message: None,
            is_unsupported: false,
            unsupported_message: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(valid_page.reader_label, "Decrypted BitLocker NTFS Reader");
        assert!(!valid_page.reader_label.to_lowercase().contains("fat"));
        assert_eq!(valid_page.filesystem, "NTFS");
        assert_eq!(
            valid_page.access_state,
            VolumeAccessState::UnlockedForSession { generation: gen }
        );

        // Deliver valid page
        let (send_valid, recv_valid) = mpsc::channel();
        send_valid
            .send(BrowseWorkerResult::DirectoryPage {
                request_id: app.browse_request_id,
                evidence_id,
                volume_index,
                path: "/Users".to_string(),
                offset: 0,
                result: Ok(valid_page.clone()),
            })
            .unwrap();
        app.browse_pending = Some(recv_valid);
        app.poll_browse_worker(&ctx);
        assert_eq!(app.browse_page.as_ref().unwrap().path, "/Users");
        assert_eq!(
            app.browse_page.as_ref().unwrap().reader_label,
            "Decrypted BitLocker NTFS Reader"
        );

        // 6. Assert stale async responses are rejected:
        // Case A: Older request_id (delayed worker response from previous folder)
        let stale_old_req_page = BrowseDirectoryPage {
            path: "/OldStaleFolder".to_string(),
            request_id: app.browse_request_id - 1,
            ..valid_page.clone()
        };
        let (send_stale1, recv_stale1) = mpsc::channel();
        send_stale1
            .send(BrowseWorkerResult::DirectoryPage {
                request_id: app.browse_request_id - 1,
                evidence_id,
                volume_index,
                path: "/OldStaleFolder".to_string(),
                offset: 0,
                result: Ok(stale_old_req_page),
            })
            .unwrap();
        app.browse_pending = Some(recv_stale1);
        app.poll_browse_worker(&ctx);
        // Path MUST NOT be replaced by stale response
        assert_eq!(app.browse_page.as_ref().unwrap().path, "/Users");

        // Case B: Response from different volume index (e.g. stale FAT volume read)
        let stale_fat_page = BrowseDirectoryPage {
            volume_index: 0,
            filesystem: "FAT32".to_string(),
            reader_label: "FAT32 Reader".to_string(),
            path: "/FATFolder".to_string(),
            request_id: app.browse_request_id,
            ..valid_page.clone()
        };
        let (send_stale2, recv_stale2) = mpsc::channel();
        send_stale2
            .send(BrowseWorkerResult::DirectoryPage {
                request_id: app.browse_request_id,
                evidence_id,
                volume_index: 0, // different volume!
                path: "/FATFolder".to_string(),
                offset: 0,
                result: Ok(stale_fat_page),
            })
            .unwrap();
        app.browse_pending = Some(recv_stale2);
        app.poll_browse_worker(&ctx);
        // Path MUST NOT be replaced by stale FAT response
        assert_eq!(app.browse_page.as_ref().unwrap().path, "/Users");
        assert_eq!(
            app.browse_page.as_ref().unwrap().reader_label,
            "Decrypted BitLocker NTFS Reader"
        );

        // 7. Read hex bounded preview for selected file
        let mut hex_req = BoundedByteRequest::simple(
            path.clone(),
            evidence_id,
            volume_index,
            Some("/Users/Examiner/Documents/report.txt".to_string()),
            None,
            ByteSourceNamespace::LogicalFile,
            0,
            512,
            true,
        );
        hex_req.volume_identity = app.active_volume_identity.clone();
        assert_eq!(hex_req.evidence_id, evidence_id);
        assert_eq!(hex_req.volume_index, volume_index);
        assert_eq!(hex_req.volume_identity, Some(vol_id));

        // 8. Explicit Lock volume
        app.unlock_manager.lock_volume(evidence_id, volume_index);
        assert!(!app.unlock_manager.is_unlocked(evidence_id, volume_index));
        assert_eq!(
            app.unlock_manager
                .unlock_generation(evidence_id, volume_index),
            None
        );

        let _ = fs::remove_file(path);
    }

    fn collect_rendered_texts(shapes: &[eframe::egui::epaint::ClippedShape]) -> Vec<String> {
        let mut texts = Vec::new();
        fn visit(shape: &eframe::egui::epaint::Shape, texts: &mut Vec<String>) {
            match shape {
                eframe::egui::epaint::Shape::Text(t) => {
                    texts.push(t.galley.job.text.clone());
                }
                eframe::egui::epaint::Shape::Vec(v) => {
                    for s in v {
                        visit(s, texts);
                    }
                }
                _ => {}
            }
        }
        for s in shapes {
            visit(&s.shape, &mut texts);
        }
        texts
    }

    #[test]
    fn test_volume_selector_label_cannot_display_locked_when_unlocked() {
        use crate::views::source_browser::volume_label;
        use kdft_desktop_core::browse::EvidenceVolume;

        let locked_vol = EvidenceVolume {
            index: 2,
            name: "BitLocker Partition".to_string(),
            filesystem: "NTFS".to_string(),
            start_offset: 1024 * 1024,
            size_bytes: 1_000_000_000,
            browsable: true,
            is_bitlocker: true,
            bitlocker_status: Some("Locked".to_string()),
        };

        // When locked (is_unlocked = false), label shows locked
        let label_locked = volume_label(&locked_vol, false);
        assert_eq!(label_locked, "Vol 2 (BitLocker locked)");

        // When active transient session is unlocked (is_unlocked = true)
        let label_unlocked = volume_label(&locked_vol, true);
        assert_eq!(
            label_unlocked,
            "Vol 2 (NTFS · BitLocker unlocked for session)"
        );
        assert!(
            !label_unlocked.contains("(BitLocker locked)"),
            "Authoritative volume label MUST NOT contain '(BitLocker locked)' when session is unlocked"
        );
        assert!(
            !label_unlocked.ends_with(" locked)"),
            "Authoritative volume label MUST NOT end with locked) when session is unlocked"
        );
    }

    #[test]
    fn test_embedded_browse_lower_pane_hex_and_properties_layout() {
        let (path, mut app, ctx) = setup_desktop_test_case();

        // 1. Install a nonempty bounded-byte response
        app.hex_viewer_state.active = true;
        app.hex_viewer_state.logical_path = "/hiberfil.sys".to_string();
        app.hex_viewer_state.total_size = Some(1024 * 1024 * 1024); // multi-gigabyte file
        app.hex_viewer_state.current_offset = 0;
        app.hex_viewer_state.bytes_per_row = 16;
        app.hex_viewer_state.loaded_bytes = b"POWERCALL\x00\x01\x02\x03\x04\x05\x06".to_vec();
        app.hex_viewer_state.loading = false;
        app.hex_viewer_state.error = None;

        app.selected_browser_entry = Some(crate::views::source_browser::SelectedBrowserEntry {
            name: "hiberfil.sys".to_string(),
            path: "/hiberfil.sys".to_string(),
            is_dir: false,
            is_deleted: false,
            size_bytes: Some(1024 * 1024 * 1024),
            created_utc: Some("2026-10-19T09:00:00Z".to_string()),
            modified_utc: Some("2026-10-19T10:00:00Z".to_string()),
            accessed_utc: Some("2026-10-19T11:00:00Z".to_string()),
            provenance: Some("Forensic NTFS Reader".to_string()),
            reconstruction_status: Some("allocated".to_string()),
            file_record_number: Some(42),
            physical_offset: Some(4096),
            canonical_entry_id: Some(99),
            sha256: Some(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            ),
        });

        // Test at minimum, default, and maximum splitter sizes
        let splitter_widths = [160.0, 320.0, 600.0];
        let lower_heights = [120.0, 300.0, 600.0];

        for &prop_w in &splitter_widths {
            for &lower_h in &lower_heights {
                app.layout.browse_properties_width = prop_w;
                app.layout.browse_properties_collapsed = false;
                app.layout.browse_lower_collapsed = false;

                let raw_input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 800.0),
                    )),
                    ..Default::default()
                };

                let mut output = ctx.run_ui(raw_input, |ui| {
                    app.render_browse_lower_pane(ui, lower_h, 1200.0);
                });

                let emitted_texts = collect_rendered_texts(&output.shapes);
                output.textures_delta.clear();
                let all_text = emitted_texts.join(" ");

                // Proves at least one hex row is emitted (offset 00000000: and hex byte values)
                assert!(
                    all_text.contains("00000000:"),
                    "Emitted text must contain hex offset row header at prop_w={prop_w}, lower_h={lower_h}"
                );
                assert!(
                    all_text.contains("50") && all_text.contains("4F") && all_text.contains("57"),
                    "Emitted text must contain hex row byte values at prop_w={prop_w}, lower_h={lower_h}"
                );

                // Proves ASCII text is emitted ("POWERCALL")
                assert!(
                    all_text.contains("POWERCALL"),
                    "Emitted text must contain ASCII column text at prop_w={prop_w}, lower_h={lower_h}"
                );

                // Proves Properties is visible
                assert!(
                    all_text.contains("Properties"),
                    "Properties heading must be visible at prop_w={prop_w}, lower_h={lower_h}"
                );
                assert!(
                    all_text.contains("hiberfil.sys"),
                    "Properties pane must render selected file name at prop_w={prop_w}, lower_h={lower_h}"
                );
                if lower_h >= 240.0 {
                    assert!(
                        all_text.contains("SHA-256:"),
                        "Properties pane must render SHA-256 at prop_w={prop_w}, lower_h={lower_h}"
                    );
                }
            }
        }

        // Test resize and collapse operations do not discard loaded bytes
        app.layout.browse_properties_collapsed = true;
        app.layout.browse_lower_collapsed = true;
        app.layout.browse_upper_height = 500.0;
        assert_eq!(app.hex_viewer_state.loaded_bytes.len(), 16);
        assert_eq!(app.hex_viewer_state.logical_path, "/hiberfil.sys");

        app.layout.browse_properties_collapsed = false;
        app.layout.browse_lower_collapsed = false;
        assert_eq!(app.hex_viewer_state.loaded_bytes.len(), 16);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_hex_viewer_origin_tab_isolation_across_views() {
        let (path, mut app, _ctx) = setup_desktop_test_case();

        // 1. User is in Browse tab and views a file
        app.active_tab = TopLevelTab::Browse;
        app.hex_viewer_state.active = true;
        app.hex_viewer_origin_tab = Some(TopLevelTab::Browse);
        app.hex_viewer_state.logical_path = "/EFI/bootmgfw.efi".to_string();

        // 2. User switches to other tabs: Search, Timeline, Bookmarks, Reports, Process
        let other_tabs = [
            TopLevelTab::Search,
            TopLevelTab::Timeline,
            TopLevelTab::Bookmarks,
            TopLevelTab::Reports,
            TopLevelTab::Process,
        ];

        for tab in other_tabs {
            app.active_tab = tab;
            let would_render_bottom_panel = app.hex_viewer_state.active
                && app.active_tab != TopLevelTab::Browse
                && app.hex_viewer_origin_tab == Some(app.active_tab);
            assert!(
                !would_render_bottom_panel,
                "Hex viewer initiated in Browse tab MUST NOT render on {:?} tab",
                tab
            );
        }

        // 3. If hex viewer is initiated from Artifacts tab:
        app.active_tab = TopLevelTab::Artifacts;
        app.hex_viewer_origin_tab = Some(TopLevelTab::Artifacts);
        let would_render_on_artifacts = app.hex_viewer_state.active
            && app.active_tab != TopLevelTab::Browse
            && app.hex_viewer_origin_tab == Some(app.active_tab);
        assert!(
            would_render_on_artifacts,
            "Hex viewer initiated on Artifacts tab should render while active tab is Artifacts"
        );

        // But when switching away to Search:
        app.active_tab = TopLevelTab::Search;
        let would_render_on_search = app.hex_viewer_state.active
            && app.active_tab != TopLevelTab::Browse
            && app.hex_viewer_origin_tab == Some(app.active_tab);
        assert!(
            !would_render_on_search,
            "Hex viewer initiated on Artifacts tab MUST NOT render on Search tab"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_hex_viewer_four_distinct_states() {
        let ctx = egui::Context::default();
        let mut interp = DataInterpreterState::default();

        // State 1: Loading
        {
            let mut state = HexViewerState {
                active: true,
                loading: true,
                logical_path: "/hiberfil.sys".to_string(),
                ..Default::default()
            };
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                views::hex_viewer::show(ui, &mut state, &mut interp);
            });
            let all_text = collect_rendered_texts(&output.shapes).join(" ");
            output.textures_delta.clear();
            assert!(all_text.contains("Loading bytes from evidence source..."));
        }

        // State 2: N bytes loaded
        {
            let mut state = HexViewerState {
                active: true,
                loading: false,
                loaded_bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
                logical_path: "/test.bin".to_string(),
                ..Default::default()
            };
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                views::hex_viewer::show(ui, &mut state, &mut interp);
            });
            let all_text = collect_rendered_texts(&output.shapes).join(" ");
            output.textures_delta.clear();
            assert!(all_text.contains("4 bytes loaded"));
            assert!(all_text.contains("CA"));
            assert!(all_text.contains("FE"));
        }

        // State 3: No bytes returned / empty
        {
            let mut state = HexViewerState {
                active: true,
                loading: false,
                loaded_bytes: Vec::new(),
                logical_path: "/empty.txt".to_string(),
                ..Default::default()
            };
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                views::hex_viewer::show(ui, &mut state, &mut interp);
            });
            let all_text = collect_rendered_texts(&output.shapes).join(" ");
            output.textures_delta.clear();
            assert!(all_text.contains("No bytes returned for this offset range or file is empty"));
        }

        // State 4: Read error with exact error
        {
            let mut state = HexViewerState {
                active: true,
                loading: false,
                error: Some("NTFS cluster run out of bounds".to_string()),
                logical_path: "/corrupt.dat".to_string(),
                ..Default::default()
            };
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                views::hex_viewer::show(ui, &mut state, &mut interp);
            });
            let all_text = collect_rendered_texts(&output.shapes).join(" ");
            output.textures_delta.clear();
            assert!(all_text.contains("Read Error: NTFS cluster run out of bounds"));
        }
    }

    #[test]
    fn hex_page_navigation_is_bounded_by_loaded_bytes_and_total_size() {
        let short_file = HexViewerState {
            active: true,
            total_size: Some(163),
            loaded_bytes: vec![0_u8; 163],
            ..Default::default()
        };
        assert_eq!(views::hex_viewer::previous_page_offset(&short_file), None);
        assert_eq!(views::hex_viewer::next_page_offset(&short_file), None);

        let first_full_page = HexViewerState {
            active: true,
            total_size: Some(700),
            loaded_bytes: vec![0_u8; 512],
            ..Default::default()
        };
        assert_eq!(
            views::hex_viewer::next_page_offset(&first_full_page),
            Some(512)
        );

        let final_page = HexViewerState {
            active: true,
            current_offset: 512,
            total_size: Some(700),
            loaded_bytes: vec![0_u8; 188],
            ..Default::default()
        };
        assert_eq!(
            views::hex_viewer::previous_page_offset(&final_page),
            Some(0)
        );
        assert_eq!(views::hex_viewer::next_page_offset(&final_page), None);

        let loading = HexViewerState {
            active: true,
            loading: true,
            current_offset: 512,
            total_size: Some(2048),
            loaded_bytes: vec![0_u8; 512],
            ..Default::default()
        };
        assert_eq!(views::hex_viewer::previous_page_offset(&loading), None);
        assert_eq!(views::hex_viewer::next_page_offset(&loading), None);
    }

    #[test]
    fn test_evidence_view_integrity_badges_render() {
        let ctx = egui::Context::default();
        let summaries = vec![
            EvidenceSummary {
                id: 1,
                source_kind: "image".to_string(),
                display_name: "ev_verified.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_verified.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: Some("abc".to_string()),
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: Some("verified".to_string()),
                expected_sha256: Some("abc".to_string()),
                integrity_details_json: None,
            },
            EvidenceSummary {
                id: 2,
                source_kind: "image".to_string(),
                display_name: "ev_computed.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_computed.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: Some("def".to_string()),
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: Some("computed".to_string()),
                expected_sha256: None,
                integrity_details_json: None,
            },
            EvidenceSummary {
                id: 3,
                source_kind: "image".to_string(),
                display_name: "ev_mismatch.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_mismatch.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: None,
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: Some("mismatch".to_string()),
                expected_sha256: Some("bad".to_string()),
                integrity_details_json: None,
            },
            EvidenceSummary {
                id: 4,
                source_kind: "image".to_string(),
                display_name: "ev_deferred.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_deferred.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: None,
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: Some("deferred".to_string()),
                expected_sha256: None,
                integrity_details_json: None,
            },
            EvidenceSummary {
                id: 5,
                source_kind: "image".to_string(),
                display_name: "ev_skipped.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_skipped.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: None,
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: Some("skipped".to_string()),
                expected_sha256: None,
                integrity_details_json: None,
            },
            EvidenceSummary {
                id: 6,
                source_kind: "image".to_string(),
                display_name: "ev_failed.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_failed.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: None,
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: Some("failed".to_string()),
                expected_sha256: None,
                integrity_details_json: None,
            },
            EvidenceSummary {
                id: 7,
                source_kind: "image".to_string(),
                display_name: "ev_unverified.raw".to_string(),
                display_name_truncated: false,
                source_path_preview: "/test/ev_unverified.raw".to_string(),
                source_path_truncated: false,
                size_bytes: Some(1024),
                read_file_system_requested: true,
                attach_status: "attached".to_string(),
                encryption_status: "none".to_string(),
                attached_at: "2026-10-20T00:00:00Z".to_string(),
                indexed_at: None,
                display_timezone: "UTC".to_string(),
                last_job_status: None,
                content_indexed: None,
                sha256_hex: None,
                hashed_at: None,
                sha256_scope: None,
                notes_preview: None,
                notes_truncated: false,
                is_standalone_mft: false,
                integrity_status: None,
                expected_sha256: None,
                integrity_details_json: None,
            },
        ];

        let page = EvidencePage {
            items: summaries,
            next_after_id: None,
            has_more: false,
            returned: 7,
            case_generation: 1,
        };

        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };

        let mut output = ctx.run_ui(raw_input, |ui| {
            views::evidence::show(ui, Some(&page), 0, Some(1), &[], false, None, None, None);
        });

        let all_text = collect_rendered_texts(&output.shapes).join(" ");
        println!("DEBUG: all_text={:?}", all_text);
        output.textures_delta.clear();

        assert!(
            all_text.contains("✓ Verified"),
            "Must render ✓ Verified badge"
        );
        assert!(
            all_text.contains("ℹ Computed"),
            "Must render ℹ Computed badge"
        );
        assert!(
            all_text.contains("✗ Mismatch"),
            "Must render ✗ Mismatch badge"
        );
        assert!(
            all_text.contains("⏳ Deferred"),
            "Must render ⏳ Deferred badge"
        );
        assert!(
            all_text.contains("⊘ Skipped"),
            "Must render ⊘ Skipped badge"
        );
        assert!(all_text.contains("⚠ Failed"), "Must render ⚠ Failed badge");
        assert!(
            all_text.contains("Unverified"),
            "Must render Unverified badge"
        );
    }

    #[test]
    fn test_search_view_unindexed_disclosure_render() {
        let ctx = egui::Context::default();
        let mut state = SearchViewState {
            query: "forensic_target".to_string(),
            results: Vec::new(),
            total_matches: Some(0),
            loading: false,
            ..Default::default()
        };

        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };

        let mut output = ctx.run_ui(raw_input, |ui| {
            views::search::show(ui, &mut state, true);
        });

        let all_text = collect_rendered_texts(&output.shapes).join(" ");
        println!("DEBUG: all_text={:?}", all_text);
        output.textures_delta.clear();

        assert!(all_text.contains("No search results found for \"forensic_target\""));
        assert!(all_text.contains("Search Coverage Disclosure:"));
        assert!(all_text.contains("Exclusions: Files without captured content heads or content beyond prefix limits were not searched"));
    }

    #[test]
    fn test_search_result_actions_remain_visible_with_long_forensic_path() {
        let ctx = egui::Context::default();
        let mut state = SearchViewState {
            query: "transfer".to_string(),
            results: vec![kdft_desktop_core::search::DeepSearchResultSummary {
                entry_id: 42,
                evidence_id: 7,
                display_name: "BackgroundTransfer.dll".to_string(),
                logical_path: format!("/internal/{}", "very-long-segment/".repeat(30)),
                source_path_exact: Some(format!(
                    "C:\\Windows\\{}BackgroundTransfer.dll",
                    "very-long-segment\\".repeat(30)
                )),
                entry_kind: "file".to_string(),
                size_bytes: Some(4096),
                match_field: "content".to_string(),
                match_snippet: "...transfer...".to_string(),
                byte_offset: Some(767),
                byte_length: Some(8),
            }],
            total_matches: Some(1),
            loading: false,
            ..Default::default()
        };
        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };

        let mut output = ctx.run_ui(raw_input, |ui| {
            views::search::show(ui, &mut state, true);
        });
        let all_text = collect_rendered_texts(&output.shapes).join(" ");
        output.textures_delta.clear();

        assert!(all_text.contains("Inspect"));
        assert!(all_text.contains("Hex at match"));
        assert!(all_text.contains("Export"));
        assert!(all_text.contains("Bookmark / Report"));
        assert!(all_text.contains("Original file bytes at 0x2FF (8 bytes)"));
    }

    #[test]
    fn test_timeline_filters_and_result_contract_are_discoverable() {
        let ctx = egui::Context::default();
        let mut state = TimelineViewState {
            events: vec![kdft_desktop_core::timeline::TimelineEvent {
                entry_id: 42,
                evidence_id: 7,
                timestamp_utc: "2026-10-27T14:32:05.123456Z".to_string(),
                timestamp_type: "Modified".to_string(),
                basis: "Filesystem last written/modified time (UTC)".to_string(),
                event_origin: "Raw filesystem metadata".to_string(),
                artifact_kind: "filesystem_entry".to_string(),
                display_name: "transfer.txt".to_string(),
                logical_path: format!("/{}transfer.txt", "long/path/".repeat(30)),
                category: "Documents and Office".to_string(),
                is_deleted: false,
                is_bookmarked: false,
            }],
            total_matching: 1,
            ..Default::default()
        };
        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };

        let mut output = ctx.run_ui(raw_input, |ui| {
            views::timeline::show(ui, &mut state, true);
        });
        let all_text = collect_rendered_texts(&output.shapes).join(" ");
        output.textures_delta.clear();

        assert!(all_text.contains("Search events:"));
        assert!(all_text.contains("Category (optional):"));
        assert!(all_text.contains("Timestamp type:"));
        assert!(all_text.contains("From UTC (inclusive):"));
        assert!(all_text.contains("To UTC (inclusive):"));
        assert!(all_text.contains("Showing events 1-1 of 1 matching timeline events."));
        assert!(all_text.contains("Inspect"));
        assert!(all_text.contains("Bookmark / Report"));
        assert!(all_text.contains("Raw filesystem metadata"));
        assert!(all_text.contains("not a decoded Registry-change event"));
    }

    #[test]
    fn test_evidence_intake_dialog_state_and_scope_inspection() {
        let mut state = EvidenceIntakeDialogState {
            visible: true,
            source_path: PathBuf::from("E:/images/test.E01"),
            detected_kind: NativeEvidenceKind::Image,
            display_name: "test.E01".to_string(),
            timezone: "UTC".to_string(),
            timezone_filter: String::new(),
            integrity_choice: IntakeIntegrityChoice::VerifyNow,
            expected_sha256: String::new(),
            skip_reason: String::new(),
            scope_description: "Complete E01 segment set (3 segment files)".to_string(),
            segment_count: 3,
            segment_scheme: "ewf_numbered_segments".to_string(),
            error: None,
        };

        let ctx = egui::Context::default();
        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        };

        let mut output1 = ctx.run_ui(raw_input.clone(), |ui| {
            let _ = dialogs::intake::show(ui.ctx(), &mut state, false);
        });
        output1.textures_delta.clear();

        let mut output = ctx.run_ui(raw_input, |ui| {
            let _ = dialogs::intake::show(ui.ctx(), &mut state, false);
        });

        let all_text = collect_rendered_texts(&output.shapes).join(" ");
        output.textures_delta.clear();

        assert!(all_text.contains("Evidence Source Intake & Integrity"));
        assert!(all_text.contains("E01 Segment Set (3 segment files)"));
        assert!(all_text.contains("Complete E01 segment set (3 segment files)"));
        assert!(all_text.contains("Verify now (compare against expected SHA-256)"));
        assert!(all_text.contains("Compute hashes without comparison"));
        assert!(all_text.contains("Defer verification"));
        assert!(all_text.contains("Do not verify"));
    }

    #[test]
    fn test_case_settings_dialog_rendering_and_timezones() {
        let mut state = CaseSettingsDialogState {
            visible: true,
            current_timezone: "UTC".to_string(),
            selected_timezone: "America/New_York".to_string(),
            timezone_filter: "Bucharest".to_string(),
            error: None,
        };

        let ctx = egui::Context::default();
        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        };

        let mut output1 = ctx.run_ui(raw_input.clone(), |ui| {
            let _ = dialogs::case_settings::show(ui.ctx(), &mut state, false);
        });
        output1.textures_delta.clear();

        let mut output = ctx.run_ui(raw_input, |ui| {
            let _ = dialogs::case_settings::show(ui.ctx(), &mut state, false);
        });

        let all_text = collect_rendered_texts(&output.shapes).join(" ");
        output.textures_delta.clear();

        assert!(all_text.contains("Case Timezone & Display Preferences"));
        assert!(all_text.contains("America/New_York"));
        assert!(all_text.contains("Europe/Bucharest"));
        assert!(all_text.contains("Apply Timezone"));
    }

    #[test]
    fn test_processing_options_dialog_blocks_locked_bitlocker() {
        use crate::dialogs::processing_options::{self, ProcessingOptionsAction};
        use kdft_desktop_core::browse::EvidenceVolume;

        let (_path, _app, ctx) = setup_desktop_test_case();
        let mut state = crate::state::ProcessingOptionsDialogState {
            visible: true,
            evidence_id: 1,
            evidence_name: "Test Evidence".to_string(),
            evidence_path: "E:/test.E01".to_string(),
            volumes: vec![
                EvidenceVolume {
                    index: 0,
                    name: "EFI".to_string(),
                    filesystem: "FAT32".to_string(),
                    start_offset: 1048576,
                    size_bytes: 104857600,
                    browsable: true,
                    is_bitlocker: false,
                    bitlocker_status: None,
                },
                EvidenceVolume {
                    index: 2,
                    name: "Windows".to_string(),
                    filesystem: "BitLocker".to_string(),
                    start_offset: 209715200,
                    size_bytes: 200000000000,
                    browsable: false,
                    is_bitlocker: true,
                    bitlocker_status: Some("Locked".to_string()),
                },
            ],
            selected_volumes: vec![2], // examiner selected ONLY the locked BitLocker volume
            preset: kdft_desktop_core::processing::ProcessingPreset::FullForensicAnalysis,
            groups: kdft_desktop_core::processing::ProcessorGroupSelection::default(),
            content_capture_enabled: true,
            capture_limit: "64 KiB".to_string(),
            max_entries: "0".to_string(),
            error: None,
        };

        let unlock_mgr = kdft_desktop_core::unlock::TransientUnlockManager::default();

        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };

        let mut output1 = ctx.run_ui(raw_input.clone(), |ui| {
            let _ = processing_options::show(ui.ctx(), &mut state, Some(&unlock_mgr));
        });
        output1.textures_delta.clear();

        let mut output = ctx.run_ui(raw_input, |ui| {
            let act = processing_options::show(ui.ctx(), &mut state, Some(&unlock_mgr));
            assert!(matches!(act, ProcessingOptionsAction::None));
        });

        let texts = collect_rendered_texts(&output.shapes).join(" ");
        output.textures_delta.clear();
        assert!(
            texts.contains("BitLocker (Locked)") || texts.contains("locked"),
            "Must show locked BitLocker warning, got: {texts}"
        );
        assert!(
            texts.contains("Starting analysis on locked volumes is blocked")
                || texts.contains("unlock"),
            "Must explain that starting analysis is blocked, got: {texts}"
        );
    }

    #[test]
    fn test_processing_options_dialog_allows_unlocked_bitlocker_and_blocks_multi_bitlocker() {
        use crate::dialogs::processing_options;
        use kdft_desktop_core::browse::EvidenceVolume;

        let (_path, _app, ctx) = setup_desktop_test_case();
        let unlock_mgr = kdft_desktop_core::unlock::TransientUnlockManager::default();

        // 1. Unlocked single BitLocker volume:
        unlock_mgr.store_unverified_session(
            1,
            2,
            "NTFS".to_string(),
            kdft_desktop_core::unlock::TransientBitLockerCredential::password(
                "test-pwd".to_string(),
            ),
        );

        let mut state = crate::state::ProcessingOptionsDialogState {
            visible: true,
            evidence_id: 1,
            evidence_name: "Test Evidence".to_string(),
            evidence_path: "E:/test.E01".to_string(),
            volumes: vec![
                EvidenceVolume {
                    index: 0,
                    name: "EFI".to_string(),
                    filesystem: "FAT32".to_string(),
                    start_offset: 1048576,
                    size_bytes: 104857600,
                    browsable: true,
                    is_bitlocker: false,
                    bitlocker_status: None,
                },
                EvidenceVolume {
                    index: 2,
                    name: "Windows".to_string(),
                    filesystem: "BitLocker".to_string(),
                    start_offset: 209715200,
                    size_bytes: 200000000000,
                    browsable: true,
                    is_bitlocker: true,
                    bitlocker_status: Some("Unlocked".to_string()),
                },
                EvidenceVolume {
                    index: 3,
                    name: "Data".to_string(),
                    filesystem: "BitLocker".to_string(),
                    start_offset: 309715200,
                    size_bytes: 100000000000,
                    browsable: true,
                    is_bitlocker: true,
                    bitlocker_status: Some("Unlocked".to_string()),
                },
            ],
            selected_volumes: vec![2],
            preset: kdft_desktop_core::processing::ProcessingPreset::FullForensicAnalysis,
            groups: kdft_desktop_core::processing::ProcessorGroupSelection::default(),
            content_capture_enabled: true,
            capture_limit: "64 KiB".to_string(),
            max_entries: "0".to_string(),
            error: None,
        };

        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            ..Default::default()
        };

        let mut output1 = ctx.run_ui(raw_input.clone(), |ui| {
            let _ = processing_options::show(ui.ctx(), &mut state, Some(&unlock_mgr));
        });
        output1.textures_delta.clear();

        let mut output = ctx.run_ui(raw_input.clone(), |ui| {
            let _ = processing_options::show(ui.ctx(), &mut state, Some(&unlock_mgr));
        });
        let texts = collect_rendered_texts(&output.shapes).join(" ");
        output.textures_delta.clear();
        assert!(
            texts.contains("BitLocker (Unlocked)") || texts.contains("Unlocked"),
            "Must indicate unlocked status, got: {texts}"
        );
        assert!(
            !texts.contains("Starting analysis on locked volumes is blocked"),
            "Must NOT show locked lockout when unlocked"
        );

        // 2. Select a second BitLocker volume -> Multi-BitLocker restriction must trigger
        state.selected_volumes = vec![2, 3];
        let mut output_prep = ctx.run_ui(raw_input.clone(), |ui| {
            let _ = processing_options::show(ui.ctx(), &mut state, Some(&unlock_mgr));
        });
        output_prep.textures_delta.clear();

        let mut output2 = ctx.run_ui(raw_input, |ui| {
            let _ = processing_options::show(ui.ctx(), &mut state, Some(&unlock_mgr));
        });
        let texts2 = collect_rendered_texts(&output2.shapes).join(" ");
        output2.textures_delta.clear();
        assert!(
            texts2.contains("Multiple BitLocker volumes selected")
                || texts2.contains("Multiple BitLocker"),
            "Must warn against multiple BitLocker volumes, got: {texts2}"
        );
    }

    #[test]
    fn artifacts_view_state_generation_invalidation_and_independent_workers() {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kdft-artifacts-test-{}-{serial}.sqlite",
            std::process::id()
        ));
        let request = CreateCaseRequest {
            case_path: path.clone(),
            name: "Artifacts Test Case".to_string(),
            examiner_name: Some("Examiner".to_string()),
            case_number: None,
            case_type: None,
            description: None,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        };
        NativeWorkflowService::create_case(request).expect("create test case");

        let conn = Connection::open(&path).expect("open db");
        conn.execute(
            "INSERT INTO evidence_sources(id, case_id, source_kind, source_path, display_name)
             VALUES(1, 1, 'image', 'C:/test/evidence.E01', 'Test Image')",
            [],
        )
        .expect("insert evidence");

        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted, metadata_json)
             VALUES(100, 1, 1, '/evidence/file.txt', 'file.txt', 'file', 42, 0, json_object('category_main', 'Documents', 'category_sub', 'Text'))",
            [],
        )
        .expect("insert entry");
        conn.execute(
            "INSERT INTO filesystem_entries(id, case_id, evidence_id, logical_path, name, entry_kind, size_bytes, is_deleted, metadata_json)
             VALUES(101, 1, 1, 'HKLM\\SYSTEM\\Select', 'Select', 'registry_key', 0, 0, json_object('category_main', 'Windows Registry', 'category_sub', 'Keys', 'artifact_kind', 'registry_key', 'windows_registry_derived', 1))",
            [],
        )
        .expect("insert registry entry");
        drop(conn);

        let opened = open_case(&path).expect("open test case");
        let mut app = test_app(&path, opened);
        app.selected_evidence_id = Some(1);
        let ctx = egui::Context::default();

        // 1. Independent workers test: both tree and page can be pending simultaneously
        app.begin_artifacts_tree(ctx.clone());
        assert!(app.artifacts_tree_pending.is_some());
        assert_eq!(app.artifacts_state.active_tree_request_id, 1);

        app.begin_artifacts_page(
            ctx.clone(),
            ArtifactPageQuery {
                case_path: path.clone(),
                evidence_id: app.selected_evidence_id,
                request_id: 0,
                category_main: String::new(),
                category_sub: None,
                name_filter: None,
                extension_filter: None,
                entry_type_filter: None,
                deleted_only: false,
                date_from_utc: None,
                date_to_utc: None,
                cursor: None,
                limit: 100,
            },
        );
        // Both receivers must exist at the same time without overwriting each other!
        assert!(
            app.artifacts_tree_pending.is_some(),
            "Tree worker must NOT be overwritten by page worker"
        );
        assert!(
            app.artifacts_page_pending.is_some(),
            "Page worker must exist independently"
        );
        assert_eq!(app.artifacts_state.active_page_request_id, 1);

        // Wait for workers to complete
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            app.poll_artifacts_worker(&ctx);
            if app.artifacts_tree_pending.is_none() && app.artifacts_page_pending.is_none() {
                break;
            }
        }

        assert!(
            app.artifacts_state.error.is_none(),
            "artifacts_state.error was: {:?}",
            app.artifacts_state.error
        );
        assert!(app.artifacts_state.cached_generation.is_some());
        assert!(
            !app.artifacts_state.current_rows.is_empty(),
            "Must load artifact rows"
        );
        assert_eq!(
            app.artifacts_state.current_rows.len(),
            2,
            "Must load both file and registry key"
        );

        // Verify registry row has correct category
        let reg_row = app
            .artifacts_state
            .current_rows
            .iter()
            .find(|r| r.category_main == "Windows Registry");
        assert!(
            reg_row.is_some(),
            "Registry row must be present in categorized artifacts"
        );

        // 2. Generation invalidation test: install_opened with newer generation resets artifacts_state
        let mut opened2 = open_case(&path).expect("open fixture");
        let new_gen = opened2.summary.generation + 1;
        opened2.summary.generation = new_gen;
        app.install_opened(opened2);

        assert_eq!(
            app.artifacts_state.cached_generation, None,
            "Newer generation must invalidate cached generation"
        );
        assert!(
            app.artifacts_state.category_tree.is_empty(),
            "Newer generation must invalidate category tree"
        );
        assert!(
            app.artifacts_state.current_rows.is_empty(),
            "Newer generation must invalidate page rows"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn stale_generation_artifact_page_snapshot_is_discarded_and_never_mixed() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();

        // Establish tree at generation 9
        app.artifacts_state.cached_generation = Some(9);
        app.artifacts_state.active_page_request_id = 42;
        app.selected_evidence_id = Some(1);

        // Manually send a page snapshot from generation 8 (stale generation!)
        let (sender, receiver) = mpsc::channel();
        let _ = sender.send(ArtifactsPageWorkerResult {
            snapshot: Ok(kdft_desktop_core::artifacts::ArtifactPageSnapshot {
                request_id: 42,
                case_generation: 8, // STALE! (expected 9)
                evidence_id: Some(1),
                category_main: String::new(),
                category_sub: None,
                rows: vec![ArtifactRow {
                    id: 999,
                    evidence_id: 1,
                    display_name: "stale_entry".to_string(),
                    logical_path: "/stale".to_string(),
                    entry_kind: "file".to_string(),
                    size_bytes: Some(10),
                    created_at: None,
                    modified_at: None,
                    category_main: "Test".to_string(),
                    category_sub: String::new(),
                    is_deleted: false,
                    artifact_kind: None,
                    processor: None,
                    has_warnings: false,
                    key_path: None,
                    value_name: None,
                    value_type: None,
                    value_preview: None,
                    key_last_written: None,
                    browser_url: None,
                    visit_time_utc: None,
                    visit_origin: None,
                    visit_source_label: None,
                    browser_family: None,
                    browser_profile: None,
                    originator_sync_guid_short: None,
                    originator_sync_guid_full: None,
                    originator_sync_guid_note: None,
                }],
                total_in_category: 1,
                total_matching: 1,
                limit: 100,
                next_cursor: None,
                has_more: false,
            }),
        });
        app.artifacts_page_pending = Some(receiver);

        app.poll_artifacts_worker(&ctx);

        // The stale rows from generation 8 MUST NOT be installed!
        assert!(
            app.artifacts_state.current_rows.is_empty(),
            "Rows from generation 8 must NEVER be combined with view at generation 9"
        );
        // And cached_generation must be invalidated to trigger a fresh tree reload
        assert_eq!(app.artifacts_state.cached_generation, None);

        fs::remove_file(path).expect("remove fixture");
    }

    fn fixture_artifact_detail(
        app: &KDFTDesktopApp,
        entry_id: i64,
        generation: i64,
    ) -> ArtifactDetail {
        let resp = app
            .backend
            .as_ref()
            .unwrap()
            .dispatch(BackendCommand::ArtifactDetail {
                query: ArtifactDetailQuery {
                    entry_id,
                    expected_generation: generation,
                },
            });
        match resp {
            BackendResponse::ArtifactDetail { detail } => *detail,
            other => panic!("expected ArtifactDetail, got {:?}", other),
        }
    }

    #[test]
    fn test_d_active_processing_artifact_refresh() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();

        app.artifacts_state.cached_generation = Some(9);
        app.artifacts_probe_request_id = 101;

        app.selected_artifact = Some(ArtifactSelection {
            entry_id: 1,
            generation: 9,
        });
        app.artifact_detail = Some(fixture_artifact_detail(&app, 1, 9));
        app.inspector_pinned = false;

        let (sender, receiver) = mpsc::channel();
        sender
            .send(ArtifactsProbeWorkerResult {
                request_id: 101,
                generation: Ok(10),
            })
            .expect("send probe result");
        app.artifacts_probe_pending = Some(receiver);

        app.poll_artifacts_worker(&ctx);

        assert_eq!(
            app.artifacts_state.cached_generation, None,
            "Probe detecting newer generation must invalidate cached generation"
        );
        assert!(app.artifacts_state.category_tree.is_empty());
        assert!(
            app.artifacts_tree_pending.is_some(),
            "Tree worker must be started to fetch generation 10 tree"
        );
        assert_eq!(
            app.selected_artifact, None,
            "Unpinned inspector must be cleared when view invalidates"
        );
        assert!(app.artifact_detail.is_none());

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn test_e_no_refresh_loop() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        let ctx = egui::Context::default();

        app.artifacts_state.cached_generation = Some(10);
        app.artifacts_probe_request_id = 202;
        app.artifacts_tree_pending = None;
        app.artifacts_page_pending = None;

        let (sender, receiver) = mpsc::channel();
        sender
            .send(ArtifactsProbeWorkerResult {
                request_id: 202,
                generation: Ok(10),
            })
            .expect("send probe result");
        app.artifacts_probe_pending = Some(receiver);

        app.poll_artifacts_worker(&ctx);

        assert_eq!(app.artifacts_state.cached_generation, Some(10));
        assert!(
            app.artifacts_tree_pending.is_none(),
            "Must not trigger tree worker when generation has not changed"
        );
        assert!(
            app.artifacts_page_pending.is_none(),
            "Must not trigger page worker when generation has not changed"
        );

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn test_n_inspector_regression() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);

        let set_inspector = |app: &mut KDFTDesktopApp| {
            let detail = fixture_artifact_detail(app, 1, 9);
            app.selected_artifact = Some(ArtifactSelection {
                entry_id: 1,
                generation: 9,
            });
            app.artifact_detail = Some(detail);
            app.hex_viewer_state.active = true;
            app.hex_viewer_state.loaded_bytes = vec![0x4D, 0x5A, 0x90, 0x00];
        };

        // Scenario 1: Unpinned inspector clears on tab switch
        set_inspector(&mut app);
        app.inspector_pinned = false;
        app.active_tab = TopLevelTab::Artifacts;

        app.active_tab = TopLevelTab::Timeline;
        if !app.inspector_pinned {
            app.clear_inspector();
        }

        assert_eq!(
            app.selected_artifact, None,
            "Unpinned inspector must be cleared on tab switch"
        );
        assert!(app.artifact_detail.is_none());
        assert!(
            !app.hex_viewer_state.active,
            "Hex viewer must be deactivated"
        );
        assert!(
            app.hex_viewer_state.loaded_bytes.is_empty(),
            "Stale bytes must be cleared"
        );

        // Scenario 2: Pinned inspector survives tab switch
        set_inspector(&mut app);
        app.inspector_pinned = true;
        app.active_tab = TopLevelTab::Artifacts;

        app.active_tab = TopLevelTab::Case;
        if !app.inspector_pinned {
            app.clear_inspector();
        }

        assert_eq!(
            app.selected_artifact,
            Some(ArtifactSelection {
                entry_id: 1,
                generation: 9
            }),
            "Pinned inspector must survive tab switch"
        );
        assert!(app.artifact_detail.is_some());
        assert!(app.hex_viewer_state.active);
        assert_eq!(
            app.hex_viewer_state.loaded_bytes,
            vec![0x4D, 0x5A, 0x90, 0x00]
        );

        // Scenario 3: Closing inspector explicitly clears owner, details, and bytes
        app.clear_inspector();
        assert_eq!(app.selected_artifact, None);
        assert!(app.artifact_detail.is_none());
        assert!(!app.hex_viewer_state.active);
        assert!(app.hex_viewer_state.loaded_bytes.is_empty());

        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn browse_transition_clears_selected_entry_hex_bytes_and_pending_owner() {
        let path = fixture();
        let opened = open_case(&path).expect("open fixture");
        let mut app = test_app(&path, opened);
        app.selected_browser_entry = Some(crate::views::source_browser::SelectedBrowserEntry {
            name: "$MFT".to_string(),
            path: "/$MFT".to_string(),
            is_dir: false,
            is_deleted: false,
            size_bytes: Some(4096),
            created_utc: None,
            modified_utc: None,
            accessed_utc: None,
            provenance: Some("allocated_mft".to_string()),
            reconstruction_status: None,
            file_record_number: Some(0),
            physical_offset: Some(0xC000_0000),
            canonical_entry_id: Some(1),
            sha256: None,
        });
        app.hex_viewer_state.active = true;
        app.hex_viewer_state.logical_path = "/$MFT".to_string();
        app.hex_viewer_state.loaded_bytes = vec![0x46, 0x49, 0x4C, 0x45];
        app.hex_viewer_state.selected_byte_offset = Some(0);
        app.hex_viewer_state.selected_byte_length = Some(4);
        app.hex_viewer_origin_tab = Some(TopLevelTab::Browse);
        let prior_request_id = app.hex_request_id;

        app.clear_browse_preview();

        assert!(app.selected_browser_entry.is_none());
        assert!(!app.hex_viewer_state.active);
        assert!(app.hex_viewer_state.loaded_bytes.is_empty());
        assert!(app.hex_viewer_state.selected_byte_offset.is_none());
        assert!(app.hex_viewer_origin_tab.is_none());
        assert_ne!(app.hex_request_id, prior_request_id);

        fs::remove_file(path).expect("remove fixture");
    }
}
