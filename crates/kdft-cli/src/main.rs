#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use kdft_case::progress::{
    with_job_progress, EtaStatus, JobProgressSnapshot, JobProgressState, JobProgressTracker,
    ProgressObserver, RateStatus,
};
use kdft_case::{
    add_bookmark_item, add_evidence, analyze_signatures, case_info, create_bookmark,
    create_bookmark_folder, create_case, deep_search_page, filesystem_entry_count, global_options,
    import_browser_history, import_browser_history_for_family, list_bookmark_folders,
    list_bookmark_items, list_bookmarks, list_evidence, list_installed_resources,
    parse_archive_artifacts, parse_document_artifacts, remove_bookmark, remove_bookmark_item,
    report_data, update_global_options, AddEvidenceOptions, AnalyzeSignaturesOptions, BookmarkType,
    BrowserDatabaseDetected, CreateBookmarkItemOptions, CreateBookmarkOptions, CreateCaseOptions,
    DeepSearchCursor, DeepSearchOptions, DeepSearchResult, EvidenceKind, GlobalOptionPathUpdate,
    ImportBrowserHistoryOptions, ProcessEvidenceOptions, UpdateGlobalOptions,
};
use serde::Serialize;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(name = "kdft", version)]
#[command(about = "KDFT-DFIR command-line interface")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    Bookmark {
        #[command(subcommand)]
        command: BookmarkCommand,
    },
    Options {
        #[command(subcommand)]
        command: OptionsCommand,
    },
    Resources {
        #[command(subcommand)]
        command: ResourcesCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Search {
        #[command(subcommand)]
        command: SearchCommand,
    },
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    Create(Box<CreateCaseArgs>),
    Info(CasePathArgs),
}

#[derive(Debug, Args)]
struct CreateCaseArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    examiner: Option<String>,
    #[arg(long)]
    case_number: Option<String>,
    #[arg(long)]
    case_type: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    default_export_folder: Option<PathBuf>,
    #[arg(long)]
    temporary_folder: Option<PathBuf>,
    #[arg(long)]
    index_folder: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CasePathArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    Add(AddEvidenceArgs),
    Process(ProcessEvidenceArgs),
    SignatureAnalysis(SignatureAnalysisArgs),
    List(CasePathArgs),
}

#[derive(Debug, Args)]
struct AddEvidenceArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    path: PathBuf,
    #[arg(long, default_value = "auto")]
    kind: String,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    read_file_system: Option<bool>,
    #[arg(long = "no-read-file-system", conflicts_with = "read_file_system")]
    no_read_file_system: bool,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProcessEvidenceArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    evidence_id: i64,
    /// Maximum entries to index; 0 (the default) means unlimited - the whole
    /// selected evidence is processed.
    #[arg(long, default_value_t = 0)]
    max_entries: usize,
    /// Skip every per-file content read (fast metadata-only index). Content
    /// search stays unavailable for this evidence until re-processed.
    #[arg(long)]
    metadata_only: bool,
    /// Skip parsing .eml / RFC-822 messages into email metadata.
    #[arg(long)]
    skip_emails: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SignatureAnalysisArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    evidence_id: Option<i64>,
    /// Maximum entries to analyze; 0 (the default) means unlimited.
    #[arg(long, default_value_t = 0)]
    max_entries: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum BookmarkCommand {
    FolderCreate(CreateBookmarkFolderArgs),
    FolderList(CasePathArgs),
    Create(CreateBookmarkArgs),
    List(CasePathArgs),
    ItemAdd(AddBookmarkItemArgs),
    ItemList(ListBookmarkItemsArgs),
    Remove(RemoveBookmarkArgs),
    ItemRemove(RemoveBookmarkItemArgs),
}

#[derive(Debug, Subcommand)]
enum OptionsCommand {
    Get(CasePathArgs),
    Set(SetGlobalOptionsArgs),
}

#[derive(Debug, Args)]
struct SetGlobalOptionsArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    config_root: Option<PathBuf>,
    #[arg(long)]
    clear_config_root: bool,
    #[arg(long)]
    evidence_library_root: Option<PathBuf>,
    #[arg(long)]
    clear_evidence_library_root: bool,
    #[arg(long)]
    default_storage_root: Option<PathBuf>,
    #[arg(long)]
    clear_default_storage_root: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ResourcesCommand {
    List(CasePathArgs),
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Fast report summary. Directory trees are only built on export, so
    /// `directory_trees` is always empty here.
    Preview(CasePathArgs),
    Export(ExportReportArgs),
}

#[derive(Debug, Subcommand)]
enum SearchCommand {
    Deep(DeepSearchArgs),
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    Import(ImportHistoryArgs),
}

#[derive(Debug, Args)]
struct DeepSearchArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    query: String,
    #[arg(long)]
    evidence_id: Option<i64>,
    #[arg(long, default_value_t = true)]
    include_content: bool,
    /// Maximum results to emit; 0 follows cursor pages through the complete
    /// indexed search (default). A positive value is an explicit examiner
    /// result limit and is reported as truncated if more matches exist.
    #[arg(long, default_value_t = 0)]
    max_results: usize,
    /// Generic indexed-content bytes to consider per file (1..=4096). This
    /// cannot widen the 4,096-byte capture made during processing; complete
    /// persisted DOCX/ZIP parser text segments are searched separately.
    #[arg(long, default_value_t = 4096)]
    max_file_bytes: u64,
    /// Restrict hits to entries whose stored category contains this text.
    #[arg(long)]
    category: Option<String>,
    /// Restrict hits to these file extensions, comma separated (jpg,png,zip).
    #[arg(long, value_delimiter = ',')]
    file_types: Option<Vec<String>>,
    #[arg(long)]
    json: bool,
}

const CLI_DEEP_SEARCH_PAGE_SIZE: usize = 500;

#[derive(Debug, Serialize)]
struct DeepSearchRunSummary {
    results_returned: usize,
    complete: bool,
    truncated: bool,
    stop_reason: Option<&'static str>,
    examiner_result_limit: Option<usize>,
    continuation: Option<DeepSearchCursor>,
    coverage: Option<serde_json::Value>,
}

#[derive(Debug, Args)]
struct ImportHistoryArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    path: PathBuf,
    /// Maximum visit rows to import; 0 imports all available rows.
    #[arg(long, default_value_t = 0)]
    max_visits: usize,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ExportReportArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateBookmarkFolderArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    parent_id: Option<i64>,
    #[arg(long)]
    comment: Option<String>,
    #[arg(long, default_value_t = true)]
    show_in_report: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateBookmarkArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    folder_id: i64,
    #[arg(long = "type", default_value = "notable_file")]
    bookmark_type: String,
    #[arg(long)]
    data_type: Option<String>,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    comment: Option<String>,
    #[arg(long, default_value_t = true)]
    in_report: bool,
    #[arg(long)]
    source_ref_json: Option<String>,
    #[arg(long)]
    content_ref_json: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AddBookmarkItemArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    bookmark_id: i64,
    #[arg(long)]
    evidence_id: Option<i64>,
    #[arg(long)]
    entry_id: Option<i64>,
    #[arg(long)]
    item_order: Option<i64>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    logical_path: Option<String>,
    #[arg(long)]
    selection_offset: Option<i64>,
    #[arg(long)]
    selection_length: Option<i64>,
    #[arg(long)]
    data_preview: Option<String>,
    #[arg(long)]
    item_ref_json: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ListBookmarkItemsArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    bookmark_id: Option<i64>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RemoveBookmarkArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    bookmark_id: i64,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RemoveBookmarkItemArgs {
    #[arg(long)]
    case: PathBuf,
    #[arg(long)]
    item_id: i64,
    #[arg(long)]
    json: bool,
}

fn run_deep_search_pages(
    args: &DeepSearchArgs,
    mut emit: impl FnMut(&DeepSearchResult) -> Result<()>,
) -> Result<DeepSearchRunSummary> {
    let examiner_limit = (args.max_results > 0).then_some(args.max_results);
    let mut cursor = None;
    let mut results_returned = 0_usize;

    loop {
        let page_size = examiner_limit
            .map(|limit| {
                limit
                    .saturating_sub(results_returned)
                    .min(CLI_DEEP_SEARCH_PAGE_SIZE)
            })
            .unwrap_or(CLI_DEEP_SEARCH_PAGE_SIZE);
        if page_size == 0 {
            anyhow::bail!("internal Deep Search paging reached a zero-sized page");
        }
        let page = deep_search_page(
            &args.case,
            DeepSearchOptions {
                query: args.query.clone(),
                evidence_id: args.evidence_id,
                include_content: args.include_content,
                // The paged API treats this as a response bound only.
                max_results: page_size,
                max_file_bytes: args.max_file_bytes,
                category: args.category.clone(),
                file_types: args.file_types.clone(),
            },
            cursor,
            page_size,
        )?;
        let coverage = serde_json::to_value(&page.coverage)?;
        for result in &page.results {
            emit(result)?;
        }
        results_returned = results_returned.saturating_add(page.results.len());

        if page.complete {
            return Ok(DeepSearchRunSummary {
                results_returned,
                complete: true,
                truncated: false,
                stop_reason: None,
                examiner_result_limit: examiner_limit,
                continuation: None,
                coverage: Some(coverage),
            });
        }
        let next_cursor = page
            .next_cursor
            .context("incomplete Deep Search page did not provide a continuation")?;
        if examiner_limit.is_some_and(|limit| results_returned >= limit) {
            // A page can end exactly at a search-phase boundary (for example,
            // after the last path hit but before parsed-content inspection).
            // Probe one bounded result so an exact-size complete result set is
            // never mislabeled truncated. Keep the original cursor: the probe
            // is not emitted and a future unlimited run must resume before it.
            let probe = deep_search_page(
                &args.case,
                DeepSearchOptions {
                    query: args.query.clone(),
                    evidence_id: args.evidence_id,
                    include_content: args.include_content,
                    max_results: 1,
                    max_file_bytes: args.max_file_bytes,
                    category: args.category.clone(),
                    file_types: args.file_types.clone(),
                },
                Some(next_cursor.clone()),
                1,
            )?;
            if probe.complete && probe.results.is_empty() {
                return Ok(DeepSearchRunSummary {
                    results_returned,
                    complete: true,
                    truncated: false,
                    stop_reason: None,
                    examiner_result_limit: examiner_limit,
                    continuation: None,
                    coverage: Some(coverage),
                });
            }
            return Ok(DeepSearchRunSummary {
                results_returned,
                complete: false,
                truncated: true,
                stop_reason: Some("examiner_result_limit"),
                examiner_result_limit: examiner_limit,
                continuation: Some(next_cursor),
                coverage: Some(coverage),
            });
        }
        cursor = Some(next_cursor);
    }
}

fn execute_deep_search(args: &DeepSearchArgs) -> Result<()> {
    if args.json {
        // Stream the result array page-by-page so `--max-results 0` does not
        // require retaining an unbounded case-wide Vec merely to produce JSON.
        let stdout = io::stdout();
        let mut output = io::BufWriter::new(stdout.lock());
        output.write_all(b"{\"results\":[")?;
        let mut first = true;
        let summary = run_deep_search_pages(args, |result| {
            if !first {
                output.write_all(b",")?;
            }
            first = false;
            serde_json::to_writer(&mut output, result)?;
            Ok(())
        })?;
        output.write_all(b"],\"summary\":")?;
        serde_json::to_writer(&mut output, &summary)?;
        output.write_all(b"}\n")?;
        output.flush()?;
        return Ok(());
    }

    let summary = run_deep_search_pages(args, |result| {
        println!("{result:#?}");
        Ok(())
    })?;
    println!(
        "Deep Search: {} result(s); state={}; generic indexed content={} bytes/file; parser text=all persisted supported-parser segments.",
        summary.results_returned,
        if summary.complete { "complete" } else { "truncated" },
        summary
            .coverage
            .as_ref()
            .and_then(|value| value["generic_file_content_bytes_per_file"].as_u64())
            .unwrap_or(4096)
    );
    if summary.truncated {
        println!(
            "TRUNCATED by explicit --max-results {}. More indexed matches exist; rerun with --max-results 0 for all cursor pages.",
            summary.examiner_result_limit.unwrap_or(0)
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Case { command } => match command {
            CaseCommand::Create(args) => {
                let args = *args;
                let id = create_case(
                    &args.case,
                    CreateCaseOptions {
                        name: args.name,
                        examiner_name: args.examiner,
                        case_number: args.case_number,
                        case_type: args.case_type,
                        description: args.description,
                        default_export_folder: args.default_export_folder,
                        temporary_folder: args.temporary_folder,
                        index_folder: args.index_folder,
                    },
                )?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({ "case_id": id, "case": args.case })
                    );
                } else {
                    println!("Created case {} at {}", id, args.case.display());
                }
            }
            CaseCommand::Info(args) => {
                let info = case_info(&args.case)?;
                print_json_or_debug(args.json, &info)?;
            }
        },
        Command::Evidence { command } => match command {
            EvidenceCommand::Add(args) => {
                let evidence_path = args.path.clone();
                let add_result = add_evidence(
                    &args.case,
                    AddEvidenceOptions {
                        path: args.path,
                        kind: EvidenceKind::parse(&args.kind)?,
                        read_file_system_requested: args
                            .read_file_system
                            .unwrap_or(!args.no_read_file_system),
                        notes: args.notes,
                    },
                );
                match add_result {
                    Ok(id) => {
                        let entry_count = filesystem_entry_count(&args.case)?;
                        if args.json {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "evidence_id": id,
                                    "filesystem_entries": entry_count,
                                    "indexed": false
                                })
                            );
                        } else {
                            println!("Attached evidence source {id}; no indexing was run.");
                        }
                    }
                    Err(error) => {
                        let Some(detected) = error.downcast_ref::<BrowserDatabaseDetected>() else {
                            return Err(error);
                        };
                        let family = detected.family;
                        let profile_root = evidence_path
                            .parent()
                            .filter(|path| !path.as_os_str().is_empty())
                            .unwrap_or_else(|| Path::new("."));
                        let result = import_browser_history_for_family(
                            &args.case,
                            family,
                            ImportBrowserHistoryOptions {
                                history_path: profile_root.to_path_buf(),
                                max_visits: 0,
                                evidence_name: None,
                            },
                        )?;
                        if args.json {
                            let mut value = serde_json::to_value(&result)?;
                            let object = value.as_object_mut().with_context(|| {
                                "browser history import result was not a JSON object"
                            })?;
                            object.insert(
                                "detected".to_string(),
                                serde_json::Value::String(format!(
                                    "{}_history_database",
                                    family.as_str()
                                )),
                            );
                            println!("{}", serde_json::to_string_pretty(&value)?);
                        } else {
                            println!(
                                "Detected {} history database at {} - parsed {} records ({} visits) from profile {}.",
                                family.label(),
                                evidence_path.display(),
                                result.entries_indexed,
                                result.visits_indexed,
                                profile_root.display()
                            );
                            print_json_or_debug(false, &result)?;
                        }
                    }
                }
            }
            EvidenceCommand::Process(args) => {
                let tracker = cli_progress_tracker(args.evidence_id, "process");
                let stage_count = if args.metadata_only { 2 } else { 5 };
                tracker.start_stage(
                    if args.metadata_only {
                        "Filesystem inventory"
                    } else {
                        "Filesystem inventory and content capture"
                    },
                    1,
                    Some(stage_count),
                    "entries",
                    None,
                );
                tracker.set_evidence_id(args.evidence_id);
                tracker.set_auto_advance_database_entries(true);
                let processed = with_job_progress(&tracker, || {
                    let result = kdft_case::process_evidence_with_profile(
                        &args.case,
                        ProcessEvidenceOptions {
                            evidence_id: args.evidence_id,
                            max_entries: args.max_entries,
                        },
                        kdft_case::ProcessingProfile {
                            capture_content: !args.metadata_only,
                            parse_emails: !args.metadata_only && !args.skip_emails,
                            parse_browsers: !args.metadata_only,
                        },
                    )?;
                    tracker.set_auto_advance_database_entries(false);
                    let (archive_result, document_result, windows_artifact_result) =
                        if args.metadata_only {
                            (None, None, None)
                        } else {
                            tracker.start_stage(
                                "Archive member parsing",
                                2,
                                Some(stage_count),
                                "archives",
                                None,
                            );
                            let archives = parse_archive_artifacts(&args.case, args.evidence_id)?;
                            tracker.start_stage(
                                "Document content parsing",
                                3,
                                Some(stage_count),
                                "documents",
                                None,
                            );
                            let documents = parse_document_artifacts(&args.case, args.evidence_id)?;
                            tracker.start_stage(
                                "Windows artifact parsing",
                                4,
                                Some(stage_count),
                                "Windows artifact sources",
                                None,
                            );
                            let windows_artifacts =
                                kdft_case::windows_artifacts::parse_windows_artifacts(
                                    &args.case,
                                    args.evidence_id,
                                )?;
                            (Some(archives), Some(documents), Some(windows_artifacts))
                        };
                    Ok::<_, anyhow::Error>((
                        result,
                        archive_result,
                        document_result,
                        windows_artifact_result,
                    ))
                });
                let (result, archive_result, document_result, windows_artifact_result) =
                    match processed {
                        Ok(result) => result,
                        Err(error) => {
                            tracker.record_error(None);
                            tracker.finish(JobProgressState::Failed);
                            persist_failed_progress(&args.case, &tracker);
                            return Err(error);
                        }
                    };
                tracker.set_auto_advance_database_entries(false);
                tracker.start_stage(
                    "Finalization",
                    stage_count,
                    Some(stage_count),
                    "steps",
                    Some(1),
                );
                tracker.advance(1, Some("Process results committed".to_string()));
                let pipeline_truncated = result.truncated
                    || archive_result
                        .as_ref()
                        .is_some_and(|archives| archives.truncated)
                    || document_result
                        .as_ref()
                        .is_some_and(|documents| documents.truncated)
                    || windows_artifact_result
                        .as_ref()
                        .is_some_and(|artifacts| artifacts.status == "truncated");
                if archive_result
                    .as_ref()
                    .is_some_and(|archives| archives.truncated)
                {
                    tracker.record_truncation(
                        "archive parsing completed with partial coverage; filesystem indexing completed",
                    );
                }
                if document_result
                    .as_ref()
                    .is_some_and(|documents| documents.truncated)
                {
                    tracker.record_truncation(
                        "document parsing completed with partial coverage; filesystem indexing completed",
                    );
                }
                if windows_artifact_result
                    .as_ref()
                    .is_some_and(|artifacts| artifacts.status == "truncated")
                {
                    tracker.record_truncation(
                        "Windows artifact parsing completed with partial coverage; filesystem indexing completed",
                    );
                }
                tracker.finish(if pipeline_truncated {
                    JobProgressState::Truncated
                } else {
                    JobProgressState::Complete
                });
                kdft_case::record_job_progress_summary(
                    &args.case,
                    result.job_id,
                    &tracker.snapshot(),
                )?;
                let mut output = serde_json::to_value(&result)?;
                if let Some(archive_result) = archive_result {
                    output
                        .as_object_mut()
                        .context("process result serialized to a non-object")?
                        .insert(
                            "archive_parsing".to_string(),
                            serde_json::to_value(archive_result)?,
                        );
                }
                if let Some(document_result) = document_result {
                    output
                        .as_object_mut()
                        .context("process result serialized to a non-object")?
                        .insert(
                            "document_parsing".to_string(),
                            serde_json::to_value(document_result)?,
                        );
                }
                if let Some(windows_artifact_result) = windows_artifact_result {
                    output
                        .as_object_mut()
                        .context("process result serialized to a non-object")?
                        .insert(
                            "windows_artifact_parsing".to_string(),
                            serde_json::to_value(windows_artifact_result)?,
                        );
                }
                let final_progress = tracker.snapshot();
                apply_cli_pipeline_status(&mut output, pipeline_truncated, &final_progress)?;
                print_json_or_debug(args.json, &output)?;
            }
            EvidenceCommand::SignatureAnalysis(args) => {
                let tracker = cli_progress_tracker(args.evidence_id.unwrap_or(0), "analyze");
                tracker.start_stage("File signature analysis", 1, Some(2), "files", None);
                if let Some(evidence_id) = args.evidence_id {
                    tracker.set_evidence_id(evidence_id);
                }
                let analyzed = with_job_progress(&tracker, || {
                    analyze_signatures(
                        &args.case,
                        AnalyzeSignaturesOptions {
                            evidence_id: args.evidence_id,
                            max_entries: args.max_entries,
                        },
                    )
                });
                let result = match analyzed {
                    Ok(result) => result,
                    Err(error) => {
                        tracker.record_error(None);
                        tracker.finish(JobProgressState::Failed);
                        persist_failed_progress(&args.case, &tracker);
                        return Err(error);
                    }
                };
                tracker.start_stage("Finalization", 2, Some(2), "steps", Some(1));
                tracker.advance(1, Some("Analysis results committed".to_string()));
                tracker.finish(if result.truncated {
                    JobProgressState::Truncated
                } else {
                    JobProgressState::Complete
                });
                kdft_case::record_job_progress_summary(
                    &args.case,
                    result.job_id,
                    &tracker.snapshot(),
                )?;
                print_json_or_debug(args.json, &result)?;
            }
            EvidenceCommand::List(args) => {
                let evidence = list_evidence(&args.case)?;
                print_json_or_debug(args.json, &evidence)?;
            }
        },
        Command::Bookmark { command } => match command {
            BookmarkCommand::FolderCreate(args) => {
                let id = create_bookmark_folder(
                    &args.case,
                    args.parent_id,
                    &args.name,
                    args.comment.as_deref(),
                    args.show_in_report,
                )?;
                if args.json {
                    println!("{}", serde_json::json!({ "folder_id": id }));
                } else {
                    println!("Created bookmark folder {id}");
                }
            }
            BookmarkCommand::FolderList(args) => {
                let folders = list_bookmark_folders(&args.case)?;
                print_json_or_debug(args.json, &folders)?;
            }
            BookmarkCommand::Create(args) => {
                let source_ref_json =
                    parse_optional_json_object(args.source_ref_json, "source-ref-json")?;
                let content_ref_json =
                    parse_optional_json_object(args.content_ref_json, "content-ref-json")?;
                let id = create_bookmark(
                    &args.case,
                    CreateBookmarkOptions {
                        folder_id: args.folder_id,
                        bookmark_type: BookmarkType::parse(&args.bookmark_type)?,
                        data_type: args.data_type,
                        title: args.title,
                        examiner_comment: args.comment,
                        in_report: args.in_report,
                        source_ref_json,
                        content_ref_json,
                    },
                )?;
                if args.json {
                    println!("{}", serde_json::json!({ "bookmark_id": id }));
                } else {
                    println!("Created bookmark {id}");
                }
            }
            BookmarkCommand::List(args) => {
                let bookmarks = list_bookmarks(&args.case)?;
                print_json_or_debug(args.json, &bookmarks)?;
            }
            BookmarkCommand::ItemAdd(args) => {
                let item_ref_json =
                    parse_optional_json_object(args.item_ref_json, "item-ref-json")?;
                let created_item = add_bookmark_item(
                    &args.case,
                    CreateBookmarkItemOptions {
                        bookmark_id: args.bookmark_id,
                        evidence_id: args.evidence_id,
                        entry_id: args.entry_id,
                        item_order: args.item_order,
                        display_name: args.display_name,
                        logical_path: args.logical_path,
                        selection_offset: args.selection_offset,
                        selection_length: args.selection_length,
                        data_preview: args.data_preview,
                        item_ref_json,
                    },
                )?;
                if args.json {
                    print_json_or_debug(true, &created_item)?;
                } else {
                    println!("Added bookmark item {}", created_item.id);
                }
            }
            BookmarkCommand::ItemList(args) => {
                let items = list_bookmark_items(&args.case, args.bookmark_id)?;
                print_json_or_debug(args.json, &items)?;
            }
            BookmarkCommand::Remove(args) => {
                let result = remove_bookmark(&args.case, args.bookmark_id)?;
                print_json_or_debug(args.json, &result)?;
            }
            BookmarkCommand::ItemRemove(args) => {
                let result = remove_bookmark_item(&args.case, args.item_id)?;
                print_json_or_debug(args.json, &result)?;
            }
        },
        Command::Options { command } => match command {
            OptionsCommand::Get(args) => {
                let options = global_options(&args.case)?;
                print_json_or_debug(args.json, &options)?;
            }
            OptionsCommand::Set(args) => {
                let options = update_global_options(
                    &args.case,
                    UpdateGlobalOptions {
                        config_root: path_update(
                            args.config_root,
                            args.clear_config_root,
                            "config-root",
                        )?,
                        evidence_library_root: path_update(
                            args.evidence_library_root,
                            args.clear_evidence_library_root,
                            "evidence-library-root",
                        )?,
                        default_storage_root: path_update(
                            args.default_storage_root,
                            args.clear_default_storage_root,
                            "default-storage-root",
                        )?,
                    },
                )?;
                print_json_or_debug(args.json, &options)?;
            }
        },
        Command::Resources { command } => match command {
            ResourcesCommand::List(args) => {
                let resources = list_installed_resources(&args.case)?;
                print_json_or_debug(args.json, &resources)?;
            }
        },
        Command::Report { command } => match command {
            ReportCommand::Preview(args) => {
                let report = report_data(&args.case)?;
                print_json_or_debug(args.json, &report)?;
            }
            ReportCommand::Export(args) => {
                let report = report_data(&args.case)?;
                let rendered = kdft_case::render_report(&report);
                if let Some(parent) = args
                    .output
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("creating report directory {}", parent.display())
                    })?;
                }
                kdft_case::write_new_file_atomically(&args.output, rendered.html.as_bytes())
                    .with_context(|| format!("writing report {}", args.output.display()))?;
                // Report the standard whole-file digest alongside the embedded
                // footer prefix digest, using the bytes written to disk.
                let report_file_sha256 = kdft_case::sha256_hex(&fs::read(&args.output)?);
                // CLI and workbench exports record the same report.export audit
                // event in the case.
                kdft_case::record_report_export(
                    &args.case,
                    &args.output.to_string_lossy(),
                    &rendered.content_prefix_sha256,
                    &report_file_sha256,
                )?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "report": args.output,
                            "folders": report.folders.len(),
                            "content_prefix_sha256": rendered.content_prefix_sha256,
                            "report_file_sha256": report_file_sha256
                        })
                    );
                } else {
                    println!(
                        "Wrote report {} (file SHA-256 {report_file_sha256})",
                        args.output.display()
                    );
                }
            }
        },
        Command::Search { command } => match command {
            SearchCommand::Deep(args) => {
                execute_deep_search(&args)?;
            }
        },
        Command::History { command } => match command {
            HistoryCommand::Import(args) => {
                let result = import_browser_history(
                    &args.case,
                    ImportBrowserHistoryOptions {
                        history_path: args.path,
                        max_visits: args.max_visits,
                        evidence_name: args.name,
                    },
                )?;
                print_json_or_debug(args.json, &result)?;
            }
        },
    }
    Ok(())
}

/// Keep the CLI's top-level process contract aligned with the UI: a partial
/// optional parser pass makes the *pipeline* partial even when the filesystem
/// inventory itself completed successfully.
fn apply_cli_pipeline_status(
    output: &mut serde_json::Value,
    pipeline_truncated: bool,
    progress: &JobProgressSnapshot,
) -> Result<()> {
    let object = output
        .as_object_mut()
        .context("process result serialized to a non-object")?;
    object.insert(
        "status".to_string(),
        serde_json::Value::String(
            if pipeline_truncated {
                "truncated"
            } else {
                "completed"
            }
            .to_string(),
        ),
    );
    object.insert(
        "truncated".to_string(),
        serde_json::Value::Bool(pipeline_truncated),
    );
    object.insert(
        "progress".to_string(),
        serde_json::to_value(progress).context("serializing final process progress")?,
    );
    Ok(())
}

fn parse_optional_json_object(value: Option<String>, field: &str) -> Result<serde_json::Value> {
    let value = match value {
        Some(value) => {
            serde_json::from_str(&value).with_context(|| format!("parsing --{field} as JSON"))?
        }
        None => serde_json::json!({}),
    };
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("--{field} must be a JSON object");
    }
}

fn path_update(
    value: Option<PathBuf>,
    clear: bool,
    field: &str,
) -> Result<Option<GlobalOptionPathUpdate>> {
    match (value, clear) {
        (Some(_), true) => anyhow::bail!("--{field} conflicts with --clear-{field}"),
        (Some(value), false) => Ok(Some(GlobalOptionPathUpdate::Set(value))),
        (None, true) => Ok(Some(GlobalOptionPathUpdate::Clear)),
        (None, false) => Ok(None),
    }
}

fn cli_progress_tracker(evidence_id: i64, job_type: &str) -> JobProgressTracker {
    let observer: ProgressObserver = Arc::new(|snapshot| {
        eprintln!("{}", format_cli_progress(&snapshot));
    });
    JobProgressTracker::new(
        format!("cli-{job_type}-{}-{evidence_id}", std::process::id()),
        job_type,
        Some(observer),
    )
}

fn persist_failed_progress(case_path: &Path, tracker: &JobProgressTracker) {
    let snapshot = tracker.snapshot();
    let Some(job_id) = snapshot.job_id else {
        return;
    };
    if let Err(error) = kdft_case::record_job_progress_summary(case_path, job_id, &snapshot) {
        eprintln!("recording failed job telemetry for job {job_id} failed: {error:#}");
    }
}

fn format_cli_progress(progress: &JobProgressSnapshot) -> String {
    let state = match progress.state {
        JobProgressState::Active => "active",
        JobProgressState::Complete => "complete",
        JobProgressState::Truncated => "truncated",
        JobProgressState::Cancelled => "cancelled",
        JobProgressState::Failed => "failed",
    };
    let mut fields = vec![format!("state={state}")];
    if let Some(stage) = progress.stage_name.as_deref() {
        let position = match (progress.stage_index, progress.stage_count) {
            (Some(index), Some(count)) => format!(" ({index}/{count})"),
            (Some(index), None) => format!(" ({index})"),
            _ => String::new(),
        };
        fields.push(format!("stage={stage}{position}"));
    }
    fields.push(format!(
        "elapsed={}",
        format_cli_duration(progress.elapsed_ms)
    ));
    let processed = match progress.total_items {
        Some(total) => format!(
            "processed={}/{} {}",
            progress.processed_items, total, progress.item_unit
        ),
        None => format!(
            "processed={} {}",
            progress.processed_items, progress.item_unit
        ),
    };
    fields.push(processed);
    if let Some(percentage) = progress.percentage {
        fields.push(format!("percent={percentage:.1}%"));
    }
    if let Some(rate) = progress.rate_per_second {
        fields.push(format!("rate={rate:.1} {}/s", progress.item_unit));
    } else if progress.state == JobProgressState::Active {
        fields.push(match progress.rate_status {
            RateStatus::Calculating => "rate=calculating".to_string(),
            RateStatus::Unknown => "rate=unknown".to_string(),
            RateStatus::Available => "rate=unknown".to_string(),
        });
    }
    let eta = match progress.eta_status {
        EtaStatus::Unavailable => None,
        EtaStatus::Calculating => Some("estimated_remaining=calculating".to_string()),
        EtaStatus::Unknown => Some("estimated_remaining=unknown".to_string()),
        EtaStatus::Estimated => Some(format!(
            "estimated_remaining={}",
            format_cli_duration(progress.eta_seconds.unwrap_or(0).saturating_mul(1_000))
        )),
    };
    if let Some(eta) = eta {
        fields.push(eta);
    }
    if let Some(volume) = progress.current_volume.as_deref() {
        fields.push(format!("volume={volume}"));
    }
    if let Some(current) = progress.current_object.as_deref() {
        fields.push(format!("current={current}"));
    }
    fields.push(format!(
        "skipped={} errors={}",
        progress.skipped_count, progress.error_count
    ));
    if progress.truncation_reason_count > 0 {
        fields.push(format!(
            "truncation_reason_reports={} retained={} omitted={}",
            progress.truncation_reason_count,
            progress.truncation_reasons.len(),
            progress.truncation_reasons_omitted
        ));
        if !progress.truncation_reasons.is_empty() {
            fields.push(format!(
                "truncation_reasons={}",
                progress.truncation_reasons.join("; ")
            ));
        }
    }
    if progress.state.is_terminal() && !progress.completed_stages.is_empty() {
        fields.push(format!(
            "stage_times={}",
            progress
                .completed_stages
                .iter()
                .map(|stage| format!("{}:{}", stage.name, format_cli_duration(stage.elapsed_ms)))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    fields.join(" | ")
}

fn format_cli_duration(milliseconds: u64) -> String {
    let seconds = milliseconds / 1_000;
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn print_json_or_debug<T>(json: bool, value: &T) -> Result<()>
where
    T: serde::Serialize + std::fmt::Debug,
{
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("{value:#?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn parsed_deep_args(extra: &[&str]) -> DeepSearchArgs {
        let mut argv = vec![
            "kdft",
            "search",
            "deep",
            "--case",
            "case.kdft.sqlite",
            "--query",
            "needle",
        ];
        argv.extend_from_slice(extra);
        let cli = Cli::try_parse_from(argv).expect("Deep Search arguments should parse");
        match cli.command {
            Command::Search {
                command: SearchCommand::Deep(args),
            } => args,
            _ => panic!("expected search deep command"),
        }
    }

    #[test]
    fn deep_search_cli_defaults_to_all_and_preserves_explicit_limit() {
        let defaults = parsed_deep_args(&[]);
        assert_eq!(defaults.max_results, 0);
        assert_eq!(defaults.max_file_bytes, 4096);
        assert_eq!(parsed_deep_args(&["--max-results", "17"]).max_results, 17);
    }

    #[test]
    fn cli_process_status_marks_optional_parser_partial_at_top_level() -> Result<()> {
        let tracker = cli_progress_tracker(1, "process-test");
        tracker.finish(JobProgressState::Truncated);
        let mut output = serde_json::json!({
            "entries_indexed": 42,
            "truncated": false,
            "document_parsing": { "status": "truncated" }
        });
        apply_cli_pipeline_status(&mut output, true, &tracker.snapshot())?;
        assert_eq!(output["status"], "truncated");
        assert_eq!(output["truncated"], true);
        assert_eq!(output["progress"]["state"], "truncated");
        assert_eq!(output["entries_indexed"], 42);
        Ok(())
    }

    #[test]
    fn deep_search_cli_pages_all_results_and_discloses_examiner_limit() -> Result<()> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "kdft-cli-deep-pages-{}-{unique}",
            std::process::id()
        ));
        let evidence = root.join("evidence");
        fs::create_dir_all(&evidence)?;
        for index in 0..5 {
            fs::write(evidence.join(format!("needle-file-{index}.txt")), b"data")?;
        }
        let case = root.join("case.kdft.sqlite");
        create_case(
            &case,
            CreateCaseOptions {
                name: "CLI paged search".to_string(),
                examiner_name: None,
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )?;
        let evidence_id = add_evidence(
            &case,
            AddEvidenceOptions {
                path: evidence.clone(),
                kind: EvidenceKind::Auto,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        kdft_case::process_evidence(
            &case,
            ProcessEvidenceOptions {
                evidence_id,
                max_entries: 100,
            },
        )?;

        let mut args = DeepSearchArgs {
            case: case.clone(),
            query: "needle-file".to_string(),
            evidence_id: Some(evidence_id),
            include_content: false,
            max_results: 0,
            max_file_bytes: 4096,
            category: None,
            file_types: None,
            json: false,
        };
        let mut names = Vec::new();
        let all = run_deep_search_pages(&args, |result| {
            names.push(result.display_name.clone());
            Ok(())
        })?;
        assert!(all.complete);
        assert!(!all.truncated);
        assert_eq!(all.results_returned, 5);
        assert_eq!(names.len(), 5);

        args.max_results = 2;
        let limited = run_deep_search_pages(&args, |_| Ok(()))?;
        assert!(!limited.complete);
        assert!(limited.truncated);
        assert_eq!(limited.results_returned, 2);
        assert_eq!(limited.stop_reason, Some("examiner_result_limit"));
        assert!(limited.continuation.is_some());

        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
