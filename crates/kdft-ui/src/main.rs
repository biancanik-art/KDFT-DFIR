#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use kdft_case::progress::{
    with_job_progress, DiagnosticObserver, JobDiagnosticEvent, JobProgressSnapshot,
    JobProgressState, JobProgressTracker,
};
use kdft_case::{
    add_evidence, analyze_signatures, bookmark_indexed_folder_recursive,
    bookmark_live_folder_recursive, browser_auto_import_disclosures, carve_evidence, case_info,
    case_mutation_generation, category_entry_counts, clear_all_findings,
    count_filesystem_entries_for_timeline, create_bookmark, create_bookmark_folder, create_case,
    evidence_source_exists, evidence_tree_entry_count, export_image_file, export_image_tree,
    export_indexed_browser_profile, export_local_file, export_local_tree, filesystem_entry_by_id,
    filesystem_entry_count, filesystem_entry_disk_location, hash_evidence,
    import_browser_artifacts_into_evidence, import_browser_history,
    import_browser_history_for_family, list_bookmark_folders, list_bookmark_items, list_bookmarks,
    list_entries_by_category_filtered, list_evidence, list_evidence_tree_entries_limited,
    list_filesystem_entries_for_timeline, list_image_tree_files, list_local_tree_files,
    max_filesystem_entry_id, parse_archive_artifacts, parse_document_artifacts,
    parse_embedded_mailboxes, parse_identity_artifacts, read_filesystem_entry_bytes,
    record_live_export, record_live_export_with_source_kind, record_live_tree_export,
    record_live_tree_export_with_source_kind, record_processing_pass_failure_audit,
    record_report_export, recover_filesystem_entry, remove_bookmark, remove_bookmark_item,
    remove_evidence, render_report, report_data, report_data_with_directory_structure,
    AddEvidenceOptions, AnalyzeSignaturesOptions, BookmarkType, BrowserDatabaseDetected,
    BrowserFamily, CarveOptions, CategoryEntryCursor, CategoryEntryFilters,
    CreateBookmarkItemOptions, CreateBookmarkOptions, CreateCaseOptions, DeepSearchOptions,
    EvidenceKind, ImportBrowserArtifactsIntoEvidenceOptions, ImportBrowserHistoryOptions,
    ProcessEvidenceOptions, ReadEntryBytesOptions, RecoverEntryOptions,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_ACTIVE_CONNECTIONS: usize = 32;
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

struct ConnectionGuard {
    active: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        let mut current = active.load(Ordering::Acquire);
        loop {
            if current >= MAX_ACTIVE_CONNECTIONS {
                return None;
            }
            match active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Self {
                        active: Arc::clone(active),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn main() -> Result<()> {
    let Some(args) = ServerArgs::parse()? else {
        return Ok(());
    };
    let config = Arc::new(ServerConfig::new(args.case_path.as_deref())?);
    let (listener, port) = bind_listener(&args.host, args.port)?;
    let url_host = if args.host == "::1" {
        "[::1]"
    } else {
        args.host.as_str()
    };
    let url = format!("http://{url_host}:{port}/");
    println!("KDFT UI listening at {url}");
    if args.open {
        let _ = open_target(&url);
    }

    // One thread per connection so a long-running job (e.g. indexing a
    // multi-terabyte disk) never blocks the rest of the UI.
    let active_connections = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let Some(connection_guard) = ConnectionGuard::acquire(&active_connections) else {
                    let _ = stream.set_write_timeout(Some(HTTP_IO_TIMEOUT));
                    let _ = write_http_response(
                        &mut stream,
                        json_error(503, "too many active local UI connections"),
                    );
                    continue;
                };
                let config = Arc::clone(&config);
                std::thread::spawn(move || {
                    let _connection_guard = connection_guard;
                    if let Err(err) = handle_connection(stream, &config) {
                        eprintln!("request failed: {err:#}");
                    }
                });
            }
            Err(err) => eprintln!("connection failed: {err}"),
        }
    }
    Ok(())
}

struct ServerArgs {
    host: String,
    port: u16,
    open: bool,
    case_path: Option<PathBuf>,
}

impl ServerArgs {
    fn parse() -> Result<Option<Self>> {
        Self::parse_from(std::env::args_os().skip(1))
    }

    fn parse_from<I>(args: I) -> Result<Option<Self>>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut host = "127.0.0.1".to_string();
        let mut port = 8777_u16;
        let mut open = false;
        let mut case_path = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let arg = arg
                .to_str()
                .context("KDFT UI arguments must be valid Unicode")?;
            match arg {
                "--host" => {
                    let value = args.next().context("--host requires a value")?;
                    host = value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("--host must be valid Unicode"))?;
                }
                "--port" => {
                    let value = args.next().context("--port requires a value")?;
                    let value = value.to_str().context("--port must be valid Unicode")?;
                    port = value
                        .parse::<u16>()
                        .with_context(|| format!("invalid TCP port {value:?}"))?;
                }
                "--case" => {
                    let value = args.next().context("--case requires a value")?;
                    case_path = Some(PathBuf::from(value));
                }
                "--open" => open = true,
                "-h" | "--help" => {
                    print_server_help();
                    return Ok(None);
                }
                "-V" | "--version" => {
                    println!("kdft-ui {}", env!("CARGO_PKG_VERSION"));
                    return Ok(None);
                }
                _ => bail!("unknown KDFT UI argument {arg:?}; use --help for usage"),
            }
        }
        Ok(Some(Self {
            host,
            port,
            open,
            case_path,
        }))
    }
}

fn print_server_help() {
    println!(
        "KDFT local browser workbench\n\nUsage: kdft-ui [OPTIONS]\n\nOptions:\n  --host <HOST>  Loopback host [default: 127.0.0.1]\n  --port <PORT>  Starting TCP port [default: 8777]\n  --case <PATH>  Case opened when a browser visits the base address\n  --open         Open the workbench in the default browser\n  -h, --help     Print help\n  -V, --version  Print version"
    );
}

struct ServerConfig {
    default_case_path: String,
    default_case_pinned: bool,
    default_evidence_path: String,
    default_vhd_sample_path: String,
    default_history_path: String,
    default_report_path: String,
    workspace_root: String,
    progress: ProgressRegistry,
    auth_token: String,
    exported_reports: Mutex<HashSet<PathBuf>>,
}

impl ServerConfig {
    fn new(default_case_path: Option<&Path>) -> Result<Self> {
        let cwd = std::env::current_dir().context("reading current directory")?;
        let output = cwd.join("ui-output");
        let default_case_pinned = default_case_path.is_some();
        let default_case_path = default_case_path
            .map(|path| {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    cwd.join(path)
                }
            })
            .unwrap_or_else(|| output.join("workbench.kdft.sqlite"));
        Ok(Self {
            default_case_path: default_case_path.to_string_lossy().into_owned(),
            default_case_pinned,
            default_evidence_path: cwd
                .join("testdata")
                .join("smoke-evidence")
                .to_string_lossy()
                .into_owned(),
            default_vhd_sample_path: output
                .join("fat-partition-smoke.vhd")
                .to_string_lossy()
                .into_owned(),
            default_history_path: default_history_path(),
            default_report_path: output
                .join("quick-report.html")
                .to_string_lossy()
                .into_owned(),
            workspace_root: cwd.to_string_lossy().into_owned(),
            progress: ProgressRegistry::default(),
            auth_token: random_auth_token()?,
            exported_reports: Mutex::new(HashSet::new()),
        })
    }
}

fn random_auth_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).context("generating local UI authentication token")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

const MAX_RETAINED_PROGRESS_JOBS: usize = 64;

#[derive(Default)]
struct ProgressRegistry {
    state: Mutex<ProgressRegistryState>,
}

#[derive(Default)]
struct ProgressRegistryState {
    next_sequence: u64,
    jobs: HashMap<String, RegisteredProgress>,
}

struct RegisteredProgress {
    sequence: u64,
    tracker: JobProgressTracker,
    diagnostic_log_path: Option<PathBuf>,
}

impl ProgressRegistry {
    fn start(
        &self,
        operation_id: &str,
        job_type: &str,
        diagnostic_observer: Option<DiagnosticObserver>,
        diagnostic_log_path: Option<PathBuf>,
    ) -> Result<JobProgressTracker> {
        validate_progress_id(operation_id)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .jobs
            .get(operation_id)
            .is_some_and(|registered| !registered.tracker.snapshot().state.is_terminal())
        {
            bail!("a progress operation with this id is already active");
        }
        if state.jobs.len() >= MAX_RETAINED_PROGRESS_JOBS {
            let removable = state
                .jobs
                .iter()
                .filter(|(_, registered)| registered.tracker.snapshot().state.is_terminal())
                .min_by_key(|(_, registered)| registered.sequence)
                .map(|(id, _)| id.clone());
            if let Some(removable) = removable {
                state.jobs.remove(&removable);
            } else {
                bail!("too many progress operations are active");
            }
        }
        state.next_sequence = state.next_sequence.saturating_add(1);
        let sequence = state.next_sequence;
        let tracker = JobProgressTracker::new_with_diagnostic_observer(
            operation_id,
            job_type,
            None,
            diagnostic_observer,
        );
        state.jobs.insert(
            operation_id.to_string(),
            RegisteredProgress {
                sequence,
                tracker: tracker.clone(),
                diagnostic_log_path,
            },
        );
        Ok(tracker)
    }

    fn snapshot(&self, operation_id: &str) -> Result<Option<JobProgressSnapshot>> {
        validate_progress_id(operation_id)?;
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(state
            .jobs
            .get(operation_id)
            .map(|registered| registered.tracker.snapshot()))
    }

    fn diagnostic_log_path(&self, operation_id: &str) -> Result<Option<PathBuf>> {
        validate_progress_id(operation_id)?;
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(state
            .jobs
            .get(operation_id)
            .and_then(|registered| registered.diagnostic_log_path.clone()))
    }
}

fn validate_progress_id(operation_id: &str) -> Result<()> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("progress_id must be 1-128 ASCII letters, digits, hyphens, or underscores");
    }
    Ok(())
}

#[derive(Deserialize)]
struct CreateCaseRequest {
    case_path: String,
    name: String,
    examiner: Option<String>,
    case_number: Option<String>,
    case_type: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
struct AddEvidenceRequest {
    case_path: String,
    path: String,
    kind: Option<String>,
    read_file_system: Option<bool>,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct ProcessEvidenceRequest {
    case_path: String,
    evidence_id: i64,
    max_entries: Option<usize>,
    progress_id: Option<String>,
    // Existing evidence is processed additively by default. Initial attach
    // forces a file-system index; an examiner must explicitly select this
    // option to discard and rebuild an existing snapshot.
    reindex_filesystem: Option<bool>,
    // Processing options (professional-suite style). Omitted fields keep the
    // established defaults so existing API callers remain compatible.
    capture_content: Option<bool>,
    parse_emails: Option<bool>,
    parse_browsers: Option<bool>,
    parse_identities: Option<bool>,
    /// Parse indexed ZIP packages into provenance-linked member records.
    parse_archives: Option<bool>,
    /// Extract searchable text from indexed DOCX packages.
    parse_documents: Option<bool>,
    /// Parse supported indexed Windows artifacts (LNK, Jump Lists, Prefetch,
    /// EVTX, and USN Journal streams).
    parse_windows_artifacts: Option<bool>,
    run_hash: Option<bool>,
    run_file_hash: Option<bool>,
    run_signature_analysis: Option<bool>,
    run_carve: Option<bool>,
    carve_max_scan_bytes: Option<u64>,
    carve_max_files: Option<usize>,
}

#[derive(Deserialize)]
struct AnalyzeSignaturesRequest {
    case_path: String,
    evidence_id: Option<i64>,
    max_entries: Option<usize>,
}

#[derive(Deserialize)]
struct RemoveEvidenceRequest {
    case_path: String,
    evidence_id: i64,
}

#[derive(Deserialize)]
struct CarveEvidenceRequest {
    case_path: String,
    evidence_id: i64,
    max_scan_bytes: Option<u64>,
    max_files: Option<usize>,
}

#[derive(Deserialize)]
struct RecoverEntryRequest {
    case_path: String,
    entry_id: i64,
    output_path: String,
}

#[derive(Deserialize)]
struct OpenEntryRequest {
    case_path: String,
    entry_id: i64,
    #[serde(default)]
    acknowledge_host_app_risk: bool,
}

#[derive(Deserialize)]
struct DeepSearchRequest {
    case_path: String,
    query: String,
    evidence_id: Option<i64>,
    include_content: Option<bool>,
    #[serde(default, deserialize_with = "lenient_opt_usize")]
    max_results: Option<usize>,
    cursor: Option<kdft_case::DeepSearchCursor>,
    #[serde(default, deserialize_with = "lenient_opt_u64")]
    max_file_bytes: Option<u64>,
    category: Option<String>,
    /// Comma-separated extensions, e.g. "jpg,png,zip".
    file_types: Option<String>,
}

#[derive(Deserialize)]
struct RawSearchRequest {
    case_path: String,
    evidence_id: i64,
    query: String,
    #[serde(default, deserialize_with = "lenient_opt_usize")]
    max_results: Option<usize>,
    cursor: Option<kdft_case::RawSearchCursor>,
    /// 0 means unlimited (scan the whole evidence source).
    #[serde(default, deserialize_with = "lenient_opt_u64")]
    max_scan_bytes: Option<u64>,
}

// Examiner-typed limits arrive as arbitrary JSON numbers; a value big enough
// round-trips through JavaScript as scientific notation (5e+21), which a plain
// usize/u64 field rejects and that used to fail the entire search request.
// Saturate instead of erroring - every consumer clamps to the range it honors
// (content bytes are limited to the bytes actually indexed). Search result
// counts are response-page sizes, not coverage caps; a continuation retrieves
// every later match. Non-numbers and negatives fall back to None so the
// handler default applies.
fn lenient_json_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(unsigned) = value.as_u64() {
        return Some(unsigned);
    }
    let float = value.as_f64()?;
    if !float.is_finite() || float < 0.0 {
        return None;
    }
    if float >= u64::MAX as f64 {
        return Some(u64::MAX);
    }
    Some(float as u64)
}

fn lenient_opt_u64<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.as_ref().and_then(lenient_json_u64))
}

fn lenient_opt_usize<'de, D>(deserializer: D) -> std::result::Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value
        .as_ref()
        .and_then(lenient_json_u64)
        .map(|number| usize::try_from(number).unwrap_or(usize::MAX)))
}

#[derive(Deserialize)]
struct ImportHistoryRequest {
    case_path: String,
    history_path: String,
    max_visits: Option<usize>,
    evidence_name: Option<String>,
}

#[derive(Deserialize)]
struct ImportHistoryFromImageRequest {
    case_path: String,
    evidence_id: i64,
    volume: usize,
    /// Absolute path (within the image volume) to the browser profile folder
    /// - e.g. a Firefox profile directory or a Chromium "Default"/"Profile N"
    ///   directory. Must be a folder, not a single file, since the parsers need
    ///   several co-located files (History/Login Data/Cookies, or
    ///   places.sqlite/cookies.sqlite/logins.json).
    image_path: String,
    max_visits: Option<usize>,
    evidence_name: Option<String>,
}

#[derive(Deserialize)]
struct QuickBookmarkRequest {
    case_path: String,
    folder_name: Option<String>,
    title: Option<String>,
    comment: Option<String>,
    bookmark_type: Option<String>,
    data_type: Option<String>,
    evidence_id: Option<i64>,
    entry_id: Option<i64>,
    display_name: Option<String>,
    logical_path: Option<String>,
    selection_offset: Option<i64>,
    selection_length: Option<i64>,
    data_preview: Option<String>,
    item_ref_json: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RemoveBookmarkRequest {
    case_path: String,
    bookmark_id: i64,
}

#[derive(Deserialize)]
struct BulkBookmarkRequest {
    case_path: String,
    folder_name: Option<String>,
    title: Option<String>,
    comment: Option<String>,
    bookmark_type: Option<String>,
    data_type: Option<String>,
    entry_ids: Vec<i64>,
}

#[derive(Deserialize)]
struct RemoveBookmarkItemRequest {
    case_path: String,
    item_id: i64,
}

#[derive(Deserialize)]
struct RemoveBookmarkFolderRequest {
    case_path: String,
    folder_id: i64,
}

#[derive(Deserialize)]
struct BookmarkFolderRecursiveIndexedRequest {
    case_path: String,
    folder_name: Option<String>,
    title: Option<String>,
    comment: Option<String>,
    evidence_id: i64,
    logical_path: String,
    max_entries: Option<usize>,
}

#[derive(Deserialize)]
struct BookmarkFolderRecursiveLiveRequest {
    case_path: String,
    folder_name: Option<String>,
    title: Option<String>,
    comment: Option<String>,
    evidence_id: i64,
    volume: usize,
    path: String,
    max_entries: Option<usize>,
}

#[derive(Deserialize)]
struct ClearFindingsRequest {
    case_path: String,
}

#[derive(Deserialize)]
struct ExportReportRequest {
    case_path: String,
    output_path: String,
}

#[derive(Deserialize)]
struct RecategorizeRequest {
    case_path: String,
}

#[derive(Serialize)]
struct UiState {
    case: kdft_case::CaseInfo,
    evidence: Vec<kdft_case::EvidenceSource>,
    entries: Vec<kdft_case::FilesystemEntry>,
    entries_truncated: bool,
    entries_limit: usize,
    /// Exact per-category counts from SQL. Populated when the compact Entries
    /// snapshot cannot represent Categories completely (because physical rows
    /// were paged or parser-derived records exist only in Categories).
    category_counts: Vec<kdft_case::CategoryCount>,
    folders: Vec<kdft_case::BookmarkFolder>,
    bookmarks: Vec<kdft_case::Bookmark>,
    items: Vec<kdft_case::BookmarkItem>,
    entry_count: i64,
    report: kdft_case::ReportData,
}

#[derive(Serialize)]
struct FsListing {
    path: String,
    parent: Option<String>,
    roots: Vec<String>,
    entries: Vec<FsEntry>,
}

#[derive(Serialize)]
struct FsEntry {
    name: String,
    path: String,
    kind: String,
    size_bytes: Option<u64>,
}

#[derive(Serialize)]
struct PickResult {
    path: Option<String>,
}

#[derive(Serialize)]
struct QuickBookmarkResponse {
    folder_id: i64,
    bookmark_id: i64,
    item: kdft_case::BookmarkItem,
}

struct HttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
}

fn bind_listener(host: &str, port: u16) -> Result<(TcpListener, u16)> {
    if !matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "::1" | "localhost"
    ) {
        bail!("the KDFT UI can bind only to a loopback host (127.0.0.1, ::1, or localhost)");
    }
    for offset in 0..25_u16 {
        let candidate = port.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind((host, candidate)) {
            return Ok((listener, candidate));
        }
    }
    bail!("could not bind local UI server starting at {host}:{port}");
}

fn handle_connection(mut stream: TcpStream, config: &ServerConfig) -> Result<()> {
    stream
        .set_read_timeout(Some(HTTP_IO_TIMEOUT))
        .context("setting HTTP read timeout")?;
    stream
        .set_write_timeout(Some(HTTP_IO_TIMEOUT))
        .context("setting HTTP write timeout")?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            return write_http_response(
                &mut stream,
                json_error(400, &format!("invalid HTTP request: {error:#}")),
            );
        }
    };
    let local_port = stream
        .local_addr()
        .context("reading local HTTP address")?
        .port();
    if let Err(response) = authorize_request(&request, config, local_port) {
        return write_http_response(&mut stream, response);
    }
    let response = route_request(&request, config);
    write_http_response(&mut stream, response)
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    read_http_request_from(stream)
}

fn read_bounded_line<R: BufRead>(reader: &mut R, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    let read = reader
        .take((maximum + 1) as u64)
        .read_until(b'\n', &mut line)
        .with_context(|| format!("reading HTTP {label}"))?;
    if read > maximum {
        bail!("HTTP {label} exceeds {maximum} bytes");
    }
    Ok(line)
}

fn read_http_request_from<R: Read>(source: R) -> Result<HttpRequest> {
    let mut reader = BufReader::new(source);
    let request_line = read_bounded_line(&mut reader, MAX_REQUEST_LINE_BYTES, "request line")?;
    let request_line = std::str::from_utf8(&request_line).context("request line is not UTF-8")?;
    if request_line.trim().is_empty() {
        bail!("empty HTTP request");
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("HTTP method is missing")?.to_string();
    let target = parts.next().context("HTTP target is missing")?.to_string();
    let version = parts.next().context("HTTP version is missing")?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        bail!("malformed or unsupported HTTP request line");
    }
    if !matches!(method.as_str(), "GET" | "POST") || !target.starts_with('/') {
        bail!("unsupported HTTP method or target");
    }
    let mut headers = HashMap::new();
    let mut total_header_bytes = 0usize;
    loop {
        let line = read_bounded_line(&mut reader, MAX_HEADER_LINE_BYTES, "header line")?;
        if line.is_empty() {
            bail!("unexpected EOF in HTTP headers");
        }
        total_header_bytes = total_header_bytes
            .checked_add(line.len())
            .context("HTTP header size overflow")?;
        if total_header_bytes > MAX_HEADER_BYTES {
            bail!("HTTP headers exceed {MAX_HEADER_BYTES} bytes");
        }
        let line = std::str::from_utf8(&line).context("HTTP header is not UTF-8")?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let (name, value) = trimmed.split_once(':').context("malformed HTTP header")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("invalid HTTP header name");
        }
        let name = name.to_ascii_lowercase();
        if headers
            .insert(name.clone(), value.trim().to_string())
            .is_some()
        {
            bail!("duplicate HTTP header: {name}");
        }
    }
    if headers.contains_key("transfer-encoding") {
        bail!("Transfer-Encoding is not supported");
    }
    let content_length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .context("invalid Content-Length header")?,
        None => 0,
    };
    if content_length > MAX_REQUEST_BODY_BYTES {
        bail!("HTTP request body exceeds {MAX_REQUEST_BODY_BYTES} bytes");
    }
    if method == "GET" && content_length != 0 {
        bail!("GET requests cannot contain a body");
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .context("reading HTTP request body")?;
    }
    Ok(HttpRequest {
        method,
        target,
        headers,
        body,
    })
}

fn loopback_host_matches(host: &str, local_port: u16) -> bool {
    let normalized = host.trim().to_ascii_lowercase();
    if normalized == format!("localhost:{local_port}") {
        return true;
    }
    normalized
        .parse::<SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback() && address.port() == local_port)
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn request_cookie<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.headers.get("cookie")?.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn authorize_request(
    request: &HttpRequest,
    config: &ServerConfig,
    local_port: u16,
) -> std::result::Result<(), HttpResponse> {
    let Some(host) = request.headers.get("host") else {
        return Err(json_error(400, "Host header is required"));
    };
    if !loopback_host_matches(host, local_port) {
        return Err(json_error(403, "request Host is not the local KDFT server"));
    }
    if let Some(origin) = request.headers.get("origin") {
        let expected = format!("http://{}", host.to_ascii_lowercase());
        if origin.to_ascii_lowercase() != expected {
            return Err(json_error(403, "cross-origin requests are not allowed"));
        }
    }

    let (path, _) = split_target(&request.target);
    if matches!(path.as_str(), "/" | "/api/health" | "/favicon.ico") {
        return Ok(());
    }
    let authorized = request_cookie(request, "KDFT-Auth")
        .is_some_and(|token| constant_time_equal(token, &config.auth_token));
    if !authorized {
        return Err(json_error(403, "local UI authentication failed"));
    }
    Ok(())
}

#[cfg(test)]
mod http_security_tests {
    use super::*;
    use std::io::Cursor;

    fn request(
        config: &ServerConfig,
        host: &str,
        origin: Option<&str>,
        token: bool,
    ) -> HttpRequest {
        let mut headers = HashMap::from([("host".to_string(), host.to_string())]);
        if let Some(origin) = origin {
            headers.insert("origin".to_string(), origin.to_string());
        }
        if token {
            headers.insert(
                "cookie".to_string(),
                format!("KDFT-Auth={}", config.auth_token),
            );
        }
        HttpRequest {
            method: "POST".to_string(),
            target: "/api/state".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn bounded_http_parser_rejects_oversized_or_ambiguous_requests() {
        let too_large = format!(
            "POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:8777\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BODY_BYTES + 1
        );
        assert!(read_http_request_from(Cursor::new(too_large)).is_err());

        let duplicate = b"POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:8777\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert!(read_http_request_from(Cursor::new(duplicate)).is_err());

        let chunked = b"POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:8777\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(read_http_request_from(Cursor::new(chunked)).is_err());
    }

    #[test]
    fn http_parser_preserves_valid_headers_and_body() {
        let bytes =
            b"POST /api/state HTTP/1.1\r\nHost: 127.0.0.1:8777\r\nContent-Length: 2\r\n\r\n{}";
        let parsed = read_http_request_from(Cursor::new(bytes)).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.headers["host"], "127.0.0.1:8777");
        assert_eq!(parsed.body, b"{}");
    }

    #[test]
    fn api_requires_local_host_same_origin_and_process_token() {
        let config = ServerConfig::new(None).unwrap();
        assert!(authorize_request(
            &request(
                &config,
                "127.0.0.1:8777",
                Some("http://127.0.0.1:8777"),
                true
            ),
            &config,
            8777
        )
        .is_ok());
        assert!(authorize_request(
            &request(&config, "evil.example:8777", None, true),
            &config,
            8777
        )
        .is_err());
        assert!(authorize_request(
            &request(&config, "127.0.0.1:8777", Some("http://evil.example"), true),
            &config,
            8777
        )
        .is_err());
        assert!(authorize_request(
            &request(&config, "127.0.0.1:8777", None, false),
            &config,
            8777
        )
        .is_err());
    }

    #[test]
    fn listener_rejects_non_loopback_bind_and_connections_are_bounded() {
        assert!(bind_listener("0.0.0.0", 8777).is_err());
        let counter = Arc::new(AtomicUsize::new(0));
        let guards = (0..MAX_ACTIVE_CONNECTIONS)
            .map(|_| ConnectionGuard::acquire(&counter).unwrap())
            .collect::<Vec<_>>();
        assert!(ConnectionGuard::acquire(&counter).is_none());
        drop(guards);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }
}

fn route_request(request: &HttpRequest, config: &ServerConfig) -> HttpResponse {
    let (path, query) = split_target(&request.target);
    match (request.method.as_str(), path.as_str()) {
        ("GET", "/") => {
            let mut response = html_response(index_html(config));
            response.headers.push((
                "Set-Cookie",
                format!(
                    "KDFT-Auth={}; Path=/; HttpOnly; SameSite=Strict",
                    config.auth_token
                ),
            ));
            response
        }
        ("GET", "/api/health") => json_ok(json!({ "status": "ok" })),
        ("GET", "/api/pick") => api_response(api_pick_path(&query)),
        ("GET", "/api/jobs/progress") => api_response(api_job_progress(&query, config)),
        ("GET", "/api/fs/list") => api_response(api_fs_list(&query)),
        ("GET", "/api/image/volumes") => api_response(api_image_volumes(&query)),
        ("GET", "/api/image/dir") => api_response(api_image_dir(&query)),
        ("GET", "/api/image/bytes") => api_response(api_image_bytes(&query)),
        ("GET", "/api/image/find") => api_response(api_image_find(&query)),
        ("POST", "/api/image/export") => api_response(api_image_export(&request.body)),
        ("POST", "/api/image/export-tree") => api_response(api_image_export_tree(&request.body)),
        ("POST", "/api/image/bitlocker/unlock/list") => {
            api_response(api_bitlocker_unlock_list(&request.body))
        }
        ("POST", "/api/image/bitlocker/unlock/bytes") => {
            api_response(api_bitlocker_unlock_bytes(&request.body))
        }
        ("GET", "/api/entries/dir") => api_response(api_entries_dir(&query)),
        ("GET", "/api/entry") => api_response(api_entry_lookup(&query)),
        ("GET", "/api/entry/disk-location") => api_response(api_entry_disk_location(&query)),
        ("GET", "/api/entries/category") => api_response(api_entries_category(&query)),
        ("GET", "/api/state") => api_response(api_state(&query)),
        ("GET", "/api/timeline/entries") => api_response(api_timeline_entries(&query)),
        ("GET", "/api/entry/bytes") => api_response(api_entry_bytes(&query)),
        ("GET", "/api/entry/raw") => match api_entry_raw(&query) {
            Ok((content_type, body)) => HttpResponse {
                status: 200,
                reason: "OK",
                content_type,
                body,
                headers: Vec::new(),
            },
            Err(err) => json_error(400, &format!("{err:#}")),
        },
        ("GET", "/api/image/raw") => match api_image_raw(&query) {
            Ok((content_type, body)) => HttpResponse {
                status: 200,
                reason: "OK",
                content_type,
                body,
                headers: Vec::new(),
            },
            Err(err) => json_error(400, &format!("{err:#}")),
        },
        ("POST", "/api/case/create") => api_response(api_create_case(&request.body)),
        ("POST", "/api/evidence/add") => api_response(api_add_evidence(&request.body)),
        ("POST", "/api/evidence/remove") => api_response(api_remove_evidence(&request.body)),
        ("POST", "/api/evidence/hash") => api_response(api_hash_evidence(&request.body)),
        ("POST", "/api/evidence/carve") => api_response(api_carve_evidence(&request.body)),
        ("POST", "/api/evidence/process") => {
            api_response(api_process_evidence(&request.body, config))
        }
        ("POST", "/api/evidence/run-processors") => {
            api_response(api_run_processors(&request.body, config))
        }
        ("POST", "/api/evidence/parse-browsers") => api_response(api_parse_browsers(&request.body)),
        ("POST", "/api/evidence/analyze-signatures") => {
            api_response(api_analyze_signatures(&request.body))
        }
        ("POST", "/api/entry/recover") => api_response(api_recover_entry(&request.body)),
        ("POST", "/api/entry/open") => api_response(api_open_entry(&request.body)),
        ("POST", "/api/history/import") => api_response(api_import_history(&request.body)),
        ("POST", "/api/history/import-from-image") => {
            api_response(api_import_history_from_image(&request.body))
        }
        ("POST", "/api/search/deep") => api_response(api_deep_search(&request.body)),
        ("POST", "/api/search/raw") => api_response(api_raw_search(&request.body)),
        ("POST", "/api/bookmark/quick") => api_response(api_quick_bookmark(&request.body)),
        ("POST", "/api/bookmark/remove") => api_response(api_remove_bookmark(&request.body)),
        ("POST", "/api/bookmark/bulk") => api_response(api_bulk_bookmark(&request.body)),
        ("POST", "/api/bookmark/item/remove") => {
            api_response(api_remove_bookmark_item(&request.body))
        }
        ("POST", "/api/bookmark/folder/remove") => {
            api_response(api_remove_bookmark_folder(&request.body))
        }
        ("POST", "/api/bookmark/folder-recursive-indexed") => {
            api_response(api_bookmark_folder_recursive_indexed(&request.body))
        }
        ("POST", "/api/bookmark/folder-recursive-live") => {
            api_response(api_bookmark_folder_recursive_live(&request.body))
        }
        ("POST", "/api/findings/clear") => api_response(api_clear_findings(&request.body)),
        ("POST", "/api/case/recategorize") => api_response(api_recategorize(&request.body)),
        ("POST", "/api/report/export") => api_response(api_export_report(&request.body, config)),
        ("POST", "/api/report/open") => api_response(api_open_report(&request.body, config)),
        ("GET", "/favicon.ico") => HttpResponse {
            status: 204,
            reason: "No Content",
            content_type: "text/plain; charset=utf-8",
            body: Vec::new(),
            headers: Vec::new(),
        },
        _ => json_error(404, "not found"),
    }
}

fn api_state(query: &HashMap<String, String>) -> Result<UiState> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    // Loading state is a pure read: no stale-finding cleanup here (it writes and
    // ran on every refresh); cleanup happens on bookmark/process actions.
    // Cap entries shipped to the browser. Loading hundreds of thousands of
    // entries into one page hangs it; beyond the cap the examiner uses the
    // lazy indexed tree, Live browse, category pages, or Deep Search - all of
    // which fetch their own data. 5,000 inline entries measured ~14.6 MB /
    // ~4 s on every load of a 119k-entry case while only feeding the initial
    // flat grid; 500 keeps small cases fully inline and big cases fast.
    const STATE_ENTRY_LIMIT: usize = 500;
    let database_entry_count = filesystem_entry_count(&case_path)?;
    let entry_count = evidence_tree_entry_count(&case_path)?;
    let entries = list_evidence_tree_entries_limited(&case_path, None, Some(STATE_ENTRY_LIMIT))?;
    let entries_truncated = entry_count as usize > entries.len();
    let category_counts = if database_entry_count as usize > entries.len() {
        cached_category_counts(&case_path, database_entry_count)?
    } else {
        Vec::new()
    };
    Ok(UiState {
        case: case_info(&case_path)?,
        evidence: list_evidence(&case_path)?,
        entries,
        entries_truncated,
        entries_limit: STATE_ENTRY_LIMIT,
        category_counts,
        folders: list_bookmark_folders(&case_path)?,
        bookmarks: list_bookmarks(&case_path)?,
        items: list_bookmark_items(&case_path, None)?,
        entry_count,
        report: report_data(&case_path)?,
    })
}

fn api_job_progress(
    query: &HashMap<String, String>,
    config: &ServerConfig,
) -> Result<serde_json::Value> {
    let operation_id = query
        .get("progress_id")
        .map(String::as_str)
        .context("progress_id query parameter is required")?;
    match config.progress.snapshot(operation_id)? {
        Some(snapshot) => {
            let mut value = serde_json::to_value(snapshot).context("serializing job progress")?;
            if let Some(path) = config.progress.diagnostic_log_path(operation_id)? {
                value
                    .as_object_mut()
                    .context("job progress serialized to a non-object")?
                    .insert(
                        "diagnostic_log_path".to_string(),
                        serde_json::json!(path.to_string_lossy()),
                    );
            }
            Ok(value)
        }
        None => bail!("progress operation was not found"),
    }
}

#[derive(Serialize)]
struct TimelineEntriesResponse {
    entries: Vec<kdft_case::FilesystemEntry>,
    entry_count: i64,
    truncated: bool,
}

/// Dedicated entry source for "Build timeline", separate from `/api/state`'s
/// `STATE_ENTRY_LIMIT` (500) - that cap exists because shipping the FULL
/// entry list on every page load hangs the browser tab for huge cases, but
/// Timeline is one deliberate, occasional click, not a per-load fetch, so it
/// can afford a much higher default and does not need to piggyback on
/// whatever the examiner happened to have already scrolled/browsed into
/// client-side state.
const TIMELINE_DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Shared "0 means no limit" resolution. Omitting `max_entries` also yields
/// the public zero sentinel, so downstream walkers can distinguish unlimited
/// traversal from a positive examiner-supplied limit.
fn resolve_unlimited_max_entries(requested: Option<usize>) -> usize {
    requested.unwrap_or(0)
}

fn api_timeline_entries(query: &HashMap<String, String>) -> Result<TimelineEntriesResponse> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    // 0 means "no limit at all" - Timeline building only reads the already-
    // indexed case database, it never touches the evidence, so unlike
    // processing there is no real safety reason to force a ceiling on it.
    let max_entries = match query
        .get("max_entries")
        .and_then(|value| value.parse::<usize>().ok())
    {
        Some(0) => None,
        Some(value) => Some(value),
        None => Some(TIMELINE_DEFAULT_MAX_ENTRIES),
    };
    // Optional inclusive RFC3339 date-range bounds (examiner-picked in the
    // Timeline tab before "Build timeline"). When present, filtering happens
    // in SQL across every known timestamp field so large cases don't pay for
    // shipping + client-side-scanning the whole entry table just to keep a
    // narrow window - see list_filesystem_entries_for_timeline.
    let from = query
        .get("from")
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    let to = query
        .get("to")
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    let time_range = match (from, to) {
        (Some(from), Some(to)) => Some((from, to)),
        _ => None,
    };
    let entries = list_filesystem_entries_for_timeline(&case_path, max_entries, time_range)?;
    let entry_count = if time_range.is_some() {
        count_filesystem_entries_for_timeline(&case_path, time_range)?
    } else {
        filesystem_entry_count(&case_path)?
    };
    let truncated = entry_count as usize > entries.len();
    Ok(TimelineEntriesResponse {
        entries,
        entry_count,
        truncated,
    })
}

/// Cached exact category counts for large (truncated) cases. The SQL GROUP BY
/// scans every row's metadata_json (~2s on a 360k-entry case), so the result is
/// cached per case path. Count/max-id catch row-set changes and the monotonic
/// case mutation generation catches in-place recategorization/metadata edits.
fn cached_category_counts(
    case_path: &Path,
    entry_count: i64,
) -> Result<Vec<kdft_case::CategoryCount>> {
    struct CacheEntry {
        entry_count: i64,
        max_entry_id: i64,
        mutation_generation: i64,
        counts: Vec<kdft_case::CategoryCount>,
    }
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, CacheEntry>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
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
            CacheEntry {
                entry_count,
                max_entry_id,
                mutation_generation,
                counts: counts.clone(),
            },
        );
    }
    Ok(counts)
}

fn api_entry_bytes(query: &HashMap<String, String>) -> Result<kdft_case::EntryBytes> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let entry_id = query_i64(query, "entry_id")?;
    let offset = query_u64(query, "offset")?.unwrap_or(0);
    let length = query_usize(query, "length")?.unwrap_or(512);
    read_filesystem_entry_bytes(
        &case_path,
        ReadEntryBytesOptions {
            entry_id,
            offset,
            length,
        },
    )
}

fn api_entry_disk_location(
    query: &HashMap<String, String>,
) -> Result<kdft_case::EntryDiskLocation> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let entry_id = query_i64(query, "entry_id")?;
    filesystem_entry_disk_location(&case_path, entry_id)
}

/// Bounded raw preview used by the picture thumbnail grid. Serves the entry's leading bytes
/// with a sniffed image content type; refuses entries that do not start with a known image
/// signature so this endpoint cannot be used to dump arbitrary evidence bytes to the browser.
const RAW_PREVIEW_DEFAULT_BYTES: usize = 2 * 1024 * 1024;
const RAW_PREVIEW_MAX_BYTES: usize = 8 * 1024 * 1024;

fn api_entry_raw(query: &HashMap<String, String>) -> Result<(&'static str, Vec<u8>)> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let entry_id = query_i64(query, "entry_id")?;
    let length = query_usize(query, "length")?
        .unwrap_or(RAW_PREVIEW_DEFAULT_BYTES)
        .min(RAW_PREVIEW_MAX_BYTES);
    let data = read_filesystem_entry_bytes(
        &case_path,
        ReadEntryBytesOptions {
            entry_id,
            offset: 0,
            length,
        },
    )?;
    let content_type = detect_image_content_type(&data.bytes)
        .context("entry does not start with a supported image signature")?;
    Ok((content_type, data.bytes))
}

/// Live-browse variant of /api/entry/raw: decode one file straight from an
/// attached live source and serve it as an image. Same signature sniffing as
/// the indexed endpoint, so it cannot dump arbitrary bytes.
fn api_image_raw(query: &HashMap<String, String>) -> Result<(&'static str, Vec<u8>)> {
    let (case_path, source) = live_evidence_from_query(query)?;
    let path = query
        .get("path")
        .context("path query parameter is required")?;
    let length = query_usize(query, "length")?
        .unwrap_or(RAW_PREVIEW_MAX_BYTES)
        .min(RAW_PREVIEW_MAX_BYTES);
    let (bytes, _total_size) = match source.source_kind.as_str() {
        "image" => {
            let volume_index: usize = query
                .get("volume")
                .context("volume query parameter is required")?
                .parse()
                .context("volume must be an integer")?;
            kdft_case::read_image_directory_bytes(
                Path::new(&source.source_path),
                volume_index,
                path,
                0,
                length,
            )?
        }
        "folder" | "file" => {
            kdft_case::read_local_evidence_bytes(&case_path, source.id, path, 0, length)?
        }
        other => bail!("live raw preview is not available for {other} evidence"),
    };
    let content_type = detect_image_content_type(&bytes)
        .context("live file does not start with a supported image signature")?;
    Ok((content_type, bytes))
}

fn detect_image_content_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("image/png")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        Some("image/x-icon")
    } else {
        None
    }
}

#[derive(Debug)]
struct LiveEvidenceRef {
    id: i64,
    source_kind: String,
    source_path: String,
    display_name: String,
    size_bytes: Option<i64>,
}

fn live_evidence_source(case_path: &Path, evidence_id: i64) -> Result<LiveEvidenceRef> {
    let evidence = list_evidence(case_path)?;
    let source = evidence
        .into_iter()
        .find(|item| item.id == evidence_id)
        .with_context(|| format!("evidence {evidence_id} not found"))?;
    Ok(LiveEvidenceRef {
        id: source.id,
        source_kind: source.source_kind,
        source_path: source.source_path,
        display_name: source.display_name,
        size_bytes: source.size_bytes,
    })
}

fn live_evidence_from_query(query: &HashMap<String, String>) -> Result<(PathBuf, LiveEvidenceRef)> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let evidence_id: i64 = query
        .get("evidence_id")
        .context("evidence_id query parameter is required")?
        .parse()
        .context("evidence_id must be an integer")?;
    let source = live_evidence_source(&case_path, evidence_id)?;
    Ok((case_path, source))
}

fn local_live_volume(source: &LiveEvidenceRef) -> serde_json::Value {
    let source_path = Path::new(&source.source_path);
    let label = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&source.display_name);
    let size_bytes = source
        .size_bytes
        .and_then(|value| u64::try_from(value).ok())
        .or_else(|| {
            fs::metadata(source_path)
                .ok()
                .map(|metadata| metadata.len())
        })
        .unwrap_or(0);
    json!({
        "index": 0,
        "name": label,
        "filesystem": "LOCAL",
        "start_offset": 0,
        "size_bytes": size_bytes,
        "browsable": true,
        "source_kind": source.source_kind,
    })
}

fn api_image_volumes(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let (_case_path, source) = live_evidence_from_query(query)?;
    if source.source_kind == "image" {
        let volumes = kdft_case::list_image_volumes(Path::new(&source.source_path))?;
        return Ok(json!({ "volumes": volumes }));
    }
    if source.source_kind == "folder" || source.source_kind == "file" {
        return Ok(json!({ "volumes": [local_live_volume(&source)] }));
    }
    bail!(
        "live browsing is not available for {} evidence",
        source.source_kind
    )
}

fn api_image_dir(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let (case_path, source) = live_evidence_from_query(query)?;
    let path = query.get("path").map(String::as_str).unwrap_or("/");
    match source.source_kind.as_str() {
        "image" => {
            let volume_index: usize = query
                .get("volume")
                .context("volume query parameter is required")?
                .parse()
                .context("volume must be an integer")?;
            let entries = kdft_case::list_image_directory(
                Path::new(&source.source_path),
                volume_index,
                path,
            )?;
            let total_entries = entries.len();
            Ok(json!({
                "entries": entries,
                "total_entries": total_entries,
                "next_cursor": null,
                "truncated": false,
            }))
        }
        "folder" | "file" => {
            const LIVE_DIRECTORY_PAGE_SIZE: usize = 1_000;
            const LIVE_DIRECTORY_MAX_PAGE_SIZE: usize = 5_000;
            let limit = query
                .get("limit")
                .map(|value| value.parse::<usize>().context("limit must be an integer"))
                .transpose()?
                .unwrap_or(LIVE_DIRECTORY_PAGE_SIZE)
                .clamp(1, LIVE_DIRECTORY_MAX_PAGE_SIZE);
            let after = query
                .get("after_name")
                .map(|name| -> Result<kdft_case::LocalDirectoryCursor> {
                    let is_dir = query
                        .get("after_is_dir")
                        .context("after_is_dir is required with after_name")?
                        .parse::<bool>()
                        .context("after_is_dir must be true or false")?;
                    Ok(kdft_case::LocalDirectoryCursor {
                        name: name.clone(),
                        is_dir,
                    })
                })
                .transpose()?;
            let listing = kdft_case::list_local_directory_page(
                &case_path,
                source.id,
                path,
                after.as_ref(),
                limit,
            )?;
            Ok(json!({
                "entries": listing.entries,
                "total_entries": listing.total_entries,
                "next_cursor": listing.next_cursor,
                "truncated": listing.truncated,
            }))
        }
        other => bail!("live browsing is not available for {other} evidence"),
    }
}

#[derive(Deserialize)]
struct LiveExportRequest {
    case_path: String,
    evidence_id: i64,
    volume: usize,
    path: String,
    output_path: String,
}

fn api_image_export(body: &[u8]) -> Result<kdft_case::LiveExportResult> {
    let request: LiveExportRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_path = request_path(&request.output_path, "output_path")?;
    let source = live_evidence_source(&case_path, request.evidence_id)?;
    let result = match source.source_kind.as_str() {
        "image" => {
            let result = export_image_file(
                Path::new(&source.source_path),
                request.volume,
                &request.path,
                &output_path,
            )?;
            record_live_export(
                &case_path,
                request.evidence_id,
                request.volume,
                &request.path,
                &result,
            )?;
            result
        }
        "folder" | "file" => {
            let result =
                export_local_file(&case_path, request.evidence_id, &request.path, &output_path)?;
            record_live_export_with_source_kind(
                &case_path,
                request.evidence_id,
                &source.source_kind,
                request.volume,
                &request.path,
                &result,
            )?;
            result
        }
        other => bail!("live export is not available for {other} evidence"),
    };
    Ok(result)
}

#[derive(Deserialize)]
struct LiveTreeExportRequest {
    case_path: String,
    evidence_id: i64,
    volume: usize,
    path: String,
    output_dir: String,
    max_files: Option<usize>,
}

fn api_image_export_tree(body: &[u8]) -> Result<kdft_case::LiveTreeExportResult> {
    let request: LiveTreeExportRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_dir = request_path(&request.output_dir, "output_dir")?;
    let source = live_evidence_source(&case_path, request.evidence_id)?;
    let result = match source.source_kind.as_str() {
        "image" => {
            let result = export_image_tree(
                Path::new(&source.source_path),
                request.volume,
                &request.path,
                &output_dir,
                request.max_files,
            )?;
            record_live_tree_export(
                &case_path,
                request.evidence_id,
                request.volume,
                &request.path,
                &result,
            )?;
            result
        }
        "folder" => {
            let result = export_local_tree(
                &case_path,
                request.evidence_id,
                &request.path,
                &output_dir,
                request.max_files,
            )?;
            record_live_tree_export_with_source_kind(
                &case_path,
                request.evidence_id,
                &source.source_kind,
                request.volume,
                &request.path,
                &result,
            )?;
            result
        }
        "file" => bail!("recursive live export is not available for single-file evidence"),
        other => bail!("live export is not available for {other} evidence"),
    };
    Ok(result)
}

#[derive(Deserialize)]
struct BitlockerUnlockCredentialRequest {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

// Builds a call-scoped BitLocker credential from the request. The recovery
// key/password is never logged, echoed in a notice/error, written to the audit
// trail, or persisted to the case database - it borrows the request value only
// for the duration of the unlock call.
fn bitlocker_credential_from(
    unlock: &BitlockerUnlockCredentialRequest,
) -> Result<kdft_case::BitLockerUnlockCredential<'_>> {
    match unlock.kind.as_str() {
        "recovery_key" => Ok(kdft_case::BitLockerUnlockCredential::RecoveryKey(
            &unlock.value,
        )),
        "password" => Ok(kdft_case::BitLockerUnlockCredential::Password(
            &unlock.value,
        )),
        other => bail!("unknown BitLocker unlock type '{other}' (use recovery_key or password)"),
    }
}

fn bitlocker_image_source(case_path: &Path, evidence_id: i64) -> Result<LiveEvidenceRef> {
    let source = live_evidence_source(case_path, evidence_id)?;
    if source.source_kind != "image" {
        bail!("BitLocker unlock is only available for image evidence");
    }
    Ok(source)
}

#[derive(Deserialize)]
struct BitlockerUnlockListRequest {
    case_path: String,
    evidence_id: i64,
    volume_index: usize,
    unlock: BitlockerUnlockCredentialRequest,
    dir_path: Option<String>,
}

fn api_bitlocker_unlock_list(body: &[u8]) -> Result<serde_json::Value> {
    let request: BitlockerUnlockListRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let source = bitlocker_image_source(&case_path, request.evidence_id)?;
    let credential = bitlocker_credential_from(&request.unlock)?;
    let dir_path = request.dir_path.as_deref().unwrap_or("/");
    let entries = kdft_case::list_bitlocker_ntfs_directory(
        Path::new(&source.source_path),
        request.volume_index,
        credential,
        dir_path,
    )?;
    Ok(json!({ "entries": entries, "dir_path": dir_path }))
}

#[derive(Deserialize)]
struct BitlockerUnlockBytesRequest {
    case_path: String,
    evidence_id: i64,
    volume_index: usize,
    unlock: BitlockerUnlockCredentialRequest,
    file_path: String,
    offset: Option<u64>,
    length: Option<usize>,
}

fn api_bitlocker_unlock_bytes(body: &[u8]) -> Result<serde_json::Value> {
    let request: BitlockerUnlockBytesRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let source = bitlocker_image_source(&case_path, request.evidence_id)?;
    let credential = bitlocker_credential_from(&request.unlock)?;
    let offset = request.offset.unwrap_or(0);
    let length = request.length.unwrap_or(512);
    let (bytes, total_size) = kdft_case::read_bitlocker_ntfs_file_bytes(
        Path::new(&source.source_path),
        request.volume_index,
        credential,
        &request.file_path,
        offset,
        length,
    )?;
    let bytes_read = bytes.len();
    Ok(json!({
        "logical_path": request.file_path,
        "offset": offset,
        "requested_length": length,
        "bytes_read": bytes_read,
        "total_size": total_size,
        "eof": offset.saturating_add(bytes_read as u64) >= total_size,
        "bytes": bytes,
    }))
}

fn api_image_bytes(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let (case_path, source) = live_evidence_from_query(query)?;
    let offset = query_u64(query, "offset")?.unwrap_or(0);
    let length = query
        .get("length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(512);
    if query_bool(query, "raw") {
        if source.source_kind != "image" {
            bail!("raw image bytes are only available for image evidence");
        }
        let (bytes, total_size) =
            kdft_case::read_image_raw_bytes(&case_path, source.id, offset, length)?;
        let bytes_read = bytes.len();
        return Ok(json!({
            "logical_path": "Whole device (raw)",
            "offset": offset.min(total_size),
            "requested_length": length.min(8 * 1024 * 1024),
            "bytes_read": bytes_read,
            "total_size": total_size,
            "eof": offset.saturating_add(bytes_read as u64) >= total_size,
            "bytes": bytes,
            "raw": true,
        }));
    }
    let path = query
        .get("path")
        .context("path query parameter is required")?;
    let (bytes, total_size) = match source.source_kind.as_str() {
        "image" => {
            let volume_index: usize = query
                .get("volume")
                .context("volume query parameter is required")?
                .parse()
                .context("volume must be an integer")?;
            kdft_case::read_image_directory_bytes(
                Path::new(&source.source_path),
                volume_index,
                path,
                offset,
                length,
            )?
        }
        "folder" | "file" => {
            kdft_case::read_local_evidence_bytes(&case_path, source.id, path, offset, length)?
        }
        other => bail!("live byte reading is not available for {other} evidence"),
    };
    let bytes_read = bytes.len();
    Ok(json!({
        "logical_path": path,
        "offset": offset,
        "requested_length": length,
        "bytes_read": bytes_read,
        "total_size": total_size,
        "eof": offset.saturating_add(bytes_read as u64) >= total_size,
        "bytes": bytes,
    }))
}

fn api_image_find(query: &HashMap<String, String>) -> Result<kdft_case::ImageRawFindResult> {
    let (case_path, source) = live_evidence_from_query(query)?;
    if source.source_kind != "image" {
        bail!("raw image find is only available for image evidence");
    }
    let start = query_u64(query, "start")?.unwrap_or(0);
    let q = query
        .get("q")
        .map(String::as_str)
        .context("q query parameter is required")?;
    let kind =
        kdft_case::RawFindKind::parse(query.get("kind").map(String::as_str).unwrap_or("text"))?;
    kdft_case::find_in_image_raw(&case_path, source.id, start, q, kind)
}

fn api_entries_dir(query: &HashMap<String, String>) -> Result<serde_json::Value> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let evidence_id: i64 = query
        .get("evidence_id")
        .context("evidence_id query parameter is required")?
        .parse()
        .context("evidence_id must be an integer")?;
    let path = query.get("path").map(String::as_str).unwrap_or("/");
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10_000);
    let offset = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    cached_indexed_directory(&case_path, evidence_id, path, offset, limit)
}

/// Cached indexed-directory listings. Count/max-id catch inserted or removed
/// rows; the monotonic case mutation generation also catches in-place metadata
/// changes such as signature analysis. Deep folders are fast anyway;
/// this exists because the ROOT of a six-figure-entry case costs ~2s of
/// subtree aggregation per call and the tree re-renders after every examiner
/// action - only the first browse should pay that.
fn cached_indexed_directory(
    case_path: &Path,
    evidence_id: i64,
    dir_path: &str,
    offset: usize,
    limit: usize,
) -> Result<serde_json::Value> {
    struct CacheEntry {
        entry_count: i64,
        max_entry_id: i64,
        mutation_generation: i64,
        listing: serde_json::Value,
    }
    type Key = (PathBuf, i64, String, usize, usize);
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<Key, CacheEntry>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let entry_count = filesystem_entry_count(case_path)?;
    let max_entry_id = max_filesystem_entry_id(case_path)?;
    let mutation_generation = case_mutation_generation(case_path)?;
    let key: Key = (
        case_path.to_path_buf(),
        evidence_id,
        dir_path.to_string(),
        offset,
        limit,
    );
    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.get(&key) {
            if entry.entry_count == entry_count
                && entry.max_entry_id == max_entry_id
                && entry.mutation_generation == mutation_generation
            {
                return Ok(entry.listing.clone());
            }
        }
    }
    let listing =
        kdft_case::list_indexed_directory_page(case_path, evidence_id, dir_path, offset, limit)?;
    let listing = serde_json::to_value(&listing).context("serializing directory listing")?;
    if let Ok(mut guard) = cache.lock() {
        // Stale generations never validate again; drop everything once the
        // map grows past a browsing session's working set.
        if guard.len() >= 512 {
            guard.clear();
        }
        guard.insert(
            key,
            CacheEntry {
                entry_count,
                max_entry_id,
                mutation_generation,
                listing: listing.clone(),
            },
        );
    }
    Ok(listing)
}

/// Looks up a single filesystem entry by id, regardless of whether it has
/// been paged into the browser's own entry cache - used by Deep Search
/// results ("Source" button / clicking a row) to resolve a hit into a real
/// tree location even when the containing folder has never been browsed.
fn api_entry_lookup(query: &HashMap<String, String>) -> Result<kdft_case::FilesystemEntry> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
    let entry_id = query_i64(query, "entry_id")?;
    kdft_case::filesystem_entry_by_id(&case_path, entry_id)?
        .with_context(|| format!("entry {entry_id} not found in this case"))
}

fn api_entries_category(query: &HashMap<String, String>) -> Result<kdft_case::CategoryEntryPage> {
    let case_path = query
        .get("case_path")
        .map(String::as_str)
        .context("case_path query parameter is required")
        .and_then(|value| request_path(value, "case_path"))?;
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
    let main = query.get("main").map(String::as_str).unwrap_or("");
    let sub = query.get("sub").map(String::as_str);
    let limit = query_usize(query, "limit")?.unwrap_or(1_000);
    let offset = query_usize(query, "offset")?.unwrap_or(0);
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
    list_entries_by_category_filtered(
        &case_path,
        evidence_id,
        main,
        sub,
        &filters,
        after.as_ref(),
        limit,
        offset,
    )
}

fn api_fs_list(query: &HashMap<String, String>) -> Result<FsListing> {
    let requested = match query.get("path").map(String::as_str) {
        Some(value) if !value.trim().is_empty() => request_path(value, "path")?,
        _ => std::env::current_dir().context("reading current directory")?,
    };
    let mut path = requested.clone();
    if path.is_file() {
        path = path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| format!("path has no parent: {}", requested.display()))?;
    }
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!("path is not a directory: {}", path.display());
    }

    let display_path = path.to_string_lossy().into_owned();
    let parent = path
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned());
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(&path).with_context(|| format!("reading directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", path.display()))?;
        let entry_path = entry.path();
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let name = entry.file_name().to_string_lossy().trim().to_string();
        entries.push(FsEntry {
            name: if name.is_empty() {
                "(unnamed)".to_string()
            } else {
                name
            },
            path: entry_path.to_string_lossy().into_owned(),
            kind: kind.to_string(),
            size_bytes: if file_type.is_file() {
                Some(metadata.len())
            } else {
                None
            },
        });
    }
    entries.sort_by(|left, right| {
        let left_rank = if left.kind == "directory" { 0 } else { 1 };
        let right_rank = if right.kind == "directory" { 0 } else { 1 };
        left_rank
            .cmp(&right_rank)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });

    Ok(FsListing {
        path: display_path,
        parent,
        roots: filesystem_roots(),
        entries,
    })
}

static PICK_DIALOG_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn api_pick_path(query: &HashMap<String, String>) -> Result<PickResult> {
    let mode = query.get("mode").map(String::as_str).unwrap_or("file");
    if mode != "file" && mode != "folder" {
        bail!("mode must be file or folder");
    }
    let filter = query.get("filter").map(String::as_str).unwrap_or("any");
    let start = query.get("start").map(String::as_str).unwrap_or("");
    if PICK_DIALOG_OPEN.swap(true, std::sync::atomic::Ordering::SeqCst) {
        bail!("a browse dialog is already open; finish or cancel it first");
    }
    let result = run_native_pick_dialog(mode, filter, start);
    PICK_DIALOG_OPEN.store(false, std::sync::atomic::Ordering::SeqCst);
    result.map(|path| PickResult { path })
}

#[cfg(windows)]
fn run_native_pick_dialog(mode: &str, filter: &str, start: &str) -> Result<Option<String>> {
    use std::os::windows::process::CommandExt;

    let ps_filter = match filter {
        "image" => {
            let patterns =
                "*.E01;*.EX01;*.L01;*.dd;*.raw;*.img;*.001;*.vhd;*.vhdx;*.vmdk;*.vdi;*.iso";
            format!("Disk images ({patterns})|{patterns}|All files (*.*)|*.*")
        }
        "browser_history" => {
            let patterns = "History;History.db;places.sqlite;*.sqlite;*.sqlite3;*.db;*.db3";
            format!("Browser history databases ({patterns})|{patterns}|All files (*.*)|*.*")
        }
        _ => "All files (*.*)|*.*".to_string(),
    };
    // Single-quoted PowerShell strings only terminate on a quote; doubling
    // embedded quotes and dropping control characters keeps the value inert.
    let ps_start = start
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .replace('\'', "''");
    let dialog_body = if mode == "folder" {
        // OpenFileDialog with a placeholder file name doubles as a modern
        // Explorer folder picker; FolderBrowserDialog on .NET Framework is the
        // legacy tree control.
        r#"$dialog.Title = 'Select folder - open the folder, then press Open'
$dialog.ValidateNames = $false
$dialog.CheckFileExists = $false
$dialog.CheckPathExists = $true
$dialog.FileName = 'Select this folder'
$dialog.AddExtension = $false
$dialog.Filter = 'Folders|*.kdft-folder-picker'"#
            .to_string()
    } else {
        format!(
            "$dialog.Title = 'Select evidence file'\n$dialog.CheckFileExists = $true\n$dialog.Filter = '{ps_filter}'"
        )
    };
    let script = format!(
        r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.RestoreDirectory = $true
{dialog_body}
$start = '{ps_start}'
if ($start) {{
  if (Test-Path -LiteralPath $start -PathType Container) {{ $dialog.InitialDirectory = $start }}
  else {{
    $parent = $null
    try {{ $parent = Split-Path -Path $start -Parent }} catch {{}}
    if ($parent -and (Test-Path -LiteralPath $parent -PathType Container)) {{ $dialog.InitialDirectory = $parent }}
  }}
}}
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.StartPosition = 'CenterScreen'
$owner.Size = New-Object System.Drawing.Size(1, 1)
$owner.Add_Shown({{ $owner.Activate(); $owner.BringToFront() }})
$owner.Show()
$result = $dialog.ShowDialog($owner)
$owner.Dispose()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {{
  $picked = $dialog.FileName
  if ('{mode}' -eq 'folder') {{ $picked = [System.IO.Path]::GetDirectoryName($picked) }}
  [Console]::Out.Write($picked)
}}
"#
    );
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).context("generating picker script name")?;
    let random = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let script_path =
        std::env::temp_dir().join(format!("kdft-pick-{}-{random}.ps1", std::process::id()));
    let mut script_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&script_path)
        .context("creating picker script")?;
    script_file
        .write_all(script.as_bytes())
        .context("writing picker script")?;
    script_file.sync_all().context("syncing picker script")?;
    drop(script_file);
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-STA",
            "-WindowStyle",
            "Hidden",
            "-File",
        ])
        .arg(&script_path)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = fs::remove_file(&script_path);
    let output = output.context("launching Windows file dialog")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("file dialog failed: {}", stderr.trim());
    }
    let picked = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if picked.is_empty() {
        Ok(None)
    } else {
        Ok(Some(picked))
    }
}

#[cfg(not(windows))]
#[cfg(target_os = "macos")]
fn run_native_pick_dialog(mode: &str, _filter: &str, start: &str) -> Result<Option<String>> {
    let prompt = if mode == "folder" {
        "Select folder"
    } else {
        "Select evidence file"
    };
    let command = if mode == "folder" {
        "choose folder"
    } else {
        "choose file"
    };
    let mut script = format!(
        "POSIX path of ({command} with prompt \"{}\"",
        escape_applescript_string(prompt)
    );
    if let Some(location) = picker_existing_start_location(start) {
        script.push_str(&format!(
            " default location (POSIX file \"{}\")",
            escape_applescript_string(&location)
        ));
    }
    script.push(')');

    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .context("launching macOS file dialog")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(1) && stderr.contains("User canceled") {
            return Ok(None);
        }
        bail!("file dialog failed: {}", stderr.trim());
    }
    let picked = trim_picker_stdout(&output.stdout);
    if picked.is_empty() {
        Ok(None)
    } else {
        Ok(Some(picked))
    }
}

#[cfg(target_os = "macos")]
fn escape_applescript_string(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars().filter(|ch| !ch.is_control()) {
        if ch == '"' || ch == '\\' {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

#[cfg(any(target_os = "macos", all(unix, not(target_os = "macos"))))]
fn picker_existing_start_location(start: &str) -> Option<String> {
    let start = start.trim();
    if start.is_empty() {
        return None;
    }
    let path = Path::new(start);
    if path.is_dir() {
        Some(start.to_string())
    } else if path.is_file() {
        path.parent()
            .filter(|parent| parent.exists())
            .map(|parent| parent.to_string_lossy().to_string())
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", all(unix, not(target_os = "macos"))))]
fn trim_picker_stdout(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .trim_end_matches(&['\r', '\n'][..])
        .to_string()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn run_native_pick_dialog(mode: &str, filter: &str, start: &str) -> Result<Option<String>> {
    match run_zenity_pick_dialog(mode, filter, start) {
        Ok(path) => return Ok(path),
        Err(err) if is_command_not_found(&err) => {}
        Err(err) => return Err(err),
    }
    match run_kdialog_pick_dialog(mode, start) {
        Ok(path) => Ok(path),
        Err(err) if is_command_not_found(&err) => {
            bail!("no graphical file picker found; install zenity or type the path manually")
        }
        Err(err) => Err(err),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn run_zenity_pick_dialog(mode: &str, filter: &str, start: &str) -> Result<Option<String>> {
    let mut command = Command::new("zenity");
    command.arg("--file-selection");
    if mode == "folder" {
        command.arg("--directory");
    }
    if let Some(location) = picker_existing_start_location(start) {
        let filename = if location.ends_with('/') {
            location
        } else {
            format!("{location}/")
        };
        command.arg(format!("--filename={filename}"));
    }
    if mode == "file" && filter == "image" {
        command.arg("--file-filter=Disk images | *.E01 *.EX01 *.L01 *.dd *.raw *.img *.001 *.vhd *.vhdx *.vmdk *.vdi *.iso");
        command.arg("--file-filter=All files | *");
    }
    if mode == "file" && filter == "browser_history" {
        command.arg("--file-filter=Browser history databases | History History.db places.sqlite *.sqlite *.sqlite3 *.db *.db3");
        command.arg("--file-filter=All files | *");
    }
    let output = command.output().context("launching zenity file dialog")?;
    handle_unix_picker_output(output, "zenity file dialog")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn run_kdialog_pick_dialog(mode: &str, start: &str) -> Result<Option<String>> {
    let mut command = Command::new("kdialog");
    if mode == "folder" {
        command.arg("--getexistingdirectory");
    } else {
        command.arg("--getopenfilename");
    }
    if let Some(location) = picker_existing_start_location(start) {
        command.arg(location);
    }
    let output = command.output().context("launching kdialog file dialog")?;
    handle_unix_picker_output(output, "kdialog file dialog")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn handle_unix_picker_output(output: std::process::Output, label: &str) -> Result<Option<String>> {
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{label} failed: {}", stderr.trim());
    }
    let picked = trim_picker_stdout(&output.stdout);
    if picked.is_empty() {
        Ok(None)
    } else {
        Ok(Some(picked))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn is_command_not_found(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::NotFound)
            .unwrap_or(false)
    })
}

fn filesystem_roots() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        ('A'..='Z')
            .filter_map(|letter| {
                let root = format!("{letter}:\\");
                if Path::new(&root).exists() {
                    Some(root)
                } else {
                    None
                }
            })
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec!["/".to_string()]
    }
}

fn default_history_path() -> String {
    let mut candidates = Vec::new();
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let local_app_data = PathBuf::from(local_app_data);
        candidates.push(
            local_app_data
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("History"),
        );
        candidates.push(
            local_app_data
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("History"),
        );
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn api_create_case(body: &[u8]) -> Result<serde_json::Value> {
    let request: CreateCaseRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let case_id = create_case(
        &case_path,
        CreateCaseOptions {
            name: non_empty(request.name, "name")?,
            examiner_name: request.examiner,
            case_number: request.case_number,
            case_type: request.case_type,
            description: request.description,
            default_export_folder: None,
            temporary_folder: None,
            index_folder: None,
        },
    )?;
    Ok(json!({ "case_id": case_id, "case": case_path }))
}

fn api_add_evidence(body: &[u8]) -> Result<serde_json::Value> {
    let request: AddEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let evidence_path = request_path(&request.path, "path")?;
    let kind = EvidenceKind::parse(request.kind.as_deref().unwrap_or("auto"))?;
    let add_result = add_evidence(
        &case_path,
        AddEvidenceOptions {
            path: evidence_path.clone(),
            kind,
            read_file_system_requested: request.read_file_system.unwrap_or(true),
            notes: request.notes,
        },
    );
    match add_result {
        Ok(evidence_id) => Ok(json!({
            "evidence_id": evidence_id,
            // Add-evidence only inserts an evidence_sources row; it never creates filesystem_entries
            // for the new source (that happens in a later explicit process step), so this is always 0.
            // Previously reported the case-wide entry count, which was misleading once a case has more
            // than one evidence source.
            "filesystem_entries": 0,
            "indexed": false
        })),
        Err(error) => {
            let Some(detected) = error.downcast_ref::<BrowserDatabaseDetected>() else {
                return Err(error);
            };
            import_detected_browser_database(&case_path, &evidence_path, detected.family)
        }
    }
}

fn import_detected_browser_database(
    case_path: &Path,
    database_path: &Path,
    family: BrowserFamily,
) -> Result<serde_json::Value> {
    let profile_root = database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let result = import_browser_history_for_family(
        case_path,
        family,
        ImportBrowserHistoryOptions {
            history_path: profile_root.to_path_buf(),
            max_visits: 0,
            evidence_name: None,
        },
    )?;
    let mut response =
        serde_json::to_value(result).context("serializing detected browser import result")?;
    response
        .as_object_mut()
        .context("detected browser import result serialized to a non-object")?
        .insert(
            "detected".to_string(),
            serde_json::Value::String(format!("{}_history_database", family.as_str())),
        );
    Ok(response)
}

fn api_process_evidence(body: &[u8], config: &ServerConfig) -> Result<serde_json::Value> {
    let request: ProcessEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let (diagnostic_log, diagnostic_start_error) =
        match StreamingDiagnosticLog::start(&case_path, request.evidence_id, "analysis") {
            Ok(log) => (Some(log), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
    let diagnostic_observer = diagnostic_log
        .as_ref()
        .map(StreamingDiagnosticLog::observer);
    let diagnostic_log_path = diagnostic_log.as_ref().map(|log| log.path.clone());
    let tracker = match request.progress_id.as_deref() {
        Some(operation_id) => config.progress.start(
            operation_id,
            "process",
            diagnostic_observer,
            diagnostic_log_path,
        )?,
        None => JobProgressTracker::new_with_diagnostic_observer(
            format!("process-evidence-{}", request.evidence_id),
            "process",
            None,
            diagnostic_observer,
        ),
    };
    tracker.set_evidence_id(request.evidence_id);
    let result = with_job_progress(&tracker, || {
        api_process_evidence_tracked(&case_path, &request, &tracker)
    });
    match result {
        Ok(mut response) => {
            let diagnostic_response = response.clone();
            attach_processing_diagnostic_log(
                &case_path,
                request.evidence_id,
                "analysis",
                &tracker.snapshot(),
                Some(&diagnostic_response),
                None,
                diagnostic_log.as_ref(),
                diagnostic_start_error.as_deref(),
                &mut response,
            );
            Ok(response)
        }
        Err(error) => {
            tracker.record_error(None);
            tracker.finish(JobProgressState::Failed);
            let snapshot = tracker.snapshot();
            if let Some(job_id) = snapshot.job_id {
                if let Err(progress_error) =
                    kdft_case::record_job_progress_summary(&case_path, job_id, &snapshot)
                {
                    eprintln!(
                        "recording failed process telemetry for job {job_id} failed: {progress_error:#}"
                    );
                }
            }
            match finish_processing_diagnostic_log(
                &case_path,
                request.evidence_id,
                "analysis-failed",
                &snapshot,
                None,
                Some(&format!("{error:#}")),
                diagnostic_log.as_ref(),
            ) {
                Ok(path) => {
                    Err(error.context(format!("diagnostic log saved to {}", path.display())))
                }
                Err(log_error) => Err(error.context(format!(
                    "saving the processing diagnostic log also failed: {log_error:#}"
                ))),
            }
        }
    }
}

/// Runs examiner-selected processors against the existing immutable indexed
/// snapshot. Unlike `/api/evidence/process`, this path never calls the base
/// file-system walker and therefore never deletes `filesystem_entries`.
fn api_run_processors(body: &[u8], config: &ServerConfig) -> Result<serde_json::Value> {
    let request: ProcessEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let (diagnostic_log, diagnostic_start_error) =
        match StreamingDiagnosticLog::start(&case_path, request.evidence_id, "processors") {
            Ok(log) => (Some(log), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
    let diagnostic_observer = diagnostic_log
        .as_ref()
        .map(StreamingDiagnosticLog::observer);
    let diagnostic_log_path = diagnostic_log.as_ref().map(|log| log.path.clone());
    let tracker = match request.progress_id.as_deref() {
        Some(operation_id) => config.progress.start(
            operation_id,
            "processors",
            diagnostic_observer,
            diagnostic_log_path,
        )?,
        None => JobProgressTracker::new_with_diagnostic_observer(
            format!("run-processors-{}", request.evidence_id),
            "processors",
            None,
            diagnostic_observer,
        ),
    };
    tracker.set_evidence_id(request.evidence_id);
    let result = with_job_progress(&tracker, || {
        api_run_processors_tracked(&case_path, &request, &tracker)
    });
    match result {
        Ok(mut response) => {
            let diagnostic_response = response.clone();
            attach_processing_diagnostic_log(
                &case_path,
                request.evidence_id,
                "processors",
                &tracker.snapshot(),
                Some(&diagnostic_response),
                None,
                diagnostic_log.as_ref(),
                diagnostic_start_error.as_deref(),
                &mut response,
            );
            Ok(response)
        }
        Err(error) => {
            tracker.record_error(None);
            tracker.finish(JobProgressState::Failed);
            let snapshot = tracker.snapshot();
            match finish_processing_diagnostic_log(
                &case_path,
                request.evidence_id,
                "processors-failed",
                &snapshot,
                None,
                Some(&format!("{error:#}")),
                diagnostic_log.as_ref(),
            ) {
                Ok(path) => {
                    Err(error.context(format!("diagnostic log saved to {}", path.display())))
                }
                Err(log_error) => Err(error.context(format!(
                    "saving the processor diagnostic log also failed: {log_error:#}"
                ))),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn attach_processing_diagnostic_log(
    case_path: &Path,
    evidence_id: i64,
    operation: &str,
    snapshot: &JobProgressSnapshot,
    response: Option<&serde_json::Value>,
    error: Option<&str>,
    running_log: Option<&StreamingDiagnosticLog>,
    start_error: Option<&str>,
    output: &mut serde_json::Value,
) {
    match finish_processing_diagnostic_log(
        case_path,
        evidence_id,
        operation,
        snapshot,
        response,
        error,
        running_log,
    ) {
        Ok(path) => {
            if let Some(object) = output.as_object_mut() {
                object.insert(
                    "diagnostic_log_path".to_string(),
                    serde_json::json!(path.to_string_lossy()),
                );
            }
        }
        Err(log_error) => {
            eprintln!("saving processing diagnostic log failed: {log_error:#}");
            if let Some(object) = output.as_object_mut() {
                object.insert(
                    "diagnostic_log_error".to_string(),
                    serde_json::json!(format!("{log_error:#}")),
                );
            }
        }
    }
    if let Some(start_error) = start_error {
        if let Some(object) = output.as_object_mut() {
            object.insert(
                "diagnostic_stream_start_warning".to_string(),
                serde_json::json!(start_error),
            );
        }
    }
}

struct StreamingDiagnosticLog {
    path: PathBuf,
    file: Arc<Mutex<fs::File>>,
    write_error: Arc<Mutex<Option<String>>>,
}

impl StreamingDiagnosticLog {
    fn start(case_path: &Path, evidence_id: i64, operation: &str) -> Result<Self> {
        let case_filename = case_path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("kdft-case");
        let directory = case_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("{case_filename}.logs"));
        fs::create_dir_all(&directory).with_context(|| {
            format!("creating diagnostic-log directory {}", directory.display())
        })?;
        let operation = sanitize_diagnostic_operation(operation);
        let generated_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        for attempt in 0..1_024_u32 {
            let path = directory.join(format!(
                "{operation}-evidence-{evidence_id}-{generated_unix_ms}-{}-{attempt}.log",
                std::process::id()
            ));
            let mut file = match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(open_error) if open_error.kind() == std::io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(open_error) => {
                    return Err(open_error)
                        .with_context(|| format!("creating diagnostic log {}", path.display()))
                }
            };
            writeln!(file, "KDFT processing diagnostic log")?;
            writeln!(file, "case_path={}", case_path.display())?;
            writeln!(file, "evidence_id={evidence_id}")?;
            writeln!(file, "operation={operation}")?;
            writeln!(file, "generated_unix_ms={generated_unix_ms}")?;
            writeln!(file, "source_evidence_modified=false")?;
            writeln!(file, "event_format=json_lines")?;
            writeln!(file, "\n=== Complete diagnostic event stream ===")?;
            file.flush()?;
            return Ok(Self {
                path,
                file: Arc::new(Mutex::new(file)),
                write_error: Arc::new(Mutex::new(None)),
            });
        }
        bail!("could not reserve a unique processing diagnostic-log filename")
    }

    fn observer(&self) -> DiagnosticObserver {
        let file = self.file.clone();
        let write_error = self.write_error.clone();
        Arc::new(move |event: JobDiagnosticEvent| {
            if write_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
            {
                return;
            }
            let result = (|| -> Result<()> {
                let mut file = file
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                serde_json::to_writer(&mut *file, &event)
                    .context("serializing streamed diagnostic event")?;
                writeln!(file)?;
                file.flush()?;
                Ok(())
            })();
            if let Err(error) = result {
                *write_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(format!("{error:#}"));
            }
        })
    }

    fn finish(
        &self,
        snapshot: &JobProgressSnapshot,
        response: Option<&serde_json::Value>,
        error: Option<&str>,
    ) -> Result<()> {
        if let Some(error) = self
            .write_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            bail!("streaming diagnostic events failed: {error}");
        }
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        writeln!(file, "\n=== Progress messages and terminal state ===")?;
        serde_json::to_writer_pretty(&mut *file, snapshot)
            .context("serializing diagnostic progress snapshot")?;
        writeln!(file)?;
        if let Some(response) = response {
            writeln!(file, "\n=== Processor response ===")?;
            serde_json::to_writer_pretty(&mut *file, response)
                .context("serializing diagnostic processor response")?;
            writeln!(file)?;
        }
        if let Some(error) = error {
            writeln!(file, "\n=== Terminal error ===")?;
            writeln!(file, "{error}")?;
        }
        file.sync_all()
            .with_context(|| format!("syncing diagnostic log {}", self.path.display()))?;
        Ok(())
    }
}

fn sanitize_diagnostic_operation(operation: &str) -> String {
    operation
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn finish_processing_diagnostic_log(
    case_path: &Path,
    evidence_id: i64,
    operation: &str,
    snapshot: &JobProgressSnapshot,
    response: Option<&serde_json::Value>,
    error: Option<&str>,
    running_log: Option<&StreamingDiagnosticLog>,
) -> Result<PathBuf> {
    if let Some(log) = running_log {
        log.finish(snapshot, response, error)?;
        return Ok(log.path.clone());
    }
    write_processing_diagnostic_log(case_path, evidence_id, operation, snapshot, response, error)
}

fn write_processing_diagnostic_log(
    case_path: &Path,
    evidence_id: i64,
    operation: &str,
    snapshot: &JobProgressSnapshot,
    response: Option<&serde_json::Value>,
    error: Option<&str>,
) -> Result<PathBuf> {
    let log = StreamingDiagnosticLog::start(case_path, evidence_id, operation)?;
    log.finish(snapshot, response, error)?;
    Ok(log.path)
}

fn api_run_processors_tracked(
    case_path: &Path,
    request: &ProcessEvidenceRequest,
    tracker: &JobProgressTracker,
) -> Result<serde_json::Value> {
    if request.reindex_filesystem.unwrap_or(false) {
        bail!("additive processor endpoint cannot rebuild the filesystem snapshot");
    }
    if !processing_evidence_exists(case_path, request.evidence_id)? {
        bail!("evidence source does not exist in the active case");
    }

    let stage_count = optional_processing_stage_count(request).saturating_add(1);
    let mut stage_index = 0_usize;
    let mut response = serde_json::json!({
        "evidence_id": request.evidence_id,
        "reindexed": false,
    });
    append_optional_processing_passes(
        case_path,
        request,
        &mut response,
        tracker,
        &mut stage_index,
        stage_count,
    )?;

    let pipeline_failed = response_contains_failed_pass(&response);
    let pipeline_truncated = response_contains_truncated_pass(&response);
    stage_index += 1;
    tracker.start_stage(
        "Finalization",
        stage_index,
        Some(stage_count),
        "steps",
        Some(1),
    );
    tracker.advance(
        1,
        Some("Processor results committed; filesystem snapshot preserved".to_string()),
    );
    let final_state = if pipeline_failed {
        JobProgressState::Failed
    } else if pipeline_truncated {
        JobProgressState::Truncated
    } else {
        JobProgressState::Complete
    };
    tracker.finish(final_state);
    let final_progress = tracker.snapshot();
    let object = response
        .as_object_mut()
        .context("processor response serialized to a non-object")?;
    object.insert(
        "status".to_string(),
        serde_json::Value::String(
            match final_state {
                JobProgressState::Complete => "completed",
                JobProgressState::Truncated => "truncated",
                JobProgressState::Cancelled => "cancelled",
                JobProgressState::Failed => "failed",
                JobProgressState::Active => "running",
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
        serde_json::to_value(final_progress).context("serializing processor progress")?,
    );
    Ok(response)
}

fn api_process_evidence_tracked(
    case_path: &Path,
    request: &ProcessEvidenceRequest,
    tracker: &JobProgressTracker,
) -> Result<serde_json::Value> {
    let stage_count = process_stage_count(request);
    let mut stage_index = 1_usize;
    let inventory_stage = if request.capture_content.unwrap_or(true) {
        "Filesystem inventory and content capture"
    } else {
        "Filesystem inventory"
    };
    tracker.start_stage(
        inventory_stage,
        stage_index,
        Some(stage_count),
        "entries",
        None,
    );
    tracker.set_auto_advance_database_entries(true);
    let index_result = kdft_case::process_evidence_with_profile(
        case_path,
        ProcessEvidenceOptions {
            evidence_id: request.evidence_id,
            // Omitting max_entries means unlimited (kdft-case treats 0 as no cap).
            // Processing covers the whole selected evidence; a caller that wants a
            // bound must send one explicitly.
            max_entries: request.max_entries.unwrap_or(0),
        },
        kdft_case::ProcessingProfile {
            capture_content: request.capture_content.unwrap_or(true),
            parse_emails: request.parse_emails.unwrap_or(true),
            parse_browsers: request.parse_browsers.unwrap_or(true),
        },
    )?;
    tracker.set_auto_advance_database_entries(false);
    // Examiner-selected follow-up passes, each already an independent audited
    // job. The base index result stays at the top level so existing callers
    // keep working; per-pass results (or their failure text) are nested. A
    // failed optional pass must not discard the completed index.
    let mut response =
        serde_json::to_value(&index_result).context("serializing processing result")?;
    append_optional_processing_passes(
        case_path,
        request,
        &mut response,
        tracker,
        &mut stage_index,
        stage_count,
    )?;
    let pipeline_failed = response_contains_failed_pass(&response);
    let pipeline_truncated = index_result.truncated || response_contains_truncated_pass(&response);
    if pipeline_truncated && !index_result.truncated {
        tracker.record_truncation(
            "one or more optional parsing passes completed with partial coverage; filesystem indexing completed",
        );
    }
    stage_index += 1;
    tracker.start_stage(
        "Finalization",
        stage_index,
        Some(stage_count),
        "steps",
        Some(1),
    );
    tracker.advance(1, Some("Process results committed".to_string()));
    let final_state = if pipeline_failed {
        JobProgressState::Failed
    } else if pipeline_truncated {
        JobProgressState::Truncated
    } else {
        JobProgressState::Complete
    };
    tracker.finish(final_state);
    let final_progress = tracker.snapshot();
    kdft_case::record_job_progress_summary(case_path, index_result.job_id, &final_progress)?;
    let response_object = response
        .as_object_mut()
        .context("processing result serialized to a non-object")?;
    response_object.insert(
        "status".to_string(),
        serde_json::Value::String(
            match final_state {
                JobProgressState::Complete => "completed",
                JobProgressState::Truncated => "truncated",
                JobProgressState::Cancelled => "cancelled",
                JobProgressState::Failed => "failed",
                JobProgressState::Active => "running",
            }
            .to_string(),
        ),
    );
    response_object.insert(
        "truncated".to_string(),
        serde_json::Value::Bool(pipeline_truncated),
    );
    response_object.insert(
        "index_truncated".to_string(),
        serde_json::Value::Bool(index_result.truncated),
    );
    response_object.insert(
        "progress".to_string(),
        serde_json::to_value(final_progress).context("serializing final job progress")?,
    );
    Ok(response)
}

fn response_contains_failed_pass(response: &serde_json::Value) -> bool {
    response.as_object().is_some_and(|object| {
        object.iter().any(|(name, value)| {
            name != "error"
                && (value.get("error").is_some_and(|error| !error.is_null())
                    || value.get("status").and_then(serde_json::Value::as_str) == Some("failed"))
        })
    })
}

fn response_contains_truncated_pass(response: &serde_json::Value) -> bool {
    response.as_object().is_some_and(|object| {
        object.iter().any(|(name, value)| {
            name != "truncated"
                && (value.get("truncated").and_then(serde_json::Value::as_bool) == Some(true)
                    || value.get("status").and_then(serde_json::Value::as_str) == Some("truncated"))
        })
    })
}

// Preserve the historical API contract for callers that predate the three
// explicit parser switches: content-enabled processing ran all three passes,
// while metadata-only processing skipped them. The browser always sends the
// new fields, so an examiner can now run any pass independently of content_head
// capture.
fn parse_archives_enabled(request: &ProcessEvidenceRequest) -> bool {
    request
        .parse_archives
        .unwrap_or_else(|| request.capture_content.unwrap_or(true))
}

fn parse_documents_enabled(request: &ProcessEvidenceRequest) -> bool {
    request
        .parse_documents
        .unwrap_or_else(|| request.capture_content.unwrap_or(true))
}

fn parse_windows_artifacts_enabled(request: &ProcessEvidenceRequest) -> bool {
    request
        .parse_windows_artifacts
        .unwrap_or_else(|| request.capture_content.unwrap_or(true))
}

fn process_stage_count(request: &ProcessEvidenceRequest) -> usize {
    2 + optional_processing_stage_count(request)
}

fn optional_processing_stage_count(request: &ProcessEvidenceRequest) -> usize {
    usize::from(request.run_hash.unwrap_or(false))
        + usize::from(request.run_signature_analysis.unwrap_or(false))
        + usize::from(request.run_carve.unwrap_or(false))
        + usize::from(request.run_file_hash.unwrap_or(false))
        + usize::from(parse_archives_enabled(request))
        + usize::from(parse_documents_enabled(request))
        + (2 * usize::from(parse_windows_artifacts_enabled(request)))
        + usize::from(request.parse_emails.unwrap_or(true))
        + usize::from(request.parse_browsers.unwrap_or(true))
        + usize::from(request.parse_identities.unwrap_or(true))
}

fn begin_processing_stage(
    tracker: &JobProgressTracker,
    stage_index: &mut usize,
    stage_count: usize,
    name: &str,
    unit: &str,
) {
    *stage_index += 1;
    tracker.start_stage(name, *stage_index, Some(stage_count), unit, None);
}

fn append_optional_processing_passes(
    case_path: &Path,
    request: &ProcessEvidenceRequest,
    response: &mut serde_json::Value,
    tracker: &JobProgressTracker,
    stage_index: &mut usize,
    stage_count: usize,
) -> Result<()> {
    let extras = response
        .as_object_mut()
        .context("processing result serialized to a non-object")?;
    if parse_archives_enabled(request) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Archive member parsing",
            "archives",
        );
        extras.insert(
            "archive_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "archive parsing",
                tracker,
                || parse_archive_artifacts(case_path, request.evidence_id),
            )?,
        );
    }
    if parse_documents_enabled(request) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Document content parsing",
            "documents",
        );
        extras.insert(
            "document_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "document parsing",
                tracker,
                || parse_document_artifacts(case_path, request.evidence_id),
            )?,
        );
    }
    if parse_windows_artifacts_enabled(request) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Windows artifact parsing",
            "Windows artifact sources",
        );
        extras.insert(
            "windows_artifact_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "Windows artifact parsing",
                tracker,
                || {
                    kdft_case::windows_artifacts::parse_windows_artifacts(
                        case_path,
                        request.evidence_id,
                    )
                },
            )?,
        );
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Windows Registry artifact parsing",
            "Registry hives",
        );
        extras.insert(
            "windows_registry_artifact_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "Windows Registry artifact parsing",
                tracker,
                || {
                    kdft_case::windows_registry_artifacts::parse_windows_registry_artifacts(
                        case_path,
                        request.evidence_id,
                    )
                },
            )?,
        );
    }
    if request.parse_emails.unwrap_or(true) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Embedded mailbox parsing",
            "mailboxes",
        );
        extras.insert(
            "email_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "embedded mailbox parsing",
                tracker,
                || parse_embedded_mailboxes(case_path, request.evidence_id, 0),
            )?,
        );
    }
    if request.parse_browsers.unwrap_or(true) {
        // ext volumes auto-import during the walk itself; this post-index pass
        // covers NTFS/FAT images and local folder evidence.
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Browser artifact parsing",
            "profiles",
        );
        extras.insert(
            "browser_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "browser parsing",
                tracker,
                || run_browser_parsing_pass(case_path, request.evidence_id, Some(tracker)),
            )?,
        );
    }
    if request.parse_identities.unwrap_or(true) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Identity artifact parsing",
            "hives",
        );
        extras.insert(
            "identity_parsing".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "identity parsing",
                tracker,
                || parse_identity_artifacts(case_path, request.evidence_id),
            )?,
        );
    }
    append_slow_integrity_passes(
        case_path,
        request,
        extras,
        tracker,
        stage_index,
        stage_count,
    )?;
    Ok(())
}

/// Expensive whole-source and per-file verification belongs after the
/// high-value structured parsers. A large compressed image must not withhold
/// browser, event, execution, and identity records for hours merely because
/// signature verification was selected in the same run.
fn append_slow_integrity_passes(
    case_path: &Path,
    request: &ProcessEvidenceRequest,
    extras: &mut serde_json::Map<String, serde_json::Value>,
    tracker: &JobProgressTracker,
    stage_index: &mut usize,
    stage_count: usize,
) -> Result<()> {
    if request.run_signature_analysis.unwrap_or(false) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "File signature analysis",
            "files",
        );
        extras.insert(
            "signature_analysis".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "signature analysis",
                tracker,
                || {
                    analyze_signatures(
                        case_path,
                        AnalyzeSignaturesOptions {
                            evidence_id: Some(request.evidence_id),
                            // Every reconstructable indexed logical file is checked.
                            max_entries: 0,
                        },
                    )
                },
            )?,
        );
    }
    if request.run_file_hash.unwrap_or(false) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Indexed-file hashing",
            "files",
        );
        extras.insert(
            "file_hash".to_string(),
            run_optional_processing_pass(
                case_path,
                request.evidence_id,
                "file hashing",
                tracker,
                || {
                    kdft_case::hash_indexed_files(
                        case_path,
                        kdft_case::HashIndexedFilesOptions {
                            evidence_id: request.evidence_id,
                            max_files: 0,
                            max_file_bytes: 0,
                        },
                    )
                },
            )?,
        );
    }
    if request.run_hash.unwrap_or(false) {
        begin_processing_stage(
            tracker,
            stage_index,
            stage_count,
            "Evidence hashing",
            "bytes",
        );
        extras.insert(
            "hash".to_string(),
            run_optional_processing_pass(case_path, request.evidence_id, "hash", tracker, || {
                hash_evidence(case_path, request.evidence_id)
            })?,
        );
    }
    if request.run_carve.unwrap_or(false) {
        begin_processing_stage(tracker, stage_index, stage_count, "File carving", "bytes");
        extras.insert(
            "carve".to_string(),
            run_optional_processing_pass(case_path, request.evidence_id, "carve", tracker, || {
                carve_evidence(
                    case_path,
                    request.evidence_id,
                    CarveOptions {
                        max_scan_bytes: request.carve_max_scan_bytes.unwrap_or(0),
                        max_files: request.carve_max_files.unwrap_or(0),
                    },
                )
            })?,
        );
    }
    Ok(())
}

fn run_optional_processing_pass<T, F>(
    case_path: &Path,
    evidence_id: i64,
    pass_name: &str,
    tracker: &JobProgressTracker,
    operation: F,
) -> Result<serde_json::Value>
where
    T: Serialize,
    F: FnOnce() -> Result<T>,
{
    if !processing_evidence_exists(case_path, evidence_id)? {
        tracker.record_skip(None);
        return Ok(removed_evidence_pass_result(evidence_id, pass_name));
    }
    match operation() {
        Ok(result) => {
            let value =
                serde_json::to_value(result).context("serializing optional processing pass")?;
            let removed_after_start = processing_evidence_exists(case_path, evidence_id)
                .map(|exists| !exists)
                .unwrap_or(false);
            let nested_foreign_key = json_contains_foreign_key_failure(&value);
            if nested_foreign_key {
                preserve_processing_pass_failure(
                    case_path,
                    evidence_id,
                    pass_name,
                    &value.to_string(),
                );
            }
            if removed_after_start || nested_foreign_key {
                tracker.record_error(None);
                tracker.record_skip(None);
                Ok(removed_evidence_pass_result(evidence_id, pass_name))
            } else {
                Ok(value)
            }
        }
        Err(error) => {
            tracker.record_error(None);
            // The source can disappear in the narrow race after the existence
            // check. A foreign-key failure is the other observable shape of
            // that same removal race, so neither is exposed to the examiner.
            let removed_after_start = processing_evidence_exists(case_path, evidence_id)
                .map(|exists| !exists)
                .unwrap_or(false);
            if removed_after_start || is_foreign_key_failure(&error) {
                preserve_processing_pass_failure(
                    case_path,
                    evidence_id,
                    pass_name,
                    &format!("{error:#}"),
                );
                Ok(removed_evidence_pass_result(evidence_id, pass_name))
            } else {
                Ok(serde_json::json!({ "error": error.to_string() }))
            }
        }
    }
}

fn preserve_processing_pass_failure(
    case_path: &Path,
    evidence_id: i64,
    pass_name: &str,
    underlying_error: &str,
) {
    // The examiner response must remain the clean removal wording even if the
    // audit database is itself unavailable during teardown. The raw text is
    // never copied into the response or UI notice.
    let _ =
        record_processing_pass_failure_audit(case_path, evidence_id, pass_name, underlying_error);
}

fn processing_evidence_exists(case_path: &Path, evidence_id: i64) -> Result<bool> {
    evidence_source_exists(case_path, evidence_id)
}

fn removed_evidence_pass_result(evidence_id: i64, pass_name: &str) -> serde_json::Value {
    serde_json::json!({
        "error": format!(
            "evidence {evidence_id} was removed while processing was running; the {pass_name} pass did not run"
        )
    })
}

fn is_foreign_key_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .to_ascii_lowercase()
            .contains("foreign key constraint failed")
    })
}

fn json_contains_foreign_key_failure(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => text
            .to_ascii_lowercase()
            .contains("foreign key constraint failed"),
        serde_json::Value::Array(values) => values.iter().any(json_contains_foreign_key_failure),
        serde_json::Value::Object(values) => values.values().any(json_contains_foreign_key_failure),
        _ => false,
    }
}

fn normalized_browser_profile_identity(
    path: &str,
    volume_index_zero_based: Option<usize>,
) -> (Option<usize>, String) {
    (
        volume_index_zero_based,
        path.replace('\\', "/").trim_end_matches('/').to_string(),
    )
}

fn observed_browser_profile_count(
    candidates: &[(String, Option<usize>)],
    disclosures: &[serde_json::Value],
) -> usize {
    let mut identities = HashSet::new();
    for (path, volume) in candidates {
        identities.insert(normalized_browser_profile_identity(path, *volume));
    }
    let mut malformed_disclosures = 0_usize;
    for disclosure in disclosures {
        let Some(path) = disclosure
            .get("source_profile_path")
            .and_then(serde_json::Value::as_str)
        else {
            malformed_disclosures = malformed_disclosures.saturating_add(1);
            continue;
        };
        let volume = disclosure
            .get("volume_index_zero_based")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        identities.insert(normalized_browser_profile_identity(path, volume));
    }
    identities.len().saturating_add(malformed_disclosures)
}

fn browser_profile_disclosure_matches(
    disclosure: &serde_json::Value,
    candidate_identity: &(Option<usize>, String),
) -> bool {
    let Some(path) = disclosure
        .get("source_profile_path")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let volume = disclosure
        .get("volume_index_zero_based")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok());
    normalized_browser_profile_identity(path, volume) == *candidate_identity
}

fn browser_disclosure_diagnostic_count(item: &serde_json::Value) -> u64 {
    item.get("parse_error_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            item.get("parse_errors")
                .and_then(serde_json::Value::as_array)
                .map(|errors| errors.len() as u64)
                .unwrap_or(0)
        })
}

fn browser_disclosure_was_persisted(item: &serde_json::Value) -> bool {
    matches!(
        item.get("status").and_then(serde_json::Value::as_str),
        Some("completed" | "completed_with_errors")
    )
}

/// Post-index browser-artifact pass: detect profiles among the indexed
/// entries and replace each profile's derived records under the original
/// evidence source. A failure on one profile is reported and does not stop
/// the others.
fn run_browser_parsing_pass(
    case_path: &Path,
    evidence_id: i64,
    tracker: Option<&JobProgressTracker>,
) -> Result<serde_json::Value> {
    let source = live_evidence_source(case_path, evidence_id)?;
    let candidates = kdft_case::find_browser_profile_candidates(case_path, evidence_id)?;
    let ext_imports = browser_auto_import_disclosures(case_path, evidence_id)?;
    let candidate_identities = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.profile_path.clone(),
                candidate.volume_index_zero_based,
            )
        })
        .collect::<Vec<_>>();
    let profiles_observed = observed_browser_profile_count(&candidate_identities, &ext_imports);
    if let Some(tracker) = tracker {
        tracker.set_item_unit("profiles");
        tracker.set_total_items(Some(candidates.len() as u64));
    }
    let mut imported = Vec::new();
    let mut errors = Vec::new();
    let mut skipped_ext = 0_usize;
    for candidate in &candidates {
        if let Some(tracker) = tracker {
            tracker.set_current_object(candidate.profile_path.clone());
        }
        // ext-parsed profiles were already imported mid-walk.
        if candidate
            .filesystem_parser
            .as_deref()
            .is_some_and(|parser| parser.contains("ext"))
        {
            let candidate_identity = normalized_browser_profile_identity(
                &candidate.profile_path,
                candidate.volume_index_zero_based,
            );
            let matching_disclosure = ext_imports.iter().any(|disclosure| {
                browser_disclosure_was_persisted(disclosure)
                    && browser_profile_disclosure_matches(disclosure, &candidate_identity)
            });
            if matching_disclosure {
                skipped_ext += 1;
                if let Some(tracker) = tracker {
                    tracker.advance(1, Some(candidate.profile_path.clone()));
                }
                continue;
            }
        }
        let label = format!(
            "{} profile: {} (auto-parsed from {})",
            candidate.db_name, candidate.profile_path, source.display_name
        );
        let result = match source.source_kind.as_str() {
            "image" => {
                let Some(volume) = candidate.volume_index_zero_based else {
                    errors.push(serde_json::json!({
                        "profile": candidate.profile_path,
                        "error": "no volume index recorded for this entry",
                    }));
                    if let Some(tracker) = tracker {
                        tracker.record_error(Some(candidate.profile_path.clone()));
                        tracker.record_skip(Some(candidate.profile_path.clone()));
                        tracker.advance(1, Some(candidate.profile_path.clone()));
                    }
                    continue;
                };
                stage_and_import_image_profile_into_evidence(
                    case_path,
                    evidence_id,
                    &source.source_path,
                    volume,
                    &candidate.profile_path,
                    Some(label.clone()),
                    0,
                )
            }
            "folder" => {
                let local = Path::new(&source.source_path).join(
                    candidate
                        .profile_path
                        .replace('/', std::path::MAIN_SEPARATOR_STR),
                );
                import_browser_artifacts_into_evidence(
                    case_path,
                    ImportBrowserArtifactsIntoEvidenceOptions {
                        evidence_id,
                        history_path: local,
                        max_visits: 0,
                        source_profile_path: candidate.profile_path.clone(),
                        volume_index_zero_based: candidate.volume_index_zero_based,
                        legacy_evidence_name: Some(label),
                    },
                )
            }
            other => {
                errors.push(serde_json::json!({
                    "profile": candidate.profile_path,
                    "error": format!("browser parsing is not available for {other} evidence"),
                }));
                if let Some(tracker) = tracker {
                    tracker.record_error(Some(candidate.profile_path.clone()));
                    tracker.record_skip(Some(candidate.profile_path.clone()));
                    tracker.advance(1, Some(candidate.profile_path.clone()));
                }
                continue;
            }
        };
        match result {
            Ok(outcome) => {
                if outcome.parse_error_count > 0 {
                    if let Some(tracker) = tracker {
                        tracker.record_errors(
                            outcome.parse_error_count,
                            Some(candidate.profile_path.clone()),
                        );
                    }
                }
                imported.push(serde_json::json!({
                    "profile": candidate.profile_path,
                    "evidence_id": outcome.evidence_id,
                    "visits_indexed": outcome.visits_indexed,
                    "entries_indexed": outcome.entries_indexed,
                    "parse_errors": outcome.parse_errors,
                    "parse_error_count": outcome.parse_error_count,
                    "parse_error_samples_omitted": outcome.parse_error_samples_omitted,
                    "visit_limit_reached": outcome.visit_limit_reached,
                    "artifact_limit_reached": outcome.artifact_limit_reached,
                    "limited_artifact_kinds": outcome.limited_artifact_kinds,
                    "status": outcome.status,
                }));
            }
            Err(error) => {
                errors.push(serde_json::json!({
                    "profile": candidate.profile_path,
                    "error": error.to_string(),
                }));
                if let Some(tracker) = tracker {
                    tracker.record_error(Some(candidate.profile_path.clone()));
                    tracker.record_skip(Some(candidate.profile_path.clone()));
                }
            }
        }
        if let Some(tracker) = tracker {
            tracker.advance(1, Some(candidate.profile_path.clone()));
        }
    }
    let imported_parse_errors = imported.iter().fold(0_u64, |total, item| {
        total.saturating_add(
            item.get("parse_error_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| {
                    item.get("parse_errors")
                        .and_then(serde_json::Value::as_array)
                        .map(|errors| errors.len() as u64)
                        .unwrap_or(0)
                }),
        )
    });
    let ext_parse_errors = ext_imports.iter().fold(0_u64, |total, item| {
        total.saturating_add(browser_disclosure_diagnostic_count(item))
    });
    let ext_failures = ext_imports
        .iter()
        .filter(|item| item.get("status").and_then(serde_json::Value::as_str) == Some("failed"))
        .count();
    let ext_failures_without_diagnostics = ext_imports
        .iter()
        .filter(|item| {
            item.get("status").and_then(serde_json::Value::as_str) == Some("failed")
                && browser_disclosure_diagnostic_count(item) == 0
        })
        .count() as u64;
    let parse_error_count = imported_parse_errors.saturating_add(ext_parse_errors);
    let truncated = !errors.is_empty() || parse_error_count > 0 || ext_failures > 0;
    if truncated {
        if let Some(tracker) = tracker {
            let ext_error_events =
                ext_parse_errors.saturating_add(ext_failures_without_diagnostics);
            if ext_error_events > 0 {
                tracker.record_errors(
                    ext_error_events,
                    Some("EXT browser profile import".to_string()),
                );
            }
            tracker.record_truncation(format!(
                "browser parsing reported {} post-index profile failure(s), {} EXT profile failure(s), and {} parser/staging error(s)",
                errors.len(), ext_failures, parse_error_count
            ));
        }
    }
    Ok(serde_json::json!({
        "profiles_found": candidates.len(),
        "profiles_observed": profiles_observed,
        "profiles_handled_during_walk": skipped_ext,
        "imported": imported,
        "ext_imports": ext_imports,
        "ext_failures": ext_failures,
        "errors": errors,
        "parse_error_count": parse_error_count,
        "truncated": truncated,
        "status": if truncated { "truncated" } else { "completed" },
    }))
}

fn api_parse_browsers(body: &[u8]) -> Result<serde_json::Value> {
    let request: RemoveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    run_browser_parsing_pass(&case_path, request.evidence_id, None)
}

fn api_analyze_signatures(body: &[u8]) -> Result<kdft_case::AnalyzeSignaturesResult> {
    let request: AnalyzeSignaturesRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    analyze_signatures(
        &case_path,
        AnalyzeSignaturesOptions {
            evidence_id: request.evidence_id,
            // An omitted maximum scans every eligible indexed entry.
            max_entries: request.max_entries.unwrap_or(0),
        },
    )
}

fn api_remove_evidence(body: &[u8]) -> Result<kdft_case::RemoveEvidenceResult> {
    let request: RemoveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    remove_evidence(&case_path, request.evidence_id)
}

fn api_hash_evidence(body: &[u8]) -> Result<kdft_case::HashEvidenceResult> {
    let request: RemoveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    hash_evidence(&case_path, request.evidence_id)
}

fn api_carve_evidence(body: &[u8]) -> Result<kdft_case::CarveResult> {
    let request: CarveEvidenceRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    carve_evidence(
        &case_path,
        request.evidence_id,
        CarveOptions {
            max_scan_bytes: request.max_scan_bytes.unwrap_or(0),
            max_files: request.max_files.unwrap_or(0),
        },
    )
}

fn api_recover_entry(body: &[u8]) -> Result<kdft_case::RecoverEntryResult> {
    let request: RecoverEntryRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let output_path = request_path(&request.output_path, "output_path")?;
    recover_filesystem_entry(
        &case_path,
        RecoverEntryOptions {
            entry_id: request.entry_id,
            output_path,
        },
    )
}

const EXTERNAL_PREVIEW_MAX_BYTES: u64 = 256 * 1024 * 1024;

fn external_preview_extension(name: &str) -> Option<String> {
    let extension = Path::new(name)
        .extension()?
        .to_string_lossy()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "pdf"
            | "txt"
            | "log"
            | "csv"
            | "tsv"
            | "json"
            | "xml"
            | "rtf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ods"
            | "odt"
            | "ppt"
            | "pptx"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "bmp"
            | "webp"
            | "tif"
            | "tiff"
            | "wav"
            | "mp3"
            | "mp4"
            | "mov"
            | "avi"
    )
    .then_some(extension)
}

fn sanitize_external_preview_component(value: &str, max_len: usize) -> String {
    let mut sanitized = String::new();
    let mut previous_was_separator = false;
    for ch in value.chars() {
        let accepted = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_');
        if accepted {
            sanitized.push(ch);
            previous_was_separator = false;
        } else if !previous_was_separator {
            sanitized.push('_');
            previous_was_separator = true;
        }
        if sanitized.len() >= max_len {
            break;
        }
    }
    sanitized.trim_matches(['.', '_']).to_string()
}

fn safe_external_preview_name(entry_id: i64, name: &str) -> String {
    let leaf = name
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("preview.bin");
    let extension = Path::new(leaf)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| sanitize_external_preview_component(value, 16))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "bin".to_string());
    let stem = leaf.strip_suffix(&format!(".{extension}")).unwrap_or(leaf);
    let stem = sanitize_external_preview_component(stem, 96);
    let stem = if stem.is_empty() {
        "preview"
    } else {
        stem.as_str()
    };
    format!("{entry_id}-{stem}.{extension}")
}

fn external_preview_output_path(case_path: &Path, entry_id: i64, name: &str) -> PathBuf {
    let case_stem = case_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("case");
    let parent = case_path.parent().unwrap_or_else(|| Path::new("."));
    let base = parent
        .join(format!("{case_stem}-previews"))
        .join(safe_external_preview_name(entry_id, name));
    let mut candidate = base.clone();
    let mut suffix = 2usize;
    while candidate.exists() {
        let stem = base
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("preview");
        let extension = base.extension().and_then(|value| value.to_str());
        let file_name = extension.map_or_else(
            || format!("{stem}-{suffix}"),
            |extension| format!("{stem}-{suffix}.{extension}"),
        );
        candidate.set_file_name(file_name);
        suffix = suffix.saturating_add(1);
    }
    candidate
}

fn unique_report_output_path(requested_path: &Path) -> PathBuf {
    if !requested_path.exists() {
        return requested_path.to_path_buf();
    }
    let mut suffix = 2usize;
    let stem = requested_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("quick-report");
    let extension = requested_path
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty());
    let mut candidate = requested_path.to_path_buf();
    while candidate.exists() {
        let file_name = extension.map_or_else(
            || format!("{stem}-{suffix}"),
            |extension| format!("{stem}-{suffix}.{extension}"),
        );
        candidate = requested_path.with_file_name(file_name);
        suffix = suffix.saturating_add(1);
    }
    candidate
}

fn api_open_entry(body: &[u8]) -> Result<serde_json::Value> {
    let request: OpenEntryRequest = parse_json_body(body)?;
    if !request.acknowledge_host_app_risk {
        bail!(
            "opening untrusted evidence in a host application requires explicit examiner risk acknowledgement"
        );
    }
    let case_path = request_path(&request.case_path, "case_path")?;
    let entry = filesystem_entry_by_id(&case_path, request.entry_id)?
        .with_context(|| format!("filesystem entry {} not found", request.entry_id))?;
    if entry.entry_kind != "file" {
        bail!("only file entries can be opened externally");
    }
    let extension = external_preview_extension(&entry.name).with_context(|| {
        format!(
            "external preview is not enabled for {}; recover the file explicitly to inspect it safely",
            entry.name
        )
    })?;
    let size = entry
        .size_bytes
        .and_then(|value| u64::try_from(value).ok())
        .context("file size is unknown; recover the file explicitly before opening it")?;
    if size > EXTERNAL_PREVIEW_MAX_BYTES {
        bail!(
            "file is {} bytes; external preview is limited to {} bytes",
            size,
            EXTERNAL_PREVIEW_MAX_BYTES
        );
    }
    let output_path = external_preview_output_path(&case_path, entry.id, &entry.name);
    let recovered = recover_filesystem_entry(
        &case_path,
        RecoverEntryOptions {
            entry_id: entry.id,
            output_path: output_path.clone(),
        },
    )?;
    if recovered.status != "completed" || recovered.bytes_written != recovered.total_size {
        bail!(
            "preview recovery was partial ({} of {} bytes); the file was not opened",
            recovered.bytes_written,
            recovered.total_size
        );
    }
    let mut permissions = fs::metadata(&output_path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&output_path, permissions)
        .with_context(|| format!("marking preview copy read-only {}", output_path.display()))?;
    open_target(&output_path.to_string_lossy())?;
    Ok(json!({
        "entry_id": entry.id,
        "output_path": output_path,
        "bytes_written": recovered.bytes_written,
        "status": recovered.status,
        "extension": extension,
        "read_only": true,
    }))
}

fn api_import_history(body: &[u8]) -> Result<kdft_case::BrowserHistoryImportResult> {
    let request: ImportHistoryRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let history_path = request_path(&request.history_path, "history_path")?;
    import_browser_history(
        &case_path,
        ImportBrowserHistoryOptions {
            history_path,
            max_visits: request.max_visits.unwrap_or(0),
            evidence_name: request.evidence_name,
        },
    )
}

/// Browser history import (`import_browser_history`) needs several
/// co-located files on a real local path (History/Login Data/Cookies, or
/// places.sqlite/cookies.sqlite/logins.json) - it can't read them straight
/// out of an attached disk image. This stages the requested profile folder
/// out of the image (reusing the existing, already-validated live tree-export
/// machinery), then runs the normal importer against that local copy. The
/// staged copy is kept PERMANENTLY (next to the case file, not in a temp
/// directory that gets deleted) because the resulting evidence source's
/// `source_path` points at it - the byte viewer ("View bytes" on any imported
/// record) resolves real disk bytes back through that same path, so deleting
/// it would silently break byte-level review of everything just imported.
fn sanitize_staging_name(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "profile".to_string()
    } else {
        cleaned
    }
}

fn ensure_staging_directory_not_reparse(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading staging root metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("staging root cannot be a symbolic link: {}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("staging root cannot be a reparse point: {}", path.display());
        }
    }
    if !metadata.is_dir() {
        bail!("staging root is not a directory: {}", path.display());
    }
    Ok(())
}

fn api_import_history_from_image(body: &[u8]) -> Result<kdft_case::BrowserHistoryImportResult> {
    let request: ImportHistoryFromImageRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let source = live_evidence_source(&case_path, request.evidence_id)?;
    if source.source_kind != "image" {
        bail!(
            "import-from-image is only for disk-image evidence; folder/file evidence already \
             has a real local path - use the regular Browser history import with that path \
             instead"
        );
    }
    stage_and_import_image_profile(
        &case_path,
        request.evidence_id,
        &source.source_path,
        request.volume,
        &request.image_path,
        request.evidence_name,
        request.max_visits.unwrap_or(0),
    )
}

fn stage_image_profile(
    case_path: &Path,
    evidence_id: i64,
    source_path: &str,
    volume: usize,
    image_path: &str,
) -> Result<PathBuf> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let case_stem = case_path
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "case".to_string());
    let imports_root = case_path
        .parent()
        .map(|parent| parent.join(format!("{case_stem}-history-imports")))
        .unwrap_or_else(|| PathBuf::from(format!("{case_stem}-history-imports")));
    let profile_name = image_path
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("profile");
    let staging_key = format!(
        "{}|{}|{}",
        source_path.to_ascii_lowercase(),
        volume,
        image_path.replace('\\', "/").to_ascii_lowercase()
    );
    let digest = kdft_case::sha256_hex(staging_key.as_bytes());
    let staging_root = imports_root.join(format!(
        "{}-{}-{unique}",
        sanitize_staging_name(profile_name),
        &digest[..16]
    ));
    let building_root = imports_root.join(format!(
        ".{}-{}-building-{unique}",
        sanitize_staging_name(profile_name),
        &digest[..16]
    ));
    fs::create_dir_all(&imports_root)
        .with_context(|| format!("creating staging root {}", imports_root.display()))?;
    ensure_staging_directory_not_reparse(&imports_root)?;
    fs::create_dir(&building_root)
        .with_context(|| format!("creating staging folder {}", building_root.display()))?;
    let files_exported = export_indexed_browser_profile(
        case_path,
        evidence_id,
        image_path,
        Some(volume),
        &building_root,
    );
    let files_exported = match files_exported {
        Ok(result) => result,
        Err(err) => {
            return Err(err);
        }
    };
    if files_exported == 0 {
        bail!(
            "no files were found under {} - point this at the browser profile folder itself \
             (the one directly containing History/places.sqlite/Cookies/logins.json)",
            image_path
        );
    }
    fs::rename(&building_root, &staging_root).with_context(|| {
        format!(
            "publishing staging folder {} as {}",
            building_root.display(),
            staging_root.display()
        )
    })?;
    Ok(staging_root)
}

/// Manual import-from-image keeps a dedicated evidence source and publishes
/// each staged profile to a new path so an older import is never deleted.
fn stage_and_import_image_profile(
    case_path: &Path,
    evidence_id: i64,
    source_path: &str,
    volume: usize,
    image_path: &str,
    evidence_name: Option<String>,
    max_visits: usize,
) -> Result<kdft_case::BrowserHistoryImportResult> {
    let staging_root =
        stage_image_profile(case_path, evidence_id, source_path, volume, image_path)?;
    import_browser_history(
        case_path,
        ImportBrowserHistoryOptions {
            history_path: staging_root.clone(),
            max_visits,
            evidence_name,
        },
    )
}

fn stage_and_import_image_profile_into_evidence(
    case_path: &Path,
    evidence_id: i64,
    source_path: &str,
    volume: usize,
    image_path: &str,
    legacy_evidence_name: Option<String>,
    max_visits: usize,
) -> Result<kdft_case::BrowserHistoryImportResult> {
    let staging_root =
        stage_image_profile(case_path, evidence_id, source_path, volume, image_path)?;
    import_browser_artifacts_into_evidence(
        case_path,
        ImportBrowserArtifactsIntoEvidenceOptions {
            evidence_id,
            history_path: staging_root,
            max_visits,
            source_profile_path: image_path.to_string(),
            volume_index_zero_based: Some(volume),
            legacy_evidence_name,
        },
    )
}

fn api_deep_search(body: &[u8]) -> Result<kdft_case::DeepSearchPage> {
    let request: DeepSearchRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let page_size = request.max_results.unwrap_or(200);
    kdft_case::deep_search_page(
        &case_path,
        DeepSearchOptions {
            query: request.query,
            evidence_id: request.evidence_id,
            include_content: request.include_content.unwrap_or(true),
            // Kept for compatibility with the non-paged search options; the
            // paged API uses `page_size` as a response bound only.
            max_results: page_size,
            max_file_bytes: request.max_file_bytes.unwrap_or(64 * 1024),
            category: request.category.filter(|value| !value.trim().is_empty()),
            file_types: request
                .file_types
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .filter(|list| !list.is_empty()),
        },
        request.cursor,
        page_size,
    )
}

fn api_raw_search(body: &[u8]) -> Result<kdft_case::RawSearchResult> {
    let request: RawSearchRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    kdft_case::raw_disk_search_page(
        &case_path,
        kdft_case::RawDiskSearchOptions {
            evidence_id: request.evidence_id,
            query: request.query,
            max_results: request.max_results.unwrap_or(200),
            max_scan_bytes: request.max_scan_bytes.unwrap_or(0),
        },
        request.cursor,
    )
}

fn api_quick_bookmark(body: &[u8]) -> Result<QuickBookmarkResponse> {
    let request: QuickBookmarkRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    // Validate the whole request BEFORE the first case write: creating the
    // destination folder first meant a rejected request (bad bookmark_type /
    // item_ref_json) still left a permanent empty folder and its audit event
    // in the case.
    let item_ref_json = request.item_ref_json.unwrap_or_else(|| json!({}));
    if !item_ref_json.is_object() {
        bail!("item_ref_json must be a JSON object");
    }
    let bookmark_type = BookmarkType::parse(
        request
            .bookmark_type
            .as_deref()
            .unwrap_or("highlighted_data"),
    )?;
    let folder_name = request
        .folder_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Findings");
    let title = request
        .title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Bookmarked evidence")
        .to_string();
    let data_type = request
        .data_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Search Hit")
        .to_string();
    let source_ref_json = json!({
        "evidence_id": request.evidence_id,
        "entry_id": request.entry_id,
        "logical_path": request.logical_path,
    });
    let content_ref_json = json!({
        "selection_offset": request.selection_offset,
        "selection_length": request.selection_length,
        "preview": request.data_preview,
    });
    // One transaction for folder + bookmark + item: a failure at any step
    // (bad entry id, constraint violation) leaves nothing behind.
    let result = kdft_case::create_bookmark_with_items(
        &case_path,
        folder_name,
        CreateBookmarkOptions {
            folder_id: 0, // assigned inside the transaction
            bookmark_type,
            data_type: Some(data_type),
            title: Some(title),
            examiner_comment: request.comment,
            in_report: true,
            source_ref_json,
            content_ref_json,
        },
        vec![CreateBookmarkItemOptions {
            bookmark_id: 0, // assigned inside the transaction
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
    let item = result
        .items
        .into_iter()
        .next()
        .context("bookmark item was not created")?;
    Ok(QuickBookmarkResponse {
        folder_id: result.folder_id,
        bookmark_id: result.bookmark_id,
        item,
    })
}

fn api_clear_findings(body: &[u8]) -> Result<kdft_case::ClearStaleFindingsResult> {
    let request: ClearFindingsRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    clear_all_findings(&case_path)
}

fn api_remove_bookmark(body: &[u8]) -> Result<kdft_case::RemoveBookmarkResult> {
    let request: RemoveBookmarkRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    remove_bookmark(&case_path, request.bookmark_id)
}

fn api_remove_bookmark_item(body: &[u8]) -> Result<kdft_case::RemoveBookmarkItemResult> {
    let request: RemoveBookmarkItemRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    remove_bookmark_item(&case_path, request.item_id)
}

fn api_remove_bookmark_folder(body: &[u8]) -> Result<kdft_case::RemoveBookmarkFolderResult> {
    let request: RemoveBookmarkFolderRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    kdft_case::remove_bookmark_folder(&case_path, request.folder_id)
}

fn api_bulk_bookmark(body: &[u8]) -> Result<kdft_case::BulkBookmarkItemsResult> {
    let request: BulkBookmarkRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    if request.entry_ids.is_empty() {
        bail!("entry_ids must not be empty");
    }
    let folder_name = request
        .folder_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Findings");
    let bookmark_type =
        BookmarkType::parse(request.bookmark_type.as_deref().unwrap_or("file_group"))?;
    // One transaction for folder + bookmark + all items (see quick bookmark).
    let (_folder_id, result) =
        kdft_case::create_bookmark_with_bulk_entries(
            &case_path,
            folder_name,
            CreateBookmarkOptions {
                folder_id: 0, // assigned inside the transaction
                bookmark_type,
                data_type: request.data_type,
                title: Some(request.title.unwrap_or_else(|| {
                    format!("Bulk bookmark ({} entries)", request.entry_ids.len())
                })),
                examiner_comment: request.comment,
                in_report: true,
                source_ref_json: json!({}),
                content_ref_json: json!({}),
            },
            &request.entry_ids,
        )?;
    Ok(result)
}

fn recursive_bookmark_folder_title(path: &str) -> String {
    let display = if path.trim().is_empty() { "/" } else { path };
    format!("Folder (recursive): {display}")
}

fn api_bookmark_folder_recursive_indexed(
    body: &[u8],
) -> Result<kdft_case::RecursiveBookmarkResult> {
    let request: BookmarkFolderRecursiveIndexedRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let max_entries = resolve_unlimited_max_entries(request.max_entries);
    let folder_name = request
        .folder_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Evidence Folders");
    let folder_id = ensure_report_folder(&case_path, folder_name)?;
    let bookmark_id = create_bookmark(
        &case_path,
        CreateBookmarkOptions {
            folder_id,
            bookmark_type: BookmarkType::FolderInfo,
            data_type: Some("Evidence Folder (recursive)".to_string()),
            title: Some(
                request
                    .title
                    .unwrap_or_else(|| recursive_bookmark_folder_title(&request.logical_path)),
            ),
            examiner_comment: request.comment,
            in_report: true,
            source_ref_json: json!({
                "evidence_id": request.evidence_id,
                "logical_path": request.logical_path,
            }),
            content_ref_json: json!({}),
        },
    )?;
    bookmark_indexed_folder_recursive(
        &case_path,
        bookmark_id,
        request.evidence_id,
        &request.logical_path,
        max_entries,
    )
}

fn api_bookmark_folder_recursive_live(body: &[u8]) -> Result<kdft_case::RecursiveBookmarkResult> {
    let request: BookmarkFolderRecursiveLiveRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let max_entries = resolve_unlimited_max_entries(request.max_entries);
    let source = live_evidence_source(&case_path, request.evidence_id)?;
    let (volume_name, filesystem, listing) = match source.source_kind.as_str() {
        "image" => {
            let volumes = kdft_case::list_image_volumes(Path::new(&source.source_path))?;
            let volume = volumes
                .get(request.volume)
                .with_context(|| format!("volume index {} out of range", request.volume))?;
            let listing = list_image_tree_files(
                Path::new(&source.source_path),
                request.volume,
                &request.path,
                max_entries,
            )?;
            (volume.name.clone(), volume.filesystem.clone(), listing)
        }
        "folder" => {
            let listing =
                list_local_tree_files(&case_path, request.evidence_id, &request.path, max_entries)?;
            (String::new(), String::new(), listing)
        }
        other => bail!("recursive live bookmarking is not available for {other} evidence"),
    };
    let folder_name = request
        .folder_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Source Browse");
    let folder_id = ensure_report_folder(&case_path, folder_name)?;
    let path_title = if request.path.trim().is_empty() {
        "/"
    } else {
        &request.path
    };
    let bookmark_id = create_bookmark(
        &case_path,
        CreateBookmarkOptions {
            folder_id,
            bookmark_type: BookmarkType::FolderInfo,
            data_type: Some("Live folder (recursive)".to_string()),
            title: Some(
                request
                    .title
                    .unwrap_or_else(|| recursive_bookmark_folder_title(path_title)),
            ),
            examiner_comment: request.comment,
            in_report: true,
            source_ref_json: json!({
                "evidence_id": request.evidence_id,
                "volume": request.volume,
                "path": request.path,
            }),
            content_ref_json: json!({}),
        },
    )?;
    bookmark_live_folder_recursive(
        &case_path,
        bookmark_id,
        request.evidence_id,
        &source.source_kind,
        &source.source_path,
        request.volume,
        &volume_name,
        &filesystem,
        listing,
    )
}

const REPORT_DIRECTORY_TREE_MAX_LINES: usize = 2000;

// Re-run category classification over existing indexed entries without
// reading the evidence source again.
fn api_recategorize(body: &[u8]) -> Result<serde_json::Value> {
    let request: RecategorizeRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let updated = kdft_case::recategorize_case_entries(&case_path)?;
    Ok(serde_json::json!({ "entries_updated": updated }))
}

fn api_export_report(body: &[u8], config: &ServerConfig) -> Result<serde_json::Value> {
    let request: ExportReportRequest = parse_json_body(body)?;
    let case_path = request_path(&request.case_path, "case_path")?;
    let requested_output_path = request_path(&request.output_path, "output_path")?;
    let output_path = unique_report_output_path(&requested_output_path);
    let report = report_data_with_directory_structure(&case_path, REPORT_DIRECTORY_TREE_MAX_LINES)?;
    let rendered = render_report(&report);
    if let Some(parent) = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report directory {}", parent.display()))?;
    }
    kdft_case::write_new_file_atomically(&output_path, rendered.html.as_bytes())
        .with_context(|| format!("writing report {}", output_path.display()))?;
    // Hash the bytes actually written so `report_file_sha256` is reproducible
    // with an ordinary whole-file hash tool.
    let report_file_sha256 = kdft_case::sha256_hex(
        &fs::read(&output_path)
            .with_context(|| format!("re-reading report for hashing {}", output_path.display()))?,
    );
    record_report_export(
        &case_path,
        &output_path.to_string_lossy(),
        &rendered.content_prefix_sha256,
        &report_file_sha256,
    )?;
    let canonical_output = output_path
        .canonicalize()
        .with_context(|| format!("canonicalizing report {}", output_path.display()))?;
    config
        .exported_reports
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(canonical_output.clone());
    Ok(json!({
        "report": canonical_output,
        "folders": report.folders.len(),
        "content_prefix_sha256": rendered.content_prefix_sha256,
        "report_file_sha256": report_file_sha256
    }))
}

fn api_open_report(body: &[u8], config: &ServerConfig) -> Result<serde_json::Value> {
    let request: ExportReportRequest = parse_json_body(body)?;
    let output_path = request_path(&request.output_path, "output_path")?;
    let canonical_output = output_path
        .canonicalize()
        .with_context(|| format!("opening report {}", output_path.display()))?;
    let extension = canonical_output
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !matches!(extension.to_ascii_lowercase().as_str(), "html" | "htm") {
        bail!("only HTML reports exported by this KDFT process can be opened");
    }
    let was_exported = config
        .exported_reports
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&canonical_output);
    if !was_exported {
        bail!("report was not exported by this KDFT process");
    }
    open_target(&canonical_output.to_string_lossy())?;
    Ok(json!({ "opened": canonical_output }))
}

fn ensure_report_folder(case_path: &Path, folder_name: &str) -> Result<i64> {
    let folders = list_bookmark_folders(case_path)?;
    if let Some(folder) = folders
        .iter()
        .find(|folder| folder.parent_id.is_none() && folder.name == folder_name)
    {
        return Ok(folder.id);
    }
    create_bookmark_folder(case_path, None, folder_name, None, true)
}

fn parse_json_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    if body.is_empty() {
        bail!("request body is required");
    }
    serde_json::from_slice(body).context("parsing request JSON")
}

fn request_path(value: &str, field: &str) -> Result<PathBuf> {
    let normalized = normalize_request_path(value);
    if normalized.is_empty() {
        bail!("{field} is required");
    }
    if let Some(corrected) = existence_gated_path_correction(&normalized) {
        return Ok(PathBuf::from(corrected));
    }
    Ok(PathBuf::from(normalized))
}

// Cross-prefix paste rescue ("/home/a/Downloads//media/usb/x.dd"): the pure
// doubling detector only trusts a repeat of the path's own leading prefix, so
// a paste that switches roots needs this second chance. Rewriting is gated on
// the filesystem: only when the typed path does not exist and the candidate
// does can the rewrite never redirect a valid evidence path.
fn existence_gated_path_correction(value: &str) -> Option<String> {
    if Path::new(value).exists() {
        return None;
    }
    let restart = last_wellknown_root_restart(value)?;
    let corrected = value[restart..].trim();
    if !corrected.is_empty() && Path::new(corrected).exists() {
        Some(corrected.to_string())
    } else {
        None
    }
}

fn last_wellknown_root_restart(value: &str) -> Option<usize> {
    if !value.starts_with('/') {
        return None;
    }
    const PREFIXES: [&str; 6] = [
        "/Users/",
        "/home/",
        "/Volumes/",
        "/mnt/",
        "/media/",
        "/tmp/",
    ];
    let mut restart = None;
    for prefix in PREFIXES {
        let mut offset = 1;
        while offset < value.len() {
            let Some(position) = value[offset..].find(prefix) else {
                break;
            };
            let index = offset + position;
            restart = Some(restart.map_or(index, |current: usize| current.max(index)));
            offset = index + prefix.len();
        }
    }
    restart
}

fn normalize_request_path(value: &str) -> String {
    let trimmed = trim_balanced_path_quotes(value);
    let without_file_url = strip_file_url_prefix(&trimmed);
    correct_doubled_absolute_path(&without_file_url).unwrap_or(without_file_url)
}

fn trim_balanced_path_quotes(value: &str) -> String {
    let mut trimmed = value.trim();
    loop {
        let Some(first) = trimmed.chars().next() else {
            return String::new();
        };
        let Some(last) = trimmed.chars().next_back() else {
            return String::new();
        };
        let matching = matches!(
            (first, last),
            ('"', '"') | ('\'', '\'') | ('\u{201c}', '\u{201d}') | ('\u{2018}', '\u{2019}')
        );
        if !matching || trimmed.len() < first.len_utf8() + last.len_utf8() {
            break;
        }
        trimmed = trimmed[first.len_utf8()..trimmed.len() - last.len_utf8()].trim();
    }
    trimmed.to_string()
}

fn strip_file_url_prefix(value: &str) -> String {
    let Some(prefix) = value.get(..7) else {
        return value.to_string();
    };
    if !prefix.eq_ignore_ascii_case("file://") {
        return value.to_string();
    }
    let mut path = decode_percent_20(&value[7..]);
    if is_drive_marker_at(path.as_bytes(), 1) {
        path.remove(0);
    }
    path
}

fn decode_percent_20(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut lookahead = chars.clone();
            if matches!(lookahead.next(), Some(next) if next.eq_ignore_ascii_case(&'2'))
                && matches!(lookahead.next(), Some('0'))
            {
                chars.next();
                chars.next();
                decoded.push(' ');
                continue;
            }
        }
        decoded.push(ch);
    }
    decoded
}

fn correct_doubled_absolute_path(value: &str) -> Option<String> {
    let restart = [
        last_drive_restart(value),
        last_posix_restart(value),
        last_repeated_leading_prefix(value),
    ]
    .into_iter()
    .flatten()
    .max()?;
    let corrected = value[restart..].trim();
    if corrected.is_empty() {
        None
    } else {
        Some(corrected.to_string())
    }
}

fn last_drive_restart(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut restart = None;
    for index in 1..bytes.len().saturating_sub(2) {
        if is_drive_marker_at(bytes, index) && !drive_marker_inside_long_prefix(bytes, index) {
            restart = Some(index);
        }
    }
    restart
}

fn is_drive_marker_at(bytes: &[u8], index: usize) -> bool {
    index + 2 < bytes.len()
        && bytes[index].is_ascii_alphabetic()
        && bytes[index + 1] == b':'
        && matches!(bytes[index + 2], b'\\' | b'/')
}

fn drive_marker_inside_long_prefix(bytes: &[u8], index: usize) -> bool {
    if index < 4 {
        return false;
    }
    let prefix = &bytes[index - 4..index];
    prefix == b"\\\\?\\" || prefix == b"\\\\.\\" || prefix == b"//?/" || prefix == b"//./"
}

fn last_posix_restart(value: &str) -> Option<usize> {
    // Only the path's own leading components restarting mid-string is a safe
    // doubling signal; well-known roots like "/media/" or "/Users/" are legal
    // mid-path names ("/home/beel/media/photos" must not be rewritten).
    let leading = leading_posix_prefix(value)?;
    let mut offset = 1;
    let mut restart = None;
    while offset < value.len() {
        let Some(position) = value[offset..].find(leading) else {
            break;
        };
        let index = offset + position;
        restart = Some(index);
        offset = index + leading.len();
    }
    restart
}

fn leading_posix_prefix(value: &str) -> Option<&str> {
    if !value.starts_with('/') || value.len() < 4 || value.as_bytes()[1] == b'/' {
        return None;
    }
    let bytes = value.as_bytes();
    let first = bytes[1..].iter().position(|byte| *byte == b'/')? + 1;
    let second = bytes[first + 1..].iter().position(|byte| *byte == b'/')? + first + 1;
    if second == first + 1 {
        return None;
    }
    Some(&value[..=second])
}

fn last_repeated_leading_prefix(value: &str) -> Option<usize> {
    let prefix = leading_double_slash_prefix(value)?;
    let mut offset = 1;
    let mut restart = None;
    while offset < value.len() {
        let Some(position) = value[offset..].find(prefix) else {
            break;
        };
        let index = offset + position;
        restart = Some(index);
        offset = index + prefix.len();
    }
    restart
}

fn leading_double_slash_prefix(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() < 4 || !is_separator(bytes[0]) || bytes[0] != bytes[1] {
        return None;
    }
    let first = bytes[2..]
        .iter()
        .position(|byte| is_separator(*byte))
        .map(|position| position + 2)?;
    if first == 2 || first + 1 >= bytes.len() {
        return None;
    }
    let second = bytes[first + 1..]
        .iter()
        .position(|byte| is_separator(*byte))
        .map(|position| position + first + 1);
    match second {
        Some(index) if index > first + 1 => Some(&value[..index]),
        None => Some(value),
        _ => None,
    }
}

fn is_separator(byte: u8) -> bool {
    matches!(byte, b'\\' | b'/')
}

#[cfg(test)]
mod tests {
    use super::{
        api_add_evidence, api_carve_evidence, api_image_dir, api_job_progress, api_state,
        append_optional_processing_passes, browser_disclosure_diagnostic_count,
        browser_disclosure_was_persisted, browser_profile_disclosure_matches,
        cached_indexed_directory, external_preview_extension, external_preview_output_path,
        inline_script_json, normalize_request_path, normalized_browser_profile_identity,
        observed_browser_profile_count, parse_archives_enabled, parse_documents_enabled,
        parse_windows_artifacts_enabled, process_stage_count, run_optional_processing_pass,
        safe_external_preview_name, trim_balanced_path_quotes, ProcessEvidenceRequest, ServerArgs,
        StreamingDiagnosticLog, INDEX_HTML,
    };
    use super::{DeepSearchRequest, RawSearchRequest};
    use kdft_case::progress::{JobProgressState, JobProgressTracker};
    use rusqlite::{params, Connection};
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn unique_test_path(label: &str, suffix: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!(
            "kdft-ui-{label}-{}-{nonce}{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn server_arguments_handle_help_version_and_invalid_values_without_starting(
    ) -> anyhow::Result<()> {
        assert!(ServerArgs::parse_from([OsString::from("--help")])?.is_none());
        assert!(ServerArgs::parse_from([OsString::from("--version")])?.is_none());
        assert!(ServerArgs::parse_from([OsString::from("--unknown")]).is_err());
        assert!(
            ServerArgs::parse_from([OsString::from("--port"), OsString::from("not-a-port")])
                .is_err()
        );

        let parsed = ServerArgs::parse_from([
            OsString::from("--host"),
            OsString::from("::1"),
            OsString::from("--port"),
            OsString::from("8780"),
            OsString::from("--case"),
            OsString::from("C:\\Cases\\demo.kdft.sqlite"),
            OsString::from("--open"),
        ])?
        .ok_or_else(|| anyhow::anyhow!("valid server arguments did not request a server run"))?;
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port, 8780);
        assert_eq!(
            parsed.case_path,
            Some(PathBuf::from("C:\\Cases\\demo.kdft.sqlite"))
        );
        assert!(parsed.open);
        Ok(())
    }

    #[test]
    fn inline_bootstrap_json_cannot_terminate_the_script_element() {
        let payload = serde_json::json!({
            "path": "C:/evidence/</script><script>globalThis.pwned=true</script>/image.E01",
            "separators": "\u{2028}\u{2029}&<>"
        });
        let encoded = inline_script_json(&payload);
        assert!(!encoded.contains("</script>"));
        assert!(!encoded.contains("<script>"));
        assert!(encoded.contains("\\u003c/script\\u003e"));
        assert!(encoded.contains("\\u2028\\u2029\\u0026\\u003c\\u003e"));
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    fn create_ui_test_case(case_path: &Path, name: &str) -> anyhow::Result<()> {
        kdft_case::create_case(
            case_path,
            kdft_case::CreateCaseOptions {
                name: name.to_string(),
                examiner_name: None,
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )?;
        Ok(())
    }

    fn create_ui_test_chromium_history(history_path: &Path) -> anyhow::Result<()> {
        let conn = Connection::open(history_path)?;
        conn.execute_batch(
            "CREATE TABLE urls(
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER NOT NULL,
                typed_count INTEGER NOT NULL,
                last_visit_time INTEGER NOT NULL,
                hidden INTEGER NOT NULL
             );
             CREATE TABLE visits(
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER,
                transition INTEGER NOT NULL,
                segment_id INTEGER,
                visit_duration INTEGER NOT NULL
             );
             INSERT INTO urls(id, url, title, visit_count, typed_count, last_visit_time, hidden)
             VALUES (1, 'https://example.test/detected', 'Detected History', 1, 1, 13300000020000000, 0);
             INSERT INTO visits(id, url, visit_time, from_visit, transition, segment_id, visit_duration)
             VALUES (1, 1, 13300000020000000, 0, 1, 0, 1000);",
        )?;
        Ok(())
    }

    fn processing_request(
        capture_content: bool,
        parse_archives: Option<bool>,
        parse_documents: Option<bool>,
        parse_windows_artifacts: Option<bool>,
    ) -> ProcessEvidenceRequest {
        ProcessEvidenceRequest {
            case_path: "unused.kdft.sqlite".to_string(),
            evidence_id: 1,
            max_entries: Some(0),
            progress_id: None,
            reindex_filesystem: Some(false),
            capture_content: Some(capture_content),
            parse_emails: Some(false),
            parse_browsers: Some(false),
            parse_identities: Some(false),
            parse_archives,
            parse_documents,
            parse_windows_artifacts,
            run_hash: Some(false),
            run_file_hash: Some(false),
            run_signature_analysis: Some(false),
            run_carve: Some(false),
            carve_max_scan_bytes: Some(0),
            carve_max_files: Some(0),
        }
    }

    #[test]
    fn processing_diagnostics_are_saved_beside_the_case_with_messages() -> anyhow::Result<()> {
        let case_path = unique_test_path("diagnostic-log", ".kdft.sqlite");
        let log = StreamingDiagnosticLog::start(&case_path, 7, "processors")?;
        let tracker = JobProgressTracker::new_with_diagnostic_observer(
            "diagnostic-test",
            "process",
            None,
            Some(log.observer()),
        );
        tracker.start_stage(
            "Structured artifact parsing",
            1,
            Some(1),
            "records",
            Some(1),
        );
        tracker.advance(1, Some("parsed a known-answer record".to_string()));
        for index in 0..25 {
            tracker.record_truncation(format!("known decoder limitation disclosed #{index:02}"));
        }
        tracker.finish(JobProgressState::Truncated);
        let response = serde_json::json!({
            "status": "truncated",
            "limitation": "known decoder limitation disclosed"
        });
        log.finish(&tracker.snapshot(), Some(&response), None)?;
        let path = log.path.clone();
        let text = fs::read_to_string(&path)?;
        assert!(text.contains("source_evidence_modified=false"));
        assert!(text.contains("event_format=json_lines"));
        assert!(text.contains("parsed a known-answer record"));
        assert!(text.contains("known decoder limitation disclosed #24"));
        assert!(text.contains("\"kind\":\"partial_coverage\""));
        let expected_directory = case_path.parent().unwrap().join(format!(
            "{}.logs",
            case_path.file_name().unwrap().to_string_lossy()
        ));
        assert_eq!(path.parent(), Some(expected_directory.as_path()));
        if let Some(directory) = path.parent() {
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }

    #[test]
    fn active_progress_exposes_the_complete_diagnostic_log_path() -> anyhow::Result<()> {
        let case_path = unique_test_path("active-diagnostic-log", ".kdft.sqlite");
        let log = StreamingDiagnosticLog::start(&case_path, 9, "analysis")?;
        let config = super::ServerConfig::new(None)?;
        let progress_id = "diagnostic-path-test";
        let tracker = config.progress.start(
            progress_id,
            "process",
            Some(log.observer()),
            Some(log.path.clone()),
        )?;
        tracker.start_stage("Inventory", 1, Some(1), "entries", None);
        tracker.record_truncation("complete-stream-known-answer");
        let query = HashMap::from([("progress_id".to_string(), progress_id.to_string())]);
        let progress = api_job_progress(&query, &config)?;
        assert_eq!(
            progress["diagnostic_log_path"].as_str(),
            Some(log.path.to_string_lossy().as_ref())
        );
        assert_eq!(progress["diagnostic_event_count"], 2);
        let text = fs::read_to_string(&log.path)?;
        assert!(text.contains("complete-stream-known-answer"));
        if let Some(directory) = log.path.parent() {
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }

    #[test]
    fn artifact_processors_are_selectable_independently_of_content_capture() {
        let selected = processing_request(false, Some(true), Some(true), Some(true));
        assert!(parse_archives_enabled(&selected));
        assert!(parse_documents_enabled(&selected));
        assert!(parse_windows_artifacts_enabled(&selected));
        assert_eq!(process_stage_count(&selected), 6);

        let skipped = processing_request(true, Some(false), Some(false), Some(false));
        assert!(!parse_archives_enabled(&skipped));
        assert!(!parse_documents_enabled(&skipped));
        assert!(!parse_windows_artifacts_enabled(&skipped));
        assert_eq!(process_stage_count(&skipped), 2);
    }

    #[test]
    fn legacy_processing_requests_keep_their_previous_parser_defaults() {
        let metadata_only = processing_request(false, None, None, None);
        assert_eq!(process_stage_count(&metadata_only), 2);

        let content_enabled = processing_request(true, None, None, None);
        assert_eq!(process_stage_count(&content_enabled), 6);
    }

    #[test]
    fn processing_panel_exposes_only_real_selectable_processors() {
        for id in [
            "optParseArchives",
            "optParseDocuments",
            "optParseWindowsArtifacts",
            "optParseIdentities",
        ] {
            assert!(INDEX_HTML.contains(&format!("id=\"{id}\"")));
        }
        assert!(!INDEX_HTML.contains("input type=\"checkbox\" disabled"));
        assert!(!INDEX_HTML.contains("links / jump lists (not yet supported)"));
        assert!(!INDEX_HTML.contains("event logs (not yet supported)"));
        for redundant_label in [
            "> Parse email messages<",
            "> Parse browser artifacts<",
            "> Parse identities",
            "> Parse ZIP",
            "> Parse DOCX",
            "> Parse Windows artifacts",
        ] {
            assert!(!INDEX_HTML.contains(redundant_label));
        }
        assert!(!INDEX_HTML.contains(
            "Live Browse (before processing) always shows the full disk read-only with no limit"
        ));
        assert!(!INDEX_HTML.contains("E01, dd/raw, VHD/VHDX, VMDK, VDI disk images"));
        assert!(INDEX_HTML.contains("Attach only keeps the evidence read-only"));
        assert!(!INDEX_HTML.contains(">Live browse</button>"));
        assert!(INDEX_HTML.contains(">Browse source</button>"));
        assert!(INDEX_HTML.contains(">Choose&hellip;</button>"));
        assert!(INDEX_HTML.contains(">View index</button>"));
    }

    #[test]
    fn deep_search_survives_navigation_and_fullscreen_back() {
        assert!(INDEX_HTML.contains("function persistDeepSearchSession()"));
        assert!(INDEX_HTML.contains("function restoreDeepSearchSession()"));
        assert!(INDEX_HTML.contains("function deepSearchSessionCasePath()"));
        let persistence = INDEX_HTML
            .split_once("function persistDeepSearchSession() {")
            .expect("Deep Search persistence function")
            .1
            .split_once("function restoreDeepSearchSession()")
            .expect("end of Deep Search persistence function")
            .0;
        assert!(persistence.contains("const casePath = deepSearchSessionCasePath()"));
        assert!(!persistence.contains("currentCasePath()"));
        assert!(INDEX_HTML.contains("sessionStorage.setItem(deepSearchSessionKey(casePath)"));
        assert!(
            INDEX_HTML.contains("window.addEventListener(\"pagehide\", persistDeepSearchSession)")
        );
        assert!(INDEX_HTML.contains("kdftViewerFullscreen: true"));
        assert!(INDEX_HTML.contains("window.addEventListener(\"popstate\""));
        assert!(!INDEX_HTML.contains("$(\"bitwiseControls\").hidden"));
        assert!(!INDEX_HTML.contains(
            "This case has no indexed entries; Deep Search only searches processed evidence"
        ));
    }

    #[test]
    fn case_refresh_ignores_out_of_order_responses() {
        let refresh = INDEX_HTML
            .split_once("async function refresh() {")
            .expect("refresh function")
            .1
            .split_once("function suggestedNewCasePath()")
            .expect("end of refresh function")
            .0;
        assert!(refresh.contains("const generation = ++state.refreshGeneration"));
        assert!(
            refresh
                .matches("refreshRequestIsCurrent(casePath, generation)")
                .count()
                >= 3
        );
        assert!(refresh.contains("state.loadedCasePath = casePath"));
        assert!(INDEX_HTML.contains("function clearLoadedCaseForRefresh(casePath)"));
        assert!(INDEX_HTML.contains("loaded && state.loadedCasePath === target"));
    }

    #[test]
    fn restored_tabs_refresh_local_auth_and_tolerate_missing_optional_controls() {
        assert!(INDEX_HTML.contains("async function fetchWithLocalAuthRetry(request)"));
        assert!(INDEX_HTML.contains("if (response.status !== 403)"));
        assert!(INDEX_HTML.contains("await refreshLocalUiAuthentication()"));
        assert!(INDEX_HTML.contains("credentials: \"same-origin\""));
        assert!(INDEX_HTML.contains("if (recategorizeButton)"));
        assert!(!INDEX_HTML.contains("$(\"recategorizeBtn\").hidden"));
        assert!(!INDEX_HTML.contains("$(\"fsOptionsRow\").hidden"));
        assert!(!INDEX_HTML.contains("$(\"historyOptionsRow\").hidden"));
    }

    #[test]
    fn selected_search_bookmarking_includes_filtered_out_rows() {
        let bookmarking = INDEX_HTML
            .split_once("async function bookmarkSelectedSearchResults() {")
            .expect("selected search bookmarking function")
            .1
            .split_once("async function clearFindings()")
            .expect("end of selected search bookmarking function")
            .0;
        assert!(bookmarking.contains("const indexedRows = selectedSearchResultRows()"));
        assert!(bookmarking.contains("const rawRows = selectedRawSearchResultRows()"));
        assert!(!bookmarking.contains("selectedVisibleSearchResultRows()"));
        assert!(!bookmarking.contains("selectedVisibleRawSearchResultRows()"));
        assert!(bookmarking.contains("remainingIndexedKeys.delete(row.key)"));
        assert!(bookmarking.contains("remainingRawKeys.delete(row.key)"));
    }

    #[test]
    fn raw_search_continuation_preserves_grid_filters_and_sort() {
        let load_more = INDEX_HTML
            .split_once("async function loadMoreRawSearchResults() {")
            .expect("raw search continuation function")
            .1
            .split_once("function bitwiseStopReasonNote(merged)")
            .expect("end of raw search continuation function")
            .0;
        assert!(!load_more.contains("resetGridView(\"rawSearch\")"));
        assert!(load_more.contains("renderRawSearchResults()"));
    }

    #[test]
    fn fullscreen_history_exit_is_single_step_and_popstate_synchronized() {
        let fullscreen = INDEX_HTML
            .split_once("function setViewerFullscreen(enabled, historyMode = \"auto\") {")
            .expect("fullscreen state function")
            .1
            .split_once("function updateEntryRowHighlight()")
            .expect("end of fullscreen state functions")
            .0;
        assert!(fullscreen.contains("state.viewerFullscreenHistoryPending = true"));
        assert_eq!(fullscreen.matches("history.back()").count(), 1);
        assert!(fullscreen.contains("function toggleViewerFullscreen()"));
        assert!(INDEX_HTML.contains(
            "setViewerFullscreen(Boolean(event.state && event.state.kdftViewerFullscreen), \"popstate\")"
        ));
    }

    #[test]
    fn analysis_fullscreen_preserves_direct_browse_location() {
        assert!(INDEX_HTML.contains("const location = currentAnalyzeLocation();"));
        assert!(INDEX_HTML.contains("params.set(\"tree_mode\", treeMode)"));
        assert!(INDEX_HTML.contains("params.set(\"live_volume\", String(location.liveVolume))"));
        assert!(INDEX_HTML.contains("PAGE_PARAMS.get(\"tree_mode\") === \"live\""));
        assert!(INDEX_HTML.contains("await applyPendingAnalysisSelection();"));
        assert!(INDEX_HTML.contains("await applyAnalyzeLocation({"));
        assert!(INDEX_HTML.contains("params.set(\"viewer_target\", \"live\")"));
        assert!(INDEX_HTML.contains("params.set(\"viewer_target\", \"raw\")"));
        assert!(INDEX_HTML.contains("params.set(\"viewer_entry_id\", String(state.hex.entryId))"));
        assert!(INDEX_HTML.contains("await restorePendingViewerTarget(pending, evidence)"));
        assert!(INDEX_HTML.contains("pending.applying || !state.data"));
        assert!(INDEX_HTML.contains("if (!pendingLiveRestore && maybeAutoLiveBrowse(evidence))"));
        assert!(!INDEX_HTML.contains(
            "${liveBrowseButtonHtml(evidence)}\n               ${processActionHtml(evidence)}"
        ));
    }

    #[test]
    fn bitwise_hits_support_shared_multi_selection_and_bulk_bookmarking() {
        assert!(INDEX_HTML.contains("selectedRawSearchKeys: new Set()"));
        assert!(INDEX_HTML.contains("{ key: \"select\", label: \"\", sortable: false"));
        assert!(INDEX_HTML.contains("function toggleRawSearchHitSelection"));
        assert!(INDEX_HTML.contains("function selectedVisibleRawSearchResultRows"));
        assert!(INDEX_HTML.contains("function selectedRawSearchResultRows"));
        assert!(INDEX_HTML.contains("bookmarkRawSearchHitRecord(row.hit"));
        assert!(INDEX_HTML.contains("remainingRawKeys.delete(row.key)"));
        assert!(INDEX_HTML.contains("event.shiftKey && state.lastRawSearchKey"));
        assert!(INDEX_HTML.contains("aria-label=\"Select raw hit at"));
    }

    #[test]
    fn large_category_view_filters_before_paging_and_loads_on_scroll() {
        assert!(INDEX_HTML.contains("function armCategoryInfiniteScroll"));
        assert!(INDEX_HTML.contains("new IntersectionObserver"));
        assert!(INDEX_HTML.contains("filter_extension"));
        assert!(INDEX_HTML.contains("params.after_path = cache.nextCursor.logical_path"));
        assert!(INDEX_HTML.contains("Scroll to load more results"));
        assert!(!INDEX_HTML.contains("onclick=\"loadMoreCategoryEntries()\""));
    }

    #[test]
    fn analysis_messages_stay_outside_the_evidence_and_inspector_panes() {
        assert!(!INDEX_HTML.contains("id=\"analysisNotice\""));
        assert!(!INDEX_HTML.contains("id=\"viewerNotice\""));
        assert!(INDEX_HTML.contains("function processingCompletionNotice"));
        assert!(INDEX_HTML.contains("Diagnostic log: "));
    }

    #[test]
    fn every_main_category_has_an_independent_expand_collapse_toggle() {
        assert!(INDEX_HTML.contains("collapsedCategoryMains: new Set()"));
        assert!(INDEX_HTML.contains("function toggleCategoryMain(mainName)"));
        assert!(INDEX_HTML.contains("toggleCategoryMain('"));
        assert!(INDEX_HTML.contains("title=\"${expanded ? \"Collapse\" : \"Expand\"}"));
    }

    #[test]
    fn api_state_keeps_parser_records_out_of_entries_but_in_categories() -> anyhow::Result<()> {
        let case_path = unique_test_path("entry-category-separation", ".sqlite");
        let source_dir = unique_test_path("entry-category-separation-source", "");
        fs::create_dir_all(&source_dir)?;
        fs::write(source_dir.join("FTK Imager 8.2.0.iso"), b"physical iso")?;
        create_ui_test_case(&case_path, "entry-category-separation")?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: source_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        kdft_case::process_evidence(
            &case_path,
            kdft_case::ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;

        let conn = Connection::open(&case_path)?;
        let case_id: i64 = conn.query_row("SELECT id FROM cases LIMIT 1", [], |row| row.get(0))?;
        conn.execute(
            "INSERT INTO filesystem_entries(
                 case_id, evidence_id, logical_path, name, entry_kind, metadata_json
             ) VALUES (?1, ?2, '/Windows Artifacts/usn/1.record',
                       'FTK Imager 8.2.0.iso', 'record', ?3)",
            params![
                case_id,
                evidence_id,
                serde_json::json!({
                    "artifact_kind": "windows_usn_record",
                    "category_main": "User Activity",
                    "category_sub": "NTFS change journal",
                    "category_hidden": false,
                })
                .to_string(),
            ],
        )?;
        drop(conn);

        let query = HashMap::from([(
            "case_path".to_string(),
            case_path.to_string_lossy().into_owned(),
        )]);
        let state = api_state(&query)?;
        assert!(state
            .entries
            .iter()
            .all(|entry| entry.entry_kind != "record"));
        assert_eq!(state.entry_count as usize, state.entries.len());
        assert!(state.category_counts.iter().any(|row| {
            row.main == "User Activity" && row.sub == "NTFS change journal" && row.count == 1
        }));

        let _ = fs::remove_file(&case_path);
        let _ = fs::remove_file(case_path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(case_path.with_extension("sqlite-shm"));
        let _ = fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn live_browse_distinguishes_raw_bytes_from_volumes_and_indexed_categories() {
        assert!(INDEX_HTML.contains("Image bytes (raw; not a volume)"));
        assert!(INDEX_HTML
            .contains("The raw image row is a byte view and is not counted as another volume."));
        assert!(INDEX_HTML.contains("analysis-status transient-guidance"));
        assert!(INDEX_HTML.contains(
            "animation: transientGuidanceExpire var(--guidance-duration, 7s) ease forwards"
        ));
        assert!(INDEX_HTML.contains("liveGuidanceExpiresAt: 0"));
        assert!(INDEX_HTML.contains("state.liveGuidanceExpiresAt = Date.now() + 7000"));
        assert!(INDEX_HTML.contains("const guidanceRemainingMs = Math.max(0"));
        assert!(INDEX_HTML
            .contains("$(\"treeCount\").textContent = String(state.live.volumes.length);"));
        assert!(INDEX_HTML.contains("leaveLiveBrowseForIndexedMode()"));
        assert!(INDEX_HTML
            .contains("direct-browse rows are intentionally not mirrored into Categories"));
        assert!(INDEX_HTML.contains("Closed source browse. Showing indexed categories."));
    }

    #[test]
    fn picture_gallery_is_available_for_indexed_and_live_images() {
        assert!(INDEX_HTML.contains("function renderThumbnailCategoryContents"));
        assert!(INDEX_HTML.contains("function renderLiveThumbnailContents"));
        assert!(INDEX_HTML.contains("Gallery view"));
        assert!(INDEX_HTML.contains("/api/image/raw?case_path="));
        assert!(INDEX_HTML.contains("/api/entry/raw?case_path="));
    }

    #[test]
    fn browser_profile_observed_count_unions_path_and_volume_exactly() {
        let candidates = vec![
            ("/home/alice/.config/chromium/Default".to_string(), Some(0)),
            ("/home/alice/.config/chromium/Default".to_string(), Some(1)),
            ("C:\\Users\\Alice\\Chrome\\Default".to_string(), None),
        ];
        let disclosures = vec![
            serde_json::json!({
                "source_profile_path": "/home/alice/.config/chromium/Default/",
                "volume_index_zero_based": 0,
            }),
            serde_json::json!({
                "source_profile_path": "/home/bob/.mozilla/firefox/gold.default",
                "volume_index_zero_based": 1,
            }),
            serde_json::json!({
                "source_profile_path": "C:/Users/Alice/Chrome/Default",
                "volume_index_zero_based": null,
            }),
            serde_json::json!({"status": "failed"}),
        ];

        // Two overlap exactly after separator normalization, one disclosure
        // is disjoint, the same EXT path on another volume stays distinct,
        // and a malformed failed disclosure is still counted visibly.
        assert_eq!(observed_browser_profile_count(&candidates, &disclosures), 5);
        let volume_one =
            normalized_browser_profile_identity("/home/alice/.config/chromium/Default", Some(1));
        assert!(!browser_profile_disclosure_matches(
            &disclosures[0],
            &volume_one
        ));
        assert_eq!(
            browser_disclosure_diagnostic_count(&serde_json::json!({
                "status": "failed",
                "parse_errors": ["legacy sampled error"]
            })),
            1
        );
        assert!(!browser_disclosure_was_persisted(
            &serde_json::json!({"status": "failed"})
        ));
        assert!(browser_disclosure_was_persisted(
            &serde_json::json!({"status": "completed_with_errors"})
        ));
        assert!(!browser_profile_disclosure_matches(
            &serde_json::json!({
                "source_profile_path": "/home/alice/.config/chromium/Default"
            }),
            &volume_one
        ));
    }

    fn cleanup_ui_test_case(case_path: &Path) {
        let _ = std::fs::remove_file(case_path);
        let case_text = case_path.to_string_lossy();
        let _ = std::fs::remove_file(format!("{case_text}-wal"));
        let _ = std::fs::remove_file(format!("{case_text}-shm"));
    }

    #[test]
    fn manual_carve_api_defaults_to_unlimited_file_count() -> anyhow::Result<()> {
        let case_path = unique_test_path("carve-unlimited-default", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "carve-unlimited-default")?;
        let source_dir = unique_test_path("carve-unlimited-source", "");
        std::fs::create_dir_all(&source_dir)?;
        let image_path = source_dir.join("many-jpegs.img");
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, b'x', 0xFF, 0xD9, 0];
        let mut image = Vec::with_capacity(jpeg.len() * 1_001);
        for _ in 0..1_001 {
            image.extend_from_slice(&jpeg);
        }
        std::fs::write(&image_path, image)?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: image_path,
                kind: kdft_case::EvidenceKind::Image,
                read_file_system_requested: false,
                notes: None,
            },
        )?;

        let body = serde_json::json!({
            "case_path": case_path.to_string_lossy(),
            "evidence_id": evidence_id
        })
        .to_string();
        let result = api_carve_evidence(body.as_bytes())?;
        assert_eq!(result.carved_files, 1_001);
        assert_eq!(result.status, "completed");
        assert!(!result.truncated);

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn add_evidence_api_detects_and_imports_bare_chromium_history() -> anyhow::Result<()> {
        let case_path = unique_test_path("detected-history", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "detected-history")?;
        let profile_dir = unique_test_path("chromium-profile", "");
        std::fs::create_dir_all(&profile_dir)?;
        let history_path = profile_dir.join("History");
        create_ui_test_chromium_history(&history_path)?;
        // The already-detected family must stay authoritative even if another
        // supported DB name is present beside the selected History file.
        Connection::open(profile_dir.join("places.sqlite"))?
            .execute_batch("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT);")?;

        let body = serde_json::json!({
            "case_path": case_path.to_string_lossy(),
            "path": history_path.to_string_lossy(),
            // Reproduce the Image-path UI flow that originally misclassified
            // the extensionless SQLite database as disk evidence.
            "kind": "image",
            "read_file_system": true
        })
        .to_string();
        let response = api_add_evidence(body.as_bytes())?;
        assert_eq!(response["detected"], "chromium_history_database");
        assert_eq!(response["visits_indexed"], 1);
        assert!(response["entries_indexed"].as_u64().unwrap_or_default() >= 2);

        let evidence = kdft_case::list_evidence(&case_path)?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source_kind, "browser_history");
        assert!(evidence
            .iter()
            .all(|source| source.source_kind != "image" && source.source_kind != "file"));

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(profile_dir);
        Ok(())
    }

    #[test]
    fn browser_post_index_pass_surfaces_exact_ext_import_failure() -> anyhow::Result<()> {
        let case_path = unique_test_path("ext-browser-disclosure", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "ext-browser-disclosure")?;
        let evidence_dir = unique_test_path("ext-browser-disclosure-source", "");
        let profile_dir = evidence_dir.join("User Data").join("Default");
        std::fs::create_dir_all(&profile_dir)?;
        create_ui_test_chromium_history(&profile_dir.join("History"))?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        kdft_case::process_evidence_with_profile(
            &case_path,
            kdft_case::ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
            kdft_case::ProcessingProfile {
                capture_content: false,
                parse_emails: false,
                parse_browsers: false,
            },
        )?;

        let conn = Connection::open(&case_path)?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = json_set(
                 json_remove(metadata_json, '$.source_path_exact'),
                 '$.filesystem_parser', 'ext4',
                 '$.ext_path', '/home/alice/.config/chromium/Default/History',
                 '$.partition_index', 1
             )
             WHERE evidence_id = ?1 AND name = 'History'",
            [evidence_id],
        )?;
        let job_id: i64 = conn.query_row(
            "SELECT id FROM evidence_jobs
             WHERE evidence_id = ?1 AND job_type = 'filesystem_index'
             ORDER BY id DESC LIMIT 1",
            [evidence_id],
            |row| row.get(0),
        )?;
        conn.execute(
            "UPDATE evidence_jobs SET parameters_json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::json!({
                    "auto_browser_imports": [{
                        "browser_derivation_key": "ext-failed-profile",
                        "source_profile_path": "/home/alice/.config/chromium/Default",
                        "volume_index_zero_based": 0,
                        "entries_indexed": 0,
                        "parse_errors": ["sampled staging error"],
                        "parse_error_count": 3,
                        "parse_error_samples_omitted": 2,
                        "status": "failed"
                    }],
                    "browser_parse_error_count": 3
                })
                .to_string(),
                job_id,
            ],
        )?;
        drop(conn);

        let response = super::run_browser_parsing_pass(&case_path, evidence_id, None)?;
        assert_eq!(response["profiles_found"].as_u64(), Some(1));
        assert_eq!(response["profiles_observed"].as_u64(), Some(1));
        assert_eq!(response["profiles_handled_during_walk"].as_u64(), Some(0));
        assert_eq!(response["ext_imports"].as_array().map(Vec::len), Some(1));
        assert_eq!(response["ext_failures"].as_u64(), Some(1));
        assert_eq!(response["errors"].as_array().map(Vec::len), Some(1));
        assert_eq!(response["parse_error_count"].as_u64(), Some(3));
        assert_eq!(response["truncated"].as_bool(), Some(true));
        assert_eq!(response["status"].as_str(), Some("truncated"));
        assert_eq!(
            response["ext_imports"][0]["parse_error_samples_omitted"].as_u64(),
            Some(2)
        );

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn browser_post_index_pass_does_not_skip_ext_profile_without_disclosure() -> anyhow::Result<()>
    {
        let case_path = unique_test_path("ext-browser-no-disclosure", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "ext-browser-no-disclosure")?;
        let evidence_dir = unique_test_path("ext-browser-no-disclosure-source", "");
        let profile_dir = evidence_dir.join("User Data").join("Default");
        std::fs::create_dir_all(&profile_dir)?;
        create_ui_test_chromium_history(&profile_dir.join("History"))?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: evidence_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        kdft_case::process_evidence_with_profile(
            &case_path,
            kdft_case::ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
            kdft_case::ProcessingProfile {
                capture_content: false,
                parse_emails: false,
                parse_browsers: false,
            },
        )?;
        let conn = Connection::open(&case_path)?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = json_set(
                 json_remove(metadata_json, '$.source_path_exact'),
                 '$.filesystem_parser', 'ext4',
                 '$.ext_path', '/home/alice/.config/chromium/Default/History',
                 '$.partition_index', 1
             )
             WHERE evidence_id = ?1 AND name = 'History'",
            [evidence_id],
        )?;
        drop(conn);

        let response = super::run_browser_parsing_pass(&case_path, evidence_id, None)?;
        assert_eq!(response["profiles_found"].as_u64(), Some(1));
        assert_eq!(response["profiles_observed"].as_u64(), Some(1));
        assert_eq!(response["profiles_handled_during_walk"].as_u64(), Some(0));
        assert_eq!(response["ext_imports"].as_array().map(Vec::len), Some(0));
        assert_eq!(response["errors"].as_array().map(Vec::len), Some(1));
        assert_eq!(response["truncated"].as_bool(), Some(true));
        assert_eq!(response["status"].as_str(), Some("truncated"));

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(evidence_dir);
        Ok(())
    }

    #[test]
    fn removed_evidence_follow_up_passes_report_clean_errors_and_keep_index_result(
    ) -> anyhow::Result<()> {
        let case_path = unique_test_path("removed-follow-ups", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "removed-follow-ups")?;
        let source_dir = unique_test_path("removed-follow-up-source", "");
        std::fs::create_dir_all(&source_dir)?;
        std::fs::write(source_dir.join("evidence.txt"), b"indexed before removal")?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: source_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let index_result = kdft_case::process_evidence_with_profile(
            &case_path,
            kdft_case::ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
            kdft_case::ProcessingProfile {
                capture_content: true,
                parse_emails: false,
                parse_browsers: false,
            },
        )?;
        let expected_job_id = index_result.job_id;
        let expected_entries = index_result.entries_indexed;
        let expected_status = index_result.status.clone();

        // This is the seam between the completed index and the first optional
        // pass in api_process_evidence: reproduce a concurrent examiner remove.
        kdft_case::remove_evidence(&case_path, evidence_id)?;
        let request = ProcessEvidenceRequest {
            case_path: case_path.to_string_lossy().into_owned(),
            evidence_id,
            max_entries: Some(0),
            progress_id: None,
            reindex_filesystem: Some(false),
            capture_content: Some(true),
            parse_emails: Some(false),
            parse_browsers: Some(true),
            parse_identities: Some(true),
            parse_archives: Some(true),
            parse_documents: Some(true),
            parse_windows_artifacts: Some(true),
            run_hash: Some(true),
            run_file_hash: Some(true),
            run_signature_analysis: Some(true),
            run_carve: Some(true),
            carve_max_scan_bytes: Some(0),
            carve_max_files: Some(0),
        };
        let mut response = serde_json::to_value(index_result)?;
        let tracker = JobProgressTracker::new("removed-follow-ups", "process", None);
        let stage_count = super::process_stage_count(&request);
        let mut stage_index = 1;
        append_optional_processing_passes(
            &case_path,
            &request,
            &mut response,
            &tracker,
            &mut stage_index,
            stage_count,
        )?;

        assert_eq!(response["job_id"], expected_job_id);
        assert_eq!(response["entries_indexed"], expected_entries);
        assert_eq!(response["status"], expected_status);
        for (field, pass_name) in [
            ("hash", "hash"),
            ("signature_analysis", "signature analysis"),
            ("carve", "carve"),
            ("file_hash", "file hashing"),
            ("windows_artifact_parsing", "Windows artifact parsing"),
            (
                "windows_registry_artifact_parsing",
                "Windows Registry artifact parsing",
            ),
            ("browser_parsing", "browser parsing"),
            ("identity_parsing", "identity parsing"),
        ] {
            assert_eq!(
                response[field]["error"],
                format!(
                    "evidence {evidence_id} was removed while processing was running; the {pass_name} pass did not run"
                )
            );
        }
        let response_text = response.to_string();
        assert!(!response_text.contains("FOREIGN KEY"));
        assert!(!response_text.contains("not found"));

        // Defense in depth: even if a pass loses the removal race after its
        // existence check and only returns SQLite's FK text, the API result is
        // still the same clean examiner-facing wording.
        let replacement_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: source_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let foreign_key_result = run_optional_processing_pass(
            &case_path,
            replacement_id,
            "signature analysis",
            &tracker,
            || -> anyhow::Result<serde_json::Value> {
                Err(anyhow::anyhow!("FOREIGN KEY constraint failed"))
            },
        )?;
        assert_eq!(
            foreign_key_result["error"],
            format!(
                "evidence {replacement_id} was removed while processing was running; the signature analysis pass did not run"
            )
        );
        assert!(!foreign_key_result.to_string().contains("FOREIGN KEY"));
        let nested_foreign_key_result = run_optional_processing_pass(
            &case_path,
            replacement_id,
            "browser parsing",
            &tracker,
            || {
                Ok(serde_json::json!({
                    "errors": [{ "error": "FOREIGN KEY constraint failed" }]
                }))
            },
        )?;
        assert_eq!(
            nested_foreign_key_result["error"],
            format!(
                "evidence {replacement_id} was removed while processing was running; the browser parsing pass did not run"
            )
        );
        assert!(!nested_foreign_key_result
            .to_string()
            .contains("FOREIGN KEY"));
        let audit_conn = Connection::open(&case_path)?;
        let mut audit_stmt = audit_conn.prepare(
            "SELECT details_json
             FROM audit_events
             WHERE event_type = 'evidence.processing_pass.failed'
             ORDER BY id",
        )?;
        let audit_details = audit_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(audit_details.len(), 2);
        assert!(audit_details
            .iter()
            .all(|details| details.contains("FOREIGN KEY constraint failed")));
        drop(audit_stmt);
        drop(audit_conn);

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn process_api_runs_selected_artifact_passes_without_content_capture() -> anyhow::Result<()> {
        let case_path = unique_test_path("process-progress", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "process-progress")?;
        let source_dir = unique_test_path("process-progress-source", "");
        std::fs::create_dir_all(&source_dir)?;
        std::fs::write(source_dir.join("alpha.txt"), b"alpha")?;
        std::fs::write(source_dir.join("beta.txt"), b"beta")?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: source_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        let progress_id = format!("ui-test-process-progress-{}", std::process::id());
        let body = serde_json::json!({
            "case_path": case_path.to_string_lossy(),
            "evidence_id": evidence_id,
            "max_entries": 0,
            "progress_id": progress_id,
            "capture_content": false,
            "parse_emails": false,
            "parse_browsers": false,
            "parse_identities": false,
            "parse_archives": true,
            "parse_documents": true,
            "parse_windows_artifacts": true,
            "run_hash": false,
            "run_file_hash": false,
            "run_signature_analysis": false,
            "run_carve": false
        })
        .to_string();
        let config = super::ServerConfig::new(None)?;
        let response = super::api_process_evidence(body.as_bytes(), &config)?;
        assert_eq!(response["status"], "completed");
        assert_eq!(response["progress"]["state"], "complete");
        assert_eq!(response["progress"]["stage_count"], 6);
        assert_eq!(
            response["progress"]["completed_stages"]
                .as_array()
                .map(Vec::len),
            Some(6)
        );
        assert_eq!(response["archive_parsing"]["status"], "completed");
        assert_eq!(response["archive_parsing"]["archives_found"], 0);
        assert_eq!(response["document_parsing"]["status"], "completed");
        assert_eq!(response["document_parsing"]["documents_found"], 0);
        assert_eq!(response["windows_artifact_parsing"]["status"], "completed");
        assert_eq!(
            response["windows_artifact_parsing"]["snapshot_candidate_count"],
            0
        );
        assert_eq!(
            response["windows_registry_artifact_parsing"]["status"],
            "completed"
        );
        assert_eq!(
            response["windows_registry_artifact_parsing"]["hives_found"],
            0
        );
        assert_eq!(response["progress"]["percentage"], 100.0);
        let retained = config
            .progress
            .snapshot(&progress_id)?
            .expect("registered progress snapshot");
        assert_eq!(retained.state, JobProgressState::Complete);
        assert_eq!(
            retained.current_object.as_deref(),
            Some("Process results committed")
        );
        let conn = Connection::open(&case_path)?;
        let persisted_state: String = conn.query_row(
            "SELECT json_extract(parameters_json, '$.progress.state')
             FROM evidence_jobs WHERE id = ?1",
            [response["job_id"].as_i64().expect("process job id")],
            |row| row.get(0),
        )?;
        assert_eq!(persisted_state, "complete");
        drop(conn);

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn indexed_directory_cache_invalidates_for_in_place_metadata_mutation() -> anyhow::Result<()> {
        let case_path = unique_test_path("indexed-cache-generation", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "indexed-cache-generation")?;
        let source_dir = unique_test_path("indexed-cache-generation-source", "");
        std::fs::create_dir_all(&source_dir)?;
        std::fs::write(source_dir.join("probe.txt"), b"cache probe")?;
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: source_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: true,
                notes: None,
            },
        )?;
        kdft_case::process_evidence(
            &case_path,
            kdft_case::ProcessEvidenceOptions {
                evidence_id,
                max_entries: 0,
            },
        )?;

        let before = cached_indexed_directory(&case_path, evidence_id, "/", 0, 100)?;
        assert_eq!(
            before["children"][0]["metadata_json"]["cache_probe"],
            serde_json::Value::Null
        );

        let conn = Connection::open(&case_path)?;
        let case_id: i64 = conn.query_row("SELECT id FROM cases LIMIT 1", [], |row| row.get(0))?;
        conn.execute(
            "UPDATE filesystem_entries
             SET metadata_json = json_set(metadata_json, '$.cache_probe', 'updated')
             WHERE evidence_id = ?1 AND name = 'probe.txt'",
            [evidence_id],
        )?;
        conn.execute(
            "INSERT INTO audit_events(case_id, event_type, actor, details_json)
             VALUES (?1, 'test.metadata_mutation', 'test', '{}')",
            [case_id],
        )?;
        drop(conn);

        let after = cached_indexed_directory(&case_path, evidence_id, "/", 0, 100)?;
        assert_eq!(
            after["children"][0]["metadata_json"]["cache_probe"],
            "updated"
        );

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(source_dir);
        Ok(())
    }

    #[test]
    fn local_live_directory_api_exposes_a_resumable_page() -> anyhow::Result<()> {
        let case_path = unique_test_path("live-directory-page", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "live-directory-page")?;
        let source_dir = unique_test_path("live-directory-page-source", "");
        std::fs::create_dir_all(&source_dir)?;
        for index in 0..1005 {
            std::fs::write(source_dir.join(format!("item-{index:04}.txt")), b"x")?;
        }
        let evidence_id = kdft_case::add_evidence(
            &case_path,
            kdft_case::AddEvidenceOptions {
                path: source_dir.clone(),
                kind: kdft_case::EvidenceKind::Folder,
                read_file_system_requested: false,
                notes: None,
            },
        )?;
        let mut query = HashMap::from([
            (
                "case_path".to_string(),
                case_path.to_string_lossy().into_owned(),
            ),
            ("evidence_id".to_string(), evidence_id.to_string()),
            ("path".to_string(), "/".to_string()),
            ("limit".to_string(), "1000".to_string()),
        ]);
        let first = api_image_dir(&query)?;
        assert_eq!(first["entries"].as_array().map(Vec::len), Some(1000));
        assert_eq!(first["total_entries"], 1005);
        assert_eq!(first["truncated"], true);
        let cursor = &first["next_cursor"];
        query.insert(
            "after_name".to_string(),
            cursor["name"].as_str().expect("cursor name").to_string(),
        );
        query.insert(
            "after_is_dir".to_string(),
            cursor["is_dir"].as_bool().expect("cursor type").to_string(),
        );
        let second = api_image_dir(&query)?;
        assert_eq!(second["entries"].as_array().map(Vec::len), Some(5));
        assert_eq!(second["next_cursor"], serde_json::Value::Null);
        assert_eq!(second["truncated"], false);

        cleanup_ui_test_case(&case_path);
        let _ = std::fs::remove_dir_all(source_dir);
        Ok(())
    }

    // A rejected quick-bookmark request must not write anything to the case:
    // the folder used to be created before bookmark_type validation, leaving
    // a permanent empty folder (plus audit noise) behind a 400 response.
    #[test]
    fn quick_bookmark_rejects_invalid_type_without_creating_the_folder() -> anyhow::Result<()> {
        let case_path = std::env::temp_dir().join(format!(
            "kdft-ui-quick-bookmark-validation-{}.kdft.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&case_path);
        kdft_case::create_case(
            &case_path,
            kdft_case::CreateCaseOptions {
                name: "quick-bookmark-validation".to_string(),
                examiner_name: None,
                case_number: None,
                case_type: None,
                description: None,
                default_export_folder: None,
                temporary_folder: None,
                index_folder: None,
            },
        )?;
        let body = serde_json::json!({
            "case_path": case_path.to_string_lossy(),
            "folder_name": "Leak Check",
            "title": "invalid type",
            "bookmark_type": "file"
        })
        .to_string();
        let error = match super::api_quick_bookmark(body.as_bytes()) {
            Ok(_) => panic!("invalid bookmark_type must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unsupported bookmark type"),
            "unexpected error: {error}"
        );
        let folders = kdft_case::list_bookmark_folders(&case_path)?;
        assert!(
            folders.iter().all(|folder| folder.name != "Leak Check"),
            "rejected request must not create its destination folder"
        );
        let _ = std::fs::remove_file(&case_path);
        Ok(())
    }

    #[test]
    fn quick_report_export_creates_unique_output_paths_and_keeps_previous_report_intact(
    ) -> anyhow::Result<()> {
        let case_path = unique_test_path("quick-report-collision", ".kdft.sqlite");
        cleanup_ui_test_case(&case_path);
        create_ui_test_case(&case_path, "quick-report-collision")?;

        let output_path = unique_test_path("quick-report-collision", ".html");
        let _ = std::fs::remove_file(&output_path);

        let export_request = |path: &Path| -> anyhow::Result<serde_json::Value> {
            let body = serde_json::json!({
                "case_path": case_path.to_string_lossy(),
                "output_path": path.to_string_lossy(),
            })
            .to_string();
            let config = super::ServerConfig::new(None)?;
            super::api_export_report(body.as_bytes(), &config)
        };

        let first = export_request(&output_path)?;
        let first_path = std::path::Path::new(first["report"].as_str().expect("report path"));
        let first_bytes = std::fs::read(first_path)?;

        let second = export_request(&output_path)?;
        let second_path = std::path::Path::new(second["report"].as_str().expect("report path"));

        assert_ne!(first_path, second_path);
        let second_bytes = std::fs::read(second_path)?;
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first_bytes, std::fs::read(&output_path)?);

        std::fs::remove_file(&output_path)?;
        std::fs::remove_file(second_path)?;
        cleanup_ui_test_case(&case_path);
        Ok(())
    }

    // Examiner-typed limits big enough to round-trip through JavaScript as
    // scientific notation (5e+21) used to fail the whole request with a serde
    // type error; the lenient deserializers must saturate instead. The search
    // handler treats this value as an explicit response-page size, never as a
    // hidden coverage limit.
    #[test]
    fn deep_search_request_accepts_scientific_notation_limits() {
        let request: DeepSearchRequest = serde_json::from_slice(
            br#"{"case_path":"x","query":"hack","max_results":5e21,"max_file_bytes":4.096e34}"#,
        )
        .expect("huge numeric limits must not fail the request");
        assert_eq!(request.max_results, Some(usize::MAX));
        assert_eq!(request.max_file_bytes, Some(u64::MAX));
    }

    #[test]
    fn raw_search_request_saturates_fractional_and_rejects_negative_limits() {
        let request: RawSearchRequest = serde_json::from_slice(
            br#"{"case_path":"x","evidence_id":1,"query":"q","max_results":2.5,"max_scan_bytes":-3}"#,
        )
        .expect("odd numeric limits must not fail the request");
        assert_eq!(request.max_results, Some(2));
        // Negative falls back to None so the handler default applies.
        assert_eq!(request.max_scan_bytes, None);
    }

    #[test]
    fn search_requests_still_accept_plain_integer_limits() {
        let request: DeepSearchRequest = serde_json::from_slice(
            br#"{"case_path":"x","query":"hack","max_results":50,"max_file_bytes":4096}"#,
        )
        .expect("plain limits must parse");
        assert_eq!(request.max_results, Some(50));
        assert_eq!(request.max_file_bytes, Some(4096));
    }

    #[test]
    fn search_apis_reject_oversized_pages_instead_of_clamping() {
        let deep = super::api_deep_search(
            br#"{"case_path":"missing.kdft.sqlite","query":"needle","max_results":1001}"#,
        )
        .expect_err("oversized indexed page must be rejected");
        assert!(deep.to_string().contains("response maximum"));

        let raw = super::api_raw_search(
            br#"{"case_path":"missing.kdft.sqlite","evidence_id":1,"query":"needle","max_results":1001}"#,
        )
        .expect_err("oversized raw page must be rejected");
        assert!(raw.to_string().contains("response maximum"));
    }

    #[test]
    fn external_preview_only_accepts_bounded_document_and_media_formats() {
        assert_eq!(
            external_preview_extension("report.PDF").as_deref(),
            Some("pdf")
        );
        assert_eq!(
            external_preview_extension("table.xlsx").as_deref(),
            Some("xlsx")
        );
        assert_eq!(
            external_preview_extension("notes.csv").as_deref(),
            Some("csv")
        );
        assert_eq!(external_preview_extension("payload.exe"), None);
        assert_eq!(external_preview_extension("script.ps1"), None);
        assert_eq!(external_preview_extension("no-extension"), None);
    }

    #[test]
    fn external_host_application_open_requires_strong_untrusted_evidence_confirmation() {
        for warning in [
            "SECURITY WARNING: UNTRUSTED EVIDENCE",
            "launch a host application outside KDFT's internal viewer",
            "malicious macros, exploits, external links",
            "KDFT cannot sandbox or make the host application safe",
            "Cancel is the safe default; use View bytes in KDFT",
            "appropriately isolated forensic environment",
        ] {
            assert!(INDEX_HTML.contains(warning), "missing warning: {warning}");
        }

        let external_open = INDEX_HTML
            .split_once("async function openSelectedEntryExternal(entryId = null) {")
            .expect("external-open function")
            .1
            .split_once("function updateByteContextControls()")
            .expect("end of external-open function")
            .0;
        let confirmation = external_open
            .find("window.confirm(externalOpenWarning(entry))")
            .expect("explicit external-open confirmation");
        let host_launch_request = external_open
            .find("apiPost(\"/api/entry/open\"")
            .expect("host-app launch request");
        assert!(
            confirmation < host_launch_request,
            "confirmation must occur before the host-app launch request"
        );
        assert!(external_open.contains("return;"));
        assert!(external_open.contains("acknowledge_host_app_risk: true"));
    }

    #[test]
    fn external_host_application_api_rejects_missing_risk_acknowledgement() {
        let error = super::api_open_entry(br#"{"case_path":"missing.kdft.sqlite","entry_id":1}"#)
            .expect_err("host-app open without explicit risk acknowledgement must fail");
        assert!(error
            .to_string()
            .contains("requires explicit examiner risk acknowledgement"));
    }

    #[test]
    fn external_preview_name_is_flat_and_preserves_the_extension() {
        let name = safe_external_preview_name(42, r#"..\folder/unsafe name?.PDF"#);
        assert_eq!(name, "42-unsafe_name.PDF");
        assert!(!name.contains('/') && !name.contains('\\'));

        let long_name = format!("{}.xlsx", "a".repeat(300));
        let long_safe = safe_external_preview_name(7, &long_name);
        assert!(long_safe.starts_with("7-"));
        assert!(long_safe.ends_with(".xlsx"));
        assert!(long_safe.len() <= 7 + 96 + 5);
    }

    #[test]
    fn external_preview_path_stays_beside_the_case() {
        let path =
            external_preview_output_path(Path::new("/Cases/case-001.kdft.sqlite"), 9, "report.pdf");
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("9-report.pdf")
        );
        assert_eq!(
            path.parent()
                .and_then(|value| value.file_name())
                .and_then(|value| value.to_str()),
            Some("case-001.kdft-previews")
        );
    }

    #[test]
    fn path_quote_trimming_accepts_pasted_windows_paths() {
        assert_eq!(
            trim_balanced_path_quotes(r#"  "C:\Users\examiner\Downloads\case file.E01"  "#),
            r#"C:\Users\examiner\Downloads\case file.E01"#
        );
        assert_eq!(
            trim_balanced_path_quotes("'C:/Users/examiner/Downloads/case file.E01'"),
            "C:/Users/examiner/Downloads/case file.E01"
        );
        assert_eq!(
            trim_balanced_path_quotes(r#"C:\Users\examiner\Downloads\case file.E01"#),
            r#"C:\Users\examiner\Downloads\case file.E01"#
        );
    }

    #[test]
    fn path_normalization_corrects_concatenated_posix_paths() {
        assert_eq!(
            normalize_request_path("/Users/examiner/Downloads//Users/examiner/Downloads/image.E01"),
            "/Users/examiner/Downloads/image.E01"
        );
        assert_eq!(
            normalize_request_path("/home/examiner/old/home/examiner/new/image.E01"),
            "/home/examiner/new/image.E01"
        );
    }

    #[test]
    fn path_normalization_keeps_wellknown_roots_used_as_folder_names() {
        assert_eq!(
            normalize_request_path("/home/beel/media/photos/image.E01"),
            "/home/beel/media/photos/image.E01"
        );
        assert_eq!(
            normalize_request_path("/Users/kris/Documents/Users/report.pdf"),
            "/Users/kris/Documents/Users/report.pdf"
        );
        assert_eq!(
            normalize_request_path("/home/beel/backup/home/old.dd"),
            "/home/beel/backup/home/old.dd"
        );
        assert_eq!(
            normalize_request_path("/tmp/case/tmp.dd"),
            "/tmp/case/tmp.dd"
        );
    }

    #[test]
    fn path_normalization_corrects_concatenated_windows_paths() {
        assert_eq!(
            normalize_request_path(r#"C:\Evidence\oldC:\Evidence\new\image.E01"#),
            r#"C:\Evidence\new\image.E01"#
        );
        assert_eq!(
            normalize_request_path("C:/Evidence/oldD:/Evidence/new/image.E01"),
            "D:/Evidence/new/image.E01"
        );
    }

    #[test]
    fn path_normalization_preserves_leading_unc_and_long_paths() {
        assert_eq!(
            normalize_request_path(r#"\\server\share\image.E01"#),
            r#"\\server\share\image.E01"#
        );
        assert_eq!(
            normalize_request_path(r#"\\?\C:\very\long\image.E01"#),
            r#"\\?\C:\very\long\image.E01"#
        );
    }

    #[test]
    fn path_normalization_corrects_repeated_unc_prefix() {
        assert_eq!(
            normalize_request_path(r#"\\server\share\old\\server\share\new.E01"#),
            r#"\\server\share\new.E01"#
        );
        assert_eq!(
            normalize_request_path(r#"\\?\C:\old\\?\C:\new\image.E01"#),
            r#"\\?\C:\new\image.E01"#
        );
    }

    #[test]
    fn path_normalization_strips_file_url_prefix_and_percent_20() {
        assert_eq!(
            normalize_request_path("file:///Users/examiner/Downloads/case%20file.E01"),
            "/Users/examiner/Downloads/case file.E01"
        );
        assert_eq!(
            normalize_request_path("file:///C:/Users/examiner/Downloads/case%20file.E01"),
            "C:/Users/examiner/Downloads/case file.E01"
        );
    }

    #[test]
    fn timeline_client_extracts_last_access_time_used_by_server_range_filter() {
        // kdft-case includes this key in TIMELINE_TIME_FIELD_KEYS. If the UI
        // omits it, a ranged query can return matching entries whose only
        // in-range timestamp is then discarded client-side, yielding an empty
        // timeline despite a non-zero server match count.
        assert!(super::INDEX_HTML
            .contains(r#"{ key: "last_access_time_utc", label: "Last Access Date/Time" }"#));
    }
}

fn query_i64(query: &HashMap<String, String>, field: &str) -> Result<i64> {
    query
        .get(field)
        .with_context(|| format!("{field} query parameter is required"))?
        .parse::<i64>()
        .with_context(|| format!("parsing {field}"))
}

fn query_u64(query: &HashMap<String, String>, field: &str) -> Result<Option<u64>> {
    query
        .get(field)
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("parsing {field}"))
        })
        .transpose()
}

fn query_usize(query: &HashMap<String, String>, field: &str) -> Result<Option<usize>> {
    query
        .get(field)
        .map(|value| {
            value
                .parse::<usize>()
                .with_context(|| format!("parsing {field}"))
        })
        .transpose()
}

fn query_bool(query: &HashMap<String, String>, field: &str) -> bool {
    query
        .get(field)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn non_empty(value: String, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} cannot be empty");
    }
    Ok(trimmed.to_string())
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, query_string) = target.split_once('?').unwrap_or((target, ""));
    let mut query = HashMap::new();
    for pair in query_string.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(url_decode(key), url_decode(value));
    }
    (path.to_string(), query)
}

fn url_decode(value: &str) -> String {
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.as_bytes().iter().copied();
    while let Some(ch) = chars.next() {
        match ch {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hi = chars.next();
                let lo = chars.next();
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    if let (Some(hi), Some(lo)) = (hex_value(hi), hex_value(lo)) {
                        bytes.push((hi << 4) | lo);
                    }
                }
            }
            _ => bytes.push(ch),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn json_ok<T: Serialize>(value: T) -> HttpResponse {
    let body = serde_json::to_vec(&json!({ "ok": true, "data": value }))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialization failed\"}".to_vec());
    HttpResponse {
        status: 200,
        reason: "OK",
        content_type: "application/json; charset=utf-8",
        body,
        headers: Vec::new(),
    }
}

fn api_response<T: Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(value) => json_ok(value),
        // {err:#} keeps the cause chain (e.g. "... : No such file or directory")
        // so the UI notice explains WHY, not just where, an operation failed.
        Err(err) => json_error(400, &format!("{err:#}")),
    }
}

fn json_error(status: u16, message: &str) -> HttpResponse {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let body = serde_json::to_vec(&json!({ "ok": false, "error": message }))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialization failed\"}".to_vec());
    HttpResponse {
        status,
        reason,
        content_type: "application/json; charset=utf-8",
        body,
        headers: Vec::new(),
    }
}

fn html_response(html: String) -> HttpResponse {
    HttpResponse {
        status: 200,
        reason: "OK",
        content_type: "text/html; charset=utf-8",
        body: html.into_bytes(),
        headers: Vec::new(),
    }
}

fn write_http_response(stream: &mut TcpStream, response: HttpResponse) -> Result<()> {
    // Disable caching for every response so the browser cannot mix UI assets or API data
    // from different executable versions.
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    )
    .context("writing HTTP response headers")?;
    for (name, value) in &response.headers {
        if value.contains(['\r', '\n']) {
            bail!("invalid response header value");
        }
        write!(stream, "{name}: {value}\r\n").context("writing HTTP response header")?;
    }
    write!(stream, "Connection: close\r\n\r\n").context("finishing HTTP response headers")?;
    stream
        .write_all(&response.body)
        .context("writing HTTP response body")
}

fn open_target(target: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Pass the path as one argument instead of through cmd.exe's command
        // parser; evidence filenames can legally contain shell metacharacters.
        Command::new("explorer.exe")
            .arg(target)
            .spawn()
            .context("opening target")?;
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(target)
            .spawn()
            .context("opening target")?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(target)
            .spawn()
            .context("opening target")?;
    }
    Ok(())
}

fn index_html(config: &ServerConfig) -> String {
    let bootstrap = json!({
        "defaultCasePath": config.default_case_path,
        "defaultCasePinned": config.default_case_pinned,
        "defaultEvidencePath": config.default_evidence_path,
        "defaultVhdSamplePath": config.default_vhd_sample_path,
        "defaultHistoryPath": config.default_history_path,
        "defaultReportPath": config.default_report_path,
        "workspaceRoot": config.workspace_root,
        // Lets the page detect entries categorized by an OLDER classifier and
        // only then offer the category-refresh maintenance action.
        "classifierVersion": kdft_case::ENTRY_CATEGORY_CLASSIFIER_VERSION,
    });
    INDEX_HTML.replace("__KDFT_BOOTSTRAP__", &inline_script_json(&bootstrap))
}

fn inline_script_json(value: &serde_json::Value) -> String {
    // HTML treats a closing script tag as markup even when it appears inside a
    // JavaScript string. Encode markup-significant characters before placing
    // JSON in the inline bootstrap script so hostile-but-valid local paths
    // cannot terminate the script element.
    value
        .to_string()
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

const INDEX_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KDFT Workbench</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef2ee;
      --surface: #ffffff;
      --surface-2: #f7f9f8;
      --text: #1c2526;
      --muted: #657271;
      --line: #d6dfdc;
      --accent: #0b6f63;
      --accent-2: #8c3f21;
      --warn: #b7791f;
      --bad: #b42318;
      --shadow: 0 18px 48px rgba(27, 38, 38, 0.10);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    body.analysis-fullscreen {
      background: #fff;
    }
    body.viewer-fullscreen {
      overflow: hidden;
    }
    button, input, select, textarea { font: inherit; }
    button {
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
      font-weight: 650;
      min-height: 36px;
      padding: 8px 12px;
    }
    button.secondary {
      background: #253230;
    }
    button.ghost {
      background: transparent;
      color: var(--accent);
      border: 1px solid var(--line);
    }
    button.offset-link {
      background: transparent;
      border: none;
      padding: 0;
      color: var(--accent);
      font: inherit;
      text-decoration: underline dotted;
      cursor: pointer;
    }
    button.offset-link:hover { text-decoration: underline; }
    td.offset-link-cell { cursor: pointer; }
    td.offset-link-cell:hover { text-decoration: underline; }
    .analyzing-overlay {
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: rgba(0, 0, 0, .55);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .analyzing-card {
      background: #1b1e26;
      color: #f1f5f4;
      border: 1px solid #4b5563;
      border-radius: 10px;
      padding: 22px 26px;
      max-width: 460px;
      text-align: center;
      box-shadow: 0 12px 44px rgba(0, 0, 0, .55);
    }
    .analyzing-card.telemetry {
      width: min(760px, calc(100vw - 36px));
      max-width: 760px;
      text-align: left;
    }
    .analyzing-title { font-weight: 600; font-size: 15px; margin-bottom: 14px; }
    .analyzing-heading-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 14px;
    }
    .analyzing-heading-row .analyzing-title { margin: 0; }
    .progress-state {
      border: 1px solid currentColor;
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .04em;
      text-transform: uppercase;
      color: #55c9bb;
    }
    .progress-state.truncated, .progress-state.cancelled { color: #ffb454; }
    .progress-state.failed { color: #ff7b72; }
    .progress-state.complete { color: #64d488; }
    .analyzing-bar {
      height: 12px;
      border-radius: 6px;
      overflow: hidden;
      background: rgba(255, 255, 255, .12);
      margin-bottom: 12px;
    }
    .analyzing-bar-fill {
      height: 100%;
      width: 40%;
      border-radius: 6px;
      background: linear-gradient(90deg, #ff8a1e, #ff3b30);
      animation: analyzingSweep 1.15s ease-in-out infinite;
    }
    .analyzing-bar-fill.known { animation: none; }
    @keyframes analyzingSweep {
      0% { margin-left: -42%; }
      100% { margin-left: 100%; }
    }
    .analyzing-ascii {
      min-height: 58px;
      margin: 0 0 12px;
      color: #55c9bb;
      font: 600 13px/1.15 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      white-space: pre;
      user-select: none;
    }
    .analyzing-note { font-size: 12px; opacity: .82; line-height: 1.45; }
    .progress-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      margin: 12px 0;
    }
    .progress-metric {
      border: 1px solid #4b5563;
      border-radius: 7px;
      padding: 8px 10px;
      min-width: 0;
    }
    .progress-metric-label {
      display: block;
      opacity: .68;
      font-size: 10px;
      font-weight: 800;
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    .progress-metric-value {
      display: block;
      margin-top: 3px;
      font: 600 12px/1.35 ui-monospace, SFMono-Regular, Consolas, monospace;
      overflow-wrap: anywhere;
    }
    .progress-context {
      display: grid;
      gap: 7px;
      margin-top: 10px;
      font-size: 12px;
      line-height: 1.4;
    }
    .progress-context-row {
      border-left: 3px solid #55c9bb;
      padding-left: 9px;
      overflow-wrap: anywhere;
    }
    .progress-context-label { font-weight: 800; }
    .progress-recent {
      margin: 3px 0 0 18px;
      padding: 0;
      max-height: 74px;
      overflow: hidden;
      opacity: .76;
    }
    .progress-stage-times {
      margin-top: 10px;
      font-size: 11px;
      opacity: .72;
      overflow-wrap: anywhere;
    }
    @media (max-width: 680px) {
      .progress-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (prefers-reduced-motion: reduce) {
      .analyzing-bar-fill { animation: none; width: 100%; opacity: .65; }
    }
    button.ghost.danger {
      color: var(--bad);
      border-color: rgba(180,35,24,.35);
    }
    button:disabled {
      cursor: not-allowed;
      opacity: .45;
    }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      min-height: 36px;
      padding: 8px 10px;
    }
    input[type="checkbox"] {
      width: 17px;
      height: 17px;
      min-height: 17px;
      padding: 0;
      margin: 0;
      vertical-align: middle;
    }
    textarea { min-height: 70px; resize: vertical; }
    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .app {
      display: grid;
      grid-template-columns: minmax(300px, 360px) 1fr;
      min-height: 100vh;
    }
    .app.sidebar-collapsed {
      grid-template-columns: 0 1fr;
    }
    .app.sidebar-collapsed .sidebar {
      display: none;
    }
    .sidebar {
      grid-column: 1;
      border-right: 1px solid var(--line);
      background: #fbfcfb;
      padding: 20px;
      display: grid;
      align-content: start;
      gap: 16px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .mark {
      width: 38px;
      height: 38px;
      border-radius: 8px;
      background: var(--text);
      color: #fff;
      display: grid;
      place-items: center;
      font-weight: 800;
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: 20px; }
    h2 { font-size: 17px; }
    h3 { font-size: 14px; }
    .muted { color: var(--muted); }
    .tiny { font-size: 12px; }
    .panel {
      width: 100%;
      min-width: 0;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .sidebar .panel {
      box-shadow: none;
      padding: 14px;
      display: grid;
      gap: 12px;
    }
    main {
      grid-column: 2;
      padding: 20px;
      display: grid;
      gap: 16px;
      align-content: start;
      min-width: 0;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 6px 12px;
    }
    .topbar-case {
      display: flex;
      align-items: baseline;
      gap: 10px;
      min-width: 0;
    }
    .topbar-case h2 {
      font-size: 14px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    #caseMeta {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 42vw;
    }
    .sidebar-toggle {
      min-height: 26px;
      padding: 2px 9px;
      align-self: center;
      font-size: 15px;
      line-height: 1;
    }
    .stats {
      display: flex;
      gap: 16px;
      flex-shrink: 0;
    }
    .stat {
      display: flex;
      align-items: baseline;
      gap: 5px;
      border: 0;
      background: transparent;
      padding: 0;
    }
    .stat strong {
      font-size: 15px;
    }
    .tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .tab {
      background: #fff;
      color: var(--text);
      border: 1px solid var(--line);
    }
    .tab.active {
      background: var(--text);
      color: #fff;
      border-color: var(--text);
    }
    .tab-shortcut {
      margin-left: 6px;
      color: inherit;
      opacity: .62;
      font-size: 11px;
      font-weight: 800;
    }
    .tab.active .tab-shortcut {
      opacity: .85;
    }
    .view { display: none; }
    .view.active {
      display: grid;
      gap: 16px;
    }
    .view.analyze-view.active,
    .view.timeline-view.active {
      min-height: calc(100vh - 172px);
    }
    .grid-2 {
      display: grid;
      grid-template-columns: minmax(300px, 420px) 1fr;
      gap: 16px;
      align-items: start;
    }
    .dashboard-grid {
      display: grid;
      grid-template-columns: minmax(280px, .9fr) minmax(340px, 1fr) minmax(360px, 1.1fr);
      gap: 16px;
      align-items: start;
    }
    .dashboard-grid .panel {
      min-width: 0;
    }
    .dashboard-facts {
      display: grid;
      gap: 1px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--line);
    }
    .dashboard-fact {
      display: grid;
      grid-template-columns: minmax(120px, .8fr) minmax(0, 1fr);
      gap: 12px;
      align-items: start;
      background: #fff;
      padding: 8px 10px;
    }
    .dashboard-fact span {
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .dashboard-fact strong {
      min-width: 0;
      overflow-wrap: anywhere;
      font-size: 13px;
    }
    .dashboard-table-wrap {
      overflow: auto;
    }
    .dashboard-category-list {
      display: grid;
      gap: 8px;
    }
    .dashboard-category-row {
      width: 100%;
      display: grid;
      grid-template-columns: minmax(130px, .9fr) minmax(0, 1.4fr) auto;
      gap: 10px;
      align-items: center;
      min-height: 38px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font-size: 13px;
      font-weight: 750;
      text-align: left;
    }
    .dashboard-category-row:hover {
      background: #e8f3f0;
      color: var(--accent);
      border-color: rgba(11,111,99,.35);
    }
    .dashboard-category-label {
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .dashboard-category-bar {
      height: 10px;
      overflow: hidden;
      border-radius: 999px;
      background: var(--surface-2);
    }
    .dashboard-category-bar span {
      display: block;
      width: var(--bar-width);
      height: 100%;
      border-radius: inherit;
      background: #9ec9d5;
    }
    .dashboard-category-count {
      color: var(--muted);
      font-size: 12px;
      font-variant-numeric: tabular-nums;
    }
    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid var(--line);
      padding: 14px 16px;
    }
    .panel-body {
      padding: 16px;
      display: grid;
      gap: 12px;
    }
    .form-grid {
      display: grid;
      gap: 10px;
    }
    /* The hidden attribute must win over element display rules (e.g. .row is
       a grid), or toggled-off option rows keep showing. */
    [hidden] { display: none !important; }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .toolbar-select {
      width: auto;
      min-width: 160px;
      min-height: 30px;
      padding: 5px 8px;
      text-transform: none;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      background: var(--surface-2);
    }
    td.actions {
      width: 190px;
    }
    .bookmark-items {
      margin: 0;
      padding: 0;
      display: grid;
      gap: 6px;
      list-style: none;
    }
    .bookmark-items li {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: center;
    }
    .bookmark-items span {
      overflow-wrap: anywhere;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      border: 1px solid var(--line);
      color: var(--muted);
      background: #fff;
      min-height: 26px;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
    }
    .pill.good { color: var(--accent); border-color: rgba(11,111,99,.35); }
    .pill.warn { color: var(--warn); border-color: rgba(183,121,31,.35); }
    .pill.bad { color: var(--bad); border-color: rgba(180,35,24,.35); }
    .notice {
      border-left: 4px solid var(--accent);
      background: #edf8f5;
      padding: 10px 12px;
      border-radius: 6px;
      min-height: 40px;
    }
    .notice.bad {
      border-color: var(--bad);
      background: #fff3f0;
    }
    .empty {
      color: var(--muted);
      padding: 16px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      background: var(--surface-2);
    }
    #searchResults {
      overflow: auto;
    }
    .search-results-table {
      table-layout: fixed;
      min-width: 1380px;
    }
    .search-results-table th,
    .search-results-table td {
      overflow-wrap: anywhere;
    }
    .search-results-table th:nth-child(1),
    .search-results-table td:nth-child(1) {
      width: 34px;
    }
    .search-results-table th:nth-child(2),
    .search-results-table td:nth-child(2) {
      width: 250px;
    }
    .search-results-table th:nth-child(3),
    .search-results-table td:nth-child(3) {
      width: 90px;
    }
    .search-results-table th:nth-child(4),
    .search-results-table td:nth-child(4) {
      width: 150px;
    }
    .search-results-table th:nth-child(5),
    .search-results-table td:nth-child(5) {
      width: 230px;
    }
    .search-results-table th:nth-child(6),
    .search-results-table td:nth-child(6),
    .search-results-table th:nth-child(7),
    .search-results-table td:nth-child(7) {
      width: 165px;
    }
    .search-results-table th:nth-child(9),
    .search-results-table td:nth-child(9) {
      width: 180px;
    }
    .grid-header-cell,
    .search-header-cell {
      display: grid;
      gap: 4px;
      align-content: start;
    }
    button.grid-sort-button,
    button.search-sort-button {
      width: 100%;
      min-height: 20px;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      line-height: 1.2;
      text-align: left;
      text-transform: uppercase;
    }
    button.grid-sort-button:hover,
    button.grid-sort-button.active,
    button.search-sort-button:hover,
    button.search-sort-button.active {
      color: var(--accent);
    }
    .grid-sort-indicator,
    .search-sort-indicator {
      margin-left: 4px;
      color: var(--accent);
      font-size: 10px;
      white-space: nowrap;
    }
    .grid-column-filter,
    .search-column-filter {
      min-height: 24px;
      padding: 3px 5px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .path-pick-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: end;
    }
    .path-pick-label {
      min-width: 0;
    }
    .processing-options {
      margin: 6px 0;
      border: 1px solid var(--line, #d9e1e8);
      border-radius: 6px;
      padding: 4px 8px;
    }
    .processing-options summary {
      cursor: pointer;
      user-select: none;
    }
    .processing-options > p { display: none; }
    .processing-options-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(210px, 100%), 1fr));
      gap: 2px 12px;
      margin: 6px 0;
    }
    .check-option {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      font-size: 0.85em;
      line-height: 1.25;
      min-width: 0;
      white-space: normal;
      overflow-wrap: anywhere;
    }
    .check-option input[type="checkbox"] {
      margin: 0;
      flex: none;
    }
    .check-option input[type="number"] {
      width: 88px;
      flex: none;
    }
    .check-option input[disabled] + span,
    .processing-options-grid.muted .check-option {
      opacity: 0.55;
    }
    .browser-panel {
      grid-column: 1 / -1;
      min-height: calc(100vh - 180px);
    }
    .analyze-view .browser-panel {
      grid-column: 1;
    }
    .browser-panel .panel-body {
      height: calc(100vh - 252px);
      min-height: 560px;
      padding: 10px;
    }
    .browser-workspace {
      display: grid;
      --inspector-width: 520px;
      grid-template-columns: minmax(230px, 300px) minmax(360px, 1fr) 12px minmax(320px, var(--inspector-width));
      grid-template-rows: minmax(0, 1fr);
      gap: 10px;
      height: 100%;
      min-height: 0;
    }
    .browser-workspace.inspector-collapsed {
      grid-template-columns: minmax(230px, 300px) minmax(0, 1fr);
    }
    .browser-workspace.inspector-collapsed .pane-resizer,
    .browser-workspace.inspector-collapsed .browser-viewer {
      display: none;
    }
    .pane-resizer {
      min-width: 12px;
      position: relative;
      border-radius: 999px;
      background: rgba(14,83,75,.08);
      cursor: col-resize;
      touch-action: none;
    }
    .pane-resizer::before {
      content: "";
      position: absolute;
      inset: 0 3px;
      border-radius: 999px;
      background: rgba(14,83,75,.18);
    }
    .pane-resizer:hover,
    .pane-resizer.dragging {
      background: rgba(14,83,75,.18);
    }
    .pane-resizer:hover::before,
    .pane-resizer.dragging::before {
      background: #0e534b;
    }
    body.resizing-inspector {
      cursor: col-resize;
      user-select: none;
    }
    .browser-tree,
    .browser-list,
    .browser-viewer {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      min-width: 0;
      overflow: hidden;
    }
    .browser-tree {
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
    }
    .browser-list,
    .browser-viewer {
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
    }
    .pane-title {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      min-height: 40px;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
      color: var(--muted);
    }
    .tree-list {
      overflow: auto;
      padding: 6px;
    }
    .tree-mode {
      display: flex;
      gap: 6px;
      padding: 6px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }
    .tree-mode button {
      flex: 1;
      min-height: 30px;
      padding: 5px 8px;
      background: transparent;
      color: var(--muted);
      border: 1px solid var(--line);
    }
    .tree-mode button.active {
      background: var(--text);
      color: #fff;
      border-color: var(--text);
    }
    .tree-row {
      width: 100%;
      display: grid;
      grid-template-columns: 18px minmax(0, 1fr) auto;
      gap: 6px;
      align-items: center;
      min-height: 30px;
      padding: 5px 8px 5px calc(8px + (var(--depth) * 14px));
      border: 0;
      border-radius: 6px;
      background: transparent;
      color: var(--text);
      font-size: 13px;
      font-weight: 650;
      text-align: left;
    }
    .tree-row:hover,
    .tree-row.active {
      background: #e8f3f0;
      color: var(--accent);
    }
    .tree-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      min-height: 18px;
      border-radius: 4px;
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      font-weight: 900;
    }
    .tree-toggle.can-toggle:hover {
      background: rgba(11,111,99,.10);
      color: var(--accent);
    }
    .tree-label-row {
      display: flex;
      align-items: center;
      gap: 5px;
      min-width: 0;
    }
    .tree-label {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .browser-table-wrap {
      min-height: 0;
      overflow: auto;
    }
    .infinite-scroll-sentinel {
      min-height: 32px;
      padding: 8px 12px;
      color: var(--muted);
      font-size: 12px;
      text-align: center;
    }
    .browser-table-wrap table {
      font-size: 12px;
    }
    .browser-table-wrap .email-table {
      table-layout: fixed;
      min-width: 920px;
    }
    .browser-table-wrap .category-table {
      table-layout: fixed;
      min-width: 2480px;
    }
    .browser-table-wrap .folder-table {
      table-layout: fixed;
      min-width: 2180px;
    }
    /* Large-case browse exposes the same forensic fields as the regular grid. */
    .browser-table-wrap .idx-table {
      table-layout: fixed;
      min-width: 2180px;
    }
    .browser-table-wrap .idx-table th:nth-child(1),
    .browser-table-wrap .idx-table td:nth-child(1) {
      width: 34px;
    }
    .browser-table-wrap .idx-table th:nth-child(3),
    .browser-table-wrap .idx-table td:nth-child(3) {
      width: 72px;
    }
    .browser-table-wrap .idx-table th:nth-child(5),
    .browser-table-wrap .idx-table td:nth-child(5) {
      width: 176px;
    }
    /* Live browse table: checkbox / Name / Type / Size / Modified. Row click
       opens, right-click acts - no per-row buttons, so it fits the pane. */
    .browser-table-wrap .live-table {
      table-layout: fixed;
      min-width: 100%;
    }
    .browser-table-wrap .live-table th:nth-child(1),
    .browser-table-wrap .live-table td:nth-child(1) {
      width: 34px;
    }
    .browser-table-wrap .live-table th:nth-child(3),
    .browser-table-wrap .live-table td:nth-child(3) {
      width: 64px;
    }
    .browser-table-wrap .live-table th:nth-child(4),
    .browser-table-wrap .live-table td:nth-child(4) {
      width: 88px;
    }
    .browser-table-wrap .live-table th:nth-child(5),
    .browser-table-wrap .live-table td:nth-child(5) {
      width: 170px;
    }
    .timeline-panel {
      grid-column: 1 / -1;
      min-height: calc(100vh - 180px);
    }
    .timeline-panel .panel-body {
      height: calc(100vh - 252px);
      min-height: 560px;
      padding: 10px;
    }
    .timeline-shell {
      display: grid;
      grid-template-rows: auto minmax(170px, 30%) auto minmax(0, 1fr);
      gap: 10px;
      height: 100%;
      min-height: 0;
    }
    .timeline-bottom {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(300px, 360px);
      gap: 10px;
      min-height: 0;
      min-width: 0;
    }
    .raw-hits-head {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin: 14px 0 8px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
    }
    .raw-hits-head h3 {
      margin: 0;
      font-size: 13px;
    }
    .timeline-detail {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      overflow: auto;
      min-height: 0;
      padding: 10px;
      font-size: 12px;
    }
    .timeline-detail .timeline-detail-empty {
      color: var(--muted);
      font-size: 12px;
      padding: 6px 2px;
    }
    .timeline-detail-head {
      display: flex;
      flex-direction: column;
      gap: 6px;
      padding-bottom: 8px;
      margin-bottom: 8px;
      border-bottom: 1px solid var(--line);
    }
    .timeline-detail-selected {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }
    .timeline-detail-jumps {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .timeline-detail-jumps h4 {
      margin: 2px 0;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
    }
    .timeline-jump {
      display: flex;
      align-items: baseline;
      gap: 6px;
      width: 100%;
      text-align: left;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      padding: 3px 7px;
      cursor: pointer;
      font-size: 12px;
      font-variant-numeric: tabular-nums;
      color: var(--text);
    }
    .timeline-jump:hover,
    .timeline-jump.active {
      border-color: var(--accent, #2563eb);
      background: rgba(37, 99, 235, 0.08);
    }
    .timeline-jump .timeline-jump-clock {
      flex: none;
    }
    .timeline-jump .timeline-jump-attr {
      color: var(--muted);
    }
    @media (max-width: 1180px) {
      .timeline-bottom {
        grid-template-columns: minmax(0, 1fr);
        grid-auto-rows: minmax(0, 1fr);
      }
    }
    .timeline-controls {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 8px 10px;
    }
    .timeline-summary {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      min-width: 0;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .timeline-summary strong {
      color: var(--text);
      font-variant-numeric: tabular-nums;
    }
    .timeline-graph {
      position: relative;
      min-height: 170px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }
    .timeline-graph-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 8px 10px 0;
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
    }
    .timeline-graph-focus {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .timeline-graph-svg {
      display: block;
      width: 100%;
      height: 145px;
    }
    .timeline-axis-label {
      fill: var(--muted);
      font-size: 11px;
    }
    .timeline-graph-area {
      fill: rgba(0, 113, 188, .12);
    }
    .timeline-graph-line {
      fill: none;
      stroke: #0071bc;
      stroke-width: 2;
    }
    .timeline-graph-point {
      fill: #0071bc;
      stroke: #fff;
      stroke-width: 2;
      cursor: pointer;
    }
    .timeline-graph-point:hover,
    .timeline-graph-point.active {
      fill: #004f8a;
      stroke: #004f8a;
    }
    .timeline-graph-cursor {
      stroke: #0071bc;
      stroke-width: 1.5;
      opacity: .75;
      pointer-events: none;
    }
    .timeline-graph-hitbox {
      fill: transparent;
      cursor: pointer;
    }
    .timeline-graph-tooltip {
      position: absolute;
      z-index: 6;
      display: none;
      max-width: 220px;
      border: 1px solid rgba(0, 0, 0, .28);
      border-radius: 4px;
      background: #fff;
      box-shadow: 0 8px 22px rgba(0, 0, 0, .16);
      padding: 7px 9px;
      color: var(--text);
      font-size: 12px;
      line-height: 1.35;
      pointer-events: none;
    }
    .timeline-graph-tooltip strong {
      display: block;
      font-size: 12px;
    }
    .timeline-selection-nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 7px 10px;
    }
    .timeline-selection-title {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 15px;
      font-weight: 900;
    }
    .timeline-timestamp-pager {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      flex: 0 0 auto;
      color: #0b6fb3;
      font-size: 15px;
      font-weight: 800;
      white-space: nowrap;
    }
    .timeline-timestamp-pager button {
      min-width: 28px;
      border: 0;
      background: transparent;
      color: #0b6fb3;
      font-size: 17px;
      font-weight: 900;
      cursor: pointer;
    }
    .timeline-table-wrap {
      min-height: 0;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }
    .timeline-table-wrap .analysis-status,
    .timeline-table-wrap .empty {
      margin: 10px;
    }
    .timeline-table {
      table-layout: fixed;
      min-width: 1220px;
      font-size: 12px;
    }
    .timeline-table th {
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .timeline-table th,
    .timeline-table td {
      padding: 5px 8px;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }
    .timeline-table th:nth-child(1),
    .timeline-table td:nth-child(1) {
      width: 178px;
    }
    .timeline-table th:nth-child(2),
    .timeline-table td:nth-child(2) {
      width: 190px;
    }
    .timeline-table th:nth-child(3),
    .timeline-table td:nth-child(3) {
      width: 150px;
    }
    .timeline-table th:nth-child(4),
    .timeline-table td:nth-child(4) {
      width: 190px;
    }
    .timeline-table th:nth-child(5),
    .timeline-table td:nth-child(5) {
      width: 110px;
    }
    .timeline-badge {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 800;
      white-space: nowrap;
    }
    .timeline-badge.timeline-communication {
      color: #9a4f00;
      border-color: rgba(194, 97, 0, .35);
      background: #fff7ed;
    }
    .timeline-badge.timeline-opening {
      color: #0b6f45;
      border-color: rgba(11, 111, 69, .32);
      background: #ecfdf3;
    }
    .timeline-badge.timeline-knowledge {
      color: #4b5563;
      border-color: rgba(107, 114, 128, .35);
      background: #f3f4f6;
    }
    .timeline-item-name {
      display: inline;
      font-weight: 800;
    }
    .timeline-item-path {
      display: block;
      margin-top: 2px;
      color: var(--muted);
      font-size: 11px;
      overflow-wrap: anywhere;
    }
    .timeline-item-value {
      color: var(--text);
      max-width: 360px;
      overflow-wrap: anywhere;
    }
    /* Right-click context menu (live browse rows) */
    .ctx-menu {
      position: fixed;
      z-index: 300;
      min-width: 230px;
      padding: 4px;
      background: var(--panel, #fff);
      border: 1px solid var(--border, #d7dee5);
      border-radius: 8px;
      box-shadow: 0 8px 28px rgba(15, 32, 39, .22);
    }
    .ctx-menu button {
      display: block;
      width: 100%;
      padding: 7px 12px;
      border: none;
      background: none;
      text-align: left;
      font: inherit;
      font-size: 13px;
      border-radius: 6px;
      cursor: pointer;
      color: inherit;
    }
    .ctx-menu button:hover {
      background: rgba(11, 111, 99, .10);
    }
    .ctx-menu .sep {
      height: 1px;
      margin: 4px 6px;
      background: var(--border, #d7dee5);
    }
    /* Draggable column resize: a grip on every header edge. Sticky headers in
       .browser-table-wrap are already positioned; plain tables need relative. */
    table th {
      position: relative;
    }
    .col-resizer {
      /* Kept fully inside its own header: a negative right offset would be
         painted over by the next sticky th and shrink the drag target. */
      position: absolute;
      top: 0;
      right: 0;
      bottom: 0;
      width: 9px;
      cursor: col-resize;
      z-index: 4;
      touch-action: none;
    }
    .col-resizer:hover,
    .col-resizer.dragging {
      background: rgba(11, 111, 99, .30);
    }
    .browser-table-wrap th {
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .browser-table-wrap th,
    .browser-table-wrap td {
      padding: 4px 8px;
      line-height: 1.2;
    }
    .browser-table-wrap .category-table th:nth-child(1),
    .browser-table-wrap .category-table td:nth-child(1),
    .browser-table-wrap .email-table th:nth-child(1),
    .browser-table-wrap .email-table td:nth-child(1),
    .browser-table-wrap .folder-table th:nth-child(1),
    .browser-table-wrap .folder-table td:nth-child(1) {
      width: 34px;
    }
    .browser-table-wrap .category-table th:nth-child(2),
    .browser-table-wrap .category-table td:nth-child(2) {
      width: 320px;
    }
    .browser-table-wrap .category-table th:nth-child(3),
    .browser-table-wrap .category-table td:nth-child(3) {
      width: 180px;
    }
    .browser-table-wrap .folder-table th:nth-child(2),
    .browser-table-wrap .folder-table td:nth-child(2) {
      width: 300px;
    }
    .browser-table-wrap .email-table th:nth-child(2),
    .browser-table-wrap .email-table td:nth-child(2),
    .browser-table-wrap .email-table th:nth-child(3),
    .browser-table-wrap .email-table td:nth-child(3) {
      width: 220px;
    }
    .browser-table-wrap .email-table th:nth-child(4),
    .browser-table-wrap .email-table td:nth-child(4) {
      width: 150px;
    }
    .browser-table-wrap .email-table th:nth-child(5),
    .browser-table-wrap .email-table td:nth-child(5) {
      width: 260px;
    }
    .browser-table-wrap .email-table th:nth-child(7),
    .browser-table-wrap .email-table td:nth-child(7) {
      width: 78px;
    }
    .thumb-toolbar {
      display: flex;
      justify-content: flex-end;
      padding: 4px 8px;
    }
    .date-filter {
      display: inline-flex;
      gap: 4px;
      align-items: center;
    }
    .panel-summary {
      cursor: pointer;
      font-weight: 800;
      font-size: 15px;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .panel-summary::before {
      content: "\25B8";
      font-size: 11px;
      transition: transform 0.15s;
    }
    details[open] > .panel-summary::before {
      transform: rotate(90deg);
    }
    details > .panel-summary + * {
      margin-top: 10px;
    }
    .evidence-type-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 6px;
    }
    .evidence-type {
      padding: 10px 6px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-2);
      color: var(--text);
      cursor: pointer;
    }
    .evidence-type.active {
      border-color: #0f766e;
      background: #0f766e;
      color: #ffffff;
    }
    .preview-card.image-preview {
      display: flex;
      justify-content: center;
      padding: 6px;
    }
    .preview-card.image-preview img {
      max-width: 100%;
      max-height: 260px;
      object-fit: contain;
      border-radius: 6px;
    }
    .preview-card.image-preview.thumb-broken::after {
      content: "no preview";
      font-size: 11px;
      color: #94a3b8;
    }
    .date-filter input[type="date"] {
      height: 26px;
      width: 128px;
      padding: 2px 4px;
      font-size: 11px;
    }
    .thumb-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
      gap: 8px;
      padding: 8px;
      overflow-y: auto;
    }
    .thumb-card {
      position: relative;
      border: 1px solid rgba(148, 163, 184, 0.25);
      border-radius: 8px;
      padding: 6px;
      cursor: pointer;
      background: rgba(15, 23, 42, 0.35);
    }
    .thumb-card.selected,
    .thumb-card.multi-selected {
      border-color: #38bdf8;
      background: rgba(56, 189, 248, 0.12);
    }
    .thumb-card > input[type="checkbox"] {
      position: absolute;
      top: 10px;
      left: 10px;
      z-index: 1;
    }
    .thumb-frame {
      height: 112px;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      border-radius: 6px;
      background: rgba(2, 6, 23, 0.6);
    }
    .thumb-frame img {
      max-width: 100%;
      max-height: 100%;
      object-fit: contain;
    }
    .thumb-frame.thumb-broken img {
      display: none;
    }
    .thumb-frame.thumb-broken::after {
      content: "no preview";
      font-size: 11px;
      color: #94a3b8;
    }
    .thumb-name {
      margin-top: 6px;
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .browser-table-wrap .category-table th:nth-child(4),
    .browser-table-wrap .category-table td:nth-child(4),
    .browser-table-wrap .folder-table th:nth-child(3),
    .browser-table-wrap .folder-table td:nth-child(3) {
      width: 82px;
    }
    .browser-table-wrap .category-table th:nth-child(5),
    .browser-table-wrap .category-table td:nth-child(5),
    .browser-table-wrap .folder-table th:nth-child(4),
    .browser-table-wrap .folder-table td:nth-child(4) {
      width: 72px;
    }
    .browser-table-wrap .category-table th:nth-child(6),
    .browser-table-wrap .category-table td:nth-child(6),
    .browser-table-wrap .folder-table th:nth-child(5),
    .browser-table-wrap .folder-table td:nth-child(5) {
      width: 94px;
    }
    .browser-table-wrap .category-table th:nth-child(7),
    .browser-table-wrap .category-table td:nth-child(7),
    .browser-table-wrap .folder-table th:nth-child(6),
    .browser-table-wrap .folder-table td:nth-child(6) {
      width: 150px;
    }
    .browser-table-wrap .category-table th:nth-child(8),
    .browser-table-wrap .category-table td:nth-child(8),
    .browser-table-wrap .folder-table th:nth-child(7),
    .browser-table-wrap .folder-table td:nth-child(7) {
      width: 150px;
    }
    .browser-table-wrap .category-table th:nth-child(9),
    .browser-table-wrap .category-table td:nth-child(9),
    .browser-table-wrap .folder-table th:nth-child(8),
    .browser-table-wrap .folder-table td:nth-child(8) {
      width: 150px;
    }
    .browser-table-wrap .folder-table th:nth-child(9),
    .browser-table-wrap .folder-table td:nth-child(9) {
      width: 150px;
    }
    .browser-table-wrap th.grid-col-name {
      width: 320px;
    }
    .browser-table-wrap th.grid-col-category {
      width: 190px;
    }
    .browser-table-wrap th.grid-col-type {
      width: 100px;
    }
    .browser-table-wrap th.grid-col-ext {
      width: 82px;
    }
    .browser-table-wrap th.grid-col-size {
      width: 96px;
    }
    .browser-table-wrap th.grid-col-flags,
    .browser-table-wrap th.grid-col-offset {
      width: 150px;
    }
    .browser-table-wrap th.grid-col-artifactTime,
    .browser-table-wrap th.grid-col-created,
    .browser-table-wrap th.grid-col-modified,
    .browser-table-wrap th.grid-col-accessed,
    .browser-table-wrap th.grid-col-mftModified,
    .browser-table-wrap td.entry-time {
      width: 176px;
      white-space: nowrap;
    }
    .browser-table-wrap th.grid-col-sha256,
    .browser-table-wrap td.entry-hash {
      width: 470px;
      white-space: nowrap;
    }
    .browser-table-wrap .toolbar {
      gap: 5px;
    }
    .browser-table-wrap button {
      min-height: 26px;
      padding: 3px 7px;
    }
    .category-table .toolbar,
    .email-table .toolbar,
    .folder-table .toolbar {
      flex-wrap: nowrap;
      justify-content: flex-end;
    }
    .icon {
      flex-shrink: 0;
      vertical-align: middle;
      color: var(--muted);
    }
    .file-icon,
    .category-icon {
      float: left;
      margin-right: 6px;
      margin-top: 2px;
      color: var(--muted);
    }
    .file-icon-folder { color: #c9972b; }
    .file-icon-image,
    .file-icon-video { color: #4a7fd6; }
    .file-icon-audio { color: #8a5cd6; }
    .file-icon-executable { color: #d64a4a; }
    .file-icon-archive,
    .file-icon-disk-image { color: #4aa06b; }
    .file-icon-email { color: #d68a3f; }
    .tree-label-row .category-icon {
      float: none;
      margin-top: 0;
      margin-right: 0;
      flex-shrink: 0;
    }
    .entry-name {
      display: block;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 750;
    }
    .entry-path {
      display: block;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--muted);
      font-size: 11px;
      line-height: 1.25;
    }
    .entry-kind,
    .entry-ext,
    .entry-size,
    .entry-offset,
    .entry-time,
    .email-cell {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .email-body-cell {
      color: var(--muted);
    }
    .entry-flags {
      display: flex;
      flex-wrap: nowrap;
      gap: 4px;
      overflow: hidden;
      white-space: nowrap;
    }
    .entry-flags .pill {
      flex: 0 1 auto;
      min-width: 0;
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      min-height: 22px;
      padding: 2px 6px;
      font-size: 11px;
    }
    .entry-flags .pill.more {
      flex: 0 0 auto;
    }
    .entry-category {
      display: block;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .entry-row {
      cursor: pointer;
    }
    .entry-row.selected td {
      background: #e8f3f0;
    }
    .entry-row.multi-selected td {
      background: #f1f7f5;
    }
    .entry-row.selected.multi-selected td {
      background: #dcefe9;
    }
    .browser-viewer-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }
    .browser-viewer.viewer-idle .hex-meta {
      display: none;
    }
    .hex-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .hex-meta label {
      max-width: 130px;
    }
    .hex-meta select,
    .hex-meta input {
      min-height: 30px;
      padding: 5px 7px;
    }
    .byte-context {
      display: grid;
      grid-template-columns: repeat(2, minmax(58px, 1fr));
      min-width: 132px;
      min-height: 30px;
      border: 1px solid var(--line);
      border-radius: 6px;
      overflow: hidden;
      background: #fff;
    }
    .byte-context button {
      min-height: 30px;
      padding: 5px 8px;
      border: 0;
      border-radius: 0;
      background: transparent;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
    }
    .byte-context button + button {
      border-left: 1px solid var(--line);
    }
    .byte-context button.active {
      background: var(--text);
      color: #fff;
    }
    .byte-context button:disabled {
      cursor: not-allowed;
      color: #9aa7a4;
      background: #f3f6f5;
    }
    .hex-view {
      overflow: auto;
      background: #0f1716;
      color: #eef7f4;
      min-height: 0;
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 13px;
    }
    .hex-current {
      position: sticky;
      top: 0;
      z-index: 2;
      display: flex;
      flex-wrap: wrap;
      gap: 8px 14px;
      align-items: center;
      min-width: max-content;
      padding: 8px 10px;
      border-bottom: 1px solid rgba(255,255,255,.12);
      background: #121f1d;
      color: #d8e8e4;
      user-select: none;
    }
    .hex-current strong {
      margin-right: 5px;
      color: #8fd5c8;
      font-size: 11px;
    }
    .hex-current-spacer {
      flex: 1 1 auto;
      min-width: 10px;
    }
    .hex-current button {
      min-height: 28px;
      padding: 4px 9px;
      font-size: 11px;
    }
    .hex-current button.ghost {
      border-color: rgba(143,213,200,.45);
      color: #8fd5c8;
    }
    .hex-grid {
      min-width: max-content;
    }
    .hex-row {
      display: grid;
      grid-template-columns: 100px max-content max-content;
      gap: 8px;
      min-width: max-content;
      padding: 5px 10px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      white-space: pre;
    }
    .hex-row:nth-child(2n) {
      background: rgba(255,255,255,.025);
    }
    .hex-offset {
      color: #8fd5c8;
    }
    .hex-bytes {
      display: grid;
      grid-template-columns: repeat(var(--bytes-per-row, 16), 2ch);
      column-gap: 1ch;
      min-width: calc(var(--bytes-per-row, 16) * 3ch);
    }
    .hex-ascii {
      display: grid;
      grid-template-columns: repeat(var(--bytes-per-row, 16), 1ch);
      min-width: calc(var(--bytes-per-row, 16) * 1ch);
      color: #f0c38a;
    }
    .hex-cell {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 18px;
      border-radius: 3px;
      cursor: cell;
      user-select: none;
      touch-action: none;
    }
    .hex-cell:hover {
      background: rgba(255,255,255,.12);
    }
    .hex-cell.selected {
      background: #ffd166;
      color: #0f1716;
    }
    .hex-info,
    .raw-find {
      min-width: max-content;
      padding: 8px 10px;
      border-bottom: 1px solid rgba(255,255,255,.12);
      background: #142522;
      color: #d8e8e4;
    }
    .hex-info {
      min-width: 0;
      color: #f0c38a;
      font-weight: 750;
      line-height: 1.4;
      white-space: normal;
      overflow-wrap: anywhere;
    }
    .raw-find {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 3;
    }
    .raw-find input,
    .raw-find select {
      min-height: 28px;
      padding: 4px 7px;
      border: 1px solid rgba(255,255,255,.2);
      border-radius: 4px;
      background: #0f1716;
      color: #eef7f4;
    }
    .raw-find input {
      width: min(320px, 45vw);
    }
    .raw-find button {
      min-height: 28px;
      padding: 4px 9px;
      font-size: 11px;
    }
    .raw-find button.ghost {
      border-color: rgba(143,213,200,.45);
      color: #8fd5c8;
    }
    .raw-find-status {
      color: #f0c38a;
      overflow-wrap: anywhere;
    }
    .hex-decode {
      display: grid;
      gap: 10px;
      min-width: max-content;
      padding: 10px;
      border-top: 1px solid rgba(255,255,255,.12);
      background: #121a19;
    }
    .hex-decode-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      color: #8fd5c8;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }
    .data-interpreter {
      position: fixed;
      top: 120px;
      right: 24px;
      z-index: 1100;
      min-width: 300px;
      max-width: 380px;
      background: #121a19;
      border: 1px solid rgba(143,213,200,.35);
      border-radius: 8px;
      box-shadow: 0 8px 24px rgba(0,0,0,.5);
      font-size: 12px;
    }
    .di-head {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      cursor: move;
      color: #8fd5c8;
      font-weight: 800;
      font-size: 11px;
      text-transform: uppercase;
      border-bottom: 1px solid rgba(255,255,255,.12);
      user-select: none;
      touch-action: none;
    }
    .di-head .hex-endian {
      margin-left: auto;
    }
    .di-close {
      background: transparent;
      border: none;
      color: #8fd5c8;
      font-size: 14px;
      cursor: pointer;
      padding: 0 4px;
    }
    .di-table {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 2px 12px;
      margin: 0;
      padding: 8px 10px;
    }
    .di-table dt {
      color: #7fa89f;
      white-space: nowrap;
    }
    .di-table dd {
      margin: 0;
      color: #e4efec;
      font-family: ui-monospace, Consolas, monospace;
      word-break: break-all;
    }
    .hex-endian {
      display: inline-flex;
      gap: 2px;
    }
    .hex-endian button {
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 800;
      background: transparent;
      color: #8fd5c8;
      border: 1px solid rgba(143,213,200,.4);
      border-radius: 4px;
      cursor: pointer;
    }
    .hex-endian button.active {
      background: #8fd5c8;
      color: #10201c;
    }
    .hex-decode-grid {
      display: grid;
      grid-template-columns: minmax(320px, 1fr) minmax(260px, .8fr);
      gap: 10px;
    }
    .hex-decode-group {
      overflow: hidden;
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 6px;
      background: #0f1716;
    }
    .hex-decode-group h3 {
      padding: 7px 9px;
      border-bottom: 1px solid rgba(255,255,255,.1);
      color: #f0c38a;
      font-size: 11px;
      text-transform: uppercase;
    }
    .hex-decode-table {
      display: grid;
      grid-template-columns: 160px minmax(220px, 1fr);
    }
    .hex-decode-table dt,
    .hex-decode-table dd {
      min-width: 0;
      padding: 6px 8px;
      border-top: 1px solid rgba(255,255,255,.06);
    }
    .hex-decode-table dt:nth-of-type(1),
    .hex-decode-table dd:nth-of-type(1) {
      border-top: 0;
    }
    .hex-decode-table dt {
      color: #8fd5c8;
      font-weight: 750;
    }
    .hex-decode-table dd {
      margin: 0;
      color: #eef7f4;
      overflow-wrap: anywhere;
      white-space: pre-wrap;
    }
    body.viewer-fullscreen #browserViewer {
      position: fixed;
      inset: 0;
      z-index: 1000;
      border: 0;
      border-radius: 0;
      box-shadow: none;
      grid-template-rows: auto minmax(0, 1fr);
    }
    body.viewer-fullscreen #browserViewer .browser-viewer-head {
      border-bottom-color: #cfd9d6;
    }
    body.viewer-fullscreen #hexView {
      font-size: 14px;
    }
    body.viewer-fullscreen .browser-workspace.inspector-collapsed #browserViewer {
      display: grid;
    }
    .text-view {
      min-height: 0;
      overflow: auto;
      padding: 10px;
      background: #fff;
      color: var(--text);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 13px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .metadata-view {
      min-height: 0;
      overflow: auto;
      padding: 12px;
      background: #fff;
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .inspector-summary {
      display: grid;
      gap: 8px;
      padding-bottom: 12px;
      margin-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }
    .inspector-title {
      margin: 0;
      color: var(--text);
      font-size: 16px;
      line-height: 1.2;
      font-family: inherit;
    }
    .inspector-path {
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .inspector-badges,
    .inspector-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }
    .inspector-actions button {
      min-height: 28px;
      padding: 4px 8px;
    }
    .preview-card {
      display: grid;
      gap: 8px;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-2);
    }
    .preview-title {
      margin: 0;
      color: var(--text);
      font-family: inherit;
      font-size: 14px;
      line-height: 1.25;
    }
    .preview-meta {
      display: grid;
      gap: 4px;
      color: var(--muted);
      font-size: 12px;
    }
    .preview-body {
      max-height: 220px;
      overflow: auto;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      font-size: 13px;
      line-height: 1.35;
    }
    .preview-url {
      color: var(--accent);
      overflow-wrap: anywhere;
    }
    .metadata-grid {
      display: grid;
      grid-template-columns: 160px minmax(0, 1fr);
      gap: 6px 12px;
    }
    .metadata-grid dt {
      color: var(--muted);
      font-weight: 800;
    }
    .metadata-grid dd {
      margin: 0;
      min-width: 0;
      overflow-wrap: anywhere;
    }
    .category-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 8px;
      padding: 8px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }
    .category-card {
      display: grid;
      gap: 4px;
      min-height: 72px;
      padding: 9px 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: var(--text);
      text-align: left;
    }
    .category-card.active {
      border-color: rgba(11,111,99,.55);
      background: #e8f3f0;
    }
    .category-card strong {
      font-size: 17px;
      line-height: 1;
    }
    .category-card span {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .category-row-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }
    .metadata-section {
      display: grid;
      gap: 8px;
      padding-bottom: 12px;
      margin-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }
    .metadata-section h3 {
      margin: 0;
      color: var(--text);
      font-family: inherit;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    .metadata-section summary {
      cursor: pointer;
      color: var(--text);
      font-weight: 800;
      text-transform: uppercase;
      font-size: 12px;
    }
    .metadata-section pre {
      max-height: 260px;
      overflow: auto;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-2);
      color: var(--text);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      white-space: pre-wrap;
    }
    .analysis-status {
      border-left: 4px solid var(--warn);
      background: #fff7ed;
      color: var(--text);
      padding: 10px 12px;
      font-size: 13px;
      line-height: 1.35;
    }
    /* Short-lived examiner guidance must not permanently consume evidence
       workspace height. Error and warning notices intentionally do not use
       this class and therefore remain visible. */
    .analysis-status.transient-guidance {
      overflow: hidden;
      animation: transientGuidanceExpire var(--guidance-duration, 7s) ease forwards;
    }
    @keyframes transientGuidanceExpire {
      0%, 72% {
        opacity: 1;
        max-height: 120px;
        padding-top: 10px;
        padding-bottom: 10px;
        border-left-width: 4px;
      }
      100% {
        opacity: 0;
        max-height: 0;
        padding-top: 0;
        padding-bottom: 0;
        border-left-width: 0;
        visibility: hidden;
      }
    }
    body.analysis-fullscreen .app {
      grid-template-columns: 1fr;
      min-height: 100vh;
    }
    body.analysis-fullscreen .sidebar,
    body.analysis-fullscreen .topbar,
    body.analysis-fullscreen .tabs {
      display: none;
    }
    body.analysis-fullscreen main {
      padding: 8px;
      gap: 0;
      min-height: 100vh;
    }
    body.analysis-fullscreen .view.active {
      gap: 0;
    }
    body.analysis-fullscreen .view.analyze-view.active,
    body.analysis-fullscreen .browser-panel {
      min-height: calc(100vh - 16px);
    }
    body.analysis-fullscreen .browser-panel {
      border-radius: 0;
      box-shadow: none;
    }
    body.analysis-fullscreen .browser-panel .panel-body {
      height: calc(100vh - 72px);
      min-height: 560px;
      padding: 8px;
    }
    body.analysis-fullscreen .browser-workspace {
      --inspector-width: 540px;
      grid-template-columns: minmax(260px, 340px) minmax(420px, 1fr) 12px minmax(340px, var(--inspector-width));
      grid-template-rows: minmax(0, 1fr);
      height: 100%;
      min-height: 0;
    }
    body.analysis-fullscreen .browser-workspace.inspector-collapsed {
      grid-template-columns: minmax(260px, 340px) minmax(0, 1fr);
    }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 0;
      background: #111c1b;
      color: #edf8f5;
      border-radius: 8px;
      padding: 12px;
      max-height: 260px;
      overflow: auto;
    }
    @media (max-width: 980px) {
      .app { grid-template-columns: 1fr; }
      .sidebar { border-right: 0; border-bottom: 1px solid var(--line); }
      .topbar, .grid-2, .dashboard-grid { grid-template-columns: 1fr; }
      .stats { min-width: 0; grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 620px) {
      main, .sidebar { padding: 12px; }
      .row { grid-template-columns: 1fr; }
      .dashboard-category-row { grid-template-columns: 1fr auto; }
      .dashboard-category-bar { grid-column: 1 / -1; }
      .browser-panel .panel-body { height: auto; min-height: 0; }
      .browser-workspace { grid-template-columns: 1fr; grid-template-rows: auto minmax(260px, 40vh) minmax(340px, 1fr); }
      .pane-resizer { display: none; }
      .browser-tree { max-height: 260px; }
      .browser-viewer-head { grid-template-columns: 1fr; }
      td.actions { width: auto; }
      table, thead, tbody, tr, th, td { display: block; }
      thead { display: none; }
      tr { border-bottom: 1px solid var(--line); padding: 8px 0; }
      td { border: 0; padding: 6px 0; }
      .hex-decode-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app">
    <aside class="sidebar">
      <div class="brand">
        <div class="mark">K</div>
        <div>
          <h1>KDFT Workbench</h1>
          <p class="muted tiny">Local case interface</p>
        </div>
      </div>

      <section class="panel">
        <h2>Case</h2>
        <label>Case database<input id="casePath" spellcheck="false"></label>
        <div class="toolbar">
          <button id="refreshCase" class="secondary">Refresh</button>
        </div>
      </section>

      <section class="panel">
        <button id="caseOpenSetup" class="secondary">New / Open Case</button>
      </section>

      <div id="notice" class="notice">Ready.</div>
    </aside>

    <main>
      <section class="panel topbar">
        <div class="topbar-case">
          <button id="toggleSidebar" class="ghost sidebar-toggle" title="Show or hide the case sidebar">&#9776;</button>
          <h2 id="caseTitle">No case loaded</h2>
          <span id="caseMeta" class="muted tiny"></span>
        </div>
        <div class="stats">
          <span class="stat"><span class="muted tiny">Evidence</span><strong id="statEvidence">0</strong></span>
          <span class="stat"><span class="muted tiny">Entries</span><strong id="statEntries">0</strong></span>
          <span class="stat"><span class="muted tiny">Bookmarks</span><strong id="statBookmarks">0</strong></span>
          <span class="stat"><span class="muted tiny">Report</span><strong id="statReport">0</strong></span>
        </div>
      </section>

      <nav class="tabs">
        <button class="tab active" data-view="dashboardView" title="Case Dashboard (Alt+1)">Case Dashboard<span class="tab-shortcut">Alt+1</span></button>
        <button class="tab" data-view="evidenceView" title="Add and manage evidence (Alt+2)">Evidence<span class="tab-shortcut">Alt+2</span></button>
        <button class="tab" data-view="analyzeView" title="Analyze artifacts (Alt+3)">Analyze<span class="tab-shortcut">Alt+3</span></button>
        <button class="tab" data-view="searchView" title="Deep Search (Alt+4)">Deep Search<span class="tab-shortcut">Alt+4</span></button>
        <button class="tab" data-view="bookmarksView" title="Bookmarks (Alt+5)">Bookmarks<span class="tab-shortcut">Alt+5</span></button>
        <button class="tab" data-view="reportView" title="Quick Report (Alt+6)">Quick Report<span class="tab-shortcut">Alt+6</span></button>
        <button class="tab" data-view="timelineView" title="Timeline (Alt+7)">Timeline<span class="tab-shortcut">Alt+7</span></button>
      </nav>

      <section id="setupView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Create New Case</h2><span class="pill good">Step 1</span></div>
            <div class="panel-body form-grid">
              <label>Case database file<input id="setupCasePath" spellcheck="false" placeholder="C:\Cases\my-case.kdft.sqlite"></label>
              <label>Name<input id="newCaseName" value="Workbench Case"></label>
              <label>Case number<input id="newCaseNumber" placeholder="e.g. 2026-0042"></label>
              <label>Case type<select id="newCaseType">
                <option value="">unspecified</option>
                <option>Administrative review</option>
                <option>Criminal</option>
                <option>Corporate compliance</option>
                <option>eDiscovery</option>
                <option>Fraud</option>
                <option>Human resources</option>
                <option>Intrusion / incident response</option>
                <option>Other</option>
              </select></label>
              <label>Examiner<input id="newCaseExaminer" autocomplete="name"></label>
              <label>Description<textarea id="newCaseDescription" placeholder="Scan / case description"></textarea></label>
              <button id="createCase">Create Case</button>
              <p class="muted tiny">After creating the case, add disk images, folders, files, or browser history from Evidence.</p>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Open Existing Case</h2><span class="pill">Resume</span></div>
            <div class="panel-body form-grid">
              <label>Case database<input id="caseOpenPath" spellcheck="false" placeholder="C:\Cases\my-case.kdft.sqlite"></label>
              <button id="caseOpenButton" class="secondary">Open Case</button>
              <p class="muted tiny">Opens the case and shows its dashboard.</p>
            </div>
          </section>
        </div>
      </section>

      <section id="dashboardView" class="view active">
        <div class="dashboard-grid">
          <section class="panel">
            <div class="panel-head"><h2>Case Overview</h2><span class="pill">Summary</span></div>
            <div id="dashboardCaseOverview" class="panel-body"></div>
          </section>

          <section class="panel">
            <div class="panel-head"><h2>Evidence Overview</h2><span class="pill">Sources</span></div>
            <div id="dashboardEvidenceOverview" class="panel-body"></div>
          </section>

          <section class="panel">
            <div class="panel-head"><h2>Artifact Categories</h2><span class="pill">Indexed</span></div>
            <div id="dashboardArtifactCategories" class="panel-body"></div>
          </section>
        </div>
      </section>

      <section id="evidenceView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Add Evidence</h2><span class="pill good">Read File System</span></div>
            <div class="panel-body form-grid">
              <div class="evidence-type-row" id="evidenceTypeRow">
                <button class="evidence-type active" data-type="image">Disk image</button>
                <button class="evidence-type" data-type="folder" title="A local folder of files">Folder</button>
                <button class="evidence-type" data-type="file" title="A single local file">Single file</button>
                <button class="evidence-type" data-type="browser_history" title="Chrome/Edge/Chromium, Firefox, or Safari history DB file; profile folders can be pasted manually">Browser history</button>
              </div>
              <div class="path-pick-row">
                <label id="evidencePathLabel" class="path-pick-label">Image path<input id="evidencePath" spellcheck="false" placeholder="C:\Evidence\image.E01"></label>
                <button id="browseEvidence" class="secondary">Choose&hellip;</button>
              </div>
              <div class="row" id="fsOptionsRow">
                <label title="Attach only keeps the evidence read-only and immediately available through Browse source. Index now additionally creates the searchable snapshot used by Deep Search, Categories, Bookmarks, and Reports.">Read File System<select id="readFileSystem" title="Browse source is always complete and read-only. This choice controls whether KDFT also creates the searchable case index."><option value="true">yes &mdash; index now</option><option value="false">no &mdash; attach only</option></select></label>
              </div>
              <details id="processingOptions" class="processing-options" title="Processors can be rerun additively. Legacy OLE, structured Unix syslog, and picture-content analysis do not yet have dedicated decoders; Deep Search already uses captured content and extracted parser text.">
                <summary class="muted tiny">Processors</summary>
                <div class="processing-options-grid">
                  <label class="check-option" title="Re-read the evidence file system and replace the existing indexed snapshot before running the selected processors. Leave this OFF to add or rerun processors without deleting previously indexed files or other processor results."><input type="checkbox" id="optReindexFilesystem"> Re-index filesystem (rebuild snapshot)</label>
                  <label class="check-option" title="Read each file's leading bytes into the case for Deep Search content matching. Turning this OFF gives a much faster metadata-only index (names, paths, timestamps, sizes, offsets) - content search then reports 'not indexed' for this evidence until re-processed with content on."><input type="checkbox" id="optCaptureContent" checked> Capture file content for search</label>
                  <label class="check-option" title="Stream every indexed .eml / RFC-822 candidate without a file-size cap and parse embedded PST/OST mailboxes into message metadata. MIME body/attachment decoding remains separately disclosed."><input type="checkbox" id="optParseEmails" checked> Email messages</label>
                  <label class="check-option" title="Compute the evidence SHA-256 over the decoded logical media after indexing (full read of the media - can take long on large images). Also records the acquisition segment manifest."><input type="checkbox" id="optRunHash"> Compute evidence hash</label>
                  <label class="check-option" title="Compute a SHA-256 for EVERY indexed file's complete reconstructed content and stamp it into the entry metadata. Reads every file - can take long on large or compressed images. Files that cannot be fully reconstructed get a disclosed skip reason instead of a partial-content hash."><input type="checkbox" id="optRunFileHash"> Hash files (SHA-256 per file)</label>
                  <label class="check-option" title="Verify file types by content signature after indexing and stamp match/mismatch/alias per entry. Enabled by default so renamed files are visible in new analyses."><input type="checkbox" id="optRunSignatures" checked> Verify file types (signatures)</label>
                  <label class="check-option" title="Signature-carve the whole decoded media after indexing (can take long on large images). Carved lengths are marked verified or not-verified per file."><input type="checkbox" id="optRunCarve"> Carve by file signature</label>
                  <label class="check-option" title="Detect browser profiles among the indexed entries (Chromium History, Firefox places.sqlite, Safari History.db) and parse their visit/download/login records into the case."><input type="checkbox" id="optRunBrowserParse" checked> Browser artifacts</label>
                  <label class="check-option" title="Extract local accounts, SID-to-profile mappings, browser accounts, cookie/session indicators, host/network configuration, IP/DNS/gateway values, Wi-Fi profiles, known credential stores, and plaintext passwords/tokens from exact structured configuration fields. Encrypted material is never presented as decoded plaintext."><input type="checkbox" id="optParseIdentities" checked> Identities, accounts, networks and secrets</label>
                  <label class="check-option" title="Recover each indexed ZIP candidate and parse its members into provenance-linked records. Exact package names, CRC, sizes, compression, and complete textual-member segments are retained."><input type="checkbox" id="optParseArchives" checked> ZIP archive members</label>
                  <label class="check-option" title="Recover each indexed DOCX package and extract supported WordprocessingML text parts into complete ordered searchable segments. Unsupported text-bearing parts are disclosed as partial coverage."><input type="checkbox" id="optParseDocuments" checked> DOCX document text</label>
                  <label class="check-option" title="Recover and parse supported Windows artifact sources: LNK shortcuts, automatic/custom Jump Lists, Prefetch, EVTX event records, NTFS USN Journal streams, scheduled-task XML, Amcache, UserAssist, ShellBags, and exact Run/RunOnce Registry values. Unsupported Shimcache/SRUM decoding remains explicitly disclosed."><input type="checkbox" id="optParseWindowsArtifacts" checked> Windows artifacts (activity, execution, Registry)</label>
                </div>
                <p class="muted tiny">Scope note: generic legacy OLE documents, structured Unix syslog records, and picture-content analysis do not yet have dedicated parsers. Deep Search already uses captured file content and extracted parser text, so a second misleading “keyword index” switch is not needed.</p>
              </details>
              <div class="row" id="historyOptionsRow" hidden>
                <label>Max visits (0 = all)<input id="historyMaxVisits" type="number" min="0" value="0"></label>
              </div>
              <label>Notes<textarea id="evidenceNotes"></textarea></label>
              <button id="addEvidence">Add Evidence</button>
            </div>
          </section>

          <section class="panel">
            <div class="panel-head">
              <h2>Evidence Sources</h2>
            </div>
            <div class="panel-body">
              <div id="evidenceTable"></div>
            </div>
          </section>

        </div>
      </section>

      <section id="analyzeView" class="view analyze-view">
          <section class="panel browser-panel">
            <div class="panel-head">
              <div>
                <h2>Analyze Evidence</h2>
                <p id="browserTitle" class="muted tiny">Select an evidence source</p>
              </div>
              <div class="toolbar">
                <button id="analyzeBack" class="ghost" title="Back in Analyze" disabled>&larr; Back</button>
                <button id="analyzeForward" class="ghost" title="Forward in Analyze" disabled>Forward &rarr;</button>
                <button id="liveBrowse" class="ghost" title="Browse the complete attached source read-only without waiting for indexing. Index limits affect Deep Search, Categories, Bookmarks, and Reports, not this direct source view.">Browse source</button>
                <button id="recategorizeBtn" class="ghost" hidden title="Entries in this case were categorized by an older classifier version. Refresh re-runs the current classifier over the case database only (fast; evidence is not re-read).">Update categories</button>
                <button id="exportReportFromAnalyze" class="ghost">Export report</button>
                <button id="openAnalyzeWindow" class="ghost">Open full screen</button>
              </div>
            </div>
            <div class="panel-body">
              <div class="browser-workspace">
                <div class="browser-tree">
                  <div class="pane-title"><span id="treeTitle">Entries</span><span id="treeCount" class="tiny">0</span></div>
                  <div class="tree-mode">
                    <button id="treeModeFilesystem" class="active">Entries</button>
                    <button id="treeModeCategories">Categories</button>
                  </div>
                  <div id="filesystemTree" class="tree-list"></div>
                </div>
                <div class="browser-list">
                  <div class="pane-title">
                    <span>Folder Contents</span>
                    <span id="folderTitle" class="tiny">/</span>
                    <span class="toolbar">
                      <span class="tiny date-filter">
                        <input type="date" id="dateFilterFrom" title="Show only rows with a timestamp on or after this date">
                        <input type="date" id="dateFilterTo" title="Show only rows with a timestamp on or before this date">
                        <button id="dateFilterClear" class="ghost" title="Clear date filter">All dates</button>
                      </span>
                      <span id="selectedCount" class="tiny">0 selected</span>
                      <button id="selectVisibleRows" class="ghost">Select visible</button>
                      <button id="bookmarkReportSelected" class="ghost" disabled>Report selected</button>
                      <select id="selectedAction" class="toolbar-select" title="Selected actions">
                        <option value="" disabled selected hidden>Selected actions</option>
                        <option value="bookmark">Bookmark selected</option>
                        <option value="bookmark_report">Bookmark + export report</option>
                        <option value="export_files">Export selected file bytes</option>
                        <option value="export_csv">Export selected as CSV</option>
                        <option value="clear">Clear selection</option>
                      </select>
                      <button id="toggleInspector" class="ghost">Hide inspector</button>
                    </span>
                  </div>
                  <div id="entryTable" class="browser-table-wrap"></div>
                </div>
                <div id="viewerResizer" class="pane-resizer" title="Drag to resize inspector"></div>
                <div id="browserViewer" class="browser-viewer viewer-idle">
                  <div class="browser-viewer-head">
                    <div>
                      <div class="pane-title" style="border:0;padding:0;background:transparent;min-height:0"><span>Inspector</span></div>
                      <div id="hexStatus" class="muted tiny">Select an item for preview, details, and bytes.</div>
                    </div>
                    <div class="hex-meta">
                      <div id="byteContext" class="byte-context" role="group" aria-label="Byte context">
                        <button id="byteContextFile" class="active" type="button" aria-pressed="true">File</button>
                        <button id="byteContextFilesystem" type="button" aria-pressed="false" disabled>File system</button>
                      </div>
                      <label>Display<select id="viewerMode"><option value="hex">Hex + ASCII</option><option value="text">Text</option><option value="metadata">Details</option></select></label>
                      <label>Bytes/row<select id="bytesPerRow"><option value="16">16</option><option value="8">8</option><option value="32">32</option></select></label>
                      <label>Offset base<select id="offsetBase"><option value="hex">hex</option><option value="decimal">decimal</option></select></label>
                      <label>Offset<input id="hexOffset" spellcheck="false" value="0"></label>
                      <label>Length<input id="hexLength" type="number" min="16" value="512"></label>
                      <button id="showEntryDetails" class="ghost">Details</button>
                      <button id="hexPrev" class="ghost">Prev</button>
                      <button id="hexGo" class="secondary">Go</button>
                      <button id="hexNext" class="ghost">Next</button>
                      <button id="openSelectedEntry" class="ghost" disabled>Open file</button>
                      <button id="bookmarkSelectedEntry" class="ghost">Bookmark</button>
                      <button id="dataInterpreterToggle" class="ghost" onclick="toggleDataInterpreter()">Data Interpreter</button>
                      <button id="toggleViewerFullscreen" class="ghost" aria-pressed="false">Full screen</button>
                    </div>
                  </div>
                  <div id="hexView" class="hex-view"></div>
                </div>
              </div>
            </div>
          </section>
      </section>

      <section id="timelineView" class="view timeline-view">
        <section class="panel timeline-panel">
          <div class="panel-head">
            <div>
              <h2>Timeline</h2>
              <p id="timelineSubtitle" class="muted tiny">Timestamped events from loaded case entries</p>
            </div>
            <div class="toolbar">
              <span id="timelineCount" class="pill">not built</span>
              <button id="buildTimeline" class="secondary">Build timeline</button>
            </div>
          </div>
          <div class="panel-body">
            <div class="timeline-shell">
              <div class="timeline-controls">
                <div id="timelineSummary" class="timeline-summary">No timeline built.</div>
                <span class="tiny date-filter timeline-date-filter">
                  <input type="date" id="timelineDateFrom" title="Show only events on or after this date">
                  <input type="date" id="timelineDateTo" title="Show only events on or before this date">
                  <button id="timelineDateFilterClear" class="ghost" title="Clear date filter">All dates</button>
                </span>
              </div>
              <div id="timelineGraph" class="timeline-graph"></div>
              <div id="timelineTimestampNav" class="timeline-selection-nav"></div>
              <div class="timeline-bottom">
                <div id="timelineTable" class="timeline-table-wrap"></div>
                <aside id="timelineDetail" class="timeline-detail"></aside>
              </div>
            </div>
          </div>
        </section>
      </section>

      <section id="searchView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Deep Search</h2><span class="pill">Indexed + bitwise</span></div>
            <div class="panel-body form-grid">
              <label>Query<input id="searchQuery" placeholder="keyword, file name, URL, hex:50 4B"></label>
              <label>Search mode<select id="searchMode" title="Indexed is a fast lookup over the processed case database. All also scans the raw evidence byte-for-byte (unallocated space and file slack included) for the same query.">
                <option value="indexed">Indexed (fast)</option>
                <option value="all">All - indexed + bitwise (whole disk)</option>
              </select></label>
              <label>Evidence<select id="searchEvidence"><option value="">All evidence</option></select></label>
              <div class="row">
                <label>Include content<select id="includeContent"><option value="true">yes</option><option value="false">no</option></select></label>
                <label>Results per page<input id="maxResults" type="number" min="1" max="1000" value="200" title="Protective response-page range: 1-1,000. This never caps total search coverage; cursors and Load more continue until complete. Larger values are rejected, not silently clamped."></label>
              </div>
              <label>Max file bytes<input id="maxFileBytes" type="number" min="1" max="4096" value="4096" title="Indexed content search only has each file's first 4,096 bytes available (indexed at Read File System time) - this can only narrow that window, not widen it. The bitwise pass in All mode has no such limit."></label>
              <div class="row">
                <label>Category scope<input id="searchCategory" placeholder="e.g. Email, Pictures, Recovery"></label>
                <label>File types<input id="searchFileTypes" placeholder="jpg,png,zip"></label>
              </div>
              <p class="muted tiny">Prefix the query with <strong>hex:</strong> for a byte-pattern search (e.g. hex:FF D8 FF); hits report byte offsets. Indexed path/metadata coverage includes every entry in scope across all pages. Generic file-content matching covers only the first <strong>4,096 bytes per file</strong> captured during processing; supported DOCX/ZIP parsers search all text segments they persisted, with unsupported parts disclosed in parser metadata. Category/file-type scopes and Max file bytes apply to the indexed pass. <strong>All</strong> mode additionally scans each selected image/file source byte-for-byte to EOF, including unallocated space and slack. Raw hits prove an absolute offset and volume containment, not ownership by a parsed file; folder evidence has no single raw stream and is explicitly skipped. Results are paged: a full page never means later matches were discarded; use Load more until Complete is shown.</p>
              <button id="runSearch">Run Search</button>
            </div>
          </section>

          <section class="panel">
            <div class="panel-head"><h2>Results</h2><span id="searchCount" class="pill">0</span></div>
            <div class="panel-body">
              <div class="toolbar">
                <button id="selectAllSearchResults" class="ghost">Select all</button>
                <button id="bookmarkSelectedSearchResults" class="ghost">Bookmark selected</button>
                <button id="clearSelectedSearchResults" class="ghost">Clear</button>
                <button id="loadMoreSearchResults" class="ghost" hidden>Load more indexed results</button>
                <span id="searchSelectedCount" class="muted tiny">0 selected</span>
                <span id="searchFilterStatus" class="muted tiny"></span>
              </div>
              <div id="searchResults"></div>
              <div id="rawSearchSection" hidden>
                <div class="raw-hits-head">
                  <h3>Bitwise whole-disk hits</h3>
                  <span id="rawSearchCount" class="pill">0</span>
                  <span id="rawSearchStatus" class="muted tiny"></span>
                  <button id="loadMoreRawSearchResults" class="ghost" hidden>Load more bitwise hits</button>
                </div>
                <div id="rawSearchResults"></div>
              </div>
            </div>
          </section>
        </div>
      </section>

      <section id="bookmarksView" class="view">
        <section class="panel">
          <div class="panel-head">
            <h2>Bookmarks</h2>
            <div class="toolbar">
              <span class="pill good">In report</span>
              <button id="clearFindings" class="ghost danger">Clear findings</button>
            </div>
          </div>
          <div class="panel-body">
            <div id="bookmarksTable"></div>
          </div>
        </section>
      </section>

      <section id="reportView" class="view">
        <div class="grid-2">
          <section class="panel">
            <div class="panel-head"><h2>Export</h2><span class="pill">HTML</span></div>
            <div class="panel-body form-grid">
              <label>Output path<input id="reportPath" spellcheck="false"></label>
              <div class="toolbar">
                <button id="exportReport">Export Report</button>
                <button id="openReport" class="ghost">Open</button>
              </div>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Preview Data</h2><span id="reportCount" class="pill">0 folders</span></div>
            <div class="panel-body">
              <pre id="reportPreview">{}</pre>
            </div>
          </section>
        </div>
      </section>
    </main>
  </div>

  <div id="ctxMenu" class="ctx-menu" hidden></div>

  <script>
    const BOOTSTRAP = __KDFT_BOOTSTRAP__;
    const PAGE_PARAMS = new URLSearchParams(window.location.search);
    const ANALYSIS_MODE = PAGE_PARAMS.get("mode") === "analysis";
    const REQUESTED_EVIDENCE_ID = Number(PAGE_PARAMS.get("evidence_id") || "");
    // Processing indexes the whole selected evidence. The helper remains for
    // existing call sites and reports unlimited (the backend treats 0 as no cap).
    function currentProcessMaxEntries() {
      return 0;
    }

    // Recursive folder bookmarking (right-click a folder -> "Bookmark folder
    // (recursive)", live or indexed) only writes case-database rows
    // referencing already-listed files - it never touches or copies the
    // evidence itself, so it defaults to fully unlimited (0). The backend
    // (resolve_unlimited_max_entries in kdft-ui) honors 0 as "no cap at all",
    // not just a high number. API callers may still set an explicit positive
    // examiner limit when they deliberately want a bounded operation.
    function currentRecursiveBookmarkLimit() {
      return 0;
    }

    // Timeline event expansion happens in the browser and produces several
    // events per entry. Keep one build bounded; examiners can use the date
    // range to page through the complete case without freezing the tab.
    function currentTimelineBuildLimit() {
      return 20000;
    }
    if (ANALYSIS_MODE) {
      document.body.classList.add("analysis-fullscreen");
    }
    function makeHexState(entryId = null, offset = 0, length = 512, data = null) {
      return {
        entryId,
        offset,
        length,
        data,
        fetching: false,
        byteContext: "file",
        diskLocation: null,
        locationLoading: false,
        locationError: "",
        selStart: null,
        selEnd: null,
        live: null,
        raw: null,
        find: { query: "", kind: "text", status: "", continuation: null, nextStart: null, active: false, lastMatch: null, matchLength: null }
      };
    }
    const state = {
      casePath: PAGE_PARAMS.get("case_path")
        || (BOOTSTRAP.defaultCasePinned
          ? BOOTSTRAP.defaultCasePath
          : (localStorage.getItem("kdft.casePath") || BOOTSTRAP.defaultCasePath)),
      loadedCasePath: null,
      refreshGeneration: 0,
      data: null,
      searchResults: [],
      searchCursor: null,
      searchComplete: true,
      searchPageLoading: false,
      searchCoverage: null,
      selectedSearchKeys: new Set(),
      selectedRawSearchKeys: new Set(),
      lastRawSearchKey: null,
      searchSessionRestoredCasePath: null,
      searchSort: { column: "", direction: "asc" },
      searchColumnFilters: {},
      gridViews: {},
      lookupEntries: new Map(),
      currentEntryGrid: { gridId: "", entries: [] },
      currentLiveGrid: { gridId: "", items: [] },
      browserState: { evidenceId: null, selectedPath: "/", treeMode: "filesystem", selectedCategory: "" },
      analyzeHistory: { back: [], forward: [], applying: false },
      live: { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null },
      idx: { evidenceId: null, dirCache: {}, dirPaging: {}, expanded: new Set(), selPath: "/" },
      cat: { evidenceId: null, key: null, entries: [], total: null, categoryTotal: null, nextCursor: null, loading: false, error: "", pageSize: 1000 },
      expandedTreePaths: new Map(),
      collapsedCategoryMains: new Set(),
      inspectorCollapsed: false,
      viewerFullscreen: false,
      viewerFullscreenHistoryPending: false,
      selectedEntryIds: new Set(),
      lastSelectedEntryId: null,
      pictureViewMode: "grid",
      liveGuidanceExpiresAt: 0,
      dateFilter: { from: "", to: "" },
      timeline: newTimelineState(),
      hex: makeHexState(),
      lastReportPath: BOOTSTRAP.defaultReportPath,
      pendingAnalysisSelection: ANALYSIS_MODE ? {
        evidenceId: Number.isFinite(REQUESTED_EVIDENCE_ID) && REQUESTED_EVIDENCE_ID > 0 ? REQUESTED_EVIDENCE_ID : null,
        selectedPath: PAGE_PARAMS.get("selected_path") || null,
        treeMode: PAGE_PARAMS.get("tree_mode") === "live"
          ? "live"
          : (PAGE_PARAMS.get("tree_mode") === "categories" || PAGE_PARAMS.has("selected_category") || PAGE_PARAMS.has("category") ? "categories" : "filesystem"),
        selectedCategory: PAGE_PARAMS.get("selected_category") || PAGE_PARAMS.get("category") || "",
        liveVolume: PAGE_PARAMS.get("live_volume") || "",
        viewerTarget: PAGE_PARAMS.get("viewer_target") || "",
        viewerEntryId: PAGE_PARAMS.get("viewer_entry_id") || "",
        viewerVolume: PAGE_PARAMS.get("viewer_volume") || "",
        viewerPath: PAGE_PARAMS.get("viewer_path") || "",
        viewerName: PAGE_PARAMS.get("viewer_name") || "",
        viewerLogicalPath: PAGE_PARAMS.get("viewer_logical_path") || "",
        viewerOffset: PAGE_PARAMS.get("viewer_offset") || "",
        viewerLength: PAGE_PARAMS.get("viewer_length") || "",
        viewerStartOffset: PAGE_PARAMS.get("viewer_start_offset") || "",
        viewerSize: PAGE_PARAMS.get("viewer_size") || "",
        viewerMode: PAGE_PARAMS.get("viewer_mode") || "",
        viewerSelectionStart: PAGE_PARAMS.get("viewer_selection_start") || "",
        viewerSelectionEnd: PAGE_PARAMS.get("viewer_selection_end") || "",
        applied: false
      } : null
    };
    const $ = (id) => document.getElementById(id);
    let hexSelecting = false;
    let hexSelectionAnchor = null;
    let hexPointerId = null;
    let categoryFilterTimer = null;
    let categoryScrollObserver = null;
    const liveVolumeRequests = new Map();
    let localAuthRefreshPromise = null;

    function loadLiveVolumes(evidenceId) {
      const requestKey = currentCasePath() + "|" + String(evidenceId);
      const existing = liveVolumeRequests.get(requestKey);
      if (existing) {
        return existing;
      }
      const request = apiGet("/api/image/volumes", {
        case_path: currentCasePath(),
        evidence_id: evidenceId
      }).finally(() => {
        if (liveVolumeRequests.get(requestKey) === request) {
          liveVolumeRequests.delete(requestKey);
        }
      });
      liveVolumeRequests.set(requestKey, request);
      return request;
    }

    function newCategoryCache(evidenceId = null, key = "") {
      return { evidenceId, key, entries: [], total: null, categoryTotal: null, nextCursor: null, loading: false, error: "", pageSize: 1000 };
    }

    function newTimelineState() {
      return {
        built: false,
        prompted: false,
        casePath: "",
        // Entries fetched directly from /api/timeline/entries when the examiner
        // clicks "Build timeline" - a dedicated, much-higher-limit fetch,
        // independent of whatever happens to already be cached in
        // state.data.entries from ordinary page browsing (see
        // requestTimelineBuild). Empty until the first successful build.
        entries: [],
        truncated: false,
        sourceEntries: 0,
        loadedEntryCount: 0,
        totalEntryCount: 0,
        events: [],
        selectedEntryId: null,
        selectedEventIndex: null,
        graphBuckets: [],
        focusBucket: null,
        scrollToSelected: false,
        building: false,
        buildGeneration: 0
      };
    }

    // Deep Search can be expensive (especially an E01 whole-disk pass), so a
    // browser-history mistake must not discard a completed page of results.
    // Keep the latest search in per-tab session storage: it survives reload,
    // Back/Forward and leaving/re-entering this localhost page, but disappears
    // when the examiner closes the tab and is never written into the evidence.
    function deepSearchSessionCasePath() {
      return normalizePathInput(state.loadedCasePath || state.casePath || "");
    }

    function deepSearchSessionKey(casePath = deepSearchSessionCasePath()) {
      return "kdft.deepSearch.v1:" + String(casePath || "");
    }

    function deepSearchFormSnapshot() {
      const value = (id, fallback = "") => {
        const field = $(id);
        return field ? field.value : fallback;
      };
      return {
        query: value("searchQuery"),
        mode: currentSearchMode(),
        evidence: value("searchEvidence"),
        includeContent: value("includeContent", "true"),
        maxResults: value("maxResults", "200"),
        maxFileBytes: value("maxFileBytes", "4096"),
        category: value("searchCategory"),
        fileTypes: value("searchFileTypes")
      };
    }

    function persistDeepSearchSession() {
      const casePath = deepSearchSessionCasePath();
      if (!casePath) {
        return false;
      }
      const snapshot = {
        version: 1,
        casePath,
        savedAt: new Date().toISOString(),
        form: deepSearchFormSnapshot(),
        searchResults: state.searchResults || [],
        searchCursor: state.searchCursor || null,
        searchComplete: Boolean(state.searchComplete),
        searchCoverage: state.searchCoverage || null,
        searchError: state.searchError || null,
        rawSearchResult: state.rawSearchResult || null,
        selectedSearchKeys: Array.from(state.selectedSearchKeys || []),
        selectedRawSearchKeys: Array.from(state.selectedRawSearchKeys || []),
        gridViews: {
          search: state.gridViews && state.gridViews.search ? state.gridViews.search : null,
          rawSearch: state.gridViews && state.gridViews.rawSearch ? state.gridViews.rawSearch : null
        }
      };
      try {
        sessionStorage.setItem(deepSearchSessionKey(casePath), JSON.stringify(snapshot));
        return true;
      } catch (err) {
        // Storage quotas vary. Preserve at least the examiner's query/options
        // rather than allowing a large result page to erase everything.
        try {
          sessionStorage.setItem(deepSearchSessionKey(casePath), JSON.stringify({
            version: 1,
            casePath,
            savedAt: snapshot.savedAt,
            form: snapshot.form,
            storageWarning: "Result page exceeded browser session storage. Re-run the search to reload hits."
          }));
        } catch (ignored) {
          // Private/locked-down browsers can disable sessionStorage entirely.
        }
        return false;
      }
    }

    function restoreDeepSearchSession() {
      const casePath = deepSearchSessionCasePath();
      if (!casePath || state.searchSessionRestoredCasePath === casePath) {
        return false;
      }
      state.searchSessionRestoredCasePath = casePath;
      let snapshot;
      try {
        snapshot = JSON.parse(sessionStorage.getItem(deepSearchSessionKey(casePath)) || "null");
      } catch (err) {
        return false;
      }
      if (!snapshot || snapshot.version !== 1 || snapshot.casePath !== casePath || !snapshot.form) {
        return false;
      }
      const form = snapshot.form;
      $("searchQuery").value = String(form.query || "");
      $("searchMode").value = form.mode === "all" ? "all" : "indexed";
      $("searchEvidence").value = String(form.evidence || "");
      $("includeContent").value = form.includeContent === "false" ? "false" : "true";
      $("maxResults").value = String(form.maxResults || "200");
      $("maxFileBytes").value = String(form.maxFileBytes || "4096");
      $("searchCategory").value = String(form.category || "");
      $("searchFileTypes").value = String(form.fileTypes || "");
      state.searchResults = Array.isArray(snapshot.searchResults) ? snapshot.searchResults : [];
      state.searchCursor = snapshot.searchCursor || null;
      state.searchComplete = snapshot.searchComplete !== false;
      state.searchCoverage = snapshot.searchCoverage || null;
      state.searchError = snapshot.searchError || null;
      state.rawSearchResult = snapshot.rawSearchResult && Array.isArray(snapshot.rawSearchResult.hits)
        ? snapshot.rawSearchResult
        : null;
      state.searchRunning = false;
      state.rawSearchRunning = false;
      state.selectedSearchKeys = new Set(Array.isArray(snapshot.selectedSearchKeys) ? snapshot.selectedSearchKeys : []);
      state.selectedRawSearchKeys = new Set(Array.isArray(snapshot.selectedRawSearchKeys) ? snapshot.selectedRawSearchKeys : []);
      if (snapshot.gridViews && snapshot.gridViews.search) {
        state.gridViews.search = snapshot.gridViews.search;
        state.searchSort = snapshot.gridViews.search.sort || { column: "", direction: "asc" };
        state.searchColumnFilters = snapshot.gridViews.search.filters || {};
      }
      if (snapshot.gridViews && snapshot.gridViews.rawSearch) {
        state.gridViews.rawSearch = snapshot.gridViews.rawSearch;
      }
      const rawSection = $("rawSearchSection");
      if (rawSection) {
        rawSection.hidden = currentSearchMode() !== "all";
      }
      renderSearchResults();
      renderRawSearchResults();
      if (snapshot.storageWarning) {
        setNotice(snapshot.storageWarning, true);
      } else {
        const loaded = state.searchResults.length + (state.rawSearchResult ? state.rawSearchResult.hits.length : 0);
        setNotice("Restored the previous Deep Search query and " + loaded.toLocaleString() + " loaded result" + (loaded === 1 ? "" : "s") + " for this tab.");
      }
      return true;
    }

    function newLiveBrowseState() {
      return { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
    }

    function newIndexedBrowseState() {
      return { evidenceId: null, dirCache: {}, dirPaging: {}, expanded: new Set(), selPath: "/" };
    }

    function invalidateIndexedBrowseCache(evidenceId) {
      if (evidenceId == null || Number(state.idx.evidenceId) === Number(evidenceId)) {
        state.idx = newIndexedBrowseState();
      }
    }

    function evidenceListSignature(data = state.data) {
      return ((data && data.evidence) || [])
        .map((item) => [Number(item.id), item.source_kind || "", item.source_path || "", item.attached_at || ""])
        .sort((left, right) => left[0] - right[0])
        .map((identity) => JSON.stringify(identity))
        .join("|");
    }

    function sameEvidenceIdentity(left, right) {
      return Boolean(left && right)
        && Number(left.id) === Number(right.id)
        && left.source_kind === right.source_kind
        && left.source_path === right.source_path
        && left.attached_at === right.attached_at;
    }

    function selectedEvidenceIdentityMatches(expected) {
      return sameEvidenceIdentity(selectedEvidenceSource(), expected);
    }

    function clearRemovedEvidenceViewState(evidenceId) {
      const id = Number(evidenceId);
      if (state.browserState.evidenceId === id) {
        state.browserState = { evidenceId: null, selectedPath: "/", treeMode: "filesystem", selectedCategory: "" };
      }
      if (state.live.evidenceId === id) {
        state.live = newLiveBrowseState();
      }
      if (state.idx.evidenceId === id) {
        state.idx = newIndexedBrowseState();
      }
      // Category caches can be scoped to "all" while still containing rows
      // from the removed source, so every removal invalidates the whole cache.
      state.cat = newCategoryCache();
      state.selectedEntryIds = new Set();
      state.lastSelectedEntryId = null;
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      setCurrentEntryGrid("", []);
      setCurrentLiveGrid("", []);
      state.analyzeHistory.back = state.analyzeHistory.back.filter((location) => Number(location.evidenceId) !== id);
      state.analyzeHistory.forward = state.analyzeHistory.forward.filter((location) => Number(location.evidenceId) !== id);
      state.expandedTreePaths.delete(String(id));
      if (state.liveAutoTried) {
        state.liveAutoTried.delete(id);
      }
      if (state.pendingAnalysisSelection && Number(state.pendingAnalysisSelection.evidenceId) === id) {
        state.pendingAnalysisSelection.evidenceId = null;
        state.pendingAnalysisSelection.selectedPath = null;
        state.pendingAnalysisSelection.selectedCategory = "";
      }
      // Search and timeline results are independent caches, not projections of
      // state.data, and otherwise retain rows belonging to removed evidence.
      state.lookupEntries = new Map();
      state.searchResults = [];
      state.selectedSearchKeys = new Set();
      state.selectedRawSearchKeys = new Set();
      state.lastRawSearchKey = null;
      state.rawSearchResult = null;
      state.timeline = newTimelineState();
      state.timeline.casePath = state.casePath;
      updateAnalyzeNavButtons();
      // Analyze evidence/path selection is carried in state and URL params.
      // No localStorage key persists it; kdft.evidencePath is only the Add
      // Evidence input and intentionally remains untouched.
    }

    function reconcileAnalyzeEvidenceState() {
      if (!state.data) {
        return;
      }
      const validIds = new Set(state.data.evidence.map((item) => Number(item.id)));
      const currentId = Number(state.browserState.evidenceId);
      if (!validIds.has(currentId)) {
        const treeMode = state.browserState.treeMode || "filesystem";
        state.browserState = {
          evidenceId: state.data.evidence.length ? state.data.evidence[0].id : null,
          selectedPath: "/",
          treeMode,
          selectedCategory: ""
        };
        state.selectedEntryIds = new Set();
        state.lastSelectedEntryId = null;
        state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      }
      const selectedId = Number(state.browserState.evidenceId);
      if (state.live.evidenceId != null && (!validIds.has(Number(state.live.evidenceId)) || Number(state.live.evidenceId) !== selectedId)) {
        state.live = newLiveBrowseState();
        setCurrentLiveGrid("", []);
      }
      if (state.idx.evidenceId != null && (!validIds.has(Number(state.idx.evidenceId)) || Number(state.idx.evidenceId) !== selectedId)) {
        state.idx = newIndexedBrowseState();
      }
      if (state.cat.evidenceId != null && state.cat.evidenceId !== "all" && !validIds.has(Number(state.cat.evidenceId))) {
        state.cat = newCategoryCache();
      }
      const hexEvidenceId = state.hex && state.hex.live
        ? Number(state.hex.live.evidenceId)
        : (state.hex && state.hex.raw ? Number(state.hex.raw.evidenceId) : null);
      if (hexEvidenceId != null && !validIds.has(hexEvidenceId)) {
        state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      }
    }

    function setNotice(message, bad) {
      const notice = $("notice");
      if (notice) {
        notice.textContent = message;
        notice.classList.toggle("bad", Boolean(bad));
      }
    }

    async function refreshLocalUiAuthentication() {
      if (!localAuthRefreshPromise) {
        localAuthRefreshPromise = (async () => {
          const response = await fetch("/", {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin"
          });
          if (!response.ok) {
            throw new Error("Could not refresh local UI authentication (HTTP " + response.status + ").");
          }
          if (response.body) {
            await response.body.cancel();
          }
        })().finally(() => {
          localAuthRefreshPromise = null;
        });
      }
      return localAuthRefreshPromise;
    }

    async function fetchWithLocalAuthRetry(request) {
      let response = await request();
      if (response.status !== 403) {
        return response;
      }
      if (response.body) {
        await response.body.cancel();
      }
      // A restored tab or newly opened fullscreen window can issue its first
      // API request before the current process cookie replaces a stale one.
      // GET / is unauthenticated and sets the HttpOnly cookie; a rejected 403
      // never reached an API handler, so replaying the request once is safe.
      await refreshLocalUiAuthentication();
      response = await request();
      return response;
    }

    async function apiGet(path, params) {
      const qs = new URLSearchParams(params || {});
      const url = path + (qs.toString() ? "?" + qs.toString() : "");
      const response = await fetchWithLocalAuthRetry(() => fetch(url, {
        cache: "no-store",
        credentials: "same-origin"
      }));
      return readApiResponse(response);
    }

    async function apiPost(path, body) {
      const encodedBody = JSON.stringify(body);
      const response = await fetchWithLocalAuthRetry(() => fetch(path, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: encodedBody
        }));
      return readApiResponse(response);
    }

    async function apiPostReadOnlyWithNetworkRetry(path, body) {
      try {
        return await apiPost(path, body);
      } catch (err) {
        // A tab can survive a local server rebuild/restart while its pooled
        // keep-alive connection does not. Chromium reports that stale-socket
        // failure only as TypeError: Failed to fetch and does not necessarily
        // replay a POST. Indexed search is read-only, so one fresh retry is
        // safe; mutating or audited POST operations must never use this helper.
        const networkFailure = err instanceof TypeError && /failed to fetch|network/i.test(String(err.message || err));
        if (!networkFailure) {
          throw err;
        }
        await new Promise((resolve) => window.setTimeout(resolve, 250));
        return apiPost(path, body);
      }
    }

    async function readApiResponse(response) {
      const payload = await response.json();
      if (!payload.ok) {
        throw new Error(payload.error || response.statusText);
      }
      return payload.data;
    }

    function currentCasePath() {
      const value = normalizePathInput($("casePath").value);
      $("casePath").value = value;
      state.casePath = value;
      localStorage.setItem("kdft.casePath", value);
      return value;
    }

    function refreshRequestIsCurrent(casePath, generation) {
      return generation === state.refreshGeneration
        && state.casePath === casePath
        && normalizePathInput($("casePath").value) === casePath;
    }

    function clearLoadedCaseForRefresh(casePath) {
      if (!state.loadedCasePath || state.loadedCasePath === casePath) {
        return;
      }
      state.data = null;
      state.loadedCasePath = null;
      state.searchResults = [];
      state.searchCursor = null;
      state.searchComplete = true;
      state.searchPageLoading = false;
      state.searchCoverage = null;
      state.searchError = null;
      state.searchRunning = false;
      state.rawSearchResult = null;
      state.rawSearchRunning = false;
      state.selectedSearchKeys = new Set();
      state.selectedRawSearchKeys = new Set();
      state.lastRawSearchKey = null;
      state.searchSessionRestoredCasePath = null;
      state.lookupEntries = new Map();
      state.live = newLiveBrowseState();
      state.idx = newIndexedBrowseState();
      state.cat = newCategoryCache();
      state.analyzeHistory = { back: [], forward: [], applying: false };
      resetGridView("search");
      resetGridView("rawSearch");
      renderEmptyState();
      renderSearchResults();
      renderRawSearchResults();
    }

    function currentEvidencePath() {
      return currentEvidencePathDetails().value;
    }

    function currentEvidencePathDetails() {
      const result = normalizePathInputDetails($("evidencePath").value);
      $("evidencePath").value = result.value;
      localStorage.setItem("kdft.evidencePath", result.value);
      return result;
    }

    function currentReportPath() {
      const value = normalizePathInput($("reportPath").value);
      $("reportPath").value = value;
      return value;
    }

    function normalizePathInput(value) {
      return normalizePathInputDetails(value).value;
    }

    function normalizePathInputDetails(value) {
      let text = String(value ?? "").trim();
      while (text.length >= 2) {
        const first = text[0];
        const last = text[text.length - 1];
        const quoted = (first === '"' && last === '"')
          || (first === "'" && last === "'")
          || (first === "\u201c" && last === "\u201d")
          || (first === "\u2018" && last === "\u2019");
        if (!quoted) {
          break;
        }
        text = text.slice(1, -1).trim();
      }
      text = stripFileUrlPathPrefix(text);
      const restart = doubledAbsolutePathRestart(text);
      if (restart > 0) {
        return { value: text.slice(restart).trim(), corrected: true };
      }
      return { value: text, corrected: false };
    }

    function stripFileUrlPathPrefix(text) {
      if (!text.toLowerCase().startsWith("file://")) {
        return text;
      }
      let path = text.slice("file://".length).replace(/%20/gi, " ");
      if (/^\/[A-Za-z]:[\\/]/.test(path)) {
        path = path.slice(1);
      }
      return path;
    }

    function doubledAbsolutePathRestart(text) {
      let restart = -1;
      const drivePattern = /[A-Za-z]:[\\/]/g;
      let match = null;
      while ((match = drivePattern.exec(text)) !== null) {
        if (match.index > 0 && !driveMarkerInsideLongPathPrefix(text, match.index)) {
          restart = match.index;
        }
      }
      // Only a repeat of the path's own leading components is a safe doubling
      // signal; "/media/" etc. are legal mid-path names.
      const leading = leadingPosixPrefix(text);
      if (leading) {
        let index = text.indexOf(leading, 1);
        while (index !== -1) {
          restart = Math.max(restart, index);
          index = text.indexOf(leading, index + leading.length);
        }
      }
      restart = Math.max(restart, repeatedLeadingPrefixRestart(text));
      return restart;
    }

    function leadingPosixPrefix(text) {
      if (text.length < 4 || text[0] !== "/" || text[1] === "/") {
        return "";
      }
      const first = text.indexOf("/", 1);
      if (first === -1) {
        return "";
      }
      const second = text.indexOf("/", first + 1);
      if (second === -1 || second === first + 1) {
        return "";
      }
      return text.slice(0, second + 1);
    }

    function driveMarkerInsideLongPathPrefix(text, index) {
      if (index < 4) {
        return false;
      }
      const prefix = text.slice(index - 4, index);
      return prefix === "\\\\?\\" || prefix === "\\\\.\\" || prefix === "//?/" || prefix === "//./";
    }

    function repeatedLeadingPrefixRestart(text) {
      const prefix = leadingDoubleSlashPrefix(text);
      if (!prefix) {
        return -1;
      }
      let restart = -1;
      let index = text.indexOf(prefix, 1);
      while (index !== -1) {
        restart = index;
        index = text.indexOf(prefix, index + prefix.length);
      }
      return restart;
    }

    function leadingDoubleSlashPrefix(text) {
      if (text.length < 4 || !isPathSeparator(text[0]) || text[1] !== text[0]) {
        return "";
      }
      const first = nextPathSeparator(text, 2);
      if (first <= 2 || first + 1 >= text.length) {
        return "";
      }
      const second = nextPathSeparator(text, first + 1);
      if (second > first + 1) {
        return text.slice(0, second);
      }
      return second === -1 ? text : "";
    }

    function nextPathSeparator(text, start) {
      for (let index = start; index < text.length; index += 1) {
        if (isPathSeparator(text[index])) {
          return index;
        }
      }
      return -1;
    }

    function isPathSeparator(ch) {
      return ch === "/" || ch === "\\";
    }

    function pathCorrectionNotice(pathResult) {
      return "Input looked like two concatenated paths; using " + pathResult.value;
    }

    function withPathCorrectionNotice(message, pathResult) {
      return pathResult && pathResult.corrected ? pathCorrectionNotice(pathResult) + ". " + message : message;
    }

    function analysisWindowUrl() {
      const params = new URLSearchParams();
      params.set("mode", "analysis");
      params.set("case_path", currentCasePath());
      const location = currentAnalyzeLocation();
      if (location && location.evidenceId) {
        params.set("evidence_id", String(location.evidenceId));
      }
      if (location && location.selectedPath) {
        params.set("selected_path", location.selectedPath);
      }
      const treeMode = location ? (location.treeMode || "filesystem") : "filesystem";
      params.set("tree_mode", treeMode);
      if (treeMode === "categories") {
        params.set("selected_category", location.selectedCategory || "");
      } else if (treeMode === "live" && location.liveVolume !== undefined && location.liveVolume !== null) {
        params.set("live_volume", String(location.liveVolume));
      }
      const viewerOffset = state.hex && state.hex.data
        ? Number(state.hex.data.offset)
        : Number(state.hex && state.hex.offset);
      const viewerLength = Number(state.hex && state.hex.length);
      if (state.hex && state.hex.live) {
        params.set("viewer_target", "live");
        params.set("evidence_id", String(state.hex.live.evidenceId));
        params.set("viewer_volume", String(state.hex.live.volume));
        params.set("viewer_path", state.hex.live.path || "/");
        params.set("viewer_name", state.hex.live.name || "file");
      } else if (state.hex && state.hex.raw) {
        params.set("viewer_target", "raw");
        params.set("evidence_id", String(state.hex.raw.evidenceId));
        params.set("viewer_name", state.hex.raw.name || "Raw bytes");
        params.set("viewer_logical_path", state.hex.raw.logicalPath || "[raw]");
        params.set("viewer_start_offset", String(Number(state.hex.raw.startOffset) || 0));
        if (state.hex.raw.volume !== undefined && state.hex.raw.volume !== null) {
          params.set("viewer_volume", String(state.hex.raw.volume));
        }
        if (state.hex.raw.sizeBytes !== undefined && state.hex.raw.sizeBytes !== null) {
          params.set("viewer_size", String(state.hex.raw.sizeBytes));
        }
      } else if (state.hex && state.hex.entryId) {
        params.set("viewer_target", "entry");
        params.set("viewer_entry_id", String(state.hex.entryId));
      }
      if (params.has("viewer_target")) {
        params.set("viewer_offset", String(Number.isFinite(viewerOffset) ? Math.max(0, viewerOffset) : 0));
        params.set("viewer_length", String(Number.isFinite(viewerLength) ? Math.max(1, viewerLength) : 512));
        params.set("viewer_mode", $("viewerMode").value || "hex");
        if (Number.isFinite(state.hex.selStart) && Number.isFinite(state.hex.selEnd)) {
          params.set("viewer_selection_start", String(state.hex.selStart));
          params.set("viewer_selection_end", String(state.hex.selEnd));
        }
      }
      return window.location.origin + window.location.pathname + "?" + params.toString();
    }

    function openAnalyzeWindow() {
      window.open(analysisWindowUrl(), "_blank", "noopener");
    }

    async function refresh() {
      const generation = ++state.refreshGeneration;
      const casePath = currentCasePath();
      if (!casePath) {
        setNotice("Case path is empty.", true);
        return false;
      }
      clearLoadedCaseForRefresh(casePath);
      try {
        const nextData = await apiGet("/api/state", { case_path: casePath });
        if (!refreshRequestIsCurrent(casePath, generation)) {
          return false;
        }
        if (state.data) {
          const nextById = new Map(nextData.evidence.map((item) => [Number(item.id), item]));
          state.data.evidence
            .filter((item) => {
              const replacement = nextById.get(Number(item.id));
              return !replacement
                || replacement.source_kind !== item.source_kind
                || replacement.source_path !== item.source_path
                || replacement.attached_at !== item.attached_at;
            })
            .map((item) => Number(item.id))
            .forEach(clearRemovedEvidenceViewState);
          if (evidenceListSignature(state.data) !== evidenceListSignature(nextData)) {
            // An attach/remove changes the context of every mirrored notice.
            // Clear a prior processing result before rendering the new list.
            setNotice("");
          }
        }
        state.data = nextData;
        state.loadedCasePath = casePath;
        renderState();
        await applyPendingAnalysisSelection();
        if (!refreshRequestIsCurrent(casePath, generation)) {
          return false;
        }
        // Once a case is open the sidebar is rarely needed - collapse it for
        // more workspace unless the examiner has expanded it explicitly.
        if (localStorage.getItem("kdft.sidebarCollapsed") !== "0") {
          document.querySelector(".app").classList.add("sidebar-collapsed");
        }
        setNotice("Loaded " + state.data.case.name + ".");
        restoreDeepSearchSession();
        return true;
      } catch (err) {
        if (!refreshRequestIsCurrent(casePath, generation)) {
          return false;
        }
        state.data = null;
        state.loadedCasePath = null;
        renderEmptyState();
        if (!ANALYSIS_MODE) {
          caseOpenSetupView();
        }
        setNotice(err.message, true);
        return false;
      }
    }

    function suggestedNewCasePath() {
      const current = normalizePathInput($("casePath").value || "");
      const separator = current.includes("/") && !current.includes("\\") ? "/" : "\\";
      const folder = current.includes(separator)
        ? current.slice(0, current.lastIndexOf(separator))
        : "ui-output";
      const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
      return folder + separator + "case-" + stamp + ".kdft.sqlite";
    }

    function caseOpenSetupView() {
      if (!$("setupCasePath").value) {
        $("setupCasePath").value = suggestedNewCasePath();
      }
      if (!$("caseOpenPath").value) {
        $("caseOpenPath").value = normalizePathInput($("casePath").value || "");
      }
      switchView("setupView");
    }

    async function createCase() {
      try {
        const target = normalizePathInput($("setupCasePath").value);
        if (!target) {
          setNotice("Enter a case database file path first.", true);
          return;
        }
        const proceedWithStorage = window.confirm(
          "Make sure this case is being created on storage with enough free space.\n\n" +
          "Processing/indexing evidence writes real data into the case database, and large " +
          "images can need a lot of room. Pick a drive with plenty of free space before " +
          "continuing.\n\nContinue creating the case?"
        );
        if (!proceedWithStorage) {
          setNotice("Case creation cancelled.");
          return;
        }
        $("casePath").value = target;
        state.casePath = target;
        localStorage.setItem("kdft.casePath", target);
        clearLoadedCaseForRefresh(target);
        const data = await apiPost("/api/case/create", {
          case_path: target,
          name: $("newCaseName").value,
          examiner: $("newCaseExaminer").value,
          case_number: $("newCaseNumber").value,
          case_type: $("newCaseType").value,
          description: $("newCaseDescription").value
        });
        const loaded = await refresh();
        if (loaded && state.loadedCasePath === target) {
          switchView("evidenceView");
          setNotice("Created case " + data.case_id + ". Now add evidence.");
        }
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function openExistingCase() {
      const target = normalizePathInput($("caseOpenPath").value);
      if (!target) {
        setNotice("Enter the case database path to open.", true);
        return;
      }
      if (state.loadedCasePath && state.loadedCasePath !== target) {
        persistDeepSearchSession();
      }
      $("casePath").value = target;
      state.casePath = target;
      localStorage.setItem("kdft.casePath", target);
      const loaded = await refresh();
      if (loaded && state.loadedCasePath === target) {
        switchView("dashboardView");
      }
    }

    function currentEvidenceType() {
      const active = document.querySelector("#evidenceTypeRow .evidence-type.active");
      return active ? active.dataset.type : "image";
    }

    const EVIDENCE_TYPE_LABELS = {
      image: { label: "Image path", placeholder: "C:\\Evidence\\image.E01", button: "Add Evidence", pick: "file", filter: "image" },
      folder: { label: "Folder path", placeholder: "C:\\Evidence\\source-folder", button: "Add Evidence", pick: "folder", filter: "any" },
      file: { label: "File path", placeholder: "C:\\Evidence\\document.pdf", button: "Add Evidence", pick: "file", filter: "any" },
      browser_history: { label: "History DB file", placeholder: "C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", button: "Import Browser History", pick: "file", filter: "browser_history" }
    };

    function setEvidenceType(type) {
      document.querySelectorAll("#evidenceTypeRow .evidence-type").forEach((button) => {
        button.classList.toggle("active", button.dataset.type === type);
      });
      const spec = EVIDENCE_TYPE_LABELS[type] || EVIDENCE_TYPE_LABELS.image;
      const label = $("evidencePathLabel");
      label.childNodes[0].textContent = spec.label;
      $("evidencePath").placeholder = spec.placeholder;
      $("addEvidence").textContent = spec.button;
      const fsOptions = $("fsOptionsRow");
      const historyOptions = $("historyOptionsRow");
      if (fsOptions) {
        fsOptions.hidden = type === "browser_history";
      }
      if (historyOptions) {
        historyOptions.hidden = type !== "browser_history";
      }
    }

    async function addEvidence() {
      const pathDetails = currentEvidencePathDetails();
      const pathParts = String(pathDetails.value || "evidence").split(/[\\/]/);
      const displayName = pathParts[pathParts.length - 1] || "evidence";
      const type = currentEvidenceType();
      const processNow = type !== "browser_history" && $("readFileSystem").value === "true";
      const progressId = processNow ? newJobProgressId() : null;
      return runAnalyze(displayName, () => addEvidenceInner(type, processNow, progressId), {
        mode: "attach",
        title: "Adding evidence ",
        note: "Discovering split segments and opening the evidence container. If processing was selected, indexing continues in this same protected operation. Please wait and do not open other views or click Add Evidence again.",
        progressId
      });
    }

    async function addEvidenceInner(type, processNow, progressId = null) {
      if (type === "browser_history") {
        await importHistory();
        return;
      }
      const evidencePath = currentEvidencePathDetails();
      try {
        if (evidencePath.corrected) {
          setNotice(pathCorrectionNotice(evidencePath) + ".");
        }
        const data = await apiPost("/api/evidence/add", {
          case_path: currentCasePath(),
          path: evidencePath.value,
          kind: type,
          read_file_system: processNow,
          notes: $("evidenceNotes").value
        });
        setNotice("");
        if (data.detected) {
          await refresh();
          const importedEvidence = state.data && state.data.evidence.find((item) => item.id === data.evidence_id);
          if (!importedEvidence) {
            setNotice("");
            return;
          }
          selectEvidenceSource(data.evidence_id, data.visits_indexed > 0 ? "/Browser Activities/Visits" : "/Browser Activities");
          const detectedFamily = String(data.detected).split("_")[0];
          const familyLabel = detectedFamily === "firefox" ? "Firefox" : (detectedFamily === "safari" ? "Safari" : "Chromium");
          setNotice(withPathCorrectionNotice(
            "Detected " + familyLabel + " history database - parsed " + Number(data.entries_indexed || 0).toLocaleString()
              + " records (" + Number(data.visits_indexed || 0).toLocaleString() + " visits).",
            evidencePath
          ));
          return;
        }
        if (!processNow) {
          await refresh();
          if (!state.data || !state.data.evidence.some((item) => item.id === data.evidence_id)) {
            setNotice("");
            return;
          }
          selectEvidenceSource(data.evidence_id, "/");
          setNotice(withPathCorrectionNotice("Attached evidence " + data.evidence_id + ".", evidencePath));
          return;
        }
        try {
          const processed = await apiPost("/api/evidence/process", {
            case_path: currentCasePath(),
            evidence_id: data.evidence_id,
            max_entries: currentProcessMaxEntries(),
            progress_id: progressId,
            ...processingOptionsPayload(true)
          });
          if (state.analyzing) {
            state.analyzing.telemetry = processed.progress || state.analyzing.telemetry;
            state.analyzing.telemetryReceivedAt = Date.now();
            renderAnalyzingOverlay();
          }
          const message = processingCompletionNotice(
            processed,
            "Evidence " + data.evidence_id + " attached and processed"
          );
          invalidateIndexedBrowseCache(data.evidence_id);
          await refresh();
          if (!state.data || !state.data.evidence.some((item) => item.id === data.evidence_id)) {
            setNotice("");
            return;
          }
          invalidateIndexedBrowseCache(data.evidence_id);
          selectEvidenceSource(data.evidence_id, preferredAnalysisPath(data.evidence_id), "filesystem");
          setNotice(withPathCorrectionNotice(message, evidencePath));
        } catch (processErr) {
          invalidateIndexedBrowseCache(data.evidence_id);
          await refresh();
          if (!state.data || !state.data.evidence.some((item) => item.id === data.evidence_id)) {
            setNotice("");
            return;
          }
          selectEvidenceSource(data.evidence_id, "/");
          setNotice(withPathCorrectionNotice("Attached evidence " + data.evidence_id + ", but processing failed: " + processErr.message, evidencePath), true);
        }
      } catch (err) {
        setNotice(withPathCorrectionNotice(err.message, evidencePath), true);
      }
    }

    async function pickEvidencePath() {
      const type = currentEvidenceType();
      const spec = EVIDENCE_TYPE_LABELS[type] || EVIDENCE_TYPE_LABELS.image;
      const browseButton = $("browseEvidence");
      browseButton.disabled = true;
      setNotice(spec.pick === "folder"
        ? "Choose the folder in the system dialog, then press Open."
        : "Choose the file in the system dialog.");
      try {
        const data = await apiGet("/api/pick", {
          mode: spec.pick,
          filter: spec.filter,
          start: currentEvidencePath()
        });
        if (data.path) {
          $("evidencePath").value = data.path;
          localStorage.setItem("kdft.evidencePath", data.path);
          setNotice("Selected " + data.path + ".");
        } else {
          setNotice("Browse cancelled.");
        }
      } catch (err) {
        setNotice(err.message, true);
      } finally {
        browseButton.disabled = false;
      }
    }

    // Blocking progress overlay for a long analyze. Analyzing indexes the whole
    // disk inside one DB write transaction, so while it runs the examiner must
    // NOT start a second analyze or open other views (those writes collide with
    // the lock and surface as "database is locked"). This overlay both shows the
    // tool is working and physically blocks interaction until it finishes, so a
    // single uninterrupted analyze runs to completion - no batching, no caps.
    function formatJobDuration(milliseconds) {
      const totalSeconds = Math.max(0, Math.floor(Number(milliseconds || 0) / 1000));
      const hours = Math.floor(totalSeconds / 3600);
      const minutes = Math.floor((totalSeconds % 3600) / 60);
      const seconds = totalSeconds % 60;
      if (hours > 0) return hours + "h " + minutes + "m " + seconds + "s";
      if (minutes > 0) return minutes + "m " + seconds + "s";
      return seconds + "s";
    }

    function newJobProgressId() {
      const suffix = window.crypto && typeof window.crypto.randomUUID === "function"
        ? window.crypto.randomUUID()
        : Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
      return "ui-" + suffix;
    }

    function progressStateLabel(value) {
      return ({ active: "Active", complete: "Complete", truncated: "Truncated", cancelled: "Cancelled", failed: "Failed" })[value] || "Unknown";
    }

    function progressStateClass(value) {
      return ["active", "complete", "truncated", "cancelled", "failed"].includes(value)
        ? value
        : "unknown";
    }

    function progressTelemetryHtml(progress, receivedAt) {
      const activeAge = progress.state === "active" ? Math.max(0, Date.now() - Number(receivedAt || Date.now())) : 0;
      const elapsedMs = Number(progress.elapsed_ms || 0) + activeAge;
      const stageElapsedMs = Number(progress.stage_elapsed_ms || 0) + activeAge;
      const stagePosition = progress.stage_index
        ? "Stage " + Number(progress.stage_index).toLocaleString()
          + (progress.stage_count ? " of " + Number(progress.stage_count).toLocaleString() : "")
        : "Current stage";
      const knownTotal = progress.total_items !== null && progress.total_items !== undefined;
      const percentageKnown = progress.percentage !== null && progress.percentage !== undefined && Number.isFinite(Number(progress.percentage));
      const percentage = percentageKnown ? Math.max(0, Math.min(100, Number(progress.percentage))) : null;
      const processedText = Number(progress.processed_items || 0).toLocaleString()
        + (knownTotal ? " / " + Number(progress.total_items).toLocaleString() : "")
        + " " + escapeHtml(progress.item_unit || "items");
      const rateText = progress.rate_per_second !== null && progress.rate_per_second !== undefined
        ? Number(progress.rate_per_second).toLocaleString(undefined, { maximumFractionDigits: 1 }) + " " + escapeHtml(progress.item_unit || "items") + "/s"
        : (progress.rate_status === "unknown" ? "Unknown" : (progress.state === "active" ? "Calculating" : "Not available"));
      let etaMetric = "";
      if (progress.eta_status === "calculating") {
        etaMetric = '<div class="progress-metric"><span class="progress-metric-label">Estimated remaining</span><span class="progress-metric-value">Calculating</span></div>';
      } else if (progress.eta_status === "unknown") {
        etaMetric = '<div class="progress-metric"><span class="progress-metric-label">Estimated remaining</span><span class="progress-metric-value">Unknown</span></div>';
      } else if (progress.eta_status === "estimated") {
        etaMetric = '<div class="progress-metric"><span class="progress-metric-label">Estimated remaining</span><span class="progress-metric-value">' + escapeHtml(formatJobDuration(Number(progress.eta_seconds || 0) * 1000)) + '</span></div>';
      }
      const barStyle = percentageKnown ? ' style="width:' + percentage.toFixed(2) + '%;margin-left:0"' : "";
      const barClass = percentageKnown ? "analyzing-bar-fill known" : "analyzing-bar-fill";
      const current = progress.current_object
        ? '<div class="progress-context-row"><span class="progress-context-label">Current:</span> ' + escapeHtml(progress.current_object) + '</div>'
        : "";
      const volume = progress.current_volume
        ? '<div class="progress-context-row"><span class="progress-context-label">Volume / partition:</span> ' + escapeHtml(progress.current_volume) + '</div>'
        : "";
      const recent = (progress.recently_processed || []).length
        ? '<div class="progress-context-row"><span class="progress-context-label">Recently processed:</span><ul class="progress-recent">'
          + progress.recently_processed.map((item) => '<li>' + escapeHtml(item) + '</li>').join("") + '</ul></div>'
        : "";
      const reasonTexts = progress.truncation_reasons || [];
      const reasonReports = Number(progress.truncation_reason_count || reasonTexts.length);
      const reasonsOmitted = Number(progress.truncation_reasons_omitted || 0);
      const truncationDetails = reasonTexts.length || reasonsOmitted
        ? '<div class="progress-context-row"><span class="progress-context-label">Warnings / partial coverage (' + reasonReports.toLocaleString() + ' report' + (reasonReports === 1 ? '' : 's') + '):</span> '
          + escapeHtml(reasonTexts.join("; "))
          + (reasonsOmitted ? ' <span class="muted">(' + reasonsOmitted.toLocaleString() + ' additional report' + (reasonsOmitted === 1 ? '' : 's') + ' hidden from this bounded dialog; the diagnostic log remains complete)</span>' : '')
          + '</div>'
        : "";
      const diagnosticPath = progress.diagnostic_log_path
        ? '<div class="progress-context-row"><span class="progress-context-label">Complete diagnostic log:</span> <span class="mono">' + escapeHtml(progress.diagnostic_log_path) + '</span></div>'
        : "";
      const stageTimes = (progress.completed_stages || []).length
        ? '<div class="progress-stage-times">Completed stages: '
          + progress.completed_stages.map((stage) => escapeHtml(stage.name) + " " + escapeHtml(formatJobDuration(stage.elapsed_ms))).join(" · ")
          + '</div>'
        : "";
      return '<div class="analyzing-card telemetry" role="alertdialog" aria-busy="' + (progress.state === "active" ? "true" : "false") + '">' +
        '<div class="analyzing-heading-row"><div class="analyzing-title">' + escapeHtml(progress.stage_name || "Processing") +
          '<div class="analyzing-note">' + escapeHtml(stagePosition) + ' · stage elapsed ' + escapeHtml(formatJobDuration(stageElapsedMs)) + '</div></div>' +
          '<span class="progress-state ' + progressStateClass(progress.state) + '">' + escapeHtml(progressStateLabel(progress.state)) + '</span></div>' +
        '<div class="analyzing-bar"><div class="' + barClass + '"' + barStyle + '></div></div>' +
        '<div class="progress-grid">' +
          '<div class="progress-metric"><span class="progress-metric-label">Elapsed</span><span class="progress-metric-value">' + escapeHtml(formatJobDuration(elapsedMs)) + '</span></div>' +
          '<div class="progress-metric"><span class="progress-metric-label">Processed</span><span class="progress-metric-value">' + processedText + (percentageKnown ? " · " + percentage.toFixed(1) + "%" : "") + '</span></div>' +
          '<div class="progress-metric"><span class="progress-metric-label">Recent rate</span><span class="progress-metric-value">' + rateText + '</span></div>' +
          etaMetric +
          '<div class="progress-metric"><span class="progress-metric-label">Skipped / errors</span><span class="progress-metric-value">' + Number(progress.skipped_count || 0).toLocaleString() + ' / ' + Number(progress.error_count || 0).toLocaleString() + '</span></div>' +
        '</div><div class="progress-context">' + volume + current + recent + truncationDetails + diagnosticPath + '</div>' + stageTimes + '</div>';
    }

    function renderAnalyzingOverlay() {
      let el = document.getElementById("analyzingOverlay");
      if (!state.analyzing) {
        if (el) { el.remove(); }
        return;
      }
      if (!el) {
        el = document.createElement("div");
        el.id = "analyzingOverlay";
        el.className = "analyzing-overlay";
        document.body.appendChild(el);
      }
      const secs = Math.max(0, Math.floor((Date.now() - state.analyzing.startedAt) / 1000));
      const mins = Math.floor(secs / 60);
      const elapsed = mins > 0 ? mins + "m " + (secs % 60) + "s" : secs + "s";
      if (state.analyzing.telemetry) {
        el.innerHTML = progressTelemetryHtml(state.analyzing.telemetry, state.analyzing.telemetryReceivedAt);
        return;
      }
      const asciiFrames = [
        "  /\\_/\\   🔎\\n ( o.o )  [·  ]\\n  > ^ <   indexing",
        "  /\\_/\\    🔎\\n ( o.o )  [·· ]\\n  > ^ <   indexing",
        "  /\\_/\\     🔎\\n ( -.- )  [···]\\n  > ^ <   indexing",
        "  /\\_/\\    🔎\\n ( o.o )  [ ··]\\n  > ^ <   indexing"
      ];
      const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      const asciiFrame = asciiFrames[reducedMotion ? 0 : (secs % asciiFrames.length)];
      el.innerHTML =
        '<div class="analyzing-card" role="alertdialog" aria-busy="true">' +
          '<div class="analyzing-title">Analyzing ' + escapeHtml(state.analyzing.name) + '…</div>' +
          '<pre class="analyzing-ascii" aria-hidden="true">' + escapeHtml(asciiFrame) + '</pre>' +
          '<div class="analyzing-bar"><div class="analyzing-bar-fill"></div></div>' +
          '<div class="analyzing-note">Reading and indexing the whole disk. This can take a while on a large image - ' +
          'please wait and do not click Analyze again or open other views until it finishes. Elapsed: ' + escapeHtml(elapsed) + '</div>' +
        '</div>';
      if (state.analyzing.mode === "attach") {
        const attachingFrames = [
          "  /\\_/\\    .--.\n ( o.o )  [E01]--\n  > ^ <   gathering",
          "  /\\_/\\      .--.\n ( o.o )  [E01][E02]--\n  > ^ <   gathering",
          "  /\\_/\\        .--.\n ( -.- )  [E01][E02][...]\n  > ^ <   gathering",
          "  /\\_/\\      .--.\n ( o.o )  [E01][E02]--\n  > ^ <   gathering"
        ];
        const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        el.querySelector(".analyzing-title").textContent = state.analyzing.title + state.analyzing.name + "…";
        el.querySelector(".analyzing-ascii").textContent = attachingFrames[reducedMotion ? 0 : (secs % attachingFrames.length)];
        el.querySelector(".analyzing-note").textContent = state.analyzing.note + " Elapsed: " + elapsed;
      }
    }

    async function pollAnalyzingProgress(operationId) {
      const analyzing = state.analyzing;
      if (!analyzing || analyzing.progressId !== operationId || analyzing.pollPending) return;
      analyzing.pollPending = true;
      try {
        const progress = await apiGet("/api/jobs/progress", { progress_id: operationId });
        if (state.analyzing && state.analyzing.progressId === operationId) {
          state.analyzing.telemetry = progress;
          state.analyzing.telemetryReceivedAt = Date.now();
          renderAnalyzingOverlay();
        }
      } catch (_) {
        // The POST may not have registered its tracker yet. The next bounded
        // poll will retry; processing errors still surface through the POST.
      } finally {
        if (state.analyzing && state.analyzing.progressId === operationId) {
          state.analyzing.pollPending = false;
        }
      }
    }

    async function runAnalyze(name, worker, options = {}) {
      if (state.analyzing) {
        setNotice("A protected evidence operation is already running - wait for it to finish before starting another.", true);
        return undefined;
      }
      state.analyzing = {
        name: name || "evidence",
        mode: options.mode || "analyze",
        title: options.title || "Analyzing ",
        note: options.note || "Reading and indexing the whole disk. This can take a while on a large image - please wait and do not click Analyze again or open other views until it finishes.",
        startedAt: Date.now(),
        timer: null,
        progressTimer: null,
        progressId: options.progressId || null,
        pollPending: false,
        telemetry: null,
        telemetryReceivedAt: null
      };
      renderAnalyzingOverlay();
      state.analyzing.timer = window.setInterval(renderAnalyzingOverlay, 1000);
      if (state.analyzing.progressId) {
        const operationId = state.analyzing.progressId;
        pollAnalyzingProgress(operationId);
        state.analyzing.progressTimer = window.setInterval(() => pollAnalyzingProgress(operationId), 250);
      }
      try {
        return await worker();
      } finally {
        if (state.analyzing && state.analyzing.timer) { window.clearInterval(state.analyzing.timer); }
        if (state.analyzing && state.analyzing.progressTimer) { window.clearInterval(state.analyzing.progressTimer); }
        if (state.analyzing && state.analyzing.telemetry) { state.lastJobProgress = state.analyzing.telemetry; }
        state.analyzing = null;
        renderAnalyzingOverlay();
      }
    }

    // Examiner-selected processing options (professional-suite style), sent
    // with every Process / Analyze run. Checkbox state persists in
    // localStorage so a chosen profile sticks across sessions.
    const PROCESSING_OPTION_CHECKBOXES = ["optReindexFilesystem", "optCaptureContent", "optParseEmails", "optRunHash", "optRunFileHash", "optRunSignatures", "optRunCarve", "optRunBrowserParse", "optParseIdentities", "optParseArchives", "optParseDocuments", "optParseWindowsArtifacts"];

    function processingOptionsPayload(forceReindex = false) {
      return {
        reindex_filesystem: forceReindex || $("optReindexFilesystem").checked,
        capture_content: $("optCaptureContent").checked,
        parse_emails: $("optParseEmails").checked,
        parse_browsers: $("optRunBrowserParse").checked,
        parse_identities: $("optParseIdentities").checked,
        parse_archives: $("optParseArchives").checked,
        parse_documents: $("optParseDocuments").checked,
        parse_windows_artifacts: $("optParseWindowsArtifacts").checked,
        run_hash: $("optRunHash").checked,
        run_file_hash: $("optRunFileHash").checked,
        run_signature_analysis: $("optRunSignatures").checked,
        run_carve: $("optRunCarve").checked,
        // A zero byte limit requests the complete decoded-media scan.
        carve_max_scan_bytes: 0,
        carve_max_files: 0
      };
    }

    // One-line outcome of the optional passes for the completion notice. The
    // base index remains available after a pass failure, while overall status
    // still reports failed/truncated coverage honestly.
    function processingExtrasSummary(data) {
      const parts = [];
      if (!$("optCaptureContent").checked) {
        parts.push("metadata-only index - content search stays unavailable for this evidence until re-processed with content on");
      }
      if (data.hash) {
        parts.push(data.hash.error ? "hash FAILED: " + data.hash.error : "hash " + String(data.hash.sha256_hex || "").slice(0, 16) + "…");
      }
      if (data.signature_analysis) {
        const sig = data.signature_analysis;
        parts.push(sig.error ? "signatures FAILED: " + sig.error : "signatures: " + sig.matches + " match / " + sig.mismatches + " mismatch / " + sig.unknown + " unknown"
          + (Number(sig.up_to_date_files_skipped || 0) ? " / " + Number(sig.up_to_date_files_skipped).toLocaleString() + " completed checkpoint(s) reused" : ""));
      }
      if (data.carve) {
        parts.push(data.carve.error
          ? "carve FAILED: " + data.carve.error
          : "carved " + Number(data.carve.carved_files || 0).toLocaleString() + " file(s)"
            + (data.carve.truncated
              ? " (truncated: " + ((data.carve.truncation_reasons || []).join("; ") || "see job record") + ")"
              : ""));
      }
      if (data.file_hash) {
        parts.push(data.file_hash.error
          ? "file hashing FAILED: " + data.file_hash.error
          : "hashed " + Number(data.file_hash.files_hashed || 0).toLocaleString() + " file(s)"
            + " using " + Number(data.file_hash.worker_threads || 1).toLocaleString() + " CPU worker(s)"
            + (data.file_hash.up_to_date_files_skipped
              ? " / " + Number(data.file_hash.up_to_date_files_skipped).toLocaleString() + " completed checkpoint(s) reused"
              : "")
            + (data.file_hash.files_skipped ? " (" + data.file_hash.files_skipped + " skipped, reasons stamped per entry)" : ""));
      }
      if (data.archive_parsing) {
        const ap = data.archive_parsing;
        parts.push(ap.error
          ? "archive parsing FAILED: " + ap.error
          : "archives: " + Number(ap.archives_parsed || 0).toLocaleString() + " / "
            + Number(ap.archives_found || 0).toLocaleString() + " parsed, "
            + Number(ap.members_indexed || 0).toLocaleString() + " member(s) indexed"
            + (Number(ap.up_to_date_archives_skipped || 0) ? ", " + Number(ap.up_to_date_archives_skipped).toLocaleString() + " committed checkpoint(s) reused" : "")
            + (Number(ap.signature_mismatch_count || 0) ? ", " + Number(ap.signature_mismatch_count).toLocaleString() + " extension/signature mismatch(es) skipped" : "")
            + (Number(ap.parse_error_count || 0) ? ", " + Number(ap.parse_error_count).toLocaleString() + " parser error(s)" : ""));
      }
      if (data.document_parsing) {
        const dp = data.document_parsing;
        parts.push(dp.error
          ? "document parsing FAILED: " + dp.error
          : "documents: " + Number(dp.documents_parsed || 0).toLocaleString() + " / "
            + Number(dp.documents_found || 0).toLocaleString() + " parsed, "
            + Number(dp.segments_indexed || 0).toLocaleString() + " text segment(s)"
            + (Number(dp.up_to_date_documents_skipped || 0) ? ", " + Number(dp.up_to_date_documents_skipped).toLocaleString() + " committed checkpoint(s) reused" : "")
            + (Number(dp.reused_partial_documents || 0) ? " (including " + Number(dp.reused_partial_documents).toLocaleString() + " previously disclosed partial)" : "")
            + (Number(dp.partial_documents || 0) ? ", " + Number(dp.partial_documents).toLocaleString() + " partial" : "")
            + (Number(dp.parse_error_count || 0) ? ", " + Number(dp.parse_error_count).toLocaleString() + " failed" : ""));
      }
      if (data.windows_artifact_parsing) {
        const wp = data.windows_artifact_parsing;
        parts.push(wp.error
          ? "Windows artifact parsing FAILED: " + wp.error
          : "Windows artifacts (" + String(wp.status || "unknown") + "): "
            + Number(wp.parsed_sources || 0).toLocaleString() + " / "
            + Number(wp.snapshot_candidate_count || 0).toLocaleString() + " source(s) parsed, "
            + Number(wp.derived_entries || 0).toLocaleString() + " derived entries, "
            + Number(wp.text_segments || 0).toLocaleString() + " text segment(s)"
            + (Number(wp.up_to_date_sources_skipped || 0) ? ", " + Number(wp.up_to_date_sources_skipped).toLocaleString() + " committed source checkpoint(s) reused" : "")
            + (Number(wp.reused_partial_sources || 0) ? " (including " + Number(wp.reused_partial_sources).toLocaleString() + " previously disclosed partial)" : "")
            + (Number(wp.partial_sources || 0) ? ", " + Number(wp.partial_sources).toLocaleString() + " partial" : "")
            + (Number(wp.failed_sources || 0) ? ", " + Number(wp.failed_sources).toLocaleString() + " failed" : "")
            + (Number(wp.diagnostic_count || 0) ? ", " + Number(wp.diagnostic_count).toLocaleString() + " diagnostic(s) disclosed in the job record" : ""));
      }
      if (data.windows_registry_artifact_parsing) {
        const wr = data.windows_registry_artifact_parsing;
        parts.push(wr.error
          ? "Windows Registry artifact parsing FAILED: " + wr.error
          : "Windows Registry artifacts (" + String(wr.status || "unknown") + "): "
            + Number(wr.amcache_records_indexed || 0).toLocaleString() + " Amcache, "
            + Number(wr.userassist_records_indexed || 0).toLocaleString() + " UserAssist, "
            + Number(wr.shellbag_records_indexed || 0).toLocaleString() + " ShellBag, "
            + Number(wr.startup_records_indexed || 0).toLocaleString() + " startup record(s)"
            + (Number(wr.shimcache_sources_seen || 0) ? "; Shimcache source retained (decoder limitation disclosed)" : "")
            + (Number(wr.srum_sources_seen || 0) ? "; SRUM source retained (ESE decoder limitation disclosed)" : "")
            + (Number(wr.parse_error_count || 0) ? ", " + Number(wr.parse_error_count).toLocaleString() + " hive error(s)" : ""));
      }
      if (data.email_parsing) {
        const ep = data.email_parsing;
        parts.push(ep.error
          ? "mailbox parsing FAILED: " + ep.error
          : "mailboxes: " + Number(ep.mailboxes_parsed || 0).toLocaleString() + " / "
            + Number(ep.mailboxes_found || 0).toLocaleString() + " parsed, "
            + Number(ep.messages_indexed || 0).toLocaleString() + " message(s)"
            + (Number(ep.parse_error_count || 0) ? ", " + Number(ep.parse_error_count).toLocaleString() + " failed" : ""));
      }
      if (data.browser_parsing) {
        const bp = data.browser_parsing;
        if (bp.error) {
          parts.push("browser parsing FAILED: " + bp.error);
        } else if (Number(bp.profiles_found || 0) > 0 || (bp.ext_imports || []).length > 0) {
          const extImports = bp.ext_imports || [];
          const profilesObserved = Number(
            bp.profiles_observed ?? Math.max(Number(bp.profiles_found || 0), extImports.length)
          );
          const visits = (bp.imported || []).concat(extImports).reduce((sum, item) => sum + Number(item.visits_indexed || 0), 0);
          const parseErrors = Number(bp.parse_error_count || 0);
          const importedProfiles = (bp.imported || []).length + extImports.filter((item) => item.status !== "failed").length;
          parts.push("browser profiles: " + profilesObserved + " found/disclosed, " + importedProfiles + " imported (" + visits.toLocaleString() + " visits)"
            + (Number(bp.profiles_handled_during_walk || 0) ? ", " + Number(bp.profiles_handled_during_walk).toLocaleString() + " handled during EXT indexing" : "")
            + ((bp.errors || []).length || Number(bp.ext_failures || 0) ? ", " + ((bp.errors || []).length + Number(bp.ext_failures || 0)) + " failed" : "")
            + (parseErrors ? ", " + parseErrors + " parser error" + (parseErrors === 1 ? "" : "s") + " disclosed in the job record" : ""));
        }
      }
      if (data.identity_parsing) {
        const ip = data.identity_parsing;
        parts.push(ip.error
          ? "identity parsing FAILED: " + ip.error
          : "identities: " + Number(ip.local_accounts_indexed || 0).toLocaleString() + " local account(s), "
            + Number(ip.domain_accounts_indexed || 0).toLocaleString() + " configured domain account(s), "
            + Number(ip.user_profiles_indexed || 0).toLocaleString() + " user profile(s), "
            + Number(ip.browser_accounts_indexed || 0).toLocaleString() + " browser account(s), "
            + Number(ip.host_identities_indexed || 0).toLocaleString() + " host identity finding(s), "
            + Number(ip.network_artifacts_indexed || 0).toLocaleString() + " IP/network finding(s), "
            + Number(ip.wifi_profiles_indexed || 0).toLocaleString() + " Wi-Fi profile(s), "
            + Number(ip.credential_stores_indexed || 0).toLocaleString() + " credential/secret store(s), "
            + Number(ip.plaintext_secrets_indexed || 0).toLocaleString() + " structured plaintext secret(s)"
            + ((ip.parse_errors || []).length ? ", " + ip.parse_errors.length + " hive error(s) disclosed" : ""));
      }
      return parts.length ? " " + parts.join("; ") + "." : "";
    }

    function processingProgressSummary(progress) {
      if (!progress) return "";
      const stages = (progress.completed_stages || [])
        .map((stage) => stage.name + " " + formatJobDuration(stage.elapsed_ms))
        .join(", ");
      return " Final state: " + progressStateLabel(progress.state)
        + ". Total elapsed: " + formatJobDuration(progress.elapsed_ms)
        + (stages ? ". Stage times: " + stages : "")
        + ". Skipped / errors: " + Number(progress.skipped_count || 0).toLocaleString()
        + " / " + Number(progress.error_count || 0).toLocaleString()
        + (Number(progress.truncation_reasons_omitted || 0)
          ? ". Additional warning reports hidden from the bounded dialog (all are retained in the diagnostic log): "
            + Number(progress.truncation_reasons_omitted).toLocaleString()
          : "") + ".";
    }

    function processingCompletionNotice(data, subject) {
      const status = String(data && data.status || "unknown");
      const stateText = status === "completed"
        ? "completed"
        : (status === "truncated" ? "completed with partial coverage" : status);
      const progress = data && data.progress ? data.progress : {};
      const warningCount = Number(progress.truncation_reason_count
        ?? (data && data.truncation_reason_count)
        ?? ((data && data.truncation_reasons) || []).length
        ?? 0);
      let message = subject + " — " + stateText + ".";
      if (warningCount > 0) {
        message += " " + warningCount.toLocaleString() + " warning/partial-coverage report"
          + (warningCount === 1 ? "" : "s") + ".";
      }
      if (data && data.diagnostic_log_path) {
        message += " Diagnostic log: " + data.diagnostic_log_path + ".";
      } else if (data && data.diagnostic_log_error) {
        message += " Diagnostic log could not be saved: " + data.diagnostic_log_error + ".";
      }
      return message;
    }

    async function processEvidence(id) {
      const evidence = state.data && state.data.evidence.find((item) => item.id === id);
      const label = evidence ? evidence.display_name : "evidence #" + id;
      const evidenceSignatureBefore = evidenceListSignature();
      const progressId = newJobProgressId();
      const options = processingOptionsPayload();
      const hasExistingIndex = evidenceIndexedEntryCount(id) > 0;
      const additive = hasExistingIndex && !options.reindex_filesystem;
      await runAnalyze(label, async () => {
        try {
          const data = await apiPost(additive ? "/api/evidence/run-processors" : "/api/evidence/process", {
            case_path: currentCasePath(),
            evidence_id: id,
            max_entries: currentProcessMaxEntries(),
            progress_id: progressId,
            ...options
          });
          if (state.analyzing) {
            state.analyzing.telemetry = data.progress || state.analyzing.telemetry;
            state.analyzing.telemetryReceivedAt = Date.now();
            renderAnalyzingOverlay();
          }
          let subject = additive
            ? "Selected processors finished; the existing filesystem snapshot was preserved"
            : "Evidence " + label + " processed";
          if (!additive && data.bookmark_items_relinked > 0) {
            subject += "; re-linked " + data.bookmark_items_relinked + " bookmark item(s)";
          }
          const message = processingCompletionNotice(data, subject);
          invalidateIndexedBrowseCache(id);
          await refresh();
          if (evidenceListSignature() !== evidenceSignatureBefore
            || !state.data
            || !state.data.evidence.some((item) => item.id === id)) {
            // A late process callback must not restore a sticky message (or
            // selection) after attach/remove changed the evidence context.
            setNotice("");
            return;
          }
          if (state.live.evidenceId === id) {
            state.live = newLiveBrowseState();
          }
          invalidateIndexedBrowseCache(id);
          selectEvidenceSource(id, preferredAnalysisPath(id), "filesystem");
          setNotice(message);
        } catch (err) {
          invalidateIndexedBrowseCache(id);
          await refresh();
          if (evidenceListSignature() !== evidenceSignatureBefore
            || !state.data
            || !state.data.evidence.some((item) => item.id === id)) {
            setNotice("");
          } else {
            setNotice(err.message, true);
          }
        }
      }, { progressId });
    }

    async function removeEvidence(id) {
      const evidence = state.data && state.data.evidence.find((item) => item.id === id);
      const name = evidence ? evidence.display_name : "evidence #" + id;
      if (!window.confirm("Remove " + name + " from this case? Indexed entries for this source will be removed.")) {
        return;
      }
      try {
        const data = await apiPost("/api/evidence/remove", {
          case_path: currentCasePath(),
          evidence_id: id
        });
        setNotice("");
        clearRemovedEvidenceViewState(id);
        const message = "Removed evidence " + data.evidence_id + " and " + data.removed_entries + " indexed entries.";
        await refresh();
        setNotice(message);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function recoverEntry(entryId) {
      const entry = findLoadedEntry(entryId);
      if (!entry) {
        setNotice("Entry is not loaded.", true);
        return;
      }
      const labels = recoveryActionText(entry);
      const defaultPath = defaultRecoveryPath(entry);
      const outputPath = window.prompt(labels.prompt + " to:", defaultPath);
      if (!outputPath) {
        return;
      }
      try {
        setNotice(labels.button + " in progress...");
        const data = await apiPost("/api/entry/recover", {
          case_path: currentCasePath(),
          entry_id: entryId,
          output_path: normalizePathInput(outputPath)
        });
        setNotice(labels.past + " " + data.bytes_written + " bytes to " + data.output_path + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function showEntryDetails() {
      if (!currentHexEntry()) {
        setNotice("Select an item before opening details.", true);
        return;
      }
      $("viewerMode").value = "metadata";
      renderHexViewer();
    }

    function bindInspectorResize() {
      const handle = $("viewerResizer");
      const workspace = document.querySelector(".browser-workspace");
      if (!handle || !workspace) {
        return;
      }
      const applyWidth = (rawWidth) => {
        const rect = workspace.getBoundingClientRect();
        const minWidth = 320;
        const maxWidth = Math.min(900, Math.max(minWidth, rect.width - 620));
        const width = Math.max(minWidth, Math.min(maxWidth, rawWidth));
        workspace.style.setProperty("--inspector-width", width + "px");
        return width;
      };
      const storedWidth = Number(localStorage.getItem("kdft.inspectorWidth"));
      if (Number.isFinite(storedWidth) && storedWidth > 0) {
        requestAnimationFrame(() => applyWidth(storedWidth));
      }
      handle.addEventListener("pointerdown", (event) => {
        if (window.matchMedia("(max-width: 980px)").matches) {
          return;
        }
        event.preventDefault();
        try {
          handle.setPointerCapture(event.pointerId);
        } catch (_) {}
        setInspectorCollapsed(false);
        handle.classList.add("dragging");
        document.body.classList.add("resizing-inspector");
        const onMove = (moveEvent) => {
          const rect = workspace.getBoundingClientRect();
          applyWidth(rect.right - moveEvent.clientX);
        };
        const onUp = () => {
          handle.classList.remove("dragging");
          document.body.classList.remove("resizing-inspector");
          const width = parseFloat(getComputedStyle(workspace).getPropertyValue("--inspector-width"));
          if (Number.isFinite(width)) {
            localStorage.setItem("kdft.inspectorWidth", String(Math.round(width)));
          }
          document.removeEventListener("pointermove", onMove);
          document.removeEventListener("pointerup", onUp);
          document.removeEventListener("pointercancel", onUp);
        };
        document.addEventListener("pointermove", onMove);
        document.addEventListener("pointerup", onUp);
        document.addEventListener("pointercancel", onUp);
      });
    }

    function setInspectorCollapsed(collapsed) {
      state.inspectorCollapsed = Boolean(collapsed);
      const workspace = document.querySelector(".browser-workspace");
      if (workspace) {
        workspace.classList.toggle("inspector-collapsed", state.inspectorCollapsed);
      }
      const button = $("toggleInspector");
      if (button) {
        button.textContent = state.inspectorCollapsed ? "Show inspector" : "Hide inspector";
      }
    }

    function toggleInspectorPane() {
      setInspectorCollapsed(!state.inspectorCollapsed);
    }

    function currentAnalyzeLocation() {
      // Live Browse keeps its own state namespace (state.live.*) separate from the indexed/
      // category browser (state.browserState) - fold it into the same location shape so a single
      // Back/Forward history covers folder-by-folder live browsing as well as
      // indexed tabs and categories.
      if (state.live.active && state.live.evidenceId && state.live.selKey) {
        const separator = state.live.selKey.indexOf("|");
        const volume = separator === -1 ? state.live.selKey : state.live.selKey.slice(0, separator);
        const path = separator === -1 ? "/" : state.live.selKey.slice(separator + 1);
        return {
          evidenceId: state.live.evidenceId,
          treeMode: "live",
          selectedPath: normalizeLogicalPath(path || "/"),
          selectedCategory: "",
          liveVolume: volume
        };
      }
      const browserState = state.browserState || {};
      if (!browserState.evidenceId) {
        return null;
      }
      const treeMode = browserState.treeMode === "categories" ? "categories" : "filesystem";
      return {
        evidenceId: browserState.evidenceId,
        treeMode,
        selectedPath: normalizeLogicalPath(browserState.selectedPath || "/"),
        selectedCategory: treeMode === "categories" ? (browserState.selectedCategory || "") : ""
      };
    }

    function analyzeLocationKey(location) {
      if (!location) {
        return "";
      }
      return [
        location.evidenceId || "",
        location.treeMode || "filesystem",
        normalizeLogicalPath(location.selectedPath || "/"),
        location.selectedCategory || "",
        location.treeMode === "live" ? (location.liveVolume || "") : ""
      ].join("|");
    }

    function sameAnalyzeLocation(left, right) {
      return analyzeLocationKey(left) === analyzeLocationKey(right);
    }

    function commitAnalyzeNavigation(previous) {
      if (state.analyzeHistory.applying) {
        updateAnalyzeNavButtons();
        return;
      }
      const current = currentAnalyzeLocation();
      if (previous && current && !sameAnalyzeLocation(previous, current)) {
        state.analyzeHistory.back.push(previous);
        if (state.analyzeHistory.back.length > 80) {
          state.analyzeHistory.back.shift();
        }
        state.analyzeHistory.forward = [];
      }
      updateAnalyzeNavButtons();
    }

    function updateAnalyzeNavButtons() {
      const back = $("analyzeBack");
      const forward = $("analyzeForward");
      if (back) {
        back.disabled = state.analyzeHistory.back.length === 0;
      }
      if (forward) {
        forward.disabled = state.analyzeHistory.forward.length === 0;
      }
    }

    async function applyAnalyzeLocation(location) {
      if (!location) {
        return;
      }
      state.analyzeHistory.applying = true;
      try {
        if (location.treeMode === "live") {
          const expectedEvidence = state.data && state.data.evidence.find((item) => item.id === location.evidenceId);
          if (!expectedEvidence) {
            return;
          }
          let openedLiveForLocation = false;
          state.browserState = {
            evidenceId: location.evidenceId,
            selectedPath: normalizeLogicalPath(location.selectedPath || "/"),
            treeMode: "filesystem",
            selectedCategory: ""
          };
          if (!(state.live.active && state.live.evidenceId === location.evidenceId)) {
            const initialLiveState = state.live;
            const data = await loadLiveVolumes(location.evidenceId);
            if (state.live !== initialLiveState
              || Number(state.browserState.evidenceId) !== Number(location.evidenceId)
              || !selectedEvidenceIdentityMatches(expectedEvidence)) {
              return;
            }
            state.live = { active: true, evidenceId: location.evidenceId, volumes: data.volumes || [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
            openedLiveForLocation = true;
          }
          const liveState = state.live;
          const path = normalizeLogicalPath(location.selectedPath || "/");
          try {
            const entries = await liveLoadDir(location.liveVolume, path);
            if (entries === null || state.live !== liveState) {
              return;
            }
            state.live.selKey = liveKey(location.liveVolume, path);
            state.live.expanded.add(state.live.selKey);
            if (openedLiveForLocation) {
              state.liveGuidanceExpiresAt = Date.now() + 7000;
            }
          } catch (err) {
            if (state.live !== liveState) {
              return;
            }
            setNotice(err.message, true);
          }
        } else {
          if (state.live.active) {
            state.live = { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
          }
          const treeMode = location.treeMode === "categories" ? "categories" : "filesystem";
          state.browserState = {
            evidenceId: location.evidenceId,
            selectedPath: normalizeLogicalPath(location.selectedPath || "/"),
            treeMode,
            selectedCategory: treeMode === "categories" ? (location.selectedCategory || "") : ""
          };
          if (treeMode === "categories") {
            state.cat = newCategoryCache(location.evidenceId, location.selectedCategory || "");
          } else {
            expandTreePath(state.browserState.selectedPath);
            if (state.idx.evidenceId === location.evidenceId) {
              state.idx.selPath = state.browserState.selectedPath;
              state.idx.expanded.add(state.idx.selPath);
            }
          }
        }
        state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
        renderEvidenceBrowserEntries();
        renderHexViewer();
        switchView("analyzeView");
      } finally {
        state.analyzeHistory.applying = false;
        updateAnalyzeNavButtons();
      }
    }

    async function analyzeBack() {
      const target = state.analyzeHistory.back.pop();
      if (!target) {
        updateAnalyzeNavButtons();
        return;
      }
      const current = currentAnalyzeLocation();
      if (current && !sameAnalyzeLocation(current, target)) {
        state.analyzeHistory.forward.push(current);
      }
      await applyAnalyzeLocation(target);
    }

    async function analyzeForward() {
      const target = state.analyzeHistory.forward.pop();
      if (!target) {
        updateAnalyzeNavButtons();
        return;
      }
      const current = currentAnalyzeLocation();
      if (current && !sameAnalyzeLocation(current, target)) {
        state.analyzeHistory.back.push(current);
      }
      await applyAnalyzeLocation(target);
    }

    async function analyzeDiskImageEntry(entryId) {
      const entry = findLoadedEntry(entryId);
      const evidence = selectedEvidenceSource();
      if (!entry || !evidence) {
        setNotice("Select a disk image entry first.", true);
        return;
      }
      const imagePath = evidenceEntryLocalPath(evidence, entry);
      if (!imagePath) {
        setNotice("This disk image entry cannot be analyzed directly from its current source.", true);
        return;
      }
      const progressId = newJobProgressId();
      await runAnalyze(entry.name || evidence.display_name, async () => {
        let imageEvidence = null;
        let newlyAttached = false;
        try {
          imageEvidence = state.data.evidence.find((item) => sameLocalPath(item.source_path, imagePath));
          if (!imageEvidence) {
            const attached = await apiPost("/api/evidence/add", {
              case_path: currentCasePath(),
              path: imagePath,
              kind: "image",
              read_file_system: true,
              notes: "Promoted from " + evidence.display_name + " " + entry.logical_path
            });
            setNotice("");
            await refresh();
            imageEvidence = state.data.evidence.find((item) => item.id === attached.evidence_id);
            newlyAttached = true;
          }
          if (!imageEvidence) {
            setNotice("Image evidence was attached but is not loaded yet.", true);
            return;
          }
          const options = processingOptionsPayload(newlyAttached);
          const additive = !newlyAttached
            && evidenceIndexedEntryCount(imageEvidence.id) > 0
            && !options.reindex_filesystem;
          const processed = await apiPost(additive ? "/api/evidence/run-processors" : "/api/evidence/process", {
            case_path: currentCasePath(),
            evidence_id: imageEvidence.id,
            max_entries: currentProcessMaxEntries(),
            progress_id: progressId,
            ...options
          });
          if (state.analyzing) {
            state.analyzing.telemetry = processed.progress || state.analyzing.telemetry;
            state.analyzing.telemetryReceivedAt = Date.now();
            renderAnalyzingOverlay();
          }
          const message = processingCompletionNotice(
            processed,
            additive
              ? "Selected processors finished for " + imageEvidence.display_name + "; filesystem snapshot preserved"
              : "Image " + imageEvidence.display_name + " analyzed"
          );
          invalidateIndexedBrowseCache(imageEvidence.id);
          await refresh();
          if (!state.data || !state.data.evidence.some((item) => item.id === imageEvidence.id)) {
            setNotice("");
            return;
          }
          if (state.live.evidenceId === imageEvidence.id) {
            state.live = newLiveBrowseState();
          }
          invalidateIndexedBrowseCache(imageEvidence.id);
          selectEvidenceSource(imageEvidence.id, preferredAnalysisPath(imageEvidence.id), "filesystem");
          setNotice(message);
        } catch (err) {
          if (imageEvidence) {
            invalidateIndexedBrowseCache(imageEvidence.id);
          }
          await refresh();
          setNotice(err.message, true);
        }
      }, { progressId });
    }

    async function importHistory() {
      const historyPath = currentEvidencePathDetails();
      try {
        if (historyPath.corrected) {
          setNotice(pathCorrectionNotice(historyPath) + ".");
        }
        const data = await apiPost("/api/history/import", {
          case_path: currentCasePath(),
          history_path: historyPath.value,
          max_visits: nonNegativeNumberValue("historyMaxVisits", 0)
        });
        const message = "Imported browser activities: " + data.entries_indexed + " records (" + data.status + ").";
        setNotice("");
        await refresh();
        if (!state.data || !state.data.evidence.some((item) => item.id === data.evidence_id)) {
          setNotice("");
          return;
        }
        selectEvidenceSource(data.evidence_id, data.visits_indexed > 0 ? "/Browser Activities/Visits" : "/Browser Activities");
        setNotice(withPathCorrectionNotice(message, historyPath));
      } catch (err) {
        setNotice(withPathCorrectionNotice(err.message, historyPath), true);
      }
    }

    function selectEvidenceSource(id, selectedPath = "/", treeMode = null, recordNavigation = true) {
      const previous = currentAnalyzeLocation();
      if (state.live.active && state.live.evidenceId !== id) {
        state.live = newLiveBrowseState();
        setCurrentLiveGrid("", []);
      }
      state.browserState = {
        evidenceId: id,
        selectedPath: normalizeLogicalPath(selectedPath),
        treeMode: treeMode || state.browserState.treeMode || "filesystem",
        selectedCategory: ""
      };
      state.cat = newCategoryCache();
      expandTreePath(state.browserState.selectedPath);
      state.selectedEntryIds = new Set();
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      renderEvidenceBrowserEntries();
      renderHexViewer();
      switchView("analyzeView");
      const evidence = state.data.evidence.find((item) => item.id === id);
      setNotice(evidence ? "Selected evidence " + evidence.display_name + "." : "Selected evidence.");
      if (recordNavigation) {
        commitAnalyzeNavigation(previous);
      } else {
        updateAnalyzeNavButtons();
      }
    }

    function selectFolder(path, recordNavigation = true) {
      const previous = currentAnalyzeLocation();
      state.browserState.treeMode = "filesystem";
      state.browserState.selectedPath = normalizeLogicalPath(path || "/");
      expandTreePath(state.browserState.selectedPath);
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      renderEvidenceBrowserEntries();
      renderHexViewer();
      setNotice("Selected folder " + displayPath(state.browserState.selectedPath) + ".");
      if (recordNavigation) {
        commitAnalyzeNavigation(previous);
      } else {
        updateAnalyzeNavButtons();
      }
    }

    function leaveLiveBrowseForIndexedMode() {
      if (!state.live.active) {
        return false;
      }
      state.live = newLiveBrowseState();
      setCurrentLiveGrid("", []);
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      return true;
    }

    function selectCategory(categoryKey, recordNavigation = true) {
      const previous = currentAnalyzeLocation();
      const key = categoryKey || "";
      const leftLiveBrowse = leaveLiveBrowseForIndexedMode();
      state.browserState.treeMode = "categories";
      state.browserState.selectedCategory = key;
      if (state.cat.evidenceId !== ALL_EVIDENCE_CATEGORY_SCOPE || state.cat.key !== key) {
        state.cat = newCategoryCache(ALL_EVIDENCE_CATEGORY_SCOPE, key);
      }
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      renderEvidenceBrowserEntries();
      renderHexViewer();
      setNotice((leftLiveBrowse ? "Closed source browse. " : "")
        + "Selected indexed category " + (categoryLabel(key) || "All Categories") + ".");
      if (recordNavigation) {
        commitAnalyzeNavigation(previous);
      } else {
        updateAnalyzeNavButtons();
      }
    }

    function setBrowserTreeMode(mode, recordNavigation = true) {
      const previous = currentAnalyzeLocation();
      state.browserState.treeMode = mode === "categories" ? "categories" : "filesystem";
      if (state.browserState.treeMode === "categories") {
        const leftLiveBrowse = leaveLiveBrowseForIndexedMode();
        state.browserState.selectedCategory = state.browserState.selectedCategory || "";
        if (leftLiveBrowse && evidenceIndexedEntryCount(state.browserState.evidenceId) === 0) {
          setNotice("Categories use indexed evidence. Complete Analyze image to populate them; live files are not categories.", true);
        } else if (leftLiveBrowse) {
          setNotice("Closed source browse. Showing indexed categories.");
        }
      }
      renderEvidenceBrowserEntries();
      if (recordNavigation) {
        commitAnalyzeNavigation(previous);
      } else {
        updateAnalyzeNavButtons();
      }
    }

    function toggleEntrySelection(entryId, checked, event) {
      if (event && event.shiftKey && state.lastSelectedEntryId) {
        selectEntryRange(state.lastSelectedEntryId, entryId, true);
        renderEvidenceBrowserEntries();
        setNotice("Selected " + selectedEntriesForActions().length + " visible entries.");
        return;
      }
      setEntrySelection(entryId, checked);
      state.lastSelectedEntryId = entryId;
      renderSelectionCount();
    }

    function setEntrySelection(entryId, selected) {
      if (selected) {
        state.selectedEntryIds.add(entryId);
      } else {
        state.selectedEntryIds.delete(entryId);
      }
    }

    function selectEntryRange(fromEntryId, toEntryId, selected) {
      const ids = visibleEntryIds();
      const fromIndex = ids.indexOf(fromEntryId);
      const toIndex = ids.indexOf(toEntryId);
      if (fromIndex < 0 || toIndex < 0) {
        setEntrySelection(toEntryId, selected);
        state.lastSelectedEntryId = toEntryId;
        return;
      }
      const start = Math.min(fromIndex, toIndex);
      const end = Math.max(fromIndex, toIndex);
      ids.slice(start, end + 1).forEach((id) => setEntrySelection(id, selected));
      state.lastSelectedEntryId = toEntryId;
    }

    function handleEntryRowClick(event, entryId) {
      if (event && event.shiftKey && state.lastSelectedEntryId) {
        selectEntryRange(state.lastSelectedEntryId, entryId, true);
        renderEvidenceBrowserEntries();
        setNotice("Selected " + selectedEntriesForActions().length + " visible entries.");
        return;
      }
      if (event && (event.ctrlKey || event.metaKey)) {
        setEntrySelection(entryId, !state.selectedEntryIds.has(entryId));
        state.lastSelectedEntryId = entryId;
        renderEvidenceBrowserEntries();
        renderSelectionCount();
        return;
      }
      state.lastSelectedEntryId = entryId;
      selectBrowserEntry(entryId);
    }

    function selectVisibleEntries() {
      if (state.live.active) {
        const visible = visibleLiveEntries();
        if (visible.length === 0) {
          setNotice("No visible live entries to select.", true);
          return;
        }
        visible.forEach((item) => setLiveSelection(item, true));
        renderLiveBrowse();
        setNotice("Selected " + visible.length + " visible live entries.");
        return;
      }
      const entries = visibleFolderEntries();
      if (entries.length === 0) {
        setNotice("No visible entries to select.", true);
        return;
      }
      entries.forEach((entry) => state.selectedEntryIds.add(entry.id));
      renderEvidenceBrowserEntries();
      setNotice("Selected " + entries.length + " visible entries.");
    }

    function clearEntrySelection() {
      state.selectedEntryIds = new Set();
      state.lastSelectedEntryId = null;
      renderEvidenceBrowserEntries();
      renderSelectionCount();
    }

    function restoreEntrySelection(ids) {
      if (!state.data) {
        state.selectedEntryIds = new Set();
        return;
      }
      const valid = new Set(state.data.entries.map((entry) => entry.id));
      for (const path in state.idx.dirCache) {
        state.idx.dirCache[path].forEach((child) => {
          if (child.entry_id != null) {
            valid.add(child.entry_id);
          }
        });
      }
      (state.cat.entries || []).forEach((entry) => valid.add(entry.id));
      state.selectedEntryIds = new Set(ids.filter((id) => valid.has(id)));
    }

    async function bookmarkSelectedEntries() {
      const ids = selectedEntriesForActions().map((entry) => entry.id);
      if (ids.length === 0) {
        setNotice("Select one or more visible entries first.", true);
        return { succeeded: 0, failed: ids.length };
      }
      // One request for the whole selection (bulk_add_bookmark_items runs every insert in a
      // single server-side transaction) instead of one HTTP round-trip per entry - the old
      // per-entry loop measured ~17ms/item, so a real ~23k-entry "All Categories" selection
      // took nearly 7 minutes with no progress feedback, which read as a hung/crashed tab.
      if (ids.length > 500) {
        setNotice("Bookmarking " + ids.length.toLocaleString() + " selected entries...");
      }
      try {
        const result = await apiPost("/api/bookmark/bulk", {
          case_path: currentCasePath(),
          folder_name: "Findings",
          title: "Bulk bookmark (" + ids.length + " entries)",
          comment: "Bookmarked via Selected actions on " + new Date().toISOString() + ".",
          bookmark_type: "file_group",
          entry_ids: ids
        });
        await refresh();
        restoreEntrySelection(ids);
        renderEvidenceBrowserEntries();
        renderSelectionCount();
        const succeeded = result.items_added;
        const failed = (result.skipped_entry_ids || []).length;
        if (failed) {
          setNotice("Bookmarked " + succeeded + " selected entries; " + failed + " were no longer available and were skipped.", true);
          return { succeeded, failed };
        }
        setNotice("Bookmarked " + succeeded + " selected entries.");
        return { succeeded, failed: 0 };
      } catch (err) {
        setNotice(err.message || String(err), true);
        return { succeeded: 0, failed: ids.length };
      }
    }

    async function exportSelectedEntries() {
      const ids = selectedEntriesForActions().map((entry) => entry.id);
      if (ids.length === 0) {
        setNotice("Select one or more visible file entries first.", true);
        return { succeeded: 0, failed: ids.length };
      }
      const fileIds = ids.filter((entryId) => {
        const entry = findLoadedEntry(entryId);
        return entry && entry.entry_kind === "file";
      });
      if (fileIds.length === 0) {
        setNotice("Selected rows are records or folders. Use Report selected to add them to the report; only file entries have bytes to export.", true);
        return { succeeded: 0, failed: ids.length };
      }
      let succeeded = 0;
      const failed = [];
      let lastError = "";
      for (const entryId of fileIds) {
        const entry = findLoadedEntry(entryId);
        try {
          await apiPost("/api/entry/recover", {
            case_path: currentCasePath(),
            entry_id: entryId,
            output_path: defaultRecoveryPath(entry)
          });
          succeeded += 1;
        } catch (err) {
          failed.push(entryId);
          lastError = err.message || String(err);
        }
      }
      await refresh();
      restoreEntrySelection(ids);
      renderEvidenceBrowserEntries();
      renderSelectionCount();
      const skipped = ids.length - fileIds.length;
      if (failed.length) {
        const skippedText = skipped ? "; skipped " + skipped + " non-file item" + (skipped === 1 ? "" : "s") : "";
        setNotice("Exported " + succeeded + " selected file" + (succeeded === 1 ? "" : "s") + skippedText + "; " + failed.length + " failed" + (lastError ? ": " + lastError : "."), true);
        return { succeeded, failed: failed.length };
      }
      const skippedText = skipped ? "; skipped " + skipped + " non-file item" + (skipped === 1 ? "" : "s") : "";
      setNotice("Exported " + succeeded + " selected file" + (succeeded === 1 ? "" : "s") + " to ui-output" + skippedText + ".");
      return { succeeded, failed: 0 };
    }

    async function handleSelectedAction() {
      const selectedAction = $("selectedAction");
      const action = selectedAction.value;
      selectedAction.selectedIndex = 0;
      if (!action) {
        return;
      }
      if (state.live.active) {
        if (action === "bookmark") {
          await bookmarkSelectedLive();
        } else if (action === "bookmark_report") {
          await bookmarkSelectedLive();
          await exportReport();
        } else if (action === "export_files") {
          await exportSelectedLive();
        } else if (action === "clear") {
          clearLiveSelection();
        } else {
          setNotice("That action is not available while browsing the source directly.", true);
        }
        return;
      }
      if (action === "bookmark") {
        await bookmarkSelectedEntries();
        return;
      }
      if (action === "bookmark_report") {
        const result = await bookmarkSelectedEntries();
        if (result && result.succeeded > 0) {
          await exportReport();
        }
        return;
      }
      if (action === "export_files") {
        if (!selectedFileExportAllowed()) {
          setNotice(fileExportUnavailableMessage(), true);
          return;
        }
        await exportSelectedEntries();
        return;
      }
      if (action === "export_csv") {
        exportSelectedCsv();
        return;
      }
      if (action === "clear") {
        clearEntrySelection();
      }
    }

    async function bookmarkSelectionAndExportReport() {
      const selectedAction = $("selectedAction");
      if (selectedAction) {
        selectedAction.selectedIndex = 0;
      }
      if (state.live.active) {
        if (selectedVisibleLiveItems().length === 0) {
          setNotice("Select rows before reporting selected items.", true);
          return;
        }
        setNotice("Bookmarking selected source items for the report...");
        await bookmarkSelectedLive();
        await exportReport();
        return;
      }
      const count = selectedEntriesForActions().length;
      if (count === 0) {
        setNotice("Select rows before reporting selected items.", true);
        return;
      }
      setNotice("Bookmarking " + count + " selected item" + (count === 1 ? "" : "s") + " for the report...");
      const result = await bookmarkSelectedEntries();
      if (result && result.succeeded > 0) {
        await exportReport();
      }
    }

    function spreadsheetSafeText(value) {
      let text = "";
      if (value != null && typeof value === "object") {
        try {
          text = JSON.stringify(value);
        } catch (err) {
          text = String(value);
        }
      } else if (value != null) {
        text = String(value);
      }
      // Evidence-controlled strings must not execute as spreadsheet formulas.
      return /^[=+@]/.test(text) || /^-[^0-9.]/.test(text) ? "'" + text : text;
    }

    function csvField(value) {
      const text = spreadsheetSafeText(value);
      return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    }

    // Export selected artifacts with identity, classification, size, MAC
    // times, deletion state, and offsets.
    function exportSelectedCsvLegacy() {
      const entries = selectedEntriesForActions();
      if (entries.length === 0) {
        setNotice("Select rows to export first.", true);
        return;
      }
      const header = ["Name", "Logical path", "Evidence", "Category", "Type", "Size (bytes)",
        "Created", "Accessed", "Modified", "Deleted", "Flags", "Offset"];
      const evidenceNames = new Map((state.data.evidence || []).map((item) => [item.id, item.display_name]));
      const lines = [header.join(",")];
      entries.forEach((entry) => {
        lines.push([
          csvField(entry.name || logicalName(entry.logical_path)),
          csvField(entry.logical_path),
          csvField(evidenceNames.get(entry.evidence_id) || entry.evidence_id),
          csvField(entryCategoryLabel(entry)),
          csvField(entry.entry_kind),
          csvField(entry.size_bytes == null ? "" : entry.size_bytes),
          csvField(filesystemCreatedTime(entry)),
          csvField(filesystemAccessedTime(entry)),
          csvField(filesystemModifiedTime(entry)),
          csvField(entry.is_deleted ? "yes" : "no"),
          csvField(entryFlagsText(entry)),
          csvField(entryPrimaryOffset(entry))
        ].join(","));
      });
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const blob = new Blob(["ï»¿" + lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "kdft-export-" + stamp + ".csv";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      setNotice("Exported " + entries.length + " selected item(s) to CSV.");
    }

    function delimitedField(value, delimiter) {
      const text = spreadsheetSafeText(value);
      if (delimiter === "\t") {
        return text.replace(/\t/g, " ").replace(/\r?\n/g, " ");
      }
      return csvField(text);
    }

    const ARTIFACT_EXPORT_BASE_KEYS = new Set([
      "artifact_kind", "parser", "parser_name", "browser_parser", "identity_parser",
      "windows_parser", "category_main", "category_sub", "category_hidden",
      "artifact_time_utc", "source_artifact_path", "derived_from_entry_id"
    ]);

    function artifactExportColumns(entries) {
      const columns = [
        { label: "Entry ID", value: (entry) => entry.id },
        { label: "Evidence ID", value: (entry) => entry.evidence_id },
        { label: "Evidence", value: (entry) => {
          const evidence = (state.data && state.data.evidence || []).find((item) => item.id === entry.evidence_id);
          return evidence ? evidence.display_name : entry.evidence_id;
        }},
        { label: "Artifact kind", value: (entry, metadata) => metadata.artifact_kind || "" },
        { label: "Parser", value: (entry, metadata) => metadata.parser || metadata.parser_name || metadata.browser_parser || metadata.identity_parser || metadata.windows_parser || "" },
        { label: "Category main", value: (entry, metadata) => metadata.category_main || "" },
        { label: "Category sub", value: (entry, metadata) => metadata.category_sub || "" },
        { label: "Name", value: (entry) => entry.name || logicalName(entry.logical_path) },
        { label: "Logical path", value: (entry) => entry.logical_path },
        { label: "Entry kind", value: (entry) => entry.entry_kind },
        { label: "Size bytes", value: (entry) => entry.size_bytes == null ? "" : entry.size_bytes },
        { label: "Deleted", value: (entry) => entry.is_deleted ? "yes" : "no" },
        { label: "Created UTC", value: (entry) => filesystemCreatedTime(entry) },
        { label: "Accessed UTC", value: (entry) => filesystemAccessedTime(entry) },
        { label: "Modified UTC", value: (entry) => filesystemModifiedTime(entry) },
        { label: "Artifact time UTC", value: (entry, metadata) => metadata.artifact_time_utc || "" },
        { label: "Flags", value: (entry) => entryFlagsText(entry) },
        { label: "Offset", value: (entry) => entryPrimaryOffset(entry) },
        { label: "Source artifact path", value: (entry, metadata) => metadata.source_artifact_path || metadata.source_path_exact || "" },
        { label: "Derived from entry ID", value: (entry, metadata) => metadata.derived_from_entry_id || metadata.source_entry_id || "" }
      ];
      const metadataKeys = new Set();
      entries.forEach((entry) => {
        const metadata = entry.metadata_json && typeof entry.metadata_json === "object" ? entry.metadata_json : {};
        Object.keys(metadata).forEach((key) => {
          if (!ARTIFACT_EXPORT_BASE_KEYS.has(key)) {
            metadataKeys.add(key);
          }
        });
      });
      Array.from(metadataKeys).sort((left, right) => left.localeCompare(right)).forEach((key) => {
        columns.push({ label: "meta." + key, value: (entry, metadata) => metadata[key] });
      });
      return columns;
    }

    function downloadArtifactTable(entries, format, stem) {
      if (!entries.length) {
        setNotice("There are no artifact rows to export.", true);
        return;
      }
      const delimiter = format === "tsv" ? "\t" : ",";
      const columns = artifactExportColumns(entries);
      const lines = [columns.map((column) => delimitedField(column.label, delimiter)).join(delimiter)];
      entries.forEach((entry) => {
        const metadata = entry.metadata_json && typeof entry.metadata_json === "object" ? entry.metadata_json : {};
        lines.push(columns.map((column) => delimitedField(column.value(entry, metadata), delimiter)).join(delimiter));
      });
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const safeStem = String(stem || "artifacts").replace(/[^a-z0-9._-]+/gi, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "artifacts";
      const mime = format === "tsv" ? "text/tab-separated-values;charset=utf-8" : "text/csv;charset=utf-8";
      const blob = new Blob(["\uFEFF" + lines.join("\r\n") + "\r\n"], { type: mime });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "kdft-" + safeStem + "-" + stamp + "." + format;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      setNotice("Exported " + entries.length.toLocaleString() + " artifact row(s) to " + format.toUpperCase() + ".");
    }

    function exportSelectedArtifacts(format = "csv") {
      const entries = selectedEntriesForActions();
      if (entries.length === 0) {
        setNotice("Select rows to export first.", true);
        return;
      }
      downloadArtifactTable(entries, format, "selected-artifacts");
    }

    function exportSelectedCsv() {
      exportSelectedArtifacts("csv");
    }

    async function exportCategoryArtifacts(key, format) {
      const selected = splitCategoryKey(key || "");
      if (!selected.main) {
        setNotice("Right-click a specific category or subcategory to export its artifact sheet.", true);
        return;
      }
      const entries = [];
      let total = null;
      let cursor = null;
      setNotice("Preparing " + categoryLabel(key) + " artifact " + format.toUpperCase() + "...");
      try {
        do {
          const params = { case_path: currentCasePath(), main: selected.main, limit: 1000 };
          if (selected.sub) {
            params.sub = selected.sub;
          }
          if (cursor) {
            params.after_path = cursor.logical_path;
            params.after_id = cursor.id;
          }
          const page = await apiGet("/api/entries/category", params);
          const pageEntries = (page.entries || []).map(normalizeCategoryEntry);
          entries.push(...pageEntries);
          total = Number(page.total_in_category || entries.length);
          cursor = page.next_cursor || null;
          if (pageEntries.length === 0) {
            break;
          }
          if (cursor) {
            setNotice("Preparing " + categoryLabel(key) + " artifact " + format.toUpperCase() + ": " + entries.length.toLocaleString() + " / " + total.toLocaleString() + " rows...");
          }
        } while (cursor);
        downloadArtifactTable(entries, format, categoryLabel(key));
      } catch (err) {
        setNotice("Artifact export failed: " + (err.message || String(err)), true);
      }
    }

    function selectBrowserEntry(entryId) {
      const entry = findLoadedEntry(entryId);
      if (!entry) {
        setNotice("Entry is not loaded.", true);
        return;
      }
      if (entry.entry_kind === "directory") {
        selectFolder(entry.logical_path);
        return;
      }
      state.hex = makeHexState(entry.id, 0, numberValue("hexLength", 512));
      $("viewerMode").value = "metadata";
      loadEntryDiskLocation(entry.id);
      renderHexViewer();
      const evidence = selectedEvidenceSource();
      if (entry.entry_kind === "file" && isPromotableDiskImageEntry(entry, evidence)) {
        setNotice("Raw container bytes - use Analyze image to browse decoded contents.");
        return;
      }
      setNotice("Selected " + (entry.name || logicalName(entry.logical_path)) + ".");
    }

    async function openEntry(entryId) {
      state.hex = makeHexState(entryId, 0, numberValue("hexLength", 512));
      $("viewerMode").value = "hex";
      $("hexOffset").value = String(state.hex.offset);
      const locationRequest = loadEntryDiskLocation(entryId);
      await fetchEntryBytes();
      await locationRequest;
      // The live-browse "view bytes" paths (openLiveFile, openLiveRawDevice,
      // etc.) already do this - this one was missing it, so clicking "View
      // bytes" on an indexed entry fetched the bytes successfully but showed
      // nothing if the inspector pane was collapsed.
      setInspectorCollapsed(false);
    }

    function resolvedDiskLocation() {
      const location = state.hex && state.hex.diskLocation;
      return location && location.available && location.decoded_media_offset != null ? location : null;
    }

    function isFilesystemByteContext() {
      return Boolean(state.hex && (state.hex.raw || (state.hex.entryId && state.hex.byteContext === "filesystem")));
    }

    function diskLocationMappedLength(location) {
      if (!location) {
        return 0;
      }
      const value = Number(location.contiguous_bytes);
      return Number.isFinite(value) && value > 0 ? value : 1;
    }

    function decodedRangeWithinDiskLocation(location, start, end) {
      if (!location || location.decoded_media_offset == null) {
        return false;
      }
      const mappedStart = Number(location.decoded_media_offset);
      const mappedEnd = mappedStart + diskLocationMappedLength(location) - 1;
      return start >= mappedStart && end <= mappedEnd;
    }

    function fileRangeWithinDiskLocation(location, start, end) {
      if (!location || location.file_relative_offset == null) {
        return false;
      }
      const mappedStart = Number(location.file_relative_offset);
      const mappedEnd = mappedStart + diskLocationMappedLength(location) - 1;
      return start >= mappedStart && end <= mappedEnd;
    }

    function updateResolvedOffsetCell(entryId) {
      const entry = findLoadedEntry(entryId);
      const location = resolvedDiskLocation();
      if (!entry || !location) {
        return;
      }
      entry.metadata_json = entry.metadata_json || {};
      entry.metadata_json.resolved_decoded_media_offset = location.decoded_media_offset;
      entry.metadata_json.resolved_offset_basis = location.basis;
      document.querySelectorAll(`.entry-row[data-entry-id="${entryId}"] .entry-offset`).forEach((cell) => {
        const label = entryPrimaryOffset(entry);
        cell.textContent = label;
        cell.title = label + " | " + location.basis;
      });
    }

    async function loadEntryDiskLocation(entryId = state.hex.entryId) {
      if (!entryId || !state.hex || state.hex.entryId !== entryId) {
        return null;
      }
      const targetState = state.hex;
      targetState.locationLoading = true;
      targetState.locationError = "";
      updateByteContextControls();
      try {
        const location = await apiGet("/api/entry/disk-location", {
          case_path: currentCasePath(),
          entry_id: entryId
        });
        if (state.hex !== targetState || state.hex.entryId !== entryId) {
          return location;
        }
        targetState.diskLocation = location;
        targetState.locationLoading = false;
        targetState.locationError = location.available ? "" : (location.warning || "File-system location unavailable.");
        updateResolvedOffsetCell(entryId);
        updateByteContextControls();
        renderHexViewer();
        return location;
      } catch (err) {
        if (state.hex === targetState) {
          targetState.locationLoading = false;
          targetState.locationError = err.message || String(err);
          updateByteContextControls();
          renderHexViewer();
        }
        return null;
      }
    }

    async function setByteContext(context) {
      if (!state.hex || state.hex.live || state.hex.raw || !state.hex.entryId) {
        return;
      }
      const currentOffset = Number(state.hex.data ? state.hex.data.offset : state.hex.offset) || 0;
      if (context === "filesystem") {
        let location = resolvedDiskLocation();
        if (!location) {
          location = await loadEntryDiskLocation(state.hex.entryId);
        }
        if (!location || !location.available || location.decoded_media_offset == null) {
          setNotice((location && location.warning) || state.hex.locationError || "File-system location is unavailable for this entry.", true);
          return;
        }
        state.hex.byteContext = "filesystem";
        state.hex.offset = fileRangeWithinDiskLocation(location, currentOffset, currentOffset)
          ? Number(location.decoded_media_offset) + currentOffset - Number(location.file_relative_offset || 0)
          : Number(location.decoded_media_offset);
      } else {
        const location = resolvedDiskLocation();
        state.hex.byteContext = "file";
        state.hex.offset = location && decodedRangeWithinDiskLocation(location, currentOffset, currentOffset)
          ? Number(location.file_relative_offset || 0) + currentOffset - Number(location.decoded_media_offset)
          : 0;
      }
      state.hex.data = null;
      clearHexSelection();
      $("viewerMode").value = "hex";
      $("hexOffset").value = String(state.hex.offset);
      updateByteContextControls();
      await fetchEntryBytes();
    }

    const EXTERNAL_OPEN_EXTENSIONS = new Set([
      "pdf", "txt", "log", "csv", "tsv", "json", "xml", "rtf",
      "doc", "docx", "xls", "xlsx", "ods", "odt", "ppt", "pptx",
      "jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff",
      "wav", "mp3", "mp4", "mov", "avi"
    ]);

    function canOpenEntryExternally(entry) {
      return Boolean(entry && entry.id && entry.entry_kind === "file" && EXTERNAL_OPEN_EXTENSIONS.has(filesystemFileExtension(entry)));
    }

    function externalOpenWarning(entry) {
      const name = entry && (entry.name || logicalName(entry.logical_path))
        ? (entry.name || logicalName(entry.logical_path))
        : "the selected file";
      return [
        "SECURITY WARNING: UNTRUSTED EVIDENCE",
        "Opening " + name + " will launch a host application outside KDFT's internal viewer. The recovered copy is read-only, but its content may still contain malicious macros, exploits, external links, or media crafted to compromise this computer.",
        "KDFT cannot sandbox or make the host application safe. Cancel is the safe default; use View bytes in KDFT whenever possible.",
        "Select OK only if you accept this risk and are working in an appropriately isolated forensic environment."
      ].join("\n\n");
    }

    async function openSelectedEntryExternal(entryId = null) {
      const entry = entryId ? findLoadedEntry(entryId) : currentHexEntry();
      if (!entry || !entry.id || entry.entry_kind !== "file") {
        setNotice("Select an indexed file before opening it.", true);
        return;
      }
      if (!canOpenEntryExternally(entry)) {
        setNotice("This file type is not enabled for external preview. Recover it explicitly for controlled inspection.", true);
        return;
      }
      if (!window.confirm(externalOpenWarning(entry))) {
        return;
      }
      try {
        setNotice("Preparing read-only preview for " + (entry.name || logicalName(entry.logical_path)) + "...");
        const data = await apiPost("/api/entry/open", {
          case_path: currentCasePath(),
          entry_id: entry.id,
          acknowledge_host_app_risk: true
        });
        setNotice("Opened read-only preview copy " + data.output_path + ".");
      } catch (err) {
        setNotice(err.message || String(err), true);
      }
    }

    function updateByteContextControls() {
      const fileButton = $("byteContextFile");
      const filesystemButton = $("byteContextFilesystem");
      const openButton = $("openSelectedEntry");
      if (!fileButton || !filesystemButton) {
        return;
      }
      const entry = currentHexEntry();
      const raw = Boolean(state.hex && state.hex.raw);
      const live = Boolean(state.hex && state.hex.live);
      const indexedFile = Boolean(entry && entry.id && entry.entry_kind === "file");
      const fileActive = !raw && state.hex.byteContext !== "filesystem";
      const filesystemActive = raw || state.hex.byteContext === "filesystem";
      fileButton.classList.toggle("active", fileActive);
      fileButton.setAttribute("aria-pressed", String(fileActive));
      fileButton.disabled = raw || (!indexedFile && !live);
      filesystemButton.classList.toggle("active", filesystemActive);
      filesystemButton.setAttribute("aria-pressed", String(filesystemActive));
      const location = resolvedDiskLocation();
      filesystemButton.disabled = !raw && (!indexedFile || !location);
      if (raw) {
        filesystemButton.title = "Decoded evidence bytes at absolute media offsets.";
      } else if (state.hex.locationLoading) {
        filesystemButton.title = "Resolving the file's first authoritative media location...";
      } else if (location) {
        filesystemButton.title = location.basis + (location.warning ? " | " + location.warning : "");
      } else {
        filesystemButton.title = state.hex.locationError || "No authoritative file-data offset is available.";
      }
      if (openButton) {
        openButton.disabled = !canOpenEntryExternally(entry);
        openButton.title = openButton.disabled
          ? "External preview is available for bounded document, data, image, and media files."
          : "Recover a read-only copy and open it with the registered application.";
      }
    }

    async function fetchEntryBytes() {
      if (!state.hex.entryId && !state.hex.live && !state.hex.raw) {
        renderHexViewer();
        return;
      }
      if (state.hex.fetching) {
        return;
      }
      state.hex.fetching = true;
      try {
        let data;
        const filesystemContext = isFilesystemByteContext();
        if (state.hex.raw) {
          data = await apiGet("/api/image/bytes", {
              case_path: currentCasePath(),
              evidence_id: state.hex.raw.evidenceId,
              raw: true,
              offset: state.hex.offset,
              length: state.hex.length
            });
          data.byte_context = "filesystem";
        } else if (state.hex.live) {
          data = await apiGet("/api/image/bytes", {
              case_path: currentCasePath(),
              evidence_id: state.hex.live.evidenceId,
              volume: state.hex.live.volume,
              path: state.hex.live.path,
              offset: state.hex.offset,
              length: state.hex.length
            });
        } else if (filesystemContext) {
          const location = resolvedDiskLocation();
          if (!location) {
            throw new Error(state.hex.locationError || "File-system location is unavailable for this entry.");
          }
          data = await apiGet("/api/image/bytes", {
            case_path: currentCasePath(),
            evidence_id: location.evidence_id,
            raw: true,
            offset: state.hex.offset,
            length: state.hex.length
          });
          data.byte_context = "filesystem";
          data.entry_id = state.hex.entryId;
          data.disk_location = location;
          data.file_relative_offset = Number(location.file_relative_offset || 0)
            + Number(data.offset) - Number(location.decoded_media_offset);
        } else {
          data = await apiGet("/api/entry/bytes", {
              case_path: currentCasePath(),
              entry_id: state.hex.entryId,
              offset: state.hex.offset,
              length: state.hex.length
            });
          data.byte_context = "file";
          data.file_relative_offset = Number(data.offset);
        }
        clearHexSelection();
        state.hex.data = data;
        $("hexOffset").value = String(data.offset);
        $("hexLength").value = String(data.requested_length);
        state.hex.fetching = false;
        renderHexViewer();
        setNotice(filesystemContext
          ? "Opened file-system bytes at decoded-media offset " + data.offset + "."
          : "Opened file bytes at file-relative offset " + data.offset + ".");
      } catch (err) {
        clearHexSelection();
        state.hex.data = null;
        state.hex.fetching = false;
        renderHexViewer(err.message);
        setNotice(err.message, true);
      }
    }

    async function gotoHexOffset() {
      state.hex.offset = offsetValue();
      state.hex.length = numberValue("hexLength", 512);
      await fetchEntryBytes();
    }

    async function stepHex(delta) {
      const length = numberValue("hexLength", 512);
      const current = state.hex.data ? Number(state.hex.data.offset) : offsetValue();
      state.hex.length = length;
      state.hex.offset = Math.max(0, current + (delta * length));
      await fetchEntryBytes();
    }

    function resetRawFindProgress() {
      if (!state.hex || !state.hex.find) {
        return;
      }
      state.hex.find.status = "";
      state.hex.find.continuation = null;
      state.hex.find.nextStart = null;
      state.hex.find.lastMatch = null;
      state.hex.find.matchLength = null;
    }

    function rawFindSetQuery(value) {
      if (!state.hex.find) {
        return;
      }
      state.hex.find.query = value;
      resetRawFindProgress();
    }

    function rawFindSetKind(value) {
      if (!state.hex.find) {
        return;
      }
      state.hex.find.kind = value === "hex" ? "hex" : "text";
      resetRawFindProgress();
      renderHexViewer();
    }

    function rawFindKeydown(event) {
      if (event.key === "Enter") {
        event.preventDefault();
        rawFindNext(false);
      }
    }

    function rawFindCancel() {
      if (!state.hex.find) {
        return;
      }
      state.hex.find.status = "";
      state.hex.find.continuation = null;
      renderHexViewer();
    }

    async function rawFindNext(continuing = false) {
      if (!state.hex.raw) {
        setNotice("Open raw image bytes before finding.", true);
        return;
      }
      const find = state.hex.find;
      const query = String(find.query || "").trim();
      if (!query) {
        find.status = "Enter a find query.";
        renderHexViewer();
        return;
      }
      const start = continuing && find.continuation != null
        ? Number(find.continuation)
        : (find.nextStart != null ? Number(find.nextStart) : Number(state.hex.offset || 0));
      find.active = true;
      find.status = "Scanning from " + formatRawFindOffset(start) + "...";
      find.continuation = null;
      renderHexViewer();
      try {
        const data = await apiGet("/api/image/find", {
          case_path: currentCasePath(),
          evidence_id: state.hex.raw.evidenceId,
          start: Math.max(0, Math.floor(start)),
          q: query,
          kind: find.kind === "hex" ? "hex" : "text"
        });
        find.active = false;
        if (data.match_offset != null) {
          const matchOffset = Number(data.match_offset);
          const matchLength = Math.max(1, Number(data.match_length || 1));
          find.lastMatch = matchOffset;
          find.matchLength = matchLength;
          find.nextStart = matchOffset + 1;
          find.continuation = null;
          find.status = "match at " + formatRawFindOffset(matchOffset);
          state.hex.length = numberValue("hexLength", 512);
          state.hex.offset = Math.max(0, matchOffset - Math.floor(state.hex.length / 2));
          $("hexOffset").value = String(state.hex.offset);
          await fetchEntryBytes();
          state.hex.selStart = matchOffset;
          state.hex.selEnd = matchOffset + matchLength - 1;
          renderHexViewer();
          setNotice("Raw find match at " + formatRawFindOffset(matchOffset) + ".");
          return;
        }
        const scannedTo = Number(data.scanned_to || start);
        if (data.eof) {
          find.status = "No match found through EOF.";
          find.continuation = null;
          find.nextStart = null;
        } else {
          find.status = "No match in this window; scanned to " + formatRawFindOffset(scannedTo) + ".";
          find.continuation = Number(data.next_scan_offset == null ? scannedTo : data.next_scan_offset);
          find.nextStart = find.continuation;
        }
        renderHexViewer();
      } catch (err) {
        find.active = false;
        find.status = err.message || String(err);
        renderHexViewer();
        setNotice(err.message || String(err), true);
      }
    }

    function currentSearchMode() {
      const el = $("searchMode");
      return el && el.value === "all" ? "all" : "indexed";
    }

    // Show the bitwise-only controls and clear any stale bitwise results when
    // the examiner flips the single search window between Indexed and All.
    function updateSearchModeUi() {
      const mode = currentSearchMode();
      const controls = $("bitwiseControls");
      if (controls) {
        controls.hidden = mode !== "all";
      }
      if (mode !== "all") {
        state.rawSearchResult = null;
        state.selectedRawSearchKeys = new Set();
        state.lastRawSearchKey = null;
        const section = $("rawSearchSection");
        if (section) {
          section.hidden = true;
        }
        renderRawSearchResults();
      }
      persistDeepSearchSession();
    }

    // One-line summary of how the indexed pass ended, reused by every notice
    // the unified search shows afterwards so a failed indexed pass stays
    // visible instead of being overwritten by the bitwise status.
    function indexedPassSummary() {
      if (state.searchError) {
        return "Indexed pass FAILED (" + state.searchError + ")";
      }
      return "Indexed: " + state.searchResults.length + " result" + (state.searchResults.length === 1 ? "" : "s") +
        (state.searchComplete ? " (complete)" : " loaded (more available)");
    }

    function searchPageSize() {
      const field = $("maxResults");
      const value = Number(field.value);
      if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error("Results per page must be a whole number from 1 to 1,000.");
      }
      if (value > 1000) {
        throw new Error("Results per page exceeds the protective maximum of 1,000. This is only a response-page bound; use Load more for complete coverage.");
      }
      return value;
    }

    async function loadMoreSearchResults() {
      if (state.searchPageLoading || state.searchComplete || !state.searchCursor) {
        return;
      }
      state.searchPageLoading = true;
      renderSearchResults();
      try {
        const page = await apiPostReadOnlyWithNetworkRetry("/api/search/deep", {
          case_path: currentCasePath(),
          query: $("searchQuery").value,
          evidence_id: $("searchEvidence").value ? Number($("searchEvidence").value) : null,
          include_content: $("includeContent").value === "true",
          max_results: searchPageSize(),
          cursor: state.searchCursor,
          max_file_bytes: boundedNumberValue("maxFileBytes", 4096, 1, 4096),
          category: $("searchCategory").value || null,
          file_types: $("searchFileTypes").value || null
        });
        state.searchResults.push(...(page.results || []));
        state.searchCursor = page.next_cursor || null;
        state.searchComplete = Boolean(page.complete);
        state.searchCoverage = page.coverage || state.searchCoverage;
        setNotice(indexedPassSummary() + ".");
      } catch (err) {
        setNotice("Could not load the next indexed-search page: " + (err.message || err), true);
      } finally {
        state.searchPageLoading = false;
        renderSearchResults();
        persistDeepSearchSession();
      }
    }

    async function runSearch() {
      if (state.searchRunning) {
        setNotice("A search is already running.");
        return;
      }
      state.searchRunning = true;
      const runButton = $("runSearch");
      if (runButton) {
        runButton.disabled = true;
        runButton.textContent = "Searching...";
      }
      const mode = currentSearchMode();
      state.searchResults = [];
      state.searchCursor = null;
      state.searchComplete = false;
      state.searchPageLoading = false;
      state.searchCoverage = null;
      state.searchError = null;
      state.selectedSearchKeys = new Set();
      state.selectedRawSearchKeys = new Set();
      state.lastRawSearchKey = null;
      resetGridView("search");
      renderSearchResults();
      // Reset the bitwise section every run; it only re-appears for All mode.
      state.rawSearchResult = null;
      resetGridView("rawSearch");
      const rawSection = $("rawSearchSection");
      if (rawSection) {
        rawSection.hidden = mode !== "all";
      }
      renderRawSearchResults();
      persistDeepSearchSession();
      try {
        const page = await apiPostReadOnlyWithNetworkRetry("/api/search/deep", {
          case_path: currentCasePath(),
          query: $("searchQuery").value,
          evidence_id: $("searchEvidence").value ? Number($("searchEvidence").value) : null,
          include_content: $("includeContent").value === "true",
          // Response page size only. The returned cursor continues through
          // all later matches without retaining an unbounded browser array.
          max_results: searchPageSize(),
          cursor: null,
          max_file_bytes: boundedNumberValue("maxFileBytes", 4096, 1, 4096),
          category: $("searchCategory").value || null,
          file_types: $("searchFileTypes").value || null
        });
        state.searchResults = page.results || [];
        state.searchCursor = page.next_cursor || null;
        state.searchComplete = Boolean(page.complete);
        state.searchCoverage = page.coverage || null;
      } catch (err) {
        // Do NOT abort here: in All mode the bitwise pass is independent of
        // the indexed pass and must still run (a failed indexed pass used to
        // silently skip it, leaving a blank "No results" with no explanation).
        state.searchError = err.message || String(err);
      }
      state.selectedSearchKeys = new Set();
      gridViewState("search");
      renderSearchResults();
      if (mode !== "all") {
        setNotice(
          state.searchError
            ? "Indexed search failed: " + state.searchError
            : indexedPassSummary() + ".",
          Boolean(state.searchError)
        );
        state.searchRunning = false;
        if (runButton) {
          runButton.disabled = false;
          runButton.textContent = "Run Search";
        }
        persistDeepSearchSession();
        return;
      }
      setNotice(indexedPassSummary() + ". Running bitwise whole-disk scan...", Boolean(state.searchError));
      try {
        await runBitwiseForUnifiedSearch();
      } finally {
        state.searchRunning = false;
        if (runButton) {
          runButton.disabled = false;
          runButton.textContent = "Run Search";
        }
      }
    }

    // Which evidence sources the bitwise pass scans: the one selected in the
    // shared Evidence dropdown, or every image/file source when "All evidence"
    // is chosen (record/folder sources have no single raw byte stream to scan).
    function bitwiseEvidenceTargets(evidenceValue) {
      if (!state.data) {
        return [];
      }
      const isScannable = (item) => item.source_kind === "image" || item.source_kind === "file";
      if (evidenceValue) {
        const id = Number(evidenceValue);
        const item = state.data.evidence.find((entry) => entry.id === id);
        return item && isScannable(item) ? [{ id: item.id, name: item.display_name }] : [];
      }
      return state.data.evidence.filter(isScannable).map((item) => ({ id: item.id, name: item.display_name }));
    }

    async function runBitwiseForUnifiedSearch() {
      const query = $("searchQuery").value;
      if (!query.trim()) {
        setNotice("Enter a query to run the bitwise pass.", true);
        return;
      }
      const targets = bitwiseEvidenceTargets($("searchEvidence").value);
      // Preserve each source's scan provenance without duplicating its hits.
      const merged = { hits: [], bytes_scanned: 0, total_size: 0, truncated: false, complete: true, sources: [], multiSource: targets.length > 1, query, provenance: {} };
      if (!targets.length) {
        state.rawSearchResult = merged;
        renderRawSearchResults();
        setNotice(indexedPassSummary() + ". Bitwise pass skipped: the selected evidence has no raw byte stream (only image/file sources can be scanned byte-for-byte).", true);
        return;
      }
      let maxResults;
      try {
        maxResults = searchPageSize();
      } catch (err) {
        setNotice(err.message || String(err), true);
        return;
      }
      // A zero byte limit requests the complete selected evidence stream.
      const maxScanBytes = 0;
      state.rawSearchRunning = true;
      renderRawSearchResults();
      const status = $("rawSearchStatus");
      if (status) {
        status.textContent = "Scanning " + targets.length + " source" + (targets.length === 1 ? "" : "s") + "...";
      }
      for (const target of targets) {
        try {
          const result = await apiPost("/api/search/raw", {
            case_path: currentCasePath(),
            evidence_id: target.id,
            query,
            max_results: maxResults,
            max_scan_bytes: maxScanBytes,
            cursor: null
          });
          const provenance = { ...result };
          delete provenance.hits;
          (result.hits || []).forEach((hit) => merged.hits.push({ ...hit, evidence_id: target.id, evidence_name: target.name, search_provenance: provenance }));
          merged.bytes_scanned += Number(result.bytes_scanned) || 0;
          merged.total_size += Number(result.total_size) || 0;
          merged.truncated = merged.truncated || Boolean(result.truncated);
          merged.complete = merged.complete && Boolean(result.complete);
          merged.provenance[target.id] = provenance;
          merged.sources.push({ evidence_id: target.id, name: target.name, hits: (result.hits || []).length, bytes_scanned: result.bytes_scanned, covered_through: (Number(result.scan_start) || 0) + (Number(result.bytes_scanned) || 0), total_size: result.total_size, truncated: result.truncated, complete: Boolean(result.complete), next_cursor: result.next_cursor || null, stop_reason: result.stop_reason || null, evidence_sha256_hex: result.evidence_sha256_hex || null, coverage: result.coverage || null });
        } catch (err) {
          merged.complete = false;
          merged.sources.push({ evidence_id: target.id, name: target.name, error: err.message || String(err) });
        }
      }
      state.rawSearchRunning = false;
      state.rawSearchResult = merged;
      resetGridView("rawSearch");
      renderRawSearchResults();
      persistDeepSearchSession();
      const errored = merged.sources.filter((source) => source.error);
      const scannedText = formatBytes(merged.bytes_scanned) + " scanned across " + targets.length + " source" + (targets.length === 1 ? "" : "s");
      setNotice(
        indexedPassSummary() + ". Bitwise: " + merged.hits.length.toLocaleString() + " hit(s), " + scannedText +
          bitwiseStopReasonNote(merged) +
          (errored.length ? "; " + errored.length + " source(s) errored" : "") + ".",
        Boolean(state.searchError) || merged.truncated || errored.length > 0
      );
    }

    async function loadMoreRawSearchResults() {
      const merged = state.rawSearchResult;
      if (!merged || state.rawSearchRunning) {
        return;
      }
      const pending = (merged.sources || []).filter((source) => !source.error && source.next_cursor);
      if (!pending.length) {
        return;
      }
      state.rawSearchRunning = true;
      renderRawSearchResults();
      for (const source of pending) {
        try {
          const result = await apiPost("/api/search/raw", {
            case_path: currentCasePath(),
            evidence_id: source.evidence_id,
            query: merged.query,
            max_results: searchPageSize(),
            max_scan_bytes: 0,
            cursor: source.next_cursor
          });
          const provenance = { ...result };
          delete provenance.hits;
          (result.hits || []).forEach((hit) => merged.hits.push({
            ...hit,
            evidence_id: source.evidence_id,
            evidence_name: source.name,
            search_provenance: provenance
          }));
          source.hits += (result.hits || []).length;
          source.bytes_scanned = (Number(source.bytes_scanned) || 0) + (Number(result.bytes_scanned) || 0);
          source.covered_through = Math.max(
            Number(source.covered_through) || 0,
            (Number(result.scan_start) || 0) + (Number(result.bytes_scanned) || 0)
          );
          source.truncated = Boolean(result.truncated);
          source.complete = Boolean(result.complete);
          source.next_cursor = result.next_cursor || null;
          source.stop_reason = result.stop_reason || null;
          source.coverage = result.coverage || source.coverage || null;
          merged.provenance[source.evidence_id] = provenance;
        } catch (err) {
          source.error = err.message || String(err);
        }
      }
      state.rawSearchRunning = false;
      merged.bytes_scanned = (merged.sources || []).reduce(
        (sum, source) => sum + (Number(source.covered_through) || 0),
        0
      );
      merged.complete = (merged.sources || []).every((source) => !source.error && source.complete);
      merged.truncated = !merged.complete;
      renderRawSearchResults();
      persistDeepSearchSession();
      const errored = (merged.sources || []).filter((source) => source.error);
      setNotice(
        "Bitwise: " + merged.hits.length.toLocaleString() + " hit(s) loaded" +
          bitwiseStopReasonNote(merged) +
          (errored.length ? "; " + errored.length + " source(s) errored" : "") + ".",
        merged.truncated || errored.length > 0
      );
    }

    // EA-009: report WHY the bitwise pass stopped rather than a blanket "scan
    // limit". A response-page boundary with a cursor is recoverable; a byte
    // budget or error is incomplete. Uses the backend-reported per-source
    // stop_reason; falls back to the truncated flag for older results.
    function bitwiseStopReasonNote(merged) {
      const sources = (merged && merged.sources) || [];
      if (sources.some((source) => source.next_cursor)) {
        return " (more matches available - use Load more; later hits have not been discarded)";
      }
      const reasons = sources.filter((source) => !source.error).map((source) => source.stop_reason).filter(Boolean);
      if (reasons.includes("result_limit")) {
        return " (response page ended without a continuation; re-run to verify coverage)";
      }
      if (reasons.includes("byte_limit")) {
        return " (stopped at an examiner-selected byte budget; run with an unlimited byte range for full coverage)";
      }
      if (!reasons.length && merged && merged.truncated) {
        return " (stopped early; coverage is incomplete)";
      }
      return merged && merged.complete ? " (complete)" : "";
    }

    async function goToSearchResult(index) {
      const hit = state.searchResults[index];
      if (!hit) {
        setNotice("Search result is no longer loaded.", true);
        return;
      }
      await goToEntryFolder(hit.entry_id);
    }

    // Deep Search queries the case database directly and can return entries
    // anywhere in a large, lazily browsed case - not just ones the examiner
    // has already navigated to. findLoadedEntry() only checks the browser's
    // own in-memory cache, so a fresh /api/entry lookup is the fallback for
    // "Source"/row-click on a hit that isn't cached yet (this used to fail
    // outright with "Entry is not loaded in the current case state.").
    async function goToEntryFolder(entryId) {
      let entry = findLoadedEntry(entryId);
      if (!entry) {
        try {
          entry = await apiGet("/api/entry", { case_path: currentCasePath(), entry_id: entryId });
          state.lookupEntries.set(Number(entry.id), entry);
        } catch (err) {
          setNotice("Could not load entry " + entryId + ": " + err.message, true);
          return;
        }
      }
      const selectedPath = entry.entry_kind === "directory"
        ? normalizeLogicalPath(entry.logical_path)
        : parentLogicalPath(entry.logical_path);
      state.browserState = {
        evidenceId: entry.evidence_id,
        selectedPath,
        treeMode: "filesystem",
        selectedCategory: ""
      };
      expandTreePath(selectedPath);
      state.selectedEntryIds = new Set([entry.id]);
      state.hex = makeHexState(entry.id, 0, numberValue("hexLength", 512));
      $("viewerMode").value = "metadata";
      switchView("analyzeView");
      // Large lazily-browsed cases keep their own folder cache (state.idx),
      // separate from state.browserState. renderEvidenceBrowserEntries()
      // only (re)loads it when the EVIDENCE SOURCE changes, not when only
      // the target folder changes within the same source - so jumping to a
      // specific file here has to explicitly (re)load its folder into
      // state.idx too, the same way normal tree navigation
      // (idxSelectDir/idxRestorePath) does. Without this, the folder pane
      // silently kept showing whatever was loaded before (often just "/")
      // while the inspector on the right correctly showed the new entry.
      if (state.data && state.data.entries_truncated) {
        state.idx = { evidenceId: entry.evidence_id, dirCache: {}, expanded: new Set(["/"]), selPath: "/" };
        try {
          await idxRestorePath(selectedPath);
        } catch (err) {
          setNotice(err.message, true);
          return;
        }
      }
      renderEvidenceBrowserEntries();
      const offset = entryPrimaryOffset(entry);
      const location = offset ? " File starts at " + offset + "." : "";
      setNotice("Opened source for " + (entry.name || logicalName(entry.logical_path)) + "." + location);
    }

    async function bookmarkEvidence(index) {
      const evidence = state.data.evidence[index];
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: "Evidence",
          title: "Evidence: " + evidence.display_name,
          comment: evidence.notes || "",
          bookmark_type: "notable_file",
          data_type: "Evidence Source",
          evidence_id: evidence.id,
          display_name: evidence.display_name,
          logical_path: evidence.source_path,
          item_ref_json: { kind: "evidence_source", source_kind: evidence.source_kind }
        });
        await refresh();
        setNotice("Bookmarked evidence " + evidence.id + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function idxChildToEntry(child) {
      return {
        id: child.entry_id,
        evidence_id: state.idx.evidenceId,
        logical_path: child.logical_path,
        name: child.name,
        entry_kind: child.entry_kind || (child.is_dir ? "directory" : "file"),
        size_bytes: child.size_bytes,
        is_deleted: child.is_deleted,
        metadata_json: child.metadata_json || {}
      };
    }

    function findLoadedEntry(entryId) {
      if (!state.data) {
        return null;
      }
      const inState = state.data.entries.find((item) => item.id === entryId);
      if (inState) {
        return inState;
      }
      const lookedUp = state.lookupEntries && state.lookupEntries.get(Number(entryId));
      if (lookedUp) {
        return lookedUp;
      }
      const inCategory = (state.cat.entries || []).find((item) => item.id === entryId);
      if (inCategory) {
        return inCategory;
      }
      // Entry may have come from the lazy indexed browse cache instead.
      for (const path in state.idx.dirCache) {
        const child = state.idx.dirCache[path].find((item) => item.entry_id === entryId);
        if (child) {
          return idxChildToEntry(child);
        }
      }
      return null;
    }

    async function bookmarkEntry(entryId, refreshAfter = true) {
      // timelineEntryById is a superset of findLoadedEntry (adds the dedicated
      // timeline fetch set), so bookmarking works from the Timeline tab on a
      // large/truncated case too; identical to findLoadedEntry when no timeline
      // is built.
      const entry = typeof timelineEntryById === "function" ? timelineEntryById(entryId) : findLoadedEntry(entryId);
      if (!entry) {
        setNotice("Entry is not loaded.", true);
        return;
      }
      const bookmark = entryBookmarkPayload(entry);
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: bookmark.folderName,
          title: bookmark.title,
          comment: bookmark.comment,
          bookmark_type: bookmark.bookmarkType,
          data_type: bookmark.dataType,
          evidence_id: entry.evidence_id,
          entry_id: entry.id,
          display_name: bookmark.displayName,
          logical_path: entry.logical_path,
          data_preview: bookmark.dataPreview,
          item_ref_json: bookmark.itemRefJson
        });
        if (refreshAfter) {
          await refresh();
          setNotice("Bookmarked entry " + displayPath(entry.logical_path) + ".");
        }
      } catch (err) {
        setNotice(err.message, true);
        if (!refreshAfter) {
          throw err;
        }
      }
    }

    async function bookmarkFolderPath(path, refreshAfter = true) {
      const evidence = selectedEvidenceSource();
      if (!evidence) {
        setNotice("Select an evidence source first.", true);
        return;
      }
      const normalized = normalizeLogicalPath(path || "/");
      const displayName = normalized === "/" ? evidence.display_name : logicalName(normalized);
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: "Evidence Folders",
          title: "Folder: " + displayPath(normalized),
          comment: "Indexed folder path: " + displayPath(normalized),
          bookmark_type: "folder_info",
          data_type: "Evidence Folder",
          evidence_id: evidence.id,
          display_name: displayName,
          logical_path: normalized,
          data_preview: displayPath(normalized),
          item_ref_json: {
            kind: "filesystem_folder",
            evidence_id: evidence.id,
            logical_path: normalized,
            display_name: displayName,
            source_kind: evidence.source_kind,
            source_path: evidence.source_path
          }
        });
        if (refreshAfter) {
          await refresh();
          setNotice("Bookmarked folder " + displayPath(normalized) + ".");
        }
      } catch (err) {
        setNotice(err.message, true);
        if (!refreshAfter) {
          throw err;
        }
      }
    }

    async function bookmarkFolderPathRecursive(path) {
      const evidence = selectedEvidenceSource();
      if (!evidence) {
        setNotice("Select an evidence source first.", true);
        return;
      }
      const normalized = normalizeLogicalPath(path || "/");
      setNotice("Bookmarking " + displayPath(normalized) + " recursively...");
      try {
        const data = await apiPost("/api/bookmark/folder-recursive-indexed", {
          case_path: currentCasePath(),
          evidence_id: evidence.id,
          logical_path: normalized,
          folder_name: "Evidence Folders",
          max_entries: currentRecursiveBookmarkLimit()
        });
        await refresh();
        const partial = [];
        if (data.file_limit_reached) {
          partial.push("the examiner file limit was reached (" + data.total_candidates + " total under this folder)");
        }
        if ((data.skipped_entry_ids || []).length > 0) {
          partial.push(data.skipped_entry_ids.length + " database entr" + (data.skipped_entry_ids.length === 1 ? "y was" : "ies were") + " not added");
        }
        setNotice(
          "Bookmarked " + data.items_added + " file(s) recursively from " + displayPath(normalized) + "." +
            (partial.length ? " Partial result: " + partial.join("; ") + "." : ""),
          partial.length > 0
        );
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function bookmarkCategory(key, refreshAfter = true) {
      const evidence = selectedEvidenceSource();
      if (!evidence) {
        setNotice("Select an evidence source first.", true);
        return;
      }
      const label = categoryLabel(key || "") || "All Categories";
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: "Categories",
          title: "Category: " + label,
          comment: "Indexed category: " + label,
          bookmark_type: "record",
          data_type: "Category",
          evidence_id: evidence.id,
          display_name: label,
          logical_path: "/Categories/" + sanitizeSegment(label) + ".record",
          data_preview: label,
          item_ref_json: {
            kind: "category",
            evidence_id: evidence.id,
            category_key: key || "",
            category_label: label,
            source_kind: evidence.source_kind,
            source_path: evidence.source_path
          }
        });
        if (refreshAfter) {
          await refresh();
          setNotice("Bookmarked category " + label + ".");
        }
      } catch (err) {
        setNotice(err.message, true);
        if (!refreshAfter) {
          throw err;
        }
      }
    }

    async function bookmarkCategoryAndExport(key) {
      await bookmarkCategory(key, false);
      await refresh();
      await exportReport();
    }

    async function bookmarkSearchResult(index) {
      const hit = state.searchResults[index];
      await bookmarkSearchHit(hit, true);
    }

    async function bookmarkSearchHit(hit, refreshAfter = true, casePath = currentCasePath()) {
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: casePath,
          folder_name: "Search Hits",
          title: "Search hit: " + hit.display_name,
          comment: "Match kind: " + hit.match_kind,
          bookmark_type: hit.match_kind === "content" ? "highlighted_data" : "notable_file",
          data_type: "Search Hit",
          evidence_id: hit.evidence_id,
          entry_id: hit.entry_id,
          display_name: hit.display_name,
          logical_path: hit.logical_path,
          selection_offset: hit.selection_offset,
          selection_length: hit.selection_length,
          data_preview: hit.data_preview,
          item_ref_json: searchResultItemRef(hit)
        });
        if (refreshAfter) {
          await refresh();
          setNotice("Bookmarked result " + hit.entry_id + ".");
        }
      } catch (err) {
        setNotice(err.message, true);
        if (!refreshAfter) {
          throw err;
        }
      }
    }

    async function bookmarkSelectedSearchResults() {
      const casePath = state.loadedCasePath;
      if (!casePath || normalizePathInput($("casePath").value) !== casePath) {
        setNotice("The loaded case changed. Reload it before bookmarking search results.", true);
        return;
      }
      const indexedRows = selectedSearchResultRows();
      const rawRows = selectedRawSearchResultRows();
      const remainingIndexedKeys = new Set(state.selectedSearchKeys || []);
      const remainingRawKeys = new Set(state.selectedRawSearchKeys || []);
      if (indexedRows.length + rawRows.length === 0) {
        const selected = remainingIndexedKeys.size + remainingRawKeys.size;
        setNotice(
          selected
            ? "The selected search results are no longer loaded. Re-run the search before bookmarking them."
            : "No indexed or bitwise search results selected.",
          true
        );
        return;
      }
      let succeeded = 0;
      const failedIndexedKeys = [];
      const failedRawKeys = [];
      let lastError = "";
      for (const row of indexedRows) {
        const hit = row.hit;
        if (!hit) {
          failedIndexedKeys.push(row.key);
          lastError = "Search result is no longer loaded.";
          continue;
        }
        try {
          await bookmarkSearchHit(hit, false, casePath);
          succeeded += 1;
          remainingIndexedKeys.delete(row.key);
        } catch (err) {
          failedIndexedKeys.push(row.key);
          lastError = err.message || String(err);
        }
      }
      for (const row of rawRows) {
        try {
          await bookmarkRawSearchHitRecord(row.hit, state.rawSearchResult, false, casePath);
          succeeded += 1;
          remainingRawKeys.delete(row.key);
        } catch (err) {
          failedRawKeys.push(row.key);
          lastError = err.message || String(err);
        }
      }
      if (state.loadedCasePath !== casePath || normalizePathInput($("casePath").value) !== casePath) {
        return;
      }
      state.selectedSearchKeys = remainingIndexedKeys;
      state.selectedRawSearchKeys = remainingRawKeys;
      const refreshed = await refresh();
      if (!refreshed || state.loadedCasePath !== casePath) {
        return;
      }
      renderSearchResults();
      renderRawSearchResults();
      persistDeepSearchSession();
      const failed = failedIndexedKeys.length + failedRawKeys.length;
      const unavailable = Math.max(0, remainingIndexedKeys.size + remainingRawKeys.size - failed);
      if (failed || unavailable) {
        const failureSummary = failed
          ? failed + " failed" + (lastError ? ": " + lastError : "")
          : "";
        const unavailableSummary = unavailable
          ? unavailable + " selected result" + (unavailable === 1 ? " is" : "s are") + " no longer loaded"
          : "";
        setNotice(
          "Bookmarked " + succeeded + " selected search result" + (succeeded === 1 ? "" : "s") + "; "
            + [failureSummary, unavailableSummary].filter(Boolean).join("; ") + ".",
          true
        );
        return;
      }
      setNotice("Bookmarked " + succeeded + " selected search result" + (succeeded === 1 ? "" : "s") + " into the report.");
    }

    async function clearFindings() {
      const bookmarkCount = state.data ? state.data.bookmarks.length : 0;
      const reportCount = state.data ? state.data.report.folders.length : 0;
      if (bookmarkCount === 0 && reportCount === 0) {
        setNotice("No findings to clear.");
        return;
      }
      if (!window.confirm("Clear all bookmarks and report findings for this case? Evidence and indexed entries stay attached.")) {
        return;
      }
      try {
        const cleared = await apiPost("/api/findings/clear", {
          case_path: currentCasePath()
        });
        await refresh();
        setNotice("Cleared " + cleared.removed_bookmarks + " bookmarks and " + cleared.removed_items + " bookmarked items.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function removeBookmarkUi(bookmarkId, label) {
      const title = label || ("bookmark " + bookmarkId);
      if (!window.confirm("Remove bookmark \"" + title + "\" from this case and report?")) {
        return;
      }
      try {
        const removed = await apiPost("/api/bookmark/remove", {
          case_path: currentCasePath(),
          bookmark_id: bookmarkId
        });
        await refresh();
        setNotice("Removed bookmark " + bookmarkId + " and " + removed.removed_items + " item" + (removed.removed_items === 1 ? "" : "s") + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function removeBookmarkItemUi(itemId, label) {
      const title = label || ("item " + itemId);
      if (!window.confirm("Remove bookmarked item \"" + title + "\" from this bookmark?")) {
        return;
      }
      try {
        const removed = await apiPost("/api/bookmark/item/remove", {
          case_path: currentCasePath(),
          item_id: itemId
        });
        await refresh();
        setNotice("Removed bookmarked item " + removed.item_id + " from bookmark " + removed.bookmark_id + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function toggleSearchResultSelection(index, selected) {
      const hit = state.searchResults[index];
      if (!hit) {
        renderSearchSelectionCount();
        return;
      }
      const key = searchResultKey(hit);
      if (selected) {
        state.selectedSearchKeys.add(key);
      } else {
        state.selectedSearchKeys.delete(key);
      }
      renderSearchSelectionCount();
      persistDeepSearchSession();
    }

    function selectAllSearchResults() {
      state.selectedSearchKeys = new Set(visibleSearchResultRows().map((row) => row.key));
      state.selectedRawSearchKeys = new Set(visibleRawSearchResultRows().map((row) => row.key));
      renderSearchResults();
      renderRawSearchResults();
      persistDeepSearchSession();
    }

    function clearSelectedSearchResults() {
      state.selectedSearchKeys = new Set();
      state.selectedRawSearchKeys = new Set();
      state.lastRawSearchKey = null;
      renderSearchResults();
      renderRawSearchResults();
      persistDeepSearchSession();
    }

    // Re-run the classifier over the existing indexed entries (fast DB-only
    // pass, no image re-read) so category changes show up without re-indexing.
    async function recategorizeCase() {
      const btn = $("recategorizeBtn");
      if (btn) { btn.disabled = true; }
      setNotice("Re-categorizing indexed entries (re-running the classifier, no re-indexing)...");
      try {
        const data = await apiPost("/api/case/recategorize", { case_path: currentCasePath() });
        await refresh();
        setNotice("Re-categorized " + Number(data.entries_updated || 0).toLocaleString() + " entries with the current classifier.");
      } catch (err) {
        setNotice("Re-categorize failed: " + err.message, true);
      } finally {
        if (btn) { btn.disabled = false; }
      }
    }

    async function exportReport() {
      try {
        const data = await apiPost("/api/report/export", {
          case_path: currentCasePath(),
          output_path: currentReportPath()
        });
        state.lastReportPath = data.report;
        if (data.report) {
          const nextPath = normalizePathInput(data.report);
          $("reportPath").value = nextPath;
          state.lastReportPath = nextPath;
        }
        await refresh();
        // Show the FULL-FILE digest: it is what sha256sum/certutil reproduce.
        // The embedded footer digest only covers bytes before the footer.
        setNotice(
          "Wrote report " + data.report
          + (data.report_file_sha256 ? " (file SHA-256 " + data.report_file_sha256 + ")" : "")
          + "."
        );
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function openReport() {
      const reportPath = normalizePathInput(state.lastReportPath || currentReportPath());
      state.lastReportPath = reportPath;
      $("reportPath").value = reportPath;
      try {
        await apiPost("/api/report/open", {
          case_path: currentCasePath(),
          output_path: reportPath
        });
        setNotice("Opened report.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function renderState() {
      const data = state.data;
      $("caseTitle").textContent = data.case.name;
      $("caseMeta").textContent = "Examiner: " + (data.case.examiner_name || "unknown") + " | Created: " + data.case.created_at;
      // Category refresh is maintenance, not a daily control: only offer it
      // when the loaded entry sample shows categories stamped by an OLDER
      // classifier than this build (re-processing always stamps the current
      // one, so a freshly processed case never shows the button).
      const staleCategories = (data.entries || []).some((entry) => {
        const source = entry.metadata_json && entry.metadata_json.category_source;
        return source && source !== BOOTSTRAP.classifierVersion;
      });
      const recategorizeButton = $("recategorizeBtn");
      if (recategorizeButton) {
        recategorizeButton.hidden = !staleCategories;
      }
      $("statEvidence").textContent = data.evidence.length;
      $("statEntries").textContent = data.entry_count;
      $("statBookmarks").textContent = data.bookmarks.length;
      $("statReport").textContent = data.report.folders.length;
      if (!data.evidence.some((item) => item.id === state.browserState.evidenceId)) {
        const treeMode = state.browserState.treeMode || "filesystem";
        state.browserState = {
          evidenceId: data.evidence.length > 0 ? data.evidence[0].id : null,
          selectedPath: "/",
          treeMode,
          selectedCategory: ""
        };
      }
      pruneSelectedEntries();
      if (state.timeline.casePath && state.timeline.casePath !== state.casePath) {
        state.timeline = newTimelineState();
      }
      if (!state.timeline.casePath) {
        state.timeline.casePath = state.casePath;
      }
      if (state.timeline.built) {
        rebuildTimelineEvents();
      }
      syncDateFilterInputs();
      renderDashboard();
      renderEvidence();
      renderEvidenceBrowserEntries();
      renderTimeline();
      renderSearchEvidence();
      renderBookmarks();
      renderReport();
    }

    function pendingViewerInteger(value, fallback, minimum, maximum) {
      if (value === "" || value === null || value === undefined) {
        return fallback;
      }
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed)) {
        return fallback;
      }
      return Math.min(maximum, Math.max(minimum, parsed));
    }

    async function restorePendingViewerTarget(pending, evidence) {
      if (!pending || !pending.viewerTarget || !evidence) {
        return;
      }
      const offset = pendingViewerInteger(pending.viewerOffset, 0, 0, Number.MAX_SAFE_INTEGER);
      const length = pendingViewerInteger(pending.viewerLength, 512, 16, 8 * 1024 * 1024);
      if (pending.viewerTarget === "live") {
        if (!state.live.active || Number(state.live.evidenceId) !== Number(evidence.id)) {
          return;
        }
        const volume = pendingViewerInteger(
          pending.viewerVolume || pending.liveVolume,
          0,
          0,
          Number.MAX_SAFE_INTEGER
        );
        const path = normalizeLogicalPath(pending.viewerPath || "/");
        state.hex = makeHexState(null, offset, length);
        state.hex.live = {
          evidenceId: evidence.id,
          volume,
          path,
          name: pending.viewerName || logicalName(path) || "file"
        };
      } else if (pending.viewerTarget === "raw") {
        const size = pendingViewerInteger(
          pending.viewerSize,
          evidence.size_bytes == null ? null : Number(evidence.size_bytes),
          0,
          Number.MAX_SAFE_INTEGER
        );
        state.hex = makeHexState(null, offset, length);
        state.hex.byteContext = "filesystem";
        state.hex.raw = {
          evidenceId: evidence.id,
          name: pending.viewerName || evidence.display_name || "Raw bytes",
          logicalPath: pending.viewerLogicalPath || "[raw] " + (evidence.display_name || "evidence"),
          startOffset: pendingViewerInteger(
            pending.viewerStartOffset,
            0,
            0,
            Number.MAX_SAFE_INTEGER
          ),
          volume: pending.viewerVolume === ""
            ? null
            : pendingViewerInteger(pending.viewerVolume, null, 0, Number.MAX_SAFE_INTEGER),
          sizeBytes: size
        };
      } else if (pending.viewerTarget === "entry") {
        const entryId = pendingViewerInteger(pending.viewerEntryId, 0, 1, Number.MAX_SAFE_INTEGER);
        if (!entryId) {
          return;
        }
        await goToEntryFolder(entryId);
        if (!state.hex || Number(state.hex.entryId) !== entryId) {
          return;
        }
        state.hex.offset = offset;
        state.hex.length = length;
      } else {
        return;
      }

      const viewerMode = ["hex", "text", "metadata"].includes(pending.viewerMode)
        ? pending.viewerMode
        : "hex";
      $("viewerMode").value = viewerMode;
      $("hexOffset").value = String(offset);
      $("hexLength").value = String(length);
      await fetchEntryBytes();
      const selectionStart = pendingViewerInteger(
        pending.viewerSelectionStart,
        -1,
        0,
        Number.MAX_SAFE_INTEGER
      );
      const selectionEnd = pendingViewerInteger(
        pending.viewerSelectionEnd,
        -1,
        0,
        Number.MAX_SAFE_INTEGER
      );
      if (selectionStart >= 0 && selectionEnd >= selectionStart) {
        state.hex.selStart = selectionStart;
        state.hex.selEnd = selectionEnd;
        renderHexViewer();
      }
      setInspectorCollapsed(false);
    }

    async function applyPendingAnalysisSelection() {
      const pending = state.pendingAnalysisSelection;
      if (!pending || pending.applied || pending.applying || !state.data) {
        return;
      }
      const requested = pending.evidenceId;
      const evidence = state.data.evidence.find((item) => item.id === requested)
        || state.data.evidence.find((item) => item.id === state.browserState.evidenceId)
        || state.data.evidence[0];
      pending.applying = true;
      try {
        if (evidence) {
          if (pending.treeMode === "live") {
            await applyAnalyzeLocation({
              evidenceId: evidence.id,
              treeMode: "live",
              selectedPath: pending.selectedPath || "/",
              selectedCategory: "",
              liveVolume: pending.liveVolume || "0"
            });
          } else {
            selectEvidenceSource(evidence.id, pending.selectedPath || preferredAnalysisPath(evidence.id));
          }
          if (pending.treeMode === "categories") {
            selectCategory(pending.selectedCategory || "");
          }
          await restorePendingViewerTarget(pending, evidence);
        } else {
          switchView("analyzeView");
        }
        pending.applied = true;
      } finally {
        pending.applying = false;
      }
    }

    function renderEmptyState() {
      $("caseTitle").textContent = "No case loaded";
      $("caseMeta").textContent = "";
      $("statEvidence").textContent = "0";
      $("statEntries").textContent = "0";
      $("statBookmarks").textContent = "0";
      $("statReport").textContent = "0";
      renderDashboard();
      $("evidenceTable").innerHTML = empty("No evidence.");
      $("filesystemTree").innerHTML = empty("No evidence selected.");
      $("entryTable").innerHTML = empty("No entries.");
      $("treeCount").textContent = "0";
      $("folderTitle").textContent = "/";
      $("selectedCount").textContent = "0 selected";
      state.browserState = { evidenceId: null, selectedPath: "/", treeMode: "filesystem", selectedCategory: "" };
      state.expandedTreePaths = new Map();
      state.selectedEntryIds = new Set();
      setCurrentEntryGrid("", []);
      setCurrentLiveGrid("", []);
      state.cat = newCategoryCache();
      state.timeline = newTimelineState();
      state.hex = makeHexState();
      renderHexViewer();
      renderTimeline();
      $("bookmarksTable").innerHTML = empty("No bookmarks.");
      $("reportPreview").textContent = "{}";
      $("reportCount").textContent = "0 folders";
    }

    function renderDashboard() {
      if (!state.data) {
        $("dashboardCaseOverview").innerHTML = empty("Load or create a case to see dashboard details.");
        $("dashboardEvidenceOverview").innerHTML = empty("No evidence sources.");
        $("dashboardArtifactCategories").innerHTML = empty("No artifact categories.");
        return;
      }
      $("dashboardCaseOverview").innerHTML = renderDashboardCaseOverview(state.data);
      $("dashboardEvidenceOverview").innerHTML = renderDashboardEvidenceOverview(state.data);
      $("dashboardArtifactCategories").innerHTML = renderDashboardArtifactCategories(state.data);
    }

    function renderDashboardCaseOverview(data) {
      const facts = [
        ["Case name", data.case.name],
        ["Case number", data.case.case_number || "unspecified"],
        ["Case type", data.case.case_type || "unspecified"],
        ["Examiner", data.case.examiner_name || "unknown"],
        ["Created", data.case.created_at || "unknown"],
        ["Timezone", data.case.timezone || "unknown"],
        ["Evidence sources", data.evidence.length],
        ["Indexed entries", data.entry_count],
        ["Bookmarks", data.bookmarks.length]
      ];
      const description = data.case.description
        ? `<p class="muted tiny dashboard-description">${escapeHtml(data.case.description)}</p>`
        : "";
      return `<div class="dashboard-facts">${facts.map(([label, value]) => dashboardFact(label, value)).join("")}</div>${description}`;
    }

    function dashboardFact(label, value) {
      return `<div class="dashboard-fact"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
    }

    function renderDashboardEvidenceOverview(data) {
      if (data.evidence.length === 0) {
        return empty("No evidence sources attached.");
      }
      // Exact per-evidence counts come from the report rows (SQL COUNT);
      // the shipped entry list is capped on large cases.
      const reportCounts = new Map((data.report && data.report.evidence || [])
        .map((row) => [row.id, row.entries_indexed]));
      const sampleCounts = evidenceEntryCounts(data.entries);
      const rows = data.evidence.map((item) => {
        const entryCount = reportCounts.has(item.id)
          ? reportCounts.get(item.id)
          : (sampleCounts.get(item.id) || 0);
        const indexed = item.indexed_at
          ? escapeHtml(item.indexed_at)
          : evidenceProcessingStatusHtml(item, entryCount);
        return `
          <tr>
            <td><strong>${escapeHtml(item.display_name)}</strong><br><span class="muted tiny">${escapeHtml(item.source_path)}</span></td>
            <td><span class="pill">${escapeHtml(item.source_kind)}</span></td>
            <td>${item.size_bytes == null ? '<span class="muted tiny">unknown</span>' : escapeHtml(formatBytes(item.size_bytes))}</td>
            <td>${escapeHtml(Number(entryCount).toLocaleString())}</td>
            <td>${indexed}</td>
          </tr>`;
      }).join("");
      return `<div class="dashboard-table-wrap">${table(["Source", "Kind", "Size", "Entries", "Indexed"], rows)}</div>`;
    }

    function evidenceEntryCounts(entries) {
      const counts = new Map();
      entries.forEach((entry) => {
        counts.set(entry.evidence_id, (counts.get(entry.evidence_id) || 0) + 1);
      });
      return counts;
    }

    function evidenceIndexedEntryCount(evidenceId) {
      if (!state.data) {
        return 0;
      }
      const reportRow = (state.data.report && state.data.report.evidence || [])
        .find((row) => row.id === evidenceId);
      if (reportRow) {
        return Number(reportRow.entries_indexed) || 0;
      }
      return evidenceEntryCounts(state.data.entries).get(evidenceId) || 0;
    }

    function evidenceProcessingStatusText(item, entryCount = evidenceIndexedEntryCount(item.id)) {
      if (item.indexed_at) {
        return "indexed";
      }
      if (item.read_file_system_requested && (Number(entryCount) > 0 || item.last_job_status === "truncated")) {
        return "partially indexed";
      }
      return "attached";
    }

    function evidenceProcessingStatusHtml(item, entryCount = evidenceIndexedEntryCount(item.id)) {
      const status = evidenceProcessingStatusText(item, entryCount);
      // content_indexed === false: the latest index was run metadata-only, so
      // Deep Search content matching cannot see this evidence. Say so where
      // the examiner picks evidence, not just in the job log.
      const metadataOnly = item.content_indexed === false
        ? ' <span class="pill warn" title="The latest index for this evidence was metadata-only (Capture file content was off). Deep Search content matching is unavailable until it is re-processed with content on.">metadata-only</span>'
        : "";
      if (status === "indexed") {
        return '<span class="pill good">indexed</span>' + metadataOnly;
      }
      if (status === "partially indexed") {
        return '<span class="pill warn">partially indexed</span>' + metadataOnly;
      }
      return '<span class="pill warn">attached</span>' + metadataOnly;
    }

    function renderDashboardArtifactCategories(data) {
      const categories = serverCategoryCountsAvailable()
        ? serverDashboardCategoryCounts(data.category_counts)
        : dashboardCategoryCounts(data.entries);
      if (categories.length === 0) {
        return empty("No indexed artifact categories.");
      }
      const maxCount = categories[0].count || 1;
      const rows = categories.map((category) => {
        const width = Math.max(4, Math.round((category.count / maxCount) * 100));
        return `<button class="dashboard-category-row" onclick="jumpToDashboardCategory('${escapeAttr(escapeJs(category.main))}')" title="Open ${escapeAttr(category.main)} in Analyze categories">
          <span class="dashboard-category-label">${escapeHtml(category.main)}</span>
          <span class="dashboard-category-bar" aria-hidden="true"><span style="--bar-width:${width}%"></span></span>
          <span class="dashboard-category-count">${category.count.toLocaleString()}</span>
        </button>`;
      }).join("");
      return `<div class="dashboard-category-list">${rows}</div>`;
    }

    // Exact SQL counts are shipped whenever the compact physical Entries
    // snapshot cannot represent Categories completely, including small cases
    // with parser-derived records that intentionally exist only in Categories.
    function serverCategoryCountsAvailable() {
      return Boolean(state.data
        && Array.isArray(state.data.category_counts) && state.data.category_counts.length > 0);
    }

    function serverDashboardCategoryCounts(categoryCounts) {
      const counts = new Map();
      categoryCounts.forEach((row) => {
        counts.set(row.main, (counts.get(row.main) || 0) + row.count);
      });
      return Array.from(counts.entries())
        .map(([main, count]) => ({ main, count }))
        .sort((left, right) => right.count - left.count || left.main.localeCompare(right.main));
    }

    function dashboardCategoryCounts(entries) {
      const counts = new Map();
      categorizedVisibleEntries(entries).forEach((entry) => {
        const main = dashboardEntryMainCategory(entry);
        counts.set(main, (counts.get(main) || 0) + 1);
      });
      return Array.from(counts.entries())
        .map(([main, count]) => ({ main, count }))
        .sort((left, right) => right.count - left.count || left.main.localeCompare(right.main));
    }

    function dashboardEntryMainCategory(entry) {
      const metadata = entry.metadata_json || {};
      return metadata.category_main ? String(metadata.category_main) : entryCategory(entry).main;
    }

    function jumpToDashboardCategory(mainName) {
      if (!state.data) {
        switchView("analyzeView");
        return;
      }
      const evidenceId = dashboardEvidenceIdForCategory(mainName);
      if (evidenceId && state.browserState.evidenceId !== evidenceId) {
        state.browserState.evidenceId = evidenceId;
        state.browserState.selectedPath = preferredAnalysisPath(evidenceId);
        state.selectedEntryIds = new Set();
        state.lastSelectedEntryId = null;
      }
      selectCategory(categoryKey(mainName, ""));
      switchView("analyzeView");
    }

    function dashboardEvidenceIdForCategory(mainName) {
      const matchesCategory = (entry) => dashboardEntryMainCategory(entry) === mainName;
      const currentEvidenceId = state.browserState.evidenceId;
      if (currentEvidenceId && state.data.entries.some((entry) => entry.evidence_id === currentEvidenceId && matchesCategory(entry))) {
        return currentEvidenceId;
      }
      const match = state.data.entries.find(matchesCategory);
      if (match) {
        return match.evidence_id;
      }
      return currentEvidenceId || (state.data.evidence[0] && state.data.evidence[0].id) || null;
    }

    function evidenceGridColumns() {
      return [
        { key: "source", label: "Source", sortable: true, filterable: true, sortType: "text" },
        { key: "kind", label: "Kind", sortable: true, filterable: true, sortType: "text" },
        { key: "status", label: "Status", sortable: true, filterable: true, sortType: "text" },
        { key: "actions", label: "", sortable: false, filterable: false, sortType: "none" }
      ];
    }

    function evidenceGridRow(item, evidenceIndex) {
      return {
        item,
        evidenceIndex,
        values: {
          source: compactParts([item.display_name, item.source_path, item.sha256_hex ? "SHA-256: " + item.sha256_hex : ""]),
          kind: item.source_kind,
          status: compactParts([evidenceProcessingStatusText(item), item.sha256_hex ? "hashed" : ""])
        }
      };
    }

    function renderEvidenceGridRow(row) {
      const item = row.item;
      return `
        <tr>
          <td><strong>${escapeHtml(item.display_name)}</strong><br><span class="muted tiny">${escapeHtml(item.source_path)}</span>${item.sha256_hex ? `<br><span class="muted tiny" title="SHA-256 computed ${escapeAttr(item.hashed_at || "")}">SHA-256: ${escapeHtml(item.sha256_hex)}</span>` : ""}</td>
          <td><span class="pill">${escapeHtml(item.source_kind)}</span></td>
          <td>${evidenceProcessingStatusHtml(item)}${item.sha256_hex ? ' <span class="pill good">hashed</span>' : ""}</td>
          <td class="actions">
            <div class="toolbar">
              ${indexedBrowseButtonHtml(item)}
              ${liveBrowseButtonHtml(item)}
              ${processActionHtml(item)}
              ${item.source_kind === "folder" || item.source_kind === "browser_history" ? "" : `<button class="ghost" onclick="hashEvidence(${item.id})">${item.sha256_hex ? "Re-hash" : "Hash"}</button>`}
              ${item.source_kind === "image" ? `<button class="ghost" onclick="carveEvidence(${item.id})">Carve</button>` : ""}
              <button class="ghost" onclick="bookmarkEvidence(${row.evidenceIndex})">Bookmark</button>
              <button class="ghost danger" onclick="removeEvidence(${item.id})">Remove</button>
            </div>
          </td>
        </tr>`;
    }

    function renderEvidence() {
      const rows = state.data.evidence.map((item, index) => evidenceGridRow(item, index));
      if (rows.length === 0) {
        $("evidenceTable").innerHTML = empty("No evidence.");
        return;
      }
      const columns = evidenceGridColumns();
      const tableResult = sortableGridTable("evidence", columns, rows, "", renderEvidenceGridRow);
      const filterStatus = gridFilterStatusHtml("evidence", columns, tableResult.visibleRows.length, rows.length, "evidence sources");
      $("evidenceTable").innerHTML = filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No evidence sources match the column filters."));
    }

    async function carveEvidence(id) {
      const gib = window.prompt("Signature-carve decoded image data. Scan how many GiB from the start? Leave blank for the whole image.", "");
      if (gib === null) {
        return;
      }
      const trimmedGib = gib.trim();
      const parsed = Number(trimmedGib);
      if (trimmedGib && (!Number.isFinite(parsed) || parsed <= 0)) {
        setNotice("Carve scan limit must be a positive number of GiB, or blank for the whole image.", true);
        return;
      }
      const fileLimitText = window.prompt("Maximum carved files to record? Leave blank for unlimited.", "");
      if (fileLimitText === null) {
        return;
      }
      const trimmedFileLimit = fileLimitText.trim();
      const parsedFileLimit = Number(trimmedFileLimit);
      if (trimmedFileLimit && (!Number.isSafeInteger(parsedFileLimit) || parsedFileLimit <= 0)) {
        setNotice("Carved-file limit must be a positive whole number, or blank for unlimited.", true);
        return;
      }
      const maxScanBytes = trimmedGib ? Math.round(parsed * 1024 * 1024 * 1024) : 0;
      if (trimmedGib && !Number.isSafeInteger(maxScanBytes)) {
        setNotice("Carve scan limit is too large to represent exactly; use a smaller GiB value or blank for the whole image.", true);
        return;
      }
      const maxFiles = trimmedFileLimit ? parsedFileLimit : 0;
      setNotice("Carving evidence " + id + " (scanning image for file signatures)...");
      try {
        const data = await apiPost("/api/evidence/carve", {
          case_path: currentCasePath(),
          evidence_id: id,
          max_scan_bytes: maxScanBytes,
          max_files: maxFiles
        });
        await refresh();
        selectEvidenceSource(id, "/Image Analysis/Carved");
        const reasons = data.truncation_reasons || [];
        setNotice("Carved " + data.carved_files + " file(s) from " + formatBytes(data.bytes_scanned)
          + " (" + (data.status || (data.truncated ? "truncated" : "completed")) + ")."
          + (reasons.length ? " Truncation reason: " + reasons.join("; ") + "." : ""), data.truncated);
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function hashEvidence(id) {
      setNotice("Hashing evidence " + id + " (reads the full source; large images take a while)...");
      try {
        const data = await apiPost("/api/evidence/hash", {
          case_path: currentCasePath(),
          evidence_id: id
        });
        await refresh();
        setNotice("Evidence " + id + " SHA-256: " + data.sha256_hex + " (" + formatBytes(data.bytes_hashed) + " hashed).");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    function processActionHtml(item) {
      if (item.source_kind === "browser_history") {
        return `<button disabled>Imported</button>`;
      }
      if (item.source_kind === "image" || looksLikeDiskImage(item.source_path)) {
        return `<button class="secondary" onclick="processEvidence(${item.id})">Analyze image</button>`;
      }
      return `<button class="ghost" onclick="processEvidence(${item.id})">Process</button>`;
    }

    function indexedBrowseButtonHtml(item) {
      if (evidenceIndexedEntryCount(item.id) === 0) {
        return "";
      }
      return `<button class="secondary" onclick="selectEvidenceSource(${item.id}, preferredAnalysisPath(${item.id}))" title="Open the processed filesystem index and derived categories for this evidence.">View index</button>`;
    }

    function supportsLiveBrowseEvidence(item) {
      return !!item && (item.source_kind === "image" || item.source_kind === "folder" || item.source_kind === "file");
    }

    function liveBrowseButtonHtml(item) {
      if (!supportsLiveBrowseEvidence(item)) {
        return "";
      }
      const title = item.source_kind === "image"
        ? "Browse the complete image read-only without indexing. Index limits affect Deep Search, Categories, Bookmarks, and Reports, not this direct source view."
        : "Browse the complete attached source read-only without indexing. Index limits affect Deep Search, Categories, Bookmarks, and Reports, not this direct source view.";
      return `<button class="secondary" onclick="liveBrowseEvidence(${item.id})" title="${escapeAttr(title)}">Browse source</button>`;
    }

    function liveBrowseUnavailableMessage(evidence) {
      if (!evidence) {
        return "Select an evidence source, then Browse source.";
      }
      return "Browse source is available for disk images, folders, and single files; selected source is " + evidence.source_kind + ".";
    }

    function liveBrowseReadyNotice(evidence) {
      if (evidence.source_kind === "image") {
        return "Browsing " + evidence.display_name + " directly from the image - no indexing.";
      }
      if (evidence.source_kind === "folder") {
        return "Browsing " + evidence.display_name + " as it is on disk right now - no indexing.";
      }
      return "Browsing " + evidence.display_name + " directly from the file - no indexing.";
    }

    function looksLikeDiskImage(path) {
      return /\.(e01|ex01|l01|raw|dd|img|vdi|vmdk|vhd|vhdx|aff4|iso)$/i.test(path || "");
    }

    function preferredAnalysisPath(evidenceId) {
      if (!state.data) {
        return "/";
      }
      const entries = state.data.entries
        .filter((entry) => entry.evidence_id === evidenceId)
        .map((entry) => ({ ...entry, logical_path: normalizeLogicalPath(entry.logical_path) }));
      const volume = entries.find((entry) =>
        entry.entry_kind === "directory"
        && entry.metadata_json
        && entry.metadata_json.artifact_kind === "filesystem_volume"
      );
      if (volume) {
        return volume.logical_path;
      }
      if (entries.some((entry) => entry.logical_path.startsWith("/Image Analysis/Volumes/"))) {
        return "/Image Analysis/Volumes";
      }
      if (entries.some((entry) => entry.logical_path.startsWith("/Image Analysis/Partitions/"))) {
        return "/Image Analysis/Partitions";
      }
      return "/";
    }

    function pruneSelectedEntries() {
      if (!state.data) {
        state.selectedEntryIds = new Set();
        return;
      }
      const valid = new Set(state.data.entries.map((entry) => entry.id));
      for (const path in state.idx.dirCache) {
        state.idx.dirCache[path].forEach((child) => {
          if (child.entry_id != null) {
            valid.add(child.entry_id);
          }
        });
      }
      (state.cat.entries || []).forEach((entry) => valid.add(entry.id));
      state.selectedEntryIds = new Set(Array.from(state.selectedEntryIds).filter((id) => valid.has(id)));
    }

    function liveKey(volume, path) {
      return volume + "|" + path;
    }

    // Evidence-row shortcut: jump straight into live browse for one source
    // (attach-only evidence needs no indexing to be examined).
    async function liveBrowseEvidence(id) {
      if (state.live.active) {
        state.live = { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
      }
      selectEvidenceSource(id);
      await toggleLiveBrowse();
    }

    async function toggleLiveBrowse() {
      const evidence = selectedEvidenceSource();
      if (state.live.active) {
        const previous = currentAnalyzeLocation();
        state.live = { active: false, evidenceId: null, volumes: [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
        renderEvidenceBrowserEntries();
        setNotice("Source browse closed.");
        commitAnalyzeNavigation(previous);
        return;
      }
      if (!supportsLiveBrowseEvidence(evidence)) {
        setNotice(liveBrowseUnavailableMessage(evidence), true);
        return;
      }
      const previous = currentAnalyzeLocation();
      // Live browsing is a direct filesystem view. Categories are derived
      // only from the persisted index and therefore cannot be represented by
      // the same live directory rows.
      state.browserState.treeMode = "filesystem";
      state.browserState.selectedCategory = "";
      const initialLiveState = state.live;
      let openedLiveState = null;
      setNotice(evidence.source_kind === "image"
        ? "Reading volumes from " + evidence.display_name + "..."
        : "Opening live view for " + evidence.display_name + "...");
      try {
        const data = await loadLiveVolumes(evidence.id);
        if (state.live !== initialLiveState || !selectedEvidenceIdentityMatches(evidence)) {
          return;
        }
        openedLiveState = { active: true, evidenceId: evidence.id, volumes: data.volumes || [], dirCache: {}, expanded: new Set(), selKey: null, selected: new Map(), lastKey: null };
        state.live = openedLiveState;
        const first = openedLiveState.volumes.find((volume) => volume.browsable);
        if (first) {
          const entries = await liveLoadDir(first.index, "/");
          if (entries === null || state.live !== openedLiveState) {
            return;
          }
          openedLiveState.expanded.add(liveKey(first.index, "/"));
          openedLiveState.selKey = liveKey(first.index, "/");
        }
        state.liveGuidanceExpiresAt = Date.now() + 7000;
        renderEvidenceBrowserEntries();
        if (state.live !== openedLiveState || !selectedEvidenceIdentityMatches(evidence)) {
          return;
        }
        setNotice(liveBrowseReadyNotice(evidence));
        commitAnalyzeNavigation(previous);
      } catch (err) {
        if (!selectedEvidenceIdentityMatches(evidence)
          || (state.live !== initialLiveState && state.live !== openedLiveState)) {
          return;
        }
        state.live = newLiveBrowseState();
        setNotice(err.message, true);
        // Fall back to the attached-source placeholder (matters when live
        // browse was auto-started for an un-indexed image).
        renderEvidenceBrowserEntries();
      }
    }

    async function liveLoadDir(volume, path) {
      const key = liveKey(volume, path);
      const liveState = state.live;
      const evidenceId = liveState.evidenceId;
      liveState.dirPaging = liveState.dirPaging || {};
      if (!liveState.dirCache[key]) {
        const data = await apiGet("/api/image/dir", {
          case_path: currentCasePath(),
          evidence_id: evidenceId,
          volume: volume,
          path: path,
          limit: 1000
        });
        if (state.live !== liveState || state.live.evidenceId !== evidenceId) {
          return null;
        }
        liveState.dirCache[key] = data.entries || [];
        liveState.dirPaging[key] = {
          nextCursor: data.next_cursor || null,
          totalEntries: Number(data.total_entries || (data.entries || []).length),
          loading: false
        };
      }
      return liveState.dirCache[key];
    }

    async function liveLoadMore(volume, path) {
      const key = liveKey(volume, path);
      const liveState = state.live;
      liveState.dirPaging = liveState.dirPaging || {};
      const paging = liveState.dirPaging[key];
      if (!paging || !paging.nextCursor || paging.loading) {
        return;
      }
      paging.loading = true;
      try {
        const cursor = paging.nextCursor;
        const data = await apiGet("/api/image/dir", {
          case_path: currentCasePath(),
          evidence_id: liveState.evidenceId,
          volume: volume,
          path: path,
          limit: 1000,
          after_name: cursor.name,
          after_is_dir: Boolean(cursor.is_dir)
        });
        if (state.live !== liveState) {
          return;
        }
        const existing = liveState.dirCache[key] || [];
        const seen = new Set(existing.map((entry) => (entry.is_dir ? "d:" : "f:") + entry.name));
        (data.entries || []).forEach((entry) => {
          const identity = (entry.is_dir ? "d:" : "f:") + entry.name;
          if (!seen.has(identity)) {
            seen.add(identity);
            existing.push(entry);
          }
        });
        liveState.dirCache[key] = existing;
        paging.nextCursor = data.next_cursor || null;
        paging.totalEntries = Number(data.total_entries || existing.length);
      } catch (err) {
        if (state.live === liveState) {
          setNotice("Could not load the next live-directory page: " + err.message, true);
        }
      } finally {
        paging.loading = false;
        if (state.live === liveState) {
          renderLiveBrowse();
        }
      }
    }

    async function liveToggleDir(volume, path) {
      const key = liveKey(volume, path);
      if (state.live.expanded.has(key)) {
        state.live.expanded.delete(key);
      } else {
        const liveState = state.live;
        try {
          const entries = await liveLoadDir(volume, path);
          if (entries === null || state.live !== liveState) { return; }
        } catch (err) {
          if (state.live !== liveState) { return; }
          setNotice(err.message, true);
          return;
        }
        state.live.expanded.add(key);
      }
      renderLiveBrowse();
    }

    async function liveSelectDir(volume, path, recordNavigation = true) {
      const previous = currentAnalyzeLocation();
      const liveState = state.live;
      try {
        const entries = await liveLoadDir(volume, path);
        if (entries === null || state.live !== liveState) { return; }
      } catch (err) {
        if (state.live !== liveState) { return; }
        setNotice(err.message, true);
        return;
      }
      state.live.selKey = liveKey(volume, path);
      state.live.expanded.add(state.live.selKey);
      renderLiveBrowse();
      if (recordNavigation) {
        commitAnalyzeNavigation(previous);
      } else {
        updateAnalyzeNavButtons();
      }
    }

    function liveChildPath(path, name) {
      return path === "/" ? "/" + name : path + "/" + name;
    }

    async function openLiveFile(volume, path, name) {
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      state.hex.live = { evidenceId: state.live.evidenceId, volume: volume, path: path, name: name };
      // Pictures open straight into Details so the inspector shows the image;
      // everything else keeps the hex-first flow.
      const image = isImageEntry(currentHexEntry());
      $("viewerMode").value = image ? "metadata" : "hex";
      $("hexOffset").value = "0";
      await fetchEntryBytes();
      setInspectorCollapsed(false);
    }

    async function openLiveRawDevice() {
      const evidence = state.data && state.data.evidence.find((item) => item.id === state.live.evidenceId);
      state.hex = makeHexState(null, 0, numberValue("hexLength", 512));
      state.hex.byteContext = "filesystem";
      state.hex.raw = {
        evidenceId: state.live.evidenceId,
        name: "Whole device (raw)",
        logicalPath: "[device] Whole device (raw)",
        startOffset: 0,
        volume: null,
        sizeBytes: evidence && evidence.size_bytes != null ? evidence.size_bytes : null
      };
      $("viewerMode").value = "hex";
      $("hexOffset").value = "0";
      await fetchEntryBytes();
      setInspectorCollapsed(false);
    }

    async function openLiveVolumeRaw(volumeIndex) {
      const volume = (state.live.volumes || []).find((item) => Number(item.index) === Number(volumeIndex));
      if (!volume) {
        setNotice("Volume is no longer loaded.", true);
        return;
      }
      const startOffset = Number(volume.start_offset || 0);
      state.hex = makeHexState(null, startOffset, numberValue("hexLength", 512));
      state.hex.byteContext = "filesystem";
      state.hex.raw = {
        evidenceId: state.live.evidenceId,
        name: volume.name + " raw bytes",
        logicalPath: "[vol " + volume.index + "] " + volume.name + " raw bytes",
        startOffset,
        volume: volume.index,
        sizeBytes: volume.size_bytes == null ? null : Number(volume.size_bytes)
      };
      $("viewerMode").value = "hex";
      $("hexOffset").value = String(startOffset);
      await fetchEntryBytes();
      setInspectorCollapsed(false);
    }

    function liveEntryByPath(volume, path) {
      const normalized = normalizeLogicalPath(path || "/");
      const slash = normalized.lastIndexOf("/");
      const parent = slash <= 0 ? "/" : normalized.slice(0, slash);
      const name = slash < 0 ? normalized : normalized.slice(slash + 1);
      const entries = state.live.dirCache[liveKey(volume, parent)] || [];
      return entries.find((entry) => entry.name === name) || null;
    }

    function liveBookmarkItemRef(volume, path, name, isDir) {
      const entry = liveEntryByPath(volume, path) || {};
      const evidence = selectedEvidenceSource() || (state.data && state.data.evidence.find((item) => item.id === state.live.evidenceId)) || {};
      const volumeInfo = (state.live.volumes || []).find((item) => Number(item.index) === Number(volume)) || {};
      const logicalPath = "[vol " + volume + "] " + path;
      const metadata = {
        source_kind: evidence.source_kind || "",
        source_path: evidence.source_path || "",
        source_display_name: evidence.display_name || "",
        volume_index: volume,
        volume_name: volumeInfo.name || "",
        volume_filesystem: volumeInfo.filesystem || "",
        volume_start_offset: volumeInfo.start_offset,
        volume_size_bytes: volumeInfo.size_bytes,
        created_utc: entry.created_utc,
        modified_utc: entry.modified_utc,
        accessed_utc: entry.accessed_utc,
        ntfs_file_record_number: entry.ntfs_file_record_number,
        mft_record_logical_offset: entry.mft_record_logical_offset,
        mft_record_physical_offset: entry.mft_record_physical_offset,
        file_data_logical_offset: entry.file_data_logical_offset,
        file_data_physical_offset: entry.file_data_physical_offset,
        ntfs_mft_record_modification_time_utc: entry.ntfs_mft_record_modification_time_utc,
        symlink: Boolean(entry.symlink)
      };
      return {
        kind: isDir ? "live_dir" : "live_file",
        entry_kind: isDir ? "directory" : "file",
        evidence_id: state.live.evidenceId,
        logical_path: logicalPath,
        relative_path: path,
        display_name: name,
        volume: volume,
        path: path,
        volume_name: volumeInfo.name || "",
        filesystem: volumeInfo.filesystem || "",
        volume_start_offset: volumeInfo.start_offset,
        volume_size_bytes: volumeInfo.size_bytes,
        size_bytes: entry.size_bytes == null ? null : entry.size_bytes,
        created_utc: entry.created_utc,
        modified_utc: entry.modified_utc,
        accessed_utc: entry.accessed_utc,
        ntfs_file_record_number: entry.ntfs_file_record_number,
        mft_record_logical_offset: entry.mft_record_logical_offset,
        mft_record_physical_offset: entry.mft_record_physical_offset,
        file_data_logical_offset: entry.file_data_logical_offset,
        file_data_physical_offset: entry.file_data_physical_offset,
        ntfs_mft_record_modification_time_utc: entry.ntfs_mft_record_modification_time_utc,
        is_deleted: false,
        symlink: Boolean(entry.symlink),
        file_extension: isDir ? "" : fileExtension(name || path),
        metadata
      };
    }

    function liveBookmarkPreview(volume, path, name, isDir) {
      const entry = liveEntryByPath(volume, path) || {};
      return compactParts([
        isDir ? "Live folder" : "Live file",
        entry.size_bytes == null ? "" : formatBytes(entry.size_bytes),
        entry.modified_utc ? "modified " + entry.modified_utc : "",
        entry.created_utc ? "created " + entry.created_utc : "",
        entry.accessed_utc ? "accessed " + entry.accessed_utc : ""
      ]) || (isDir ? "Live folder" : "Live file");
    }

    async function postLiveBookmark(volume, path, name, isDir) {
      const itemRef = liveBookmarkItemRef(volume, path, name, isDir);
      await apiPost("/api/bookmark/quick", {
        case_path: currentCasePath(),
        folder_name: "Source Browse",
        title: name,
        bookmark_type: isDir ? "folder_info" : "notable_file",
        data_type: isDir ? "Live folder" : "Live file",
        evidence_id: state.live.evidenceId,
        logical_path: "[vol " + volume + "] " + path,
        display_name: name,
        data_preview: liveBookmarkPreview(volume, path, name, isDir),
        item_ref_json: itemRef
      });
    }

    async function bookmarkLiveItem(volume, path, name, isDir) {
      try {
        await postLiveBookmark(volume, path, name, isDir);
        await refresh();
        state.live.active = true;
        renderEvidenceBrowserEntries();
        setNotice("Bookmarked " + (isDir ? "folder " : "") + name + " from the source browse.");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function bookmarkLiveFolderRecursive(volume, path, name) {
      setNotice("Bookmarking " + (name || path) + " recursively (live)...");
      try {
        const data = await apiPost("/api/bookmark/folder-recursive-live", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume: volume,
          path: path,
          folder_name: "Source Browse",
          max_entries: currentRecursiveBookmarkLimit()
        });
        await refresh();
        state.live.active = true;
        renderEvidenceBrowserEntries();
        const partial = [];
        if (data.file_limit_reached) {
          partial.push("the examiner file limit was reached");
        }
        if (data.skipped_count > 0) {
          const sample = Array.isArray(data.skipped) && data.skipped.length ? ": " + data.skipped[0] : "";
          partial.push(data.skipped_count + " item(s) could not be traversed" + sample);
        }
        setNotice(
          "Bookmarked " + data.items_added + " file(s) recursively from " + (name || path) + "." +
            (partial.length ? " Partial result: " + partial.join("; ") + "." : ""),
          Boolean(data.truncated)
        );
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // ---- Live selection (checkboxes, ranges) and bulk actions ----

    function visibleLiveEntries() {
      if (state.currentLiveGrid && state.currentLiveGrid.gridId === "live") {
        return state.currentLiveGrid.items || [];
      }
      const selected = state.live.selKey;
      if (!selected) {
        return [];
      }
      const selPath = selected.split("|").slice(1).join("|");
      const selVolume = Number(selected.split("|")[0]);
      return (state.live.dirCache[selected] || []).map((entry) => ({
        volume: selVolume,
        path: liveChildPath(selPath, entry.name),
        name: entry.name,
        is_dir: entry.is_dir,
        symlink: Boolean(entry.symlink)
      }));
    }

    function selectedVisibleLiveItems() {
      const selected = state.live && state.live.selected ? state.live.selected : new Map();
      return visibleLiveEntries().filter((item) => selected.has(liveKey(item.volume, item.path)));
    }

    function setLiveSelection(item, selected) {
      const key = liveKey(item.volume, item.path);
      if (selected) {
        state.live.selected.set(key, item);
      } else {
        state.live.selected.delete(key);
      }
    }

    function toggleLiveSelection(volume, path, name, isDir, checked, event) {
      const item = { volume: volume, path: path, name: name, is_dir: isDir };
      const key = liveKey(volume, path);
      if (event && event.shiftKey && state.live.lastKey) {
        selectLiveRange(state.live.lastKey, key, true);
      } else {
        setLiveSelection(item, checked);
      }
      state.live.lastKey = key;
      renderLiveBrowse();
    }

    function selectLiveRange(fromKey, toKey, selected) {
      const visible = visibleLiveEntries();
      const keys = visible.map((item) => liveKey(item.volume, item.path));
      const fromIndex = keys.indexOf(fromKey);
      const toIndex = keys.indexOf(toKey);
      if (fromIndex === -1 || toIndex === -1) {
        return;
      }
      const [start, end] = fromIndex <= toIndex ? [fromIndex, toIndex] : [toIndex, fromIndex];
      for (let index = start; index <= end; index += 1) {
        setLiveSelection(visible[index], selected);
      }
    }

    function clearLiveSelection() {
      state.live.selected = new Map();
      state.live.lastKey = null;
      renderLiveBrowse();
      setNotice("Selection cleared.");
    }

    function handleLiveRowClick(event, volume, path, name, isDir, symlink = false) {
      hideContextMenu();
      const key = liveKey(volume, path);
      if (event.ctrlKey || event.metaKey) {
        toggleLiveSelection(volume, path, name, isDir, !state.live.selected.has(key), null);
        state.live.lastKey = key;
        return;
      }
      if (event.shiftKey && state.live.lastKey) {
        selectLiveRange(state.live.lastKey, key, true);
        state.live.lastKey = key;
        renderLiveBrowse();
        return;
      }
      if (symlink) {
        setNotice("Browse lists symlinks but does not follow them.", true);
        return;
      }
      if (isDir) {
        liveSelectDir(volume, path);
      } else {
        openLiveFile(volume, path, name);
        renderLiveBrowse();
      }
    }

    const LIVE_BOOKMARK_BATCH_LIMIT = 300;

    async function bookmarkSelectedLive() {
      hideContextMenu();
      const items = selectedVisibleLiveItems();
      if (items.length === 0) {
        setNotice("No source items selected.", true);
        return;
      }
      if (items.length > LIVE_BOOKMARK_BATCH_LIMIT) {
        setNotice("Too many items selected (" + items.length + "). Bookmark at most " + LIVE_BOOKMARK_BATCH_LIMIT + " at a time; bookmark the parent folder instead.", true);
        return;
      }
      let done = 0;
      let failed = 0;
      for (const item of items) {
        try {
          await postLiveBookmark(item.volume, item.path, item.name, item.is_dir);
          done += 1;
        } catch (err) {
          failed += 1;
        }
      }
      await refresh();
      state.live.active = true;
      renderEvidenceBrowserEntries();
      setNotice("Bookmarked " + done + " live item(s)" + (failed ? ", " + failed + " failed" : "") + ".");
    }

    function describeLiveTreePartial(data) {
      const issues = [];
      if (data.file_limit_reached) {
        issues.push("examiner file limit reached" + (data.file_limit ? " (" + data.file_limit + ")" : ""));
      }
      const oversized = Number(data.oversized_files_skipped || 0);
      if (oversized > 0) {
        issues.push(
          oversized + " oversized file(s) exceeded the protective per-file limit of " +
          formatBytes(Number(data.protective_file_size_limit_bytes || 0))
        );
      }
      const otherSkipped = Math.max(0, Number(data.skipped_count || 0) - oversized);
      if (otherSkipped > 0) {
        issues.push(otherSkipped + " other item(s) skipped after a traversal or read error");
      }
      if (data.truncated && issues.length === 0) {
        issues.push("partial export");
      }
      if (Array.isArray(data.skipped) && data.skipped.length > 0) {
        issues.push("first reason: " + data.skipped[0]);
      }
      return issues.join("; ");
    }

    async function exportSelectedLive() {
      hideContextMenu();
      const items = selectedVisibleLiveItems();
      if (items.length === 0) {
        setNotice("No source items selected.", true);
        return;
      }
      const root = BOOTSTRAP.workspaceRoot || ".";
      let files = 0;
      let bytes = 0;
      let failures = [];
      let index = 0;
      for (const item of items) {
        index += 1;
        setNotice("Exporting " + index + "/" + items.length + ": " + item.name + "...");
        try {
          if (item.is_dir) {
            const outputDir = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
              "live-tree-" + safeFileName(item.name)
            ]);
            const data = await apiPost("/api/image/export-tree", {
              case_path: currentCasePath(),
              evidence_id: state.live.evidenceId,
              volume: item.volume,
              path: item.path,
              output_dir: outputDir
            });
            files += data.files_exported;
            bytes += data.bytes_written;
            if (data.truncated || data.skipped_count > 0) {
              failures.push(item.name + ": " + describeLiveTreePartial(data));
            }
          } else {
            const outputPath = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
              "live-vol" + item.volume + "-" + safeFileName(item.name)
            ]);
            const data = await apiPost("/api/image/export", {
              case_path: currentCasePath(),
              evidence_id: state.live.evidenceId,
              volume: item.volume,
              path: item.path,
              output_path: outputPath
            });
            files += 1;
            bytes += data.bytes_written;
          }
        } catch (err) {
          failures.push(item.name + ": " + err.message);
        }
      }
      const problems = failures.length ? " Issues: " + failures.slice(0, 5).join(" | ") : "";
      setNotice("Exported " + files + " file(s), " + formatBytes(bytes) + " to ui-output\\exported." + problems, failures.length > 0);
    }

    async function exportLiveTree(volume, path, name) {
      hideContextMenu();
      const root = BOOTSTRAP.workspaceRoot || ".";
      const outputDir = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
        "live-tree-" + safeFileName(name || "vol" + volume)
      ]);
      setNotice("Exporting folder " + (name || path) + " recursively...");
      try {
        const data = await apiPost("/api/image/export-tree", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume: volume,
          path: path,
          output_dir: outputDir
        });
        const partial = describeLiveTreePartial(data);
        setNotice(
          "Exported " + data.files_exported + " file(s), " + formatBytes(data.bytes_written) +
          " to " + data.output_dir + " (manifest with SHA-256 written)." +
          (partial ? " Partial result: " + partial + "." : ""),
          Boolean(data.truncated)
        );
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // Right-click a browser profile folder in Live Browse (a Firefox profile
    // dir, or a Chromium "Default"/"Profile N" dir) to parse its real history/
    // bookmarks/logins/cookies straight out of the image - no manual export
    // step. Stages the folder server-side into a temp dir, runs the existing
    // History/places.sqlite parser against it, and cleans up automatically
    // (see api_import_history_from_image in kdft-ui).
    async function importLiveFolderAsBrowserHistory(volume, path, name) {
      hideContextMenu();
      setNotice("Importing browser history from " + (name || path) + "...");
      try {
        const data = await apiPost("/api/history/import-from-image", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume: volume,
          image_path: path,
          max_visits: nonNegativeNumberValue("historyMaxVisits", 0),
          evidence_name: name || undefined
        });
        await refresh();
        const partial = [];
        if (data.visit_limit_reached) {
          partial.push("the examiner visit limit was reached");
        }
        if (data.artifact_limit_reached) {
          const limitedKinds = (data.limited_artifact_kinds || []).join(", ");
          partial.push("the examiner per-artifact row limit was reached" +
            (limitedKinds ? " for " + limitedKinds : ""));
        }
        if (Number(data.parse_error_count || 0) > 0) {
          partial.push(Number(data.parse_error_count).toLocaleString() + " parser/staging error(s) disclosed");
        }
        setNotice(
          "Imported browser history from " + (name || path) + ": " +
          data.entries_indexed.toLocaleString() + " record(s) (" +
          data.visits_indexed.toLocaleString() + " visits, " +
          data.bookmarks_indexed.toLocaleString() + " bookmarks)." +
          (partial.length ? " Partial result: " + partial.join("; ") + "." : ""),
          Boolean(data.truncated)
        );
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // ---- Live context menu ----

    function hideContextMenu() {
      const menu = $("ctxMenu");
      if (menu) {
        menu.hidden = true;
      }
    }

    function ctxItem(label, call) {
      return `<button onclick="hideContextMenu(); ${call}">${escapeHtml(label)}</button>`;
    }

    function showLiveContextMenu(event, volume, path, name, isDir) {
      event.preventDefault();
      event.stopPropagation();
      const menu = $("ctxMenu");
      if (!menu) {
        return;
      }
      const escPath = escapeAttr(escapeJs(path));
      const escName = escapeAttr(escapeJs(name));
      const args = `${volume}, '${escPath}', '${escName}'`;
      const selCount = selectedVisibleLiveItems().length;
      const rows = [];
      if (isDir) {
        rows.push(ctxItem("Open folder", `liveSelectDir(${volume}, '${escPath}')`));
        rows.push(ctxItem("Bookmark folder", `bookmarkLiveItem(${args}, true)`));
        rows.push(ctxItem("Bookmark folder (recursive)", `bookmarkLiveFolderRecursive(${args})`));
        rows.push(ctxItem("Export folder (recursive)", `exportLiveTree(${args})`));
        rows.push(ctxItem("Import as browser history", `importLiveFolderAsBrowserHistory(${volume}, '${escPath}', '${escName}')`));
      } else {
        rows.push(ctxItem("View bytes", `openLiveFile(${args})`));
        rows.push(ctxItem("Bookmark file", `bookmarkLiveItem(${args}, false)`));
        rows.push(ctxItem("Export file", `exportLiveFile(${args})`));
      }
      if (selCount > 0) {
        rows.push('<div class="sep"></div>');
        rows.push(ctxItem("Bookmark selected (" + selCount + ")", "bookmarkSelectedLive()"));
        rows.push(ctxItem("Export selected (" + selCount + ")", "exportSelectedLive()"));
        rows.push(ctxItem("Clear selection", "clearLiveSelection()"));
      }
      openContextMenu(menu, rows, event);
    }

    function openContextMenu(menu, rows, event) {
      menu.innerHTML = rows.join("");
      menu.hidden = false;
      const menuRect = menu.getBoundingClientRect();
      const x = Math.min(event.clientX, window.innerWidth - menuRect.width - 8);
      const y = Math.min(event.clientY, window.innerHeight - menuRect.height - 8);
      menu.style.left = Math.max(4, x) + "px";
      menu.style.top = Math.max(4, y) + "px";
    }

    function entrySelectionCtxRows(rows) {
      const selCount = selectedEntriesForActions().length;
      if (selCount > 0) {
        rows.push('<div class="sep"></div>');
        rows.push(ctxItem("Bookmark selected (" + selCount + ")", "bookmarkSelectedEntries()"));
        rows.push(ctxItem("Report selected (" + selCount + ")", "bookmarkSelectionAndExportReport()"));
        const fileCount = selectedFileEntryCount();
        if (fileCount > 0) {
          rows.push(ctxItem("Export file bytes (" + fileCount + ")", "exportSelectedEntries()"));
        }
        rows.push(ctxItem("Export selected as CSV (" + selCount + ")", "exportSelectedCsv()"));
        rows.push(ctxItem("Export selected as TSV (" + selCount + ")", "exportSelectedArtifacts('tsv')"));
        rows.push(ctxItem("Clear selection", "clearEntrySelection()"));
      }
    }

    function showEntryContextMenu(event, entryId) {
      const entry = findLoadedEntry(entryId);
      const menu = $("ctxMenu");
      if (!entry || !menu) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const rows = [];
      if (entry.entry_kind === "directory") {
        const escLogicalPath = escapeAttr(escapeJs(entry.logical_path));
        rows.push(ctxItem("Open folder", `selectFolder('${escLogicalPath}')`));
        rows.push(ctxItem("Bookmark folder", `bookmarkEntry(${entryId})`));
        rows.push(ctxItem("Bookmark folder (recursive)", `bookmarkFolderPathRecursive('${escLogicalPath}')`));
      } else {
        rows.push(ctxItem("View bytes", `openEntry(${entryId})`));
        rows.push(ctxItem("Details", `selectBrowserEntry(${entryId})`));
        if (canOpenEntryExternally(entry)) {
          rows.push(ctxItem("Open file", `openSelectedEntryExternal(${entryId})`));
        }
        if (entry.entry_kind === "file" && isPromotableDiskImageEntry(entry, evidenceSourceForEntry(entry))) {
          rows.push(ctxItem("Analyze image", `analyzeDiskImageEntry(${entryId})`));
        }
        rows.push(ctxItem("Bookmark", `bookmarkEntry(${entryId})`));
        if (entry.entry_kind === "file") {
          rows.push(ctxItem(recoveryActionText(entry).button, `recoverEntry(${entryId})`));
        }
        rows.push(ctxItem("Go to folder", `goToEntryFolder(${entryId})`));
      }
      entrySelectionCtxRows(rows);
      openContextMenu(menu, rows, event);
    }

    // With in-lane Source/Bookmark buttons removed, right-click is the
    // action surface for search hits (row click still navigates to source).
    function showSearchResultContextMenu(event, index) {
      const menu = $("ctxMenu");
      if (!menu || !Number.isFinite(index)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      openContextMenu(menu, [
        ctxItem("Go to source", `goToSearchResult(${index})`),
        ctxItem("Bookmark hit", `bookmarkSearchResult(${index})`)
      ], event);
    }

    function showRawHitContextMenu(event, index) {
      const menu = $("ctxMenu");
      if (!menu || !Number.isFinite(index)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      openContextMenu(menu, [
        ctxItem("Open in hex viewer", `openRawHitInHex(${index})`),
        ctxItem("Bookmark hit", `bookmarkRawSearchHit(${index})`)
      ], event);
    }

    function showFolderContextMenu(event, path, idxDir, entryId) {
      const menu = $("ctxMenu");
      if (!menu) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const escPath = escapeAttr(escapeJs(path));
      const rows = [ctxItem("Open folder", idxDir ? `idxSelectDir('${escPath}')` : `selectFolder('${escPath}')`)];
      const numericEntryId = Number(entryId);
      if (Number.isFinite(numericEntryId) && numericEntryId > 0) {
        rows.push(ctxItem("Bookmark folder", `bookmarkEntry(${numericEntryId})`));
      } else {
        rows.push(ctxItem("Bookmark folder", `bookmarkFolderPath('${escPath}')`));
      }
      rows.push(ctxItem("Bookmark folder (recursive)", `bookmarkFolderPathRecursive('${escPath}')`));
      entrySelectionCtxRows(rows);
      openContextMenu(menu, rows, event);
    }

    function showCategoryContextMenu(event, key) {
      const menu = $("ctxMenu");
      if (!menu) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const escKey = escapeAttr(escapeJs(key || ""));
      const rows = [
        ctxItem("Open category", `selectCategory('${escKey}')`),
        ctxItem("Bookmark category", `bookmarkCategory('${escKey}')`),
        ctxItem("Bookmark + export report", `bookmarkCategoryAndExport('${escKey}')`)
      ];
      if (key) {
        rows.push('<div class="sep"></div>');
        rows.push(ctxItem("Export category artifact sheet (CSV)", `exportCategoryArtifacts('${escKey}', 'csv')`));
        rows.push(ctxItem("Export category artifact sheet (TSV)", `exportCategoryArtifacts('${escKey}', 'tsv')`));
      }
      entrySelectionCtxRows(rows);
      openContextMenu(menu, rows, event);
    }

    // One delegated handler covers every indexed surface (File System rows,
    // Categories incl. server-backed pages, lazy browse, search results,
    // thumbnails). Live rows keep their inline handler, which stops
    // propagation before this one runs.
    function handleGlobalContextMenu(event) {
      const target = event.target;
      if (!target || !target.closest) {
        return;
      }
      if (target.closest("input, textarea, select, #ctxMenu")) {
        return;
      }
      const categoryRow = target.closest("[data-category-key]");
      if (categoryRow) {
        showCategoryContextMenu(event, categoryRow.dataset.categoryKey || "");
        return;
      }
      // Search-result and bitwise-hit rows come BEFORE the generic entry-id
      // branch: with in-lane buttons removed, right-click is their action
      // surface, and search rows also carry data-entry-id.
      const searchRow = target.closest("[data-search-index]");
      if (searchRow) {
        showSearchResultContextMenu(event, Number(searchRow.dataset.searchIndex));
        return;
      }
      const rawHitRow = target.closest("[data-raw-hit-index]");
      if (rawHitRow) {
        showRawHitContextMenu(event, Number(rawHitRow.dataset.rawHitIndex));
        return;
      }
      const timelineRow = target.closest("[data-timeline-event-index]");
      if (timelineRow) {
        const entryId = Number(timelineRow.dataset.entryId);
        if (Number.isFinite(entryId)) {
          showTimelineContextMenu(event, entryId, timelineRow.dataset.timelineEventIndex);
        }
        return;
      }
      const entryRow = target.closest("[data-entry-id]");
      if (entryRow) {
        const entryId = Number(entryRow.dataset.entryId);
        if (Number.isFinite(entryId)) {
          showEntryContextMenu(event, entryId);
        }
        return;
      }
      const idxDirRow = target.closest("[data-idx-dir]");
      if (idxDirRow) {
        showFolderContextMenu(event, idxDirRow.dataset.idxDir, true, idxDirRow.dataset.folderEntryId);
        return;
      }
      const folderRow = target.closest("[data-folder-path]");
      if (folderRow) {
        showFolderContextMenu(event, folderRow.dataset.folderPath, false, folderRow.dataset.folderEntryId);
      }
    }

    async function exportLiveFile(volume, path, name) {
      const root = BOOTSTRAP.workspaceRoot || ".";
      const outputPath = joinLocalPath(joinLocalPath(root, ["ui-output", "exported"]), [
        "live-vol" + volume + "-" + safeFileName(name)
      ]);
      const evidence = state.data && state.data.evidence.find((item) => item.id === state.live.evidenceId);
      setNotice("Exporting " + name + (evidence && evidence.source_kind === "image" ? " from the image..." : " from the attached source..."));
      try {
        const data = await apiPost("/api/image/export", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume: volume,
          path: path,
          output_path: outputPath
        });
        setNotice("Exported " + name + " to " + data.output_path + " (" + formatBytes(data.bytes_written) + ", SHA-256 " + data.sha256_hex.slice(0, 16) + "...).");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    // Attached, un-indexed evidence opens directly in live browsing. Attempt
    // this once per evidence source.
    function maybeAutoLiveBrowse(evidence) {
      if (!supportsLiveBrowseEvidence(evidence) || state.live.active) {
        return false;
      }
      if (evidence.indexed_at) {
        return false;
      }
      state.liveAutoTried = state.liveAutoTried || new Set();
      if (state.liveAutoTried.has(evidence.id)) {
        return false;
      }
      state.liveAutoTried.add(evidence.id);
      $("filesystemTree").innerHTML = empty(evidence.source_kind === "image" ? "Reading volumes from the image..." : "Opening live source...");
      $("entryTable").innerHTML = empty(evidence.source_kind === "image" ? "Reading the attached image directly (no indexing)..." : "Reading the attached source directly (no indexing)...");
      toggleLiveBrowse();
      return true;
    }

    function renderLiveDirRows(volume, path, depth, rows) {
      const dirKey = liveKey(volume, path);
      const entries = state.live.dirCache[dirKey] || [];
      entries.filter((entry) => entry.is_dir).forEach((entry) => {
        const childPath = liveChildPath(path, entry.name);
        const key = liveKey(volume, childPath);
        const expanded = state.live.expanded.has(key);
        const active = state.live.selKey === key ? " active" : "";
        rows.push(`<button class="tree-row${active}" style="--depth:${depth}" onclick="liveSelectDir(${volume}, '${escapeAttr(escapeJs(childPath))}')" title="${escapeAttr(childPath)}">
          <span class="tree-toggle can-toggle" onclick="event.stopPropagation(); liveToggleDir(${volume}, '${escapeAttr(escapeJs(childPath))}')">${expanded ? "-" : "+"}</span>
          <span class="tree-label">${escapeHtml(entry.name)}</span>
          <span class="muted tiny"></span>
        </button>`);
        if (expanded) {
          renderLiveDirRows(volume, childPath, depth + 1, rows);
        }
      });
      const paging = state.live.dirPaging && state.live.dirPaging[dirKey];
      if (paging && paging.nextCursor) {
        rows.push(`<button class="tree-row" style="--depth:${depth}" onclick="liveLoadMore(${volume}, '${escapeAttr(escapeJs(path))}')"${paging.loading ? " disabled" : ""}>
          <span class="tree-toggle"></span>
          <span class="tree-label">Load more...</span>
          <span class="muted tiny">${entries.length.toLocaleString()} / ${paging.totalEntries.toLocaleString()}</span>
        </button>`);
      }
    }

    function liveGridColumns() {
      return [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" },
        { key: "name", label: "Name", sortable: true, filterable: true, sortType: "text" },
        { key: "type", label: "Type", sortable: true, filterable: true, sortType: "text" },
        { key: "size", label: "Size", sortable: true, filterable: true, sortType: "number" },
        { key: "modified", label: "Modified", sortable: true, filterable: true, sortType: "time" }
      ];
    }

    function liveGridRow(entry, selVolume, selPath, viewedPath) {
      const childPath = liveChildPath(selPath, entry.name);
      const type = entry.symlink ? "Symlink" : (entry.is_dir ? "Folder" : "File");
      const size = entry.size_bytes == null ? "" : formatBytes(entry.size_bytes);
      const modified = entry.modified_utc || entry.created_utc || "";
      return {
        entry,
        item: {
          volume: selVolume,
          path: childPath,
          name: entry.name,
          is_dir: entry.is_dir,
          symlink: Boolean(entry.symlink)
        },
        key: liveKey(selVolume, childPath),
        viewed: viewedPath === childPath,
        values: {
          name: entry.name,
          type,
          size,
          modified
        },
        sortValues: {
          size: entry.size_bytes == null ? NaN : Number(entry.size_bytes),
          modified: Date.parse(modified)
        }
      };
    }

    function renderLiveGridRow(row) {
      const entry = row.entry;
      const escChild = escapeAttr(escapeJs(row.item.path));
      const escName = escapeAttr(escapeJs(entry.name));
      const isChecked = state.live.selected.has(row.key);
      const rowClasses = "entry-row" + (isChecked ? " multi-selected" : "") + (row.viewed ? " selected" : "");
      const rowArgs = `event, ${row.item.volume}, '${escChild}', '${escName}', ${entry.is_dir}, ${entry.symlink ? "true" : "false"}`;
      return `<tr class="${rowClasses}" onclick="handleLiveRowClick(${rowArgs})" oncontextmenu="showLiveContextMenu(${rowArgs})">
          <td><input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleLiveSelection(${row.item.volume}, '${escChild}', '${escName}', ${entry.is_dir}, this.checked, event)"></td>
          <td><span class="entry-name">${escapeHtml(entry.name)}</span></td>
          <td class="entry-kind">${escapeHtml(row.values.type)}</td>
          <td class="entry-size">${row.values.size}</td>
          <td class="entry-time">${escapeHtml(row.values.modified)}</td>
        </tr>`;
    }

    function isLiveImageEntry(entry) {
      if (!entry || entry.is_dir) {
        return false;
      }
      const name = String(entry.name || "").toLowerCase();
      return [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"]
        .some((ext) => name.endsWith(ext));
    }

    function liveImageRawUrl(evidenceId, volume, path) {
      return "/api/image/raw?case_path=" + encodeURIComponent(currentCasePath())
        + "&evidence_id=" + encodeURIComponent(String(evidenceId))
        + "&volume=" + encodeURIComponent(String(volume))
        + "&path=" + encodeURIComponent(path);
    }

    function renderLiveThumbnailContents(rows, evidenceId) {
      const cards = rows.map((row) => {
        const entry = row.entry;
        const item = row.item;
        const escPath = escapeAttr(escapeJs(item.path));
        const escName = escapeAttr(escapeJs(item.name));
        const isChecked = state.live.selected.has(row.key);
        const selectedRow = row.viewed ? " selected" : "";
        const rowArgs = `event, ${item.volume}, '${escPath}', '${escName}', false, ${entry.symlink ? "true" : "false"}`;
        return `<div class="thumb-card entry-row${selectedRow}${isChecked ? " multi-selected" : ""}"
          onclick="openLiveFile(${item.volume}, '${escPath}', '${escName}')"
          oncontextmenu="showLiveContextMenu(${rowArgs})" title="${escapeAttr(item.path)}">
          <input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleLiveSelection(${item.volume}, '${escPath}', '${escName}', false, this.checked, event)">
          <div class="thumb-frame"><img loading="lazy" src="${escapeAttr(liveImageRawUrl(evidenceId, item.volume, item.path))}" alt="" onerror="this.parentElement.classList.add('thumb-broken')"></div>
          <div class="thumb-name">${escapeHtml(item.name)}</div>
          <div class="thumb-meta muted tiny">${entry.size_bytes == null ? "" : escapeHtml(formatBytes(entry.size_bytes))}</div>
        </div>`;
      });
      return `<div class="thumb-toolbar"><button class="ghost" onclick="setPictureViewMode('list')">List view</button></div><div class="thumb-grid">${cards.join("")}</div>`;
    }

    function renderLiveBrowse() {
      renderTreeModeControls();
      const evidence = state.data && state.data.evidence.find((item) => item.id === state.live.evidenceId);
      const localLive = evidence && (evidence.source_kind === "folder" || evidence.source_kind === "file");
      $("treeTitle").textContent = localLive ? "Attached source" : "Volumes";
      $("browserTitle").textContent = (evidence ? evidence.display_name : "Image") + " | browse";
      const rows = [];
      if (evidence && evidence.source_kind === "image") {
        const rawActive = state.hex.raw && state.hex.raw.volume == null ? " active" : "";
        rows.push(`<button class="tree-row${rawActive}" style="--depth:0" onclick="openLiveRawDevice()" title="Decoded image byte stream; this is not an additional filesystem volume">
          <span class="tree-toggle"></span>
          <span class="tree-label">Image bytes (raw; not a volume)</span>
          <span class="muted tiny">Open byte view</span>
        </button>`);
      }
      state.live.volumes.forEach((volume) => {
        const key = liveKey(volume.index, "/");
        const expanded = state.live.expanded.has(key);
        const active = (state.live.selKey === key || (state.hex.raw && Number(state.hex.raw.volume) === Number(volume.index))) ? " active" : "";
        const toggle = volume.browsable
          ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); liveToggleDir(${volume.index}, '/')">${expanded ? "-" : "+"}</span>`
          : `<span class="tree-toggle"></span>`;
        const click = volume.browsable ? `onclick="liveSelectDir(${volume.index}, '/')"` : "";
        rows.push(`<button class="tree-row${active}" style="--depth:0" ${click} title="${escapeAttr(volume.filesystem + " " + formatBytes(volume.size_bytes))}">
          ${toggle}
          <span class="tree-label">${escapeHtml(volume.name)} <span class="muted tiny">${escapeHtml(volume.filesystem)}</span></span>
          <span class="muted tiny" onclick="event.stopPropagation(); openLiveVolumeRaw(${volume.index})">View raw bytes</span>
        </button>`);
        if (volume.bitlocker) {
          rows.push(bitlockerStatusRow(volume));
        }
        if (volume.browsable && expanded) {
          renderLiveDirRows(volume.index, "/", 1, rows);
        }
      });
      // Count filesystem volumes only. The separate raw-image byte stream is
      // a viewing affordance, not a second detected volume.
      $("treeCount").textContent = String(state.live.volumes.length);
      $("filesystemTree").innerHTML = rows.join("") || empty("No browsable volumes.");

      const selected = state.live.selKey;
      const entries = selected ? (state.live.dirCache[selected] || []) : [];
      const paging = selected && state.live.dirPaging ? state.live.dirPaging[selected] : null;
      const selPath = selected ? selected.split("|").slice(1).join("|") : "/";
      const selVolume = selected ? Number(selected.split("|")[0]) : 0;
      $("folderTitle").textContent = selected ? selPath : "Select a volume";
      if (!selected) {
        $("entryTable").innerHTML = empty("Select a volume or folder on the left to browse it.");
        setCurrentLiveGrid("live", []);
        renderSelectionCount();
        return;
      }
      const viewedPath = state.hex.live && state.hex.live.volume === selVolume ? state.hex.live.path : null;
      const columns = liveGridColumns();
      const tableResult = sortableGridTable("live", columns, entries.map((entry) => liveGridRow(entry, selVolume, selPath, viewedPath)), "live-table", renderLiveGridRow);
      setCurrentLiveGrid("live", tableResult.visibleRows.map((row) => row.item));
      renderSelectionCount();
      const caveat = evidence && evidence.source_kind === "folder"
        ? `<div class="analysis-status">Direct browse reads the current disk state (not a preserved snapshot).</div>`
        : "";
      const guidanceRemainingMs = Math.max(0, Number(state.liveGuidanceExpiresAt || 0) - Date.now());
      const guidanceStyle = `style="--guidance-duration:${guidanceRemainingMs}ms"`;
      const imageLayout = guidanceRemainingMs > 0 && evidence && evidence.source_kind === "image"
        ? `<div class="analysis-status transient-guidance" role="status" ${guidanceStyle}>Detected ${state.live.volumes.length.toLocaleString()} filesystem volume${state.live.volumes.length === 1 ? "" : "s"}. The raw image row is a byte view and is not counted as another volume.</div>`
        : "";
      const liveHint = guidanceRemainingMs > 0
        ? `<div class="analysis-status transient-guidance" role="status" ${guidanceStyle}>Browse: click a file for hex/text, right-click a row for bookmark/export (folders can bookmark or export recursively), Ctrl/Shift-click or checkboxes to multi-select.</div>`
        : "";
      const hint = caveat + imageLayout + liveHint;
      const filterStatus = gridFilterStatusHtml("live", columns, tableResult.visibleRows.length, entries.length, "items");
      const pageStatus = paging && paging.nextCursor
        ? `<div class="analysis-status">Loaded ${entries.length.toLocaleString()} of ${paging.totalEntries.toLocaleString()} items. <button class="ghost" onclick="liveLoadMore(${selVolume}, '${escapeAttr(escapeJs(selPath))}')"${paging.loading ? " disabled" : ""}>Load more</button></div>`
        : "";
      const allPictures = entries.length > 0 && entries.every((entry) => isLiveImageEntry(entry));
      if (allPictures && state.pictureViewMode !== "list") {
        $("entryTable").innerHTML = hint + pageStatus + filterStatus
          + renderLiveThumbnailContents(tableResult.visibleRows, state.live.evidenceId)
          + (tableResult.visibleRows.length ? "" : empty("No pictures match the column filters."));
      } else {
        const galleryToggle = allPictures
          ? `<div class="thumb-toolbar"><button class="ghost" onclick="setPictureViewMode('grid')">Gallery view</button></div>`
          : "";
        $("entryTable").innerHTML = entries.length
          ? hint + pageStatus + galleryToggle + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No items match the column filters."))
          : empty("This folder is empty.");
      }
    }

    // BitLocker: honest status line + unlock affordance for a locked volume.
    // The decrypt layer is read-only over the evidence; the recovery key/password
    // is held in memory only (state.bitlocker.unlock) for the browse session and
    // never written to localStorage, the case DB, notices, or logs.
    function bitlockerStatusRow(volume) {
      const bl = volume.bitlocker || {};
      const method = bl.encryption_method ? (bl.encryption_method.description || bl.encryption_method.raw || "") : "";
      const protectors = Array.isArray(bl.protectors)
        ? bl.protectors.map((p) => (p && (p.kind || p.label || p.raw)) || "").filter(Boolean).join(", ")
        : "";
      const hasCredentialProtector = bl.can_unlock_with_recovery_key || bl.can_unlock_with_password;
      // decrypt_supported === false means the cipher was identified but this
      // build's decrypt layer refuses it (only AES-128-CBC with/without the
      // Elephant diffuser is validated); a credential cannot help until then,
      // so say that honestly instead of offering a doomed unlock.
      const cipherUnsupported = bl.decrypt_supported === false;
      const canUnlock = hasCredentialProtector && !cipherUnsupported;
      const unlocked = state.bitlocker && state.bitlocker.active && Number(state.bitlocker.volumeIndex) === Number(volume.index);
      const action = unlocked
        ? `<button class="ghost tiny" onclick="event.stopPropagation(); lockBitlockerVolume()">Lock (forget key)</button>`
        : (canUnlock
          ? `<button class="ghost tiny" onclick="event.stopPropagation(); unlockBitlockerVolume(${volume.index})">Unlock &amp; browse</button>`
          : (cipherUnsupported
            ? `<span class="muted tiny">Detected, but this build cannot decrypt ${escapeHtml(String(method || "this cipher"))} yet (decrypt is limited to AES-128-CBC &plusmn; diffuser); a recovery key/password will not help until then</span>`
            : `<span class="muted tiny">Cannot decrypt (no recovery-key/password protector${bl.tpm_only ? "; TPM-only" : ""})</span>`));
      return `<div class="tree-row bitlocker-info" style="--depth:1">
        <span class="tree-toggle"></span>
        <span class="tree-label"><span class="muted tiny">${escapeHtml(bl.status || "BitLocker volume")}${method ? " - " + escapeHtml(String(method)) : ""}${protectors ? " - " + escapeHtml(protectors) : ""}</span></span>
        ${action}
      </div>`;
    }

    async function unlockBitlockerVolume(volumeIndex) {
      const which = window.prompt("BitLocker unlock - enter 'r' for a 48-digit recovery key, or 'p' for a password:", "r");
      if (which == null) {
        return;
      }
      const kind = which.trim().toLowerCase().startsWith("p") ? "password" : "recovery_key";
      const value = window.prompt(
        kind === "password" ? "Enter the BitLocker password:" : "Enter the 48-digit recovery key (six-digit groups separated by dashes):",
        ""
      );
      if (value == null || !value.trim()) {
        setNotice("BitLocker unlock cancelled.", true);
        return;
      }
      setNotice("Unlocking BitLocker volume " + volumeIndex + " (key used for this request, held in memory only)...");
      try {
        const data = await apiPost("/api/image/bitlocker/unlock/list", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume_index: Number(volumeIndex),
          unlock: { type: kind, value: value },
          dir_path: "/"
        });
        state.bitlocker = { active: true, volumeIndex: Number(volumeIndex), unlock: { type: kind, value: value }, path: "/", entries: data.entries || [], preview: null };
        renderLiveBrowse();
        renderBitlockerEntries();
        setNotice("Unlocked BitLocker volume " + volumeIndex + ": " + (data.entries || []).length + " root entries. Use Lock to clear the key from memory.");
      } catch (err) {
        setNotice("BitLocker unlock failed: " + err.message, true);
      }
    }

    function lockBitlockerVolume() {
      if (state.bitlocker && state.bitlocker.unlock) {
        state.bitlocker.unlock.value = ""; // best-effort scrub before dropping
      }
      state.bitlocker = null;
      renderLiveBrowse();
      setNotice("BitLocker volume locked - the key was cleared from memory.");
    }

    async function bitlockerDrill(path) {
      const bl = state.bitlocker;
      if (!bl || !bl.active) {
        return;
      }
      try {
        const data = await apiPost("/api/image/bitlocker/unlock/list", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume_index: bl.volumeIndex,
          unlock: bl.unlock,
          dir_path: path
        });
        bl.path = path;
        bl.entries = data.entries || [];
        bl.preview = null;
        renderBitlockerEntries();
      } catch (err) {
        setNotice("BitLocker browse failed: " + err.message, true);
      }
    }

    async function openBitlockerFileBytes(path, name) {
      const bl = state.bitlocker;
      if (!bl || !bl.active) {
        return;
      }
      try {
        const data = await apiPost("/api/image/bitlocker/unlock/bytes", {
          case_path: currentCasePath(),
          evidence_id: state.live.evidenceId,
          volume_index: bl.volumeIndex,
          unlock: bl.unlock,
          file_path: path,
          offset: 0,
          length: 256
        });
        const bytes = data.bytes || [];
        bl.preview = { name: name, offset: 0, hex: bytes.map(byteHex).join(" "), ascii: printableAsciiPreview(bytes) };
        renderBitlockerEntries();
        setNotice("Read " + (data.bytes_read || bytes.length) + " bytes of " + name + " (total " + formatBytes(data.total_size || 0) + ").");
      } catch (err) {
        setNotice("BitLocker byte read failed: " + err.message, true);
      }
    }

    function renderBitlockerEntries() {
      const bl = state.bitlocker;
      if (!bl || !bl.active) {
        return;
      }
      $("folderTitle").textContent = "BitLocker vol " + bl.volumeIndex + " : " + (bl.path || "/");
      const parent = bl.path && bl.path !== "/" ? (bl.path.replace(/\/[^\/]*$/, "") || "/") : null;
      const rows = [];
      if (parent !== null) {
        rows.push(`<tr><td colspan="3"><button class="ghost tiny" onclick="bitlockerDrill('${escapeAttr(escapeJs(parent))}')">.. up</button></td></tr>`);
      }
      (bl.entries || []).forEach((entry) => {
        const child = liveChildPath(bl.path || "/", entry.name);
        if (entry.is_dir) {
          rows.push(`<tr><td><button class="ghost tiny" onclick="bitlockerDrill('${escapeAttr(escapeJs(child))}')">${escapeHtml(entry.name)}/</button></td><td>Folder</td><td></td></tr>`);
        } else {
          rows.push(`<tr><td><button class="ghost tiny" onclick="openBitlockerFileBytes('${escapeAttr(escapeJs(child))}','${escapeAttr(escapeJs(entry.name))}')">${escapeHtml(entry.name)}</button></td><td>File</td><td>${entry.size_bytes == null ? "" : escapeHtml(formatBytes(entry.size_bytes))}</td></tr>`);
        }
      });
      const dump = bl.preview
        ? `<div class="analysis-status">First bytes of ${escapeHtml(bl.preview.name)} (offset ${bl.preview.offset}):<br><span class="mono tiny">${escapeHtml(bl.preview.hex)}</span><br><span class="mono tiny">${escapeHtml(bl.preview.ascii)}</span></div>`
        : "";
      $("entryTable").innerHTML =
        `<div class="analysis-status">Decrypted BitLocker NTFS volume - read-only, key held in memory only. <button class="ghost tiny" onclick="lockBitlockerVolume()">Lock (forget key)</button></div>` +
        dump +
        `<table class="live-table"><thead><tr><th>Name</th><th>Type</th><th>Size</th></tr></thead><tbody>${rows.join("") || '<tr><td colspan="3" class="muted">Empty folder.</td></tr>'}</tbody></table>`;
    }

    // Lazy indexed browse: for cases too big to ship every entry, load folders
    // on demand from the case database (/api/entries/dir). Same data as the
    // normal indexed tree, but never loads more than one folder at a time.
    async function idxLoadDir(path) {
      const idxState = state.idx;
      const evidenceId = idxState.evidenceId;
      idxState.dirPaging = idxState.dirPaging || {};
      if (!idxState.dirCache[path]) {
        const data = await apiGet("/api/entries/dir", {
          case_path: currentCasePath(),
          evidence_id: evidenceId,
          path: path,
          offset: 0,
          limit: 1000
        });
        if (state.idx !== idxState || state.idx.evidenceId !== evidenceId) {
          return null;
        }
        idxState.dirCache[path] = data.children || [];
        idxState.dirPaging[path] = {
          nextOffset: data.next_offset == null ? null : Number(data.next_offset),
          totalChildren: data.total_children == null
            ? (data.children || []).length
            : Number(data.total_children),
          loading: false,
          pending: null
        };
      }
      return idxState.dirCache[path];
    }

    async function idxLoadMore(path, renderAfter = true) {
      const idxState = state.idx;
      const evidenceId = idxState.evidenceId;
      idxState.dirPaging = idxState.dirPaging || {};
      const paging = idxState.dirPaging[path];
      if (!paging || paging.nextOffset == null) {
        return false;
      }
      if (!paging.pending) {
        const requestedOffset = paging.nextOffset;
        paging.loading = true;
        paging.pending = (async () => {
          try {
            const data = await apiGet("/api/entries/dir", {
              case_path: currentCasePath(),
              evidence_id: evidenceId,
              path: path,
              offset: requestedOffset,
              limit: 1000
            });
            if (state.idx !== idxState
              || idxState.evidenceId !== evidenceId
              || idxState.dirPaging[path] !== paging) {
              return false;
            }
            const nextOffset = data.next_offset == null ? null : Number(data.next_offset);
            if (nextOffset != null && nextOffset <= requestedOffset) {
              throw new Error("the directory continuation did not advance");
            }
            const existing = idxState.dirCache[path] || [];
            const seen = new Set(existing.map((child) => child.logical_path));
            (data.children || []).forEach((child) => {
              if (!seen.has(child.logical_path)) {
                seen.add(child.logical_path);
                existing.push(child);
              }
            });
            idxState.dirCache[path] = existing;
            paging.nextOffset = nextOffset;
            paging.totalChildren = data.total_children == null
              ? existing.length
              : Number(data.total_children);
            return true;
          } catch (err) {
            if (state.idx === idxState) {
              setNotice("Could not load the next indexed-directory page: " + err.message, true);
            }
            return false;
          } finally {
            paging.loading = false;
            paging.pending = null;
          }
        })();
      }
      const loaded = await paging.pending;
      if (loaded && renderAfter && state.idx === idxState) {
        renderIndexedBrowse();
      }
      return loaded;
    }

    async function idxEnsureChildLoaded(parentPath, childPath, shouldContinue = () => true) {
      const idxState = state.idx;
      const children = await idxLoadDir(parentPath);
      if (children === null || state.idx !== idxState || !shouldContinue()) {
        return false;
      }
      while (!children.some((child) => child.logical_path === childPath)) {
        if (!shouldContinue()) {
          return false;
        }
        const paging = idxState.dirPaging && idxState.dirPaging[parentPath];
        if (!paging || paging.nextOffset == null) {
          return false;
        }
        const loaded = await idxLoadMore(parentPath, false);
        if (!loaded || state.idx !== idxState) {
          return false;
        }
      }
      return true;
    }

    async function idxToggleDir(path) {
      if (state.idx.expanded.has(path)) {
        state.idx.expanded.delete(path);
      } else {
        const idxState = state.idx;
        try {
          const children = await idxLoadDir(path);
          if (children === null || state.idx !== idxState) { return; }
        } catch (err) {
          if (state.idx !== idxState) { return; }
          setNotice(err.message, true);
          return;
        }
        state.idx.expanded.add(path);
      }
      renderIndexedBrowse();
    }

    async function idxSelectDir(path, recordNavigation = true) {
      const previous = currentAnalyzeLocation();
      const idxState = state.idx;
      try {
        const children = await idxLoadDir(path);
        if (children === null || state.idx !== idxState) { return; }
      } catch (err) {
        if (state.idx !== idxState) { return; }
        setNotice(err.message, true);
        return;
      }
      state.idx.selPath = path;
      state.browserState.treeMode = "filesystem";
      state.browserState.selectedPath = normalizeLogicalPath(path || "/");
      state.idx.expanded.add(path);
      renderIndexedBrowse();
      if (recordNavigation) {
        commitAnalyzeNavigation(previous);
      } else {
        updateAnalyzeNavButtons();
      }
    }

    // Restores a stored selected_path (fullscreen/query restore) in lazy
    // indexed browse: loads and expands every ancestor folder so the tree
    // opens down to the selection. The synthetic containers are collapsed
    // out of the tree, so they are skipped rather than loaded.
    async function idxRestorePath(path) {
      const idxState = state.idx;
      const target = normalizeLogicalPath(path || "/");
      const restoreIsCurrent = () => state.idx === idxState
        && state.browserState.treeMode !== "categories"
        && normalizeLogicalPath(state.browserState.selectedPath || "/") === target;
      const root = await idxLoadDir("/");
      if (root === null || !restoreIsCurrent()) {
        return;
      }
      if (target === "/") {
        return;
      }
      const synthetic = new Set(["/Image Analysis", "/Image Analysis/Volumes", "/Image Analysis/Partitions"]);
      const segments = target.split("/").filter(Boolean);
      let current = "";
      let visibleParent = "/";
      for (const segment of segments) {
        current += "/" + segment;
        if (synthetic.has(current)) {
          continue;
        }
        try {
          const found = await idxEnsureChildLoaded(visibleParent, current, restoreIsCurrent);
          if (!found || !restoreIsCurrent()) {
            return;
          }
          const children = await idxLoadDir(current);
          if (children === null || !restoreIsCurrent()) {
            return;
          }
        } catch (err) {
          return;
        }
        state.idx.expanded.add(current);
        state.idx.selPath = current;
        visibleParent = current;
      }
    }

    function idxChildPath(parent, name) {
      return parent === "/" ? "/" + name : parent + "/" + name;
    }

    function indexedGridColumns() {
      return [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" },
        { key: "name", label: "Name", sortable: true, filterable: true, sortType: "text" },
        { key: "type", label: "Type", sortable: true, filterable: true, sortType: "text" },
        { key: "ext", label: "Extension", sortable: true, filterable: true, sortType: "text" },
        { key: "size", label: "Size", sortable: true, filterable: true, sortType: "number" },
        { key: "artifactTime", label: "Artifact time", sortable: true, filterable: true, sortType: "time" },
        { key: "created", label: "Created", sortable: true, filterable: true, sortType: "time" },
        { key: "modified", label: "Modified", sortable: true, filterable: true, sortType: "time" },
        { key: "accessed", label: "Accessed", sortable: true, filterable: true, sortType: "time" },
        { key: "mftModified", label: "MFT modified", sortable: true, filterable: true, sortType: "time" },
        { key: "sha256", label: "SHA-256", sortable: true, filterable: true, sortType: "text" }
      ];
    }

    function indexedGridRow(child) {
      const entry = child.entry_id != null ? idxChildToEntry(child) : null;
      const type = child.is_dir ? "Folder" : (entry ? filesystemTypeLabel(entry) : "File");
      const size = child.size_bytes == null ? "" : formatBytes(child.size_bytes);
      const flags = child.is_deleted ? "deleted" : "";
      const artifactTime = artifactEventTime(entry);
      const created = filesystemCreatedTime(entry);
      const modified = filesystemModifiedTime(entry);
      const accessed = filesystemAccessedTime(entry);
      const mftModified = filesystemMftModifiedTime(entry);
      const sha256 = filesystemFileSha256(entry);
      return {
        child,
        entry,
        selectable: !child.is_dir && child.entry_id != null,
        values: {
          name: compactParts([child.name, flags]),
          type,
          ext: filesystemFileExtension(entry),
          size,
          artifactTime,
          created,
          modified,
          accessed,
          mftModified,
          sha256
        },
        sortValues: {
          size: child.size_bytes == null ? NaN : Number(child.size_bytes),
          artifactTime: Date.parse(artifactTime),
          created: Date.parse(created),
          modified: Date.parse(modified),
          accessed: Date.parse(accessed),
          mftModified: Date.parse(mftModified)
        }
      };
    }

    function renderIndexedGridRow(row) {
      const child = row.child;
      const selectable = row.selectable;
      const isChecked = selectable && state.selectedEntryIds.has(child.entry_id);
      const checkbox = selectable
        ? `<input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleEntrySelection(${child.entry_id}, this.checked, event)">`
        : "";
      const nameCell = `<span class="entry-name">${escapeHtml(child.name)}</span>`;
      const flags = child.is_deleted ? '<span class="pill bad">deleted</span>' : "";
      // No in-lane buttons: rows are worked via selection + right-click.
      const rowClick = child.is_dir
        ? ` style="cursor:pointer" onclick="idxSelectDir('${escapeAttr(escapeJs(child.logical_path))}')"`
        : (selectable ? ` style="cursor:pointer" onclick="handleEntryRowClick(event, ${child.entry_id})"` : "");
      const ctxAttr = child.is_dir
        ? ` data-idx-dir="${escapeAttr(child.logical_path)}"`
        : (selectable ? ` data-entry-id="${child.entry_id}"` : "");
      return `<tr class="entry-row${isChecked ? " multi-selected" : ""}"${rowClick}${ctxAttr}>
          <td>${checkbox}</td>
          <td>${nameCell} ${flags}</td>
          <td class="entry-kind">${escapeHtml(row.values.type)}</td>
          <td class="entry-ext">${escapeHtml(row.values.ext)}</td>
          <td class="entry-size">${row.values.size}</td>
          <td class="entry-time entry-artifact-time" title="${escapeAttr(row.values.artifactTime)}">${escapeHtml(row.values.artifactTime)}</td>
          <td class="entry-time" title="${escapeAttr(row.values.created)}">${escapeHtml(row.values.created)}</td>
          <td class="entry-time" title="${escapeAttr(row.values.modified)}">${escapeHtml(row.values.modified)}</td>
          <td class="entry-time" title="${escapeAttr(row.values.accessed)}">${escapeHtml(row.values.accessed)}</td>
          <td class="entry-time" title="${escapeAttr(row.values.mftModified)}">${escapeHtml(row.values.mftModified)}</td>
          <td class="entry-hash mono" title="${escapeAttr(row.values.sha256)}">${escapeHtml(row.values.sha256)}</td>
        </tr>`;
    }

    function visibleIndexedGridRows(children) {
      return visibleGridRows("indexed", indexedGridColumns(), children.map(indexedGridRow));
    }

    function renderIdxDirRows(path, depth, rows) {
      const children = state.idx.dirCache[path] || [];
      children.filter((child) => child.is_dir).forEach((child) => {
        const childPath = child.logical_path;
        const expanded = state.idx.expanded.has(childPath);
        const active = state.idx.selPath === childPath ? " active" : "";
        const toggle = child.has_children
          ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); idxToggleDir('${escapeAttr(escapeJs(childPath))}')">${expanded ? "-" : "+"}</span>`
          : `<span class="tree-toggle"></span>`;
        const entryAttr = child.entry_id != null ? ` data-folder-entry-id="${child.entry_id}"` : "";
        rows.push(`<button class="tree-row${active}" style="--depth:${depth}" onclick="idxSelectDir('${escapeAttr(escapeJs(childPath))}')" data-idx-dir="${escapeAttr(childPath)}"${entryAttr} title="${escapeAttr(displayPath(childPath))}">
          ${toggle}
          <span class="tree-label">${escapeHtml(child.name)}</span>
          <span class="muted tiny"></span>
        </button>`);
        if (expanded) {
          renderIdxDirRows(childPath, depth + 1, rows);
        }
      });
      const paging = state.idx.dirPaging && state.idx.dirPaging[path];
      if (paging && paging.nextOffset != null) {
        rows.push(`<button class="tree-row" style="--depth:${depth}" onclick="idxLoadMore('${escapeAttr(escapeJs(path))}')">
          <span class="tree-toggle"></span>
          <span class="tree-label">Load more...</span>
          <span class="muted tiny">${children.length.toLocaleString()} / ${paging.totalChildren.toLocaleString()}</span>
        </button>`);
      }
    }

    function renderIndexedBrowse() {
      // Async dir loads can resolve after the examiner switched to Categories
      // or Live browse; never let a late load stomp those views.
      if (state.live.active || state.browserState.treeMode === "categories") {
        return;
      }
      renderTreeModeControls();
      const evidence = state.data && state.data.evidence.find((item) => item.id === state.idx.evidenceId);
      $("browserTitle").textContent = (evidence ? evidence.display_name : "Evidence") + " | indexed (lazy)";
      $("treeTitle").textContent = "Entries";
      const device = evidence ? evidence.display_name : "Entries";
      const rootActive = state.idx.selPath === "/" ? " active" : "";
      const rootExpanded = state.idx.expanded.has("/");
      const rows = [`<button class="tree-row${rootActive}" style="--depth:0" onclick="idxSelectDir('/')" data-idx-dir="/" title="/">
        <span class="tree-toggle can-toggle" onclick="event.stopPropagation(); idxToggleDir('/')">${rootExpanded ? "-" : "+"}</span>
        <span class="tree-label">${escapeHtml(device)}</span>
        <span class="muted tiny"></span>
      </button>`];
      if (rootExpanded) {
        renderIdxDirRows("/", 1, rows);
      }
      $("filesystemTree").innerHTML = rows.join("");
      $("treeCount").textContent = (state.data.entry_count || 0).toLocaleString();

      const selPath = state.idx.selPath || "/";
      const children = state.idx.dirCache[selPath] || [];
      $("folderTitle").textContent = displayPath(selPath);
      const columns = indexedGridColumns();
      const gridRows = children.map(indexedGridRow);
      const tableResult = sortableGridTable("indexed", columns, gridRows, "idx-table", renderIndexedGridRow);
      setCurrentEntryGrid("indexed", tableResult.visibleRows.filter((row) => row.selectable).map((row) => row.entry).filter(Boolean));
      const banner = `<div class="analysis-status">Large case (${(state.data.entry_count || 0).toLocaleString()} entries): browsing the full index folder by folder. Open folders on the left; use Deep Search to find files by name or content.</div>`;
      const paging = state.idx.dirPaging && state.idx.dirPaging[selPath];
      const pageControl = paging && paging.nextOffset != null
        ? `<div class="analysis-status">Showing ${children.length.toLocaleString()} of ${paging.totalChildren.toLocaleString()} direct children. <button class="ghost tiny" onclick="idxLoadMore('${escapeAttr(escapeJs(selPath))}')">Load next 1,000</button></div>`
        : "";
      const filterStatus = gridFilterStatusHtml("indexed", columns, tableResult.visibleRows.length, children.length, "items");
      $("entryTable").innerHTML = banner + pageControl + (children.length
        ? filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No indexed items match the column filters."))
        : empty("This folder has no direct children."));
      renderSelectionCount();
    }

    function renderEvidenceBrowserEntries() {
      reconcileAnalyzeEvidenceState();
      if (state.live.active) {
        renderLiveBrowse();
        renderHexViewer();
        return;
      }
      if (state.data && state.browserState.evidenceId
        && state.browserState.treeMode !== "categories"
        && !(state.pendingAnalysisSelection
          && !state.pendingAnalysisSelection.applied
          && state.pendingAnalysisSelection.treeMode === "live")) {
        const evidenceForAuto = state.data.evidence.find((item) => item.id === state.browserState.evidenceId);
        if (evidenceForAuto && evidenceIndexedEntryCount(evidenceForAuto.id) === 0 && maybeAutoLiveBrowse(evidenceForAuto)) {
          renderHexViewer();
          return;
        }
      }
      // Big case: browse the indexed tree lazily so we never load everything.
      if (state.data && state.data.entries_truncated && state.browserState.evidenceId
        && state.browserState.treeMode !== "categories") {
        if (state.idx.evidenceId !== state.browserState.evidenceId) {
          state.idx = {
            evidenceId: state.browserState.evidenceId,
            dirCache: {},
            dirPaging: {},
            expanded: new Set(["/"]),
            selPath: "/"
          };
          $("filesystemTree").innerHTML = empty("Loading directory tree...");
          $("entryTable").innerHTML = empty("Loading...");
          setCurrentEntryGrid("indexed", []);
          renderTreeModeControls();
          idxRestorePath(state.browserState.selectedPath).then(renderIndexedBrowse).catch((err) => setNotice(err.message, true));
          renderHexViewer();
          return;
        }
        renderIndexedBrowse();
        renderHexViewer();
        return;
      }
      renderTreeModeControls();
      if (!state.data || !state.browserState.evidenceId) {
        $("browserTitle").textContent = "Select an evidence source";
        $("filesystemTree").innerHTML = empty("Select an evidence source.");
        $("entryTable").innerHTML = empty("Select an evidence source.");
        $("treeCount").textContent = "0";
        $("folderTitle").textContent = "/";
        setCurrentEntryGrid("", []);
        renderHexViewer();
        return;
      }
      const evidence = state.data.evidence.find((item) => item.id === state.browserState.evidenceId);
      $("browserTitle").textContent = evidence ? evidence.display_name + " | " + evidence.source_kind : "Select an evidence source";
      const entries = selectedEvidenceEntries();
      if (state.browserState.treeMode === "categories") {
        renderCategoryTree(entries);
        if (serverCategoryBrowseActive()) {
          renderServerCategoryContents();
        } else {
          renderCategoryContents(entries);
        }
        renderHexViewer();
        return;
      }
      if (entries.length === 0) {
        const pendingLiveRestore = state.pendingAnalysisSelection
          && !state.pendingAnalysisSelection.applied
          && state.pendingAnalysisSelection.treeMode === "live";
        if (!pendingLiveRestore && maybeAutoLiveBrowse(evidence)) {
          renderHexViewer();
          return;
        }
        renderAttachedEvidenceSource(evidence);
        renderHexViewer();
        return;
      }
      const knownFolders = directoryPathSet(entries);
      const syntheticSelection = syntheticContainerSet(knownFolders);
      if (!knownFolders.has(normalizeLogicalPath(state.browserState.selectedPath))
        || syntheticSelection.has(normalizeLogicalPath(state.browserState.selectedPath))) {
        state.browserState.selectedPath = "/";
      }
      renderFilesystemTree(entries, knownFolders);
      renderFolderContents(entries, knownFolders);
      renderHexViewer();
    }

    function renderTreeModeControls() {
      updateAnalyzeNavButtons();
      const mode = state.browserState.treeMode || "filesystem";
      $("treeTitle").textContent = mode === "categories" ? "Categories" : "Entries";
      $("treeModeFilesystem").classList.toggle("active", mode === "filesystem");
      $("treeModeCategories").classList.toggle("active", state.browserState.treeMode === "categories");
    }

    function selectedEvidenceEntries() {
      if (!state.data || !state.browserState.evidenceId) {
        return [];
      }
      return state.data.entries
        .filter((entry) => entry.evidence_id === state.browserState.evidenceId)
        .map((entry) => ({ ...entry, logical_path: normalizeLogicalPath(entry.logical_path) }));
    }

    function attachedEvidenceGridColumns() {
      return [
        { key: "source", label: "Attached Source", sortable: true, filterable: true, sortType: "text" },
        { key: "kind", label: "Kind", sortable: true, filterable: true, sortType: "text" },
        { key: "size", label: "Size", sortable: true, filterable: true, sortType: "number" },
        { key: "attached", label: "Attached", sortable: true, filterable: true, sortType: "time" },
        { key: "actions", label: "", sortable: false, filterable: false, sortType: "none" }
      ];
    }

    function attachedEvidenceGridRow(evidence, evidenceIndex, status) {
      const size = evidence.size_bytes == null ? "" : formatBytes(evidence.size_bytes);
      return {
        evidence,
        evidenceIndex,
        status,
        values: {
          source: compactParts([evidence.display_name, evidence.source_path]),
          kind: compactParts([evidence.source_kind, evidenceProcessingStatusText(evidence)]),
          size,
          attached: evidence.attached_at || ""
        },
        sortValues: {
          size: evidence.size_bytes == null ? NaN : Number(evidence.size_bytes),
          attached: Date.parse(evidence.attached_at || "")
        }
      };
    }

    function renderAttachedEvidenceGridRow(row) {
      const evidence = row.evidence;
      const bookmark = row.evidenceIndex >= 0
        ? `<button class="ghost" onclick="bookmarkEvidence(${row.evidenceIndex})">Bookmark</button>`
        : "";
      return `
        <tr class="entry-row">
          <td><strong>${escapeHtml(evidence.display_name)}</strong><br><span class="muted tiny">${escapeHtml(evidence.source_path)}</span></td>
          <td><span class="pill">${escapeHtml(evidence.source_kind)}</span> ${row.status}</td>
          <td>${evidence.size_bytes == null ? "" : formatBytes(evidence.size_bytes)}</td>
          <td>${escapeHtml(evidence.attached_at || "")}</td>
          <td class="actions">
            <div class="toolbar">
              ${processActionHtml(evidence)}
              ${bookmark}
              <button class="ghost danger" onclick="removeEvidence(${evidence.id})">Remove</button>
            </div>
          </td>
        </tr>`;
    }

    function renderAttachedEvidenceSource(evidence) {
      if (!evidence) {
        $("filesystemTree").innerHTML = empty("No evidence selected.");
        $("treeCount").textContent = "0";
        $("folderTitle").textContent = "/";
        $("entryTable").innerHTML = empty("No evidence selected.");
        setCurrentEntryGrid("attached", []);
        return;
      }
      $("treeCount").textContent = "1";
      $("folderTitle").textContent = "Attached Evidence";
      $("filesystemTree").innerHTML = `<button class="tree-row active" style="--depth:0" title="${escapeAttr(evidence.source_path)}">
        <span class="tree-toggle"></span>
        <span class="tree-label">${escapeHtml(evidence.display_name)}</span>
        <span class="muted tiny">source</span>
      </button>`;
      const evidenceIndex = state.data.evidence.findIndex((item) => item.id === evidence.id);
      const status = evidenceProcessingStatusHtml(evidence);
      const liveNotice = (evidence.source_kind === "folder" || evidence.source_kind === "file") && !evidence.indexed_at
        ? `<div class="analysis-status">Browse shows this ${evidence.source_kind === "folder" ? "folder" : "file"} as it is on disk right now. Process (Read File System) to index it for search, categories, and reports.</div>`
        : "";
      const columns = attachedEvidenceGridColumns();
      const rows = [attachedEvidenceGridRow(evidence, evidenceIndex, status)];
      const tableResult = sortableGridTable("attached", columns, rows, "", renderAttachedEvidenceGridRow);
      setCurrentEntryGrid("attached", []);
      const filterStatus = gridFilterStatusHtml("attached", columns, tableResult.visibleRows.length, rows.length, "sources");
      $("entryTable").innerHTML = liveNotice + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("Attached source does not match the column filters."));
      renderSelectionCount();
    }

    function renderFilesystemTree(entries, knownFolders) {
      const synthetic = syntheticContainerSet(knownFolders);
      const expanded = expandedTreeSet();
      ensureTreeAncestorsExpanded(state.browserState.selectedPath);
      const filterOn = dateFilterActive();
      const passing = filterOn ? applyDateFilter(entries) : null;
      const device = selectedEvidenceSource();
      const selected = normalizeLogicalPath(state.browserState.selectedPath);
      const rows = [];
      // A depth-first walk keeps every directory beneath its parent.
      const walk = (path, depth) => {
        let childFolders = displayChildFolders(knownFolders, path, synthetic);
        if (filterOn) {
          childFolders = childFolders.filter((child) => matchingSubtreeCount(passing, child) > 0);
        }
        const count = filterOn
          ? matchingSubtreeCount(passing, path)
          : displayFolderChildCount(entries, knownFolders, path, synthetic);
        const active = selected === path ? " active" : "";
        const isExpanded = expanded.has(path);
        const toggle = childFolders.length > 0
          ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); toggleTreePath('${escapeAttr(escapeJs(path))}')" title="${isExpanded ? "Collapse" : "Expand"}">${isExpanded ? "-" : "+"}</span>`
          : `<span class="tree-toggle"></span>`;
        const label = path === "/"
          ? (device ? device.display_name : "Entries")
          : logicalName(path);
        const folderEntry = entries.find((entry) =>
          entry.entry_kind === "directory" && normalizeLogicalPath(entry.logical_path) === normalizeLogicalPath(path)
        );
        const entryAttr = folderEntry ? ` data-folder-entry-id="${folderEntry.id}"` : "";
        rows.push(`<button class="tree-row${active}" style="--depth:${depth}" onclick="selectFolder('${escapeAttr(escapeJs(path))}')" data-folder-path="${escapeAttr(path)}"${entryAttr} title="${escapeAttr(path)}">
          ${toggle}
          <span class="tree-label">${escapeHtml(label)}</span>
          <span class="muted tiny">${count}</span>
        </button>`);
        if (isExpanded) {
          childFolders.forEach((child) => walk(child, depth + 1));
        }
      };
      walk("/", 0);
      $("treeCount").textContent = String(rows.length);
      $("filesystemTree").innerHTML = rows.join("") || empty("No folders.");
    }

    function serverCategoryBrowseActive() {
      return Boolean(serverCategoryCountsAvailable()
        && state.browserState.treeMode === "categories"
        && state.browserState.evidenceId);
    }

    // Categories are a case-wide artifact classification, not tied to any one
    // evidence source - the sidebar counts (category_entry_counts, backend)
    // already aggregate across every evidence source in the case. The grid
    // used to silently scope to whichever single evidence source happened to
    // be "selected" elsewhere (tree/live-browse navigation), which made
    // newly-imported evidence (e.g. a browser-history import) invisible under
    // its own category unless the examiner separately switched evidence
    // source - confusing, and inconsistent with the sidebar counts they were
    // already looking at. "all" is a sentinel meaning "every evidence source
    // in this case", handled by loadServerCategoryEntries() below.
    const ALL_EVIDENCE_CATEGORY_SCOPE = "all";

    function ensureCategoryCacheForSelection() {
      const key = state.browserState.selectedCategory || "";
      const evidenceId = ALL_EVIDENCE_CATEGORY_SCOPE;
      if (state.cat.evidenceId !== evidenceId || state.cat.key !== key) {
        state.cat = newCategoryCache(evidenceId, key);
      }
      return state.cat;
    }

    function normalizeCategoryEntry(entry) {
      return {
        ...entry,
        logical_path: normalizeLogicalPath(entry.logical_path),
        metadata_json: entry.metadata_json || {}
      };
    }

    function categoryServerQueryFilters() {
      const view = gridViewState("category");
      const filters = view.filters || {};
      const result = {
        filter_name: String(filters.name || "").trim(),
        filter_extension: String(filters.ext || "").trim(),
        filter_type: String(filters.type || "").trim(),
        filter_flags: String(filters.flags || "").trim(),
        filter_sha256: String(filters.sha256 || "").trim()
      };
      if (state.dateFilter.from) {
        result.from_utc = state.dateFilter.from + "T00:00:00Z";
      }
      if (state.dateFilter.to) {
        result.to_utc = state.dateFilter.to + "T23:59:59.999Z";
      }
      return result;
    }

    function scheduleServerCategoryReload(delay = 250) {
      if (categoryFilterTimer) {
        clearTimeout(categoryFilterTimer);
      }
      categoryFilterTimer = setTimeout(() => {
        categoryFilterTimer = null;
        if (!serverCategoryBrowseActive()) {
          return;
        }
        state.cat = newCategoryCache(
          ALL_EVIDENCE_CATEGORY_SCOPE,
          state.browserState.selectedCategory || ""
        );
        renderEvidenceBrowserEntries();
      }, delay);
    }

    async function loadServerCategoryEntries(reset = false) {
      const cache = ensureCategoryCacheForSelection();
      if (!cache.evidenceId || cache.loading) {
        return;
      }
      if (reset) {
        cache.entries = [];
        cache.total = null;
        cache.categoryTotal = null;
        cache.nextCursor = null;
        cache.error = "";
      }
      const selected = splitCategoryKey(cache.key || "");
      cache.loading = true;
      cache.error = "";
      try {
        const params = {
          case_path: currentCasePath(),
          main: selected.main || "",
          limit: cache.pageSize,
          ...categoryServerQueryFilters()
        };
        // "all" (every evidence source in the case) is the normal case for
        // Categories - only send evidence_id when scoped to one source.
        if (cache.evidenceId !== ALL_EVIDENCE_CATEGORY_SCOPE) {
          params.evidence_id = cache.evidenceId;
        }
        if (selected.sub) {
          params.sub = selected.sub;
        }
        if (!reset && cache.nextCursor) {
          params.after_path = cache.nextCursor.logical_path;
          params.after_id = cache.nextCursor.id;
        }
        const data = await apiGet("/api/entries/category", params);
        if (state.cat !== cache
          || state.browserState.treeMode !== "categories"
          || (state.browserState.selectedCategory || "") !== cache.key) {
          cache.loading = false;
          return;
        }
        const seen = new Set(cache.entries.map((entry) => entry.id));
        (data.entries || []).map(normalizeCategoryEntry).forEach((entry) => {
          if (!seen.has(entry.id)) {
            cache.entries.push(entry);
            seen.add(entry.id);
          }
        });
        cache.total = Number(data.total_matching ?? data.total_in_category ?? 0);
        cache.categoryTotal = Number(data.total_in_category ?? cache.total);
        cache.nextCursor = data.next_cursor || null;
        cache.loading = false;
        renderEvidenceBrowserEntries();
        renderHexViewer();
      } catch (err) {
        if (state.cat === cache) {
          cache.error = err.message || String(err);
          cache.loading = false;
          renderEvidenceBrowserEntries();
        }
        setNotice(err.message || String(err), true);
      }
    }

    function loadMoreCategoryEntries() {
      loadServerCategoryEntries(false);
    }

    function categoryInfiniteScrollHtml(cache) {
      if (!cache.nextCursor && !cache.loading) {
        return "";
      }
      return `<div id="categoryScrollSentinel" class="infinite-scroll-sentinel">${cache.loading ? "Loading more results..." : "Scroll to load more results"}</div>`;
    }

    function armCategoryInfiniteScroll() {
      if (categoryScrollObserver) {
        categoryScrollObserver.disconnect();
        categoryScrollObserver = null;
      }
      const cache = state.cat;
      const root = $("entryTable");
      const sentinel = $("categoryScrollSentinel");
      if (!root || !sentinel || cache.loading || !cache.nextCursor) {
        return;
      }
      if (!("IntersectionObserver" in window)) {
        sentinel.textContent = "Continue scrolling is unavailable in this browser.";
        return;
      }
      categoryScrollObserver = new IntersectionObserver((events) => {
        if (events.some((event) => event.isIntersecting)) {
          categoryScrollObserver.disconnect();
          categoryScrollObserver = null;
          loadMoreCategoryEntries();
        }
      }, { root, rootMargin: "600px 0px", threshold: 0 });
      categoryScrollObserver.observe(sentinel);
    }

    function categoryServerStatusHtml(rows, cache) {
      if (cache.total == null && cache.loading) {
        return `<div class="analysis-status">Loading category entries...</div>`;
      }
      const total = Number(cache.total || 0);
      const categoryTotal = Number(cache.categoryTotal ?? total);
      const filtersActive = gridColumnFiltersActive("category", categoryGridColumns()) || dateFilterActive();
      const matchNote = filtersActive && categoryTotal !== total
        ? ` matches from ${categoryTotal.toLocaleString()} category entries`
        : "";
      const loading = cache.loading ? ` <span class="muted tiny">Loading...</span>` : "";
      const continuation = cache.nextCursor ? " Scroll for more." : "";
      return `<div class="analysis-status">Showing ${rows.length.toLocaleString()} of ${total.toLocaleString()}${matchNote}.${continuation}${loading}</div>`;
    }

    function emptyIndexedCategoryMessage(fallback = "No entries in this category.") {
      const evidence = selectedEvidenceSource();
      if (evidence && evidenceIndexedEntryCount(evidence.id) === 0) {
        return "No indexed categories are available. Complete Analyze image successfully; direct-browse rows are intentionally not mirrored into Categories.";
      }
      return fallback;
    }

    function renderServerCategoryContents() {
      const cache = ensureCategoryCacheForSelection();
      const selectedLabel = categoryLabel(cache.key) || "All Categories";
      if (cache.total == null && !cache.loading && !cache.error) {
        $("folderTitle").textContent = selectedLabel + " | loading";
        $("entryTable").innerHTML = empty("Loading category entries...");
        loadServerCategoryEntries(true);
        setCurrentEntryGrid("category", []);
        renderSelectionCount();
        return;
      }
      // The server applies date and supported column filters before paging, so
      // every match in the category remains discoverable regardless of where
      // it sorts in the full result set.
      const rows = cache.entries || [];
      const total = cache.total == null ? 0 : Number(cache.total);
      $("folderTitle").textContent = selectedLabel + " | " + total.toLocaleString() + " total";
      if (cache.error) {
        $("entryTable").innerHTML = categoryServerStatusHtml(rows, cache) + empty(cache.error);
        setCurrentEntryGrid("category", []);
        renderSelectionCount();
        return;
      }
      const status = categoryServerStatusHtml(rows, cache);
      const continuation = categoryInfiniteScrollHtml(cache);
      if (rows.length === 0) {
        const message = total === 0
          ? emptyIndexedCategoryMessage()
          : "No entries loaded yet.";
        $("entryTable").innerHTML = status + empty(message) + continuation;
        setCurrentEntryGrid("category", []);
        renderSelectionCount();
        armCategoryInfiniteScroll();
        return;
      }
      if (shouldRenderEmailCategory(rows)) {
        renderEmailCategoryContents(rows, status, continuation);
        return;
      }
      if (shouldRenderThumbnailCategory(rows)) {
        renderThumbnailCategoryContents(rows, status, continuation);
        return;
      }
      renderCategoryRows(rows, status, continuation);
    }

    function renderCategoryTree(entries) {
      // Small cases can derive category counts from the already-loaded snapshot.
      // Large cases use exact SQL category counts; filters for the selected
      // category are independently applied by the server before pagination.
      const useServerCounts = serverCategoryCountsAvailable();
      const categoryEntries = categorizedVisibleEntries(applyDateFilter(entries));
      const mains = new Map();
      let totalCount = 0;
      if (useServerCounts) {
        state.data.category_counts.forEach((row) => {
          if (!mains.has(row.main)) {
            mains.set(row.main, { count: 0, subs: new Map() });
          }
          const main = mains.get(row.main);
          main.count += row.count;
          totalCount += row.count;
          if (row.sub) {
            main.subs.set(row.sub, (main.subs.get(row.sub) || 0) + row.count);
          }
        });
      } else {
        categoryEntries.forEach((entry) => {
          const category = entryCategory(entry);
          if (!mains.has(category.main)) {
            mains.set(category.main, { count: 0, subs: new Map() });
          }
          const main = mains.get(category.main);
          main.count += 1;
          main.subs.set(category.sub, (main.subs.get(category.sub) || 0) + 1);
        });
        totalCount = categoryEntries.length;
      }
      ensureCategoryTreeSub(mains, "Recovery", "Deleted files");
      ensureCategoryTreeSub(mains, "Recovery", "Unallocated space");
      const selected = state.browserState.selectedCategory || "";
      const rows = [
        categoryTreeRow("", "All Categories", totalCount, 0, selected === "", "")
      ];
      Array.from(mains.entries())
        .sort((left, right) => left[0].localeCompare(right[0]))
        .forEach(([mainName, main]) => {
          const mainKey = categoryKey(mainName, "");
          const expanded = !state.collapsedCategoryMains.has(mainName);
          rows.push(categoryTreeRow(
            mainKey,
            mainName,
            main.count,
            1,
            selected === mainKey,
            mainName,
            main.subs.size > 0,
            expanded
          ));
          if (expanded) {
            Array.from(main.subs.entries())
              .sort((left, right) => left[0].localeCompare(right[0]))
              .forEach(([subName, count]) => {
                const subKey = categoryKey(mainName, subName);
                rows.push(categoryTreeRow(subKey, subName, count, 2, selected === subKey, mainName));
              });
          }
        });
      $("treeCount").textContent = String(Array.from(mains.values()).filter((main) => main.count > 0).length);
      $("filesystemTree").innerHTML = rows.join("") || empty("No categories.");
    }

    function ensureCategoryTreeSub(mains, mainName, subName) {
      if (!mains.has(mainName)) {
        mains.set(mainName, { count: 0, subs: new Map() });
      }
      const main = mains.get(mainName);
      if (!main.subs.has(subName)) {
        main.subs.set(subName, 0);
      }
    }

    function toggleCategoryMain(mainName) {
      if (state.collapsedCategoryMains.has(mainName)) {
        state.collapsedCategoryMains.delete(mainName);
      } else {
        state.collapsedCategoryMains.add(mainName);
      }
      renderCategoryTree((state.data && state.data.entries) || []);
    }

    function categoryTreeRow(key, label, count, depth, active, iconCategory, hasChildren = false, expanded = true) {
      const icon = depth === 0
        ? svgIconHtml('<rect x="1.5" y="1.5" width="13" height="13" rx="2"/>', "category-icon", "All Categories")
        : categoryIconHtml(iconCategory, iconCategory);
      const toggle = hasChildren
        ? `<span class="tree-toggle can-toggle" onclick="event.stopPropagation(); toggleCategoryMain('${escapeAttr(escapeJs(label))}')" title="${expanded ? "Collapse" : "Expand"} ${escapeAttr(label)}">${expanded ? "-" : "+"}</span>`
        : `<span class="tree-toggle"></span>`;
      return `<button class="tree-row${active ? " active" : ""}" style="--depth:${depth}" onclick="selectCategory('${escapeAttr(escapeJs(key))}')" data-category-key="${escapeAttr(key)}" title="${escapeAttr(categoryLabel(key) || label)}">
        ${toggle}
        <span class="tree-label-row">${icon}<span class="tree-label">${escapeHtml(label)}</span></span>
        <span class="muted tiny">${Number(count).toLocaleString()}</span>
      </button>`;
    }

    function renderCategoryContents(entries) {
      const selected = state.browserState.selectedCategory || "";
      const rows = applyDateFilter(categoryEntriesForSelection(entries, selected));
      const selectedLabel = categoryLabel(selected) || "All Categories";
      const filterNote = dateFilterActive() ? " (date filtered)" : "";
      $("folderTitle").textContent = selectedLabel + " | " + rows.length + " result" + (rows.length === 1 ? "" : "s") + filterNote;
      const status = truncatedEntriesNoticeHtml();
      if (rows.length === 0) {
        $("entryTable").innerHTML = status + empty(emptyIndexedCategoryMessage());
        setCurrentEntryGrid("category", []);
        renderSelectionCount();
        return;
      }
      if (shouldRenderEmailCategory(rows)) {
        renderEmailCategoryContents(rows, status);
        return;
      }
      if (shouldRenderThumbnailCategory(rows)) {
        renderThumbnailCategoryContents(rows, status);
        return;
      }
      renderCategoryRows(rows, status);
    }

    function categoryGridColumns() {
      return [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" },
        { key: "name", label: "Name", sortable: true, filterable: true, sortType: "text" },
        { key: "category", label: "Category", sortable: true, filterable: true, sortType: "text" },
        { key: "type", label: "Type", sortable: true, filterable: true, sortType: "text" },
        { key: "ext", label: "Extension", sortable: true, filterable: true, sortType: "text" },
        { key: "size", label: "Size", sortable: true, filterable: true, sortType: "number" },
        { key: "flags", label: "Flags", sortable: true, filterable: true, sortType: "text" },
        { key: "offset", label: "Offset", sortable: true, filterable: true, sortType: "number" },
        { key: "artifactTime", label: "Artifact time", sortable: true, filterable: true, sortType: "time" },
        { key: "created", label: "Created", sortable: true, filterable: true, sortType: "time" },
        { key: "modified", label: "Modified", sortable: true, filterable: true, sortType: "time" },
        { key: "accessed", label: "Accessed", sortable: true, filterable: true, sortType: "time" },
        { key: "mftModified", label: "MFT modified", sortable: true, filterable: true, sortType: "time" },
        { key: "sha256", label: "SHA-256", sortable: true, filterable: true, sortType: "text" }
      ];
    }

    function categoryGridRow(entry) {
      const name = entry.name || logicalName(entry.logical_path);
      const ext = filesystemFileExtension(entry);
      const size = entry.size_bytes == null ? "" : formatBytes(entry.size_bytes);
      const offset = entryPrimaryOffset(entry);
      const artifactTime = artifactEventTime(entry);
      const created = filesystemCreatedTime(entry);
      const modified = filesystemModifiedTime(entry);
      const accessed = filesystemAccessedTime(entry);
      const mftModified = filesystemMftModifiedTime(entry);
      const flags = entryFlagsText(entry) || "-";
      const sha256 = filesystemFileSha256(entry);
      return {
        entry,
        values: {
          name: compactParts([name, displayPath(entry.logical_path)]),
          category: entryCategoryLabel(entry),
          type: activityLabel(entry),
          ext,
          size,
          flags,
          offset,
          artifactTime,
          created,
          modified,
          accessed,
          mftModified,
          sha256
        },
        sortValues: {
          size: entry.size_bytes == null ? NaN : Number(entry.size_bytes),
          offset: gridNumericValue(offset),
          artifactTime: Date.parse(artifactTime),
          created: Date.parse(created),
          modified: Date.parse(modified),
          accessed: Date.parse(accessed),
          mftModified: Date.parse(mftModified)
        }
      };
    }

    // Rows use selection and the context menu; per-row action buttons would
    // overlap evidence metadata columns in narrow layouts.
    function renderCategoryGridRow(row) {
      const entry = row.entry;
      const selectedRow = state.hex.entryId === entry.id ? " selected" : "";
      const isChecked = state.selectedEntryIds.has(entry.id);
      const checked = isChecked ? " checked" : "";
      const multiSelected = isChecked ? " multi-selected" : "";
      return `
          <tr class="entry-row${selectedRow}${multiSelected}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})">
            <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)"></td>
            <td title="${escapeAttr(entry.logical_path)}">${fileIconHtml(entry)}<span class="entry-name">${escapeHtml(entry.name || logicalName(entry.logical_path))}</span><span class="entry-path">${escapeHtml(displayPath(entry.logical_path))}</span></td>
            <td title="${escapeAttr(entryCategoryLabel(entry) + " | " + entryCategoryDetail(entry))}">${categoryIconHtml(entryCategory(entry).main)}<span class="entry-category">${escapeHtml(entryCategoryLabel(entry))}</span></td>
            <td class="entry-kind">${escapeHtml(activityLabel(entry))}</td>
            <td class="entry-ext">${escapeHtml(filesystemFileExtension(entry))}</td>
            <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
            <td class="entry-flags" title="${escapeAttr(entryFlagsText(entry))}">${entryFlagsHtml(entry)}</td>
            <td class="entry-offset" title="${escapeAttr(entryPrimaryOffset(entry))}">${escapeHtml(entryPrimaryOffset(entry))}</td>
            <td class="entry-time entry-artifact-time" title="${escapeAttr(artifactEventTime(entry))}">${escapeHtml(artifactEventTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemCreatedTime(entry))}">${escapeHtml(filesystemCreatedTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemModifiedTime(entry))}">${escapeHtml(filesystemModifiedTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemAccessedTime(entry))}">${escapeHtml(filesystemAccessedTime(entry))}</td>
            <td class="entry-time" title="${escapeAttr(filesystemMftModifiedTime(entry))}">${escapeHtml(filesystemMftModifiedTime(entry))}</td>
            <td class="entry-hash mono" title="${escapeAttr(filesystemFileSha256(entry))}">${escapeHtml(filesystemFileSha256(entry))}</td>
          </tr>`;
    }

    function visibleCategoryGridRows(rows) {
      return visibleGridRows("category", categoryGridColumns(), rows.map(categoryGridRow));
    }

    function renderCategoryRows(rows, prefixHtml = "", suffixHtml = "") {
      const columns = categoryGridColumns();
      const tableResult = sortableGridTable("category", columns, rows.map(categoryGridRow), "category-table", renderCategoryGridRow);
      const gridToggle = rows.length > 0 && rows.every((entry) => isImageEntry(entry))
        ? `<div class="thumb-toolbar"><button class="ghost" onclick="setPictureViewMode('grid')">Gallery view</button></div>`
        : "";
      setCurrentEntryGrid("category", tableResult.visibleRows.map((row) => row.entry));
      const filterStatus = gridFilterStatusHtml("category", columns, tableResult.visibleRows.length, rows.length, "entries");
      $("entryTable").innerHTML = prefixHtml + gridToggle + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No entries match the column filters.")) + suffixHtml;
      renderSelectionCount();
      armCategoryInfiniteScroll();
    }

    function shouldRenderEmailCategory(rows) {
      return rows.length > 0 && rows.every((entry) => isEmailEntry(entry));
    }

    function dateFilterActive() {
      return Boolean(state.dateFilter.from || state.dateFilter.to);
    }

    function entryTimestamps(entry) {
      return [categoryTime(entry), filesystemCreatedTime(entry), filesystemAccessedTime(entry),
        filesystemModifiedTime(entry), filesystemMftModifiedTime(entry)].filter(Boolean);
    }

    // Keep rows with at least one timestamp inside the absolute date range.
    // Rows without any parseable timestamp are hidden while a filter is active.
    function applyDateFilter(rows) {
      if (!dateFilterActive()) {
        return rows;
      }
      const from = state.dateFilter.from ? Date.parse(state.dateFilter.from + "T00:00:00Z") : -Infinity;
      const to = state.dateFilter.to ? Date.parse(state.dateFilter.to + "T23:59:59.999Z") : Infinity;
      return rows.filter((entry) => entryTimestamps(entry).some((text) => {
        const value = Date.parse(text);
        return Number.isFinite(value) && value >= from && value <= to;
      }));
    }

    function syncDateFilterInputs() {
      [
        ["dateFilterFrom", "from"],
        ["dateFilterTo", "to"],
        ["timelineDateFrom", "from"],
        ["timelineDateTo", "to"]
      ].forEach(([id, field]) => {
        const input = $(id);
        if (input && input.value !== (state.dateFilter[field] || "")) {
          input.value = state.dateFilter[field] || "";
        }
      });
    }

    function setDateFilterValue(field, value) {
      const key = field === "to" ? "to" : "from";
      if (state.dateFilter[key] === value) {
        syncDateFilterInputs();
        return;
      }
      state.dateFilter[key] = value;
      state.timeline.focusBucket = null;
      syncDateFilterInputs();
      if (serverCategoryBrowseActive()) {
        scheduleServerCategoryReload(0);
      } else {
        renderEvidenceBrowserEntries();
      }
      renderTimeline();
    }

    function clearDateFilter() {
      state.dateFilter = { from: "", to: "" };
      state.timeline.focusBucket = null;
      syncDateFilterInputs();
      if (serverCategoryBrowseActive()) {
        scheduleServerCategoryReload(0);
      } else {
        renderEvidenceBrowserEntries();
      }
      renderTimeline();
    }

    function isImageEntry(entry) {
      if (entry.entry_kind !== "file") {
        return false;
      }
      const name = (entry.name || entry.logical_path || "").toLowerCase();
      return [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"]
        .some((ext) => name.endsWith(ext));
    }

    function shouldRenderThumbnailCategory(rows) {
      return state.pictureViewMode !== "list"
        && rows.length > 0
        && rows.every((entry) => isImageEntry(entry));
    }

    function setPictureViewMode(mode) {
      state.pictureViewMode = mode;
      renderEvidenceBrowserEntries();
    }

    function entryRawUrl(entry) {
      const meta = entry && entry.metadata_json;
      if (entry && entry.id == null && meta && meta.source === "live_browse") {
        return "/api/image/raw?case_path=" + encodeURIComponent(currentCasePath())
          + "&evidence_id=" + encodeURIComponent(String(entry.evidence_id))
          + "&volume=" + encodeURIComponent(String(meta.volume))
          + "&path=" + encodeURIComponent(meta.image_path);
      }
      return "/api/entry/raw?case_path=" + encodeURIComponent(currentCasePath())
        + "&entry_id=" + encodeURIComponent(String(entry.id));
    }

    function renderThumbnailCategoryContents(rows, prefixHtml = "", suffixHtml = "") {
      const cards = rows.map((entry) => {
        const selectedRow = state.hex.entryId === entry.id ? " selected" : "";
        const isChecked = state.selectedEntryIds.has(entry.id);
        return `
          <div class="thumb-card entry-row${selectedRow}${isChecked ? " multi-selected" : ""}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})" title="${escapeAttr(entry.logical_path)}">
            <input type="checkbox"${isChecked ? " checked" : ""} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)">
            <div class="thumb-frame"><img loading="lazy" src="${escapeAttr(entryRawUrl(entry))}" alt="" onerror="this.parentElement.classList.add('thumb-broken')"></div>
            <div class="thumb-name">${escapeHtml(entry.name || logicalName(entry.logical_path))}</div>
            <div class="thumb-meta muted tiny">${entry.size_bytes == null ? "" : escapeHtml(formatBytes(entry.size_bytes))}</div>
          </div>`;
      });
      $("entryTable").innerHTML = prefixHtml + `<div class="thumb-toolbar"><button class="ghost" onclick="setPictureViewMode('list')">List view</button></div><div class="thumb-grid">${cards.join("")}</div>` + suffixHtml;
      setCurrentEntryGrid("category", rows);
      renderSelectionCount();
      armCategoryInfiniteScroll();
    }

    function emailGridColumns() {
      return [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" },
        { key: "to", label: "To", sortable: true, filterable: true, sortType: "text" },
        { key: "from", label: "From", sortable: true, filterable: true, sortType: "text" },
        { key: "date", label: "Date/Time", sortable: true, filterable: true, sortType: "time" },
        { key: "subject", label: "Subject", sortable: true, filterable: true, sortType: "text" },
        { key: "body", label: "Body", sortable: true, filterable: true, sortType: "text" },
        { key: "size", label: "Size", sortable: true, filterable: true, sortType: "number" }
      ];
    }

    function emailGridRow(entry) {
      const metadata = entry.metadata_json || {};
      const to = firstText(metadata.email_to, metadata.email_bcc);
      const from = firstText(metadata.email_from, metadata.email_reply_to);
      const date = firstText(metadata.email_date, categoryTime(entry));
      const subject = emailDisplayName(entry);
      const body = firstText(metadata.email_body_preview, metadata.email_parser_error, "");
      const size = entry.size_bytes == null ? "" : formatBytes(entry.size_bytes);
      return {
        entry,
        values: { to, from, date, subject, body, size },
        sortValues: {
          date: Date.parse(date),
          size: entry.size_bytes == null ? NaN : Number(entry.size_bytes)
        }
      };
    }

    function renderEmailGridRow(row) {
      const entry = row.entry;
      const selectedRow = state.hex.entryId === entry.id ? " selected" : "";
      const isChecked = state.selectedEntryIds.has(entry.id);
      const checked = isChecked ? " checked" : "";
      const multiSelected = isChecked ? " multi-selected" : "";
      return `
          <tr class="entry-row${selectedRow}${multiSelected}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})">
            <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)"></td>
            <td class="email-cell" title="${escapeAttr(row.values.to)}">${escapeHtml(row.values.to)}</td>
            <td class="email-cell" title="${escapeAttr(row.values.from)}">${escapeHtml(row.values.from)}</td>
            <td class="email-cell" title="${escapeAttr(row.values.date)}">${escapeHtml(row.values.date)}</td>
            <td class="email-cell" title="${escapeAttr(row.values.subject)}">${escapeHtml(row.values.subject)}</td>
            <td class="email-cell email-body-cell" title="${escapeAttr(row.values.body)}">${escapeHtml(row.values.body)}</td>
            <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
          </tr>`;
    }

    function visibleEmailGridRows(rows) {
      return visibleGridRows("email", emailGridColumns(), rows.map(emailGridRow));
    }

    function renderEmailCategoryContents(rows, prefixHtml = "", suffixHtml = "") {
      const columns = emailGridColumns();
      const tableResult = sortableGridTable("email", columns, rows.map(emailGridRow), "email-table", renderEmailGridRow);
      setCurrentEntryGrid("email", tableResult.visibleRows.map((row) => row.entry));
      const filterStatus = gridFilterStatusHtml("email", columns, tableResult.visibleRows.length, rows.length, "emails");
      $("entryTable").innerHTML = prefixHtml + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No emails match the column filters.")) + suffixHtml;
      renderSelectionCount();
      armCategoryInfiniteScroll();
    }

    function categorySummaryHtml(entries, selectedKey) {
      const categoryEntries = categorizedVisibleEntries(entries);
      const mains = new Map();
      categoryEntries.forEach((entry) => {
        const category = entryCategory(entry);
        if (!mains.has(category.main)) {
          mains.set(category.main, { count: 0, subs: new Map() });
        }
        const main = mains.get(category.main);
        main.count += 1;
        main.subs.set(category.sub, (main.subs.get(category.sub) || 0) + 1);
      });
      const allActive = !selectedKey;
      const cards = [
        categorySummaryCard("", "All Categories", categoryEntries.length, "Visible categorized results", allActive)
      ];
      Array.from(mains.entries())
        .sort((left, right) => right[1].count - left[1].count || left[0].localeCompare(right[0]))
        .slice(0, 5)
        .forEach(([mainName, main]) => {
          const topSubs = Array.from(main.subs.entries())
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .slice(0, 2)
            .map(([subName, count]) => subName + " " + count)
            .join(" | ");
          const key = categoryKey(mainName, "");
          cards.push(categorySummaryCard(key, mainName, main.count, topSubs || "No subcategories", selectedKey === key));
        });
      return `<div class="category-summary">${cards.join("")}</div>`;
    }

    function categorySummaryCard(key, label, count, detail, active) {
      return `<button class="category-card${active ? " active" : ""}" onclick="selectCategory('${escapeAttr(escapeJs(key))}')" title="${escapeAttr(label)}">
        <span class="muted tiny">${escapeHtml(label)}</span>
        <strong>${escapeHtml(count)}</strong>
        <span class="muted tiny">${escapeHtml(detail || "")}</span>
      </button>`;
    }

    function categoryRowBadges(entry) {
      const evidence = evidenceSourceForEntry(entry);
      const metadata = entry.metadata_json || {};
      const badges = [
        evidence ? "Source: " + evidence.display_name : "",
        metadata.filesystem_parser ? "Parser: " + metadata.filesystem_parser : "",
        metadata.category_confidence ? "Confidence: " + metadata.category_confidence : ""
      ].filter(Boolean);
      return badges.map((value) => `<span class="pill">${escapeHtml(value)}</span>`).join("");
    }

    function entryFlags(entry) {
      const metadata = entry.metadata_json || {};
      const flags = [];
      if (entry.is_deleted || metadata.recovery_source === "ntfs_deleted_mft" || metadata.artifact_kind === "deleted_file_record") {
        flags.push({ label: "deleted", tone: "bad" });
      }
      if (metadata.is_file_slack) {
        flags.push({ label: "slack", tone: "warn" });
      }
      if (metadata.is_unallocated || metadata.artifact_kind === "unallocated_space") {
        flags.push({ label: "unallocated", tone: "warn" });
      }
      if (flags.length === 0 && metadata.storage_area) {
        flags.push({ label: storageAreaLabel(metadata.storage_area), tone: "" });
      }
      return flags;
    }

    function entryFlagsHtml(entry) {
      const flags = entryFlags(entry);
      if (!flags.length) {
        return '<span class="muted tiny">-</span>';
      }
      const visible = flags.length > 2
        ? [flags[0], { label: "+" + (flags.length - 1), tone: "more" }]
        : flags;
      return visible.map((flag) => `<span class="pill ${flag.tone ? escapeAttr(flag.tone) : ""}">${escapeHtml(flag.label)}</span>`).join("");
    }

    function entryFlagsText(entry) {
      return entryFlags(entry).map((flag) => flag.label).join(", ");
    }

    function storageAreaLabel(value) {
      return String(value || "").replace(/_/g, " ");
    }

    function entryPrimaryOffset(entry) {
      const metadata = entry.metadata_json || {};
      const value = firstDefined(
        metadata.resolved_decoded_media_offset,
        metadata.file_data_physical_offset,
        metadata.mft_record_physical_offset,
        metadata.physical_offset,
        metadata.file_data_logical_offset,
        metadata.mft_record_logical_offset,
        metadata.logical_offset,
      );
      return formatOffsetValue(value);
    }

    // Shared icon system. One mapping table per axis (category and file kind) is
    // reused by the category tree and grid columns. Inline stroke-only SVGs use
    // currentColor so they adapt to the active theme without external assets.
    const CATEGORY_ICON_SHAPES = {
      "Web Activity": '<circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5c2.2 2 2.2 11 0 13M8 1.5c-2.2 2-2.2 11 0 13"/>',
      "Pictures and Media": '<rect x="1.5" y="2.5" width="13" height="11" rx="1"/><circle cx="5.5" cy="6" r="1.3"/><path d="M2 12l3.5-4 2.5 2.8 2-2.3L14 12"/>',
      "Documents and Office": '<path d="M4 1.5h5.5L12 4v10.5H4z"/><path d="M9.5 1.5V4H12"/><path d="M5.8 8h4.4M5.8 10.2h4.4"/>',
      "Email and Communications": '<rect x="1.5" y="3" width="13" height="10" rx="1"/><path d="M2 3.8l6 5 6-5"/>',
      "Operating System": '<circle cx="8" cy="8" r="2.3"/><path d="M8 1.8v2M8 12.2v2M14.2 8h-2M3.8 8h-2M12.3 3.7l-1.4 1.4M5.1 10.9l-1.4 1.4M12.3 12.3l-1.4-1.4M5.1 5.1L3.7 3.7"/>',
      "Accounts and Identity": '<circle cx="8" cy="5.3" r="2.6"/><path d="M2.5 14c0-3.3 2.5-5.3 5.5-5.3s5.5 2 5.5 5.3"/>',
      "Program Execution": '<path d="M8.6 1.5L3 9h4l-.6 5.5L13 7h-4z"/>',
      "Recovery": '<path d="M3 8a5 5 0 1 1 1.6 3.7"/><path d="M3 11.5V8h3.5"/>',
      "Archives and Containers": '<rect x="1.7" y="4" width="12.6" height="10" rx="1"/><path d="M1.7 7h12.6"/><path d="M6.8 4v10M9.2 4v1.4M9.2 7v1.4M9.2 10v1.4"/>',
      "Databases": '<ellipse cx="8" cy="3.6" rx="5.5" ry="2.1"/><path d="M2.5 3.6v8.8c0 1.16 2.46 2.1 5.5 2.1s5.5-.94 5.5-2.1V3.6"/><path d="M2.5 8c0 1.16 2.46 2.1 5.5 2.1s5.5-.94 5.5-2.1"/>',
      "Cloud and Web": '<path d="M4.8 12.5a3.3 3.3 0 0 1-.5-6.55A4 4 0 0 1 12 5a3 3 0 0 1 .8 5.9v.1"/><path d="M5 12.5h7"/>',
      "Location and Maps": '<path d="M8 14.3S3 9.7 3 6.3a5 5 0 0 1 10 0c0 3.4-5 8-5 8z"/><circle cx="8" cy="6.2" r="1.7"/>',
      "Mobile Devices": '<rect x="4.5" y="1.5" width="7" height="13" rx="1.2"/><path d="M6.8 12.3h2.4"/>',
      "Development and Source Code": '<path d="M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5M9 3l-2 10"/>',
      "Security and Encryption": '<rect x="3" y="7.3" width="10" height="7.2" rx="1"/><path d="M5 7.3V5a3 3 0 0 1 6 0v2.3"/><circle cx="8" cy="10.6" r="1"/>',
      "Uncategorized": '<circle cx="8" cy="8" r="6.5"/><path d="M6.1 6.2a2 2 0 1 1 2.7 1.9c-.7.3-1.2.9-1.2 1.7v.3"/><circle cx="7.9" cy="11.5" r="0.15" fill="currentColor" stroke="none"/>',
      "Other Files": '<path d="M4 1.5h5.5L12 4v10.5H4z"/><path d="M9.5 1.5V4H12"/>'
    };
    const DEFAULT_CATEGORY_ICON_SHAPE = '<circle cx="8" cy="8" r="1.4" fill="currentColor" stroke="none"/>';

    function svgIconHtml(shape, className, title) {
      return `<svg class="icon ${escapeAttr(className)}" viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${title ? ` role="img"` : ""}>${title ? `<title>${escapeHtml(title)}</title>` : ""}${shape}</svg>`;
    }

    function categoryIconHtml(mainName, title) {
      const shape = CATEGORY_ICON_SHAPES[mainName] || DEFAULT_CATEGORY_ICON_SHAPE;
      return svgIconHtml(shape, "category-icon", title || mainName || "");
    }

    const FILE_ICON_SHAPES = {
      folder: '<path d="M1.7 4.2c0-.66.54-1.2 1.2-1.2h3.1l1.3 1.6h5.8c.66 0 1.2.54 1.2 1.2v6.4c0 .66-.54 1.2-1.2 1.2H2.9c-.66 0-1.2-.54-1.2-1.2z"/>',
      image: '<rect x="1.5" y="2.5" width="13" height="11" rx="1"/><circle cx="5.5" cy="6" r="1.3"/><path d="M2 12l3.5-4 2.5 2.8 2-2.3L14 12"/>',
      video: '<rect x="1.5" y="3" width="13" height="10" rx="1"/><path d="M6.6 6v4l3.4-2z" fill="currentColor" stroke="none"/>',
      audio: '<path d="M5 10.5V4l7-1.5v6"/><circle cx="4" cy="11.3" r="1.7"/><circle cx="10.5" cy="9.8" r="1.7"/>',
      pdf: '<path d="M4 1.5h5.5L12 4v10.5H4z"/><path d="M9.5 1.5V4H12"/><path d="M5.3 11.5V8.3h.9c.6 0 1 .4 1 1s-.4 1-1 1h-.9M8.5 11.5V8.3h.9c.7 0 1.2.5 1.2 1.6s-.5 1.6-1.2 1.6zM11.4 8.3v3.2M11.4 9.8h1.2"/>',
      document: '<path d="M4 1.5h5.5L12 4v10.5H4z"/><path d="M9.5 1.5V4H12"/><path d="M5.8 8h4.4M5.8 10.2h4.4"/>',
      presentation: '<rect x="2" y="2.5" width="12" height="9" rx="1"/><path d="M8 11.5v2.5M5.5 14h5"/><path d="M5 9V5.3h2c1.1 0 1.8.7 1.8 1.8S8.1 9 7 9z"/>',
      spreadsheet: '<rect x="2.5" y="2.5" width="11" height="11" rx="1"/><path d="M2.5 6.2h11M2.5 9.8h11M6.5 2.5v11M10.5 2.5v11"/>',
      archive: '<rect x="1.7" y="4" width="12.6" height="10" rx="1"/><path d="M1.7 7h12.6"/><path d="M6.8 4v10M9.2 4v1.4M9.2 7v1.4M9.2 10v1.4"/>',
      "disk-image": '<ellipse cx="8" cy="4" rx="6" ry="2.2"/><path d="M2 4v8c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2V4"/><path d="M2 8c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2"/>',
      executable: '<circle cx="8" cy="8" r="6.3"/><path d="M6 5.3L9.3 8 6 10.7"/>',
      email: '<rect x="1.5" y="3" width="13" height="10" rx="1"/><path d="M2 3.8l6 5 6-5"/>',
      ads: '<path d="M1.7 4.2c0-.66.54-1.2 1.2-1.2h3.1l1.3 1.6h5.8c.66 0 1.2.54 1.2 1.2v6.4c0 .66-.54 1.2-1.2 1.2H2.9c-.66 0-1.2-.54-1.2-1.2z"/><path d="M9.5 6.5l3 3M12.5 6.5l-3 3"/>',
      generic: '<path d="M4 1.5h5.5L12 4v10.5H4z"/><path d="M9.5 1.5V4H12"/>'
    };

    const FILE_EXTENSION_ICON_SLUG = {
      jpg: "image", jpeg: "image", png: "image", gif: "image", bmp: "image", tif: "image", tiff: "image",
      heic: "image", heif: "image", webp: "image", ico: "image", svg: "image", psd: "image", raw: "image",
      cr2: "image", nef: "image", arw: "image", dng: "image",
      mp4: "video", mov: "video", avi: "video", mkv: "video", wmv: "video", m4v: "video", "3gp": "video",
      webm: "video", flv: "video", mpg: "video", mpeg: "video",
      mp3: "audio", wav: "audio", m4a: "audio", aac: "audio", flac: "audio", ogg: "audio", wma: "audio",
      pdf: "pdf",
      doc: "document", docx: "document", docm: "document", rtf: "document", odt: "document", txt: "document",
      md: "document", wpd: "document",
      xls: "spreadsheet", xlsx: "spreadsheet", xlsm: "spreadsheet", csv: "spreadsheet", ods: "spreadsheet", tsv: "spreadsheet",
      ppt: "presentation", pptx: "presentation", pptm: "presentation", pps: "presentation", ppsx: "presentation", odp: "presentation", key: "presentation",
      zip: "archive", rar: "archive", "7z": "archive", tar: "archive", gz: "archive", tgz: "archive",
      bz2: "archive", xz: "archive", cab: "archive",
      e01: "disk-image", ex01: "disk-image", l01: "disk-image", lx01: "disk-image", aff4: "disk-image",
      dd: "disk-image", img: "disk-image", iso: "disk-image", vhd: "disk-image", vhdx: "disk-image",
      vmdk: "disk-image", vdi: "disk-image", qcow2: "disk-image",
      exe: "executable", dll: "executable", sys: "executable", com: "executable", scr: "executable",
      msi: "executable", bat: "executable", cmd: "executable", ps1: "executable", sh: "executable",
      eml: "email", msg: "email", pst: "email", ost: "email", mbox: "email"
    };

    function fileIconSlug(entry) {
      if (!entry) {
        return "generic";
      }
      if (entry.entry_kind === "directory") {
        return "folder";
      }
      const name = String(entry.name || entry.logical_path || "");
      if (name.includes(":") && !/^[a-zA-Z]:[\\/]/.test(name)) {
        return "ads";
      }
      const ext = filesystemFileExtension(entry);
      const pathText = (String(entry.logical_path || "") + "/" + name).toLowerCase();
      if (ext === "img" && /\/tencent\/|\/qq_games\/|\/qqgames\//.test(pathText.replaceAll("\\\\", "/"))) {
        return "image";
      }
      return FILE_EXTENSION_ICON_SLUG[ext] || "generic";
    }

    function fileIconHtml(entry) {
      const slug = fileIconSlug(entry);
      return svgIconHtml(FILE_ICON_SHAPES[slug] || FILE_ICON_SHAPES.generic, "file-icon file-icon-" + slug, "");
    }

    function filesystemTypeLabel(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      if (!entry) {
        return "";
      }
      if (metadata.artifact_kind === "disk_partition") {
        return "Partition";
      }
      if (metadata.artifact_kind === "unallocated_space" || metadata.is_unallocated) {
        return "Unallocated Space";
      }
      if (entry.entry_kind === "directory") {
        return "Folder";
      }
      if (entry.entry_kind === "file") {
        return archiveOrImageExtension(entry) ? "Image" : "File";
      }
      return activityLabel(entry);
    }

    function archiveOrImageExtension(entry) {
      const ext = filesystemFileExtension(entry);
      return ["zip", "e01", "ex01", "raw", "dd", "img", "iso", "vhd", "vhdx", "vmdk", "vdi"].includes(ext);
    }

    function filesystemFileExtension(entry) {
      if (!entry) {
        return "";
      }
      const metadata = entry.metadata_json || {};
      return firstText(metadata.file_extension, fileExtension(entry.name || entry.logical_path));
    }

    function browserArtifactDisplayTime(metadata, role) {
      const kind = metadata && metadata.artifact_kind;
      if (kind === "browser_history_visit") {
        return firstText(metadata.visit_time_utc, metadata.last_visit_time_utc);
      }
      if (kind === "browser_url") {
        return firstText(metadata.last_visit_time_utc);
      }
      if (kind === "browser_search_term") {
        if (role === "created") {
          return firstText(metadata.last_visit_time_utc, metadata.first_used_utc, metadata.last_used_utc);
        }
        return firstText(metadata.last_visit_time_utc, metadata.last_used_utc, metadata.first_used_utc);
      }
      if (kind === "browser_download") {
        if (role === "modified") {
          return firstText(metadata.end_time_utc, metadata.start_time_utc, metadata.last_modified_utc, metadata.date_added_utc);
        }
        return firstText(metadata.start_time_utc, metadata.end_time_utc, metadata.date_added_utc);
      }
      if (kind === "browser_bookmark") {
        if (role === "created") {
          return firstText(metadata.date_added_utc, metadata.date_last_used_utc, metadata.last_modified_utc);
        }
        if (role === "accessed") {
          return firstText(metadata.date_last_used_utc, metadata.last_modified_utc, metadata.date_added_utc);
        }
        return firstText(metadata.last_modified_utc, metadata.date_last_used_utc, metadata.date_added_utc);
      }
      if (kind === "browser_login") {
        if (role === "created") {
          return firstText(metadata.date_created_utc, metadata.time_created_utc, metadata.date_last_used_utc, metadata.time_last_used_utc);
        }
        if (role === "accessed") {
          return firstText(metadata.date_last_used_utc, metadata.time_last_used_utc, metadata.date_created_utc, metadata.time_created_utc);
        }
        return firstText(metadata.time_password_changed_utc, metadata.date_last_used_utc, metadata.time_last_used_utc, metadata.date_created_utc, metadata.time_created_utc);
      }
      if (kind === "browser_cookie") {
        if (role === "created") {
          return firstText(metadata.creation_utc, metadata.last_access_utc, metadata.last_accessed_utc);
        }
        return firstText(metadata.last_access_utc, metadata.last_accessed_utc, metadata.creation_utc);
      }
      if (kind === "browser_cache_entry") {
        return firstText(metadata.created_utc, metadata.creation_utc, metadata.last_modified_utc);
      }
      return "";
    }

    function artifactEventTime(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(
        metadata.email_date,
        browserArtifactDisplayTime(metadata, "modified"),
        metadata.registry_key_last_write_utc,
        metadata.evtx_logged_utc
      );
    }

    function filesystemFileSha256(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.file_sha256);
    }

    function hasFilesystemTimes(entry) {
      return !!entry && entry.entry_kind !== "record";
    }

    function filesystemCreatedTime(entry) {
      if (!hasFilesystemTimes(entry)) return "";
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_standard_creation_time_utc, metadata.standard_information_created_utc, metadata.ntfs_creation_time_utc, metadata.file_name_created_utc, metadata.created_utc, metadata.fat_created);
    }

    function filesystemAccessedTime(entry) {
      if (!hasFilesystemTimes(entry)) return "";
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_standard_access_time_utc, metadata.standard_information_accessed_utc, metadata.ntfs_access_time_utc, metadata.file_name_accessed_utc, metadata.accessed_utc, metadata.fat_accessed);
    }

    function filesystemModifiedTime(entry) {
      if (!hasFilesystemTimes(entry)) return "";
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_standard_modification_time_utc, metadata.standard_information_modified_utc, metadata.ntfs_modification_time_utc, metadata.file_name_modified_utc, metadata.modified_utc, metadata.fat_modified);
    }

    function filesystemMftModifiedTime(entry) {
      if (!hasFilesystemTimes(entry)) return "";
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.ntfs_standard_mft_record_modification_time_utc, metadata.standard_information_mft_modified_utc, metadata.ntfs_mft_record_modification_time_utc, metadata.file_name_mft_modified_utc, metadata.mft_modified_utc);
    }

    function folderGridColumns() {
      return [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" },
        { key: "name", label: "Name", sortable: true, filterable: true, sortType: "text" },
        { key: "type", label: "Type", sortable: true, filterable: true, sortType: "text" },
        { key: "ext", label: "File ext", sortable: true, filterable: true, sortType: "text" },
        { key: "size", label: "Size", sortable: true, filterable: true, sortType: "number" },
        { key: "artifactTime", label: "Artifact time", sortable: true, filterable: true, sortType: "time" },
        { key: "created", label: "Created", sortable: true, filterable: true, sortType: "time" },
        { key: "accessed", label: "Accessed", sortable: true, filterable: true, sortType: "time" },
        { key: "modified", label: "Modified", sortable: true, filterable: true, sortType: "time" },
        { key: "mftModified", label: "MFT modified", sortable: true, filterable: true, sortType: "time" },
        { key: "sha256", label: "SHA-256", sortable: true, filterable: true, sortType: "text" }
      ];
    }

    function folderGridFolderRow(path, count, countKind, folderEntry) {
      const created = filesystemCreatedTime(folderEntry);
      const accessed = filesystemAccessedTime(folderEntry);
      const modified = filesystemModifiedTime(folderEntry);
      const mftModified = filesystemMftModifiedTime(folderEntry);
      return {
        kind: "folder",
        path,
        count,
        countKind,
        folderEntry,
        selectable: false,
        values: {
          name: logicalName(path),
          type: "Folder",
          ext: "",
          size: "",
          artifactTime: "",
          created,
          accessed,
          modified,
          mftModified,
          sha256: ""
        },
        sortValues: {
          size: NaN,
          artifactTime: NaN,
          created: Date.parse(created),
          accessed: Date.parse(accessed),
          modified: Date.parse(modified),
          mftModified: Date.parse(mftModified)
        }
      };
    }

    function folderGridEntryRow(entry) {
      const created = filesystemCreatedTime(entry);
      const accessed = filesystemAccessedTime(entry);
      const modified = filesystemModifiedTime(entry);
      const mftModified = filesystemMftModifiedTime(entry);
      const artifactTime = artifactEventTime(entry);
      const sha256 = filesystemFileSha256(entry);
      const size = entry.size_bytes == null ? "" : formatBytes(entry.size_bytes);
      return {
        kind: "entry",
        entry,
        selectable: true,
        values: {
          name: entry.name || logicalName(entry.logical_path),
          type: filesystemTypeLabel(entry),
          ext: filesystemFileExtension(entry),
          size,
          artifactTime,
          created,
          accessed,
          modified,
          mftModified,
          sha256
        },
        sortValues: {
          size: entry.size_bytes == null ? NaN : Number(entry.size_bytes),
          artifactTime: Date.parse(artifactTime),
          created: Date.parse(created),
          accessed: Date.parse(accessed),
          modified: Date.parse(modified),
          mftModified: Date.parse(mftModified)
        }
      };
    }

    function renderFolderGridRow(row) {
      if (row.kind === "folder") {
        const folderEntry = row.folderEntry;
        return `
          <tr class="entry-row" onclick="selectFolder('${escapeAttr(escapeJs(row.path))}')"${folderEntry ? ` data-entry-id="${folderEntry.id}"` : ` data-folder-path="${escapeAttr(row.path)}"`}>
            <td></td>
            <td title="${escapeAttr(row.path)}">${svgIconHtml(FILE_ICON_SHAPES.folder, "file-icon file-icon-folder", "")}<span class="entry-name">${escapeHtml(logicalName(row.path))}</span></td>
            <td class="entry-kind" title="${row.count} ${escapeAttr(row.countKind)} item${row.count === 1 ? "" : "s"}">Folder</td>
            <td class="entry-ext"></td>
            <td class="entry-size"></td>
            <td class="entry-time entry-artifact-time"></td>
            <td class="entry-time" title="${escapeAttr(row.values.created)}">${escapeHtml(row.values.created)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.accessed)}">${escapeHtml(row.values.accessed)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.modified)}">${escapeHtml(row.values.modified)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.mftModified)}">${escapeHtml(row.values.mftModified)}</td>
            <td class="entry-hash mono"></td>
          </tr>`;
      }
      const entry = row.entry;
      const selected = state.hex.entryId === entry.id ? " selected" : "";
      const isChecked = state.selectedEntryIds.has(entry.id);
      const checked = isChecked ? " checked" : "";
      const multiSelected = isChecked ? " multi-selected" : "";
      return `
          <tr class="entry-row${selected}${multiSelected}" data-entry-id="${entry.id}" onclick="handleEntryRowClick(event, ${entry.id})">
            <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleEntrySelection(${entry.id}, this.checked, event)"></td>
            <td title="${escapeAttr(entry.logical_path)}">${fileIconHtml(entry)}<span class="entry-name">${escapeHtml(entry.name || logicalName(entry.logical_path))}</span></td>
            <td class="entry-kind">${escapeHtml(filesystemTypeLabel(entry))}</td>
            <td class="entry-ext">${escapeHtml(filesystemFileExtension(entry))}</td>
            <td class="entry-size">${entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)}</td>
            <td class="entry-time entry-artifact-time" title="${escapeAttr(row.values.artifactTime)}">${escapeHtml(row.values.artifactTime)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.created)}">${escapeHtml(row.values.created)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.accessed)}">${escapeHtml(row.values.accessed)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.modified)}">${escapeHtml(row.values.modified)}</td>
            <td class="entry-time" title="${escapeAttr(row.values.mftModified)}">${escapeHtml(row.values.mftModified)}</td>
            <td class="entry-hash mono" title="${escapeAttr(row.values.sha256)}">${escapeHtml(row.values.sha256)}</td>
          </tr>`;
    }

    function visibleFolderGridRows(entries, knownFolders) {
      const synthetic = syntheticContainerSet(knownFolders);
      const folder = normalizeLogicalPath(state.browserState.selectedPath || "/");
      const childFolders = displayChildFolders(knownFolders, folder, synthetic);
      const children = applyDateFilter(displayFolderChildren(entries, folder, synthetic));
      let folderSpecs = childFolders.map((path) => ({
        path,
        count: displayFolderChildCount(entries, knownFolders, path, synthetic),
        countKind: "direct"
      }));
      if (dateFilterActive()) {
        const passing = applyDateFilter(entries);
        folderSpecs = folderSpecs
          .map((spec) => {
            const normalized = normalizeLogicalPath(spec.path);
            const prefix = normalized === "/" ? "/" : normalized + "/";
            const matches = passing.filter((entry) => {
              const entryPath = normalizeLogicalPath(entry.logical_path);
              return entryPath === normalized || entryPath.startsWith(prefix);
            }).length;
            return { path: spec.path, count: matches, countKind: "matching" };
          })
          .filter((spec) => spec.count > 0);
      }
      const folderRows = folderSpecs.map(({ path, count, countKind }) => {
        const folderEntry = entries.find((entry) =>
          entry.entry_kind === "directory" && normalizeLogicalPath(entry.logical_path) === normalizeLogicalPath(path)
        );
        return folderGridFolderRow(path, count, countKind, folderEntry);
      });
      return visibleGridRows("folder", folderGridColumns(), folderRows.concat(children.map(folderGridEntryRow)));
    }

    function renderFolderContents(entries, knownFolders) {
      const synthetic = syntheticContainerSet(knownFolders);
      const folder = normalizeLogicalPath(state.browserState.selectedPath || "/");
      $("folderTitle").textContent = displayPath(folder) + (dateFilterActive() ? " (date filtered)" : "");
      const childFolders = displayChildFolders(knownFolders, folder, synthetic);
      const children = applyDateFilter(displayFolderChildren(entries, folder, synthetic));
      const status = truncatedEntriesNoticeHtml() + imageAnalysisStatusHtml(entries);
      // Folder rows follow the date filter too: keep a folder only when its own
      // timestamps match or its subtree still contains a matching entry, so
      // navigation always leads somewhere with results.
      let folderSpecs = childFolders.map((path) => ({
        path,
        count: displayFolderChildCount(entries, knownFolders, path, synthetic),
        countKind: "direct"
      }));
      if (dateFilterActive()) {
        const passing = applyDateFilter(entries);
        folderSpecs = folderSpecs
          .map((spec) => {
            const normalized = normalizeLogicalPath(spec.path);
            const prefix = normalized === "/" ? "/" : normalized + "/";
            const matches = passing.filter((entry) => {
              const entryPath = normalizeLogicalPath(entry.logical_path);
              return entryPath === normalized || entryPath.startsWith(prefix);
            }).length;
            return { path: spec.path, count: matches, countKind: "matching" };
          })
          .filter((spec) => spec.count > 0);
      }
      if (folderSpecs.length === 0 && children.length === 0) {
        $("entryTable").innerHTML = status + empty(dateFilterActive()
          ? "No entries in this folder match the date filter."
          : "No entries in this folder.");
        setCurrentEntryGrid("folder", []);
        renderSelectionCount();
        return;
      }
      const folderRows = folderSpecs.map(({ path, count, countKind }) => {
        const folderEntry = entries.find((entry) =>
          entry.entry_kind === "directory" && normalizeLogicalPath(entry.logical_path) === normalizeLogicalPath(path)
        );
        return folderGridFolderRow(path, count, countKind, folderEntry);
      });
      const columns = folderGridColumns();
      const gridRows = folderRows.concat(children.map(folderGridEntryRow));
      const tableResult = sortableGridTable("folder", columns, gridRows, "folder-table", renderFolderGridRow);
      setCurrentEntryGrid("folder", tableResult.visibleRows.filter((row) => row.selectable).map((row) => row.entry));
      const filterStatus = gridFilterStatusHtml("folder", columns, tableResult.visibleRows.length, gridRows.length, "items");
      $("entryTable").innerHTML = status + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No folder items match the column filters."));
      renderSelectionCount();
    }

    function truncatedEntriesNoticeHtml() {
      if (!state.data || !state.data.entries_truncated) {
        return "";
      }
      const total = (state.data.entry_count || 0).toLocaleString();
      const shown = (state.data.entries_limit || state.data.entries.length).toLocaleString();
      return `<div class="analysis-status">This case has ${total} indexed entries; only the first ${shown} are loaded in this indexed view (loading all of them would hang the browser). Use <strong>Browse source</strong> to navigate the whole disk directly, or <strong>Deep Search</strong> to find specific files.</div>`;
    }

    function imageAnalysisStatusHtml(entries) {
      const evidence = selectedEvidenceSource();
      if (!evidence || !(evidence.source_kind === "image" || looksLikeDiskImage(evidence.source_path))) {
        return "";
      }
      const hasParsedVolume = entries.some((entry) =>
        entry.entry_kind === "directory"
        && entry.metadata_json
        && entry.metadata_json.artifact_kind === "filesystem_volume"
      );
      if (hasParsedVolume) {
        return "";
      }
      const wholeVolume = entries.find((entry) =>
        entry.metadata_json
        && entry.metadata_json.artifact_kind === "disk_volume"
        && entry.metadata_json.start_offset === 0
      );
      if (wholeVolume && wholeVolume.metadata_json.filesystem) {
        const fs = wholeVolume.metadata_json.filesystem;
        return `<div class="analysis-status">Detected a whole-image ${escapeHtml(fs)} volume at byte 0. Folder browsing for ${escapeHtml(fs)} is not indexed yet.</div>`;
      }
      const report = entries.find((entry) =>
        entry.metadata_json
        && entry.metadata_json.artifact_kind === "disk_partition_report"
      );
      if (report && report.metadata_json && report.metadata_json.error) {
        return `<div class="analysis-status">No browsable filesystem was indexed. Partition analysis reported: ${escapeHtml(report.metadata_json.error)}</div>`;
      }
      return "";
    }

    function renderSelectionCount() {
      const count = state.live.active
        ? selectedVisibleLiveItems().length
        : selectedEntriesForActions().length;
      $("selectedCount").textContent = count + " selected";
      updateSelectedActionControls();
    }

    function selectedEntriesForActions() {
      const selected = state.selectedEntryIds || new Set();
      return visibleFolderEntries().filter((entry) => entry && selected.has(entry.id));
    }

    function selectedFileEntryCount() {
      return selectedEntriesForActions().filter((entry) => entry.entry_kind === "file").length;
    }

    function selectedFileExportAllowed() {
      if (state.live.active) {
        return selectedVisibleLiveItems().length > 0;
      }
      return selectedFileEntryCount() > 0;
    }

    function fileExportUnavailableMessage() {
      if (state.live.active) {
        return "Select one or more live files or folders before exporting.";
      }
      return "Selected rows are records or folders. Use Report selected to add them to the report; only file entries have bytes to export.";
    }

    function updateSelectedActionControls() {
      const reportButton = $("bookmarkReportSelected");
      const selectedAction = $("selectedAction");
      const count = state.live.active
        ? selectedVisibleLiveItems().length
        : selectedEntriesForActions().length;
      if (reportButton) {
        reportButton.disabled = count === 0;
      }
      if (!selectedAction) {
        return;
      }
      const exportOption = selectedAction.querySelector('option[value="export_files"]');
      if (!exportOption) {
        return;
      }
      if (state.live.active) {
        exportOption.disabled = count === 0;
        exportOption.textContent = "Export selected source items";
        return;
      }
      const fileCount = selectedFileEntryCount();
      exportOption.disabled = fileCount === 0;
      exportOption.textContent = fileCount > 0 && fileCount < count
        ? "Export file bytes (" + fileCount + ")"
        : "Export selected file bytes";
    }

    function activityLabel(entry) {
      if (isEmailEntry(entry)) {
        return "Email";
      }
      if (entry.entry_kind !== "record") {
        return entry.entry_kind;
      }
      const kind = entry.metadata_json && entry.metadata_json.artifact_kind;
      if (kind === "browser_history_visit") return "Visit";
      if (kind === "browser_url") return "URL";
      if (kind === "browser_search_term") return "Search";
      if (kind === "browser_download") return "Download";
      if (kind === "browser_bookmark") return "Bookmark";
      if (kind === "browser_login") return "Saved Login";
      if (kind === "browser_cookie") return "Cookie";
      if (kind === "browser_preference") return "Preference";
      return "Record";
    }

    function entrySummary(entry) {
      const metadata = entry.metadata_json || {};
      if (isEmailEntry(entry)) {
        return emailPreview(entry);
      }
      if (isBrowserActivityEntry(entry)) {
        return browserActivityPreview(entry);
      }
      if (metadata.url) {
        return metadata.visit_time_utc ? metadata.visit_time_utc + " | " + metadata.url : metadata.url;
      }
      if (metadata.analysis_category || metadata.category_main) {
        return compactParts([entryCategoryLabel(entry), entry.logical_path]);
      }
      if (metadata.category) {
        return compactParts([metadata.category, entry.logical_path]);
      }
      return entry.logical_path;
    }

    function idxBrowseActive() {
      return !!(state.data && state.data.entries_truncated
        && state.browserState.treeMode !== "categories"
        && state.idx.evidenceId
        && state.idx.evidenceId === state.browserState.evidenceId);
    }

    function visibleFolderEntries() {
      if (state.currentEntryGrid && state.currentEntryGrid.gridId) {
        return state.currentEntryGrid.entries || [];
      }
      if (state.browserState.treeMode === "categories") {
        if (serverCategoryBrowseActive()) {
          return applyDateFilter(state.cat.entries || []);
        }
        return applyDateFilter(categoryEntriesForSelection(selectedEvidenceEntries(), state.browserState.selectedCategory || ""));
      }
      if (idxBrowseActive()) {
        return (state.idx.dirCache[state.idx.selPath || "/"] || [])
          .filter((child) => !child.is_dir && child.entry_id != null)
          .map(idxChildToEntry);
      }
      return folderChildren(selectedEvidenceEntries(), state.browserState.selectedPath || "/");
    }

    function visibleEntryIds() {
      return visibleFolderEntries()
        .filter((entry) => entry.entry_kind !== "directory")
        .map((entry) => entry.id);
    }

    function selectedEvidenceSource() {
      if (!state.data || !state.browserState.evidenceId) {
        return null;
      }
      return state.data.evidence.find((item) => item.id === state.browserState.evidenceId) || null;
    }

    function evidenceSourceForEntry(entry) {
      if (!state.data || !entry) {
        return null;
      }
      return state.data.evidence.find((item) => item.id === entry.evidence_id) || null;
    }

    function isPromotableDiskImageEntry(entry, evidence) {
      return !!entry
        && !!evidence
        && entry.entry_kind === "file"
        && (evidence.source_kind === "folder" || evidence.source_kind === "file")
        && looksLikeDiskImage(entry.name || entry.logical_path)
        && !!evidenceEntryLocalPath(evidence, entry);
    }

    function evidenceEntryLocalPath(evidence, entry) {
      if (!evidence || !entry) {
        return null;
      }
      if (evidence.source_kind === "file") {
        return evidence.source_path;
      }
      if (evidence.source_kind !== "folder") {
        return null;
      }
      const parts = normalizeLogicalPath(entry.logical_path).split("/").filter(Boolean);
      return joinLocalPath(evidence.source_path, parts);
    }

    function joinLocalPath(root, parts) {
      const baseValue = String(root || "");
      if (!baseValue || !parts || parts.length === 0) {
        return baseValue;
      }
      const windowsPath = /^[A-Za-z]:[\\/]/.test(baseValue) || baseValue.startsWith("\\\\") || baseValue.startsWith("//");
      const sep = windowsPath ? "\\" : "/";
      let base = baseValue;
      while (base.length > 3 && /[\\/]$/.test(base)) {
        base = base.slice(0, -1);
      }
      return (/[\\/]$/.test(base) ? base : base + sep) + parts.join(sep);
    }

    function sameLocalPath(left, right) {
      const normalize = (value) => String(value || "")
        .replace(/^\\\\\?\\/, "")
        .replace(/\\/g, "/")
        .replace(/\/+$/g, "")
        .toLowerCase();
      return normalize(left) === normalize(right);
    }

    function defaultRecoveryPath(entry) {
      const root = BOOTSTRAP.workspaceRoot || ".";
      const folder = recoveryActionText(entry).folder;
      return joinLocalPath(joinLocalPath(root, ["ui-output", folder]), [
        String(entry.id) + "-" + safeFileName(entry.name || logicalName(entry.logical_path) || "recovered.bin")
      ]);
    }

    function isDeletedRecoveryEntry(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return Boolean(entry && (
        entry.is_deleted
        || metadata.recovery_source === "ntfs_deleted_mft"
        || metadata.artifact_kind === "deleted_file_record"
      ));
    }

    function isRecoveryEntry(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return Boolean(entry && (
        isDeletedRecoveryEntry(entry)
        || metadata.artifact_kind === "unallocated_space"
        || metadata.is_unallocated
        || metadata.is_file_slack
      ));
    }

    function recoveryActionText(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      if (metadata.artifact_kind === "unallocated_space" || metadata.is_unallocated) {
        return { button: "Export unallocated", prompt: "Export unallocated stream", past: "Exported", folder: "exported" };
      }
      if (metadata.is_file_slack) {
        return { button: "Export slack", prompt: "Export file slack", past: "Exported", folder: "exported" };
      }
      if (isDeletedRecoveryEntry(entry)) {
        return { button: "Recover", prompt: "Recover file", past: "Recovered", folder: "recovered" };
      }
      return { button: "Export file", prompt: "Export file", past: "Exported", folder: "exported" };
    }

    function safeFileName(value) {
      const cleaned = String(value || "recovered.bin")
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
        .replace(/\s+/g, " ")
        .trim();
      return cleaned || "recovered.bin";
    }

    function categorizedVisibleEntries(entries) {
      return entries.filter((entry) => {
        if (entry.entry_kind === "directory") return false;
        const metadata = entry.metadata_json || {};
        if (metadata.category_hidden === true || metadata.category_hidden === 1) return false;
        if (metadata.artifact_kind === "filesystem_parser_error"
          || metadata.artifact_kind === "filesystem_parser_summary") return false;
        return !(metadata.category_main === "Operating System" && metadata.category_sub === "System files");
      });
    }

    function categoryEntriesForSelection(entries, key) {
      const selected = splitCategoryKey(key || "");
      return categorizedVisibleEntries(entries)
        .filter((entry) => {
          if (!selected.main) {
            return true;
          }
          const category = entryCategory(entry);
          if (category.main !== selected.main) {
            return false;
          }
          return !selected.sub || category.sub === selected.sub;
        })
        .sort((left, right) => {
          const leftCategory = entryCategoryLabel(left);
          const rightCategory = entryCategoryLabel(right);
          return leftCategory.localeCompare(rightCategory) || compareEntries(left, right);
        });
    }

    function entryCategoryLabel(entry) {
      const category = entryCategory(entry);
      return category.sub ? category.main + " / " + category.sub : category.main;
    }

    function entryCategoryDetail(entry) {
      const metadata = entry.metadata_json || {};
      return firstText(metadata.category_detail, metadata.analysis_category, entrySummary(entry));
    }

    function entryCategory(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.category_main !== undefined && metadata.category_main !== null && String(metadata.category_main).trim()) {
        return {
          main: String(metadata.category_main),
          sub: metadata.category_sub === undefined || metadata.category_sub === null ? "" : String(metadata.category_sub)
        };
      }
      return { main: "Uncategorized", sub: "" };
    }

    function inferEntryCategory(entry) {
      const metadata = entry.metadata_json || {};
      const artifact = metadata.artifact_kind || "";
      if (artifact === "browser_history_visit") return { main: "Web Activity", sub: "Visits" };
      if (artifact === "browser_url") return { main: "Web Activity", sub: "URLs" };
      if (artifact === "browser_search_term") return { main: "Web Activity", sub: "Searches" };
      if (artifact === "browser_download") return { main: "Web Activity", sub: "Downloads" };
      if (artifact === "browser_cookie") return { main: "Accounts and Identity", sub: "Cookies and sessions" };
      if (artifact === "browser_bookmark") return { main: "Web Activity", sub: "Bookmarks" };
      if (artifact === "browser_preference") return { main: "Accounts and Identity", sub: "Browser profile settings" };
      if (["windows_local_account", "windows_domain_account", "browser_account"].includes(artifact)) return { main: "Accounts and Identity", sub: "Local and domain accounts" };
      if (["credential_store", "secret_store"].includes(artifact)) return { main: "Accounts and Identity", sub: "Credential and secret stores" };
      if (artifact === "plaintext_secret") return { main: "Accounts and Identity", sub: "Recovered plaintext secrets" };
      if (artifact === "host_identity") return { main: "Accounts and Identity", sub: "Hosts and computer names" };
      if (artifact === "network_configuration") return { main: "Network and Connectivity", sub: "IP and network configuration" };
      if (artifact === "wifi_profile") return { main: "Network and Connectivity", sub: "Wi-Fi profiles" };
      if (["windows_amcache_record", "windows_userassist_record", "windows_shimcache_record"].includes(artifact)) return { main: "Program Execution", sub: "Execution artifacts" };
      if (["windows_scheduled_task", "windows_startup_record"].includes(artifact)) return { main: "Program Execution", sub: "Startup and scheduled tasks" };
      if (artifact === "windows_shellbag_record") return { main: "User Activity", sub: "Shellbags" };
      if (artifact === "email_message") return { main: "Email and Communications", sub: "Email messages" };
      if (artifact === "email_store") return { main: "Email and Communications", sub: "Email stores" };
      if (artifact === "deleted_file_record" || metadata.recovery_source === "ntfs_deleted_mft" || entry.is_deleted) return { main: "Recovery", sub: "Deleted files" };
      if (artifact === "unallocated_space" || metadata.is_unallocated) return { main: "Recovery", sub: "Unallocated space" };
      if (/disk_|filesystem_/.test(artifact)) return { main: "Operating System", sub: "Disk and filesystem structure" };

      const text = (String(entry.logical_path || "") + "/" + String(entry.name || "")).toLowerCase();
      const ext = fileExtension(entry.name || entry.logical_path);
      const filename = String(entry.name || logicalName(entry.logical_path) || "").toLowerCase();
      const browserContext = /chrome|chromium|microsoft[\/\\]edge|mozilla|firefox|safari|opera|brave|vivaldi|netscape|internet explorer|temporary internet files|content\.ie5|browser/.test(text);
      if (ext === "img" && /[\\\/]tencent[\\\/]|[\\\/]qq_games[\\\/]|[\\\/]qqgames[\\\/]/.test(text)) return { main: "Pictures and Media", sub: "Graphics and design" };
      if (hasExt(ext, ["jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "heif", "webp", "cr2", "nef", "arw", "dng", "svg", "ico", "psd", "ai", "emf", "wmf", "jfif", "raf", "orf"])) return { main: "Pictures and Media", sub: "Pictures" };
      if (hasExt(ext, ["mp4", "mov", "avi", "mkv", "wmv", "m4v", "3gp", "webm", "flv", "mpg", "mpeg", "ts", "m2ts", "vob", "ogv", "asf", "rm"])) return { main: "Pictures and Media", sub: "Video" };
      if (hasExt(ext, ["mp3", "wav", "m4a", "aac", "flac", "ogg", "wma", "amr", "mid", "midi", "aif", "aiff", "ape", "opus", "ra", "au"])) return { main: "Pictures and Media", sub: "Audio" };
      if (hasExt(ext, ["eml"])) return { main: "Email and Communications", sub: "Email messages" };
      if (hasExt(ext, ["pst", "ost", "msg", "mbox", "olm", "dbx", "nsf", "edb"]) && /mail|exchange|outlook/.test(text)) return { main: "Email and Communications", sub: "Email stores" };
      if (hasExt(ext, ["pst", "ost", "msg", "mbox", "olm", "dbx", "nsf"])) return { main: "Email and Communications", sub: "Email stores" };
      const knownCredentialStore = hasExt(ext, ["kdbx", "kdb", "psafe3"])
        || ((browserContext || /[\/\\]users[\/\\]/.test(text))
          && ["login data", "key4.db", "key3.db", "logins.json", "signons.sqlite", "cert9.db", "wallet.dat"].includes(filename))
        || /[\/\\]microsoft[\/\\](credentials|vault|protect)[\/\\]/.test(text)
        || /[\/\\]\.ssh[\/\\](id_rsa|id_dsa|id_ecdsa|id_ed25519)$/.test(text)
        || /[\/\\]\.aws[\/\\]credentials$/.test(text);
      if (knownCredentialStore) return { main: "Accounts and Identity", sub: "Credential and secret stores" };
      if (hasExt(ext, ["pem", "cer", "crt", "der", "pfx", "p12", "p7b", "csr", "gpg", "asc", "sig"])) return { main: "Accounts and Identity", sub: "Certificates and keys" };
      if (/onedrive|dropbox|google drive|icloud|\/box\//.test(text)) return { main: "Cloud and Web", sub: "Cloud sync" };
      // Generic words (history/cache/...) only mean browser artifacts inside a
      // browser path; otherwise system32/dllcache etc. classify as web content.
      if (/places\.sqlite|webcachev01\.dat|favicons|top sites|visited links/.test(text) || (browserContext && /history|cache|bookmarks|downloads/.test(text))) return { main: "Cloud and Web", sub: "Browser artifacts" };
      if (hasExt(ext, ["html", "htm", "mht", "mhtml", "xhtml", "css", "url", "webloc"])) return { main: "Cloud and Web", sub: "Web pages and links" };
      if (hasExt(ext, ["torrent", "ica", "rdp", "ovpn", "pcap", "pcapng"])) return { main: "Cloud and Web", sub: "Network and remote access" };
      const exactExecutionSource = (ext === "pf" && /[\/\\]windows[\/\\]prefetch[\/\\]/.test(text))
        || (filename === "amcache.hve" && /[\/\\]windows[\/\\]appcompat[\/\\]programs[\/\\]/.test(text))
        || ext === "lnk"
        || filename.endsWith(".automaticdestinations-ms")
        || filename.endsWith(".customdestinations-ms");
      if (exactExecutionSource) return { main: "Program Execution", sub: "Execution artifacts" };
      if (hasExt(ext, ["exe", "dll", "sys", "com", "scr", "msi", "msp", "msu", "cpl", "ocx", "drv", "efi", "bin", "so", "dylib", "apk", "ipa", "app", "appx", "xap"])) return { main: "Program Execution", sub: "Executables and binaries" };
      if (hasExt(ext, ["bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "jar", "sh", "hta", "scpt", "applescript"])) return { main: "Program Execution", sub: "Scripts" };
      if (/\/windows\/system32\/config\/|\/ntuser\.dat|\/usrclass\.dat/.test(text) || hasExt(ext, ["hiv", "reg"])) return { main: "Operating System", sub: "Registry hives" };
      if (/\.evtx|\.etl|winevt\/logs/.test(text) || hasExt(ext, ["evtx", "evt", "etl", "log"])) return { main: "Operating System", sub: "Logs and events" };
      if (hasExt(ext, ["dmp", "mdmp", "hdmp", "chk"]) || /pagefile\.sys|hiberfil\.sys|swapfile\.sys|memory\.dmp/.test(text)) return { main: "Operating System", sub: "Memory and crash dumps" };
      if (hasExt(ext, ["ini", "inf", "cfg", "conf", "config", "plist", "pol", "admx", "adml", "manifest", "cat", "mum"])) return { main: "Operating System", sub: "Configuration files" };
      if (hasExt(ext, ["ttf", "otf", "ttc", "fon", "woff", "woff2", "eot"])) return { main: "Operating System", sub: "Fonts" };
      if (hasExt(ext, ["cur", "ani", "theme", "deskthemepack", "scf", "library-ms", "searchconnector-ms"])) return { main: "Operating System", sub: "Shell and appearance" };
      if (hasExt(ext, ["pdf", "xps", "oxps"])) return { main: "Documents and Office", sub: "PDF and fixed layout" };
      if (hasExt(ext, ["doc", "docx", "docm", "dot", "dotx", "rtf", "odt", "wpd", "pages", "one", "onetoc2"])) return { main: "Documents and Office", sub: "Word processing" };
      if (hasExt(ext, ["xls", "xlsx", "xlsm", "xlsb", "xlt", "csv", "tsv", "ods", "numbers"])) return { main: "Documents and Office", sub: "Spreadsheets" };
      if (hasExt(ext, ["ppt", "pptx", "pptm", "pps", "ppsx", "odp", "key"])) return { main: "Documents and Office", sub: "Presentations" };
      if (hasExt(ext, ["txt", "text", "md", "nfo", "readme"])) return { main: "Documents and Office", sub: "Plain text" };
      if (hasExt(ext, ["epub", "mobi", "azw", "azw3", "fb2", "chm", "hlp", "djvu"])) return { main: "Documents and Office", sub: "E-books and help" };
      if (hasExt(ext, ["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzh", "arj", "z", "cab", "wim", "swm", "deb", "rpm", "pkg", "dmg"])) return { main: "Archives and Containers", sub: "Archives" };
      if (hasExt(ext, ["e01", "ex01", "l01", "lx01", "aff4", "ad1", "raw", "dd", "img", "iso", "vhd", "vhdx", "vmdk", "vdi", "qcow2", "ova", "ovf", "vmem", "vmsn", "vmss", "nvram"])) return { main: "Archives and Containers", sub: "Disk images and VM files" };
      if (hasExt(ext, ["db", "sqlite", "sqlite3", "sqlitedb", "db3", "db-wal", "db-shm", "mdb", "accdb", "edb", "sdf", "frm", "ibd", "myd", "realm", "mdf", "ldf", "bak"])) return { main: "Databases", sub: "Application databases" };
      if (hasExt(ext, ["py", "rs", "go", "java", "cs", "cpp", "c", "h", "hpp", "php", "rb", "ts", "tsx", "jsx", "swift", "kt", "pl", "lua", "sql", "json", "xml", "yaml", "yml", "toml", "sln", "csproj", "gradle", "makefile"])) return { main: "Development and Source Code", sub: "Source and project files" };
      if (hasExt(ext, ["bup", "spf", "spi", "gho", "tib", "vbk", "vib"])) return { main: "Archives and Containers", sub: "Backups" };
      if (hasExt(ext, ["tmp", "temp", "crdownload", "partial", "part", "download"])) return { main: "Other Files", sub: "Temporary and partial files" };
      if (!ext) return { main: "Other Files", sub: "No extension" };
      return { main: "Other Files", sub: "Other extensions" };
    }

    function categoryTime(entry) {
      const metadata = entry.metadata_json || {};
      return firstText(
        artifactEventTime(entry),
        filesystemModifiedTime(entry),
        filesystemMftModifiedTime(entry),
        filesystemCreatedTime(entry)
      );
    }

    const TIMELINE_HOUR_MS = 60 * 60 * 1000;
    const TIMELINE_DAY_MS = 24 * TIMELINE_HOUR_MS;
    const TIMELINE_TABLE_RENDER_LIMIT = 2000;
    const TIMELINE_METADATA_TIME_FIELDS = [
      { key: "email_date", label: "Email Date/Time" },
      { key: "visit_time_utc", label: "Visit Date/Time" },
      { key: "last_visit_time_utc", label: "Last Visit Date/Time" },
      { key: "first_used_utc", label: "First Used Date/Time" },
      { key: "last_used_utc", label: "Last Used Date/Time" },
      { key: "date_added_utc", label: "Added Date/Time" },
      { key: "date_last_used_utc", label: "Last Used Date/Time" },
      { key: "start_time_utc", label: "Started Date/Time" },
      { key: "end_time_utc", label: "Ended Date/Time" },
      { key: "date_created_utc", label: "Created Date/Time" },
      { key: "time_created_utc", label: "Created Date/Time" },
      { key: "time_last_used_utc", label: "Last Used Date/Time" },
      { key: "time_password_changed_utc", label: "Password Changed Date/Time" },
      { key: "creation_utc", label: "Created Date/Time" },
      { key: "last_access_time_utc", label: "Last Access Date/Time" },
      { key: "last_access_utc", label: "Last Access Date/Time" },
      { key: "last_accessed_utc", label: "Last Access Date/Time" },
      { key: "expires_utc", label: "Expires Date/Time" },
      { key: "expiry_utc", label: "Expires Date/Time" },
      { key: "last_modified_utc", label: "Last Modified Date/Time" },
      { key: "created_utc", label: "Created Date/Time" },
      { key: "accessed_utc", label: "Accessed Date/Time" },
      { key: "modified_utc", label: "Last Modified Date/Time" },
      { key: "mft_modified_utc", label: "MFT Modified Date/Time" },
      { key: "file_name_created_utc", label: "File Name Created Date/Time" },
      { key: "file_name_accessed_utc", label: "File Name Accessed Date/Time" },
      { key: "file_name_modified_utc", label: "File Name Modified Date/Time" },
      { key: "file_name_mft_modified_utc", label: "File Name MFT Modified Date/Time" },
      { key: "standard_information_created_utc", label: "Standard Info Created Date/Time" },
      { key: "standard_information_accessed_utc", label: "Standard Info Accessed Date/Time" },
      { key: "standard_information_modified_utc", label: "Standard Info Modified Date/Time" },
      { key: "standard_information_mft_modified_utc", label: "Standard Info MFT Modified Date/Time" },
      { key: "registry_key_last_write_utc", label: "Registry Last Write Date/Time" },
      { key: "evtx_logged_utc", label: "Logged Date/Time" },
      // NTFS/FAT parser keys - kept in sync with TIMELINE_TIME_FIELD_KEYS in
      // kdft-case so the SQL date-range prefilter and this client-side event
      // extraction agree on what counts as a timestamp. Duplicates of what the
      // filesystem*Time helpers already surface are merged by the per-entry
      // timestamp bucket.
      { key: "ntfs_creation_time_utc", label: "NTFS FILE_NAME Created Date/Time" },
      { key: "ntfs_modification_time_utc", label: "NTFS FILE_NAME Modified Date/Time" },
      { key: "ntfs_access_time_utc", label: "NTFS FILE_NAME Accessed Date/Time" },
      { key: "ntfs_mft_record_modification_time_utc", label: "NTFS FILE_NAME MFT Modified Date/Time" },
      { key: "ntfs_standard_creation_time_utc", label: "NTFS STANDARD_INFORMATION Created Date/Time" },
      { key: "ntfs_standard_modification_time_utc", label: "NTFS STANDARD_INFORMATION Modified Date/Time" },
      { key: "ntfs_standard_access_time_utc", label: "NTFS STANDARD_INFORMATION Accessed Date/Time" },
      { key: "ntfs_standard_mft_record_modification_time_utc", label: "NTFS STANDARD_INFORMATION MFT Modified Date/Time" },
      { key: "fat_created", label: "Created Date/Time" },
      { key: "fat_modified", label: "Last Modified Date/Time" },
      { key: "fat_accessed", label: "Accessed Date/Time" }
    ];

    function timelineSourceEntries() {
      if (!state.data) {
        return [];
      }
      const byId = new Map();
      const addEntry = (entry) => {
        if (!entry || entry.id == null || byId.has(entry.id)) {
          return;
        }
        byId.set(entry.id, { ...entry, logical_path: normalizeLogicalPath(entry.logical_path) });
      };
      (state.data.entries || []).forEach(addEntry);
      (state.cat.entries || []).forEach(addEntry);
      for (const path in state.idx.dirCache) {
        (state.idx.dirCache[path] || []).map(idxChildToEntry).forEach(addEntry);
      }
      return Array.from(byId.values());
    }

    function timelineTimestampKey(text) {
      const parsed = Date.parse(text);
      return Number.isFinite(parsed) ? String(parsed) : String(text).trim().toLowerCase();
    }

    function addTimelineCandidate(bucket, label, value) {
      const text = firstText(value);
      if (!text) {
        return;
      }
      const key = timelineTimestampKey(text);
      if (!bucket.has(key)) {
        bucket.set(key, {
          timestamp: text,
          timestampMs: Date.parse(text),
          labels: []
        });
      }
      const item = bucket.get(key);
      if (!item.labels.includes(label)) {
        item.labels.push(label);
      }
    }

    function timelineEventsForEntry(entry) {
      const metadata = entry.metadata_json || {};
      const bucket = new Map();
      addTimelineCandidate(bucket, "Artifact Date/Time", categoryTime(entry));
      addTimelineCandidate(bucket, "Created Date/Time", filesystemCreatedTime(entry));
      addTimelineCandidate(bucket, "Accessed Date/Time", filesystemAccessedTime(entry));
      addTimelineCandidate(bucket, "Last Modified Date/Time", filesystemModifiedTime(entry));
      addTimelineCandidate(bucket, "MFT Modified Date/Time", filesystemMftModifiedTime(entry));
      addTimelineCandidate(bucket, "Browser Created Date/Time", browserArtifactDisplayTime(metadata, "created"));
      addTimelineCandidate(bucket, "Browser Accessed Date/Time", browserArtifactDisplayTime(metadata, "accessed"));
      addTimelineCandidate(bucket, "Browser Modified Date/Time", browserArtifactDisplayTime(metadata, "modified"));
      TIMELINE_METADATA_TIME_FIELDS.forEach((field) => {
        addTimelineCandidate(bucket, field.label, metadata[field.key]);
      });
      return Array.from(bucket.values()).map((event, index) => ({
        entry,
        index,
        timestamp: event.timestamp,
        timestampMs: event.timestampMs,
        attribute: event.labels.join(" / ")
      }));
    }

    function collectTimelineEvents(entries) {
      const events = [];
      entries.forEach((entry) => {
        timelineEventsForEntry(entry).forEach((event) => events.push(event));
      });
      return events.sort((left, right) => {
        const leftMissing = !Number.isFinite(left.timestampMs);
        const rightMissing = !Number.isFinite(right.timestampMs);
        if (leftMissing !== rightMissing) {
          return leftMissing ? 1 : -1;
        }
        if (!leftMissing && left.timestampMs !== right.timestampMs) {
          return left.timestampMs - right.timestampMs;
        }
        return (left.entry.id || 0) - (right.entry.id || 0) || left.index - right.index;
      });
    }

    function rebuildTimelineEvents() {
      if (!state.data || !state.timeline.built) {
        return;
      }
      // Prefer the dedicated server-fetched set from the last "Build timeline"
      // click (comprehensive, up to the examiner's Timeline build limit) over
      // whatever's incidentally cached in client state from ordinary browsing.
      const entries = state.timeline.entries.length ? state.timeline.entries : timelineSourceEntries();
      state.timeline.casePath = state.casePath;
      state.timeline.sourceEntries = entries.length;
      state.timeline.loadedEntryCount = entries.length;
      state.timeline.totalEntryCount = Number(state.data.entry_count || entries.length);
      state.timeline.events = collectTimelineEvents(entries);
    }

    async function requestTimelineBuild() {
      if (!state.data) {
        setNotice("Load a case before building the timeline.", true);
        return;
      }
      if (state.timeline.building) {
        setNotice("A timeline build is already running.");
        return;
      }
      const total = Number(state.data.entry_count || 0);
      const rangeActive = dateFilterActive();
      // A date range set BEFORE building lets the server filter with SQL
      // (json_extract over every known timestamp field, see
      // list_filesystem_entries_for_timeline) instead of shipping every
      // indexed entry to the browser to scan client-side - that full scan is
      // what froze the tab on cases with tens of thousands of entries. This
      // is a real filter, not a row-count preview: nothing whose timestamp
      // falls inside the chosen window is ever left out, no matter how large
      // the case is.
      if (!rangeActive) {
        const proceed = window.confirm(
          "No date range is set above, so this will scan all " + total.toLocaleString() +
          " indexed entries and can be slow or freeze the tab on large cases.\n\n" +
          "Click Cancel, set a From/To date in the fields above, then click Build timeline again to scan only that window.\n\n" +
          "Build from all entries anyway?"
        );
        if (!proceed) {
          state.timeline.prompted = true;
          renderTimeline();
          return;
        }
      }
      const limit = currentTimelineBuildLimit();
      state.timeline.prompted = true;
      state.timeline.building = true;
      const buildGeneration = Number(state.timeline.buildGeneration || 0) + 1;
      state.timeline.buildGeneration = buildGeneration;
      renderTimeline();
      setNotice(rangeActive ? "Building timeline for the selected date range..." : "Building timeline for all entries...");
      try {
        const params = { case_path: currentCasePath(), max_entries: limit };
        if (rangeActive) {
          params.from = state.dateFilter.from ? state.dateFilter.from + "T00:00:00Z" : "0001-01-01T00:00:00Z";
          params.to = state.dateFilter.to ? state.dateFilter.to + "T23:59:59.999Z" : "9999-12-31T23:59:59Z";
        }
        const data = await apiGet("/api/timeline/entries", params);
        if (buildGeneration !== state.timeline.buildGeneration) {
          return;
        }
        state.timeline.built = true;
        state.timeline.entries = (data.entries || []).map((entry) => ({ ...entry, logical_path: normalizeLogicalPath(entry.logical_path) }));
        state.timeline.truncated = Boolean(data.truncated);
        rebuildTimelineEvents();
        renderTimeline();
        const matchedTotal = Number(data.entry_count || total);
        const scopeNote = rangeActive
          ? " (" + matchedTotal.toLocaleString() + " indexed entries fell in the selected date range)"
          : "";
        const truncatedNote = state.timeline.truncated
          ? " Scan was truncated - narrow the date range for full coverage."
          : "";
        setNotice("Built timeline with " + state.timeline.events.length.toLocaleString() + " timestamped event" + (state.timeline.events.length === 1 ? "" : "s") + "." + scopeNote + truncatedNote, state.timeline.truncated);
      } catch (err) {
        state.timeline.prompted = true;
        setNotice(err.message, true);
      } finally {
        if (buildGeneration === state.timeline.buildGeneration) {
          state.timeline.building = false;
          renderTimeline();
        }
      }
    }

    function maybePromptTimelineBuild() {
      if (!state.data || state.timeline.built || state.timeline.prompted) {
        return;
      }
      state.timeline.prompted = true;
      window.setTimeout(requestTimelineBuild, 0);
    }

    function timelineDateFilteredEvents(events) {
      if (!dateFilterActive()) {
        return events;
      }
      const from = state.dateFilter.from ? Date.parse(state.dateFilter.from + "T00:00:00Z") : -Infinity;
      const to = state.dateFilter.to ? Date.parse(state.dateFilter.to + "T23:59:59.999Z") : Infinity;
      return events.filter((event) =>
        Number.isFinite(event.timestampMs) && event.timestampMs >= from && event.timestampMs <= to
      );
    }

    function timelineFocusFilteredEvents(events) {
      const focus = state.timeline.focusBucket;
      if (!focus) {
        return events;
      }
      const startMs = Number(focus.startMs);
      const endMs = Number(focus.endMs);
      if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
        return events;
      }
      return events.filter((event) =>
        Number.isFinite(event.timestampMs) && event.timestampMs >= startMs && event.timestampMs < endMs
      );
    }

    function timelineBucketStart(timestampMs, unit) {
      const date = new Date(timestampMs);
      if (unit === "hour") {
        return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), date.getUTCHours());
      }
      return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
    }

    function timelineBucketLabel(timestampMs, unit) {
      const date = new Date(timestampMs);
      const options = unit === "hour"
        ? { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" }
        : { month: "short", day: "numeric", year: "numeric" };
      return date.toLocaleString(undefined, options);
    }

    function timelineAxisLabel(timestampMs, unit) {
      const date = new Date(timestampMs);
      const options = unit === "hour"
        ? { month: "short", day: "numeric", hour: "numeric" }
        : { month: "short", day: "numeric" };
      return date.toLocaleString(undefined, options);
    }

    function timelineGraphData(events) {
      const validEvents = events.filter((event) => Number.isFinite(event.timestampMs));
      if (!validEvents.length) {
        return { buckets: [], unit: "day", maxCount: 0 };
      }
      let minMs = Infinity;
      let maxMs = -Infinity;
      validEvents.forEach((event) => {
        minMs = Math.min(minMs, event.timestampMs);
        maxMs = Math.max(maxMs, event.timestampMs);
      });
      const unit = maxMs - minMs <= 3 * TIMELINE_DAY_MS ? "hour" : "day";
      const intervalMs = unit === "hour" ? TIMELINE_HOUR_MS : TIMELINE_DAY_MS;
      const bucketsByStart = new Map();
      validEvents.forEach((event) => {
        const startMs = timelineBucketStart(event.timestampMs, unit);
        if (!bucketsByStart.has(startMs)) {
          bucketsByStart.set(startMs, {
            startMs,
            endMs: startMs + intervalMs,
            unit,
            count: 0,
            firstEntryId: null,
            firstEventIndex: null
          });
        }
        const bucket = bucketsByStart.get(startMs);
        bucket.count += 1;
        if (bucket.firstEntryId === null && event.entry && event.entry.id != null) {
          bucket.firstEntryId = event.entry.id;
          bucket.firstEventIndex = event.index;
        }
      });
      const buckets = Array.from(bucketsByStart.values()).sort((left, right) => left.startMs - right.startMs);
      const maxCount = buckets.reduce((max, bucket) => Math.max(max, bucket.count), 0);
      return { buckets, unit, maxCount };
    }

    function timelineGraphTickIndexes(count) {
      if (count <= 0) {
        return [];
      }
      if (count === 1) {
        return [0];
      }
      const indexes = [];
      const maxTicks = Math.min(6, count);
      for (let tick = 0; tick < maxTicks; tick += 1) {
        const index = Math.round(((count - 1) * tick) / (maxTicks - 1));
        if (!indexes.includes(index)) {
          indexes.push(index);
        }
      }
      return indexes;
    }

    function renderTimelineGraph(events) {
      const graph = $("timelineGraph");
      if (!graph) {
        return;
      }
      const data = timelineGraphData(events);
      state.timeline.graphBuckets = data.buckets;
      if (!data.buckets.length) {
        graph.innerHTML = empty("No timeline data to plot.");
        return;
      }
      const width = 1000;
      const height = 145;
      const left = 34;
      const right = 22;
      const top = 12;
      const bottom = 36;
      const plotWidth = width - left - right;
      const plotHeight = height - top - bottom;
      const maxCount = Math.max(1, data.maxCount);
      const points = data.buckets.map((bucket, index) => {
        const x = data.buckets.length === 1
          ? left + (plotWidth / 2)
          : left + ((bucket.startMs - data.buckets[0].startMs) / (data.buckets[data.buckets.length - 1].startMs - data.buckets[0].startMs)) * plotWidth;
        const y = top + (1 - (bucket.count / maxCount)) * plotHeight;
        return { bucket, index, x, y };
      });
      const linePath = points.map((point, index) =>
        (index === 0 ? "M" : "L") + point.x.toFixed(1) + " " + point.y.toFixed(1)
      ).join(" ");
      const areaPath = points.length
        ? "M" + points[0].x.toFixed(1) + " " + (height - bottom).toFixed(1) + " " + points.map((point, index) =>
          (index === 0 ? "L" : "L") + point.x.toFixed(1) + " " + point.y.toFixed(1)
        ).join(" ") + " L" + points[points.length - 1].x.toFixed(1) + " " + (height - bottom).toFixed(1) + " Z"
        : "";
      const focus = state.timeline.focusBucket;
      const focusedPoint = focus
        ? points.find((point) => point.bucket.startMs === focus.startMs && point.bucket.endMs === focus.endMs)
        : null;
      const tickHtml = timelineGraphTickIndexes(points.length).map((index) => {
        const point = points[index];
        return `<g>
          <line x1="${point.x.toFixed(1)}" y1="${top}" x2="${point.x.toFixed(1)}" y2="${height - bottom}" stroke="rgba(148, 163, 184, .32)" stroke-width="1"/>
          <text class="timeline-axis-label" x="${point.x.toFixed(1)}" y="${height - 14}" text-anchor="middle">${escapeHtml(timelineAxisLabel(point.bucket.startMs, data.unit))}</text>
        </g>`;
      }).join("");
      const pointHtml = points.map((point) => {
        const previousX = point.index > 0 ? points[point.index - 1].x : left;
        const nextX = point.index < points.length - 1 ? points[point.index + 1].x : width - right;
        const hitLeft = point.index === 0 ? left : (previousX + point.x) / 2;
        const hitRight = point.index === points.length - 1 ? width - right : (point.x + nextX) / 2;
        const active = focusedPoint && focusedPoint.index === point.index ? " active" : "";
        return `<circle class="timeline-graph-point${active}" cx="${point.x.toFixed(1)}" cy="${point.y.toFixed(1)}" r="5"/>
          <rect class="timeline-graph-hitbox" x="${hitLeft.toFixed(1)}" y="${top}" width="${Math.max(8, hitRight - hitLeft).toFixed(1)}" height="${plotHeight}"
            onmouseenter="showTimelineGraphTooltip(event, ${point.index})"
            onmousemove="moveTimelineGraphTooltip(event)"
            onmouseleave="hideTimelineGraphTooltip()"
            onclick="focusTimelineBucket(${point.index})"/>`;
      }).join("");
      const cursorHtml = focusedPoint
        ? `<line class="timeline-graph-cursor" x1="${focusedPoint.x.toFixed(1)}" y1="${top}" x2="${focusedPoint.x.toFixed(1)}" y2="${height - bottom}"/>`
        : "";
      const focusHtml = focus
        ? `<span class="timeline-graph-focus"><span>${escapeHtml(timelineBucketLabel(focus.startMs, focus.unit))} (${Number(focus.count || 0).toLocaleString()} hits)</span><button class="ghost" onclick="clearTimelineBucketFocus()">Clear bucket</button></span>`
        : `<span>${data.unit === "hour" ? "Hourly" : "Daily"} buckets</span>`;
      graph.innerHTML = `
        <div class="timeline-graph-head">
          <span>Activity density</span>
          ${focusHtml}
        </div>
        <svg class="timeline-graph-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="Timeline activity density">
          <line x1="${left}" y1="${height - bottom}" x2="${width - right}" y2="${height - bottom}" stroke="rgba(100, 116, 139, .45)" stroke-width="1"/>
          ${tickHtml}
          <path class="timeline-graph-area" d="${areaPath}"></path>
          <path class="timeline-graph-line" d="${linePath}"></path>
          ${cursorHtml}
          ${pointHtml}
        </svg>
        <div id="timelineGraphTooltip" class="timeline-graph-tooltip"></div>`;
    }

    function showTimelineGraphTooltip(event, index) {
      const bucket = (state.timeline.graphBuckets || [])[index];
      const tooltip = $("timelineGraphTooltip");
      if (!bucket || !tooltip) {
        return;
      }
      tooltip.innerHTML = `<strong>Date: ${escapeHtml(timelineBucketLabel(bucket.startMs, bucket.unit))}</strong><span>Hit count: ${Number(bucket.count || 0).toLocaleString()}</span>`;
      tooltip.style.display = "block";
      moveTimelineGraphTooltip(event);
    }

    function moveTimelineGraphTooltip(event) {
      const tooltip = $("timelineGraphTooltip");
      const graph = $("timelineGraph");
      if (!tooltip || !graph || tooltip.style.display !== "block") {
        return;
      }
      const rect = graph.getBoundingClientRect();
      let left = event.clientX - rect.left + 12;
      let top = event.clientY - rect.top + 12;
      const maxLeft = Math.max(8, rect.width - tooltip.offsetWidth - 8);
      const maxTop = Math.max(8, rect.height - tooltip.offsetHeight - 8);
      tooltip.style.left = Math.min(Math.max(8, left), maxLeft) + "px";
      tooltip.style.top = Math.min(Math.max(8, top), maxTop) + "px";
    }

    function hideTimelineGraphTooltip() {
      const tooltip = $("timelineGraphTooltip");
      if (tooltip) {
        tooltip.style.display = "none";
      }
    }

    function focusTimelineBucket(index) {
      const bucket = (state.timeline.graphBuckets || [])[index];
      if (!bucket) {
        return;
      }
      state.timeline.focusBucket = {
        startMs: bucket.startMs,
        endMs: bucket.endMs,
        unit: bucket.unit,
        label: timelineBucketLabel(bucket.startMs, bucket.unit),
        count: bucket.count
      };
      if (bucket.firstEntryId !== null) {
        state.timeline.selectedEntryId = bucket.firstEntryId;
        state.timeline.selectedEventIndex = bucket.firstEventIndex;
        state.hex = makeHexState(bucket.firstEntryId, 0, numberValue("hexLength", 512));
        const viewerMode = $("viewerMode");
        if (viewerMode) {
          viewerMode.value = "metadata";
        }
      }
      state.timeline.scrollToSelected = true;
      hideTimelineGraphTooltip();
      renderTimeline();
      if (bucket.firstEntryId !== null) {
        renderHexViewer();
      }
      setNotice("Focused timeline table on " + timelineBucketLabel(bucket.startMs, bucket.unit) + ".");
    }

    function clearTimelineBucketFocus() {
      state.timeline.focusBucket = null;
      state.timeline.scrollToSelected = true;
      renderTimeline();
    }

    function compareTimelineEventOrder(left, right) {
      const leftMissing = !Number.isFinite(left.timestampMs);
      const rightMissing = !Number.isFinite(right.timestampMs);
      if (leftMissing !== rightMissing) {
        return leftMissing ? 1 : -1;
      }
      if (!leftMissing && left.timestampMs !== right.timestampMs) {
        return left.timestampMs - right.timestampMs;
      }
      return (left.index || 0) - (right.index || 0);
    }

    function timelineEventsForEntryId(entryId) {
      const numericEntryId = Number(entryId);
      return (state.timeline.events || [])
        .filter((event) => event.entry && Number(event.entry.id) === numericEntryId)
        .slice()
        .sort(compareTimelineEventOrder);
    }

    // Timeline entries come from the dedicated /api/timeline/entries fetch and
    // may not be in state.data/cat/idx at all on a large (truncated) case, so
    // findLoadedEntry alone can miss them. Resolve from the timeline's own
    // fetched set (and the events it built) first, then fall back to the
    // ordinary loaded-entry lookup.
    function timelineEntryById(entryId) {
      const numericEntryId = Number(entryId);
      if (Number.isFinite(numericEntryId)) {
        const fetched = (state.timeline.entries || []).find((item) => Number(item.id) === numericEntryId);
        if (fetched) {
          return fetched;
        }
        const event = (state.timeline.events || []).find((item) => item.entry && Number(item.entry.id) === numericEntryId);
        if (event && event.entry) {
          return event.entry;
        }
      }
      return findLoadedEntry(entryId);
    }

    function timelineSelectedEventPosition(events) {
      if (!events.length) {
        return -1;
      }
      const selectedIndex = Number(state.timeline.selectedEventIndex);
      const position = events.findIndex((event) => Number(event.index) === selectedIndex);
      return position >= 0 ? position : 0;
    }

    function timelineSelectionNavHtml() {
      const selectedEntryId = state.timeline.selectedEntryId !== null && state.timeline.selectedEntryId !== undefined
        ? state.timeline.selectedEntryId
        : state.hex.entryId;
      if (!selectedEntryId) {
        return `<div class="timeline-selection-title muted">Select a timeline event</div>`;
      }
      const entry = timelineEntryById(selectedEntryId);
      if (!entry) {
        return `<div class="timeline-selection-title muted">Selected timeline item is not loaded</div>`;
      }
      const events = timelineEventsForEntryId(entry.id);
      if (!events.length) {
        return `<div class="timeline-selection-title">${escapeHtml(timelineItemName(entry))}</div><div class="timeline-timestamp-pager">0 TIMESTAMPS</div>`;
      }
      const position = timelineSelectedEventPosition(events);
      const current = events[position];
      const title = timelineItemName(entry);
      const eventTitle = current ? compactParts([current.timestamp, current.attribute]) : "";
      const pager = events.length > 1
        ? `<div class="timeline-timestamp-pager" title="${escapeAttr(eventTitle)}">
            <button type="button" onclick="event.stopPropagation(); stepTimelineTimestamp(-1)" title="Previous timestamp">&lt;</button>
            <span>${position + 1} OF ${events.length} TIMESTAMPS</span>
            <button type="button" onclick="event.stopPropagation(); stepTimelineTimestamp(1)" title="Next timestamp">&gt;</button>
          </div>`
        : `<div class="timeline-timestamp-pager" title="${escapeAttr(eventTitle)}">1 TIMESTAMP</div>`;
      return `<div class="timeline-selection-title" title="${escapeAttr(displayPath(entry.logical_path))}">${fileIconHtml(entry)}${escapeHtml(title)}</div>${pager}`;
    }

    function selectTimelineEvent(entryId, eventIndex, clearFocus) {
      const entry = timelineEntryById(entryId);
      if (!entry) {
        setNotice("Timeline entry is not loaded.", true);
        return;
      }
      const events = timelineEventsForEntryId(entry.id);
      const numericEventIndex = Number(eventIndex);
      const selectedEvent = events.find((event) => Number(event.index) === numericEventIndex) || events[0] || null;
      state.timeline.selectedEntryId = entry.id;
      state.timeline.selectedEventIndex = selectedEvent ? selectedEvent.index : null;
      if (clearFocus) {
        state.timeline.focusBucket = null;
      }
      state.timeline.scrollToSelected = true;
      state.hex = makeHexState(entry.id, 0, numberValue("hexLength", 512));
      const viewerMode = $("viewerMode");
      if (viewerMode) {
        viewerMode.value = "metadata";
      }
      renderTimeline();
      renderHexViewer();
      setNotice("Selected timeline item " + (entry.name || logicalName(entry.logical_path)) + ".");
    }

    function stepTimelineTimestamp(delta) {
      const selectedEntryId = state.timeline.selectedEntryId !== null && state.timeline.selectedEntryId !== undefined
        ? state.timeline.selectedEntryId
        : state.hex.entryId;
      const events = timelineEventsForEntryId(selectedEntryId);
      if (events.length <= 1) {
        return;
      }
      const position = timelineSelectedEventPosition(events);
      const nextPosition = (position + delta + events.length) % events.length;
      selectTimelineEvent(selectedEntryId, events[nextPosition].index, true);
    }

    function scrollTimelineToSelectedEvent() {
      if (!state.timeline.scrollToSelected) {
        return;
      }
      state.timeline.scrollToSelected = false;
      window.setTimeout(() => {
        const table = $("timelineTable");
        const entryId = Number(state.timeline.selectedEntryId);
        const eventIndex = Number(state.timeline.selectedEventIndex);
        if (!table || !Number.isFinite(entryId) || !Number.isFinite(eventIndex)) {
          return;
        }
        const row = table.querySelector(`.entry-row[data-entry-id="${entryId}"][data-timeline-event-index="${eventIndex}"]`);
        if (row) {
          table.scrollTop = Math.max(0, row.offsetTop - Math.round(table.clientHeight / 2));
        } else {
          table.scrollTop = 0;
        }
      }, 0);
    }

    function timelineGridColumns() {
      return [
        { key: "time", label: "Date/time", sortable: true, filterable: true, sortType: "time" },
        { key: "attribute", label: "Date/time attribute", sortable: true, filterable: true, sortType: "text" },
        { key: "timelineCategory", label: "Timeline category", sortable: true, filterable: true, sortType: "text" },
        { key: "category", label: "Category", sortable: true, filterable: true, sortType: "text" },
        { key: "type", label: "Type", sortable: true, filterable: true, sortType: "text" },
        { key: "item", label: "Item", sortable: true, filterable: true, sortType: "text" },
        { key: "itemValue", label: "Item value", sortable: true, filterable: true, sortType: "text" }
      ];
    }

    function timelineCategoryForEvent(event) {
      const entry = event.entry;
      const metadata = entry.metadata_json || {};
      const category = entryCategory(entry);
      const text = String(event.attribute || "").toLowerCase();
      if (isEmailEntry(entry) || category.main === "Email and Communications") {
        return { label: "User communication", tone: "communication" };
      }
      if (/access|visit|last used|opened|started|download/.test(text)
        || metadata.artifact_kind === "browser_history_visit"
        || metadata.artifact_kind === "browser_download") {
        return { label: "File/folder opening", tone: "opening" };
      }
      return { label: "File knowledge", tone: "knowledge" };
    }

    function timelineItemName(entry) {
      const metadata = entry.metadata_json || {};
      if (isEmailEntry(entry)) {
        return emailDisplayName(entry);
      }
      return firstText(metadata.title, metadata.file_name, metadata.registry_value_name, metadata.registry_key_name, metadata.url, entry.name, logicalName(entry.logical_path));
    }

    function timelineItemValue(entry) {
      const metadata = entry.metadata_json || {};
      if (isEmailEntry(entry)) {
        return compactParts([
          metadata.email_from ? "From: " + metadata.email_from : "",
          metadata.email_to ? "To: " + metadata.email_to : "",
          firstText(metadata.email_subject, metadata.email_body_preview)
        ]);
      }
      if (metadata.artifact_kind === "registry_value") {
        return compactParts([metadata.registry_key_path, metadata.registry_value_data]);
      }
      if (metadata.artifact_kind === "evtx_event_record") {
        return compactParts([metadata.evtx_provider, metadata.evtx_summary]);
      }
      if (isBrowserActivityEntry(entry)) {
        return firstText(metadata.url, metadata.target_path, metadata.tab_url, metadata.source_url, browserActivityPreview(entry));
      }
      return firstText(entrySummary(entry), displayPath(entry.logical_path));
    }

    function timelineGridRow(event) {
      const entry = event.entry;
      const timelineCategory = timelineCategoryForEvent(event);
      const item = timelineItemName(entry);
      const itemValue = timelineItemValue(entry);
      return {
        event,
        values: {
          time: event.timestamp,
          attribute: event.attribute,
          timelineCategory: timelineCategory.label,
          category: entryCategoryLabel(entry),
          type: activityLabel(entry),
          item,
          itemValue
        },
        sortValues: {
          time: event.timestampMs
        },
        timelineCategory
      };
    }

    function renderTimelineGridRow(row) {
      const event = row.event;
      const entry = event.entry;
      const category = entryCategory(entry);
      const selected = Number(state.timeline.selectedEntryId) === Number(entry.id)
        && Number(state.timeline.selectedEventIndex) === Number(event.index)
        ? " selected"
        : "";
      const tone = row.timelineCategory.tone || "knowledge";
      return `
          <tr class="entry-row${selected}" data-entry-id="${entry.id}" data-timeline-event-index="${event.index}" onclick="selectTimelineEntry(${entry.id}, ${event.index})" ondblclick="goToEntryFolder(${entry.id})">
            <td class="entry-time" title="${escapeAttr(row.values.time)}">${escapeHtml(row.values.time)}</td>
            <td title="${escapeAttr(row.values.attribute)}">${escapeHtml(row.values.attribute)}</td>
            <td><span class="timeline-badge timeline-${escapeAttr(tone)}">${escapeHtml(row.values.timelineCategory)}</span></td>
            <td title="${escapeAttr(row.values.category)}">${categoryIconHtml(category.main)}<span class="entry-category">${escapeHtml(row.values.category)}</span></td>
            <td class="entry-kind">${escapeHtml(row.values.type)}</td>
            <td title="${escapeAttr(entry.logical_path)}">${fileIconHtml(entry)}<span class="timeline-item-name">${escapeHtml(row.values.item)}</span><span class="timeline-item-path">${escapeHtml(displayPath(entry.logical_path))}</span></td>
            <td class="timeline-item-value" title="${escapeAttr(row.values.itemValue)}">${escapeHtml(row.values.itemValue)}</td>
          </tr>`;
    }

    function selectTimelineEntry(entryId, eventIndex) {
      selectTimelineEvent(entryId, eventIndex, false);
    }

    // Which plotted graph bucket holds a given timestamp, so the detail pane's
    // per-timestamp "jump" action can move the graph cursor to it.
    function timelineBucketIndexForMs(timestampMs) {
      if (!Number.isFinite(timestampMs)) {
        return -1;
      }
      const buckets = state.timeline.graphBuckets || [];
      return buckets.findIndex((bucket) => timestampMs >= bucket.startMs && timestampMs < bucket.endMs);
    }

    // "Jump to this timestamp on the timeline": select the exact event AND move
    // the graph focus to the bucket containing it (same focus mechanism the
    // graph points use), so the cursor and the filtered table both land on it.
    function jumpTimelineToEvent(entryId, eventIndex) {
      const events = timelineEventsForEntryId(entryId);
      const numericEventIndex = Number(eventIndex);
      const target = events.find((event) => Number(event.index) === numericEventIndex) || null;
      if (target && Number.isFinite(target.timestampMs)) {
        const bucketIndex = timelineBucketIndexForMs(target.timestampMs);
        if (bucketIndex >= 0) {
          // focusTimelineBucket lands on the bucket's first event; re-select the
          // specific one afterwards so the examiner's chosen timestamp stays
          // selected, not just the bucket.
          focusTimelineBucket(bucketIndex);
        }
      }
      selectTimelineEvent(entryId, eventIndex, false);
    }

    // One clickable chip per timestamp facet of the selected entry (Created /
    // Accessed / Modified / MFT modified / artifact times), each a clock-icon
    // "jump to this timestamp on the timeline" action per the reference design.
    function timelineEventJumpChips(entry) {
      const events = timelineEventsForEntryId(entry.id);
      if (!events.length) {
        return "";
      }
      const selectedIndex = Number(state.timeline.selectedEventIndex);
      const chips = events.map((event) => {
        const active = Number(event.index) === selectedIndex ? " active" : "";
        const stamp = escapeHtml(event.timestamp || "(no timestamp)");
        const attr = escapeHtml(event.attribute || "Timestamp");
        return `<button type="button" class="timeline-jump${active}" title="Jump to this timestamp on the timeline"
            onclick="jumpTimelineToEvent(${entry.id}, ${event.index})">
            <span class="timeline-jump-clock" aria-hidden="true">&#128340;</span>
            <span class="timeline-jump-stamp">${stamp}</span>
            <span class="timeline-jump-attr">${attr}</span>
          </button>`;
      }).join("");
      return `<div class="timeline-detail-jumps"><h4>Timestamps (${events.length})</h4>${chips}</div>`;
    }

    // Right-hand detail pane. Reuses the shared metadataView inspector, which
    // already adapts by artifact type (file entries -> Forensic Location +
    // MAC Times; email/browser records -> their artifact info sections), so the
    // "detail pane adapts by type" requirement is satisfied without a bespoke
    // variant. A timeline-specific header adds the selected timestamp and the
    // per-timestamp jump chips on top.
    function renderTimelineDetail() {
      const pane = $("timelineDetail");
      if (!pane) {
        return;
      }
      if (!state.data || !state.timeline.built) {
        pane.innerHTML = `<div class="timeline-detail-empty">Build the timeline, then select an event to see file details or artifact information.</div>`;
        return;
      }
      const selectedEntryId = state.timeline.selectedEntryId !== null && state.timeline.selectedEntryId !== undefined
        ? state.timeline.selectedEntryId
        : null;
      if (selectedEntryId === null) {
        pane.innerHTML = `<div class="timeline-detail-empty">Select a timeline event to see file details or artifact information.</div>`;
        return;
      }
      const entry = timelineEntryById(selectedEntryId);
      if (!entry) {
        pane.innerHTML = `<div class="timeline-detail-empty">The selected timeline item is not loaded.</div>`;
        return;
      }
      const events = timelineEventsForEntryId(entry.id);
      const position = timelineSelectedEventPosition(events);
      const current = position >= 0 ? events[position] : null;
      const selectedLine = current
        ? `<div class="timeline-detail-selected">${fileIconHtml(entry)}<span>${escapeHtml(current.timestamp || "(no timestamp)")}</span><span class="timeline-jump-attr">${escapeHtml(current.attribute || "")}</span></div>`
        : `<div class="timeline-detail-selected">${fileIconHtml(entry)}<span>${escapeHtml(timelineItemName(entry))}</span></div>`;
      const head = `<div class="timeline-detail-head">${selectedLine}${timelineEventJumpChips(entry)}</div>`;
      pane.innerHTML = head + metadataView(entry);
    }

    // Single-entry "Create export/report": bookmark this one entry, then export
    // the case report - reuses the same exportReport() the selection flow uses.
    async function bookmarkEntryAndExportReport(entryId) {
      try {
        await bookmarkEntry(entryId, false);
      } catch (err) {
        setNotice(err.message || String(err), true);
        return;
      }
      await refresh();
      await exportReport();
    }

    // Single-entry "Save artifact to...": write this file's bytes out via the
    // same /api/entry/recover path exportSelectedEntries uses.
    async function exportTimelineEntryFile(entryId) {
      const entry = timelineEntryById(entryId);
      if (!entry) {
        setNotice("Timeline entry is not loaded.", true);
        return;
      }
      if (entry.entry_kind !== "file") {
        setNotice("Only file entries have bytes to save. This row is a " + (entry.entry_kind || "record") + ".", true);
        return;
      }
      setNotice("Saving " + (entry.name || logicalName(entry.logical_path)) + "...");
      try {
        const data = await apiPost("/api/entry/recover", {
          case_path: currentCasePath(),
          entry_id: entry.id,
          output_path: defaultRecoveryPath(entry)
        });
        setNotice("Saved " + (entry.name || logicalName(entry.logical_path)) + " to " + (data.output_path || "ui-output") + ".");
      } catch (err) {
        setNotice(err.message || String(err), true);
      }
    }

    // Timeline-specific right-click menu (reference design: Create export/report
    // | Add/remove tag | Save artifact to...), reusing the shared ctxItem/
    // openContextMenu/entrySelectionCtxRows machinery.
    function showTimelineContextMenu(event, entryId, eventIndex) {
      const entry = timelineEntryById(entryId);
      const menu = $("ctxMenu");
      if (!entry || !menu) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const numericEventIndex = Number(eventIndex);
      const rows = [];
      if (Number.isFinite(numericEventIndex)) {
        rows.push(ctxItem("Select event", `selectTimelineEvent(${entryId}, ${numericEventIndex}, false)`));
        rows.push(ctxItem("Jump to this timestamp", `jumpTimelineToEvent(${entryId}, ${numericEventIndex})`));
      }
      if (entry.entry_kind === "file" && entry.id != null) {
        rows.push(ctxItem("View bytes", `openEntry(${entryId})`));
      }
      rows.push(ctxItem("Go to folder", `goToEntryFolder(${entryId})`));
      rows.push('<div class="sep"></div>');
      rows.push(ctxItem("Add/remove tag (bookmark)", `bookmarkEntry(${entryId})`));
      rows.push(ctxItem("Create export/report", `bookmarkEntryAndExportReport(${entryId})`));
      if (entry.entry_kind === "file" && entry.id != null) {
        rows.push(ctxItem("Save artifact to...", `exportTimelineEntryFile(${entryId})`));
      }
      entrySelectionCtxRows(rows);
      openContextMenu(menu, rows, event);
    }

    function timelineScopeNoticeHtml() {
      if (!state.data || !state.data.entries_truncated) {
        return "";
      }
      const loaded = Number(state.timeline.loadedEntryCount || 0).toLocaleString();
      const total = Number(state.timeline.totalEntryCount || state.data.entry_count || 0).toLocaleString();
      return `<div class="analysis-status">Timeline is built client-side from ${loaded} loaded entries out of ${total} indexed entries.</div>`;
    }

    function renderTimeline() {
      const table = $("timelineTable");
      const graph = $("timelineGraph");
      const timestampNav = $("timelineTimestampNav");
      const count = $("timelineCount");
      const summary = $("timelineSummary");
      const buildButton = $("buildTimeline");
      if (!table || !graph || !timestampNav || !count || !summary) {
        return;
      }
      if (buildButton) {
        buildButton.disabled = Boolean(state.timeline.building);
        buildButton.textContent = state.timeline.building ? "Building..." : "Build timeline";
      }
      syncDateFilterInputs();
      if (!state.data) {
        count.textContent = "not built";
        summary.textContent = "No case loaded.";
        graph.innerHTML = empty("No timeline data to plot.");
        timestampNav.innerHTML = `<div class="timeline-selection-title muted">Select a timeline event</div>`;
        table.innerHTML = empty("Load or create a case to build a timeline.");
        renderTimelineDetail();
        return;
      }
      if (state.timeline.casePath && state.timeline.casePath !== state.casePath) {
        state.timeline = newTimelineState();
      }
      if (!state.timeline.built) {
        count.textContent = "not built";
        summary.innerHTML = `<span><strong>${Number(state.data.entry_count || 0).toLocaleString()}</strong> indexed entries available</span>`;
        graph.innerHTML = empty("No timeline data to plot.");
        timestampNav.innerHTML = `<div class="timeline-selection-title muted">Build the timeline to select timestamped events</div>`;
        table.innerHTML = empty("Build the timeline to aggregate timestamped events from loaded entries.");
        renderTimelineDetail();
        return;
      }
      const allEvents = state.timeline.events || [];
      const dateFilteredEvents = timelineDateFilteredEvents(allEvents);
      const tableEvents = timelineFocusFilteredEvents(dateFilteredEvents);
      renderTimelineGraph(dateFilteredEvents);
      timestampNav.innerHTML = timelineSelectionNavHtml();
      // Never create hundreds of thousands of DOM rows. The complete bounded
      // event set remains available for the graph/date/bucket calculations;
      // the table shows a safe window and asks for a narrower range/bucket.
      const renderedEvents = tableEvents.slice(0, TIMELINE_TABLE_RENDER_LIMIT);
      const rows = renderedEvents.map(timelineGridRow);
      const columns = timelineGridColumns();
      const tableResult = sortableGridTable("timeline", columns, rows, "timeline-table", renderTimelineGridRow);
      count.textContent = tableResult.visibleRows.length.toLocaleString() + " events";
      const baseText = dateFilterActive()
        ? "date filtered from " + allEvents.length.toLocaleString() + " total events"
        : allEvents.length.toLocaleString() + " total events";
      const focusText = state.timeline.focusBucket
        ? "bucket " + timelineBucketLabel(state.timeline.focusBucket.startMs, state.timeline.focusBucket.unit)
        : "";
      summary.innerHTML = `<span><strong>${tableResult.visibleRows.length.toLocaleString()}</strong> table rows</span><span>${tableEvents.length.toLocaleString()} matching events</span><span>${escapeHtml(focusText || baseText)}</span><span>${Number(state.timeline.sourceEntries || 0).toLocaleString()} loaded entries scanned</span>`;
      const filterStatus = gridFilterStatusHtml("timeline", columns, tableResult.visibleRows.length, renderedEvents.length, "rendered events");
      const renderLimitNotice = tableEvents.length > renderedEvents.length
        ? `<div class="analysis-status">Showing the first ${TIMELINE_TABLE_RENDER_LIMIT.toLocaleString()} of ${tableEvents.length.toLocaleString()} matching events to keep the browser responsive. Narrow the date range or select a graph bucket to inspect another window.</div>`
        : "";
      const noRows = tableResult.visibleRows.length
        ? ""
        : empty(tableEvents.length ? "No timeline events match the column filters." : "No timestamped events match the active date or bucket filter.");
      table.innerHTML = timelineScopeNoticeHtml() + renderLimitNotice + filterStatus + tableResult.html + noRows;
      renderTimelineDetail();
      scrollTimelineToSelectedEvent();
    }

    function categoryKey(main, sub) {
      return sub ? main + "|||" + sub : main;
    }

    function splitCategoryKey(key) {
      if (!key) {
        return { main: "", sub: "" };
      }
      const parts = String(key).split("|||");
      return { main: parts[0] || "", sub: parts[1] || "" };
    }

    function categoryLabel(key) {
      const parts = splitCategoryKey(key);
      return parts.main && parts.sub ? parts.main + " / " + parts.sub : parts.main;
    }

    function fileExtension(value) {
      const name = String(value || "").split(/[\\/]/).pop() || "";
      const index = name.lastIndexOf(".");
      return index >= 0 && index < name.length - 1 ? name.slice(index + 1).toLowerCase() : "";
    }

    function hasExt(ext, values) {
      return values.includes(String(ext || "").toLowerCase());
    }

    function folderChildren(entries, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      return entries
        .filter((entry) => parentLogicalPath(entry.logical_path) === normalized)
        .sort(compareEntries);
    }

    function directChildFolders(knownFolders, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      return Array.from(knownFolders)
        .map(normalizeLogicalPath)
        .filter((path) => path !== normalized && parentLogicalPath(path) === normalized)
        .sort(compareLogicalPaths);
    }

    // Collapse internal analysis containers only in the display tree. Stored
    // logical paths, bookmarks, and URLs retain their full paths.
    function syntheticContainerSet(knownFolders) {
      const synthetic = new Set();
      if (knownFolders.has("/Image Analysis")) {
        synthetic.add("/Image Analysis");
        ["/Image Analysis/Volumes", "/Image Analysis/Partitions"].forEach((path) => {
          if (knownFolders.has(path)) {
            synthetic.add(path);
          }
        });
      }
      return synthetic;
    }

    function displayParentPath(path, synthetic) {
      let parent = parentLogicalPath(path);
      while (parent !== "/" && synthetic.has(parent)) {
        parent = parentLogicalPath(parent);
      }
      return parent;
    }

    function displayChildFolders(knownFolders, folder, synthetic) {
      const normalized = normalizeLogicalPath(folder || "/");
      return Array.from(knownFolders)
        .map(normalizeLogicalPath)
        .filter((path) => path !== normalized && !synthetic.has(path) && displayParentPath(path, synthetic) === normalized)
        .sort(compareLogicalPaths);
    }

    function displayFolderChildren(entries, folder, synthetic) {
      const normalized = normalizeLogicalPath(folder || "/");
      return entries
        .filter((entry) => {
          const path = normalizeLogicalPath(entry.logical_path);
          return !synthetic.has(path) && displayParentPath(path, synthetic) === normalized;
        })
        .sort(compareEntries);
    }

    function displayFolderChildCount(entries, knownFolders, folder, synthetic) {
      return displayFolderChildren(entries, folder, synthetic).length
        + displayChildFolders(knownFolders, folder, synthetic).length;
    }

    function matchingSubtreeCount(passingEntries, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      const prefix = normalized === "/" ? "/" : normalized + "/";
      return passingEntries.filter((entry) => {
        const entryPath = normalizeLogicalPath(entry.logical_path);
        return entryPath === normalized || entryPath.startsWith(prefix);
      }).length;
    }

    function expandedTreeSet() {
      const key = String(state.browserState.evidenceId || "none");
      if (!state.expandedTreePaths.has(key)) {
        state.expandedTreePaths.set(key, new Set(["/"]));
      }
      return state.expandedTreePaths.get(key);
    }

    function expandTreePath(path) {
      const normalized = normalizeLogicalPath(path || "/");
      const expanded = expandedTreeSet();
      expanded.add("/");
      treeAncestors(normalized).forEach((ancestor) => expanded.add(ancestor));
      expanded.add(normalized);
    }

    function ensureTreeAncestorsExpanded(path) {
      const expanded = expandedTreeSet();
      expanded.add("/");
      treeAncestors(path).forEach((ancestor) => expanded.add(ancestor));
    }

    function toggleTreePath(path) {
      const normalized = normalizeLogicalPath(path || "/");
      const expanded = expandedTreeSet();
      if (expanded.has(normalized)) {
        expanded.delete(normalized);
      } else {
        expanded.add(normalized);
      }
      renderEvidenceBrowserEntries();
    }

    function treeAncestors(path) {
      const parts = normalizeLogicalPath(path || "/").split("/").filter(Boolean);
      const ancestors = [];
      let current = "/";
      for (let index = 0; index < parts.length - 1; index += 1) {
        current = current === "/" ? "/" + parts[index] : current + "/" + parts[index];
        ancestors.push(current);
      }
      return ["/"].concat(ancestors.filter((ancestor) => ancestor !== "/"));
    }

    function folderChildCount(entries, knownFolders, folder) {
      const normalized = normalizeLogicalPath(folder || "/");
      const entryCount = entries.filter((entry) => parentLogicalPath(entry.logical_path) === normalized).length;
      const folderCount = Array.from(knownFolders)
        .map(normalizeLogicalPath)
        .filter((path) => path !== normalized && parentLogicalPath(path) === normalized)
        .length;
      return entryCount + folderCount;
    }

    function directoryPathSet(entries) {
      const paths = new Set(["/"]);
      entries.forEach((entry) => {
        const path = normalizeLogicalPath(entry.logical_path);
        let parent = parentLogicalPath(path);
        paths.add(parent);
        while (parent !== "/") {
          parent = parentLogicalPath(parent);
          paths.add(parent);
        }
        if (entry.entry_kind === "directory") {
          paths.add(path);
        }
      });
      return paths;
    }

    // Display form of a stored logical path: the synthetic image-analysis
    // containers are dropped so paths read device-relative like the Entries
    // tree. Tooltips and forensic records keep the full stored path.
    function displayPath(path) {
      return normalizeLogicalPath(path)
        .replace(/^\/Image Analysis\/(Volumes|Partitions)(\/|$)/, "/")
        .replace(/^\/Image Analysis(\/|$)/, "/");
    }

    function normalizeLogicalPath(path) {
      let value = String(path || "/").replace(/\\/g, "/");
      if (!value.startsWith("/")) {
        value = "/" + value;
      }
      value = value.replace(/\/+/g, "/");
      if (value.length > 1) {
        value = value.replace(/\/+$/g, "");
      }
      return value || "/";
    }

    function parentLogicalPath(path) {
      const normalized = normalizeLogicalPath(path);
      if (normalized === "/") {
        return "/";
      }
      const parts = normalized.split("/").filter(Boolean);
      parts.pop();
      return parts.length ? "/" + parts.join("/") : "/";
    }

    function logicalName(path) {
      const normalized = normalizeLogicalPath(path);
      if (normalized === "/") {
        return "/";
      }
      const parts = normalized.split("/").filter(Boolean);
      return parts[parts.length - 1] || normalized;
    }

    function sanitizeSegment(value) {
      const sanitized = String(value || "")
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
        .replace(/\s+/g, " ")
        .trim();
      return sanitized || "item";
    }

    function pathDepth(path) {
      return normalizeLogicalPath(path).split("/").filter(Boolean).length;
    }

    function compareLogicalPaths(left, right) {
      const leftDepth = pathDepth(left);
      const rightDepth = pathDepth(right);
      return leftDepth - rightDepth || left.toLowerCase().localeCompare(right.toLowerCase());
    }

    function compareEntries(left, right) {
      const leftRank = left.entry_kind === "directory" ? 0 : left.entry_kind === "file" ? 1 : 2;
      const rightRank = right.entry_kind === "directory" ? 0 : right.entry_kind === "file" ? 1 : 2;
      return leftRank - rightRank || (left.name || left.logical_path).toLowerCase().localeCompare((right.name || right.logical_path).toLowerCase());
    }

    function isBrowserActivityEntry(entry) {
      const kind = entry && entry.metadata_json && entry.metadata_json.artifact_kind;
      return entry && entry.entry_kind === "record"
        && isBrowserActivityKind(kind);
    }

    function isBrowserActivityKind(kind) {
      return kind === "browser_history_visit"
        || kind === "browser_url"
        || kind === "browser_search_term"
        || kind === "browser_download"
        || kind === "browser_bookmark"
        || kind === "browser_login"
        || kind === "browser_cookie"
        || kind === "browser_preference";
    }

    function isEmailEntry(entry) {
      const kind = entry && entry.metadata_json && entry.metadata_json.artifact_kind;
      return kind === "email_message" || kind === "email_store";
    }

    function entryBookmarkPayload(entry) {
      if (isEmailEntry(entry)) {
        const displayName = emailDisplayName(entry);
        return {
          folderName: "Emails",
          title: "Email: " + displayName,
          comment: emailPreview(entry),
          bookmarkType: "email",
          dataType: "Email Message",
          displayName,
          dataPreview: emailPreview(entry),
          itemRefJson: emailItemRef(entry)
        };
      }
      if (!isBrowserActivityEntry(entry)) {
        return {
          folderName: "Evidence Entries",
          title: "Entry: " + (entry.name || logicalName(entry.logical_path)),
          comment: "",
          bookmarkType: entry.entry_kind === "file" ? "notable_file" : "folder_info",
          dataType: "Evidence Entry",
          displayName: entry.name || logicalName(entry.logical_path),
          dataPreview: null,
          itemRefJson: filesystemEntryItemRef(entry)
        };
      }
      const label = activityLabel(entry);
      const displayName = browserActivityDisplayName(entry);
      return {
        folderName: "Browser Activities",
        title: label + ": " + displayName,
        comment: browserActivityPreview(entry),
        bookmarkType: "record",
        dataType: "Browser Activity",
        displayName,
        dataPreview: browserActivityPreview(entry),
        itemRefJson: browserActivityItemRef(entry)
      };
    }

    function emailDisplayName(entry) {
      const metadata = entry.metadata_json || {};
      return firstText(metadata.email_subject, metadata.email_message_id, entry.name, logicalName(entry.logical_path));
    }

    function emailPreview(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "email_store") {
        return compactParts([metadata.email_format ? String(metadata.email_format).toUpperCase() + " mailbox store" : "Mailbox store", metadata.email_parser_status]);
      }
      return compactParts([
        metadata.email_date,
        metadata.email_from ? "From: " + metadata.email_from : "",
        metadata.email_to ? "To: " + metadata.email_to : "",
        metadata.email_subject ? "Subject: " + metadata.email_subject : "",
        metadata.email_attachment_names ? "Attachments: " + arrayText(metadata.email_attachment_names) : "",
        metadata.email_body_preview
      ]);
    }

    function emailItemRef(entry) {
      const metadata = entry.metadata_json || {};
      const ref = {
        kind: "email_message",
        artifact_kind: metadata.artifact_kind || "email_message",
        evidence_id: entry.evidence_id,
        entry_id: entry.id,
        entry_kind: entry.entry_kind,
        logical_path: entry.logical_path,
        display_name: emailDisplayName(entry),
        size_bytes: entry.size_bytes,
        is_deleted: Boolean(entry.is_deleted),
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        mft_record_logical_offset: metadata.mft_record_logical_offset,
        mft_record_physical_offset: metadata.mft_record_physical_offset,
        file_data_logical_offset: metadata.file_data_logical_offset,
        file_data_physical_offset: metadata.file_data_physical_offset,
        file_extension: filesystemFileExtension(entry),
        signature_status: metadata.signature_status || "",
        detected_signature: metadata.detected_signature || "",
        metadata: reportMetadata(metadata)
      };
      [
        "email_format", "email_parser", "email_parser_status", "email_parser_error",
        "email_from", "email_to", "email_cc", "email_bcc", "email_subject",
        "email_date", "email_message_id", "email_reply_to", "email_in_reply_to",
        "email_body_preview", "email_attachment_names", "pst_folder_path", "pst_parser_scope",
        "pst_attachment_content_extraction", "pst_deleted_recovery", "source_entry_name", "filesystem_parser", "ntfs_path",
        "fat_path", "ntfs_standard_modification_time_utc", "ntfs_modification_time_utc"
      ].forEach((key) => {
        if (metadata[key] !== undefined && metadata[key] !== null && String(metadata[key]).length > 0) {
          ref[key] = metadata[key];
        }
      });
      return ref;
    }

    function browserActivityDisplayName(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "browser_history_visit") {
        return firstText(metadata.title, metadata.url, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_url") {
        return firstText(metadata.title, metadata.url, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_search_term") {
        return firstText(metadata.search_term ? "Search: " + metadata.search_term : "", metadata.url, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_download") {
        return firstText(metadata.file_name, metadata.target_path, metadata.current_path, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_bookmark") {
        return firstText(metadata.name, metadata.title, metadata.url, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_login") {
        return firstText(compactParts([metadata.username || metadata.http_realm, metadata.host ? "@ " + metadata.host : ""]), metadata.origin_url, metadata.hostname, entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_cookie") {
        return firstText(compactParts([metadata.cookie_name, metadata.host]), entry.name, logicalName(entry.logical_path));
      }
      if (metadata.artifact_kind === "browser_preference") {
        return firstText(metadata.category, metadata.name, entry.name, logicalName(entry.logical_path));
      }
      return firstText(entry.name, logicalName(entry.logical_path));
    }

    function browserActivityPreview(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "browser_history_visit") {
        return compactParts([metadata.visit_time_utc, firstText(metadata.title), metadata.url]);
      }
      if (metadata.artifact_kind === "browser_url") {
        return compactParts([metadata.last_visit_time_utc, firstText(metadata.title), metadata.url, metadata.visit_count !== undefined ? "visits " + metadata.visit_count : ""]);
      }
      if (metadata.artifact_kind === "browser_search_term") {
        return compactParts([metadata.last_visit_time_utc, metadata.search_term ? "Search: " + metadata.search_term : "", metadata.url]);
      }
      if (metadata.artifact_kind === "browser_download") {
        return compactParts([metadata.start_time_utc, metadata.file_name, metadata.target_path, metadata.tab_url || metadata.source_url]);
      }
      if (metadata.artifact_kind === "browser_bookmark") {
        return compactParts([firstText(metadata.name, metadata.title), metadata.url, metadata.folder]);
      }
      if (metadata.artifact_kind === "browser_login") {
        return compactParts([metadata.date_last_used_utc || metadata.time_last_used_utc, metadata.username || metadata.http_realm, metadata.host || metadata.origin_url || metadata.hostname]);
      }
      if (metadata.artifact_kind === "browser_cookie") {
        return compactParts([metadata.creation_utc, metadata.cookie_name, metadata.host, metadata.cookie_path]);
      }
      if (metadata.artifact_kind === "browser_preference") {
        return compactParts([metadata.category, preferenceSummary(metadata)]);
      }
      return entry.logical_path;
    }

    function preferenceSummary(metadata) {
      const values = [
        metadata.name ? "profile " + metadata.name : "",
        Array.isArray(metadata.startup_urls) && metadata.startup_urls.length ? "startup " + metadata.startup_urls.join(", ") : "",
        metadata.homepage ? "homepage " + metadata.homepage : "",
        metadata.download_default_directory ? "downloads " + metadata.download_default_directory : "",
        metadata.extension_count !== undefined && metadata.extension_count !== null ? metadata.extension_count + " extensions" : ""
      ];
      return compactParts(values) || compactJson(metadata);
    }

    function browserActivityItemRef(entry) {
      const metadata = entry.metadata_json || {};
      const ref = {
        kind: "browser_activity",
        activity_kind: metadata.artifact_kind || "record",
        browser_family: metadata.browser_family || "chromium",
        evidence_id: entry.evidence_id,
        entry_id: entry.id,
        entry_kind: entry.entry_kind,
        logical_path: entry.logical_path,
        display_name: browserActivityDisplayName(entry),
        metadata: reportMetadata(metadata)
      };
      [
        "url", "title", "host", "visit_time_utc", "transition_type", "visit_count",
        "typed_count", "visit_duration_microseconds", "visit_id", "url_id",
        "last_visit_time_utc", "visit_time_chrome", "last_visit_time_chrome",
        "transition", "hidden", "name", "folder", "date_added_utc",
        "date_last_used_utc", "date_added_chrome", "date_last_used_chrome",
        "guid", "search_term", "file_name", "target_path", "current_path",
        "start_time_utc", "end_time_utc", "start_time_chrome", "end_time_chrome",
        "received_bytes", "total_bytes", "state", "danger_type",
        "interrupt_reason", "referrer", "tab_url", "source_url", "mime_type",
        "origin_url", "action_url", "hostname", "http_realm", "username",
        "date_created_utc", "date_last_used_utc", "time_created_utc",
        "time_last_used_utc", "time_password_changed_utc", "times_used",
        "password_note", "cookie_name", "cookie_path", "creation_utc",
        "last_access_utc", "last_accessed_utc", "expires_utc", "expiry_utc",
        "is_secure", "is_httponly", "value_note",
        "category", "startup_urls", "homepage", "restore_on_startup",
        "homepage_is_newtabpage", "download_default_directory", "prompt_for_download",
        "created_by_version", "last_used", "avatar_index", "extension_count",
        "source_artifact", "source_artifact_path", "source_file_size_bytes",
        "source_file_created_utc", "source_file_modified_utc", "source_file_accessed_utc"
      ].forEach((key) => {
        if (metadata[key] !== undefined && metadata[key] !== null && String(metadata[key]).length > 0) {
          ref[key] = metadata[key];
        }
      });
      return ref;
    }

    function searchResultItemRef(hit) {
      const entry = findLoadedEntry(hit.entry_id);
      const metadata = entry ? (entry.metadata_json || {}) : {};
      return {
        kind: "search_result",
        match_kind: hit.match_kind,
        evidence_id: hit.evidence_id,
        entry_id: hit.entry_id,
        logical_path: hit.logical_path,
        display_name: hit.display_name,
        selection_offset: hit.selection_offset,
        selection_length: hit.selection_length,
        data_preview: hit.data_preview,
        size_bytes: entry ? entry.size_bytes : null,
        is_deleted: entry ? Boolean(entry.is_deleted) : false,
        relative_path: hit.logical_path,
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        mft_record_logical_offset: metadata.mft_record_logical_offset,
        mft_record_physical_offset: metadata.mft_record_physical_offset,
        file_data_logical_offset: metadata.file_data_logical_offset,
        file_data_physical_offset: metadata.file_data_physical_offset,
        finding_logical_offset: hit.selection_offset,
        file_extension: entry ? filesystemFileExtension(entry) : fileExtension(hit.logical_path),
        signature_status: metadata.signature_status || "",
        detected_signature: metadata.detected_signature || "",
        metadata: reportMetadata(metadata)
      };
    }

    function filesystemEntryItemRef(entry) {
      const metadata = entry.metadata_json || {};
      return {
        kind: "filesystem_entry",
        entry_kind: entry.entry_kind,
        evidence_id: entry.evidence_id,
        entry_id: entry.id,
        logical_path: entry.logical_path,
        relative_path: entry.logical_path,
        display_name: entry.name || logicalName(entry.logical_path),
        size_bytes: entry.size_bytes,
        is_deleted: Boolean(entry.is_deleted),
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        mft_record_logical_offset: metadata.mft_record_logical_offset,
        mft_record_physical_offset: metadata.mft_record_physical_offset,
        file_data_logical_offset: metadata.file_data_logical_offset,
        file_data_physical_offset: metadata.file_data_physical_offset,
        file_extension: filesystemFileExtension(entry),
        signature_status: metadata.signature_status || "",
        detected_signature: metadata.detected_signature || "",
        metadata: reportMetadata(metadata)
      };
    }

    // Build a reproducible record for a selected byte range. Indexed entries,
    // live files, and raw offsets are normalized by currentHexEntry().
    function hexSelectionItemRef(entry, range, bytes) {
      const metadata = entry.metadata_json || {};
      const evidence = evidenceSourceForEntry(entry) || {};
      const isRaw = metadata.source === "raw_image";
      const isLive = metadata.source === "live_browse";
      const filesystemContext = isRaw || (!isLive && state.hex.entryId === entry.id && state.hex.byteContext === "filesystem");
      const liveEntry = isLive ? (liveEntryByPath(metadata.volume, metadata.image_path) || {}) : {};
      const containerStartOffset = isRaw ? (Number(metadata.start_offset) || 0) : null;
      const fileDataPhysicalOffset = firstDefined(isLive ? liveEntry.file_data_physical_offset : metadata.file_data_physical_offset);
      const fileDataFileOffset = Number(firstDefined(isLive ? liveEntry.file_data_file_offset : metadata.file_data_file_offset) || 0);
      const fileDataContiguousBytes = Number(firstDefined(isLive ? liveEntry.file_data_contiguous_bytes : metadata.file_data_contiguous_bytes));
      const diskLocation = !isRaw && !isLive ? resolvedDiskLocation() : null;
      const selectionLength = range.end - range.start + 1;
      let selectionFileStart = range.start;
      let selectionFileEnd = range.end;
      let selectionDecodedStart = null;
      let selectionDecodedEnd = null;
      let physicalBasis = "unknown - offset within source could not be resolved";
      if (filesystemContext) {
        selectionDecodedStart = range.start;
        selectionDecodedEnd = range.end;
        physicalBasis = isRaw
          ? "direct decoded-media offsets in raw view"
          : "direct decoded-media offsets in file-system view";
        if (isRaw) {
          selectionFileStart = range.start - containerStartOffset;
          selectionFileEnd = range.end - containerStartOffset;
        } else if (diskLocation && decodedRangeWithinDiskLocation(diskLocation, range.start, range.end)) {
          selectionFileStart = Number(diskLocation.file_relative_offset || 0)
            + range.start - Number(diskLocation.decoded_media_offset);
          selectionFileEnd = selectionFileStart + selectionLength - 1;
          physicalBasis = diskLocation.basis + " (verified contiguous mapping)";
        } else {
          selectionFileStart = null;
          selectionFileEnd = null;
        }
      } else if (diskLocation && fileRangeWithinDiskLocation(diskLocation, range.start, range.end)) {
        selectionDecodedStart = Number(diskLocation.decoded_media_offset)
          + range.start - Number(diskLocation.file_relative_offset || 0);
        selectionDecodedEnd = selectionDecodedStart + selectionLength - 1;
        physicalBasis = diskLocation.basis + " (verified contiguous mapping)";
      } else if (fileDataPhysicalOffset != null) {
        const delta = range.start - fileDataFileOffset;
        const rangeIsVerified = delta >= 0 && Number.isFinite(fileDataContiguousBytes)
          && range.end < fileDataFileOffset + fileDataContiguousBytes;
        if (rangeIsVerified || (delta === 0 && selectionLength === 1)) {
          selectionDecodedStart = Number(fileDataPhysicalOffset) + delta;
          selectionDecodedEnd = selectionDecodedStart + selectionLength - 1;
          physicalBasis = rangeIsVerified
            ? "parser-recorded file-data range (verified contiguous mapping)"
            : "parser-recorded exact file-data start";
        }
      }
      const createdUtc = firstDefined(isLive ? liveEntry.created_utc : metadata.created_utc);
      const modifiedUtc = firstDefined(isLive ? liveEntry.modified_utc : metadata.modified_utc);
      const accessedUtc = firstDefined(isLive ? liveEntry.accessed_utc : metadata.accessed_utc);
      return {
        kind: "highlighted_bytes",
        entry_kind: entry.entry_kind,
        evidence_id: entry.evidence_id,
        entry_id: entry.id || null,
        logical_path: entry.logical_path,
        relative_path: isLive ? metadata.image_path : entry.logical_path,
        display_name: entry.name || logicalName(entry.logical_path),
        evidence_source: evidence.display_name || evidence.source_path || "",
        source: isRaw ? "raw_image_container" : (isLive ? "live_browse_unindexed" : "indexed_case_entry"),
        volume: metadata.volume == null ? null : metadata.volume,
        size_bytes: isLive ? (liveEntry.size_bytes == null ? null : liveEntry.size_bytes) : entry.size_bytes,
        is_deleted: Boolean(entry.is_deleted),
        storage_area: metadata.storage_area || "",
        is_file_slack: Boolean(metadata.is_file_slack),
        is_unallocated: Boolean(metadata.is_unallocated),
        has_macb_times: Boolean(createdUtc || modifiedUtc || accessedUtc),
        created_utc: createdUtc || null,
        modified_utc: modifiedUtc || null,
        accessed_utc: accessedUtc || null,
        mft_record_logical_offset: isLive ? liveEntry.mft_record_logical_offset : metadata.mft_record_logical_offset,
        mft_record_physical_offset: isLive ? liveEntry.mft_record_physical_offset : metadata.mft_record_physical_offset,
        file_data_logical_offset: isLive ? liveEntry.file_data_logical_offset : metadata.file_data_logical_offset,
        file_data_physical_offset: fileDataPhysicalOffset,
        container_start_offset: containerStartOffset,
        byte_context: filesystemContext ? "filesystem" : "file",
        selection_view_offset_start: range.start,
        selection_view_offset_end: range.end,
        selection_file_offset_start: selectionFileStart,
        selection_file_offset_end: selectionFileEnd,
        selection_logical_offset_start: selectionFileStart,
        selection_logical_offset_end: selectionFileEnd,
        selection_length_bytes: selectionLength,
        selection_decoded_media_offset_start: selectionDecodedStart,
        selection_decoded_media_offset_end: selectionDecodedEnd,
        selection_physical_offset_start: selectionDecodedStart,
        selection_physical_offset_end: selectionDecodedEnd,
        physical_offset_basis: physicalBasis,
        file_extension: filesystemFileExtension(entry),
        hex_preview: bytes.map(byteHex).join(" "),
        ascii_preview: printableAsciiPreview(bytes),
        metadata: reportMetadata(metadata)
      };
    }

    function reportMetadata(metadata) {
      const copy = {};
      Object.keys(metadata || {}).forEach((key) => {
        if (key !== "search_text") {
          copy[key] = metadata[key];
        }
      });
      if (isBrowserActivityKind(copy.artifact_kind)) {
        if (!firstText(copy.created_utc)) {
          const created = browserArtifactDisplayTime(copy, "created");
          if (created) {
            copy.created_utc = created;
          }
        }
        if (!firstText(copy.accessed_utc)) {
          const accessed = browserArtifactDisplayTime(copy, "accessed");
          if (accessed) {
            copy.accessed_utc = accessed;
          }
        }
        if (!firstText(copy.modified_utc)) {
          const modified = browserArtifactDisplayTime(copy, "modified");
          if (modified) {
            copy.modified_utc = modified;
          }
        }
      }
      return copy;
    }

    function firstText(...values) {
      for (const value of values) {
        const text = String(value ?? "").trim();
        if (text) {
          return text;
        }
      }
      return "";
    }

    function firstDefined(...values) {
      for (const value of values) {
        if (value !== undefined && value !== null && String(value).length > 0) {
          return value;
        }
      }
      return null;
    }

    function compactParts(values) {
      return values.map((value) => String(value ?? "").trim()).filter(Boolean).join(" | ");
    }

    function arrayText(value) {
      if (Array.isArray(value)) {
        return value.map((part) => String(part ?? "").trim()).filter(Boolean).join(", ");
      }
      return String(value ?? "").trim();
    }

    function compactJson(value) {
      try {
        return JSON.stringify(value);
      } catch (_) {
        return "";
      }
    }

    function setInspectorState(stateName) {
      const pane = $("browserViewer");
      if (!pane) {
        return;
      }
      pane.classList.toggle("viewer-idle", stateName === "idle");
      pane.classList.toggle("viewer-detail", stateName === "detail");
      pane.classList.toggle("viewer-active", stateName === "active");
    }

    function currentHexEntry() {
      if (state.hex.raw) {
        return {
          id: null,
          entry_kind: "file",
          evidence_id: state.hex.raw.evidenceId,
          name: state.hex.raw.name,
          logical_path: state.hex.raw.logicalPath,
          size_bytes: state.hex.raw.sizeBytes,
          is_deleted: false,
          metadata_json: {
            source: "raw_image",
            start_offset: state.hex.raw.startOffset,
            volume: state.hex.raw.volume == null ? null : state.hex.raw.volume
          }
        };
      }
      // Live-browse files have no indexed entry row; synthesize one so the
      // viewer renders instead of falling back to "No item selected".
      if (state.hex.live) {
        return {
          id: null,
          entry_kind: "file",
          evidence_id: state.hex.live.evidenceId,
          name: state.hex.live.name,
          logical_path: "[vol " + state.hex.live.volume + "] " + state.hex.live.path,
          metadata_json: { source: "live_browse", volume: state.hex.live.volume, image_path: state.hex.live.path }
        };
      }
      return state.data && state.hex.entryId ? findLoadedEntry(state.hex.entryId) : null;
    }

    function isReadableFileEntry(entry) {
      return !!entry && entry.entry_kind === "file";
    }

    function setViewerFullscreen(enabled, historyMode = "auto") {
      const next = Boolean(enabled);
      const historyMarked = Boolean(history.state && history.state.kdftViewerFullscreen);
      if (!next && state.viewerFullscreen && historyMode === "auto" && historyMarked) {
        // The marked entry was created solely to make Back/Escape an in-app
        // fullscreen exit. Wait for popstate to synchronize the UI; guarding
        // the request prevents key-repeat or a double click from going back a
        // second time and abandoning the workbench.
        if (!state.viewerFullscreenHistoryPending) {
          state.viewerFullscreenHistoryPending = true;
          history.back();
        }
        return;
      }
      if (historyMode === "popstate") {
        state.viewerFullscreenHistoryPending = false;
      }
      if (next && !state.viewerFullscreen && historyMode === "auto" && !historyMarked) {
        // Give a newly opened analysis tab one safe in-app history step. The
        // browser Back button then exits the byte-view fullscreen state instead
        // of immediately abandoning KDFT for the browser start page.
        const prior = history.state && typeof history.state === "object" ? history.state : {};
        history.pushState({ ...prior, kdftViewerFullscreen: true }, "", window.location.href);
      }
      state.viewerFullscreen = next;
      document.body.classList.toggle("viewer-fullscreen", state.viewerFullscreen);
      const button = $("toggleViewerFullscreen");
      if (button) {
        button.textContent = state.viewerFullscreen ? "Exit full screen" : "Full screen";
        button.className = state.viewerFullscreen ? "secondary" : "ghost";
        button.setAttribute("aria-pressed", String(state.viewerFullscreen));
      }
      if (state.viewerFullscreen) {
        const entry = currentHexEntry();
        if (!isReadableFileEntry(entry)) {
          return;
        }
        if ($("viewerMode").value === "metadata") {
          $("viewerMode").value = "hex";
        }
        if (!state.hex.data && (state.hex.entryId || state.hex.live || state.hex.raw) && !state.hex.fetching) {
          fetchEntryBytes();
        } else {
          renderHexViewer();
        }
      }
    }

    function toggleViewerFullscreen() {
      setViewerFullscreen(!state.viewerFullscreen);
    }

    function updateEntryRowHighlight() {
      const selectedId = state.hex && state.hex.entryId ? String(state.hex.entryId) : "";
      document.querySelectorAll("#entryTable .entry-row[data-entry-id]").forEach((row) => {
        row.classList.toggle("selected", row.dataset.entryId === selectedId);
      });
    }

    function clearHexSelection() {
      if (!state.hex) {
        return;
      }
      state.hex.selStart = null;
      state.hex.selEnd = null;
    }

    function isHexOffset(value) {
      return typeof value === "number" && Number.isFinite(value);
    }

    function normalizedHexSelection() {
      if (!state.hex || !isHexOffset(state.hex.selStart) || !isHexOffset(state.hex.selEnd)) {
        return null;
      }
      return {
        start: Math.min(state.hex.selStart, state.hex.selEnd),
        end: Math.max(state.hex.selStart, state.hex.selEnd)
      };
    }

    function selectedHexRangeForData(data) {
      const selection = normalizedHexSelection();
      const bytes = data && data.bytes ? data.bytes : [];
      if (!selection || bytes.length === 0) {
        return null;
      }
      const windowStart = Number(data.offset) || 0;
      const windowEnd = windowStart + bytes.length - 1;
      const start = Math.max(selection.start, windowStart);
      const end = Math.min(selection.end, windowEnd);
      return end >= start ? { start, end } : null;
    }

    function hexBytesForRange(data, range) {
      if (!data || !range || !data.bytes) {
        return [];
      }
      const baseOffset = Number(data.offset) || 0;
      const startIndex = Math.max(0, range.start - baseOffset);
      const endIndex = Math.min(data.bytes.length, range.end - baseOffset + 1);
      return Array.from(data.bytes).slice(startIndex, endIndex);
    }

    function currentHexDecode(data) {
      const bytes = data && data.bytes ? Array.from(data.bytes) : [];
      const selectedRange = selectedHexRangeForData(data);
      if (selectedRange) {
        return {
          selected: true,
          start: selectedRange.start,
          count: selectedRange.end - selectedRange.start + 1,
          bytes: hexBytesForRange(data, selectedRange)
        };
      }
      return {
        selected: false,
        start: Number(data && data.offset) || 0,
        count: bytes.length,
        bytes
      };
    }

    function hexViewerStatus(entry, data) {
      const path = entry ? entry.logical_path + " | " : "";
      const bytesRead = Number(data.bytes_read || 0);
      if (isFilesystemByteContext()) {
        const location = resolvedDiskLocation();
        const offset = Number(data.offset || 0);
        const end = offset + Math.max(0, bytesRead - 1);
        let mapping = "";
        if (location) {
          const mappedStart = Number(location.decoded_media_offset);
          const mappedEnd = mappedStart + diskLocationMappedLength(location) - 1;
          if (offset >= mappedStart && offset <= mappedEnd) {
            const fileOffset = Number(location.file_relative_offset || 0) + offset - mappedStart;
            const verifiedBytes = Math.min(bytesRead, mappedEnd - offset + 1);
            mapping = " | mapped file offset " + formatOffsetPair(fileOffset);
            if (verifiedBytes < bytesRead) {
              mapping += " | first " + verifiedBytes + " bytes in verified file-data range";
            }
          } else if (bytesRead > 0 && end >= mappedStart && offset <= mappedEnd) {
            mapping = " | window overlaps resolved file-data range";
          } else {
            mapping = " | outside resolved file-data range";
          }
        }
        return path + "File system view | decoded-media offset " + formatOffsetPair(offset)
          + mapping + " | " + bytesRead + " media bytes read";
      }
      return path + "File view | file-relative offset " + formatOffsetPair(data.offset)
        + " | " + bytesRead + " bytes read | " + formatBytes(data.total_size) + " file total"
        + (data.eof ? " | EOF" : "");
    }

    function byteContextNotice() {
      if (!state.hex || !state.hex.data) {
        return "";
      }
      if (!isFilesystemByteContext()) {
        return `<div class="hex-info"><strong>File view:</strong> logical file bytes; offsets are file-relative.</div>`;
      }
      const location = resolvedDiskLocation();
      if (!location) {
        return `<div class="hex-info"><strong>File system view:</strong> decoded evidence bytes; offsets are absolute decoded-media offsets.</div>`;
      }
      const mappedStart = Number(location.decoded_media_offset);
      const mappedEnd = mappedStart + diskLocationMappedLength(location) - 1;
      const fileStart = Number(location.file_relative_offset || 0);
      const warning = location.warning ? `<br>${escapeHtml(location.warning)}` : "";
      return `<div class="hex-info"><strong>File system view:</strong> decoded-media range ${escapeHtml(formatOffsetPair(mappedStart))}-${escapeHtml(formatOffsetPair(mappedEnd))} maps to file offset ${escapeHtml(formatOffsetPair(fileStart))}. Basis: ${escapeHtml(location.basis)}.${warning}</div>`;
    }

    function renderHexViewer(error) {
      updateDataInterpreter();
      updateByteContextControls();
      const data = state.hex.data;
      const entry = currentHexEntry();
      const mode = $("viewerMode").value;
      updateEntryRowHighlight();
      if (error) {
        setInspectorState("detail");
        $("hexStatus").textContent = error;
        $("hexView").innerHTML = "";
        $("hexView").className = "hex-view";
        return;
      }
      if (!entry) {
        setViewerFullscreen(false);
        setInspectorState("idle");
        $("hexStatus").textContent = "Select a file for bytes or a browser activity record for details.";
        $("hexView").className = "metadata-view";
        $("hexView").innerHTML = empty("No item selected.");
        return;
      }
      if (mode === "metadata") {
        setInspectorState("detail");
        $("hexStatus").textContent = entry.logical_path + " | metadata";
        $("hexView").className = "metadata-view";
        $("hexView").innerHTML = metadataView(entry);
        return;
      }
      if (!data) {
        setInspectorState("detail");
        $("hexStatus").textContent = state.hex.fetching
          ? entry.logical_path + " | reading bytes..."
          : entry.logical_path + (isFilesystemByteContext()
            ? " | File system view | choose View to read decoded-media bytes."
            : " | File view | choose View to read file bytes.");
        $("hexView").className = "hex-view";
        $("hexView").innerHTML = "";
        return;
      }
      setInspectorState("active");
      $("hexStatus").textContent = hexViewerStatus(entry, data);
      if (mode === "text") {
        $("hexView").className = "text-view";
        $("hexView").textContent = decodeText(data.bytes);
      } else {
        $("hexView").className = "hex-view";
        $("hexView").style.setProperty("--bytes-per-row", String(numberValue("bytesPerRow", 16)));
        $("hexView").innerHTML = hexInspector(data);
      }
    }

    function hexInspector(data) {
      const decode = currentHexDecode(data);
      return [
        rawFindBar(),
        byteContextNotice(),
        containerByteNotice(),
        hexCurrentBar(decode),
        `<div class="hex-grid">${hexRows(data.bytes, data.offset)}</div>`,
        hexDecodePanel(decode)
      ].filter(Boolean).join("");
    }

    function containerByteNotice() {
      const entry = currentHexEntry();
      const evidence = evidenceSourceForEntry(entry);
      if (entry && isPromotableDiskImageEntry(entry, evidence)) {
        return `<div class="hex-info">Raw container bytes - use Analyze image to browse decoded contents.</div>`;
      }
      return "";
    }

    function rawFindBar() {
      if (!state.hex.raw) {
        return "";
      }
      const find = state.hex.find || {};
      const status = find.status ? `<span class="raw-find-status">${escapeHtml(find.status)}</span>` : "";
      const continueButton = find.continuation != null && !find.active
        ? `<button class="ghost" onclick="rawFindNext(true)">Continue</button><button class="ghost" onclick="rawFindCancel()">Cancel</button>`
        : "";
      return `
        <div class="raw-find">
          <label>Find<input id="rawFindQuery" spellcheck="false" value="${escapeAttr(find.query || "")}" oninput="rawFindSetQuery(this.value)" onkeydown="rawFindKeydown(event)"></label>
          <label>Kind<select id="rawFindKind" onchange="rawFindSetKind(this.value)"><option value="text"${find.kind !== "hex" ? " selected" : ""}>text</option><option value="hex"${find.kind === "hex" ? " selected" : ""}>hex</option></select></label>
          <button class="secondary" onclick="rawFindNext(false)"${find.active ? " disabled" : ""}>Find next</button>
          ${continueButton}
          ${status}
        </div>`;
    }

    function hexCurrentBar(decode) {
      const byteLabel = decode.count === 1 ? "1 byte" : decode.count + " bytes";
      const disabled = decode.selected ? "" : " disabled";
      return `
        <div class="hex-current">
          <span class="hex-current-item"><strong>Current offset</strong>${escapeHtml(formatOffsetPair(decode.start))}</span>
          <span class="hex-current-item"><strong>Current selection</strong>${escapeHtml(byteLabel)}</span>
          <span class="hex-current-spacer"></span>
          <button id="copyHexSelection" class="ghost"${disabled}>COPY SELECTION</button>
          <button id="saveHexSelection" class="ghost"${disabled}>SAVE SELECTION</button>
        </div>
      `;
    }

    function hexRows(bytes, baseOffset) {
      if (!bytes || bytes.length === 0) {
        return `<div class="hex-row"><span class="hex-offset">${displayOffset(baseOffset)}</span><span></span><span class="hex-ascii">EOF</span></div>`;
      }
      const rows = [];
      const baseOffsetValue = Number(baseOffset) || 0;
      const bytesPerRow = numberValue("bytesPerRow", 16);
      const selection = selectedHexRangeForData({ bytes, offset: baseOffsetValue });
      for (let index = 0; index < bytes.length; index += bytesPerRow) {
        const chunk = bytes.slice(index, index + bytesPerRow);
        const hex = chunk.map((value, chunkIndex) => {
          const offset = baseOffsetValue + index + chunkIndex;
          return hexByteCell(value, offset, selection);
        }).join("");
        const ascii = chunk.map((value, chunkIndex) => {
          const offset = baseOffsetValue + index + chunkIndex;
          return hexAsciiCell(value, offset, selection);
        }).join("");
        rows.push(`<div class="hex-row"><span class="hex-offset">${displayOffset(baseOffsetValue + index)}</span><span class="hex-bytes">${hex}</span><span class="hex-ascii">${ascii}</span></div>`);
      }
      return rows.join("");
    }

    function hexByteCell(value, offset, selection) {
      const selected = selection && offset >= selection.start && offset <= selection.end;
      const className = selected ? "hex-cell hex-byte selected" : "hex-cell hex-byte";
      return `<span class="${className}" data-byte-offset="${offset}">${byteHex(value)}</span>`;
    }

    function hexAsciiCell(value, offset, selection) {
      const selected = selection && offset >= selection.start && offset <= selection.end;
      const className = selected ? "hex-cell hex-char selected" : "hex-cell hex-char";
      const text = value >= 32 && value <= 126 ? String.fromCharCode(value) : ".";
      return `<span class="${className}" data-byte-offset="${offset}">${escapeHtml(text)}</span>`;
    }

    function hexDecodePanel(decode) {
      const bytes = decode.bytes;
      const be = hexEndianness() === "be";
      const suffix = be ? "BE" : "LE";
      const stringRows = [
        ["ASCII", decodeAscii(bytes)],
        ["Binary (Base 64)", encodeBase64(bytes)],
        ["UTF-7 (ASCII fallback)", decodeAscii(bytes)],
        ["UTF-8", decodeWithTextDecoder("utf-8", bytes)],
        [`UTF-16 ${suffix} (Unicode)`, decodeWithTextDecoder(be ? "utf-16be" : "utf-16le", bytes)],
        [`UTF-32 ${suffix}`, decodeUtf32(bytes, be)]
      ];
      const integerRows = [
        ["8-bit U / S", decodeIntPair(bytes, 1, be)],
        ["16-bit U / S", decodeIntPair(bytes, 2, be)],
        ["32-bit U / S", decodeIntPair(bytes, 4, be)],
        ["64-bit U / S", decodeIntPair(bytes, 8, be)]
      ];
      const dateRows = [
        ["Chrome", decodeChromeTime(bytes, be)],
        ["FireFox", decodeFirefoxTime(bytes, be)],
        ["HFS+ 32-bit BE", decodeHfsTime(bytes)],
        ["Windows FILETIME", decodeFiletime(bytes, be)],
        [`Unix 32-bit ${suffix}`, decodeUnixTime(bytes, be)]
      ];
      return `
        <section class="hex-decode">
          <div class="hex-decode-head"><span>DECODE</span><span class="hex-endian"><button class="${be ? "" : "active"}" onclick="setHexEndianness('le')" title="Interpret multi-byte values little-endian">LE</button><button class="${be ? "active" : ""}" onclick="setHexEndianness('be')" title="Interpret multi-byte values big-endian">BE</button></span></div>
          <div class="hex-decode-grid">
            <section class="hex-decode-group">
              <h3>STRING</h3>
              <dl class="hex-decode-table">${decodeRows(stringRows)}</dl>
            </section>
            <section class="hex-decode-group">
              <h3>INTEGER</h3>
              <dl class="hex-decode-table">${decodeRows(integerRows)}</dl>
            </section>
            <section class="hex-decode-group">
              <h3>DATE / TIME</h3>
              <dl class="hex-decode-table">${decodeRows(dateRows)}</dl>
            </section>
          </div>
        </section>
      `;
    }

    function hexEndianness() {
      return localStorage.getItem("kdft.hexEndianness") === "be" ? "be" : "le";
    }

    function setHexEndianness(value) {
      localStorage.setItem("kdft.hexEndianness", value === "be" ? "be" : "le");
      renderHexViewer();
    }

    function readUintFirst(bytes, size, be) {
      if (!bytes || bytes.length < size) {
        return null;
      }
      let value = 0n;
      if (be) {
        for (let index = 0; index < size; index += 1) {
          value = (value << 8n) | BigInt(bytes[index] & 255);
        }
      } else {
        for (let index = size - 1; index >= 0; index -= 1) {
          value = (value << 8n) | BigInt(bytes[index] & 255);
        }
      }
      return value;
    }

    function decodeIntPair(bytes, size, be) {
      const value = readUintFirst(bytes, size, be);
      if (value == null) {
        return null;
      }
      const bits = BigInt(size * 8);
      const signed = value >= (1n << (bits - 1n)) ? value - (1n << bits) : value;
      return signed === value ? value.toString(10) : `${value.toString(10)} / ${signed.toString(10)}`;
    }

    function firstBytes(bytes, size) {
      return bytes && bytes.length >= size ? bytes.slice(0, size) : null;
    }

    function decodeFloat(bytes, size, be) {
      const slice = firstBytes(bytes, size);
      if (!slice) {
        return null;
      }
      const view = new DataView(Uint8Array.from(slice).buffer);
      const value = size === 4 ? view.getFloat32(0, !be) : view.getFloat64(0, !be);
      return String(value);
    }

    function decodeUnixMillis(bytes, be) {
      const slice = firstBytes(bytes, 8);
      if (!slice) {
        return null;
      }
      return saneIsoDate(Number(readUintFirst(slice, 8, be)));
    }

    function decodeDosDateTime(bytes, be) {
      const slice = firstBytes(bytes, 4);
      if (!slice) {
        return null;
      }
      // FAT layout: 16-bit time then 16-bit date; the toggle sets each word's order.
      const time = Number(readUintFirst(slice.slice(0, 2), 2, be));
      const date = Number(readUintFirst(slice.slice(2, 4), 2, be));
      const day = date & 31;
      const month = (date >> 5) & 15;
      const year = 1980 + ((date >> 9) & 127);
      const seconds = (time & 31) * 2;
      const minutes = (time >> 5) & 63;
      const hours = (time >> 11) & 31;
      if (month < 1 || month > 12 || day < 1 || hours > 23 || minutes > 59 || seconds > 59) {
        return null;
      }
      return saneIsoDate(Date.UTC(year, month - 1, day, hours, minutes, seconds));
    }

    function decodeGuid(bytes) {
      const b = firstBytes(bytes, 16);
      if (!b) {
        return null;
      }
      const hex = (arr) => arr.map(byteHex).join("").toLowerCase();
      return `${hex([b[3], b[2], b[1], b[0]])}-${hex([b[5], b[4]])}-${hex([b[7], b[6]])}-${hex([b[8], b[9]])}-${hex(b.slice(10, 16))}`;
    }

    function ensureDataInterpreterDom() {
      let panel = document.getElementById("dataInterpreter");
      if (panel) {
        return panel;
      }
      panel = document.createElement("div");
      panel.id = "dataInterpreter";
      panel.className = "data-interpreter";
      panel.hidden = true;
      panel.innerHTML = `
        <div class="di-head" id="diHead">
          <span>Data Interpreter</span>
          <span class="hex-endian"><button id="diLe" onclick="setHexEndianness('le')" title="Little-endian">LE</button><button id="diBe" onclick="setHexEndianness('be')" title="Big-endian">BE</button></span>
          <button class="di-close" onclick="toggleDataInterpreter(false)" title="Close">&times;</button>
        </div>
        <dl class="di-table" id="diTable"></dl>`;
      document.body.appendChild(panel);
      bindDataInterpreterDrag(panel);
      return panel;
    }

    function toggleDataInterpreter(force) {
      const panel = ensureDataInterpreterDom();
      const open = typeof force === "boolean" ? force : panel.hidden;
      panel.hidden = !open;
      localStorage.setItem("kdft.dataInterpreter.open", open ? "1" : "0");
      if (open) {
        applyDataInterpreterPos(panel);
        updateDataInterpreter();
      }
    }

    function positionDataInterpreter(panel, left, top) {
      const maxLeft = Math.max(0, window.innerWidth - panel.offsetWidth);
      const maxTop = Math.max(0, window.innerHeight - 48);
      panel.style.right = "auto";
      panel.style.left = Math.min(Math.max(0, left), maxLeft) + "px";
      panel.style.top = Math.min(Math.max(0, top), maxTop) + "px";
    }

    function applyDataInterpreterPos(panel) {
      let pos = null;
      try {
        pos = JSON.parse(localStorage.getItem("kdft.dataInterpreter.pos") || "null");
      } catch (_) {}
      if (pos && Number.isFinite(pos.left) && Number.isFinite(pos.top)) {
        positionDataInterpreter(panel, pos.left, pos.top);
      }
    }

    function bindDataInterpreterDrag(panel) {
      const head = panel.querySelector("#diHead");
      let drag = null;
      head.addEventListener("pointerdown", (event) => {
        if (event.target.closest("button")) {
          return;
        }
        const rect = panel.getBoundingClientRect();
        drag = { dx: event.clientX - rect.left, dy: event.clientY - rect.top, id: event.pointerId };
        if (head.setPointerCapture) {
          try {
            head.setPointerCapture(event.pointerId);
          } catch (_) {}
        }
        event.preventDefault();
      });
      head.addEventListener("pointermove", (event) => {
        if (!drag || event.pointerId !== drag.id) {
          return;
        }
        positionDataInterpreter(panel, event.clientX - drag.dx, event.clientY - drag.dy);
      });
      const stop = (event) => {
        if (!drag || event.pointerId !== drag.id) {
          return;
        }
        drag = null;
        const rect = panel.getBoundingClientRect();
        localStorage.setItem("kdft.dataInterpreter.pos", JSON.stringify({ left: rect.left, top: rect.top }));
      };
      head.addEventListener("pointerup", stop);
      head.addEventListener("pointercancel", stop);
    }

    function dataInterpreterRows(bytes, be) {
      const chrome8 = firstBytes(bytes, 8);
      const hfs4 = firstBytes(bytes, 4);
      return [
        ["uint8 / int8", decodeIntPair(bytes, 1, be)],
        ["uint16 / int16", decodeIntPair(bytes, 2, be)],
        ["uint32 / int32", decodeIntPair(bytes, 4, be)],
        ["uint64 / int64", decodeIntPair(bytes, 8, be)],
        ["float32", decodeFloat(bytes, 4, be)],
        ["float64", decodeFloat(bytes, 8, be)],
        ["DOS date/time", decodeDosDateTime(bytes, be)],
        ["Unix 32-bit", firstBytes(bytes, 4) ? decodeUnixTime(bytes, be) : null],
        ["Unix ms 64-bit", decodeUnixMillis(bytes, be)],
        ["Windows FILETIME", chrome8 ? decodeFiletime(bytes, be) : null],
        ["Chrome/WebKit", chrome8 ? decodeChromeTime(chrome8, be) : null],
        ["FireFox PRTime", chrome8 ? decodeFirefoxTime(chrome8, be) : null],
        ["HFS+ 32-bit BE", hfs4 ? decodeHfsTime(hfs4) : null],
        ["GUID/UUID", decodeGuid(bytes)]
      ];
    }

    function updateDataInterpreter() {
      const panel = document.getElementById("dataInterpreter");
      if (!panel || panel.hidden) {
        return;
      }
      const be = hexEndianness() === "be";
      panel.querySelector("#diLe").className = be ? "" : "active";
      panel.querySelector("#diBe").className = be ? "active" : "";
      const table = panel.querySelector("#diTable");
      const data = state.hex && state.hex.data;
      if (!data || !data.bytes || data.bytes.length === 0) {
        table.innerHTML = "<dt>Cursor</dt><dd>&mdash; open bytes in the hex view</dd>";
        return;
      }
      const windowStart = Number(data.offset) || 0;
      const selection = normalizedHexSelection();
      const cursor = selection ? selection.start : windowStart;
      const index = Math.max(0, cursor - windowStart);
      const bytes = Array.from(data.bytes).slice(index, index + 16);
      const rows = dataInterpreterRows(bytes, be);
      table.innerHTML = `<dt>Cursor</dt><dd>${escapeHtml(formatOffsetPair(cursor))}</dd>` +
        rows.map((row) => `<dt>${escapeHtml(row[0])}</dt><dd>${decodeValue(row[1])}</dd>`).join("");
    }

    function decodeRows(rows) {
      return rows.map((row) => `<dt>${escapeHtml(row[0])}</dt><dd>${decodeValue(row[1])}</dd>`).join("");
    }

    function decodeValue(value) {
      if (value == null || value === "") {
        return "&mdash;";
      }
      return escapeHtml(visibleDecodedText(value));
    }

    function visibleDecodedText(value) {
      return String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ".");
    }

    function decodeAscii(bytes) {
      return bytes.map((value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
    }

    function encodeBase64(bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      let binary = "";
      const chunkSize = 0x8000;
      for (let index = 0; index < bytes.length; index += chunkSize) {
        binary += String.fromCharCode(...bytes.slice(index, index + chunkSize));
      }
      return btoa(binary);
    }

    function decodeWithTextDecoder(label, bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      try {
        return new TextDecoder(label, { fatal: false }).decode(Uint8Array.from(bytes));
      } catch (_) {
        return decodeAscii(bytes);
      }
    }

    function decodeUtf32(bytes, be) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      const chars = [];
      for (let index = 0; index + 3 < bytes.length; index += 4) {
        const point = be
          ? ((bytes[index] & 255) * 0x1000000) +
            ((bytes[index + 1] & 255) * 0x10000) +
            ((bytes[index + 2] & 255) * 0x100) +
            (bytes[index + 3] & 255)
          : (bytes[index] & 255) +
            ((bytes[index + 1] & 255) * 0x100) +
            ((bytes[index + 2] & 255) * 0x10000) +
            ((bytes[index + 3] & 255) * 0x1000000);
        if (point <= 0x10FFFF && (point < 0xD800 || point > 0xDFFF)) {
          chars.push(String.fromCodePoint(point));
        } else {
          chars.push(String.fromCharCode(0xFFFD));
        }
      }
      if (bytes.length % 4 !== 0) {
        chars.push(String.fromCharCode(0xFFFD));
      }
      return chars.join("");
    }

    function decodeChromeTime(bytes, be) {
      if (!bytes || bytes.length !== 8) {
        return null;
      }
      const micros = readUintFirst(bytes, 8, be);
      const millis = Number(micros / 1000n) - 11644473600000;
      return saneIsoDate(millis);
    }

    function decodeFirefoxTime(bytes, be) {
      if (!bytes || bytes.length !== 8) {
        return null;
      }
      const micros = readUintFirst(bytes, 8, be);
      const millis = Number(micros / 1000n);
      return saneIsoDate(millis);
    }

    function decodeHfsTime(bytes) {
      if (!bytes || bytes.length !== 4) {
        return null;
      }
      const seconds =
        ((bytes[0] & 255) * 0x1000000) +
        ((bytes[1] & 255) * 0x10000) +
        ((bytes[2] & 255) * 0x100) +
        (bytes[3] & 255);
      return saneIsoDate(Date.UTC(1904, 0, 1) + (seconds * 1000));
    }

    function saneIsoDate(millis) {
      if (!Number.isFinite(millis)) {
        return null;
      }
      const date = new Date(millis);
      if (!Number.isFinite(date.getTime())) {
        return null;
      }
      const year = date.getUTCFullYear();
      if (year < 1601 || year > 2200) {
        return null;
      }
      return date.toISOString();
    }

    function byteHex(value) {
      return (Number(value) & 255).toString(16).padStart(2, "0").toUpperCase();
    }

    function printableAsciiPreview(bytes) {
      return (bytes || []).map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : ".")).join("");
    }

    function formatOffsetPair(value) {
      const offset = Number(value) || 0;
      return `${offset} (0x${offset.toString(16).toUpperCase().padStart(8, "0")})`;
    }

    function formatRawFindOffset(value) {
      const offset = Number(value) || 0;
      return "0x" + offset.toString(16).toUpperCase().padStart(8, "0") + " / dec " + offset;
    }

    function bindHexSelection() {
      const view = $("hexView");
      if (!view) {
        return;
      }
      view.addEventListener("pointerdown", startHexSelection);
      view.addEventListener("pointermove", moveHexSelection);
      view.addEventListener("pointerup", endHexSelection);
      view.addEventListener("pointercancel", endHexSelection);
      view.addEventListener("click", (event) => {
        if (!event.target || !event.target.closest) {
          return;
        }
        if (event.target.closest("#copyHexSelection")) {
          copyHexSelection();
        } else if (event.target.closest("#saveHexSelection")) {
          saveHexSelection();
        }
      });
    }

    function startHexSelection(event) {
      if (event.button !== 0) {
        return;
      }
      const offset = hexOffsetFromTarget(event.target);
      if (offset == null) {
        return;
      }
      const selection = normalizedHexSelection();
      const anchor = event.shiftKey && selection ? selection.start : offset;
      event.preventDefault();
      hexSelecting = true;
      hexSelectionAnchor = anchor;
      hexPointerId = event.pointerId;
      const view = $("hexView");
      if (view && view.setPointerCapture) {
        try {
          view.setPointerCapture(event.pointerId);
        } catch (_) {}
      }
      setHexSelection(anchor, offset);
    }

    function moveHexSelection(event) {
      if (!hexSelecting || event.pointerId !== hexPointerId) {
        return;
      }
      const offset = hexOffsetFromPoint(event.clientX, event.clientY);
      if (offset == null) {
        return;
      }
      event.preventDefault();
      setHexSelection(hexSelectionAnchor, offset);
    }

    function endHexSelection(event) {
      if (!hexSelecting || event.pointerId !== hexPointerId) {
        return;
      }
      const offset = hexOffsetFromPoint(event.clientX, event.clientY);
      if (offset != null) {
        setHexSelection(hexSelectionAnchor, offset);
      }
      hexSelecting = false;
      hexSelectionAnchor = null;
      const view = $("hexView");
      if (view && view.releasePointerCapture) {
        try {
          view.releasePointerCapture(event.pointerId);
        } catch (_) {}
      }
      hexPointerId = null;
    }

    function hexOffsetFromPoint(clientX, clientY) {
      const target = document.elementFromPoint(clientX, clientY);
      return hexOffsetFromTarget(target);
    }

    function hexOffsetFromTarget(target) {
      if (!target || !target.closest) {
        return null;
      }
      const cell = target.closest("[data-byte-offset]");
      if (!cell || !$("hexView").contains(cell)) {
        return null;
      }
      const offset = Number(cell.dataset.byteOffset);
      return Number.isFinite(offset) ? offset : null;
    }

    function setHexSelection(anchor, focus) {
      if (!state.hex || !state.hex.data || !Number.isFinite(anchor) || !Number.isFinite(focus)) {
        return;
      }
      const start = Math.min(Math.floor(anchor), Math.floor(focus));
      const end = Math.max(Math.floor(anchor), Math.floor(focus));
      if (state.hex.selStart === start && state.hex.selEnd === end) {
        return;
      }
      state.hex.selStart = start;
      state.hex.selEnd = end;
      renderHexViewer();
    }

    // The hex viewer's "Bookmark" button: if bytes are highlighted, bookmark
    // that exact range as a highlighted_data bookmark item (works for indexed
    // entries, live-browse files, and raw container offsets alike, since none
    // of those previously produced a bookmarkable "entry" for a byte range).
    // With no byte selection it falls back to whole-item bookmarking.
    async function bookmarkHexTarget() {
      const entry = currentHexEntry();
      if (!entry) {
        setNotice("Select a file before bookmarking.", true);
        return;
      }
      const range = selectedHexRangeForData(state.hex.data);
      if (!range) {
        if (state.hex.entryId) {
          await bookmarkEntry(state.hex.entryId);
        } else if (state.hex.live) {
          try {
            await postLiveBookmark(state.hex.live.volume, state.hex.live.path, state.hex.live.name, false);
            await refresh();
            setNotice("Bookmarked " + state.hex.live.name + ".");
          } catch (err) {
            setNotice(err.message, true);
          }
        } else {
          setNotice("Select bytes to bookmark a highlighted range, or bookmark the whole file from its tree row.", true);
        }
        return;
      }
      const bytes = hexBytesForRange(state.hex.data, range);
      const displayName = entry.name || logicalName(entry.logical_path);
      const offsetLabel = "0x" + range.start.toString(16).toUpperCase() + "-0x" + range.end.toString(16).toUpperCase();
      const offsetKind = isFilesystemByteContext() ? "decoded-media offset" : "file offset";
      try {
        await apiPost("/api/bookmark/quick", {
          case_path: currentCasePath(),
          folder_name: "Highlighted Data",
          title: "Highlight: " + displayName + " @ " + offsetKind + " " + offsetLabel,
          comment: bytes.length + " byte(s) selected at " + offsetKind + " " + offsetLabel + ".",
          bookmark_type: "highlighted_data",
          data_type: "Highlighted Bytes",
          evidence_id: entry.evidence_id,
          entry_id: entry.id || null,
          display_name: displayName,
          logical_path: entry.logical_path,
          selection_offset: range.start,
          selection_length: bytes.length,
          data_preview: printableAsciiPreview(bytes),
          item_ref_json: hexSelectionItemRef(entry, range, bytes)
        });
        await refresh();
        setNotice("Bookmarked " + bytes.length + " selected byte(s) from " + displayPath(entry.logical_path) + ".");
      } catch (err) {
        setNotice(err.message, true);
      }
    }

    async function copyHexSelection() {
      const range = selectedHexRangeForData(state.hex.data);
      if (!range) {
        setNotice("Select bytes before copying.", true);
        return;
      }
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        setNotice("Clipboard copy is not available in this browser.", true);
        return;
      }
      const bytes = hexBytesForRange(state.hex.data, range);
      const text = bytes.map(byteHex).join(" ");
      try {
        await navigator.clipboard.writeText(text);
        setNotice("Copied " + bytes.length + " selected bytes.");
      } catch (err) {
        setNotice("Clipboard copy failed: " + err.message, true);
      }
    }

    // Download the selected bytes as a .bin file.
    function saveHexSelection() {
      const range = selectedHexRangeForData(state.hex.data);
      if (!range) {
        setNotice("Select bytes before saving.", true);
        return;
      }
      const bytes = hexBytesForRange(state.hex.data, range);
      const entry = currentHexEntry();
      const baseName = entry ? (entry.name || logicalName(entry.logical_path)) : "entry-" + state.hex.entryId;
      const safeName = String(baseName).replace(/[^A-Za-z0-9._-]+/g, "_");
      const contextName = isFilesystemByteContext() ? "media" : "file";
      const fileName = safeName + "-" + contextName + "-0x" + range.start.toString(16).toUpperCase() + "-" + bytes.length + "b.bin";
      const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
      setNotice("Saved " + bytes.length + " selected bytes to " + fileName + ".");
    }

    function decodeUnixTime(bytes, be) {
      if (!bytes || bytes.length < 4) {
        return "";
      }
      const seconds = Number(readUintFirst(bytes, 4, be));
      if (seconds === 0) {
        return "";
      }
      const date = new Date(seconds * 1000);
      const year = date.getUTCFullYear();
      return Number.isFinite(date.getTime()) && year >= 1980 && year <= 2100 ? date.toISOString() : "";
    }

    function decodeFiletime(bytes, be) {
      if (!bytes || bytes.length < 8) {
        return "";
      }
      const value = readUintFirst(bytes, 8, be);
      if (value === 0n) {
        return "";
      }
      const unixMs = Number((value - 116444736000000000n) / 10000n);
      const date = new Date(unixMs);
      const year = date.getUTCFullYear();
      return Number.isFinite(date.getTime()) && year >= 1700 && year <= 2200 ? date.toISOString() : "";
    }

    function displayOffset(value) {
      const offset = Number(value) || 0;
      if ($("offsetBase").value === "decimal") {
        return String(offset);
      }
      return "0x" + offset.toString(16).toUpperCase().padStart(8, "0");
    }

    function offsetValue() {
      const raw = String($("hexOffset").value || "0").trim();
      const value = raw.toLowerCase().startsWith("0x") ? Number.parseInt(raw, 16) : Number(raw);
      return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
    }

    function decodeText(bytes) {
      if (!bytes || bytes.length === 0) {
        return "";
      }
      try {
        return new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(bytes));
      } catch (_) {
        return bytes.map((value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
      }
    }

    function artifactTimestampRows(raw) {
      return [
        ["Email Date", raw.email_date],
        ["Visit Time", raw.visit_time_utc],
        ["Last Visit", raw.last_visit_time_utc],
        ["First Used", raw.first_used_utc],
        ["Last Used", raw.last_used_utc || raw.date_last_used_utc || raw.time_last_used_utc],
        ["Added", raw.date_added_utc],
        ["Started", raw.start_time_utc],
        ["Ended", raw.end_time_utc],
        ["Account Created", raw.date_created_utc || raw.time_created_utc],
        ["Password Changed", raw.time_password_changed_utc],
        ["Cookie Created", raw.creation_utc],
        ["Last Access", raw.last_access_utc || raw.last_accessed_utc],
        ["Expires", raw.expires_utc || raw.expiry_utc],
        ["Registry Last Write", raw.registry_key_last_write_utc],
        ["Event Logged", raw.evtx_logged_utc],
        ["Cache Created", raw.artifact_kind === "browser_cache_entry" ? raw.created_utc : ""]
      ];
    }

    function sourceFileTimesSection(raw) {
      const basis = raw.source_file_time_basis || "";
      const path = raw.source_artifact_path_exact || raw.source_artifact_path;
      const hasSource = path || raw.source_file_created_utc || raw.source_file_modified_utc || raw.source_file_accessed_utc;
      if (!hasSource) return "";
      let title = "Source File Times";
      let basisLabel = "Basis not recorded";
      if (basis === "original_evidence_filesystem") {
        title = "Original Source File MACB";
        basisLabel = "Indexed source filesystem metadata";
      } else if (basis === "local_source_filesystem") {
        title = "Imported Local Source File Times";
        basisLabel = "Local filesystem metadata captured at import";
      } else if (basis === "original_evidence_path_resolved_times_unavailable") {
        title = "Original Source File";
        basisLabel = "Source path resolved; filesystem times unavailable";
      }
      return detailSection(title, [
        ["Path", path],
        ["Source Entry ID", raw.source_entry_id],
        ["Timestamp Basis", basisLabel],
        ["Created", raw.source_file_created_utc],
        ["Modified", raw.source_file_modified_utc],
        ["Accessed", raw.source_file_accessed_utc],
        ["MFT Modified", raw.source_file_mft_modified_utc],
        ["SHA-256", raw.source_file_sha256],
        ["Size", raw.source_file_size_bytes == null ? "" : formatBytes(raw.source_file_size_bytes)]
      ]);
    }

    function stagingCopyTimesSection(raw) {
      const hasStaging = raw.source_artifact_staging_path || raw.staging_file_created_utc || raw.staging_file_modified_utc || raw.staging_file_accessed_utc;
      if (!hasStaging) return "";
      return detailSection("Staging Copy Times (not evidence MACB)", [
        ["Path", raw.source_artifact_staging_path],
        ["Created", raw.staging_file_created_utc],
        ["Modified", raw.staging_file_modified_utc],
        ["Accessed", raw.staging_file_accessed_utc],
        ["Size", raw.staging_file_size_bytes == null ? "" : formatBytes(raw.staging_file_size_bytes)]
      ]);
    }

    function metadataView(entry) {
      const metadata = JSON.stringify(entry.metadata_json || {}, null, 2);
      const raw = entry.metadata_json || {};
      const evidence = evidenceSourceForEntry(entry);
      return [
        inspectorSummary(entry),
        previewSection(entry),
        detailSection("Overview", [
          ["ID", entry.id],
          ["Evidence", evidence ? evidence.display_name + " (#" + evidence.id + ")" : entry.evidence_id],
          ["Path", entry.logical_path],
          ["Relative Path", relativePathForEntry(entry)],
          ["Name", entry.name],
          ["Kind", entry.entry_kind],
          ["Size", entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)],
          ["Deleted", entry.is_deleted ? "yes" : "no"],
          ["Category", entryCategoryLabel(entry)],
          ["Category Detail", entryCategoryDetail(entry)]
        ]),
        detailSection("Forensic Location", [
          ["Storage Area", raw.storage_area],
          ["Recovery Source", raw.recovery_source],
          ["Recovery Status", raw.recovery_status],
          ["Logical Offset", formatOffsetValue(raw.logical_offset || raw.finding_logical_offset || raw.start_offset)],
          ["Physical Offset", formatOffsetValue(raw.physical_offset)],
          ["MFT Record Logical Offset", formatOffsetValue(raw.mft_record_logical_offset)],
          ["MFT Record Physical Offset", formatOffsetValue(raw.mft_record_physical_offset)],
          ["File Data Logical Offset", formatOffsetValue(raw.file_data_logical_offset)],
          ["File Data Physical Offset", formatOffsetValue(raw.file_data_physical_offset)],
          ["Partition Start", formatOffsetValue(raw.partition_start_offset || raw.start_offset)],
          ["Partition Size", formatByteCountValue(raw.partition_size_bytes || raw.size_bytes)],
          ["In File Slack", raw.is_file_slack ? "yes" : ""],
          ["In Unallocated Space", raw.is_unallocated ? "yes" : ""]
        ]),
        detailSection("Category", [
          ["Main", raw.category_main],
          ["Subcategory", raw.category_sub],
          ["Detail", raw.category_detail],
          ["Analysis", raw.analysis_category],
          ["Confidence", raw.category_confidence],
          ["Rule Source", raw.category_source],
          ["Tags", Array.isArray(raw.category_tags) ? raw.category_tags.join(", ") : raw.category_tags]
        ]),
        detailSection("Type Verification", [
          ["Status", raw.signature_status],
          ["Extension", raw.file_extension],
          ["Expected Type", raw.expected_signature],
          ["Detected Type", raw.detected_signature],
          ["Description", raw.signature_description],
          ["Category", raw.signature_category],
          ["Detection Basis", raw.signature_detection_basis],
          ["Mismatch Basis", raw.signature_mismatch_basis],
          ["Reason", raw.signature_reason],
          ["Analyzer", raw.signature_analysis]
        ]),
        recordDetails(entry),
        detailSection("Artifact Timestamps", artifactTimestampRows(raw)),
        detailSection("File-system MACB", [
          ["Created", filesystemCreatedTime(entry)],
          ["Modified", filesystemModifiedTime(entry)],
          ["Accessed", filesystemAccessedTime(entry)],
          ["MFT Modified", filesystemMftModifiedTime(entry)]
        ]),
        sourceFileTimesSection(raw),
        stagingCopyTimesSection(raw),
        detailSection("Parser And Source", [
          ["Artifact Kind", raw.artifact_kind],
          ["Filesystem Parser", raw.filesystem_parser],
          ["Filesystem", raw.filesystem],
          ["Partition Start", formatOffsetValue(raw.partition_start_offset || raw.start_offset)],
          ["Partition Size", formatByteCountValue(raw.partition_size_bytes || raw.size_bytes)],
          ["MFT Record", raw.mft_file_record_number || raw.ntfs_file_record_number],
          ["MFT Sequence", raw.mft_sequence_number],
          ["NTFS Path", raw.ntfs_path],
          ["FAT Path", raw.fat_path],
          ["Source Artifact", raw.source_artifact],
          ["Source Path", raw.source_artifact_path_exact || raw.source_artifact_path || raw.source_path],
          ["Source Profile", raw.source_profile_path_exact],
          ["Derived From Evidence", raw.source_evidence_id]
        ]),
        `<section class="metadata-section"><details><summary>Metadata JSON</summary><pre>${escapeHtml(metadata)}</pre></details></section>`
      ].filter(Boolean).join("");
    }

    function previewSection(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "email_message") {
        return emailPreviewSection(entry, metadata);
      }
      if (metadata.artifact_kind === "browser_history_visit" || metadata.artifact_kind === "browser_bookmark" || metadata.artifact_kind === "browser_preference") {
        return browserPreviewSection(entry, metadata);
      }
      if (entry.entry_kind === "record") {
        return genericRecordPreviewSection(entry, metadata);
      }
      if (isImageEntry(entry)) {
        return imagePreviewSection(entry);
      }
      return "";
    }

    function imagePreviewSection(entry) {
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card image-preview">
        <img loading="lazy" src="${escapeAttr(entryRawUrl(entry))}" alt="" onerror="this.parentElement.classList.add('thumb-broken'); this.remove();">
      </div></section>`;
    }

    function emailPreviewSection(entry, metadata) {
      const title = firstText(metadata.email_subject, entry.name, logicalName(entry.logical_path));
      const metaRows = [
        metadata.email_from ? "From: " + metadata.email_from : "",
        metadata.email_to ? "To: " + metadata.email_to : "",
        metadata.email_date ? "Date: " + metadata.email_date : "",
        metadata.email_message_id ? "Message ID: " + metadata.email_message_id : ""
      ].filter(Boolean).map((value) => `<span>${escapeHtml(value)}</span>`).join("");
      const body = firstText(metadata.email_body_preview, metadata.email_parser_error, "No message body preview.");
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card">
        <h4 class="preview-title">${escapeHtml(title)}</h4>
        <div class="preview-meta">${metaRows || `<span>${escapeHtml(emailPreview(entry) || "Parsed email message")}</span>`}</div>
        <div class="preview-body">${escapeHtml(body)}</div>
      </div></section>`;
    }

    function browserPreviewSection(entry, metadata) {
      const title = firstText(metadata.title, metadata.name, metadata.category, entry.name, logicalName(entry.logical_path));
      const url = firstText(metadata.url, metadata.homepage);
      const metaRows = [
        metadata.visit_time_utc ? "Visited: " + metadata.visit_time_utc : "",
        metadata.date_added_utc ? "Added: " + metadata.date_added_utc : "",
        metadata.folder ? "Folder: " + metadata.folder : "",
        (metadata.source_artifact_path_exact || metadata.source_artifact_path) ? "Source: " + (metadata.source_artifact_path_exact || metadata.source_artifact_path) : ""
      ].filter(Boolean).map((value) => `<span>${escapeHtml(value)}</span>`).join("");
      const body = firstText(browserActivityPreview(entry), compactJson(metadata));
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card">
        <h4 class="preview-title">${escapeHtml(title)}</h4>
        ${url ? `<div class="preview-url">${escapeHtml(url)}</div>` : ""}
        <div class="preview-meta">${metaRows}</div>
        <div class="preview-body">${escapeHtml(body)}</div>
      </div></section>`;
    }

    function genericRecordPreviewSection(entry, metadata) {
      const body = firstText(entrySummary(entry), compactJson(metadata));
      return `<section class="metadata-section"><h3>Preview</h3><div class="preview-card">
        <h4 class="preview-title">${escapeHtml(entry.name || logicalName(entry.logical_path))}</h4>
        <div class="preview-meta"><span>${escapeHtml(entry.logical_path)}</span></div>
        <div class="preview-body">${escapeHtml(body)}</div>
      </div></section>`;
    }

    function inspectorSummary(entry) {
      const raw = entry.metadata_json || {};
      const evidence = evidenceSourceForEntry(entry);
      const synthetic = entry.id == null;
      const canAnalyze = entry.entry_kind === "file" && isPromotableDiskImageEntry(entry, evidence);
      const canViewBytes = entry.entry_kind === "file" && !synthetic;
      const badges = [
        inspectorBadge(entry.entry_kind),
        entry.size_bytes == null ? "" : inspectorBadge(formatBytes(entry.size_bytes)),
        entry.is_deleted ? inspectorBadge("deleted", "bad") : "",
        raw.is_file_slack ? inspectorBadge("file slack", "warn") : "",
        raw.is_unallocated ? inspectorBadge("unallocated", "warn") : "",
        raw.signature_status ? inspectorBadge(
          "signature: " + raw.signature_status,
          raw.signature_status === "mismatch" ? "bad" : (raw.signature_status === "unknown" ? "warn" : "")
        ) : "",
        raw.filesystem_parser ? inspectorBadge("parser: " + raw.filesystem_parser) : "",
        raw.category_confidence ? inspectorBadge("confidence: " + raw.category_confidence) : ""
      ].filter(Boolean).join("");
      const actions = [
        canViewBytes ? `<button class="secondary" onclick="openEntry(${entry.id})">View bytes</button>` : "",
        canOpenEntryExternally(entry) ? `<button class="ghost" onclick="openSelectedEntryExternal(${entry.id})">Open file</button>` : "",
        canAnalyze ? `<button class="secondary" onclick="analyzeDiskImageEntry(${entry.id})">Analyze image</button>` : "",
        entry.entry_kind === "file" && !synthetic ? `<button class="ghost" onclick="recoverEntry(${entry.id})">${escapeHtml(recoveryActionText(entry).button)}</button>` : "",
        !synthetic ? `<button class="ghost" onclick="bookmarkEntry(${entry.id})">Bookmark</button>` : ""
      ].filter(Boolean).join("");
      return `
        <section class="inspector-summary">
          <h2 class="inspector-title">${escapeHtml(entry.name || logicalName(entry.logical_path))}</h2>
          <div class="inspector-path">${escapeHtml(entry.logical_path)}</div>
          <div class="inspector-badges">${badges}</div>
          <div class="inspector-actions">${actions}</div>
        </section>`;
    }

    function inspectorBadge(text, tone = "") {
      return `<span class="pill ${tone ? escapeAttr(tone) : ""}">${escapeHtml(text)}</span>`;
    }

    function relativePathForEntry(entry) {
      const raw = entry.metadata_json || {};
      return firstText(raw.relative_path, raw.ntfs_path, raw.fat_path, entry.logical_path);
    }

    function formatOffsetValue(value) {
      if (value === undefined || value === null || String(value).length === 0) {
        return "";
      }
      const text = String(value);
      const number = typeof value === "number" ? value : (/^\d+$/.test(text) ? Number(text) : NaN);
      if (!Number.isFinite(number)) {
        return text;
      }
      return text + " (0x" + Math.trunc(number).toString(16).toUpperCase() + ")";
    }

    function formatByteCountValue(value) {
      if (value === undefined || value === null || String(value).length === 0) {
        return "";
      }
      const text = String(value);
      const number = typeof value === "number" ? value : (/^\d+$/.test(text) ? Number(text) : NaN);
      if (!Number.isFinite(number)) {
        return text;
      }
      return formatBytes(number) + " (" + text + " bytes)";
    }

    function recordDetails(entry) {
      const metadata = entry.metadata_json || {};
      if (metadata.artifact_kind === "email_message") {
        return detailSection("Email", [
          ["Format", metadata.email_format],
          ["Parser", metadata.email_parser || metadata.email_parser_status],
          ["From", metadata.email_from],
          ["To", metadata.email_to],
          ["Cc", metadata.email_cc],
          ["Bcc", metadata.email_bcc],
          ["Subject", metadata.email_subject],
          ["Date", metadata.email_date],
          ["Message ID", metadata.email_message_id],
          ["Reply-To", metadata.email_reply_to],
          ["In Reply To", metadata.email_in_reply_to],
          ["Body Preview", metadata.email_body_preview],
          ["Attachment Names", arrayText(metadata.email_attachment_names)],
          ["PST Folder", metadata.pst_folder_path],
          ["PST Parser Scope", metadata.pst_parser_scope],
          ["PST Attachment Content", metadata.pst_attachment_content_extraction],
          ["PST Deleted Recovery", metadata.pst_deleted_recovery],
          ["Parser Error", metadata.email_parser_error]
        ]);
      }
      if (metadata.artifact_kind === "email_store") {
        return detailSection("Email Store", [
          ["Format", metadata.email_format],
          ["Parser Status", metadata.email_parser_status],
          ["Path", entry.logical_path],
          ["Size", entry.size_bytes == null ? "" : formatBytes(entry.size_bytes)]
        ]);
      }
      if (metadata.artifact_kind === "browser_history_visit") {
        return detailSection("Browser Activity", [
          ["Activity", "Visit"],
          ["URL", metadata.url],
          ["Title", metadata.title],
          ["Host", metadata.host],
          ["Visit Time", metadata.visit_time_utc],
          ["Last URL Visit", metadata.last_visit_time_utc],
          ["Transition", metadata.transition_type],
          ["Visit Count", metadata.visit_count],
          ["Typed Count", metadata.typed_count],
          ["Duration", metadata.visit_duration_microseconds ? metadata.visit_duration_microseconds + " microseconds" : ""],
          ["Visit ID", metadata.visit_id],
          ["URL ID", metadata.url_id],
          ["Chrome Visit Time", metadata.visit_time_chrome],
          ["Chrome Last URL Visit", metadata.last_visit_time_chrome],
          ["Transition Code", metadata.transition],
          ["Hidden", metadata.hidden],
          ["Source Artifact", metadata.source_artifact],
          ["Source Path", metadata.source_artifact_path_exact || metadata.source_artifact_path]
        ]);
      }
      if (metadata.artifact_kind === "browser_bookmark") {
        return detailSection("Browser Activity", [
          ["Activity", "Bookmark"],
          ["URL", metadata.url],
          ["Name", metadata.name],
          ["Host", metadata.host],
          ["Folder", metadata.folder],
          ["Added", metadata.date_added_utc],
          ["Last Used", metadata.date_last_used_utc],
          ["Chrome Added", metadata.date_added_chrome],
          ["Chrome Last Used", metadata.date_last_used_chrome],
          ["GUID", metadata.guid],
          ["Source Artifact", metadata.source_artifact],
          ["Source Path", metadata.source_artifact_path_exact || metadata.source_artifact_path]
        ]);
      }
      if (metadata.artifact_kind === "browser_preference") {
        return detailSection("Browser Activity", [
          ["Activity", "Preference"],
          ["Category", metadata.category],
          ["Profile Name", metadata.name],
          ["Startup URLs", Array.isArray(metadata.startup_urls) ? metadata.startup_urls.join(", ") : ""],
          ["Homepage", metadata.homepage],
          ["Download Directory", metadata.download_default_directory],
          ["Extensions", metadata.extension_count],
          ["Created By Version", metadata.created_by_version],
          ["Last Used", metadata.last_used],
          ["Restore On Startup", metadata.restore_on_startup],
          ["Homepage Is New Tab", metadata.homepage_is_newtabpage],
          ["Prompt For Download", metadata.prompt_for_download],
          ["Source Artifact", metadata.source_artifact],
          ["Source Path", metadata.source_artifact_path_exact || metadata.source_artifact_path]
        ]);
      }
      return "";
    }

    function detailSection(title, rows) {
      const body = detailRows(rows);
      return body ? `<section class="metadata-section"><h3>${escapeHtml(title)}</h3><dl class="metadata-grid">${body}</dl></section>` : "";
    }

    function detailRows(rows) {
      return rows
        .filter((row) => row[1] !== undefined && row[1] !== null && String(row[1]).length > 0)
        .map((row) => `<dt>${escapeHtml(row[0])}</dt><dd>${escapeHtml(row[1])}</dd>`)
        .join("");
    }

    function renderSearchEvidence() {
      const current = $("searchEvidence").value;
      $("searchEvidence").innerHTML = '<option value="">All evidence</option>' + state.data.evidence.map((item) =>
        `<option value="${item.id}">${escapeHtml(item.id + " - " + item.display_name)}</option>`
      ).join("");
      $("searchEvidence").value = current;
    }

    // Bitwise hits from the unified search's "All" mode. The backend provides
    // authoritative sector size and partition containment.
    function rawSearchResultColumns() {
      const columns = [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" }
      ];
      if (state.rawSearchResult && state.rawSearchResult.multiSource) {
        columns.push({ key: "evidence", label: "Evidence", sortable: true, filterable: true, sortType: "text" });
      }
      columns.push(
        { key: "offset", label: "Offset", sortable: true, filterable: true, sortType: "number" },
        { key: "sector", label: "Sector (512B)", sortable: true, filterable: true, sortType: "number" },
        { key: "partition", label: "Partition", sortable: true, filterable: true, sortType: "text" },
        { key: "region", label: "Region", sortable: true, filterable: true, sortType: "text" },
        { key: "encoding", label: "Encoding", sortable: true, filterable: true, sortType: "text" },
        { key: "length", label: "Length", sortable: true, filterable: true, sortType: "number" },
        { key: "preview", label: "Hex", sortable: false, filterable: true, sortType: "text" },
        { key: "ascii", label: "ASCII", sortable: false, filterable: true, sortType: "text" }
      );
      return columns;
    }

    function rawSearchHitKey(hit) {
      return JSON.stringify([
        hit.evidence_id,
        Number(hit.offset) || 0,
        Number(hit.length) || 0,
        hit.encoding || "",
        hit.data_preview || ""
      ]);
    }

    function rawSearchGridRow(hit, hitIndex) {
      const offset = Number(hit.offset) || 0;
      // The backend now reports the authoritative sector; keep the local
      // computation only as a fallback for older results.
      const sector = hit.sector != null ? Number(hit.sector) : Math.floor(offset / 512);
      const partition = hit.volume_name || (hit.partition_index != null ? "#" + hit.partition_index : "");
      const partitionTitle = [
        hit.volume_name ? "Volume: " + hit.volume_name : "",
        hit.filesystem ? "Filesystem: " + hit.filesystem : "",
        hit.partition_start_offset != null ? "Partition start: " + Number(hit.partition_start_offset).toLocaleString() : ""
      ].filter(Boolean).join(" | ");
      return {
        hit,
        hitIndex,
        key: rawSearchHitKey(hit),
        partitionTitle,
        values: {
          select: "",
          evidence: hit.evidence_name || (hit.evidence_id != null ? String(hit.evidence_id) : ""),
          offset: offset.toLocaleString() + " (0x" + offset.toString(16).toUpperCase() + ")",
          sector: sector.toLocaleString(),
          partition: partition,
          region: hit.region || "",
          encoding: hit.encoding,
          length: String(hit.length),
          preview: hit.data_preview,
          ascii: hit.ascii_preview || "",
          actions: ""
        },
        sortValues: {
          offset,
          sector,
          length: Number(hit.length) || 0
        }
      };
    }

    function visibleRawSearchResultRows() {
      const result = state.rawSearchResult;
      const rows = result && Array.isArray(result.hits)
        ? result.hits.map(rawSearchGridRow)
        : [];
      return visibleGridRows("rawSearch", rawSearchResultColumns(), rows);
    }

    function selectedVisibleRawSearchResultRows() {
      const selected = state.selectedRawSearchKeys || new Set();
      return visibleRawSearchResultRows().filter((row) => selected.has(row.key));
    }

    function selectedRawSearchResultRows() {
      const result = state.rawSearchResult;
      const selected = state.selectedRawSearchKeys || new Set();
      const rows = result && Array.isArray(result.hits)
        ? result.hits.map(rawSearchGridRow)
        : [];
      return rows.filter((row) => selected.has(row.key));
    }

    function toggleRawSearchHitSelection(hitIndex, selected, event = null) {
      const result = state.rawSearchResult;
      const hit = result && result.hits ? result.hits[hitIndex] : null;
      if (!hit) {
        renderSearchSelectionCount();
        return;
      }
      const key = rawSearchHitKey(hit);
      const visible = visibleRawSearchResultRows();
      if (event && event.shiftKey && state.lastRawSearchKey) {
        const anchor = visible.findIndex((row) => row.key === state.lastRawSearchKey);
        const target = visible.findIndex((row) => row.key === key);
        if (anchor >= 0 && target >= 0) {
          const from = Math.min(anchor, target);
          const to = Math.max(anchor, target);
          visible.slice(from, to + 1).forEach((row) => {
            if (selected) {
              state.selectedRawSearchKeys.add(row.key);
            } else {
              state.selectedRawSearchKeys.delete(row.key);
            }
          });
        }
      } else if (selected) {
        state.selectedRawSearchKeys.add(key);
      } else {
        state.selectedRawSearchKeys.delete(key);
      }
      state.lastRawSearchKey = key;
      renderRawSearchResults();
      persistDeepSearchSession();
    }

    function handleRawSearchHitRowClick(event, hitIndex) {
      if (event.target.closest("button, input, a")) {
        return;
      }
      const result = state.rawSearchResult;
      const hit = result && result.hits ? result.hits[hitIndex] : null;
      if (!hit) {
        return;
      }
      const key = rawSearchHitKey(hit);
      if (!event.ctrlKey && !event.metaKey && !event.shiftKey) {
        state.selectedRawSearchKeys = new Set([key]);
        state.lastRawSearchKey = key;
        renderRawSearchResults();
        persistDeepSearchSession();
        return;
      }
      toggleRawSearchHitSelection(hitIndex, !state.selectedRawSearchKeys.has(key), event);
    }

    function renderRawSearchGridRow(row) {
      const multi = state.rawSearchResult && state.rawSearchResult.multiSource;
      const checked = (state.selectedRawSearchKeys || new Set()).has(row.key) ? " checked" : "";
      const evidenceCell = multi
        ? `<td title="${escapeAttr(row.values.evidence)}">${escapeHtml(row.values.evidence)}</td>`
        : "";
      // Offset and both previews are clickable: they open the whole-device hex
      // viewer positioned on these exact bytes, with the hit pre-selected, so
      // the examiner can widen the selection and bookmark it manually from the
      // full hex/ASCII view (this is the "bigger preview" affordance).
      const openTitle = "Open this offset in the hex/ASCII viewer (hit bytes pre-selected; drag to extend, then Bookmark selection)";
      return `
      <tr data-raw-hit-index="${row.hitIndex}" onclick="handleRawSearchHitRowClick(event, ${row.hitIndex})">
        <td><input type="checkbox"${checked} aria-label="Select raw hit at ${escapeAttr(row.values.offset)}" onclick="event.stopPropagation(); toggleRawSearchHitSelection(${row.hitIndex}, this.checked, event)"></td>
        ${evidenceCell}
        <td class="entry-offset"><button class="offset-link" title="${escapeAttr(openTitle)}" onclick="event.stopPropagation(); openRawHitInHex(${row.hitIndex})">${escapeHtml(row.values.offset)}</button></td>
        <td>${escapeHtml(row.values.sector)}</td>
        <td title="${escapeAttr(row.partitionTitle || row.values.partition)}">${escapeHtml(row.values.partition)}</td>
        <td class="tiny" title="${escapeAttr(row.values.region)}">${escapeHtml(row.values.region)}</td>
        <td>${escapeHtml(row.values.encoding)}</td>
        <td>${escapeHtml(row.values.length)}</td>
        <td class="mono tiny offset-link-cell" title="${escapeAttr(openTitle)}" onclick="event.stopPropagation(); openRawHitInHex(${row.hitIndex})">${escapeHtml(row.values.preview)}</td>
        <td class="mono tiny offset-link-cell" title="${escapeAttr(openTitle)}" onclick="event.stopPropagation(); openRawHitInHex(${row.hitIndex})">${escapeHtml(row.values.ascii)}</td>
      </tr>`;
    }

    // Opens the whole-device raw hex viewer at a hit's absolute disk offset and
    // pre-selects the hit bytes, so a bitwise-search offset is a click-through
    // to the exact location in hex/ASCII. Selection offsets are absolute and the
    // whole-device container base is 0, so a bookmark of the (possibly widened)
    // selection records the correct absolute decoded-media offset.
    async function openRawHitInHex(hitIndex) {
      const result = state.rawSearchResult;
      const hit = result && result.hits ? result.hits[hitIndex] : null;
      if (!hit) {
        setNotice("This bitwise hit is no longer loaded - re-run the search.", true);
        return;
      }
      const evidenceId = hit.evidence_id;
      const evidence = state.data && state.data.evidence.find((item) => item.id === evidenceId);
      if (evidence && evidence.source_kind !== "image" && evidence.source_kind !== "file") {
        setNotice("Only image/file evidence has a raw byte stream to open in hex.", true);
        return;
      }
      const prov = (result.provenance || {})[evidenceId] || {};
      const offset = Number(hit.offset) || 0;
      const length = Math.max(1, Number(hit.length) || 1);
      const bpr = numberValue("bytesPerRow", 16);
      // Land a little before the hit so it has visible context, aligned to the
      // row width so columns line up.
      let viewStart = Math.max(0, offset - 128);
      viewStart -= viewStart % bpr;
      const viewLength = Math.max(numberValue("hexLength", 512), (offset - viewStart) + length + 128);
      const name = (prov.evidence_display_name || (evidence && evidence.display_name) || "evidence");
      state.hex = makeHexState(null, viewStart, viewLength);
      state.hex.raw = {
        evidenceId: evidenceId,
        name: name + " @ " + offset,
        logicalPath: "[raw] " + name + " whole-disk @ offset " + offset,
        startOffset: 0,
        volume: null,
        sizeBytes: prov.total_size != null ? Number(prov.total_size) : (evidence && evidence.size_bytes != null ? evidence.size_bytes : null)
      };
      $("viewerMode").value = "hex";
      // Save the expensive search before leaving its view. Returning through
      // the app tabs or browser history can then restore it without rescanning.
      persistDeepSearchSession();
      switchView("analyzeView");
      try {
        await fetchEntryBytes();
      } catch (err) {
        setNotice("Could not read bytes at offset " + offset + ": " + (err.message || err), true);
        return;
      }
      // Pre-select the hit bytes (absolute offsets) - same mechanism the raw
      // find uses - so the examiner can immediately see and extend the match.
      state.hex.selStart = offset;
      state.hex.selEnd = offset + length - 1;
      renderHexViewer();
      setInspectorCollapsed(false);
      setNotice("Opened " + name + " at disk offset " + offset.toLocaleString() + " (0x" + offset.toString(16).toUpperCase() + "). Hit bytes are selected - drag to extend, then use Bookmark selection.");
    }

    function renderRawSearchResults() {
      const container = $("rawSearchResults");
      const count = $("rawSearchCount");
      const status = $("rawSearchStatus");
      if (!container || !count) {
        return;
      }
      renderSearchSelectionCount();
      const result = state.rawSearchResult;
      const loadMore = $("loadMoreRawSearchResults");
      if (loadMore) {
        const hasMore = Boolean(result && (result.sources || []).some((source) => source.next_cursor));
        loadMore.hidden = !hasMore;
        loadMore.disabled = Boolean(state.rawSearchRunning);
        loadMore.textContent = state.rawSearchRunning ? "Loading..." : "Load more bitwise hits";
      }
      if (!result) {
        count.textContent = "0";
        if (status) {
          status.textContent = state.rawSearchRunning ? "Scanning evidence bytes..." : "";
        }
        container.innerHTML = state.rawSearchRunning
          ? empty("Bitwise whole-disk scan running - reading real evidence bytes; a large scan limit can take a while...")
          : empty("Run a search in \"All\" mode to scan evidence byte-for-byte.");
        return;
      }
      const sources = result.sources || [];
      const errored = sources.filter((source) => source.error);
      if (status) {
        const sourceText = sources.length
          ? " across " + sources.length + " source" + (sources.length === 1 ? "" : "s")
          : "";
        status.textContent = formatBytes(result.bytes_scanned) + " scanned" + sourceText +
          bitwiseStopReasonNote(result) +
          (errored.length ? "; " + errored.length + " errored" : "");
      }
      const columns = rawSearchResultColumns();
      const rows = (result.hits || []).map(rawSearchGridRow);
      const tableResult = sortableGridTable("rawSearch", columns, rows, "raw-search-table", renderRawSearchGridRow);
      count.textContent = tableResult.visibleRows.length.toLocaleString();
      const filterStatus = gridFilterStatusHtml("rawSearch", columns, tableResult.visibleRows.length, rows.length, "hits");
      // Surface sources without an acquisition hash so offset findings are not
      // mistaken for fully identified evidence.
      const unhashed = sources.filter((source) => !source.error && !source.evidence_sha256_hex);
      const hashWarning = rows.length && unhashed.length
        ? `<div class="analysis-status" style="color:var(--warn, #b58900)">Evidence not yet hashed: ${escapeHtml(unhashed.map((source) => source.name || String(source.evidence_id)).join(", "))}. Compute the evidence SHA-256 (Evidence tab &gt; Hash) before relying on these offsets; bookmarked hits carry this warning into the report.</div>`
        : "";
      const attributions = Array.from(new Set(sources
        .filter((source) => source.coverage && source.coverage.hit_attribution)
        .map((source) => source.coverage.hit_attribution)));
      const rawCoverageNote = attributions.length
        ? `<div class="analysis-status">Raw coverage: ${escapeHtml(attributions.join(" | "))}. Folder evidence has no single raw byte stream and is not silently treated as scanned.</div>`
        : "";
      const errorNote = errored.length
        ? empty("Could not scan: " + errored.map((source) => (source.name || source.evidence_id) + " (" + source.error + ")").join("; "))
        : "";
      const emptyNote = sources.length === 0
        ? empty("No image or file evidence to scan byte-for-byte. Attach a disk image or file source.")
        : empty("No bitwise hits found in the scanned range" + bitwiseStopReasonNote(result) + ".");
      container.innerHTML = rows.length
        ? rawCoverageNote + hashWarning + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No hits match the column filters.")) + errorNote
        : rawCoverageNote + emptyNote + errorNote;
    }

    // Build item_ref_json for one whole-disk bitwise hit. Scan provenance
    // supplies evidence identity, hash, parameters, and partition containment.
    function rawSearchHitItemRef(hit, prov) {
      const offset = Number(hit.offset) || 0;
      const length = Number(hit.length) || 0;
      return {
        kind: "highlighted_bytes",
        source: "raw_image_whole_disk_scan",
        evidence_id: prov.evidence_id,
        entry_id: null,
        logical_path: "raw image whole-disk scan",
        relative_path: prov.source_path,
        display_name: (prov.evidence_display_name || prov.source_path || "evidence") + " @ offset " + offset,
        evidence_source: prov.evidence_display_name || prov.source_path || "",
        source_path: prov.source_path,
        evidence_sha256_hex: prov.evidence_sha256_hex || null,
        evidence_hashed_at: prov.evidence_hashed_at || null,
        selection_logical_offset_start: offset,
        selection_logical_offset_end: offset + Math.max(length, 1) - 1,
        selection_physical_offset_start: offset,
        selection_physical_offset_end: offset + Math.max(length, 1) - 1,
        selection_length_bytes: length,
        physical_offset_basis: "decoded-media byte offset (within the decoded image stream, not the container/segment file); whole-image scan from offset 0 - exact, not fragment-approximate",
        sector: hit.sector != null ? Number(hit.sector) : Math.floor(offset / 512),
        sector_size: prov.sector_size != null ? Number(prov.sector_size) : 512,
        partition_index: hit.partition_index == null ? null : hit.partition_index,
        volume_name: hit.volume_name || null,
        partition_start_offset: hit.partition_start_offset == null ? null : hit.partition_start_offset,
        filesystem: hit.filesystem || null,
        region: hit.region || "",
        encoding: hit.encoding,
        hex_preview: hit.data_preview,
        ascii_preview: hit.ascii_preview || "",
        query: prov.query,
        encodings: prov.encodings || [],
        scan_start: prov.scan_start != null ? Number(prov.scan_start) : 0,
        max_scan_bytes: prov.max_scan_bytes,
        max_results: prov.max_results,
        bytes_scanned: prov.bytes_scanned,
        total_size: prov.total_size,
        truncated: Boolean(prov.truncated),
        complete: Boolean(prov.complete),
        stop_reason: prov.stop_reason || null,
        continuation_available: Boolean(prov.next_cursor),
        coverage: prov.coverage || null,
        searched_at: prov.searched_at,
        actor: prov.actor
      };
    }

    async function bookmarkRawSearchHitRecord(hit, result, refreshAfter = true, casePath = currentCasePath()) {
      if (!hit || !result) {
        throw new Error("This bitwise hit is no longer loaded - re-run the search.");
      }
      const prov = hit.search_provenance || (result.provenance || {})[hit.evidence_id];
      if (!prov) {
        throw new Error("No scan provenance is loaded for this hit's evidence - re-run the search.");
      }
      const itemRef = rawSearchHitItemRef(hit, prov);
      const offsetLabel = Number(hit.offset).toLocaleString() + " (0x" + Number(hit.offset).toString(16).toUpperCase() + ")";
      const hashNote = prov.evidence_sha256_hex
        ? ""
        : " WARNING: evidence had no acquisition SHA-256 at search time - hash the evidence before relying on this offset in court.";
      await apiPost("/api/bookmark/quick", {
        case_path: casePath,
        folder_name: "Raw Search Hits",
        title: "Raw hit: " + (prov.evidence_display_name || "evidence " + hit.evidence_id) + " @ " + offsetLabel,
        comment: "Whole-disk bitwise hit for query \"" + (prov.query || result.query || "") + "\" (" + hit.encoding + ") at byte offset " + offsetLabel + ", sector " + itemRef.sector + ", " + (itemRef.region || "unclassified region") + "." + hashNote,
        bookmark_type: "highlighted_data",
        data_type: "Highlighted Bytes",
        evidence_id: hit.evidence_id,
        entry_id: null,
        display_name: itemRef.display_name,
        logical_path: itemRef.logical_path,
        selection_offset: Number(hit.offset) || 0,
        selection_length: Number(hit.length) || 0,
        data_preview: hit.data_preview,
        item_ref_json: itemRef
      });
      if (refreshAfter) {
        await refresh();
        setNotice("Bookmarked bitwise hit at offset " + offsetLabel + " into \"Raw Search Hits\"." + hashNote, Boolean(hashNote));
      }
      return hashNote;
    }

    async function bookmarkRawSearchHit(hitIndex) {
      const result = state.rawSearchResult;
      const hit = result && result.hits ? result.hits[hitIndex] : null;
      try {
        await bookmarkRawSearchHitRecord(hit, result, true);
      } catch (err) {
        setNotice(err.message || String(err), true);
      }
    }

    function searchResultColumns() {
      return [
        { key: "select", label: "", sortable: false, filterable: false, sortType: "none" },
        { key: "entry", label: "Entry", sortable: true, filterable: true, sortType: "text" },
        { key: "match", label: "Match", sortable: true, filterable: true, sortType: "text" },
        { key: "host", label: "Host", sortable: true, filterable: true, sortType: "text" },
        { key: "referrer", label: "Referrer", sortable: true, filterable: true, sortType: "text" },
        { key: "time", label: "Time", sortable: true, filterable: true, sortType: "time" },
        { key: "offset", label: "Offset", sortable: true, filterable: true, sortType: "number" },
        { key: "preview", label: "Preview", sortable: true, filterable: true, sortType: "text" }
      ];
    }

    function gridColumns(gridId) {
      switch (gridId) {
        case "search": return searchResultColumns();
        case "rawSearch": return rawSearchResultColumns();
        case "category": return categoryGridColumns();
        case "folder": return folderGridColumns();
        case "bookmarks": return bookmarksGridColumns();
        case "email": return emailGridColumns();
        case "live": return liveGridColumns();
        case "indexed": return indexedGridColumns();
        case "evidence": return evidenceGridColumns();
        case "attached": return attachedEvidenceGridColumns();
        case "timeline": return timelineGridColumns();
        default: return [];
      }
    }

    function defaultGridViewState() {
      return { sort: { column: "", direction: "asc" }, filters: {} };
    }

    function gridViewState(gridId) {
      state.gridViews = state.gridViews || {};
      if (!state.gridViews[gridId]) {
        const view = defaultGridViewState();
        if (gridId === "search") {
          view.sort = state.searchSort || view.sort;
          view.filters = state.searchColumnFilters || {};
        }
        state.gridViews[gridId] = view;
      }
      if (gridId === "search") {
        state.searchSort = state.gridViews[gridId].sort;
        state.searchColumnFilters = state.gridViews[gridId].filters;
      }
      return state.gridViews[gridId];
    }

    function resetGridView(gridId) {
      state.gridViews = state.gridViews || {};
      state.gridViews[gridId] = defaultGridViewState();
      if (gridId === "search") {
        state.searchSort = state.gridViews[gridId].sort;
        state.searchColumnFilters = state.gridViews[gridId].filters;
      }
    }

    function gridColumnByKey(gridId, key) {
      return gridColumns(gridId).find((column) => column.key === key) || null;
    }

    function gridColumnFilterValue(gridId, key) {
      const view = gridViewState(gridId);
      return String((view.filters || {})[key] || "");
    }

    function gridColumnFiltersActive(gridId, columns = gridColumns(gridId)) {
      return columns.some((column) =>
        column.filterable && gridColumnFilterValue(gridId, column.key).trim().length > 0
      );
    }

    function activeGridFilters(gridId, columns) {
      return columns
        .filter((column) => column.filterable)
        .map((column) => ({
          key: column.key,
          text: gridColumnFilterValue(gridId, column.key).trim().toLowerCase()
        }))
        .filter((filter) => filter.text.length > 0);
    }

    function gridFilteredRows(gridId, columns, rows) {
      const activeFilters = activeGridFilters(gridId, columns);
      if (activeFilters.length === 0) {
        return rows;
      }
      return rows.filter((row) => activeFilters.every((filter) =>
        String((row.values || {})[filter.key] || "").toLowerCase().includes(filter.text)
      ));
    }

    function gridNumericValue(value) {
      if (value === undefined || value === null || String(value).length === 0) {
        return NaN;
      }
      if (typeof value === "number") {
        return Number.isFinite(value) ? value : NaN;
      }
      const text = String(value).trim();
      if (/^0x[0-9a-f]+$/i.test(text)) {
        return Number.parseInt(text.slice(2), 16);
      }
      if (/^\d+$/.test(text)) {
        return Number(text);
      }
      const match = text.match(/^\d+(?:\.\d+)?/);
      return match ? Number(match[0]) : NaN;
    }

    function gridSortValue(row, column) {
      const key = column.key;
      if (row.sortValues && Object.prototype.hasOwnProperty.call(row.sortValues, key)) {
        return row.sortValues[key];
      }
      const value = (row.values || {})[key];
      if (column.sortType === "number") {
        return gridNumericValue(value);
      }
      if (column.sortType === "time") {
        return Date.parse(value);
      }
      return value;
    }

    function gridSortValueMissing(row, column) {
      const value = gridSortValue(row, column);
      if (column.sortType === "number" || column.sortType === "time") {
        return !Number.isFinite(value);
      }
      return String(value || "").trim().length === 0;
    }

    function compareGridSortValues(left, right, column) {
      if (typeof column.compare === "function") {
        return column.compare(left, right);
      }
      if (column.sortType === "number" || column.sortType === "time") {
        return rowSortNumber(left, column) - rowSortNumber(right, column);
      }
      return String(gridSortValue(left, column) || "").localeCompare(
        String(gridSortValue(right, column) || ""),
        undefined,
        { sensitivity: "base", numeric: true }
      );
    }

    function rowSortNumber(row, column) {
      const value = gridSortValue(row, column);
      return Number.isFinite(value) ? value : 0;
    }

    function gridSortedRows(gridId, columns, rows) {
      const sort = gridViewState(gridId).sort || {};
      const column = sort.column ? columns.find((item) => item.key === sort.column) : null;
      if (!column || !column.sortable) {
        return rows;
      }
      const descending = sort.direction === "desc";
      return rows.slice().sort((left, right) => {
        const leftMissing = gridSortValueMissing(left, column);
        const rightMissing = gridSortValueMissing(right, column);
        if (leftMissing !== rightMissing) {
          return leftMissing ? 1 : -1;
        }
        const compared = compareGridSortValues(left, right, column);
        if (compared !== 0) {
          return descending ? -compared : compared;
        }
        return (left.index || 0) - (right.index || 0);
      });
    }

    function visibleGridRows(gridId, columns, rows) {
      const indexedRows = rows.map((row, index) => ({ index, ...row }));
      return gridSortedRows(gridId, columns, gridFilteredRows(gridId, columns, indexedRows));
    }

    function rerenderGrid(gridId) {
      if (gridId === "search") {
        renderSearchResults();
        return;
      }
      if (gridId === "rawSearch") {
        renderRawSearchResults();
        return;
      }
      if (gridId === "bookmarks") {
        renderBookmarks();
        return;
      }
      if (gridId === "evidence") {
        renderEvidence();
        return;
      }
      if (gridId === "timeline") {
        renderTimeline();
        return;
      }
      renderEvidenceBrowserEntries();
    }

    function toggleGridSort(gridId, columnKey) {
      const column = gridColumnByKey(gridId, columnKey);
      if (!column || !column.sortable) {
        return;
      }
      const view = gridViewState(gridId);
      const current = view.sort || {};
      view.sort = {
        column: columnKey,
        direction: current.column === columnKey && current.direction === "asc" ? "desc" : "asc"
      };
      if (gridId === "search") {
        state.searchSort = view.sort;
      }
      rerenderGrid(gridId);
    }

    function gridFilterInputId(gridId, columnKey) {
      return "gridFilter_" + gridId + "_" + columnKey;
    }

    function setGridColumnFilter(gridId, columnKey, value) {
      const view = gridViewState(gridId);
      view.filters = view.filters || {};
      if (String(value || "").trim()) {
        view.filters[columnKey] = value;
      } else {
        delete view.filters[columnKey];
      }
      if (gridId === "search") {
        state.searchColumnFilters = view.filters;
      }
      const reloadCompleteCategory = gridId === "category" && serverCategoryBrowseActive();
      rerenderGrid(gridId);
      if (reloadCompleteCategory) {
        scheduleServerCategoryReload();
      }
      const input = $(gridFilterInputId(gridId, columnKey));
      if (input) {
        input.focus();
        const position = input.value.length;
        input.setSelectionRange(position, position);
      }
    }

    function gridSortIndicator(gridId, column) {
      const sort = gridViewState(gridId).sort || {};
      if (sort.column !== column.key) {
        return "";
      }
      if (column.sortType === "number") {
        return sort.direction === "desc" ? "9-0" : "0-9";
      }
      if (column.sortType === "time") {
        return sort.direction === "desc" ? "New-Old" : "Old-New";
      }
      return sort.direction === "desc" ? "Z-A" : "A-Z";
    }

    function gridHeaderCell(gridId, column) {
      const columnClass = "grid-col-" + String(column.key || "column").replace(/[^A-Za-z0-9_-]/g, "-");
      if (!column.sortable && !column.filterable) {
        return `<th class="${escapeAttr(columnClass)}">${escapeHtml(column.label)}</th>`;
      }
      const indicator = gridSortIndicator(gridId, column);
      const active = indicator ? " active" : "";
      const grid = escapeAttr(escapeJs(gridId));
      const key = escapeAttr(escapeJs(column.key));
      const label = escapeHtml(column.label);
      const indicatorHtml = indicator ? `<span class="grid-sort-indicator">${escapeHtml(indicator)}</span>` : "";
      const filter = column.filterable
        ? `<input id="${escapeAttr(gridFilterInputId(gridId, column.key))}" class="grid-column-filter" value="${escapeAttr(gridColumnFilterValue(gridId, column.key))}" placeholder="filter" title="Filter ${escapeAttr(column.label)}" oninput="setGridColumnFilter('${grid}', '${key}', this.value)" onclick="event.stopPropagation()" onkeydown="event.stopPropagation()">`
        : "";
      return `<th class="${escapeAttr(columnClass)}"><div class="grid-header-cell"><button type="button" class="grid-sort-button${active}" title="Sort ${escapeAttr(column.label)}" onclick="toggleGridSort('${grid}', '${key}')">${label}${indicatorHtml}</button>${filter}</div></th>`;
    }

    function sortableGridTable(gridId, columns, rows, className, renderRow) {
      const visibleRows = visibleGridRows(gridId, columns, rows);
      const classAttr = className ? ` class="${escapeAttr(className)}"` : "";
      const headers = columns.map((column) => gridHeaderCell(gridId, column)).join("");
      const body = visibleRows.map(renderRow).join("");
      return {
        visibleRows,
        html: `<table${classAttr}><thead><tr>${headers}</tr></thead><tbody>${body}</tbody></table>`
      };
    }

    function gridFilterStatusHtml(gridId, columns, visibleCount, totalCount, noun = "rows") {
      if (!gridColumnFiltersActive(gridId, columns)) {
        return "";
      }
      return `<div class="analysis-status">Column filters active: ${Number(visibleCount).toLocaleString()} of ${Number(totalCount).toLocaleString()} ${escapeHtml(noun)} shown.</div>`;
    }

    function setCurrentEntryGrid(gridId, entries) {
      state.currentEntryGrid = {
        gridId,
        entries: entries || []
      };
    }

    function setCurrentLiveGrid(gridId, items) {
      state.currentLiveGrid = {
        gridId,
        items: items || []
      };
    }

    function searchResultKey(hit) {
      return JSON.stringify([
        hit.evidence_id,
        hit.entry_id,
        hit.match_kind,
        hit.selection_offset,
        hit.selection_length,
        hit.logical_path,
        hit.display_name,
        hit.data_preview
      ]);
    }

    function searchResultHost(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.host, metadata.hostname);
    }

    function searchResultReferrer(entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstText(metadata.referrer, metadata.source_url, metadata.tab_url);
    }

    function searchResultTime(entry) {
      if (!entry) {
        return "";
      }
      return firstText(
        categoryTime(entry),
        filesystemCreatedTime(entry),
        filesystemAccessedTime(entry),
        filesystemModifiedTime(entry),
        filesystemMftModifiedTime(entry)
      );
    }

    function searchResultOffsetRaw(hit, entry) {
      const metadata = entry && entry.metadata_json ? entry.metadata_json : {};
      return firstDefined(
        metadata.file_data_physical_offset,
        metadata.file_data_logical_offset,
        metadata.mft_record_physical_offset,
        metadata.mft_record_logical_offset,
        metadata.physical_offset,
        metadata.logical_offset,
        metadata.partition_start_offset,
        metadata.start_offset,
        hit ? hit.selection_offset : null
      );
    }

    function searchNumericValue(value) {
      return gridNumericValue(value);
    }

    function loadedSearchEntryMap() {
      const entries = new Map();
      const addEntry = (entry) => {
        if (entry && entry.id != null && !entries.has(entry.id)) {
          entries.set(entry.id, entry);
        }
      };
      if (state.data && Array.isArray(state.data.entries)) {
        state.data.entries.forEach(addEntry);
      }
      (state.cat.entries || []).forEach(addEntry);
      for (const path in state.idx.dirCache) {
        (state.idx.dirCache[path] || []).forEach((child) => addEntry(idxChildToEntry(child)));
      }
      return entries;
    }

    function searchResultRow(hit, index, entryMap = null) {
      const entry = entryMap ? entryMap.get(hit.entry_id) : findLoadedEntry(hit.entry_id);
      const offsetRaw = searchResultOffsetRaw(hit, entry);
      const offset = formatOffsetValue(offsetRaw);
      const host = searchResultHost(entry);
      const referrer = searchResultReferrer(entry);
      const time = searchResultTime(entry);
      const match = compactParts([hit.match_kind, entry && entry.is_deleted ? "deleted" : ""]);
      const values = {
        entry: compactParts([hit.display_name, hit.logical_path]),
        match,
        host,
        referrer,
        time,
        offset,
        preview: hit.data_preview || ""
      };
      return {
        hit,
        index,
        entry,
        key: searchResultKey(hit),
        values,
        sortValues: {
          offset: searchNumericValue(offsetRaw),
          time: Date.parse(time)
        }
      };
    }

    function searchColumnFiltersActive() {
      return gridColumnFiltersActive("search", searchResultColumns());
    }

    function visibleSearchResultRows() {
      const entryMap = loadedSearchEntryMap();
      const rows = state.searchResults.map((hit, index) => searchResultRow(hit, index, entryMap));
      return visibleGridRows("search", searchResultColumns(), rows);
    }

    function selectedVisibleSearchResultRows() {
      const selected = state.selectedSearchKeys || new Set();
      return visibleSearchResultRows().filter((row) => selected.has(row.key));
    }

    function selectedSearchResultRows() {
      const selected = state.selectedSearchKeys || new Set();
      const entryMap = loadedSearchEntryMap();
      return state.searchResults
        .map((hit, index) => searchResultRow(hit, index, entryMap))
        .filter((row) => selected.has(row.key));
    }

    function searchResultsTable(rows) {
      const headers = searchResultColumns().map((column) => gridHeaderCell("search", column)).join("");
      return `<table class="search-results-table"><thead><tr>${headers}</tr></thead><tbody>${rows}</tbody></table>`;
    }

    // Evidence in the current search scope whose latest index was run
    // metadata-only: content matching cannot see those files, and pretending
    // the search covered them would be a silent coverage gap.
    function metadataOnlySearchWarningHtml() {
      if (!state.data) {
        return "";
      }
      const scoped = $("searchEvidence").value ? Number($("searchEvidence").value) : null;
      const affected = (state.data.evidence || []).filter((item) =>
        item.content_indexed === false && (scoped === null || item.id === scoped));
      if (!affected.length) {
        return "";
      }
      const names = affected.map((item) => item.display_name).join(", ");
      return `<div class="analysis-status" style="color:var(--warn, #9a6700)">Content matching is unavailable for ${escapeHtml(names)}: the latest index was metadata-only (Capture file content was off). Path/metadata hits still work; re-process with content on for content search.</div>`;
    }

    function indexedSearchCoverageHtml() {
      const coverage = state.searchCoverage;
      if (!coverage) {
        return "";
      }
      const bytes = Number(coverage.generic_file_content_bytes_per_file) || 4096;
      return `<div class="analysis-status">Indexed coverage: all entries in the selected scope across the complete page sequence. Generic file content is limited to the first ${bytes.toLocaleString()} captured bytes per file. Structured parser text: ${escapeHtml(coverage.parser_derived_text_scope || "all persisted parser-emitted text segments")}. Raw evidence bytes are ${coverage.raw_evidence_bytes_included ? "included" : "not included; use All mode for a whole-source byte scan"}.</div>`;
    }

    function renderSearchResults() {
      const visibleRows = visibleSearchResultRows();
      const filterOn = searchColumnFiltersActive();
      const loadMore = $("loadMoreSearchResults");
      if (loadMore) {
        loadMore.hidden = Boolean(state.searchError) || state.searchComplete || !state.searchCursor;
        loadMore.disabled = state.searchPageLoading;
        loadMore.textContent = state.searchPageLoading ? "Loading..." : "Load more indexed results";
      }
      $("searchCount").textContent = String(visibleRows.length);
      const filterStatus = $("searchFilterStatus");
      if (filterStatus) {
        filterStatus.textContent = filterOn
          ? "Column filters active: " + visibleRows.length + " of " + state.searchResults.length + " shown"
          : "";
      }
      if (state.searchError) {
        // The indexed pass failed - say so in the results area itself, not
        // only in a transient notice (in All mode the bitwise pass still runs
        // below this message).
        $("searchResults").innerHTML = `<div class="analysis-status" style="color:var(--bad, #c0392b)">Indexed search failed: ${escapeHtml(state.searchError)}</div>`;
        renderSearchSelectionCount();
        return;
      }
      if (state.searchResults.length === 0 && state.data && Number(state.data.entry_count || 0) === 0) {
        $("searchResults").innerHTML = currentSearchMode() === "all"
          ? `<div class="analysis-status"><strong>Indexed search unavailable:</strong> this case has no processed entries. The independent bitwise whole-disk results appear below and search decoded evidence bytes, including unallocated space and slack.</div>`
          : `<div class="analysis-status"><strong>Indexed search unavailable:</strong> this case has no processed entries. Process the evidence first, switch to All for a bitwise whole-disk scan, or use raw find in Browse.</div>`;
        renderSearchSelectionCount();
        return;
      }
      const rows = visibleRows.map((row) => {
        const hit = row.hit;
        const index = row.index;
        const checked = (state.selectedSearchKeys || new Set()).has(row.key) ? " checked" : "";
        const deleted = row.entry && row.entry.is_deleted ? ' <span class="pill bad">deleted</span>' : "";
        return `
        <tr class="entry-row" onclick="goToSearchResult(${index})" data-entry-id="${hit.entry_id}" data-search-index="${index}">
          <td><input type="checkbox"${checked} onclick="event.stopPropagation(); toggleSearchResultSelection(${index}, this.checked)"></td>
          <td title="${escapeAttr(row.values.entry)}"><strong>${escapeHtml(hit.display_name)}</strong><br><span class="muted tiny">${escapeHtml(hit.logical_path)}</span></td>
          <td><span class="pill ${hit.match_kind === "content" ? "good" : ""}">${escapeHtml(hit.match_kind)}</span>${deleted}</td>
          <td title="${escapeAttr(row.values.host)}">${escapeHtml(row.values.host)}</td>
          <td title="${escapeAttr(row.values.referrer)}">${escapeHtml(row.values.referrer)}</td>
          <td class="entry-time" title="${escapeAttr(row.values.time)}">${escapeHtml(row.values.time)}</td>
          <td class="entry-offset" title="${escapeAttr(row.values.offset)}">${escapeHtml(row.values.offset)}</td>
          <td>${escapeHtml(row.values.preview)}</td>
        </tr>`;
      }).join("");
      if (state.searchResults.length === 0) {
        $("searchResults").innerHTML = indexedSearchCoverageHtml() + metadataOnlySearchWarningHtml() + empty("No results.");
      } else {
        $("searchResults").innerHTML = indexedSearchCoverageHtml() + metadataOnlySearchWarningHtml() + searchResultsTable(rows) + (rows ? "" : empty("No results match the column filters."));
      }
      renderSearchSelectionCount();
    }

    function renderSearchSelectionCount() {
      const selected = (state.selectedSearchKeys || new Set()).size
        + (state.selectedRawSearchKeys || new Set()).size;
      const visible = selectedVisibleSearchResultRows().length
        + selectedVisibleRawSearchResultRows().length;
      $("searchSelectedCount").textContent = selected + " selected"
        + (visible < selected ? " (" + visible + " visible)" : "");
    }

    function bookmarksGridColumns() {
      return [
        { key: "bookmark", label: "Bookmark", sortable: true, filterable: true, sortType: "text" },
        { key: "type", label: "Type", sortable: true, filterable: true, sortType: "text" },
        { key: "items", label: "Items", sortable: true, filterable: true, sortType: "number" },
        { key: "comment", label: "Comment", sortable: true, filterable: true, sortType: "text" },
        { key: "actions", label: "", sortable: false, filterable: false, sortType: "none" }
      ];
    }

    function bookmarkGridRow(bookmark, folderNames) {
      const items = state.data.items.filter((item) => item.bookmark_id === bookmark.id);
      const title = bookmark.title || bookmark.bookmark_type;
      const itemLabels = items.map((item) => item.display_name || item.logical_path || ("Item " + item.id));
      return {
        bookmark,
        items,
        itemLabels,
        title,
        folderName: folderNames.get(bookmark.folder_id) || "",
        values: {
          bookmark: compactParts([title, folderNames.get(bookmark.folder_id) || ""]),
          type: bookmark.bookmark_type,
          items: itemLabels.join(" | ") || "No items",
          comment: bookmark.examiner_comment || ""
        },
        sortValues: {
          items: items.length
        }
      };
    }

    function renderBookmarkGridRow(row) {
      const itemRows = row.items.length
        ? `<ul class="bookmark-items">${row.items.map((item, index) => {
            const itemLabel = row.itemLabels[index];
            return `<li>
                <span>${escapeHtml(itemLabel)}</span>
                <button class="ghost danger" onclick="removeBookmarkItemUi(${item.id}, '${escapeAttr(escapeJs(itemLabel))}')">Remove item</button>
              </li>`;
          }).join("")}</ul>`
        : '<span class="muted tiny">No items</span>';
      return `
          <tr>
            <td><strong>${escapeHtml(row.title)}</strong><br><span class="muted tiny">${escapeHtml(row.folderName)}</span></td>
            <td><span class="pill">${escapeHtml(row.bookmark.bookmark_type)}</span></td>
            <td>${itemRows}</td>
            <td>${escapeHtml(row.bookmark.examiner_comment || "")}</td>
            <td class="actions"><button class="ghost danger" onclick="removeBookmarkUi(${row.bookmark.id}, '${escapeAttr(escapeJs(row.title))}')">Remove</button></td>
          </tr>`;
    }

    // Folders with no bookmarks and no child folders can be removed (audited).
    // Rendered as a small management strip so leftover/accidental folders can
    // finally be cleaned up without touching the case database by hand.
    function emptyBookmarkFolderStripHtml() {
      const usedFolderIds = new Set(state.data.bookmarks.map((bookmark) => bookmark.folder_id));
      const parentIds = new Set(state.data.folders.filter((folder) => folder.parent_id != null).map((folder) => folder.parent_id));
      const removable = state.data.folders.filter((folder) => !usedFolderIds.has(folder.id) && !parentIds.has(folder.id));
      if (!removable.length) {
        return "";
      }
      const chips = removable.map((folder) =>
        `<span class="pill">${escapeHtml(folder.name)} <a href="#" onclick="removeBookmarkFolder(${folder.id}); return false;" title="Remove this empty folder (recorded in the audit trail)">remove</a></span>`
      ).join(" ");
      return `<div class="muted tiny" style="margin:4px 0 8px">Empty folders: ${chips}</div>`;
    }

    async function removeBookmarkFolder(folderId) {
      if (!confirm("Remove this empty bookmark folder? The removal is recorded in the case audit trail.")) {
        return;
      }
      try {
        const data = await apiPost("/api/bookmark/folder/remove", {
          case_path: currentCasePath(),
          folder_id: folderId
        });
        await refresh();
        setNotice("Removed empty folder \"" + data.name + "\".");
      } catch (err) {
        setNotice("Folder removal failed: " + err.message, true);
      }
    }

    function renderBookmarks() {
      const folderNames = new Map(state.data.folders.map((folder) => [folder.id, folder.name]));
      const folderStrip = emptyBookmarkFolderStripHtml();
      const rows = state.data.bookmarks.map((bookmark) => bookmarkGridRow(bookmark, folderNames));
      if (rows.length === 0) {
        $("bookmarksTable").innerHTML = folderStrip + empty("No bookmarks.");
        return;
      }
      const columns = bookmarksGridColumns();
      const tableResult = sortableGridTable("bookmarks", columns, rows, "", renderBookmarkGridRow);
      const filterStatus = gridFilterStatusHtml("bookmarks", columns, tableResult.visibleRows.length, rows.length, "bookmarks");
      $("bookmarksTable").innerHTML = folderStrip + filterStatus + tableResult.html + (tableResult.visibleRows.length ? "" : empty("No bookmarks match the column filters."));
    }

    function renderReport() {
      $("reportCount").textContent = state.data.report.folders.length + " folders";
      $("reportPreview").textContent = JSON.stringify(state.data.report, null, 2);
    }

    function table(headers, rows, className = "") {
      const classAttr = className ? ` class="${escapeAttr(className)}"` : "";
      return `<table${classAttr}><thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>`;
    }

    function empty(text) {
      return `<div class="empty">${escapeHtml(text)}</div>`;
    }

    function numberValue(id, fallback) {
      const value = Number($(id).value);
      return Number.isFinite(value) && value > 0 ? value : fallback;
    }

    // Clamps an examiner-typed limit to the range the backend actually honors
    // and writes the clamped value back into the field, so the UI never
    // implies a bigger number did something. Numbers past ~2^53 also stop
    // surviving the JSON round-trip as integers (they serialize as scientific
    // notation), which used to fail the whole search request.
    function boundedNumberValue(id, fallback, min, max) {
      const field = $(id);
      const raw = String(field.value).trim() === "" ? NaN : Number(field.value);
      const base = Number.isFinite(raw) ? raw : fallback;
      const value = Math.min(Math.max(Math.floor(base), min), max);
      if (String(field.value) !== String(value)) {
        field.value = String(value);
      }
      return value;
    }

    function nonNegativeNumberValue(id, fallback) {
      const value = Number($(id).value);
      return Number.isFinite(value) && value >= 0 ? value : fallback;
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }[ch]));
    }

    function escapeAttr(value) {
      return escapeHtml(value).replace(/`/g, "&#96;");
    }

    function escapeJs(value) {
      return String(value ?? "")
        .replace(/\\/g, "\\\\")
        .replace(/'/g, "\\'")
        .replace(/\r/g, "\\r")
        .replace(/\n/g, "\\n");
    }

    function formatBytes(value) {
      const units = ["B", "KB", "MB", "GB", "TB"];
      let size = Number(value) || 0;
      let unit = 0;
      while (size >= 1024 && unit < units.length - 1) {
        size = size / 1024;
        unit += 1;
      }
      return (unit === 0 ? String(size) : size.toFixed(1)) + " " + units[unit];
    }

    function bindTabs() {
      document.querySelectorAll(".tab").forEach((button) => {
        button.addEventListener("click", () => {
          switchView(button.dataset.view);
        });
      });
    }

    function isFormInputTarget(target) {
      return Boolean(target && target.closest && target.closest("input, textarea, select"));
    }

    function shortcutDigit(event) {
      if (/^[1-7]$/.test(event.key)) {
        return event.key;
      }
      const match = String(event.code || "").match(/^(Digit|Numpad)([1-7])$/);
      return match ? match[2] : "";
    }

    function shortcutViewForDigit(digit) {
      return {
        "1": "dashboardView",
        "2": "evidenceView",
        "3": "analyzeView",
        "4": "searchView",
        "5": "bookmarksView",
        "6": "reportView",
        "7": "timelineView"
      }[digit] || "";
    }

    function handleGlobalKeydown(event) {
      if (event.key === "Escape" && state.viewerFullscreen) {
        event.preventDefault();
        setViewerFullscreen(false);
        return;
      }
      if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "f" && state.hex.raw) {
        event.preventDefault();
        const input = $("rawFindQuery");
        if (input) {
          input.focus();
          input.select();
        }
        return;
      }
      if (!event.altKey || event.ctrlKey || event.metaKey || isFormInputTarget(event.target)) {
        return;
      }
      const viewId = shortcutViewForDigit(shortcutDigit(event));
      if (!viewId) {
        return;
      }
      event.preventDefault();
      switchView(viewId);
    }

    function switchView(viewId) {
      const leavingSearch = $("searchView").classList.contains("active") && viewId !== "searchView";
      if (leavingSearch) {
        persistDeepSearchSession();
      }
      document.querySelectorAll(".tab").forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.view === viewId);
      });
      document.querySelectorAll(".view").forEach((view) => {
        view.classList.toggle("active", view.id === viewId);
      });
      if (viewId === "timelineView") {
        renderTimeline();
        maybePromptTimelineBuild();
      }
    }

    // Draggable column widths on every rendered table. Widths persist per
    // table kind (class + column count) so File System, Categories, Live
    // browse, Search, etc. each remember their own layout.
    function columnWidthKey(tableEl, columnCount) {
      const kind = (tableEl.className || "table").split(/\s+/)[0] || "table";
      return "kdft.colWidths." + kind + ":" + columnCount;
    }

    function loadColumnWidths(key) {
      try {
        return JSON.parse(localStorage.getItem(key)) || {};
      } catch (err) {
        return {};
      }
    }

    function makeTableColumnsResizable(tableEl) {
      if (!tableEl || tableEl.dataset.resizable === "1") {
        return;
      }
      tableEl.dataset.resizable = "1";
      const ths = Array.from(tableEl.querySelectorAll("thead th"));
      if (ths.length === 0) {
        return;
      }
      const storeKey = columnWidthKey(tableEl, ths.length);
      const saved = loadColumnWidths(storeKey);
      ths.forEach((th, index) => {
        if (saved[index]) {
          th.style.width = saved[index] + "px";
          tableEl.style.tableLayout = "fixed";
        }
        const grip = document.createElement("span");
        grip.className = "col-resizer";
        grip.title = "Drag to resize column";
        grip.addEventListener("pointerdown", (event) => {
          event.preventDefault();
          event.stopPropagation();
          grip.classList.add("dragging");
          const startX = event.clientX;
          const startWidth = th.getBoundingClientRect().width;
          // Fixed layout makes the header width authoritative for the column.
          tableEl.style.tableLayout = "fixed";
          const onMove = (moveEvent) => {
            th.style.width = Math.max(48, startWidth + moveEvent.clientX - startX) + "px";
          };
          const onUp = () => {
            document.removeEventListener("pointermove", onMove);
            document.removeEventListener("pointerup", onUp);
            grip.classList.remove("dragging");
            const widths = loadColumnWidths(storeKey);
            widths[index] = Math.round(th.getBoundingClientRect().width);
            localStorage.setItem(storeKey, JSON.stringify(widths));
          };
          document.addEventListener("pointermove", onMove);
          document.addEventListener("pointerup", onUp);
        });
        th.appendChild(grip);
      });
    }

    function enhanceRenderedTables() {
      document.querySelectorAll("table").forEach(makeTableColumnsResizable);
    }

    new MutationObserver(enhanceRenderedTables).observe(document.body, { childList: true, subtree: true });
    enhanceRenderedTables();

    // The context menu closes on any outside click, Escape, or scroll.
    document.addEventListener("click", hideContextMenu);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        hideContextMenu();
      }
    });
    document.addEventListener("scroll", hideContextMenu, true);
    document.addEventListener("contextmenu", handleGlobalContextMenu);

    $("casePath").value = normalizePathInput(state.casePath);
    $("evidencePath").value = normalizePathInput(localStorage.getItem("kdft.evidencePath") || BOOTSTRAP.defaultEvidencePath);
    $("reportPath").value = normalizePathInput(BOOTSTRAP.defaultReportPath);
    // Clear any persisted processing cap from the removed "Processing limit" input.
    localStorage.removeItem("kdft.processMaxEntries");
    PROCESSING_OPTION_CHECKBOXES.forEach((id) => {
      const stored = localStorage.getItem("kdft." + id);
      if (stored !== null) {
        $(id).checked = stored === "true";
      }
      $(id).addEventListener("change", () => {
        localStorage.setItem("kdft." + id, String($(id).checked));
      });
    });
    if (localStorage.getItem("kdft.dataInterpreter.open") === "1") {
      toggleDataInterpreter(true);
    }
    $("refreshCase").addEventListener("click", refresh);
    $("toggleSidebar").addEventListener("click", () => {
      const collapsed = document.querySelector(".app").classList.toggle("sidebar-collapsed");
      localStorage.setItem("kdft.sidebarCollapsed", collapsed ? "1" : "0");
    });
    if (localStorage.getItem("kdft.sidebarCollapsed") === "1") {
      document.querySelector(".app").classList.add("sidebar-collapsed");
    }
    $("createCase").addEventListener("click", createCase);
    $("caseOpenSetup").addEventListener("click", caseOpenSetupView);
    $("caseOpenButton").addEventListener("click", openExistingCase);
    $("addEvidence").addEventListener("click", addEvidence);
    document.querySelectorAll("#evidenceTypeRow .evidence-type").forEach((button) => {
      button.addEventListener("click", () => setEvidenceType(button.dataset.type));
    });
    $("selectVisibleRows").addEventListener("click", selectVisibleEntries);
    $("bookmarkReportSelected").addEventListener("click", bookmarkSelectionAndExportReport);
    $("selectedAction").addEventListener("change", handleSelectedAction);
    // "input" fires as soon as a complete date is typed or picked - no Enter
    // needed; the value stays "" until the date is complete.
    [
      ["dateFilterFrom", "from"],
      ["dateFilterTo", "to"],
      ["timelineDateFrom", "from"],
      ["timelineDateTo", "to"]
    ].forEach(([id, field]) => {
      ["input", "change"].forEach((eventName) => {
        $(id).addEventListener(eventName, () => setDateFilterValue(field, $(id).value));
      });
    });
    $("dateFilterClear").addEventListener("click", clearDateFilter);
    $("timelineDateFilterClear").addEventListener("click", clearDateFilter);
    $("buildTimeline").addEventListener("click", requestTimelineBuild);
    $("toggleInspector").addEventListener("click", toggleInspectorPane);
    $("analyzeBack").addEventListener("click", analyzeBack);
    $("analyzeForward").addEventListener("click", analyzeForward);
    $("exportReportFromAnalyze").addEventListener("click", exportReport);
    const recategorizeButton = $("recategorizeBtn");
    if (recategorizeButton) {
      recategorizeButton.addEventListener("click", recategorizeCase);
    }
    $("openAnalyzeWindow").addEventListener("click", openAnalyzeWindow);
    $("liveBrowse").addEventListener("click", toggleLiveBrowse);
    $("treeModeFilesystem").addEventListener("click", () => setBrowserTreeMode("filesystem"));
    $("treeModeCategories").addEventListener("click", () => setBrowserTreeMode("categories"));
    $("browseEvidence").addEventListener("click", pickEvidencePath);
    $("runSearch").addEventListener("click", runSearch);
    $("loadMoreSearchResults").addEventListener("click", loadMoreSearchResults);
    $("loadMoreRawSearchResults").addEventListener("click", loadMoreRawSearchResults);
    $("searchMode").addEventListener("change", updateSearchModeUi);
    $("selectAllSearchResults").addEventListener("click", selectAllSearchResults);
    $("bookmarkSelectedSearchResults").addEventListener("click", bookmarkSelectedSearchResults);
    $("clearSelectedSearchResults").addEventListener("click", clearSelectedSearchResults);
    $("clearFindings").addEventListener("click", clearFindings);
    $("exportReport").addEventListener("click", exportReport);
    $("openReport").addEventListener("click", openReport);
    $("hexPrev").addEventListener("click", () => stepHex(-1));
    $("hexGo").addEventListener("click", gotoHexOffset);
    $("hexNext").addEventListener("click", () => stepHex(1));
    $("byteContextFile").addEventListener("click", () => setByteContext("file"));
    $("byteContextFilesystem").addEventListener("click", () => setByteContext("filesystem"));
    $("openSelectedEntry").addEventListener("click", () => openSelectedEntryExternal());
    $("showEntryDetails").addEventListener("click", showEntryDetails);
    $("toggleViewerFullscreen").addEventListener("click", toggleViewerFullscreen);
    $("bookmarkSelectedEntry").addEventListener("click", bookmarkHexTarget);
    $("viewerMode").addEventListener("change", () => {
      if ((state.hex.entryId || state.hex.live || state.hex.raw) && $("viewerMode").value !== "metadata" && !state.hex.data && !state.hex.fetching) {
        fetchEntryBytes();
      } else {
        renderHexViewer();
      }
    });
    $("bytesPerRow").addEventListener("change", renderHexViewer);
    $("offsetBase").addEventListener("change", renderHexViewer);
    $("hexOffset").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        gotoHexOffset();
      }
    });
    document.addEventListener("keydown", handleGlobalKeydown);
    window.addEventListener("pagehide", persistDeepSearchSession);
    window.addEventListener("popstate", (event) => {
      state.viewerFullscreenHistoryPending = false;
      setViewerFullscreen(Boolean(event.state && event.state.kdftViewerFullscreen), "popstate");
    });
    bindTabs();
    bindInspectorResize();
    bindHexSelection();
    setInspectorCollapsed(state.inspectorCollapsed);
    updateAnalyzeNavButtons();
    if (ANALYSIS_MODE) {
      switchView("analyzeView");
    }
    renderHexViewer();
    refresh();
  </script>
</body>
</html>
"###;
