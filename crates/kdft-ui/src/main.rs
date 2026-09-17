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
    // Return empty by default. Forensic tools should analyze target evidence images
    // and cases, never probe the investigator's own host browser paths on startup.
    String::new()
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
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!(
            "kdft-ui-{label}-{}-{nonce}-{seq}{suffix}",
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
    fn deep_search_ui_aggregates_examiner_batches_through_protected_api_pages() {
        assert!(INDEX_HTML.contains("const SEARCH_API_PAGE_MAX = 1000;"));
        assert!(INDEX_HTML.contains("const SEARCH_BATCH_MAX = 10000;"));
        assert!(INDEX_HTML.contains("onchange=\"normalizeSearchBatchSizeOnChange()\""));
        assert!(INDEX_HTML.contains("KDFT transparently retrieves this batch"));

        let value_normalizer = INDEX_HTML
            .split_once("function normalizedSearchBatchSizeValue(")
            .expect("Deep Search batch-size value normalizer")
            .1
            .split_once("function normalizeSearchBatchSizeInput(")
            .expect("end of Deep Search batch-size value normalizer")
            .0;
        assert!(value_normalizer.contains("Math.min(SEARCH_BATCH_MAX"));
        assert!(!value_normalizer.contains("throw new Error"));

        let input_normalizer = INDEX_HTML
            .split_once("function normalizeSearchBatchSizeInput(")
            .expect("Deep Search page-size normalizer")
            .1
            .split_once("function normalizeSearchBatchSizeOnChange()")
            .expect("end of Deep Search page-size normalizer")
            .0;
        assert!(input_normalizer.contains("field.value = String(normalized)"));
        assert!(!input_normalizer.contains("throw new Error"));

        let indexed_batch = INDEX_HTML
            .split_once("async function fetchIndexedSearchBatch(")
            .expect("indexed batch aggregator")
            .1
            .split_once("async function loadMoreSearchResults()")
            .expect("end of indexed batch aggregator")
            .0;
        assert!(indexed_batch.contains("while (batch.results.length < requestedCount"));
        assert!(indexed_batch.contains("Math.min(SEARCH_API_PAGE_MAX, remaining)"));
        assert!(indexed_batch.contains("batch.next_cursor = nextCursor"));
        assert!(indexed_batch.contains("pagesFetched: 0"));
        assert!(indexed_batch.contains("batch.error = err.message || String(err)"));
        assert!(indexed_batch.contains("searchRunIsCurrent(scope, generation)"));
        assert!(indexed_batch.contains("Indexed-search continuation did not advance"));

        let raw_batch = INDEX_HTML
            .split_once("async function fetchRawSearchBatch(")
            .expect("bitwise batch aggregator")
            .1
            .split_once("async function runBitwiseForUnifiedSearch(scope, generation)")
            .expect("end of bitwise batch aggregator")
            .0;
        assert!(raw_batch.contains("while (batch.hits.length < requestedCount"));
        assert!(raw_batch.contains("Math.min(SEARCH_API_PAGE_MAX, Math.max(1, remaining))"));
        assert!(raw_batch.contains("batch.next_cursor = nextCursor"));
        assert!(raw_batch.contains("pagesFetched: 0"));
        assert!(raw_batch.contains("async function fetchRawSearchAggregateBatch("));
        assert!(
            raw_batch.contains("let remaining = normalizedSearchBatchSizeValue(requestedCount)")
        );
        assert!(raw_batch.contains("remaining -= batch.hits.length"));
        assert!(raw_batch.contains("if (remaining <= 0)"));
        assert!(raw_batch.contains("searchRunIsCurrent(scope, generation)"));
        assert!(raw_batch.contains("Bitwise-search continuation did not advance"));

        assert!(INDEX_HTML.contains("Search criteria changed after this result set was created"));
        assert!(INDEX_HTML
            .contains("Search criteria changed after this bitwise result set was created"));
        assert!(INDEX_HTML.contains("Bitwise pass was not started: "));

        let restore = INDEX_HTML
            .split_once("function restoreDeepSearchSession() {")
            .expect("Deep Search restore function")
            .1
            .split_once("function newLiveBrowseState()")
            .expect("end of Deep Search restore function")
            .0;
        assert!(
            restore.contains("normalizeSearchBatchSizeInput({ announce: false, persist: false })")
        );
    }

    #[test]
    fn deep_search_results_are_revision_bound_and_freeze_on_scope_edits() {
        assert!(INDEX_HTML.contains("kdft.deepSearch.v2:"));
        assert!(INDEX_HTML.contains("function deepSearchCaseRevision("));
        assert!(INDEX_HTML.contains("data.case.created_at"));
        assert!(INDEX_HTML.contains("snapshot.caseRevision !== caseRevision"));
        assert!(INDEX_HTML.contains(
            "Discarded saved Deep Search results because the case or evidence index changed"
        ));
        assert!(INDEX_HTML.contains("scope.caseRevision === deepSearchCaseRevision()"));
        assert!(INDEX_HTML.contains("function handleDeepSearchCriteriaEdited("));
        assert!(INDEX_HTML.contains("Existing results are frozen"));
        assert!(INDEX_HTML.contains("requireCurrentDeepSearchResults(\"bookmarking\")"));
        assert!(INDEX_HTML
            .contains("fetchRawSearchAggregateBatch(merged, scope, batchSize, generation)"));

        let bindings = INDEX_HTML
            .split_once("\"searchQuery\",")
            .expect("Deep Search criteria binding list")
            .1
            .split_once("$(\"selectAllSearchResults\")")
            .expect("end of Deep Search criteria bindings")
            .0;
        assert!(bindings.contains("\"searchEvidence\""));
        assert!(bindings.contains("\"maxResults\""));
        assert!(bindings.contains("handleDeepSearchCriteriaEdited"));
    }

    #[test]
    fn deep_search_final_scope_edges_are_truthful_and_recoverable() {
        let revision_clear = INDEX_HTML
            .split_once("function clearDeepSearchResultsForRevisionChange() {")
            .expect("Deep Search revision-clear function")
            .1
            .split_once("function sameEvidenceIdentity(")
            .expect("end of Deep Search revision-clear function")
            .0;
        assert!(revision_clear.contains("runButton.disabled = false"));
        assert!(revision_clear.contains("runButton.textContent = \"Run Search\""));

        let bitwise_run = INDEX_HTML
            .split_once("async function runBitwiseForUnifiedSearch(scope, generation) {")
            .expect("unified bitwise function")
            .1
            .split_once("async function loadMoreRawSearchResults()")
            .expect("end of unified bitwise function")
            .0;
        assert!(bitwise_run.contains("if (!targets.length)"));
        assert!(bitwise_run
            .contains("merged.attempt_error = \"the selected evidence has no raw byte stream"));
        assert!(bitwise_run.contains("persistDeepSearchSession()"));

        let run_search = INDEX_HTML
            .split_once("async function runSearch() {")
            .expect("Deep Search run function")
            .1
            .split_once("function bitwiseEvidenceTargets(")
            .expect("end of Deep Search run function")
            .0;
        assert!(run_search.contains("if (!err.kdftStaleSearch)"));
        assert!(run_search.contains("Bitwise search failed:"));

        let stop_reason = INDEX_HTML
            .split_once("function bitwiseStopReasonNote(merged) {")
            .expect("bitwise stop-reason function")
            .1
            .split_once("async function goToSearchResult(")
            .expect("end of bitwise stop-reason function")
            .0;
        assert!(stop_reason.contains("coverage incomplete; continuation/retry available"));
        assert!(!stop_reason.contains("more matches available"));

        let metadata_warning = INDEX_HTML
            .split_once("function metadataOnlySearchWarningHtml() {")
            .expect("metadata-only warning function")
            .1
            .split_once("function indexedSearchCoverageHtml()")
            .expect("end of metadata-only warning function")
            .0;
        assert!(metadata_warning.contains("state.searchScope.evidenceId"));
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
    fn mailbox_ui_discloses_native_boundary_and_attempt_metadata() {
        for disclosure in [
            "PST/OST/NST",
            "ANSI v14/v15",
            "classic Unicode v23",
            "Unicode v36 (4K)",
            "v37 (WIP-capable; protection not determined)",
        ] {
            assert!(INDEX_HTML.contains(disclosure), "missing {disclosure}");
        }
        for key in [
            "pff_client_signature",
            "pst_header_version",
            "pst_page_size_bytes",
            "pst_native_reader_supported",
            "pst_embedded_magic_offset",
            "pst_header_first_32_bytes_hex",
            "email_parser_last_attempt_status",
            "email_parser_last_attempt_pst_variant",
            "email_parser_last_attempt_pff_client_signature",
            "email_parser_last_attempt_pst_header_version",
            "email_parser_last_attempt_pst_page_size_bytes",
            "email_parser_last_attempt_pst_native_reader_supported",
            "email_parser_last_attempt_pst_embedded_magic_offset",
            "email_parser_last_attempt_pst_header_first_32_bytes_hex",
            "email_parser_replacement_committed",
            "email_parser_replacement_rolled_back",
            "email_parser_previous_records_preserved",
            "email_parser_retained_record_count",
            "email_parser_error",
        ] {
            assert!(INDEX_HTML.contains(key), "missing {key}");
        }
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
        // For web URLs and documents, invoke the standard Windows Shell protocol
        // handler via url.dll. Direct explorer.exe invocation is reserved strictly
        // for local filesystem directories, avoiding heuristic behavioral flags on
        // unsigned binaries launching URLs.
        if target.starts_with("http://") || target.starts_with("https://") {
            Command::new("rundll32.exe")
                .args(["url.dll,FileProtocolHandler", target])
                .spawn()
                .context("opening URL in default browser")?;
        } else if std::path::Path::new(target).is_dir() {
            Command::new("explorer.exe")
                .arg(target)
                .spawn()
                .context("opening directory in explorer")?;
        } else {
            Command::new("rundll32.exe")
                .args(["url.dll,FileProtocolHandler", target])
                .spawn()
                .context("opening target file")?;
        }
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

const INDEX_HTML: &str = include_str!("../frontend/index.html");
