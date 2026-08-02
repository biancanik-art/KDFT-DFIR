#![allow(clippy::too_many_arguments)]

use chrono::{DateTime, Utc};
pub use outlook_pst::ltp::table_context::TableContext;
pub use outlook_pst::messaging::attachment::{
    AnsiAttachment, Attachment, AttachmentData, UnicodeAttachment,
};
pub use outlook_pst::messaging::folder::{AnsiFolder, Folder, UnicodeFolder};
pub use outlook_pst::messaging::message::{AnsiMessage, Message, UnicodeMessage};
pub use outlook_pst::messaging::store::{AnsiStore, Store, UnicodeStore};
pub use outlook_pst::{AnsiPstFile, UnicodePstFile};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Only properties consumed by the adapter are materialized by outlook-pst.
/// Passing `None` would load every message property, including unrelated large
/// binaries, before the streaming sink sees the message.
const PST_MESSAGE_PROPERTY_IDS: &[u16] = &[
    0x001A, // PidTagMessageClass
    0x0037, // PidTagSubject
    0x0039, // PidTagClientSubmitTime
    0x0C1A, // PidTagSenderName
    0x0C1F, // PidTagSenderEmailAddress
    0x0E06, // PidTagMessageDeliveryTime
    0x0E07, // PidTagMessageFlags
    0x0FFF, // PidTagEntryId (diagnostic only; row NID is authoritative)
    0x1000, // PidTagBody
    0x1013, // PidTagHtml
    0x3007, // PidTagCreationTime
    0x3008, // PidTagLastModificationTime
    0x3FDE, // PidTagInternetCodepage
];

/// Only the method and payload are needed when reopening an attachment. Its
/// filename, MIME type, declared size, and other metadata were already read
/// from the attachment table without materializing the payload.
const PST_ATTACHMENT_PROPERTY_IDS: &[u16] = &[
    0x3701, // PidTagAttachDataBinary / PidTagAttachDataObject
    0x3705, // PidTagAttachMethod
];

/// Maximum size of one MAPI property materialized by the locally patched
/// outlook-pst reader. Crossing this bound is an explicit parse error/partial
/// result, never silent truncation.
pub const PST_PROPERTY_MATERIALIZATION_BOUND_BYTES: usize =
    outlook_pst::ltp::prop_context::MAX_PROPERTY_VALUE_BYTES;

/// PST format encoding variant detected during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PstEncodingFormat {
    Unicode,
    Ansi,
    Unknown,
}

/// Status of PST file processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PstStatus {
    Recognized,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PstBodyKind {
    PlainText,
    Html,
}

#[derive(Debug, Clone, Copy)]
pub enum PstTextRef<'a> {
    String8(&'a [u8], Option<u16>),
    Unicode(&'a [u16]),
    Binary(&'a [u8], Option<u16>),
}

/// Metadata and counts for a PST folder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PstFolderInfo {
    pub node_id: u32,
    pub display_name: String,
    pub path: String,
    pub subfolder_count: u32,
    pub content_count: u32,
    pub unread_count: u32,
}

/// Recipient information in a message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PstRecipientInfo {
    pub display_name: Option<String>,
    pub email_address: Option<String>,
    pub recipient_type: Option<String>,
}

/// Attachment information in a message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PstAttachmentInfo {
    pub attachment_index: u32,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: u64,
    pub is_embedded_message: bool,
    pub content_id: Option<String>,
    pub is_skipped: bool,
}

/// Header and metadata for a PST message object (bounded text, no unbounded Vecs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PstMessageHeader {
    pub node_id: u32,
    pub entry_id_hex: String,
    pub folder_path: String,
    pub message_class: String,
    pub subject: Option<String>,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub client_submit_time: Option<DateTime<Utc>>,
    pub delivery_time: Option<DateTime<Utc>>,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_modification_time: Option<DateTime<Utc>>,
    pub body_plain_preview: Option<String>,
    pub body_html_preview: Option<String>,
    pub body_plain_truncated: bool,
    pub body_html_truncated: bool,
    pub recipient_count: u32,
    pub attachment_count: u32,
    pub has_attachments: bool,
    pub message_flags: u32,
    pub internet_code_page: Option<u16>,
}

/// Telemetry metrics, bounded error samples, and skipped item counters for PST processing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PstTelemetry {
    pub status: PstStatus,
    pub total_folders: u64,
    pub total_messages: u64,
    pub total_attachments: u64,
    pub total_recipients: u64,
    pub total_bytes_streamed: u64,
    pub total_errors: u64,
    pub error_samples: Vec<String>,
    pub errors_omitted: u64,
    pub skipped_items: u64,
    pub skipped_bytes: u64,
    /// Forensic coverage losses such as a folder-depth safety rejection.
    pub coverage_truncations: u64,
    /// Display-only preview shortening; complete bodies still reach the sink.
    pub preview_truncations: u64,
    pub message_limit_reached: bool,
    pub encoding_format: PstEncodingFormat,
}

impl Default for PstTelemetry {
    fn default() -> Self {
        Self {
            status: PstStatus::Recognized,
            total_folders: 0,
            total_messages: 0,
            total_attachments: 0,
            total_recipients: 0,
            total_bytes_streamed: 0,
            total_errors: 0,
            error_samples: Vec::new(),
            errors_omitted: 0,
            skipped_items: 0,
            skipped_bytes: 0,
            coverage_truncations: 0,
            preview_truncations: 0,
            message_limit_reached: false,
            encoding_format: PstEncodingFormat::Unknown,
        }
    }
}

impl PstTelemetry {
    pub fn record_error(&mut self, err_msg: String) {
        self.total_errors = self.total_errors.saturating_add(1);
        if self.error_samples.len() < 50 {
            self.error_samples.push(err_msg);
        } else {
            self.errors_omitted = self.errors_omitted.saturating_add(1);
        }
        if self.status != PstStatus::Failed {
            self.status = PstStatus::Partial;
        }
    }

    pub fn record_skip(&mut self, bytes: u64) {
        self.skipped_items = self.skipped_items.saturating_add(1);
        self.skipped_bytes = self.skipped_bytes.saturating_add(bytes);
        if self.status != PstStatus::Failed {
            self.status = PstStatus::Partial;
        }
    }

    pub fn record_truncation(&mut self) {
        self.coverage_truncations = self.coverage_truncations.saturating_add(1);
        if self.status != PstStatus::Failed {
            self.status = PstStatus::Partial;
        }
    }

    pub fn record_preview_truncation(&mut self) {
        // A preview may be bounded while the complete body is still delivered
        // through `on_message_body`; this is display telemetry, not omission.
        self.preview_truncations = self.preview_truncations.saturating_add(1);
    }
}

/// Configuration parameters for bounded PST parsing memory protection.
#[derive(Debug, Clone)]
pub struct PstAdapterOptions {
    /// Maximum allowed memory allocation for a single attachment payload in bytes. Default: 50 MiB.
    pub max_attachment_size: u64,
    /// Maximum length in characters for message text body previews. Default: 64 KiB.
    pub max_body_chars: usize,
    /// Maximum depth allowed during recursive folder hierarchy traversal. Default: 32.
    pub max_folder_depth: usize,
    /// Optional examiner-requested message bound. None means unlimited.
    pub max_messages: Option<u64>,
}

impl Default for PstAdapterOptions {
    fn default() -> Self {
        Self {
            max_attachment_size: 50 * 1024 * 1024,
            max_body_chars: 64 * 1024,
            max_folder_depth: 32,
            max_messages: None,
        }
    }
}

/// Trait for streaming PST content items without storing full mailbox contents in memory.
pub trait PstStreamSink {
    /// Callback when a folder is visited.
    fn on_folder(&mut self, folder: &PstFolderInfo) -> io::Result<()>;

    /// Callback when a message object header is visited.
    fn on_message_header(&mut self, message: &PstMessageHeader) -> io::Result<()>;

    /// Complete message body text. The adapter borrows the property value owned
    /// by outlook-pst, so a sink can segment/persist it without another full copy.
    fn on_message_body(
        &mut self,
        folder_path: &str,
        message_node_id: u32,
        kind: PstBodyKind,
        body: PstTextRef<'_>,
    ) -> io::Result<()>;

    /// Callback when a message recipient record is visited.
    fn on_recipient(
        &mut self,
        folder_path: &str,
        message_node_id: u32,
        recipient: &PstRecipientInfo,
    ) -> io::Result<()>;

    /// Callback when an attachment header is visited.
    fn on_attachment_header(
        &mut self,
        folder_path: &str,
        message_node_id: u32,
        attachment: &PstAttachmentInfo,
    ) -> io::Result<()>;

    /// Callback to stream attachment bytes to a sink.
    fn on_attachment_bytes(
        &mut self,
        folder_path: &str,
        message_node_id: u32,
        attachment: &PstAttachmentInfo,
        bytes: &[u8],
    ) -> io::Result<()>;

    /// Called after a non-preflight-skipped attachment fails to produce a
    /// payload, so persistent sinks never leave a misleading `pending` row.
    fn on_attachment_failure(
        &mut self,
        folder_path: &str,
        message_node_id: u32,
        attachment: &PstAttachmentInfo,
        reason: &str,
    ) -> io::Result<()>;
}

/// Test-only helper sink for collecting counts and metadata in unit tests.
#[cfg(test)]
pub struct MemoryCountingSink {
    pub folders: Vec<PstFolderInfo>,
    pub message_headers: Vec<PstMessageHeader>,
    pub recipients: Vec<PstRecipientInfo>,
    pub attachments: Vec<PstAttachmentInfo>,
    pub attachment_bytes_count: u64,
}

#[cfg(test)]
impl MemoryCountingSink {
    pub fn new() -> Self {
        Self {
            folders: Vec::new(),
            message_headers: Vec::new(),
            recipients: Vec::new(),
            attachments: Vec::new(),
            attachment_bytes_count: 0,
        }
    }
}

#[cfg(test)]
impl Default for MemoryCountingSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl PstStreamSink for MemoryCountingSink {
    fn on_folder(&mut self, folder: &PstFolderInfo) -> io::Result<()> {
        self.folders.push(folder.clone());
        Ok(())
    }

    fn on_message_header(&mut self, message: &PstMessageHeader) -> io::Result<()> {
        self.message_headers.push(message.clone());
        Ok(())
    }

    fn on_message_body(
        &mut self,
        _folder_path: &str,
        _message_node_id: u32,
        _kind: PstBodyKind,
        _body: PstTextRef<'_>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn on_recipient(
        &mut self,
        _folder_path: &str,
        _message_node_id: u32,
        recipient: &PstRecipientInfo,
    ) -> io::Result<()> {
        self.recipients.push(recipient.clone());
        Ok(())
    }

    fn on_attachment_header(
        &mut self,
        _folder_path: &str,
        _message_node_id: u32,
        attachment: &PstAttachmentInfo,
    ) -> io::Result<()> {
        self.attachments.push(attachment.clone());
        Ok(())
    }

    fn on_attachment_bytes(
        &mut self,
        _folder_path: &str,
        _message_node_id: u32,
        _attachment: &PstAttachmentInfo,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.attachment_bytes_count = self
            .attachment_bytes_count
            .saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn on_attachment_failure(
        &mut self,
        _folder_path: &str,
        _message_node_id: u32,
        _attachment: &PstAttachmentInfo,
        _reason: &str,
    ) -> io::Result<()> {
        Ok(())
    }
}

/// Safely convert Windows 64-bit FILETIME integer to Utc DateTime.
pub fn filetime_to_datetime(ft: i64) -> Option<DateTime<Utc>> {
    if ft <= 0 {
        return None;
    }
    const EPOCH_DIFFERENCE: i64 = 11_644_473_600;
    let seconds_since_1601 = ft.checked_div(10_000_000)?;
    let nanos = (ft.checked_rem(10_000_000)? * 100) as u32;
    let unix_secs = seconds_since_1601.checked_sub(EPOCH_DIFFERENCE)?;
    DateTime::from_timestamp(unix_secs, nanos)
}

/// Main entry point for bounded-memory streaming PST parsing.
///
/// Note: The underlying `outlook-pst` library materializes message property contexts in memory per-message;
/// this adapter enforces strict per-field truncation bounds on all extracted string properties and streams attachment
/// payloads directly to the provided `PstStreamSink` to minimize total memory footprint.
pub struct PstParserAdapter;

impl PstParserAdapter {
    /// Detect PST file encoding format from magic and version in header.
    /// Strictly rejects undocumented versions to prevent false-complete Unicode mislabeling.
    pub fn detect_format(file_bytes: &[u8]) -> PstEncodingFormat {
        if file_bytes.len() < 12 {
            return PstEncodingFormat::Unknown;
        }
        if &file_bytes[0..4] != b"!BDN" {
            return PstEncodingFormat::Unknown;
        }
        let ver = u16::from_le_bytes([file_bytes[10], file_bytes[11]]);
        match ver {
            14 | 15 => PstEncodingFormat::Ansi,
            23 | 36 => PstEncodingFormat::Unicode,
            _ => PstEncodingFormat::Unknown,
        }
    }

    /// Stream PST file contents from disk path using default bounds options.
    pub fn stream_pst_file<S: PstStreamSink>(
        path: &Path,
        sink: &mut S,
    ) -> io::Result<PstTelemetry> {
        Self::stream_pst_file_with_options(path, sink, &PstAdapterOptions::default())
    }

    /// Stream PST file contents from disk path with explicit memory allocation options.
    pub fn stream_pst_file_with_options<S: PstStreamSink>(
        path: &Path,
        sink: &mut S,
        options: &PstAdapterOptions,
    ) -> io::Result<PstTelemetry> {
        let mut telemetry = PstTelemetry::default();
        if !path.exists() {
            telemetry.record_error(format!("File does not exist: {}", path.display()));
            telemetry.status = PstStatus::Failed;
            return Ok(telemetry);
        }

        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                telemetry.record_error(format!("Failed to open file {}: {e}", path.display()));
                telemetry.status = PstStatus::Failed;
                return Ok(telemetry);
            }
        };

        let mut buf = [0u8; 16];
        let n = match file.read(&mut buf) {
            Ok(bytes_read) => bytes_read,
            Err(e) => {
                telemetry.record_error(format!(
                    "Failed to read header from {}: {e}",
                    path.display()
                ));
                telemetry.status = PstStatus::Failed;
                return Ok(telemetry);
            }
        };
        let header_bytes = &buf[..n];

        let format = Self::detect_format(header_bytes);
        telemetry.encoding_format = format;

        match format {
            PstEncodingFormat::Unicode => match UnicodePstFile::open_read_only(path) {
                Ok(unicode_pst) => {
                    Self::process_unicode_pst(unicode_pst, sink, options, &mut telemetry)?;
                }
                Err(err) => {
                    telemetry.record_error(format!("Unicode PST open error: {err}"));
                    telemetry.status = PstStatus::Failed;
                }
            },
            PstEncodingFormat::Ansi => match AnsiPstFile::open_read_only(path) {
                Ok(ansi_pst) => {
                    Self::process_ansi_pst(ansi_pst, sink, options, &mut telemetry)?;
                }
                Err(err) => {
                    telemetry.record_error(format!("ANSI PST open error: {err}"));
                    telemetry.status = PstStatus::Failed;
                }
            },
            PstEncodingFormat::Unknown => {
                telemetry.record_error(format!(
                    "Unsupported or unrecognized PST header format for {}",
                    path.display()
                ));
                telemetry.status = PstStatus::Failed;
            }
        }

        Ok(telemetry)
    }

    fn process_unicode_pst<S: PstStreamSink>(
        pst: UnicodePstFile,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
    ) -> io::Result<()> {
        let pst_rc = std::rc::Rc::new(pst);
        let store = match UnicodeStore::read(pst_rc) {
            Ok(s) => s,
            Err(err) => {
                telemetry.record_error(format!("Failed to initialize Unicode Store: {err}"));
                telemetry.status = PstStatus::Failed;
                return Ok(());
            }
        };

        let mut visited_nodes = HashSet::new();
        let root_entry_id = match store.properties().ipm_sub_tree_entry_id() {
            Ok(eid) => eid,
            Err(_) => match store
                .properties()
                .make_entry_id(outlook_pst::ndb::node_id::NID_ROOT_FOLDER)
            {
                Ok(eid) => eid,
                Err(err) => {
                    telemetry
                        .record_error(format!("Failed to determine root folder entry id: {err}"));
                    telemetry.status = PstStatus::Failed;
                    return Ok(());
                }
            },
        };

        match UnicodeFolder::read(store.clone(), &root_entry_id) {
            Ok(root_folder) => {
                Self::traverse_unicode_folder(
                    &store,
                    &root_folder,
                    "",
                    0,
                    &mut visited_nodes,
                    sink,
                    options,
                    telemetry,
                )?;
                if telemetry.total_folders == 0 {
                    telemetry
                        .record_error("Zero folders parsed from root folder hierarchy".to_string());
                    telemetry.status = PstStatus::Failed;
                }
            }
            Err(err) => {
                telemetry.record_error(format!("Failed to open root folder in Unicode PST: {err}"));
                telemetry.status = PstStatus::Failed;
            }
        }
        Ok(())
    }

    fn traverse_unicode_folder<S: PstStreamSink>(
        store: &std::rc::Rc<UnicodeStore>,
        folder: &UnicodeFolder,
        parent_path: &str,
        depth: usize,
        visited_nodes: &mut HashSet<u32>,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
    ) -> io::Result<()> {
        if depth > options.max_folder_depth {
            telemetry.record_error(format!(
                "Folder hierarchy depth limit ({}) exceeded at path: {}",
                options.max_folder_depth, parent_path
            ));
            telemetry.record_skip(0);
            return Ok(());
        }

        let props = folder.properties();
        let node_id_u32 = u32::from(props.node_id());
        if !visited_nodes.insert(node_id_u32) {
            telemetry.record_error(format!(
                "Cycle detected in folder node_id 0x{:08X} at path: {}",
                node_id_u32, parent_path
            ));
            telemetry.record_skip(0);
            return Ok(());
        }

        Self::do_traverse_unicode_folder(
            store,
            folder,
            parent_path,
            depth,
            visited_nodes,
            sink,
            options,
            telemetry,
            node_id_u32,
        )
    }

    fn do_traverse_unicode_folder<S: PstStreamSink>(
        store: &std::rc::Rc<UnicodeStore>,
        folder: &UnicodeFolder,
        parent_path: &str,
        depth: usize,
        visited_nodes: &mut HashSet<u32>,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
        node_id_u32: u32,
    ) -> io::Result<()> {
        let props = folder.properties();
        let folder_name = props.display_name().unwrap_or_else(|_| "Root".to_string());
        let current_path = if parent_path.is_empty() {
            folder_name.clone()
        } else {
            format!("{}/{}", parent_path, folder_name)
        };

        let subfolder_count = if props.has_sub_folders().unwrap_or(false) {
            folder
                .hierarchy_table()
                .map(|t| t.rows_matrix().count() as u32)
                .unwrap_or(0)
        } else {
            0
        };

        let content_count = props.content_count().unwrap_or(0) as u32;
        let unread_count = props.unread_count().unwrap_or(0) as u32;

        let folder_info = PstFolderInfo {
            node_id: node_id_u32,
            display_name: folder_name,
            path: current_path.clone(),
            subfolder_count,
            content_count,
            unread_count,
        };

        sink.on_folder(&folder_info)?;
        telemetry.total_folders = telemetry.total_folders.saturating_add(1);

        // Process messages in contents table without whole-table row-id Vec
        if let Some(contents_table) = folder.contents_table() {
            for row in contents_table.rows_matrix() {
                if Self::message_limit_reached(options, telemetry) {
                    break;
                }
                let row_nid = u32::from(row.id());
                if let Ok(entry_id) = store.properties().make_entry_id(row_nid.into()) {
                    match UnicodeMessage::read(
                        store.clone(),
                        &entry_id,
                        Some(PST_MESSAGE_PROPERTY_IDS),
                    ) {
                        Ok(msg) => {
                            Self::process_unicode_message(
                                store,
                                msg,
                                row_nid,
                                &current_path,
                                sink,
                                options,
                                telemetry,
                            )?;
                        }
                        Err(err) => {
                            telemetry.record_error(format!(
                                "Failed to open message node 0x{:08X} in folder {}: {err}",
                                row_nid, current_path
                            ));
                            telemetry.record_skip(0);
                        }
                    }
                } else {
                    telemetry.record_error(format!(
                        "Failed to construct entry_id for message node 0x{:08X} in folder {}",
                        row_nid, current_path
                    ));
                    telemetry.record_skip(0);
                }
            }
        }

        // Recurse into subfolders in hierarchy table without whole-table row-id Vec
        if let Some(hierarchy_table) = folder.hierarchy_table() {
            for child_row in hierarchy_table.rows_matrix() {
                if telemetry.message_limit_reached {
                    break;
                }
                let child_nid = u32::from(child_row.id());
                if let Ok(entry_id) = store.properties().make_entry_id(child_nid.into()) {
                    match UnicodeFolder::read(store.clone(), &entry_id) {
                        Ok(child_folder) => {
                            Self::traverse_unicode_folder(
                                store,
                                &child_folder,
                                &current_path,
                                depth + 1,
                                visited_nodes,
                                sink,
                                options,
                                telemetry,
                            )?;
                        }
                        Err(err) => {
                            telemetry.record_error(format!(
                                "Failed to read subfolder node 0x{:08X} in folder {}: {err}",
                                child_nid, current_path
                            ));
                            telemetry.record_skip(0);
                        }
                    }
                } else {
                    telemetry.record_error(format!(
                        "Failed to construct entry_id for subfolder node 0x{:08X} in folder {}",
                        child_nid, current_path
                    ));
                    telemetry.record_skip(0);
                }
            }
        }

        Ok(())
    }

    fn process_unicode_message<S: PstStreamSink>(
        _store: &std::rc::Rc<UnicodeStore>,
        msg: std::rc::Rc<UnicodeMessage>,
        node_id_u32: u32,
        folder_path: &str,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
    ) -> io::Result<()> {
        let props = msg.properties();
        let internet_code_page = pst_internet_code_page(props.get(0x3FDE));
        record_code_page_problem(props, internet_code_page, node_id_u32, telemetry);
        // The contents-table row NID is authoritative. PidTagEntryId can be
        // absent or malformed and must never fabricate node 0 provenance.

        let (subject, subj_trunc) = props
            .get(0x0037)
            .map(|v| extract_and_truncate_string_prop(v, 1024, internet_code_page))
            .unwrap_or((None, false));
        if subj_trunc {
            telemetry.record_truncation();
        }

        let (sender_name, sender_name_trunc) = props
            .get(0x0C1A)
            .map(|v| extract_and_truncate_string_prop(v, 1024, internet_code_page))
            .unwrap_or((None, false));
        if sender_name_trunc {
            telemetry.record_truncation();
        }

        let (sender_email, sender_email_trunc) = props
            .get(0x0C1F)
            .map(|v| extract_and_truncate_string_prop(v, 1024, internet_code_page))
            .unwrap_or((None, false));
        if sender_email_trunc {
            telemetry.record_truncation();
        }

        let message_class = props
            .message_class()
            .unwrap_or_else(|_| "IPM.Note".to_string());

        let creation_time = props.creation_time().ok().and_then(filetime_to_datetime);
        let last_modification_time = props
            .last_modification_time()
            .ok()
            .and_then(filetime_to_datetime);

        let client_submit_time = props
            .get(0x0039)
            .and_then(extract_time_prop)
            .and_then(filetime_to_datetime);
        let delivery_time = props
            .get(0x0E06)
            .and_then(extract_time_prop)
            .and_then(filetime_to_datetime);

        let (body_plain_preview, body_plain_truncated) = props
            .get(0x1000)
            .map(|v| {
                extract_and_truncate_string_prop(v, options.max_body_chars, internet_code_page)
            })
            .unwrap_or((None, false));
        if body_plain_truncated {
            telemetry.record_preview_truncation();
        }

        let (body_html_preview, body_html_truncated) = props
            .get(0x1013)
            .map(|v| {
                extract_and_truncate_string_prop(v, options.max_body_chars, internet_code_page)
            })
            .unwrap_or((None, false));
        if body_html_truncated {
            telemetry.record_preview_truncation();
        }

        let recipient_count = msg
            .recipient_table()
            .map(|t| t.rows_matrix().count() as u32)
            .unwrap_or(0);

        let attachment_count = msg
            .attachment_table()
            .map(|t| t.rows_matrix().count() as u32)
            .unwrap_or(0);

        let (canonical_node_id, canonical_entry_id) = authoritative_message_identity(node_id_u32);
        let msg_header = PstMessageHeader {
            node_id: canonical_node_id,
            entry_id_hex: canonical_entry_id,
            folder_path: folder_path.to_string(),
            message_class,
            subject,
            sender_name,
            sender_email,
            client_submit_time,
            delivery_time,
            creation_time,
            last_modification_time,
            body_plain_preview,
            body_html_preview,
            body_plain_truncated,
            body_html_truncated,
            recipient_count,
            attachment_count,
            has_attachments: attachment_count > 0,
            message_flags: props.message_flags().unwrap_or(0) as u32,
            internet_code_page,
        };

        sink.on_message_header(&msg_header)?;
        telemetry.total_messages = telemetry.total_messages.saturating_add(1);
        if let Some(body) = props
            .get(0x1000)
            .and_then(|value| property_text_ref(value, internet_code_page))
        {
            sink.on_message_body(folder_path, node_id_u32, PstBodyKind::PlainText, body)?;
        }
        if let Some(body) = props
            .get(0x1013)
            .and_then(|value| property_text_ref(value, internet_code_page))
        {
            sink.on_message_body(folder_path, node_id_u32, PstBodyKind::Html, body)?;
        }

        if let Some(recip_table) = msg.recipient_table() {
            for row in recip_table.rows_matrix() {
                let display_name = row
                    .columns(recip_table.context())
                    .ok()
                    .and_then(|cols| extract_col_string(&cols, recip_table.context(), 0x3001));
                let email_address = row
                    .columns(recip_table.context())
                    .ok()
                    .and_then(|cols| extract_col_string(&cols, recip_table.context(), 0x39FE));
                let recipient_type = row
                    .columns(recip_table.context())
                    .ok()
                    .and_then(|cols| extract_col_i32(&cols, recip_table.context(), 0x0C15))
                    .map(pst_recipient_type_label);
                let recip = PstRecipientInfo {
                    display_name,
                    email_address,
                    recipient_type,
                };
                sink.on_recipient(folder_path, node_id_u32, &recip)?;
                telemetry.total_recipients = telemetry.total_recipients.saturating_add(1);
            }
        }

        if let Some(attach_table) = msg.attachment_table() {
            for (idx, row) in attach_table.rows_matrix().enumerate() {
                let row_nid = u32::from(row.id());
                let cols_opt = row.columns(attach_table.context()).ok();

                let attach_method = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_i32(cols, attach_table.context(), 0x3705));

                let raw_size_i32 = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_i32(cols, attach_table.context(), 0x0E20));

                let declared_size_opt = match raw_size_i32 {
                    Some(s) if s >= 0 => Some(s as u64),
                    _ => None,
                };

                let filename = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_string(cols, attach_table.context(), 0x3707))
                    .or_else(|| {
                        cols_opt.as_ref().and_then(|cols| {
                            extract_col_string(cols, attach_table.context(), 0x3704)
                        })
                    });

                let mime_type = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_string(cols, attach_table.context(), 0x370E));

                let content_id = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_string(cols, attach_table.context(), 0x3712));

                let is_embedded_message = attach_method == Some(5);
                let size_bytes = declared_size_opt.unwrap_or(0);
                let mut is_skipped = false;

                if declared_size_opt.is_none() {
                    is_skipped = true;
                    telemetry.record_error(format!(
                        "Attachment {} in msg 0x{:08X} has missing/negative size ({:?}); payload skipped",
                        idx, node_id_u32, raw_size_i32
                    ));
                } else if size_bytes > options.max_attachment_size {
                    is_skipped = true;
                    telemetry.record_error(format!(
                        "Attachment {} in msg 0x{:08X} size {} exceeds allocation limit {}; payload skipped",
                        idx, node_id_u32, size_bytes, options.max_attachment_size
                    ));
                }

                match attach_method {
                    Some(1) | Some(5) => {}
                    Some(m) => {
                        is_skipped = true;
                        telemetry.record_error(format!(
                            "Attachment {} in msg 0x{:08X} uses unsupported PR_ATTACH_METHOD {}; payload skipped",
                            idx, node_id_u32, m
                        ));
                    }
                    None => {
                        is_skipped = true;
                        telemetry.record_error(format!(
                            "Attachment {} in msg 0x{:08X} missing PR_ATTACH_METHOD; payload skipped",
                            idx, node_id_u32
                        ));
                    }
                }

                let attach_info = PstAttachmentInfo {
                    attachment_index: idx as u32,
                    filename,
                    mime_type,
                    size_bytes,
                    is_embedded_message,
                    content_id,
                    is_skipped,
                };

                sink.on_attachment_header(folder_path, node_id_u32, &attach_info)?;
                telemetry.total_attachments = telemetry.total_attachments.saturating_add(1);

                if is_skipped {
                    telemetry.record_skip(size_bytes);
                    continue;
                }

                // Protect memory: attempt Attachment read ONLY after size & method bounds validation!
                match UnicodeAttachment::read(
                    msg.clone(),
                    row_nid.into(),
                    Some(PST_ATTACHMENT_PROPERTY_IDS),
                ) {
                    Ok(attachment) => {
                        if let Some(data) = attachment.data() {
                            match data {
                                AttachmentData::Binary(bin) => {
                                    let buf = bin.buffer();
                                    if buf.len() as u64 > options.max_attachment_size {
                                        telemetry.record_skip(buf.len() as u64);
                                        let reason = format!(
                                            "Attachment {} in msg 0x{:08X} actual payload size {} exceeds memory bound",
                                            idx, node_id_u32, buf.len()
                                        );
                                        sink.on_attachment_failure(
                                            folder_path,
                                            node_id_u32,
                                            &attach_info,
                                            &reason,
                                        )?;
                                        telemetry.record_error(reason);
                                    } else {
                                        if buf.len() as u64 != size_bytes {
                                            telemetry.record_error(format!(
                                                "Attachment {} in msg 0x{:08X} declared size {} but payload size is {}",
                                                idx,
                                                node_id_u32,
                                                size_bytes,
                                                buf.len()
                                            ));
                                        }
                                        sink.on_attachment_bytes(
                                            folder_path,
                                            node_id_u32,
                                            &attach_info,
                                            buf,
                                        )?;
                                        telemetry.total_bytes_streamed = telemetry
                                            .total_bytes_streamed
                                            .saturating_add(buf.len() as u64);
                                    }
                                }
                                AttachmentData::Message(_) => {
                                    telemetry.record_skip(size_bytes);
                                    let reason = format!(
                                        "Attachment {} in msg 0x{:08X} is embedded Message payload; recursion skipped",
                                        idx, node_id_u32
                                    );
                                    sink.on_attachment_failure(
                                        folder_path,
                                        node_id_u32,
                                        &attach_info,
                                        &reason,
                                    )?;
                                    telemetry.record_error(reason);
                                }
                            }
                        } else {
                            telemetry.record_skip(size_bytes);
                            let reason = format!(
                                "Attachment {} in msg 0x{:08X} has no readable payload",
                                idx, node_id_u32
                            );
                            sink.on_attachment_failure(
                                folder_path,
                                node_id_u32,
                                &attach_info,
                                &reason,
                            )?;
                            telemetry.record_error(reason);
                        }
                    }
                    Err(err) => {
                        telemetry.record_skip(size_bytes);
                        let reason = format!(
                            "Failed to read attachment {} in msg 0x{:08X}: {err}",
                            idx, node_id_u32
                        );
                        sink.on_attachment_failure(
                            folder_path,
                            node_id_u32,
                            &attach_info,
                            &reason,
                        )?;
                        telemetry.record_error(reason);
                    }
                }
            }
        }

        Ok(())
    }

    fn process_ansi_pst<S: PstStreamSink>(
        pst: AnsiPstFile,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
    ) -> io::Result<()> {
        let pst_rc = std::rc::Rc::new(pst);
        let store = match AnsiStore::read(pst_rc) {
            Ok(s) => s,
            Err(err) => {
                telemetry.record_error(format!("Failed to initialize ANSI Store: {err}"));
                telemetry.status = PstStatus::Failed;
                return Ok(());
            }
        };

        let mut visited_nodes = HashSet::new();
        let root_entry_id = match store.properties().ipm_sub_tree_entry_id() {
            Ok(eid) => eid,
            Err(_) => match store
                .properties()
                .make_entry_id(outlook_pst::ndb::node_id::NID_ROOT_FOLDER)
            {
                Ok(eid) => eid,
                Err(err) => {
                    telemetry
                        .record_error(format!("Failed to determine root folder entry id: {err}"));
                    telemetry.status = PstStatus::Failed;
                    return Ok(());
                }
            },
        };

        match AnsiFolder::read(store.clone(), &root_entry_id) {
            Ok(root_folder) => {
                Self::traverse_ansi_folder(
                    &store,
                    &root_folder,
                    "",
                    0,
                    &mut visited_nodes,
                    sink,
                    options,
                    telemetry,
                )?;
                if telemetry.total_folders == 0 {
                    telemetry
                        .record_error("Zero folders parsed from root folder hierarchy".to_string());
                    telemetry.status = PstStatus::Failed;
                }
            }
            Err(err) => {
                telemetry.record_error(format!("Failed to open root folder in ANSI PST: {err}"));
                telemetry.status = PstStatus::Failed;
            }
        }
        Ok(())
    }

    fn traverse_ansi_folder<S: PstStreamSink>(
        store: &std::rc::Rc<AnsiStore>,
        folder: &AnsiFolder,
        parent_path: &str,
        depth: usize,
        visited_nodes: &mut HashSet<u32>,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
    ) -> io::Result<()> {
        if depth > options.max_folder_depth {
            telemetry.record_error(format!(
                "Folder hierarchy depth limit ({}) exceeded at path: {}",
                options.max_folder_depth, parent_path
            ));
            telemetry.record_skip(0);
            return Ok(());
        }

        let props = folder.properties();
        let node_id_u32 = u32::from(props.node_id());
        if !visited_nodes.insert(node_id_u32) {
            telemetry.record_error(format!(
                "Cycle detected in folder node_id 0x{:08X} at path: {}",
                node_id_u32, parent_path
            ));
            telemetry.record_skip(0);
            return Ok(());
        }

        Self::do_traverse_ansi_folder(
            store,
            folder,
            parent_path,
            depth,
            visited_nodes,
            sink,
            options,
            telemetry,
            node_id_u32,
        )
    }

    fn do_traverse_ansi_folder<S: PstStreamSink>(
        store: &std::rc::Rc<AnsiStore>,
        folder: &AnsiFolder,
        parent_path: &str,
        depth: usize,
        visited_nodes: &mut HashSet<u32>,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
        node_id_u32: u32,
    ) -> io::Result<()> {
        let props = folder.properties();
        let folder_name = props.display_name().unwrap_or_else(|_| "Root".to_string());
        let current_path = if parent_path.is_empty() {
            folder_name.clone()
        } else {
            format!("{}/{}", parent_path, folder_name)
        };

        let subfolder_count = if props.has_sub_folders().unwrap_or(false) {
            folder
                .hierarchy_table()
                .map(|t| t.rows_matrix().count() as u32)
                .unwrap_or(0)
        } else {
            0
        };

        let content_count = props.content_count().unwrap_or(0) as u32;
        let unread_count = props.unread_count().unwrap_or(0) as u32;

        let folder_info = PstFolderInfo {
            node_id: node_id_u32,
            display_name: folder_name,
            path: current_path.clone(),
            subfolder_count,
            content_count,
            unread_count,
        };

        sink.on_folder(&folder_info)?;
        telemetry.total_folders = telemetry.total_folders.saturating_add(1);

        if let Some(contents_table) = folder.contents_table() {
            for row in contents_table.rows_matrix() {
                if Self::message_limit_reached(options, telemetry) {
                    break;
                }
                let row_nid = u32::from(row.id());
                if let Ok(entry_id) = store.properties().make_entry_id(row_nid.into()) {
                    match AnsiMessage::read(
                        store.clone(),
                        &entry_id,
                        Some(PST_MESSAGE_PROPERTY_IDS),
                    ) {
                        Ok(msg) => {
                            Self::process_ansi_message(
                                store,
                                msg,
                                row_nid,
                                &current_path,
                                sink,
                                options,
                                telemetry,
                            )?;
                        }
                        Err(err) => {
                            telemetry.record_error(format!(
                                "Failed to open message node 0x{:08X} in folder {}: {err}",
                                row_nid, current_path
                            ));
                            telemetry.record_skip(0);
                        }
                    }
                } else {
                    telemetry.record_error(format!(
                        "Failed to construct entry_id for message node 0x{:08X} in folder {}",
                        row_nid, current_path
                    ));
                    telemetry.record_skip(0);
                }
            }
        }

        if let Some(hierarchy_table) = folder.hierarchy_table() {
            for child_row in hierarchy_table.rows_matrix() {
                if telemetry.message_limit_reached {
                    break;
                }
                let child_nid = u32::from(child_row.id());
                if let Ok(entry_id) = store.properties().make_entry_id(child_nid.into()) {
                    match AnsiFolder::read(store.clone(), &entry_id) {
                        Ok(child_folder) => {
                            Self::traverse_ansi_folder(
                                store,
                                &child_folder,
                                &current_path,
                                depth + 1,
                                visited_nodes,
                                sink,
                                options,
                                telemetry,
                            )?;
                        }
                        Err(err) => {
                            telemetry.record_error(format!(
                                "Failed to read subfolder node 0x{:08X} in folder {}: {err}",
                                child_nid, current_path
                            ));
                            telemetry.record_skip(0);
                        }
                    }
                } else {
                    telemetry.record_error(format!(
                        "Failed to construct entry_id for subfolder node 0x{:08X} in folder {}",
                        child_nid, current_path
                    ));
                    telemetry.record_skip(0);
                }
            }
        }

        Ok(())
    }

    fn process_ansi_message<S: PstStreamSink>(
        _store: &std::rc::Rc<AnsiStore>,
        msg: std::rc::Rc<AnsiMessage>,
        node_id_u32: u32,
        folder_path: &str,
        sink: &mut S,
        options: &PstAdapterOptions,
        telemetry: &mut PstTelemetry,
    ) -> io::Result<()> {
        let props = msg.properties();
        // The contents-table row NID is authoritative. PidTagEntryId can be
        // absent or malformed and must never fabricate node 0 provenance.
        let internet_code_page = pst_internet_code_page(props.get(0x3FDE));
        record_code_page_problem(props, internet_code_page, node_id_u32, telemetry);

        let (subject, subj_trunc) = props
            .get(0x0037)
            .map(|v| extract_and_truncate_string_prop(v, 1024, internet_code_page))
            .unwrap_or((None, false));
        if subj_trunc {
            telemetry.record_truncation();
        }

        let (sender_name, sender_name_trunc) = props
            .get(0x0C1A)
            .map(|v| extract_and_truncate_string_prop(v, 1024, internet_code_page))
            .unwrap_or((None, false));
        if sender_name_trunc {
            telemetry.record_truncation();
        }

        let (sender_email, sender_email_trunc) = props
            .get(0x0C1F)
            .map(|v| extract_and_truncate_string_prop(v, 1024, internet_code_page))
            .unwrap_or((None, false));
        if sender_email_trunc {
            telemetry.record_truncation();
        }

        let message_class = props
            .message_class()
            .unwrap_or_else(|_| "IPM.Note".to_string());

        let creation_time = props.creation_time().ok().and_then(filetime_to_datetime);
        let last_modification_time = props
            .last_modification_time()
            .ok()
            .and_then(filetime_to_datetime);
        let client_submit_time = props
            .get(0x0039)
            .and_then(extract_time_prop)
            .and_then(filetime_to_datetime);
        let delivery_time = props
            .get(0x0E06)
            .and_then(extract_time_prop)
            .and_then(filetime_to_datetime);

        let (body_plain_preview, body_plain_truncated) = props
            .get(0x1000)
            .map(|v| {
                extract_and_truncate_string_prop(v, options.max_body_chars, internet_code_page)
            })
            .unwrap_or((None, false));
        if body_plain_truncated {
            telemetry.record_preview_truncation();
        }

        let (body_html_preview, body_html_truncated) = props
            .get(0x1013)
            .map(|v| {
                extract_and_truncate_string_prop(v, options.max_body_chars, internet_code_page)
            })
            .unwrap_or((None, false));
        if body_html_truncated {
            telemetry.record_preview_truncation();
        }

        let recipient_count = msg
            .recipient_table()
            .map(|t| t.rows_matrix().count() as u32)
            .unwrap_or(0);

        let attachment_count = msg
            .attachment_table()
            .map(|t| t.rows_matrix().count() as u32)
            .unwrap_or(0);

        let (canonical_node_id, canonical_entry_id) = authoritative_message_identity(node_id_u32);
        let msg_header = PstMessageHeader {
            node_id: canonical_node_id,
            entry_id_hex: canonical_entry_id,
            folder_path: folder_path.to_string(),
            message_class,
            subject,
            sender_name,
            sender_email,
            client_submit_time,
            delivery_time,
            creation_time,
            last_modification_time,
            body_plain_preview,
            body_html_preview,
            body_plain_truncated,
            body_html_truncated,
            recipient_count,
            attachment_count,
            has_attachments: attachment_count > 0,
            message_flags: props.message_flags().unwrap_or(0) as u32,
            internet_code_page,
        };

        sink.on_message_header(&msg_header)?;
        telemetry.total_messages = telemetry.total_messages.saturating_add(1);
        if let Some(body) = props
            .get(0x1000)
            .and_then(|value| property_text_ref(value, internet_code_page))
        {
            sink.on_message_body(folder_path, node_id_u32, PstBodyKind::PlainText, body)?;
        }
        if let Some(body) = props
            .get(0x1013)
            .and_then(|value| property_text_ref(value, internet_code_page))
        {
            sink.on_message_body(folder_path, node_id_u32, PstBodyKind::Html, body)?;
        }

        if let Some(recip_table) = msg.recipient_table() {
            for row in recip_table.rows_matrix() {
                let display_name = row
                    .columns(recip_table.context())
                    .ok()
                    .and_then(|cols| extract_col_string(&cols, recip_table.context(), 0x3001));
                let email_address = row
                    .columns(recip_table.context())
                    .ok()
                    .and_then(|cols| extract_col_string(&cols, recip_table.context(), 0x39FE));
                let recipient_type = row
                    .columns(recip_table.context())
                    .ok()
                    .and_then(|cols| extract_col_i32(&cols, recip_table.context(), 0x0C15))
                    .map(pst_recipient_type_label);
                let recip = PstRecipientInfo {
                    display_name,
                    email_address,
                    recipient_type,
                };
                sink.on_recipient(folder_path, node_id_u32, &recip)?;
                telemetry.total_recipients = telemetry.total_recipients.saturating_add(1);
            }
        }

        if let Some(attach_table) = msg.attachment_table() {
            for (idx, row) in attach_table.rows_matrix().enumerate() {
                let row_nid = u32::from(row.id());
                let cols_opt = row.columns(attach_table.context()).ok();

                let attach_method = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_i32(cols, attach_table.context(), 0x3705));

                let raw_size_i32 = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_i32(cols, attach_table.context(), 0x0E20));

                let declared_size_opt = match raw_size_i32 {
                    Some(s) if s >= 0 => Some(s as u64),
                    _ => None,
                };

                let filename = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_string(cols, attach_table.context(), 0x3707))
                    .or_else(|| {
                        cols_opt.as_ref().and_then(|cols| {
                            extract_col_string(cols, attach_table.context(), 0x3704)
                        })
                    });

                let mime_type = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_string(cols, attach_table.context(), 0x370E));

                let content_id = cols_opt
                    .as_ref()
                    .and_then(|cols| extract_col_string(cols, attach_table.context(), 0x3712));

                let is_embedded_message = attach_method == Some(5);
                let size_bytes = declared_size_opt.unwrap_or(0);
                let mut is_skipped = false;

                if declared_size_opt.is_none() {
                    is_skipped = true;
                    telemetry.record_error(format!(
                        "Attachment {} in msg 0x{:08X} has missing/negative size ({:?}); payload skipped",
                        idx, node_id_u32, raw_size_i32
                    ));
                } else if size_bytes > options.max_attachment_size {
                    is_skipped = true;
                    telemetry.record_error(format!(
                        "Attachment {} in msg 0x{:08X} size {} exceeds allocation limit {}; payload skipped",
                        idx, node_id_u32, size_bytes, options.max_attachment_size
                    ));
                }

                match attach_method {
                    Some(1) | Some(5) => {}
                    Some(m) => {
                        is_skipped = true;
                        telemetry.record_error(format!(
                            "Attachment {} in msg 0x{:08X} uses unsupported PR_ATTACH_METHOD {}; payload skipped",
                            idx, node_id_u32, m
                        ));
                    }
                    None => {
                        is_skipped = true;
                        telemetry.record_error(format!(
                            "Attachment {} in msg 0x{:08X} missing PR_ATTACH_METHOD; payload skipped",
                            idx, node_id_u32
                        ));
                    }
                }

                let attach_info = PstAttachmentInfo {
                    attachment_index: idx as u32,
                    filename,
                    mime_type,
                    size_bytes,
                    is_embedded_message,
                    content_id,
                    is_skipped,
                };

                sink.on_attachment_header(folder_path, node_id_u32, &attach_info)?;
                telemetry.total_attachments = telemetry.total_attachments.saturating_add(1);

                if is_skipped {
                    telemetry.record_skip(size_bytes);
                    continue;
                }

                match AnsiAttachment::read(
                    msg.clone(),
                    row_nid.into(),
                    Some(PST_ATTACHMENT_PROPERTY_IDS),
                ) {
                    Ok(attachment) => {
                        if let Some(data) = attachment.data() {
                            match data {
                                AttachmentData::Binary(bin) => {
                                    let buf = bin.buffer();
                                    if buf.len() as u64 > options.max_attachment_size {
                                        telemetry.record_skip(buf.len() as u64);
                                        let reason = format!(
                                            "Attachment {} in msg 0x{:08X} actual payload size {} exceeds memory bound",
                                            idx, node_id_u32, buf.len()
                                        );
                                        sink.on_attachment_failure(
                                            folder_path,
                                            node_id_u32,
                                            &attach_info,
                                            &reason,
                                        )?;
                                        telemetry.record_error(reason);
                                    } else {
                                        if buf.len() as u64 != size_bytes {
                                            telemetry.record_error(format!(
                                                "Attachment {} in msg 0x{:08X} declared size {} but payload size is {}",
                                                idx,
                                                node_id_u32,
                                                size_bytes,
                                                buf.len()
                                            ));
                                        }
                                        sink.on_attachment_bytes(
                                            folder_path,
                                            node_id_u32,
                                            &attach_info,
                                            buf,
                                        )?;
                                        telemetry.total_bytes_streamed = telemetry
                                            .total_bytes_streamed
                                            .saturating_add(buf.len() as u64);
                                    }
                                }
                                AttachmentData::Message(_) => {
                                    telemetry.record_skip(size_bytes);
                                    let reason = format!(
                                        "Attachment {} in msg 0x{:08X} is embedded Message payload; recursion skipped",
                                        idx, node_id_u32
                                    );
                                    sink.on_attachment_failure(
                                        folder_path,
                                        node_id_u32,
                                        &attach_info,
                                        &reason,
                                    )?;
                                    telemetry.record_error(reason);
                                }
                            }
                        } else {
                            telemetry.record_skip(size_bytes);
                            let reason = format!(
                                "Attachment {} in msg 0x{:08X} has no readable payload",
                                idx, node_id_u32
                            );
                            sink.on_attachment_failure(
                                folder_path,
                                node_id_u32,
                                &attach_info,
                                &reason,
                            )?;
                            telemetry.record_error(reason);
                        }
                    }
                    Err(err) => {
                        telemetry.record_skip(size_bytes);
                        let reason = format!(
                            "Failed to read attachment {} in msg 0x{:08X}: {err}",
                            idx, node_id_u32
                        );
                        sink.on_attachment_failure(
                            folder_path,
                            node_id_u32,
                            &attach_info,
                            &reason,
                        )?;
                        telemetry.record_error(reason);
                    }
                }
            }
        }

        Ok(())
    }

    fn message_limit_reached(options: &PstAdapterOptions, telemetry: &mut PstTelemetry) -> bool {
        let Some(limit) = options.max_messages else {
            return false;
        };
        if telemetry.total_messages < limit {
            return false;
        }
        if !telemetry.message_limit_reached {
            telemetry.message_limit_reached = true;
            if telemetry.status != PstStatus::Failed {
                telemetry.status = PstStatus::Partial;
            }
        }
        true
    }
}

fn authoritative_message_identity(row_node_id: u32) -> (u32, String) {
    (row_node_id, format!("0x{row_node_id:08X}"))
}

fn extract_and_truncate_string_prop(
    val: &outlook_pst::ltp::prop_context::PropertyValue,
    max_chars: usize,
    code_page: Option<u16>,
) -> (Option<String>, bool) {
    match val {
        outlook_pst::ltp::prop_context::PropertyValue::String8(value) => {
            decode_codepage_preview(value.buffer(), code_page, max_chars)
        }
        outlook_pst::ltp::prop_context::PropertyValue::Binary(value) => {
            decode_codepage_preview(value.buffer(), code_page, max_chars)
        }
        outlook_pst::ltp::prop_context::PropertyValue::Unicode(value) => {
            let mut chars = char::decode_utf16(value.buffer().iter().copied())
                .map(|decoded| decoded.unwrap_or(char::REPLACEMENT_CHARACTER));
            let bounded = chars.by_ref().take(max_chars).collect::<String>();
            let truncated = chars.next().is_some();
            (Some(bounded), truncated)
        }
        _ => (None, false),
    }
}

fn decode_codepage_preview(
    bytes: &[u8],
    code_page: Option<u16>,
    max_chars: usize,
) -> (Option<String>, bool) {
    // Four source bytes per requested character covers UTF-8 and the Windows
    // encodings supported by codepage-strings, plus a small boundary margin.
    let prefix_len = max_chars
        .saturating_mul(4)
        .saturating_add(8)
        .min(bytes.len());
    let prefix = &bytes[..prefix_len];
    let decoded = codepage_strings::Coding::new(code_page.unwrap_or(1252))
        .map(|coding| coding.decode_lossy(prefix))
        .unwrap_or_else(|_| String::from_utf8_lossy(prefix));
    let mut chars = decoded.chars();
    let bounded = chars.by_ref().take(max_chars).collect::<String>();
    let truncated = prefix_len < bytes.len() || chars.next().is_some();
    (Some(bounded), truncated)
}

fn pst_internet_code_page(
    value: Option<&outlook_pst::ltp::prop_context::PropertyValue>,
) -> Option<u16> {
    match value {
        Some(outlook_pst::ltp::prop_context::PropertyValue::Integer32(value)) => {
            u16::try_from(*value).ok()
        }
        Some(outlook_pst::ltp::prop_context::PropertyValue::Integer16(value)) => {
            u16::try_from(*value).ok()
        }
        _ => None,
    }
}

fn record_code_page_problem(
    properties: &outlook_pst::messaging::message::MessageProperties,
    code_page: Option<u16>,
    node_id: u32,
    telemetry: &mut PstTelemetry,
) {
    let has_non_ascii_legacy_text = [0x0037, 0x0C1A, 0x0C1F, 0x1000, 0x1013]
        .iter()
        .filter_map(|property_id| properties.get(*property_id))
        .any(|value| match value {
            outlook_pst::ltp::prop_context::PropertyValue::String8(value) => {
                !value.buffer().is_ascii()
            }
            outlook_pst::ltp::prop_context::PropertyValue::Binary(value) => {
                !value.buffer().is_ascii()
            }
            _ => false,
        });
    record_code_page_issue(has_non_ascii_legacy_text, code_page, node_id, telemetry);
}

fn record_code_page_issue(
    has_non_ascii_legacy_text: bool,
    code_page: Option<u16>,
    node_id: u32,
    telemetry: &mut PstTelemetry,
) {
    if !has_non_ascii_legacy_text {
        return;
    }
    match code_page {
        Some(code_page) if codepage_strings::Coding::new(code_page).is_err() => {
            telemetry.record_error(format!(
                "Message 0x{node_id:08X} uses unsupported Internet code page {code_page}; legacy text is preserved with replacement decoding"
            ));
        }
        None => telemetry.record_error(format!(
            "Message 0x{node_id:08X} contains non-ASCII legacy text without PidTagInternetCodepage; Windows-1252 fallback decoding was used"
        )),
        Some(_) => {}
    }
}

fn property_text_ref(
    value: &outlook_pst::ltp::prop_context::PropertyValue,
    code_page: Option<u16>,
) -> Option<PstTextRef<'_>> {
    match value {
        outlook_pst::ltp::prop_context::PropertyValue::String8(text) => {
            Some(PstTextRef::String8(text.buffer(), code_page))
        }
        outlook_pst::ltp::prop_context::PropertyValue::Unicode(text) => {
            Some(PstTextRef::Unicode(text.buffer()))
        }
        outlook_pst::ltp::prop_context::PropertyValue::Binary(binary) => {
            Some(PstTextRef::Binary(binary.buffer(), code_page))
        }
        _ => None,
    }
}

fn extract_time_prop(val: &outlook_pst::ltp::prop_context::PropertyValue) -> Option<i64> {
    match val {
        outlook_pst::ltp::prop_context::PropertyValue::Time(t) => Some(*t),
        _ => None,
    }
}

fn extract_col_string(
    cols: &[Option<outlook_pst::ltp::table_context::TableRowColumnValue>],
    context: &outlook_pst::ltp::table_context::TableContextInfo,
    prop_id: u16,
) -> Option<String> {
    for (idx, desc) in context.columns().iter().enumerate() {
        if desc.prop_id() == prop_id {
            if let Some(Some(outlook_pst::ltp::table_context::TableRowColumnValue::Small(pv))) =
                cols.get(idx)
            {
                return match pv {
                    outlook_pst::ltp::prop_context::PropertyValue::String8(s) => {
                        Some(s.to_string())
                    }
                    outlook_pst::ltp::prop_context::PropertyValue::Unicode(s) => {
                        Some(s.to_string())
                    }
                    _ => None,
                };
            }
        }
    }
    None
}

fn extract_col_i32(
    cols: &[Option<outlook_pst::ltp::table_context::TableRowColumnValue>],
    context: &outlook_pst::ltp::table_context::TableContextInfo,
    prop_id: u16,
) -> Option<i32> {
    for (idx, desc) in context.columns().iter().enumerate() {
        if desc.prop_id() == prop_id {
            if let Some(Some(outlook_pst::ltp::table_context::TableRowColumnValue::Small(
                outlook_pst::ltp::prop_context::PropertyValue::Integer32(i),
            ))) = cols.get(idx)
            {
                return Some(*i);
            }
        }
    }
    None
}

fn pst_recipient_type_label(value: i32) -> String {
    match value {
        1 => "to".to_string(),
        2 => "cc".to_string(),
        3 => "bcc".to_string(),
        other => format!("unknown ({other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pst_format_detection_unknown_magic() {
        let dummy_data = b"NOT_A_PST_HEADER_DATA";
        assert_eq!(
            PstParserAdapter::detect_format(dummy_data),
            PstEncodingFormat::Unknown
        );
    }

    #[test]
    fn test_pst_format_detection_undocumented_version_rejected() {
        let mut header = vec![0u8; 64];
        header[0..4].copy_from_slice(b"!BDN");
        header[10] = 99; // Undocumented version
        header[11] = 0;
        assert_eq!(
            PstParserAdapter::detect_format(&header),
            PstEncodingFormat::Unknown
        );
    }

    #[test]
    fn test_pst_format_detection_unicode() {
        let mut header = vec![0u8; 64];
        header[0..4].copy_from_slice(b"!BDN");
        header[10] = 23;
        header[11] = 0;
        assert_eq!(
            PstParserAdapter::detect_format(&header),
            PstEncodingFormat::Unicode
        );
    }

    #[test]
    fn test_pst_format_detection_ansi() {
        let mut header = vec![0u8; 64];
        header[0..4].copy_from_slice(b"!BDN");
        header[10] = 14;
        header[11] = 0;
        assert_eq!(
            PstParserAdapter::detect_format(&header),
            PstEncodingFormat::Ansi
        );
    }

    #[test]
    fn test_filetime_conversion() {
        let ft: i64 = 134116896000000000;
        let dt = filetime_to_datetime(ft);
        assert!(dt.is_some());
        let dt_val = dt.unwrap();
        assert_eq!(dt_val.format("%Y-%m-%d").to_string(), "2025-12-31");
    }

    #[test]
    fn test_telemetry_error_and_skip_bounding() {
        let mut telemetry = PstTelemetry::default();
        for i in 0..100 {
            telemetry.record_error(format!("Error sample {}", i));
        }
        telemetry.record_skip(1024);
        assert_eq!(telemetry.total_errors, 100);
        assert_eq!(telemetry.error_samples.len(), 50);
        assert_eq!(telemetry.errors_omitted, 50);
        assert_eq!(telemetry.error_samples[0], "Error sample 0");
        assert_eq!(telemetry.error_samples[49], "Error sample 49");
        assert_eq!(telemetry.skipped_items, 1);
        assert_eq!(telemetry.skipped_bytes, 1024);
        assert_eq!(telemetry.status, PstStatus::Partial);
    }

    #[test]
    fn test_memory_counting_sink_behavior() {
        let mut sink = MemoryCountingSink::new();
        let folder = PstFolderInfo {
            node_id: 1,
            display_name: "Inbox".to_string(),
            path: "Inbox".to_string(),
            subfolder_count: 0,
            content_count: 1,
            unread_count: 0,
        };
        let msg = PstMessageHeader {
            node_id: 2,
            entry_id_hex: "0x02".to_string(),
            folder_path: "Inbox".to_string(),
            message_class: "IPM.Note".to_string(),
            subject: Some("Test".to_string()),
            sender_name: None,
            sender_email: None,
            client_submit_time: None,
            delivery_time: None,
            creation_time: None,
            last_modification_time: None,
            body_plain_preview: Some("Hello".to_string()),
            body_html_preview: None,
            body_plain_truncated: false,
            body_html_truncated: false,
            recipient_count: 0,
            attachment_count: 0,
            has_attachments: false,
            message_flags: 0,
            internet_code_page: Some(1252),
        };
        sink.on_folder(&folder).unwrap();
        sink.on_message_header(&msg).unwrap();
        assert_eq!(sink.folders.len(), 1);
        assert_eq!(sink.message_headers.len(), 1);
    }

    #[test]
    fn test_negative_and_missing_size_attachment_skipping() {
        let mut telemetry = PstTelemetry::default();
        let raw_negative_size: Option<i32> = Some(-500);
        let declared_size_opt = match raw_negative_size {
            Some(s) if s >= 0 => Some(s as u64),
            _ => None,
        };
        assert!(declared_size_opt.is_none());
        telemetry.record_error("Negative attachment size".to_string());
        telemetry.record_skip(0);
        assert_eq!(telemetry.status, PstStatus::Partial);
        assert_eq!(telemetry.skipped_items, 1);
    }

    #[test]
    fn message_limit_is_unavailable_by_default_and_does_not_truncate() {
        let options = PstAdapterOptions::default();
        let mut telemetry = PstTelemetry {
            total_messages: u64::MAX,
            ..PstTelemetry::default()
        };
        assert!(!PstParserAdapter::message_limit_reached(
            &options,
            &mut telemetry
        ));
        assert!(!telemetry.message_limit_reached);
        assert_eq!(telemetry.status, PstStatus::Recognized);
    }

    #[test]
    fn examiner_message_limit_marks_partial_at_exact_boundary() {
        let options = PstAdapterOptions {
            max_messages: Some(3),
            ..PstAdapterOptions::default()
        };
        let mut below = PstTelemetry {
            total_messages: 2,
            ..PstTelemetry::default()
        };
        assert!(!PstParserAdapter::message_limit_reached(
            &options, &mut below
        ));
        assert_eq!(below.status, PstStatus::Recognized);

        below.total_messages = 3;
        assert!(PstParserAdapter::message_limit_reached(
            &options, &mut below
        ));
        assert!(below.message_limit_reached);
        assert_eq!(below.status, PstStatus::Partial);
    }

    #[test]
    fn bounded_body_preview_is_not_forensic_omission() {
        let mut telemetry = PstTelemetry::default();
        telemetry.record_preview_truncation();
        assert_eq!(telemetry.coverage_truncations, 0);
        assert_eq!(telemetry.preview_truncations, 1);
        assert_eq!(telemetry.status, PstStatus::Recognized);
        assert_eq!(telemetry.skipped_items, 0);
    }

    #[test]
    fn binary_pid_tag_html_uses_cp1252_and_preserves_complete_body_bytes() {
        let raw_html = b"<p>Price: \x80</p>".to_vec();
        let property = outlook_pst::ltp::prop_context::PropertyValue::Binary(
            outlook_pst::ltp::prop_context::BinaryValue::new(raw_html.clone()),
        );

        let (preview, truncated) = extract_and_truncate_string_prop(&property, 128, Some(1252));
        assert_eq!(preview.as_deref(), Some("<p>Price: €</p>"));
        assert!(!truncated);

        match property_text_ref(&property, Some(1252)).unwrap() {
            PstTextRef::Binary(bytes, code_page) => {
                assert_eq!(bytes, raw_html.as_slice());
                assert_eq!(code_page, Some(1252));
            }
            unexpected => panic!("expected complete binary HTML body, got {unexpected:?}"),
        }

        let mut telemetry = PstTelemetry::default();
        record_code_page_issue(true, Some(1252), 0x1224, &mut telemetry);
        assert_eq!(telemetry.status, PstStatus::Recognized);
        assert_eq!(telemetry.total_errors, 0);
        assert_eq!(telemetry.skipped_items, 0);
    }

    #[test]
    fn binary_html_preview_limit_does_not_mark_complete_body_omitted() {
        let raw_html = b"<p>complete body</p>".to_vec();
        let property = outlook_pst::ltp::prop_context::PropertyValue::Binary(
            outlook_pst::ltp::prop_context::BinaryValue::new(raw_html.clone()),
        );
        let (preview, truncated) = extract_and_truncate_string_prop(&property, 3, Some(1252));
        assert_eq!(preview.as_deref(), Some("<p>"));
        assert!(truncated);

        let mut telemetry = PstTelemetry::default();
        telemetry.record_preview_truncation();
        assert_eq!(telemetry.status, PstStatus::Recognized);
        assert_eq!(telemetry.coverage_truncations, 0);
        assert_eq!(telemetry.preview_truncations, 1);
        assert_eq!(telemetry.skipped_items, 0);
        match property_text_ref(&property, Some(1252)).unwrap() {
            PstTextRef::Binary(bytes, _) => assert_eq!(bytes, raw_html.as_slice()),
            unexpected => panic!("expected complete binary HTML body, got {unexpected:?}"),
        }
    }

    #[test]
    fn unsupported_code_page_uses_replacement_and_records_partial_coverage() {
        let (decoded, truncated) = decode_codepage_preview(&[0x80], Some(u16::MAX), 16);
        assert_eq!(decoded.as_deref(), Some("�"));
        assert!(!truncated);

        let mut telemetry = PstTelemetry::default();
        record_code_page_issue(true, Some(u16::MAX), 0x42, &mut telemetry);
        assert_eq!(telemetry.status, PstStatus::Partial);
        assert_eq!(telemetry.total_errors, 1);
        assert!(telemetry.error_samples[0].contains("unsupported Internet code page 65535"));
        assert!(telemetry.error_samples[0].contains("0x00000042"));
    }

    #[test]
    fn missing_code_page_uses_cp1252_fallback_and_records_partial_coverage() {
        let (decoded, truncated) = decode_codepage_preview(&[0x80], None, 16);
        assert_eq!(decoded.as_deref(), Some("€"));
        assert!(!truncated);

        let mut telemetry = PstTelemetry::default();
        record_code_page_issue(true, None, 0x43, &mut telemetry);
        assert_eq!(telemetry.status, PstStatus::Partial);
        assert_eq!(telemetry.total_errors, 1);
        assert!(telemetry.error_samples[0].contains("without PidTagInternetCodepage"));
        assert!(telemetry.error_samples[0].contains("Windows-1252 fallback"));
    }

    #[test]
    fn contents_table_row_nid_is_the_only_canonical_message_identity_input() {
        let (node_id, entry_id_hex) = authoritative_message_identity(0xA1B2_C3E4);
        assert_eq!(node_id, 0xA1B2_C3E4);
        assert_eq!(entry_id_hex, "0xA1B2C3E4");
    }

    #[test]
    fn property_allow_lists_include_every_property_dereferenced_after_filtering() {
        for required in [0x001A, 0x0037, 0x0E07, 0x0FFF, 0x1000, 0x1013, 0x3FDE] {
            assert!(PST_MESSAGE_PROPERTY_IDS.contains(&required));
        }
        assert_eq!(PST_ATTACHMENT_PROPERTY_IDS, &[0x3701, 0x3705]);
    }
}
