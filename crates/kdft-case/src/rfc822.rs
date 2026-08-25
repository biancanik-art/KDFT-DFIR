//! Bounded RFC 5322 / MIME message parser.
//!
//! The input is consumed to EOF so the raw-message digest and byte count remain exact.
//! MIME parsing operates on a bounded prefix; an over-limit message is explicitly
//! reported as `limit_reached` rather than silently presenting partial coverage.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use encoding_rs::Encoding;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{self, Read};

/// Default maximum line length allowed in header parsing before truncation (16 KiB).
pub const DEFAULT_MAX_HEADER_LINE_BYTES: usize = 16_384;

/// Maximum characters retained in the nonblank-line body preview buffer.
pub const MAX_BODY_PREVIEW_CHARS: usize = 1_200;

/// Defensive cumulative cap for any retained target header value.
pub const MAX_RETAINED_HEADER_VALUE_BYTES: usize = 64 * 1024;

/// Maximum diagnostic strings retained in memory and persisted by callers.
pub const MAX_DIAGNOSTICS: usize = 32;

const MAX_DIAGNOSTIC_CHARS: usize = 256;
const MAX_CONFIG_HEADER_LINE_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BODY_PREVIEW_CHARS: usize = 64 * 1024;
const MAX_MIME_CAPTURE_BYTES: usize = 128 * 1024 * 1024;
const MAX_MIME_PARTS: usize = 4_096;
const MAX_MIME_DEPTH: usize = 32;
const MAX_HEADERS_PER_PART: usize = 512;
const MAX_HEADER_BLOCK_BYTES: usize = 2 * 1024 * 1024;
/// Maximum decoded UTF-8 text retained for search across all MIME bodies in one message.
pub const MAX_SEARCHABLE_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_BOUNDARY_BYTES: usize = 200;

/// Overall parser coverage status. Presentation-preview truncation does not make
/// an otherwise complete parse incomplete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rfc822ParseStatus {
    Complete,
    Partial,
    Unsupported,
    LimitReached,
    #[default]
    NotRecognized,
}

impl Rfc822ParseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::LimitReached => "limit_reached",
            Self::NotRecognized => "not_recognized",
        }
    }
}

/// Per-part MIME provenance. Offsets are absolute byte offsets in the original
/// RFC 5322 message, with end offsets exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rfc822PartMetadata {
    pub index: usize,
    pub parent_index: Option<usize>,
    pub depth: usize,
    pub content_type: String,
    pub charset: Option<String>,
    pub transfer_encoding: String,
    pub disposition: Option<String>,
    pub filename: Option<String>,
    pub filename_path_risks: Vec<String>,
    pub is_attachment: bool,
    pub header_start: u64,
    pub header_end: u64,
    pub body_start: u64,
    pub body_end: u64,
    pub raw_body_size: u64,
    pub raw_body_sha256: Option<String>,
    pub decoded_size: Option<u64>,
    pub decoded_sha256: Option<String>,
    pub decoded_content_complete: bool,
    pub text_preview: Option<String>,
    pub text_preview_truncated: bool,
    pub status: Rfc822ParseStatus,
    pub diagnostics: Vec<String>,
}

/// Exact decoded text retained for indexing. `content` is never normalized;
/// preview normalization is deliberately kept separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rfc822TextSegment {
    pub part_index: usize,
    pub content_type: String,
    pub charset: Option<String>,
    pub transfer_encoding: String,
    pub raw_header_start: u64,
    pub raw_header_end: u64,
    pub raw_body_start: u64,
    pub raw_body_end: u64,
    pub decoded_size: u64,
    pub decoded_sha256: String,
    pub content_complete: bool,
    pub content: String,
}

/// Parsed RFC 822 / EML metadata and streaming statistics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rfc822Metadata {
    /// Sender address ("From" header).
    pub from: Option<String>,
    /// Primary recipient address(es) ("To" header).
    pub to: Option<String>,
    /// Carbon copy recipient(s) ("Cc" header).
    pub cc: Option<String>,
    /// Blind carbon copy recipient(s) ("Bcc" header).
    pub bcc: Option<String>,
    /// Message subject ("Subject" header).
    pub subject: Option<String>,
    /// Message date ("Date" header).
    pub date: Option<String>,
    /// Unique Message-ID ("Message-ID" header).
    pub message_id: Option<String>,
    /// Reply address ("Reply-To" header).
    pub reply_to: Option<String>,
    /// Message reference ("In-Reply-To" header).
    pub in_reply_to: Option<String>,

    /// Conservatively extracted mailbox addr-spec values from address headers.
    pub from_addresses: Vec<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub reply_to_addresses: Vec<String>,
    /// Syntactically valid `<id-left@id-right>` tokens retained from Message-ID headers.
    pub message_ids: Vec<String>,
    /// RFC 2822 date normalized to UTC when the declared value was valid.
    pub date_utc: Option<String>,

    /// Retained nonblank-line body preview (up to 1,200 Unicode characters).
    pub body_preview: String,

    /// MIME part from which `body_preview` was selected.
    pub body_preview_part_index: Option<usize>,

    /// Exact SHA-256 of every raw byte consumed from the message stream.
    pub raw_message_sha256: Option<String>,

    /// MIME parsing was limited to a bounded prefix while raw hashing continued.
    pub message_capture_truncated: bool,

    /// Overall MIME/RFC 5322 parse coverage.
    pub parser_status: Rfc822ParseStatus,

    /// MIME part inventory with raw offsets and raw/decoded digests.
    pub mime_parts: Vec<Rfc822PartMetadata>,

    /// Bounded exact decoded body text for search-segment persistence.
    pub searchable_text_segments: Vec<Rfc822TextSegment>,

    pub attachment_count: usize,
    pub unsupported_part_count: usize,
    pub partial_part_count: usize,
    pub limit_hit_count: usize,
    pub warning_count: usize,

    /// Total bytes consumed from the underlying reader.
    pub bytes_consumed: u64,

    /// Whether the message was recognized as containing valid RFC 822 structure or headers.
    pub recognized_status: bool,

    /// True if the header section terminated normally with a blank line separator.
    pub header_complete: bool,

    /// True if any header line exceeded size limits and was truncated.
    pub header_truncated: bool,

    /// True if body preview reached the 1,200 character cap.
    pub body_truncated: bool,

    /// True if a pathological overlong header line was detected.
    pub pathological_header_detected: bool,

    /// Count of malformed lines encountered during header parsing.
    pub malformed_lines_count: usize,

    /// Count of headers parsed that were not among the 9 target metadata fields.
    pub skipped_headers_count: usize,

    /// Total count of errors/warnings encountered during parsing.
    pub error_count: usize,

    /// Diagnostic warnings and notices recorded during parsing.
    pub diagnostics: Vec<String>,

    /// Diagnostics suppressed after the bounded retained list became full.
    pub diagnostics_omitted_count: usize,
}

impl Rfc822Metadata {
    /// Returns true if any targeted header field or non-empty body preview was extracted.
    pub fn is_recognized(&self) -> bool {
        self.recognized_status
    }

    /// Returns the parsed value for a specific header by case-insensitive header name.
    pub fn get_header(&self, name: &str) -> Option<&str> {
        match name.to_ascii_lowercase().as_str() {
            "from" => self.from.as_deref(),
            "to" => self.to.as_deref(),
            "cc" => self.cc.as_deref(),
            "bcc" => self.bcc.as_deref(),
            "subject" => self.subject.as_deref(),
            "date" => self.date.as_deref(),
            "message-id" => self.message_id.as_deref(),
            "reply-to" => self.reply_to.as_deref(),
            "in-reply-to" => self.in_reply_to.as_deref(),
            _ => None,
        }
    }

    /// Returns true if at least one of the 9 target metadata fields is present.
    pub fn has_any_target_header(&self) -> bool {
        self.from.is_some()
            || self.to.is_some()
            || self.cc.is_some()
            || self.bcc.is_some()
            || self.subject.is_some()
            || self.date.is_some()
            || self.message_id.is_some()
            || self.reply_to.is_some()
            || self.in_reply_to.is_some()
    }
}

/// Options for configuring the RFC 822 parser execution.
#[derive(Debug, Clone)]
pub struct Rfc822ParserOptions {
    /// Maximum bytes allowed for a single header line before truncation (default: 16,384).
    pub max_header_line_bytes: usize,
    /// Maximum characters stored in nonblank-line body preview (default: 1,200).
    pub max_body_preview_chars: usize,
}

impl Default for Rfc822ParserOptions {
    fn default() -> Self {
        Self {
            max_header_line_bytes: DEFAULT_MAX_HEADER_LINE_BYTES,
            max_body_preview_chars: MAX_BODY_PREVIEW_CHARS,
        }
    }
}

/// Parse RFC 822 / EML stream with default options.
pub fn parse_rfc822<R: Read>(reader: R) -> io::Result<Rfc822Metadata> {
    parse_rfc822_with_options(reader, &Rfc822ParserOptions::default())
}

/// Internal parser state machine step.
enum ParserState {
    Headers,
    Body,
    FastForward,
}

struct PendingHeader {
    name: String,
    value: String,
}

/// Parse RFC 822 / EML stream with explicit configuration options.
pub fn parse_rfc822_with_options<R: Read>(
    mut reader: R,
    options: &Rfc822ParserOptions,
) -> io::Result<Rfc822Metadata> {
    if options.max_header_line_bytes == 0
        || options.max_header_line_bytes > MAX_CONFIG_HEADER_LINE_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("max_header_line_bytes must be between 1 and {MAX_CONFIG_HEADER_LINE_BYTES}"),
        ));
    }
    if options.max_body_preview_chars == 0
        || options.max_body_preview_chars > MAX_CONFIG_BODY_PREVIEW_CHARS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("max_body_preview_chars must be between 1 and {MAX_CONFIG_BODY_PREVIEW_CHARS}"),
        ));
    }
    let mut meta = Rfc822Metadata::default();
    let mut state = ParserState::Headers;
    let mut pending_header: Option<PendingHeader> = None;
    let mut line_buf = Vec::with_capacity(512);
    let mut seen_cr = false;
    let mut line_truncated = false;
    let mut body_chars_count = 0usize;
    let mut chunk = [0u8; 8192];
    let mut raw_message = Vec::new();
    let mut raw_message_hasher = Sha256::new();
    let mut capture_truncated = false;

    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        meta.bytes_consumed = meta.bytes_consumed.saturating_add(n as u64);
        raw_message_hasher.update(&chunk[..n]);
        let remaining = MAX_MIME_CAPTURE_BYTES.saturating_sub(raw_message.len());
        let retained = remaining.min(n);
        raw_message.extend_from_slice(&chunk[..retained]);
        capture_truncated |= retained != n;

        if matches!(state, ParserState::FastForward) {
            continue;
        }

        for &b in &chunk[..n] {
            if seen_cr {
                seen_cr = false;
                if b == b'\n' {
                    process_line(
                        &line_buf,
                        &mut state,
                        &mut pending_header,
                        &mut meta,
                        options,
                        &mut body_chars_count,
                    );
                    line_buf.clear();
                    line_truncated = false;
                    if matches!(state, ParserState::FastForward) {
                        break;
                    }
                    continue;
                } else {
                    push_byte(
                        &mut line_buf,
                        b'\r',
                        options.max_header_line_bytes,
                        &mut line_truncated,
                        &state,
                        &mut meta,
                    );
                }
            }

            if b == b'\r' {
                seen_cr = true;
            } else if b == b'\n' {
                process_line(
                    &line_buf,
                    &mut state,
                    &mut pending_header,
                    &mut meta,
                    options,
                    &mut body_chars_count,
                );
                line_buf.clear();
                line_truncated = false;
                if matches!(state, ParserState::FastForward) {
                    break;
                }
            } else {
                push_byte(
                    &mut line_buf,
                    b,
                    options.max_header_line_bytes,
                    &mut line_truncated,
                    &state,
                    &mut meta,
                );
            }
        }
    }

    if seen_cr {
        push_byte(
            &mut line_buf,
            b'\r',
            options.max_header_line_bytes,
            &mut line_truncated,
            &state,
            &mut meta,
        );
    }

    if !line_buf.is_empty() {
        process_line(
            &line_buf,
            &mut state,
            &mut pending_header,
            &mut meta,
            options,
            &mut body_chars_count,
        );
    }

    if matches!(state, ParserState::Headers) {
        emit_pending_header(pending_header.take(), &mut meta);
        if !meta.header_complete && meta.bytes_consumed > 0 {
            meta.error_count = meta.error_count.saturating_add(1);
            record_diagnostic(
                &mut meta,
                "Missing header-body separator before end of stream",
            );
        }
    }

    meta.raw_message_sha256 = Some(hex_digest(raw_message_hasher.finalize()));
    meta.message_capture_truncated = capture_truncated;
    // The first pass exists only to consume the stream with strict line bounds.
    // MIME-aware parsing below is authoritative, so reset first-pass semantic
    // counters and preview data instead of double-counting the same header fault.
    meta.header_complete = false;
    meta.header_truncated = false;
    meta.pathological_header_detected = false;
    meta.malformed_lines_count = 0;
    meta.skipped_headers_count = 0;
    meta.error_count = 0;
    meta.diagnostics.clear();
    meta.diagnostics_omitted_count = 0;
    meta.body_preview.clear();
    meta.body_truncated = false;
    meta.body_preview_part_index = None;
    apply_mime_semantics(&raw_message, !capture_truncated, &mut meta, options);
    meta.recognized_status = meta.has_any_target_header()
        || !meta.mime_parts.is_empty()
            && meta
                .mime_parts
                .first()
                .is_some_and(|part| part.content_type != "text/plain");
    if !meta.recognized_status {
        meta.parser_status = Rfc822ParseStatus::NotRecognized;
    }
    Ok(meta)
}

fn push_byte(
    line_buf: &mut Vec<u8>,
    b: u8,
    max_bytes: usize,
    line_truncated: &mut bool,
    state: &ParserState,
    meta: &mut Rfc822Metadata,
) {
    if *line_truncated {
        return;
    }
    if line_buf.len() < max_bytes {
        line_buf.push(b);
    } else {
        *line_truncated = true;
        if matches!(state, ParserState::Headers) {
            meta.pathological_header_detected = true;
            meta.header_truncated = true;
            meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
            meta.error_count = meta.error_count.saturating_add(1);
            record_diagnostic(
                meta,
                format!(
                    "Header line exceeded limit of {} bytes; truncating line",
                    max_bytes
                ),
            );
        }
    }
}

fn process_line(
    line_buf: &[u8],
    state: &mut ParserState,
    pending_header: &mut Option<PendingHeader>,
    meta: &mut Rfc822Metadata,
    options: &Rfc822ParserOptions,
    body_chars_count: &mut usize,
) {
    match state {
        ParserState::Headers => {
            if line_buf.is_empty() {
                emit_pending_header(pending_header.take(), meta);
                meta.header_complete = true;
                *state = ParserState::Body;
            } else if line_buf[0] == b' ' || line_buf[0] == b'\t' {
                if let Some(pending) = pending_header {
                    let (line_str, valid_utf8) = bytes_to_str(line_buf);
                    if !valid_utf8 {
                        meta.error_count = meta.error_count.saturating_add(1);
                        record_diagnostic(
                            meta,
                            "Non-UTF-8 bytes encountered in folded header line",
                        );
                    }
                    let trimmed = line_str.trim_start_matches([' ', '\t']);
                    append_bounded_header_value(
                        &mut pending.value,
                        trimmed,
                        " ",
                        options.max_header_line_bytes,
                        meta,
                        "Folded header value exceeded the retained-value limit",
                    );
                } else {
                    meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
                    meta.error_count = meta.error_count.saturating_add(1);
                    record_diagnostic(meta, "Orphaned folded header line encountered");
                }
            } else {
                let colon_pos = line_buf.iter().position(|&b| b == b':');
                if let Some(idx) = colon_pos {
                    emit_pending_header(pending_header.take(), meta);
                    let (name_str, name_utf8) = bytes_to_str(&line_buf[..idx]);
                    let (val_str, val_utf8) = bytes_to_str(&line_buf[idx + 1..]);
                    if !name_utf8 || !val_utf8 {
                        meta.error_count = meta.error_count.saturating_add(1);
                        record_diagnostic(meta, "Non-UTF-8 bytes encountered in header field");
                    }
                    let name = name_str.trim().to_string();
                    let val = val_str.trim_start_matches([' ', '\t']).to_string();
                    *pending_header = Some(PendingHeader { name, value: val });
                } else {
                    let (line_str, _) = bytes_to_str(line_buf);
                    let recovered_empty_target = pending_header
                        .as_mut()
                        .filter(|pending| {
                            pending.value.is_empty() && is_target_header(&pending.name)
                        })
                        .map(|pending| {
                            append_bounded_header_value(
                                &mut pending.value,
                                line_str.trim(),
                                "",
                                options.max_header_line_bytes,
                                meta,
                                "Recovered unindented header value exceeded the retained-value limit",
                            );
                        })
                        .is_some();
                    meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
                    meta.error_count = meta.error_count.saturating_add(1);
                    if recovered_empty_target {
                        record_diagnostic(
                            meta,
                            "Recovered an unindented value following an empty target header",
                        );
                    } else {
                        emit_pending_header(pending_header.take(), meta);
                        record_diagnostic(
                            meta,
                            format!("Malformed header line (missing colon): {line_str}"),
                        );
                    }
                }
            }
        }
        ParserState::Body => {
            let (line_str, valid_utf8) = bytes_to_str(line_buf);
            if !valid_utf8 {
                meta.error_count = meta.error_count.saturating_add(1);
                record_diagnostic(meta, "Non-UTF-8 bytes encountered in body line");
            }
            let trimmed = line_str.trim();
            if !trimmed.is_empty() {
                if !meta.body_preview.is_empty() {
                    if *body_chars_count < options.max_body_preview_chars {
                        meta.body_preview.push('\n');
                        *body_chars_count += 1;
                    } else {
                        meta.body_truncated = true;
                        *state = ParserState::FastForward;
                        return;
                    }
                }
                for ch in line_str.chars() {
                    if ch == '\r' {
                        continue;
                    }
                    if *body_chars_count < options.max_body_preview_chars {
                        meta.body_preview.push(ch);
                        *body_chars_count += 1;
                    } else {
                        meta.body_truncated = true;
                        *state = ParserState::FastForward;
                        break;
                    }
                }
            }
        }
        ParserState::FastForward => {}
    }
}

fn emit_pending_header(pending: Option<PendingHeader>, meta: &mut Rfc822Metadata) {
    let Some(header) = pending else { return };
    let name_lower = header.name.to_ascii_lowercase();
    let raw_val = header.value.trim();
    let val = if raw_val.len() > MAX_RETAINED_HEADER_VALUE_BYTES {
        meta.header_truncated = true;
        meta.pathological_header_detected = true;
        meta.error_count = meta.error_count.saturating_add(1);
        record_diagnostic(
            meta,
            "Target header exceeded the cumulative retained-value limit",
        );
        utf8_prefix(raw_val, MAX_RETAINED_HEADER_VALUE_BYTES).to_string()
    } else {
        raw_val.to_string()
    };
    if val.is_empty() {
        if is_target_header(&name_lower) {
            meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
            meta.error_count = meta.error_count.saturating_add(1);
            record_diagnostic(
                meta,
                format!("Target header {name_lower} had no retained value"),
            );
        } else {
            meta.skipped_headers_count = meta.skipped_headers_count.saturating_add(1);
        }
        return;
    }

    match name_lower.as_str() {
        "from" => set_or_update(&mut meta.from, val),
        "to" => {
            let current = meta.to.take();
            meta.to = append_recipient(current, val, meta);
        }
        "cc" => {
            let current = meta.cc.take();
            meta.cc = append_recipient(current, val, meta);
        }
        "bcc" => {
            let current = meta.bcc.take();
            meta.bcc = append_recipient(current, val, meta);
        }
        "subject" => set_or_update(&mut meta.subject, val),
        "date" => set_or_update(&mut meta.date, val),
        "message-id" => set_or_update(&mut meta.message_id, val),
        "reply-to" => {
            let current = meta.reply_to.take();
            meta.reply_to = append_recipient(current, val, meta);
        }
        "in-reply-to" => set_or_update(&mut meta.in_reply_to, val),
        _ => {
            meta.skipped_headers_count = meta.skipped_headers_count.saturating_add(1);
        }
    }
}

fn set_or_update(field: &mut Option<String>, val: String) {
    if field.is_none() {
        *field = Some(val);
    }
}

fn append_recipient(
    field: Option<String>,
    val: String,
    meta: &mut Rfc822Metadata,
) -> Option<String> {
    match field {
        Some(mut existing) => {
            append_bounded_header_value(
                &mut existing,
                &val,
                ", ",
                MAX_RETAINED_HEADER_VALUE_BYTES,
                meta,
                "Repeated recipient headers exceeded the retained-value limit",
            );
            Some(existing)
        }
        None => Some(val),
    }
}

fn is_target_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "from"
            | "to"
            | "cc"
            | "bcc"
            | "subject"
            | "date"
            | "message-id"
            | "reply-to"
            | "in-reply-to"
    )
}

fn append_bounded_header_value(
    target: &mut String,
    value: &str,
    separator: &str,
    limit: usize,
    meta: &mut Rfc822Metadata,
    diagnostic: &str,
) {
    if value.is_empty() {
        return;
    }
    let separator = if target.is_empty() { "" } else { separator };
    let needed = separator.len().saturating_add(value.len());
    let remaining = limit.saturating_sub(target.len());
    if needed <= remaining {
        target.push_str(separator);
        target.push_str(value);
        return;
    }

    if remaining > 0 {
        let separator_prefix = utf8_prefix(separator, remaining);
        target.push_str(separator_prefix);
        let value_remaining = remaining.saturating_sub(separator_prefix.len());
        target.push_str(utf8_prefix(value, value_remaining));
    }
    meta.header_truncated = true;
    meta.pathological_header_detected = true;
    meta.error_count = meta.error_count.saturating_add(1);
    record_diagnostic(meta, diagnostic);
}

fn utf8_prefix(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn record_diagnostic(meta: &mut Rfc822Metadata, message: impl AsRef<str>) {
    if meta.diagnostics.len() >= MAX_DIAGNOSTICS {
        meta.diagnostics_omitted_count = meta.diagnostics_omitted_count.saturating_add(1);
        return;
    }
    let message = message.as_ref();
    let bounded = message
        .chars()
        .take(MAX_DIAGNOSTIC_CHARS)
        .collect::<String>();
    meta.diagnostics.push(bounded);
}

fn bytes_to_str(bytes: &[u8]) -> (Cow<'_, str>, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (Cow::Borrowed(s), true),
        Err(_) => (String::from_utf8_lossy(bytes), false),
    }
}

#[derive(Debug, Clone)]
struct HeaderField {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct HeaderBlock {
    fields: Vec<HeaderField>,
    header_start: usize,
    header_end: usize,
    body_start: usize,
    complete: bool,
}

#[derive(Debug, Default)]
struct MimeContext {
    next_part_index: usize,
    searchable_text_bytes: usize,
    limit_reached: bool,
    partial: bool,
    unsupported: bool,
}

#[derive(Debug)]
struct DecodedPayload {
    retained: Vec<u8>,
    decoded_size: u64,
    decoded_sha256: Option<String>,
    complete: bool,
    status: Rfc822ParseStatus,
    diagnostic: Option<String>,
}

#[derive(Debug, Default)]
struct MimeValue {
    main: String,
    params: BTreeMap<String, String>,
}

#[derive(Debug)]
struct MultipartRanges {
    parts: Vec<(usize, usize)>,
    closing_boundary_seen: bool,
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn apply_mime_semantics(
    raw: &[u8],
    message_complete: bool,
    meta: &mut Rfc822Metadata,
    options: &Rfc822ParserOptions,
) {
    let root_headers = parse_header_block(raw, 0, raw.len(), meta, options);
    if !root_headers.complete && !raw.is_empty() {
        meta.error_count = meta.error_count.saturating_add(1);
        record_diagnostic(meta, "Missing header-body separator before end of stream");
    }
    apply_decoded_top_level_headers(&root_headers, meta);

    let mut context = MimeContext::default();
    parse_mime_entity(
        raw,
        0,
        raw.len(),
        root_headers,
        0,
        None,
        message_complete,
        meta,
        options,
        &mut context,
    );

    if !message_complete {
        context.limit_reached = true;
        meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
        record_diagnostic(
            meta,
            format!(
                "MIME parsing stopped at the bounded {MAX_MIME_CAPTURE_BYTES}-byte message-capture limit; raw hashing continued to EOF"
            ),
        );
    }
    meta.parser_status = if context.limit_reached {
        Rfc822ParseStatus::LimitReached
    } else if context.partial || !root_header_is_complete(meta) || meta.malformed_lines_count > 0 {
        Rfc822ParseStatus::Partial
    } else if context.unsupported {
        Rfc822ParseStatus::Unsupported
    } else if meta.has_any_target_header() || !meta.mime_parts.is_empty() {
        Rfc822ParseStatus::Complete
    } else {
        Rfc822ParseStatus::NotRecognized
    };
}

fn root_header_is_complete(meta: &Rfc822Metadata) -> bool {
    meta.header_complete && !meta.header_truncated
}

fn parse_header_block(
    raw: &[u8],
    start: usize,
    end: usize,
    meta: &mut Rfc822Metadata,
    options: &Rfc822ParserOptions,
) -> HeaderBlock {
    let end = end.min(raw.len());
    let mut fields = Vec::new();
    let mut pending: Option<HeaderField> = None;
    let mut position = start.min(end);
    let mut total_header_bytes = 0usize;
    let mut complete = false;
    let mut header_end = position;

    while position < end {
        let (line_start, content_end, next) = next_raw_line(raw, position, end);
        total_header_bytes = total_header_bytes.saturating_add(next.saturating_sub(line_start));
        header_end = next;
        position = next;

        if total_header_bytes > MAX_HEADER_BLOCK_BYTES {
            meta.header_truncated = true;
            meta.pathological_header_detected = true;
            meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
            record_diagnostic(
                meta,
                format!("MIME header block exceeded the {MAX_HEADER_BLOCK_BYTES}-byte limit"),
            );
            break;
        }

        let full_line = &raw[line_start..content_end];
        if full_line.is_empty() {
            if let Some(field) = pending.take() {
                retain_header_field(&mut fields, field, meta);
            }
            complete = true;
            break;
        }

        let line = if full_line.len() > options.max_header_line_bytes {
            meta.header_truncated = true;
            meta.pathological_header_detected = true;
            meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
            meta.error_count = meta.error_count.saturating_add(1);
            meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
            record_diagnostic(
                meta,
                format!(
                    "MIME header line at raw offset {line_start} exceeded limit of {} bytes",
                    options.max_header_line_bytes
                ),
            );
            &full_line[..options.max_header_line_bytes]
        } else {
            full_line
        };

        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            if let Some(field) = pending.as_mut() {
                let unfolded = String::from_utf8_lossy(line)
                    .trim_start_matches([' ', '\t'])
                    .to_string();
                if !field.value.is_empty() {
                    field.value.push(' ');
                }
                let retained_limit =
                    MAX_RETAINED_HEADER_VALUE_BYTES.min(options.max_header_line_bytes);
                let remaining = retained_limit.saturating_sub(field.value.len());
                field.value.push_str(utf8_prefix(&unfolded, remaining));
                if unfolded.len() > remaining {
                    meta.header_truncated = true;
                    meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
                }
            } else {
                meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
                meta.error_count = meta.error_count.saturating_add(1);
                record_diagnostic(meta, "Orphaned folded MIME header line encountered");
            }
            continue;
        }

        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            if let Some(field) = pending.take() {
                retain_header_field(&mut fields, field, meta);
            }
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
            let value = String::from_utf8_lossy(&line[colon + 1..])
                .trim_start_matches([' ', '\t'])
                .to_string();
            if !valid_header_name(&name) {
                meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
                meta.error_count = meta.error_count.saturating_add(1);
                record_diagnostic(
                    meta,
                    format!("Invalid MIME header field name at raw offset {line_start}"),
                );
                pending = None;
            } else {
                pending = Some(HeaderField { name, value });
            }
        } else {
            let recovered = pending
                .as_mut()
                .filter(|field| field.value.is_empty() && is_target_header(&field.name))
                .map(|field| {
                    field.value = String::from_utf8_lossy(line).trim().to_string();
                })
                .is_some();
            meta.malformed_lines_count = meta.malformed_lines_count.saturating_add(1);
            meta.error_count = meta.error_count.saturating_add(1);
            record_diagnostic(
                meta,
                if recovered {
                    "Recovered an unindented value following an empty target MIME header"
                } else {
                    "Malformed MIME header line (missing colon)"
                },
            );
            if !recovered {
                if let Some(field) = pending.take() {
                    retain_header_field(&mut fields, field, meta);
                }
            }
        }
    }
    if let Some(field) = pending.take() {
        retain_header_field(&mut fields, field, meta);
    }

    HeaderBlock {
        fields,
        header_start: start,
        header_end,
        body_start: if complete { position } else { end },
        complete,
    }
}

fn retain_header_field(
    fields: &mut Vec<HeaderField>,
    field: HeaderField,
    meta: &mut Rfc822Metadata,
) {
    if fields.len() < MAX_HEADERS_PER_PART {
        fields.push(field);
    } else {
        meta.skipped_headers_count = meta.skipped_headers_count.saturating_add(1);
        meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
        record_diagnostic(
            meta,
            format!("MIME part exceeded the {MAX_HEADERS_PER_PART}-header retention limit"),
        );
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && byte != b':')
}

fn next_raw_line(raw: &[u8], start: usize, end: usize) -> (usize, usize, usize) {
    let mut cursor = start;
    while cursor < end && raw[cursor] != b'\n' {
        cursor += 1;
    }
    let next = if cursor < end { cursor + 1 } else { end };
    let content_end = if cursor > start && raw[cursor.saturating_sub(1)] == b'\r' {
        cursor - 1
    } else {
        cursor
    };
    (start, content_end, next)
}

fn header_values<'a>(block: &'a HeaderBlock, name: &str) -> impl Iterator<Item = &'a str> {
    let lower = name.to_ascii_lowercase();
    block
        .fields
        .iter()
        .filter(move |field| field.name.eq_ignore_ascii_case(&lower))
        .map(|field| field.value.as_str())
}

fn first_header_value<'a>(block: &'a HeaderBlock, name: &str) -> Option<&'a str> {
    header_values(block, name).next()
}

fn decoded_header_join(
    block: &HeaderBlock,
    name: &str,
    separator: &str,
    meta: &mut Rfc822Metadata,
) -> Option<String> {
    let values = header_values(block, name)
        .map(|value| decode_rfc2047_header(value, meta))
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    let joined = values.join(separator);
    if joined.len() > DEFAULT_MAX_HEADER_LINE_BYTES {
        meta.header_truncated = true;
        meta.pathological_header_detected = true;
        meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
        record_diagnostic(
            meta,
            "Decoded target header exceeded the retained-value limit",
        );
        Some(utf8_prefix(&joined, DEFAULT_MAX_HEADER_LINE_BYTES).to_string())
    } else {
        Some(joined)
    }
}

fn apply_decoded_top_level_headers(block: &HeaderBlock, meta: &mut Rfc822Metadata) {
    meta.header_complete = block.complete;
    meta.skipped_headers_count = block
        .fields
        .iter()
        .filter(|field| !is_target_header(&field.name))
        .count();
    meta.from = decoded_header_join(block, "from", ", ", meta);
    meta.to = decoded_header_join(block, "to", ", ", meta);
    meta.cc = decoded_header_join(block, "cc", ", ", meta);
    meta.bcc = decoded_header_join(block, "bcc", ", ", meta);
    meta.subject = decoded_header_join(block, "subject", " ", meta);
    meta.date = decoded_header_join(block, "date", " ", meta);
    meta.message_id = decoded_header_join(block, "message-id", " ", meta);
    meta.reply_to = decoded_header_join(block, "reply-to", ", ", meta);
    meta.in_reply_to = decoded_header_join(block, "in-reply-to", " ", meta);

    meta.from_addresses = meta
        .from
        .as_deref()
        .map(extract_addresses)
        .unwrap_or_default();
    meta.to_addresses = meta
        .to
        .as_deref()
        .map(extract_addresses)
        .unwrap_or_default();
    meta.cc_addresses = meta
        .cc
        .as_deref()
        .map(extract_addresses)
        .unwrap_or_default();
    meta.bcc_addresses = meta
        .bcc
        .as_deref()
        .map(extract_addresses)
        .unwrap_or_default();
    meta.reply_to_addresses = meta
        .reply_to
        .as_deref()
        .map(extract_addresses)
        .unwrap_or_default();
    meta.message_ids = meta
        .message_id
        .as_deref()
        .map(extract_message_ids)
        .unwrap_or_default();
    meta.date_utc = meta
        .date
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
        .map(|value| value.with_timezone(&Utc).to_rfc3339());
}

#[allow(clippy::too_many_arguments)]
fn parse_mime_entity(
    raw: &[u8],
    entity_start: usize,
    entity_end: usize,
    headers: HeaderBlock,
    depth: usize,
    parent_index: Option<usize>,
    entity_complete: bool,
    meta: &mut Rfc822Metadata,
    options: &Rfc822ParserOptions,
    context: &mut MimeContext,
) {
    if context.next_part_index >= MAX_MIME_PARTS {
        context.limit_reached = true;
        meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
        record_diagnostic(
            meta,
            format!("MIME part count exceeded the {MAX_MIME_PARTS}-part limit"),
        );
        return;
    }
    if depth > MAX_MIME_DEPTH {
        context.limit_reached = true;
        meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
        record_diagnostic(
            meta,
            format!("MIME nesting exceeded the {MAX_MIME_DEPTH}-level limit"),
        );
        return;
    }

    let index = context.next_part_index;
    context.next_part_index += 1;
    let content_type = parse_mime_value(
        first_header_value(&headers, "content-type").unwrap_or("text/plain"),
        meta,
    );
    let disposition = first_header_value(&headers, "content-disposition")
        .map(|value| parse_mime_value(value, meta));
    let transfer_encoding = first_header_value(&headers, "content-transfer-encoding")
        .unwrap_or("7bit")
        .trim()
        .to_ascii_lowercase();
    let filename = disposition
        .as_ref()
        .and_then(|value| value.params.get("filename").cloned())
        .or_else(|| content_type.params.get("name").cloned());
    let filename_path_risks = filename
        .as_deref()
        .map(attachment_filename_path_risks)
        .unwrap_or_default();
    let disposition_name = disposition
        .as_ref()
        .map(|value| value.main.to_ascii_lowercase());
    let is_attachment = disposition_name.as_deref() == Some("attachment") || filename.is_some();
    let body_start = headers.body_start.min(entity_end);
    let body_end = entity_end.min(raw.len()).max(body_start);
    let raw_body = &raw[body_start..body_end];
    let raw_body_sha256 = entity_complete.then(|| sha256_hex(raw_body));
    let mut part = Rfc822PartMetadata {
        index,
        parent_index,
        depth,
        content_type: content_type.main.to_ascii_lowercase(),
        charset: content_type.params.get("charset").cloned(),
        transfer_encoding: transfer_encoding.clone(),
        disposition: disposition_name,
        filename,
        filename_path_risks,
        is_attachment,
        header_start: headers.header_start as u64,
        header_end: headers.header_end as u64,
        body_start: body_start as u64,
        body_end: body_end as u64,
        raw_body_size: raw_body.len() as u64,
        raw_body_sha256,
        decoded_size: None,
        decoded_sha256: None,
        decoded_content_complete: false,
        text_preview: None,
        text_preview_truncated: false,
        status: if headers.complete && entity_complete {
            Rfc822ParseStatus::Complete
        } else {
            Rfc822ParseStatus::Partial
        },
        diagnostics: Vec::new(),
    };

    if is_attachment {
        meta.attachment_count = meta.attachment_count.saturating_add(1);
    }
    if !headers.complete || !entity_complete {
        context.partial = true;
        bounded_part_diagnostic(
            &mut part,
            "Part headers or terminating boundary were incomplete",
        );
    }

    if part.content_type.starts_with("multipart/") {
        let Some(boundary) = content_type.params.get("boundary") else {
            mark_part_status(&mut part, Rfc822ParseStatus::Partial);
            context.partial = true;
            bounded_part_diagnostic(&mut part, "Multipart part did not declare a boundary");
            retain_mime_part(meta, part);
            return;
        };
        if boundary.is_empty()
            || boundary.len() > MAX_BOUNDARY_BYTES
            || boundary.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
        {
            mark_part_status(&mut part, Rfc822ParseStatus::Partial);
            context.partial = true;
            bounded_part_diagnostic(
                &mut part,
                "Multipart boundary was empty, overlong, or contained a line break",
            );
            retain_mime_part(meta, part);
            return;
        }

        let ranges = find_multipart_ranges(raw, body_start, body_end, boundary.as_bytes());
        if ranges.parts.is_empty() {
            mark_part_status(&mut part, Rfc822ParseStatus::Partial);
            context.partial = true;
            bounded_part_diagnostic(&mut part, "Declared multipart boundary was not found");
        } else if !ranges.closing_boundary_seen {
            mark_part_status(&mut part, Rfc822ParseStatus::Partial);
            context.partial = true;
            bounded_part_diagnostic(&mut part, "Multipart closing boundary was not found");
        }
        retain_mime_part(meta, part);
        for (child_start, child_end) in ranges.parts {
            if child_start >= child_end {
                continue;
            }
            let child_headers = parse_header_block(raw, child_start, child_end, meta, options);
            parse_mime_entity(
                raw,
                child_start,
                child_end,
                child_headers,
                depth + 1,
                Some(index),
                ranges.closing_boundary_seen,
                meta,
                options,
                context,
            );
        }
        return;
    }

    let retain_limit = if part.content_type.starts_with("text/") && !part.is_attachment {
        MAX_SEARCHABLE_TEXT_BYTES
            .saturating_sub(context.searchable_text_bytes)
            .saturating_add(8)
            .min(MAX_SEARCHABLE_TEXT_BYTES)
    } else {
        0
    };
    let decoded = decode_transfer_encoding(raw_body, &transfer_encoding, retain_limit);
    part.decoded_size = decoded.complete.then_some(decoded.decoded_size);
    part.decoded_sha256 = (decoded.complete && entity_complete)
        .then_some(decoded.decoded_sha256)
        .flatten();
    part.decoded_content_complete = decoded.complete && entity_complete;
    if let Some(diagnostic) = decoded.diagnostic {
        bounded_part_diagnostic(&mut part, &diagnostic);
    }
    if decoded.status == Rfc822ParseStatus::Unsupported {
        mark_part_status(&mut part, Rfc822ParseStatus::Unsupported);
        context.unsupported = true;
    } else if decoded.status == Rfc822ParseStatus::Partial {
        mark_part_status(&mut part, Rfc822ParseStatus::Partial);
        context.partial = true;
    }

    if part.content_type.starts_with("text/") && !part.is_attachment && decoded.complete {
        match decode_text_charset(&decoded.retained, part.charset.as_deref()) {
            Ok((text, had_replacements, charset_recovered)) => {
                let normalized = normalize_body_preview(&text, options.max_body_preview_chars);
                part.text_preview_truncated =
                    normalized.1 || decoded.decoded_size > decoded.retained.len() as u64;
                part.text_preview = (!normalized.0.is_empty()).then_some(normalized.0);
                if let Some(decoded_sha256) = part.decoded_sha256.clone() {
                    let remaining =
                        MAX_SEARCHABLE_TEXT_BYTES.saturating_sub(context.searchable_text_bytes);
                    let retained_text = utf8_prefix(&text, remaining).to_string();
                    let content_complete = part.decoded_content_complete
                        && decoded.decoded_size == decoded.retained.len() as u64
                        && retained_text.len() == text.len();
                    if !retained_text.is_empty() {
                        context.searchable_text_bytes = context
                            .searchable_text_bytes
                            .saturating_add(retained_text.len());
                        meta.searchable_text_segments.push(Rfc822TextSegment {
                            part_index: index,
                            content_type: part.content_type.clone(),
                            charset: part.charset.clone(),
                            transfer_encoding: part.transfer_encoding.clone(),
                            raw_header_start: part.header_start,
                            raw_header_end: part.header_end,
                            raw_body_start: part.body_start,
                            raw_body_end: part.body_end,
                            decoded_size: decoded.decoded_size,
                            decoded_sha256,
                            content_complete,
                            content: retained_text,
                        });
                    }
                    if !content_complete {
                        context.limit_reached = true;
                        meta.limit_hit_count = meta.limit_hit_count.saturating_add(1);
                        mark_part_status(&mut part, Rfc822ParseStatus::LimitReached);
                        bounded_part_diagnostic(
                            &mut part,
                            format!(
                                "Decoded body text exceeded the {MAX_SEARCHABLE_TEXT_BYTES}-byte per-message searchable-text budget"
                            )
                            .as_str(),
                        );
                    }
                }
                if had_replacements {
                    mark_part_status(&mut part, Rfc822ParseStatus::Partial);
                    context.partial = true;
                    bounded_part_diagnostic(
                        &mut part,
                        "Declared text charset produced replacement characters",
                    );
                }
                if charset_recovered {
                    meta.warning_count = meta.warning_count.saturating_add(1);
                    bounded_part_diagnostic(
                        &mut part,
                        "No charset was declared; valid UTF-8 bytes were used for preview",
                    );
                }
            }
            Err(diagnostic) => {
                mark_part_status(&mut part, Rfc822ParseStatus::Unsupported);
                context.unsupported = true;
                bounded_part_diagnostic(&mut part, &diagnostic);
            }
        }
    }

    if meta.body_preview.is_empty()
        && part.content_type.eq_ignore_ascii_case("text/plain")
        && !part.is_attachment
    {
        if let Some(preview) = part.text_preview.clone() {
            meta.body_preview = preview;
            meta.body_preview_part_index = Some(index);
            meta.body_truncated = part.text_preview_truncated;
        }
    }
    retain_mime_part(meta, part);
    let _ = entity_start;
}

fn mark_part_status(part: &mut Rfc822PartMetadata, status: Rfc822ParseStatus) {
    let rank = |value| match value {
        Rfc822ParseStatus::NotRecognized => 0,
        Rfc822ParseStatus::Complete => 1,
        Rfc822ParseStatus::Unsupported => 2,
        Rfc822ParseStatus::Partial => 3,
        Rfc822ParseStatus::LimitReached => 4,
    };
    if rank(status) > rank(part.status) {
        part.status = status;
    }
}

fn retain_mime_part(meta: &mut Rfc822Metadata, part: Rfc822PartMetadata) {
    match part.status {
        Rfc822ParseStatus::Partial => {
            meta.partial_part_count = meta.partial_part_count.saturating_add(1);
        }
        Rfc822ParseStatus::Unsupported => {
            meta.unsupported_part_count = meta.unsupported_part_count.saturating_add(1);
        }
        Rfc822ParseStatus::NotRecognized
        | Rfc822ParseStatus::Complete
        | Rfc822ParseStatus::LimitReached => {}
    }
    meta.mime_parts.push(part);
}

fn bounded_part_diagnostic(part: &mut Rfc822PartMetadata, diagnostic: &str) {
    if part.diagnostics.len() < 8 {
        part.diagnostics.push(
            diagnostic
                .chars()
                .take(MAX_DIAGNOSTIC_CHARS)
                .collect::<String>(),
        );
    }
}

fn find_multipart_ranges(raw: &[u8], start: usize, end: usize, boundary: &[u8]) -> MultipartRanges {
    let mut cursor = start;
    let mut part_start = None;
    let mut parts = Vec::new();
    let mut closing_boundary_seen = false;
    while cursor < end {
        let (line_start, content_end, next) = next_raw_line(raw, cursor, end);
        let content = &raw[line_start..content_end];
        if let Some(closing) = classify_boundary_line(content, boundary) {
            if let Some(previous_start) = part_start.take() {
                let previous_end = strip_boundary_crlf(raw, previous_start, line_start);
                if previous_start <= previous_end {
                    parts.push((previous_start, previous_end));
                }
            }
            if closing {
                closing_boundary_seen = true;
                break;
            }
            part_start = Some(next);
        }
        cursor = next;
    }
    if !closing_boundary_seen {
        if let Some(previous_start) = part_start {
            if previous_start <= end {
                parts.push((previous_start, end));
            }
        }
    }
    MultipartRanges {
        parts,
        closing_boundary_seen,
    }
}

fn classify_boundary_line(line: &[u8], boundary: &[u8]) -> Option<bool> {
    let marker_len = boundary.len().checked_add(2)?;
    if line.len() < marker_len || &line[..2] != b"--" || &line[2..marker_len] != boundary {
        return None;
    }
    let remainder = &line[marker_len..];
    if remainder.iter().all(|byte| matches!(byte, b' ' | b'\t')) {
        return Some(false);
    }
    let after_close = remainder.strip_prefix(b"--")?;
    after_close
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t'))
        .then_some(true)
}

fn strip_boundary_crlf(raw: &[u8], start: usize, end: usize) -> usize {
    if end >= start + 2 && &raw[end - 2..end] == b"\r\n" {
        end - 2
    } else if end > start && raw[end - 1] == b'\n' {
        end - 1
    } else {
        end
    }
}

fn decode_transfer_encoding(raw: &[u8], encoding: &str, retain_limit: usize) -> DecodedPayload {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "" | "7bit" | "8bit" | "binary" => decoded_from_identity(raw, retain_limit),
        "base64" => decode_base64_payload(raw, retain_limit),
        "quoted-printable" => decode_quoted_printable_payload(raw, retain_limit),
        other => DecodedPayload {
            retained: Vec::new(),
            decoded_size: 0,
            decoded_sha256: None,
            complete: false,
            status: Rfc822ParseStatus::Unsupported,
            diagnostic: Some(format!(
                "Unsupported Content-Transfer-Encoding {other:?}; part metadata and raw offsets were retained"
            )),
        },
    }
}

fn decoded_from_identity(raw: &[u8], retain_limit: usize) -> DecodedPayload {
    DecodedPayload {
        retained: raw[..raw.len().min(retain_limit)].to_vec(),
        decoded_size: raw.len() as u64,
        decoded_sha256: Some(sha256_hex(raw)),
        complete: true,
        status: Rfc822ParseStatus::Complete,
        diagnostic: None,
    }
}

fn decode_base64_payload(raw: &[u8], retain_limit: usize) -> DecodedPayload {
    let mut quartet = [0u8; 4];
    let mut quartet_len = 0usize;
    let mut retained = Vec::with_capacity(retain_limit.min(4096));
    let mut hasher = Sha256::new();
    let mut decoded_size = 0u64;
    let mut malformed = None;
    let mut saw_padding = false;

    for &byte in raw {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if saw_padding {
            malformed = Some("Non-whitespace base64 data followed a padded quantum".to_string());
            break;
        }
        quartet[quartet_len] = byte;
        quartet_len += 1;
        if quartet_len == 4 {
            let mut output = [0u8; 3];
            match base64::engine::general_purpose::STANDARD.decode_slice(quartet, &mut output) {
                Ok(count) => {
                    update_decoded_output(
                        &output[..count],
                        retain_limit,
                        &mut retained,
                        &mut hasher,
                        &mut decoded_size,
                    );
                    saw_padding = quartet.contains(&b'=');
                }
                Err(error) => {
                    malformed = Some(format!("Invalid base64 transfer encoding: {error}"));
                    break;
                }
            }
            quartet_len = 0;
        }
    }

    if malformed.is_none() && quartet_len != 0 {
        if quartet_len == 1 {
            malformed = Some("Invalid one-byte trailing base64 quantum".to_string());
        } else {
            let mut output = [0u8; 3];
            match base64::engine::general_purpose::STANDARD_NO_PAD
                .decode_slice(&quartet[..quartet_len], &mut output)
            {
                Ok(count) => update_decoded_output(
                    &output[..count],
                    retain_limit,
                    &mut retained,
                    &mut hasher,
                    &mut decoded_size,
                ),
                Err(error) => {
                    malformed = Some(format!("Invalid trailing base64 quantum: {error}"));
                }
            }
        }
    }

    let complete = malformed.is_none();
    DecodedPayload {
        retained,
        decoded_size,
        decoded_sha256: complete.then(|| hex_digest(hasher.finalize())),
        complete,
        status: if complete {
            Rfc822ParseStatus::Complete
        } else {
            Rfc822ParseStatus::Partial
        },
        diagnostic: malformed,
    }
}

fn decode_quoted_printable_payload(raw: &[u8], retain_limit: usize) -> DecodedPayload {
    let mut retained = Vec::with_capacity(retain_limit.min(4096));
    let mut hasher = Sha256::new();
    let mut decoded_size = 0u64;
    let mut malformed_count = 0usize;
    let mut cursor = 0usize;
    while cursor < raw.len() {
        if raw[cursor] != b'=' {
            update_decoded_output(
                &raw[cursor..cursor + 1],
                retain_limit,
                &mut retained,
                &mut hasher,
                &mut decoded_size,
            );
            cursor += 1;
            continue;
        }
        if raw.get(cursor + 1..cursor + 3) == Some(b"\r\n") {
            cursor += 3;
            continue;
        }
        if raw.get(cursor + 1) == Some(&b'\n') {
            cursor += 2;
            continue;
        }
        if let (Some(high), Some(low)) = (raw.get(cursor + 1), raw.get(cursor + 2)) {
            if let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low)) {
                let byte = (high << 4) | low;
                update_decoded_output(
                    &[byte],
                    retain_limit,
                    &mut retained,
                    &mut hasher,
                    &mut decoded_size,
                );
                cursor += 3;
                continue;
            }
        }
        malformed_count = malformed_count.saturating_add(1);
        update_decoded_output(
            b"=",
            retain_limit,
            &mut retained,
            &mut hasher,
            &mut decoded_size,
        );
        cursor += 1;
    }
    let complete = malformed_count == 0;
    DecodedPayload {
        retained,
        decoded_size,
        decoded_sha256: complete.then(|| hex_digest(hasher.finalize())),
        complete,
        status: if complete {
            Rfc822ParseStatus::Complete
        } else {
            Rfc822ParseStatus::Partial
        },
        diagnostic: (!complete).then(|| {
            format!(
                "Quoted-printable body contained {malformed_count} malformed escape sequence(s)"
            )
        }),
    }
}

fn update_decoded_output(
    bytes: &[u8],
    retain_limit: usize,
    retained: &mut Vec<u8>,
    hasher: &mut Sha256,
    decoded_size: &mut u64,
) {
    hasher.update(bytes);
    *decoded_size = decoded_size.saturating_add(bytes.len() as u64);
    let remaining = retain_limit.saturating_sub(retained.len());
    retained.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_text_charset(
    bytes: &[u8],
    charset: Option<&str>,
) -> Result<(String, bool, bool), String> {
    let Some(charset) = charset.map(str::trim).filter(|value| !value.is_empty()) else {
        if bytes.iter().all(u8::is_ascii) {
            return Ok((String::from_utf8_lossy(bytes).into_owned(), false, false));
        }
        return std::str::from_utf8(bytes)
            .map(|text| (text.to_string(), false, true))
            .map_err(|_| {
                "Text part has non-ASCII bytes without a declared charset and is not valid UTF-8"
                    .to_string()
            });
    };
    let Some(encoding) = Encoding::for_label(charset.as_bytes()) else {
        return Err(format!(
            "Unsupported or unrecognized MIME charset {charset:?}; decoded bytes were hashed but not rendered as text"
        ));
    };
    let (decoded, _, had_errors) = encoding.decode(bytes);
    Ok((decoded.into_owned(), had_errors, false))
}

fn normalize_body_preview(text: &str, max_chars: usize) -> (String, bool) {
    let mut out = String::new();
    let mut count = 0usize;
    let mut omitted = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if !out.is_empty() {
            if count >= max_chars {
                omitted = true;
                break;
            }
            out.push('\n');
            count += 1;
        }
        for character in line.chars() {
            if count >= max_chars {
                omitted = true;
                break;
            }
            out.push(character);
            count += 1;
        }
        if omitted {
            break;
        }
    }
    if !omitted {
        omitted = text.chars().filter(|character| *character != '\r').count() > count;
    }
    (out, omitted)
}

fn parse_mime_value(value: &str, meta: &mut Rfc822Metadata) -> MimeValue {
    let segments = split_quoted(value, b';');
    let main = segments
        .first()
        .map(|segment| segment.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let mut params = BTreeMap::new();
    for segment in segments.into_iter().skip(1) {
        let Some((name, raw_value)) = segment.split_once('=') else {
            meta.warning_count = meta.warning_count.saturating_add(1);
            record_diagnostic(meta, "MIME parameter without an equals sign was ignored");
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let raw_value = unquote_parameter(raw_value.trim());
        if name.ends_with('*') {
            let canonical = name.trim_end_matches('*').to_string();
            match decode_rfc2231_parameter(&raw_value) {
                Some(decoded) => {
                    params.insert(canonical, decoded);
                }
                None => {
                    meta.warning_count = meta.warning_count.saturating_add(1);
                    record_diagnostic(
                        meta,
                        format!("RFC 2231 MIME parameter {name:?} could not be decoded"),
                    );
                }
            }
        } else if name.contains('*') {
            meta.warning_count = meta.warning_count.saturating_add(1);
            record_diagnostic(
                meta,
                format!("RFC 2231 continuation parameter {name:?} is unsupported"),
            );
        } else {
            params.entry(name).or_insert(raw_value);
        }
    }
    MimeValue { main, params }
}

fn split_quoted(value: &str, delimiter: u8) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == delimiter {
            parts.push(value[start..index].to_string());
            start = index + 1;
        }
    }
    parts.push(value[start..].to_string());
    parts
}

fn unquote_parameter(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let mut out = String::new();
        let mut escaped = false;
        for character in value[1..value.len() - 1].chars() {
            if escaped {
                out.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                out.push(character);
            }
        }
        if escaped {
            out.push('\\');
        }
        out
    } else {
        value.to_string()
    }
}

fn decode_rfc2231_parameter(value: &str) -> Option<String> {
    let (charset, encoded) = if let Some((charset, remainder)) = value.split_once('\'') {
        let (_, encoded) = remainder.split_once('\'')?;
        (Some(charset), encoded)
    } else {
        (None, value)
    };
    let bytes = percent_decode(encoded)?;
    match charset.filter(|value| !value.is_empty()) {
        Some(charset) => decode_text_charset(&bytes, Some(charset))
            .ok()
            .map(|decoded| decoded.0),
        None => String::from_utf8(bytes).ok(),
    }
}

fn percent_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let high = *bytes.get(cursor + 1)?;
            let low = *bytes.get(cursor + 2)?;
            out.push((hex_value(high)? << 4) | hex_value(low)?);
            cursor += 3;
        } else {
            out.push(bytes[cursor]);
            cursor += 1;
        }
    }
    Some(out)
}

fn decode_rfc2047_header(value: &str, meta: &mut Rfc822Metadata) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut previous_encoded = false;
    while let Some(relative_start) = value[cursor..].find("=?") {
        let start = cursor + relative_start;
        let between = &value[cursor..start];
        let Some((decoded, end)) = decode_one_encoded_word(value, start) else {
            out.push_str(&value[cursor..start + 2]);
            cursor = start + 2;
            previous_encoded = false;
            meta.warning_count = meta.warning_count.saturating_add(1);
            record_diagnostic(
                meta,
                "Malformed RFC 2047 encoded-word was retained verbatim",
            );
            continue;
        };
        if !(previous_encoded && between.chars().all(char::is_whitespace)) {
            out.push_str(between);
        }
        match decoded {
            Ok(text) => {
                out.push_str(&text);
                previous_encoded = true;
            }
            Err(diagnostic) => {
                out.push_str(&value[start..end]);
                previous_encoded = false;
                meta.warning_count = meta.warning_count.saturating_add(1);
                record_diagnostic(meta, diagnostic);
            }
        }
        cursor = end;
    }
    out.push_str(&value[cursor..]);
    out
}

fn decode_one_encoded_word(value: &str, start: usize) -> Option<(Result<String, String>, usize)> {
    let rest = value.get(start + 2..)?;
    let charset_end = rest.find('?')?;
    let charset = &rest[..charset_end];
    let after_charset = &rest[charset_end + 1..];
    let encoding_end = after_charset.find('?')?;
    let encoding = &after_charset[..encoding_end];
    let encoded_start = start + 2 + charset_end + 1 + encoding_end + 1;
    let encoded_rest = value.get(encoded_start..)?;
    let encoded_end_relative = encoded_rest.find("?=")?;
    let encoded_end = encoded_start + encoded_end_relative;
    let end = encoded_end + 2;
    let encoded = value.get(encoded_start..encoded_end)?;
    let bytes = match encoding.to_ascii_lowercase().as_str() {
        "b" => match base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Some((
                    Err(format!("Invalid RFC 2047 base64 encoded-word: {error}")),
                    end,
                ));
            }
        },
        "q" => match decode_rfc2047_q(encoded.as_bytes()) {
            Ok(bytes) => bytes,
            Err(error) => return Some((Err(error), end)),
        },
        _ => {
            return Some((
                Err(format!("Unsupported RFC 2047 encoding {encoding:?}")),
                end,
            ));
        }
    };
    let decoded = decode_text_charset(&bytes, Some(charset)).map(|decoded| decoded.0);
    Some((decoded, end))
}

fn decode_rfc2047_q(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(encoded.len());
    let mut cursor = 0usize;
    while cursor < encoded.len() {
        match encoded[cursor] {
            b'_' => {
                out.push(b' ');
                cursor += 1;
            }
            b'=' => {
                let Some(high) = encoded.get(cursor + 1).and_then(|byte| hex_value(*byte)) else {
                    return Err("Invalid RFC 2047 Q encoded-word escape".to_string());
                };
                let Some(low) = encoded.get(cursor + 2).and_then(|byte| hex_value(*byte)) else {
                    return Err("Invalid RFC 2047 Q encoded-word escape".to_string());
                };
                out.push((high << 4) | low);
                cursor += 3;
            }
            byte => {
                out.push(byte);
                cursor += 1;
            }
        }
    }
    Ok(out)
}

fn extract_addresses(value: &str) -> Vec<String> {
    split_quoted(value, b',')
        .into_iter()
        .flat_map(|segment| split_quoted(&segment, b';'))
        .filter_map(|segment| {
            let trimmed = segment.trim();
            let candidate = trimmed
                .rfind('<')
                .and_then(|start| {
                    trimmed[start + 1..]
                        .find('>')
                        .map(|end| &trimmed[start + 1..start + 1 + end])
                })
                .unwrap_or(trimmed)
                .trim()
                .trim_matches('"');
            valid_addr_spec(candidate).then(|| candidate.to_string())
        })
        .collect()
}

fn valid_addr_spec(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn extract_message_ids(value: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut remainder = value;
    while let Some(start) = remainder.find('<') {
        let after = &remainder[start + 1..];
        let Some(end) = after.find('>') else { break };
        let candidate = &after[..end];
        if valid_addr_spec(candidate) {
            ids.push(format!("<{candidate}>"));
        }
        remainder = &after[end + 1..];
    }
    ids
}

fn attachment_filename_path_risks(filename: &str) -> Vec<String> {
    let mut risks = Vec::new();
    let normalized = filename.replace('\\', "/");
    if normalized.starts_with('/') || normalized.starts_with("//") {
        risks.push("absolute_or_unc_path".to_string());
    }
    if normalized
        .as_bytes()
        .get(1)
        .is_some_and(|byte| *byte == b':')
    {
        risks.push("drive_qualified_path".to_string());
    }
    if normalized.split('/').any(|component| component == "..") {
        risks.push("parent_traversal".to_string());
    }
    if filename.contains('\\') {
        risks.push("backslash_separator".to_string());
    }
    risks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read};

    /// Custom Read wrapper that returns data in 1-byte chunks to test split boundaries.
    struct TinyReader<R> {
        inner: R,
        chunk_size: usize,
    }

    impl<R: Read> TinyReader<R> {
        fn new(inner: R, chunk_size: usize) -> Self {
            Self { inner, chunk_size }
        }
    }

    impl<R: Read> Read for TinyReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let max_read = std::cmp::min(buf.len(), self.chunk_size);
            self.inner.read(&mut buf[..max_read])
        }
    }

    /// Custom Read implementation that simulates an I/O error mid-stream.
    struct FailingReader {
        bytes_before_error: usize,
        read_so_far: usize,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.read_so_far >= self.bytes_before_error {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Simulated I/O failure",
                ))
            } else {
                let to_read = std::cmp::min(buf.len(), self.bytes_before_error - self.read_so_far);
                for (i, slot) in buf[..to_read].iter_mut().enumerate() {
                    *slot = b"From: test@example.com\r\n"[i % 24];
                }
                self.read_so_far += to_read;
                Ok(to_read)
            }
        }
    }

    #[test]
    fn test_large_message_streaming() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"From: alice@example.com\r\n");
        msg.extend_from_slice(b"To: bob@example.com\r\n");
        msg.extend_from_slice(b"Cc: charlie@example.com\r\n");
        msg.extend_from_slice(b"Bcc: secret@example.com\r\n");
        msg.extend_from_slice(b"Subject: Test Large Email Stream\r\n");
        msg.extend_from_slice(b"Date: Sun, 26 Jul 2026 10:00:00 +0000\r\n");
        msg.extend_from_slice(b"Message-ID: <msg12345@example.com>\r\n");
        msg.extend_from_slice(b"Reply-To: support@example.com\r\n");
        msg.extend_from_slice(b"In-Reply-To: <ref99999@example.com>\r\n");
        msg.extend_from_slice(b"X-Custom-Header: Skipped Header Value\r\n");
        msg.extend_from_slice(b"\r\n"); // Header end

        // Add > 1.2 MiB body
        let line = b"This is a nonblank body line in a very large email message.\n";
        while msg.len() < 1_300_000 {
            msg.extend_from_slice(line);
        }

        let total_len = msg.len() as u64;
        let reader = Cursor::new(msg);
        let meta = parse_rfc822(reader).expect("Parsing large message failed");

        assert_eq!(meta.from.as_deref(), Some("alice@example.com"));
        assert_eq!(meta.to.as_deref(), Some("bob@example.com"));
        assert_eq!(meta.cc.as_deref(), Some("charlie@example.com"));
        assert_eq!(meta.bcc.as_deref(), Some("secret@example.com"));
        assert_eq!(meta.subject.as_deref(), Some("Test Large Email Stream"));
        assert_eq!(
            meta.date.as_deref(),
            Some("Sun, 26 Jul 2026 10:00:00 +0000")
        );
        assert_eq!(meta.message_id.as_deref(), Some("<msg12345@example.com>"));
        assert_eq!(meta.reply_to.as_deref(), Some("support@example.com"));
        assert_eq!(meta.in_reply_to.as_deref(), Some("<ref99999@example.com>"));

        assert_eq!(meta.skipped_headers_count, 1);
        assert!(meta.header_complete);
        assert!(!meta.header_truncated);
        assert!(meta.body_truncated);
        assert_eq!(meta.body_preview.chars().count(), MAX_BODY_PREVIEW_CHARS);
        assert_eq!(meta.bytes_consumed, total_len);
        assert!(meta.is_recognized());
    }

    #[test]
    fn test_separators_split_across_tiny_reads() {
        let eml = "From: sender@domain.com\r\nTo: recv@domain.com\r\nSubject: Folded\r\n  Subject Line\r\n\r\nFirst body line.\r\nSecond body line.\r\n";
        let tiny = TinyReader::new(Cursor::new(eml.as_bytes()), 1);
        let meta = parse_rfc822(tiny).expect("Tiny read parsing failed");

        assert_eq!(meta.from.as_deref(), Some("sender@domain.com"));
        assert_eq!(meta.to.as_deref(), Some("recv@domain.com"));
        assert_eq!(meta.subject.as_deref(), Some("Folded Subject Line"));
        assert_eq!(meta.body_preview, "First body line.\nSecond body line.");
        assert!(meta.header_complete);
        assert_eq!(meta.bytes_consumed, eml.len() as u64);
    }

    #[test]
    fn test_folded_headers() {
        let eml = "Subject: Line 1\r\n Line 2\r\n\tLine 3\r\nTo: Alice\r\n  <alice@a.com>,\r\n Bob <bob@b.com>\r\n\r\nBody text";
        let meta = parse_rfc822(Cursor::new(eml)).expect("Folded header parse failed");

        assert_eq!(meta.subject.as_deref(), Some("Line 1 Line 2 Line 3"));
        assert_eq!(
            meta.to.as_deref(),
            Some("Alice <alice@a.com>, Bob <bob@b.com>")
        );
        assert!(meta.header_complete);
    }

    #[test]
    fn test_utf8_split_boundaries() {
        let eml = "Subject: Header 😀 Emoji & Special Characters Café Ñ\r\nFrom: \"Testing 🌟\" <test@domain.com>\r\n\r\nBody line 1 with 😀 emoji.\r\nBody line 2 with 日本語 text.\r\n";
        let tiny = TinyReader::new(Cursor::new(eml.as_bytes()), 1);
        let meta = parse_rfc822(tiny).expect("UTF-8 split boundary test failed");

        assert_eq!(
            meta.subject.as_deref(),
            Some("Header 😀 Emoji & Special Characters Café Ñ")
        );
        assert_eq!(
            meta.from.as_deref(),
            Some("\"Testing 🌟\" <test@domain.com>")
        );
        assert!(meta.body_preview.contains("Body line 1 with 😀 emoji."));
        assert!(meta.body_preview.contains("Body line 2 with 日本語 text."));
    }

    #[test]
    fn test_pathological_overlong_header() {
        let mut eml = Vec::new();
        eml.extend_from_slice(b"From: normal@example.com\r\n");
        eml.extend_from_slice(b"X-Pathological-Header: ");
        eml.resize(eml.len() + 20_000, b'A');
        eml.extend_from_slice(b"\r\n");
        eml.extend_from_slice(b"Subject: Recovered Subject\r\n\r\nBody preview line.");

        let options = Rfc822ParserOptions {
            max_header_line_bytes: 4096,
            max_body_preview_chars: 1200,
        };

        let meta = parse_rfc822_with_options(Cursor::new(eml), &options)
            .expect("Pathological header parse failed");

        assert_eq!(meta.from.as_deref(), Some("normal@example.com"));
        assert_eq!(meta.subject.as_deref(), Some("Recovered Subject"));
        assert_eq!(meta.body_preview, "Body preview line.");
        assert!(meta.pathological_header_detected);
        assert!(meta.header_truncated);
        assert!(meta.malformed_lines_count > 0);
        assert!(meta.error_count > 0);
        assert!(meta
            .diagnostics
            .iter()
            .any(|d| d.contains("exceeded limit of 4096 bytes")));
    }

    #[test]
    fn test_missing_separator_and_unrecognized_input() {
        let eml = "From: no_separator@example.com\r\nSubject: Truncated Stream";
        let meta = parse_rfc822(Cursor::new(eml)).expect("Missing separator test failed");

        assert!(!meta.header_complete);
        assert_eq!(meta.from.as_deref(), Some("no_separator@example.com"));
        assert_eq!(meta.subject.as_deref(), Some("Truncated Stream"));
        assert!(meta
            .diagnostics
            .iter()
            .any(|d| d.contains("Missing header-body separator")));
    }

    #[test]
    fn test_malformed_header_lines() {
        let eml = "From: valid@example.com\r\nThis line has no colon separator\r\nSubject: Valid Subject\r\n\r\nBody";
        let meta = parse_rfc822(Cursor::new(eml)).expect("Malformed line test failed");

        assert_eq!(meta.from.as_deref(), Some("valid@example.com"));
        assert_eq!(meta.subject.as_deref(), Some("Valid Subject"));
        assert_eq!(meta.malformed_lines_count, 1);
        assert_eq!(meta.error_count, 1);
        assert!(meta.diagnostics.iter().any(|d| d.contains("missing colon")));
    }

    #[test]
    fn test_io_error_propagation() {
        let reader = FailingReader {
            bytes_before_error: 50,
            read_so_far: 0,
        };
        let res = parse_rfc822(reader);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_bounded_retained_memory() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"From: memory_test@example.com\r\n\r\n");
        // 5 MiB of body lines
        let chunk = b"Line of text with some content to test bounded memory usage.\n";
        while msg.len() < 5_000_000 {
            msg.extend_from_slice(chunk);
        }

        let expected_len = msg.len() as u64;
        let reader = Cursor::new(msg);
        let meta = parse_rfc822(reader).expect("Memory test failed");

        assert!(meta.body_preview.len() <= MAX_BODY_PREVIEW_CHARS * 4);
        assert_eq!(meta.body_preview.chars().count(), MAX_BODY_PREVIEW_CHARS);
        assert!(meta.body_truncated);
        assert_eq!(meta.bytes_consumed, expected_len);
    }

    #[test]
    fn recovers_gold_unindented_empty_header_values_with_disclosure() {
        let eml =
            "Subject:\r\nFound key\r\nFrom:\r\nFrank Analyst <frank@example.test>\r\n\r\nBody";
        let meta = parse_rfc822(Cursor::new(eml)).expect("gold-style message parses");

        assert_eq!(meta.subject.as_deref(), Some("Found key"));
        assert_eq!(
            meta.from.as_deref(),
            Some("Frank Analyst <frank@example.test>")
        );
        assert!(meta.is_recognized());
        assert!(meta.malformed_lines_count >= 2);
        assert!(meta
            .diagnostics
            .iter()
            .any(|value| value.contains("Recovered an unindented value")));
    }

    #[test]
    fn folded_header_and_diagnostics_are_bounded() {
        let mut folded = String::from("Subject: retained\r\n");
        for _ in 0..2_000 {
            folded.push_str(" continuation-value-that-must-not-grow-without-bound\r\n");
        }
        folded.push_str("\r\nBody");
        let meta = parse_rfc822(Cursor::new(folded)).expect("folded message parses");
        assert!(meta
            .subject
            .as_ref()
            .is_some_and(|value| value.len() <= DEFAULT_MAX_HEADER_LINE_BYTES));
        assert!(meta.header_truncated);

        let mut malformed = String::from("From: sender@example.test\r\n");
        for index in 0..200 {
            malformed.push_str(&format!("malformed line {index}\r\n"));
        }
        malformed.push_str("\r\nBody");
        let meta = parse_rfc822(Cursor::new(malformed)).expect("malformed message parses");
        assert_eq!(meta.diagnostics.len(), MAX_DIAGNOSTICS);
        assert!(meta.diagnostics_omitted_count > 0);
        assert!(meta
            .diagnostics
            .iter()
            .all(|value| value.chars().count() <= MAX_DIAGNOSTIC_CHARS));
    }

    #[test]
    fn body_only_and_empty_target_headers_are_not_recognized() {
        let body_only = parse_rfc822(Cursor::new("\r\nordinary body"))
            .expect("body-only text parses defensively");
        assert!(!body_only.is_recognized());

        let empty = parse_rfc822(Cursor::new("From:\r\nSubject:\r\n\r\nBody"))
            .expect("empty headers parse defensively");
        assert!(!empty.is_recognized());
    }

    #[test]
    fn body_truncation_requires_an_omitted_character() {
        let exact = format!("From: sender@example.test\r\n\r\n{}", "x".repeat(12));
        let options = Rfc822ParserOptions {
            max_header_line_bytes: DEFAULT_MAX_HEADER_LINE_BYTES,
            max_body_preview_chars: 12,
        };
        let meta =
            parse_rfc822_with_options(Cursor::new(exact), &options).expect("exact preview parses");
        assert_eq!(meta.body_preview.chars().count(), 12);
        assert!(!meta.body_truncated);

        let over = format!("From: sender@example.test\r\n\r\n{}", "x".repeat(13));
        let meta = parse_rfc822_with_options(Cursor::new(over), &options)
            .expect("overlong preview parses");
        assert_eq!(meta.body_preview.chars().count(), 12);
        assert!(meta.body_truncated);
    }

    #[test]
    fn nested_mime_decodes_body_and_hashes_attachment_without_mixing_bytes() {
        let eml = concat!(
            "From: =?UTF-8?Q?Alice_Analyst?= <alice@example.test>\r\n",
            "To: Bob <bob@example.test>\r\n",
            "Subject: =?UTF-8?B?Rm9yZW5zaWMg8J+UkQ==?=\r\n",
            "Date: Mon, 24 Aug 2026 16:30:00 +0300\r\n",
            "Message-ID: <case-1@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
            "\r\n",
            "preamble is not a body\r\n",
            "--outer\r\n",
            "Content-Type: multipart/alternative; boundary=inner\r\n",
            "\r\n",
            "--inner\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Hello=20world=21\r\nSecond line.\r\n",
            "--inner\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "PHA+SGVsbG8gd29ybGQhPC9wPg==\r\n",
            "--inner--\r\n",
            "--outer\r\n",
            "Content-Type: application/octet-stream; name=evil.bin\r\n",
            "Content-Disposition: attachment; filename=\"../../evil.bin\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "AAECAwQ=\r\n",
            "--outer--\r\n"
        );
        let meta = parse_rfc822(Cursor::new(eml.as_bytes())).expect("nested MIME parses");

        assert_eq!(meta.parser_status, Rfc822ParseStatus::Complete);
        assert_eq!(meta.subject.as_deref(), Some("Forensic 🔑"));
        assert_eq!(meta.from_addresses, ["alice@example.test"]);
        assert_eq!(meta.to_addresses, ["bob@example.test"]);
        assert_eq!(meta.message_ids, ["<case-1@example.test>"]);
        assert_eq!(meta.date_utc.as_deref(), Some("2026-08-24T13:30:00+00:00"));
        assert_eq!(meta.body_preview, "Hello world!\nSecond line.");
        assert!(!meta.body_preview.contains("outer"));
        assert!(!meta.body_preview.contains("AAECAwQ"));
        assert_eq!(meta.attachment_count, 1);
        assert_eq!(meta.searchable_text_segments.len(), 2);
        assert_eq!(
            meta.searchable_text_segments[0].content,
            "Hello world!\r\nSecond line."
        );
        assert!(meta.searchable_text_segments[0].content_complete);

        let attachment = meta
            .mime_parts
            .iter()
            .find(|part| part.is_attachment)
            .expect("attachment metadata retained");
        assert_eq!(attachment.filename.as_deref(), Some("../../evil.bin"));
        assert!(attachment
            .filename_path_risks
            .contains(&"parent_traversal".to_string()));
        assert_eq!(attachment.decoded_size, Some(5));
        let expected_attachment_sha256 = sha256_hex(&[0, 1, 2, 3, 4]);
        assert_eq!(
            attachment.decoded_sha256.as_deref(),
            Some(expected_attachment_sha256.as_str())
        );
        assert!(attachment.decoded_content_complete);
        let raw_body =
            &eml.as_bytes()[attachment.body_start as usize..attachment.body_end as usize];
        assert!(raw_body.starts_with(b"AAECAwQ="));
        let expected_raw_body_sha256 = sha256_hex(raw_body);
        assert_eq!(
            attachment.raw_body_sha256.as_deref(),
            Some(expected_raw_body_sha256.as_str())
        );
        let expected_message_sha256 = sha256_hex(eml.as_bytes());
        assert_eq!(
            meta.raw_message_sha256.as_deref(),
            Some(expected_message_sha256.as_str())
        );
    }

    #[test]
    fn unsupported_transfer_encoding_is_metadata_only_not_a_false_body() {
        let eml = concat!(
            "From: a@example.test\r\n",
            "Subject: Unsupported transfer\r\n",
            "Content-Type: text/plain; charset=x-unknown\r\n",
            "Content-Transfer-Encoding: x-kdft-rot13\r\n",
            "\r\n",
            "frperg-obql"
        );
        let meta = parse_rfc822(Cursor::new(eml)).expect("unsupported message is inventoried");
        assert_eq!(meta.parser_status, Rfc822ParseStatus::Unsupported);
        assert!(meta.body_preview.is_empty());
        assert!(meta.searchable_text_segments.is_empty());
        assert_eq!(meta.unsupported_part_count, 1);
        assert_eq!(meta.mime_parts[0].decoded_sha256, None);
        assert!(meta.mime_parts[0]
            .diagnostics
            .iter()
            .any(|value| value.contains("Unsupported Content-Transfer-Encoding")));
    }

    #[test]
    fn malformed_transfer_and_unclosed_boundary_are_partial_not_complete() {
        let malformed_qp = concat!(
            "From: a@example.test\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n\r\n",
            "broken=QZvalue"
        );
        let meta = parse_rfc822(Cursor::new(malformed_qp)).expect("malformed QP is retained");
        assert_eq!(meta.parser_status, Rfc822ParseStatus::Partial);
        assert_eq!(meta.partial_part_count, 1);
        assert_eq!(meta.mime_parts[0].decoded_sha256, None);
        assert!(meta.searchable_text_segments.is_empty());

        let unclosed = concat!(
            "From: a@example.test\r\n",
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\nContent-Type: text/plain\r\n\r\npartial body"
        );
        let meta = parse_rfc822(Cursor::new(unclosed)).expect("unclosed multipart is retained");
        assert_eq!(meta.parser_status, Rfc822ParseStatus::Partial);
        assert_eq!(meta.partial_part_count, 2);
        assert!(meta.mime_parts[0]
            .diagnostics
            .iter()
            .any(|value| value.contains("closing boundary")));
    }

    #[test]
    fn rfc2047_charset_and_folded_adjacent_words_decode_without_spurious_space() {
        let eml = concat!(
            "From: =?windows-1252?Q?Andr=E9?= <andre@example.test>\r\n",
            "Subject: =?UTF-8?Q?one?=\r\n",
            " =?UTF-8?Q?_two?=\r\n",
            "Content-Type: text/plain; charset=windows-1252\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n\r\n",
            "caf=E9"
        );
        let meta = parse_rfc822(Cursor::new(eml)).expect("declared charsets decode");
        assert_eq!(meta.from.as_deref(), Some("André <andre@example.test>"));
        assert_eq!(meta.subject.as_deref(), Some("one two"));
        assert_eq!(meta.body_preview, "café");
        assert_eq!(meta.searchable_text_segments[0].content, "café");
    }

    #[test]
    fn searchable_text_budget_is_explicit_and_hash_still_covers_full_body() {
        let body = "x".repeat(MAX_SEARCHABLE_TEXT_BYTES + 19);
        let eml = format!(
            "From: a@example.test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
        );
        let meta = parse_rfc822(Cursor::new(eml)).expect("bounded large text parses");
        assert_eq!(meta.parser_status, Rfc822ParseStatus::LimitReached);
        assert_eq!(meta.searchable_text_segments.len(), 1);
        assert_eq!(
            meta.searchable_text_segments[0].content.len(),
            MAX_SEARCHABLE_TEXT_BYTES
        );
        assert!(!meta.searchable_text_segments[0].content_complete);
        assert!(meta.mime_parts[0].decoded_content_complete);
        assert!(meta.mime_parts[0].decoded_sha256.is_some());
        assert_eq!(meta.mime_parts[0].status, Rfc822ParseStatus::LimitReached);
        assert_eq!(meta.partial_part_count, 0);
    }

    #[test]
    fn invalid_parser_options_are_rejected() {
        let zero = Rfc822ParserOptions {
            max_header_line_bytes: 0,
            max_body_preview_chars: 1,
        };
        assert_eq!(
            parse_rfc822_with_options(Cursor::new("From: a\r\n\r\n"), &zero)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let oversized = Rfc822ParserOptions {
            max_header_line_bytes: DEFAULT_MAX_HEADER_LINE_BYTES,
            max_body_preview_chars: MAX_CONFIG_BODY_PREVIEW_CHARS + 1,
        };
        assert_eq!(
            parse_rfc822_with_options(Cursor::new("From: a\r\n\r\n"), &oversized)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
