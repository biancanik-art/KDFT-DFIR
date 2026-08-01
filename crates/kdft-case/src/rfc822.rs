//! Bounded-memory streaming RFC 822 / EML metadata parser.
//!
//! Provides streaming extraction of key RFC 822 email metadata fields (From, To,
//! Cc, Bcc, Subject, Date, Message-ID, Reply-To, In-Reply-To) and a bounded 1,200-character
//! nonblank-line body preview without loading the full message into memory.

use std::borrow::Cow;
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

    /// Retained nonblank-line body preview (up to 1,200 Unicode characters).
    pub body_preview: String,

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

    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };

        meta.bytes_consumed = meta.bytes_consumed.saturating_add(n as u64);

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

    meta.recognized_status = meta.has_any_target_header();
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
