//! Bounded-memory, read-only ZIP package traversal.
//!
//! Members are never extracted to filesystem paths. The member name returned
//! by [`zip::read::ZipFile::name`] is reported unchanged, alongside its raw ZIP
//! bytes. Callers receive textual member payloads as ordered, borrowed byte
//! segments so they can apply the appropriate character encoding without this
//! layer altering forensic content.
//!
//! There is deliberately no member-count or total-content limit. Memory use is
//! bounded independently of archive size. Binary members are also streamed to
//! EOF (without content callbacks) so decompression and CRC errors are surfaced.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Seek};

use zip::result::ZipError;
use zip::{CompressionMethod, ZipArchive};

/// Maximum uncompressed payload in one text event.
pub const TEXT_SEGMENT_BYTES: usize = 64 * 1024;

const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "csv", "tsv", "json", "xml", "html", "htm", "md", "log", "ini", "cfg", "yaml", "yml",
];

/// Immutable metadata for one central-directory member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipMemberMetadata {
    /// Stable zero-based position in the ZIP central directory.
    pub archive_index: usize,
    /// Canonical decoded package name returned by the ZIP reader, unchanged.
    pub name: String,
    /// Exact internal filename bytes reported by the ZIP reader.
    pub name_raw: Vec<u8>,
    pub is_directory: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub compression_method: CompressionMethod,
    /// Whether content is emitted, based only on the member's extension.
    pub is_textual: bool,
}

/// A transient event emitted while walking an archive.
///
/// Borrowed values are valid only for the duration of the callback. A caller
/// that needs to retain them must copy them into its own bounded/persistent
/// storage.
#[derive(Debug, Clone, Copy)]
pub enum ZipEvent<'a> {
    /// Emitted exactly once before content is read for an accepted member.
    Member(&'a ZipMemberMetadata),
    /// Exact uncompressed bytes from a member with a textual extension.
    TextSegment {
        member: &'a ZipMemberMetadata,
        segment_index: u64,
        byte_offset: u64,
        bytes: &'a [u8],
        is_final: bool,
    },
}

/// Aggregate counts returned after every member has been validated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZipParseSummary {
    pub member_count: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub text_member_count: usize,
    pub text_segment_count: u64,
    /// Includes content read only for validation, such as binary members.
    pub uncompressed_bytes_read: u128,
    pub text_bytes_emitted: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipParserErrorKind {
    InvalidArchive,
    UnsupportedArchive,
    ArchiveIo,
    CorruptMember,
    EncryptedMember,
    UnsupportedMember,
    MemberIo,
    CounterOverflow,
}

impl ZipParserErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArchive => "invalid_archive",
            Self::UnsupportedArchive => "unsupported_archive",
            Self::ArchiveIo => "archive_io",
            Self::CorruptMember => "corrupt_member",
            Self::EncryptedMember => "encrypted_member",
            Self::UnsupportedMember => "unsupported_member",
            Self::MemberIo => "member_io",
            Self::CounterOverflow => "counter_overflow",
        }
    }
}

/// Parser failure with stable member context where available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipParserError {
    pub kind: ZipParserErrorKind,
    pub archive_index: Option<usize>,
    pub member_name: Option<String>,
    pub compression_method: Option<CompressionMethod>,
    pub message: String,
}

impl ZipParserError {
    fn archive(kind: ZipParserErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            archive_index: None,
            member_name: None,
            compression_method: None,
            message: message.into(),
        }
    }

    fn member(
        kind: ZipParserErrorKind,
        archive_index: usize,
        member_name: Option<String>,
        compression_method: Option<CompressionMethod>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            archive_index: Some(archive_index),
            member_name,
            compression_method,
            message: message.into(),
        }
    }
}

impl fmt::Display for ZipParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ZIP {} error", self.kind.as_str())?;
        if let Some(index) = self.archive_index {
            write!(formatter, " at member {index}")?;
        }
        if let Some(name) = &self.member_name {
            write!(formatter, " ({name:?})")?;
        }
        write!(formatter, ": {}", self.message)
    }
}

impl Error for ZipParserError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipCallbackEventKind {
    Member,
    TextSegment,
}

/// Either a parser failure or a caller callback failure.
#[derive(Debug)]
pub enum ZipParseError<E> {
    Parser(ZipParserError),
    Callback {
        archive_index: usize,
        member_name: String,
        event_kind: ZipCallbackEventKind,
        source: E,
    },
}

impl<E> From<ZipParserError> for ZipParseError<E> {
    fn from(error: ZipParserError) -> Self {
        Self::Parser(error)
    }
}

impl<E: fmt::Display> fmt::Display for ZipParseError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parser(error) => error.fmt(formatter),
            Self::Callback {
                archive_index,
                member_name,
                event_kind,
                source,
            } => write!(
                formatter,
                "ZIP callback error during {event_kind:?} for member {archive_index} ({member_name:?}): {source}"
            ),
        }
    }
}

impl<E: Error + 'static> Error for ZipParseError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parser(error) => Some(error),
            Self::Callback { source, .. } => Some(source),
        }
    }
}

/// Walk a ZIP with an infallible callback.
pub fn parse_zip<R, F>(reader: R, mut on_event: F) -> Result<ZipParseSummary, ZipParserError>
where
    R: Read + Seek,
    F: for<'event> FnMut(ZipEvent<'event>),
{
    match try_parse_zip(reader, |event| {
        on_event(event);
        Ok::<(), Infallible>(())
    }) {
        Ok(summary) => Ok(summary),
        Err(ZipParseError::Parser(error)) => Err(error),
        Err(ZipParseError::Callback { source, .. }) => match source {},
    }
}

/// Walk a ZIP with a fallible callback while keeping memory bounded.
///
/// Text segmentation is based on extension only. Segment bytes and package
/// names are never decoded, sanitized, normalized, or written to disk. A CRC
/// failure can occur after earlier callbacks, so callers persisting events
/// should use a transaction if they require all-or-nothing ingestion.
pub fn try_parse_zip<R, F, E>(
    reader: R,
    mut on_event: F,
) -> Result<ZipParseSummary, ZipParseError<E>>
where
    R: Read + Seek,
    F: for<'event> FnMut(ZipEvent<'event>) -> Result<(), E>,
{
    let mut archive = ZipArchive::new(reader)
        .map_err(|error| ZipParseError::Parser(classify_archive_error(error)))?;
    let member_count = archive.len();
    let mut summary = ZipParseSummary {
        member_count,
        ..ZipParseSummary::default()
    };

    for archive_index in 0..member_count {
        let known_name = archive.name_for_index(archive_index).map(str::to_owned);
        let raw_member = archive.by_index_raw(archive_index).map_err(|error| {
            ZipParseError::Parser(classify_member_zip_error(
                archive_index,
                known_name.clone(),
                None,
                error,
            ))
        })?;

        let compression_method = raw_member.compression();
        let metadata = ZipMemberMetadata {
            archive_index,
            name: raw_member.name().to_owned(),
            name_raw: raw_member.name_raw().to_vec(),
            is_directory: raw_member.is_dir(),
            compressed_size: raw_member.compressed_size(),
            uncompressed_size: raw_member.size(),
            crc32: raw_member.crc32(),
            compression_method,
            is_textual: !raw_member.is_dir() && has_text_extension(raw_member.name()),
        };
        let encrypted = raw_member.encrypted();
        drop(raw_member);

        if encrypted {
            return Err(ZipParserError::member(
                ZipParserErrorKind::EncryptedMember,
                archive_index,
                Some(metadata.name.clone()),
                Some(compression_method),
                "encrypted ZIP members require a password and are not accepted",
            )
            .into());
        }
        if let Some(method_code) = unsupported_method_code(compression_method) {
            return Err(ZipParserError::member(
                ZipParserErrorKind::UnsupportedMember,
                archive_index,
                Some(metadata.name.clone()),
                Some(compression_method),
                format!("compression method {method_code} is not supported by this build"),
            )
            .into());
        }

        on_event(ZipEvent::Member(&metadata)).map_err(|source| ZipParseError::Callback {
            archive_index,
            member_name: metadata.name.clone(),
            event_kind: ZipCallbackEventKind::Member,
            source,
        })?;

        if metadata.is_directory {
            summary.directory_count += 1;
        } else {
            summary.file_count += 1;
        }
        if metadata.is_textual {
            summary.text_member_count += 1;
        }

        let mut member = archive.by_index(archive_index).map_err(|error| {
            ZipParseError::Parser(classify_member_zip_error(
                archive_index,
                Some(metadata.name.clone()),
                Some(compression_method),
                error,
            ))
        })?;

        let member_bytes_read = if metadata.is_textual {
            stream_text_member(&mut member, &metadata, &mut on_event, &mut summary)?
        } else {
            stream_validation_only(&mut member, &metadata)?
        };

        if member_bytes_read != metadata.uncompressed_size {
            return Err(ZipParserError::member(
                ZipParserErrorKind::CorruptMember,
                archive_index,
                Some(metadata.name.clone()),
                Some(compression_method),
                format!(
                    "uncompressed size mismatch: central directory declares {}, read {}",
                    metadata.uncompressed_size, member_bytes_read
                ),
            )
            .into());
        }
        summary.uncompressed_bytes_read += u128::from(member_bytes_read);
    }

    Ok(summary)
}

fn stream_text_member<R, F, E>(
    member: &mut R,
    metadata: &ZipMemberMetadata,
    on_event: &mut F,
    summary: &mut ZipParseSummary,
) -> Result<u64, ZipParseError<E>>
where
    R: Read,
    F: for<'event> FnMut(ZipEvent<'event>) -> Result<(), E>,
{
    // One-segment lookahead marks the final segment and forces the ZIP reader
    // to validate CRC before that final segment is published.
    let mut current = [0_u8; TEXT_SEGMENT_BYTES];
    let mut next = [0_u8; TEXT_SEGMENT_BYTES];
    let mut current_len = read_member_chunk(member, &mut current, metadata)?;
    let mut bytes_read = current_len as u64;
    let mut byte_offset = 0_u64;
    let mut segment_index = 0_u64;

    while current_len != 0 {
        let next_len = read_member_chunk(member, &mut next, metadata)?;
        bytes_read = bytes_read.checked_add(next_len as u64).ok_or_else(|| {
            ZipParseError::Parser(counter_overflow_error(metadata, "member byte count"))
        })?;

        on_event(ZipEvent::TextSegment {
            member: metadata,
            segment_index,
            byte_offset,
            bytes: &current[..current_len],
            is_final: next_len == 0,
        })
        .map_err(|source| ZipParseError::Callback {
            archive_index: metadata.archive_index,
            member_name: metadata.name.clone(),
            event_kind: ZipCallbackEventKind::TextSegment,
            source,
        })?;

        summary.text_segment_count =
            summary.text_segment_count.checked_add(1).ok_or_else(|| {
                ZipParseError::Parser(counter_overflow_error(metadata, "text segment count"))
            })?;
        summary.text_bytes_emitted += current_len as u128;
        byte_offset = byte_offset.checked_add(current_len as u64).ok_or_else(|| {
            ZipParseError::Parser(counter_overflow_error(metadata, "text byte offset"))
        })?;
        segment_index = segment_index.checked_add(1).ok_or_else(|| {
            ZipParseError::Parser(counter_overflow_error(metadata, "member segment index"))
        })?;

        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }

    Ok(bytes_read)
}

fn stream_validation_only<R: Read>(
    member: &mut R,
    metadata: &ZipMemberMetadata,
) -> Result<u64, ZipParserError> {
    let mut buffer = [0_u8; TEXT_SEGMENT_BYTES];
    let mut bytes_read = 0_u64;
    loop {
        let count = read_member_chunk(member, &mut buffer, metadata)?;
        if count == 0 {
            return Ok(bytes_read);
        }
        bytes_read = bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| counter_overflow_error(metadata, "member byte count"))?;
    }
}

fn read_member_chunk<R: Read>(
    member: &mut R,
    buffer: &mut [u8],
    metadata: &ZipMemberMetadata,
) -> Result<usize, ZipParserError> {
    member.read(buffer).map_err(|error| {
        let kind = match error.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                ZipParserErrorKind::CorruptMember
            }
            io::ErrorKind::Unsupported => ZipParserErrorKind::UnsupportedMember,
            _ => ZipParserErrorKind::MemberIo,
        };
        ZipParserError::member(
            kind,
            metadata.archive_index,
            Some(metadata.name.clone()),
            Some(metadata.compression_method),
            error.to_string(),
        )
    })
}

fn has_text_extension(name: &str) -> bool {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let Some((_, extension)) = leaf.rsplit_once('.') else {
        return false;
    };
    TEXT_EXTENSIONS
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

#[allow(deprecated)]
fn unsupported_method_code(method: CompressionMethod) -> Option<u16> {
    match method {
        CompressionMethod::Unsupported(code) => Some(code),
        _ => None,
    }
}

fn classify_archive_error(error: ZipError) -> ZipParserError {
    let kind = match &error {
        ZipError::InvalidArchive(_) | ZipError::FileNotFound => ZipParserErrorKind::InvalidArchive,
        ZipError::UnsupportedArchive(_) | ZipError::InvalidPassword => {
            ZipParserErrorKind::UnsupportedArchive
        }
        ZipError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ) =>
        {
            ZipParserErrorKind::InvalidArchive
        }
        ZipError::Io(_) => ZipParserErrorKind::ArchiveIo,
        _ => ZipParserErrorKind::UnsupportedArchive,
    };
    ZipParserError::archive(kind, error.to_string())
}

fn classify_member_zip_error(
    archive_index: usize,
    member_name: Option<String>,
    compression_method: Option<CompressionMethod>,
    error: ZipError,
) -> ZipParserError {
    let kind = match &error {
        ZipError::UnsupportedArchive(message) if *message == ZipError::PASSWORD_REQUIRED => {
            ZipParserErrorKind::EncryptedMember
        }
        ZipError::UnsupportedArchive(_) => ZipParserErrorKind::UnsupportedMember,
        ZipError::InvalidPassword => ZipParserErrorKind::EncryptedMember,
        ZipError::InvalidArchive(_) | ZipError::FileNotFound => ZipParserErrorKind::CorruptMember,
        ZipError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ) =>
        {
            ZipParserErrorKind::CorruptMember
        }
        ZipError::Io(error) if error.kind() == io::ErrorKind::Unsupported => {
            ZipParserErrorKind::UnsupportedMember
        }
        ZipError::Io(_) => ZipParserErrorKind::MemberIo,
        _ => ZipParserErrorKind::UnsupportedMember,
    };
    ZipParserError::member(
        kind,
        archive_index,
        member_name,
        compression_method,
        error.to_string(),
    )
}

fn counter_overflow_error(metadata: &ZipMemberMetadata, counter: &str) -> ZipParserError {
    ZipParserError::member(
        ZipParserErrorKind::CounterOverflow,
        metadata.archive_index,
        Some(metadata.name.clone()),
        Some(metadata.compression_method),
        format!("{counter} exceeded its numeric representation"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn single_file_zip(name: &str, data: &[u8], method: CompressionMethod) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(method);
        writer.start_file(name, options).unwrap();
        writer.write_all(data).unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn enumerates_past_an_artificial_1024_member_cap() {
        const ARTIFICIAL_OLD_CAP: usize = 1_024;
        const EXPECTED: usize = ARTIFICIAL_OLD_CAP + 37;

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for index in 0..EXPECTED {
            writer
                .start_file(format!("entries/{index:04}.bin"), options)
                .unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();

        let mut indices = Vec::new();
        let summary = parse_zip(Cursor::new(bytes), |event| {
            if let ZipEvent::Member(member) = event {
                indices.push(member.archive_index);
            }
        })
        .unwrap();

        assert_eq!(summary.member_count, EXPECTED);
        assert_eq!(summary.file_count, EXPECTED);
        assert_eq!(indices.len(), EXPECTED);
        assert_eq!(indices[ARTIFICIAL_OLD_CAP], ARTIFICIAL_OLD_CAP);
        assert_eq!(indices.last(), Some(&(EXPECTED - 1)));
    }

    #[test]
    fn preserves_nested_names_and_raw_package_names() {
        let exact_name = "nested/../gold/Case Notes.TXT";
        let payload = b"gold evidence";
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.add_directory("nested/", options).unwrap();
        writer.start_file(exact_name, options).unwrap();
        writer.write_all(payload).unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let mut members = Vec::new();
        let mut extracted = Vec::new();
        let summary = parse_zip(Cursor::new(bytes), |event| match event {
            ZipEvent::Member(member) => members.push(member.clone()),
            ZipEvent::TextSegment { bytes, .. } => extracted.extend_from_slice(bytes),
        })
        .unwrap();

        assert_eq!(summary.member_count, 2);
        assert!(members[0].is_directory);
        assert_eq!(members[0].name, "nested/");
        assert_eq!(members[1].archive_index, 1);
        assert_eq!(members[1].name, exact_name);
        assert_eq!(members[1].name_raw, exact_name.as_bytes());
        assert!(members[1].is_textual);
        assert_eq!(extracted, payload);
    }

    #[test]
    fn preserves_the_tail_after_a_full_text_segment() {
        let mut payload = vec![b'a'; TEXT_SEGMENT_BYTES];
        payload.extend_from_slice(b"tail-survives");
        let bytes = single_file_zip("notes.md", &payload, CompressionMethod::Deflated);

        let mut segments = Vec::new();
        let mut offsets = Vec::new();
        let mut final_flags = Vec::new();
        let summary = parse_zip(Cursor::new(bytes), |event| {
            if let ZipEvent::TextSegment {
                byte_offset,
                bytes,
                is_final,
                ..
            } = event
            {
                offsets.push(byte_offset);
                segments.push(bytes.to_vec());
                final_flags.push(is_final);
            }
        })
        .unwrap();

        assert!(segments.len() >= 2);
        assert_eq!(offsets[0], 0);
        assert_eq!(final_flags.iter().filter(|flag| **flag).count(), 1);
        assert_eq!(final_flags.last(), Some(&true));
        assert_eq!(segments.concat(), payload);
        assert_eq!(summary.text_bytes_emitted, payload.len() as u128);
        assert_eq!(summary.uncompressed_bytes_read, payload.len() as u128);
    }

    #[test]
    fn reports_binary_metadata_without_emitting_binary_content() {
        // CRC32 for the standard test vector "123456789".
        let payload = b"123456789";
        let bytes = single_file_zip("objects/blob.bin", payload, CompressionMethod::Stored);
        let mut metadata = None;
        let mut text_events = 0;

        let summary = parse_zip(Cursor::new(bytes), |event| match event {
            ZipEvent::Member(member) => metadata = Some(member.clone()),
            ZipEvent::TextSegment { .. } => text_events += 1,
        })
        .unwrap();
        let metadata = metadata.unwrap();

        assert_eq!(metadata.archive_index, 0);
        assert_eq!(metadata.compressed_size, payload.len() as u64);
        assert_eq!(metadata.uncompressed_size, payload.len() as u64);
        assert_eq!(metadata.crc32, 0xcbf4_3926);
        assert_eq!(metadata.compression_method, CompressionMethod::Stored);
        assert!(!metadata.is_textual);
        assert_eq!(text_events, 0);
        assert_eq!(summary.uncompressed_bytes_read, payload.len() as u128);
    }

    #[test]
    fn rejects_invalid_and_checksum_corrupt_archives_explicitly() {
        let invalid = parse_zip(Cursor::new(b"not a ZIP archive".to_vec()), |_| {}).unwrap_err();
        assert_eq!(invalid.kind, ZipParserErrorKind::InvalidArchive);

        let payload = b"unique-stored-payload-for-crc-test";
        let mut corrupt = single_file_zip("corrupt.txt", payload, CompressionMethod::Stored);
        let payload_offset = corrupt
            .windows(payload.len())
            .position(|window| window == payload)
            .unwrap();
        corrupt[payload_offset] ^= 0x40;

        let checksum_error = parse_zip(Cursor::new(corrupt), |_| {}).unwrap_err();
        assert_eq!(checksum_error.kind, ZipParserErrorKind::CorruptMember);
        assert_eq!(checksum_error.archive_index, Some(0));
        assert_eq!(checksum_error.member_name.as_deref(), Some("corrupt.txt"));
        assert!(checksum_error.message.contains("checksum"));
    }

    #[test]
    fn rejects_encrypted_and_unsupported_members_before_content_events() {
        let payload = b"content";

        let mut encrypted = single_file_zip("secret.txt", payload, CompressionMethod::Stored);
        patch_u16_after_signature(&mut encrypted, b"PK\x03\x04", 6, 1);
        patch_u16_after_signature(&mut encrypted, b"PK\x01\x02", 8, 1);
        let mut encrypted_events = 0;
        let encrypted_error =
            parse_zip(Cursor::new(encrypted), |_| encrypted_events += 1).unwrap_err();
        assert_eq!(encrypted_events, 0);
        assert_eq!(encrypted_error.kind, ZipParserErrorKind::EncryptedMember);
        assert_eq!(encrypted_error.member_name.as_deref(), Some("secret.txt"));

        let mut unsupported = single_file_zip("odd.txt", payload, CompressionMethod::Stored);
        patch_u16_after_signature(&mut unsupported, b"PK\x03\x04", 8, 98);
        patch_u16_after_signature(&mut unsupported, b"PK\x01\x02", 10, 98);
        let unsupported_error = parse_zip(Cursor::new(unsupported), |_| {}).unwrap_err();
        assert_eq!(
            unsupported_error.kind,
            ZipParserErrorKind::UnsupportedMember
        );
        assert_eq!(unsupported_error.member_name.as_deref(), Some("odd.txt"));
        assert!(unsupported_error.message.contains("98"));
    }

    fn patch_u16_after_signature(bytes: &mut [u8], signature: &[u8], offset: usize, value: u16) {
        let signature_offset = bytes
            .windows(signature.len())
            .position(|window| window == signature)
            .unwrap();
        let field_offset = signature_offset + offset;
        bytes[field_offset..field_offset + 2].copy_from_slice(&value.to_le_bytes());
    }
}
