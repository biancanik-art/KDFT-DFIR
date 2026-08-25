//! Bounded-memory, read-only ZIP package traversal.
//!
//! Members are never extracted to filesystem paths. Potentially dangerous
//! member names are retained as evidence and labelled, never normalized into a
//! host path. The member name returned by [`zip::read::ZipFile::name`] is
//! reported unchanged alongside the filename bytes selected by the ZIP reader.
//! (A valid Info-ZIP Unicode Path extra field can replace the literal central
//! directory filename bytes, so those selected bytes are not falsely described
//! as the on-disk filename field.) Callers receive textual member payloads as
//! ordered, borrowed byte segments so they can apply the appropriate character
//! encoding without this layer altering forensic content.
//!
//! There is deliberately no member-count or total-content coverage limit.
//! Payload buffering is bounded independently of archive size; the upstream ZIP
//! reader retains central-directory metadata proportional to the member count.
//! Binary members are also streamed to EOF (without content callbacks) so
//! decompression and CRC errors are surfaced. A bad, encrypted, or unsupported
//! member does not hide unrelated valid members.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Seek};

use zip::read::HasZipMetadata;
use zip::result::ZipError;
use zip::{CompressionMethod, ZipArchive};

/// Maximum uncompressed payload in one text event.
pub const TEXT_SEGMENT_BYTES: usize = 64 * 1024;

/// Maximum number of representative member diagnostics retained in memory.
/// Every affected member is still counted and emitted through [`ZipEvent`].
pub const RETAINED_MEMBER_DIAGNOSTICS: usize = 128;

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
    /// Filename bytes selected by the ZIP reader. These are normally the
    /// central-directory filename bytes, but a valid Unicode Path extra field
    /// can replace them. They are therefore evidence-facing reader bytes, not
    /// a claim about the literal on-disk filename field.
    pub name_reader_bytes: Vec<u8>,
    pub name_is_utf8: bool,
    pub is_directory: bool,
    pub is_symlink: bool,
    pub unix_mode: Option<u32>,
    pub encrypted: bool,
    pub uses_data_descriptor: bool,
    pub uses_zip64: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub compression_method: CompressionMethod,
    /// Whether content is emitted, based only on the member's extension.
    pub is_textual: bool,
    /// Offset of the ZIP payload within the recovered source stream. Usually
    /// zero, but non-zero for self-extracting/prefixed ZIPs.
    pub archive_stream_offset: u64,
    /// All following offsets are relative to the recovered ZIP source stream,
    /// not evidence-media offsets and not decoded member offsets.
    pub local_header_offset: u64,
    pub compressed_data_offset: u64,
    pub compressed_data_end: u64,
    pub central_directory_header_offset: u64,
    /// Stable risk labels for an evidence name which must never be materialized
    /// directly as a host filesystem path.
    pub path_risk_codes: Vec<&'static str>,
}

impl ZipMemberMetadata {
    pub fn has_path_risk(&self) -> bool {
        !self.path_risk_codes.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipMemberStatus {
    Validated,
    Encrypted,
    UnsupportedCompression,
    Corrupt,
    IoError,
    InternalError,
}

impl ZipMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Encrypted => "encrypted",
            Self::UnsupportedCompression => "unsupported_compression",
            Self::Corrupt => "corrupt",
            Self::IoError => "io_error",
            Self::InternalError => "internal_error",
        }
    }
}

/// Terminal result for a member whose central/local metadata was readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipMemberOutcome {
    pub status: ZipMemberStatus,
    pub uncompressed_bytes_read: u64,
    /// True only after the decoder reached EOF, the observed byte count matched
    /// the central directory, and the ZIP reader accepted the CRC.
    pub crc32_validated: bool,
    pub content_complete: bool,
    pub diagnostic: Option<ZipParserError>,
}

/// A central-directory member whose local metadata could not be read. Its
/// stable index and any available decoded name are retained so later members
/// can still be examined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipUnavailableMember {
    pub archive_index: usize,
    pub member_name: Option<String>,
    pub path_risk_codes: Vec<&'static str>,
    pub diagnostic: ZipParserError,
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
    /// Emitted exactly once after a member's content attempt. Callers which
    /// persisted provisional text must discard it unless `content_complete`
    /// and `crc32_validated` are both true.
    MemberOutcome {
        member: &'a ZipMemberMetadata,
        outcome: &'a ZipMemberOutcome,
    },
    /// Emitted when local metadata is unreadable. The parser continues to later
    /// central-directory members.
    MemberUnavailable(&'a ZipUnavailableMember),
}

/// Aggregate counts returned after every member has been validated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZipParseSummary {
    pub archive_stream_offset: u64,
    pub central_directory_offset: u64,
    pub archive_uses_zip64: bool,
    pub member_count: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub validated_member_count: usize,
    pub validated_file_count: usize,
    pub encrypted_member_count: usize,
    pub unsupported_member_count: usize,
    pub corrupt_member_count: usize,
    pub io_error_member_count: usize,
    pub internal_error_member_count: usize,
    pub metadata_unavailable_member_count: usize,
    pub path_risk_member_count: usize,
    pub crc32_validated_member_count: usize,
    pub text_member_count: usize,
    pub text_segment_count: u64,
    /// Includes only members which reached EOF, matched their declared size,
    /// and passed CRC validation.
    pub uncompressed_bytes_read: u128,
    pub text_bytes_emitted: u128,
    /// Parser diagnostics exclude encrypted/unsupported members, which are
    /// explicit coverage limitations rather than evidence corruption.
    pub member_diagnostic_count: usize,
    pub member_diagnostics: Vec<ZipParserError>,
    pub member_diagnostics_omitted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipArchiveStatus {
    Complete,
    Partial,
    Unsupported,
}

impl ZipArchiveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }
}

impl ZipParseSummary {
    pub fn status(&self) -> ZipArchiveStatus {
        if self.validated_member_count == self.member_count {
            return ZipArchiveStatus::Complete;
        }
        let structural_failures = self
            .corrupt_member_count
            .saturating_add(self.io_error_member_count)
            .saturating_add(self.internal_error_member_count)
            .saturating_add(self.metadata_unavailable_member_count);
        if self.file_count > 0
            && self.validated_file_count == 0
            && structural_failures == 0
            && self
                .encrypted_member_count
                .saturating_add(self.unsupported_member_count)
                == self.file_count
        {
            ZipArchiveStatus::Unsupported
        } else {
            ZipArchiveStatus::Partial
        }
    }

    pub fn limitation_member_count(&self) -> usize {
        self.encrypted_member_count
            .saturating_add(self.unsupported_member_count)
    }
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
    MemberOutcome,
    MemberUnavailable,
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
        archive_stream_offset: archive.offset(),
        central_directory_offset: archive.central_directory_start(),
        archive_uses_zip64: archive.zip64_comment().is_some(),
        member_count,
        ..ZipParseSummary::default()
    };

    for archive_index in 0..member_count {
        let known_name = archive.name_for_index(archive_index).map(str::to_owned);
        let raw_member = match archive.by_index_raw(archive_index) {
            Ok(member) => member,
            Err(error) => {
                let unavailable = unavailable_member(
                    archive_index,
                    known_name,
                    classify_member_zip_error(archive_index, None, None, error),
                );
                emit_unavailable_member(&mut on_event, &unavailable)?;
                record_unavailable_member(&mut summary, unavailable);
                continue;
            }
        };

        let compression_method = raw_member.compression();
        let compressed_data_offset = raw_member.data_start();
        let Some(compressed_data_end) =
            compressed_data_offset.checked_add(raw_member.compressed_size())
        else {
            let name = raw_member.name().to_owned();
            let diagnostic = ZipParserError::member(
                ZipParserErrorKind::CounterOverflow,
                archive_index,
                Some(name.clone()),
                Some(compression_method),
                "compressed member data extent exceeds u64",
            );
            drop(raw_member);
            let unavailable = unavailable_member(archive_index, Some(name), diagnostic);
            emit_unavailable_member(&mut on_event, &unavailable)?;
            record_unavailable_member(&mut summary, unavailable);
            continue;
        };
        let zip_metadata = raw_member.get_metadata();
        let metadata = ZipMemberMetadata {
            archive_index,
            name: raw_member.name().to_owned(),
            name_reader_bytes: raw_member.name_raw().to_vec(),
            name_is_utf8: zip_metadata.is_utf8,
            is_directory: raw_member.is_dir(),
            is_symlink: raw_member.is_symlink(),
            unix_mode: raw_member.unix_mode(),
            encrypted: raw_member.encrypted(),
            uses_data_descriptor: zip_metadata.using_data_descriptor,
            uses_zip64: zip_metadata.large_file,
            compressed_size: raw_member.compressed_size(),
            uncompressed_size: raw_member.size(),
            crc32: raw_member.crc32(),
            compression_method,
            is_textual: !raw_member.is_dir() && has_text_extension(raw_member.name()),
            archive_stream_offset: summary.archive_stream_offset,
            local_header_offset: raw_member.header_start(),
            compressed_data_offset,
            compressed_data_end,
            central_directory_header_offset: raw_member.central_header_start(),
            path_risk_codes: path_risk_codes(raw_member.name()),
        };
        drop(raw_member);

        on_event(ZipEvent::Member(&metadata)).map_err(|source| ZipParseError::Callback {
            archive_index,
            member_name: metadata.name.clone(),
            event_kind: ZipCallbackEventKind::Member,
            source,
        })?;

        if metadata.is_directory {
            summary.directory_count = summary.directory_count.saturating_add(1);
        } else {
            summary.file_count = summary.file_count.saturating_add(1);
        }
        if metadata.has_path_risk() {
            summary.path_risk_member_count = summary.path_risk_member_count.saturating_add(1);
        }
        if metadata.uses_zip64 {
            summary.archive_uses_zip64 = true;
        }

        let (outcome, stream_stats) = member_outcome(&mut archive, &metadata, &mut on_event)?;
        on_event(ZipEvent::MemberOutcome {
            member: &metadata,
            outcome: &outcome,
        })
        .map_err(|source| ZipParseError::Callback {
            archive_index,
            member_name: metadata.name.clone(),
            event_kind: ZipCallbackEventKind::MemberOutcome,
            source,
        })?;
        record_member_outcome(&mut summary, &metadata, &outcome, stream_stats);
    }

    Ok(summary)
}

#[derive(Debug, Clone, Copy, Default)]
struct MemberStreamStats {
    bytes_read: u64,
    text_segment_count: u64,
    text_bytes_emitted: u128,
}

fn unavailable_member(
    archive_index: usize,
    member_name: Option<String>,
    mut diagnostic: ZipParserError,
) -> ZipUnavailableMember {
    diagnostic.member_name.clone_from(&member_name);
    ZipUnavailableMember {
        archive_index,
        path_risk_codes: member_name
            .as_deref()
            .map(path_risk_codes)
            .unwrap_or_default(),
        member_name,
        diagnostic,
    }
}

fn emit_unavailable_member<F, E>(
    on_event: &mut F,
    unavailable: &ZipUnavailableMember,
) -> Result<(), ZipParseError<E>>
where
    F: for<'event> FnMut(ZipEvent<'event>) -> Result<(), E>,
{
    on_event(ZipEvent::MemberUnavailable(unavailable)).map_err(|source| ZipParseError::Callback {
        archive_index: unavailable.archive_index,
        member_name: unavailable
            .member_name
            .clone()
            .unwrap_or_else(|| format!("Member-{}", unavailable.archive_index)),
        event_kind: ZipCallbackEventKind::MemberUnavailable,
        source,
    })
}

fn record_unavailable_member(summary: &mut ZipParseSummary, unavailable: ZipUnavailableMember) {
    summary.metadata_unavailable_member_count =
        summary.metadata_unavailable_member_count.saturating_add(1);
    if !unavailable.path_risk_codes.is_empty() {
        summary.path_risk_member_count = summary.path_risk_member_count.saturating_add(1);
    }
    retain_member_diagnostic(summary, unavailable.diagnostic);
}

fn member_outcome<R, F, E>(
    archive: &mut ZipArchive<R>,
    metadata: &ZipMemberMetadata,
    on_event: &mut F,
) -> Result<(ZipMemberOutcome, Option<MemberStreamStats>), ZipParseError<E>>
where
    R: Read + Seek,
    F: for<'event> FnMut(ZipEvent<'event>) -> Result<(), E>,
{
    if metadata.encrypted {
        return Ok((
            ZipMemberOutcome {
                status: ZipMemberStatus::Encrypted,
                uncompressed_bytes_read: 0,
                crc32_validated: false,
                content_complete: false,
                diagnostic: Some(ZipParserError::member(
                    ZipParserErrorKind::EncryptedMember,
                    metadata.archive_index,
                    Some(metadata.name.clone()),
                    Some(metadata.compression_method),
                    "encrypted member metadata retained; content was not attempted without an examiner-supplied password",
                )),
            },
            None,
        ));
    }
    if let Some(method_code) = unsupported_method_code(metadata.compression_method) {
        return Ok((
            ZipMemberOutcome {
                status: ZipMemberStatus::UnsupportedCompression,
                uncompressed_bytes_read: 0,
                crc32_validated: false,
                content_complete: false,
                diagnostic: Some(ZipParserError::member(
                    ZipParserErrorKind::UnsupportedMember,
                    metadata.archive_index,
                    Some(metadata.name.clone()),
                    Some(metadata.compression_method),
                    format!(
                        "compression method {method_code} is not supported by this build; metadata retained"
                    ),
                )),
            },
            None,
        ));
    }

    let mut member = match archive.by_index(metadata.archive_index) {
        Ok(member) => member,
        Err(error) => {
            return Ok((
                member_outcome_from_error(classify_member_zip_error(
                    metadata.archive_index,
                    Some(metadata.name.clone()),
                    Some(metadata.compression_method),
                    error,
                )),
                None,
            ));
        }
    };
    let streamed = if metadata.is_textual {
        stream_text_member(&mut member, metadata, on_event)
    } else {
        stream_validation_only(&mut member, metadata)
            .map(|bytes_read| MemberStreamStats {
                bytes_read,
                ..MemberStreamStats::default()
            })
            .map_err(ZipParseError::Parser)
    };
    match streamed {
        Ok(stats) if stats.bytes_read == metadata.uncompressed_size => Ok((
            ZipMemberOutcome {
                status: ZipMemberStatus::Validated,
                uncompressed_bytes_read: stats.bytes_read,
                crc32_validated: true,
                content_complete: true,
                diagnostic: None,
            },
            Some(stats),
        )),
        Ok(stats) => Ok((
            ZipMemberOutcome {
                status: ZipMemberStatus::Corrupt,
                uncompressed_bytes_read: stats.bytes_read,
                crc32_validated: false,
                content_complete: false,
                diagnostic: Some(ZipParserError::member(
                    ZipParserErrorKind::CorruptMember,
                    metadata.archive_index,
                    Some(metadata.name.clone()),
                    Some(metadata.compression_method),
                    format!(
                        "uncompressed size mismatch: central directory declares {}, read {}",
                        metadata.uncompressed_size, stats.bytes_read
                    ),
                )),
            },
            None,
        )),
        Err(ZipParseError::Parser(error)) => Ok((member_outcome_from_error(error), None)),
        Err(callback @ ZipParseError::Callback { .. }) => Err(callback),
    }
}

fn member_outcome_from_error(error: ZipParserError) -> ZipMemberOutcome {
    let status = match error.kind {
        ZipParserErrorKind::EncryptedMember => ZipMemberStatus::Encrypted,
        ZipParserErrorKind::UnsupportedMember | ZipParserErrorKind::UnsupportedArchive => {
            ZipMemberStatus::UnsupportedCompression
        }
        ZipParserErrorKind::CorruptMember | ZipParserErrorKind::InvalidArchive => {
            ZipMemberStatus::Corrupt
        }
        ZipParserErrorKind::MemberIo | ZipParserErrorKind::ArchiveIo => ZipMemberStatus::IoError,
        ZipParserErrorKind::CounterOverflow => ZipMemberStatus::InternalError,
    };
    ZipMemberOutcome {
        status,
        uncompressed_bytes_read: 0,
        crc32_validated: false,
        content_complete: false,
        diagnostic: Some(error),
    }
}

fn record_member_outcome(
    summary: &mut ZipParseSummary,
    metadata: &ZipMemberMetadata,
    outcome: &ZipMemberOutcome,
    stream_stats: Option<MemberStreamStats>,
) {
    match outcome.status {
        ZipMemberStatus::Validated => {
            summary.validated_member_count = summary.validated_member_count.saturating_add(1);
            if !metadata.is_directory {
                summary.validated_file_count = summary.validated_file_count.saturating_add(1);
            }
            summary.crc32_validated_member_count =
                summary.crc32_validated_member_count.saturating_add(1);
            if let Some(stats) = stream_stats {
                summary.uncompressed_bytes_read = summary
                    .uncompressed_bytes_read
                    .saturating_add(u128::from(stats.bytes_read));
                if metadata.is_textual {
                    summary.text_member_count = summary.text_member_count.saturating_add(1);
                    summary.text_segment_count = summary
                        .text_segment_count
                        .saturating_add(stats.text_segment_count);
                    summary.text_bytes_emitted = summary
                        .text_bytes_emitted
                        .saturating_add(stats.text_bytes_emitted);
                }
            }
        }
        ZipMemberStatus::Encrypted => {
            summary.encrypted_member_count = summary.encrypted_member_count.saturating_add(1);
        }
        ZipMemberStatus::UnsupportedCompression => {
            summary.unsupported_member_count = summary.unsupported_member_count.saturating_add(1);
        }
        ZipMemberStatus::Corrupt => {
            summary.corrupt_member_count = summary.corrupt_member_count.saturating_add(1);
            retain_outcome_diagnostic(summary, outcome);
        }
        ZipMemberStatus::IoError => {
            summary.io_error_member_count = summary.io_error_member_count.saturating_add(1);
            retain_outcome_diagnostic(summary, outcome);
        }
        ZipMemberStatus::InternalError => {
            summary.internal_error_member_count =
                summary.internal_error_member_count.saturating_add(1);
            retain_outcome_diagnostic(summary, outcome);
        }
    }
}

fn retain_outcome_diagnostic(summary: &mut ZipParseSummary, outcome: &ZipMemberOutcome) {
    if let Some(diagnostic) = outcome.diagnostic.clone() {
        retain_member_diagnostic(summary, diagnostic);
    }
}

fn retain_member_diagnostic(summary: &mut ZipParseSummary, diagnostic: ZipParserError) {
    summary.member_diagnostic_count = summary.member_diagnostic_count.saturating_add(1);
    if summary.member_diagnostics.len() < RETAINED_MEMBER_DIAGNOSTICS {
        summary.member_diagnostics.push(diagnostic);
    } else {
        summary.member_diagnostics_omitted = summary.member_diagnostics_omitted.saturating_add(1);
    }
}

fn stream_text_member<R, F, E>(
    member: &mut R,
    metadata: &ZipMemberMetadata,
    on_event: &mut F,
) -> Result<MemberStreamStats, ZipParseError<E>>
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
    let mut text_bytes_emitted = 0_u128;

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

        text_bytes_emitted = text_bytes_emitted
            .checked_add(current_len as u128)
            .ok_or_else(|| {
                ZipParseError::Parser(counter_overflow_error(metadata, "text byte count"))
            })?;
        byte_offset = byte_offset.checked_add(current_len as u64).ok_or_else(|| {
            ZipParseError::Parser(counter_overflow_error(metadata, "text byte offset"))
        })?;
        segment_index = segment_index.checked_add(1).ok_or_else(|| {
            ZipParseError::Parser(counter_overflow_error(metadata, "member segment index"))
        })?;

        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }

    Ok(MemberStreamStats {
        bytes_read,
        text_segment_count: segment_index,
        text_bytes_emitted,
    })
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

fn path_risk_codes(name: &str) -> Vec<&'static str> {
    let bytes = name.as_bytes();
    let has_drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    let has_unc_prefix = name.starts_with("\\\\") || name.starts_with("//");
    let has_leading_separator = name.starts_with('/') || name.starts_with('\\');
    let has_drive_absolute = has_drive_prefix
        && bytes
            .get(2)
            .is_some_and(|separator| matches!(separator, b'/' | b'\\'));
    let has_parent_component = name.split(['/', '\\']).any(|component| component == "..");

    let mut risks = Vec::new();
    if has_leading_separator || has_drive_absolute {
        risks.push("absolute_path");
    }
    if has_parent_component {
        risks.push("parent_component");
    }
    if name.contains('\\') {
        risks.push("backslash_separator");
    }
    if has_drive_prefix {
        risks.push("windows_drive_prefix");
    }
    if has_unc_prefix {
        risks.push("unc_path");
    }
    if name.contains('\0') {
        risks.push("nul_byte");
    }
    risks
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
            ZipEvent::MemberOutcome { .. } => {}
            ZipEvent::MemberUnavailable(member) => {
                panic!("unexpected unavailable member: {member:?}")
            }
        })
        .unwrap();

        assert_eq!(summary.member_count, 2);
        assert!(members[0].is_directory);
        assert_eq!(members[0].name, "nested/");
        assert_eq!(members[1].archive_index, 1);
        assert_eq!(members[1].name, exact_name);
        assert_eq!(members[1].name_reader_bytes, exact_name.as_bytes());
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
            ZipEvent::MemberOutcome { .. } => {}
            ZipEvent::MemberUnavailable(member) => {
                panic!("unexpected unavailable member: {member:?}")
            }
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
    fn invalid_archive_is_fatal_but_checksum_failure_is_member_partial() {
        let invalid = parse_zip(Cursor::new(b"not a ZIP archive".to_vec()), |_| {}).unwrap_err();
        assert_eq!(invalid.kind, ZipParserErrorKind::InvalidArchive);

        let payload = b"unique-stored-payload-for-crc-test";
        let mut corrupt = single_file_zip("corrupt.txt", payload, CompressionMethod::Stored);
        let payload_offset = corrupt
            .windows(payload.len())
            .position(|window| window == payload)
            .unwrap();
        corrupt[payload_offset] ^= 0x40;

        let mut outcomes = Vec::new();
        let summary = parse_zip(Cursor::new(corrupt), |event| {
            if let ZipEvent::MemberOutcome { member, outcome } = event {
                outcomes.push((member.archive_index, outcome.clone()));
            }
        })
        .unwrap();
        assert_eq!(summary.status(), ZipArchiveStatus::Partial);
        assert_eq!(summary.corrupt_member_count, 1);
        assert_eq!(summary.validated_member_count, 0);
        assert_eq!(summary.member_diagnostic_count, 1);
        assert_eq!(outcomes.len(), 1);
        let checksum_error = outcomes[0].1.diagnostic.as_ref().unwrap();
        assert_eq!(outcomes[0].1.status, ZipMemberStatus::Corrupt);
        assert_eq!(checksum_error.kind, ZipParserErrorKind::CorruptMember);
        assert_eq!(checksum_error.archive_index, Some(0));
        assert_eq!(checksum_error.member_name.as_deref(), Some("corrupt.txt"));
        assert!(checksum_error
            .message
            .to_ascii_lowercase()
            .contains("checksum"));
    }

    #[test]
    fn encrypted_and_unsupported_members_retain_metadata_without_content_claims() {
        let payload = b"content";

        let mut encrypted = single_file_zip("secret.txt", payload, CompressionMethod::Stored);
        patch_u16_after_signature(&mut encrypted, b"PK\x03\x04", 6, 1);
        patch_u16_after_signature(&mut encrypted, b"PK\x01\x02", 8, 1);
        let mut encrypted_metadata = None;
        let mut encrypted_outcome = None;
        let mut encrypted_text_events = 0;
        let encrypted_summary = parse_zip(Cursor::new(encrypted), |event| match event {
            ZipEvent::Member(member) => encrypted_metadata = Some(member.clone()),
            ZipEvent::TextSegment { .. } => encrypted_text_events += 1,
            ZipEvent::MemberOutcome { outcome, .. } => encrypted_outcome = Some(outcome.clone()),
            ZipEvent::MemberUnavailable(member) => {
                panic!("unexpected unavailable member: {member:?}")
            }
        })
        .unwrap();
        let encrypted_metadata = encrypted_metadata.unwrap();
        let encrypted_outcome = encrypted_outcome.unwrap();
        assert!(encrypted_metadata.encrypted);
        assert_eq!(encrypted_outcome.status, ZipMemberStatus::Encrypted);
        assert!(!encrypted_outcome.content_complete);
        assert!(!encrypted_outcome.crc32_validated);
        assert_eq!(encrypted_text_events, 0);
        assert_eq!(encrypted_summary.status(), ZipArchiveStatus::Unsupported);
        assert_eq!(encrypted_summary.encrypted_member_count, 1);
        assert_eq!(encrypted_summary.member_diagnostic_count, 0);

        let mut unsupported = single_file_zip("odd.txt", payload, CompressionMethod::Stored);
        patch_u16_after_signature(&mut unsupported, b"PK\x03\x04", 8, 98);
        patch_u16_after_signature(&mut unsupported, b"PK\x01\x02", 10, 98);
        let mut unsupported_outcome = None;
        let unsupported_summary = parse_zip(Cursor::new(unsupported), |event| {
            if let ZipEvent::MemberOutcome { outcome, .. } = event {
                unsupported_outcome = Some(outcome.clone());
            }
        })
        .unwrap();
        let unsupported_outcome = unsupported_outcome.unwrap();
        assert_eq!(
            unsupported_outcome.status,
            ZipMemberStatus::UnsupportedCompression
        );
        assert!(!unsupported_outcome.content_complete);
        assert!(!unsupported_outcome.crc32_validated);
        assert_eq!(unsupported_summary.status(), ZipArchiveStatus::Unsupported);
        assert_eq!(unsupported_summary.unsupported_member_count, 1);
        assert_eq!(unsupported_summary.member_diagnostic_count, 0);
    }

    #[test]
    fn corrupt_member_does_not_hide_a_later_valid_member() {
        let corrupt_payload = vec![b'x'; TEXT_SEGMENT_BYTES + 17];
        let valid_payload = b"later-valid-evidence";
        let mut bytes = multi_file_zip(&[
            ("first.txt", corrupt_payload.as_slice()),
            ("second.txt", valid_payload.as_slice()),
        ]);
        let corrupt_offset = bytes
            .windows(corrupt_payload.len())
            .position(|window| window == corrupt_payload)
            .unwrap();
        bytes[corrupt_offset] ^= 0x40;

        // This models the database integration: text is provisional until the
        // terminal outcome confirms complete size and CRC validation.
        let mut retained_text = [Vec::new(), Vec::new()];
        let mut outcomes = Vec::new();
        let summary = parse_zip(Cursor::new(bytes), |event| match event {
            ZipEvent::Member(_) => {}
            ZipEvent::TextSegment { member, bytes, .. } => {
                retained_text[member.archive_index].extend_from_slice(bytes);
            }
            ZipEvent::MemberOutcome { member, outcome } => {
                if !outcome.content_complete || !outcome.crc32_validated {
                    retained_text[member.archive_index].clear();
                }
                outcomes.push((member.name.clone(), outcome.status));
            }
            ZipEvent::MemberUnavailable(member) => {
                panic!("unexpected unavailable member: {member:?}")
            }
        })
        .unwrap();

        assert_eq!(summary.status(), ZipArchiveStatus::Partial);
        assert_eq!(summary.corrupt_member_count, 1);
        assert_eq!(summary.validated_member_count, 1);
        assert_eq!(summary.validated_file_count, 1);
        assert_eq!(summary.text_member_count, 1);
        assert_eq!(retained_text[0], Vec::<u8>::new());
        assert_eq!(retained_text[1], valid_payload);
        assert_eq!(
            outcomes,
            vec![
                ("first.txt".to_string(), ZipMemberStatus::Corrupt),
                ("second.txt".to_string(), ZipMemberStatus::Validated),
            ]
        );
    }

    #[test]
    fn reports_path_risks_without_normalizing_evidence_names() {
        assert!(path_risk_codes("safe/nested/file.txt").is_empty());
        assert_eq!(path_risk_codes("/absolute.txt"), vec!["absolute_path"]);
        assert_eq!(path_risk_codes("../escape.txt"), vec!["parent_component"]);
        assert_eq!(
            path_risk_codes(r"nested\windows.txt"),
            vec!["backslash_separator"]
        );
        assert_eq!(
            path_risk_codes(r"C:relative.txt"),
            vec!["windows_drive_prefix"]
        );
        assert_eq!(
            path_risk_codes(r"C:\absolute.txt"),
            vec![
                "absolute_path",
                "backslash_separator",
                "windows_drive_prefix",
            ]
        );
        assert_eq!(
            path_risk_codes(r"\\server\share\evidence.txt"),
            vec!["absolute_path", "backslash_separator", "unc_path"]
        );
    }

    #[test]
    fn source_offsets_remain_relative_to_the_recovered_zip_stream() {
        let payload = b"offset-ground-truth";
        let zip = single_file_zip("offset.txt", payload, CompressionMethod::Stored);
        let prefix = b"self-extracting-prefix";
        let mut prefixed = prefix.to_vec();
        prefixed.extend_from_slice(&zip);
        let source = prefixed.clone();
        let mut metadata = None;

        let summary = parse_zip(Cursor::new(prefixed), |event| {
            if let ZipEvent::Member(member) = event {
                metadata = Some(member.clone());
            }
        })
        .unwrap();
        let metadata = metadata.unwrap();

        assert_eq!(summary.archive_stream_offset, prefix.len() as u64);
        assert_eq!(metadata.archive_stream_offset, prefix.len() as u64);
        assert_eq!(metadata.local_header_offset, prefix.len() as u64);
        assert_eq!(
            &source
                [metadata.local_header_offset as usize..metadata.local_header_offset as usize + 4],
            b"PK\x03\x04"
        );
        assert_eq!(
            &source
                [metadata.compressed_data_offset as usize..metadata.compressed_data_end as usize],
            payload
        );
        assert!(metadata.compressed_data_end <= metadata.central_directory_header_offset);
        assert_eq!(
            metadata.central_directory_header_offset,
            summary.central_directory_offset
        );
    }

    #[test]
    fn accepts_data_descriptor_and_records_its_semantics() {
        let payload = b"descriptor-backed-text";
        let name = "descriptor.txt";
        let bytes = stored_zip_with_data_descriptor(name, payload);
        let mut metadata = None;
        let mut extracted = Vec::new();

        let summary = parse_zip(Cursor::new(bytes), |event| match event {
            ZipEvent::Member(member) => metadata = Some(member.clone()),
            ZipEvent::TextSegment { bytes, .. } => extracted.extend_from_slice(bytes),
            ZipEvent::MemberOutcome { .. } => {}
            ZipEvent::MemberUnavailable(member) => {
                panic!("unexpected unavailable member: {member:?}")
            }
        })
        .unwrap();
        let metadata = metadata.unwrap();

        assert!(metadata.uses_data_descriptor);
        assert_eq!(metadata.compressed_data_offset, (30 + name.len()) as u64);
        assert_eq!(
            metadata.compressed_data_end,
            metadata.compressed_data_offset + payload.len() as u64
        );
        assert_eq!(summary.status(), ZipArchiveStatus::Complete);
        assert_eq!(summary.crc32_validated_member_count, 1);
        assert_eq!(extracted, payload);
    }

    #[test]
    fn recognizes_zip64_member_metadata_without_large_allocation() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(true);
        writer.start_file("zip64.txt", options).unwrap();
        writer.write_all(b"small fixture, ZIP64 metadata").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut metadata = None;

        let summary = parse_zip(Cursor::new(bytes), |event| {
            if let ZipEvent::Member(member) = event {
                metadata = Some(member.clone());
            }
        })
        .unwrap();

        assert!(metadata.unwrap().uses_zip64);
        assert!(summary.archive_uses_zip64);
        assert_eq!(summary.status(), ZipArchiveStatus::Complete);
    }

    fn multi_file_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, payload) in files {
            writer.start_file(*name, options).unwrap();
            writer.write_all(payload).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn stored_zip_with_data_descriptor(name: &str, payload: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let crc32 = test_crc32(payload);
        let mut bytes = Vec::new();

        push_u32(&mut bytes, 0x0403_4b50);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, 1 << 3);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u16(&mut bytes, name_bytes.len() as u16);
        push_u16(&mut bytes, 0);
        bytes.extend_from_slice(name_bytes);
        bytes.extend_from_slice(payload);
        push_u32(&mut bytes, 0x0807_4b50);
        push_u32(&mut bytes, crc32);
        push_u32(&mut bytes, payload.len() as u32);
        push_u32(&mut bytes, payload.len() as u32);

        let central_start = bytes.len() as u32;
        push_u32(&mut bytes, 0x0201_4b50);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, 1 << 3);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, crc32);
        push_u32(&mut bytes, payload.len() as u32);
        push_u32(&mut bytes, payload.len() as u32);
        push_u16(&mut bytes, name_bytes.len() as u16);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        bytes.extend_from_slice(name_bytes);
        let central_size = bytes.len() as u32 - central_start;

        push_u32(&mut bytes, 0x0605_4b50);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, 1);
        push_u32(&mut bytes, central_size);
        push_u32(&mut bytes, central_start);
        push_u16(&mut bytes, 0);
        bytes
    }

    fn test_crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
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
