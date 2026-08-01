//! Bounded, incremental parsing for the NTFS `$UsnJrnl:$J` stream.
//!
//! The production API accepts [`Read`] and never buffers the complete journal. Only one
//! examiner-bounded record plus a fixed I/O chunk is resident at a time. USN V2 and V3 records
//! are decoded; V4 and unknown versions are counted and disclosed as unsupported. Resynchronizing
//! after damaged framing follows the format's 8-byte record alignment; the parser does not perform
//! an unbounded byte-by-byte carve for misaligned record signatures.

#![allow(dead_code)]

use std::fmt;
use std::io::{self, Read};

const READ_CHUNK_BYTES: usize = 8 * 1024;
const DEFAULT_MAX_RECORD_BYTES: usize = 1024 * 1024;
const HARD_MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_FILENAME_BYTES: usize = 64 * 1024;
const HARD_MAX_DIAGNOSTIC_SAMPLES: usize = 256;
const DEFAULT_DIAGNOSTIC_SAMPLES: usize = 32;
const DIAGNOSTIC_MESSAGE_BYTES: usize = 512;
const FILETIME_UNIX_EPOCH_100NS: i64 = 116_444_736_000_000_000;

const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
const USN_REASON_INDEXABLE_CHANGE: u32 = 0x0000_4000;
const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
const USN_REASON_TRANSACTED_CHANGE: u32 = 0x0040_0000;
const USN_REASON_INTEGRITY_CHANGE: u32 = 0x0080_0000;
const USN_REASON_CLOSE: u32 = 0x8000_0000;

const KNOWN_REASON_MASK: u32 = USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_TRUNCATION
    | USN_REASON_NAMED_DATA_OVERWRITE
    | USN_REASON_NAMED_DATA_EXTEND
    | USN_REASON_NAMED_DATA_TRUNCATION
    | USN_REASON_FILE_CREATE
    | USN_REASON_FILE_DELETE
    | USN_REASON_EA_CHANGE
    | USN_REASON_SECURITY_CHANGE
    | USN_REASON_RENAME_OLD_NAME
    | USN_REASON_RENAME_NEW_NAME
    | USN_REASON_INDEXABLE_CHANGE
    | USN_REASON_BASIC_INFO_CHANGE
    | USN_REASON_HARD_LINK_CHANGE
    | USN_REASON_COMPRESSION_CHANGE
    | USN_REASON_ENCRYPTION_CHANGE
    | USN_REASON_OBJECT_ID_CHANGE
    | USN_REASON_REPARSE_POINT_CHANGE
    | USN_REASON_STREAM_CHANGE
    | USN_REASON_TRANSACTED_CHANGE
    | USN_REASON_INTEGRITY_CHANGE
    | USN_REASON_CLOSE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnTerminalStatus {
    Recognized,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnVersion {
    V2,
    V3,
}

/// V2 uses the traditional 48-bit MFT entry plus 16-bit sequence number. V3 stores the complete
/// 128-bit file identifier without pretending its high 64 bits are an MFT sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnFileReference {
    V2 { raw: u64, entry: u64, sequence: u16 },
    V3 { low: u64, high: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    pub version: UsnVersion,
    pub major_version: u16,
    pub minor_version: u16,
    pub record_length: u32,
    pub file_reference: UsnFileReference,
    pub parent_reference: UsnFileReference,
    pub usn: i64,
    pub timestamp_filetime: i64,
    pub timestamp_utc: Option<String>,
    pub reason: u32,
    pub reason_flags: Vec<&'static str>,
    pub unknown_reason_bits: u32,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
    pub byte_offset: u64,
}

#[derive(Debug, Clone)]
pub struct UsnParseOptions {
    /// Maximum allocation for one framed V2/V3 record. This is a memory guard, not a journal
    /// coverage cap: oversized records are discarded incrementally and parsing continues.
    pub max_record_bytes: usize,
    pub max_filename_bytes: usize,
    pub diagnostic_sample_limit: usize,
}

impl Default for UsnParseOptions {
    fn default() -> Self {
        Self {
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_filename_bytes: DEFAULT_MAX_FILENAME_BYTES,
            diagnostic_sample_limit: DEFAULT_DIAGNOSTIC_SAMPLES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnDiagnostic {
    pub offset: u64,
    pub kind: UsnErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsnStreamStats {
    pub bytes_read: u64,
    pub sparse_zero_bytes_skipped: u64,
    pub records_seen: u64,
    pub records_parsed: u64,
    pub records_emitted: u64,
    pub v2_records: u64,
    pub v3_records: u64,
    pub unsupported_v4_records: u64,
    pub unknown_version_records: u64,
    pub corrupt_records: u64,
    pub truncated_records: u64,
    pub oversized_records: u64,
    pub diagnostic_count: u64,
    pub diagnostics: Vec<UsnDiagnostic>,
    pub diagnostics_omitted: u64,
}

impl UsnStreamStats {
    fn diagnostic(
        &mut self,
        options: &UsnParseOptions,
        offset: u64,
        kind: UsnErrorKind,
        message: impl AsRef<str>,
    ) {
        self.diagnostic_count = self.diagnostic_count.saturating_add(1);
        if self.diagnostics.len() < options.diagnostic_sample_limit {
            self.diagnostics.push(UsnDiagnostic {
                offset,
                kind,
                message: bounded_text(message.as_ref(), DIAGNOSTIC_MESSAGE_BYTES),
            });
        } else {
            self.diagnostics_omitted = self.diagnostics_omitted.saturating_add(1);
        }
    }

    fn terminal_status(&self) -> UsnTerminalStatus {
        if self.corrupt_records > 0
            || self.truncated_records > 0
            || self.oversized_records > 0
            || self.unsupported_v4_records > 0
            || self.unknown_version_records > 0
        {
            UsnTerminalStatus::Partial
        } else {
            UsnTerminalStatus::Recognized
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnStreamResult {
    pub status: UsnTerminalStatus,
    pub stats: UsnStreamStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnErrorKind {
    InvalidOptions,
    Io,
    Sink,
    TruncatedRecord,
    InvalidRecordLength,
    InvalidVersion,
    InvalidFileNameOffset,
    InvalidFileNameLength,
    InvalidUtf16,
    CheckedArithmeticOverflow,
    Allocation,
}

#[derive(Debug, Clone)]
pub struct UsnParseError {
    pub status: UsnTerminalStatus,
    pub kind: UsnErrorKind,
    pub offset: u64,
    pub message: String,
    pub stats: Box<UsnStreamStats>,
}

impl fmt::Display for UsnParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "USN {:?} error at byte {}: {}",
            self.kind, self.offset, self.message
        )
    }
}

impl std::error::Error for UsnParseError {}

pub trait UsnSink {
    type Error: fmt::Display;

    fn record(&mut self, record: &UsnRecord) -> Result<(), Self::Error>;
}

/// Incrementally parse a `$UsnJrnl:$J` stream.
///
/// Parse damage is disclosed in a successful [`UsnTerminalStatus::Partial`] result when the next
/// aligned record can still be located. Reader and sink failures are fatal and always return
/// `Err` with [`UsnTerminalStatus::Failed`] and the counters accumulated before failure.
pub fn parse_usn_journal<R: Read, S: UsnSink>(
    mut reader: R,
    sink: &mut S,
    options: &UsnParseOptions,
) -> Result<UsnStreamResult, UsnParseError> {
    validate_options(options).map_err(|message| UsnParseError {
        status: UsnTerminalStatus::Failed,
        kind: UsnErrorKind::InvalidOptions,
        offset: 0,
        message,
        stats: Box::default(),
    })?;

    let mut stats = UsnStreamStats::default();
    let mut stream_offset = 0_u64;
    let mut header = [0_u8; 8];

    loop {
        let header_read =
            read_fill_bounded(&mut reader, &mut header, &mut stats).map_err(|error| {
                failed_error(
                    UsnErrorKind::Io,
                    stream_offset,
                    format!("reading record header: {error}"),
                    &stats,
                )
            })?;
        if header_read == 0 {
            break;
        }
        if header_read < header.len() {
            let trailing = &header[..header_read];
            if trailing.iter().all(|byte| *byte == 0) {
                stats.sparse_zero_bytes_skipped = stats
                    .sparse_zero_bytes_skipped
                    .saturating_add(u64::try_from(header_read).unwrap_or(u64::MAX));
            } else {
                stats.truncated_records = stats.truncated_records.saturating_add(1);
                stats.corrupt_records = stats.corrupt_records.saturating_add(1);
                stats.diagnostic(
                    options,
                    stream_offset,
                    UsnErrorKind::TruncatedRecord,
                    format!(
                        "{} non-zero trailing byte(s) cannot form a USN header",
                        header_read
                    ),
                );
            }
            break;
        }

        if header.iter().all(|byte| *byte == 0) {
            stats.sparse_zero_bytes_skipped = stats.sparse_zero_bytes_skipped.saturating_add(8);
            stream_offset = checked_offset_add(stream_offset, 8, &stats)?;
            continue;
        }

        let record_length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let major_version = u16::from_le_bytes([header[4], header[5]]);
        stats.records_seen = stats.records_seen.saturating_add(1);

        if record_length == 0 || record_length < 8 {
            stats.corrupt_records = stats.corrupt_records.saturating_add(1);
            stats.diagnostic(
                options,
                stream_offset,
                UsnErrorKind::InvalidRecordLength,
                format!("record length {record_length} is smaller than the 8-byte prefix"),
            );
            stream_offset = checked_offset_add(stream_offset, 8, &stats)?;
            continue;
        }

        let aligned_length = align_record_length(record_length).ok_or_else(|| {
            failed_error(
                UsnErrorKind::CheckedArithmeticOverflow,
                stream_offset,
                format!("aligning record length {record_length}"),
                &stats,
            )
        })?;
        let remaining_framed_bytes = aligned_length.checked_sub(8).ok_or_else(|| {
            failed_error(
                UsnErrorKind::CheckedArithmeticOverflow,
                stream_offset,
                "subtracting the record prefix from aligned length".to_string(),
                &stats,
            )
        })?;

        let recognized_version = major_version == 2 || major_version == 3;
        let minimum_length = if major_version == 3 { 76_u32 } else { 60_u32 };
        if !recognized_version {
            if major_version == 4 {
                stats.unsupported_v4_records = stats.unsupported_v4_records.saturating_add(1);
            } else {
                stats.unknown_version_records = stats.unknown_version_records.saturating_add(1);
            }
            stats.diagnostic(
                options,
                stream_offset,
                UsnErrorKind::InvalidVersion,
                format!("USN major version {major_version} is not decoded"),
            );
            if !discard_exact(
                &mut reader,
                remaining_framed_bytes,
                &mut stats,
                stream_offset,
            )? {
                note_truncated_record(
                    &mut stats,
                    options,
                    stream_offset,
                    "unsupported record ends beyond the available stream",
                );
                break;
            }
            stream_offset = checked_offset_add(stream_offset, aligned_length, &stats)?;
            continue;
        }

        if record_length < minimum_length {
            stats.corrupt_records = stats.corrupt_records.saturating_add(1);
            stats.diagnostic(
                options,
                stream_offset,
                UsnErrorKind::InvalidRecordLength,
                format!("V{major_version} record length {record_length} is below {minimum_length}"),
            );
            if !discard_exact(
                &mut reader,
                remaining_framed_bytes,
                &mut stats,
                stream_offset,
            )? {
                note_truncated_record(
                    &mut stats,
                    options,
                    stream_offset,
                    "short record ends beyond the available stream",
                );
                break;
            }
            stream_offset = checked_offset_add(stream_offset, aligned_length, &stats)?;
            continue;
        }

        let record_length_usize = usize::try_from(record_length).map_err(|_| {
            failed_error(
                UsnErrorKind::CheckedArithmeticOverflow,
                stream_offset,
                format!("record length {record_length} does not fit usize"),
                &stats,
            )
        })?;
        if record_length_usize > options.max_record_bytes {
            stats.oversized_records = stats.oversized_records.saturating_add(1);
            stats.diagnostic(
                options,
                stream_offset,
                UsnErrorKind::InvalidRecordLength,
                format!(
                    "record length {record_length_usize} exceeds configured {}-byte allocation guard; discarded incrementally",
                    options.max_record_bytes
                ),
            );
            if !discard_exact(
                &mut reader,
                remaining_framed_bytes,
                &mut stats,
                stream_offset,
            )? {
                note_truncated_record(
                    &mut stats,
                    options,
                    stream_offset,
                    "oversized record ends beyond the available stream",
                );
                break;
            }
            stream_offset = checked_offset_add(stream_offset, aligned_length, &stats)?;
            continue;
        }

        let mut record_bytes = Vec::new();
        record_bytes
            .try_reserve_exact(record_length_usize)
            .map_err(|error| {
                failed_error(
                    UsnErrorKind::Allocation,
                    stream_offset,
                    format!("reserving {record_length_usize}-byte record buffer: {error}"),
                    &stats,
                )
            })?;
        record_bytes.resize(record_length_usize, 0);
        record_bytes[..8].copy_from_slice(&header);
        let body_read = read_fill_bounded(&mut reader, &mut record_bytes[8..], &mut stats)
            .map_err(|error| {
                failed_error(
                    UsnErrorKind::Io,
                    stream_offset,
                    format!("reading V{major_version} record body: {error}"),
                    &stats,
                )
            })?;
        if body_read != record_bytes.len().saturating_sub(8) {
            note_truncated_record(
                &mut stats,
                options,
                stream_offset,
                format!(
                    "record declares {record_length_usize} bytes but only {} were available",
                    body_read.saturating_add(8)
                ),
            );
            break;
        }

        let padding = aligned_length
            .checked_sub(u64::from(record_length))
            .ok_or_else(|| {
                failed_error(
                    UsnErrorKind::CheckedArithmeticOverflow,
                    stream_offset,
                    "calculating aligned record padding".to_string(),
                    &stats,
                )
            })?;
        if !discard_exact(&mut reader, padding, &mut stats, stream_offset)? {
            note_truncated_record(
                &mut stats,
                options,
                stream_offset,
                "record alignment padding is truncated",
            );
            break;
        }

        match parse_single_record(&record_bytes, major_version, stream_offset, options) {
            Ok(record) => {
                stats.records_parsed = stats.records_parsed.saturating_add(1);
                sink.record(&record).map_err(|error| {
                    failed_error(
                        UsnErrorKind::Sink,
                        stream_offset,
                        format!("record sink rejected V{major_version} record: {error}"),
                        &stats,
                    )
                })?;
                stats.records_emitted = stats.records_emitted.saturating_add(1);
                if major_version == 2 {
                    stats.v2_records = stats.v2_records.saturating_add(1);
                } else {
                    stats.v3_records = stats.v3_records.saturating_add(1);
                }
            }
            Err(error) => {
                stats.corrupt_records = stats.corrupt_records.saturating_add(1);
                stats.diagnostic(options, stream_offset, error.kind, error.message);
            }
        }

        stream_offset = checked_offset_add(stream_offset, aligned_length, &stats)?;
    }

    Ok(UsnStreamResult {
        status: stats.terminal_status(),
        stats,
    })
}

fn validate_options(options: &UsnParseOptions) -> Result<(), String> {
    if options.max_record_bytes < 76 {
        return Err("max_record_bytes must be at least 76".to_string());
    }
    if options.max_record_bytes > HARD_MAX_RECORD_BYTES {
        return Err(format!(
            "max_record_bytes exceeds hard {}-byte memory guard",
            HARD_MAX_RECORD_BYTES
        ));
    }
    if options.max_filename_bytes == 0 || options.max_filename_bytes > options.max_record_bytes {
        return Err(
            "max_filename_bytes must be non-zero and no larger than max_record_bytes".to_string(),
        );
    }
    if options.diagnostic_sample_limit > HARD_MAX_DIAGNOSTIC_SAMPLES {
        return Err(format!(
            "diagnostic_sample_limit exceeds hard sample bound {HARD_MAX_DIAGNOSTIC_SAMPLES}"
        ));
    }
    Ok(())
}

fn parse_single_record(
    data: &[u8],
    major_version: u16,
    byte_offset: u64,
    options: &UsnParseOptions,
) -> Result<UsnRecord, RecordError> {
    let record_length = read_u32(data, 0)?;
    let minor_version = read_u16(data, 6)?;
    let (
        file_reference,
        parent_reference,
        usn,
        timestamp_filetime,
        reason,
        source_info,
        security_id,
        file_attributes,
        filename_length_offset,
        filename_offset_offset,
    ) = if major_version == 2 {
        let file_raw = read_u64(data, 8)?;
        let parent_raw = read_u64(data, 16)?;
        (
            v2_reference(file_raw),
            v2_reference(parent_raw),
            read_i64(data, 24)?,
            read_i64(data, 32)?,
            read_u32(data, 40)?,
            read_u32(data, 44)?,
            read_u32(data, 48)?,
            read_u32(data, 52)?,
            56,
            58,
        )
    } else {
        (
            UsnFileReference::V3 {
                low: read_u64(data, 8)?,
                high: read_u64(data, 16)?,
            },
            UsnFileReference::V3 {
                low: read_u64(data, 24)?,
                high: read_u64(data, 32)?,
            },
            read_i64(data, 40)?,
            read_i64(data, 48)?,
            read_u32(data, 56)?,
            read_u32(data, 60)?,
            read_u32(data, 64)?,
            read_u32(data, 68)?,
            72,
            74,
        )
    };

    let filename_length = usize::from(read_u16(data, filename_length_offset)?);
    let filename_offset = usize::from(read_u16(data, filename_offset_offset)?);
    if filename_length > options.max_filename_bytes {
        return Err(RecordError::new(
            UsnErrorKind::InvalidFileNameLength,
            format!(
                "filename is {filename_length} bytes, above configured {}-byte bound",
                options.max_filename_bytes
            ),
        ));
    }
    if filename_length % 2 != 0 {
        return Err(RecordError::new(
            UsnErrorKind::InvalidFileNameLength,
            format!("UTF-16 filename length {filename_length} is odd"),
        ));
    }
    let filename_end = filename_offset
        .checked_add(filename_length)
        .ok_or_else(|| {
            RecordError::new(
                UsnErrorKind::CheckedArithmeticOverflow,
                "filename offset plus length overflows usize",
            )
        })?;
    if filename_offset > data.len() || filename_end > data.len() {
        return Err(RecordError::new(
            UsnErrorKind::InvalidFileNameOffset,
            format!(
                "filename range {filename_offset}..{filename_end} exceeds record length {}",
                data.len()
            ),
        ));
    }
    let mut code_units = Vec::new();
    code_units
        .try_reserve_exact(filename_length / 2)
        .map_err(|error| {
            RecordError::new(
                UsnErrorKind::Allocation,
                format!("reserving UTF-16 filename buffer: {error}"),
            )
        })?;
    for pair in data[filename_offset..filename_end].chunks_exact(2) {
        code_units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let file_name = String::from_utf16(&code_units).map_err(|_| {
        RecordError::new(
            UsnErrorKind::InvalidUtf16,
            "filename contains an unpaired UTF-16 surrogate",
        )
    })?;

    Ok(UsnRecord {
        version: if major_version == 2 {
            UsnVersion::V2
        } else {
            UsnVersion::V3
        },
        major_version,
        minor_version,
        record_length,
        file_reference,
        parent_reference,
        usn,
        timestamp_filetime,
        timestamp_utc: filetime_to_rfc3339(timestamp_filetime),
        reason,
        reason_flags: decode_reason_flags(reason),
        unknown_reason_bits: reason & !KNOWN_REASON_MASK,
        source_info,
        security_id,
        file_attributes,
        file_name,
        byte_offset,
    })
}

fn v2_reference(raw: u64) -> UsnFileReference {
    UsnFileReference::V2 {
        raw,
        entry: raw & 0x0000_FFFF_FFFF_FFFF,
        sequence: (raw >> 48) as u16,
    }
}

#[derive(Debug)]
struct RecordError {
    kind: UsnErrorKind,
    message: String,
}

impl RecordError {
    fn new(kind: UsnErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, RecordError> {
    let bytes = checked_slice(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, RecordError> {
    let bytes = checked_slice(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, RecordError> {
    let bytes = checked_slice(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_i64(data: &[u8], offset: usize) -> Result<i64, RecordError> {
    let bytes = checked_slice(data, offset, 8)?;
    Ok(i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn checked_slice(data: &[u8], offset: usize, length: usize) -> Result<&[u8], RecordError> {
    let end = offset.checked_add(length).ok_or_else(|| {
        RecordError::new(
            UsnErrorKind::CheckedArithmeticOverflow,
            "field offset plus length overflows usize",
        )
    })?;
    data.get(offset..end).ok_or_else(|| {
        RecordError::new(
            UsnErrorKind::TruncatedRecord,
            format!(
                "field range {offset}..{end} exceeds record length {}",
                data.len()
            ),
        )
    })
}

fn read_fill_bounded<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    stats: &mut UsnStreamStats,
) -> io::Result<usize> {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        let chunk_end = filled.saturating_add(READ_CHUNK_BYTES).min(buffer.len());
        match reader.read(&mut buffer[filled..chunk_end]) {
            Ok(0) => break,
            Ok(count) => {
                filled = filled.saturating_add(count);
                stats.bytes_read = stats
                    .bytes_read
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn discard_exact<R: Read>(
    reader: &mut R,
    mut bytes: u64,
    stats: &mut UsnStreamStats,
    record_offset: u64,
) -> Result<bool, UsnParseError> {
    let mut scratch = [0_u8; READ_CHUNK_BYTES];
    while bytes > 0 {
        let request = usize::try_from(bytes.min(READ_CHUNK_BYTES as u64)).map_err(|_| {
            failed_error(
                UsnErrorKind::CheckedArithmeticOverflow,
                record_offset,
                "discard request does not fit usize".to_string(),
                stats,
            )
        })?;
        let count = read_fill_bounded(reader, &mut scratch[..request], stats).map_err(|error| {
            failed_error(
                UsnErrorKind::Io,
                record_offset,
                format!("discarding framed record bytes: {error}"),
                stats,
            )
        })?;
        if count == 0 {
            return Ok(false);
        }
        bytes = bytes.saturating_sub(u64::try_from(count).unwrap_or(u64::MAX));
    }
    Ok(true)
}

fn align_record_length(record_length: u32) -> Option<u64> {
    u64::from(record_length)
        .checked_add(7)
        .map(|length| length & !7_u64)
}

fn checked_offset_add(
    offset: u64,
    amount: u64,
    stats: &UsnStreamStats,
) -> Result<u64, UsnParseError> {
    offset.checked_add(amount).ok_or_else(|| {
        failed_error(
            UsnErrorKind::CheckedArithmeticOverflow,
            offset,
            format!("stream offset plus {amount} overflows u64"),
            stats,
        )
    })
}

fn note_truncated_record(
    stats: &mut UsnStreamStats,
    options: &UsnParseOptions,
    offset: u64,
    message: impl AsRef<str>,
) {
    stats.truncated_records = stats.truncated_records.saturating_add(1);
    stats.corrupt_records = stats.corrupt_records.saturating_add(1);
    stats.diagnostic(options, offset, UsnErrorKind::TruncatedRecord, message);
}

fn failed_error(
    kind: UsnErrorKind,
    offset: u64,
    message: String,
    stats: &UsnStreamStats,
) -> UsnParseError {
    UsnParseError {
        status: UsnTerminalStatus::Failed,
        kind,
        offset,
        message: bounded_text(&message, DIAGNOSTIC_MESSAGE_BYTES),
        stats: Box::new(stats.clone()),
    }
}

fn bounded_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn decode_reason_flags(reason: u32) -> Vec<&'static str> {
    let mut flags = Vec::with_capacity(23);
    for (mask, name) in [
        (USN_REASON_DATA_OVERWRITE, "USN_REASON_DATA_OVERWRITE"),
        (USN_REASON_DATA_EXTEND, "USN_REASON_DATA_EXTEND"),
        (USN_REASON_DATA_TRUNCATION, "USN_REASON_DATA_TRUNCATION"),
        (
            USN_REASON_NAMED_DATA_OVERWRITE,
            "USN_REASON_NAMED_DATA_OVERWRITE",
        ),
        (USN_REASON_NAMED_DATA_EXTEND, "USN_REASON_NAMED_DATA_EXTEND"),
        (
            USN_REASON_NAMED_DATA_TRUNCATION,
            "USN_REASON_NAMED_DATA_TRUNCATION",
        ),
        (USN_REASON_FILE_CREATE, "USN_REASON_FILE_CREATE"),
        (USN_REASON_FILE_DELETE, "USN_REASON_FILE_DELETE"),
        (USN_REASON_EA_CHANGE, "USN_REASON_EA_CHANGE"),
        (USN_REASON_SECURITY_CHANGE, "USN_REASON_SECURITY_CHANGE"),
        (USN_REASON_RENAME_OLD_NAME, "USN_REASON_RENAME_OLD_NAME"),
        (USN_REASON_RENAME_NEW_NAME, "USN_REASON_RENAME_NEW_NAME"),
        (USN_REASON_INDEXABLE_CHANGE, "USN_REASON_INDEXABLE_CHANGE"),
        (USN_REASON_BASIC_INFO_CHANGE, "USN_REASON_BASIC_INFO_CHANGE"),
        (USN_REASON_HARD_LINK_CHANGE, "USN_REASON_HARD_LINK_CHANGE"),
        (
            USN_REASON_COMPRESSION_CHANGE,
            "USN_REASON_COMPRESSION_CHANGE",
        ),
        (USN_REASON_ENCRYPTION_CHANGE, "USN_REASON_ENCRYPTION_CHANGE"),
        (USN_REASON_OBJECT_ID_CHANGE, "USN_REASON_OBJECT_ID_CHANGE"),
        (
            USN_REASON_REPARSE_POINT_CHANGE,
            "USN_REASON_REPARSE_POINT_CHANGE",
        ),
        (USN_REASON_STREAM_CHANGE, "USN_REASON_STREAM_CHANGE"),
        (USN_REASON_TRANSACTED_CHANGE, "USN_REASON_TRANSACTED_CHANGE"),
        (USN_REASON_INTEGRITY_CHANGE, "USN_REASON_INTEGRITY_CHANGE"),
        (USN_REASON_CLOSE, "USN_REASON_CLOSE"),
    ] {
        if reason & mask != 0 {
            flags.push(name);
        }
    }
    flags
}

/// Convert a positive Windows FILETIME to UTC with its native 100 ns precision. Years outside
/// 1601..=9999 are rejected instead of wrapping date arithmetic.
fn filetime_to_rfc3339(filetime: i64) -> Option<String> {
    if filetime <= 0 {
        return None;
    }
    let unix_ticks = filetime.checked_sub(FILETIME_UNIX_EPOCH_100NS)?;
    let unix_seconds = unix_ticks.div_euclid(10_000_000);
    let subsecond_ticks = unix_ticks.rem_euclid(10_000_000);
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days)?;
    if !(1601..=9999).contains(&year) {
        return None;
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    if subsecond_ticks == 0 {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    } else {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{subsecond_ticks:07}Z"
        ))
    }
}

/// Howard Hinnant's civil-from-days transform, with checked offsets for hostile timestamps.
fn civil_from_days(days_since_unix_epoch: i64) -> Option<(i64, i64, i64)> {
    let z = days_since_unix_epoch.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z.checked_sub(146_096)? }.div_euclid(146_097);
    let day_of_era = z.checked_sub(era.checked_mul(146_097)?)?;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year =
        day_of_era.checked_sub(365 * year_of_era + year_of_era / 4 - year_of_era / 100)?;
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year = year.checked_add(1)?;
    }
    Some((year, month, day))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct CollectSink {
        records: Vec<UsnRecord>,
    }

    impl UsnSink for CollectSink {
        type Error = io::Error;

        fn record(&mut self, record: &UsnRecord) -> Result<(), Self::Error> {
            self.records.push(record.clone());
            Ok(())
        }
    }

    struct TinyChunkReader<R> {
        inner: R,
        max_chunk: usize,
        largest_request: usize,
    }

    impl<R: Read> Read for TinyChunkReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.largest_request = self.largest_request.max(buffer.len());
            let request = buffer.len().min(self.max_chunk);
            self.inner.read(&mut buffer[..request])
        }
    }

    fn build_v2(name: &str, reason: u32, timestamp: i64) -> Vec<u8> {
        let name_bytes = utf16_bytes(name);
        let record_length = 60_u32 + u32::try_from(name_bytes.len()).unwrap();
        let aligned = usize::try_from(align_record_length(record_length).unwrap()).unwrap();
        let mut bytes = vec![0_u8; aligned];
        bytes[0..4].copy_from_slice(&record_length.to_le_bytes());
        bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0007_0000_0000_0042_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x0008_0000_0000_0021_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&123_i64.to_le_bytes());
        bytes[32..40].copy_from_slice(&timestamp.to_le_bytes());
        bytes[40..44].copy_from_slice(&reason.to_le_bytes());
        bytes[44..48].copy_from_slice(&3_u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&77_u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&0x20_u32.to_le_bytes());
        bytes[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        bytes[58..60].copy_from_slice(&60_u16.to_le_bytes());
        bytes[60..60 + name_bytes.len()].copy_from_slice(&name_bytes);
        bytes
    }

    fn build_v3(name: &str) -> Vec<u8> {
        let name_bytes = utf16_bytes(name);
        let record_length = 76_u32 + u32::try_from(name_bytes.len()).unwrap();
        let aligned = usize::try_from(align_record_length(record_length).unwrap()).unwrap();
        let mut bytes = vec![0_u8; aligned];
        bytes[0..4].copy_from_slice(&record_length.to_le_bytes());
        bytes[4..6].copy_from_slice(&3_u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&1_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&2_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&3_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&4_u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&999_i64.to_le_bytes());
        bytes[56..60].copy_from_slice(&USN_REASON_FILE_DELETE.to_le_bytes());
        bytes[68..72].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[72..74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        bytes[74..76].copy_from_slice(&76_u16.to_le_bytes());
        bytes[76..76 + name_bytes.len()].copy_from_slice(&name_bytes);
        bytes
    }

    fn utf16_bytes(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn streams_tiny_chunks_and_decodes_v2_v3_fields() {
        let timestamp = FILETIME_UNIX_EPOCH_100NS + 12_345_678;
        let mut journal = vec![0_u8; 16];
        journal.extend(build_v2(
            "created.txt",
            USN_REASON_FILE_CREATE | USN_REASON_CLOSE,
            timestamp,
        ));
        journal.extend(build_v3("deleted.bin"));
        let mut reader = TinyChunkReader {
            inner: Cursor::new(journal),
            max_chunk: 3,
            largest_request: 0,
        };
        let mut sink = CollectSink::default();
        let result = parse_usn_journal(&mut reader, &mut sink, &UsnParseOptions::default())
            .expect("journal should parse");

        assert_eq!(result.status, UsnTerminalStatus::Recognized);
        assert_eq!(result.stats.records_emitted, 2);
        assert_eq!(result.stats.v2_records, 1);
        assert_eq!(result.stats.v3_records, 1);
        assert_eq!(result.stats.sparse_zero_bytes_skipped, 16);
        assert!(reader.largest_request <= READ_CHUNK_BYTES);
        assert_eq!(sink.records[0].file_name, "created.txt");
        assert_eq!(
            sink.records[0].timestamp_utc.as_deref(),
            Some("1970-01-01T00:00:01.2345678Z")
        );
        assert_eq!(sink.records[0].minor_version, 1);
        assert_eq!(
            sink.records[0].file_reference,
            UsnFileReference::V2 {
                raw: 0x0007_0000_0000_0042,
                entry: 0x42,
                sequence: 7,
            }
        );
        assert!(sink.records[0]
            .reason_flags
            .contains(&"USN_REASON_FILE_CREATE"));
        assert_eq!(
            sink.records[1].file_reference,
            UsnFileReference::V3 { low: 1, high: 2 }
        );
    }

    struct RejectSink;

    impl UsnSink for RejectSink {
        type Error = &'static str;

        fn record(&mut self, _record: &UsnRecord) -> Result<(), Self::Error> {
            Err("injected sink rejection")
        }
    }

    #[test]
    fn sink_failure_is_fatal_err_with_partial_counts() {
        let mut sink = RejectSink;
        let error = parse_usn_journal(
            Cursor::new(build_v2("fail.txt", 0, 0)),
            &mut sink,
            &UsnParseOptions::default(),
        )
        .expect_err("sink rejection must never be a successful result");
        assert_eq!(error.status, UsnTerminalStatus::Failed);
        assert_eq!(error.kind, UsnErrorKind::Sink);
        assert_eq!(error.stats.records_seen, 1);
        assert_eq!(error.stats.records_parsed, 1);
        assert_eq!(error.stats.records_emitted, 0);
        assert!(error.message.contains("injected sink rejection"));
    }

    struct FailAfterReader {
        inner: Cursor<Vec<u8>>,
        bytes_before_failure: usize,
    }

    impl Read for FailAfterReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.bytes_before_failure == 0 {
                return Err(io::Error::other("injected journal read failure"));
            }
            let request = buffer.len().min(self.bytes_before_failure);
            let count = self.inner.read(&mut buffer[..request])?;
            self.bytes_before_failure = self.bytes_before_failure.saturating_sub(count);
            Ok(count)
        }
    }

    #[test]
    fn reader_failure_is_fatal_with_exact_bytes_and_record_counts() {
        let reader = FailAfterReader {
            inner: Cursor::new(build_v2("read-error.txt", 0, 0)),
            bytes_before_failure: 18,
        };
        let mut sink = CollectSink::default();
        let error = parse_usn_journal(reader, &mut sink, &UsnParseOptions::default())
            .expect_err("reader failure must not be converted to partial success");
        assert_eq!(error.status, UsnTerminalStatus::Failed);
        assert_eq!(error.kind, UsnErrorKind::Io);
        assert_eq!(error.stats.bytes_read, 18);
        assert_eq!(error.stats.records_seen, 1);
        assert_eq!(error.stats.records_emitted, 0);
        assert!(error.message.contains("injected journal read failure"));
    }

    #[test]
    fn diagnostics_are_bounded_with_exact_omitted_count() {
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend_from_slice(&4_u32.to_le_bytes());
            data.extend_from_slice(&2_u16.to_le_bytes());
            data.extend_from_slice(&0_u16.to_le_bytes());
        }
        let options = UsnParseOptions {
            diagnostic_sample_limit: 2,
            ..UsnParseOptions::default()
        };
        let mut sink = CollectSink::default();
        let result = parse_usn_journal(Cursor::new(data), &mut sink, &options).unwrap();
        assert_eq!(result.status, UsnTerminalStatus::Partial);
        assert_eq!(result.stats.corrupt_records, 5);
        assert_eq!(result.stats.diagnostic_count, 5);
        assert_eq!(result.stats.diagnostics.len(), 2);
        assert_eq!(result.stats.diagnostics_omitted, 3);
    }

    #[test]
    fn oversized_record_is_discarded_incrementally_and_next_record_survives() {
        let declared = 96_u32;
        let mut oversized = vec![0_u8; usize::try_from(declared).unwrap()];
        oversized[0..4].copy_from_slice(&declared.to_le_bytes());
        oversized[4..6].copy_from_slice(&2_u16.to_le_bytes());
        oversized.extend(build_v2("after.txt", 0, 0));
        let options = UsnParseOptions {
            max_record_bytes: 80,
            max_filename_bytes: 64,
            diagnostic_sample_limit: 8,
        };
        let mut sink = CollectSink::default();
        let result = parse_usn_journal(Cursor::new(oversized), &mut sink, &options).unwrap();
        assert_eq!(result.status, UsnTerminalStatus::Partial);
        assert_eq!(result.stats.oversized_records, 1);
        assert_eq!(result.stats.records_emitted, 1);
        assert_eq!(sink.records[0].file_name, "after.txt");
    }

    #[test]
    fn truncated_record_and_unsupported_version_are_explicit_partial() {
        let mut unsupported = vec![0_u8; 80];
        unsupported[0..4].copy_from_slice(&80_u32.to_le_bytes());
        unsupported[4..6].copy_from_slice(&4_u16.to_le_bytes());
        let mut truncated = build_v2("truncated.txt", 0, 0);
        truncated.truncate(truncated.len().saturating_sub(3));
        unsupported.extend(truncated);
        let mut sink = CollectSink::default();
        let result = parse_usn_journal(
            Cursor::new(unsupported),
            &mut sink,
            &UsnParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, UsnTerminalStatus::Partial);
        assert_eq!(result.stats.unsupported_v4_records, 1);
        assert_eq!(result.stats.truncated_records, 1);
        assert_eq!(result.stats.records_emitted, 0);
    }

    #[test]
    fn reason_bits_and_filetime_boundaries_are_preserved() {
        let flags = decode_reason_flags(USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME);
        assert_eq!(
            flags,
            vec!["USN_REASON_RENAME_OLD_NAME", "USN_REASON_RENAME_NEW_NAME"]
        );
        assert_eq!(
            filetime_to_rfc3339(FILETIME_UNIX_EPOCH_100NS).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(filetime_to_rfc3339(0), None);
    }

    #[test]
    fn invalid_options_fail_before_reading() {
        let mut sink = CollectSink::default();
        let options = UsnParseOptions {
            diagnostic_sample_limit: HARD_MAX_DIAGNOSTIC_SAMPLES + 1,
            ..UsnParseOptions::default()
        };
        let error = parse_usn_journal(Cursor::new(Vec::<u8>::new()), &mut sink, &options)
            .expect_err("unbounded diagnostics must be rejected");
        assert_eq!(error.status, UsnTerminalStatus::Failed);
        assert_eq!(error.kind, UsnErrorKind::InvalidOptions);
        assert_eq!(error.stats.bytes_read, 0);
    }
}
