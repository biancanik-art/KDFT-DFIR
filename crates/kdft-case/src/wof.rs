// Copyright 2026 KDFT contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded random-access decoding for Windows Overlay Filter (WOF) file data.
//!
//! WOF stores a sparse unnamed NTFS `$DATA` stream together with a
//! `WofCompressedData` named stream.  The reparse point identifies the file
//! provider and compression algorithm.  The named stream begins with a table
//! of cumulative, stream-relative chunk ends; the compressed chunks follow the
//! table.  Logical file offsets therefore do **not** map one-to-one to a single
//! physical evidence offset.  Callers must retain both the logical range and
//! the named-stream chunk ranges returned in [`WofRangeProvenance`].
//!
//! Only the XPRESS-Huffman algorithms already available in this workspace are
//! decoded here.  LZX is recognized but deliberately returned as unsupported;
//! an algorithm is never inferred from a filename, stream size, or payload.

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

/// `IO_REPARSE_TAG_WOF` from Windows' reparse-point ABI.
pub const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;
/// WOF external-info version supported by the file provider.
pub const WOF_CURRENT_VERSION: u32 = 1;
/// WOF file-provider identifier.
pub const WOF_PROVIDER_FILE: u32 = 2;
/// File-provider metadata version supported by this reader.
pub const FILE_PROVIDER_CURRENT_VERSION: u32 = 1;

const REPARSE_HEADER_BYTES: usize = 8;
const FILE_PROVIDER_PAYLOAD_BYTES: usize = 16;
const FOUR_GIB: u64 = 1_u64 << 32;

/// Compression algorithm declared by `WOF_FILE_PROVIDER_EXTERNAL_INFO`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WofAlgorithm {
    Xpress4k,
    Lzx,
    Xpress8k,
    Xpress16k,
}

impl WofAlgorithm {
    pub fn from_raw(value: u32) -> Result<Self, WofError> {
        match value {
            0 => Ok(Self::Xpress4k),
            1 => Ok(Self::Lzx),
            2 => Ok(Self::Xpress8k),
            3 => Ok(Self::Xpress16k),
            other => Err(WofError::UnknownAlgorithm(other)),
        }
    }

    pub fn raw(self) -> u32 {
        match self {
            Self::Xpress4k => 0,
            Self::Lzx => 1,
            Self::Xpress8k => 2,
            Self::Xpress16k => 3,
        }
    }

    pub fn chunk_size(self) -> usize {
        match self {
            Self::Xpress4k => 4 * 1024,
            Self::Lzx => 32 * 1024,
            Self::Xpress8k => 8 * 1024,
            Self::Xpress16k => 16 * 1024,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Xpress4k => "xpress4k",
            Self::Lzx => "lzx",
            Self::Xpress8k => "xpress8k",
            Self::Xpress16k => "xpress16k",
        }
    }
}

/// Validated WOF reparse metadata for a file-provider stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WofFileInfo {
    pub wof_version: u32,
    pub provider: u32,
    pub file_provider_version: u32,
    pub algorithm: WofAlgorithm,
}

/// Hard bounds supplied by the caller for untrusted WOF metadata and data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WofDecodeLimits {
    /// Maximum number of logical bytes this operation may return.
    pub max_output_bytes: usize,
    /// Maximum chunk-table allocation/read.
    pub max_chunk_table_bytes: usize,
    /// Maximum declared logical chunks, even if the table would otherwise fit.
    pub max_chunks: u64,
}

impl WofDecodeLimits {
    pub fn for_output(max_output_bytes: usize) -> Self {
        Self {
            max_output_bytes,
            max_chunk_table_bytes: 64 * 1024 * 1024,
            max_chunks: 16 * 1024 * 1024,
        }
    }
}

/// Encoding of one backing-stream chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WofChunkEncoding {
    Raw,
    XpressHuffman,
}

/// Coordinate provenance for one decoded logical chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WofChunkProvenance {
    pub chunk_index: u64,
    /// Offset in the reconstructed logical unnamed stream.
    pub logical_start: u64,
    pub logical_end_exclusive: u64,
    /// Offset relative to the start of `:WofCompressedData`.
    pub backing_start: u64,
    pub backing_end_exclusive: u64,
    pub encoding: WofChunkEncoding,
}

/// Provenance for a bounded reconstructed range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WofRangeProvenance {
    pub algorithm: WofAlgorithm,
    pub chunk_size: usize,
    pub table_entry_width: usize,
    pub table_bytes: u64,
    pub logical_offset: u64,
    pub logical_length: usize,
    pub chunks: Vec<WofChunkProvenance>,
}

impl WofRangeProvenance {
    /// Explicit coordinate description suitable for persisted parser metadata.
    pub const LOGICAL_COORDINATE_SYSTEM: &'static str =
        "reconstructed WOF logical file-relative bytes";
    pub const BACKING_COORDINATE_SYSTEM: &'static str = "WofCompressedData stream-relative bytes";
    pub const PHYSICAL_MAPPING_NOTE: &'static str = "WOF logical bytes are reconstructed from compressed chunks and do not map one-to-one to a single physical evidence offset; resolve the named stream's NTFS runs separately";
}

/// A decoded range and its logical/backing coordinate provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WofDecodedRange {
    pub bytes: Vec<u8>,
    pub provenance: WofRangeProvenance,
}

#[derive(Debug)]
pub enum WofError {
    InvalidReparseBuffer(&'static str),
    UnexpectedReparseTag(u32),
    UnsupportedWofVersion(u32),
    UnsupportedProvider(u32),
    UnsupportedFileProviderVersion(u32),
    UnknownAlgorithm(u32),
    UnsupportedAlgorithm(WofAlgorithm),
    InvalidRange {
        offset: u64,
        length: usize,
        logical_length: u64,
    },
    OutputLimitExceeded {
        requested: usize,
        limit: usize,
    },
    ChunkCountLimitExceeded {
        chunks: u64,
        limit: u64,
    },
    ChunkTableLimitExceeded {
        bytes: u64,
        limit: usize,
    },
    TruncatedChunkTable {
        needed: u64,
        backing_length: u64,
    },
    InvalidChunkTable {
        entry_index: u64,
        previous: u64,
        current: u64,
        payload_length: u64,
    },
    InvalidChunkLength {
        chunk_index: u64,
        stored_length: u64,
        logical_length: usize,
    },
    DecompressionFailed {
        chunk_index: u64,
        reason: String,
    },
    OutputLengthMismatch {
        chunk_index: u64,
        expected: usize,
        actual: usize,
    },
    IntegerOverflow(&'static str),
    Io(io::Error),
}

impl fmt::Display for WofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReparseBuffer(reason) => write!(f, "invalid WOF reparse buffer: {reason}"),
            Self::UnexpectedReparseTag(tag) => {
                write!(f, "unexpected reparse tag 0x{tag:08x}; expected WOF")
            }
            Self::UnsupportedWofVersion(version) => {
                write!(f, "unsupported WOF version {version}")
            }
            Self::UnsupportedProvider(provider) => {
                write!(f, "unsupported WOF provider {provider}")
            }
            Self::UnsupportedFileProviderVersion(version) => {
                write!(f, "unsupported WOF file-provider version {version}")
            }
            Self::UnknownAlgorithm(algorithm) => {
                write!(f, "unknown WOF compression algorithm {algorithm}")
            }
            Self::UnsupportedAlgorithm(algorithm) => write!(
                f,
                "WOF compression algorithm {} is recognized but unsupported",
                algorithm.name()
            ),
            Self::InvalidRange {
                offset,
                length,
                logical_length,
            } => write!(
                f,
                "WOF logical range {offset}+{length} is outside the {logical_length}-byte file"
            ),
            Self::OutputLimitExceeded { requested, limit } => write!(
                f,
                "WOF range requests {requested} output bytes; operation limit is {limit}"
            ),
            Self::ChunkCountLimitExceeded { chunks, limit } => write!(
                f,
                "WOF metadata declares {chunks} chunks; operation limit is {limit}"
            ),
            Self::ChunkTableLimitExceeded { bytes, limit } => write!(
                f,
                "WOF chunk table requires {bytes} bytes; operation limit is {limit}"
            ),
            Self::TruncatedChunkTable {
                needed,
                backing_length,
            } => write!(
                f,
                "WOF chunk table requires {needed} bytes but backing stream has {backing_length}"
            ),
            Self::InvalidChunkTable {
                entry_index,
                previous,
                current,
                payload_length,
            } => write!(
                f,
                "invalid WOF chunk-table entry {entry_index}: previous={previous}, current={current}, payload={payload_length}"
            ),
            Self::InvalidChunkLength {
                chunk_index,
                stored_length,
                logical_length,
            } => write!(
                f,
                "WOF chunk {chunk_index} stores {stored_length} bytes for a {logical_length}-byte logical chunk"
            ),
            Self::DecompressionFailed {
                chunk_index,
                reason,
            } => write!(f, "WOF chunk {chunk_index} decompression failed: {reason}"),
            Self::OutputLengthMismatch {
                chunk_index,
                expected,
                actual,
            } => write!(
                f,
                "WOF chunk {chunk_index} decoded {actual} bytes; expected exactly {expected}"
            ),
            Self::IntegerOverflow(context) => write!(f, "integer overflow while {context}"),
            Self::Io(error) => write!(f, "WOF backing-stream I/O error: {error}"),
        }
    }
}

impl Error for WofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for WofError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Parse the complete 24-byte WOF reparse buffer, including its 8-byte header.
pub fn parse_reparse_buffer(buffer: &[u8]) -> Result<WofFileInfo, WofError> {
    if buffer.len() < REPARSE_HEADER_BYTES {
        return Err(WofError::InvalidReparseBuffer(
            "shorter than the 8-byte reparse header",
        ));
    }
    let tag = le_u32(buffer, 0)?;
    if tag != IO_REPARSE_TAG_WOF {
        return Err(WofError::UnexpectedReparseTag(tag));
    }
    let data_length = usize::from(le_u16(buffer, 4)?);
    if data_length != FILE_PROVIDER_PAYLOAD_BYTES {
        return Err(WofError::InvalidReparseBuffer(
            "file-provider payload length is not 16 bytes",
        ));
    }
    let total = REPARSE_HEADER_BYTES
        .checked_add(data_length)
        .ok_or(WofError::IntegerOverflow("sizing the reparse buffer"))?;
    if buffer.len() != total {
        return Err(WofError::InvalidReparseBuffer(
            "buffer length does not exactly match ReparseDataLength",
        ));
    }
    parse_reparse_payload(&buffer[REPARSE_HEADER_BYTES..])
}

/// Parse the 16-byte WOF/file-provider payload from an NTFS reparse attribute.
pub fn parse_reparse_payload(payload: &[u8]) -> Result<WofFileInfo, WofError> {
    if payload.len() != FILE_PROVIDER_PAYLOAD_BYTES {
        return Err(WofError::InvalidReparseBuffer(
            "file-provider payload is not exactly 16 bytes",
        ));
    }
    let wof_version = le_u32(payload, 0)?;
    if wof_version != WOF_CURRENT_VERSION {
        return Err(WofError::UnsupportedWofVersion(wof_version));
    }
    let provider = le_u32(payload, 4)?;
    if provider != WOF_PROVIDER_FILE {
        return Err(WofError::UnsupportedProvider(provider));
    }
    let file_provider_version = le_u32(payload, 8)?;
    if file_provider_version != FILE_PROVIDER_CURRENT_VERSION {
        return Err(WofError::UnsupportedFileProviderVersion(
            file_provider_version,
        ));
    }
    let algorithm = WofAlgorithm::from_raw(le_u32(payload, 12)?)?;
    Ok(WofFileInfo {
        wof_version,
        provider,
        file_provider_version,
        algorithm,
    })
}

/// Decode only the chunks intersecting a requested logical range.
///
/// The chunk table is validated in full, but unrelated compressed chunks are
/// never read or decompressed.  `backing_length` must be the trusted length of
/// the `:WofCompressedData` stream; `logical_length` is the unnamed stream's
/// declared logical length.
pub fn decode_range<R: Read + Seek>(
    backing: &mut R,
    backing_length: u64,
    logical_length: u64,
    info: WofFileInfo,
    logical_offset: u64,
    requested_length: usize,
    limits: WofDecodeLimits,
) -> Result<WofDecodedRange, WofError> {
    if info.algorithm == WofAlgorithm::Lzx {
        return Err(WofError::UnsupportedAlgorithm(info.algorithm));
    }
    if requested_length > limits.max_output_bytes {
        return Err(WofError::OutputLimitExceeded {
            requested: requested_length,
            limit: limits.max_output_bytes,
        });
    }
    if logical_offset > logical_length {
        return Err(WofError::InvalidRange {
            offset: logical_offset,
            length: requested_length,
            logical_length,
        });
    }
    let requested_u64 = u64::try_from(requested_length)
        .map_err(|_| WofError::IntegerOverflow("converting requested range length"))?;
    let requested_end =
        logical_offset
            .checked_add(requested_u64)
            .ok_or(WofError::InvalidRange {
                offset: logical_offset,
                length: requested_length,
                logical_length,
            })?;
    let logical_end = requested_end.min(logical_length);
    let output_length = usize::try_from(logical_end - logical_offset)
        .map_err(|_| WofError::IntegerOverflow("converting bounded output length"))?;

    let chunk_size = info.algorithm.chunk_size();
    let chunk_size_u64 = chunk_size as u64;
    let chunk_count = if logical_length == 0 {
        0
    } else {
        logical_length
            .checked_add(chunk_size_u64 - 1)
            .ok_or(WofError::IntegerOverflow(
                "rounding the logical chunk count",
            ))?
            / chunk_size_u64
    };
    if chunk_count > limits.max_chunks {
        return Err(WofError::ChunkCountLimitExceeded {
            chunks: chunk_count,
            limit: limits.max_chunks,
        });
    }
    let table_entry_width = if logical_length >= FOUR_GIB { 8 } else { 4 };
    let table_entries = chunk_count.saturating_sub(1);
    let table_bytes = table_entries
        .checked_mul(table_entry_width as u64)
        .ok_or(WofError::IntegerOverflow("sizing the WOF chunk table"))?;
    if table_bytes > limits.max_chunk_table_bytes as u64 {
        return Err(WofError::ChunkTableLimitExceeded {
            bytes: table_bytes,
            limit: limits.max_chunk_table_bytes,
        });
    }
    if table_bytes > backing_length {
        return Err(WofError::TruncatedChunkTable {
            needed: table_bytes,
            backing_length,
        });
    }
    let payload_length = backing_length - table_bytes;
    let cumulative_ends = read_and_validate_table(
        backing,
        table_entries,
        table_entry_width,
        table_bytes,
        payload_length,
    )?;
    validate_chunk_boundaries(
        &cumulative_ends,
        chunk_count,
        payload_length,
        logical_length,
        chunk_size_u64,
    )?;

    let empty_provenance = || WofRangeProvenance {
        algorithm: info.algorithm,
        chunk_size,
        table_entry_width,
        table_bytes,
        logical_offset,
        logical_length: output_length,
        chunks: Vec::new(),
    };
    if output_length == 0 {
        return Ok(WofDecodedRange {
            bytes: Vec::new(),
            provenance: empty_provenance(),
        });
    }
    if chunk_count == 0 {
        return Err(WofError::InvalidRange {
            offset: logical_offset,
            length: requested_length,
            logical_length,
        });
    }

    let first_chunk = logical_offset / chunk_size_u64;
    let last_chunk = (logical_end - 1) / chunk_size_u64;
    let selected_chunk_count = last_chunk - first_chunk + 1;
    let selected_capacity = usize::try_from(selected_chunk_count)
        .map_err(|_| WofError::IntegerOverflow("allocating WOF chunk provenance"))?;
    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(selected_capacity)
        .map_err(|_| WofError::IntegerOverflow("allocating bounded WOF chunk provenance"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_length)
        .map_err(|_| WofError::IntegerOverflow("allocating bounded WOF output"))?;

    for chunk_index in first_chunk..=last_chunk {
        let logical_chunk_start =
            chunk_index
                .checked_mul(chunk_size_u64)
                .ok_or(WofError::IntegerOverflow(
                    "computing WOF logical chunk start",
                ))?;
        let logical_chunk_end = logical_chunk_start
            .checked_add(chunk_size_u64)
            .ok_or(WofError::IntegerOverflow("computing WOF logical chunk end"))?
            .min(logical_length);
        let expected_chunk_length = usize::try_from(logical_chunk_end - logical_chunk_start)
            .map_err(|_| WofError::IntegerOverflow("converting WOF logical chunk length"))?;

        let relative_start = if chunk_index == 0 {
            0
        } else {
            cumulative_ends[(chunk_index - 1) as usize]
        };
        let relative_end = if chunk_index + 1 == chunk_count {
            payload_length
        } else {
            cumulative_ends[chunk_index as usize]
        };
        let stored_length =
            relative_end
                .checked_sub(relative_start)
                .ok_or(WofError::IntegerOverflow(
                    "computing WOF stored chunk length",
                ))?;
        if stored_length == 0 || stored_length > expected_chunk_length as u64 {
            return Err(WofError::InvalidChunkLength {
                chunk_index,
                stored_length,
                logical_length: expected_chunk_length,
            });
        }
        let backing_start =
            table_bytes
                .checked_add(relative_start)
                .ok_or(WofError::IntegerOverflow(
                    "computing WOF backing chunk start",
                ))?;
        let backing_end = table_bytes
            .checked_add(relative_end)
            .ok_or(WofError::IntegerOverflow("computing WOF backing chunk end"))?;
        let stored_length_usize = usize::try_from(stored_length)
            .map_err(|_| WofError::IntegerOverflow("converting WOF stored chunk length"))?;
        let mut stored = vec![0_u8; stored_length_usize];
        backing.seek(SeekFrom::Start(backing_start))?;
        backing.read_exact(&mut stored)?;

        let (decoded, encoding) = if stored_length_usize == expected_chunk_length {
            (stored, WofChunkEncoding::Raw)
        } else {
            let decoded =
                xpress_huffman::decompress(&stored, expected_chunk_length).map_err(|error| {
                    WofError::DecompressionFailed {
                        chunk_index,
                        reason: error.to_string(),
                    }
                })?;
            if decoded.len() != expected_chunk_length {
                return Err(WofError::OutputLengthMismatch {
                    chunk_index,
                    expected: expected_chunk_length,
                    actual: decoded.len(),
                });
            }
            (decoded, WofChunkEncoding::XpressHuffman)
        };

        let copy_start = logical_offset.max(logical_chunk_start) - logical_chunk_start;
        let copy_end = logical_end.min(logical_chunk_end) - logical_chunk_start;
        let copy_start = usize::try_from(copy_start)
            .map_err(|_| WofError::IntegerOverflow("converting WOF copy start"))?;
        let copy_end = usize::try_from(copy_end)
            .map_err(|_| WofError::IntegerOverflow("converting WOF copy end"))?;
        output.extend_from_slice(&decoded[copy_start..copy_end]);
        chunks.push(WofChunkProvenance {
            chunk_index,
            logical_start: logical_chunk_start,
            logical_end_exclusive: logical_chunk_end,
            backing_start,
            backing_end_exclusive: backing_end,
            encoding,
        });
    }

    if output.len() != output_length {
        return Err(WofError::OutputLengthMismatch {
            chunk_index: last_chunk,
            expected: output_length,
            actual: output.len(),
        });
    }
    Ok(WofDecodedRange {
        bytes: output,
        provenance: WofRangeProvenance {
            chunks,
            ..empty_provenance()
        },
    })
}

fn read_and_validate_table<R: Read + Seek>(
    backing: &mut R,
    table_entries: u64,
    entry_width: usize,
    table_bytes: u64,
    payload_length: u64,
) -> Result<Vec<u64>, WofError> {
    let table_length = usize::try_from(table_bytes)
        .map_err(|_| WofError::IntegerOverflow("converting WOF chunk table length"))?;
    let entry_count = usize::try_from(table_entries)
        .map_err(|_| WofError::IntegerOverflow("converting WOF chunk table count"))?;
    let mut table = vec![0_u8; table_length];
    if table_length > 0 {
        backing.seek(SeekFrom::Start(0))?;
        backing.read_exact(&mut table)?;
    }
    let mut ends = Vec::new();
    ends.try_reserve_exact(entry_count)
        .map_err(|_| WofError::IntegerOverflow("allocating WOF cumulative offsets"))?;
    let mut previous = 0_u64;
    for index in 0..entry_count {
        let byte_offset = index
            .checked_mul(entry_width)
            .ok_or(WofError::IntegerOverflow("indexing the WOF chunk table"))?;
        let current = match entry_width {
            4 => u64::from(le_u32(&table, byte_offset)?),
            8 => le_u64(&table, byte_offset)?,
            _ => return Err(WofError::InvalidReparseBuffer("invalid table width")),
        };
        if current <= previous || current > payload_length {
            return Err(WofError::InvalidChunkTable {
                entry_index: index as u64,
                previous,
                current,
                payload_length,
            });
        }
        ends.push(current);
        previous = current;
    }
    Ok(ends)
}

fn validate_chunk_boundaries(
    cumulative_ends: &[u64],
    chunk_count: u64,
    payload_length: u64,
    logical_length: u64,
    chunk_size: u64,
) -> Result<(), WofError> {
    let mut previous = 0_u64;
    for chunk_index in 0..chunk_count {
        let end = if chunk_index + 1 == chunk_count {
            payload_length
        } else {
            cumulative_ends[chunk_index as usize]
        };
        let stored_length = end.checked_sub(previous).ok_or(WofError::IntegerOverflow(
            "validating WOF stored chunk boundaries",
        ))?;
        let logical_start =
            chunk_index
                .checked_mul(chunk_size)
                .ok_or(WofError::IntegerOverflow(
                    "validating WOF logical chunk start",
                ))?;
        let logical_end = logical_start
            .checked_add(chunk_size)
            .ok_or(WofError::IntegerOverflow(
                "validating WOF logical chunk end",
            ))?
            .min(logical_length);
        let logical_chunk_length = usize::try_from(logical_end - logical_start)
            .map_err(|_| WofError::IntegerOverflow("validating WOF logical chunk length"))?;
        if stored_length == 0 || stored_length > logical_chunk_length as u64 {
            return Err(WofError::InvalidChunkLength {
                chunk_index,
                stored_length,
                logical_length: logical_chunk_length,
            });
        }
        previous = end;
    }
    Ok(())
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, WofError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(WofError::InvalidReparseBuffer("truncated 16-bit field"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, WofError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(WofError::InvalidReparseBuffer("truncated 32-bit field"))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, WofError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(WofError::InvalidReparseBuffer("truncated 64-bit field"))?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TrackingReader {
        cursor: Cursor<Vec<u8>>,
        reads: Vec<(u64, usize)>,
    }

    impl TrackingReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                cursor: Cursor::new(bytes),
                reads: Vec::new(),
            }
        }
    }

    impl Read for TrackingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let start = self.cursor.position();
            let read = self.cursor.read(buffer)?;
            self.reads.push((start, read));
            Ok(read)
        }
    }

    impl Seek for TrackingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.cursor.seek(position)
        }
    }

    fn info(algorithm: WofAlgorithm) -> WofFileInfo {
        WofFileInfo {
            wof_version: WOF_CURRENT_VERSION,
            provider: WOF_PROVIDER_FILE,
            file_provider_version: FILE_PROVIDER_CURRENT_VERSION,
            algorithm,
        }
    }

    /// Build a deterministic, non-evidentiary XPRESS-Huffman stream. The
    /// canonical tree contains one literal and one length-17, offset-1 match;
    /// the stream therefore expands to a caller-selected run of one byte.
    fn repeated_byte_xpress_stream(byte: u8, match_count: usize) -> (Vec<u8>, Vec<u8>) {
        assert!(match_count > 0);
        const TABLE_BYTES: usize = 256;
        const MATCH_LENGTH: usize = 17;
        const MATCH_SYMBOL: usize = 256 + 14;

        let mut compressed = vec![0_u8; TABLE_BYTES];
        for symbol in [byte as usize, MATCH_SYMBOL] {
            let slot = &mut compressed[symbol / 2];
            if symbol % 2 == 0 {
                *slot = (*slot & 0xF0) | 1;
            } else {
                *slot = (*slot & 0x0F) | 0x10;
            }
        }

        // Canonical code 0 is the literal; code 1 is the match. The decoder
        // consumes bits most-significant-first from little-endian 16-bit words.
        let mut bits = Vec::with_capacity(match_count + 1);
        bits.push(false);
        bits.extend(std::iter::repeat_n(true, match_count));
        for word_bits in bits.chunks(16) {
            let mut word = 0_u16;
            for (index, bit) in word_bits.iter().enumerate() {
                if *bit {
                    word |= 1 << (15 - index);
                }
            }
            compressed.extend_from_slice(&word.to_le_bytes());
        }
        // Preserve decoder look-ahead after the final populated word.
        compressed.extend_from_slice(&[0, 0, 0, 0]);
        let expected = vec![byte; 1 + MATCH_LENGTH * match_count];
        (compressed, expected)
    }

    #[test]
    fn parses_only_exact_wof_file_provider_reparse_metadata() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&IO_REPARSE_TAG_WOF.to_le_bytes());
        buffer.extend_from_slice(&(FILE_PROVIDER_PAYLOAD_BYTES as u16).to_le_bytes());
        buffer.extend_from_slice(&0_u16.to_le_bytes());
        buffer.extend_from_slice(&WOF_CURRENT_VERSION.to_le_bytes());
        buffer.extend_from_slice(&WOF_PROVIDER_FILE.to_le_bytes());
        buffer.extend_from_slice(&FILE_PROVIDER_CURRENT_VERSION.to_le_bytes());
        buffer.extend_from_slice(&2_u32.to_le_bytes());
        let parsed = parse_reparse_buffer(&buffer).expect("valid WOF metadata");
        assert_eq!(parsed.algorithm, WofAlgorithm::Xpress8k);

        let mut wrong_tag = buffer.clone();
        wrong_tag[0..4].copy_from_slice(&0xA000_0003_u32.to_le_bytes());
        assert!(matches!(
            parse_reparse_buffer(&wrong_tag),
            Err(WofError::UnexpectedReparseTag(0xA000_0003))
        ));
        let mut unknown = buffer;
        unknown[20..24].copy_from_slice(&99_u32.to_le_bytes());
        assert!(matches!(
            parse_reparse_buffer(&unknown),
            Err(WofError::UnknownAlgorithm(99))
        ));

        let mut wrong_wof_version = unknown.clone();
        wrong_wof_version[8..12].copy_from_slice(&2_u32.to_le_bytes());
        wrong_wof_version[20..24].copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            parse_reparse_buffer(&wrong_wof_version),
            Err(WofError::UnsupportedWofVersion(2))
        ));
        let mut wrong_provider = wrong_wof_version.clone();
        wrong_provider[8..12].copy_from_slice(&WOF_CURRENT_VERSION.to_le_bytes());
        wrong_provider[12..16].copy_from_slice(&99_u32.to_le_bytes());
        assert!(matches!(
            parse_reparse_buffer(&wrong_provider),
            Err(WofError::UnsupportedProvider(99))
        ));
        let mut wrong_provider_version = wrong_provider;
        wrong_provider_version[12..16].copy_from_slice(&WOF_PROVIDER_FILE.to_le_bytes());
        wrong_provider_version[16..20].copy_from_slice(&2_u32.to_le_bytes());
        assert!(matches!(
            parse_reparse_buffer(&wrong_provider_version),
            Err(WofError::UnsupportedFileProviderVersion(2))
        ));
        let mut trailing = wrong_provider_version;
        trailing[16..20].copy_from_slice(&FILE_PROVIDER_CURRENT_VERSION.to_le_bytes());
        trailing.push(0);
        assert!(matches!(
            parse_reparse_buffer(&trailing),
            Err(WofError::InvalidReparseBuffer(_))
        ));
    }

    #[test]
    fn decodes_synthetic_xpress8k_known_answer() {
        let (backing, expected) = repeated_byte_xpress_stream(b'K', 400);
        assert!(backing.len() < expected.len());
        let decoded = decode_range(
            &mut Cursor::new(&backing),
            backing.len() as u64,
            expected.len() as u64,
            info(WofAlgorithm::Xpress8k),
            0,
            expected.len(),
            WofDecodeLimits::for_output(expected.len()),
        )
        .expect("synthetic XPRESS8K fixture must decode");
        assert_eq!(decoded.bytes, expected);
        assert_eq!(decoded.provenance.chunks.len(), 1);
        assert_eq!(
            decoded.provenance.chunks[0].encoding,
            WofChunkEncoding::XpressHuffman
        );
    }

    #[test]
    fn range_read_decodes_only_intersecting_raw_chunks() {
        let first = vec![b'A'; 4096];
        let second = vec![b'B'; 4096];
        let third = vec![b'C'; 808];
        let mut backing = Vec::new();
        backing.extend_from_slice(&4096_u32.to_le_bytes());
        backing.extend_from_slice(&8192_u32.to_le_bytes());
        backing.extend_from_slice(&first);
        backing.extend_from_slice(&second);
        backing.extend_from_slice(&third);
        let decoded = decode_range(
            &mut Cursor::new(&backing),
            backing.len() as u64,
            9000,
            info(WofAlgorithm::Xpress4k),
            4090,
            20,
            WofDecodeLimits::for_output(20),
        )
        .expect("cross-chunk raw range");
        assert_eq!(&decoded.bytes[..6], &[b'A'; 6]);
        assert_eq!(&decoded.bytes[6..], &[b'B'; 14]);
        assert_eq!(decoded.provenance.chunks.len(), 2);
        assert!(decoded
            .provenance
            .chunks
            .iter()
            .all(|chunk| chunk.encoding == WofChunkEncoding::Raw));
        assert_eq!(decoded.provenance.chunks[0].backing_start, 8);
        assert_eq!(decoded.provenance.chunks[1].backing_start, 4104);
    }

    #[test]
    fn random_read_never_reads_unrelated_payload_chunks() {
        let first = vec![b'A'; 4096];
        let second = vec![b'B'; 4096];
        let third = vec![b'C'; 4096];
        let mut backing = Vec::new();
        backing.extend_from_slice(&4096_u32.to_le_bytes());
        backing.extend_from_slice(&8192_u32.to_le_bytes());
        backing.extend_from_slice(&first);
        backing.extend_from_slice(&second);
        backing.extend_from_slice(&third);
        let backing_length = backing.len() as u64;
        let mut tracked = TrackingReader::new(backing);
        let decoded = decode_range(
            &mut tracked,
            backing_length,
            12_288,
            info(WofAlgorithm::Xpress4k),
            4096,
            16,
            WofDecodeLimits::for_output(16),
        )
        .expect("bounded second-chunk read");
        assert_eq!(decoded.bytes, vec![b'B'; 16]);
        assert_eq!(decoded.provenance.chunks.len(), 1);
        assert_eq!(decoded.provenance.chunks[0].chunk_index, 1);
        assert_eq!(tracked.reads, vec![(0, 8), (4104, 4096)]);
    }

    #[test]
    fn rejects_non_monotonic_and_out_of_bounds_chunk_tables() {
        let mut non_monotonic = Vec::new();
        non_monotonic.extend_from_slice(&100_u32.to_le_bytes());
        non_monotonic.extend_from_slice(&99_u32.to_le_bytes());
        non_monotonic.resize(200, 0);
        assert!(matches!(
            decode_range(
                &mut Cursor::new(&non_monotonic),
                non_monotonic.len() as u64,
                9000,
                info(WofAlgorithm::Xpress4k),
                0,
                1,
                WofDecodeLimits::for_output(1),
            ),
            Err(WofError::InvalidChunkTable { entry_index: 1, .. })
        ));

        let mut outside = Vec::new();
        outside.extend_from_slice(&999_u32.to_le_bytes());
        outside.resize(100, 0);
        assert!(matches!(
            decode_range(
                &mut Cursor::new(&outside),
                outside.len() as u64,
                5000,
                info(WofAlgorithm::Xpress4k),
                0,
                1,
                WofDecodeLimits::for_output(1),
            ),
            Err(WofError::InvalidChunkTable { entry_index: 0, .. })
        ));

        let mut empty_last_chunk = Vec::new();
        empty_last_chunk.extend_from_slice(&4_u32.to_le_bytes());
        empty_last_chunk.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            decode_range(
                &mut Cursor::new(&empty_last_chunk),
                empty_last_chunk.len() as u64,
                8192,
                info(WofAlgorithm::Xpress4k),
                0,
                1,
                WofDecodeLimits::for_output(1),
            ),
            Err(WofError::InvalidChunkLength {
                chunk_index: 1,
                stored_length: 0,
                ..
            })
        ));
    }

    #[test]
    fn enforces_table_chunk_and_output_bomb_limits() {
        let mut tiny = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            decode_range(
                &mut tiny,
                0,
                8192,
                info(WofAlgorithm::Xpress4k),
                0,
                1,
                WofDecodeLimits::for_output(1),
            ),
            Err(WofError::TruncatedChunkTable { .. })
        ));

        let mut limits = WofDecodeLimits::for_output(10);
        limits.max_chunks = 1;
        assert!(matches!(
            decode_range(
                &mut Cursor::new(Vec::<u8>::new()),
                0,
                8192,
                info(WofAlgorithm::Xpress4k),
                0,
                1,
                limits,
            ),
            Err(WofError::ChunkCountLimitExceeded { .. })
        ));
        assert!(matches!(
            decode_range(
                &mut Cursor::new(Vec::<u8>::new()),
                0,
                0,
                info(WofAlgorithm::Xpress4k),
                0,
                11,
                WofDecodeLimits::for_output(10),
            ),
            Err(WofError::OutputLimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_short_xpress_output_and_never_falls_back_to_raw() {
        let backing = vec![0_u8; 256];
        let error = decode_range(
            &mut Cursor::new(&backing),
            backing.len() as u64,
            4096,
            info(WofAlgorithm::Xpress4k),
            0,
            1,
            WofDecodeLimits::for_output(1),
        )
        .expect_err("short compressed output must be rejected");
        assert!(matches!(
            error,
            WofError::DecompressionFailed { .. } | WofError::OutputLengthMismatch { .. }
        ));
    }

    #[test]
    fn lzx_is_recognized_but_explicitly_unsupported() {
        let error = decode_range(
            &mut Cursor::new(Vec::<u8>::new()),
            0,
            0,
            info(WofAlgorithm::Lzx),
            0,
            0,
            WofDecodeLimits::for_output(0),
        )
        .expect_err("LZX must not be guessed or silently skipped");
        assert!(matches!(
            error,
            WofError::UnsupportedAlgorithm(WofAlgorithm::Lzx)
        ));
    }
}
