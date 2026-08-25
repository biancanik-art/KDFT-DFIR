//! Bounded streaming support for Windows Automatic and Custom Destinations Jump Lists.
//!
//! Automatic Destinations use checked random access over CFB FAT/DIFAT/miniFAT chains. Embedded
//! LNK payloads are streamed to a sink and are never collected by the production parser. Custom
//! Destinations are scanned incrementally; because this module does not interpret the complete LNK
//! grammar, signature-to-signature boundaries are explicitly reported as heuristic/partial.

#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

pub const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
pub const LNK_SIGNATURE: [u8; 20] = [
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];
const CUSTOM_DESTINATIONS_EMPTY_FOOTER: [u8; 4] = [0xAB, 0xFB, 0xBF, 0xBA];

const FREE_SECTOR: u32 = 0xFFFF_FFFF;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const FAT_SECTOR: u32 = 0xFFFF_FFFD;
const DIFAT_SECTOR: u32 = 0xFFFF_FFFC;
const NO_STREAM: u32 = 0xFFFF_FFFF;
const CFB_HEADER_BYTES: usize = 512;
const CFB_DIRECTORY_ENTRY_BYTES: usize = 128;
const CFB_MINI_SECTOR_BYTES: usize = 64;
const DEFAULT_IO_BUFFER_BYTES: usize = 64 * 1024;
const MIN_IO_BUFFER_BYTES: usize = 512;
const HARD_MAX_IO_BUFFER_BYTES: usize = 1024 * 1024;
const DEFAULT_DIAGNOSTIC_SAMPLES: usize = 32;
const HARD_MAX_DIAGNOSTIC_SAMPLES: usize = 256;
const HARD_MAX_CUSTOM_CATEGORIES: u32 = 4_096;
const HARD_MAX_CUSTOM_CATEGORY_NAME_BYTES: usize = 128 * 1024;
const DIAGNOSTIC_MESSAGE_BYTES: usize = 512;
const FILETIME_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;

pub const AUTOMATIC_DESTINATIONS_LIMITATIONS: &[&str] = &[
    "AppID is external filename context and is not derived from CFB content",
    "DestList per-entry access counts and timestamps are not decoded by this module",
    "embedded LNK fields require the downstream LNK parser; this module streams exact payload bytes",
    "CFB directory tree reachability is not reconstructed; allocated stream entries in directory sectors are examined",
    "non-DestList streams whose names are not hexadecimal Jump List entry identifiers are retained as auxiliary container streams and are not inferred to be LNK records",
];

pub const CUSTOM_DESTINATIONS_LIMITATIONS: &[&str] = &[
    "record boundaries are inferred from LNK signatures and therefore remain heuristic",
    "AppID is external filename context and is not derived from the payload",
    "embedded LNK fields require the downstream LNK parser; this module streams payload bytes",
    "structurally valid zero-entry categories are retained as container metadata even when no embedded LNK exists",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpListTerminalStatus {
    Recognized,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpListContainerKind {
    AutomaticDestinations,
    CustomDestinations,
}

#[derive(Debug, Clone)]
pub struct JumpListParseOptions {
    /// Bounded scan/copy buffer. This is not a payload coverage limit.
    pub io_buffer_bytes: usize,
    pub diagnostic_sample_limit: usize,
}

impl Default for JumpListParseOptions {
    fn default() -> Self {
        Self {
            io_buffer_bytes: DEFAULT_IO_BUFFER_BYTES,
            diagnostic_sample_limit: DEFAULT_DIAGNOSTIC_SAMPLES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpListLnkMetadata {
    pub container: JumpListContainerKind,
    pub label: String,
    pub declared_size: u64,
    pub source_offset: u64,
    pub stored_in_mini_stream: bool,
    pub created_filetime: Option<u64>,
    pub created_utc: Option<String>,
    pub modified_filetime: Option<u64>,
    pub modified_utc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestListMetadata {
    pub declared_size: u64,
    pub header_bytes_read: usize,
    pub version: Option<u32>,
    pub entry_count: Option<u32>,
    pub pinned_entry_count: Option<u32>,
    /// The fourth DWORD is retained without assigning undocumented semantics.
    pub unknown_header_dword: Option<u32>,
    pub last_entry_id: Option<u64>,
    pub action_count: Option<u64>,
    pub created_filetime: Option<u64>,
    pub created_utc: Option<String>,
    pub modified_filetime: Option<u64>,
    pub modified_utc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpListDiagnostic {
    pub label: Option<String>,
    pub offset: Option<u64>,
    pub kind: JumpListErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JumpListStats {
    pub file_size: u64,
    pub bytes_read: u64,
    pub sector_size: Option<u32>,
    pub sector_count: Option<u32>,
    pub directory_streams: u64,
    pub lnk_candidates: u64,
    pub lnk_streams_emitted: u64,
    pub lnk_bytes_emitted: u64,
    pub dest_list_streams: u64,
    pub auxiliary_streams: u64,
    /// CFB v3 stores a 32-bit stream size. Older writers can leave the unused upper DWORD dirty;
    /// this records every non-zero upper DWORD ignored under the MS-CFB v3 compatibility rule.
    pub v3_stream_size_high_dwords_ignored: u64,
    pub custom_container_envelope_validated: bool,
    pub custom_categories_declared: Option<u32>,
    pub custom_categories_validated: u64,
    pub custom_zero_entry_categories: u64,
    pub custom_entries_without_complete_lnk_headers_declared: u64,
    pub corrupt_streams: u64,
    pub incomplete_streams: u64,
    pub omitted_lnk_streams: u64,
    pub omitted_lnk_bytes: u64,
    pub missing_dest_list: u64,
    pub heuristic_custom_boundaries: bool,
    pub diagnostic_count: u64,
    pub diagnostics: Vec<JumpListDiagnostic>,
    pub diagnostics_omitted: u64,
}

impl JumpListStats {
    fn diagnostic(
        &mut self,
        options: &JumpListParseOptions,
        label: Option<&str>,
        offset: Option<u64>,
        kind: JumpListErrorKind,
        message: impl AsRef<str>,
    ) {
        self.diagnostic_count = self.diagnostic_count.saturating_add(1);
        if self.diagnostics.len() < options.diagnostic_sample_limit {
            self.diagnostics.push(JumpListDiagnostic {
                label: label.map(bounded_label),
                offset,
                kind,
                message: bounded_text(message.as_ref(), DIAGNOSTIC_MESSAGE_BYTES),
            });
        } else {
            self.diagnostics_omitted = self.diagnostics_omitted.saturating_add(1);
        }
    }

    fn status(&self) -> JumpListTerminalStatus {
        if self.corrupt_streams > 0
            || self.incomplete_streams > 0
            || self.omitted_lnk_streams > 0
            || self.omitted_lnk_bytes > 0
            || self.missing_dest_list > 0
            || self.heuristic_custom_boundaries
            || self.diagnostic_count > 0
        {
            JumpListTerminalStatus::Partial
        } else {
            JumpListTerminalStatus::Recognized
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpListStreamResult {
    pub status: JumpListTerminalStatus,
    pub stats: JumpListStats,
    pub dest_list: Option<DestListMetadata>,
    pub limitations: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpListErrorKind {
    InvalidOptions,
    Io,
    NotJumpList,
    InvalidCfbHeader,
    InvalidDifat,
    InvalidFat,
    InvalidMiniFat,
    InvalidDirectory,
    InvalidStream,
    ChainCycle,
    TruncatedData,
    CheckedArithmeticOverflow,
    Allocation,
    Sink,
}

#[derive(Debug, Clone)]
pub struct JumpListError {
    pub status: JumpListTerminalStatus,
    pub kind: JumpListErrorKind,
    pub offset: Option<u64>,
    pub message: String,
    pub stats: Box<JumpListStats>,
}

impl fmt::Display for JumpListError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(offset) => write!(
                formatter,
                "Jump List {:?} error at byte {}: {}",
                self.kind, offset, self.message
            ),
            None => write!(
                formatter,
                "Jump List {:?} error: {}",
                self.kind, self.message
            ),
        }
    }
}

impl std::error::Error for JumpListError {}

/// Streaming destination for embedded LNK payloads.
///
/// After a successful `begin_lnk`, the parser calls `end_lnk(..., false)` when a read or chunk
/// callback fails, where possible. A failure from `begin_lnk` or from `end_lnk` itself is terminal
/// and cannot be followed by another reliable callback; sinks should also discard any open record
/// whenever the top-level parser returns `Err`.
pub trait JumpListSink {
    type Error: fmt::Display;

    fn begin_lnk(&mut self, metadata: &JumpListLnkMetadata) -> Result<(), Self::Error>;

    fn lnk_chunk(
        &mut self,
        metadata: &JumpListLnkMetadata,
        logical_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;

    fn end_lnk(
        &mut self,
        metadata: &JumpListLnkMetadata,
        complete: bool,
    ) -> Result<(), Self::Error>;

    fn dest_list(&mut self, _metadata: &DestListMetadata) -> Result<(), Self::Error> {
        Ok(())
    }

    fn corrupt_stream(&mut self, _diagnostic: &JumpListDiagnostic) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
struct CoreError {
    kind: JumpListErrorKind,
    offset: Option<u64>,
    message: String,
}

impl CoreError {
    fn new(kind: JumpListErrorKind, offset: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset,
            message: message.into(),
        }
    }

    fn io(offset: Option<u64>, operation: &str, error: io::Error) -> Self {
        Self::new(
            JumpListErrorKind::Io,
            offset,
            format!("{operation}: {error}"),
        )
    }
}

type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Clone)]
struct CfbHeader {
    major_version: u16,
    sector_size: usize,
    mini_sector_size: usize,
    sector_count: u32,
    number_of_fat_sectors: u32,
    first_directory_sector: u32,
    mini_stream_cutoff: u32,
    first_mini_fat_sector: u32,
    number_of_mini_fat_sectors: u32,
    first_difat_sector: u32,
    number_of_difat_sectors: u32,
    inline_difat: Vec<u32>,
}

#[derive(Debug, Clone)]
struct DirectoryEntry {
    label: String,
    object_type: u8,
    start_sector: u32,
    stream_size: u64,
    stream_size_high_dword_ignored: bool,
    created_filetime: Option<u64>,
    modified_filetime: Option<u64>,
}

#[derive(Debug, Clone)]
struct RootEntry {
    start_sector: u32,
    stream_size: u64,
}

struct CfbContext<'a, R: Read + Seek> {
    reader: &'a mut R,
    file_size: u64,
    header: CfbHeader,
    fat_sectors: Vec<u32>,
    fat_cache_sector: Option<u32>,
    fat_cache: Vec<u8>,
}

#[derive(Debug, Clone)]
struct MiniContext {
    mini_fat_sectors: Vec<u32>,
    root_stream_sectors: Vec<u32>,
    root_stream_size: u64,
}

#[derive(Debug, Clone, Copy)]
enum StreamPlan {
    Regular { start_sector: u32, size: u64 },
    Mini { start_sector: u32, size: u64 },
}

/// Probe CFB magic without consuming the caller's current position.
pub fn is_automatic_destinations<R: Read + Seek>(reader: &mut R) -> io::Result<bool> {
    let original = reader.stream_position()?;
    let mut magic = [0_u8; 8];
    let read_result = read_up_to(reader, &mut magic);
    let restore_result = reader.seek(SeekFrom::Start(original));
    match (read_result, restore_result) {
        (Ok(count), Ok(_)) => Ok(count == magic.len() && magic == CFB_MAGIC),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

/// Probe for an LNK signature incrementally without collecting the file.
pub fn is_custom_destinations<R: Read + Seek>(
    reader: &mut R,
    options: &JumpListParseOptions,
) -> Result<bool, JumpListError> {
    validate_options(options).map_err(public_invalid_options)?;
    let original = reader.stream_position().map_err(|error| JumpListError {
        status: JumpListTerminalStatus::Failed,
        kind: JumpListErrorKind::Io,
        offset: None,
        message: format!("reading original stream position: {error}"),
        stats: Box::default(),
    })?;
    let file_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| JumpListError {
            status: JumpListTerminalStatus::Failed,
            kind: JumpListErrorKind::Io,
            offset: None,
            message: format!("measuring custom destinations stream: {error}"),
            stats: Box::default(),
        })?;
    let mut stats = JumpListStats {
        file_size,
        ..JumpListStats::default()
    };
    let found = match find_next_signature(reader, 0, file_size, options, &mut stats)
        .map_err(|error| public_error(error, stats.clone()))?
    {
        Some(_) => true,
        None => inspect_custom_container_without_lnk(reader, file_size, &mut stats)
            .map_err(|error| public_error(error, stats.clone()))?
            .is_some(),
    };
    reader
        .seek(SeekFrom::Start(original))
        .map_err(|error| JumpListError {
            status: JumpListTerminalStatus::Failed,
            kind: JumpListErrorKind::Io,
            offset: Some(original),
            message: format!("restoring stream position: {error}"),
            stats: Box::new(stats),
        })?;
    Ok(found)
}

pub fn parse_automatic_destinations<R: Read + Seek, S: JumpListSink>(
    reader: &mut R,
    sink: &mut S,
    options: &JumpListParseOptions,
) -> Result<JumpListStreamResult, JumpListError> {
    if let Err(message) = validate_options(options) {
        return Err(public_invalid_options(message));
    }
    let mut stats = JumpListStats::default();
    match parse_automatic_inner(reader, sink, options, &mut stats) {
        Ok(dest_list) => Ok(JumpListStreamResult {
            status: stats.status(),
            stats,
            dest_list,
            limitations: AUTOMATIC_DESTINATIONS_LIMITATIONS,
        }),
        Err(error) => Err(public_error(error, stats)),
    }
}

pub fn parse_custom_destinations<R: Read + Seek, S: JumpListSink>(
    reader: &mut R,
    sink: &mut S,
    options: &JumpListParseOptions,
) -> Result<JumpListStreamResult, JumpListError> {
    if let Err(message) = validate_options(options) {
        return Err(public_invalid_options(message));
    }
    let mut stats = JumpListStats::default();
    match parse_custom_inner(reader, sink, options, &mut stats) {
        Ok(()) => Ok(JumpListStreamResult {
            status: stats.status(),
            stats,
            dest_list: None,
            limitations: CUSTOM_DESTINATIONS_LIMITATIONS,
        }),
        Err(error) => Err(public_error(error, stats)),
    }
}

fn parse_automatic_inner<R: Read + Seek, S: JumpListSink>(
    reader: &mut R,
    sink: &mut S,
    options: &JumpListParseOptions,
    stats: &mut JumpListStats,
) -> CoreResult<Option<DestListMetadata>> {
    let file_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| CoreError::io(None, "measuring CFB file", error))?;
    stats.file_size = file_size;
    if file_size < CFB_HEADER_BYTES as u64 {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            Some(0),
            format!("file is {file_size} bytes; CFB header requires 512"),
        ));
    }

    let mut raw_header = [0_u8; CFB_HEADER_BYTES];
    read_exact_at(reader, 0, &mut raw_header, stats)?;
    let header = parse_cfb_header(&raw_header, file_size, options, stats)?;
    stats.sector_size = Some(u32::try_from(header.sector_size).map_err(|_| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            Some(30),
            "sector size does not fit u32",
        )
    })?);
    stats.sector_count = Some(header.sector_count);

    let (fat_sectors, difat_sectors) = load_difat(reader, file_size, &header, stats)?;
    let mut context = CfbContext {
        reader,
        file_size,
        fat_cache: vec![0_u8; header.sector_size],
        fat_cache_sector: None,
        header,
        fat_sectors,
    };
    verify_allocation_table_markers(&mut context, &difat_sectors, stats)?;

    let first_directory_sector = context.header.first_directory_sector;
    let directory_length = fat_chain_length(
        &mut context,
        first_directory_sector,
        None,
        "directory",
        stats,
    )?;
    if directory_length == 0 {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidDirectory,
            None,
            "CFB directory chain is empty",
        ));
    }
    let root = find_root_entry(&mut context, directory_length, stats)?;
    let mut mini_context = match build_mini_context(&mut context, &root, stats) {
        Ok(context) => context,
        Err(error) if error.kind != JumpListErrorKind::Io => {
            stats.diagnostic(
                options,
                Some("Root Entry"),
                error.offset,
                error.kind,
                &error.message,
            );
            None
        }
        Err(error) => return Err(error),
    };

    let mut dest_list = None;
    walk_directory_entries(
        &mut context,
        directory_length,
        true,
        |context, entry, stats| {
            if entry.object_type != 2 {
                return Ok(());
            }
            stats.directory_streams = stats.directory_streams.saturating_add(1);
            if entry.label.eq_ignore_ascii_case("DestList") {
                stats.dest_list_streams = stats.dest_list_streams.saturating_add(1);
                match parse_dest_list_stream(context, mini_context.as_mut(), &entry, stats) {
                    Ok(metadata) => {
                        sink.dest_list(&metadata).map_err(|error| {
                            CoreError::new(
                                JumpListErrorKind::Sink,
                                None,
                                format!("DestList sink rejected metadata: {error}"),
                            )
                        })?;
                        if dest_list.is_some() {
                            record_recoverable_stream_error(
                                stats,
                                options,
                                sink,
                                &entry.label,
                                None,
                                CoreError::new(
                                    JumpListErrorKind::InvalidStream,
                                    None,
                                    "multiple DestList streams were found",
                                ),
                            )?;
                        } else {
                            dest_list = Some(metadata);
                        }
                    }
                    Err(error) if is_recoverable_stream_error(&error) => {
                        record_recoverable_stream_error(
                            stats,
                            options,
                            sink,
                            &entry.label,
                            error.offset,
                            error,
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            } else if is_automatic_lnk_stream_label(&entry.label) {
                stats.lnk_candidates = stats.lnk_candidates.saturating_add(1);
                match parse_lnk_stream(context, mini_context.as_mut(), &entry, sink, stats) {
                    Ok(()) => {}
                    Err(error) if is_recoverable_stream_error(&error) => {
                        stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
                        stats.omitted_lnk_bytes =
                            stats.omitted_lnk_bytes.saturating_add(entry.stream_size);
                        record_recoverable_stream_error(
                            stats,
                            options,
                            sink,
                            &entry.label,
                            error.offset,
                            error,
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            } else {
                // Automatic Destinations embedded LNK streams are hexadecimal entry identifiers.
                // Other named streams (including DestListPropertyStore and SummaryInformation)
                // are container metadata. Do not invent LNK ownership or downgrade the source just
                // because an auxiliary stream does not begin with a Shell Link header.
                stats.auxiliary_streams = stats.auxiliary_streams.saturating_add(1);
            }
            Ok(())
        },
        stats,
    )?;

    if dest_list.is_none() {
        stats.missing_dest_list = stats.missing_dest_list.saturating_add(1);
        stats.diagnostic(
            options,
            Some("DestList"),
            None,
            JumpListErrorKind::InvalidStream,
            "Automatic Destinations container has no readable DestList stream",
        );
    }
    Ok(dest_list)
}

#[derive(Debug, Clone)]
struct CustomContainerInspection {
    categories_declared: u32,
    categories_validated: u64,
    zero_entry_categories: u64,
    entries_without_complete_lnk_headers_declared: u64,
    envelope_validated: bool,
    partial_offset: Option<u64>,
    partial_reason: Option<String>,
}

fn is_automatic_lnk_stream_label(label: &str) -> bool {
    let mut bytes = label.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let valid_first = matches!(first, b'1'..=b'9' | b'a'..=b'f' | b'A'..=b'F');
    valid_first && bytes.all(|byte| byte.is_ascii_hexdigit())
}

fn parse_custom_inner<R: Read + Seek, S: JumpListSink>(
    reader: &mut R,
    sink: &mut S,
    options: &JumpListParseOptions,
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    let file_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| CoreError::io(None, "measuring Custom Destinations file", error))?;
    stats.file_size = file_size;
    let Some(mut current_start) = find_next_signature(reader, 0, file_size, options, stats)? else {
        if let Some(inspection) = inspect_custom_container_without_lnk(reader, file_size, stats)? {
            apply_custom_container_inspection(stats, &inspection);
            if let Some(reason) = inspection.partial_reason {
                stats.diagnostic(
                    options,
                    Some("Custom Destinations container"),
                    inspection.partial_offset,
                    JumpListErrorKind::InvalidStream,
                    reason,
                );
            }
            return Ok(());
        }
        return Err(CoreError::new(
            JumpListErrorKind::NotJumpList,
            None,
            "no Shell Link signature or structurally valid Custom Destinations envelope was found",
        ));
    };
    stats.heuristic_custom_boundaries = true;
    stats.diagnostic(
        options,
        None,
        Some(current_start),
        JumpListErrorKind::InvalidStream,
        "Custom Destinations LNK boundaries are signature-derived and not grammar-verified",
    );

    let mut index = 1_u64;
    loop {
        let search_start = current_start
            .checked_add(LNK_SIGNATURE.len() as u64)
            .ok_or_else(|| {
                CoreError::new(
                    JumpListErrorKind::CheckedArithmeticOverflow,
                    Some(current_start),
                    "advancing past LNK signature overflows u64",
                )
            })?;
        let next = find_next_signature(reader, search_start, file_size, options, stats)?;
        let end = next.unwrap_or(file_size);
        let size = end.checked_sub(current_start).ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                Some(current_start),
                "custom LNK end precedes start",
            )
        })?;
        let metadata = JumpListLnkMetadata {
            container: JumpListContainerKind::CustomDestinations,
            label: index.to_string(),
            declared_size: size,
            source_offset: current_start,
            stored_in_mini_stream: false,
            created_filetime: None,
            created_utc: None,
            modified_filetime: None,
            modified_utc: None,
        };
        stats.directory_streams = stats.directory_streams.saturating_add(1);
        stats.lnk_candidates = stats.lnk_candidates.saturating_add(1);
        stream_file_range(reader, &metadata, sink, options, stats)?;
        if let Some(next_start) = next {
            current_start = next_start;
            index = index.saturating_add(1);
        } else {
            break;
        }
    }
    Ok(())
}

fn apply_custom_container_inspection(
    stats: &mut JumpListStats,
    inspection: &CustomContainerInspection,
) {
    stats.custom_container_envelope_validated = inspection.envelope_validated;
    stats.custom_categories_declared = Some(inspection.categories_declared);
    stats.custom_categories_validated = inspection.categories_validated;
    stats.custom_zero_entry_categories = inspection.zero_entry_categories;
    stats.custom_entries_without_complete_lnk_headers_declared =
        inspection.entries_without_complete_lnk_headers_declared;
}

fn inspect_custom_container_without_lnk<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    stats: &mut JumpListStats,
) -> CoreResult<Option<CustomContainerInspection>> {
    // A Custom Destinations container begins with version, category count, and a reserved zero
    // DWORD. A file with no embedded LNK can still be valid: known categories and zero-entry custom
    // or task categories contain only their bounded descriptors and footer. Parse that grammar
    // instead of treating absence of a Shell Link as proof of corruption.
    if file_size < 12 {
        return Ok(None);
    }
    let mut header = [0_u8; 12];
    read_exact_at(reader, 0, &mut header, stats)?;
    if slice_u32(&header, 0)? != 2 || slice_u32(&header, 8)? != 0 {
        return Ok(None);
    }
    let categories_declared = slice_u32(&header, 4)?;
    if categories_declared > HARD_MAX_CUSTOM_CATEGORIES {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidStream,
            Some(4),
            format!(
                "Custom Destinations declares {categories_declared} categories, above the hard bound {HARD_MAX_CUSTOM_CATEGORIES}"
            ),
        ));
    }
    let file_derived_category_bound = file_size.saturating_sub(12) / 12;
    if u64::from(categories_declared) > file_derived_category_bound {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            Some(4),
            format!(
                "Custom Destinations declares {categories_declared} categories, but {file_size} bytes cannot contain their minimum descriptors"
            ),
        ));
    }
    if categories_declared == 0 {
        if file_size != 12 {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidStream,
                Some(12),
                format!(
                    "zero-category Custom Destinations header has {} unexplained trailing byte(s)",
                    file_size.saturating_sub(12)
                ),
            ));
        }
        return Ok(Some(CustomContainerInspection {
            categories_declared,
            categories_validated: 0,
            zero_entry_categories: 0,
            entries_without_complete_lnk_headers_declared: 0,
            envelope_validated: true,
            partial_offset: None,
            partial_reason: None,
        }));
    }

    let mut cursor = 12_u64;
    let mut categories_validated = 0_u64;
    let mut zero_entry_categories = 0_u64;
    for category_index in 0..categories_declared {
        let category_offset = cursor;
        let category_type = read_custom_u32(reader, cursor, file_size, stats, "category type")?;
        cursor = checked_custom_advance(cursor, 4, file_size, "category type")?;
        let entry_count = match category_type {
            0 => {
                let name_characters = read_custom_u16(
                    reader,
                    cursor,
                    file_size,
                    stats,
                    "custom category name length",
                )?;
                cursor =
                    checked_custom_advance(cursor, 2, file_size, "custom category name length")?;
                let name_bytes = usize::from(name_characters).checked_mul(2).ok_or_else(|| {
                    CoreError::new(
                        JumpListErrorKind::CheckedArithmeticOverflow,
                        Some(cursor),
                        "custom category name byte count overflow",
                    )
                })?;
                if name_bytes > HARD_MAX_CUSTOM_CATEGORY_NAME_BYTES {
                    return Err(CoreError::new(
                        JumpListErrorKind::InvalidStream,
                        Some(cursor),
                        format!(
                            "custom category name is {name_bytes} bytes, above the hard bound {HARD_MAX_CUSTOM_CATEGORY_NAME_BYTES}"
                        ),
                    ));
                }
                validate_custom_category_name(reader, cursor, name_bytes, file_size, stats)?;
                cursor = checked_custom_advance(
                    cursor,
                    name_bytes as u64,
                    file_size,
                    "custom category name",
                )?;
                let count = read_custom_u32(
                    reader,
                    cursor,
                    file_size,
                    stats,
                    "custom category entry count",
                )?;
                cursor =
                    checked_custom_advance(cursor, 4, file_size, "custom category entry count")?;
                count
            }
            1 => {
                let identifier = read_custom_u32(
                    reader,
                    cursor,
                    file_size,
                    stats,
                    "known category identifier",
                )?;
                cursor = checked_custom_advance(cursor, 4, file_size, "known category identifier")?;
                if !matches!(identifier, 1 | 2) {
                    return Err(CoreError::new(
                        JumpListErrorKind::InvalidStream,
                        Some(category_offset),
                        format!(
                            "Custom Destinations category {} has invalid known-category identifier {identifier}; expected 1 (recent) or 2 (frequent)",
                            category_index.saturating_add(1)
                        ),
                    ));
                }
                0
            }
            2 => {
                let count =
                    read_custom_u32(reader, cursor, file_size, stats, "user-tasks entry count")?;
                cursor = checked_custom_advance(cursor, 4, file_size, "user-tasks entry count")?;
                count
            }
            other => {
                return Err(CoreError::new(
                    JumpListErrorKind::InvalidStream,
                    Some(category_offset),
                    format!(
                        "Custom Destinations category {} has invalid category type {other}; expected 0, 1, or 2",
                        category_index.saturating_add(1)
                    ),
                ));
            }
        };

        categories_validated = categories_validated.saturating_add(1);
        if entry_count > 0 {
            validate_terminal_custom_footer(reader, file_size, stats)?;
            return Ok(Some(CustomContainerInspection {
                categories_declared,
                categories_validated,
                zero_entry_categories,
                entries_without_complete_lnk_headers_declared: u64::from(entry_count),
                envelope_validated: true,
                partial_offset: Some(cursor),
                partial_reason: Some(format!(
                    "Custom Destinations category {} declares {entry_count} shell object entr{} but none contains a complete Shell Link header; the original source is retained and no unsupported record ownership is inferred",
                    category_index.saturating_add(1),
                    if entry_count == 1 { "y" } else { "ies" }
                )),
            }));
        }

        let footer = read_custom_u32(reader, cursor, file_size, stats, "category footer")?;
        if footer != u32::from_le_bytes(CUSTOM_DESTINATIONS_EMPTY_FOOTER) {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidStream,
                Some(cursor),
                format!(
                    "Custom Destinations category {} footer is {footer:#010X}, expected 0xBABFFBAB",
                    category_index.saturating_add(1)
                ),
            ));
        }
        cursor = checked_custom_advance(cursor, 4, file_size, "category footer")?;
        zero_entry_categories = zero_entry_categories.saturating_add(1);
    }

    if cursor != file_size {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidStream,
            Some(cursor),
            format!(
                "validated Custom Destinations categories leave {} unexplained trailing byte(s)",
                file_size.saturating_sub(cursor)
            ),
        ));
    }
    Ok(Some(CustomContainerInspection {
        categories_declared,
        categories_validated,
        zero_entry_categories,
        entries_without_complete_lnk_headers_declared: 0,
        envelope_validated: true,
        partial_offset: None,
        partial_reason: None,
    }))
}

fn checked_custom_advance(
    offset: u64,
    length: u64,
    file_size: u64,
    label: &str,
) -> CoreResult<u64> {
    let end = offset.checked_add(length).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            Some(offset),
            format!("{label} end offset overflows u64"),
        )
    })?;
    if end > file_size {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            Some(offset),
            format!("{label} extends beyond the {file_size}-byte Custom Destinations source"),
        ));
    }
    Ok(end)
}

fn read_custom_u16<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    file_size: u64,
    stats: &mut JumpListStats,
    label: &str,
) -> CoreResult<u16> {
    checked_custom_advance(offset, 2, file_size, label)?;
    let mut bytes = [0_u8; 2];
    read_exact_at(reader, offset, &mut bytes, stats)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_custom_u32<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    file_size: u64,
    stats: &mut JumpListStats,
    label: &str,
) -> CoreResult<u32> {
    checked_custom_advance(offset, 4, file_size, label)?;
    let mut bytes = [0_u8; 4];
    read_exact_at(reader, offset, &mut bytes, stats)?;
    Ok(u32::from_le_bytes(bytes))
}

fn validate_custom_category_name<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    name_bytes: usize,
    file_size: u64,
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    checked_custom_advance(offset, name_bytes as u64, file_size, "custom category name")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(name_bytes).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::Allocation,
            Some(offset),
            format!("reserving bounded custom category name: {error}"),
        )
    })?;
    bytes.resize(name_bytes, 0);
    read_exact_at(reader, offset, &mut bytes, stats)?;
    let has_invalid_utf16 = char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    )
    .any(|character| character.is_err());
    if has_invalid_utf16 {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidStream,
            Some(offset),
            "custom category name contains invalid UTF-16LE",
        ));
    }
    Ok(())
}

fn validate_terminal_custom_footer<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    let footer_offset = file_size.checked_sub(4).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::TruncatedData,
            Some(file_size),
            "Custom Destinations source is too short for a footer",
        )
    })?;
    let footer = read_custom_u32(reader, footer_offset, file_size, stats, "terminal footer")?;
    if footer != u32::from_le_bytes(CUSTOM_DESTINATIONS_EMPTY_FOOTER) {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidStream,
            Some(footer_offset),
            format!("Custom Destinations terminal footer is {footer:#010X}, expected 0xBABFFBAB"),
        ));
    }
    Ok(())
}

fn validate_options(options: &JumpListParseOptions) -> Result<(), String> {
    if !(MIN_IO_BUFFER_BYTES..=HARD_MAX_IO_BUFFER_BYTES).contains(&options.io_buffer_bytes) {
        return Err(format!(
            "io_buffer_bytes must be in {MIN_IO_BUFFER_BYTES}..={HARD_MAX_IO_BUFFER_BYTES}"
        ));
    }
    if options.diagnostic_sample_limit > HARD_MAX_DIAGNOSTIC_SAMPLES {
        return Err(format!(
            "diagnostic_sample_limit exceeds hard bound {HARD_MAX_DIAGNOSTIC_SAMPLES}"
        ));
    }
    Ok(())
}

fn parse_cfb_header(
    bytes: &[u8; CFB_HEADER_BYTES],
    file_size: u64,
    options: &JumpListParseOptions,
    stats: &mut JumpListStats,
) -> CoreResult<CfbHeader> {
    if bytes[..8] != CFB_MAGIC {
        return Err(CoreError::new(
            JumpListErrorKind::NotJumpList,
            Some(0),
            "CFB signature does not match Automatic Destinations format",
        ));
    }
    let major_version = slice_u16(bytes, 26)?;
    if major_version != 3 && major_version != 4 {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            Some(26),
            format!("unsupported CFB major version {major_version}"),
        ));
    }
    if slice_u16(bytes, 28)? != 0xFFFE {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            Some(28),
            "CFB byte order is not little-endian 0xFFFE",
        ));
    }
    let sector_shift = slice_u16(bytes, 30)?;
    let expected_shift = if major_version == 3 { 9 } else { 12 };
    if sector_shift != expected_shift {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            Some(30),
            format!(
                "CFB v{major_version} requires sector shift {expected_shift}, got {sector_shift}"
            ),
        ));
    }
    let mini_sector_shift = slice_u16(bytes, 32)?;
    if mini_sector_shift != 6 {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            Some(32),
            format!("mini sector shift must be 6, got {mini_sector_shift}"),
        ));
    }
    let sector_size = 1_usize
        .checked_shl(u32::from(sector_shift))
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                Some(30),
                "sector size shift overflows usize",
            )
        })?;
    let mini_sector_size = 1_usize
        .checked_shl(u32::from(mini_sector_shift))
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                Some(32),
                "mini sector size shift overflows usize",
            )
        })?;
    if file_size < sector_size as u64 {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            Some(file_size),
            format!("file is smaller than its {sector_size}-byte CFB header sector"),
        ));
    }
    let data_bytes = file_size.saturating_sub(sector_size as u64);
    let sector_count_u64 = data_bytes / sector_size as u64;
    if !data_bytes.is_multiple_of(sector_size as u64) {
        stats.diagnostic(
            options,
            None,
            Some(file_size),
            JumpListErrorKind::TruncatedData,
            format!(
                "{} trailing byte(s) do not form a complete CFB sector",
                data_bytes % sector_size as u64
            ),
        );
    }
    let sector_count = u32::try_from(sector_count_u64).map_err(|_| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            None,
            format!("CFB has {sector_count_u64} sectors, above u32 sector ID space"),
        )
    })?;
    if sector_count == 0 {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            "CFB contains no data sectors",
        ));
    }
    let number_of_fat_sectors = slice_u32(bytes, 44)?;
    let entries_per_fat = sector_size / 4;
    let maximum_fat_sectors = div_ceil_u64(u64::from(sector_count), entries_per_fat as u64)?;
    if number_of_fat_sectors == 0 || u64::from(number_of_fat_sectors) > maximum_fat_sectors {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidFat,
            Some(44),
            format!(
                "declared FAT sector count {number_of_fat_sectors} is invalid for {sector_count} data sectors"
            ),
        ));
    }
    let mini_stream_cutoff = slice_u32(bytes, 56)?;
    if mini_stream_cutoff != 4096 {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            Some(56),
            format!("mini stream cutoff must be 4096, got {mini_stream_cutoff}"),
        ));
    }
    let mut inline_difat = Vec::with_capacity(109);
    for index in 0_usize..109 {
        let offset = 76_usize
            .checked_add(index.checked_mul(4).ok_or_else(|| {
                CoreError::new(
                    JumpListErrorKind::CheckedArithmeticOverflow,
                    Some(76),
                    "inline DIFAT index multiplication overflow",
                )
            })?)
            .ok_or_else(|| {
                CoreError::new(
                    JumpListErrorKind::CheckedArithmeticOverflow,
                    Some(76),
                    "inline DIFAT offset overflow",
                )
            })?;
        inline_difat.push(slice_u32(bytes, offset)?);
    }
    Ok(CfbHeader {
        major_version,
        sector_size,
        mini_sector_size,
        sector_count,
        number_of_fat_sectors,
        first_directory_sector: slice_u32(bytes, 48)?,
        mini_stream_cutoff,
        first_mini_fat_sector: slice_u32(bytes, 60)?,
        number_of_mini_fat_sectors: slice_u32(bytes, 64)?,
        first_difat_sector: slice_u32(bytes, 68)?,
        number_of_difat_sectors: slice_u32(bytes, 72)?,
        inline_difat,
    })
}

fn load_difat<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    header: &CfbHeader,
    stats: &mut JumpListStats,
) -> CoreResult<(Vec<u32>, Vec<u32>)> {
    let target = usize::try_from(header.number_of_fat_sectors).map_err(|_| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            Some(44),
            "FAT sector count does not fit usize",
        )
    })?;
    let mut fat_sectors = Vec::new();
    fat_sectors.try_reserve_exact(target).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::InvalidFat,
            Some(44),
            format!("reserving FAT sector IDs: {error}"),
        )
    })?;
    let mut unique_fat = HashSet::new();
    unique_fat.try_reserve(target).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::InvalidFat,
            Some(44),
            format!("reserving FAT duplicate detector: {error}"),
        )
    })?;
    for sector in &header.inline_difat {
        if fat_sectors.len() >= target {
            break;
        }
        add_fat_sector_id(*sector, header, &mut fat_sectors, &mut unique_fat)?;
    }

    let difat_count = usize::try_from(header.number_of_difat_sectors).map_err(|_| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            Some(72),
            "DIFAT sector count does not fit usize",
        )
    })?;
    if header.number_of_difat_sectors > header.sector_count {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidDifat,
            Some(72),
            "DIFAT sector count exceeds file-derived sector count",
        ));
    }
    let mut difat_sectors = Vec::new();
    difat_sectors
        .try_reserve_exact(difat_count)
        .map_err(|error| {
            CoreError::new(
                JumpListErrorKind::InvalidDifat,
                Some(72),
                format!("reserving DIFAT chain IDs: {error}"),
            )
        })?;
    let mut seen_difat = HashSet::new();
    seen_difat.try_reserve(difat_count).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::InvalidDifat,
            Some(72),
            format!("reserving DIFAT cycle detector: {error}"),
        )
    })?;
    let mut current = header.first_difat_sector;
    let entries_per_difat = header
        .sector_size
        .checked_div(4)
        .and_then(|entries| entries.checked_sub(1))
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::InvalidDifat,
                None,
                "sector is too small for DIFAT entries and next pointer",
            )
        })?;
    let mut sector_buffer = vec![0_u8; header.sector_size];
    for index in 0..difat_count {
        validate_regular_sector(current, header.sector_count, "DIFAT")?;
        if !seen_difat.insert(current) {
            let offset = sector_file_offset(header.sector_size, current)?;
            return Err(CoreError::new(
                JumpListErrorKind::ChainCycle,
                Some(offset),
                format!("DIFAT chain cycles at sector {current}"),
            ));
        }
        difat_sectors.push(current);
        read_sector_raw(
            reader,
            file_size,
            header.sector_size,
            header.sector_count,
            current,
            &mut sector_buffer,
            stats,
        )?;
        for entry_index in 0..entries_per_difat {
            if fat_sectors.len() >= target {
                break;
            }
            let offset = entry_index.checked_mul(4).ok_or_else(|| {
                CoreError::new(
                    JumpListErrorKind::CheckedArithmeticOverflow,
                    None,
                    "DIFAT entry offset overflow",
                )
            })?;
            let sector = slice_u32(&sector_buffer, offset)?;
            add_fat_sector_id(sector, header, &mut fat_sectors, &mut unique_fat)?;
        }
        let next_offset = entries_per_difat.checked_mul(4).ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "DIFAT next-pointer offset overflow",
            )
        })?;
        current = slice_u32(&sector_buffer, next_offset)?;
        if index + 1 < difat_count && current == END_OF_CHAIN {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidDifat,
                None,
                "DIFAT chain ended before its declared sector count",
            ));
        }
    }
    if difat_count == 0 {
        if header.first_difat_sector != END_OF_CHAIN && header.first_difat_sector != FREE_SECTOR {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidDifat,
                Some(68),
                "zero DIFAT sectors declared but first DIFAT sector is allocated",
            ));
        }
    } else if current != END_OF_CHAIN {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidDifat,
            None,
            format!("DIFAT chain has extra sector marker {current:#010X}"),
        ));
    }
    if fat_sectors.len() != target {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidDifat,
            None,
            format!(
                "DIFAT identified {} FAT sectors but header declares {target}",
                fat_sectors.len()
            ),
        ));
    }
    Ok((fat_sectors, difat_sectors))
}

fn add_fat_sector_id(
    sector: u32,
    header: &CfbHeader,
    output: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
) -> CoreResult<()> {
    if sector == FREE_SECTOR {
        return Ok(());
    }
    validate_regular_sector(sector, header.sector_count, "FAT")?;
    if !seen.insert(sector) {
        let offset = sector_file_offset(header.sector_size, sector)?;
        return Err(CoreError::new(
            JumpListErrorKind::InvalidDifat,
            Some(offset),
            format!("FAT sector {sector} is listed more than once"),
        ));
    }
    output.push(sector);
    Ok(())
}

fn verify_allocation_table_markers<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    difat_sectors: &[u32],
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    for index in 0..context.fat_sectors.len() {
        let sector = context.fat_sectors[index];
        let marker = context.fat_next(sector, stats)?;
        if marker != FAT_SECTOR {
            let offset = sector_file_offset(context.header.sector_size, sector)?;
            return Err(CoreError::new(
                JumpListErrorKind::InvalidFat,
                Some(offset),
                format!("FAT sector {sector} has allocation marker {marker:#010X}"),
            ));
        }
    }
    for sector in difat_sectors {
        let marker = context.fat_next(*sector, stats)?;
        if marker != DIFAT_SECTOR {
            let offset = sector_file_offset(context.header.sector_size, *sector)?;
            return Err(CoreError::new(
                JumpListErrorKind::InvalidDifat,
                Some(offset),
                format!("DIFAT sector {sector} has allocation marker {marker:#010X}"),
            ));
        }
    }
    Ok(())
}

impl<R: Read + Seek> CfbContext<'_, R> {
    fn read_sector(
        &mut self,
        sector: u32,
        output: &mut [u8],
        stats: &mut JumpListStats,
    ) -> CoreResult<()> {
        read_sector_raw(
            self.reader,
            self.file_size,
            self.header.sector_size,
            self.header.sector_count,
            sector,
            output,
            stats,
        )
    }

    fn fat_next(&mut self, sector: u32, stats: &mut JumpListStats) -> CoreResult<u32> {
        validate_regular_sector(sector, self.header.sector_count, "FAT lookup")?;
        let entries_per_sector = self.header.sector_size / 4;
        let sector_index = usize::try_from(sector).map_err(|_| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "sector ID does not fit usize",
            )
        })?;
        let fat_ordinal = sector_index / entries_per_sector;
        let entry_ordinal = sector_index % entries_per_sector;
        let fat_sector = *self.fat_sectors.get(fat_ordinal).ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::InvalidFat,
                None,
                format!("FAT has no entry for sector {sector}"),
            )
        })?;
        if self.fat_cache_sector != Some(fat_sector) {
            self.fat_cache_sector = None;
            let mut buffer = std::mem::take(&mut self.fat_cache);
            let read_result = self.read_sector(fat_sector, &mut buffer, stats);
            self.fat_cache = buffer;
            read_result?;
            self.fat_cache_sector = Some(fat_sector);
        }
        let offset = entry_ordinal.checked_mul(4).ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "FAT entry offset overflow",
            )
        })?;
        slice_u32(&self.fat_cache, offset)
    }
}

fn fat_chain_length<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    start_sector: u32,
    expected_length: Option<u64>,
    label: &str,
    stats: &mut JumpListStats,
) -> CoreResult<u64> {
    if start_sector == END_OF_CHAIN || start_sector == FREE_SECTOR {
        if expected_length.unwrap_or(0) == 0 {
            return Ok(0);
        }
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            format!(
                "{label} chain is empty but {} sector(s) are required",
                expected_length.unwrap_or(0)
            ),
        ));
    }
    validate_regular_sector(start_sector, context.header.sector_count, label)?;
    let mut tortoise = start_sector;
    let mut hare = start_sector;
    let mut power = 1_u64;
    let mut lambda = 0_u64;
    let mut length = 0_u64;
    loop {
        validate_regular_sector(hare, context.header.sector_count, label)?;
        let next = context.fat_next(hare, stats)?;
        length = length.saturating_add(1);
        if length > u64::from(context.header.sector_count) {
            return Err(CoreError::new(
                JumpListErrorKind::ChainCycle,
                None,
                format!("{label} chain exceeds file-derived sector bound"),
            ));
        }
        if next == END_OF_CHAIN {
            break;
        }
        if next == FREE_SECTOR || next == FAT_SECTOR || next == DIFAT_SECTOR {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidFat,
                None,
                format!("{label} chain reaches invalid marker {next:#010X}"),
            ));
        }
        validate_regular_sector(next, context.header.sector_count, label)?;
        lambda = lambda.saturating_add(1);
        if next == tortoise {
            let offset = sector_file_offset(context.header.sector_size, next)?;
            return Err(CoreError::new(
                JumpListErrorKind::ChainCycle,
                Some(offset),
                format!("{label} chain cycles at sector {next}"),
            ));
        }
        if lambda == power {
            tortoise = next;
            power = power.saturating_mul(2);
            lambda = 0;
        }
        hare = next;
    }
    if let Some(expected) = expected_length {
        if length != expected {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidStream,
                None,
                format!("{label} chain has {length} sectors; declared size requires {expected}"),
            ));
        }
    }
    Ok(length)
}

fn collect_fat_chain<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    start_sector: u32,
    expected_length: u64,
    label: &str,
    stats: &mut JumpListStats,
) -> CoreResult<Vec<u32>> {
    fat_chain_length(context, start_sector, Some(expected_length), label, stats)?;
    let capacity = usize::try_from(expected_length).map_err(|_| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            None,
            format!("{label} chain length does not fit usize"),
        )
    })?;
    let mut sectors = Vec::new();
    sectors.try_reserve_exact(capacity).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::InvalidStream,
            None,
            format!("reserving {label} chain: {error}"),
        )
    })?;
    let mut current = start_sector;
    for _ in 0..expected_length {
        sectors.push(current);
        current = context.fat_next(current, stats)?;
    }
    Ok(sectors)
}

fn find_root_entry<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    directory_length: u64,
    stats: &mut JumpListStats,
) -> CoreResult<RootEntry> {
    let mut root = None;
    walk_directory_entries(
        context,
        directory_length,
        false,
        |_context, entry, _stats| {
            if entry.object_type == 5 {
                if root.is_some() {
                    return Err(CoreError::new(
                        JumpListErrorKind::InvalidDirectory,
                        None,
                        "multiple CFB root directory entries",
                    ));
                }
                root = Some(RootEntry {
                    start_sector: entry.start_sector,
                    stream_size: entry.stream_size,
                });
            }
            Ok(())
        },
        stats,
    )?;
    root.ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::InvalidDirectory,
            None,
            "CFB root directory entry is missing",
        )
    })
}

fn walk_directory_entries<R: Read + Seek, F>(
    context: &mut CfbContext<'_, R>,
    directory_length: u64,
    count_stream_size_compatibility_repairs: bool,
    mut visitor: F,
    stats: &mut JumpListStats,
) -> CoreResult<()>
where
    F: FnMut(&mut CfbContext<'_, R>, DirectoryEntry, &mut JumpListStats) -> CoreResult<()>,
{
    let mut sector = context.header.first_directory_sector;
    let mut buffer = vec![0_u8; context.header.sector_size];
    for _ in 0..directory_length {
        context.read_sector(sector, &mut buffer, stats)?;
        for chunk in buffer.chunks_exact(CFB_DIRECTORY_ENTRY_BYTES) {
            let object_type = chunk[66];
            if object_type == 0 {
                continue;
            }
            let entry = parse_directory_entry(chunk, context.header.major_version)?;
            if count_stream_size_compatibility_repairs && entry.stream_size_high_dword_ignored {
                stats.v3_stream_size_high_dwords_ignored =
                    stats.v3_stream_size_high_dwords_ignored.saturating_add(1);
            }
            visitor(context, entry, stats)?;
        }
        sector = context.fat_next(sector, stats)?;
    }
    Ok(())
}

fn parse_directory_entry(bytes: &[u8], major_version: u16) -> CoreResult<DirectoryEntry> {
    if bytes.len() != CFB_DIRECTORY_ENTRY_BYTES {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidDirectory,
            None,
            "directory entry is not 128 bytes",
        ));
    }
    let object_type = bytes[66];
    let name_length = usize::from(slice_u16(bytes, 64)?);
    let label = if name_length == 0 && object_type == 0 {
        String::new()
    } else {
        if !(2..=64).contains(&name_length) || name_length % 2 != 0 {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidDirectory,
                None,
                format!("directory name length {name_length} is invalid"),
            ));
        }
        let content_length = name_length.saturating_sub(2);
        let mut code_units = Vec::with_capacity(content_length / 2);
        for pair in bytes[..content_length].chunks_exact(2) {
            code_units.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        String::from_utf16(&code_units).map_err(|_| {
            CoreError::new(
                JumpListErrorKind::InvalidDirectory,
                None,
                "directory name contains invalid UTF-16",
            )
        })?
    };
    let created_raw = slice_u64(bytes, 100)?;
    let modified_raw = slice_u64(bytes, 108)?;
    let raw_stream_size = slice_u64(bytes, 120)?;
    let stream_size_high_dword_ignored = major_version == 3 && raw_stream_size >> 32 != 0;
    let stream_size = if major_version == 3 {
        // MS-CFB v3 directory stream sizes are 32-bit. Some older writers left the unused upper
        // DWORD uninitialized, and the specification recommends that parsers ignore it. Applying
        // that rule prevents a dirty upper DWORD from fabricating a multi-exabyte root mini stream
        // while preserving the raw anomaly as an exact parser statistic.
        raw_stream_size & u64::from(u32::MAX)
    } else {
        raw_stream_size
    };
    Ok(DirectoryEntry {
        label,
        object_type,
        start_sector: slice_u32(bytes, 116)?,
        stream_size,
        stream_size_high_dword_ignored,
        created_filetime: (created_raw != 0).then_some(created_raw),
        modified_filetime: (modified_raw != 0).then_some(modified_raw),
    })
}

fn build_mini_context<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    root: &RootEntry,
    stats: &mut JumpListStats,
) -> CoreResult<Option<MiniContext>> {
    if context.header.number_of_mini_fat_sectors == 0 || root.stream_size == 0 {
        return Ok(None);
    }
    let mini_fat_count = u64::from(context.header.number_of_mini_fat_sectors);
    let mini_fat_sectors = collect_fat_chain(
        context,
        context.header.first_mini_fat_sector,
        mini_fat_count,
        "miniFAT",
        stats,
    )?;
    let root_sector_count = div_ceil_u64(root.stream_size, context.header.sector_size as u64)?;
    let root_stream_sectors = collect_fat_chain(
        context,
        root.start_sector,
        root_sector_count,
        "root mini stream",
        stats,
    )?;
    Ok(Some(MiniContext {
        mini_fat_sectors,
        root_stream_sectors,
        root_stream_size: root.stream_size,
    }))
}

fn stream_plan<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    mini: Option<&mut MiniContext>,
    entry: &DirectoryEntry,
    stats: &mut JumpListStats,
) -> CoreResult<StreamPlan> {
    if entry.stream_size < u64::from(context.header.mini_stream_cutoff) {
        let mini = mini.ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::InvalidMiniFat,
                None,
                format!(
                    "small stream {} has no usable root mini stream",
                    entry.label
                ),
            )
        })?;
        let expected = div_ceil_u64(entry.stream_size, context.header.mini_sector_size as u64)?;
        mini_chain_length(
            context,
            mini,
            entry.start_sector,
            Some(expected),
            &entry.label,
            stats,
        )?;
        Ok(StreamPlan::Mini {
            start_sector: entry.start_sector,
            size: entry.stream_size,
        })
    } else {
        let expected = div_ceil_u64(entry.stream_size, context.header.sector_size as u64)?;
        fat_chain_length(
            context,
            entry.start_sector,
            Some(expected),
            &entry.label,
            stats,
        )?;
        Ok(StreamPlan::Regular {
            start_sector: entry.start_sector,
            size: entry.stream_size,
        })
    }
}

fn mini_chain_length<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    mini: &mut MiniContext,
    start_sector: u32,
    expected_length: Option<u64>,
    label: &str,
    stats: &mut JumpListStats,
) -> CoreResult<u64> {
    if start_sector == END_OF_CHAIN || start_sector == FREE_SECTOR {
        if expected_length.unwrap_or(0) == 0 {
            return Ok(0);
        }
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            format!("mini stream {label} is empty but data is declared"),
        ));
    }
    let maximum_mini_sectors = div_ceil_u64(
        mini.root_stream_size,
        context.header.mini_sector_size as u64,
    )?;
    if u64::from(start_sector) >= maximum_mini_sectors {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidMiniFat,
            None,
            format!("mini stream {label} starts beyond root mini stream"),
        ));
    }
    let mut tortoise = start_sector;
    let mut hare = start_sector;
    let mut power = 1_u64;
    let mut lambda = 0_u64;
    let mut length = 0_u64;
    loop {
        if u64::from(hare) >= maximum_mini_sectors {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidMiniFat,
                None,
                format!("mini stream {label} references sector {hare} outside root stream"),
            ));
        }
        let next = mini_fat_next(context, mini, hare, stats)?;
        length = length.saturating_add(1);
        if length > maximum_mini_sectors {
            return Err(CoreError::new(
                JumpListErrorKind::ChainCycle,
                None,
                format!("mini stream {label} exceeds root-stream-derived sector bound"),
            ));
        }
        if next == END_OF_CHAIN {
            break;
        }
        if next == FREE_SECTOR || next >= 0xFFFF_FFFC {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidMiniFat,
                None,
                format!("mini stream {label} reaches invalid marker {next:#010X}"),
            ));
        }
        lambda = lambda.saturating_add(1);
        if next == tortoise {
            return Err(CoreError::new(
                JumpListErrorKind::ChainCycle,
                None,
                format!("mini stream {label} cycles at mini sector {next}"),
            ));
        }
        if lambda == power {
            tortoise = next;
            power = power.saturating_mul(2);
            lambda = 0;
        }
        hare = next;
    }
    if let Some(expected) = expected_length {
        if length != expected {
            return Err(CoreError::new(
                JumpListErrorKind::InvalidStream,
                None,
                format!("mini stream {label} has {length} sectors; size requires {expected}"),
            ));
        }
    }
    Ok(length)
}

fn mini_fat_next<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    mini: &MiniContext,
    mini_sector: u32,
    stats: &mut JumpListStats,
) -> CoreResult<u32> {
    let entries_per_sector = context.header.sector_size / 4;
    let mini_index = usize::try_from(mini_sector).map_err(|_| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            None,
            "mini sector ID does not fit usize",
        )
    })?;
    let fat_ordinal = mini_index / entries_per_sector;
    let entry_ordinal = mini_index % entries_per_sector;
    let fat_sector = *mini.mini_fat_sectors.get(fat_ordinal).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::InvalidMiniFat,
            None,
            format!("miniFAT has no entry for mini sector {mini_sector}"),
        )
    })?;
    let mut buffer = vec![0_u8; context.header.sector_size];
    context.read_sector(fat_sector, &mut buffer, stats)?;
    let offset = entry_ordinal.checked_mul(4).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            None,
            "miniFAT entry offset overflow",
        )
    })?;
    slice_u32(&buffer, offset)
}

fn parse_lnk_stream<R: Read + Seek, S: JumpListSink>(
    context: &mut CfbContext<'_, R>,
    mut mini: Option<&mut MiniContext>,
    entry: &DirectoryEntry,
    sink: &mut S,
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    let plan = stream_plan(context, mini.as_deref_mut(), entry, stats)?;
    let source_offset = stream_source_offset(context, mini.as_deref(), plan)?;
    let mut signature = Vec::with_capacity(LNK_SIGNATURE.len());
    visit_stream(context, mini.as_deref_mut(), plan, stats, |_, bytes| {
        let needed = LNK_SIGNATURE.len().saturating_sub(signature.len());
        signature.extend_from_slice(&bytes[..bytes.len().min(needed)]);
        Ok(signature.len() < LNK_SIGNATURE.len())
    })?;
    if signature.as_slice() != LNK_SIGNATURE {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidStream,
            Some(source_offset),
            format!(
                "stream {} does not begin with a Shell Link header",
                entry.label
            ),
        ));
    }
    let metadata = JumpListLnkMetadata {
        container: JumpListContainerKind::AutomaticDestinations,
        label: bounded_label(&entry.label),
        declared_size: entry.stream_size,
        source_offset,
        stored_in_mini_stream: matches!(plan, StreamPlan::Mini { .. }),
        created_filetime: entry.created_filetime,
        created_utc: entry.created_filetime.and_then(filetime_to_rfc3339),
        modified_filetime: entry.modified_filetime,
        modified_utc: entry.modified_filetime.and_then(filetime_to_rfc3339),
    };
    sink.begin_lnk(&metadata).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::Sink,
            Some(metadata.source_offset),
            format!("LNK sink rejected begin for {}: {error}", metadata.label),
        )
    })?;
    let mut emitted_bytes = 0_u64;
    let stream_result = visit_stream(context, mini, plan, stats, |logical_offset, bytes| {
        sink.lnk_chunk(&metadata, logical_offset, bytes)
            .map_err(|error| {
                CoreError::new(
                    JumpListErrorKind::Sink,
                    Some(metadata.source_offset),
                    format!("LNK sink rejected data for {}: {error}", metadata.label),
                )
            })?;
        emitted_bytes =
            emitted_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        Ok(true)
    });
    stats.lnk_bytes_emitted = stats.lnk_bytes_emitted.saturating_add(emitted_bytes);
    if let Err(error) = stream_result {
        stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
        stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
        stats.omitted_lnk_bytes = stats
            .omitted_lnk_bytes
            .saturating_add(metadata.declared_size.saturating_sub(emitted_bytes));
        return Err(abort_lnk_sink(sink, &metadata, error));
    }
    if let Err(error) = sink.end_lnk(&metadata, true) {
        stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
        stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
        return Err(CoreError::new(
            JumpListErrorKind::Sink,
            Some(metadata.source_offset),
            format!(
                "LNK sink rejected completion for {} after receiving all {} bytes: {error}",
                metadata.label, metadata.declared_size
            ),
        ));
    }
    stats.lnk_streams_emitted = stats.lnk_streams_emitted.saturating_add(1);
    Ok(())
}

fn parse_dest_list_stream<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    mut mini: Option<&mut MiniContext>,
    entry: &DirectoryEntry,
    stats: &mut JumpListStats,
) -> CoreResult<DestListMetadata> {
    if entry.stream_size == 0 {
        return Ok(DestListMetadata {
            declared_size: 0,
            header_bytes_read: 0,
            version: None,
            entry_count: Some(0),
            pinned_entry_count: Some(0),
            unknown_header_dword: None,
            last_entry_id: None,
            action_count: None,
            created_filetime: entry.created_filetime,
            created_utc: entry.created_filetime.and_then(filetime_to_rfc3339),
            modified_filetime: entry.modified_filetime,
            modified_utc: entry.modified_filetime.and_then(filetime_to_rfc3339),
        });
    }
    let plan = stream_plan(context, mini.as_deref_mut(), entry, stats)?;
    let mut header_bytes = Vec::with_capacity(32);
    visit_stream(context, mini, plan, stats, |_, bytes| {
        let needed = 32_usize.saturating_sub(header_bytes.len());
        header_bytes.extend_from_slice(&bytes[..bytes.len().min(needed)]);
        Ok(header_bytes.len() < 32)
    })?;
    if header_bytes.len() < 32 {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            format!("DestList header is only {} bytes", header_bytes.len()),
        ));
    }
    Ok(DestListMetadata {
        declared_size: entry.stream_size,
        header_bytes_read: header_bytes.len(),
        version: optional_u32(&header_bytes, 0),
        entry_count: optional_u32(&header_bytes, 4),
        pinned_entry_count: optional_u32(&header_bytes, 8),
        unknown_header_dword: optional_u32(&header_bytes, 12),
        last_entry_id: optional_u64(&header_bytes, 16),
        action_count: optional_u64(&header_bytes, 24),
        created_filetime: entry.created_filetime,
        created_utc: entry.created_filetime.and_then(filetime_to_rfc3339),
        modified_filetime: entry.modified_filetime,
        modified_utc: entry.modified_filetime.and_then(filetime_to_rfc3339),
    })
}

fn visit_stream<R: Read + Seek, F>(
    context: &mut CfbContext<'_, R>,
    mini: Option<&mut MiniContext>,
    plan: StreamPlan,
    stats: &mut JumpListStats,
    mut visitor: F,
) -> CoreResult<()>
where
    F: FnMut(u64, &[u8]) -> CoreResult<bool>,
{
    match plan {
        StreamPlan::Regular { start_sector, size } => {
            let mut remaining = size;
            let mut logical_offset = 0_u64;
            let mut sector = start_sector;
            let mut buffer = vec![0_u8; context.header.sector_size];
            while remaining > 0 {
                context.read_sector(sector, &mut buffer, stats)?;
                let take = usize::try_from(remaining.min(context.header.sector_size as u64))
                    .map_err(|_| {
                        CoreError::new(
                            JumpListErrorKind::CheckedArithmeticOverflow,
                            None,
                            "regular stream chunk length does not fit usize",
                        )
                    })?;
                if !visitor(logical_offset, &buffer[..take])? {
                    break;
                }
                remaining = remaining.saturating_sub(take as u64);
                logical_offset = logical_offset.saturating_add(take as u64);
                if remaining > 0 {
                    sector = context.fat_next(sector, stats)?;
                }
            }
        }
        StreamPlan::Mini { start_sector, size } => {
            let mini = mini.ok_or_else(|| {
                CoreError::new(
                    JumpListErrorKind::InvalidMiniFat,
                    None,
                    "mini stream plan has no mini context",
                )
            })?;
            let mut remaining = size;
            let mut logical_offset = 0_u64;
            let mut sector = start_sector;
            while remaining > 0 {
                let bytes = read_mini_sector(context, mini, sector, stats)?;
                let take = usize::try_from(remaining.min(bytes.len() as u64)).map_err(|_| {
                    CoreError::new(
                        JumpListErrorKind::CheckedArithmeticOverflow,
                        None,
                        "mini stream chunk length does not fit usize",
                    )
                })?;
                if !visitor(logical_offset, &bytes[..take])? {
                    break;
                }
                remaining = remaining.saturating_sub(take as u64);
                logical_offset = logical_offset.saturating_add(take as u64);
                if remaining > 0 {
                    sector = mini_fat_next(context, mini, sector, stats)?;
                }
            }
        }
    }
    Ok(())
}

fn read_mini_sector<R: Read + Seek>(
    context: &mut CfbContext<'_, R>,
    mini: &MiniContext,
    mini_sector: u32,
    stats: &mut JumpListStats,
) -> CoreResult<Vec<u8>> {
    let logical_offset = u64::from(mini_sector)
        .checked_mul(context.header.mini_sector_size as u64)
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "mini sector logical offset overflow",
            )
        })?;
    let end = logical_offset
        .checked_add(context.header.mini_sector_size as u64)
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "mini sector end overflow",
            )
        })?;
    if end > mini.root_stream_size {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            format!("mini sector {mini_sector} exceeds root mini stream size"),
        ));
    }
    let regular_ordinal = usize::try_from(logical_offset / context.header.sector_size as u64)
        .map_err(|_| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "root mini stream sector ordinal does not fit usize",
            )
        })?;
    let within =
        usize::try_from(logical_offset % context.header.sector_size as u64).map_err(|_| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "root mini stream offset does not fit usize",
            )
        })?;
    let physical_sector = *mini
        .root_stream_sectors
        .get(regular_ordinal)
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::TruncatedData,
                None,
                format!("root mini stream has no sector ordinal {regular_ordinal}"),
            )
        })?;
    let mut regular = vec![0_u8; context.header.sector_size];
    context.read_sector(physical_sector, &mut regular, stats)?;
    let mini_end = within
        .checked_add(context.header.mini_sector_size)
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "mini sector slice end overflow",
            )
        })?;
    let bytes = regular.get(within..mini_end).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            "mini sector crosses a root stream sector boundary",
        )
    })?;
    Ok(bytes.to_vec())
}

fn stream_source_offset<R: Read + Seek>(
    context: &CfbContext<'_, R>,
    mini: Option<&MiniContext>,
    plan: StreamPlan,
) -> CoreResult<u64> {
    match plan {
        StreamPlan::Regular { start_sector, .. } => {
            sector_file_offset(context.header.sector_size, start_sector)
        }
        StreamPlan::Mini { start_sector, .. } => {
            let mini = mini.ok_or_else(|| {
                CoreError::new(
                    JumpListErrorKind::InvalidMiniFat,
                    None,
                    "mini stream source offset requires mini context",
                )
            })?;
            let logical = u64::from(start_sector)
                .checked_mul(context.header.mini_sector_size as u64)
                .ok_or_else(|| {
                    CoreError::new(
                        JumpListErrorKind::CheckedArithmeticOverflow,
                        None,
                        "mini stream source offset overflow",
                    )
                })?;
            let regular_ordinal = usize::try_from(logical / context.header.sector_size as u64)
                .map_err(|_| {
                    CoreError::new(
                        JumpListErrorKind::CheckedArithmeticOverflow,
                        None,
                        "mini stream root ordinal does not fit usize",
                    )
                })?;
            let within = logical % context.header.sector_size as u64;
            let physical_sector =
                *mini
                    .root_stream_sectors
                    .get(regular_ordinal)
                    .ok_or_else(|| {
                        CoreError::new(
                            JumpListErrorKind::TruncatedData,
                            None,
                            "mini stream source root sector is missing",
                        )
                    })?;
            sector_file_offset(context.header.sector_size, physical_sector)?
                .checked_add(within)
                .ok_or_else(|| {
                    CoreError::new(
                        JumpListErrorKind::CheckedArithmeticOverflow,
                        None,
                        "mini stream physical offset overflow",
                    )
                })
        }
    }
}

fn abort_lnk_sink<S: JumpListSink>(
    sink: &mut S,
    metadata: &JumpListLnkMetadata,
    original: CoreError,
) -> CoreError {
    match sink.end_lnk(metadata, false) {
        Ok(()) => original,
        Err(abort_error) => CoreError::new(
            JumpListErrorKind::Sink,
            Some(metadata.source_offset),
            format!(
                "{}; additionally the sink rejected incomplete completion for {}: {abort_error}",
                original.message, metadata.label
            ),
        ),
    }
}

fn stream_file_range<R: Read + Seek, S: JumpListSink>(
    reader: &mut R,
    metadata: &JumpListLnkMetadata,
    sink: &mut S,
    options: &JumpListParseOptions,
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    reader
        .seek(SeekFrom::Start(metadata.source_offset))
        .map_err(|error| {
            CoreError::io(Some(metadata.source_offset), "seeking custom LNK", error)
        })?;
    let mut remaining = metadata.declared_size;
    let mut logical_offset = 0_u64;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(options.io_buffer_bytes)
        .map_err(|error| {
            CoreError::new(
                JumpListErrorKind::Allocation,
                Some(metadata.source_offset),
                format!("reserving custom LNK streaming buffer: {error}"),
            )
        })?;
    buffer.resize(options.io_buffer_bytes, 0);
    sink.begin_lnk(metadata).map_err(|error| {
        CoreError::new(
            JumpListErrorKind::Sink,
            Some(metadata.source_offset),
            format!("LNK sink rejected begin for {}: {error}", metadata.label),
        )
    })?;
    while remaining > 0 {
        let request = match usize::try_from(remaining.min(options.io_buffer_bytes as u64)) {
            Ok(request) => request,
            Err(_) => {
                let error = CoreError::new(
                    JumpListErrorKind::CheckedArithmeticOverflow,
                    Some(metadata.source_offset),
                    "custom LNK chunk size does not fit usize",
                );
                stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
                stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
                stats.omitted_lnk_bytes = stats.omitted_lnk_bytes.saturating_add(remaining);
                return Err(abort_lnk_sink(sink, metadata, error));
            }
        };
        let count = match read_up_to(reader, &mut buffer[..request]) {
            Ok(count) => count,
            Err(error) => {
                let error = CoreError::io(
                    Some(metadata.source_offset.saturating_add(logical_offset)),
                    "reading custom LNK",
                    error,
                );
                stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
                stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
                stats.omitted_lnk_bytes = stats.omitted_lnk_bytes.saturating_add(remaining);
                return Err(abort_lnk_sink(sink, metadata, error));
            }
        };
        stats.bytes_read = stats
            .bytes_read
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if count == 0 {
            stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
            stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
            stats.omitted_lnk_bytes = stats.omitted_lnk_bytes.saturating_add(remaining);
            let error = CoreError::new(
                JumpListErrorKind::TruncatedData,
                Some(metadata.source_offset.saturating_add(logical_offset)),
                format!("custom LNK {} ended early", metadata.label),
            );
            return Err(abort_lnk_sink(sink, metadata, error));
        }
        if let Err(error) = sink.lnk_chunk(metadata, logical_offset, &buffer[..count]) {
            stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
            stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
            stats.omitted_lnk_bytes = stats.omitted_lnk_bytes.saturating_add(remaining);
            let error = CoreError::new(
                JumpListErrorKind::Sink,
                Some(metadata.source_offset.saturating_add(logical_offset)),
                format!("LNK sink rejected data for {}: {error}", metadata.label),
            );
            return Err(abort_lnk_sink(sink, metadata, error));
        }
        let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
        remaining = remaining.saturating_sub(count_u64);
        logical_offset = logical_offset.saturating_add(count_u64);
        stats.lnk_bytes_emitted = stats.lnk_bytes_emitted.saturating_add(count_u64);
    }
    if let Err(error) = sink.end_lnk(metadata, true) {
        stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
        stats.omitted_lnk_streams = stats.omitted_lnk_streams.saturating_add(1);
        return Err(CoreError::new(
            JumpListErrorKind::Sink,
            Some(metadata.source_offset),
            format!(
                "LNK sink rejected completion for {} after receiving all {} bytes: {error}",
                metadata.label, metadata.declared_size
            ),
        ));
    }
    stats.lnk_streams_emitted = stats.lnk_streams_emitted.saturating_add(1);
    Ok(())
}

fn find_next_signature<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    file_size: u64,
    options: &JumpListParseOptions,
    stats: &mut JumpListStats,
) -> CoreResult<Option<u64>> {
    if start >= file_size || file_size.saturating_sub(start) < LNK_SIGNATURE.len() as u64 {
        return Ok(None);
    }
    let overlap = LNK_SIGNATURE.len().saturating_sub(1);
    let mut position = start;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(options.io_buffer_bytes)
        .map_err(|error| {
            CoreError::new(
                JumpListErrorKind::Allocation,
                Some(start),
                format!("reserving custom signature-scan buffer: {error}"),
            )
        })?;
    buffer.resize(options.io_buffer_bytes, 0);
    while position < file_size {
        reader.seek(SeekFrom::Start(position)).map_err(|error| {
            CoreError::io(Some(position), "seeking custom signature scan", error)
        })?;
        let request = usize::try_from(
            file_size
                .saturating_sub(position)
                .min(options.io_buffer_bytes as u64),
        )
        .map_err(|_| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                Some(position),
                "signature scan request does not fit usize",
            )
        })?;
        let count = read_up_to(reader, &mut buffer[..request]).map_err(|error| {
            CoreError::io(Some(position), "reading custom signature scan", error)
        })?;
        stats.bytes_read = stats
            .bytes_read
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if count < LNK_SIGNATURE.len() {
            return Ok(None);
        }
        if let Some(relative) = buffer[..count]
            .windows(LNK_SIGNATURE.len())
            .position(|window| window == LNK_SIGNATURE)
        {
            return position
                .checked_add(relative as u64)
                .map(Some)
                .ok_or_else(|| {
                    CoreError::new(
                        JumpListErrorKind::CheckedArithmeticOverflow,
                        Some(position),
                        "signature match offset overflow",
                    )
                });
        }
        let advance = count.saturating_sub(overlap);
        if advance == 0 {
            break;
        }
        position = position.checked_add(advance as u64).ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                Some(position),
                "signature scan offset overflow",
            )
        })?;
    }
    Ok(None)
}

fn record_recoverable_stream_error<S: JumpListSink>(
    stats: &mut JumpListStats,
    options: &JumpListParseOptions,
    sink: &mut S,
    label: &str,
    offset: Option<u64>,
    error: CoreError,
) -> CoreResult<()> {
    stats.corrupt_streams = stats.corrupt_streams.saturating_add(1);
    stats.incomplete_streams = stats.incomplete_streams.saturating_add(1);
    let diagnostic = JumpListDiagnostic {
        label: Some(bounded_label(label)),
        offset,
        kind: error.kind,
        message: bounded_text(&error.message, DIAGNOSTIC_MESSAGE_BYTES),
    };
    stats.diagnostic(options, Some(label), offset, error.kind, &error.message);
    sink.corrupt_stream(&diagnostic).map_err(|sink_error| {
        CoreError::new(
            JumpListErrorKind::Sink,
            offset,
            format!("corrupt-stream sink rejected {label}: {sink_error}"),
        )
    })
}

fn is_recoverable_stream_error(error: &CoreError) -> bool {
    matches!(
        error.kind,
        JumpListErrorKind::InvalidMiniFat
            | JumpListErrorKind::InvalidStream
            | JumpListErrorKind::ChainCycle
            | JumpListErrorKind::TruncatedData
    )
}

fn read_sector_raw<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
    sector_size: usize,
    sector_count: u32,
    sector: u32,
    output: &mut [u8],
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    validate_regular_sector(sector, sector_count, "sector read")?;
    if output.len() != sector_size {
        return Err(CoreError::new(
            JumpListErrorKind::InvalidCfbHeader,
            None,
            "sector output buffer has the wrong size",
        ));
    }
    let offset = sector_file_offset(sector_size, sector)?;
    let end = offset.checked_add(sector_size as u64).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            Some(offset),
            "sector end offset overflow",
        )
    })?;
    if end > file_size {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            Some(offset),
            format!("sector {sector} ends beyond file size {file_size}"),
        ));
    }
    read_exact_at(reader, offset, output, stats)
}

fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    output: &mut [u8],
    stats: &mut JumpListStats,
) -> CoreResult<()> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| CoreError::io(Some(offset), "seeking random-access read", error))?;
    let count = read_up_to(reader, output)
        .map_err(|error| CoreError::io(Some(offset), "reading random-access bytes", error))?;
    stats.bytes_read = stats
        .bytes_read
        .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    if count != output.len() {
        return Err(CoreError::new(
            JumpListErrorKind::Io,
            Some(offset.saturating_add(count as u64)),
            format!(
                "random-access source changed or ended early: requested {} bytes, read {count}",
                output.len()
            ),
        ));
    }
    Ok(())
}

fn read_up_to<R: Read>(reader: &mut R, output: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0_usize;
    while filled < output.len() {
        match reader.read(&mut output[filled..]) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn validate_regular_sector(sector: u32, sector_count: u32, label: &str) -> CoreResult<()> {
    if sector >= sector_count {
        return Err(CoreError::new(
            JumpListErrorKind::TruncatedData,
            None,
            format!("{label} sector {sector} is outside 0..{sector_count}"),
        ));
    }
    Ok(())
}

fn sector_file_offset(sector_size: usize, sector: u32) -> CoreResult<u64> {
    u64::from(sector)
        .checked_add(1)
        .and_then(|value| value.checked_mul(sector_size as u64))
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                format!("physical offset for sector {sector} overflows u64"),
            )
        })
}

fn div_ceil_u64(value: u64, divisor: u64) -> CoreResult<u64> {
    if divisor == 0 {
        return Err(CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            None,
            "division by zero in sector count",
        ));
    }
    if value == 0 {
        return Ok(0);
    }
    value
        .checked_add(divisor.saturating_sub(1))
        .map(|adjusted| adjusted / divisor)
        .ok_or_else(|| {
            CoreError::new(
                JumpListErrorKind::CheckedArithmeticOverflow,
                None,
                "ceiling division addition overflow",
            )
        })
}

fn slice_u16(bytes: &[u8], offset: usize) -> CoreResult<u16> {
    let data = checked_slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

fn slice_u32(bytes: &[u8], offset: usize) -> CoreResult<u32> {
    let data = checked_slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn slice_u64(bytes: &[u8], offset: usize) -> CoreResult<u64> {
    let data = checked_slice(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

fn optional_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    slice_u32(bytes, offset).ok()
}

fn optional_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    slice_u64(bytes, offset).ok()
}

fn checked_slice(bytes: &[u8], offset: usize, length: usize) -> CoreResult<&[u8]> {
    let end = offset.checked_add(length).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::CheckedArithmeticOverflow,
            None,
            "slice offset plus length overflow",
        )
    })?;
    bytes.get(offset..end).ok_or_else(|| {
        CoreError::new(
            JumpListErrorKind::TruncatedData,
            Some(offset as u64),
            format!("slice {offset}..{end} exceeds {} bytes", bytes.len()),
        )
    })
}

fn public_invalid_options(message: String) -> JumpListError {
    JumpListError {
        status: JumpListTerminalStatus::Failed,
        kind: JumpListErrorKind::InvalidOptions,
        offset: None,
        message,
        stats: Box::default(),
    }
}

fn public_error(error: CoreError, stats: JumpListStats) -> JumpListError {
    JumpListError {
        status: JumpListTerminalStatus::Failed,
        kind: error.kind,
        offset: error.offset,
        message: bounded_text(&error.message, DIAGNOSTIC_MESSAGE_BYTES),
        stats: Box::new(stats),
    }
}

fn bounded_label(label: &str) -> String {
    bounded_text(label, 128)
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

fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    let filetime = i128::from(filetime);
    if filetime == 0 {
        return None;
    }
    let unix_ticks = filetime.checked_sub(FILETIME_UNIX_EPOCH_100NS)?;
    let unix_seconds = unix_ticks.div_euclid(10_000_000);
    let subsecond_ticks = unix_ticks.rem_euclid(10_000_000);
    let unix_seconds = i64::try_from(unix_seconds).ok()?;
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
        entries: Vec<(JumpListLnkMetadata, Vec<u8>, bool)>,
        active: Option<(JumpListLnkMetadata, Vec<u8>)>,
        dest_list: Option<DestListMetadata>,
        corrupt: Vec<JumpListDiagnostic>,
    }

    impl JumpListSink for CollectSink {
        type Error = &'static str;

        fn begin_lnk(&mut self, metadata: &JumpListLnkMetadata) -> Result<(), Self::Error> {
            if self.active.is_some() {
                return Err("nested LNK");
            }
            self.active = Some((metadata.clone(), Vec::new()));
            Ok(())
        }

        fn lnk_chunk(
            &mut self,
            _metadata: &JumpListLnkMetadata,
            logical_offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            let (_, payload) = self.active.as_mut().ok_or("no active LNK")?;
            if logical_offset != payload.len() as u64 {
                return Err("non-contiguous chunk");
            }
            payload.extend_from_slice(bytes);
            Ok(())
        }

        fn end_lnk(
            &mut self,
            _metadata: &JumpListLnkMetadata,
            complete: bool,
        ) -> Result<(), Self::Error> {
            let (metadata, payload) = self.active.take().ok_or("no active LNK")?;
            self.entries.push((metadata, payload, complete));
            Ok(())
        }

        fn dest_list(&mut self, metadata: &DestListMetadata) -> Result<(), Self::Error> {
            self.dest_list = Some(metadata.clone());
            Ok(())
        }

        fn corrupt_stream(&mut self, diagnostic: &JumpListDiagnostic) -> Result<(), Self::Error> {
            self.corrupt.push(diagnostic.clone());
            Ok(())
        }
    }

    fn automatic_fixture(cycle_lnk: bool) -> Vec<u8> {
        let sector_size = 512_usize;
        let sector_count = 4_usize;
        let mut cfb = vec![0_u8; sector_size * (sector_count + 1)];
        cfb[..8].copy_from_slice(&CFB_MAGIC);
        cfb[24..26].copy_from_slice(&0x003E_u16.to_le_bytes());
        cfb[26..28].copy_from_slice(&3_u16.to_le_bytes());
        cfb[28..30].copy_from_slice(&0xFFFE_u16.to_le_bytes());
        cfb[30..32].copy_from_slice(&9_u16.to_le_bytes());
        cfb[32..34].copy_from_slice(&6_u16.to_le_bytes());
        cfb[44..48].copy_from_slice(&1_u32.to_le_bytes());
        cfb[48..52].copy_from_slice(&1_u32.to_le_bytes());
        cfb[56..60].copy_from_slice(&4096_u32.to_le_bytes());
        cfb[60..64].copy_from_slice(&3_u32.to_le_bytes());
        cfb[64..68].copy_from_slice(&1_u32.to_le_bytes());
        cfb[68..72].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[72..76].copy_from_slice(&0_u32.to_le_bytes());
        cfb[76..80].copy_from_slice(&0_u32.to_le_bytes());
        for index in 1..109 {
            let offset = 76 + index * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }

        let fat = sector_size;
        cfb[fat..fat + 4].copy_from_slice(&FAT_SECTOR.to_le_bytes());
        cfb[fat + 4..fat + 8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[fat + 8..fat + 12].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[fat + 12..fat + 16].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for index in 4..sector_size / 4 {
            let offset = fat + index * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }

        let directory = sector_size * 2;
        write_directory_entry(
            &mut cfb[directory..directory + 128],
            "Root Entry",
            5,
            2,
            128,
        );
        write_directory_entry(&mut cfb[directory + 128..directory + 256], "1", 2, 0, 32);
        write_directory_entry(
            &mut cfb[directory + 256..directory + 384],
            "DestList",
            2,
            1,
            32,
        );

        let mini_stream = sector_size * 3;
        cfb[mini_stream..mini_stream + LNK_SIGNATURE.len()].copy_from_slice(&LNK_SIGNATURE);
        cfb[mini_stream + 20..mini_stream + 32].copy_from_slice(b"payload-data");
        cfb[mini_stream + 64..mini_stream + 68].copy_from_slice(&4_u32.to_le_bytes());
        cfb[mini_stream + 68..mini_stream + 72].copy_from_slice(&7_u32.to_le_bytes());
        cfb[mini_stream + 72..mini_stream + 76].copy_from_slice(&2_u32.to_le_bytes());
        cfb[mini_stream + 76..mini_stream + 80].copy_from_slice(&99_u32.to_le_bytes());
        cfb[mini_stream + 80..mini_stream + 88].copy_from_slice(&55_u64.to_le_bytes());
        cfb[mini_stream + 88..mini_stream + 96].copy_from_slice(&66_u64.to_le_bytes());

        let mini_fat = sector_size * 4;
        cfb[mini_fat..mini_fat + 4]
            .copy_from_slice(&(if cycle_lnk { 0_u32 } else { END_OF_CHAIN }).to_le_bytes());
        cfb[mini_fat + 4..mini_fat + 8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for index in 2..sector_size / 4 {
            let offset = mini_fat + index * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }
        cfb
    }

    fn empty_automatic_fixture() -> Vec<u8> {
        let sector_size = 512_usize;
        let mut cfb = vec![0_u8; sector_size * 3];
        cfb[..8].copy_from_slice(&CFB_MAGIC);
        cfb[24..26].copy_from_slice(&0x003E_u16.to_le_bytes());
        cfb[26..28].copy_from_slice(&3_u16.to_le_bytes());
        cfb[28..30].copy_from_slice(&0xFFFE_u16.to_le_bytes());
        cfb[30..32].copy_from_slice(&9_u16.to_le_bytes());
        cfb[32..34].copy_from_slice(&6_u16.to_le_bytes());
        cfb[44..48].copy_from_slice(&1_u32.to_le_bytes());
        cfb[48..52].copy_from_slice(&1_u32.to_le_bytes());
        cfb[56..60].copy_from_slice(&4096_u32.to_le_bytes());
        cfb[60..64].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[68..72].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[76..80].copy_from_slice(&0_u32.to_le_bytes());
        for index in 1..109 {
            let offset = 76 + index * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }

        let fat = sector_size;
        cfb[fat..fat + 4].copy_from_slice(&FAT_SECTOR.to_le_bytes());
        cfb[fat + 4..fat + 8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for index in 2..sector_size / 4 {
            let offset = fat + index * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }

        let directory = sector_size * 2;
        write_directory_entry(
            &mut cfb[directory..directory + 128],
            "Root Entry",
            5,
            END_OF_CHAIN,
            0,
        );
        write_directory_entry(
            &mut cfb[directory + 128..directory + 256],
            "DestList",
            2,
            END_OF_CHAIN,
            0,
        );
        cfb
    }

    fn regular_stream_fixture() -> Vec<u8> {
        let sector_size = 512_usize;
        let sector_count = 10_usize;
        let mut cfb = vec![0_u8; sector_size * (sector_count + 1)];
        cfb[..8].copy_from_slice(&CFB_MAGIC);
        cfb[24..26].copy_from_slice(&0x003E_u16.to_le_bytes());
        cfb[26..28].copy_from_slice(&3_u16.to_le_bytes());
        cfb[28..30].copy_from_slice(&0xFFFE_u16.to_le_bytes());
        cfb[30..32].copy_from_slice(&9_u16.to_le_bytes());
        cfb[32..34].copy_from_slice(&6_u16.to_le_bytes());
        cfb[44..48].copy_from_slice(&1_u32.to_le_bytes());
        cfb[48..52].copy_from_slice(&1_u32.to_le_bytes());
        cfb[56..60].copy_from_slice(&4096_u32.to_le_bytes());
        cfb[60..64].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[68..72].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        cfb[76..80].copy_from_slice(&0_u32.to_le_bytes());
        for index in 1..109 {
            let offset = 76 + index * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }

        let fat = sector_size;
        cfb[fat..fat + 4].copy_from_slice(&FAT_SECTOR.to_le_bytes());
        cfb[fat + 4..fat + 8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for sector in 2_usize..9 {
            let offset = fat + sector * 4;
            cfb[offset..offset + 4].copy_from_slice(&((sector + 1) as u32).to_le_bytes());
        }
        cfb[fat + 9 * 4..fat + 10 * 4].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        for sector in 10_usize..sector_size / 4 {
            let offset = fat + sector * 4;
            cfb[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
        }

        let directory = sector_size * 2;
        write_directory_entry(
            &mut cfb[directory..directory + 128],
            "Root Entry",
            5,
            END_OF_CHAIN,
            0,
        );
        write_directory_entry(&mut cfb[directory + 128..directory + 256], "A", 2, 2, 4096);
        let payload = sector_size * 3;
        cfb[payload..payload + LNK_SIGNATURE.len()].copy_from_slice(&LNK_SIGNATURE);
        for byte in &mut cfb[payload + LNK_SIGNATURE.len()..] {
            *byte = 0x5A;
        }
        cfb
    }

    fn external_difat_fixture(cycle: bool) -> (Cursor<Vec<u8>>, CfbHeader) {
        let sector_size = 512_usize;
        let sector_count = 14_080_u32;
        let mut data = vec![0_u8; sector_size * (sector_count as usize + 1)];
        let mut inline_difat = Vec::new();
        for sector in 0_u32..109 {
            inline_difat.push(sector);
        }
        let write_difat = |data: &mut [u8], sector: u32, fat_sector: u32, next: u32| {
            let start = sector_size * (sector as usize + 1);
            data[start..start + 4].copy_from_slice(&fat_sector.to_le_bytes());
            for index in 1..sector_size / 4 - 1 {
                let offset = start + index * 4;
                data[offset..offset + 4].copy_from_slice(&FREE_SECTOR.to_le_bytes());
            }
            let next_offset = start + sector_size - 4;
            data[next_offset..next_offset + 4].copy_from_slice(&next.to_le_bytes());
        };
        if cycle {
            write_difat(&mut data, 109, 110, 111);
            write_difat(&mut data, 111, FREE_SECTOR, 112);
            write_difat(&mut data, 112, FREE_SECTOR, 113);
            write_difat(&mut data, 113, FREE_SECTOR, 109);
        } else {
            write_difat(&mut data, 109, 110, END_OF_CHAIN);
        }
        (
            Cursor::new(data),
            CfbHeader {
                major_version: 3,
                sector_size,
                mini_sector_size: 64,
                sector_count,
                number_of_fat_sectors: 110,
                first_directory_sector: 0,
                mini_stream_cutoff: 4096,
                first_mini_fat_sector: END_OF_CHAIN,
                number_of_mini_fat_sectors: 0,
                first_difat_sector: 109,
                number_of_difat_sectors: if cycle { 5 } else { 1 },
                inline_difat,
            },
        )
    }

    fn write_directory_entry(
        entry: &mut [u8],
        name: &str,
        object_type: u8,
        start_sector: u32,
        size: u64,
    ) {
        let name_units: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        for (index, unit) in name_units.iter().enumerate() {
            let offset = index * 2;
            entry[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        entry[64..66].copy_from_slice(&((name_units.len() * 2) as u16).to_le_bytes());
        entry[66] = object_type;
        entry[67] = 1;
        entry[68..72].copy_from_slice(&NO_STREAM.to_le_bytes());
        entry[72..76].copy_from_slice(&NO_STREAM.to_le_bytes());
        entry[76..80].copy_from_slice(&NO_STREAM.to_le_bytes());
        entry[116..120].copy_from_slice(&start_sector.to_le_bytes());
        entry[120..128].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn automatic_parser_walks_fat_minifat_and_streams_exact_lnk() {
        let mut reader = Cursor::new(automatic_fixture(false));
        let mut sink = CollectSink::default();
        let result =
            parse_automatic_destinations(&mut reader, &mut sink, &JumpListParseOptions::default())
                .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert_eq!(result.stats.lnk_streams_emitted, 1);
        assert_eq!(result.stats.omitted_lnk_bytes, 0);
        assert_eq!(sink.entries.len(), 1);
        assert_eq!(sink.entries[0].1.len(), 32);
        assert_eq!(&sink.entries[0].1[..20], &LNK_SIGNATURE);
        assert!(sink.entries[0].2);
        assert_eq!(sink.entries[0].0.source_offset, 1536);
        let dest = result.dest_list.unwrap();
        assert_eq!(dest.version, Some(4));
        assert_eq!(dest.entry_count, Some(7));
        assert_eq!(dest.pinned_entry_count, Some(2));
        assert_eq!(dest.last_entry_id, Some(55));
        assert_eq!(dest.action_count, Some(66));
    }

    #[test]
    fn empty_automatic_destinations_is_valid_without_minifat() {
        let mut sink = CollectSink::default();
        let result = parse_automatic_destinations(
            &mut Cursor::new(empty_automatic_fixture()),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert_eq!(result.stats.dest_list_streams, 1);
        assert_eq!(result.stats.missing_dest_list, 0);
        assert_eq!(result.stats.lnk_candidates, 0);
        let dest = result.dest_list.unwrap();
        assert_eq!(dest.declared_size, 0);
        assert_eq!(dest.entry_count, Some(0));
    }

    #[test]
    fn dest_list_property_store_is_not_misclassified_as_lnk() {
        let mut data = automatic_fixture(false);
        let directory = 512 * 2;
        write_directory_entry(
            &mut data[directory + 384..directory + 512],
            "DestListPropertyStore",
            2,
            2,
            16,
        );
        let mini_stream = 512 * 3;
        data[mini_stream + 128..mini_stream + 144].copy_from_slice(b"property-store!!");
        let mini_fat = 512 * 4;
        data[mini_fat + 8..mini_fat + 12].copy_from_slice(&END_OF_CHAIN.to_le_bytes());

        let mut sink = CollectSink::default();
        let result = parse_automatic_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert_eq!(result.stats.auxiliary_streams, 1);
        assert_eq!(result.stats.lnk_candidates, 1);
        assert_eq!(result.stats.omitted_lnk_streams, 0);
    }

    #[test]
    fn automatic_lnk_stream_labels_are_strict_hexadecimal_entry_identifiers() {
        for label in ["1", "9", "a", "F", "10", "1f", "ABC"] {
            assert!(is_automatic_lnk_stream_label(label), "{label}");
        }
        for label in [
            "",
            "0",
            "00",
            "DestListPropertyStore",
            "\u{0005}SummaryInformation",
            "foo",
            "1g",
        ] {
            assert!(!is_automatic_lnk_stream_label(label), "{label:?}");
        }
    }

    #[test]
    fn arbitrary_non_hex_cfb_stream_is_retained_as_auxiliary_metadata() {
        let mut data = automatic_fixture(false);
        let directory = 512 * 2;
        write_directory_entry(
            &mut data[directory + 384..directory + 512],
            "\u{0005}SummaryInformation",
            2,
            2,
            16,
        );
        let mini_stream = 512 * 3;
        data[mini_stream + 128..mini_stream + 144].copy_from_slice(b"metadata-not-lnk");
        let mini_fat = 512 * 4;
        data[mini_fat + 8..mini_fat + 12].copy_from_slice(&END_OF_CHAIN.to_le_bytes());

        let mut sink = CollectSink::default();
        let result = parse_automatic_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert_eq!(result.stats.auxiliary_streams, 1);
        assert_eq!(result.stats.lnk_candidates, 1);
        assert_eq!(result.stats.omitted_lnk_streams, 0);
        assert_eq!(sink.entries.len(), 1);
    }

    #[test]
    fn cfb_v3_ignores_dirty_stream_size_high_dword_and_discloses_it() {
        let mut data = automatic_fixture(false);
        let root_size = 128_u64 | (0xDEAD_BEEF_u64 << 32);
        let directory = 512 * 2;
        data[directory + 120..directory + 128].copy_from_slice(&root_size.to_le_bytes());

        let mut sink = CollectSink::default();
        let result = parse_automatic_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert_eq!(result.stats.v3_stream_size_high_dwords_ignored, 1);
        assert_eq!(result.stats.lnk_streams_emitted, 1);
        assert_eq!(result.stats.dest_list_streams, 1);
    }

    #[test]
    fn directory_stream_size_uses_version_specific_width() {
        let mut bytes = [0_u8; CFB_DIRECTORY_ENTRY_BYTES];
        write_directory_entry(&mut bytes, "Stream", 2, 7, 5 | (9_u64 << 32));
        let version_3 = parse_directory_entry(&bytes, 3).unwrap();
        assert_eq!(version_3.stream_size, 5);
        assert!(version_3.stream_size_high_dword_ignored);
        let version_4 = parse_directory_entry(&bytes, 4).unwrap();
        assert_eq!(version_4.stream_size, 5 | (9_u64 << 32));
        assert!(!version_4.stream_size_high_dword_ignored);
    }

    #[test]
    fn regular_fat_stream_is_complete_without_payload_buffer_cap() {
        let mut reader = Cursor::new(regular_stream_fixture());
        let mut sink = CollectSink::default();
        let result =
            parse_automatic_destinations(&mut reader, &mut sink, &JumpListParseOptions::default())
                .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Partial);
        assert_eq!(result.stats.missing_dest_list, 1);
        assert_eq!(result.stats.lnk_streams_emitted, 1);
        assert_eq!(result.stats.lnk_bytes_emitted, 4096);
        assert_eq!(result.stats.omitted_lnk_bytes, 0);
        assert_eq!(sink.entries[0].1.len(), 4096);
        assert_eq!(&sink.entries[0].1[..20], &LNK_SIGNATURE);
        assert!(!sink.entries[0].0.stored_in_mini_stream);
        assert_eq!(sink.entries[0].0.source_offset, 1536);
    }

    #[test]
    fn external_difat_is_checked_and_cycle_bounded_by_declared_file() {
        let (mut valid_reader, valid_header) = external_difat_fixture(false);
        let mut stats = JumpListStats::default();
        let file_size = valid_reader.get_ref().len() as u64;
        let (fat, difat) =
            load_difat(&mut valid_reader, file_size, &valid_header, &mut stats).unwrap();
        assert_eq!(fat.len(), 110);
        assert_eq!(fat[109], 110);
        assert_eq!(difat, vec![109]);

        let (mut cycle_reader, cycle_header) = external_difat_fixture(true);
        let mut cycle_stats = JumpListStats::default();
        let cycle_size = cycle_reader.get_ref().len() as u64;
        let error = load_difat(
            &mut cycle_reader,
            cycle_size,
            &cycle_header,
            &mut cycle_stats,
        )
        .unwrap_err();
        assert_eq!(error.kind, JumpListErrorKind::ChainCycle);
    }

    #[test]
    fn mini_fat_cycle_is_bounded_and_disclosed_without_omitting_destlist() {
        let mut reader = Cursor::new(automatic_fixture(true));
        let mut sink = CollectSink::default();
        let result =
            parse_automatic_destinations(&mut reader, &mut sink, &JumpListParseOptions::default())
                .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Partial);
        assert_eq!(result.stats.corrupt_streams, 1);
        assert_eq!(result.stats.omitted_lnk_streams, 1);
        assert_eq!(result.stats.omitted_lnk_bytes, 32);
        assert_eq!(result.stats.dest_list_streams, 1);
        assert!(result.dest_list.is_some());
        assert_eq!(sink.corrupt.len(), 1);
        assert_eq!(sink.corrupt[0].kind, JumpListErrorKind::ChainCycle);
    }

    #[test]
    fn invalid_minifat_does_not_discard_regular_fat_lnk_streams() {
        let mut data = regular_stream_fixture();
        // Advertise a root mini stream and a miniFAT sector outside the file.
        // The valid 4096-byte LNK stream is FAT-backed and remains recoverable.
        data[60..64].copy_from_slice(&99_u32.to_le_bytes());
        data[64..68].copy_from_slice(&1_u32.to_le_bytes());
        let root = 512 * 2;
        data[root + 116..root + 120].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
        data[root + 120..root + 128].copy_from_slice(&64_u64.to_le_bytes());

        let mut sink = CollectSink::default();
        let result = parse_automatic_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Partial);
        assert_eq!(result.stats.lnk_streams_emitted, 1);
        assert_eq!(sink.entries.len(), 1);
        assert_eq!(&sink.entries[0].1[..LNK_SIGNATURE.len()], &LNK_SIGNATURE);
        assert!(result
            .stats
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.label.as_deref() == Some("Root Entry")));
    }

    #[test]
    fn directory_fat_cycle_is_fatal_failed() {
        let mut data = automatic_fixture(false);
        let fat = 512;
        data[fat + 4..fat + 8].copy_from_slice(&1_u32.to_le_bytes());
        let mut sink = CollectSink::default();
        let error = parse_automatic_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.status, JumpListTerminalStatus::Failed);
        assert_eq!(error.kind, JumpListErrorKind::ChainCycle);
    }

    #[test]
    fn custom_parser_finds_cross_buffer_signatures_with_bounded_reads() {
        let mut data = vec![0xAA; 510];
        data.extend_from_slice(&LNK_SIGNATURE);
        data.extend_from_slice(b"first");
        data.extend_from_slice(&LNK_SIGNATURE);
        data.extend_from_slice(b"second");
        let options = JumpListParseOptions {
            io_buffer_bytes: 512,
            diagnostic_sample_limit: 8,
        };
        let mut sink = CollectSink::default();
        let result =
            parse_custom_destinations(&mut Cursor::new(data), &mut sink, &options).unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Partial);
        assert!(result.stats.heuristic_custom_boundaries);
        assert_eq!(result.stats.lnk_streams_emitted, 2);
        assert_eq!(sink.entries.len(), 2);
        assert_eq!(&sink.entries[0].1[..20], &LNK_SIGNATURE);
        assert_eq!(sink.entries[0].1.len(), 25);
        assert_eq!(sink.entries[1].1.len(), 26);
    }

    #[test]
    fn canonical_empty_custom_destinations_is_not_a_failure() {
        for state in [1_u32, 2_u32] {
            let mut data = Vec::new();
            data.extend_from_slice(&2_u32.to_le_bytes());
            data.extend_from_slice(&1_u32.to_le_bytes());
            data.extend_from_slice(&0_u32.to_le_bytes());
            data.extend_from_slice(&1_u32.to_le_bytes());
            data.extend_from_slice(&state.to_le_bytes());
            data.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);
            let mut sink = CollectSink::default();
            let result = parse_custom_destinations(
                &mut Cursor::new(data),
                &mut sink,
                &JumpListParseOptions::default(),
            )
            .unwrap();
            assert_eq!(result.status, JumpListTerminalStatus::Recognized);
            assert_eq!(result.stats.lnk_candidates, 0);
            assert_eq!(result.stats.lnk_streams_emitted, 0);
            assert!(result.stats.custom_container_envelope_validated);
            assert_eq!(result.stats.custom_categories_declared, Some(1));
            assert_eq!(result.stats.custom_categories_validated, 1);
            assert_eq!(result.stats.custom_zero_entry_categories, 1);
        }
    }

    #[test]
    fn zero_category_custom_destinations_is_valid_container_metadata() {
        let mut data = Vec::new();
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        let mut sink = CollectSink::default();
        let result = parse_custom_destinations(
            &mut Cursor::new(data.clone()),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert!(result.stats.custom_container_envelope_validated);
        assert_eq!(result.stats.custom_categories_declared, Some(0));
        assert_eq!(result.stats.custom_categories_validated, 0);
        assert!(
            is_custom_destinations(&mut Cursor::new(data), &JumpListParseOptions::default())
                .unwrap()
        );
    }

    #[test]
    fn zero_entry_custom_and_user_task_categories_are_retained() {
        let mut data = Vec::new();
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&4_u16.to_le_bytes());
        for unit in "Work".encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);

        let mut sink = CollectSink::default();
        let result = parse_custom_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Recognized);
        assert_eq!(result.stats.custom_categories_declared, Some(2));
        assert_eq!(result.stats.custom_categories_validated, 2);
        assert_eq!(result.stats.custom_zero_entry_categories, 2);
        assert_eq!(
            result
                .stats
                .custom_entries_without_complete_lnk_headers_declared,
            0
        );
        assert!(sink.entries.is_empty());
    }

    #[test]
    fn declared_custom_entries_without_complete_lnk_are_partial_not_fatal() {
        let mut data = Vec::new();
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(b"bounded-record-bytes");
        data.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);

        let mut sink = CollectSink::default();
        let result = parse_custom_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap();
        assert_eq!(result.status, JumpListTerminalStatus::Partial);
        assert!(result.stats.custom_container_envelope_validated);
        assert_eq!(result.stats.custom_categories_declared, Some(1));
        assert_eq!(result.stats.custom_categories_validated, 1);
        assert_eq!(
            result
                .stats
                .custom_entries_without_complete_lnk_headers_declared,
            2
        );
        assert_eq!(result.stats.diagnostic_count, 1);
        assert_eq!(result.stats.lnk_streams_emitted, 0);
        assert!(sink.entries.is_empty());
    }

    #[test]
    fn malformed_custom_envelopes_are_not_silently_accepted() {
        let mut invalid_utf16 = Vec::new();
        invalid_utf16.extend_from_slice(&2_u32.to_le_bytes());
        invalid_utf16.extend_from_slice(&1_u32.to_le_bytes());
        invalid_utf16.extend_from_slice(&0_u32.to_le_bytes());
        invalid_utf16.extend_from_slice(&0_u32.to_le_bytes());
        invalid_utf16.extend_from_slice(&1_u16.to_le_bytes());
        invalid_utf16.extend_from_slice(&0xD800_u16.to_le_bytes());
        invalid_utf16.extend_from_slice(&0_u32.to_le_bytes());
        invalid_utf16.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);
        let mut sink = CollectSink::default();
        let error = parse_custom_destinations(
            &mut Cursor::new(invalid_utf16),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind, JumpListErrorKind::InvalidStream);

        let mut invalid_footer = Vec::new();
        invalid_footer.extend_from_slice(&2_u32.to_le_bytes());
        invalid_footer.extend_from_slice(&1_u32.to_le_bytes());
        invalid_footer.extend_from_slice(&0_u32.to_le_bytes());
        invalid_footer.extend_from_slice(&2_u32.to_le_bytes());
        invalid_footer.extend_from_slice(&0_u32.to_le_bytes());
        invalid_footer.extend_from_slice(&0_u32.to_le_bytes());
        let error = parse_custom_destinations(
            &mut Cursor::new(invalid_footer),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind, JumpListErrorKind::InvalidStream);

        let mut invalid_category = Vec::new();
        invalid_category.extend_from_slice(&2_u32.to_le_bytes());
        invalid_category.extend_from_slice(&1_u32.to_le_bytes());
        invalid_category.extend_from_slice(&0_u32.to_le_bytes());
        invalid_category.extend_from_slice(&99_u32.to_le_bytes());
        invalid_category.extend_from_slice(&0_u32.to_le_bytes());
        invalid_category.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);
        let error = parse_custom_destinations(
            &mut Cursor::new(invalid_category),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind, JumpListErrorKind::InvalidStream);
    }

    #[test]
    fn canonical_empty_custom_destinations_probe_recognizes_and_restores_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&CUSTOM_DESTINATIONS_EMPTY_FOOTER);
        let mut reader = Cursor::new(data);
        reader.set_position(7);
        assert!(is_custom_destinations(&mut reader, &JumpListParseOptions::default()).unwrap());
        assert_eq!(reader.position(), 7);
    }

    struct RejectSink;

    impl JumpListSink for RejectSink {
        type Error = &'static str;

        fn begin_lnk(&mut self, _metadata: &JumpListLnkMetadata) -> Result<(), Self::Error> {
            Err("injected sink rejection")
        }

        fn lnk_chunk(
            &mut self,
            _metadata: &JumpListLnkMetadata,
            _logical_offset: u64,
            _bytes: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn end_lnk(
            &mut self,
            _metadata: &JumpListLnkMetadata,
            _complete: bool,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn sink_failure_is_err_with_failed_status() {
        let mut data = Vec::from(LNK_SIGNATURE);
        data.extend_from_slice(b"payload");
        let mut sink = RejectSink;
        let error = parse_custom_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.status, JumpListTerminalStatus::Failed);
        assert_eq!(error.kind, JumpListErrorKind::Sink);
        assert!(error.message.contains("injected sink rejection"));
        assert_eq!(error.stats.lnk_streams_emitted, 0);
    }

    struct RejectChunkSink {
        ended: Option<bool>,
    }

    impl JumpListSink for RejectChunkSink {
        type Error = &'static str;

        fn begin_lnk(&mut self, _metadata: &JumpListLnkMetadata) -> Result<(), Self::Error> {
            Ok(())
        }

        fn lnk_chunk(
            &mut self,
            _metadata: &JumpListLnkMetadata,
            _logical_offset: u64,
            _bytes: &[u8],
        ) -> Result<(), Self::Error> {
            Err("injected chunk rejection")
        }

        fn end_lnk(
            &mut self,
            _metadata: &JumpListLnkMetadata,
            complete: bool,
        ) -> Result<(), Self::Error> {
            self.ended = Some(complete);
            Ok(())
        }
    }

    #[test]
    fn midstream_sink_failure_aborts_record_and_preserves_exact_omission_counts() {
        let mut data = Vec::from(LNK_SIGNATURE);
        data.extend_from_slice(b"payload");
        let declared_size = data.len() as u64;
        let mut sink = RejectChunkSink { ended: None };
        let error = parse_custom_destinations(
            &mut Cursor::new(data),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.status, JumpListTerminalStatus::Failed);
        assert_eq!(error.kind, JumpListErrorKind::Sink);
        assert_eq!(sink.ended, Some(false));
        assert_eq!(error.stats.lnk_bytes_emitted, 0);
        assert_eq!(error.stats.omitted_lnk_streams, 1);
        assert_eq!(error.stats.omitted_lnk_bytes, declared_size);
    }

    #[test]
    fn invalid_options_and_non_jump_list_fail_explicitly() {
        let mut sink = CollectSink::default();
        let options = JumpListParseOptions {
            io_buffer_bytes: 1,
            diagnostic_sample_limit: 0,
        };
        let invalid =
            parse_custom_destinations(&mut Cursor::new(Vec::<u8>::new()), &mut sink, &options)
                .unwrap_err();
        assert_eq!(invalid.kind, JumpListErrorKind::InvalidOptions);
        let not_jump = parse_custom_destinations(
            &mut Cursor::new(vec![0_u8; 1024]),
            &mut sink,
            &JumpListParseOptions::default(),
        )
        .unwrap_err();
        assert_eq!(not_jump.kind, JumpListErrorKind::NotJumpList);
    }

    #[test]
    fn diagnostic_samples_are_bounded_with_exact_omission_count() {
        let options = JumpListParseOptions {
            io_buffer_bytes: 512,
            diagnostic_sample_limit: 2,
        };
        let mut stats = JumpListStats::default();
        for index in 0..5 {
            stats.diagnostic(
                &options,
                Some("stream"),
                Some(index),
                JumpListErrorKind::InvalidStream,
                format!("bad stream {index}"),
            );
        }
        assert_eq!(stats.diagnostic_count, 5);
        assert_eq!(stats.diagnostics.len(), 2);
        assert_eq!(stats.diagnostics_omitted, 3);
    }

    #[test]
    fn recognition_probes_restore_position() {
        let mut automatic = Cursor::new(automatic_fixture(false));
        automatic.set_position(7);
        assert!(!is_automatic_destinations(&mut automatic).unwrap());
        assert_eq!(automatic.position(), 7);
        automatic.set_position(0);
        assert!(is_automatic_destinations(&mut automatic).unwrap());
        assert_eq!(automatic.position(), 0);

        let mut custom = Cursor::new(Vec::from(LNK_SIGNATURE));
        custom.set_position(3);
        assert!(is_custom_destinations(&mut custom, &JumpListParseOptions::default()).unwrap());
        assert_eq!(custom.position(), 3);
    }
}
