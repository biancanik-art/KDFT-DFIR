use chrono::{DateTime, Utc};
use std::io::Read;

/// Status of LNK file parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LnkStatus {
    Recognized,
    Partial,
    Failed,
}

/// Header metadata from a Windows Shell Link (.lnk) file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkHeaderInfo {
    pub header_size: u32,
    pub link_clsid: String,
    pub link_flags: u32,
    pub file_attributes: u32,
    pub creation_time: Option<DateTime<Utc>>,
    pub access_time: Option<DateTime<Utc>>,
    pub write_time: Option<DateTime<Utc>>,
    pub file_size: u32,
    pub icon_index: i32,
    pub show_command: u32,
    pub hot_key: u16,
    pub has_link_target_id_list: bool,
    pub has_link_info: bool,
    pub has_name: bool,
    pub has_relative_path: bool,
    pub has_working_dir: bool,
    pub has_arguments: bool,
    pub has_icon_location: bool,
    pub is_unicode: bool,
    pub force_no_link_info: bool,
}

/// Information from the VolumeID structure inside LinkInfo.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkVolumeInfo {
    pub volume_id_size: u32,
    pub drive_type: u32,
    pub drive_type_desc: String,
    pub drive_serial_number: u32,
    pub drive_serial_hex: String,
    pub volume_label: String,
}

/// Information from CommonNetworkRelativeLink inside LinkInfo.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkNetworkInfo {
    pub flags: u32,
    pub net_provider_type: Option<u32>,
    pub net_name: String,
    pub device_name: Option<String>,
}

/// LinkInfo structure parsing details.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkLinkInfo {
    pub link_info_size: u32,
    pub link_info_header_size: u32,
    pub link_info_flags: u32,
    pub local_base_path: Option<String>,
    pub common_path_suffix: Option<String>,
    pub volume_info: Option<LnkVolumeInfo>,
    pub network_info: Option<LnkNetworkInfo>,
}

/// StringData section parsing output.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LnkStringData {
    pub name_description: Option<String>,
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub command_line_arguments: Option<String>,
    pub icon_location: Option<String>,
}

/// Distributed Link Tracking (TrackerDataBlock 0xA0000003) parsed metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkTrackerData {
    pub length: u32,
    pub version: u32,
    pub machine_id: String,
    pub droid_volume_id: String,
    pub droid_object_id: String,
    pub droid_birth_volume_id: String,
    pub droid_birth_object_id: String,
}

/// Generic ExtraData block representation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkExtraDataBlock {
    pub block_size: u32,
    pub signature: u32,
    pub signature_hex: String,
    pub name: String,
}

/// Structural inventory of an ItemIDList. Item payloads are intentionally not
/// interpreted as paths unless another authoritative Shell Link field supplies
/// the target; the item boundaries remain useful forensic provenance.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkTargetIdListInfo {
    pub declared_size: u32,
    pub item_count: u32,
    pub item_sizes: Vec<u16>,
    pub item_sizes_omitted: u64,
    pub terminal_present: bool,
}

/// SpecialFolderDataBlock (0xA0000005) metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkSpecialFolderData {
    pub special_folder_id: u32,
    pub offset: u32,
}

/// Structural summary of one PropertyStoreDataBlock. The serialized property
/// values are preserved in the source bytes but are not decoded by this parser.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkPropertyStoreData {
    pub block_offset: usize,
    pub storage_count: u32,
    pub format_ids: Vec<String>,
    pub format_ids_omitted: u64,
    pub terminal_present: bool,
}

/// Source byte offsets of parsed LNK sections.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LnkSourceOffsets {
    pub header_offset: usize,
    pub header_size: usize,
    pub id_list_offset: Option<usize>,
    pub id_list_size: Option<usize>,
    pub link_info_offset: Option<usize>,
    pub link_info_size: Option<usize>,
    pub string_data_offset: Option<usize>,
    pub string_data_size: Option<usize>,
    pub extra_data_offset: Option<usize>,
    pub extra_data_size: Option<usize>,
}

/// Result of parsing a Windows Shell Link (.lnk) file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LnkParseResult {
    pub status: LnkStatus,
    pub header: Option<LnkHeaderInfo>,
    pub link_info: Option<LnkLinkInfo>,
    pub string_data: LnkStringData,
    pub tracker_data: Option<LnkTrackerData>,
    pub known_folder_id: Option<String>,
    #[serde(default)]
    pub known_folder_offset: Option<u32>,
    pub environment_path: Option<String>,
    #[serde(default)]
    pub icon_environment_path: Option<String>,
    #[serde(default)]
    pub darwin_data: Option<String>,
    #[serde(default)]
    pub shim_layer_name: Option<String>,
    #[serde(default)]
    pub console_code_page: Option<u32>,
    #[serde(default)]
    pub special_folder_data: Option<LnkSpecialFolderData>,
    #[serde(default)]
    pub target_id_list: Option<LnkTargetIdListInfo>,
    #[serde(default)]
    pub vista_and_above_id_list: Option<LnkTargetIdListInfo>,
    #[serde(default)]
    pub property_store_data: Vec<LnkPropertyStoreData>,
    pub extra_data_blocks: Vec<LnkExtraDataBlock>,
    pub extra_blocks_omitted: u64,
    #[serde(default)]
    pub trailing_zero_padding_bytes: u64,
    pub canonical_target_path: Option<String>,
    pub source_offsets: LnkSourceOffsets,
    pub warnings: Vec<String>,
    pub warnings_omitted: u64,
    /// Optional/ancillary structures that were safely bounded but not fully
    /// interpreted. These notes do not by themselves make the core parse partial.
    #[serde(default)]
    pub coverage_notes: Vec<String>,
    #[serde(default)]
    pub coverage_notes_omitted: u64,
    #[serde(default)]
    pub coverage_complete: bool,
    pub is_valid: bool,
}

/// Configuration options for LNK parsing limits.
#[derive(Debug, Clone)]
pub struct LnkParserOptions {
    pub max_file_size: usize,
}

impl Default for LnkParserOptions {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024,
        }
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

/// Helper function to safely extract u16 LE from slice.
fn get_u16_le(slice: &[u8], offset: usize) -> Option<u16> {
    let bytes = slice.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Helper function to safely extract u32 LE from slice.
fn get_u32_le(slice: &[u8], offset: usize) -> Option<u32> {
    let bytes = slice.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Helper function to safely extract i32 LE from slice.
fn get_i32_le(slice: &[u8], offset: usize) -> Option<i32> {
    let bytes = slice.get(offset..offset + 4)?;
    Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Helper function to safely extract i64 LE from slice.
fn get_i64_le(slice: &[u8], offset: usize) -> Option<i64> {
    let bytes = slice.get(offset..offset + 8)?;
    Some(i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn record_warning(warnings: &mut Vec<String>, omitted: &mut u64, msg: String) {
    if warnings.len() < 50 {
        warnings.push(msg);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn record_coverage_note(notes: &mut Vec<String>, omitted: &mut u64, msg: String) {
    if notes.len() < 50 {
        notes.push(msg);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

/// Defensive parser for Windows Shell Link (.lnk) format.
///
/// Note: `LnkParser` performs bounded whole-record in-memory parsing of LNK structures
/// up to configured memory limits, rather than chunked streaming.
pub struct LnkParser;

impl LnkParser {
    pub const SHELL_LINK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];

    /// Parse LNK bytes with default options.
    pub fn parse(data: &[u8]) -> LnkParseResult {
        Self::parse_with_options(data, &LnkParserOptions::default())
    }

    /// Stream reader parser reading up to max_file_size + 1 to protect against over-limit memory allocation.
    pub fn parse_reader<R: Read>(reader: &mut R, options: &LnkParserOptions) -> LnkParseResult {
        let mut buf = Vec::new();
        let limit = options.max_file_size.saturating_add(1);
        let mut take = reader.take(limit as u64);
        if let Err(e) = take.read_to_end(&mut buf) {
            let mut warnings = Vec::new();
            let mut warnings_omitted = 0;
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!("Failed to read LNK stream: {e}"),
            );
            return LnkParseResult {
                status: LnkStatus::Failed,
                header: None,
                link_info: None,
                string_data: LnkStringData::default(),
                tracker_data: None,
                known_folder_id: None,
                known_folder_offset: None,
                environment_path: None,
                icon_environment_path: None,
                darwin_data: None,
                shim_layer_name: None,
                console_code_page: None,
                special_folder_data: None,
                target_id_list: None,
                vista_and_above_id_list: None,
                property_store_data: Vec::new(),
                extra_data_blocks: Vec::new(),
                extra_blocks_omitted: 0,
                trailing_zero_padding_bytes: 0,
                canonical_target_path: None,
                source_offsets: LnkSourceOffsets::default(),
                warnings,
                warnings_omitted,
                coverage_notes: Vec::new(),
                coverage_notes_omitted: 0,
                coverage_complete: false,
                is_valid: false,
            };
        }

        if buf.len() > options.max_file_size {
            let mut warnings = Vec::new();
            let mut warnings_omitted = 0;
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "File size {} exceeds protective maximum LNK limit {}",
                    buf.len(),
                    options.max_file_size
                ),
            );
            return LnkParseResult {
                status: LnkStatus::Partial,
                header: None,
                link_info: None,
                string_data: LnkStringData::default(),
                tracker_data: None,
                known_folder_id: None,
                known_folder_offset: None,
                environment_path: None,
                icon_environment_path: None,
                darwin_data: None,
                shim_layer_name: None,
                console_code_page: None,
                special_folder_data: None,
                target_id_list: None,
                vista_and_above_id_list: None,
                property_store_data: Vec::new(),
                extra_data_blocks: Vec::new(),
                extra_blocks_omitted: 0,
                trailing_zero_padding_bytes: 0,
                canonical_target_path: None,
                source_offsets: LnkSourceOffsets::default(),
                warnings,
                warnings_omitted,
                coverage_notes: Vec::new(),
                coverage_notes_omitted: 0,
                coverage_complete: false,
                is_valid: false,
            };
        }

        Self::parse_with_options(&buf, options)
    }

    /// Parse LNK bytes with explicit parser options.
    pub fn parse_with_options(data: &[u8], options: &LnkParserOptions) -> LnkParseResult {
        let mut warnings = Vec::new();
        let mut warnings_omitted = 0u64;
        let mut coverage_notes = Vec::new();
        let mut coverage_notes_omitted = 0u64;
        let mut source_offsets = LnkSourceOffsets::default();

        if data.len() > options.max_file_size {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "File size {} exceeds maximum LNK limit {}",
                    data.len(),
                    options.max_file_size
                ),
            );
            return LnkParseResult {
                status: LnkStatus::Partial,
                header: None,
                link_info: None,
                string_data: LnkStringData::default(),
                tracker_data: None,
                known_folder_id: None,
                known_folder_offset: None,
                environment_path: None,
                icon_environment_path: None,
                darwin_data: None,
                shim_layer_name: None,
                console_code_page: None,
                special_folder_data: None,
                target_id_list: None,
                vista_and_above_id_list: None,
                property_store_data: Vec::new(),
                extra_data_blocks: Vec::new(),
                extra_blocks_omitted: 0,
                trailing_zero_padding_bytes: 0,
                canonical_target_path: None,
                source_offsets,
                warnings,
                warnings_omitted,
                coverage_notes,
                coverage_notes_omitted,
                coverage_complete: false,
                is_valid: false,
            };
        }

        if data.len() < 76 {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "File size {} is less than minimum LNK header size (76)",
                    data.len()
                ),
            );
            return LnkParseResult {
                status: LnkStatus::Failed,
                header: None,
                link_info: None,
                string_data: LnkStringData::default(),
                tracker_data: None,
                known_folder_id: None,
                known_folder_offset: None,
                environment_path: None,
                icon_environment_path: None,
                darwin_data: None,
                shim_layer_name: None,
                console_code_page: None,
                special_folder_data: None,
                target_id_list: None,
                vista_and_above_id_list: None,
                property_store_data: Vec::new(),
                extra_data_blocks: Vec::new(),
                extra_blocks_omitted: 0,
                trailing_zero_padding_bytes: 0,
                canonical_target_path: None,
                source_offsets,
                warnings,
                warnings_omitted,
                coverage_notes,
                coverage_notes_omitted,
                coverage_complete: false,
                is_valid: false,
            };
        }

        let header_size = match get_u32_le(data, 0) {
            Some(sz) => sz,
            None => {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    "Failed to read HeaderSize".to_string(),
                );
                return LnkParseResult {
                    status: LnkStatus::Failed,
                    header: None,
                    link_info: None,
                    string_data: LnkStringData::default(),
                    tracker_data: None,
                    known_folder_id: None,
                    known_folder_offset: None,
                    environment_path: None,
                    icon_environment_path: None,
                    darwin_data: None,
                    shim_layer_name: None,
                    console_code_page: None,
                    special_folder_data: None,
                    target_id_list: None,
                    vista_and_above_id_list: None,
                    property_store_data: Vec::new(),
                    extra_data_blocks: Vec::new(),
                    extra_blocks_omitted: 0,
                    trailing_zero_padding_bytes: 0,
                    canonical_target_path: None,
                    source_offsets,
                    warnings,
                    warnings_omitted,
                    coverage_notes,
                    coverage_notes_omitted,
                    coverage_complete: false,
                    is_valid: false,
                };
            }
        };

        if header_size != 0x4C {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!("HeaderSize is 0x{:X}, expected 0x4C", header_size),
            );
        }

        let mut clsid_bytes = [0u8; 16];
        if let Some(clsid_slice) = data.get(4..20) {
            clsid_bytes.copy_from_slice(clsid_slice);
        }
        let link_clsid = format_guid(&clsid_bytes);

        if clsid_bytes != Self::SHELL_LINK_CLSID {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "LinkCLSID {} does not match standard Shell Link CLSID",
                    link_clsid
                ),
            );
        }

        let valid_header = header_size == 0x4C && clsid_bytes == Self::SHELL_LINK_CLSID;

        source_offsets.header_offset = 0;
        source_offsets.header_size = 76;
        if !valid_header {
            return LnkParseResult {
                status: LnkStatus::Failed,
                header: None,
                link_info: None,
                string_data: LnkStringData::default(),
                tracker_data: None,
                known_folder_id: None,
                known_folder_offset: None,
                environment_path: None,
                icon_environment_path: None,
                darwin_data: None,
                shim_layer_name: None,
                console_code_page: None,
                special_folder_data: None,
                target_id_list: None,
                vista_and_above_id_list: None,
                property_store_data: Vec::new(),
                extra_data_blocks: Vec::new(),
                extra_blocks_omitted: 0,
                trailing_zero_padding_bytes: 0,
                canonical_target_path: None,
                source_offsets,
                warnings,
                warnings_omitted,
                coverage_notes,
                coverage_notes_omitted,
                coverage_complete: false,
                is_valid: false,
            };
        }

        let link_flags = get_u32_le(data, 20).unwrap_or(0);
        let file_attributes = get_u32_le(data, 24).unwrap_or(0);

        let creation_ft = get_i64_le(data, 28).unwrap_or(0);
        let access_ft = get_i64_le(data, 36).unwrap_or(0);
        let write_ft = get_i64_le(data, 44).unwrap_or(0);
        let creation_time = filetime_to_datetime(creation_ft);
        let access_time = filetime_to_datetime(access_ft);
        let write_time = filetime_to_datetime(write_ft);
        for (name, raw, parsed) in [
            ("CreationTime", creation_ft, creation_time.as_ref()),
            ("AccessTime", access_ft, access_time.as_ref()),
            ("WriteTime", write_ft, write_time.as_ref()),
        ] {
            if raw != 0 && parsed.is_none() {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!(
                        "{name} FILETIME value 0x{:016X} is not representable",
                        raw as u64
                    ),
                );
            }
        }

        let file_size = get_u32_le(data, 52).unwrap_or(0);
        let icon_index = get_i32_le(data, 56).unwrap_or(0);
        let show_command = get_u32_le(data, 60).unwrap_or(0);
        let hot_key = get_u16_le(data, 64).unwrap_or(0);

        if !matches!(show_command, 1 | 3 | 7) {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "ShowCommand is 0x{show_command:08X}; expected SW_SHOWNORMAL (1), \
                     SW_SHOWMAXIMIZED (3), or SW_SHOWMINNOACTIVE (7)"
                ),
            );
        }
        let reserved1 = get_u16_le(data, 66).unwrap_or(0);
        let reserved2 = get_u32_le(data, 68).unwrap_or(0);
        let reserved3 = get_u32_le(data, 72).unwrap_or(0);
        if reserved1 != 0 || reserved2 != 0 || reserved3 != 0 {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "ShellLinkHeader reserved fields are non-zero: \
                     Reserved1=0x{reserved1:04X}, Reserved2=0x{reserved2:08X}, \
                     Reserved3=0x{reserved3:08X}"
                ),
            );
        }
        if link_flags & 0xF800_0000 != 0 {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!("LinkFlags contains reserved high bits: 0x{link_flags:08X}"),
            );
        }

        let has_link_target_id_list = (link_flags & 0x00000001) != 0;
        let has_link_info = (link_flags & 0x00000002) != 0;
        let has_name = (link_flags & 0x00000004) != 0;
        let has_relative_path = (link_flags & 0x00000008) != 0;
        let has_working_dir = (link_flags & 0x00000010) != 0;
        let has_arguments = (link_flags & 0x00000020) != 0;
        let has_icon_location = (link_flags & 0x00000040) != 0;
        let is_unicode = (link_flags & 0x00000080) != 0;
        let force_no_link_info = (link_flags & 0x00000100) != 0;

        let header_info = LnkHeaderInfo {
            header_size,
            link_clsid,
            link_flags,
            file_attributes,
            creation_time,
            access_time,
            write_time,
            file_size,
            icon_index,
            show_command,
            hot_key,
            has_link_target_id_list,
            has_link_info,
            has_name,
            has_relative_path,
            has_working_dir,
            has_arguments,
            has_icon_location,
            is_unicode,
            force_no_link_info,
        };

        let mut offset = 76usize;
        let mut target_id_list = None;

        // 1. LinkTargetIDList: validate item boundaries even though shell-item
        // payload semantics are intentionally outside the current parser scope.
        if has_link_target_id_list {
            if let Some(id_list_size_u16) = get_u16_le(data, offset) {
                let id_list_size = id_list_size_u16 as usize;
                source_offsets.id_list_offset = Some(offset);
                if let Some(full_id_list_size) = id_list_size.checked_add(2) {
                    source_offsets.id_list_size =
                        Some(full_id_list_size.min(data.len().saturating_sub(offset)));
                    match offset.checked_add(full_id_list_size) {
                        Some(end) if end <= data.len() => {
                            target_id_list = Some(parse_item_id_list(
                                &data[offset + 2..end],
                                id_list_size_u16 as u32,
                                "LinkTargetIDList",
                                &mut warnings,
                                &mut warnings_omitted,
                            ));
                            record_coverage_note(
                                &mut coverage_notes,
                                &mut coverage_notes_omitted,
                                "LinkTargetIDList item boundaries were validated, but shell-item payload semantics were not resolved"
                                    .to_string(),
                            );
                            offset = end;
                        }
                        _ => {
                            record_warning(
                                &mut warnings,
                                &mut warnings_omitted,
                                "LinkTargetIDList bounds exceeded buffer length".to_string(),
                            );
                            offset = data.len();
                        }
                    }
                } else {
                    record_warning(
                        &mut warnings,
                        &mut warnings_omitted,
                        "LinkTargetIDList size overflowed addressable bounds".to_string(),
                    );
                    offset = data.len();
                }
            } else {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    "Truncated LinkTargetIDList header".to_string(),
                );
                offset = data.len();
            }
        }

        // 2. LinkInfo
        let mut link_info = None;
        // HasLinkInfo controls physical presence. ForceNoLinkInfo affects target
        // resolution, but does not remove the serialized structure.
        if has_link_info {
            if offset + 4 <= data.len() {
                if let Some(info_size_u32) = get_u32_le(data, offset) {
                    let info_size = info_size_u32 as usize;
                    if info_size >= 28
                        && offset
                            .checked_add(info_size)
                            .is_some_and(|o| o <= data.len())
                    {
                        source_offsets.link_info_offset = Some(offset);
                        source_offsets.link_info_size = Some(info_size);
                        link_info = Self::parse_link_info(
                            &data[offset..offset + info_size],
                            &mut warnings,
                            &mut warnings_omitted,
                        );
                        offset += info_size;
                    } else {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!("Invalid LinkInfo size {} at offset {}", info_size, offset),
                        );
                        offset = data.len();
                    }
                }
            } else {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!("Truncated LinkInfo at offset {}", offset),
                );
                offset = data.len();
            }
        }

        // 3. StringData
        let mut string_data = LnkStringData::default();
        let string_start_offset = offset;
        let mut string_layout_complete = true;

        let parse_string_field = |flag: bool,
                                  flag_name: &str,
                                  max_characters: Option<usize>,
                                  off: &mut usize,
                                  buf: &[u8],
                                  layout_complete: &mut bool,
                                  warns: &mut Vec<String>,
                                  omitted: &mut u64|
         -> Option<String> {
            if !flag {
                return None;
            }
            if !*layout_complete {
                record_warning(
                    warns,
                    omitted,
                    format!(
                        "StringData field ({flag_name}) was not parsed because a preceding \
                         field's boundary could not be established"
                    ),
                );
                return None;
            }
            if *off >= buf.len() {
                record_warning(
                    warns,
                    omitted,
                    format!(
                        "StringData field ({}) flag set but offset {} is out of bounds",
                        flag_name, off
                    ),
                );
                *layout_complete = false;
                return None;
            }
            if let (Some(maximum), Some(count)) = (max_characters, get_u16_le(buf, *off)) {
                if count as usize > maximum {
                    record_warning(
                        warns,
                        omitted,
                        format!(
                            "StringData field ({flag_name}) declares {count} characters; \
                             the format limit is {maximum}"
                        ),
                    );
                }
            }
            if let Some((s, next)) =
                Self::read_string_data(&buf[*off..], is_unicode, warns, omitted)
            {
                *off = off.saturating_add(next);
                Some(s)
            } else {
                *layout_complete = false;
                None
            }
        };

        string_data.name_description = parse_string_field(
            has_name,
            "HasName",
            Some(260),
            &mut offset,
            data,
            &mut string_layout_complete,
            &mut warnings,
            &mut warnings_omitted,
        );
        string_data.relative_path = parse_string_field(
            has_relative_path,
            "HasRelativePath",
            Some(260),
            &mut offset,
            data,
            &mut string_layout_complete,
            &mut warnings,
            &mut warnings_omitted,
        );
        string_data.working_dir = parse_string_field(
            has_working_dir,
            "HasWorkingDir",
            Some(260),
            &mut offset,
            data,
            &mut string_layout_complete,
            &mut warnings,
            &mut warnings_omitted,
        );
        string_data.command_line_arguments = parse_string_field(
            has_arguments,
            "HasArguments",
            None,
            &mut offset,
            data,
            &mut string_layout_complete,
            &mut warnings,
            &mut warnings_omitted,
        );
        string_data.icon_location = parse_string_field(
            has_icon_location,
            "HasIconLocation",
            Some(260),
            &mut offset,
            data,
            &mut string_layout_complete,
            &mut warnings,
            &mut warnings_omitted,
        );

        if offset > string_start_offset {
            source_offsets.string_data_offset = Some(string_start_offset);
            source_offsets.string_data_size = Some(offset - string_start_offset);
        }

        // A failed counted string destroys the boundary needed to locate all
        // following StringData and ExtraData. Never reinterpret its bytes as a
        // different structure.
        if !string_layout_complete {
            offset = data.len();
        }

        // 4. ExtraData Blocks (bounded to max 100 blocks)
        let mut tracker_data = None;
        let mut known_folder_id = None;
        let mut known_folder_offset = None;
        let mut environment_path = None;
        let mut icon_environment_path = None;
        let mut darwin_data = None;
        let mut shim_layer_name = None;
        let mut console_code_page = None;
        let mut special_folder_data = None;
        let mut vista_and_above_id_list = None;
        let mut property_store_data = Vec::new();
        let mut extra_data_blocks = Vec::new();
        let mut extra_blocks_omitted = 0u64;
        let extra_start_offset = offset;
        let mut terminal_seen = false;
        let mut saw_environment_block = false;
        let mut saw_icon_environment_block = false;
        let mut saw_darwin_block = false;
        let mut saw_shim_block = false;

        while offset + 4 <= data.len() {
            let block_size = match get_u32_le(data, offset) {
                Some(sz) => sz as usize,
                None => break,
            };

            if block_size < 8 {
                if block_size < 4 {
                    // The TerminalBlock is a four-byte value less than four.
                    terminal_seen = true;
                    offset += 4;
                    break;
                }
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!(
                        "ExtraData block size {} at offset {} is less than 8 bytes minimum",
                        block_size, offset
                    ),
                );
                break;
            }

            if offset
                .checked_add(block_size)
                .is_none_or(|end| end > data.len())
            {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!(
                        "ExtraData block size {} at offset {} exceeds remaining buffer",
                        block_size, offset
                    ),
                );
                break;
            }

            let block_bytes = &data[offset..offset + block_size];
            let sig = get_u32_le(block_bytes, 4).unwrap_or(0);
            let sig_hex = format!("0x{:08X}", sig);
            let name = match sig {
                0xA0000001 => "EnvironmentVariableDataBlock".to_string(),
                0xA0000002 => "ConsoleDataBlock".to_string(),
                0xA0000003 => "TrackerDataBlock".to_string(),
                0xA0000004 => "ConsoleFEDataBlock".to_string(),
                0xA0000005 => "SpecialFolderDataBlock".to_string(),
                0xA0000006 => "DarwinDataBlock".to_string(),
                0xA0000007 => "IconEnvironmentDataBlock".to_string(),
                0xA0000008 => "ShimDataBlock".to_string(),
                0xA0000009 => "PropertyStoreDataBlock".to_string(),
                0xA000000B => "KnownFolderDataBlock".to_string(),
                0xA000000C => "VistaAndAboveIDListDataBlock".to_string(),
                _ => {
                    record_coverage_note(
                        &mut coverage_notes,
                        &mut coverage_notes_omitted,
                        format!(
                            "ExtraData signature 0x{sig:08X} at offset {offset} is unsupported"
                        ),
                    );
                    format!("UnknownBlock(0x{:08X})", sig)
                }
            };

            match sig {
                0xA0000003 => {
                    if block_size != 0x60 {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "TrackerDataBlock size is 0x{block_size:X}; expected exactly 0x60"
                            ),
                        );
                    }
                    if block_size >= 0x60 {
                        let length = get_u32_le(block_bytes, 8).unwrap_or(0);
                        let version = get_u32_le(block_bytes, 12).unwrap_or(0);
                        if length != 0x58 {
                            record_warning(
                                &mut warnings,
                                &mut warnings_omitted,
                                format!("TrackerDataBlock Length is 0x{length:X}; expected 0x58"),
                            );
                        }
                        if version != 0 {
                            record_warning(
                                &mut warnings,
                                &mut warnings_omitted,
                                format!("TrackerDataBlock Version is 0x{version:X}; expected zero"),
                            );
                        }
                        let machine_bytes = block_bytes.get(16..32).unwrap_or(&[]);
                        let machine_id = read_null_terminated_ansi(
                            machine_bytes,
                            &mut warnings,
                            &mut warnings_omitted,
                        );
                        let droid_vol = format_guid(block_bytes.get(32..48).unwrap_or(&[]));
                        let droid_obj = format_guid(block_bytes.get(48..64).unwrap_or(&[]));
                        let droid_birth_vol = format_guid(block_bytes.get(64..80).unwrap_or(&[]));
                        let droid_birth_obj = format_guid(block_bytes.get(80..96).unwrap_or(&[]));

                        tracker_data = Some(LnkTrackerData {
                            length,
                            version,
                            machine_id,
                            droid_volume_id: droid_vol,
                            droid_object_id: droid_obj,
                            droid_birth_volume_id: droid_birth_vol,
                            droid_birth_object_id: droid_birth_obj,
                        });
                    }
                }

                0xA0000001 | 0xA0000007 => {
                    saw_environment_block |= sig == 0xA0000001;
                    saw_icon_environment_block |= sig == 0xA0000007;
                    if block_size != 0x314 {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "{} size is 0x{block_size:X}; expected exactly 0x314",
                                if sig == 0xA0000001 {
                                    "EnvironmentVariableDataBlock"
                                } else {
                                    "IconEnvironmentDataBlock"
                                }
                            ),
                        );
                    }
                    let parsed_path = (block_size >= 0x314)
                        .then(|| {
                            parse_environment_data_block(
                                block_bytes,
                                &mut warnings,
                                &mut warnings_omitted,
                            )
                        })
                        .flatten();
                    if sig == 0xA0000001 {
                        environment_path = parsed_path;
                    } else {
                        icon_environment_path = parsed_path;
                    }
                }
                0xA0000006 => {
                    saw_darwin_block = true;
                    if block_size != 0x314 {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "DarwinDataBlock size is 0x{block_size:X}; expected exactly 0x314"
                            ),
                        );
                    }
                    if block_size >= 0x314 {
                        darwin_data = parse_environment_data_block(
                            block_bytes,
                            &mut warnings,
                            &mut warnings_omitted,
                        );
                    }
                }
                0xA0000008 => {
                    saw_shim_block = true;
                    if block_size < 10 {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "ShimDataBlock size is 0x{block_size:X}; expected at least 0xA"
                            ),
                        );
                    } else {
                        shim_layer_name = read_null_terminated_utf16(
                            &block_bytes[8..],
                            &mut warnings,
                            &mut warnings_omitted,
                        );
                    }
                }
                0xA0000004 => {
                    if block_size != 12 {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "ConsoleFEDataBlock size is 0x{block_size:X}; expected exactly 0xC"
                            ),
                        );
                    }
                    if block_size >= 12 {
                        console_code_page = get_u32_le(block_bytes, 8);
                    }
                }
                0xA0000005 => {
                    if block_size != 16 {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "SpecialFolderDataBlock size is 0x{block_size:X}; expected exactly 0x10"
                            ),
                        );
                    }
                    if block_size >= 16 {
                        special_folder_data = Some(LnkSpecialFolderData {
                            special_folder_id: get_u32_le(block_bytes, 8).unwrap_or(0),
                            offset: get_u32_le(block_bytes, 12).unwrap_or(0),
                        });
                    }
                }
                0xA0000009 => {
                    property_store_data.push(parse_property_store_data_block(
                        block_bytes,
                        offset,
                        &mut warnings,
                        &mut warnings_omitted,
                    ));
                    record_coverage_note(
                        &mut coverage_notes,
                        &mut coverage_notes_omitted,
                        format!(
                            "PropertyStoreDataBlock at offset {offset} was structurally bounded, but serialized property values were not semantically decoded"
                        ),
                    );
                }
                0xA000000C => {
                    vista_and_above_id_list = Some(parse_item_id_list(
                        &block_bytes[8..],
                        (block_size - 8) as u32,
                        "VistaAndAboveIDListDataBlock",
                        &mut warnings,
                        &mut warnings_omitted,
                    ));
                    record_coverage_note(
                        &mut coverage_notes,
                        &mut coverage_notes_omitted,
                        format!(
                            "VistaAndAboveIDListDataBlock at offset {offset} had bounded item records, but shell-item payload semantics were not resolved"
                        ),
                    );
                }
                0xA000000B => {
                    if block_size != 0x1C {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "KnownFolderDataBlock size is 0x{block_size:X}; expected exactly 0x1C"
                            ),
                        );
                    }
                    if block_size >= 24 {
                        if let Some(kf_bytes) = block_bytes.get(8..24) {
                            known_folder_id = Some(format_guid(kf_bytes));
                        }
                    }
                    if block_size >= 28 {
                        known_folder_offset = get_u32_le(block_bytes, 24);
                    }
                }
                0xA0000002 => {
                    record_coverage_note(
                        &mut coverage_notes,
                        &mut coverage_notes_omitted,
                        format!(
                            "ConsoleDataBlock at offset {offset} was structurally bounded, but console properties were not semantically decoded"
                        ),
                    );
                }
                _ => {}
            }

            if extra_data_blocks.len() < 100 {
                extra_data_blocks.push(LnkExtraDataBlock {
                    block_size: block_size as u32,
                    signature: sig,
                    signature_hex: sig_hex,
                    name,
                });
            } else {
                extra_blocks_omitted = extra_blocks_omitted.saturating_add(1);
            }

            offset += block_size;
        }

        if string_layout_complete && !terminal_seen {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "ExtraData TerminalBlock is missing at or after offset {extra_start_offset}"
                ),
            );
        }
        let trailing_zero_padding_bytes = if terminal_seen && offset < data.len() {
            let trailing = &data[offset..];
            if trailing.iter().all(|byte| *byte == 0) {
                trailing.len() as u64
            } else {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!(
                        "{} non-padding trailing bytes follow the ExtraData TerminalBlock at offset {}",
                        trailing.len(),
                        offset - 4
                    ),
                );
                0
            }
        } else {
            0
        };
        if string_layout_complete && terminal_seen {
            for (flag_name, flag_set, block_name, block_seen) in [
                (
                    "HasExpString",
                    link_flags & 0x0000_0200 != 0,
                    "EnvironmentVariableDataBlock",
                    saw_environment_block,
                ),
                (
                    "HasDarwinID",
                    link_flags & 0x0000_1000 != 0,
                    "DarwinDataBlock",
                    saw_darwin_block,
                ),
                (
                    "HasExpIcon",
                    link_flags & 0x0000_4000 != 0,
                    "IconEnvironmentDataBlock",
                    saw_icon_environment_block,
                ),
                (
                    "RunWithShimLayer",
                    link_flags & 0x0002_0000 != 0,
                    "ShimDataBlock",
                    saw_shim_block,
                ),
            ] {
                if flag_set != block_seen {
                    record_warning(
                        &mut warnings,
                        &mut warnings_omitted,
                        format!(
                            "{flag_name} is {}, but {block_name} is {}",
                            if flag_set { "set" } else { "clear" },
                            if block_seen { "present" } else { "absent" }
                        ),
                    );
                }
            }
        }

        if offset > extra_start_offset {
            source_offsets.extra_data_offset = Some(extra_start_offset);
            source_offsets.extra_data_size = Some(offset - extra_start_offset);
        }

        let canonical_target_path = resolve_canonical_path(
            if force_no_link_info {
                None
            } else {
                link_info.as_ref()
            },
            &string_data,
            environment_path.as_deref(),
        );

        if has_link_target_id_list && canonical_target_path.is_none() {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                "Shell Link target is encoded only in LinkTargetIDList; canonical target resolution is incomplete"
                    .to_string(),
            );
        }

        let coverage_complete =
            coverage_notes.is_empty() && coverage_notes_omitted == 0 && extra_blocks_omitted == 0;

        let status = if warnings.is_empty() && warnings_omitted == 0 {
            LnkStatus::Recognized
        } else {
            LnkStatus::Partial
        };

        LnkParseResult {
            status,
            header: Some(header_info),
            link_info,
            string_data,
            tracker_data,
            known_folder_id,
            known_folder_offset,
            environment_path,
            icon_environment_path,
            darwin_data,
            shim_layer_name,
            console_code_page,
            special_folder_data,
            target_id_list,
            vista_and_above_id_list,
            property_store_data,
            extra_data_blocks,
            extra_blocks_omitted,
            trailing_zero_padding_bytes,
            canonical_target_path,
            source_offsets,
            warnings,
            warnings_omitted,
            coverage_notes,
            coverage_notes_omitted,
            coverage_complete,
            is_valid: true,
        }
    }

    fn parse_link_info(
        buf: &[u8],
        warnings: &mut Vec<String>,
        warnings_omitted: &mut u64,
    ) -> Option<LnkLinkInfo> {
        let size = get_u32_le(buf, 0)?;
        let header_size = get_u32_le(buf, 4)?;
        let flags = get_u32_le(buf, 8)?;
        let vol_id_off = get_u32_le(buf, 12)? as usize;
        let local_path_off = get_u32_le(buf, 16)? as usize;
        let net_link_off = get_u32_le(buf, 20)? as usize;
        let common_suffix_off = get_u32_le(buf, 24)? as usize;

        let local_path_unicode_off = if header_size >= 0x24 && buf.len() >= 32 {
            get_u32_le(buf, 28).map(|o| o as usize)
        } else {
            None
        };
        let common_suffix_unicode_off = if header_size >= 0x24 && buf.len() >= 36 {
            get_u32_le(buf, 32).map(|o| o as usize)
        } else {
            None
        };

        let header_size_usize = header_size as usize;
        if size as usize != buf.len() {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "LinkInfoSize declares {} bytes, but the bounded structure contains {}",
                    size,
                    buf.len()
                ),
            );
        }
        if (header_size != 0x1C && header_size < 0x24) || header_size_usize > buf.len() {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "Invalid LinkInfoHeaderSize 0x{header_size:X} for LinkInfo size {}",
                    buf.len()
                ),
            );
            return Some(LnkLinkInfo {
                link_info_size: size,
                link_info_header_size: header_size,
                link_info_flags: flags,
                local_base_path: None,
                common_path_suffix: None,
                volume_info: None,
                network_info: None,
            });
        }
        if flags & !0x03 != 0 {
            record_warning(
                warnings,
                warnings_omitted,
                format!("LinkInfoFlags contains undefined bits: 0x{flags:08X}"),
            );
        }
        if flags & 0x01 == 0 && (vol_id_off != 0 || local_path_off != 0) {
            record_warning(
                warnings,
                warnings_omitted,
                "LinkInfo volume/local-path offsets are non-zero while their presence flag is clear"
                    .to_string(),
            );
        }
        if flags & 0x02 == 0 && net_link_off != 0 {
            record_warning(
                warnings,
                warnings_omitted,
                "LinkInfo network offset is non-zero while its presence flag is clear".to_string(),
            );
        }
        let link_field_offsets = [
            vol_id_off,
            local_path_off,
            net_link_off,
            common_suffix_off,
            local_path_unicode_off.unwrap_or(0),
            common_suffix_unicode_off.unwrap_or(0),
        ];

        let local_base_path = if flags & 0x01 != 0 {
            if local_path_off < header_size_usize || local_path_off >= buf.len() {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!("LocalBasePathOffset {local_path_off} is outside LinkInfo data"),
                );
                None
            } else if header_size >= 0x24 {
                match local_path_unicode_off {
                    Some(u_off) if u_off >= header_size_usize && u_off < buf.len() => {
                        read_null_terminated_utf16(
                            string_region_to_next_offset(buf, u_off, &link_field_offsets),
                            warnings,
                            warnings_omitted,
                        )
                    }
                    _ => {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            "LocalBasePathOffsetUnicode is missing or outside LinkInfo data; using the ANSI field"
                                .to_string(),
                        );
                        Some(read_null_terminated_ansi(
                            string_region_to_next_offset(buf, local_path_off, &link_field_offsets),
                            warnings,
                            warnings_omitted,
                        ))
                    }
                }
            } else {
                Some(read_null_terminated_ansi(
                    string_region_to_next_offset(buf, local_path_off, &link_field_offsets),
                    warnings,
                    warnings_omitted,
                ))
            }
        } else {
            None
        };

        let ansi_common_suffix =
            if common_suffix_off >= header_size_usize && common_suffix_off < buf.len() {
                Some(read_null_terminated_ansi(
                    string_region_to_next_offset(buf, common_suffix_off, &link_field_offsets),
                    warnings,
                    warnings_omitted,
                ))
            } else {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!("CommonPathSuffixOffset {common_suffix_off} is outside LinkInfo data"),
                );
                None
            };
        let common_path_suffix = if header_size >= 0x24 {
            match common_suffix_unicode_off {
                Some(u_off) if u_off >= header_size_usize && u_off < buf.len() => {
                    read_null_terminated_utf16(
                        string_region_to_next_offset(buf, u_off, &link_field_offsets),
                        warnings,
                        warnings_omitted,
                    )
                }
                _ => {
                    record_warning(
                        warnings,
                        warnings_omitted,
                        "CommonPathSuffixOffsetUnicode is missing or outside LinkInfo data; using the ANSI field"
                            .to_string(),
                    );
                    ansi_common_suffix
                }
            }
        } else {
            ansi_common_suffix
        };

        let volume_info = if (flags & 0x01) != 0
            && vol_id_off >= header_size_usize
            && vol_id_off.checked_add(16).is_some_and(|e| e <= buf.len())
        {
            let v_size = get_u32_le(&buf[vol_id_off..], 0).unwrap_or(0) as usize;
            if v_size <= 16 || vol_id_off.checked_add(v_size).is_none_or(|e| e > buf.len()) {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!("Invalid VolumeID size {} at offset {}", v_size, vol_id_off),
                );
                None
            } else {
                let v_buf = &buf[vol_id_off..vol_id_off + v_size];
                let drive_type = get_u32_le(v_buf, 4).unwrap_or(0);
                let drive_sn = get_u32_le(v_buf, 8).unwrap_or(0);
                let label_off = get_u32_le(v_buf, 12).unwrap_or(0) as usize;

                let drive_type_desc = match drive_type {
                    0 => "DRIVE_UNKNOWN",
                    1 => "DRIVE_NO_ROOT_DIR",
                    2 => "DRIVE_REMOVABLE",
                    3 => "DRIVE_FIXED",
                    4 => "DRIVE_REMOTE",
                    5 => "DRIVE_CDROM",
                    6 => "DRIVE_RAMDISK",
                    _ => "DRIVE_CUSTOM",
                }
                .to_string();
                if drive_type > 6 {
                    record_warning(
                        warnings,
                        warnings_omitted,
                        format!("VolumeID DriveType {drive_type} is not defined by MS-SHLLINK"),
                    );
                }

                let volume_label = if label_off == 0x14 && v_size >= 20 {
                    let label_unicode_off = get_u32_le(v_buf, 16).unwrap_or(0) as usize;
                    if label_unicode_off >= 20 && label_unicode_off < v_size {
                        read_null_terminated_utf16(
                            &v_buf[label_unicode_off..],
                            warnings,
                            warnings_omitted,
                        )
                        .unwrap_or_default()
                    } else {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            format!(
                                "VolumeLabelOffsetUnicode {label_unicode_off} is outside VolumeID data"
                            ),
                        );
                        String::new()
                    }
                } else if label_off >= 16 && label_off < v_size {
                    read_null_terminated_ansi(&v_buf[label_off..], warnings, warnings_omitted)
                } else {
                    record_warning(
                        warnings,
                        warnings_omitted,
                        format!("VolumeLabelOffset {label_off} is outside VolumeID data"),
                    );
                    String::new()
                };

                Some(LnkVolumeInfo {
                    volume_id_size: v_size as u32,
                    drive_type,
                    drive_type_desc,
                    drive_serial_number: drive_sn,
                    drive_serial_hex: format!(
                        "{:04X}-{:04X}",
                        (drive_sn >> 16) as u16,
                        drive_sn as u16
                    ),
                    volume_label,
                })
            }
        } else {
            if (flags & 0x01) != 0 {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!("VolumeID offset {} out of bounds", vol_id_off),
                );
            }
            None
        };

        let network_info = if (flags & 0x02) != 0
            && net_link_off >= header_size_usize
            && net_link_off.checked_add(20).is_some_and(|e| e <= buf.len())
        {
            let n_size = get_u32_le(&buf[net_link_off..], 0).unwrap_or(0) as usize;
            if n_size < 20
                || net_link_off
                    .checked_add(n_size)
                    .is_none_or(|e| e > buf.len())
            {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!(
                        "Invalid CommonNetworkRelativeLink size {} at offset {}",
                        n_size, net_link_off
                    ),
                );
                None
            } else {
                let n_buf = &buf[net_link_off..net_link_off + n_size];
                let n_flags = get_u32_le(n_buf, 4).unwrap_or(0);
                let net_name_off = get_u32_le(n_buf, 8).unwrap_or(0) as usize;
                let device_name_off = get_u32_le(n_buf, 12).unwrap_or(0) as usize;
                if n_flags & !0x03 != 0 {
                    record_warning(
                        warnings,
                        warnings_omitted,
                        format!(
                            "CommonNetworkRelativeLinkFlags contains undefined bits: 0x{n_flags:08X}"
                        ),
                    );
                }

                let raw_provider_type = get_u32_le(n_buf, 16).unwrap_or(0);
                let net_provider_type = if n_flags & 0x02 != 0 {
                    Some(raw_provider_type)
                } else {
                    if raw_provider_type != 0 {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            "NetworkProviderType is non-zero while ValidNetType is clear"
                                .to_string(),
                        );
                    }
                    None
                };

                let has_unicode_offsets = net_name_off > 0x14;
                let data_floor = if has_unicode_offsets { 28 } else { 20 };
                let (net_name_u_off, device_name_u_off) = if has_unicode_offsets {
                    if n_size >= 28 {
                        (
                            get_u32_le(n_buf, 20).map(|v| v as usize),
                            get_u32_le(n_buf, 24).map(|v| v as usize),
                        )
                    } else {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            "Unicode network offsets are indicated, but the structure is shorter than 28 bytes"
                                .to_string(),
                        );
                        (None, None)
                    }
                } else {
                    (None, None)
                };
                let network_field_offsets = [
                    net_name_off,
                    device_name_off,
                    net_name_u_off.unwrap_or(0),
                    device_name_u_off.unwrap_or(0),
                ];
                let ansi_net_name = if net_name_off >= data_floor && net_name_off < n_size {
                    Some(read_null_terminated_ansi(
                        string_region_to_next_offset(n_buf, net_name_off, &network_field_offsets),
                        warnings,
                        warnings_omitted,
                    ))
                } else {
                    record_warning(
                        warnings,
                        warnings_omitted,
                        format!(
                            "NetNameOffset {net_name_off} is outside CommonNetworkRelativeLink data"
                        ),
                    );
                    None
                };

                let net_name = if has_unicode_offsets {
                    match net_name_u_off {
                        Some(u_off) if u_off >= 28 && u_off < n_size => read_null_terminated_utf16(
                            string_region_to_next_offset(n_buf, u_off, &network_field_offsets),
                            warnings,
                            warnings_omitted,
                        )
                        .unwrap_or_default(),
                        _ => {
                            record_warning(
                                warnings,
                                warnings_omitted,
                                "NetNameOffsetUnicode is missing or outside network-link data; using the ANSI field"
                                    .to_string(),
                            );
                            ansi_net_name.unwrap_or_default()
                        }
                    }
                } else {
                    ansi_net_name.unwrap_or_default()
                };

                let device_name = if n_flags & 0x01 != 0 {
                    let ansi_device = if device_name_off >= data_floor && device_name_off < n_size {
                        Some(read_null_terminated_ansi(
                            string_region_to_next_offset(
                                n_buf,
                                device_name_off,
                                &network_field_offsets,
                            ),
                            warnings,
                            warnings_omitted,
                        ))
                    } else {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            format!(
                                "DeviceNameOffset {device_name_off} is outside CommonNetworkRelativeLink data"
                            ),
                        );
                        None
                    };
                    if has_unicode_offsets {
                        match device_name_u_off {
                            Some(u_off) if u_off >= 28 && u_off < n_size => {
                                read_null_terminated_utf16(
                                    string_region_to_next_offset(
                                        n_buf,
                                        u_off,
                                        &network_field_offsets,
                                    ),
                                    warnings,
                                    warnings_omitted,
                                )
                            }
                            _ => {
                                record_warning(
                                    warnings,
                                    warnings_omitted,
                                    "DeviceNameOffsetUnicode is missing or outside network-link data; using the ANSI field"
                                        .to_string(),
                                );
                                ansi_device
                            }
                        }
                    } else {
                        ansi_device
                    }
                } else {
                    if device_name_off != 0 {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            "DeviceNameOffset is non-zero while ValidDevice is clear".to_string(),
                        );
                    }
                    None
                };

                Some(LnkNetworkInfo {
                    flags: n_flags,
                    net_provider_type,
                    net_name,
                    device_name,
                })
            }
        } else {
            if (flags & 0x02) != 0 {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!(
                        "CommonNetworkRelativeLink offset {} out of bounds",
                        net_link_off
                    ),
                );
            }
            None
        };

        Some(LnkLinkInfo {
            link_info_size: size,
            link_info_header_size: header_size,
            link_info_flags: flags,
            local_base_path,
            common_path_suffix,
            volume_info,
            network_info,
        })
    }

    fn read_string_data(
        buf: &[u8],
        is_unicode: bool,
        warnings: &mut Vec<String>,
        warnings_omitted: &mut u64,
    ) -> Option<(String, usize)> {
        if buf.len() < 2 {
            record_warning(
                warnings,
                warnings_omitted,
                "Truncated StringData character count".to_string(),
            );
            return None;
        }
        let count = get_u16_le(buf, 0)? as usize;
        if is_unicode {
            let byte_len = count.checked_mul(2)?;
            if 2 + byte_len <= buf.len() {
                let u16_slice: Vec<u16> = buf[2..2 + byte_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = match String::from_utf16(&u16_slice) {
                    Ok(value) => value,
                    Err(_) => {
                        record_warning(
                            warnings,
                            warnings_omitted,
                            "StringData contains an unpaired UTF-16 surrogate and was decoded lossily"
                                .to_string(),
                        );
                        String::from_utf16_lossy(&u16_slice)
                    }
                };
                Some((s, 2 + byte_len))
            } else {
                record_warning(
                    warnings,
                    warnings_omitted,
                    "Truncated Unicode string in StringData".to_string(),
                );
                None
            }
        } else {
            if 2 + count <= buf.len() {
                let s = decode_ansi_string(&buf[2..2 + count], warnings, warnings_omitted);
                Some((s, 2 + count))
            } else {
                record_warning(
                    warnings,
                    warnings_omitted,
                    "Truncated ANSI string in StringData".to_string(),
                );
                None
            }
        }
    }
}

fn parse_environment_data_block(
    block: &[u8],
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> Option<String> {
    if let Some(unicode_bytes) = block.get(268..788) {
        if let Some(value) = read_null_terminated_utf16(unicode_bytes, warnings, warnings_omitted) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    block.get(8..268).and_then(|ansi_bytes| {
        let value = read_null_terminated_ansi(ansi_bytes, warnings, warnings_omitted);
        (!value.is_empty()).then_some(value)
    })
}

fn parse_item_id_list(
    payload: &[u8],
    declared_size: u32,
    context: &str,
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> LnkTargetIdListInfo {
    let mut position = 0usize;
    let mut item_count = 0u32;
    let mut item_sizes = Vec::new();
    let mut item_sizes_omitted = 0u64;
    let mut terminal_present = false;

    while position < payload.len() {
        if position + 2 > payload.len() {
            record_warning(
                warnings,
                warnings_omitted,
                format!("{context} has an unmatched trailing byte at payload offset {position}"),
            );
            break;
        }

        let item_size = get_u16_le(payload, position).unwrap_or(0);
        if item_size == 0 {
            terminal_present = true;
            position += 2;
            if payload[position..].iter().any(|byte| *byte != 0) {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!(
                        "{context} contains non-zero bytes after its TerminalID at payload offset {position}"
                    ),
                );
            }
            break;
        }
        if item_size < 2 {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "{context} ItemID at payload offset {position} declares invalid size {item_size}"
                ),
            );
            break;
        }

        let item_size_usize = item_size as usize;
        let Some(end) = position.checked_add(item_size_usize) else {
            record_warning(
                warnings,
                warnings_omitted,
                format!("{context} ItemID size overflow at payload offset {position}"),
            );
            break;
        };
        if end > payload.len() {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "{context} ItemID at payload offset {position} declares {item_size} bytes, exceeding the {}-byte payload",
                    payload.len()
                ),
            );
            break;
        }

        item_count = item_count.saturating_add(1);
        if item_sizes.len() < 256 {
            item_sizes.push(item_size);
        } else {
            item_sizes_omitted = item_sizes_omitted.saturating_add(1);
        }
        position = end;
    }

    if !terminal_present {
        record_warning(
            warnings,
            warnings_omitted,
            format!("{context} is missing its two-byte TerminalID"),
        );
    }

    LnkTargetIdListInfo {
        declared_size,
        item_count,
        item_sizes,
        item_sizes_omitted,
        terminal_present,
    }
}

fn parse_property_store_data_block(
    block: &[u8],
    block_offset: usize,
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> LnkPropertyStoreData {
    let mut position = 8usize;
    let mut storage_count = 0u32;
    let mut format_ids = Vec::new();
    let mut format_ids_omitted = 0u64;
    let mut terminal_present = false;

    while position < block.len() {
        if position + 4 > block.len() {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "PropertyStoreDataBlock at offset {block_offset} has a truncated SerializedPropertyStorage size at relative offset {position}"
                ),
            );
            break;
        }

        let storage_size = get_u32_le(block, position).unwrap_or(0) as usize;
        if storage_size == 0 {
            terminal_present = true;
            position += 4;
            if block[position..].iter().any(|byte| *byte != 0) {
                record_warning(
                    warnings,
                    warnings_omitted,
                    format!(
                        "PropertyStoreDataBlock at offset {block_offset} contains non-zero bytes after its terminal storage marker"
                    ),
                );
            }
            break;
        }
        if storage_size < 24 {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "PropertyStoreDataBlock at offset {block_offset} has SerializedPropertyStorage size {storage_size}, below the 24-byte header minimum"
                ),
            );
            break;
        }

        let Some(end) = position.checked_add(storage_size) else {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "PropertyStoreDataBlock at offset {block_offset} storage size overflows at relative offset {position}"
                ),
            );
            break;
        };
        if end > block.len() {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "PropertyStoreDataBlock at offset {block_offset} storage at relative offset {position} declares {storage_size} bytes, exceeding the {}-byte block",
                    block.len()
                ),
            );
            break;
        }

        let version = get_u32_le(block, position + 4).unwrap_or(0);
        if version != 0x5350_5331 {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "PropertyStoreDataBlock at offset {block_offset} storage at relative offset {position} has version 0x{version:08X}; expected 0x53505331"
                ),
            );
        }
        let format_id = format_guid(&block[position + 8..position + 24]);
        storage_count = storage_count.saturating_add(1);
        if format_ids.len() < 32 {
            format_ids.push(format_id);
        } else {
            format_ids_omitted = format_ids_omitted.saturating_add(1);
        }
        position = end;
    }

    if !terminal_present {
        record_warning(
            warnings,
            warnings_omitted,
            format!(
                "PropertyStoreDataBlock at offset {block_offset} is missing its terminal storage marker"
            ),
        );
    }

    LnkPropertyStoreData {
        block_offset,
        storage_count,
        format_ids,
        format_ids_omitted,
        terminal_present,
    }
}

pub fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return "00000000-0000-0000-0000-000000000000".to_string();
    }
    let d1 = get_u32_le(bytes, 0).unwrap_or(0);
    let d2 = get_u16_le(bytes, 4).unwrap_or(0);
    let d3 = get_u16_le(bytes, 6).unwrap_or(0);
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1,
        d2,
        d3,
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn read_null_terminated_ansi(
    buf: &[u8],
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> String {
    let len = match buf.iter().position(|&b| b == 0) {
        Some(length) => length,
        None => {
            record_warning(
                warnings,
                warnings_omitted,
                "ANSI string is not null-terminated within its containing structure".to_string(),
            );
            buf.len()
        }
    };
    decode_ansi_string(&buf[..len], warnings, warnings_omitted)
}

fn string_region_to_next_offset<'a>(
    structure: &'a [u8],
    start: usize,
    offsets: &[usize],
) -> &'a [u8] {
    let end = offsets
        .iter()
        .copied()
        .filter(|candidate| *candidate > start && *candidate <= structure.len())
        .min()
        .unwrap_or(structure.len());
    &structure[start..end]
}

fn read_null_terminated_utf16(
    buf: &[u8],
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> Option<String> {
    if buf.len() < 2 {
        record_warning(
            warnings,
            warnings_omitted,
            "Truncated UTF-16 string".to_string(),
        );
        return None;
    }
    let mut terminated = false;
    let mut u16_units = Vec::new();
    for pair in buf.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            terminated = true;
            break;
        }
        u16_units.push(unit);
    }
    if !terminated {
        record_warning(
            warnings,
            warnings_omitted,
            "UTF-16 string is not null-terminated within its containing structure".to_string(),
        );
        if !buf.len().is_multiple_of(2) {
            record_warning(
                warnings,
                warnings_omitted,
                "UTF-16 string has an unmatched trailing byte".to_string(),
            );
        }
    }
    match String::from_utf16(&u16_units) {
        Ok(value) => Some(value),
        Err(_) => {
            record_warning(
                warnings,
                warnings_omitted,
                "UTF-16 string contains an unpaired surrogate and was decoded lossily".to_string(),
            );
            Some(String::from_utf16_lossy(&u16_units))
        }
    }
}

fn decode_ansi_string(
    bytes: &[u8],
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> String {
    if bytes.iter().any(|byte| !byte.is_ascii()) {
        record_warning(
            warnings,
            warnings_omitted,
            "ANSI string contains non-ASCII bytes; the source code page is unavailable, so a byte-preserving Latin-1 mapping was used"
                .to_string(),
        );
    }
    bytes.iter().map(|&byte| byte as char).collect()
}

fn resolve_canonical_path(
    link_info: Option<&LnkLinkInfo>,
    string_data: &LnkStringData,
    env_path: Option<&str>,
) -> Option<String> {
    let join_paths = |base: &str, suffix: &str| -> String {
        let base_trim = base.trim_end_matches('\\');
        let suffix_trim = suffix.trim_start_matches('\\');
        if base_trim.is_empty() {
            suffix_trim.to_string()
        } else if suffix_trim.is_empty() {
            base_trim.to_string()
        } else {
            format!("{}\\{}", base_trim, suffix_trim)
        }
    };

    if let Some(info) = link_info {
        if let Some(local) = &info.local_base_path {
            if let Some(suffix) = &info.common_path_suffix {
                if !suffix.is_empty() {
                    return Some(join_paths(local, suffix));
                }
            }
            return Some(local.clone());
        }
        if let Some(net) = &info.network_info {
            if let Some(suffix) = &info.common_path_suffix {
                if !suffix.is_empty() {
                    return Some(join_paths(&net.net_name, suffix));
                }
            }
            return Some(net.net_name.clone());
        }
    }

    if let Some(env) = env_path {
        if !env.is_empty() {
            return Some(env.to_string());
        }
    }

    if let Some(rel) = &string_data.relative_path {
        if !rel.is_empty() {
            return Some(rel.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_link_fixture(link_flags: u32, total_size: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; total_size.max(80)];
        buffer[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buffer[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buffer[20..24].copy_from_slice(&link_flags.to_le_bytes());
        buffer[60..64].copy_from_slice(&1_u32.to_le_bytes());
        buffer
    }

    fn write_utf16_terminated(buffer: &mut [u8], start: usize, value: &str) {
        for (index, unit) in value.encode_utf16().chain(std::iter::once(0)).enumerate() {
            let position = start + index * 2;
            buffer[position..position + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    #[test]
    fn test_lnk_header_parsing_synthetic() {
        let mut buf = vec![0u8; 80];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x80_u32.to_le_bytes()); // IsUnicode
        buf[24..28].copy_from_slice(&0x20_u32.to_le_bytes());
        buf[52..56].copy_from_slice(&1024_u32.to_le_bytes());
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        assert_eq!(res.status, LnkStatus::Recognized);
        let header = res.header.unwrap();
        assert_eq!(header.header_size, 0x4C);
        assert_eq!(header.file_size, 1024);
        assert!(header.is_unicode);
    }

    #[test]
    fn test_lnk_target_id_list_forces_partial() {
        let mut buf = shell_link_fixture(0x01, 128); // HasLinkTargetIDList

        buf[76..78].copy_from_slice(&4_u16.to_le_bytes());
        buf[78..82].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        assert_eq!(res.status, LnkStatus::Partial);
        assert!(res
            .warnings
            .iter()
            .any(|warning| warning.contains("exceeding the 4-byte payload")));
    }

    #[test]
    fn test_bounded_id_list_with_alternate_target_is_core_complete() {
        let mut buf = shell_link_fixture(0x89, 98); // IDList | RelativePath | IsUnicode
        buf[76..78].copy_from_slice(&6_u16.to_le_bytes());
        buf[78..82].copy_from_slice(&[4, 0, 0xAA, 0xBB]);
        buf[82..84].copy_from_slice(&0_u16.to_le_bytes());

        let relative = "C:\\x";
        buf[84..86].copy_from_slice(&(relative.encode_utf16().count() as u16).to_le_bytes());
        write_utf16_terminated(&mut buf, 86, relative);
        // StringData is counted and excludes its terminator, so overwrite that
        // test-helper terminator with the ExtraData TerminalBlock.
        buf[94..98].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Recognized);
        assert!(result.warnings.is_empty());
        assert!(!result.coverage_complete);
        assert_eq!(result.canonical_target_path.as_deref(), Some("C:\\x"));
        let id_list = result.target_id_list.unwrap();
        assert_eq!(id_list.item_count, 1);
        assert_eq!(id_list.item_sizes, vec![4]);
        assert!(id_list.terminal_present);
    }

    #[test]
    fn test_bounded_id_list_only_target_remains_explicitly_partial() {
        let mut buf = shell_link_fixture(0x01, 88);
        buf[76..78].copy_from_slice(&6_u16.to_le_bytes());
        buf[78..82].copy_from_slice(&[4, 0, 0xAA, 0xBB]);
        buf[82..84].copy_from_slice(&0_u16.to_le_bytes());
        buf[84..88].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Partial);
        assert!(result
            .warnings
            .iter()
            .any(|warning| { warning.contains("target is encoded only in LinkTargetIDList") }));
        assert!(!result.coverage_complete);
    }

    #[test]
    fn test_lnk_corrupt_truncated_header() {
        let buf = vec![0u8; 30];
        let res = LnkParser::parse(&buf);
        assert!(!res.is_valid);
        assert_eq!(res.status, LnkStatus::Failed);
        assert!(!res.warnings.is_empty());
    }

    #[test]
    fn test_lnk_unc_network_fixture() {
        let mut buf = vec![0u8; 200];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x02_u32.to_le_bytes()); // HasLinkInfo

        let info_start = 76;
        let info_size = 56u32;
        buf[info_start..info_start + 4].copy_from_slice(&info_size.to_le_bytes());
        buf[info_start + 4..info_start + 8].copy_from_slice(&28u32.to_le_bytes()); // header_size
        buf[info_start + 8..info_start + 12].copy_from_slice(&0x02u32.to_le_bytes()); // flags: HasCommonNetworkRelativeLink
        buf[info_start + 20..info_start + 24].copy_from_slice(&28u32.to_le_bytes()); // net_link_off = 28

        let net_start = info_start + 28;
        buf[net_start..net_start + 4].copy_from_slice(&28u32.to_le_bytes()); // net size = 28
        buf[net_start + 4..net_start + 8].copy_from_slice(&0x01u32.to_le_bytes()); // net flags
        buf[net_start + 8..net_start + 12].copy_from_slice(&20u32.to_le_bytes()); // net_name_off = 20
        buf[net_start + 20..net_start + 28].copy_from_slice(b"\\\\SERVER");

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        assert!(res.link_info.is_some());
        let info = res.link_info.unwrap();
        assert!(info.network_info.is_some());
        let net = info.network_info.unwrap();
        assert_eq!(net.net_name, "\\\\SERVER");
    }

    #[test]
    fn test_lnk_unicode_string_data_fixture() {
        let mut buf = vec![0u8; 150];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x84_u32.to_le_bytes()); // HasName | IsUnicode

        let name = "TestLink";
        let u16_name: Vec<u16> = name.encode_utf16().collect();
        buf[76..78].copy_from_slice(&(u16_name.len() as u16).to_le_bytes());
        for (i, &u) in u16_name.iter().enumerate() {
            buf[78 + (i * 2)..78 + (i * 2) + 2].copy_from_slice(&u.to_le_bytes());
        }

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        assert_eq!(
            res.string_data.name_description.as_deref(),
            Some("TestLink")
        );
    }

    #[test]
    fn test_lnk_unknown_block_is_disclosed_without_core_partial() {
        let mut buf = shell_link_fixture(0, 96);

        let block_start = 76;
        buf[block_start..block_start + 4].copy_from_slice(&16_u32.to_le_bytes());
        buf[block_start + 4..block_start + 8].copy_from_slice(&0x99999999_u32.to_le_bytes());

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        assert_eq!(res.status, LnkStatus::Recognized);
        assert!(res.warnings.is_empty());
        assert!(!res.coverage_complete);
        assert_eq!(res.coverage_notes.len(), 1);
        assert_eq!(res.extra_data_blocks.len(), 1);
        assert_eq!(res.extra_data_blocks[0].name, "UnknownBlock(0x99999999)");
    }

    #[test]
    fn test_protective_size_limit_overflow() {
        let buf = vec![0u8; 500];
        let options = LnkParserOptions { max_file_size: 100 };
        let res = LnkParser::parse_with_options(&buf, &options);
        assert_eq!(res.status, LnkStatus::Partial);
        assert!(!res.is_valid);
    }

    #[test]
    fn test_lnk_volume_info_unicode_label() {
        let mut buf = vec![0u8; 200];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x02_u32.to_le_bytes()); // HasLinkInfo

        let info_start = 76;
        let info_size = 80u32;
        buf[info_start..info_start + 4].copy_from_slice(&info_size.to_le_bytes());
        buf[info_start + 4..info_start + 8].copy_from_slice(&28u32.to_le_bytes()); // header_size
        buf[info_start + 8..info_start + 12].copy_from_slice(&0x01u32.to_le_bytes()); // VolumeIDAndLocalBasePath
        buf[info_start + 12..info_start + 16].copy_from_slice(&28u32.to_le_bytes()); // vol_id_off = 28

        let vol_start = info_start + 28;
        buf[vol_start..vol_start + 4].copy_from_slice(&48u32.to_le_bytes()); // vol size = 48
        buf[vol_start + 4..vol_start + 8].copy_from_slice(&3u32.to_le_bytes()); // DRIVE_FIXED
        buf[vol_start + 8..vol_start + 12].copy_from_slice(&0x12345678u32.to_le_bytes());
        buf[vol_start + 12..vol_start + 16].copy_from_slice(&0x14u32.to_le_bytes()); // label_off = 0x14 (indicates unicode)
        buf[vol_start + 16..vol_start + 20].copy_from_slice(&20u32.to_le_bytes()); // label_unicode_off = 20

        let label_u16: Vec<u16> = "UnicodeVol"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        for (i, &u) in label_u16.iter().enumerate() {
            buf[vol_start + 20 + (i * 2)..vol_start + 20 + (i * 2) + 2]
                .copy_from_slice(&u.to_le_bytes());
        }

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        let link_info = res.link_info.unwrap();
        let vol = link_info.volume_info.unwrap();
        assert_eq!(vol.volume_label, "UnicodeVol");
    }

    #[test]
    fn test_lnk_common_network_relative_unicode_share_name() {
        let mut buf = vec![0u8; 250];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x02_u32.to_le_bytes());

        let info_start = 76;
        let info_size = 96u32;
        buf[info_start..info_start + 4].copy_from_slice(&info_size.to_le_bytes());
        buf[info_start + 4..info_start + 8].copy_from_slice(&28u32.to_le_bytes());
        buf[info_start + 8..info_start + 12].copy_from_slice(&0x02u32.to_le_bytes()); // HasCommonNetworkRelativeLink
        buf[info_start + 20..info_start + 24].copy_from_slice(&28u32.to_le_bytes());

        let net_start = info_start + 28;
        buf[net_start..net_start + 4].copy_from_slice(&64u32.to_le_bytes()); // net size = 64
        buf[net_start + 4..net_start + 8].copy_from_slice(&0x01u32.to_le_bytes());
        buf[net_start + 8..net_start + 12].copy_from_slice(&0x18u32.to_le_bytes()); // net_name_off > 0x14
        buf[net_start + 12..net_start + 16].copy_from_slice(&0u32.to_le_bytes());
        buf[net_start + 20..net_start + 24].copy_from_slice(&28u32.to_le_bytes()); // net_name_u_off = 28

        let net_u16: Vec<u16> = "\\\\UNICODE_SRV"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        for (i, &u) in net_u16.iter().enumerate() {
            buf[net_start + 28 + (i * 2)..net_start + 28 + (i * 2) + 2]
                .copy_from_slice(&u.to_le_bytes());
        }

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        let net = res.link_info.unwrap().network_info.unwrap();
        assert_eq!(net.net_name, "\\\\UNICODE_SRV");
    }

    #[test]
    fn test_lnk_environment_variable_unicode_path() {
        let mut buf = vec![0u8; 900];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x00_u32.to_le_bytes());

        let block_start = 76;
        let block_size = 788u32;
        buf[block_start..block_start + 4].copy_from_slice(&block_size.to_le_bytes());
        buf[block_start + 4..block_start + 8].copy_from_slice(&0xA0000001_u32.to_le_bytes());

        let env_u16: Vec<u16> = "%WINDIR%\\System32\\notepad.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        for (i, &u) in env_u16.iter().enumerate() {
            buf[block_start + 268 + (i * 2)..block_start + 268 + (i * 2) + 2]
                .copy_from_slice(&u.to_le_bytes());
        }

        let res = LnkParser::parse(&buf);
        assert!(res.is_valid);
        assert_eq!(
            res.environment_path.as_deref(),
            Some("%WINDIR%\\System32\\notepad.exe")
        );
    }

    #[test]
    fn test_lnk_extra_data_terminal_block_provenance() {
        let mut buf = vec![0u8; 150];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x00_u32.to_le_bytes());

        let extra_start = 76;
        buf[extra_start..extra_start + 4].copy_from_slice(&16u32.to_le_bytes());
        buf[extra_start + 4..extra_start + 8].copy_from_slice(&0xA000000B_u32.to_le_bytes());

        // Terminal block (4 bytes 0x00000000) at offset 76 + 16 = 92
        let term_off = extra_start + 16;
        buf[term_off..term_off + 4].copy_from_slice(&0u32.to_le_bytes());

        let res = LnkParser::parse(&buf);
        assert_eq!(res.source_offsets.extra_data_offset, Some(76));
        assert_eq!(res.source_offsets.extra_data_size, Some(20)); // 16 + 4
        assert_eq!(res.trailing_zero_padding_bytes, 54);
    }

    #[test]
    fn test_nonzero_bytes_after_terminal_are_not_treated_as_padding() {
        let mut buf = vec![0u8; 81];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());
        buf[80] = 0x41;

        let result = LnkParser::parse(&buf);
        assert_eq!(result.trailing_zero_padding_bytes, 0);
        assert_eq!(result.status, LnkStatus::Partial);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("non-padding trailing bytes")));
    }

    #[test]
    fn test_lnk_read_null_terminated_utf16_empty_string() {
        let buf = [0u8, 0u8, 0x41, 0x00];
        let mut warnings = Vec::new();
        let mut warnings_omitted = 0;
        let res = read_null_terminated_utf16(&buf, &mut warnings, &mut warnings_omitted);
        assert_eq!(res, Some(String::new()));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_lnk_canonical_path_join_no_double_slash() {
        let info = LnkLinkInfo {
            link_info_size: 56,
            link_info_header_size: 28,
            link_info_flags: 1,
            local_base_path: Some("C:\\Folder\\".to_string()),
            common_path_suffix: Some("\\SubFolder\\file.txt".to_string()),
            volume_info: None,
            network_info: None,
        };
        let string_data = LnkStringData::default();
        let path = resolve_canonical_path(Some(&info), &string_data, None);
        assert_eq!(path.as_deref(), Some("C:\\Folder\\SubFolder\\file.txt"));
    }

    #[test]
    fn test_lnk_shim_and_consolefe_blocks_are_decoded() {
        let mut buf = shell_link_fixture(0x0002_0000, 120); // RunWithShimLayer

        let block1 = 76;
        buf[block1..block1 + 4].copy_from_slice(&12u32.to_le_bytes());
        buf[block1 + 4..block1 + 8].copy_from_slice(&0xA0000004_u32.to_le_bytes()); // ConsoleFEDataBlock
        buf[block1 + 8..block1 + 12].copy_from_slice(&65001_u32.to_le_bytes());

        let block2 = 88;
        buf[block2..block2 + 4].copy_from_slice(&28u32.to_le_bytes());
        buf[block2 + 4..block2 + 8].copy_from_slice(&0xA0000008_u32.to_le_bytes()); // ShimDataBlock
        write_utf16_terminated(&mut buf, block2 + 8, "WINXPSP3X");
        buf[116..120].copy_from_slice(&0_u32.to_le_bytes());

        let res = LnkParser::parse(&buf);
        assert_eq!(res.extra_data_blocks.len(), 2);
        assert_eq!(res.extra_data_blocks[0].name, "ConsoleFEDataBlock");
        assert_eq!(res.extra_data_blocks[1].name, "ShimDataBlock");
        assert_eq!(res.console_code_page, Some(65001));
        assert_eq!(res.shim_layer_name.as_deref(), Some("WINXPSP3X"));
        assert_eq!(res.status, LnkStatus::Recognized);
        assert!(res.warnings.is_empty());
        assert!(res.coverage_complete);
    }

    #[test]
    fn test_icon_environment_signature_and_flag_are_not_misclassified_as_darwin() {
        let mut buf = shell_link_fixture(0x0000_4000, 868); // HasExpIcon
        buf[76..80].copy_from_slice(&0x314_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA0000007_u32.to_le_bytes());
        write_utf16_terminated(&mut buf, 76 + 268, "%SystemRoot%\\system32\\shell32.dll");
        buf[864..868].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Recognized);
        assert!(result.warnings.is_empty());
        assert_eq!(
            result.icon_environment_path.as_deref(),
            Some("%SystemRoot%\\system32\\shell32.dll")
        );
        assert!(result.darwin_data.is_none());
        assert_eq!(result.extra_data_blocks[0].name, "IconEnvironmentDataBlock");
    }

    #[test]
    fn test_darwin_signature_and_flag_are_decoded() {
        let mut buf = shell_link_fixture(0x0000_1000, 868); // HasDarwinID
        buf[76..80].copy_from_slice(&0x314_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA0000006_u32.to_le_bytes());
        write_utf16_terminated(&mut buf, 76 + 268, "DarwinDescriptor");
        buf[864..868].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Recognized);
        assert!(result.warnings.is_empty());
        assert_eq!(result.darwin_data.as_deref(), Some("DarwinDescriptor"));
        assert!(result.icon_environment_path.is_none());
        assert_eq!(result.extra_data_blocks[0].name, "DarwinDataBlock");
    }

    #[test]
    fn test_special_folder_block_is_structurally_complete() {
        let mut buf = shell_link_fixture(0, 96);
        buf[76..80].copy_from_slice(&16_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA0000005_u32.to_le_bytes());
        buf[84..88].copy_from_slice(&42_u32.to_le_bytes());
        buf[88..92].copy_from_slice(&123_u32.to_le_bytes());
        buf[92..96].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Recognized);
        assert!(result.coverage_complete);
        let special = result.special_folder_data.unwrap();
        assert_eq!(special.special_folder_id, 42);
        assert_eq!(special.offset, 123);
    }

    #[test]
    fn test_property_store_envelope_is_bounded_without_core_partial() {
        let mut buf = shell_link_fixture(0, 116);
        buf[76..80].copy_from_slice(&36_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA0000009_u32.to_le_bytes());
        buf[84..88].copy_from_slice(&24_u32.to_le_bytes());
        buf[88..92].copy_from_slice(&0x5350_5331_u32.to_le_bytes());
        buf[92..108].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[108..112].copy_from_slice(&0_u32.to_le_bytes());
        buf[112..116].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Recognized);
        assert!(result.warnings.is_empty());
        assert!(!result.coverage_complete);
        assert_eq!(result.property_store_data.len(), 1);
        let store = &result.property_store_data[0];
        assert_eq!(store.storage_count, 1);
        assert!(store.terminal_present);
        assert_eq!(store.format_ids.len(), 1);
    }

    #[test]
    fn test_malformed_property_store_storage_remains_partial() {
        let mut buf = shell_link_fixture(0, 116);
        buf[76..80].copy_from_slice(&36_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA0000009_u32.to_le_bytes());
        buf[84..88].copy_from_slice(&40_u32.to_le_bytes());
        buf[112..116].copy_from_slice(&0_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Partial);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("exceeding the 36-byte block")));
        assert!(!result.coverage_complete);
    }

    #[test]
    fn test_lnk_clsid_mismatch_warning() {
        let mut buf = vec![0u8; 100];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&[0xFF; 16]); // Invalid CLSID

        let res = LnkParser::parse(&buf);
        assert_eq!(res.status, LnkStatus::Failed);
        assert!(!res.is_valid);
        assert!(res
            .warnings
            .iter()
            .any(|w| w.contains("does not match standard Shell Link CLSID")));
    }

    #[test]
    fn test_overwritten_deleted_candidate_fails_before_fabricating_header_fields() {
        let mut buf = vec![0u8; 100];
        // Representative of a reused deleted data run: UTF-16 text rather than
        // a ShellLinkHeader, including a non-0x4C first DWORD.
        buf[..16].copy_from_slice(&[
            0x20, 0x00, 0x20, 0x00, 0x57, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x2D, 0x00,
            0x6B, 0x00,
        ]);

        let result = LnkParser::parse(&buf);
        assert_eq!(result.status, LnkStatus::Failed);
        assert!(!result.is_valid);
        assert!(result.header.is_none());
        assert_eq!(result.warnings.len(), 2);
        assert!(result
            .warnings
            .iter()
            .all(|warning| warning.contains("HeaderSize") || warning.contains("LinkCLSID")));
    }

    #[test]
    fn test_lnk_truncated_string_data_flags() {
        let mut buf = vec![0u8; 76];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x04_u32.to_le_bytes()); // HasName flag set, but no data after header

        let res = LnkParser::parse(&buf);
        assert_eq!(res.status, LnkStatus::Partial);
        assert!(res.warnings.iter().any(|w| w.contains("HasName")));
    }

    #[test]
    fn test_lnk_n_plus_1_bounds_checks() {
        let mut buf = vec![0u8; 75]; // Exactly N-1 bytes for header
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);

        let res_sub1 = LnkParser::parse(&buf);
        assert_eq!(res_sub1.status, LnkStatus::Failed);

        buf.push(0); // Exactly N (76 bytes)
        let res_exact = LnkParser::parse(&buf);
        assert!(res_exact.header.is_some());
    }

    #[test]
    fn test_force_no_link_info_still_consumes_serialized_link_info() {
        let mut buf = vec![0u8; 118];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x0000_018A_u32.to_le_bytes()); // LinkInfo, relative, Unicode, ForceNoLinkInfo
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());

        let info_start = 76;
        buf[info_start..info_start + 4].copy_from_slice(&30_u32.to_le_bytes());
        buf[info_start + 4..info_start + 8].copy_from_slice(&28_u32.to_le_bytes());
        buf[info_start + 24..info_start + 28].copy_from_slice(&28_u32.to_le_bytes());
        // Empty ANSI CommonPathSuffix at LinkInfo offset 28.
        buf[info_start + 28] = 0;

        let relative_start = info_start + 30;
        buf[relative_start..relative_start + 2].copy_from_slice(&3_u16.to_le_bytes());
        for (index, unit) in "REL".encode_utf16().enumerate() {
            let start = relative_start + 2 + index * 2;
            buf[start..start + 2].copy_from_slice(&unit.to_le_bytes());
        }

        let result = LnkParser::parse(&buf);
        assert!(result.link_info.is_some());
        assert_eq!(result.source_offsets.link_info_offset, Some(76));
        assert_eq!(result.string_data.relative_path.as_deref(), Some("REL"));
        assert_eq!(result.canonical_target_path.as_deref(), Some("REL"));
    }

    #[test]
    fn test_common_network_flag_bits_map_device_and_provider_correctly() {
        let mut buf = vec![0u8; 136];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x02_u32.to_le_bytes());
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());

        let info = 76;
        buf[info..info + 4].copy_from_slice(&56_u32.to_le_bytes());
        buf[info + 4..info + 8].copy_from_slice(&28_u32.to_le_bytes());
        buf[info + 8..info + 12].copy_from_slice(&0x02_u32.to_le_bytes());
        buf[info + 20..info + 24].copy_from_slice(&28_u32.to_le_bytes());
        buf[info + 24..info + 28].copy_from_slice(&55_u32.to_le_bytes());

        let network = info + 28;
        buf[network..network + 4].copy_from_slice(&27_u32.to_le_bytes());
        buf[network + 4..network + 8].copy_from_slice(&0x03_u32.to_le_bytes());
        buf[network + 8..network + 12].copy_from_slice(&20_u32.to_le_bytes());
        buf[network + 12..network + 16].copy_from_slice(&24_u32.to_le_bytes());
        buf[network + 16..network + 20].copy_from_slice(&0x0002_0000_u32.to_le_bytes());
        buf[network + 20..network + 24].copy_from_slice(b"\\\\S\0");
        buf[network + 24..network + 27].copy_from_slice(b"Z:\0");

        let result = LnkParser::parse(&buf);
        let network = result.link_info.unwrap().network_info.unwrap();
        assert_eq!(network.net_name, "\\\\S");
        assert_eq!(network.device_name.as_deref(), Some("Z:"));
        assert_eq!(network.net_provider_type, Some(0x0002_0000));
    }

    #[test]
    fn test_zero_unicode_network_offset_never_decodes_structure_header() {
        let mut buf = vec![0u8; 145];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x02_u32.to_le_bytes());
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());

        let info = 76;
        buf[info..info + 4].copy_from_slice(&65_u32.to_le_bytes());
        buf[info + 4..info + 8].copy_from_slice(&28_u32.to_le_bytes());
        buf[info + 8..info + 12].copy_from_slice(&0x02_u32.to_le_bytes());
        buf[info + 20..info + 24].copy_from_slice(&28_u32.to_le_bytes());
        buf[info + 24..info + 28].copy_from_slice(&64_u32.to_le_bytes());

        let network = info + 28;
        buf[network..network + 4].copy_from_slice(&36_u32.to_le_bytes());
        buf[network + 8..network + 12].copy_from_slice(&28_u32.to_le_bytes());
        // NetNameOffsetUnicode and DeviceNameOffsetUnicode deliberately remain zero.
        buf[network + 28..network + 30].copy_from_slice(b"X\0");

        let result = LnkParser::parse(&buf);
        let network = result.link_info.unwrap().network_info.unwrap();
        assert_eq!(network.net_name, "X");
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("NetNameOffsetUnicode")));
    }

    #[test]
    fn test_short_tracker_never_fabricates_missing_guids() {
        let mut buf = vec![0u8; 144];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());
        buf[76..80].copy_from_slice(&64_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA000_0003_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert!(result.tracker_data.is_none());
        assert_eq!(result.status, LnkStatus::Partial);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("expected exactly 0x60")));
    }

    #[test]
    fn test_truncated_string_is_not_reinterpreted_as_extra_data() {
        let mut buf = vec![0u8; 92];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x04_u32.to_le_bytes());
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());
        // This is a 16-character counted string with only 14 payload bytes. The
        // first eight bytes also resemble an ExtraData header.
        buf[76..80].copy_from_slice(&16_u32.to_le_bytes());
        buf[80..84].copy_from_slice(&0xA000_0001_u32.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert!(result.extra_data_blocks.is_empty());
        assert!(result.source_offsets.extra_data_offset.is_none());
        assert_eq!(result.status, LnkStatus::Partial);
    }

    #[test]
    fn test_truncated_id_list_source_extent_is_bounded_by_file() {
        let mut buf = vec![0u8; 80];
        buf[0..4].copy_from_slice(&0x4C_u32.to_le_bytes());
        buf[4..20].copy_from_slice(&LnkParser::SHELL_LINK_CLSID);
        buf[20..24].copy_from_slice(&0x01_u32.to_le_bytes());
        buf[60..64].copy_from_slice(&1_u32.to_le_bytes());
        buf[76..78].copy_from_slice(&10_u16.to_le_bytes());

        let result = LnkParser::parse(&buf);
        assert_eq!(result.source_offsets.id_list_offset, Some(76));
        assert_eq!(result.source_offsets.id_list_size, Some(4));
    }

    #[test]
    fn test_ansi_decode_does_not_guess_utf8_without_a_code_page() {
        let mut warnings = Vec::new();
        let mut warnings_omitted = 0;
        let value = decode_ansi_string(&[0xC3, 0xA9], &mut warnings, &mut warnings_omitted);
        assert_eq!(value, "Ã©");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings_omitted, 0);
    }
}
