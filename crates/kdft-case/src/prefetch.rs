use chrono::{DateTime, Utc};
use std::io::Read;

/// Status of prefetch file parsing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrefetchStatus {
    Success,
    Partial,
    MamCompressedNotDecompressed,
    MamDecompressionFailed,
    ResourceLimitExceeded,
    UnsupportedVersion(u32),
    InvalidSignature,
    CorruptHeader,
    CorruptSectionOffsets,
}

/// Volume information entry from Section C/D of Prefetch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrefetchVolumeInfo {
    pub device_path: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub serial_number: u32,
    pub serial_number_hex: String,
    pub directory_paths: Vec<String>,
}

/// Header and execution metadata for a Windows Prefetch (.pf) file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrefetchHeaderInfo {
    pub version: u32,
    pub signature: String,
    pub executable_name: String,
    pub hash: u32,
    pub hash_hex: String,
    pub file_size: u32,
    pub run_count: u32,
    pub last_run_timestamps: Vec<DateTime<Utc>>,
}

/// Source byte offsets for prefetch data structures.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PrefetchSourceOffsets {
    pub header_offset: usize,
    pub header_size: usize,
    pub file_information_offset: usize,
    pub file_information_size: usize,
    pub run_count_offset: usize,
    pub timestamps_offset: usize,
    pub section_a_offset: usize,
    pub section_b_offset: usize,
    pub section_c_offset: usize,
    pub section_d_offset: usize,
}

/// Result of parsing a Windows Prefetch file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrefetchParseResult {
    pub status: PrefetchStatus,
    pub is_mam_compressed: bool,
    pub mam_uncompressed_size: Option<u32>,
    pub header: Option<PrefetchHeaderInfo>,
    pub referenced_filenames: Vec<String>,
    pub volumes: Vec<PrefetchVolumeInfo>,
    pub source_offsets: PrefetchSourceOffsets,
    pub total_referenced_files: usize,
    pub total_volumes: usize,
    pub warnings: Vec<String>,
    pub warnings_omitted: u64,
    pub is_complete: bool,
}

/// Options for bounded prefetch parsing.
#[derive(Debug, Clone)]
pub struct PrefetchParserOptions {
    pub max_file_size: usize,
    pub max_decompressed_size: usize,
}

impl Default for PrefetchParserOptions {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024,
            max_decompressed_size: 64 * 1024 * 1024,
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

#[allow(dead_code)]
fn get_u16_le(slice: &[u8], offset: usize) -> Option<u16> {
    let bytes = slice.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn get_u32_le(slice: &[u8], offset: usize) -> Option<u32> {
    let bytes = slice.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

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

fn decode_utf16_with_warning(
    units: &[u16],
    context: &str,
    warnings: &mut Vec<String>,
    warnings_omitted: &mut u64,
) -> String {
    match String::from_utf16(units) {
        Ok(value) => value,
        Err(_) => {
            record_warning(
                warnings,
                warnings_omitted,
                format!(
                    "{context} contains unpaired UTF-16 surrogate data; displaying a lossy value"
                ),
            );
            String::from_utf16_lossy(units)
        }
    }
}

/// Defensive parser for Windows Prefetch (.pf) files.
pub struct PrefetchParser;

impl PrefetchParser {
    pub const MAM_MAGIC_V4: [u8; 4] = [b'M', b'A', b'M', 0x04];
    pub const MAM_MAGIC_V3: [u8; 4] = [b'M', b'A', b'M', 0x03];
    pub const SCCA_MAGIC: [u8; 4] = *b"SCCA";

    /// Parse prefetch bytes with default parser options.
    pub fn parse(data: &[u8]) -> PrefetchParseResult {
        Self::parse_with_options(data, &PrefetchParserOptions::default())
    }

    /// Parse reader stream up to max_file_size + 1 to detect over-limit input.
    pub fn parse_reader<R: Read>(
        reader: &mut R,
        options: &PrefetchParserOptions,
    ) -> PrefetchParseResult {
        let mut buf = Vec::new();
        let limit = options.max_file_size.saturating_add(1);
        let mut take = reader.take(limit as u64);
        if let Err(e) = take.read_to_end(&mut buf) {
            let mut warnings = Vec::new();
            let mut warnings_omitted = 0;
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!("Failed to read prefetch stream: {e}"),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::CorruptHeader,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets: PrefetchSourceOffsets::default(),
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        if buf.len() > options.max_file_size {
            let mut warnings = Vec::new();
            let mut warnings_omitted = 0;
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "File size {} exceeds protective maximum limit {}",
                    buf.len(),
                    options.max_file_size
                ),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::ResourceLimitExceeded,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets: PrefetchSourceOffsets::default(),
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        Self::parse_with_options(&buf, options)
    }

    /// Parse prefetch bytes with explicit options.
    pub fn parse_with_options(data: &[u8], options: &PrefetchParserOptions) -> PrefetchParseResult {
        let mut warnings = Vec::new();
        let mut warnings_omitted = 0u64;
        let mut source_offsets = PrefetchSourceOffsets::default();

        if data.len() > options.max_file_size {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "File size {} exceeds protective maximum prefetch limit {}",
                    data.len(),
                    options.max_file_size
                ),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::ResourceLimitExceeded,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        if data.len() < 8 {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                "File size less than 8 bytes minimum".to_string(),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::CorruptHeader,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        // A raw Prefetch file is identified by SCCA at bytes 4..8. Only treat
        // an otherwise non-SCCA input as a MAM wrapper, which also prevents a
        // decompressed payload from being recursively mistaken for MAM.
        let is_raw_scca = data.get(4..8) == Some(Self::SCCA_MAGIC.as_slice());
        if !is_raw_scca && data.len() >= 8 && &data[0..3] == b"MAM" {
            let mam_ver = data[3];
            let uncompressed_size = get_u32_le(data, 4).unwrap_or(0);
            let declared_size = uncompressed_size as usize;

            if mam_ver == 0x04 {
                if declared_size > options.max_decompressed_size {
                    record_warning(
                        &mut warnings,
                        &mut warnings_omitted,
                        format!(
                            "MAM decompressed size {} exceeds protective maximum {}",
                            declared_size, options.max_decompressed_size
                        ),
                    );
                    return PrefetchParseResult {
                        status: PrefetchStatus::ResourceLimitExceeded,
                        is_mam_compressed: true,
                        mam_uncompressed_size: Some(uncompressed_size),
                        header: None,
                        referenced_filenames: Vec::new(),
                        volumes: Vec::new(),
                        source_offsets,
                        total_referenced_files: 0,
                        total_volumes: 0,
                        warnings,
                        warnings_omitted,
                        is_complete: false,
                    };
                }

                match xpress_huffman::decompress(&data[8..], declared_size) {
                    Ok(decompressed) if decompressed.len() > options.max_decompressed_size => {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "MAM decompression produced {} bytes, exceeding protective maximum {}",
                                decompressed.len(),
                                options.max_decompressed_size
                            ),
                        );
                        return PrefetchParseResult {
                            status: PrefetchStatus::ResourceLimitExceeded,
                            is_mam_compressed: true,
                            mam_uncompressed_size: Some(uncompressed_size),
                            header: None,
                            referenced_filenames: Vec::new(),
                            volumes: Vec::new(),
                            source_offsets,
                            total_referenced_files: 0,
                            total_volumes: 0,
                            warnings,
                            warnings_omitted,
                            is_complete: false,
                        };
                    }
                    Ok(decompressed)
                        if decompressed.get(4..8) == Some(Self::SCCA_MAGIC.as_slice()) =>
                    {
                        let mut raw_options = options.clone();
                        raw_options.max_file_size = options.max_decompressed_size;
                        let mut parsed = Self::parse_with_options(&decompressed, &raw_options);
                        parsed.is_mam_compressed = true;
                        parsed.mam_uncompressed_size = Some(uncompressed_size);
                        if decompressed.len() != declared_size {
                            let discrepancy = if decompressed.len() < declared_size {
                                format!(
                                    "{} byte shortfall",
                                    declared_size.saturating_sub(decompressed.len())
                                )
                            } else {
                                format!(
                                    "{} bytes beyond the declaration",
                                    decompressed.len().saturating_sub(declared_size)
                                )
                            };
                            record_warning(
                                &mut parsed.warnings,
                                &mut parsed.warnings_omitted,
                                format!(
                                    "MAM decompression recovered {} bytes for a {}-byte declaration ({discrepancy}); the structurally valid SCCA payload was parsed without padding, truncation, or fabricated bytes",
                                    decompressed.len(),
                                    declared_size
                                ),
                            );
                            parsed.is_complete = false;
                            if parsed.status == PrefetchStatus::Success {
                                parsed.status = PrefetchStatus::Partial;
                            }
                        }
                        return parsed;
                    }
                    Ok(decompressed) => {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "MAM decompression produced {} bytes (declared {}) but the payload is not a structurally recognizable SCCA Prefetch file",
                                decompressed.len(), declared_size
                            ),
                        );
                    }
                    Err(error) => {
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!("MAM XPRESS-Huffman decompression failed: {error}"),
                        );
                    }
                }

                return PrefetchParseResult {
                    status: PrefetchStatus::MamDecompressionFailed,
                    is_mam_compressed: true,
                    mam_uncompressed_size: Some(uncompressed_size),
                    header: None,
                    referenced_filenames: Vec::new(),
                    volumes: Vec::new(),
                    source_offsets,
                    total_referenced_files: 0,
                    total_volumes: 0,
                    warnings,
                    warnings_omitted,
                    is_complete: false,
                };
            }

            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "Recognized unsupported MAM-compressed Prefetch version 0x{:02X} (uncompressed size {} bytes)",
                    mam_ver, uncompressed_size
                ),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::MamCompressedNotDecompressed,
                is_mam_compressed: true,
                mam_uncompressed_size: Some(uncompressed_size),
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        // 2. Uncompressed SCCA Prefetch Header Parsing
        if data.len() < 84 {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                "File size less than minimum SCCA header size (84)".to_string(),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::CorruptHeader,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        let version = get_u32_le(data, 0).unwrap_or(0);
        let scca_sig = data.get(4..8).unwrap_or(&[]);
        if scca_sig != Self::SCCA_MAGIC {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!("Invalid signature {:?}, expected 'SCCA'", scca_sig),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::InvalidSignature,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        let file_size = get_u32_le(data, 12).unwrap_or(0);
        if file_size != data.len() as u32 {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "Header declared file_size {} does not match actual buffer size {}",
                    file_size,
                    data.len()
                ),
            );
        }

        // Executable Name (UTF-16LE, 60 bytes at offset 16..76)
        let exe_name_raw = match data.get(16..76) {
            Some(raw) => raw,
            None => &[],
        };
        let exe_units: Vec<u16> = exe_name_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let executable_name = decode_utf16_with_warning(
            &exe_units,
            "Executable name",
            &mut warnings,
            &mut warnings_omitted,
        );

        let hash = get_u32_le(data, 76).unwrap_or(0);
        let hash_hex = format!("0x{:08X}", hash);

        // The SCCA header is always 84 bytes. File Information begins at byte
        // 84 for every supported version; only that structure's layout varies.
        const FILE_INFORMATION_OFFSET: usize = 84;
        let (file_information_size, run_count_off, timestamps_off, max_timestamps) = match version {
            17 => (68usize, 144usize, 120usize, 1usize),
            23 => (156usize, 152usize, 128usize, 1usize),
            26 => (220usize, 208usize, 128usize, 8usize),
            30 => {
                // Windows 10 has two documented v30 File Information
                // variants. The first File Metrics offset distinguishes
                // their 220-byte and 212-byte layouts.
                let first_metrics_offset = get_u32_le(data, FILE_INFORMATION_OFFSET);
                if first_metrics_offset == Some(296) {
                    (212usize, 200usize, 128usize, 8usize)
                } else {
                    (220usize, 208usize, 128usize, 8usize)
                }
            }
            31 => (212usize, 200usize, 128usize, 8usize),
            v => {
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!("Unsupported Prefetch version {}", v),
                );
                return PrefetchParseResult {
                    status: PrefetchStatus::UnsupportedVersion(v),
                    is_mam_compressed: false,
                    mam_uncompressed_size: None,
                    header: None,
                    referenced_filenames: Vec::new(),
                    volumes: Vec::new(),
                    source_offsets,
                    total_referenced_files: 0,
                    total_volumes: 0,
                    warnings,
                    warnings_omitted,
                    is_complete: false,
                };
            }
        };

        let minimum_length = FILE_INFORMATION_OFFSET + file_information_size;
        if data.len() < minimum_length {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "File size {} is less than minimum header length {} for version {}",
                    data.len(),
                    minimum_length,
                    version
                ),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::CorruptHeader,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: None,
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        source_offsets.header_offset = 0;
        source_offsets.header_size = FILE_INFORMATION_OFFSET;
        source_offsets.file_information_offset = FILE_INFORMATION_OFFSET;
        source_offsets.file_information_size = file_information_size;
        source_offsets.run_count_offset = run_count_off;
        source_offsets.timestamps_offset = timestamps_off;

        // Parse Run Count
        let run_count = if run_count_off
            .checked_add(4)
            .is_some_and(|end| end <= data.len())
        {
            get_u32_le(data, run_count_off).unwrap_or(0)
        } else {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                "Truncated run count offset".to_string(),
            );
            0
        };

        // Parse Last Run Timestamps
        let mut last_run_timestamps = Vec::new();
        for i in 0..max_timestamps {
            let off = timestamps_off + (i * 8);
            if off.checked_add(8).is_some_and(|e| e <= data.len()) {
                if let Some(ft) = get_i64_le(data, off) {
                    if let Some(dt) = filetime_to_datetime(ft) {
                        last_run_timestamps.push(dt);
                    }
                }
            } else {
                break;
            }
        }

        // File Information begins with the nine Section A-D offset/count/size
        // fields (36 bytes) in every supported layout.
        let section_table_offset = FILE_INFORMATION_OFFSET;
        if section_table_offset + 36 > data.len() {
            record_warning(
                &mut warnings,
                &mut warnings_omitted,
                format!(
                    "Section table offset {} + 36 exceeds buffer length {}",
                    section_table_offset,
                    data.len()
                ),
            );
            return PrefetchParseResult {
                status: PrefetchStatus::CorruptSectionOffsets,
                is_mam_compressed: false,
                mam_uncompressed_size: None,
                header: Some(PrefetchHeaderInfo {
                    version,
                    signature: "SCCA".to_string(),
                    executable_name,
                    hash,
                    hash_hex,
                    file_size,
                    run_count,
                    last_run_timestamps,
                }),
                referenced_filenames: Vec::new(),
                volumes: Vec::new(),
                source_offsets,
                total_referenced_files: 0,
                total_volumes: 0,
                warnings,
                warnings_omitted,
                is_complete: false,
            };
        }

        // Section A: File metrics
        let sec_a_off = get_u32_le(data, section_table_offset).unwrap_or(0) as usize;
        let _sec_a_cnt = get_u32_le(data, section_table_offset + 4).unwrap_or(0) as usize;

        // Section B: Trace chains
        let sec_b_off = get_u32_le(data, section_table_offset + 8).unwrap_or(0) as usize;
        let _sec_b_cnt = get_u32_le(data, section_table_offset + 12).unwrap_or(0) as usize;

        // Section C: Filename strings table
        let sec_c_off = get_u32_le(data, section_table_offset + 16).unwrap_or(0) as usize;
        let sec_c_size = get_u32_le(data, section_table_offset + 20).unwrap_or(0) as usize;

        // Section D: Volumes
        let sec_d_off = get_u32_le(data, section_table_offset + 24).unwrap_or(0) as usize;
        let sec_d_cnt = get_u32_le(data, section_table_offset + 28).unwrap_or(0) as usize;
        let sec_d_size = get_u32_le(data, section_table_offset + 32).unwrap_or(0) as usize;

        source_offsets.section_a_offset = sec_a_off;
        source_offsets.section_b_offset = sec_b_off;
        source_offsets.section_c_offset = sec_c_off;
        source_offsets.section_d_offset = sec_d_off;
        let mut has_corrupt_section_offsets = false;

        // 3. Parse Section C (Filename Strings Table)
        let mut referenced_filenames = Vec::new();
        if sec_c_off > 0 && sec_c_size > 0 {
            let sec_c_end = sec_c_off.checked_add(sec_c_size);
            if sec_c_end.is_some_and(|end| end <= data.len()) {
                if !sec_c_size.is_multiple_of(2) {
                    record_warning(
                        &mut warnings,
                        &mut warnings_omitted,
                        format!(
                            "Section C size is odd ({}), expected even byte count for UTF-16",
                            sec_c_size
                        ),
                    );
                }
                let sec_c_bytes = &data[sec_c_off..sec_c_off + sec_c_size];
                let mut curr_offset = 0usize;

                while curr_offset + 2 <= sec_c_bytes.len() {
                    let u16_units: Vec<u16> = sec_c_bytes[curr_offset..]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&u| u != 0)
                        .collect();

                    let char_count = u16_units.len();
                    if char_count == 0 {
                        curr_offset += 2;
                        if curr_offset >= sec_c_bytes.len()
                            || sec_c_bytes[curr_offset..].iter().all(|&b| b == 0)
                        {
                            break;
                        }
                        continue;
                    }

                    let filename = decode_utf16_with_warning(
                        &u16_units,
                        "Referenced filename",
                        &mut warnings,
                        &mut warnings_omitted,
                    );
                    referenced_filenames.push(filename);

                    let next_step = (char_count + 1).checked_mul(2).unwrap_or(2);
                    curr_offset = curr_offset.saturating_add(next_step);
                }
            } else {
                has_corrupt_section_offsets = true;
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!(
                        "Section C (Filename Strings) bounds invalid or out of buffer: off {} size {}",
                        sec_c_off, sec_c_size
                    ),
                );
            }
        }

        // 4. Parse Section D (Volume Info & Directory Paths)
        let mut volumes = Vec::new();
        if sec_d_off > 0 && sec_d_size > 0 && sec_d_cnt > 0 {
            let sec_d_end = sec_d_off.checked_add(sec_d_size);
            if sec_d_end.is_some_and(|end| end <= data.len()) {
                let sec_d_bytes = &data[sec_d_off..sec_d_off + sec_d_size];
                let vol_entry_size = match version {
                    17 => 40usize,
                    23 | 26 => 104usize,
                    30 | 31 => 96usize,
                    _ => 104usize,
                };

                for i in 0..sec_d_cnt {
                    let v_off = match i.checked_mul(vol_entry_size) {
                        Some(off) => off,
                        None => break,
                    };
                    if v_off
                        .checked_add(vol_entry_size)
                        .is_none_or(|end| end > sec_d_bytes.len())
                    {
                        has_corrupt_section_offsets = true;
                        record_warning(
                            &mut warnings,
                            &mut warnings_omitted,
                            format!(
                                "Volume entry {} offset {} exceeds Section D size {}",
                                i, v_off, sec_d_size
                            ),
                        );
                        break;
                    }

                    let v_bytes = &sec_d_bytes[v_off..v_off + vol_entry_size];
                    let dev_path_off = get_u32_le(v_bytes, 0).unwrap_or(0) as usize;
                    let dev_path_len = get_u32_le(v_bytes, 4).unwrap_or(0) as usize;
                    let vol_creation_ft = get_i64_le(v_bytes, 8).unwrap_or(0);
                    let serial_number = get_u32_le(v_bytes, 16).unwrap_or(0);
                    let dir_strings_off = get_u32_le(v_bytes, 20).unwrap_or(0) as usize;
                    let num_dir_strings = get_u32_le(v_bytes, 24).unwrap_or(0) as usize;

                    let device_path = if dev_path_len > 0 {
                        let path_end = dev_path_len
                            .checked_mul(2)
                            .and_then(|byte_len| dev_path_off.checked_add(byte_len));
                        if let Some(end) = path_end.filter(|end| *end <= sec_d_bytes.len()) {
                            let u16s: Vec<u16> = sec_d_bytes[dev_path_off..end]
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .take_while(|&u| u != 0)
                                .collect();
                            decode_utf16_with_warning(
                                &u16s,
                                &format!("Volume {i} device path"),
                                &mut warnings,
                                &mut warnings_omitted,
                            )
                        } else {
                            has_corrupt_section_offsets = true;
                            record_warning(
                                &mut warnings,
                                &mut warnings_omitted,
                                format!(
                                    "Volume {} device path length {} at relative offset {} exceeds Section D size {}",
                                    i, dev_path_len, dev_path_off, sec_d_size
                                ),
                            );
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    // Parse directory paths from dir_strings_off
                    let mut directory_paths = Vec::new();
                    if num_dir_strings > 0 {
                        if dir_strings_off < sec_d_bytes.len() {
                            let mut curr_dir_off = dir_strings_off;
                            for directory_index in 0..num_dir_strings {
                                let Some(char_count) =
                                    get_u16_le(sec_d_bytes, curr_dir_off).map(usize::from)
                                else {
                                    has_corrupt_section_offsets = true;
                                    record_warning(
                                        &mut warnings,
                                        &mut warnings_omitted,
                                        format!(
                                            "Volume {} directory {} length at relative offset {} is out of bounds",
                                            i, directory_index, curr_dir_off
                                        ),
                                    );
                                    break;
                                };
                                if char_count == 0 {
                                    has_corrupt_section_offsets = true;
                                    record_warning(
                                        &mut warnings,
                                        &mut warnings_omitted,
                                        format!(
                                            "Volume {} directory {} declares a zero-character record",
                                            i, directory_index
                                        ),
                                    );
                                    break;
                                }
                                let string_start = curr_dir_off + 2;
                                let string_end = char_count
                                    .checked_mul(2)
                                    .and_then(|byte_len| string_start.checked_add(byte_len));
                                let Some(string_end) =
                                    string_end.filter(|end| *end <= sec_d_bytes.len())
                                else {
                                    has_corrupt_section_offsets = true;
                                    record_warning(
                                        &mut warnings,
                                        &mut warnings_omitted,
                                        format!(
                                            "Volume {} directory {} length {} at relative offset {} exceeds Section D size {}",
                                            i, directory_index, char_count, curr_dir_off, sec_d_size
                                        ),
                                    );
                                    break;
                                };
                                let encoded_units: Vec<u16> = sec_d_bytes[string_start..string_end]
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                // The Prefetch directory-record length includes the
                                // terminating UTF-16 NUL. Accept older/noncanonical
                                // samples that exclude it, but disclose that variant
                                // and consume the following terminator exactly once.
                                let (u16s, next_dir_off) = if encoded_units.last() == Some(&0) {
                                    (&encoded_units[..encoded_units.len() - 1], string_end)
                                } else if get_u16_le(sec_d_bytes, string_end) == Some(0) {
                                    record_warning(
                                        &mut warnings,
                                        &mut warnings_omitted,
                                        format!(
                                            "Volume {} directory {} length excludes its UTF-16 NUL terminator; accepted as a noncanonical record",
                                            i, directory_index
                                        ),
                                    );
                                    (&encoded_units[..], string_end + 2)
                                } else {
                                    record_warning(
                                        &mut warnings,
                                        &mut warnings_omitted,
                                        format!(
                                            "Volume {} directory {} has no UTF-16 NUL terminator; the bounded string was retained",
                                            i, directory_index
                                        ),
                                    );
                                    (&encoded_units[..], string_end)
                                };
                                let dir_path = decode_utf16_with_warning(
                                    u16s,
                                    &format!("Volume {i} directory {directory_index}"),
                                    &mut warnings,
                                    &mut warnings_omitted,
                                );
                                directory_paths.push(dir_path);
                                curr_dir_off = next_dir_off;
                            }
                        } else {
                            has_corrupt_section_offsets = true;
                            record_warning(
                                &mut warnings,
                                &mut warnings_omitted,
                                format!(
                                    "Volume {} declared {} directory strings but dir_strings_off {} is invalid",
                                    i, num_dir_strings, dir_strings_off
                                ),
                            );
                        }
                    }

                    volumes.push(PrefetchVolumeInfo {
                        device_path,
                        creation_time: filetime_to_datetime(vol_creation_ft),
                        serial_number,
                        serial_number_hex: format!(
                            "{:04X}-{:04X}",
                            (serial_number >> 16) as u16,
                            serial_number as u16
                        ),
                        directory_paths,
                    });
                }
            } else {
                has_corrupt_section_offsets = true;
                record_warning(
                    &mut warnings,
                    &mut warnings_omitted,
                    format!(
                        "Section D (Volume Info) bounds invalid or out of buffer: off {} size {}",
                        sec_d_off, sec_d_size
                    ),
                );
            }
        }

        let header_info = PrefetchHeaderInfo {
            version,
            signature: "SCCA".to_string(),
            executable_name,
            hash,
            hash_hex,
            file_size,
            run_count,
            last_run_timestamps,
        };

        let total_referenced_files = referenced_filenames.len();
        let total_volumes = volumes.len();

        let is_complete = warnings.is_empty() && warnings_omitted == 0;
        let status = if is_complete {
            PrefetchStatus::Success
        } else if has_corrupt_section_offsets {
            PrefetchStatus::CorruptSectionOffsets
        } else {
            PrefetchStatus::Partial
        };

        PrefetchParseResult {
            status,
            is_mam_compressed: false,
            mam_uncompressed_size: None,
            header: Some(header_info),
            referenced_filenames,
            volumes,
            source_offsets,
            total_referenced_files,
            total_volumes,
            warnings,
            warnings_omitted,
            is_complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a valid one-block XPRESS-Huffman stream using an eight-bit
    /// canonical code for every literal byte. This deliberately uses no LZ
    /// matches, keeping the integration fixture deterministic and auditable.
    fn mam_wrap_literal_prefetch(raw: &[u8]) -> Vec<u8> {
        assert!(raw.len() <= 64 * 1024);
        let mut compressed = vec![0u8; 256];
        compressed[..128].fill(0x88); // literal symbols 0..255, all length 8
        for pair in raw.chunks(2) {
            if pair.len() == 2 {
                // The codec reads each 16-bit bitstream word little-endian and
                // consumes its most-significant bit first.
                compressed.push(pair[1]);
                compressed.push(pair[0]);
            } else {
                compressed.push(0);
                compressed.push(pair[0]);
            }
        }
        // Decoder look-ahead. Output stops exactly at the declared size.
        compressed.extend_from_slice(&[0, 0, 0, 0]);

        let mut wrapped = Vec::with_capacity(8 + compressed.len());
        wrapped.extend_from_slice(b"MAM\x04");
        wrapped.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        wrapped.extend_from_slice(&compressed);
        wrapped
    }

    #[test]
    fn test_prefetch_mam_v4_malformed_payload_is_reported() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(b"MAM\x04");
        data[4..8].copy_from_slice(&65536_u32.to_le_bytes());

        let res = PrefetchParser::parse(&data);
        assert_eq!(res.status, PrefetchStatus::MamDecompressionFailed);
        assert!(res.is_mam_compressed);
        assert_eq!(res.mam_uncompressed_size, Some(65536));
        assert!(!res.is_complete);
    }

    #[test]
    fn test_prefetch_mam_v4_decompression_and_exact_bound() {
        let mut raw = vec![0u8; 304];
        let raw_len = raw.len();
        raw[0..4].copy_from_slice(&26u32.to_le_bytes());
        raw[4..8].copy_from_slice(b"SCCA");
        raw[12..16].copy_from_slice(&(raw_len as u32).to_le_bytes());
        let exe: Vec<u16> = "MAMTEST.EXE".encode_utf16().collect();
        for (index, unit) in exe.into_iter().enumerate() {
            raw[16 + index * 2..18 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        raw[208..212].copy_from_slice(&7u32.to_le_bytes());
        let wrapped = mam_wrap_literal_prefetch(&raw);

        let exact = PrefetchParserOptions {
            max_file_size: wrapped.len(),
            max_decompressed_size: raw_len,
        };
        let parsed = PrefetchParser::parse_with_options(&wrapped, &exact);
        assert_eq!(
            parsed.status,
            PrefetchStatus::Success,
            "{:?}",
            parsed.warnings
        );
        assert!(parsed.is_mam_compressed);
        assert_eq!(parsed.mam_uncompressed_size, Some(raw_len as u32));
        assert_eq!(
            parsed.header.as_ref().map(|header| header.run_count),
            Some(7)
        );

        let below = PrefetchParserOptions {
            max_decompressed_size: raw_len - 1,
            ..exact
        };
        let limited = PrefetchParser::parse_with_options(&wrapped, &below);
        assert_eq!(limited.status, PrefetchStatus::ResourceLimitExceeded);
        assert!(!limited.is_complete);
        assert!(limited.header.is_none());
    }

    #[test]
    fn test_prefetch_mam_three_byte_declared_shortfall_is_retained_as_partial() {
        let mut raw = vec![0u8; 305];
        let raw_len = raw.len();
        raw[0..4].copy_from_slice(&26u32.to_le_bytes());
        raw[4..8].copy_from_slice(b"SCCA");
        raw[12..16].copy_from_slice(&(raw_len as u32).to_le_bytes());
        raw[208..212].copy_from_slice(&11u32.to_le_bytes());

        let mut wrapped = mam_wrap_literal_prefetch(&raw);
        // With a larger requested output this deliberately literal fixture
        // exhausts after 307 bytes. Declare 310 to reproduce the observed
        // three-byte MAM shortfall while retaining the complete SCCA prefix.
        let declared_size = raw_len as u32 + 5;
        wrapped[4..8].copy_from_slice(&declared_size.to_le_bytes());

        let parsed = PrefetchParser::parse(&wrapped);
        assert_eq!(parsed.status, PrefetchStatus::Partial);
        assert!(!parsed.is_complete);
        assert!(parsed.is_mam_compressed);
        assert_eq!(parsed.mam_uncompressed_size, Some(declared_size));
        assert_eq!(
            parsed.header.as_ref().map(|header| header.run_count),
            Some(11)
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("3 byte shortfall")),
            "{:?}",
            parsed.warnings
        );
    }

    #[test]
    fn test_prefetch_mam_v3_recognition() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(b"MAM\x03");
        data[4..8].copy_from_slice(&32768_u32.to_le_bytes());

        let res = PrefetchParser::parse(&data);
        assert_eq!(res.status, PrefetchStatus::MamCompressedNotDecompressed);
        assert!(res.is_mam_compressed);
        assert_eq!(res.mam_uncompressed_size, Some(32768));
        assert!(!res.is_complete);
    }

    #[test]
    fn test_prefetch_mam_unknown_version_recognition() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(b"MAM\x05");
        data[4..8].copy_from_slice(&4096_u32.to_le_bytes());

        let res = PrefetchParser::parse(&data);
        assert_eq!(res.status, PrefetchStatus::MamCompressedNotDecompressed);
        assert!(res.is_mam_compressed);
        assert_eq!(res.mam_uncompressed_size, Some(4096));
        assert!(res.warnings[0].contains("version 0x05"));
        assert!(!res.is_complete);
    }

    #[test]
    fn test_prefetch_version_26_synthetic() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&26_u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        buf[12..16].copy_from_slice(&512_u32.to_le_bytes());
        let exe_u16: Vec<u16> = "NOTEPAD.EXE".encode_utf16().collect();
        for (i, &u) in exe_u16.iter().enumerate() {
            buf[16 + (i * 2)..16 + (i * 2) + 2].copy_from_slice(&u.to_le_bytes());
        }
        buf[76..80].copy_from_slice(&0xDEADBEEF_u32.to_le_bytes());

        // Run count at offset 0xD0 (208)
        buf[208..212].copy_from_slice(&42_u32.to_le_bytes());

        // Timestamp at offset 0x80 (128)
        let ft: i64 = 134116896000000000;
        buf[128..136].copy_from_slice(&ft.to_le_bytes());

        let res = PrefetchParser::parse(&buf);
        assert!(res.header.is_some());
        let header = res.header.unwrap();
        assert_eq!(header.version, 26);
        assert_eq!(header.executable_name, "NOTEPAD.EXE");
        assert_eq!(header.hash_hex, "0xDEADBEEF");
        assert_eq!(header.run_count, 42);
        assert_eq!(header.last_run_timestamps.len(), 1);
    }

    #[test]
    fn test_version_specific_file_information_layouts() {
        for (version, length, file_metrics_offset, run_count_offset) in [
            (23u32, 240usize, 240u32, 152usize),
            (30u32, 304usize, 304u32, 208usize),
            (30u32, 296usize, 296u32, 200usize),
            (31u32, 296usize, 296u32, 200usize),
        ] {
            let mut data = vec![0u8; length];
            data[0..4].copy_from_slice(&version.to_le_bytes());
            data[4..8].copy_from_slice(b"SCCA");
            data[12..16].copy_from_slice(&(length as u32).to_le_bytes());
            data[84..88].copy_from_slice(&file_metrics_offset.to_le_bytes());
            data[run_count_offset..run_count_offset + 4].copy_from_slice(&91u32.to_le_bytes());

            let parsed = PrefetchParser::parse(&data);
            assert_eq!(parsed.status, PrefetchStatus::Success, "version {version}");
            assert_eq!(
                parsed.header.as_ref().map(|header| header.run_count),
                Some(91),
                "version {version}"
            );
            assert_eq!(parsed.source_offsets.header_size, 84);
            assert_eq!(parsed.source_offsets.file_information_offset, 84);
            assert_eq!(parsed.source_offsets.run_count_offset, run_count_offset);
        }
    }

    #[test]
    fn test_prefetch_version_17_synthetic() {
        let mut buf = vec![0u8; 256];
        buf[0..4].copy_from_slice(&17_u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        buf[12..16].copy_from_slice(&256_u32.to_le_bytes());
        let exe_u16: Vec<u16> = "CMD.EXE".encode_utf16().collect();
        for (i, &u) in exe_u16.iter().enumerate() {
            buf[16 + (i * 2)..16 + (i * 2) + 2].copy_from_slice(&u.to_le_bytes());
        }

        // Version 17 File Information starts at 84. Last run is +36 and
        // run count is +60.
        let ft: i64 = 134116896000000000;
        buf[120..128].copy_from_slice(&ft.to_le_bytes());
        buf[144..148].copy_from_slice(&10_u32.to_le_bytes());

        let res = PrefetchParser::parse(&buf);
        assert!(res.header.is_some());
        let header = res.header.unwrap();
        assert_eq!(header.version, 17);
        assert_eq!(header.executable_name, "CMD.EXE");
        assert_eq!(header.run_count, 10);
        assert_eq!(header.last_run_timestamps.len(), 1);
    }

    #[test]
    fn test_prefetch_sections_c_and_d_parsing_synthetic() {
        let mut buf = vec![0u8; 1024];
        let file_len = buf.len() as u32;

        // Header
        buf[0..4].copy_from_slice(&30_u32.to_le_bytes()); // Version 30
        buf[4..8].copy_from_slice(b"SCCA");
        buf[12..16].copy_from_slice(&file_len.to_le_bytes());

        // Executable Name
        let exe_u16: Vec<u16> = "TEST.EXE".encode_utf16().collect();
        for (i, &u) in exe_u16.iter().enumerate() {
            buf[16 + (i * 2)..16 + (i * 2) + 2].copy_from_slice(&u.to_le_bytes());
        }

        let sec_table_off = 84usize;

        // The first File Metrics offset also selects the 220-byte v30 File
        // Information variant (84 + 220 = 304).
        buf[sec_table_off..sec_table_off + 4].copy_from_slice(&304u32.to_le_bytes());
        let sec_c_off = 304u32; // Filename strings table offset
        let fn1: Vec<u16> = "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let fn2: Vec<u16> = "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\KERNEL32.DLL"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut sec_c_bytes = Vec::new();
        for u in fn1 {
            sec_c_bytes.extend_from_slice(&u.to_le_bytes());
        }
        for u in fn2 {
            sec_c_bytes.extend_from_slice(&u.to_le_bytes());
        }
        let sec_c_size = sec_c_bytes.len() as u32;
        buf[sec_c_off as usize..sec_c_off as usize + sec_c_bytes.len()]
            .copy_from_slice(&sec_c_bytes);

        let sec_d_off = 600u32; // Volume info offset
        let sec_d_cnt = 1u32;
        let sec_d_size = 240u32;

        // All offsets inside a volume entry are relative to Section D.
        let dev_path_off = 96u32;
        let dev_path_u16: Vec<u16> = "\\DEVICE\\HARDDISKVOLUME1"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let dev_path_len = (dev_path_u16.len() - 1) as u32;
        for (i, &u) in dev_path_u16.iter().enumerate() {
            let absolute = sec_d_off as usize + dev_path_off as usize + (i * 2);
            buf[absolute..absolute + 2].copy_from_slice(&u.to_le_bytes());
        }

        let dir_strings_off = 160u32;
        let num_dir_strings = 1u32;
        let dir1_u16: Vec<u16> = "\\WINDOWS\\SYSTEM32"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let dir_absolute = sec_d_off as usize + dir_strings_off as usize;
        buf[dir_absolute..dir_absolute + 2].copy_from_slice(&(dir1_u16.len() as u16).to_le_bytes());
        for (i, &u) in dir1_u16.iter().enumerate() {
            let absolute = dir_absolute + 2 + (i * 2);
            buf[absolute..absolute + 2].copy_from_slice(&u.to_le_bytes());
        }
        let vol_entry_start = sec_d_off as usize;
        buf[vol_entry_start..vol_entry_start + 4].copy_from_slice(&dev_path_off.to_le_bytes());
        buf[vol_entry_start + 4..vol_entry_start + 8].copy_from_slice(&dev_path_len.to_le_bytes());
        buf[vol_entry_start + 8..vol_entry_start + 16]
            .copy_from_slice(&134116896000000000i64.to_le_bytes());
        buf[vol_entry_start + 16..vol_entry_start + 20]
            .copy_from_slice(&0x12345678u32.to_le_bytes());
        buf[vol_entry_start + 20..vol_entry_start + 24]
            .copy_from_slice(&dir_strings_off.to_le_bytes());
        buf[vol_entry_start + 24..vol_entry_start + 28]
            .copy_from_slice(&num_dir_strings.to_le_bytes());

        // Set Section Table in SCCA header (at 0x84)
        buf[sec_table_off + 16..sec_table_off + 20].copy_from_slice(&sec_c_off.to_le_bytes());
        buf[sec_table_off + 20..sec_table_off + 24].copy_from_slice(&sec_c_size.to_le_bytes());
        buf[sec_table_off + 24..sec_table_off + 28].copy_from_slice(&sec_d_off.to_le_bytes());
        buf[sec_table_off + 28..sec_table_off + 32].copy_from_slice(&sec_d_cnt.to_le_bytes());
        buf[sec_table_off + 32..sec_table_off + 36].copy_from_slice(&sec_d_size.to_le_bytes());

        let res = PrefetchParser::parse(&buf);
        assert!(res.is_complete);
        assert_eq!(res.status, PrefetchStatus::Success);
        assert_eq!(res.source_offsets.header_size, 84);
        assert_eq!(res.source_offsets.file_information_offset, 84);
        assert_eq!(res.source_offsets.file_information_size, 220);
        assert_eq!(res.source_offsets.section_a_offset, 304);
        assert_eq!(res.source_offsets.section_b_offset, 0);
        assert_eq!(res.source_offsets.section_c_offset, sec_c_off as usize);
        assert_eq!(res.source_offsets.section_d_offset, sec_d_off as usize);
        assert_eq!(res.referenced_filenames.len(), 2);
        assert_eq!(
            res.referenced_filenames[0],
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\NTDLL.DLL"
        );
        assert_eq!(
            res.referenced_filenames[1],
            "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\KERNEL32.DLL"
        );

        assert_eq!(res.volumes.len(), 1);
        let vol = &res.volumes[0];
        assert_eq!(vol.device_path, "\\DEVICE\\HARDDISKVOLUME1");
        assert_eq!(vol.serial_number_hex, "1234-5678");
        assert_eq!(vol.directory_paths.len(), 1);
        assert_eq!(vol.directory_paths[0], "\\WINDOWS\\SYSTEM32");
    }

    #[test]
    fn malformed_directory_record_is_one_warning_and_preserves_the_source() {
        for (char_count, expected) in [(0_u16, "zero-character"), (u16::MAX, "exceeds")] {
            let mut data = vec![0_u8; 504];
            let file_size = data.len() as u32;
            data[0..4].copy_from_slice(&30_u32.to_le_bytes());
            data[4..8].copy_from_slice(b"SCCA");
            data[12..16].copy_from_slice(&file_size.to_le_bytes());
            data[84..88].copy_from_slice(&304_u32.to_le_bytes());

            let section_d_offset = 304_u32;
            let section_d_size = 200_u32;
            data[108..112].copy_from_slice(&section_d_offset.to_le_bytes());
            data[112..116].copy_from_slice(&1_u32.to_le_bytes());
            data[116..120].copy_from_slice(&section_d_size.to_le_bytes());

            let volume = section_d_offset as usize;
            data[volume + 20..volume + 24].copy_from_slice(&190_u32.to_le_bytes());
            data[volume + 24..volume + 28].copy_from_slice(&u32::MAX.to_le_bytes());
            let directory = volume + 190;
            data[directory..directory + 2].copy_from_slice(&char_count.to_le_bytes());

            let parsed = PrefetchParser::parse(&data);
            assert_eq!(parsed.status, PrefetchStatus::CorruptSectionOffsets);
            assert!(!parsed.is_complete);
            assert!(parsed.header.is_some());
            assert_eq!(parsed.volumes.len(), 1);
            assert!(parsed.volumes[0].directory_paths.is_empty());
            let directory_warnings = parsed
                .warnings
                .iter()
                .filter(|warning| warning.contains("Volume 0 directory"))
                .collect::<Vec<_>>();
            assert_eq!(directory_warnings.len(), 1, "{:?}", parsed.warnings);
            assert!(directory_warnings[0].contains(expected));
            assert_eq!(parsed.warnings_omitted, 0);
        }
    }

    #[test]
    fn test_prefetch_invalid_signature() {
        let mut buf = vec![0u8; 100];
        buf[0..4].copy_from_slice(&26_u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"FAIL");

        let res = PrefetchParser::parse(&buf);
        assert_eq!(res.status, PrefetchStatus::InvalidSignature);
        assert!(!res.is_complete);
    }

    #[test]
    fn test_prefetch_corrupt_short_header() {
        let buf = vec![0u8; 5];
        let res = PrefetchParser::parse(&buf);
        assert_eq!(res.status, PrefetchStatus::CorruptHeader);
        assert!(!res.is_complete);
    }

    #[test]
    fn test_declared_size_mismatch_marks_incomplete() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&26_u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        buf[12..16].copy_from_slice(&9999_u32.to_le_bytes()); // Mismatched declared size

        let res = PrefetchParser::parse(&buf);
        assert!(!res.is_complete);
        assert_eq!(res.status, PrefetchStatus::Partial);
        assert!(!res.warnings.is_empty());
    }

    #[test]
    fn test_invalid_utf16_is_visible_partial_not_structural_corruption() {
        let mut data = vec![0u8; 304];
        data[0..4].copy_from_slice(&26u32.to_le_bytes());
        data[4..8].copy_from_slice(b"SCCA");
        data[12..16].copy_from_slice(&304u32.to_le_bytes());
        data[16..18].copy_from_slice(&0xD800u16.to_le_bytes());

        let parsed = PrefetchParser::parse(&data);
        assert_eq!(parsed.status, PrefetchStatus::Partial);
        assert!(!parsed.is_complete);
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("unpaired UTF-16 surrogate")));
    }

    #[test]
    fn test_warning_bounding_and_omitted_counts() {
        let mut warnings = Vec::new();
        let mut omitted = 0u64;
        for i in 0..100 {
            record_warning(&mut warnings, &mut omitted, format!("Warning {}", i));
        }
        assert_eq!(warnings.len(), 50);
        assert_eq!(omitted, 50);
    }

    #[test]
    fn test_prefetch_n_plus_1_header_bounds() {
        let mut buf = vec![0u8; 151]; // 84-byte header + 68-byte v17 File Information - 1
        buf[0..4].copy_from_slice(&17_u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");

        let res_sub1 = PrefetchParser::parse(&buf);
        assert_eq!(res_sub1.status, PrefetchStatus::CorruptHeader);

        buf.push(0); // Exactly 152 bytes
        buf[12..16].copy_from_slice(&152_u32.to_le_bytes());
        let res_exact = PrefetchParser::parse(&buf);
        assert!(res_exact.header.is_some());
    }
}
