//! Bounded decoder for the binary `AppCompatCache` value in a SYSTEM hive.
//!
//! The cache format is undocumented by Microsoft and versioned by its binary
//! header.  This decoder follows the published libyal layout descriptions and
//! only emits fields that the selected layout stores unambiguously.  In
//! particular, the cached `FILETIME` is a file last-modification time, not an
//! execution time, and Windows 10/11 records have no execution flag.

use serde::Serialize;

const WINDOWS_XP_SIGNATURE: u32 = 0xdead_beef;
const WINDOWS_2003_VISTA_SIGNATURE: u32 = 0xbadc_0ffe;
const WINDOWS_7_SIGNATURE: u32 = 0xbadc_0fee;
const WINDOWS_8_HEADER_SIZE: usize = 0x80;
const WINDOWS_10_HEADER_SIZE: usize = 0x30;
const WINDOWS_10_CREATORS_HEADER_SIZE: usize = 0x34;
const WINDOWS_7_ENTRY_X86_SIZE: usize = 32;
const WINDOWS_7_ENTRY_X64_SIZE: usize = 48;
const MODERN_ENTRY_HEADER_SIZE: usize = 12;
const ERROR_SAMPLE_LIMIT: usize = 32;
const ENTRY_SIGNATURE_WINDOWS_8_0: &[u8; 4] = b"00ts";
const ENTRY_SIGNATURE_WINDOWS_8_1_PLUS: &[u8; 4] = b"10ts";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ShimcacheLayout {
    Windows7X86,
    Windows7X64,
    Windows8,
    Windows81,
    Windows10PreCreators,
    Windows10CreatorsOrLater,
}

impl ShimcacheLayout {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Windows7X86 => "Windows 7 / Server 2008 R2 x86",
            Self::Windows7X64 => "Windows 7 / Server 2008 R2 x64",
            Self::Windows8 => "Windows 8 / Server 2012",
            Self::Windows81 => "Windows 8.1 / Server 2012 R2",
            Self::Windows10PreCreators => "Windows 10 pre-Creators",
            Self::Windows10CreatorsOrLater => "Windows 10/11 Creators-or-later",
        }
    }

    const fn execution_flag_semantics(self) -> &'static str {
        match self {
            Self::Windows7X86 | Self::Windows7X64 | Self::Windows8 | Self::Windows81 => {
                "insertion_flags bit 0x2; false means the bit was not set"
            }
            Self::Windows10PreCreators | Self::Windows10CreatorsOrLater => {
                "not recorded by this layout; cache presence alone is not proof of execution"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ShimcacheRecord {
    pub record_index: usize,
    pub record_offset: usize,
    pub record_size: usize,
    pub path_offset: usize,
    pub path_size: usize,
    pub path: String,
    pub file_last_modified_filetime: u64,
    pub execution_flag: Option<bool>,
    pub execution_flag_semantics: &'static str,
    pub insertion_flags: Option<u32>,
    pub entry_checksum_unverified: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ShimcacheDecodeResult {
    pub status: String,
    pub layout: Option<ShimcacheLayout>,
    pub header_signature: Option<u32>,
    pub records_expected: Option<usize>,
    pub records: Vec<ShimcacheRecord>,
    pub malformed_record_count: usize,
    pub diagnostics: Vec<String>,
    pub diagnostics_omitted: usize,
    pub limitation: Option<String>,
}

impl ShimcacheDecodeResult {
    fn new(signature: Option<u32>) -> Self {
        Self {
            status: "malformed".to_string(),
            layout: None,
            header_signature: signature,
            records_expected: None,
            records: Vec::new(),
            malformed_record_count: 0,
            diagnostics: Vec::new(),
            diagnostics_omitted: 0,
            limitation: None,
        }
    }

    fn diagnostic(&mut self, message: impl Into<String>) {
        self.malformed_record_count = self.malformed_record_count.saturating_add(1);
        if self.diagnostics.len() < ERROR_SAMPLE_LIMIT {
            self.diagnostics.push(message.into());
        } else {
            self.diagnostics_omitted = self.diagnostics_omitted.saturating_add(1);
        }
    }

    fn finish_supported(&mut self) {
        self.status = if self.malformed_record_count == 0 {
            "completed".to_string()
        } else if self.records.is_empty() {
            "malformed".to_string()
        } else {
            "partial".to_string()
        };
    }

    pub(super) fn has_failed_coverage(&self) -> bool {
        matches!(self.status.as_str(), "partial" | "malformed")
    }
}

pub(super) fn decode_appcompat_cache(bytes: &[u8]) -> ShimcacheDecodeResult {
    let signature = read_u32(bytes, 0);
    let mut result = ShimcacheDecodeResult::new(signature);
    let Some(signature) = signature else {
        result.diagnostic(format!(
            "AppCompatCache value is {} byte(s), shorter than its 4-byte layout signature",
            bytes.len()
        ));
        return result;
    };
    match signature {
        WINDOWS_XP_SIGNATURE => recognized_unsupported(
            result,
            "Windows XP x86",
            "the legacy fixed-entry Windows XP layout is recognized but not decoded by this build",
        ),
        WINDOWS_2003_VISTA_SIGNATURE => recognized_unsupported(
            result,
            "Windows Server 2003 / Vista / Server 2008",
            "the shared legacy signature cannot establish the OS generation and trailing-field semantics without additional validated context; no records were claimed",
        ),
        WINDOWS_7_SIGNATURE => decode_windows_7(bytes, result),
        0x80 => decode_modern(
            bytes,
            result,
            ModernLayout::Windows8Variant,
            WINDOWS_8_HEADER_SIZE,
            None,
        ),
        0x30 => decode_modern(
            bytes,
            result,
            ModernLayout::Windows10,
            WINDOWS_10_HEADER_SIZE,
            Some(36),
        ),
        0x34 => decode_modern(
            bytes,
            result,
            ModernLayout::Windows10Creators,
            WINDOWS_10_CREATORS_HEADER_SIZE,
            Some(40),
        ),
        _ => {
            result.status = "unrecognized_unsupported".to_string();
            result.limitation = Some(format!(
                "unrecognized AppCompatCache layout signature 0x{signature:08x}; source value retained without claiming decoded records"
            ));
            result
        }
    }
}

fn recognized_unsupported(
    mut result: ShimcacheDecodeResult,
    layout: &str,
    limitation: &str,
) -> ShimcacheDecodeResult {
    result.status = "recognized_unsupported".to_string();
    result.limitation = Some(format!("{layout}: {limitation}"));
    result
}

#[derive(Clone, Copy)]
enum ModernLayout {
    Windows8Variant,
    Windows10,
    Windows10Creators,
}

fn decode_modern(
    bytes: &[u8],
    mut result: ShimcacheDecodeResult,
    variant: ModernLayout,
    header_size: usize,
    count_offset: Option<usize>,
) -> ShimcacheDecodeResult {
    if bytes.len() < header_size {
        result.diagnostic(format!(
            "declared AppCompatCache header size {header_size} exceeds {}-byte value",
            bytes.len()
        ));
        return result;
    }
    let (layout, entry_signature, win81_extra, has_execution_flag) = match variant {
        ModernLayout::Windows8Variant => match bytes.get(header_size..header_size + 4) {
            Some(signature) if signature == ENTRY_SIGNATURE_WINDOWS_8_0 => (
                ShimcacheLayout::Windows8,
                ENTRY_SIGNATURE_WINDOWS_8_0,
                0,
                true,
            ),
            Some(signature) if signature == ENTRY_SIGNATURE_WINDOWS_8_1_PLUS => (
                ShimcacheLayout::Windows81,
                ENTRY_SIGNATURE_WINDOWS_8_1_PLUS,
                2,
                true,
            ),
            Some(signature) if signature.iter().all(|byte| *byte == 0) => {
                result.status = "recognized_unsupported".to_string();
                result.limitation = Some(
                    "Windows 8 header with no cache entries; the 8.0 versus 8.1 variant cannot be established from bytes"
                        .to_string(),
                );
                return result;
            }
            _ => {
                result.diagnostic(
                    "Windows 8 header is not followed by a 00ts or 10ts entry signature",
                );
                return result;
            }
        },
        ModernLayout::Windows10 => (
            ShimcacheLayout::Windows10PreCreators,
            ENTRY_SIGNATURE_WINDOWS_8_1_PLUS,
            0,
            false,
        ),
        ModernLayout::Windows10Creators => (
            ShimcacheLayout::Windows10CreatorsOrLater,
            ENTRY_SIGNATURE_WINDOWS_8_1_PLUS,
            0,
            false,
        ),
    };
    result.layout = Some(layout);
    result.records_expected = count_offset
        .and_then(|offset| read_u32(bytes, offset))
        .map(|count| count as usize);
    let mut cursor = header_size;
    let mut record_index = 0_usize;
    while cursor < bytes.len() {
        let remaining = &bytes[cursor..];
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }
        let Some(actual_signature) = bytes.get(cursor..cursor.saturating_add(4)) else {
            result.diagnostic(format!(
                "record {record_index} at offset {cursor} has a truncated signature"
            ));
            break;
        };
        if actual_signature != entry_signature {
            result.diagnostic(format!(
                "record {record_index} at offset {cursor} has signature {:02x?}, expected {:?}",
                actual_signature,
                String::from_utf8_lossy(entry_signature)
            ));
            break;
        }
        let Some(body_size) = read_u32(bytes, cursor.saturating_add(8)).map(|size| size as usize)
        else {
            result.diagnostic(format!(
                "record {record_index} at offset {cursor} has no body size"
            ));
            break;
        };
        let Some(body_offset) = cursor.checked_add(MODERN_ENTRY_HEADER_SIZE) else {
            result.diagnostic(format!(
                "record {record_index} offset arithmetic overflowed"
            ));
            break;
        };
        let Some(record_end) = body_offset.checked_add(body_size) else {
            result.diagnostic(format!(
                "record {record_index} body size arithmetic overflowed"
            ));
            break;
        };
        if record_end > bytes.len() || record_end <= cursor {
            result.diagnostic(format!(
                "record {record_index} at offset {cursor} declares end {record_end} outside {}-byte value",
                bytes.len()
            ));
            break;
        }
        let checksum = read_u32(bytes, cursor.saturating_add(4));
        let parsed = if has_execution_flag {
            parse_windows_8_record(
                bytes,
                record_index,
                cursor,
                body_offset,
                record_end,
                win81_extra,
                layout,
                checksum,
            )
        } else {
            parse_windows_10_record(
                bytes,
                record_index,
                cursor,
                body_offset,
                record_end,
                layout,
                checksum,
            )
        };
        match parsed {
            Ok(record) => result.records.push(record),
            Err(message) => result.diagnostic(message),
        }
        cursor = record_end;
        record_index = record_index.saturating_add(1);
    }
    if let Some(expected) = result.records_expected {
        let observed = result
            .records
            .len()
            .saturating_add(result.malformed_record_count);
        if observed != expected {
            result.diagnostic(format!(
                "header declares {expected} record(s), but {observed} record boundary/boundaries were observed"
            ));
        }
    }
    result.finish_supported();
    result
}

#[allow(clippy::too_many_arguments)]
fn parse_windows_8_record(
    bytes: &[u8],
    record_index: usize,
    record_offset: usize,
    body_offset: usize,
    record_end: usize,
    win81_extra: usize,
    layout: ShimcacheLayout,
    checksum: Option<u32>,
) -> Result<ShimcacheRecord, String> {
    let path_size = read_u16(bytes, body_offset)
        .map(usize::from)
        .ok_or_else(|| format!("record {record_index} has no path length"))?;
    let path_offset = body_offset
        .checked_add(2)
        .ok_or_else(|| format!("record {record_index} path offset overflowed"))?;
    let after_path = path_offset
        .checked_add(path_size)
        .ok_or_else(|| format!("record {record_index} path length overflowed"))?;
    let timestamp_offset = after_path
        .checked_add(8)
        .and_then(|offset| offset.checked_add(win81_extra))
        .ok_or_else(|| format!("record {record_index} timestamp offset overflowed"))?;
    let data_size_offset = timestamp_offset
        .checked_add(8)
        .ok_or_else(|| format!("record {record_index} data-size offset overflowed"))?;
    validate_embedded_data(bytes, record_index, data_size_offset, record_end)?;
    let path = decode_path(bytes, path_offset, path_size, record_end)
        .map_err(|reason| format!("record {record_index} path: {reason}"))?;
    let insertion_flags = read_u32(bytes, after_path)
        .ok_or_else(|| format!("record {record_index} has no insertion flags"))?;
    let filetime = read_u64(bytes, timestamp_offset)
        .ok_or_else(|| format!("record {record_index} has no file last-modification FILETIME"))?;
    Ok(ShimcacheRecord {
        record_index,
        record_offset,
        record_size: record_end.saturating_sub(record_offset),
        path_offset,
        path_size,
        path,
        file_last_modified_filetime: filetime,
        execution_flag: Some(insertion_flags & 0x2 != 0),
        execution_flag_semantics: layout.execution_flag_semantics(),
        insertion_flags: Some(insertion_flags),
        entry_checksum_unverified: checksum,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_windows_10_record(
    bytes: &[u8],
    record_index: usize,
    record_offset: usize,
    body_offset: usize,
    record_end: usize,
    layout: ShimcacheLayout,
    checksum: Option<u32>,
) -> Result<ShimcacheRecord, String> {
    let path_size = read_u16(bytes, body_offset)
        .map(usize::from)
        .ok_or_else(|| format!("record {record_index} has no path length"))?;
    let path_offset = body_offset
        .checked_add(2)
        .ok_or_else(|| format!("record {record_index} path offset overflowed"))?;
    let timestamp_offset = path_offset
        .checked_add(path_size)
        .ok_or_else(|| format!("record {record_index} path length overflowed"))?;
    let data_size_offset = timestamp_offset
        .checked_add(8)
        .ok_or_else(|| format!("record {record_index} data-size offset overflowed"))?;
    validate_embedded_data(bytes, record_index, data_size_offset, record_end)?;
    let path = decode_path(bytes, path_offset, path_size, record_end)
        .map_err(|reason| format!("record {record_index} path: {reason}"))?;
    let filetime = read_u64(bytes, timestamp_offset)
        .ok_or_else(|| format!("record {record_index} has no file last-modification FILETIME"))?;
    Ok(ShimcacheRecord {
        record_index,
        record_offset,
        record_size: record_end.saturating_sub(record_offset),
        path_offset,
        path_size,
        path,
        file_last_modified_filetime: filetime,
        execution_flag: None,
        execution_flag_semantics: layout.execution_flag_semantics(),
        insertion_flags: None,
        entry_checksum_unverified: checksum,
    })
}

fn validate_embedded_data(
    bytes: &[u8],
    record_index: usize,
    data_size_offset: usize,
    record_end: usize,
) -> Result<(), String> {
    let data_size = read_u32(bytes, data_size_offset)
        .map(|size| size as usize)
        .ok_or_else(|| format!("record {record_index} has no embedded-data length"))?;
    let data_offset = data_size_offset
        .checked_add(4)
        .ok_or_else(|| format!("record {record_index} embedded-data offset overflowed"))?;
    let data_end = data_offset
        .checked_add(data_size)
        .ok_or_else(|| format!("record {record_index} embedded-data length overflowed"))?;
    if data_end != record_end {
        return Err(format!(
            "record {record_index} embedded data ends at {data_end}, but its declared record ends at {record_end}"
        ));
    }
    Ok(())
}

fn decode_windows_7(bytes: &[u8], mut result: ShimcacheDecodeResult) -> ShimcacheDecodeResult {
    const HEADER_SIZE: usize = 128;
    if bytes.len() < HEADER_SIZE {
        result.diagnostic(format!(
            "Windows 7 AppCompatCache header requires {HEADER_SIZE} bytes, value has {}",
            bytes.len()
        ));
        return result;
    }
    let Some(count) = read_u32(bytes, 4).map(|value| value as usize) else {
        result.diagnostic("Windows 7 AppCompatCache header has no record count");
        return result;
    };
    result.records_expected = Some(count);
    if count == 0 {
        result.status = "recognized_unsupported".to_string();
        result.limitation = Some(
            "Windows 7 empty cache; x86 versus x64 entry layout cannot be established from bytes"
                .to_string(),
        );
        return result;
    }
    let x86_valid = windows_7_layout_valid(bytes, count, false);
    let x64_valid = windows_7_layout_valid(bytes, count, true);
    let (layout, entry_size) = match (x86_valid, x64_valid) {
        (true, false) => (ShimcacheLayout::Windows7X86, WINDOWS_7_ENTRY_X86_SIZE),
        (false, true) => (ShimcacheLayout::Windows7X64, WINDOWS_7_ENTRY_X64_SIZE),
        (true, true) => {
            result.status = "recognized_unsupported".to_string();
            result.limitation = Some(
                "Windows 7 cache validates as both x86 and x64; no architecture was guessed and no records were claimed"
                    .to_string(),
            );
            return result;
        }
        (false, false) => {
            result.diagnostic(
                "Windows 7 cache does not satisfy the bounded x86 or x64 record layout",
            );
            return result;
        }
    };
    result.layout = Some(layout);
    for record_index in 0..count {
        let Some(record_offset) = HEADER_SIZE.checked_add(record_index.saturating_mul(entry_size))
        else {
            result.diagnostic(format!("record {record_index} offset overflowed"));
            break;
        };
        match parse_windows_7_record(bytes, record_index, record_offset, entry_size, layout) {
            Ok(record) => result.records.push(record),
            Err(message) => result.diagnostic(message),
        }
    }
    result.finish_supported();
    result
}

fn windows_7_layout_valid(bytes: &[u8], count: usize, x64: bool) -> bool {
    const HEADER_SIZE: usize = 128;
    let entry_size = if x64 {
        WINDOWS_7_ENTRY_X64_SIZE
    } else {
        WINDOWS_7_ENTRY_X86_SIZE
    };
    let Some(records_end) = count
        .checked_mul(entry_size)
        .and_then(|size| HEADER_SIZE.checked_add(size))
    else {
        return false;
    };
    if records_end > bytes.len() {
        return false;
    }
    for index in 0..count {
        let Some(record_offset) = index
            .checked_mul(entry_size)
            .and_then(|size| HEADER_SIZE.checked_add(size))
        else {
            return false;
        };
        let Some(path_size) = read_u16(bytes, record_offset).map(usize::from) else {
            return false;
        };
        let path_offset = if x64 {
            read_u64(bytes, record_offset.saturating_add(8))
                .and_then(|offset| usize::try_from(offset).ok())
        } else {
            read_u32(bytes, record_offset.saturating_add(4)).map(|offset| offset as usize)
        };
        let Some(path_offset) = path_offset else {
            return false;
        };
        if path_size == 0
            || !path_size.is_multiple_of(2)
            || path_offset < records_end
            || path_offset % 2 != 0
            || path_offset
                .checked_add(path_size)
                .is_none_or(|end| end > bytes.len())
            || decode_path(bytes, path_offset, path_size, bytes.len()).is_err()
        {
            return false;
        }
        let (data_size, data_offset) = if x64 {
            (
                read_u64(bytes, record_offset.saturating_add(32)),
                read_u64(bytes, record_offset.saturating_add(40)),
            )
        } else {
            (
                read_u32(bytes, record_offset.saturating_add(24)).map(u64::from),
                read_u32(bytes, record_offset.saturating_add(28)).map(u64::from),
            )
        };
        let (Some(data_size), Some(data_offset)) = (data_size, data_offset) else {
            return false;
        };
        if data_size > 0 {
            let Ok(data_offset) = usize::try_from(data_offset) else {
                return false;
            };
            let Ok(data_size) = usize::try_from(data_size) else {
                return false;
            };
            if data_offset < records_end
                || data_offset
                    .checked_add(data_size)
                    .is_none_or(|end| end > bytes.len())
            {
                return false;
            }
        }
    }
    true
}

fn parse_windows_7_record(
    bytes: &[u8],
    record_index: usize,
    record_offset: usize,
    record_size: usize,
    layout: ShimcacheLayout,
) -> Result<ShimcacheRecord, String> {
    let x64 = layout == ShimcacheLayout::Windows7X64;
    let path_size = read_u16(bytes, record_offset)
        .map(usize::from)
        .ok_or_else(|| format!("record {record_index} has no path size"))?;
    let path_offset = if x64 {
        read_u64(bytes, record_offset.saturating_add(8))
            .and_then(|offset| usize::try_from(offset).ok())
    } else {
        read_u32(bytes, record_offset.saturating_add(4)).map(|offset| offset as usize)
    }
    .ok_or_else(|| format!("record {record_index} has no representable path offset"))?;
    let timestamp_offset = record_offset.saturating_add(if x64 { 16 } else { 8 });
    let flags_offset = record_offset.saturating_add(if x64 { 24 } else { 16 });
    let path = decode_path(bytes, path_offset, path_size, bytes.len())
        .map_err(|reason| format!("record {record_index} path: {reason}"))?;
    let filetime = read_u64(bytes, timestamp_offset)
        .ok_or_else(|| format!("record {record_index} has no file last-modification FILETIME"))?;
    let insertion_flags = read_u32(bytes, flags_offset)
        .ok_or_else(|| format!("record {record_index} has no insertion flags"))?;
    Ok(ShimcacheRecord {
        record_index,
        record_offset,
        record_size,
        path_offset,
        path_size,
        path,
        file_last_modified_filetime: filetime,
        execution_flag: Some(insertion_flags & 0x2 != 0),
        execution_flag_semantics: layout.execution_flag_semantics(),
        insertion_flags: Some(insertion_flags),
        entry_checksum_unverified: None,
    })
}

fn decode_path(
    bytes: &[u8],
    offset: usize,
    size: usize,
    containing_end: usize,
) -> Result<String, &'static str> {
    if size == 0 {
        return Err("empty path is not emitted");
    }
    if !size.is_multiple_of(2) {
        return Err("UTF-16LE path has an odd byte length");
    }
    let end = offset.checked_add(size).ok_or("path range overflowed")?;
    if end > containing_end {
        return Err("path extends beyond its containing record");
    }
    let path_bytes = bytes
        .get(offset..end)
        .ok_or("path extends beyond the value")?;
    let units = path_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&units).map_err(|_| "path contains invalid UTF-16LE")?;
    let decoded = decoded.trim_end_matches('\0');
    let decoded = decoded.strip_prefix("\\??\\").unwrap_or(decoded);
    if decoded.trim().is_empty() {
        return Err("path decodes to an empty string");
    }
    if decoded.contains('\0') {
        return Err("path contains an embedded NUL");
    }
    Ok(decoded.to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use std::path::PathBuf;

    const TEST_FILETIME: u64 = 133_000_000_000_000_000;

    fn utf16le(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    }

    fn modern_record(
        signature: &[u8; 4],
        path: &str,
        insertion_flags: Option<u32>,
        win81_extra: bool,
    ) -> Vec<u8> {
        let path = utf16le(path);
        let mut body = Vec::new();
        body.extend_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        if let Some(flags) = insertion_flags {
            body.extend_from_slice(&flags.to_le_bytes());
            body.extend_from_slice(&0_u32.to_le_bytes());
            if win81_extra {
                body.extend_from_slice(&0_u16.to_le_bytes());
            }
        }
        body.extend_from_slice(&TEST_FILETIME.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes());
        let mut record = Vec::new();
        record.extend_from_slice(signature);
        record.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
        record.extend_from_slice(&(body.len() as u32).to_le_bytes());
        record.extend_from_slice(&body);
        record
    }

    fn windows_10_blob(header_size: usize, path: &str) -> Vec<u8> {
        let mut blob = vec![0_u8; header_size];
        blob[0..4].copy_from_slice(&(header_size as u32).to_le_bytes());
        let count_offset = if header_size == WINDOWS_10_HEADER_SIZE {
            36
        } else {
            40
        };
        blob[count_offset..count_offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        blob.extend_from_slice(&modern_record(
            ENTRY_SIGNATURE_WINDOWS_8_1_PLUS,
            path,
            None,
            false,
        ));
        blob
    }

    fn windows_7_blob(x64: bool, path: &str) -> Vec<u8> {
        let entry_size = if x64 {
            WINDOWS_7_ENTRY_X64_SIZE
        } else {
            WINDOWS_7_ENTRY_X86_SIZE
        };
        let path = utf16le(path);
        let path_offset = 128 + entry_size;
        let mut blob = vec![0_u8; path_offset];
        blob[0..4].copy_from_slice(&WINDOWS_7_SIGNATURE.to_le_bytes());
        blob[4..8].copy_from_slice(&1_u32.to_le_bytes());
        blob[128..130].copy_from_slice(&(path.len() as u16).to_le_bytes());
        blob[130..132].copy_from_slice(&(path.len() as u16 + 2).to_le_bytes());
        if x64 {
            blob[136..144].copy_from_slice(&(path_offset as u64).to_le_bytes());
            blob[144..152].copy_from_slice(&TEST_FILETIME.to_le_bytes());
            blob[152..156].copy_from_slice(&2_u32.to_le_bytes());
        } else {
            blob[132..136].copy_from_slice(&(path_offset as u32).to_le_bytes());
            blob[136..144].copy_from_slice(&TEST_FILETIME.to_le_bytes());
            blob[144..148].copy_from_slice(&2_u32.to_le_bytes());
        }
        blob.extend_from_slice(&path);
        blob
    }

    #[test]
    fn windows_10_and_11_layouts_do_not_invent_execution() {
        for (header_size, expected_layout) in [
            (
                WINDOWS_10_HEADER_SIZE,
                ShimcacheLayout::Windows10PreCreators,
            ),
            (
                WINDOWS_10_CREATORS_HEADER_SIZE,
                ShimcacheLayout::Windows10CreatorsOrLater,
            ),
        ] {
            let parsed = decode_appcompat_cache(&windows_10_blob(
                header_size,
                r"\??\C:\Windows\System32\cmd.exe",
            ));
            assert_eq!(parsed.status, "completed");
            assert_eq!(parsed.layout, Some(expected_layout));
            assert_eq!(parsed.records_expected, Some(1));
            assert_eq!(parsed.records.len(), 1);
            assert_eq!(parsed.records[0].path, r"C:\Windows\System32\cmd.exe");
            assert_eq!(parsed.records[0].execution_flag, None);
            assert!(parsed.records[0]
                .execution_flag_semantics
                .contains("not proof of execution"));
        }
    }

    #[test]
    fn windows_8_variants_decode_only_their_explicit_execution_flag() {
        for (signature, extra, expected_layout) in [
            (
                ENTRY_SIGNATURE_WINDOWS_8_0,
                false,
                ShimcacheLayout::Windows8,
            ),
            (
                ENTRY_SIGNATURE_WINDOWS_8_1_PLUS,
                true,
                ShimcacheLayout::Windows81,
            ),
        ] {
            let mut blob = vec![0_u8; WINDOWS_8_HEADER_SIZE];
            blob[0..4].copy_from_slice(&(WINDOWS_8_HEADER_SIZE as u32).to_le_bytes());
            blob.extend_from_slice(&modern_record(
                signature,
                r"C:\Tools\sample.exe",
                Some(2),
                extra,
            ));
            let parsed = decode_appcompat_cache(&blob);
            assert_eq!(parsed.status, "completed");
            assert_eq!(parsed.layout, Some(expected_layout));
            assert_eq!(parsed.records.len(), 1);
            assert_eq!(parsed.records[0].execution_flag, Some(true));
            assert_eq!(parsed.records[0].insertion_flags, Some(2));
        }
    }

    #[test]
    fn windows_7_architecture_is_selected_by_bounded_offsets() {
        for (x64, expected_layout) in [
            (false, ShimcacheLayout::Windows7X86),
            (true, ShimcacheLayout::Windows7X64),
        ] {
            let parsed = decode_appcompat_cache(&windows_7_blob(x64, r"C:\Legacy\tool.exe"));
            assert_eq!(parsed.status, "completed");
            assert_eq!(parsed.layout, Some(expected_layout));
            assert_eq!(parsed.records.len(), 1);
            assert_eq!(parsed.records[0].execution_flag, Some(true));
            assert_eq!(parsed.records[0].file_last_modified_filetime, TEST_FILETIME);
        }
    }

    #[test]
    fn malformed_and_legacy_layouts_never_claim_records() {
        let mut malformed = windows_10_blob(WINDOWS_10_HEADER_SIZE, r"C:\bad.exe");
        malformed[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        let parsed = decode_appcompat_cache(&malformed);
        assert_eq!(parsed.status, "malformed");
        assert!(parsed.records.is_empty());
        assert!(parsed.malformed_record_count > 0);

        for signature in [WINDOWS_XP_SIGNATURE, WINDOWS_2003_VISTA_SIGNATURE] {
            let parsed = decode_appcompat_cache(&signature.to_le_bytes());
            assert_eq!(parsed.status, "recognized_unsupported");
            assert!(parsed.records.is_empty());
            assert!(parsed.limitation.is_some());
        }
    }

    /// Examiner-owned gold validation. The case is opened query-only, the
    /// SYSTEM hive is recovered to a fresh temporary directory, and both are
    /// left unchanged. Run explicitly with `KDFT_SHIMCACHE_GOLD_CASE` and
    /// `KDFT_SHIMCACHE_GOLD_SYSTEM_ENTRY_ID` set.
    #[test]
    #[ignore = "requires examiner-owned gold case and evidence image"]
    fn gold_system_hive_shimcache_layout_is_supported_read_only() -> Result<()> {
        let case_path = std::env::var_os("KDFT_SHIMCACHE_GOLD_CASE")
            .map(PathBuf::from)
            .context("KDFT_SHIMCACHE_GOLD_CASE is not set")?;
        let entry_id = std::env::var("KDFT_SHIMCACHE_GOLD_SYSTEM_ENTRY_ID")
            .context("KDFT_SHIMCACHE_GOLD_SYSTEM_ENTRY_ID is not set")?
            .parse::<i64>()
            .context("gold SYSTEM entry id is not an i64")?;
        let mut session = crate::EvidenceReadSession::open_worker_read_only(&case_path)?;
        let directory = std::env::temp_dir().join(format!(
            "kdft-shimcache-gold-{}-{entry_id}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)
            .with_context(|| format!("creating {}", directory.display()))?;
        let system_path = directory.join("SYSTEM");
        let validation = (|| -> Result<(ShimcacheDecodeResult, usize, usize, usize)> {
            crate::recover_filesystem_entry_in_session(
                &mut session,
                crate::RecoverEntryOptions {
                    entry_id,
                    output_path: system_path.clone(),
                },
            )?;
            let import = crate::collect_registry_hive_import(&system_path, "SYSTEM", usize::MAX)?;
            let observation = import.entries.iter().find(|entry| {
                entry.metadata["registry_key_path"]
                    .as_str()
                    .is_some_and(|path| {
                        path.replace('\\', "/")
                            .to_ascii_lowercase()
                            .contains("/control/session manager/appcompatcache")
                    })
                    && entry.metadata["registry_value_name"]
                        .as_str()
                        .is_some_and(|name| name.eq_ignore_ascii_case("AppCompatCache"))
            });
            let raw = observation
                .and_then(|entry| entry.raw_value_bytes.as_deref())
                .context("gold SYSTEM hive has no retained AppCompatCache value")?;
            let decoded = decode_appcompat_cache(raw);
            let candidate = super::super::HiveCandidate {
                entry_id,
                source_job_id: 1,
                logical_path: "/gold/SYSTEM".to_string(),
                exact_path: "Windows/System32/config/SYSTEM".to_string(),
                name: "SYSTEM".to_string(),
            };
            let (records, counts) = super::super::derive_hive_records(&candidate, &import);
            Ok((
                decoded,
                records.len(),
                counts.shimcache_sources,
                counts.shimcache_completed,
            ))
        })();
        let file_cleanup = if system_path.exists() {
            std::fs::remove_file(&system_path)
        } else {
            Ok(())
        };
        let directory_cleanup = std::fs::remove_dir(&directory);
        let (parsed, derived_records, derived_sources, completed_sources) = validation?;
        file_cleanup.with_context(|| format!("removing {}", system_path.display()))?;
        directory_cleanup.with_context(|| format!("removing {}", directory.display()))?;
        eprintln!(
            "gold Shimcache validation: status={}, layout={:?}, records={}, malformed={}, diagnostics={}",
            parsed.status,
            parsed.layout,
            parsed.records.len(),
            parsed.malformed_record_count,
            parsed.diagnostics.len()
        );
        assert_eq!(parsed.status, "completed");
        assert_eq!(
            parsed.layout,
            Some(ShimcacheLayout::Windows10CreatorsOrLater)
        );
        assert_eq!(parsed.records.len(), 365);
        assert_eq!(derived_records, 365);
        assert_eq!(derived_sources, 1);
        assert_eq!(completed_sources, 1);
        Ok(())
    }
}
