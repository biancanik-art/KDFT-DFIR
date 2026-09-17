//! Windows AppCompatCache (Shimcache) binary artifact parser.
//!
//! Decodes application execution and compatibility cache entries from the
//! `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` binary registry value.
//!
//! Supports:
//! - Windows 10 & 11 (`10ts`, `30ts`, Creators 0xee0f0dc0)
//! - Windows 8 & 8.1 (`0xeeee0f01`, `0xee0f0dc1`)
//! - Windows 7 / 2008 R2 (`0xbadc0fee`)

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Decoded Shimcache record containing executable path and execution metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimcacheEntry {
    pub path: String,
    pub last_modified_utc: Option<String>,
    pub file_size: Option<u64>,
    pub executed: Option<bool>,
    pub raw_filetime: i64,
}

const SIG_WIN10_10TS: &[u8; 4] = b"10ts";
const SIG_WIN10_30TS: &[u8; 4] = b"30ts";
const MAGIC_WIN7: u32 = 0xbadc_0fee;
const MAGIC_WIN8: u32 = 0xeeee_0f01;
const MAGIC_WIN81: u32 = 0xee0f_0dc1;
const MAGIC_WIN10_CREATORS: u32 = 0xee0f_0dc0;

const MAX_PATH_BYTES: usize = 4096;
const MAX_ENTRIES: usize = 100_000;

/// Parse raw AppCompatCache bytes from Windows Registry.
pub fn parse_shimcache(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    if data.len() < 8 {
        bail!("AppCompatCache binary payload too small: {} bytes", data.len());
    }

    // Check magic at offset 0
    let magic = read_u32_le(data, 0);

    let entries = match magic {
        Some(MAGIC_WIN7) => parse_win7(data)?,
        Some(MAGIC_WIN8) | Some(MAGIC_WIN81) => parse_win8(data)?,
        Some(MAGIC_WIN10_CREATORS) => parse_win10_creators(data)?,
        _ => {
            // Check for direct 10ts / 30ts signature at header or scan
            if data.starts_with(SIG_WIN10_10TS) || data.starts_with(SIG_WIN10_30TS) {
                parse_win10_records(data, 0)?
            } else {
                // Heuristic scan for 10ts/30ts records throughout the buffer
                scan_win10_records(data)?
            }
        }
    };

    Ok(entries)
}

fn parse_win7(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    if data.len() < 128 {
        bail!("Windows 7 AppCompatCache header too small");
    }
    let num_entries = read_u32_le(data, 4).unwrap_or(0) as usize;
    if num_entries == 0 || num_entries > MAX_ENTRIES {
        return Ok(Vec::new());
    }

    let mut entries = Vec::with_capacity(num_entries.min(1024));
    let mut offset = 128; // Standard Win7 entry table offset

    for _ in 0..num_entries {
        if offset + 32 > data.len() {
            break;
        }

        let path_len = read_u16_le(data, offset).unwrap_or(0) as usize;
        let path_offset = read_u32_le(data, offset + 4).unwrap_or(0) as usize;
        let filetime = read_i64_le(data, offset + 8).unwrap_or(0);
        let flags = read_u32_le(data, offset + 16).unwrap_or(0);
        let file_size = read_u64_le(data, offset + 20);

        if path_offset < data.len() && path_len > 0 && path_len <= MAX_PATH_BYTES {
            let end = (path_offset + path_len).min(data.len());
            if let Some(path_bytes) = data.get(path_offset..end) {
                let path = decode_utf16_lossy(path_bytes);
                if !path.trim().is_empty() {
                    let executed = if (flags & 0x02) != 0 { Some(true) } else { Some(false) };
                    entries.push(ShimcacheEntry {
                        path,
                        last_modified_utc: filetime_to_iso8601(filetime),
                        file_size,
                        executed,
                        raw_filetime: filetime,
                    });
                }
            }
        }

        offset += 32;
    }

    Ok(entries)
}

fn parse_win8(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    // Windows 8 and 8.1 have a 128-byte header followed by variable records
    let start_offset = if data.len() > 128 { 128 } else { 0 };
    scan_win10_records(&data[start_offset..])
}

fn parse_win10_creators(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    // Windows 10 Creators Update (0xee0f0dc0) has header containing entry count
    let num_entries = read_u32_le(data, 4).unwrap_or(0) as usize;
    let records = scan_win10_records(data)?;
    if num_entries > 0 && records.len() > num_entries {
        Ok(records.into_iter().take(num_entries).collect())
    } else {
        Ok(records)
    }
}

fn parse_win10_records(data: &[u8], mut offset: usize) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();

    while offset + 14 <= data.len() && entries.len() < MAX_ENTRIES {
        let tag = match data.get(offset..offset + 4) {
            Some(t) => t,
            None => break,
        };

        if tag != SIG_WIN10_10TS && tag != SIG_WIN10_30TS {
            break;
        }

        // Header format for 10ts / 30ts:
        // +0: "10ts" (4)
        // +4: unknown / CRC (4)
        // +8: entry data size (4)
        // +12: path length in bytes (2)
        // +14: path string (UTF-16LE)
        // followed by last_modified FILETIME (8)
        let path_len = match read_u16_le(data, offset + 12) {
            Some(len) => len as usize,
            None => break,
        };

        if path_len == 0 || path_len > MAX_PATH_BYTES || offset + 14 + path_len > data.len() {
            offset += 4;
            continue;
        }

        let path_bytes = &data[offset + 14..offset + 14 + path_len];
        let path = decode_utf16_lossy(path_bytes);

        let after_path = offset + 14 + path_len;
        let filetime = if after_path + 8 <= data.len() {
            read_i64_le(data, after_path).unwrap_or(0)
        } else {
            0
        };

        // Advance to next record: entry size is at offset + 8
        let entry_size = read_u32_le(data, offset + 8).unwrap_or(0) as usize;
        let step = if entry_size >= 14 + path_len {
            12 + entry_size // standard record stride
        } else {
            14 + path_len + 8 // minimal stride
        };

        if !path.trim().is_empty() {
            entries.push(ShimcacheEntry {
                path,
                last_modified_utc: filetime_to_iso8601(filetime),
                file_size: None,
                executed: None,
                raw_filetime: filetime,
            });
        }

        offset += step;
    }

    Ok(entries)
}

fn scan_win10_records(data: &[u8]) -> Result<Vec<ShimcacheEntry>> {
    let mut entries = Vec::new();
    let mut cursor = 0;

    while cursor + 22 <= data.len() && entries.len() < MAX_ENTRIES {
        // Find next "10ts" or "30ts"
        let is_10ts = data[cursor..].starts_with(SIG_WIN10_10TS);
        let is_30ts = data[cursor..].starts_with(SIG_WIN10_30TS);

        if !is_10ts && !is_30ts {
            cursor += 1;
            continue;
        }

        let path_len = read_u16_le(data, cursor + 12).unwrap_or(0) as usize;
        if path_len > 0 && path_len <= MAX_PATH_BYTES && cursor + 14 + path_len + 8 <= data.len() {
            let path_bytes = &data[cursor + 14..cursor + 14 + path_len];
            let path = decode_utf16_lossy(path_bytes);

            let ft_offset = cursor + 14 + path_len;
            let filetime = read_i64_le(data, ft_offset).unwrap_or(0);

            if !path.trim().is_empty() && (path.contains('\\') || path.contains('/')) {
                entries.push(ShimcacheEntry {
                    path,
                    last_modified_utc: filetime_to_iso8601(filetime),
                    file_size: None,
                    executed: None,
                    raw_filetime: filetime,
                });
                cursor += 14 + path_len + 8;
                continue;
            }
        }

        cursor += 4;
    }

    Ok(entries)
}

fn decode_utf16_lossy(bytes: &[u8]) -> String {
    let u16_words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let text = String::from_utf16_lossy(&u16_words);
    text.trim_end_matches('\0').to_string()
}

fn filetime_to_iso8601(ft: i64) -> Option<String> {
    if ft <= 0 {
        return None;
    }
    const EPOCH_DIFFERENCE: i64 = 11_644_473_600;
    let seconds_since_1601 = ft.checked_div(10_000_000)?;
    let nanos = (ft.checked_rem(10_000_000)? * 100) as u32;
    let unix_secs = seconds_since_1601.checked_sub(EPOCH_DIFFERENCE)?;
    DateTime::<Utc>::from_timestamp(unix_secs, nanos).map(|dt| dt.to_rfc3339())
}

fn read_u16_le(slice: &[u8], offset: usize) -> Option<u16> {
    let b = slice.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(slice: &[u8], offset: usize) -> Option<u32> {
    let b = slice.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(slice: &[u8], offset: usize) -> Option<u64> {
    let b = slice.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_i64_le(slice: &[u8], offset: usize) -> Option<i64> {
    let b = slice.get(offset..offset + 8)?;
    Some(i64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_or_tiny_payload_fails() {
        assert!(parse_shimcache(&[]).is_err());
        assert!(parse_shimcache(&[0, 1, 2, 3]).is_err());
    }

    #[test]
    fn parse_synthetic_win10_10ts_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(SIG_WIN10_10TS); // +0: 10ts
        data.extend_from_slice(&0u32.to_le_bytes()); // +4: crc
        let path = "C:\\Windows\\System32\\cmd.exe\0";
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        let entry_size = 14 + path_utf16.len() + 8;
        data.extend_from_slice(&(entry_size as u32).to_le_bytes()); // +8: entry size
        data.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes()); // +12: path len
        data.extend_from_slice(&path_utf16); // +14: path
        // 2026-01-01T00:00:00Z in FILETIME = 133800960000000000
        let ft: i64 = 133800960000000000;
        data.extend_from_slice(&ft.to_le_bytes()); // filetime

        let entries = parse_shimcache(&data).expect("should parse win10 10ts record");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "C:\\Windows\\System32\\cmd.exe");
        assert!(entries[0].last_modified_utc.is_some());
    }

    #[test]
    fn parse_synthetic_win7_entry() {
        let mut data = vec![0u8; 128]; // 128 byte header
        data[0..4].copy_from_slice(&MAGIC_WIN7.to_le_bytes()); // magic 0xbadc0fee
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // 1 entry

        // Entry at offset 128 (32 bytes)
        let path_offset = 128 + 32;
        let path = "C:\\Tools\\mimikatz.exe\0";
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();

        data.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes()); // path_len
        data.extend_from_slice(&0u16.to_le_bytes()); // max_len
        data.extend_from_slice(&(path_offset as u32).to_le_bytes()); // path_offset
        let ft: i64 = 133800960000000000;
        data.extend_from_slice(&ft.to_le_bytes()); // filetime
        data.extend_from_slice(&2u32.to_le_bytes()); // flags (executed = true)
        data.extend_from_slice(&1024u64.to_le_bytes()); // file_size
        data.extend_from_slice(&0u32.to_le_bytes()); // 4-byte padding to 32 bytes
        data.extend_from_slice(&path_utf16); // path string

        let entries = parse_shimcache(&data).expect("should parse win7 record");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "C:\\Tools\\mimikatz.exe");
        assert_eq!(entries[0].executed, Some(true));
        assert_eq!(entries[0].file_size, Some(1024));
    }
}
