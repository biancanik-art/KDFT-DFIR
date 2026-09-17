//! Bounded parser for Windows Recycle Bin index (`$I...`) metadata artifacts.
//!
//! When a file is deleted to the Recycle Bin in Windows Vista through Windows 11,
//! the OS creates a pair of files inside `$Recycle.Bin\<User SID>\`:
//! - `$R<random 6 chars>.<ext>`: The raw deleted file content.
//! - `$I<same random 6 chars>.<ext>`: The deletion metadata record.
//!
//! This module decodes both Version 1 (Windows Vista/7/8) and Version 2 (Windows 10/11)
//! `$I` files to extract the original file path, file size, deletion timestamp, and
//! associated user SID.

#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const MAX_RECYCLE_BIN_SOURCE_BYTES: u64 = 1024 * 1024; // 1 MB safety ceiling

/// A parsed record from a Windows Recycle Bin `$I` index file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecycleBinRecord {
    pub format_version: u64,
    pub original_file_size: u64,
    pub deletion_timestamp_filetime: u64,
    pub deletion_timestamp_utc: Option<String>,
    pub original_path: String,
    pub original_filename: String,
    pub original_extension: Option<String>,
    pub data_file_name: Option<String>,
    pub user_sid: Option<String>,
}

/// Converts a 64-bit Windows FILETIME (100-nanosecond intervals since 1601-01-01)
/// into an RFC-3339 formatted UTC timestamp string.
pub fn filetime_to_rfc3339(filetime: u64) -> Option<String> {
    const FILETIME_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    if filetime < FILETIME_UNIX_EPOCH_100NS {
        return None;
    }
    let nanos_100 = filetime.checked_sub(FILETIME_UNIX_EPOCH_100NS)?;
    let secs = (nanos_100 / 10_000_000) as i64;
    let subsec_nanos = ((nanos_100 % 10_000_000) * 100) as u32;
    DateTime::<Utc>::from_timestamp(secs, subsec_nanos)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Decodes a UTF-16LE byte slice into a clean Rust String, trimming at the first null character.
pub fn decode_utf16le_string(bytes: &[u8]) -> String {
    let u16_chars: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u16_chars)
}

/// Extracts the user SID from a Recycle Bin path (e.g. `$Recycle.Bin\S-1-5-21-...\$I123456.txt`).
pub fn extract_sid_from_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    for segment in normalized.split('/') {
        if segment.starts_with("S-1-") || segment.starts_with("s-1-") {
            return Some(segment.to_string());
        }
    }
    None
}

/// Computes the corresponding `$R` data payload filename from an `$I` index filename.
pub fn compute_data_file_name(index_name: &str) -> Option<String> {
    let trimmed = index_name.trim();
    if trimmed.len() >= 2 {
        let prefix = &trimmed[..2];
        if prefix.eq_ignore_ascii_case("$i") {
            return Some(format!("$R{}", &trimmed[2..]));
        }
    }
    None
}

/// Parses an in-memory buffer of a `$I` file.
pub fn parse_recycle_bin_buffer(bytes: &[u8], source_filename: &str, source_path: &str) -> Result<RecycleBinRecord> {
    if bytes.len() < 24 {
        bail!(
            "Recycle Bin $I file is too small ({} bytes, minimum header is 24 bytes)",
            bytes.len()
        );
    }

    let format_version = u64::from_le_bytes(
        bytes[0..8]
            .try_into()
            .context("reading format version")?,
    );
    let original_file_size = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .context("reading original file size")?,
    );
    let deletion_timestamp_filetime = u64::from_le_bytes(
        bytes[16..24]
            .try_into()
            .context("reading deletion timestamp")?,
    );
    let deletion_timestamp_utc = filetime_to_rfc3339(deletion_timestamp_filetime);

    let original_path = match format_version {
        1 => {
            // Windows Vista / 7 / 8 / 8.1:
            // Fixed 520-byte buffer (260 UTF-16LE characters / MAX_PATH) starting at offset 24 (0x18).
            let path_bytes = if bytes.len() >= 24 + 520 {
                &bytes[24..24 + 520]
            } else {
                &bytes[24..]
            };
            decode_utf16le_string(path_bytes)
        }
        2 => {
            // Windows 10 / 11:
            // Offset 24: 4 bytes `char_count` (u32 little-endian)
            // Offset 28: Variable-length UTF-16LE string (char_count * 2 bytes)
            if bytes.len() < 28 {
                bail!(
                    "Version 2 $I file is too short ({} bytes, minimum is 28 bytes)",
                    bytes.len()
                );
            }
            let char_count = u32::from_le_bytes(
                bytes[24..28]
                    .try_into()
                    .context("reading path character count")?,
            ) as usize;

            // Bounded safety limit: paths longer than 16,384 characters are corrupt or malicious
            let max_chars = char_count.min(16384);
            let available_chars = (bytes.len().saturating_sub(28)) / 2;
            let take_chars = max_chars.min(available_chars);
            let path_bytes = &bytes[28..28 + take_chars * 2];
            decode_utf16le_string(path_bytes)
        }
        other => {
            bail!("unsupported Recycle Bin $I format version: {other}");
        }
    };

    let original_filename = original_path
        .replace('\\', "/")
        .split('/')
        .last()
        .map(|s| s.to_string())
        .unwrap_or_else(|| original_path.clone());

    let original_extension = original_filename
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| !ext.is_empty());

    let data_file_name = compute_data_file_name(source_filename);
    let user_sid = extract_sid_from_path(source_path);

    Ok(RecycleBinRecord {
        format_version,
        original_file_size,
        deletion_timestamp_filetime,
        deletion_timestamp_utc,
        original_path,
        original_filename,
        original_extension,
        data_file_name,
        user_sid,
    })
}

/// Parses a `$I` file from disk.
pub fn parse_recycle_bin_file(
    file_path: &Path,
    source_filename: &str,
    source_path: &str,
) -> Result<RecycleBinRecord> {
    let metadata = fs::metadata(file_path)
        .with_context(|| format!("reading metadata for {}", file_path.display()))?;
    let file_size = metadata.len();
    if file_size > MAX_RECYCLE_BIN_SOURCE_BYTES {
        bail!(
            "Recycle Bin $I file is {} bytes, exceeding safety bound of {} bytes",
            file_size,
            MAX_RECYCLE_BIN_SOURCE_BYTES
        );
    }
    let bytes = fs::read(file_path)
        .with_context(|| format!("reading Recycle Bin file {}", file_path.display()))?;
    let effective_filename = if !source_filename.trim().is_empty() {
        source_filename
    } else {
        file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    };
    parse_recycle_bin_buffer(&bytes, effective_filename, source_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_rfc3339() {
        // 2024-01-01T00:00:00Z in Windows FILETIME:
        // Unix epoch = 116444736000000000
        // 2024-01-01 is 1704067200 seconds after Unix epoch
        let filetime = 116_444_736_000_000_000 + 1_704_067_200 * 10_000_000;
        let rfc3339 = filetime_to_rfc3339(filetime);
        assert_eq!(rfc3339.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn test_parse_version_2() {
        let mut data = Vec::new();
        // Version 2 (8 bytes)
        data.extend_from_slice(&2_u64.to_le_bytes());
        // Original size: 4096 bytes (8 bytes)
        data.extend_from_slice(&4096_u64.to_le_bytes());
        // FILETIME: 2024-01-01T00:00:00Z (8 bytes)
        let filetime: u64 = 116_444_736_000_000_000 + 1_704_067_200 * 10_000_000;
        data.extend_from_slice(&filetime.to_le_bytes());

        // Path: C:\Users\Alice\Secret.docx (25 chars + null = 26 chars)
        let path_utf16: Vec<u16> = "C:\\Users\\Alice\\Secret.docx\0".encode_utf16().collect();
        data.extend_from_slice(&(path_utf16.len() as u32).to_le_bytes());
        for c in path_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }

        let record = parse_recycle_bin_buffer(
            &data,
            "$I123456.docx",
            "$RECYCLE.BIN/S-1-5-21-1001/$I123456.docx",
        )
        .expect("must parse v2");

        assert_eq!(record.format_version, 2);
        assert_eq!(record.original_file_size, 4096);
        assert_eq!(record.deletion_timestamp_utc.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(record.original_path, "C:\\Users\\Alice\\Secret.docx");
        assert_eq!(record.original_filename, "Secret.docx");
        assert_eq!(record.original_extension.as_deref(), Some("docx"));
        assert_eq!(record.data_file_name.as_deref(), Some("$R123456.docx"));
        assert_eq!(record.user_sid.as_deref(), Some("S-1-5-21-1001"));
    }

    #[test]
    fn test_parse_version_1() {
        let mut data = Vec::new();
        // Version 1 (8 bytes)
        data.extend_from_slice(&1_u64.to_le_bytes());
        // Original size: 1024 bytes (8 bytes)
        data.extend_from_slice(&1024_u64.to_le_bytes());
        // FILETIME: 2024-01-01T00:00:00Z (8 bytes)
        let filetime: u64 = 116_444_736_000_000_000 + 1_704_067_200 * 10_000_000;
        data.extend_from_slice(&filetime.to_le_bytes());

        // Path: C:\Legacy\OldDoc.txt (fixed 520 bytes buffer)
        let path_utf16: Vec<u16> = "C:\\Legacy\\OldDoc.txt\0".encode_utf16().collect();
        let mut path_bytes = [0_u8; 520];
        for (i, c) in path_utf16.iter().enumerate() {
            let bytes = c.to_le_bytes();
            path_bytes[i * 2] = bytes[0];
            path_bytes[i * 2 + 1] = bytes[1];
        }
        data.extend_from_slice(&path_bytes);

        let record = parse_recycle_bin_buffer(
            &data,
            "$IAB12CD.txt",
            "$RECYCLE.BIN/S-1-5-18/$IAB12CD.txt",
        )
        .expect("must parse v1");

        assert_eq!(record.format_version, 1);
        assert_eq!(record.original_file_size, 1024);
        assert_eq!(record.original_path, "C:\\Legacy\\OldDoc.txt");
        assert_eq!(record.original_filename, "OldDoc.txt");
        assert_eq!(record.original_extension.as_deref(), Some("txt"));
        assert_eq!(record.data_file_name.as_deref(), Some("$RAB12CD.txt"));
        assert_eq!(record.user_sid.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn test_parse_file_on_disk() {
        let dir = std::env::temp_dir().join(format!("kdft-recycle-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("source.recycle.bin");

        let mut data = Vec::new();
        data.extend_from_slice(&2_u64.to_le_bytes());
        data.extend_from_slice(&2048_u64.to_le_bytes());
        let filetime: u64 = 116_444_736_000_000_000 + 1_704_067_200 * 10_000_000;
        data.extend_from_slice(&filetime.to_le_bytes());

        let path_utf16: Vec<u16> = "D:\\Documents\\Report.pdf\0".encode_utf16().collect();
        data.extend_from_slice(&(path_utf16.len() as u32).to_le_bytes());
        for c in path_utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }

        fs::write(&file_path, &data).expect("write temp file");

        let record = parse_recycle_bin_file(
            &file_path,
            "$IZXCVBN.pdf",
            "$Recycle.Bin/S-1-5-21-999999-999999/$IZXCVBN.pdf",
        )
        .expect("must parse file on disk");

        let _ = fs::remove_dir_all(&dir);

        assert_eq!(record.format_version, 2);
        assert_eq!(record.original_file_size, 2048);
        assert_eq!(record.original_path, "D:\\Documents\\Report.pdf");
        assert_eq!(record.original_filename, "Report.pdf");
        assert_eq!(record.original_extension.as_deref(), Some("pdf"));
        assert_eq!(record.data_file_name.as_deref(), Some("$RZXCVBN.pdf"));
        assert_eq!(record.user_sid.as_deref(), Some("S-1-5-21-999999-999999"));
    }
}

