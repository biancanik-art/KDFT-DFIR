#![forbid(unsafe_code)]

//! Native forensic data interpreter.
//!
//! Interprets raw bytes at cursor as integers (LE/BE), floating point,
//! binary representation, UTF-8/16 strings, GUIDs, Windows FILETIMEs,
//! Unix timestamps, and MS-DOS date/time stamps.

use crate::state::DataInterpreterState;
use chrono::DateTime;
use eframe::egui;

pub fn show(
    ui: &mut egui::Ui,
    state: &mut DataInterpreterState,
    buffer: &[u8],
    relative_offset: usize,
) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.heading("Data Interpreter");
            ui.add_space(8.0);
            if ui
                .selectable_label(state.endianness_le, "Little Endian")
                .clicked()
            {
                state.endianness_le = true;
            }
            if ui
                .selectable_label(!state.endianness_le, "Big Endian")
                .clicked()
            {
                state.endianness_le = false;
            }
        });

        ui.separator();

        if relative_offset >= buffer.len() {
            ui.weak("No byte selected or cursor out of buffer bounds.");
            return;
        }

        let slice = &buffer[relative_offset..];
        let le = state.endianness_le;

        egui::Grid::new("data_interpreter_grid")
            .striped(true)
            .num_columns(2)
            .spacing([20.0, 4.0])
            .show(ui, |ui| {
                // Binary (1 byte)
                ui.label("Binary (8-bit):");
                ui.monospace(format!("{:08b}", slice[0]));
                ui.end_row();

                // 8-bit Integer
                ui.label("Int8 / UInt8:");
                ui.monospace(format!("{} / {}", slice[0] as i8, slice[0]));
                ui.end_row();

                // 16-bit Integer
                ui.label("Int16 / UInt16:");
                if slice.len() >= 2 {
                    let b = [slice[0], slice[1]];
                    let i = if le {
                        i16::from_le_bytes(b)
                    } else {
                        i16::from_be_bytes(b)
                    };
                    let u = if le {
                        u16::from_le_bytes(b)
                    } else {
                        u16::from_be_bytes(b)
                    };
                    ui.monospace(format!("{i} / {u}"));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // 32-bit Integer
                ui.label("Int32 / UInt32:");
                if slice.len() >= 4 {
                    let b = [slice[0], slice[1], slice[2], slice[3]];
                    let i = if le {
                        i32::from_le_bytes(b)
                    } else {
                        i32::from_be_bytes(b)
                    };
                    let u = if le {
                        u32::from_le_bytes(b)
                    } else {
                        u32::from_be_bytes(b)
                    };
                    ui.monospace(format!("{i} / {u}"));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // 64-bit Integer
                ui.label("Int64 / UInt64:");
                if slice.len() >= 8 {
                    let b = [
                        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                        slice[7],
                    ];
                    let i = if le {
                        i64::from_le_bytes(b)
                    } else {
                        i64::from_be_bytes(b)
                    };
                    let u = if le {
                        u64::from_le_bytes(b)
                    } else {
                        u64::from_be_bytes(b)
                    };
                    ui.monospace(format!("{i} / {u}"));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // 32-bit Float
                ui.label("Float32:");
                if slice.len() >= 4 {
                    let b = [slice[0], slice[1], slice[2], slice[3]];
                    let f = if le {
                        f32::from_le_bytes(b)
                    } else {
                        f32::from_be_bytes(b)
                    };
                    ui.monospace(format!("{f:.6e}"));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // 64-bit Float
                ui.label("Float64:");
                if slice.len() >= 8 {
                    let b = [
                        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                        slice[7],
                    ];
                    let f = if le {
                        f64::from_le_bytes(b)
                    } else {
                        f64::from_be_bytes(b)
                    };
                    ui.monospace(format!("{f:.8e}"));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // ASCII / UTF-8
                ui.label("ASCII / UTF-8:");
                let text_sample: String = slice
                    .iter()
                    .take(16)
                    .map(|&b| {
                        if (0x20..=0x7E).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                ui.monospace(format!("\"{text_sample}\""));
                ui.end_row();

                // UTF-16LE
                ui.label("UTF-16LE:");
                if slice.len() >= 2 {
                    let u16_units: Vec<u16> = slice
                        .chunks_exact(2)
                        .take(8)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let s: String = char::decode_utf16(u16_units)
                        .map(|r| r.unwrap_or('\u{FFFD}'))
                        .collect();
                    ui.monospace(format!("\"{s}\""));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // Windows FILETIME
                ui.label("Windows FILETIME:");
                if slice.len() >= 8 {
                    let b = [
                        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                        slice[7],
                    ];
                    let ft = if le {
                        u64::from_le_bytes(b)
                    } else {
                        u64::from_be_bytes(b)
                    };
                    ui.monospace(decode_filetime(ft));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // Unix Timestamp (32-bit & 64-bit)
                ui.label("Unix Timestamp (32-bit):");
                if slice.len() >= 4 {
                    let b = [slice[0], slice[1], slice[2], slice[3]];
                    let ts = if le {
                        u32::from_le_bytes(b)
                    } else {
                        u32::from_be_bytes(b)
                    };
                    ui.monospace(decode_unix_ts(ts as i64));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // MS-DOS Date/Time
                ui.label("MS-DOS Date & Time:");
                if slice.len() >= 4 {
                    let b = [slice[0], slice[1], slice[2], slice[3]];
                    let val = if le {
                        u32::from_le_bytes(b)
                    } else {
                        u32::from_be_bytes(b)
                    };
                    ui.monospace(decode_dos_datetime(val));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();

                // GUID / UUID
                ui.label("GUID (UUID LE):");
                if slice.len() >= 16 {
                    ui.monospace(decode_guid(&slice[..16]));
                } else {
                    ui.weak("<insufficient bytes>");
                }
                ui.end_row();
            });
    });
}

/// Decodes 64-bit Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC).
pub fn decode_filetime(ft: u64) -> String {
    const FILETIME_TO_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
    if ft < FILETIME_TO_UNIX_OFFSET {
        return if ft == 0 {
            "0 (Zero / Not set)".to_string()
        } else {
            "Invalid (before 1970-01-01)".to_string()
        };
    }
    let diff = ft - FILETIME_TO_UNIX_OFFSET;
    let secs = (diff / 10_000_000) as i64;
    let nsecs = ((diff % 10_000_000) * 100) as u32;

    match DateTime::from_timestamp(secs, nsecs) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S.%3f UTC").to_string(),
        None => "Invalid FILETIME (overflow)".to_string(),
    }
}

/// Decodes Unix epoch timestamp (seconds).
pub fn decode_unix_ts(secs: i64) -> String {
    if secs == 0 {
        return "0 (1970-01-01 00:00:00 UTC)".to_string();
    }
    match DateTime::from_timestamp(secs, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Invalid / Out of range".to_string(),
    }
}

/// Decodes 32-bit MS-DOS Date & Time (low 16 bits = time, high 16 bits = date).
pub fn decode_dos_datetime(dos: u32) -> String {
    let time = (dos & 0xFFFF) as u16;
    let date = ((dos >> 16) & 0xFFFF) as u16;

    let sec = ((time & 0x1F) * 2) as u32;
    let min = ((time >> 5) & 0x3F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;

    let day = (date & 0x1F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let year = (((date >> 9) & 0x7F) + 1980) as i32;

    if (1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && min < 60 && sec < 60 {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
    } else {
        "Invalid DOS timestamp".to_string()
    }
}

/// Decodes standard Windows Little-Endian GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
pub fn decode_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return "<invalid>".to_string();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_decoding() {
        // 132439968000000000 = 2020-09-08 00:00:00 UTC
        let ft = 132439968000000000;
        let s = decode_filetime(ft);
        assert!(s.contains("2020-09-08"));
    }

    #[test]
    fn dos_datetime_decoding() {
        // 2020-01-01 12:00:00
        // year = 2020 - 1980 = 40 (0x28)
        // month = 1, day = 1 -> date = (40 << 9) | (1 << 5) | 1 = 0x5021
        // time = 12:00:00 -> hour = 12, min = 0, sec = 0 -> (12 << 11) = 0x6000
        let dos = (0x5021_u32 << 16) | 0x6000;
        let s = decode_dos_datetime(dos);
        assert_eq!(s, "2020-01-01 12:00:00 UTC");
    }

    #[test]
    fn guid_decoding() {
        let b = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let g = decode_guid(&b);
        assert_eq!(g, "{04030201-0605-0807-090A-0B0C0D0E0F10}");
    }
}
