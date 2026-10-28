#![forbid(unsafe_code)]

//! Native bounded Hex and ASCII byte viewer.
//!
//! Provides bounded byte examination across logical files, filesystem-relative
//! sectors, raw images, and BitLocker streams without loading whole files into memory.

use crate::state::{DataInterpreterState, HexViewerState};
use eframe::egui::{self, Color32, RichText, Stroke};
use std::{thread, time::Duration};

pub const HEX_PAGE_SIZE: u64 = 512;

/// Normalized inclusive page-relative selection range.
pub fn selected_byte_range(state: &HexViewerState) -> Option<(usize, usize)> {
    let start = state.selected_byte_offset?;
    if start >= state.loaded_bytes.len() {
        return None;
    }
    let length = state.selected_byte_length.unwrap_or(1).max(1);
    let end = start
        .saturating_add(length.saturating_sub(1))
        .min(state.loaded_bytes.len().saturating_sub(1));
    Some((start, end))
}

fn selected_hex_text(state: &HexViewerState) -> Option<String> {
    let (start, end) = selected_byte_range(state)?;
    Some(
        state.loaded_bytes[start..=end]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn selected_ascii_text(state: &HexViewerState) -> Option<String> {
    let (start, end) = selected_byte_range(state)?;
    Some(
        state.loaded_bytes[start..=end]
            .iter()
            .map(|byte| {
                if (0x20..=0x7e).contains(byte) {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect(),
    )
}

/// Queue egui's normal copy event and also write directly to the operating
/// system clipboard.  Windows can briefly lock the clipboard while another
/// process owns it, so retry a bounded number of times and report the actual
/// result instead of presenting an unconditional success message.
fn copy_to_system_clipboard(ctx: &egui::Context, text: String) -> Result<(), String> {
    ctx.copy_text(text.clone());
    let mut last_error = None;
    for attempt in 0..3 {
        match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(&text)) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error.to_string()),
        }
        if attempt < 2 {
            thread::sleep(Duration::from_millis(12));
        }
    }
    Err(format!(
        "system clipboard was unavailable: {}",
        last_error.unwrap_or_else(|| "unknown clipboard error".to_string())
    ))
}

fn copy_selected(
    ctx: &egui::Context,
    state: &mut HexViewerState,
    text: Option<String>,
    success: String,
) {
    let Some(text) = text else {
        state.copy_notice = Some("COPY FAILED: no byte selection is available.".to_string());
        return;
    };
    state.copy_notice = Some(match copy_to_system_clipboard(ctx, text) {
        Ok(()) => format!("COPY SUCCEEDED: {success}"),
        Err(error) => format!("COPY FAILED: {error}"),
    });
}

fn is_mft_stream(path: &str) -> bool {
    path.trim_end_matches('/').eq_ignore_ascii_case("/$MFT")
}

fn forensic_selection_text(state: &HexViewerState) -> Option<String> {
    let (start, end) = selected_byte_range(state)?;
    let logical_start = state.current_offset.saturating_add(start as u64);
    let logical_end = state.current_offset.saturating_add(end as u64);
    let length = end.saturating_sub(start).saturating_add(1);
    let mut lines = vec![
        format!("Source: {}", state.logical_path),
        format!("Length: {length} bytes (0x{length:X})"),
        format!("Logical-file range: 0x{logical_start:X}-0x{logical_end:X} (inclusive)"),
    ];

    if is_mft_stream(&state.logical_path) {
        if let Some(record_size) = state.ntfs_file_record_size.filter(|size| *size > 0) {
            lines.push(format!(
                "$MFT record range: {}+0x{:X} through {}+0x{:X} (record size {} bytes)",
                logical_start / record_size,
                logical_start % record_size,
                logical_end / record_size,
                logical_end % record_size,
                record_size
            ));
        }
    }

    if let Some(base) = state.mapped_filesystem_offset {
        lines.push(format!(
            "Filesystem-volume range: 0x{:X}-0x{:X} (inclusive)",
            base.saturating_add(start as u64),
            base.saturating_add(end as u64)
        ));
    } else {
        lines.push(
            "Filesystem-volume range: unavailable (not verified for this loaded extent)"
                .to_string(),
        );
    }
    if let Some(base) = state.mapped_decoded_media_offset {
        lines.push(format!(
            "Decoded-media range: 0x{:X}-0x{:X} (inclusive)",
            base.saturating_add(start as u64),
            base.saturating_add(end as u64)
        ));
    } else {
        lines.push(
            "Decoded-media range: unavailable (not verified for this loaded extent)".to_string(),
        );
    }
    lines.push(format!("Hex: {}", selected_hex_text(state)?));
    Some(lines.join("\n"))
}

pub fn previous_page_offset(state: &HexViewerState) -> Option<u64> {
    (!state.loading && state.current_offset > 0)
        .then(|| state.current_offset.saturating_sub(HEX_PAGE_SIZE))
}

pub fn next_page_offset(state: &HexViewerState) -> Option<u64> {
    if state.loading || state.error.is_some() || state.loaded_bytes.is_empty() {
        return None;
    }
    let loaded_end = state
        .current_offset
        .saturating_add(state.loaded_bytes.len() as u64);
    let has_more = match state.total_size {
        Some(total_size) => loaded_end < total_size,
        None => state.loaded_bytes.len() as u64 >= HEX_PAGE_SIZE,
    };
    has_more.then(|| state.current_offset.saturating_add(HEX_PAGE_SIZE))
}

pub enum HexViewerAction {
    None,
    NavigateOffset(u64),
    PrevPage,
    NextPage,
    ToggleDataInterpreter,
    Close,
}

pub fn show(
    ui: &mut egui::Ui,
    state: &mut HexViewerState,
    _interpreter_state: &mut DataInterpreterState,
) -> HexViewerAction {
    if !state.active {
        ui.group(|ui| {
            ui.heading("Hex & ASCII Viewer");
            ui.separator();
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("No file selected.\n\nSelect a file in the directory browser above to view its bounded hex and ASCII bytes.").weak());
            });
        });
        return HexViewerAction::None;
    }

    let mut action = HexViewerAction::None;

    ui.group(|ui| {
        // Controls header
        ui.horizontal(|ui| {
            ui.heading("Hex & ASCII Viewer");
            ui.label(format!("[{:?}]", state.source_namespace));
            ui.monospace(&state.logical_path);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    action = HexViewerAction::Close;
                }

                if ui
                    .button("Data Interpreter")
                    .on_hover_text("Open floating Data Interpreter window")
                    .clicked()
                {
                    action = HexViewerAction::ToggleDataInterpreter;
                }

                // Bytes per row selector
                ui.horizontal(|ui| {
                    ui.label("BPR:");
                    if ui.selectable_label(state.bytes_per_row == 8, "8").clicked() {
                        state.bytes_per_row = 8;
                    }
                    if ui
                        .selectable_label(state.bytes_per_row == 16, "16")
                        .clicked()
                    {
                        state.bytes_per_row = 16;
                    }
                    if ui
                        .selectable_label(state.bytes_per_row == 32, "32")
                        .clicked()
                    {
                        state.bytes_per_row = 32;
                    }
                });
            });
        });

        ui.separator();

        // Offset navigation bar
        ui.horizontal(|ui| {
            ui.label("Offset:");
            ui.monospace(format!(
                "0x{:08X} ({})",
                state.current_offset, state.current_offset
            ));

            if let Some(total) = state.total_size {
                ui.label(format!("/ 0x{:08X} ({} bytes)", total, total));
            }

            ui.add_space(16.0);
            if ui
                .add_enabled(
                    previous_page_offset(state).is_some(),
                    egui::Button::new("< Prev Page"),
                )
                .clicked()
            {
                action = HexViewerAction::PrevPage;
            }
            if ui
                .add_enabled(
                    next_page_offset(state).is_some(),
                    egui::Button::new("Next Page >"),
                )
                .clicked()
            {
                action = HexViewerAction::NextPage;
            }

            ui.add_space(8.0);
            ui.label("Jump to (hex/dec):");
            let response = ui
                .add(egui::TextEdit::singleline(&mut state.jump_offset_input).desired_width(100.0));
            if ui.button("Go").clicked()
                || response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            {
                let trimmed = state.jump_offset_input.trim();
                let parsed = if let Some(hex_str) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex_str, 16).ok()
                } else {
                    trimmed
                        .parse::<u64>()
                        .or_else(|_| u64::from_str_radix(trimmed, 16))
                        .ok()
                };
                if let Some(offset) = parsed {
                    if state
                        .total_size
                        .is_some_and(|total_size| total_size == 0 || offset >= total_size)
                    {
                        state.error =
                            Some(format!("Offset 0x{offset:X} is outside this logical file."));
                    } else {
                        action = HexViewerAction::NavigateOffset(offset);
                    }
                }
            }
        });

        // 4 Distinct state displays
        if let Some(err) = &state.error {
            ui.add_space(2.0);
            egui::Frame::new()
                .fill(Color32::from_rgb(74, 28, 32))
                .stroke(Stroke::new(1.5, Color32::from_rgb(230, 90, 90)))
                .inner_margin(6.0)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("Read Error: {err}"))
                            .strong()
                            .color(Color32::LIGHT_RED),
                    );
                });
        }

        if state.loading {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Loading bytes from evidence source...").strong());
            });
        } else if !state.loaded_bytes.is_empty() {
            ui.add_space(2.0);
            let count = state.loaded_bytes.len();
            let start = state.current_offset;
            let end = start + count as u64;
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{count} bytes loaded (offsets 0x{start:08X} - 0x{end:08X})"
                    ))
                    .color(Color32::from_rgb(100, 200, 120)),
                );
                if let Some(selected) = state.selected_byte_offset {
                    let absolute = state.current_offset.saturating_add(selected as u64);
                    let length = state.selected_byte_length.unwrap_or(1).max(1);
                    ui.separator();
                    ui.label(
                        RichText::new(format!(
                            "Selection starts at logical-file offset 0x{absolute:08X} ({length} byte{})",
                            if length == 1 { "" } else { "s" }
                        ))
                        .strong()
                        .color(Color32::YELLOW),
                    );
                }
            });

            if let Some((selected_start, selected_end)) = selected_byte_range(state) {
                let logical_start = state.current_offset.saturating_add(selected_start as u64);
                let logical_end = state.current_offset.saturating_add(selected_end as u64);
                let length = selected_end.saturating_sub(selected_start).saturating_add(1);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "Selection: {length} bytes (0x{length:X}) | logical 0x{logical_start:X}-0x{logical_end:X} inclusive"
                        ))
                        .strong()
                        .color(Color32::from_rgb(120, 205, 255)),
                    );
                    if is_mft_stream(&state.logical_path) {
                        if let Some(record_size) =
                            state.ntfs_file_record_size.filter(|size| *size > 0)
                        {
                            ui.separator();
                            ui.monospace(format!(
                                "$MFT record {}+0x{:X} to {}+0x{:X}",
                                logical_start / record_size,
                                logical_start % record_size,
                                logical_end / record_size,
                                logical_end % record_size
                            ));
                        }
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if let Some(base) = state.mapped_filesystem_offset {
                        ui.monospace(format!(
                            "Filesystem volume: 0x{:X}-0x{:X}",
                            base.saturating_add(selected_start as u64),
                            base.saturating_add(selected_end as u64)
                        ));
                    } else {
                        ui.label(
                            RichText::new(
                                "Filesystem-volume mapping: not proven for this logical extent (the displayed bytes remain valid)",
                            )
                            .weak(),
                        );
                    }
                    ui.separator();
                    if let Some(base) = state.mapped_decoded_media_offset {
                        ui.monospace(format!(
                            "Decoded media: 0x{:X}-0x{:X}",
                            base.saturating_add(selected_start as u64),
                            base.saturating_add(selected_end as u64)
                        ));
                    } else {
                        ui.label(
                            RichText::new(
                                "Decoded-media mapping: not proven for this logical extent",
                            )
                            .weak(),
                        );
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Copy Hex Text").clicked() {
                        let text = selected_hex_text(state);
                        copy_selected(
                            ui.ctx(),
                            state,
                            text,
                            format!(
                                "{length} bytes copied as hex from logical range 0x{logical_start:X}-0x{logical_end:X}."
                            ),
                        );
                    }
                    if ui.button("Copy ASCII").clicked() {
                        let text = selected_ascii_text(state);
                        copy_selected(
                            ui.ctx(),
                            state,
                            text,
                            format!("{length} bytes copied as printable ASCII (non-printable bytes shown as '.')."),
                        );
                    }
                    if ui.button("Copy With Coordinates").clicked() {
                        let text = forensic_selection_text(state);
                        copy_selected(
                            ui.ctx(),
                            state,
                            text,
                            format!("{length} bytes copied with forensic coordinates."),
                        );
                    }
                    if ui.button("Select Loaded Page").clicked() {
                        state.selected_byte_offset = Some(0);
                        state.selected_byte_length = Some(state.loaded_bytes.len());
                        state.selection_drag_anchor = None;
                        state.copy_notice = None;
                    }
                    if ui.button("Clear Selection").clicked() {
                        state.selected_byte_offset = None;
                        state.selected_byte_length = None;
                        state.selection_drag_anchor = None;
                        state.copy_notice = None;
                    }
                });
                if ui.input(|input| input.modifiers.command && input.key_pressed(egui::Key::C)) {
                    let text = selected_hex_text(state);
                    copy_selected(
                        ui.ctx(),
                        state,
                        text,
                        format!(
                            "{length} bytes copied as hex from logical range 0x{logical_start:X}-0x{logical_end:X}."
                        ),
                    );
                }
            }
            if let Some(notice) = &state.copy_notice {
                let color = if notice.starts_with("COPY FAILED") {
                    Color32::LIGHT_RED
                } else {
                    Color32::from_rgb(100, 220, 140)
                };
                ui.label(RichText::new(notice).strong().color(color));
            }
            ui.weak(
                "Select bytes by clicking and dragging. Copy buttons write to the Windows clipboard and report success or failure.",
            );
            for warning in &state.mapping_warnings {
                ui.label(RichText::new(warning).weak());
            }
        } else if state.error.is_none() {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(
                        "No bytes returned for this offset range or file is empty (0 bytes).",
                    )
                    .weak(),
                );
            });
        }

        ui.separator();

        // Hex & ASCII Grid - scrolls both horizontally and vertically to fill pane
        ui.vertical(|ui| {
            let bpr = state.bytes_per_row.max(8);
            // A page is bounded to 512 bytes.  Copying it avoids an immutable
            // borrow of state while pointer gestures update the selection.
            let bytes = state.loaded_bytes.clone();

            if bytes.is_empty() {
                return;
            }

            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let row_count = bytes.len().div_ceil(bpr);
                    let selected_idx = state.selected_byte_offset;
                    let selected_len = state.selected_byte_length.unwrap_or(1).max(1);

                    for row in 0..row_count {
                        let row_start = row * bpr;
                        let row_end = (row_start + bpr).min(bytes.len());
                        let row_bytes = &bytes[row_start..row_end];
                        let file_offset = state.current_offset + row_start as u64;

                        ui.horizontal(|ui| {
                            // Offset column
                            ui.monospace(format!("{:08X}:", file_offset));
                            ui.add_space(4.0);

                            // Hex columns
                            for (col_idx, &b) in row_bytes.iter().enumerate() {
                                let byte_offset = row_start + col_idx;
                                let is_selected = selected_idx.is_some_and(|start| {
                                    byte_offset >= start
                                        && byte_offset < start.saturating_add(selected_len)
                                });
                                let text = format!("{:02X}", b);

                                let label = if is_selected {
                                    RichText::new(text)
                                        .color(Color32::WHITE)
                                        .background_color(Color32::from_rgb(0, 105, 150))
                                } else {
                                    RichText::new(text)
                                };

                                let resp = ui.add(
                                    egui::Label::new(label)
                                        .sense(egui::Sense::click_and_drag()),
                                );
                                if resp.clicked() || resp.drag_started() {
                                    state.selection_drag_anchor = Some(byte_offset);
                                    state.selected_byte_offset = Some(byte_offset);
                                    state.selected_byte_length = Some(1);
                                    state.copy_notice = None;
                                }
                                let pointer_over_cell = ui.input(|input| {
                                    input.pointer.primary_down()
                                        && input
                                            .pointer
                                            .interact_pos()
                                            .is_some_and(|position| resp.rect.contains(position))
                                });
                                if pointer_over_cell {
                                    if let Some(anchor) = state.selection_drag_anchor {
                                        let range_start = anchor.min(byte_offset);
                                        let range_end = anchor.max(byte_offset);
                                        state.selected_byte_offset = Some(range_start);
                                        state.selected_byte_length = Some(
                                            range_end.saturating_sub(range_start).saturating_add(1),
                                        );
                                        state.copy_notice = None;
                                    }
                                }

                                if col_idx % 8 == 7 && col_idx + 1 < bpr {
                                    ui.add_space(4.0);
                                }
                            }

                            // Fill padding if row is short
                            if row_bytes.len() < bpr {
                                let missing = bpr - row_bytes.len();
                                for _ in 0..missing {
                                    ui.monospace("  ");
                                }
                            }

                            ui.separator();

                            // ASCII column
                            let mut ascii_str = String::with_capacity(row_bytes.len());
                            for &b in row_bytes {
                                if (0x20..=0x7E).contains(&b) {
                                    ascii_str.push(b as char);
                                } else {
                                    ascii_str.push('.');
                                }
                            }
                            ui.monospace(ascii_str);
                        });
                    }
                });
            if !ui.input(|input| input.pointer.primary_down()) {
                state.selection_drag_anchor = None;
            }
        });
    });

    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_range_is_inclusive_clamped_and_copyable() {
        let state = HexViewerState {
            active: true,
            logical_path: "/evidence.bin".to_string(),
            current_offset: 0x1000,
            loaded_bytes: vec![0x41, 0x42, 0x00, 0xFF],
            selected_byte_offset: Some(1),
            selected_byte_length: Some(99),
            ..Default::default()
        };

        assert_eq!(selected_byte_range(&state), Some((1, 3)));
        assert_eq!(selected_hex_text(&state).as_deref(), Some("42 00 FF"));
        assert_eq!(selected_ascii_text(&state).as_deref(), Some("B.."));
        let copied = forensic_selection_text(&state).expect("forensic copy");
        assert!(copied.contains("Length: 3 bytes (0x3)"));
        assert!(copied.contains("Logical-file range: 0x1001-0x1003 (inclusive)"));
        assert!(copied.contains("Hex: 42 00 FF"));
    }

    #[test]
    fn mft_selection_uses_authoritative_record_size_and_exact_mappings() {
        let state = HexViewerState {
            active: true,
            logical_path: "/$MFT".to_string(),
            current_offset: 0x1C00,
            loaded_bytes: vec![0x46; 512],
            selected_byte_offset: Some(0),
            selected_byte_length: Some(512),
            ntfs_file_record_size: Some(1024),
            mapped_filesystem_offset: Some(0xC000_1C00),
            mapped_decoded_media_offset: Some(0xD000_1C00),
            ..Default::default()
        };

        let copied = forensic_selection_text(&state).expect("forensic copy");
        assert!(copied.contains("Length: 512 bytes (0x200)"));
        assert!(copied.contains("$MFT record range: 7+0x0 through 7+0x1FF"));
        assert!(copied.contains("Filesystem-volume range: 0xC0001C00-0xC0001DFF"));
        assert!(copied.contains("Decoded-media range: 0xD0001C00-0xD0001DFF"));
    }

    #[test]
    fn absent_mapping_is_declared_instead_of_fabricated() {
        let state = HexViewerState {
            active: true,
            logical_path: "/fragmented.bin".to_string(),
            loaded_bytes: vec![0xAA],
            selected_byte_offset: Some(0),
            selected_byte_length: Some(1),
            ..Default::default()
        };

        let copied = forensic_selection_text(&state).expect("forensic copy");
        assert!(copied.contains("Filesystem-volume range: unavailable"));
        assert!(copied.contains("Decoded-media range: unavailable"));
    }
}
