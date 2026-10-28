#![forbid(unsafe_code)]

//! Deep search view.
//!
//! Provides paginated full-text and pattern search across indexed metadata,
//! parser outputs, and captured content with explicit coverage disclosures.

use crate::state::SearchViewState;
use eframe::egui::{self, Color32, RichText};
use kdft_desktop_core::search::NativeMatchMode;

pub enum SearchViewAction {
    None,
    ExecuteSearch,
    PrevPage,
    NextPage,
    InspectEntry {
        entry_id: i64,
    },
    ViewHex {
        evidence_id: i64,
        entry_id: i64,
        path: String,
        match_offset: Option<u64>,
        match_length: Option<u64>,
    },
    BookmarkResult {
        evidence_id: i64,
        entry_id: i64,
        logical_path: String,
        kind: String,
        match_field: String,
        match_snippet: String,
        match_offset: Option<u64>,
        match_length: Option<u64>,
    },
    ExportResult {
        evidence_id: i64,
        entry_id: i64,
        logical_path: String,
        display_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchHexWindow {
    pub page_offset: u64,
    pub selected_byte_offset: Option<usize>,
    pub selected_byte_length: Option<usize>,
}

pub fn hex_window_for_match(offset: Option<u64>, length: Option<u64>) -> SearchHexWindow {
    let page_offset = offset.map_or(0, |value| value / 512 * 512);
    SearchHexWindow {
        page_offset,
        selected_byte_offset: offset.and_then(|value| usize::try_from(value - page_offset).ok()),
        selected_byte_length: offset.map(|_| {
            usize::try_from(length.unwrap_or(1).max(1))
                .unwrap_or(usize::MAX)
                .min(512)
        }),
    }
}

fn match_location_text(match_field: &str, offset: Option<u64>, length: Option<u64>) -> String {
    match (match_field, offset) {
        ("content", Some(offset)) => format!(
            "Original file bytes at 0x{offset:X} ({} byte{})",
            length.unwrap_or(1),
            if length.unwrap_or(1) == 1 { "" } else { "s" }
        ),
        ("parsed_content", _) => {
            "Parsed text match — no proven original-file byte offset".to_string()
        }
        ("metadata", _) => "Metadata match — no original-file byte offset".to_string(),
        _ => "Filename/path match — no original-file byte offset".to_string(),
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut SearchViewState, has_case: bool) -> SearchViewAction {
    let mut action = SearchViewAction::None;

    if !has_case {
        ui.centered_and_justified(|ui| {
            ui.label("Open a case to execute deep forensic searches.");
        });
        return action;
    }

    ui.vertical(|ui| {
        ui.heading("Deep Search");
        ui.separator();

        // Search inputs
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Search Query:");
                let text_resp = ui.add(egui::TextEdit::singleline(&mut state.query).desired_width(320.0));

                ui.label("Match Mode:");
                egui::ComboBox::from_id_salt("search_match_mode_combo")
                    .selected_text(match state.match_mode {
                        NativeMatchMode::Contains => "Contains",
                        NativeMatchMode::Exact => "Exact Match",
                        NativeMatchMode::WholeWord => "Whole Word",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut state.match_mode, NativeMatchMode::Contains, "Contains");
                        ui.selectable_value(&mut state.match_mode, NativeMatchMode::Exact, "Exact Match");
                        ui.selectable_value(&mut state.match_mode, NativeMatchMode::WholeWord, "Whole Word");
                    });

                if ui.button(RichText::new("Search").strong()).clicked()
                    || text_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                {
                    action = SearchViewAction::ExecuteSearch;
                }

                if state.loading {
                    ui.spinner();
                    ui.weak("Searching across indexed case records...");
                }
            });
        });

        if let Some(err) = &state.error {
            ui.add_space(4.0);
            ui.colored_label(Color32::from_rgb(255, 100, 100), RichText::new(err).strong());
        }

        // Coverage statement banner
        if let Some(coverage) = &state.coverage_statement {
            ui.add_space(4.0);
            ui.group(|ui| {
                ui.colored_label(Color32::from_rgb(200, 200, 200), format!("Coverage: {coverage}"));
            });
        }

        ui.add_space(8.0);

        // Results count
        if let Some(total) = state.total_matches {
            ui.label(format!("Found {total} matching items across indexed records."));
        }

        // Results list. This deliberately uses bounded, examiner-oriented
        // cards instead of an unbounded Grid: long forensic paths must never
        // push the action controls outside the visible viewport.
        egui::ScrollArea::vertical()
            .max_height(450.0)
            .show(ui, |ui| {
                if state.results.is_empty() {
                    if !state.loading && !state.query.trim().is_empty() {
                        ui.group(|ui| {
                            ui.colored_label(
                                Color32::from_rgb(255, 180, 0),
                                RichText::new(format!("No search results found for \"{}\".", state.query.trim())).strong(),
                            );
                            ui.add_space(4.0);
                            ui.strong("Search Coverage Disclosure:");
                            ui.label("• Indexes searched: Filenames, Logical Paths, Indexed Content Heads (up to configured prefix limit), and Semantic Text Segments.");
                            ui.label("• Exclusions: Files without captured content heads or content beyond prefix limits were not searched for content matches.");
                            ui.label("• Suggestion: Verify exact keyword spelling, try prefix syntax, or enable Content Capture in Processing Options.");
                        });
                    }
                } else {
                    for res in &state.results {
                        let display_path = res.display_path();
                        let location = match_location_text(
                            &res.match_field,
                            res.byte_offset,
                            res.byte_length,
                        );
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let available = (ui.available_width() - 390.0).max(100.0);
                                let name_response = ui.add_sized(
                                    [available, 22.0],
                                    egui::Label::new(RichText::new(&res.display_name).strong())
                                        .truncate()
                                        .sense(egui::Sense::click()),
                                );
                                if name_response
                                    .on_hover_text("Inspect this indexed entry")
                                    .clicked()
                                {
                                    action = SearchViewAction::InspectEntry {
                                        entry_id: res.entry_id,
                                    };
                                }

                                if ui.button("Inspect").clicked() {
                                    action = SearchViewAction::InspectEntry {
                                        entry_id: res.entry_id,
                                    };
                                }
                                let hex_label = if res.has_file_byte_match() {
                                    "Hex at match"
                                } else {
                                    "Hex from start"
                                };
                                if ui
                                    .button(hex_label)
                                    .on_hover_text(if res.has_file_byte_match() {
                                        "Open the logical file page containing the match and highlight its bytes"
                                    } else {
                                        "This hit has no proven file-byte coordinate; open the logical file at byte 0"
                                    })
                                    .clicked()
                                {
                                    action = SearchViewAction::ViewHex {
                                        evidence_id: res.evidence_id,
                                        entry_id: res.entry_id,
                                        path: res.logical_path.clone(),
                                        match_offset: res.byte_offset,
                                        match_length: res.byte_length,
                                    };
                                }
                                if ui.button("Export").clicked() {
                                    action = SearchViewAction::ExportResult {
                                        evidence_id: res.evidence_id,
                                        entry_id: res.entry_id,
                                        logical_path: res.logical_path.clone(),
                                        display_name: res.display_name.clone(),
                                    };
                                }
                                if ui
                                    .button("Bookmark / Report")
                                    .on_hover_text(
                                        "Create a bookmark that retains this search match and can be included in reports",
                                    )
                                    .clicked()
                                {
                                    action = SearchViewAction::BookmarkResult {
                                        evidence_id: res.evidence_id,
                                        entry_id: res.entry_id,
                                        logical_path: res.logical_path.clone(),
                                        kind: res.entry_kind.clone(),
                                        match_field: res.match_field.clone(),
                                        match_snippet: res.match_snippet.clone(),
                                        match_offset: res.byte_offset,
                                        match_length: res.byte_length,
                                    };
                                }
                            });

                            ui.add(
                                egui::Label::new(RichText::new(display_path).monospace())
                                    .truncate(),
                            )
                            .on_hover_text(display_path);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&res.entry_kind).weak());
                                ui.separator();
                                ui.label(location);
                            });
                            if !res.match_snippet.is_empty() {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&res.match_snippet).monospace().weak(),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(&res.match_snippet);
                            }
                        });
                        ui.add_space(4.0);
                    }
                }
            });

        // Pagination
        if !state.results.is_empty() || state.page_index > 0 {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(format!("Page {}", state.page_index + 1));

                if ui
                    .add_enabled(state.page_index > 0, egui::Button::new("< Previous"))
                    .clicked()
                {
                    action = SearchViewAction::PrevPage;
                }

                if ui
                    .add_enabled(state.has_more, egui::Button::new("Next >"))
                    .clicked()
                {
                    action = SearchViewAction::NextPage;
                }
            });
        }
    });

    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_window_page_aligns_and_preserves_match_selection() {
        let window = hex_window_for_match(Some(0x2ff), Some(8));
        assert_eq!(window.page_offset, 0x200);
        assert_eq!(window.selected_byte_offset, Some(0xff));
        assert_eq!(window.selected_byte_length, Some(8));
    }

    #[test]
    fn non_byte_match_opens_at_file_start_without_false_highlight() {
        let window = hex_window_for_match(None, None);
        assert_eq!(window.page_offset, 0);
        assert_eq!(window.selected_byte_offset, None);
        assert_eq!(window.selected_byte_length, None);
    }
}
