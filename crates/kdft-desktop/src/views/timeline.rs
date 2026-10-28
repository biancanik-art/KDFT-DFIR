#![forbid(unsafe_code)]

//! Timeline view.
//!
//! Provides a unified, paginated chronological stream of forensic events
//! with timestamp type distinctions and filtering.

use crate::state::TimelineViewState;
use eframe::egui::{self, Color32, RichText};
use kdft_desktop_core::timeline::normalize_utc_boundary;

const TIMELINE_CATEGORIES: &[&str] = &[
    "",
    "Filesystem",
    "Operating System",
    "Windows Registry",
    "Windows Event Logs",
    "Browser Activity",
    "Accounts and Identity",
    "Documents and Office",
    "Program Execution",
    "Network and Connectivity",
    "Archives and Containers",
    "Pictures and Media",
    "Email and Communications",
    "Recovery",
];

pub enum TimelineViewAction {
    None,
    RefreshQuery,
    PrevPage,
    NextPage,
    InspectEntry {
        entry_id: i64,
    },
    BookmarkEvent {
        entry_id: i64,
        path: String,
        kind: String,
    },
}

pub fn show(
    ui: &mut egui::Ui,
    state: &mut TimelineViewState,
    has_case: bool,
) -> TimelineViewAction {
    let mut action = TimelineViewAction::None;

    if !has_case {
        ui.centered_and_justified(|ui| {
            ui.label("Open a case to inspect the chronological forensic timeline.");
        });
        return action;
    }

    ui.vertical(|ui| {
        ui.heading("Forensic Timeline");
        ui.separator();

        // Filters toolbar. Category and timestamp type are discoverable
        // choices; UTC fields advertise and validate precision-capable forms.
        ui.group(|ui| {
            let enter_pressed = ui.input(|input| input.key_pressed(egui::Key::Enter));
            let mut search_entered = false;
            let mut category_changed = false;
            let mut type_changed = false;
            ui.horizontal(|ui| {
                ui.label("Search events:");
                let text_resp =
                    ui.add(egui::TextEdit::singleline(&mut state.text_filter).desired_width(220.0));
                search_entered = text_resp.lost_focus() && enter_pressed;

                ui.label("Category (optional):");
                egui::ComboBox::from_id_salt("timeline_category_filter")
                    .selected_text(if state.category_filter.is_empty() {
                        "All categories"
                    } else {
                        &state.category_filter
                    })
                    .width(190.0)
                    .show_ui(ui, |ui| {
                        for category in TIMELINE_CATEGORIES {
                            let label = if category.is_empty() {
                                "All categories"
                            } else {
                                category
                            };
                            category_changed |= ui
                                .selectable_value(
                                    &mut state.category_filter,
                                    (*category).to_string(),
                                    label,
                                )
                                .changed();
                        }
                    });

                ui.label("Timestamp type:");
                egui::ComboBox::from_id_salt("timeline_timestamp_type")
                    .selected_text(if state.type_filter.is_empty() {
                        "All types"
                    } else {
                        &state.type_filter
                    })
                    .width(130.0)
                    .show_ui(ui, |ui| {
                        for (value, label) in [
                            ("", "All types"),
                            ("Created", "Created"),
                            ("Modified", "Modified"),
                            ("Browser Visit", "Browser Visit"),
                            ("Event Log", "Event Log"),
                            ("Registry Last Write", "Registry Last Write"),
                        ] {
                            type_changed |= ui
                                .selectable_value(
                                    &mut state.type_filter,
                                    value.to_string(),
                                    label,
                                )
                                .changed();
                        }
                    });
            });

            ui.horizontal(|ui| {
                ui.label("From UTC (inclusive):");
                let from_resp = ui
                    .add(
                        egui::TextEdit::singleline(&mut state.from_date)
                            .hint_text("YYYY-MM-DD HH:MM:SS")
                            .desired_width(205.0),
                    )
                    .on_hover_text(
                        "Accepted: YYYY, YYYY-MM-DD, UTC date/time, or RFC 3339. Fractions are supported.",
                    );

                ui.label("To UTC (inclusive):");
                let to_resp = ui
                    .add(
                        egui::TextEdit::singleline(&mut state.to_date)
                            .hint_text("YYYY-MM-DD HH:MM:SS.ffffff")
                            .desired_width(220.0),
                    )
                    .on_hover_text(
                        "Accepted: YYYY, YYYY-MM-DD, UTC date/time, or RFC 3339. A year/date includes its entire period.",
                    );

                let refresh_requested = ui.button("Apply filters").clicked()
                    || search_entered
                    || from_resp.lost_focus() && enter_pressed
                    || to_resp.lost_focus() && enter_pressed;

                if ui.button("Clear").clicked() {
                    state.text_filter.clear();
                    state.category_filter.clear();
                    state.type_filter.clear();
                    state.from_date.clear();
                    state.to_date.clear();
                    state.error = None;
                    action = TimelineViewAction::RefreshQuery;
                } else if refresh_requested || category_changed || type_changed {
                    let validation = normalize_utc_boundary(
                        (!state.from_date.trim().is_empty()).then_some(state.from_date.as_str()),
                        false,
                    )
                    .and_then(|_| {
                        normalize_utc_boundary(
                            (!state.to_date.trim().is_empty()).then_some(state.to_date.as_str()),
                            true,
                        )
                    });
                    match validation {
                        Ok(_) => {
                            state.error = None;
                            action = TimelineViewAction::RefreshQuery;
                        }
                        Err(error) => state.error = Some(error.to_string()),
                    }
                }

                if state.loading {
                    ui.spinner();
                    ui.weak("Loading timeline events...");
                }
            });
        });

        if let Some(err) = &state.error {
            ui.add_space(4.0);
            ui.colored_label(
                Color32::from_rgb(255, 100, 100),
                RichText::new(err).strong(),
            );
        }

        ui.add_space(8.0);

        if !state.loading && !state.events.is_empty() {
            let first = state.page.saturating_mul(state.page_size).saturating_add(1);
            let last = first.saturating_add(state.events.len()).saturating_sub(1);
            ui.label(format!(
                "Showing events {first}-{last} of {} matching timeline events.",
                state.total_matching,
            ));
        }

        // Timeline events table
        egui::ScrollArea::vertical()
            .max_height(480.0)
            .show(ui, |ui| {
                if state.events.is_empty() {
                    if !state.loading && state.error.is_none() {
                        ui.weak("No timestamped timeline events match these filters.");
                    }
                } else {
                    for ev in &state.events {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.monospace(RichText::new(&ev.timestamp_utc).strong());
                                ui.separator();
                                ui.label(RichText::new(&ev.timestamp_type).strong());
                                ui.separator();
                                ui.label(&ev.category);

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let bm_label = if ev.is_bookmarked {
                                            "★ Bookmarked"
                                        } else {
                                            "Bookmark / Report"
                                        };
                                        if ui.button(bm_label).clicked() {
                                            action = TimelineViewAction::BookmarkEvent {
                                                entry_id: ev.entry_id,
                                                path: ev.logical_path.clone(),
                                                kind: ev.category.clone(),
                                            };
                                        }
                                        if ui.button("Inspect").clicked() {
                                            action = TimelineViewAction::InspectEntry {
                                                entry_id: ev.entry_id,
                                            };
                                        }
                                    },
                                );
                            });
                            ui.add(
                                egui::Label::new(RichText::new(&ev.display_name).strong())
                                    .truncate(),
                            )
                            .on_hover_text(&ev.display_name);
                            ui.add(
                                egui::Label::new(RichText::new(&ev.logical_path).monospace())
                                    .truncate(),
                            )
                            .on_hover_text(&ev.logical_path);
                            ui.label(RichText::new(&ev.basis).weak());
                            let origin_color = if ev.event_origin == "Raw filesystem metadata" {
                                Color32::from_rgb(210, 175, 105)
                            } else {
                                Color32::from_rgb(100, 210, 150)
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(format!("Source: {}", ev.event_origin))
                                        .strong()
                                        .color(origin_color),
                                );
                                if ev.event_origin == "Raw filesystem metadata" {
                                    ui.weak(
                                        "This is a file timestamp, not a decoded Registry-change event.",
                                    );
                                } else if !ev.artifact_kind.is_empty() {
                                    ui.monospace(format!("artifact kind: {}", ev.artifact_kind));
                                }
                            });
                        });
                        ui.add_space(4.0);
                    }
                }
            });

        // Pagination
        if !state.events.is_empty() || state.page > 0 {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(format!("Page {}", state.page + 1));

                if ui
                    .add_enabled(state.page > 0, egui::Button::new("< Previous"))
                    .clicked()
                {
                    action = TimelineViewAction::PrevPage;
                }

                if ui
                    .add_enabled(state.has_more, egui::Button::new("Next >"))
                    .clicked()
                {
                    action = TimelineViewAction::NextPage;
                }
            });
        }
    });

    action
}
