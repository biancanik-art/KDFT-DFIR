#![forbid(unsafe_code)]

//! Case Settings dialog.
//!
//! Provides mid-case display timezone configuration and case settings without
//! altering canonical UTC timestamps stored in SQLite. Audits every change
//! with old value, new value, examiner, and UTC timestamp.

use crate::state::CaseSettingsDialogState;
use chrono::Offset;
use eframe::egui::{self, Color32, RichText, Window};

pub enum CaseSettingsAction {
    None,
    ApplyTimezone { new_timezone: String },
    Close,
}

pub fn show(
    ctx: &egui::Context,
    state: &mut CaseSettingsDialogState,
    loading: bool,
) -> CaseSettingsAction {
    if !state.visible {
        return CaseSettingsAction::None;
    }

    let mut action = CaseSettingsAction::None;
    let mut is_open = state.visible;
    let mut close_dialog = false;

    Window::new("Case Settings & Timezone")
        .open(&mut is_open)
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.heading("Case Timezone & Display Preferences");
            ui.add_space(4.0);

            ui.group(|ui| {
                ui.strong("Display Timezone");
                ui.label(
                    "Changing the case display timezone adjusts how timestamps are rendered across \
                    Browse, Artifacts, Timeline, Search, Bookmarks, and Reports. Canonical source timestamps \
                    remain stored in UTC. Existing evidence sources retain their acquisition timezone.",
                );

                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Current Timezone:");
                    ui.colored_label(
                        Color32::from_rgb(0, 220, 255),
                        RichText::new(&state.current_timezone).strong(),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label("Selected Timezone:");
                    ui.colored_label(
                        Color32::from_rgb(255, 200, 50),
                        RichText::new(&state.selected_timezone).strong(),
                    );

                    if ui.button("UTC").clicked() {
                        state.selected_timezone = "UTC".to_string();
                    }
                    if ui.button("System Time").clicked() {
                        state.selected_timezone = detect_system_timezone();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Search IANA Timezones:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.timezone_filter)
                            .hint_text("e.g. London, Tokyo, New_York, Bucharest")
                            .desired_width(220.0),
                    );
                });

                if !state.timezone_filter.trim().is_empty() {
                    let filter = state.timezone_filter.trim().to_lowercase();
                    egui::ScrollArea::vertical()
                        .max_height(100.0)
                        .show(ui, |ui| {
                            let mut matches = 0;
                            for tz in chrono_tz::TZ_VARIANTS.iter().map(|t| t.name()) {
                                if tz.to_lowercase().contains(&filter) {
                                    if ui.selectable_label(state.selected_timezone == tz, tz).clicked() {
                                        state.selected_timezone = tz.to_string();
                                        state.timezone_filter.clear();
                                    }
                                    matches += 1;
                                    if matches >= 25 {
                                        break;
                                    }
                                }
                            }
                            if matches == 0 {
                                ui.weak("No matching IANA timezones.");
                            }
                        });
                }
            });

            if let Some(err) = &state.error {
                ui.add_space(4.0);
                ui.colored_label(Color32::from_rgb(255, 90, 90), RichText::new(err).strong());
            }

            ui.add_space(8.0);
            ui.separator();

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!loading, egui::Button::new(RichText::new("Apply Timezone").strong()))
                    .clicked()
                {
                    if let Err(e) = kdft_desktop_core::normalized_timezone(&state.selected_timezone) {
                        state.error = Some(format!("Invalid timezone: {e}"));
                    } else {
                        state.error = None;
                        close_dialog = true;
                        action = CaseSettingsAction::ApplyTimezone {
                            new_timezone: state.selected_timezone.clone(),
                        };
                    }
                }

                if ui.button("Close").clicked() {
                    close_dialog = true;
                    action = CaseSettingsAction::Close;
                }

                if loading {
                    ui.spinner();
                }
            });
        });

    if close_dialog {
        is_open = false;
    }
    state.visible = is_open;
    action
}

fn detect_system_timezone() -> String {
    let now = chrono::Local::now();
    let offset_seconds = now.offset().local_minus_utc();
    if offset_seconds == 0 {
        return "UTC".to_string();
    }
    for name in chrono_tz::TZ_VARIANTS.iter().map(|tz| tz.name()) {
        if let Ok(tz) = name.parse::<chrono_tz::Tz>() {
            use chrono::TimeZone;
            let tz_now = tz.from_utc_datetime(&chrono::Utc::now().naive_utc());
            if tz_now.offset().fix().local_minus_utc() == offset_seconds {
                return name.to_string();
            }
        }
    }
    "UTC".to_string()
}
