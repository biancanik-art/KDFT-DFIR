#![forbid(unsafe_code)]

//! Evidence Intake dialog.
//!
//! Provides examiner-configured evidence intake before attachment,
//! including detected container/segment inspection, editable label,
//! searchable IANA timezone selection, integrity verification choices,
//! and exact hashing scope disclosure.

use crate::state::{EvidenceIntakeDialogState, IntakeIntegrityChoice};
use chrono::Offset;
use eframe::egui::{self, Color32, RichText, Window};
use kdft_desktop_core::NativeEvidenceKind;

pub enum EvidenceIntakeAction {
    None,
    Attach {
        source_path: std::path::PathBuf,
        detected_kind: NativeEvidenceKind,
        display_name: String,
        timezone: String,
        integrity_choice: IntakeIntegrityChoice,
        expected_sha256: Option<String>,
        skip_reason: Option<String>,
    },
    Cancel,
}

pub fn show(
    ctx: &egui::Context,
    state: &mut EvidenceIntakeDialogState,
    loading: bool,
) -> EvidenceIntakeAction {
    if !state.visible {
        return EvidenceIntakeAction::None;
    }

    let mut action = EvidenceIntakeAction::None;
    let mut is_open = state.visible;
    let mut close_dialog = false;

    Window::new("Attach Evidence - Evidence Intake Wizard")
        .open(&mut is_open)
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.heading("Evidence Source Intake & Integrity");
            ui.add_space(4.0);

            // Source & Format inspection
            ui.group(|ui| {
                ui.strong("Source Identification");
                ui.horizontal(|ui| {
                    ui.label("Source Path:");
                    ui.monospace(state.source_path.to_string_lossy());
                });

                ui.horizontal(|ui| {
                    ui.label("Detected Format:");
                    match state.detected_kind {
                        NativeEvidenceKind::Image => {
                            if state.segment_scheme == "ewf_numbered_segments" {
                                ui.colored_label(
                                    Color32::from_rgb(0, 190, 255),
                                    format!("E01 Segment Set ({} segment files)", state.segment_count),
                                );
                            } else if state.segment_scheme == "split_raw_segments" {
                                ui.colored_label(
                                    Color32::from_rgb(0, 190, 255),
                                    format!("Split Raw DD/RAW ({} segment files)", state.segment_count),
                                );
                            } else {
                                ui.colored_label(Color32::from_rgb(0, 190, 255), "Raw Forensic Disk Image");
                            }
                        }
                        NativeEvidenceKind::Folder => {
                            ui.colored_label(Color32::from_rgb(0, 200, 100), "Local Directory / Folder");
                        }
                        NativeEvidenceKind::File => {
                            ui.colored_label(Color32::from_rgb(220, 220, 100), "Single File Evidence");
                        }
                        NativeEvidenceKind::Auto => {
                            ui.colored_label(Color32::from_rgb(0, 190, 255), "Automatic Detection");
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Evidence Label:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.display_name)
                            .hint_text("Examiner label for this evidence")
                            .desired_width(320.0),
                    );
                });
            });

            ui.add_space(6.0);

            // Timezone Selection
            ui.group(|ui| {
                ui.strong("Evidence Acquisition Timezone");
                ui.label(
                    "Set the local timezone for this evidence. Timestamps remain canonical UTC in storage.",
                );

                ui.horizontal(|ui| {
                    ui.label("Selected Timezone:");
                    ui.colored_label(Color32::from_rgb(0, 220, 255), RichText::new(&state.timezone).strong());

                    if ui.button("UTC").clicked() {
                        state.timezone = "UTC".to_string();
                    }
                    if ui.button("System Time").clicked() {
                        state.timezone = detect_system_timezone();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Search IANA Timezones:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.timezone_filter)
                            .hint_text("e.g. New_York, London, Bucharest, Tokyo")
                            .desired_width(220.0),
                    );
                });

                if !state.timezone_filter.trim().is_empty() {
                    let filter = state.timezone_filter.trim().to_lowercase();
                    egui::ScrollArea::vertical()
                        .max_height(80.0)
                        .show(ui, |ui| {
                            let mut matches = 0;
                            for tz in chrono_tz::TZ_VARIANTS.iter().map(|t| t.name()) {
                                if tz.to_lowercase().contains(&filter) {
                                    if ui.selectable_label(state.timezone == tz, tz).clicked() {
                                        state.timezone = tz.to_string();
                                        state.timezone_filter.clear();
                                    }
                                    matches += 1;
                                    if matches >= 20 {
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

            ui.add_space(6.0);

            // Integrity Verification Choice
            ui.group(|ui| {
                ui.strong("Cryptographic Integrity Verification");

                ui.radio_value(
                    &mut state.integrity_choice,
                    IntakeIntegrityChoice::VerifyNow,
                    "Verify now (compare against expected SHA-256)",
                );
                ui.radio_value(
                    &mut state.integrity_choice,
                    IntakeIntegrityChoice::ComputeOnly,
                    "Compute hashes without comparison (Compute SHA-256)",
                );
                ui.radio_value(
                    &mut state.integrity_choice,
                    IntakeIntegrityChoice::Defer,
                    "Defer verification (record unverified, compute later)",
                );
                ui.radio_value(
                    &mut state.integrity_choice,
                    IntakeIntegrityChoice::Skip,
                    "Do not verify (requires mandatory examiner reason)",
                );

                ui.separator();

                match state.integrity_choice {
                    IntakeIntegrityChoice::VerifyNow => {
                        ui.horizontal(|ui| {
                            ui.label("Expected SHA-256:");
                            ui.add(
                                egui::TextEdit::singleline(&mut state.expected_sha256)
                                    .hint_text("64-character hex digest from acquisition manifest")
                                    .desired_width(320.0),
                            );
                        });
                        ui.label(
                            RichText::new("Hashing streams in a background worker without freezing the UI.")
                                .weak(),
                        );
                    }
                    IntakeIntegrityChoice::ComputeOnly => {
                        ui.weak("SHA-256 will be calculated in a background worker and recorded as 'Computed, no expected value'.");
                    }
                    IntakeIntegrityChoice::Defer => {
                        ui.weak("Evidence will be attached immediately; integrity status set to 'Deferred'.");
                    }
                    IntakeIntegrityChoice::Skip => {
                        ui.horizontal(|ui| {
                            ui.label("Examiner Reason (Mandatory):");
                            ui.add(
                                egui::TextEdit::singleline(&mut state.skip_reason)
                                    .hint_text("Reason for omitting cryptographic integrity verification")
                                    .desired_width(300.0),
                            );
                        });
                    }
                }

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.strong("Exact Hashing Scope:");
                    ui.label(&state.scope_description);
                });
            });

            if let Some(err) = &state.error {
                ui.add_space(4.0);
                ui.colored_label(Color32::from_rgb(255, 90, 90), RichText::new(err).strong());
            }

            ui.add_space(8.0);
            ui.separator();

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!loading, egui::Button::new(RichText::new("Attach Evidence").strong()))
                    .clicked()
                {
                    // Validation
                    if state.display_name.trim().is_empty() {
                        state.error = Some("Evidence label cannot be empty.".to_string());
                    } else if state.integrity_choice == IntakeIntegrityChoice::Skip
                        && state.skip_reason.trim().is_empty()
                    {
                        state.error = Some("Mandatory examiner reason required when skipping verification.".to_string());
                    } else if state.integrity_choice == IntakeIntegrityChoice::VerifyNow
                        && !state.expected_sha256.trim().is_empty()
                        && state.expected_sha256.trim().len() != 64
                    {
                        state.error = Some("Expected SHA-256 must be a 64-character hexadecimal digest.".to_string());
                    } else {
                        state.error = None;
                        close_dialog = true;
                        action = EvidenceIntakeAction::Attach {
                            source_path: state.source_path.clone(),
                            detected_kind: state.detected_kind,
                            display_name: state.display_name.trim().to_string(),
                            timezone: state.timezone.clone(),
                            integrity_choice: state.integrity_choice,
                            expected_sha256: if state.expected_sha256.trim().is_empty() {
                                None
                            } else {
                                Some(state.expected_sha256.trim().to_lowercase())
                            },
                            skip_reason: if state.skip_reason.trim().is_empty() {
                                None
                            } else {
                                Some(state.skip_reason.trim().to_string())
                            },
                        };
                    }
                }

                if ui.button("Cancel").clicked() {
                    close_dialog = true;
                    action = EvidenceIntakeAction::Cancel;
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
    // Try to match standard offset or return UTC if 0
    if offset_seconds == 0 {
        return "UTC".to_string();
    }
    // Search chrono-tz for variant with matching offset
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
