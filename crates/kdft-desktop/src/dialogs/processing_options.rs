#![forbid(unsafe_code)]

//! Processing configuration dialog ("Analyze Evidence").
//!
//! Provides preset selection, per-volume inclusion checkboxes, truthful processor
//! groups matching existing engines, content-capture configuration, and entry limits.

use crate::state::ProcessingOptionsDialogState;
use eframe::egui::{self, Color32, RichText, Window};
use kdft_desktop_core::processing::{ProcessingPreset, ProcessorGroupSelection};
use kdft_desktop_core::unlock::TransientUnlockManager;

pub enum ProcessingOptionsAction {
    None,
    StartProcessing {
        evidence_id: i64,
        selected_volumes: Vec<usize>,
        preset: ProcessingPreset,
        groups: ProcessorGroupSelection,
        content_capture_enabled: bool,
        max_entries: usize,
    },
    UnlockVolume {
        evidence_id: i64,
        volume_index: usize,
        volume_name: String,
    },
    Cancel,
}

pub fn show(
    ctx: &egui::Context,
    state: &mut ProcessingOptionsDialogState,
    unlock_mgr: Option<&TransientUnlockManager>,
) -> ProcessingOptionsAction {
    if !state.visible {
        return ProcessingOptionsAction::None;
    }

    let mut action = ProcessingOptionsAction::None;
    let mut is_open = state.visible;

    Window::new("Analyze Evidence - Processing Options")
        .open(&mut is_open)
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.heading("Forensic Evidence Processing");
            ui.label(format!("Evidence: {}", state.evidence_name));
            ui.monospace(&state.evidence_path);
            ui.add_space(8.0);

            // Detected volumes
            ui.group(|ui| {
                ui.strong("Target Volumes / Partitions");
                ui.label("Select volumes to include in analysis:");
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .show(ui, |ui| {
                        if state.volumes.is_empty() {
                            ui.weak("No distinct partition volumes detected. Analysis applies to primary source.");
                        } else {
                            for vol in &state.volumes {
                                let is_unlocked = unlock_mgr
                                    .is_some_and(|m| m.is_unlocked(state.evidence_id, vol.index));
                                let is_locked_bitlocker = vol.is_bitlocker && !is_unlocked;
                                let mut checked = state.selected_volumes.contains(&vol.index);
                                let label = format!(
                                    "Volume #{} - {} ({}, {} bytes)",
                                    vol.index,
                                    vol.name,
                                    vol.filesystem,
                                    vol.size_bytes
                                );
                                ui.horizontal(|ui| {
                                    if ui.checkbox(&mut checked, label).changed() {
                                        if checked {
                                            if !state.selected_volumes.contains(&vol.index) {
                                                state.selected_volumes.push(vol.index);
                                            }
                                        } else {
                                            state.selected_volumes.retain(|&idx| idx != vol.index);
                                        }
                                    }
                                    if is_locked_bitlocker {
                                        ui.colored_label(Color32::from_rgb(255, 140, 0), "🔒 BitLocker (Locked)");
                                        if ui.small_button("Unlock…").clicked() {
                                            action = ProcessingOptionsAction::UnlockVolume {
                                                evidence_id: state.evidence_id,
                                                volume_index: vol.index,
                                                volume_name: vol.name.clone(),
                                            };
                                        }
                                    } else if vol.is_bitlocker && is_unlocked {
                                        ui.colored_label(Color32::from_rgb(100, 220, 100), "🔓 BitLocker (Unlocked)");
                                    }
                                });
                            }
                        }
                    });

                let has_locked_vol = state.volumes.iter().any(|vol| {
                    state.selected_volumes.contains(&vol.index)
                        && vol.is_bitlocker
                        && !unlock_mgr
                            .is_some_and(|m| m.is_unlocked(state.evidence_id, vol.index))
                });
                let selected_bitlocker_count = state.volumes.iter().filter(|vol| {
                    state.selected_volumes.contains(&vol.index) && vol.is_bitlocker
                }).count();
                if has_locked_vol {
                    ui.add_space(4.0);
                    ui.colored_label(
                        Color32::from_rgb(255, 120, 100),
                        RichText::new("⚠ One or more selected target volumes are BitLocker-encrypted and locked.\nStarting analysis on locked volumes is blocked. Please unlock the volume(s) first.").strong(),
                    );
                }
                if selected_bitlocker_count > 1 {
                    ui.add_space(4.0);
                    ui.colored_label(
                        Color32::from_rgb(255, 120, 100),
                        RichText::new("⚠ Multiple BitLocker volumes selected.\nTo preserve credential isolation and forensic integrity, select only one BitLocker volume per analysis job.").strong(),
                    );
                }
            });

            ui.add_space(8.0);

            // Presets
            ui.group(|ui| {
                ui.strong("Processing Presets");
                ui.horizontal(|ui| {
                    if ui.selectable_label(state.preset == ProcessingPreset::FullForensicAnalysis, "Full Forensic").clicked() {
                        state.preset = ProcessingPreset::FullForensicAnalysis;
                        state.preset.apply(&mut state.groups);
                        state.content_capture_enabled = true;
                        state.capture_limit = "64 KiB".to_string();
                    }
                    if ui.selectable_label(state.preset == ProcessingPreset::IncidentResponseTriage, "IR Triage").clicked() {
                        state.preset = ProcessingPreset::IncidentResponseTriage;
                        state.preset.apply(&mut state.groups);
                        state.content_capture_enabled = false;
                        state.capture_limit = "Off".to_string();
                    }
                    if ui.selectable_label(state.preset == ProcessingPreset::FilesystemMetadataOnly, "Filesystem Only").clicked() {
                        state.preset = ProcessingPreset::FilesystemMetadataOnly;
                        state.preset.apply(&mut state.groups);
                        state.content_capture_enabled = false;
                        state.capture_limit = "Off".to_string();
                    }
                    if ui.selectable_label(state.preset == ProcessingPreset::Custom, "Custom").clicked() {
                        state.preset = ProcessingPreset::Custom;
                    }
                });
            });

            ui.add_space(8.0);

            // Processor Groups
            ui.group(|ui| {
                ui.strong("Processor Modules");
                ui.label("Active artifact extractors:");
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        let mut g = state.groups.filesystem_metadata;
                        if ui.checkbox(&mut g, "Filesystem & NTFS Metadata").changed() {
                            state.groups.filesystem_metadata = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.deleted_recovery_metadata;
                        if ui.checkbox(&mut g, "Deleted & Recovery Records").changed() {
                            state.groups.deleted_recovery_metadata = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.windows_registry;
                        if ui.checkbox(&mut g, "Windows Registry").changed() {
                            state.groups.windows_registry = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.windows_event_logs;
                        if ui.checkbox(&mut g, "Windows Event Logs").changed() {
                            state.groups.windows_event_logs = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.browser_activity;
                        if ui.checkbox(&mut g, "Web Browsers").changed() {
                            state.groups.browser_activity = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.email;
                        if ui.checkbox(&mut g, "Email & Mailboxes").changed() {
                            state.groups.email = g;
                            state.preset = ProcessingPreset::Custom;
                        }
                    });

                    ui.vertical(|ui| {
                        let mut g = state.groups.lnk_jump_lists;
                        if ui.checkbox(&mut g, "LNK & Jump Lists").changed() {
                            state.groups.lnk_jump_lists = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.prefetch;
                        if ui.checkbox(&mut g, "Prefetch & Execution").changed() {
                            state.groups.prefetch = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.scheduled_tasks;
                        if ui.checkbox(&mut g, "Scheduled Tasks").changed() {
                            state.groups.scheduled_tasks = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.srum_network;
                        if ui.checkbox(&mut g, "SRUM & Network").changed() {
                            state.groups.srum_network = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.accounts_identity;
                        if ui.checkbox(&mut g, "Accounts & Identity").changed() {
                            state.groups.accounts_identity = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.office_documents;
                        if ui.checkbox(&mut g, "Documents & Office").changed() {
                            state.groups.office_documents = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g = state.groups.archives_containers;
                        if ui.checkbox(&mut g, "Archives & Containers").changed() {
                            state.groups.archives_containers = g;
                            state.preset = ProcessingPreset::Custom;
                        }

                        let mut g_sql = false;
                        ui.add_enabled(false, egui::Checkbox::new(&mut g_sql, "SQLite Databases (Not implemented in this build)"))
                            .on_disabled_hover_text("SQLite database parsing is not implemented in this build.");

                        let mut g_pic = false;
                        ui.add_enabled(false, egui::Checkbox::new(&mut g_pic, "Pictures & Media Metadata (Not implemented in this build)"))
                            .on_disabled_hover_text("Picture/media metadata parsing is not implemented in this build.");
                    });
                });
            });

            ui.add_space(8.0);

            // Examiner limits & content capture
            ui.group(|ui| {
                ui.strong("Limits and Content Capture");
                let chk_res = ui.checkbox(
                    &mut state.content_capture_enabled,
                    "Index the first 64 KiB of eligible files for quick content search",
                ).on_hover_text(
                    "Enables bounded prefix capture (up to the limit) for text and hex content indexing into SQLite FTS5 for Deep Search, without buffering full files into memory."
                );
                if chk_res.changed() {
                    if state.content_capture_enabled {
                        if state.capture_limit == "Off" {
                            state.capture_limit = "64 KiB".to_string();
                        }
                    } else {
                        state.capture_limit = "Off".to_string();
                    }
                    state.groups.hashing_content_capture = state.content_capture_enabled;
                    state.preset = ProcessingPreset::Custom;
                }

                ui.horizontal(|ui| {
                    ui.label("Content capture limit:");
                    let prev_limit = state.capture_limit.clone();
                    egui::ComboBox::from_id_salt("capture_limit_combo")
                        .selected_text(&state.capture_limit)
                        .show_ui(ui, |ui| {
                            for opt in ["Off", "64 KiB", "256 KiB", "1 MiB"] {
                                ui.selectable_value(&mut state.capture_limit, opt.to_string(), opt);
                            }
                        });
                    if state.capture_limit != prev_limit {
                        state.content_capture_enabled = state.capture_limit != "Off";
                        state.groups.hashing_content_capture = state.content_capture_enabled;
                        state.preset = ProcessingPreset::Custom;
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Max entries limit (0 = unbounded):");
                    ui.add(egui::TextEdit::singleline(&mut state.max_entries).desired_width(80.0));
                });
            });

            if let Some(err) = &state.error {
                ui.add_space(4.0);
                ui.colored_label(Color32::from_rgb(255, 100, 100), RichText::new(err).strong());
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let has_locked_vol = state.volumes.iter().any(|vol| {
                    state.selected_volumes.contains(&vol.index)
                        && vol.is_bitlocker
                        && !unlock_mgr
                            .is_some_and(|m| m.is_unlocked(state.evidence_id, vol.index))
                });
                let selected_bitlocker_count = state.volumes.iter().filter(|vol| {
                    state.selected_volumes.contains(&vol.index) && vol.is_bitlocker
                }).count();
                let multi_bitlocker = selected_bitlocker_count > 1;
                let can_start = !has_locked_vol
                    && !multi_bitlocker
                    && (state.volumes.is_empty() || !state.selected_volumes.is_empty());
                let start_btn = egui::Button::new(RichText::new("Start Processing").strong());
                let mut response = ui.add_enabled(can_start, start_btn);
                if has_locked_vol {
                    response = response.on_disabled_hover_text("Cannot start analysis: unlock selected BitLocker target volume(s) first.");
                } else if multi_bitlocker {
                    response = response.on_disabled_hover_text("Cannot start analysis: select only one BitLocker volume per job.");
                } else if state.selected_volumes.is_empty() && !state.volumes.is_empty() {
                    response = response.on_disabled_hover_text("Select at least one volume to analyze.");
                } else {
                    response = response.on_hover_text("Execute forensic processing pipeline");
                }

                if can_start && response.clicked() {
                    let max_e = state.max_entries.trim().parse::<usize>().unwrap_or(0);
                    state.visible = false;
                    action = ProcessingOptionsAction::StartProcessing {
                        evidence_id: state.evidence_id,
                        selected_volumes: state.selected_volumes.clone(),
                        preset: state.preset,
                        groups: state.groups.clone(),
                        content_capture_enabled: state.content_capture_enabled,
                        max_entries: max_e,
                    };
                }

                if ui.button("Cancel").clicked() {
                    state.visible = false;
                    action = ProcessingOptionsAction::Cancel;
                }
            });
        });

    if !is_open && state.visible {
        state.visible = false;
        action = ProcessingOptionsAction::Cancel;
    }

    action
}
