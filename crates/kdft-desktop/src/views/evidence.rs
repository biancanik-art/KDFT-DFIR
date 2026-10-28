#![forbid(unsafe_code)]

//! Evidence view.
//!
//! Provides evidence attachment, obvious selection, volume detection,
//! BitLocker unlock triggers, and prominent "Analyze Evidence" execution.

use eframe::egui::{self, Color32, RichText};
use kdft_desktop_core::{unlock::BITLOCKER_LOCKED_FILESYSTEM, EvidencePage, EvidenceVolume};

pub enum EvidenceViewAction {
    None,
    AttachImage,
    AttachLocalFolder,
    SelectEvidence(i64),
    AnalyzeEvidence(i64),
    BrowseEvidence(i64),
    ViewRawBytes(i64),
    VerifyIntegrity(i64),
    CancelIntegrity,
    UnlockVolume {
        evidence_id: i64,
        volume_index: usize,
        volume_label: String,
    },
    PrevPage,
    NextPage,
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    evidence_page: Option<&EvidencePage>,
    page_index: usize,
    selected_evidence_id: Option<i64>,
    volumes: &[EvidenceVolume],
    loading: bool,
    error: Option<&str>,
    integrity_running_id: Option<i64>,
    integrity_progress: Option<(u64, Option<u64>)>,
) -> EvidenceViewAction {
    let mut action = EvidenceViewAction::None;

    ui.vertical(|ui| {
        // Toolbar
        ui.horizontal(|ui| {
            ui.heading("Evidence Sources");

            ui.add_space(16.0);
            if ui.button("+ Add Disk Image (RAW/DD/E01)...").clicked() {
                action = EvidenceViewAction::AttachImage;
            }
            if ui.button("+ Add Local Folder / Evidence...").clicked() {
                action = EvidenceViewAction::AttachLocalFolder;
            }

            if let Some(id) = selected_evidence_id {
                ui.add_space(16.0);
                if ui
                    .button(
                        RichText::new("⚡ Analyze Evidence...")
                            .strong()
                            .color(Color32::from_rgb(0, 180, 255)),
                    )
                    .on_hover_text(
                        "Open processing presets and artifact extractors for this evidence",
                    )
                    .clicked()
                {
                    action = EvidenceViewAction::AnalyzeEvidence(id);
                }

                if ui.button("Browse Filesystem...").clicked() {
                    action = EvidenceViewAction::BrowseEvidence(id);
                }

                if ui.button("View Raw Media (Hex)...").clicked() {
                    action = EvidenceViewAction::ViewRawBytes(id);
                }

                if ui.button("Verify Integrity...").clicked() {
                    action = EvidenceViewAction::VerifyIntegrity(id);
                }
            }

            if let Some(run_id) = integrity_running_id {
                ui.separator();
                ui.spinner();
                if let Some((done, total)) = integrity_progress {
                    match total {
                        Some(tot) if tot > 0 => {
                            let pct = (done as f64 / tot as f64 * 100.0).clamp(0.0, 100.0);
                            ui.label(format!(
                                "Verifying #{run_id}: {:.1}% ({}/{})",
                                pct,
                                format_bytes(Some(done as i64)),
                                format_bytes(Some(tot as i64))
                            ));
                        }
                        _ => {
                            ui.label(format!(
                                "Verifying #{run_id}: {}",
                                format_bytes(Some(done as i64))
                            ));
                        }
                    }
                } else {
                    ui.label(format!("Verifying #{run_id} cryptographic integrity..."));
                }
                if ui.button("Cancel Verification").clicked() {
                    action = EvidenceViewAction::CancelIntegrity;
                }
            }

            if loading {
                ui.spinner();
            }
        });

        ui.separator();

        if let Some(err) = error {
            ui.colored_label(
                Color32::from_rgb(255, 100, 100),
                RichText::new(err).strong(),
            );
            ui.add_space(8.0);
        }

        let Some(page) = evidence_page else {
            ui.weak("No evidence loaded. Open a case to view evidence sources.");
            return;
        };

        if page.items.is_empty() {
            ui.weak(
                "No evidence attached to this case. Use '+ Add Disk Image' to attach evidence.",
            );
            return;
        }

        // Evidence table
        egui::ScrollArea::vertical()
            .max_height(250.0)
            .show(ui, |ui| {
                egui::Grid::new("evidence_table_grid")
                    .striped(true)
                    .num_columns(7)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        ui.strong("ID");
                        ui.strong("Label / Source");
                        ui.strong("Format");
                        ui.strong("Size");
                        ui.strong("Integrity");
                        ui.strong("Source Path");
                        ui.strong("Action");
                        ui.end_row();

                        for item in &page.items {
                            let is_selected = selected_evidence_id == Some(item.id);

                            let id_text = if is_selected {
                                RichText::new(format!("#{}", item.id))
                                    .strong()
                                    .color(Color32::YELLOW)
                            } else {
                                RichText::new(format!("#{}", item.id))
                            };
                            if ui.selectable_label(is_selected, id_text).clicked() {
                                action = EvidenceViewAction::SelectEvidence(item.id);
                            }

                            let name_text = if is_selected {
                                RichText::new(&item.display_name)
                                    .strong()
                                    .color(Color32::YELLOW)
                            } else {
                                RichText::new(&item.display_name)
                            };
                            if ui.selectable_label(is_selected, name_text).clicked() {
                                action = EvidenceViewAction::SelectEvidence(item.id);
                            }

                            ui.label(&item.source_kind);
                            ui.monospace(format_bytes(item.size_bytes));

                            let integrity_label = match item.integrity_status.as_deref() {
                                Some("verified") => RichText::new("✓ Verified")
                                    .strong()
                                    .color(Color32::from_rgb(0, 220, 100)),
                                Some("computed_no_expected") => RichText::new("ℹ Computed")
                                    .color(Color32::from_rgb(0, 190, 255)),
                                Some("mismatch") => RichText::new("✗ Mismatch")
                                    .strong()
                                    .color(Color32::from_rgb(255, 60, 60)),
                                Some("deferred") => RichText::new("⏳ Deferred")
                                    .color(Color32::from_rgb(255, 170, 0)),
                                Some("skipped") => RichText::new("⊘ Skipped")
                                    .color(Color32::from_rgb(180, 180, 180)),
                                Some("canceled") => RichText::new("Canceled")
                                    .color(Color32::from_rgb(200, 150, 150)),
                                Some("failed") => {
                                    RichText::new("⚠ Failed").color(Color32::from_rgb(255, 80, 80))
                                }
                                _ => {
                                    if item.sha256_hex.is_some() {
                                        RichText::new("ℹ Computed")
                                            .color(Color32::from_rgb(0, 190, 255))
                                    } else {
                                        RichText::new("Unverified").weak()
                                    }
                                }
                            };
                            let resp = ui.label(integrity_label);
                            if let Some(details) = &item.integrity_details_json {
                                resp.on_hover_text(details);
                            } else if let Some(sha) = &item.sha256_hex {
                                resp.on_hover_text(format!("SHA-256: {sha}"));
                            }

                            ui.monospace(&item.source_path_preview);

                            if ui.button("Select").clicked() {
                                action = EvidenceViewAction::SelectEvidence(item.id);
                            }
                            ui.end_row();
                        }
                    });
            });

        // Pagination
        ui.horizontal(|ui| {
            ui.label(format!("Page {}", page_index + 1));
            if ui
                .add_enabled(page_index > 0, egui::Button::new("< Prev Page"))
                .clicked()
            {
                action = EvidenceViewAction::PrevPage;
            }
            if ui
                .add_enabled(page.has_more, egui::Button::new("Next Page >"))
                .clicked()
            {
                action = EvidenceViewAction::NextPage;
            }
        });

        // Selected Evidence Volumes & Details
        if let Some(id) = selected_evidence_id {
            let item_opt = page.items.iter().find(|i| i.id == id);
            if let Some(item) = item_opt {
                ui.add_space(12.0);
                ui.group(|ui| {
                    ui.strong(format!(
                        "Partitions & Volumes for Evidence #{} ({})",
                        item.id, item.display_name
                    ));
                    ui.separator();

                    if volumes.is_empty() {
                        ui.weak("No partition table detected or standalone filesystem image.");
                    } else {
                        egui::Grid::new("volumes_table_grid")
                            .striped(true)
                            .num_columns(5)
                            .spacing([16.0, 6.0])
                            .show(ui, |ui| {
                                ui.strong("Vol #");
                                ui.strong("Label");
                                ui.strong("Filesystem");
                                ui.strong("Length");
                                ui.strong("Action / Security");
                                ui.end_row();

                                for vol in volumes {
                                    ui.label(format!("#{}", vol.index));
                                    ui.label(&vol.name);

                                    let is_bitlocker = vol.is_bitlocker
                                        || vol.filesystem == BITLOCKER_LOCKED_FILESYSTEM
                                        || vol.filesystem.to_lowercase().contains("bitlocker");
                                    if is_bitlocker {
                                        ui.colored_label(
                                            Color32::from_rgb(255, 140, 0),
                                            &vol.filesystem,
                                        );
                                    } else {
                                        ui.label(&vol.filesystem);
                                    }

                                    ui.monospace(format_bytes(Some(vol.size_bytes as i64)));

                                    if is_bitlocker {
                                        if ui
                                            .button(RichText::new("🔑 Unlock...").strong())
                                            .clicked()
                                        {
                                            action = EvidenceViewAction::UnlockVolume {
                                                evidence_id: item.id,
                                                volume_index: vol.index,
                                                volume_label: vol.name.clone(),
                                            };
                                        }
                                    } else {
                                        ui.weak("Unlocked / Clear");
                                    }
                                    ui.end_row();
                                }
                            });
                    }
                });
            }
        }
    });

    action
}

fn format_bytes(bytes: Option<i64>) -> String {
    match bytes {
        Some(b) if b >= 0 => {
            let b = b as u64;
            const KB: u64 = 1024;
            const MB: u64 = 1024 * KB;
            const GB: u64 = 1024 * MB;
            const TB: u64 = 1024 * GB;
            if b >= TB {
                format!("{:.2} TB", b as f64 / TB as f64)
            } else if b >= GB {
                format!("{:.2} GB", b as f64 / GB as f64)
            } else if b >= MB {
                format!("{:.2} MB", b as f64 / MB as f64)
            } else if b >= KB {
                format!("{:.2} KB", b as f64 / KB as f64)
            } else {
                format!("{b} B")
            }
        }
        _ => "Unknown".to_string(),
    }
}
