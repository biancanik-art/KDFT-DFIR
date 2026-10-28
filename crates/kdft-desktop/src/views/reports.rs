#![forbid(unsafe_code)]

//! Reports view.
//!
//! Provides report configuration, preview with truthful forensic disclosures,
//! and export to HTML, JSON, or Markdown formats.

use crate::state::ReportViewState;
use eframe::egui::{self, Color32, RichText};

pub enum ReportsViewAction {
    None,
    GeneratePreview,
    ExportReport(String),
}

pub fn show(ui: &mut egui::Ui, state: &mut ReportViewState, has_case: bool) -> ReportsViewAction {
    let mut action = ReportsViewAction::None;

    if !has_case {
        ui.centered_and_justified(|ui| {
            ui.label("Open a case to generate forensic reports.");
        });
        return action;
    }

    ui.vertical(|ui| {
        ui.heading("Forensic Reports");
        ui.separator();

        // Configuration & Options
        ui.group(|ui| {
            ui.strong("Report Scope & Format");
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("Format:");
                ui.radio_value(&mut state.report_type, "html".to_string(), "HTML Document");
                ui.radio_value(&mut state.report_type, "json".to_string(), "JSON Summary");
                ui.radio_value(&mut state.report_type, "md".to_string(), "Markdown");
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.include_metadata, "Case & Evidence Metadata");
                ui.checkbox(&mut state.include_artifacts, "Artifact Highlights");
                ui.checkbox(&mut state.include_timeline, "Timeline Events");
                ui.checkbox(&mut state.include_bookmarks, "Examiner Bookmarks");
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .button(RichText::new("Generate Preview").strong())
                    .on_hover_text("Load report preview and integrity check")
                    .clicked()
                {
                    action = ReportsViewAction::GeneratePreview;
                }

                if ui
                    .button(
                        RichText::new("Export Report...")
                            .strong()
                            .color(Color32::from_rgb(0, 180, 255)),
                    )
                    .on_hover_text("Export forensic report to disk")
                    .clicked()
                {
                    action = ReportsViewAction::ExportReport(state.report_type.clone());
                }

                if state.loading {
                    ui.spinner();
                    ui.weak("Generating report data...");
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

        if let Some(status) = &state.export_status {
            ui.add_space(4.0);
            ui.colored_label(
                Color32::from_rgb(40, 200, 60),
                RichText::new(status).strong(),
            );
        }

        ui.add_space(12.0);

        // Report Preview
        if let Some(prev) = &state.preview {
            ui.group(|ui| {
                ui.heading(format!("Forensic Report: {}", prev.case_name));
                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(420.0)
                    .show(ui, |ui| {
                        egui::Grid::new("report_preview_meta_grid")
                            .num_columns(2)
                            .spacing([24.0, 4.0])
                            .show(ui, |ui| {
                                ui.label("Case Name:");
                                ui.strong(&prev.case_name);
                                ui.end_row();

                                ui.label("Case Number:");
                                ui.label(prev.case_number.as_deref().unwrap_or("None"));
                                ui.end_row();

                                ui.label("Examiner:");
                                ui.label(prev.examiner_name.as_deref().unwrap_or("Unassigned"));
                                ui.end_row();

                                ui.label("SHA-256 Integrity:");
                                ui.monospace(if prev.sha256_integrity.len() >= 16 {
                                    &prev.sha256_integrity[..16]
                                } else {
                                    &prev.sha256_integrity
                                });
                                ui.end_row();

                                ui.label("Evidence Sources:");
                                ui.label(format!("{}", prev.evidence_count));
                                ui.end_row();

                                ui.label("Total Bookmarks:");
                                ui.label(format!("{}", prev.bookmark_count));
                                ui.end_row();

                                ui.label("Status:");
                                if prev.is_complete {
                                    ui.colored_label(
                                        Color32::from_rgb(40, 200, 60),
                                        "All evidence processing complete",
                                    );
                                } else {
                                    ui.colored_label(
                                        Color32::from_rgb(255, 180, 0),
                                        "Partial / Incomplete evidence analysis present",
                                    );
                                }
                                ui.end_row();
                            });

                        ui.add_space(12.0);
                        ui.strong("Forensic Disclosures and Limitations:");
                        for lim in &prev.partial_limitations {
                            ui.label(format!("• {lim}"));
                        }
                    });
            });
        }
    });

    action
}
