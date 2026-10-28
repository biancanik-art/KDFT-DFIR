#![forbid(unsafe_code)]

//! Case management view.
//!
//! Provides case opening, case creation, database summary, and audit generation inspection.

use crate::state::NewCaseForm;
use eframe::egui::{self, Color32, RichText};
use kdft_desktop_core::CaseSummary;
use std::path::PathBuf;

pub enum CaseViewAction {
    None,
    OpenCase(PathBuf),
    CreateCase,
    CloseCase,
    BrowseCasePath,
}

pub fn show(
    ui: &mut egui::Ui,
    case_path: &mut String,
    opened_path: Option<&PathBuf>,
    summary: Option<&CaseSummary>,
    new_case: &mut NewCaseForm,
    loading: bool,
    error: Option<&str>,
) -> CaseViewAction {
    let mut action = CaseViewAction::None;

    ui.vertical(|ui| {
        ui.heading("Case Management");
        ui.separator();

        if let Some(err) = error {
            ui.colored_label(Color32::from_rgb(255, 100, 100), RichText::new(err).strong());
            ui.add_space(8.0);
        }

        // Open or Create toolbar
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Case Database:");
                ui.add(egui::TextEdit::singleline(case_path).desired_width(450.0));

                if ui.button("Browse...").clicked() {
                    action = CaseViewAction::BrowseCasePath;
                }

                if ui
                    .add_enabled(!loading && !case_path.trim().is_empty(), egui::Button::new("Open Case"))
                    .clicked()
                {
                    action = CaseViewAction::OpenCase(PathBuf::from(case_path.trim()));
                }

                if ui.button("New Case...").clicked() {
                    new_case.visible = !new_case.visible;
                }

                if opened_path.is_some() && ui.button("Close Case").clicked() {
                    action = CaseViewAction::CloseCase;
                }

                if loading {
                    ui.spinner();
                }
            });
        });

        // New case modal / inline form
        if new_case.visible {
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.strong("Create New KDFT Forensic Case");
                ui.add_space(4.0);

                egui::Grid::new("new_case_grid")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Database Path:");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut new_case.case_path).desired_width(380.0));
                            if ui.button("Browse...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_file_name("case.kdft")
                                    .add_filter("KDFT Case (*.kdft, *.sqlite)", &["kdft", "sqlite"])
                                    .save_file()
                                {
                                    new_case.case_path = path.display().to_string();
                                }
                            }
                        });
                        ui.end_row();

                        ui.label("Case Name *:");
                        ui.add(egui::TextEdit::singleline(&mut new_case.name).desired_width(380.0));
                        ui.end_row();

                        ui.label("Examiner Name:");
                        ui.add(egui::TextEdit::singleline(&mut new_case.examiner_name).desired_width(380.0));
                        ui.end_row();

                        ui.label("Case Number / Ref:");
                        ui.add(egui::TextEdit::singleline(&mut new_case.case_number).desired_width(380.0));
                        ui.end_row();
                    });

                if let Some(err) = &new_case.error {
                    ui.add_space(4.0);
                    ui.colored_label(Color32::from_rgb(255, 100, 100), RichText::new(err).strong());
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Create Case").strong()).clicked() {
                        action = CaseViewAction::CreateCase;
                    }
                    if ui.button("Cancel").clicked() {
                        new_case.visible = false;
                        new_case.error = None;
                    }
                });
            });
        }

        ui.add_space(12.0);

        // Case Summary & Metadata
        if let Some(s) = summary {
            ui.group(|ui| {
                ui.strong("Active Case Overview");
                ui.separator();

                egui::Grid::new("case_summary_grid")
                    .num_columns(2)
                    .spacing([24.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Case Name:");
                        ui.strong(&s.name);
                        ui.end_row();

                        ui.label("Case Number:");
                        ui.label(s.case_number.as_deref().unwrap_or("None"));
                        ui.end_row();

                        ui.label("Examiner:");
                        ui.label(s.examiner_name.as_deref().unwrap_or("Unassigned"));
                        ui.end_row();

                        ui.label("Database Location:");
                        ui.monospace(opened_path.map_or("", |p| p.to_str().unwrap_or("")));
                        ui.end_row();

                        ui.label("Created At (UTC):");
                        ui.label(&s.created_at);
                        ui.end_row();

                        ui.label("Snapshot Generation:");
                        ui.monospace(format!("#{}", s.generation));
                        ui.end_row();

                        ui.label("Timezone:");
                        ui.label(&s.timezone);
                        ui.end_row();
                    });
            });
        } else if opened_path.is_none() {
            ui.weak("No case database currently opened. Create a new case or open an existing .kdft database to begin.");
        }
    });

    action
}
