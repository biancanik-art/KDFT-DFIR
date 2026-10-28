#![forbid(unsafe_code)]

//! Bookmark dialogs for single findings, recursive folder bookmarks, folder creation,
//! and deletion confirmations.

use crate::state::{
    BookmarkDialogState, BookmarkTarget, CreateFolderDialogState, RemovalConfirmationState,
    RemovalTarget,
};
use eframe::egui::{self, Color32, Window};

pub enum BookmarkDialogAction {
    None,
    CreateSingle,
    CreateRecursive,
    Cancel,
}

pub fn show_bookmark_dialog(
    ctx: &egui::Context,
    state: &mut BookmarkDialogState,
    resuming_bookmark_id: Option<i64>,
    loading: bool,
) -> BookmarkDialogAction {
    if !state.visible {
        return BookmarkDialogAction::None;
    }

    let mut action = BookmarkDialogAction::None;
    let mut visible = state.visible;
    let mut close_dialog = false;

    Window::new("Bookmark Finding")
        .open(&mut visible)
        .collapsible(false)
        .resizable(true)
        .default_width(500.0)
        .show(ctx, |ui| {
            ui.label("Folder / Group Name");
            ui.text_edit_singleline(&mut state.folder_name);

            ui.label("Bookmark Title (required)");
            ui.text_edit_singleline(&mut state.title);

            ui.label("Comment (optional)");
            ui.text_edit_multiline(&mut state.comment);

            if let Some(target) = &state.target {
                ui.separator();
                ui.strong("Target Information");
                match target {
                    BookmarkTarget::IndexedResult {
                        evidence_id,
                        entry_id,
                        logical_path,
                        artifact_kind,
                        is_deleted,
                    } => {
                        ui.label(format!("Evidence ID: {evidence_id}"));
                        ui.label(format!("Entry ID: #{entry_id} (canonical indexed entry)"));
                        ui.label(format!("Logical Path: {logical_path}"));
                        ui.label(format!("Kind: {artifact_kind}"));
                        if *is_deleted {
                            ui.colored_label(Color32::YELLOW, "State: Deleted");
                        }
                    }
                    BookmarkTarget::SearchResult {
                        evidence_id,
                        entry_id,
                        logical_path,
                        artifact_kind,
                        match_field,
                        match_snippet,
                        selection_offset,
                        selection_length,
                    } => {
                        ui.label(format!("Evidence ID: {evidence_id}"));
                        ui.label(format!("Entry ID: #{entry_id} (search finding)"));
                        ui.label(format!("Logical Path: {logical_path}"));
                        ui.label(format!("Kind: {artifact_kind}"));
                        ui.label(format!("Matched field: {match_field}"));
                        if let Some(offset) = selection_offset {
                            ui.label(format!(
                                "Logical-file selection: 0x{offset:X}, {} byte(s)",
                                selection_length.unwrap_or(1)
                            ));
                        } else {
                            ui.colored_label(
                                Color32::YELLOW,
                                "This match has no proven original-file byte offset.",
                            );
                        }
                        if !match_snippet.is_empty() {
                            ui.label(format!("Match preview: {match_snippet}"));
                        }
                    }
                    BookmarkTarget::LiveSourceFile {
                        evidence_id,
                        logical_path,
                        is_dir,
                        is_deleted,
                        ..
                    } => {
                        ui.label(format!("Evidence ID: {evidence_id}"));
                        ui.label("Entry ID: Not indexed (Live source file)");
                        ui.label(format!("Path: {logical_path}"));
                        ui.label(format!(
                            "Kind: {}",
                            if *is_dir { "Directory" } else { "File" }
                        ));
                        if *is_deleted {
                            ui.colored_label(Color32::YELLOW, "State: Deleted");
                        }
                    }
                    BookmarkTarget::Folder {
                        evidence_id,
                        logical_path,
                        is_indexed,
                        ..
                    } => {
                        ui.label(format!("Evidence ID: {evidence_id}"));
                        ui.label(format!("Directory Path: {logical_path}"));
                        ui.label(format!(
                            "Indexed: {}",
                            if *is_indexed {
                                "Yes"
                            } else {
                                "Live source only"
                            }
                        ));
                        ui.checkbox(
                            &mut state.is_recursive,
                            "Recursive folder bookmark (all descendants)",
                        );
                        if state.is_recursive {
                            ui.horizontal(|ui| {
                                ui.label("Limit entries (optional, blank or 0 for no limit):");
                                ui.text_edit_singleline(&mut state.max_entries);
                            });
                        }
                    }
                    BookmarkTarget::EvidenceSource {
                        evidence_id,
                        source_name,
                    } => {
                        ui.label(format!("Evidence ID: {evidence_id}"));
                        ui.label(format!("Source Name: {source_name}"));
                    }
                }
            }

            if let Some(r_id) = resuming_bookmark_id {
                ui.colored_label(
                    Color32::from_rgb(220, 140, 0),
                    format!("Partial bookmark #{r_id} is incomplete. Resume available."),
                );
            }

            if let Some(err) = state.error.as_deref() {
                ui.colored_label(Color32::LIGHT_RED, err);
            }

            ui.add_space(8.0);
            let btn_text = if resuming_bookmark_id.is_some() {
                "Resume Bookmark"
            } else {
                "Create Bookmark"
            };
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!loading, egui::Button::new(btn_text))
                    .clicked()
                {
                    if state.title.trim().is_empty() {
                        state.error = Some("Title cannot be blank.".to_string());
                    } else if state.is_recursive || resuming_bookmark_id.is_some() {
                        action = BookmarkDialogAction::CreateRecursive;
                    } else {
                        action = BookmarkDialogAction::CreateSingle;
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog = true;
                    action = BookmarkDialogAction::Cancel;
                }
                if loading {
                    ui.spinner();
                }
            });
        });

    if close_dialog {
        visible = false;
    }
    state.visible = visible;
    action
}

pub enum CreateFolderDialogAction {
    None,
    Create {
        name: String,
        comment: Option<String>,
        show_in_report: bool,
    },
    Cancel,
}

pub fn show_create_folder_dialog(
    ctx: &egui::Context,
    state: &mut CreateFolderDialogState,
    loading: bool,
) -> CreateFolderDialogAction {
    if !state.visible {
        return CreateFolderDialogAction::None;
    }

    let mut action = CreateFolderDialogAction::None;
    let mut visible = state.visible;
    let mut close_dialog = false;

    Window::new("Create Bookmark Folder")
        .open(&mut visible)
        .collapsible(false)
        .resizable(false)
        .default_width(420.0)
        .show(ctx, |ui| {
            ui.label("Folder Name (required):");
            ui.text_edit_singleline(&mut state.name);

            ui.label("Comment (optional):");
            ui.text_edit_multiline(&mut state.comment);

            ui.checkbox(&mut state.show_in_report, "Show in forensic report");

            if let Some(err) = state.error.as_deref() {
                ui.colored_label(Color32::LIGHT_RED, err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!loading, egui::Button::new("Create Folder"))
                    .clicked()
                {
                    let trimmed = state.name.trim();
                    if trimmed.is_empty() {
                        state.error = Some("Folder name cannot be blank.".to_string());
                    } else {
                        let comment = if state.comment.trim().is_empty() {
                            None
                        } else {
                            Some(state.comment.trim().to_string())
                        };
                        action = CreateFolderDialogAction::Create {
                            name: trimmed.to_string(),
                            comment,
                            show_in_report: state.show_in_report,
                        };
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog = true;
                    action = CreateFolderDialogAction::Cancel;
                }
                if loading {
                    ui.spinner();
                }
            });
        });

    if close_dialog {
        visible = false;
    }
    state.visible = visible;
    action
}

pub enum RemovalConfirmationAction {
    None,
    Confirm(RemovalTarget),
    Cancel,
}

pub fn show_removal_dialog(
    ctx: &egui::Context,
    state: &mut RemovalConfirmationState,
    loading: bool,
) -> RemovalConfirmationAction {
    if !state.visible {
        return RemovalConfirmationAction::None;
    }

    let mut action = RemovalConfirmationAction::None;
    let mut visible = state.visible;
    let mut close_dialog = false;

    Window::new("Confirm Deletion")
        .open(&mut visible)
        .collapsible(false)
        .resizable(false)
        .default_width(380.0)
        .show(ctx, |ui| {
            if let Some(target) = &state.target {
                match target {
                    RemovalTarget::Folder { name, .. } => {
                        ui.label(format!("Delete bookmark folder '{name}'?"));
                        ui.weak("Folder must be empty before deletion.");
                    }
                    RemovalTarget::Bookmark { title, .. } => {
                        ui.label(format!("Delete bookmark '{title}'?"));
                    }
                    RemovalTarget::Item { name, .. } => {
                        ui.label(format!("Delete bookmark item '{name}'?"));
                    }
                }
            }

            if let Some(err) = state.error.as_deref() {
                ui.colored_label(Color32::LIGHT_RED, err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!loading, egui::Button::new("Delete"))
                    .clicked()
                {
                    if let Some(t) = state.target.clone() {
                        action = RemovalConfirmationAction::Confirm(t);
                    }
                }
                if ui.button("Cancel").clicked() {
                    close_dialog = true;
                    action = RemovalConfirmationAction::Cancel;
                }
                if loading {
                    ui.spinner();
                }
            });
        });

    if close_dialog {
        visible = false;
    }
    state.visible = visible;
    action
}
