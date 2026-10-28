#![forbid(unsafe_code)]

//! Forensic examiner source browser view.
//!
//! Provides live browsing of forensic disk images, partitions, and decrypted BitLocker streams:
//! - Single click: selects row and loads bounded hex and properties preview
//! - Double click or Enter: navigates into folder or opens full hex view on file
//! - Right click: context menu for forensic actions (Bookmark, Export, Hashes, Copy, Timeline)
//! - Keyboard navigation: Up/Down arrow selection, Enter to open, Backspace for parent
//! - Volume access state distinction (Locked, Unlocked, Invalid Credential, Unsupported Cipher, etc.)
//! - Verifiable reader provenance label (Decrypted BitLocker NTFS, Forensic NTFS, FAT32, etc.)

use eframe::egui::{self, Color32, RichText, Stroke};
use kdft_desktop_core::{
    unlock::TransientUnlockManager, BrowseDirectoryPage, EvidenceSummary, EvidenceVolume,
    VolumeAccessState, BITLOCKER_LOCKED_MSG,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedBrowserEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_deleted: bool,
    pub size_bytes: Option<i64>,
    pub created_utc: Option<String>,
    pub modified_utc: Option<String>,
    pub accessed_utc: Option<String>,
    pub provenance: Option<String>,
    pub reconstruction_status: Option<String>,
    pub file_record_number: Option<u64>,
    pub physical_offset: Option<u64>,
    pub canonical_entry_id: Option<i64>,
    pub sha256: Option<String>,
}

/// Derives the truthful volume label from authoritative transient access state.
pub fn volume_label(vol: &EvidenceVolume, is_unlocked: bool) -> String {
    if is_unlocked {
        format!(
            "Vol {} ({} · BitLocker unlocked for session)",
            vol.index, vol.filesystem
        )
    } else if vol.is_bitlocker {
        format!("Vol {} (BitLocker locked)", vol.index)
    } else if vol.name.trim().is_empty() {
        format!("Vol {} ({})", vol.index, vol.filesystem)
    } else {
        format!("Vol {} ({}) {}", vol.index, vol.filesystem, vol.name)
    }
}

pub enum SourceBrowserAction {
    None,
    SelectEvidence(i64),
    SelectVolume(usize),
    LockVolume {
        evidence_id: i64,
        volume_index: usize,
    },
    NavigatePath(String),
    NavigateOffset(usize),
    SelectEntry {
        evidence_id: i64,
        volume_index: usize,
        path: String,
        name: String,
        is_dir: bool,
        is_deleted: bool,
        size_bytes: Option<i64>,
        created_utc: Option<String>,
        modified_utc: Option<String>,
        accessed_utc: Option<String>,
        provenance: Option<String>,
        reconstruction_status: Option<String>,
        file_record_number: Option<u64>,
        physical_offset: Option<u64>,
        canonical_entry_id: Option<i64>,
    },
    OpenEntry {
        evidence_id: i64,
        volume_index: usize,
        path: String,
        is_dir: bool,
        canonical_entry_id: Option<i64>,
    },
    BookmarkFile {
        evidence_id: i64,
        volume_index: usize,
        path: String,
        is_dir: bool,
        is_deleted: bool,
    },
    BookmarkFolder {
        evidence_id: i64,
        volume_index: usize,
        path: String,
        is_recursive: bool,
    },
    ExportEntry {
        evidence_id: i64,
        volume_index: usize,
        path: String,
        is_dir: bool,
    },
    CalculateHashes {
        evidence_id: i64,
        volume_index: usize,
        path: String,
        is_dir: bool,
        is_recursive: bool,
    },
    ShowInTimeline {
        path: String,
    },
    ToggleDataInterpreter,
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    evidence_items: &[EvidenceSummary],
    browse_evidence_id: Option<i64>,
    browse_evidence_name: &str,
    browse_volumes: &[EvidenceVolume],
    browse_selected_volume: usize,
    browse_path: &str,
    browse_history_back: &[String],
    browse_history_forward: &[String],
    browse_page: Option<&BrowseDirectoryPage>,
    browse_loading: bool,
    browse_error: Option<&str>,
    selected_entry: Option<&SelectedBrowserEntry>,
    table_height: f32,
    unlock_manager: &TransientUnlockManager,
) -> SourceBrowserAction {
    let mut action = SourceBrowserAction::None;

    if evidence_items.is_empty() {
        ui.label("No evidence sources attached to this case. Attach an evidence file or disk image to browse.");
        return action;
    }

    // Top selector bar: Evidence Source, Volume, Reader info, and Lock Volume
    ui.horizontal(|ui| {
        ui.strong("Evidence Source:");
        egui::ComboBox::from_id_salt("source_browser_ev_select")
            .selected_text(if browse_evidence_id.is_some() {
                browse_evidence_name
            } else {
                "— Select Evidence —"
            })
            .show_ui(ui, |ui| {
                for ev in evidence_items {
                    let is_sel = browse_evidence_id == Some(ev.id);
                    if ui
                        .selectable_label(is_sel, format!("#{} {}", ev.id, ev.display_name))
                        .clicked()
                    {
                        action = SourceBrowserAction::SelectEvidence(ev.id);
                    }
                }
            });

        if !browse_volumes.is_empty() {
            ui.separator();
            ui.strong("Volume:");
            let vol_text = browse_volumes
                .get(browse_selected_volume)
                .map(|v| {
                    let is_unlocked = browse_evidence_id
                        .map(|eid| unlock_manager.is_unlocked(eid, v.index))
                        .unwrap_or(false);
                    volume_label(v, is_unlocked)
                })
                .unwrap_or_else(|| format!("Vol {browse_selected_volume}"));

            egui::ComboBox::from_id_salt("source_browser_vol_select")
                .selected_text(vol_text)
                .show_ui(ui, |ui| {
                    for (idx, vol) in browse_volumes.iter().enumerate() {
                        let is_unlocked = browse_evidence_id
                            .map(|eid| unlock_manager.is_unlocked(eid, vol.index))
                            .unwrap_or(false);
                        let label = volume_label(vol, is_unlocked);
                        if ui
                            .selectable_label(browse_selected_volume == idx, label)
                            .clicked()
                        {
                            action = SourceBrowserAction::SelectVolume(idx);
                        }
                    }
                });
        }

        if let Some(page) = browse_page {
            ui.separator();
            ui.weak(format!("Reader: {}", page.reader_label));

            if matches!(
                page.access_state,
                VolumeAccessState::UnlockedForSession { .. }
            ) {
                ui.separator();
                ui.colored_label(
                    Color32::from_rgb(40, 200, 60),
                    RichText::new("[Unlocked in Session]").strong(),
                );
                if let Some(ev_id) = browse_evidence_id {
                    if ui
                        .button(
                            RichText::new("Lock Volume").color(Color32::from_rgb(255, 100, 100)),
                        )
                        .on_hover_text(
                            "Explicitly lock this BitLocker volume and clear decrypted caches",
                        )
                        .clicked()
                    {
                        action = SourceBrowserAction::LockVolume {
                            evidence_id: ev_id,
                            volume_index: browse_selected_volume,
                        };
                    }
                }
            }
        }

        if browse_loading {
            ui.spinner();
        }
    });

    ui.separator();

    let Some(evidence_id) = browse_evidence_id else {
        ui.label("Select an evidence source above to begin browsing.");
        return action;
    };

    // Navigation toolbar: [Root] [Up] [Back] [Forward] Path [Bookmark Folder] [Data Interpreter]
    ui.horizontal(|ui| {
        let can_navigate = !browse_loading;
        let can_root = browse_path != "/" && can_navigate;
        let parent_path = parent_browse_path(browse_path);
        let can_parent = parent_path.is_some() && can_navigate;
        let can_back = !browse_history_back.is_empty() && can_navigate;
        let can_forward = !browse_history_forward.is_empty() && can_navigate;

        if ui
            .add_enabled(can_root, egui::Button::new("Root"))
            .clicked()
        {
            action = SourceBrowserAction::NavigatePath("/".to_string());
        }

        if ui
            .add_enabled(can_parent, egui::Button::new("Up"))
            .clicked()
        {
            if let Some(p) = parent_path {
                action = SourceBrowserAction::NavigatePath(p);
            }
        }

        if ui
            .add_enabled(can_back, egui::Button::new("< Back"))
            .clicked()
        {
            if let Some(prev) = browse_history_back.last() {
                action = SourceBrowserAction::NavigatePath(prev.clone());
            }
        }

        if ui
            .add_enabled(can_forward, egui::Button::new("Forward >"))
            .clicked()
        {
            if let Some(next) = browse_history_forward.last() {
                action = SourceBrowserAction::NavigatePath(next.clone());
            }
        }

        ui.separator();
        ui.label("Path:");
        ui.monospace(browse_path);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button("Data Interpreter")
                .on_hover_text("Toggle floating Data Interpreter window")
                .clicked()
            {
                action = SourceBrowserAction::ToggleDataInterpreter;
            }
        });
    });

    ui.separator();

    // Keyboard navigation shortcuts
    if ui.input(|i| i.key_pressed(egui::Key::Backspace)) {
        if let Some(p) = parent_browse_path(browse_path) {
            action = SourceBrowserAction::NavigatePath(p);
        }
    }
    if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
        if let Some(sel) = selected_entry {
            action = SourceBrowserAction::OpenEntry {
                evidence_id,
                volume_index: browse_selected_volume,
                path: sel.path.clone(),
                is_dir: sel.is_dir,
                canonical_entry_id: sel.canonical_entry_id,
            };
        }
    }

    if let Some(err) = browse_error {
        egui::Frame::new()
            .fill(Color32::from_rgb(74, 28, 32))
            .stroke(Stroke::new(1.5, Color32::from_rgb(230, 90, 90)))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Browse Error")
                        .strong()
                        .color(Color32::LIGHT_RED),
                );
                ui.label(err);
            });
    }

    let Some(page) = browse_page else {
        if browse_loading {
            ui.label("Loading directory listing...");
        } else {
            ui.label("No directory content loaded.");
        }
        return action;
    };

    // Truthful Volume Access State Display
    if page.is_locked {
        match &page.access_state {
            VolumeAccessState::InvalidCredential { message } => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(74, 28, 32))
                    .stroke(Stroke::new(1.5, Color32::from_rgb(245, 80, 80)))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("AUTHENTICATION FAILED")
                                .strong()
                                .color(Color32::LIGHT_RED),
                        );
                        ui.label(message);
                        ui.weak("Re-enter credentials in the Evidence tab to unlock this volume.");
                    });
            }
            VolumeAccessState::UnsupportedCipher { cipher } => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(60, 40, 70))
                    .stroke(Stroke::new(1.5, Color32::from_rgb(180, 100, 220)))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("UNSUPPORTED CIPHER").strong().color(Color32::from_rgb(200, 140, 240)));
                        ui.label(format!("Cipher: {cipher}. The volume uses an encryption cipher or mode not supported by this build."));
                    });
            }
            VolumeAccessState::FilesystemParseError { error } => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(70, 30, 30))
                    .stroke(Stroke::new(1.5, Color32::from_rgb(230, 80, 80)))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("FILESYSTEM PARSE ERROR")
                                .strong()
                                .color(Color32::LIGHT_RED),
                        );
                        ui.label(error);
                    });
            }
            VolumeAccessState::EvidenceIoError { error } => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(70, 30, 30))
                    .stroke(Stroke::new(1.5, Color32::from_rgb(230, 80, 80)))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("EVIDENCE I/O ERROR")
                                .strong()
                                .color(Color32::LIGHT_RED),
                        );
                        ui.label(error);
                    });
            }
            VolumeAccessState::UnsupportedFilesystem { filesystem } => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(70, 30, 30))
                    .stroke(Stroke::new(1.5, Color32::from_rgb(230, 80, 80)))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("UNSUPPORTED FILESYSTEM")
                                .strong()
                                .color(Color32::LIGHT_RED),
                        );
                        ui.label(format!("Filesystem '{filesystem}' is not supported."));
                    });
            }
            _ => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(67, 43, 19))
                    .stroke(Stroke::new(1.5, Color32::from_rgb(245, 159, 69)))
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("VOLUME LOCKED").strong().color(Color32::from_rgb(245, 159, 69)));
                        ui.label(page.locked_message.as_deref().unwrap_or(BITLOCKER_LOCKED_MSG));
                        ui.weak("Unlock this volume in the Evidence tab to browse its decrypted filesystem.");
                    });
            }
        }
        return action;
    }

    // Directory Items Table (No permanent Action buttons per row)
    let selected_path_str = selected_entry.map(|e| e.path.as_str());
    let mut selected_index: Option<usize> = None;

    egui::ScrollArea::vertical()
        .max_height(table_height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("browse_directory_grid")
                .striped(true)
                .num_columns(5)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    ui.strong("Name");
                    ui.strong("Type");
                    ui.strong("Size");
                    ui.strong("Modified (UTC)");
                    ui.strong("Status");
                    ui.end_row();

                    for (idx, entry) in page.entries.iter().enumerate() {
                        let full_path = if browse_path == "/" {
                            format!("/{}", entry.name)
                        } else {
                            format!("{}/{}", browse_path.trim_end_matches('/'), entry.name)
                        };
                        let is_row_selected = selected_path_str == Some(&full_path);
                        if is_row_selected {
                            selected_index = Some(idx);
                        }

                        let icon = if entry.is_dir { "[DIR]" } else { "[FILE]" };
                        let name_label = format!("{icon} {}", entry.name);

                        // Row interaction: single click selects; double click opens; right-click context menu
                        let resp = ui.selectable_label(
                            is_row_selected,
                            if entry.is_dir {
                                RichText::new(name_label).strong()
                            } else {
                                RichText::new(name_label)
                            },
                        );

                        if resp.clicked() {
                            action = SourceBrowserAction::SelectEntry {
                                evidence_id,
                                volume_index: browse_selected_volume,
                                path: full_path.clone(),
                                name: entry.name.clone(),
                                is_dir: entry.is_dir,
                                is_deleted: entry.is_deleted,
                                size_bytes: entry.size_bytes,
                                created_utc: entry.created_utc.clone(),
                                modified_utc: entry.modified_utc.clone(),
                                accessed_utc: entry.accessed_utc.clone(),
                                provenance: entry.provenance.clone(),
                                reconstruction_status: entry.reconstruction_status.clone(),
                                file_record_number: entry.file_record_number,
                                physical_offset: entry.physical_offset,
                                canonical_entry_id: entry.canonical_entry_id,
                            };
                        }

                        if resp.double_clicked() {
                            action = SourceBrowserAction::OpenEntry {
                                evidence_id,
                                volume_index: browse_selected_volume,
                                path: full_path.clone(),
                                is_dir: entry.is_dir,
                                canonical_entry_id: entry.canonical_entry_id,
                            };
                        }

                        resp.context_menu(|ui| {
                            if !entry.is_dir {
                                if ui.button("Open / View").clicked() {
                                    action = SourceBrowserAction::OpenEntry {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: false,
                                        canonical_entry_id: entry.canonical_entry_id,
                                    };
                                    ui.close();
                                }
                                if ui.button("View Hex").clicked() {
                                    action = SourceBrowserAction::OpenEntry {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: false,
                                        canonical_entry_id: entry.canonical_entry_id,
                                    };
                                    ui.close();
                                }
                                if ui.button("Bookmark File...").clicked() {
                                    action = SourceBrowserAction::BookmarkFile {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: false,
                                        is_deleted: entry.is_deleted,
                                    };
                                    ui.close();
                                }
                                if ui.button("Export File...").clicked() {
                                    action = SourceBrowserAction::ExportEntry {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: false,
                                    };
                                    ui.close();
                                }
                                if ui.button("Calculate Hashes").clicked() {
                                    action = SourceBrowserAction::CalculateHashes {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: false,
                                        is_recursive: false,
                                    };
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("Copy Name").clicked() {
                                    ui.ctx().copy_text(entry.name.clone());
                                    ui.close();
                                }
                                if ui.button("Copy Logical Path").clicked() {
                                    ui.ctx().copy_text(full_path.clone());
                                    ui.close();
                                }
                                if let Some(off) = entry.physical_offset {
                                    if ui.button("Copy Forensic Coordinates").clicked() {
                                        ui.ctx().copy_text(format!("namespace: physical_offset, value: 0x{:X}, unit: bytes, exact: true, basis: live filesystem reader", off));
                                        ui.close();
                                    }
                                } else if let Some(frn) = entry.file_record_number {
                                    if ui.button("Copy Forensic Coordinates").clicked() {
                                        ui.ctx().copy_text(format!("namespace: file_record_number, value: {}, unit: record, exact: true, basis: live NTFS reader", frn));
                                        ui.close();
                                    }
                                } else {
                                    ui.add_enabled(false, egui::Button::new("Copy Forensic Coordinates"))
                                        .on_disabled_hover_text("No forensic coordinates recorded for this entry");
                                }
                                if ui.button("Show in Timeline").clicked() {
                                    action = SourceBrowserAction::ShowInTimeline {
                                        path: full_path.clone(),
                                    };
                                    ui.close();
                                }
                            } else {
                                if ui.button("Open Folder").clicked() {
                                    action = SourceBrowserAction::OpenEntry {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: true,
                                        canonical_entry_id: entry.canonical_entry_id,
                                    };
                                    ui.close();
                                }
                                if ui.button("Bookmark Folder...").clicked() {
                                    action = SourceBrowserAction::BookmarkFolder {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_recursive: false,
                                    };
                                    ui.close();
                                }
                                if ui.button("Bookmark Recursively...").clicked() {
                                    action = SourceBrowserAction::BookmarkFolder {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_recursive: true,
                                    };
                                    ui.close();
                                }
                                if ui.button("Export Folder...").clicked() {
                                    action = SourceBrowserAction::ExportEntry {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: true,
                                    };
                                    ui.close();
                                }
                                if ui.button("Calculate Hashes Recursively").clicked() {
                                    action = SourceBrowserAction::CalculateHashes {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        is_dir: true,
                                        is_recursive: true,
                                    };
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("Copy Name").clicked() {
                                    ui.ctx().copy_text(entry.name.clone());
                                    ui.close();
                                }
                                if ui.button("Copy Logical Path").clicked() {
                                    ui.ctx().copy_text(full_path.clone());
                                    ui.close();
                                }
                                if ui.button("Properties").clicked() {
                                    action = SourceBrowserAction::SelectEntry {
                                        evidence_id,
                                        volume_index: browse_selected_volume,
                                        path: full_path.clone(),
                                        name: entry.name.clone(),
                                        is_dir: true,
                                        is_deleted: entry.is_deleted,
                                        size_bytes: entry.size_bytes,
                                        created_utc: entry.created_utc.clone(),
                                        modified_utc: entry.modified_utc.clone(),
                                        accessed_utc: entry.accessed_utc.clone(),
                                        provenance: entry.provenance.clone(),
                                        reconstruction_status: entry.reconstruction_status.clone(),
                                        file_record_number: entry.file_record_number,
                                        physical_offset: entry.physical_offset,
                                        canonical_entry_id: entry.canonical_entry_id,
                                    };
                                    ui.close();
                                }
                            }
                        });

                        ui.label(if entry.is_dir { "Directory" } else { "File" });
                        ui.monospace(if entry.is_dir {
                            "-".to_string()
                        } else {
                            format_size_human(entry.size_bytes)
                        });
                        ui.label(entry.modified_utc.as_deref().unwrap_or("-"));

                        if entry.is_deleted {
                            ui.colored_label(Color32::YELLOW, "Deleted");
                        } else {
                            ui.label("Active");
                        }

                        ui.end_row();
                    }
                });
        });

    // Keyboard Arrow Selection
    if ui.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
        let next_idx = match selected_index {
            Some(curr) => (curr + 1).min(page.entries.len().saturating_sub(1)),
            None => 0,
        };
        if let Some(entry) = page.entries.get(next_idx) {
            let full_path = if browse_path == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", browse_path.trim_end_matches('/'), entry.name)
            };
            action = SourceBrowserAction::SelectEntry {
                evidence_id,
                volume_index: browse_selected_volume,
                path: full_path,
                name: entry.name.clone(),
                is_dir: entry.is_dir,
                is_deleted: entry.is_deleted,
                size_bytes: entry.size_bytes,
                created_utc: entry.created_utc.clone(),
                modified_utc: entry.modified_utc.clone(),
                accessed_utc: entry.accessed_utc.clone(),
                provenance: entry.provenance.clone(),
                reconstruction_status: entry.reconstruction_status.clone(),
                file_record_number: entry.file_record_number,
                physical_offset: entry.physical_offset,
                canonical_entry_id: entry.canonical_entry_id,
            };
        }
    } else if ui.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
        let prev_idx = match selected_index {
            Some(curr) => curr.saturating_sub(1),
            None => 0,
        };
        if let Some(entry) = page.entries.get(prev_idx) {
            let full_path = if browse_path == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", browse_path.trim_end_matches('/'), entry.name)
            };
            action = SourceBrowserAction::SelectEntry {
                evidence_id,
                volume_index: browse_selected_volume,
                path: full_path,
                name: entry.name.clone(),
                is_dir: entry.is_dir,
                is_deleted: entry.is_deleted,
                size_bytes: entry.size_bytes,
                created_utc: entry.created_utc.clone(),
                modified_utc: entry.modified_utc.clone(),
                accessed_utc: entry.accessed_utc.clone(),
                provenance: entry.provenance.clone(),
                reconstruction_status: entry.reconstruction_status.clone(),
                file_record_number: entry.file_record_number,
                physical_offset: entry.physical_offset,
                canonical_entry_id: entry.canonical_entry_id,
            };
        }
    }

    // Pagination for directory
    if page.total_entries > page.entries.len() || page.offset > 0 {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(format!(
                "Entries {} - {} of {}",
                page.offset + 1,
                (page.offset + page.entries.len()).min(page.total_entries),
                page.total_entries
            ));

            if ui
                .add_enabled(page.offset > 0, egui::Button::new("< Previous"))
                .clicked()
            {
                let prev_offset = page.offset.saturating_sub(page.entries.len().max(50));
                action = SourceBrowserAction::NavigateOffset(prev_offset);
            }

            if ui
                .add_enabled(page.next_offset.is_some(), egui::Button::new("Next >"))
                .clicked()
            {
                let next_offset = page.offset + page.entries.len();
                action = SourceBrowserAction::NavigateOffset(next_offset);
            }
        });
    }

    action
}

pub fn parent_browse_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(idx) => Some(format!("/{}", &trimmed[..idx])),
        None => Some("/".to_string()),
    }
}

pub fn format_size_human(bytes: Option<i64>) -> String {
    match bytes {
        Some(b) if b >= 0 => {
            let b = b as u64;
            const KB: u64 = 1024;
            const MB: u64 = 1024 * KB;
            const GB: u64 = 1024 * MB;
            if b >= GB {
                format!("{:.2} GB", b as f64 / GB as f64)
            } else if b >= MB {
                format!("{:.2} MB", b as f64 / MB as f64)
            } else if b >= KB {
                format!("{:.2} KB", b as f64 / KB as f64)
            } else {
                format!("{b} B")
            }
        }
        _ => "-".to_string(),
    }
}
