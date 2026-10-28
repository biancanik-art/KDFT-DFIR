#![forbid(unsafe_code)]

//! Forensic examiner artifacts view.
//!
//! Provides a 3-pane examiner view:
//! - Left: Resizable category tree structured into Filesystem Inventory vs Derived Forensic Artifacts
//! - Center: Paginated artifact records without permanent action buttons (single click selects & loads preview; double click opens hex; right click context menu)
//! - Verifiable coverage badges reflecting real SQLite database records

use crate::state::ArtifactsViewState;
use eframe::egui::{self, Color32, RichText};
use kdft_desktop_core::artifacts::ArtifactCategoryNode;

pub enum ArtifactsViewAction {
    None,
    SelectCategory {
        main: String,
        sub: Option<String>,
    },
    RefreshQuery,
    RefreshAll,
    InspectEntry {
        entry_id: i64,
        path: String,
    },
    ViewHex {
        entry_id: i64,
        path: String,
    },
    BookmarkEntry {
        entry_id: i64,
        path: String,
        kind: String,
        is_deleted: bool,
    },
    ExportEntry {
        entry_id: i64,
        path: String,
    },
    CalculateHashes {
        entry_id: i64,
        path: String,
    },
    ShowInTimeline {
        path: String,
    },
    PrevPage,
    NextPage,
}

pub fn show(
    ui: &mut egui::Ui,
    state: &mut ArtifactsViewState,
    selected_entry_id: Option<i64>,
    has_case: bool,
) -> ArtifactsViewAction {
    let mut action = ArtifactsViewAction::None;

    if !has_case {
        ui.centered_and_justified(|ui| {
            ui.label("Open or create a case to explore categorized forensic artifacts.");
        });
        return action;
    }

    ui.horizontal(|ui| {
        ui.heading("Forensic Artifacts");
        if ui.button("🔄 Refresh Artifacts").clicked() {
            action = ArtifactsViewAction::RefreshAll;
        }
        if let Some(gen) = state.cached_generation {
            ui.label(
                RichText::new(format!("Snapshot Gen {}", gen))
                    .monospace()
                    .weak(),
            );
        }
        if state.loading {
            ui.spinner();
            ui.weak("Querying database...");
        }
    });
    ui.separator();

    if let Some(err) = &state.error {
        ui.colored_label(
            Color32::from_rgb(255, 100, 100),
            RichText::new(err).strong(),
        );
        ui.add_space(4.0);
    }

    // Left Panel: Resizable Category Tree with structural separation
    egui::Panel::left("artifacts_category_panel")
        .resizable(true)
        .default_size(320.0)
        .min_size(200.0)
        .max_size(720.0)
        .show(ui, |ui| {
            ui.strong("Artifact Categories");
            ui.separator();

            egui::ScrollArea::vertical()
                .max_height(600.0)
                .show(ui, |ui| {
                    if state.category_tree.is_empty() {
                        ui.weak("No categories available or evidence unindexed.");
                    } else {
                        // Separate "All Artifacts" top root from specific categories
                        let all_node = state
                            .category_tree
                            .iter()
                            .find(|n| n.id == "all" || n.main_category.is_empty());
                        let specific_nodes: Vec<_> = state
                            .category_tree
                            .iter()
                            .filter(|n| n.id != "all" && !n.main_category.is_empty())
                            .collect();

                        // 1. All Indexed Items (Root)
                        if let Some(all) = all_node {
                            render_category_node(ui, all, state, &mut action);
                            ui.add_space(6.0);
                            ui.separator();
                        }

                        let (inventory, derived): (Vec<_>, Vec<_>) = specific_nodes
                            .into_iter()
                            .partition(|n| is_filesystem_inventory(&n.main_category));

                        // 2. Filesystem Inventory Section
                        if !inventory.is_empty() {
                            ui.label(
                                RichText::new("📁 Filesystem Inventory")
                                    .strong()
                                    .color(Color32::from_rgb(140, 180, 240)),
                            );
                            for node in inventory {
                                render_category_node(ui, node, state, &mut action);
                            }
                            ui.add_space(8.0);
                        }

                        // 3. Derived Forensic Artifacts Section
                        if !derived.is_empty() {
                            ui.label(
                                RichText::new("🔬 Derived Forensic Artifacts")
                                    .strong()
                                    .color(Color32::from_rgb(140, 220, 160)),
                            );
                            for node in derived {
                                render_category_node(ui, node, state, &mut action);
                            }
                        }
                    }
                });
        });

    // Center/Main Area: Filter bar and Paginated Records Table
    ui.vertical(|ui| {
        // Filter Bar
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                let text_resp = ui
                    .add(egui::TextEdit::singleline(&mut state.search_filter).desired_width(180.0));
                ui.label("Ext:");
                let ext_resp = ui.add(
                    egui::TextEdit::singleline(&mut state.extension_filter).desired_width(50.0),
                );

                let del_resp = ui.checkbox(&mut state.deleted_only, "Deleted only");

                if ui.button("Search").clicked()
                    || text_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || ext_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    || del_resp.changed()
                {
                    action = ArtifactsViewAction::RefreshQuery;
                }
            });
        });

        ui.add_space(6.0);

        // Active category indicator
        ui.horizontal(|ui| {
            let cat_label = match (&state.selected_category, &state.selected_sub_category) {
                (Some(main), Some(sub)) => format!("{main} > {sub}"),
                (Some(main), None) => main.clone(),
                _ => "All Categories".to_string(),
            };
            ui.label(format!("Viewing: {cat_label}"));

            if let Some(total) = state.total_count {
                ui.label(format!("({total} total entries)"));
            }
        });

        ui.separator();

        let is_registry = state.selected_category.as_deref() == Some("Windows Registry");
        let is_browser_visits = state.selected_category.as_deref() == Some("Web Activity")
            && state.selected_sub_category.as_deref() == Some("Visits");

        // Paginated Records Table (No permanent Action buttons on rows)
        egui::ScrollArea::both()
            .max_height(480.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if state.current_rows.is_empty() {
                    ui.weak("No matching artifact records found.");
                } else {
                    egui::Grid::new("artifacts_records_grid")
                        .striped(true)
                        .num_columns(6)
                        .spacing([14.0, 4.0])
                        .show(ui, |ui| {
                            if is_registry {
                                ui.strong("ID");
                                ui.strong("Value / Item Name");
                                ui.strong("Key Path / Location");
                                ui.strong("Type");
                                ui.strong("Data Preview");
                                ui.strong("Last Written (UTC)");
                            } else if is_browser_visits {
                                ui.strong("ID");
                                ui.strong("Visited (UTC)");
                                ui.strong("Title");
                                ui.strong("URL");
                                ui.strong("Origin signal");
                                ui.strong("Browser profile / Sync client");
                            } else {
                                ui.strong("ID");
                                ui.strong("Name");
                                ui.strong("Path");
                                ui.strong("Category");
                                ui.strong("Size");
                                ui.strong("Modified (UTC)");
                            }
                            ui.end_row();

                            for row in &state.current_rows {
                                let selected = selected_entry_id == Some(row.id);

                                let id_label = format!("#{}", row.id);
                                let resp_id = ui.selectable_label(
                                    selected,
                                    RichText::new(&id_label).monospace(),
                                );

                                let (resp_c1, resp_c2, resp_c3, resp_c4, resp_c5) = if is_registry {
                                    let item_name = row.value_name.as_deref().unwrap_or(&row.display_name);
                                    let key_p = row.key_path.as_deref().unwrap_or(&row.logical_path);
                                    let v_type = row.value_type.as_deref().unwrap_or(&row.entry_kind);
                                    let preview = row.value_preview.as_deref().unwrap_or("-");
                                    let lw = row.key_last_written.as_deref().or(row.modified_at.as_deref()).unwrap_or("-");

                                    let r1 = ui.selectable_label(selected, item_name);
                                    let r2 = ui.selectable_label(selected, RichText::new(key_p).monospace());
                                    let r3 = ui.selectable_label(selected, v_type);
                                    let r4 = ui.selectable_label(selected, RichText::new(preview).monospace());
                                    let r5 = ui.selectable_label(selected, lw);
                                    (r1, r2, r3, r4, r5)
                                } else if is_browser_visits {
                                    let origin = browser_origin_label(
                                        row.visit_origin.as_deref(),
                                        row.visit_source_label.as_deref(),
                                    );
                                    let origin_tooltip = browser_origin_tooltip(
                                        row.visit_origin.as_deref(),
                                        row.visit_source_label.as_deref(),
                                    );
                                    let profile_sync = browser_profile_sync_label(
                                        row.browser_family.as_deref(),
                                        row.browser_profile.as_deref(),
                                        row.originator_sync_guid_short.as_deref(),
                                    );
                                    let sync_tooltip = browser_sync_tooltip(
                                        row.originator_sync_guid_full.as_deref(),
                                        row.originator_sync_guid_note.as_deref(),
                                    );

                                    let r1 = ui.selectable_label(
                                        selected,
                                        row.visit_time_utc.as_deref().unwrap_or("Not recorded"),
                                    );
                                    let r2 = ui.selectable_label(selected, &row.display_name);
                                    let r3 = ui.selectable_label(
                                        selected,
                                        RichText::new(
                                            row.browser_url
                                                .as_deref()
                                                .unwrap_or(&row.logical_path),
                                        )
                                        .monospace(),
                                    );
                                    let r4 = ui
                                        .selectable_label(selected, origin)
                                        .on_hover_text(origin_tooltip);
                                    let r5 = ui
                                        .selectable_label(selected, profile_sync)
                                        .on_hover_text(sync_tooltip);
                                    (r1, r2, r3, r4, r5)
                                } else {
                                    let r1 = ui.selectable_label(selected, &row.display_name);
                                    let r2 = ui.selectable_label(selected, RichText::new(&row.logical_path).monospace());
                                    let r3 = ui.selectable_label(selected, &row.category_main);
                                    let r4 = ui.selectable_label(selected, RichText::new(format_bytes(row.size_bytes)).monospace());
                                    let r5 = ui.selectable_label(selected, row.modified_at.as_deref().unwrap_or("-"));
                                    (r1, r2, r3, r4, r5)
                                };

                                let any_clicked = resp_id.clicked()
                                    || resp_c1.clicked()
                                    || resp_c2.clicked()
                                    || resp_c3.clicked()
                                    || resp_c4.clicked()
                                    || resp_c5.clicked();

                                let any_double_clicked = resp_id.double_clicked()
                                    || resp_c1.double_clicked()
                                    || resp_c2.double_clicked()
                                    || resp_c3.double_clicked()
                                    || resp_c4.double_clicked()
                                    || resp_c5.double_clicked();

                                if any_clicked {
                                    action = ArtifactsViewAction::InspectEntry {
                                        entry_id: row.id,
                                        path: row.logical_path.clone(),
                                    };
                                }

                                if any_double_clicked {
                                    action = ArtifactsViewAction::ViewHex {
                                        entry_id: row.id,
                                        path: row.logical_path.clone(),
                                    };
                                }

                                // Context menu on any cell of the row
                                resp_c1.context_menu(|ui| {
                                    if ui.button("Open / View").clicked() {
                                        action = ArtifactsViewAction::InspectEntry {
                                            entry_id: row.id,
                                            path: row.logical_path.clone(),
                                        };
                                        ui.close();
                                    }
                                    if ui.button("View Hex").clicked() {
                                        action = ArtifactsViewAction::ViewHex {
                                            entry_id: row.id,
                                            path: row.logical_path.clone(),
                                        };
                                        ui.close();
                                    }
                                    if ui.button("Bookmark Entry...").clicked() {
                                        action = ArtifactsViewAction::BookmarkEntry {
                                            entry_id: row.id,
                                            path: row.logical_path.clone(),
                                            kind: row.entry_kind.clone(),
                                            is_deleted: row.is_deleted,
                                        };
                                        ui.close();
                                    }
                                    if ui.button("Export File...").clicked() {
                                        action = ArtifactsViewAction::ExportEntry {
                                            entry_id: row.id,
                                            path: row.logical_path.clone(),
                                        };
                                        ui.close();
                                    }
                                    if ui.button("Calculate Hashes").clicked() {
                                        action = ArtifactsViewAction::CalculateHashes {
                                            entry_id: row.id,
                                            path: row.logical_path.clone(),
                                        };
                                        ui.close();
                                    }
                                    ui.separator();
                                    if ui.button("Copy Name").clicked() {
                                        ui.ctx().copy_text(row.display_name.clone());
                                        ui.close();
                                    }
                                    if ui.button("Copy Logical Path").clicked() {
                                        ui.ctx().copy_text(row.logical_path.clone());
                                        ui.close();
                                    }
                                    ui.add_enabled(false, egui::Button::new("Copy Forensic Coordinates"))
                                        .on_disabled_hover_text("Coordinates are recorded in Inspector projection; select entry to inspect");
                                    if ui.button("Show in Timeline").clicked() {
                                        action = ArtifactsViewAction::ShowInTimeline {
                                            path: row.logical_path.clone(),
                                        };
                                        ui.close();
                                    }
                                });

                                ui.end_row();
                            }
                        });
                }
            });

        // Keyset Pagination Controls
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(format!("Page {}", state.current_page + 1));

            if ui
                .add_enabled(state.current_page > 0, egui::Button::new("< Previous"))
                .clicked()
            {
                action = ArtifactsViewAction::PrevPage;
            }

            if ui
                .add_enabled(state.has_more, egui::Button::new("Next >"))
                .clicked()
            {
                action = ArtifactsViewAction::NextPage;
            }
        });
    });

    action
}

fn is_filesystem_inventory(category: &str) -> bool {
    let lower = category.trim().to_lowercase();
    matches!(
        lower.as_str(),
        "file system"
            | "filesystem"
            | "operating system"
            | "documents"
            | "multimedia"
            | "archives"
            | "unallocated"
            | "slack"
    )
}

fn render_category_node(
    ui: &mut egui::Ui,
    node: &ArtifactCategoryNode,
    state: &ArtifactsViewState,
    action: &mut ArtifactsViewAction,
) {
    let is_selected = state.selected_category.as_deref() == Some(&node.main_category)
        && state.selected_sub_category.as_deref() == node.sub_category.as_deref();

    let label_text = format!("{} ({})", node.label, node.count);
    let label = if is_selected {
        RichText::new(label_text).strong().color(Color32::YELLOW)
    } else {
        RichText::new(label_text)
    };

    if node.children.is_empty() {
        if ui.selectable_label(is_selected, label).clicked() {
            *action = ArtifactsViewAction::SelectCategory {
                main: node.main_category.clone(),
                sub: node.sub_category.clone(),
            };
        }
    } else {
        egui::CollapsingHeader::new(label)
            .default_open(true)
            .show(ui, |ui| {
                if ui
                    .selectable_label(is_selected, "• View All in Category")
                    .clicked()
                {
                    *action = ArtifactsViewAction::SelectCategory {
                        main: node.main_category.clone(),
                        sub: None,
                    };
                }
                for child in &node.children {
                    render_category_node(ui, child, state, action);
                }
            });
    }
}

fn format_bytes(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => {
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
        None => "-".to_string(),
    }
}

fn browser_origin_label(origin: Option<&str>, source: Option<&str>) -> String {
    let origin_label = match origin.unwrap_or("") {
        "remote_synced" => "Remote synced",
        "local_browsed" => "Local to profile",
        "synced_origin_unresolved" => "Synced; source unresolved",
        "sync_eligible_origin_unresolved" => "Sync-eligible; origin unresolved",
        "imported" => "Imported into browser",
        "extension" => "Extension generated",
        "origin_unresolved" => "Origin unresolved",
        "unknown" => "Unknown",
        "" => "Not recorded",
        value => value,
    };
    match source.filter(|value| !value.trim().is_empty()) {
        Some(source) => format!("{origin_label} · {source}"),
        None => origin_label.to_string(),
    }
}

fn browser_origin_tooltip(origin: Option<&str>, source: Option<&str>) -> String {
    format!(
        "Stored visit_origin: {}\nStored visit source: {}\n\n'Local to profile' does not prove that the visit occurred on the acquired physical device; a browser profile can be copied or restored.",
        origin.unwrap_or("not recorded"),
        source.unwrap_or("not recorded"),
    )
}

fn browser_profile_sync_label(
    family: Option<&str>,
    profile: Option<&str>,
    sync_guid_short: Option<&str>,
) -> String {
    let family_profile = match (
        family.filter(|value| !value.trim().is_empty()),
        profile.filter(|value| !value.trim().is_empty()),
    ) {
        (Some(family), Some(profile)) => format!("{family} / {profile}"),
        (Some(family), None) => family.to_string(),
        (None, Some(profile)) => profile.to_string(),
        (None, None) => "Profile not recorded".to_string(),
    };
    match sync_guid_short.filter(|value| !value.trim().is_empty()) {
        Some(guid) => format!("{family_profile} · Sync {guid}"),
        None => family_profile,
    }
}

fn browser_sync_tooltip(guid: Option<&str>, note: Option<&str>) -> String {
    match guid.filter(|value| !value.trim().is_empty()) {
        Some(guid) => format!(
            "Originating Chromium Sync client GUID: {guid}\n\n{}",
            note.unwrap_or(
                "This is an opaque Chromium Sync client identifier, not a hardware-device ID."
            )
        ),
        None => "No originating Sync client GUID is recorded for this visit. This absence does not prove that the acquired physical device created the visit.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_origin_labels_do_not_overclaim_physical_device_provenance() {
        assert_eq!(
            browser_origin_label(Some("local_browsed"), Some("browsed")),
            "Local to profile · browsed"
        );
        let tooltip = browser_origin_tooltip(Some("local_browsed"), Some("browsed"));
        assert!(tooltip.contains("does not prove"));
        assert!(tooltip.contains("physical device"));
    }

    #[test]
    fn browser_sync_label_and_tooltip_keep_guid_semantics_truthful() {
        assert_eq!(
            browser_profile_sync_label(Some("chromium"), Some("Default"), Some("abcdef12")),
            "chromium / Default · Sync abcdef12"
        );
        let tooltip = browser_sync_tooltip(
            Some("abcdef12-3456"),
            Some("Opaque client identifier; not a hardware device identifier."),
        );
        assert!(tooltip.contains("abcdef12-3456"));
        assert!(tooltip.contains("not a hardware device identifier"));
    }
}
