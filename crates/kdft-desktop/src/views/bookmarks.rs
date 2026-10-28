#![forbid(unsafe_code)]

//! Bookmarks view.
//!
//! Provides folder hierarchies, bookmark lists with Resume action for partial/incomplete
//! bookmarks, bounded item pagination, and detail inspection.

use eframe::egui::{self, Color32, RichText, Stroke};
use kdft_desktop_core::{
    BookmarkCursor, BookmarkFolderSummary, BookmarkFoldersPage, BookmarkItemDetail,
    BookmarkItemSummary, BookmarkItemsPage, BookmarkSummary, BookmarksPage,
};

pub enum BookmarksViewAction {
    None,
    NewFolder,
    Refresh,
    SelectFolder(i64),
    SelectBookmark(i64),
    SelectItem(i64),
    ResumeBookmark(i64),
    RemoveFolder(BookmarkFolderSummary),
    RemoveBookmark(BookmarkSummary),
    RemoveItem(BookmarkItemSummary),
    InspectItem(i64),
    LoadFoldersPage(Option<BookmarkCursor>),
    LoadBookmarksPage(Option<BookmarkCursor>),
    LoadItemsPage(Option<BookmarkCursor>),
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    has_case: bool,
    loading: bool,
    error: Option<&str>,
    bookmark_folders: &[BookmarkFolderSummary],
    _bookmark_folders_page: Option<&BookmarkFoldersPage>,
    _bookmark_folders_page_index: usize,
    selected_bookmark_folder: Option<i64>,
    bookmarks: &[BookmarkSummary],
    _bookmarks_page: Option<&BookmarksPage>,
    _bookmarks_page_index: usize,
    selected_bookmark_id: Option<i64>,
    bookmark_items: &[BookmarkItemSummary],
    _bookmark_items_page: Option<&BookmarkItemsPage>,
    _bookmark_items_page_index: usize,
    selected_bookmark_item_id: Option<i64>,
    selected_bookmark_item_detail: Option<&BookmarkItemDetail>,
) -> BookmarksViewAction {
    let mut action = BookmarksViewAction::None;

    if !has_case {
        ui.centered_and_justified(|ui| {
            ui.label("Open a case to view and manage bookmarks.");
        });
        return action;
    }

    ui.horizontal(|ui| {
        ui.heading("Bookmarks & Findings");
        ui.separator();
        if ui.button("+ New Folder...").clicked() {
            action = BookmarksViewAction::NewFolder;
        }
        if ui.button("Refresh").clicked() {
            action = BookmarksViewAction::Refresh;
        }
        if loading {
            ui.spinner();
        }
    });

    ui.separator();

    if let Some(err) = error {
        egui::Frame::new()
            .fill(Color32::from_rgb(74, 28, 32))
            .stroke(Stroke::new(1.5, Color32::from_rgb(230, 90, 90)))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Bookmark Error")
                        .strong()
                        .color(Color32::LIGHT_RED),
                );
                ui.label(err);
            });
    }

    // 3-column layout: Folders | Bookmarks | Items & Details
    ui.columns(3, |columns| {
        // Column 1: Folders
        columns[0].strong("Folders");
        columns[0].separator();
        if bookmark_folders.is_empty() {
            columns[0].weak("No bookmark folders.");
        } else {
            egui::ScrollArea::vertical()
                .id_salt("bm_folders_scroll")
                .show(&mut columns[0], |ui| {
                    for folder in bookmark_folders {
                        let is_sel = selected_bookmark_folder == Some(folder.id);
                        ui.horizontal(|ui| {
                            let label = format!("📁 {} ({})", folder.name, folder.bookmark_count);
                            if ui.selectable_label(is_sel, label).clicked() {
                                action = BookmarksViewAction::SelectFolder(folder.id);
                            }
                            if ui.button("Delete").clicked() {
                                action = BookmarksViewAction::RemoveFolder(folder.clone());
                            }
                        });
                    }
                });
        }

        // Column 2: Bookmarks
        columns[1].strong("Bookmarks");
        columns[1].separator();
        if bookmarks.is_empty() {
            columns[1].weak("No bookmarks in selected folder.");
        } else {
            egui::ScrollArea::vertical()
                .id_salt("bm_bookmarks_scroll")
                .show(&mut columns[1], |ui| {
                    for bm in bookmarks {
                        let is_sel = selected_bookmark_id == Some(bm.id);
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                let label = format!("🔖 {} ({} items)", bm.title, bm.item_count);
                                if ui.selectable_label(is_sel, label).clicked() {
                                    action = BookmarksViewAction::SelectBookmark(bm.id);
                                }
                                if bm.is_incomplete
                                    && ui
                                        .button(
                                            RichText::new("▶ Resume")
                                                .color(Color32::from_rgb(255, 180, 0))
                                                .strong(),
                                        )
                                        .on_hover_text("Resume incomplete recursive bookmark")
                                        .clicked()
                                {
                                    action = BookmarksViewAction::ResumeBookmark(bm.id);
                                }
                                if ui.button("Delete").clicked() {
                                    action = BookmarksViewAction::RemoveBookmark(bm.clone());
                                }
                            });

                            if bm.is_incomplete {
                                ui.colored_label(
                                    Color32::from_rgb(220, 140, 0),
                                    "⚠️ Incomplete (Partial) - Resume available",
                                );
                            }
                            if let Some(comment) = &bm.examiner_comment {
                                ui.weak(comment);
                            }
                            ui.label(RichText::new(&bm.created_at).size(10.0));
                        });
                    }
                });
        }

        // Column 3: Items & Item Detail
        columns[2].strong("Items in Bookmark");
        columns[2].separator();
        if bookmark_items.is_empty() {
            columns[2].weak("No items in selected bookmark.");
        } else {
            egui::ScrollArea::vertical()
                .id_salt("bm_items_scroll")
                .show(&mut columns[2], |ui| {
                    for item in bookmark_items {
                        let is_sel = selected_bookmark_item_id == Some(item.id);
                        ui.horizontal(|ui| {
                            let label = format!("#{} {}", item.id, item.display_name);
                            if ui.selectable_label(is_sel, label).clicked() {
                                action = BookmarksViewAction::SelectItem(item.id);
                            }
                            if let Some(entry_id) = item.entry_id {
                                if ui.button("Inspect").clicked() {
                                    action = BookmarksViewAction::InspectItem(entry_id);
                                }
                            }
                            if ui.button("Delete").clicked() {
                                action = BookmarksViewAction::RemoveItem(item.clone());
                            }
                        });
                    }
                });
        }

        if let Some(detail) = selected_bookmark_item_detail {
            columns[2].separator();
            columns[2].strong("Selected Item Detail:");
            columns[2].label(format!("Path: {}", detail.logical_path));
            if let Some(p) = &detail.data_preview {
                columns[2].monospace(p);
            }
        }
    });

    action
}
