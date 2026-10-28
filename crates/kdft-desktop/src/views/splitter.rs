#![forbid(unsafe_code)]

//! Reusable draggable and collapsible splitters for forensic workbench panes.

use eframe::egui::{self, Color32, CursorIcon, Rect, Sense, Stroke, Vec2};

/// Renders a horizontal divider between upper and lower panes.
pub fn horizontal_splitter(
    ui: &mut egui::Ui,
    _id_salt: &str,
    height: &mut f32,
    collapsed: &mut bool,
    default_height: f32,
    min_height: f32,
    max_height: f32,
) {
    let available_width = ui.available_width();
    let splitter_height = 8.0;
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(available_width, splitter_height),
        Sense::click_and_drag(),
    );

    let is_hovered = response.hovered();
    let is_dragged = response.dragged();

    if is_dragged {
        // `Response::drag_delta` is cumulative from the start of the drag.
        // Adding it every frame makes the divider accelerate and jump to a
        // limit.  Pointer delta is the bounded per-frame movement we need.
        let delta_y = ui.input(|input| input.pointer.delta().y);
        *height = adjusted_splitter_value(*height, delta_y, min_height, max_height, false);
        *collapsed = false;
    }

    if response.double_clicked() {
        *height = default_height;
        *collapsed = false;
    }

    if is_hovered || is_dragged {
        ui.ctx().set_cursor_icon(CursorIcon::ResizeVertical);
    }

    let line_color = if is_dragged || is_hovered {
        Color32::from_rgb(100, 160, 240)
    } else {
        Color32::from_rgb(60, 65, 75)
    };

    ui.painter().hline(
        rect.x_range(),
        rect.center().y,
        Stroke::new(1.5, line_color),
    );

    // Center collapse/expand toggle button
    let button_rect = Rect::from_center_size(rect.center(), Vec2::new(32.0, 14.0));
    let btn_resp = ui.allocate_rect(button_rect, Sense::click());
    let btn_color = if btn_resp.hovered() {
        Color32::from_rgb(80, 90, 110)
    } else {
        Color32::from_rgb(45, 50, 60)
    };
    ui.painter().rect_filled(button_rect, 2.0, btn_color);

    let arrow = if *collapsed { "v" } else { "^" };
    ui.painter().text(
        button_rect.center(),
        egui::Align2::CENTER_CENTER,
        arrow,
        egui::FontId::proportional(11.0),
        Color32::LIGHT_GRAY,
    );

    if btn_resp.clicked() {
        *collapsed = !*collapsed;
    }
}

/// Renders a vertical divider between left and right panes.
#[allow(clippy::too_many_arguments)]
pub fn vertical_splitter(
    ui: &mut egui::Ui,
    _id_salt: &str,
    width: &mut f32,
    collapsed: &mut bool,
    default_width: f32,
    min_width: f32,
    max_width: f32,
    collapse_to_right: bool,
) {
    let available_height = ui.available_height();
    let splitter_width = 8.0;
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(splitter_width, available_height),
        Sense::click_and_drag(),
    );

    let is_hovered = response.hovered();
    let is_dragged = response.dragged();

    if is_dragged {
        let delta_x = ui.input(|input| input.pointer.delta().x);
        *width = adjusted_splitter_value(*width, delta_x, min_width, max_width, collapse_to_right);
        *collapsed = false;
    }

    if response.double_clicked() {
        *width = default_width;
        *collapsed = false;
    }

    if is_hovered || is_dragged {
        ui.ctx().set_cursor_icon(CursorIcon::ResizeHorizontal);
    }

    let line_color = if is_dragged || is_hovered {
        Color32::from_rgb(100, 160, 240)
    } else {
        Color32::from_rgb(60, 65, 75)
    };

    ui.painter().vline(
        rect.center().x,
        rect.y_range(),
        Stroke::new(1.5, line_color),
    );

    // Center collapse/expand toggle button
    let button_rect = Rect::from_center_size(rect.center(), Vec2::new(14.0, 32.0));
    let btn_resp = ui.allocate_rect(button_rect, Sense::click());
    let btn_color = if btn_resp.hovered() {
        Color32::from_rgb(80, 90, 110)
    } else {
        Color32::from_rgb(45, 50, 60)
    };
    ui.painter().rect_filled(button_rect, 2.0, btn_color);

    let arrow = if *collapsed {
        if collapse_to_right {
            "<"
        } else {
            ">"
        }
    } else if collapse_to_right {
        ">"
    } else {
        "<"
    };
    ui.painter().text(
        button_rect.center(),
        egui::Align2::CENTER_CENTER,
        arrow,
        egui::FontId::proportional(11.0),
        Color32::LIGHT_GRAY,
    );

    if btn_resp.clicked() {
        *collapsed = !*collapsed;
    }
}

fn adjusted_splitter_value(
    current: f32,
    pointer_delta: f32,
    minimum: f32,
    maximum: f32,
    invert_delta: bool,
) -> f32 {
    let effective_delta = if invert_delta {
        -pointer_delta
    } else {
        pointer_delta
    };
    (current + effective_delta).clamp(minimum, maximum)
}

#[cfg(test)]
mod tests {
    use super::adjusted_splitter_value;

    #[test]
    fn splitter_applies_only_the_current_pointer_delta() {
        assert_eq!(
            adjusted_splitter_value(300.0, 12.0, 100.0, 600.0, false),
            312.0
        );
        assert_eq!(
            adjusted_splitter_value(312.0, 3.0, 100.0, 600.0, false),
            315.0
        );
    }

    #[test]
    fn right_hand_pane_inverts_drag_direction_and_clamps() {
        assert_eq!(
            adjusted_splitter_value(320.0, 20.0, 180.0, 500.0, true),
            300.0
        );
        assert_eq!(
            adjusted_splitter_value(190.0, 30.0, 180.0, 500.0, true),
            180.0
        );
        assert_eq!(
            adjusted_splitter_value(490.0, -30.0, 180.0, 500.0, true),
            500.0
        );
    }
}
