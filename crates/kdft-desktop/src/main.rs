#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = run() {
        report_startup_error(&error);
        std::process::exit(1);
    }
}

fn run() -> eframe::Result {
    let initial_case_path = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1_280.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_visible(true)
            .with_active(true),
        ..Default::default()
    };

    eframe::run_native(
        "KDFT Desktop",
        options,
        Box::new(move |context| {
            context
                .egui_ctx
                .send_viewport_cmd(eframe::egui::ViewportCommand::Visible(true));
            context
                .egui_ctx
                .send_viewport_cmd(eframe::egui::ViewportCommand::Minimized(false));
            context
                .egui_ctx
                .send_viewport_cmd(eframe::egui::ViewportCommand::Focus);
            Ok(Box::new(kdft_desktop::KDFTDesktopApp::new(
                context,
                initial_case_path,
            )))
        }),
    )
}

fn report_startup_error(error: &eframe::Error) {
    let description = format!("KDFT Desktop could not start.\n\n{error}");
    eprintln!("{description}");

    #[cfg(target_os = "windows")]
    {
        let _ = rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("KDFT Desktop startup error")
            .set_description(description)
            .show();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn desktop_viewport_is_explicitly_visible_and_active() {
        let viewport = eframe::egui::ViewportBuilder::default()
            .with_inner_size([1_280.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_visible(true)
            .with_active(true);

        assert_eq!(viewport.visible, Some(true));
        assert_eq!(viewport.active, Some(true));
        assert_eq!(
            viewport.inner_size,
            Some(eframe::egui::vec2(1_280.0, 800.0))
        );
        assert_eq!(
            viewport.min_inner_size,
            Some(eframe::egui::vec2(900.0, 600.0))
        );
    }
}
