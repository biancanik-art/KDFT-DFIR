#![forbid(unsafe_code)]

fn main() -> eframe::Result {
    let initial_case_path = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1_280.0, 800.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "KDFT Desktop",
        options,
        Box::new(move |context| {
            Ok(Box::new(kdft_desktop::KDFTDesktopApp::new(
                context,
                initial_case_path,
            )))
        }),
    )
}
