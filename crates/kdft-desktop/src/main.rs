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
        renderer: desktop_renderer(),
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

fn desktop_renderer() -> eframe::Renderer {
    renderer_from_name(std::env::var("KDFT_RENDERER").ok().as_deref())
}

fn renderer_from_name(name: Option<&str>) -> eframe::Renderer {
    match name.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("glow" | "opengl") => eframe::Renderer::Glow,
        _ => eframe::Renderer::Wgpu,
    }
}

fn report_startup_error(error: &eframe::Error) {
    let description = format!(
        "KDFT Desktop could not start using the {} graphics backend.\n\n{error}\n\n\
         KDFT uses DirectX/Vulkan through WGPU by default. To force the legacy OpenGL \
         renderer, set KDFT_RENDERER=glow before starting KDFT.",
        desktop_renderer()
    );
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
    use super::renderer_from_name;

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

    #[test]
    fn desktop_prefers_wgpu_and_allows_explicit_glow_fallback() {
        assert_eq!(renderer_from_name(None), eframe::Renderer::Wgpu);
        assert_eq!(renderer_from_name(Some("wgpu")), eframe::Renderer::Wgpu);
        assert_eq!(renderer_from_name(Some("glow")), eframe::Renderer::Glow);
        assert_eq!(renderer_from_name(Some(" OpenGL ")), eframe::Renderer::Glow);
    }
}
