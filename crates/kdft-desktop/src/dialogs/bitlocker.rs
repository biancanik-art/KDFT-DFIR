#![forbid(unsafe_code)]

//! BitLocker transient unlock dialog.
//!
//! Handles masked password / recovery key entry, zeroizes memory on dismiss,
//! and never persists credentials to SQLite, configuration, or audit logs.

use crate::state::BitLockerDialogState;
use eframe::egui::{self, Color32, RichText, Window};
use zeroize::Zeroize;

pub enum BitLockerDialogAction {
    None,
    Unlock {
        evidence_id: i64,
        volume_index: usize,
        is_recovery_key: bool,
        credential: zeroize::Zeroizing<String>,
    },
    Cancel,
}

pub fn show(ctx: &egui::Context, state: &mut BitLockerDialogState) -> BitLockerDialogAction {
    if !state.visible {
        return BitLockerDialogAction::None;
    }

    let mut action = BitLockerDialogAction::None;
    let mut is_open = state.visible;

    Window::new("BitLocker Volume Unlock")
        .open(&mut is_open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.heading("Unlock BitLocker Volume");
            ui.label(format!(
                "Volume #{}: {}",
                state.volume_index, state.volume_label
            ));
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.radio_value(&mut state.is_recovery_key, false, "User Password");
                ui.radio_value(&mut state.is_recovery_key, true, "48-digit Recovery Key");
            });

            ui.add_space(8.0);

            ui.label(if state.is_recovery_key {
                "Recovery Key (numbers and dashes):"
            } else {
                "BitLocker Password:"
            });

            ui.horizontal(|ui| {
                let text_edit = egui::TextEdit::singleline(&mut state.credential_input)
                    .password(!state.reveal_credential)
                    .desired_width(320.0);
                ui.add(text_edit);

                if ui
                    .button(if state.reveal_credential {
                        "Hide"
                    } else {
                        "Show"
                    })
                    .on_hover_text("Toggle password visibility")
                    .clicked()
                {
                    state.reveal_credential = !state.reveal_credential;
                }
            });

            ui.add_space(4.0);
            ui.colored_label(
                Color32::from_rgb(180, 180, 180),
                "Credentials remain in transient memory only and are never saved to disk or logs.",
            );

            if let Some(err) = &state.error {
                ui.add_space(4.0);
                ui.colored_label(
                    Color32::from_rgb(255, 100, 100),
                    RichText::new(err).strong(),
                );
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let can_unlock = !state.is_unlocking;
                if ui
                    .add_enabled(
                        can_unlock,
                        egui::Button::new(RichText::new("Unlock Volume").strong()),
                    )
                    .on_hover_text("Attempt to unlock the volume in transient memory")
                    .clicked()
                {
                    let trimmed = state.credential_input.trim();
                    if trimmed.is_empty() {
                        state.error = Some("Credential cannot be blank.".to_string());
                    } else {
                        state.error = None;
                        state.is_unlocking = true;
                        let secret = zeroize::Zeroizing::new(trimmed.to_string());
                        state.credential_input.zeroize();
                        action = BitLockerDialogAction::Unlock {
                            evidence_id: state.evidence_id,
                            volume_index: state.volume_index,
                            is_recovery_key: state.is_recovery_key,
                            credential: secret,
                        };
                    }
                }

                if ui.button("Cancel").clicked() {
                    state.is_unlocking = false;
                    state.credential_input.zeroize();
                    state.visible = false;
                    action = BitLockerDialogAction::Cancel;
                }

                if state.is_unlocking {
                    ui.spinner();
                    ui.weak("Verifying BitLocker credential...");
                }
            });
        });

    if !is_open && state.visible {
        state.is_unlocking = false;
        state.credential_input.zeroize();
        state.visible = false;
        action = BitLockerDialogAction::Cancel;
    }

    action
}
