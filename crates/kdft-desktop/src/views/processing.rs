#![forbid(unsafe_code)]

//! Processing monitor view.
//!
//! Provides live multi-stage processing progress, stage indicators, cancellation,
//! and truthful terminal states (Complete, Partial, Truncated, Cancelled, Failed).

use eframe::egui::{self, Color32, ProgressBar, RichText};
use kdft_desktop_core::{
    JobProgressSnapshot, ProcessEvidenceSummary, ProcessingJobRecord, ProcessorCoverageRecord,
};

pub enum ProcessingViewAction {
    None,
    CancelProcessing,
    AcknowledgeSummary,
    RefreshHistory,
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut egui::Ui,
    is_processing: bool,
    active_evidence_name: Option<&str>,
    snapshot: Option<&JobProgressSnapshot>,
    last_summary: Option<&ProcessEvidenceSummary>,
    error: Option<&str>,
    history_error: Option<&str>,
    job_history: &[ProcessingJobRecord],
    coverage_records: &[ProcessorCoverageRecord],
) -> ProcessingViewAction {
    let mut action = ProcessingViewAction::None;

    ui.vertical(|ui| {
        ui.heading("Processing & Indexing Monitor");
        ui.separator();

        if let Some(err) = error {
            ui.colored_label(Color32::from_rgb(255, 100, 100), RichText::new(err).strong());
            ui.add_space(8.0);
        }

        if is_processing {
            ui.group(|ui| {
                let is_cancelling = snapshot.map(|s| s.cancellation_requested).unwrap_or(false);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.strong(format!(
                        "Processing Active: {}",
                        active_evidence_name.unwrap_or("Evidence Source")
                    ));
                    if is_cancelling {
                        ui.label(RichText::new("⚠️ CANCELLATION REQUESTED - GRACEFUL SHUTDOWN").color(Color32::from_rgb(255, 140, 40)).strong());
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if is_cancelling {
                            ui.add_enabled(false, egui::Button::new("Cancelling..."));
                        } else if ui
                            .button(RichText::new("Cancel Job").color(Color32::from_rgb(255, 80, 80)))
                            .on_hover_text("Request graceful cancellation of processing")
                            .clicked()
                        {
                            action = ProcessingViewAction::CancelProcessing;
                        }
                    });
                });

                ui.add_space(8.0);

                if let Some(snap) = snapshot {
                    let stage_fraction = snap.percentage.map(|p| (p as f32 / 100.0).clamp(0.0, 1.0)).unwrap_or_else(|| {
                        if let Some(tot) = snap.total_items {
                            if tot > 0 {
                                (snap.processed_items as f32 / tot as f32).clamp(0.0, 1.0)
                            } else {
                                0.0
                            }
                        } else {
                            0.0
                        }
                    });

                    let whole_job_fraction = match (snap.stage_index, snap.stage_count) {
                        (Some(idx), Some(cnt)) if cnt > 0 => {
                            let completed = idx.saturating_sub(1) as f32;
                            ((completed + stage_fraction) / cnt as f32).clamp(0.0, 1.0)
                        }
                        _ => stage_fraction,
                    };

                    ui.horizontal(|ui| {
                        ui.weak("Whole Job:");
                        let job_progress_bar = ProgressBar::new(whole_job_fraction)
                            .show_percentage()
                            .animate(true);
                        ui.add(job_progress_bar);
                    });

                    ui.add_space(3.0);
                    ui.horizontal(|ui| {
                        let stage_label = match (snap.stage_index, snap.stage_count) {
                            (Some(idx), Some(cnt)) => format!("Stage {}/{}:", idx, cnt),
                            (Some(idx), None) => format!("Stage {}:", idx),
                            _ => "Current Stage:".to_string(),
                        };
                        ui.weak(stage_label);
                        let stage_progress_bar = ProgressBar::new(stage_fraction)
                            .show_percentage()
                            .animate(true);
                        ui.add(stage_progress_bar);
                    });

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let stage_info = match (snap.stage_index, snap.stage_count) {
                            (Some(idx), Some(cnt)) => format!("Stage: {} ({}/{})", snap.stage_name.as_deref().unwrap_or("Processing"), idx, cnt),
                            (Some(idx), None) => format!("Stage: {} (#{})", snap.stage_name.as_deref().unwrap_or("Processing"), idx),
                            _ => format!("Stage: {}", snap.stage_name.as_deref().unwrap_or("Processing")),
                        };
                        ui.label(stage_info);
                        ui.separator();
                        ui.label(format!("State: {:?}", snap.state));
                        ui.separator();
                        ui.label(format!(
                            "Items: {} / {}",
                            snap.processed_items,
                            snap.total_items
                                .map(|total| total.to_string())
                                .unwrap_or_else(|| "total calculating".to_string())
                        ));
                        if let Some(rate) = snap.rate_per_second {
                            ui.separator();
                            ui.label(format!("{:.1} items/s", rate));
                        } else if snap.last_progress_age_ms >= 5_000 {
                            ui.separator();
                            let recovering = snap.current_phase
                                == Some(kdft_desktop_core::JobProgressPhase::Recovering);
                            let io_age_ms = snap.last_recovery_io_age_ms;
                            if recovering
                                && snap.last_progress_age_ms >= 30_000
                                && io_age_ms.is_none_or(|age| age >= 30_000)
                            {
                                ui.colored_label(
                                    Color32::from_rgb(255, 90, 90),
                                    format!(
                                        "Stalled recovery: no terminal result for {}s and no bounded I/O for {}",
                                        snap.last_progress_age_ms / 1_000,
                                        io_age_ms
                                            .map(|age| format!("{}s", age / 1_000))
                                            .unwrap_or_else(|| "this stage".to_string())
                                    ),
                                );
                            } else if recovering {
                                ui.colored_label(
                                    Color32::from_rgb(255, 180, 60),
                                    format!(
                                        "Slow I/O: no terminal result for {}s; last bounded I/O {}",
                                        snap.last_progress_age_ms / 1_000,
                                        io_age_ms
                                            .map(|age| format!("{}s ago", age / 1_000))
                                            .unwrap_or_else(|| "not yet observed".to_string())
                                    ),
                                );
                            } else {
                                ui.colored_label(
                                    Color32::from_rgb(255, 180, 60),
                                    format!(
                                        "No terminal progress for {}s",
                                        snap.last_progress_age_ms / 1_000
                                    ),
                                );
                            }
                        } else {
                            ui.separator();
                            ui.weak("Rate: calculating");
                        }
                        if let Some(eta) = snap.eta_seconds {
                            ui.separator();
                            ui.label(format!("ETA: {eta}s"));
                        }
                        ui.separator();
                        ui.label(format!("Elapsed: {}s (Stage: {}s)", snap.elapsed_ms / 1000, snap.stage_elapsed_ms / 1000));
                    });

                    if let Some(obj) = &snap.current_object {
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            if let Some(phase) = snap.current_phase {
                                ui.weak("Phase:");
                                ui.strong(phase.label());
                                ui.separator();
                            }
                            if let Some(kind) = &snap.current_source_kind {
                                ui.weak("Source kind:");
                                ui.monospace(RichText::new(kind).size(11.0));
                                ui.separator();
                            }
                            ui.weak("Current Target:");
                            ui.monospace(RichText::new(obj).size(11.0));
                        });
                    }

                    if snap.stage_skipped_count > 0 || snap.stage_error_count > 0 || snap.skipped_count > 0 || snap.error_count > 0 {
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            ui.weak(format!("Stage: {} skipped, {} errors", snap.stage_skipped_count, snap.stage_error_count));
                            ui.separator();
                            ui.weak(format!("Whole Job: {} skipped, {} errors", snap.skipped_count, snap.error_count));
                        });
                    }

                    let stage_outcomes = snap.stage_outcome_counts;
                    let whole_outcomes = snap.outcome_counts;
                    let has_stage_outcomes = stage_outcomes.completed > 0
                        || stage_outcomes.partial > 0
                        || stage_outcomes.failed > 0
                        || stage_outcomes.cancelled > 0
                        || stage_outcomes.unsupported > 0
                        || stage_outcomes.up_to_date > 0;
                    if has_stage_outcomes {
                        ui.add_space(2.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.weak(format!(
                                "Stage outcomes: {} completed, {} partial, {} failed, {} cancelled, {} unsupported, {} up-to-date",
                                stage_outcomes.completed,
                                stage_outcomes.partial,
                                stage_outcomes.failed,
                                stage_outcomes.cancelled,
                                stage_outcomes.unsupported,
                                stage_outcomes.up_to_date,
                            ));
                            ui.separator();
                            ui.weak(format!(
                                "Whole job: {} completed, {} partial, {} failed, {} cancelled, {} unsupported, {} up-to-date",
                                whole_outcomes.completed,
                                whole_outcomes.partial,
                                whole_outcomes.failed,
                                whole_outcomes.cancelled,
                                whole_outcomes.unsupported,
                                whole_outcomes.up_to_date,
                            ));
                        });
                    }

                    if snap.stage_logical_bytes_recovered > 0
                        || snap.stage_recovery_read_operations > 0
                    {
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            ui.weak(format!(
                                "Stage recovery I/O: {} logical bytes reconstructed",
                                snap.stage_logical_bytes_recovered
                            ));
                            ui.separator();
                            ui.weak(format!(
                                "{} bounded read operations",
                                snap.stage_recovery_read_operations
                            ));
                        });
                    }
                } else {
                    ui.label("Initializing processing pipeline...");
                }
            });
        } else {
            ui.group(|ui| {
                ui.strong("Engine Status");
                ui.label("No processing job is currently running.");
            });
        }

        ui.add_space(16.0);

        // Terminal Summary of Last Run
        if let Some(sum) = last_summary {
            ui.group(|ui| {
                ui.heading("Last Processing Job Summary");
                ui.separator();

                let (status_text, status_color) = match sum.status.to_lowercase().as_str() {
                    "complete" => ("COMPLETE", Color32::from_rgb(40, 200, 60)),
                    "truncated" => ("TRUNCATED (Examiner Limit Reached)", Color32::from_rgb(255, 180, 0)),
                    "cancelled" => ("CANCELLED", Color32::from_rgb(255, 100, 100)),
                    "failed" => ("FAILED", Color32::from_rgb(255, 50, 50)),
                    _ => ("PARTIAL / COMPLETE WITH DIAGNOSTICS", Color32::from_rgb(200, 200, 200)),
                };

                ui.horizontal(|ui| {
                    ui.label("Terminal Status:");
                    ui.colored_label(status_color, RichText::new(status_text).strong());
                });

                ui.add_space(4.0);
                egui::Grid::new("last_process_grid")
                    .num_columns(2)
                    .spacing([24.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Job ID:");
                        ui.monospace(format!("#{}", sum.job_id));
                        ui.end_row();

                        ui.label("Evidence ID:");
                        ui.monospace(format!("#{}", sum.evidence_id));
                        ui.end_row();

                        ui.label("Indexed Entries:");
                        ui.strong(format!("{}", sum.entries_indexed));
                        ui.end_row();

                        ui.label("Retained Entries:");
                        ui.strong(format!("{}", sum.retained_entry_count));
                        ui.end_row();

                        ui.label("Raw Status:");
                        ui.label(&sum.status);
                        ui.end_row();
                    });

                if !sum.truncation_reasons.is_empty() {
                    ui.add_space(8.0);
                    ui.strong("Truncation Reasons:");
                    egui::ScrollArea::vertical()
                        .max_height(120.0)
                        .show(ui, |ui| {
                            for reason in &sum.truncation_reasons {
                                ui.colored_label(Color32::from_rgb(255, 180, 60), format!("• {reason}"));
                            }
                        });
                }

                if !sum.post_commit_warnings.is_empty() {
                    ui.add_space(8.0);
                    ui.strong("Post-Commit Diagnostic Warnings:");
                    egui::ScrollArea::vertical()
                        .max_height(120.0)
                        .show(ui, |ui| {
                            for warn in &sum.post_commit_warnings {
                                ui.colored_label(Color32::from_rgb(255, 200, 80), format!("• {warn}"));
                            }
                        });
                }
            });
        }

        ui.add_space(16.0);

        // Verifiable Processor Coverage Table
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.heading("Verifiable Processor Coverage");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh Coverage").clicked() {
                        action = ProcessingViewAction::RefreshHistory;
                    }
                });
            });
            ui.weak("Coverage status is verified strictly from persisted database records; unsupported processors are explicitly declared.");
            ui.separator();

            if coverage_records.is_empty() {
                ui.weak("No coverage data available. Open a case to inspect coverage.");
            } else {
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        egui::Grid::new("processor_coverage_grid")
                            .striped(true)
                            .num_columns(5)
                            .spacing([18.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("Processor Module");
                                ui.strong("Scope / Target");
                                ui.strong("Verifiable Status");
                                ui.strong("Output Rows");
                                ui.strong("Notes / Diagnostics");
                                ui.end_row();

                                for cov in coverage_records {
                                    ui.label(&cov.group_name);
                                    ui.label(&cov.scope);

                                    let (badge_color, badge_text) = match cov.status.as_str() {
                                        "Complete" => (Color32::from_rgb(40, 200, 60), "Complete"),
                                        "Complete (with warnings)" => (
                                            Color32::from_rgb(200, 200, 80),
                                            "Complete (with warnings)",
                                        ),
                                        "Partial" => (Color32::from_rgb(255, 180, 0), "Partial"),
                                        "Active" => (Color32::from_rgb(100, 160, 240), "Active"),
                                        "Queued" => (Color32::from_rgb(150, 150, 170), "Queued"),
                                        "Interrupted" => (
                                            Color32::from_rgb(255, 120, 80),
                                            "Interrupted",
                                        ),
                                        "Canceled" => (Color32::from_rgb(255, 140, 80), "Canceled"),
                                        "Failed" => (Color32::from_rgb(255, 60, 60), "Failed"),
                                        "Unsupported" => (Color32::from_rgb(140, 140, 150), "Unsupported"),
                                        "Not proven" => (Color32::from_rgb(220, 160, 80), "Not proven"),
                                        "Not started" | "Not run" => (
                                            Color32::from_rgb(180, 180, 180),
                                            cov.status.as_str(),
                                        ),
                                        _ => (
                                            Color32::from_rgb(180, 180, 180),
                                            cov.status.as_str(),
                                        ),
                                    };
                                    ui.colored_label(badge_color, RichText::new(badge_text).strong());

                                    ui.monospace(format!("{}", cov.count));
                                    ui.label(cov.message.as_deref().unwrap_or("-"));
                                    ui.end_row();
                                }
                            });
                    });
            }
        });

        ui.add_space(16.0);

        // Job Execution History Table
        ui.group(|ui| {
            ui.heading("Job Execution History");
            ui.weak("Persisted forensic jobs executed on evidence sources in this case.");
            if let Some(error) = history_error {
                ui.colored_label(Color32::from_rgb(255, 140, 80), error);
            }
            ui.separator();

            if job_history.is_empty() {
                ui.weak("No processing jobs recorded in this case database.");
            } else {
                egui::ScrollArea::vertical()
                    .max_height(260.0)
                    .show(ui, |ui| {
                        for job in job_history {
                            let status_color = match job.status {
                                kdft_desktop_core::ProcessingJobState::Complete => {
                                    Color32::from_rgb(40, 200, 60)
                                }
                                kdft_desktop_core::ProcessingJobState::CompleteWithWarnings => {
                                    Color32::from_rgb(200, 200, 80)
                                }
                                kdft_desktop_core::ProcessingJobState::Partial => {
                                    Color32::from_rgb(255, 180, 0)
                                }
                                kdft_desktop_core::ProcessingJobState::Running => {
                                    Color32::from_rgb(100, 160, 240)
                                }
                                kdft_desktop_core::ProcessingJobState::Canceled => {
                                    Color32::from_rgb(255, 100, 100)
                                }
                                kdft_desktop_core::ProcessingJobState::Failed => {
                                    Color32::from_rgb(255, 50, 50)
                                }
                                _ => Color32::from_rgb(180, 180, 180),
                            };
                            let title = format!(
                                "Job #{} — {} ({}) [{}]",
                                job.id,
                                job.evidence_name,
                                job.job_type,
                                job.status.label()
                            );
                            egui::CollapsingHeader::new(
                                RichText::new(title).strong().color(status_color),
                            )
                            .default_open(true)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label("Started:");
                                    ui.monospace(job.started_at.as_deref().unwrap_or("-"));
                                    ui.separator();
                                    ui.label("Finished:");
                                    ui.monospace(job.finished_at.as_deref().unwrap_or("-"));
                                });
                                if let Some(err) = &job.error {
                                    ui.colored_label(
                                        Color32::from_rgb(255, 80, 80),
                                        format!("Error: {err}"),
                                    );
                                }
                                if job.stage_executions.is_empty() {
                                    ui.weak(
                                        "No individual stage executions recorded for this job.",
                                    );
                                } else {
                                    egui::Grid::new(format!("job_exec_grid_{}", job.id))
                                        .striped(true)
                                        .num_columns(5)
                                        .spacing([14.0, 4.0])
                                        .show(ui, |ui| {
                                            ui.strong("Stage");
                                            ui.strong("Processor");
                                            ui.strong("Status");
                                            ui.strong("Items Indexed");
                                            ui.strong("Diagnostics");
                                            ui.end_row();

                                            for stage in &job.stage_executions {
                                                ui.monospace(format!("#{}", stage.stage_index));
                                                ui.label(&stage.processor_name);
                                                let sc = if stage.status == "completed" {
                                                    Color32::from_rgb(40, 200, 60)
                                                } else if stage.status
                                                    == "completed_with_diagnostics"
                                                {
                                                    Color32::from_rgb(200, 200, 80)
                                                } else {
                                                    Color32::from_rgb(255, 100, 100)
                                                };
                                                ui.colored_label(sc, &stage.status);
                                                ui.label(format!(
                                                    "{} ({} disc)",
                                                    stage.items_indexed, stage.items_discovered
                                                ));
                                                ui.label(
                                                    stage.diagnostics_json.as_deref().unwrap_or("-"),
                                                );
                                                ui.end_row();
                                            }
                                        });
                                }
                            });
                            ui.add_space(4.0);
                        }
                    });
            }
        });
    });

    action
}
