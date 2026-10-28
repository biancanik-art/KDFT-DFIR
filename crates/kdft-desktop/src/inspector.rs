use eframe::egui::{self, Color32, RichText, Stroke};
use kdft_desktop_core::{
    ArtifactCoordinate, ArtifactDetail, ArtifactMetadataState, ArtifactSectionAvailability,
    ArtifactValueAvailability, CoverageState,
};

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct InspectorResponse {
    pub bookmark_clicked: bool,
    pub close_clicked: bool,
}

pub(crate) fn show(
    ui: &mut egui::Ui,
    selection: Option<(i64, i64)>,
    detail: Option<&ArtifactDetail>,
    loading: bool,
    error: Option<&str>,
    view_stale: bool,
    pinned: &mut bool,
) -> InspectorResponse {
    let mut resp = InspectorResponse::default();
    ui.horizontal(|ui| {
        ui.heading("Inspector");
        let pin_label = if *pinned { "📌 Pinned" } else { "📍 Pin" };
        if ui
            .button(pin_label)
            .on_hover_text("Pin inspector across tab switches")
            .clicked()
        {
            *pinned = !*pinned;
        }
        if ui
            .button("❌ Close")
            .on_hover_text("Close inspector and clear detail")
            .clicked()
        {
            resp.close_clicked = true;
        }
        if detail.is_some()
            && !view_stale
            && ui
                .button("🔖 Bookmark Artifact...")
                .on_hover_text("Bookmark this inspected finding")
                .clicked()
        {
            resp.bookmark_clicked = true;
        }
    });
    ui.label("Bounded persisted artifact detail");
    ui.separator();

    if view_stale {
        warning_frame(ui, "STALE INSPECTOR", "The case generation changed. Prior detail was cleared and is not actionable. Reopen the case, then reselect the result row.");
        return resp;
    }

    let Some((entry_id, generation)) = selection else {
        ui.label("Select a result-row ID or live-source file to inspect its recorded fields.");
        ui.weak("No raw evidence bytes, arbitrary metadata JSON, or parser logs are loaded here.");
        return resp;
    };

    ui.horizontal_wrapped(|ui| {
        if entry_id == 0 {
            ui.strong("Live Source (Not Indexed)");
        } else {
            ui.strong(format!("Entry #{entry_id}"));
        }
        ui.monospace(format!("snapshot generation {generation}"));
    });

    if loading {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Loading one bounded detail record…");
        });
        return resp;
    }
    if let Some(error) = error {
        error_frame(ui, "Inspector detail unavailable", error);
        return resp;
    }
    let Some(detail) = detail else {
        ui.label("Inspector detail has not been loaded.");
        return resp;
    };
    if detail.entry_id != entry_id || detail.generation != generation {
        warning_frame(
            ui,
            "MISMATCHED SNAPSHOT",
            "The loaded detail does not match the selected row and is withheld. Reopen the case and reselect the row.",
        );
        return resp;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            show_completeness(ui, detail);
            section(ui, "Overview", true, |ui| show_overview(ui, detail));
            section(ui, "Decoded / record fields", true, |ui| {
                if detail.fields.is_empty() {
                    unavailable_row(ui, "Fields", "Not recorded");
                }
                for field in &detail.fields {
                    recorded_row(
                        ui,
                        &field.label,
                        &field.value,
                        field.value_truncated,
                        &field.source,
                    );
                }
                omitted_row(ui, detail.fields_omitted, "fields");
            });
            section(ui, "Timestamps", true, |ui| {
                show_section_status(ui, &detail.timestamps_status);
                if detail.timestamps.is_empty() {
                    unavailable_row(
                        ui,
                        "Timestamp values",
                        availability_text(detail.timestamps_status.state),
                    );
                }
                for timestamp in &detail.timestamps {
                    ui.group(|ui| {
                        ui.strong(&timestamp.label);
                        labeled_value(
                            ui,
                            "Semantic field",
                            display_or_not_recorded(&timestamp.semantic_field),
                        );
                        labeled_value(ui, "Raw persisted value", &timestamp.raw_value);
                        if timestamp.value_truncated {
                            ui.colored_label(Color32::YELLOW, "Value truncated by Inspector bound");
                        }
                        labeled_value(
                            ui,
                            "Basis",
                            timestamp.basis.as_deref().unwrap_or("Not recorded"),
                        );
                        if timestamp.basis_truncated {
                            ui.colored_label(Color32::YELLOW, "Basis truncated by Inspector bound");
                        }
                        labeled_value(
                            ui,
                            "Timezone",
                            timestamp.timezone.as_deref().unwrap_or("Not recorded"),
                        );
                        labeled_value(ui, "Persisted source", &timestamp.source);
                    });
                }
                omitted_row(ui, detail.timestamps_omitted, "timestamps");
            });
            section(ui, "Hashes", true, |ui| {
                show_section_status(ui, &detail.hashes_status);
                ui.weak("Evidence-file and decoded logical-media digests are not acquisition-segment or E01 container hashes.");
                if detail.hashes.is_empty() {
                    unavailable_row(
                        ui,
                        "Hash values",
                        availability_text(detail.hashes_status.state),
                    );
                }
                for hash in &detail.hashes {
                    ui.group(|ui| {
                        ui.strong(&hash.label);
                        labeled_value(ui, "Algorithm", &hash.algorithm);
                        labeled_value(ui, "Digest", &hash.value);
                        if hash.value_truncated {
                            ui.colored_label(Color32::YELLOW, "Digest truncated by Inspector bound");
                        }
                        labeled_value(
                            ui,
                            "Scope / input",
                            hash.scope.as_deref().unwrap_or("Not recorded"),
                        );
                        labeled_value(
                            ui,
                            "Scope status",
                            availability_text(hash.scope_availability),
                        );
                        if hash.scope_truncated {
                            ui.colored_label(Color32::YELLOW, "Scope truncated by Inspector bound");
                        }
                        labeled_value(
                            ui,
                            "Hashed at",
                            hash.hashed_at.as_deref().unwrap_or("Not recorded"),
                        );
                        if hash.hashed_at_truncated {
                            ui.colored_label(Color32::YELLOW, "Hash time truncated by Inspector bound");
                        }
                        labeled_value(ui, "Persisted source", &hash.source);
                    });
                }
                omitted_row(ui, detail.hashes_status.omitted_count, "hashes");
            });
            section(ui, "Coordinates / offsets", true, |ui| {
                show_section_status(ui, &detail.coordinates_status);
                ui.weak("Coordinates are displayed in their persisted namespace. The Inspector performs no coordinate arithmetic.");
                if detail.coordinates.is_empty() {
                    unavailable_row(
                        ui,
                        "Coordinates",
                        availability_text(detail.coordinates_status.state),
                    );
                }
                for coordinate in &detail.coordinates {
                    show_coordinate(ui, coordinate);
                }
                omitted_row(ui, detail.coordinates_status.omitted_count, "coordinates");
            });
            section(ui, "Provenance", false, |ui| {
                if detail.provenance.is_empty() {
                    unavailable_row(ui, "Provenance fields", "Not recorded");
                }
                for field in &detail.provenance {
                    recorded_row(
                        ui,
                        &field.label,
                        &field.value,
                        field.value_truncated,
                        &field.source,
                    );
                }
                omitted_row(ui, detail.provenance_omitted, "provenance fields");
            });
            section(ui, "Diagnostics and warnings", false, |ui| {
                if detail.completeness.diagnostics.is_empty() && detail.warnings.is_empty() {
                    ui.label("No bounded diagnostic or warning is recorded for this projection.");
                }
                for diagnostic in &detail.completeness.diagnostics {
                    ui.colored_label(Color32::YELLOW, diagnostic);
                }
                omitted_row(
                    ui,
                    detail.completeness.diagnostics_omitted,
                    "diagnostics",
                );
                for warning in &detail.warnings {
                    ui.colored_label(Color32::YELLOW, warning);
                }
                omitted_row(ui, detail.warnings_omitted, "warnings");
            });
        });
    resp
}

fn show_completeness(ui: &mut egui::Ui, detail: &ArtifactDetail) {
    let (fill, stroke, label) = if detail.completeness.is_complete {
        (
            Color32::from_rgb(21, 72, 53),
            Color32::from_rgb(76, 210, 145),
            "COMPLETE COVERAGE EXPLICITLY RECORDED",
        )
    } else {
        (
            Color32::from_rgb(67, 43, 19),
            Color32::from_rgb(245, 159, 69),
            "CASE PROCESSING COVERAGE NOT PROVEN COMPLETE",
        )
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.5, stroke))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.label(RichText::new(label).strong().color(stroke));
            labeled_value(
                ui,
                "Coverage state",
                coverage_state_text(detail.completeness.state),
            );
            ui.label(&detail.completeness.detail);
            if !detail.completeness.is_complete {
                ui.strong("Scope: evidence-processing coverage, not validation of this selected row.");
                ui.label(
                    "The selected record may be valid. This warning means KDFT cannot prove that the processor examined every planned candidate source.",
                );
            }
        });
}

fn show_overview(ui: &mut egui::Ui, detail: &ArtifactDetail) {
    labeled_value(ui, "Case ID", &detail.case_id.to_string());
    if detail.entry_id == 0 {
        labeled_value(ui, "Entry ID", "Not indexed (Live source file)");
    } else {
        labeled_value(ui, "Entry ID", &detail.entry_id.to_string());
    }
    labeled_value(ui, "Evidence ID", &detail.evidence_id.to_string());
    labeled_value(
        ui,
        "Parent entry ID",
        &detail
            .parent_id
            .map_or_else(|| "Not recorded".to_string(), |value| value.to_string()),
    );
    recorded_row(
        ui,
        "Display name",
        &detail.display_name,
        detail.display_name_truncated,
        "filesystem_entries.name",
    );
    recorded_row(
        ui,
        "Logical path",
        &detail.logical_path,
        detail.logical_path_truncated,
        "filesystem_entries.logical_path",
    );
    recorded_row(
        ui,
        "Evidence source path",
        &detail.source_path,
        detail.source_path_truncated,
        "evidence_sources.source_path",
    );
    recorded_row(
        ui,
        "Evidence display name",
        &detail.evidence_display_name,
        detail.evidence_display_name_truncated,
        "evidence_sources.display_name",
    );
    recorded_row(
        ui,
        "Evidence source kind",
        &detail.source_kind,
        detail.source_kind_truncated,
        "evidence_sources.source_kind",
    );
    recorded_row(
        ui,
        "Entry kind",
        &detail.entry_kind,
        detail.entry_kind_truncated,
        "filesystem_entries.entry_kind",
    );
    labeled_value(
        ui,
        "Artifact kind",
        detail.artifact_kind.as_deref().unwrap_or("Not recorded"),
    );
    if detail.artifact_kind_truncated {
        ui.colored_label(
            Color32::YELLOW,
            "Artifact kind truncated by Inspector bound",
        );
    }
    labeled_value(
        ui,
        "Size",
        &detail.size_bytes.map_or_else(
            || "Not recorded".to_string(),
            |value| {
                if value < 0 {
                    format!("{value} bytes (invalid)")
                } else {
                    format!("{value} bytes")
                }
            },
        ),
    );
    labeled_value(
        ui,
        "Allocation state",
        if detail.is_deleted {
            "Deleted"
        } else {
            "Allocated"
        },
    );
    labeled_value(
        ui,
        "Metadata state",
        metadata_state_text(detail.metadata_state),
    );
    labeled_value(
        ui,
        "Source job ID",
        &detail
            .source_job_id
            .map_or_else(|| "Not recorded".to_string(), |value| value.to_string()),
    );
    labeled_value(
        ui,
        "Source job type",
        detail.source_job_type.as_deref().unwrap_or("Not recorded"),
    );
    if detail.source_job_type_truncated {
        ui.colored_label(
            Color32::YELLOW,
            "Source job type truncated by Inspector bound",
        );
    }
    labeled_value(
        ui,
        "Source job status",
        detail
            .source_job_status
            .as_deref()
            .unwrap_or("Not recorded"),
    );
    if detail.source_job_status_truncated {
        ui.colored_label(
            Color32::YELLOW,
            "Source job status truncated by Inspector bound",
        );
    }
    labeled_value(
        ui,
        "Parser schema version",
        detail
            .parser_schema_version
            .as_deref()
            .unwrap_or("Not recorded"),
    );
    if detail.parser_schema_version_truncated {
        ui.colored_label(
            Color32::YELLOW,
            "Parser schema version truncated by Inspector bound",
        );
    }
}

fn show_coordinate(ui: &mut egui::Ui, coordinate: &ArtifactCoordinate) {
    ui.group(|ui| {
        ui.strong(&coordinate.label);
        labeled_value(
            ui,
            "Namespace",
            coordinate_namespace_label(&coordinate.namespace),
        );
        labeled_value(ui, "Namespace ID", &coordinate.namespace);
        labeled_value(
            ui,
            "Availability",
            availability_text(coordinate.availability),
        );
        let value = if coordinate.availability == ArtifactValueAvailability::Recorded {
            coordinate.value.as_deref().unwrap_or("Unavailable")
        } else {
            availability_text(coordinate.availability)
        };
        labeled_value(ui, "Recorded value", value);
        if coordinate.value_truncated {
            ui.colored_label(
                Color32::YELLOW,
                "Coordinate value truncated by Inspector bound",
            );
        }
        labeled_value(
            ui,
            "Unit",
            coordinate.unit.as_deref().unwrap_or("Not recorded"),
        );
        labeled_value(
            ui,
            "Exactness",
            if coordinate.exact {
                "Exact flag explicitly recorded"
            } else {
                "Not recorded / not proven exact"
            },
        );
        labeled_value(
            ui,
            "Basis",
            coordinate.basis.as_deref().unwrap_or("Not recorded"),
        );
        labeled_value(
            ui,
            "Scope",
            coordinate.scope.as_deref().unwrap_or("Not recorded"),
        );
        if coordinate.basis_truncated || coordinate.scope_truncated {
            ui.colored_label(
                Color32::YELLOW,
                "Basis or scope truncated by Inspector bound",
            );
        }
        if let Some(warning) = coordinate.warning.as_deref() {
            ui.colored_label(Color32::YELLOW, warning);
        }
        if matches!(
            coordinate.namespace.as_str(),
            "decoded_evidence_media" | "parser_recorded_legacy_physical"
        ) {
            ui.weak("This is not asserted to be an E01 segment/container-file offset.");
        }
    });
}

fn section(
    ui: &mut egui::Ui,
    title: &str,
    default_open: bool,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    egui::CollapsingHeader::new(title)
        .default_open(default_open)
        .show(ui, add_contents);
}

fn recorded_row(ui: &mut egui::Ui, label: &str, value: &str, truncated: bool, source: &str) {
    ui.group(|ui| {
        ui.strong(label);
        ui.label(display_or_not_recorded(value));
        if truncated {
            ui.colored_label(Color32::YELLOW, "Value truncated by Inspector bound");
        }
        ui.weak(format!("Persisted source: {source}"));
    });
}

fn unavailable_row(ui: &mut egui::Ui, label: &str, state: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.strong(label);
        ui.label(state);
    });
}

fn labeled_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.strong(format!("{label}:"));
        ui.label(display_or_not_recorded(value));
    });
}

fn show_section_status(ui: &mut egui::Ui, status: &ArtifactSectionAvailability) {
    labeled_value(ui, "Section status", availability_text(status.state));
    if let Some(reason) = status.reason.as_deref() {
        ui.weak(reason);
    }
}

fn omitted_row(ui: &mut egui::Ui, omitted: usize, item_name: &str) {
    if omitted > 0 {
        ui.colored_label(
            Color32::YELLOW,
            format!("{omitted} additional {item_name} omitted by the bounded projection."),
        );
    }
}

fn warning_frame(ui: &mut egui::Ui, title: &str, detail: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(67, 43, 19))
        .stroke(Stroke::new(1.5, Color32::from_rgb(245, 159, 69)))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(Color32::YELLOW));
            ui.label(detail);
        });
}

fn error_frame(ui: &mut egui::Ui, title: &str, detail: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(74, 28, 32))
        .stroke(Stroke::new(1.5, Color32::from_rgb(230, 90, 90)))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(Color32::LIGHT_RED));
            ui.label(detail);
        });
}

fn display_or_not_recorded(value: &str) -> &str {
    if value.is_empty() {
        "Not recorded"
    } else {
        value
    }
}

fn availability_text(availability: ArtifactValueAvailability) -> &'static str {
    match availability {
        ArtifactValueAvailability::Recorded => "Recorded",
        ArtifactValueAvailability::NotRecorded => "Not recorded",
        ArtifactValueAvailability::RecordedNull => "Recorded as NULL",
        ArtifactValueAvailability::Invalid => "Invalid",
        ArtifactValueAvailability::WithheldOversized => "Unavailable — exceeds Inspector bound",
    }
}

fn metadata_state_text(state: ArtifactMetadataState) -> &'static str {
    match state {
        ArtifactMetadataState::Absent => "Not recorded",
        ArtifactMetadataState::Empty => "Recorded empty metadata object",
        ArtifactMetadataState::Parsed => "Parsed bounded projection",
        ArtifactMetadataState::Malformed => "Invalid / malformed",
        ArtifactMetadataState::Oversized => "Unavailable — exceeds Inspector bound",
    }
}

fn coordinate_namespace_label(namespace: &str) -> &str {
    match namespace {
        "logical_file_relative" => "File-relative coordinate",
        "filesystem_volume_relative" => "Filesystem volume-relative coordinate",
        "decoded_evidence_media" => "Decoded evidence-media coordinate",
        "registry_hive_file_relative" => "Registry hive file-relative coordinate",
        "registry_value_relative" => "Registry value-relative coordinate",
        "journal_stream_relative" => "Journal stream-relative coordinate",
        "database_file_relative" => "Database file-relative coordinate",
        "acquisition_container" => "Acquisition-container coordinate",
        "parser_recorded_legacy_physical" => {
            "Legacy parser-recorded coordinate (not asserted container-physical)"
        }
        _ => "Other explicitly recorded coordinate namespace",
    }
}

fn coverage_state_text(state: CoverageState) -> &'static str {
    match state {
        CoverageState::NotProcessed => "Not processed",
        CoverageState::InProgress => "In progress",
        CoverageState::Complete => "Complete",
        CoverageState::Partial => "Partial",
        CoverageState::Failed => "Failed",
        CoverageState::Unknown => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_values_are_never_rendered_as_zero() {
        assert_eq!(
            availability_text(ArtifactValueAvailability::NotRecorded),
            "Not recorded"
        );
        assert_eq!(
            availability_text(ArtifactValueAvailability::RecordedNull),
            "Recorded as NULL"
        );
        assert_eq!(display_or_not_recorded(""), "Not recorded");
    }

    #[test]
    fn decoded_and_container_coordinate_namespaces_remain_distinct() {
        assert_eq!(
            coordinate_namespace_label("decoded_evidence_media"),
            "Decoded evidence-media coordinate"
        );
        assert_eq!(
            coordinate_namespace_label("acquisition_container"),
            "Acquisition-container coordinate"
        );
        assert_ne!(
            coordinate_namespace_label("decoded_evidence_media"),
            coordinate_namespace_label("acquisition_container")
        );
        assert_eq!(
            coordinate_namespace_label("registry_value_relative"),
            "Registry value-relative coordinate"
        );
        assert_eq!(
            coordinate_namespace_label("journal_stream_relative"),
            "Journal stream-relative coordinate"
        );
        assert_eq!(
            coordinate_namespace_label("database_file_relative"),
            "Database file-relative coordinate"
        );
    }

    #[test]
    fn incomplete_coverage_labels_are_conservative() {
        assert_eq!(coverage_state_text(CoverageState::Partial), "Partial");
        assert_eq!(coverage_state_text(CoverageState::Unknown), "Unknown");
    }
}
