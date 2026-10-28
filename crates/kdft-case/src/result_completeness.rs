//! Shared disclosure contract for queries, parsers, exports, timelines, and reports.
//!
//! A successful API call is not proof that the requested forensic scope was
//! completely evaluated.  This module makes coverage a first-class value so
//! every consumer, including a desktop UI or local AI assistant, can preserve
//! omissions and truncation instead of silently presenting a page as a whole.

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub const RESULT_COMPLETENESS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultCompletenessStatus {
    Complete,
    Partial,
    Truncated,
    Failed,
    Skipped,
    Unknown,
}

impl ResultCompletenessStatus {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn requires_prominent_disclosure(self) -> bool {
        !self.is_complete()
    }
}

/// Counts are split into input and output units deliberately. A parser may
/// process one source file and emit thousands of records, so adding those
/// values together would create a false coverage claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultCounts {
    /// Stable singular noun such as `source`, `record`, `artifact`, or `byte`.
    pub input_unit: String,
    /// Exact input scope when known. `None` means unknown, never zero.
    pub input_total: Option<u64>,
    pub input_processed: u64,
    pub input_skipped: u64,
    pub input_failed: u64,
    /// Stable singular noun such as `row`, `artifact`, or `event`.
    pub output_unit: String,
    /// Matching outputs before paging, limits, or export failures, when known.
    pub output_matched: Option<u64>,
    pub output_emitted: u64,
    pub output_omitted: u64,
}

impl ResultCounts {
    pub const fn known_input_gap(&self) -> u64 {
        self.input_skipped.saturating_add(self.input_failed)
    }

    pub const fn known_output_gap(&self) -> u64 {
        self.output_omitted
    }

    pub const fn has_known_gap(&self) -> bool {
        self.known_input_gap() > 0 || self.known_output_gap() > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultOperation {
    Parser,
    Query,
    Search,
    Timeline,
    Export,
    Report,
    AiContext,
    Other,
}

/// Exact requested scope, independent of what the operation managed to emit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultScope {
    pub operation: ResultOperation,
    pub description: String,
    pub case_id: Option<i64>,
    #[serde(default)]
    pub evidence_ids: Vec<i64>,
    /// Mutation/index generation used to prevent mixed-generation paging.
    pub case_generation: Option<String>,
    /// Canonical typed query or parser selection. Secrets must be redacted
    /// before this object is persisted, exported, logged, or shown to AI.
    #[serde(default = "empty_json_object")]
    pub canonical_request: JsonValue,
    pub requested_limit: Option<u64>,
    pub projection_version: Option<String>,
    pub output_format: Option<String>,
}

fn empty_json_object() -> JsonValue {
    JsonValue::Object(Default::default())
}

/// Continuation is explicit even when unavailable. An absent cursor must never
/// be interpreted as proof that a truncated result is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResultContinuation {
    None,
    Cursor {
        opaque_token: String,
        snapshot_generation: String,
        remaining_estimate: Option<u64>,
    },
    Retry {
        checkpoint: Option<String>,
    },
    Restart,
    Unavailable,
}

impl ResultContinuation {
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub const fn can_continue(&self) -> bool {
        matches!(
            self,
            Self::Cursor { .. } | Self::Retry { .. } | Self::Restart
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessReasonKind {
    Limit,
    ParserFailure,
    Unsupported,
    Cancelled,
    SourceUnreadable,
    MissingDependency,
    Policy,
    NotRequested,
    LegacyUnknown,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletenessReason {
    pub kind: CompletenessReasonKind,
    /// Stable, machine-readable reason code.
    pub code: String,
    /// Concise examiner-facing explanation; never place credentials here.
    pub message: String,
    pub retryable: bool,
    pub affected_input_count: Option<u64>,
    pub affected_output_count: Option<u64>,
    #[serde(default = "empty_json_object")]
    pub details: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserJobReference {
    pub evidence_job_id: Option<i64>,
    pub parser_execution_id: Option<i64>,
    pub parser_name: String,
    pub parser_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultProducer {
    /// Component that made the completeness assessment.
    pub component: String,
    pub component_version: Option<String>,
    #[serde(default)]
    pub parser_jobs: Vec<ParserJobReference>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultCompleteness {
    pub schema_version: u32,
    pub status: ResultCompletenessStatus,
    pub counts: ResultCounts,
    pub scope: ResultScope,
    pub continuation: ResultContinuation,
    #[serde(default)]
    pub reasons: Vec<CompletenessReason>,
    pub producer: ResultProducer,
    /// RFC 3339 timestamp with a zero UTC offset (`Z` or `+00:00`).
    pub assessed_at_utc: String,
}

impl ResultCompleteness {
    pub fn new(
        status: ResultCompletenessStatus,
        counts: ResultCounts,
        scope: ResultScope,
        continuation: ResultContinuation,
        reasons: Vec<CompletenessReason>,
        producer: ResultProducer,
        assessed_at_utc: String,
    ) -> Result<Self, CompletenessValidationError> {
        let result = Self {
            schema_version: RESULT_COMPLETENESS_SCHEMA_VERSION,
            status,
            counts,
            scope,
            continuation,
            reasons,
            producer,
            assessed_at_utc,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), CompletenessValidationError> {
        let mut errors = Vec::new();

        if self.schema_version != RESULT_COMPLETENESS_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {RESULT_COMPLETENESS_SCHEMA_VERSION}"
            ));
        }
        if self.scope.description.trim().is_empty() {
            errors.push("scope.description must not be empty".to_string());
        }
        if !self.scope.canonical_request.is_object() {
            errors.push("scope.canonical_request must be a JSON object".to_string());
        }
        if self.counts.input_unit.trim().is_empty() || self.counts.output_unit.trim().is_empty() {
            errors.push("input_unit and output_unit must not be empty".to_string());
        }
        if self.producer.component.trim().is_empty() {
            errors.push("producer.component must not be empty".to_string());
        }
        match DateTime::parse_from_rfc3339(&self.assessed_at_utc) {
            Ok(timestamp) if timestamp.offset().local_minus_utc() == 0 => {}
            Ok(_) => errors.push("assessed_at_utc must have a zero UTC offset".to_string()),
            Err(_) => errors.push("assessed_at_utc must be an RFC 3339 timestamp".to_string()),
        }
        if self.scope.case_id.is_some_and(|id| id <= 0) {
            errors.push("scope.case_id must be positive when present".to_string());
        }
        if self.scope.evidence_ids.iter().any(|id| *id <= 0) {
            errors.push("scope.evidence_ids must contain only positive ids".to_string());
        }
        let unique_evidence: HashSet<_> = self.scope.evidence_ids.iter().copied().collect();
        if unique_evidence.len() != self.scope.evidence_ids.len() {
            errors.push("scope.evidence_ids must not contain duplicates".to_string());
        }
        if let Some(total) = self.counts.input_total {
            let accounted = self
                .counts
                .input_processed
                .saturating_add(self.counts.input_skipped)
                .saturating_add(self.counts.input_failed);
            if accounted > total {
                errors.push("processed + skipped + failed input exceeds input_total".to_string());
            }
        }
        if let Some(matched) = self.counts.output_matched {
            let accounted = self
                .counts
                .output_emitted
                .saturating_add(self.counts.output_omitted);
            if accounted > matched {
                errors.push("emitted + omitted output exceeds output_matched".to_string());
            }
        }
        if let ResultContinuation::Cursor {
            opaque_token,
            snapshot_generation,
            ..
        } = &self.continuation
        {
            if opaque_token.trim().is_empty() {
                errors.push("cursor continuation requires an opaque_token".to_string());
            }
            if snapshot_generation.trim().is_empty() {
                errors.push("cursor continuation requires a snapshot_generation".to_string());
            }
            if self.scope.case_generation.as_deref() != Some(snapshot_generation.as_str()) {
                errors.push(
                    "cursor snapshot_generation must equal scope.case_generation".to_string(),
                );
            }
        }
        for reason in &self.reasons {
            if reason.code.trim().is_empty() || reason.message.trim().is_empty() {
                errors.push("every reason requires a non-empty code and message".to_string());
                break;
            }
            if !reason.details.is_object() {
                errors.push("every reason.details value must be a JSON object".to_string());
                break;
            }
        }
        for job in &self.producer.parser_jobs {
            if job.parser_name.trim().is_empty() {
                errors.push("every parser job requires parser_name".to_string());
                break;
            }
            if job.evidence_job_id.is_some_and(|id| id <= 0)
                || job.parser_execution_id.is_some_and(|id| id <= 0)
            {
                errors.push("parser job identifiers must be positive when present".to_string());
                break;
            }
        }

        match self.status {
            ResultCompletenessStatus::Complete => {
                if self.counts.has_known_gap() {
                    errors.push(
                        "complete status cannot contain known skipped, failed, or omitted counts"
                            .to_string(),
                    );
                }
                if !self.continuation.is_none() {
                    errors.push("complete status cannot have continuation work".to_string());
                }
                if !self.reasons.is_empty() {
                    errors
                        .push("complete status cannot contain incompleteness reasons".to_string());
                }
                if let Some(total) = self.counts.input_total {
                    if self.counts.input_processed != total {
                        errors.push(
                            "complete status requires every known input to be processed"
                                .to_string(),
                        );
                    }
                }
                if let Some(matched) = self.counts.output_matched {
                    if self.counts.output_emitted != matched {
                        errors.push(
                            "complete status requires every matching output to be emitted"
                                .to_string(),
                        );
                    }
                }
            }
            ResultCompletenessStatus::Partial => {
                if self.reasons.is_empty() {
                    errors.push("partial status requires a reason".to_string());
                }
            }
            ResultCompletenessStatus::Truncated => {
                if self.reasons.is_empty() {
                    errors.push("truncated status requires a reason".to_string());
                }
            }
            ResultCompletenessStatus::Failed => {
                if self.counts.output_emitted != 0 {
                    errors.push(
                        "failed status cannot claim emitted output; use partial instead"
                            .to_string(),
                    );
                }
                if self.reasons.is_empty() {
                    errors.push("failed status requires a reason".to_string());
                }
            }
            ResultCompletenessStatus::Skipped => {
                if self.counts.input_processed != 0
                    || self.counts.input_failed != 0
                    || self.counts.output_emitted != 0
                {
                    errors.push(
                        "skipped status cannot claim processed, failed, or emitted work"
                            .to_string(),
                    );
                }
                if self.reasons.is_empty() {
                    errors.push("skipped status requires a reason".to_string());
                }
            }
            ResultCompletenessStatus::Unknown => {
                if self.reasons.is_empty() {
                    errors.push("unknown status requires a reason".to_string());
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(CompletenessValidationError { errors })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletenessValidationError {
    pub errors: Vec<String>,
}

impl Display for CompletenessValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid result completeness contract: {}",
            self.errors.join("; ")
        )
    }
}

impl Error for CompletenessValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope() -> ResultScope {
        ResultScope {
            operation: ResultOperation::Query,
            description: "browser visits matching example.com".to_string(),
            case_id: Some(1),
            evidence_ids: vec![7],
            case_generation: Some("generation-42".to_string()),
            canonical_request: json!({"host": "example.com"}),
            requested_limit: Some(200),
            projection_version: Some("browser_visit.v1".to_string()),
            output_format: Some("json".to_string()),
        }
    }

    fn producer() -> ResultProducer {
        ResultProducer {
            component: "kdft-case".to_string(),
            component_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            parser_jobs: vec![ParserJobReference {
                evidence_job_id: Some(9),
                parser_execution_id: Some(12),
                parser_name: "chromium_history".to_string(),
                parser_version: Some("1".to_string()),
            }],
        }
    }

    fn timestamp() -> String {
        "2026-10-16T01:02:03Z".to_string()
    }

    #[test]
    fn complete_contract_serializes_with_explicit_terminal_continuation() {
        let contract = ResultCompleteness::new(
            ResultCompletenessStatus::Complete,
            ResultCounts {
                input_unit: "artifact".to_string(),
                input_total: Some(3),
                input_processed: 3,
                input_skipped: 0,
                input_failed: 0,
                output_unit: "row".to_string(),
                output_matched: Some(2),
                output_emitted: 2,
                output_omitted: 0,
            },
            scope(),
            ResultContinuation::None,
            Vec::new(),
            producer(),
            timestamp(),
        )
        .unwrap();

        let json = serde_json::to_value(&contract).unwrap();
        assert_eq!(json["status"], "complete");
        assert_eq!(json["continuation"]["kind"], "none");
        assert_eq!(json["assessed_at_utc"], "2026-10-16T01:02:03Z");
    }

    #[test]
    fn truncated_page_requires_and_preserves_snapshot_cursor() {
        let contract = ResultCompleteness::new(
            ResultCompletenessStatus::Truncated,
            ResultCounts {
                input_unit: "artifact".to_string(),
                input_total: Some(725),
                input_processed: 725,
                input_skipped: 0,
                input_failed: 0,
                output_unit: "row".to_string(),
                output_matched: Some(725),
                output_emitted: 200,
                output_omitted: 525,
            },
            scope(),
            ResultContinuation::Cursor {
                opaque_token: "opaque-signed-cursor".to_string(),
                snapshot_generation: "generation-42".to_string(),
                remaining_estimate: Some(525),
            },
            vec![CompletenessReason {
                kind: CompletenessReasonKind::Limit,
                code: "query_page_limit".to_string(),
                message: "Only the first 200 of 725 matching rows are in this response."
                    .to_string(),
                retryable: true,
                affected_input_count: None,
                affected_output_count: Some(525),
                details: json!({"limit": 200}),
            }],
            producer(),
            timestamp(),
        )
        .unwrap();

        assert!(contract.status.requires_prominent_disclosure());
        assert!(contract.continuation.can_continue());
    }

    #[test]
    fn complete_rejects_silent_omission() {
        let error = ResultCompleteness::new(
            ResultCompletenessStatus::Complete,
            ResultCounts {
                input_unit: "source".to_string(),
                input_total: Some(2),
                input_processed: 1,
                input_skipped: 1,
                input_failed: 0,
                output_unit: "artifact".to_string(),
                output_matched: Some(1),
                output_emitted: 1,
                output_omitted: 0,
            },
            scope(),
            ResultContinuation::None,
            Vec::new(),
            producer(),
            timestamp(),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("complete status cannot contain known"));
        assert!(error.to_string().contains("every known input"));
    }

    #[test]
    fn cursor_cannot_cross_case_generation() {
        let error = ResultCompleteness::new(
            ResultCompletenessStatus::Truncated,
            ResultCounts {
                input_unit: "artifact".to_string(),
                input_total: None,
                input_processed: 20,
                input_skipped: 0,
                input_failed: 0,
                output_unit: "row".to_string(),
                output_matched: None,
                output_emitted: 20,
                output_omitted: 0,
            },
            scope(),
            ResultContinuation::Cursor {
                opaque_token: "cursor".to_string(),
                snapshot_generation: "different-generation".to_string(),
                remaining_estimate: None,
            },
            Vec::new(),
            producer(),
            timestamp(),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("must equal scope.case_generation"));
    }

    #[test]
    fn failed_output_cannot_be_disguised_as_success() {
        let error = ResultCompleteness::new(
            ResultCompletenessStatus::Failed,
            ResultCounts {
                input_unit: "source".to_string(),
                input_total: Some(1),
                input_processed: 0,
                input_skipped: 0,
                input_failed: 1,
                output_unit: "artifact".to_string(),
                output_matched: None,
                output_emitted: 1,
                output_omitted: 0,
            },
            scope(),
            ResultContinuation::Retry { checkpoint: None },
            vec![CompletenessReason {
                kind: CompletenessReasonKind::ParserFailure,
                code: "parser_failed".to_string(),
                message: "The parser stopped before producing a trustworthy result.".to_string(),
                retryable: true,
                affected_input_count: Some(1),
                affected_output_count: None,
                details: json!({}),
            }],
            producer(),
            timestamp(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("use partial instead"));
    }

    #[test]
    fn non_complete_status_cannot_omit_its_reason() {
        let error = ResultCompleteness::new(
            ResultCompletenessStatus::Partial,
            ResultCounts {
                input_unit: "source".to_string(),
                input_total: Some(2),
                input_processed: 1,
                input_skipped: 1,
                input_failed: 0,
                output_unit: "artifact".to_string(),
                output_matched: Some(4),
                output_emitted: 4,
                output_omitted: 0,
            },
            scope(),
            ResultContinuation::Unavailable,
            Vec::new(),
            producer(),
            timestamp(),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("partial status requires a reason"));
    }

    #[test]
    fn assessment_timestamp_must_be_rfc3339_utc() {
        let error = ResultCompleteness::new(
            ResultCompletenessStatus::Unknown,
            ResultCounts {
                input_unit: "legacy_entry".to_string(),
                input_total: None,
                input_processed: 0,
                input_skipped: 0,
                input_failed: 0,
                output_unit: "artifact".to_string(),
                output_matched: None,
                output_emitted: 0,
                output_omitted: 0,
            },
            scope(),
            ResultContinuation::Unavailable,
            vec![CompletenessReason {
                kind: CompletenessReasonKind::LegacyUnknown,
                code: "legacy_case".to_string(),
                message: "The legacy case has no recorded coverage manifest.".to_string(),
                retryable: false,
                affected_input_count: None,
                affected_output_count: None,
                details: json!({}),
            }],
            producer(),
            "2026-10-16T04:02:03+03:00".to_string(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("zero UTC offset"));
    }
}
