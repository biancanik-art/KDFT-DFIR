use crate::{BrokerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_RETRIEVAL_ROWS: u32 = 200;
pub const MAX_RETRIEVAL_ROWS: u32 = 200;
pub const DEFAULT_CONTEXT_BYTES: u32 = 64 * 1_024;
pub const MAX_CONTEXT_BYTES: u32 = 64 * 1_024;
pub const MAX_ITEM_BYTES: u32 = 32 * 1_024;
const MAX_FILTER_VALUES: usize = 64;
const MAX_FILTER_TEXT_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RetrievalLimits {
    pub max_rows: u32,
    pub max_context_bytes: u32,
    pub max_item_bytes: u32,
}

impl Default for RetrievalLimits {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_RETRIEVAL_ROWS,
            max_context_bytes: DEFAULT_CONTEXT_BYTES,
            max_item_bytes: MAX_ITEM_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSearchFilter {
    #[serde(default)]
    pub artifact_ids: Vec<i64>,
    #[serde(default)]
    pub evidence_ids: Vec<i64>,
    #[serde(default)]
    pub artifact_kinds: Vec<String>,
    #[serde(default)]
    pub text_terms: Vec<String>,
    #[serde(default)]
    pub time_from_utc: Option<String>,
    #[serde(default)]
    pub time_to_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundedRetrievalRequest {
    pub request_id: String,
    pub case_generation: i64,
    pub scope_description: String,
    pub filter: ArtifactSearchFilter,
    #[serde(default)]
    pub cursor: Option<RetrievalCursor>,
    #[serde(default)]
    pub limits: RetrievalLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetrievalCursor {
    pub after_artifact_id: i64,
    pub case_generation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContextRecord {
    pub context_handle: String,
    pub artifact_id: i64,
    pub evidence_id: i64,
    pub artifact_kind: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub artifact_time_utc: Option<String>,
    /// Compact, redacted projection selected by KDFT. Evidence text remains
    /// untrusted data even after redaction.
    pub redacted_text: String,
    pub redaction_applied: bool,
    pub redaction_ruleset_sha256: String,
    #[serde(default)]
    pub typed_fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    RowLimit,
    ByteLimit,
    TokenLimit,
    TimeLimit,
    Cancelled,
    ParserIncomplete,
    UnsupportedSource,
    DiagnosticOmission,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetrievalCoverage {
    pub scope_description: String,
    pub query_complete: bool,
    pub eligible_artifacts: Option<u64>,
    pub retrieved_artifacts: u32,
    pub omitted_artifacts: Option<u64>,
    pub truncated: bool,
    pub truncation_reasons: Vec<TruncationReason>,
    #[serde(default)]
    pub sampling_method: Option<String>,
    pub parser_jobs_total: u32,
    pub parser_jobs_incomplete: Vec<i64>,
    pub case_generation_frozen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundedRetrievalResponse {
    pub request_id: String,
    pub case_generation: i64,
    pub filter_applied: ArtifactSearchFilter,
    #[serde(default)]
    pub request_cursor: Option<RetrievalCursor>,
    pub records: Vec<ArtifactContextRecord>,
    #[serde(default)]
    pub next_cursor: Option<RetrievalCursor>,
    pub encoded_context_bytes: u32,
    pub limits_applied: RetrievalLimits,
    pub coverage: RetrievalCoverage,
}

impl BoundedRetrievalRequest {
    pub fn validate(&self) -> Result<()> {
        bounded_nonempty("request_id", &self.request_id, 128)?;
        if self.case_generation < 0 {
            return Err(retrieval_error("case_generation cannot be negative"));
        }
        bounded_nonempty("scope_description", &self.scope_description, 4_000)?;
        self.limits.validate()?;
        self.filter.validate()?;
        if let Some(cursor) = self.cursor.as_ref() {
            if cursor.after_artifact_id < 0 {
                return Err(retrieval_error(
                    "cursor after_artifact_id cannot be negative",
                ));
            }
            if cursor.case_generation != self.case_generation {
                return Err(retrieval_error(
                    "cursor generation does not match the frozen case generation",
                ));
            }
        }
        Ok(())
    }
}

impl RetrievalLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_rows == 0 || self.max_rows > MAX_RETRIEVAL_ROWS {
            return Err(retrieval_error(format!(
                "max_rows must be 1..={MAX_RETRIEVAL_ROWS}"
            )));
        }
        if self.max_context_bytes == 0 || self.max_context_bytes > MAX_CONTEXT_BYTES {
            return Err(retrieval_error(format!(
                "max_context_bytes must be 1..={MAX_CONTEXT_BYTES}"
            )));
        }
        if self.max_item_bytes == 0
            || self.max_item_bytes > MAX_ITEM_BYTES
            || self.max_item_bytes > self.max_context_bytes
        {
            return Err(retrieval_error(format!(
                "max_item_bytes must be 1..={MAX_ITEM_BYTES} and no larger than max_context_bytes"
            )));
        }
        Ok(())
    }
}

impl ArtifactSearchFilter {
    fn validate(&self) -> Result<()> {
        for (label, values) in [
            ("artifact_ids", self.artifact_ids.len()),
            ("evidence_ids", self.evidence_ids.len()),
            ("artifact_kinds", self.artifact_kinds.len()),
            ("text_terms", self.text_terms.len()),
        ] {
            if values > MAX_FILTER_VALUES {
                return Err(retrieval_error(format!(
                    "{label} exceeds {MAX_FILTER_VALUES} values"
                )));
            }
        }
        if self
            .artifact_ids
            .iter()
            .chain(self.evidence_ids.iter())
            .any(|id| *id <= 0)
        {
            return Err(retrieval_error(
                "artifact and evidence ids must be positive",
            ));
        }
        if self.artifact_ids.iter().collect::<BTreeSet<_>>().len() != self.artifact_ids.len()
            || self.evidence_ids.iter().collect::<BTreeSet<_>>().len() != self.evidence_ids.len()
            || self.artifact_kinds.iter().collect::<BTreeSet<_>>().len()
                != self.artifact_kinds.len()
            || self.text_terms.iter().collect::<BTreeSet<_>>().len() != self.text_terms.len()
        {
            return Err(retrieval_error("filter values must be unique"));
        }
        for value in self.artifact_kinds.iter().chain(self.text_terms.iter()) {
            if value.is_empty() || value.len() > MAX_FILTER_TEXT_BYTES || value.contains('\0') {
                return Err(retrieval_error(
                    "filter text must contain 1..=1024 bytes and no NUL",
                ));
            }
        }
        if self
            .artifact_kinds
            .iter()
            .any(|value| !valid_artifact_kind(value))
        {
            return Err(retrieval_error(
                "artifact kinds must use canonical lowercase identifier characters",
            ));
        }
        for value in [self.time_from_utc.as_deref(), self.time_to_utc.as_deref()]
            .into_iter()
            .flatten()
        {
            if value.len() > 64 || chrono::DateTime::parse_from_rfc3339(value).is_err() {
                return Err(retrieval_error(
                    "timeline bounds must be bounded RFC 3339 timestamps",
                ));
            }
        }
        if let (Some(from), Some(to)) = (&self.time_from_utc, &self.time_to_utc) {
            let from = chrono::DateTime::parse_from_rfc3339(from)
                .map_err(|_| retrieval_error("invalid time_from_utc"))?;
            let to = chrono::DateTime::parse_from_rfc3339(to)
                .map_err(|_| retrieval_error("invalid time_to_utc"))?;
            if from > to {
                return Err(retrieval_error(
                    "time_from_utc must not be later than time_to_utc",
                ));
            }
        }
        Ok(())
    }
}

impl BoundedRetrievalResponse {
    pub fn build(
        request: &BoundedRetrievalRequest,
        records: Vec<ArtifactContextRecord>,
        next_cursor: Option<RetrievalCursor>,
        coverage: RetrievalCoverage,
    ) -> Result<Self> {
        request.validate()?;
        if records.len() > request.limits.max_rows as usize {
            return Err(retrieval_error("retrieval returned more than max_rows"));
        }
        let mut handles = BTreeSet::new();
        let mut artifact_ids = BTreeSet::new();
        let mut previous_artifact_id = request
            .cursor
            .as_ref()
            .map_or(0, |cursor| cursor.after_artifact_id);
        for record in &records {
            record.validate(request.case_generation)?;
            record.validate_scope(&request.filter)?;
            if !handles.insert(record.context_handle.as_str()) {
                return Err(retrieval_error(
                    "retrieval returned a duplicate context handle",
                ));
            }
            if !artifact_ids.insert(record.artifact_id) {
                return Err(retrieval_error(
                    "retrieval returned a duplicate artifact id",
                ));
            }
            if record.artifact_id <= previous_artifact_id {
                return Err(retrieval_error(
                    "artifacts must be in strictly increasing artifact-id cursor order",
                ));
            }
            previous_artifact_id = record.artifact_id;
            let bytes = serde_json::to_vec(record)
                .map_err(|source| BrokerError::Json {
                    operation: "measuring bounded artifact context",
                    source,
                })?
                .len();
            if bytes > request.limits.max_item_bytes as usize {
                return Err(retrieval_error(format!(
                    "artifact {} exceeds the per-item byte limit",
                    record.artifact_id
                )));
            }
        }
        let encoded_context_bytes = serde_json::to_vec(&records)
            .map_err(|source| BrokerError::Json {
                operation: "measuring bounded retrieval context",
                source,
            })?
            .len();
        if encoded_context_bytes > request.limits.max_context_bytes as usize {
            return Err(retrieval_error(
                "retrieval context exceeds max_context_bytes",
            ));
        }
        coverage.validate(records.len(), request)?;
        if let Some(cursor) = next_cursor.as_ref() {
            if cursor.case_generation != request.case_generation
                || records.is_empty()
                || cursor.after_artifact_id != previous_artifact_id
                || !coverage.truncated
            {
                return Err(retrieval_error(
                    "next cursor must continue a truncated result from its last artifact",
                ));
            }
        }
        Ok(Self {
            request_id: request.request_id.clone(),
            case_generation: request.case_generation,
            filter_applied: request.filter.clone(),
            request_cursor: request.cursor.clone(),
            records,
            next_cursor,
            encoded_context_bytes: encoded_context_bytes as u32,
            limits_applied: request.limits,
            coverage,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let request = BoundedRetrievalRequest {
            request_id: self.request_id.clone(),
            case_generation: self.case_generation,
            scope_description: self.coverage.scope_description.clone(),
            filter: self.filter_applied.clone(),
            cursor: self.request_cursor.clone(),
            limits: self.limits_applied,
        };
        let rebuilt = Self::build(
            &request,
            self.records.clone(),
            self.next_cursor.clone(),
            self.coverage.clone(),
        )?;
        if rebuilt.encoded_context_bytes != self.encoded_context_bytes {
            return Err(retrieval_error(
                "encoded_context_bytes does not match the bounded record payload",
            ));
        }
        Ok(())
    }
}

impl ArtifactContextRecord {
    fn validate(&self, _case_generation: i64) -> Result<()> {
        if !valid_handle(&self.context_handle)
            || self.artifact_id <= 0
            || self.evidence_id <= 0
            || self.artifact_kind.is_empty()
            || self.artifact_kind.len() > 256
            || !valid_artifact_kind(&self.artifact_kind)
            || self
                .display_name
                .as_ref()
                .is_some_and(|value| value.len() > 4_096 || value.contains('\0'))
            || self.redacted_text.len() > MAX_ITEM_BYTES as usize
            || self.redacted_text.contains('\0')
            || !self.redaction_applied
            || !crate::is_sha256(&self.redaction_ruleset_sha256)
        {
            return Err(retrieval_error(format!(
                "artifact context record {} failed bounds or redaction validation",
                self.artifact_id
            )));
        }
        if self.typed_fields.len() > 128
            || self.typed_fields.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 256
                    || key.contains('\0')
                    || value.len() > 4_096
                    || value.contains('\0')
            })
        {
            return Err(retrieval_error(
                "typed artifact fields exceed bounded key/value limits",
            ));
        }
        Ok(())
    }

    fn validate_scope(&self, filter: &ArtifactSearchFilter) -> Result<()> {
        if (!filter.artifact_ids.is_empty() && !filter.artifact_ids.contains(&self.artifact_id))
            || (!filter.evidence_ids.is_empty() && !filter.evidence_ids.contains(&self.evidence_id))
            || (!filter.artifact_kinds.is_empty()
                && !filter.artifact_kinds.contains(&self.artifact_kind))
        {
            return Err(retrieval_error(format!(
                "artifact {} is outside the frozen typed request scope",
                self.artifact_id
            )));
        }

        if filter.time_from_utc.is_some() || filter.time_to_utc.is_some() {
            let artifact_time = self
                .artifact_time_utc
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .ok_or_else(|| {
                    retrieval_error("time-filtered records require an RFC 3339 artifact time")
                })?;
            if filter.time_from_utc.as_deref().is_some_and(|value| {
                chrono::DateTime::parse_from_rfc3339(value).is_ok_and(|from| artifact_time < from)
            }) || filter.time_to_utc.as_deref().is_some_and(|value| {
                chrono::DateTime::parse_from_rfc3339(value).is_ok_and(|to| artifact_time > to)
            }) {
                return Err(retrieval_error(format!(
                    "artifact {} is outside the frozen time scope",
                    self.artifact_id
                )));
            }
        } else if self.artifact_time_utc.as_deref().is_some_and(|value| {
            value.len() > 64 || chrono::DateTime::parse_from_rfc3339(value).is_err()
        }) {
            return Err(retrieval_error("artifact_time_utc must be RFC 3339"));
        }
        Ok(())
    }
}

impl RetrievalCoverage {
    fn validate(&self, actual_records: usize, request: &BoundedRetrievalRequest) -> Result<()> {
        bounded_nonempty("coverage scope_description", &self.scope_description, 4_000)?;
        if self.scope_description != request.scope_description
            || !self.case_generation_frozen
            || self.retrieved_artifacts as usize != actual_records
            || self.parser_jobs_incomplete.iter().any(|id| *id <= 0)
        {
            return Err(retrieval_error(
                "coverage does not reconcile with the frozen request and records",
            ));
        }
        if self.truncated != !self.truncation_reasons.is_empty() {
            return Err(retrieval_error(
                "truncated and truncation_reasons must agree",
            ));
        }
        let unique_reasons = self.truncation_reasons.iter().collect::<BTreeSet<_>>();
        if unique_reasons.len() != self.truncation_reasons.len() {
            return Err(retrieval_error("truncation reasons must be unique"));
        }
        let unique_jobs = self.parser_jobs_incomplete.iter().collect::<BTreeSet<_>>();
        if unique_jobs.len() != self.parser_jobs_incomplete.len()
            || self.parser_jobs_incomplete.len() > self.parser_jobs_total as usize
        {
            return Err(retrieval_error(
                "incomplete parser jobs must be unique and no greater than parser_jobs_total",
            ));
        }
        if self.omitted_artifacts.is_some_and(|count| count > 0) && !self.truncated {
            return Err(retrieval_error(
                "omitted artifacts require an explicit truncated result",
            ));
        }
        if let (Some(eligible), Some(omitted)) = (self.eligible_artifacts, self.omitted_artifacts) {
            if eligible != u64::from(self.retrieved_artifacts) + omitted {
                return Err(retrieval_error(
                    "eligible, retrieved, and omitted counts do not reconcile",
                ));
            }
        }
        if self.query_complete
            && (self.eligible_artifacts.is_none() || self.omitted_artifacts.is_none())
        {
            return Err(retrieval_error(
                "a complete query requires exact eligible and omitted counts",
            ));
        }
        if self.truncated
            && self
                .sampling_method
                .as_deref()
                .is_none_or(|method| method.is_empty())
        {
            return Err(retrieval_error(
                "truncated retrieval requires a declared deterministic sampling or paging method",
            ));
        }
        if self
            .sampling_method
            .as_ref()
            .is_some_and(|value| value.len() > 2_000)
        {
            return Err(retrieval_error("sampling_method exceeds 2000 bytes"));
        }
        Ok(())
    }
}

fn valid_handle(value: &str) -> bool {
    value
        .strip_prefix("ctx-")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.len() <= 124)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_artifact_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn bounded_nonempty(field: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(retrieval_error(format!(
            "{field} must contain 1..={maximum} bytes and no NUL"
        )));
    }
    Ok(())
}

fn retrieval_error(message: impl Into<String>) -> BrokerError {
    BrokerError::Retrieval(message.into())
}
