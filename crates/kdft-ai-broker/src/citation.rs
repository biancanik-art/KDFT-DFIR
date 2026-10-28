use crate::retrieval::{BoundedRetrievalResponse, RetrievalCoverage, TruncationReason};
use crate::{is_sha256, BrokerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoordinateSystem {
    PhysicalMediaBytes,
    PartitionLogicalBytes,
    DecryptedBitlockerVolumeLogicalBytes,
    FilesystemFileBytes,
    FilesystemRecord,
    RegistryHiveBytes,
    EvtxFileBytes,
    SqliteDatabaseBytes,
    SqliteRow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceCoordinate {
    pub role: String,
    #[serde(default)]
    pub source_entry_id: Option<i64>,
    #[serde(default)]
    pub source_path: Option<String>,
    pub coordinate_system: CoordinateSystem,
    #[serde(default)]
    pub partition_index: Option<u32>,
    #[serde(default)]
    pub volume_index: Option<u32>,
    #[serde(default)]
    pub partition_start_offset_bytes: Option<u64>,
    #[serde(default)]
    pub offset_bytes: Option<u64>,
    #[serde(default)]
    pub length_bytes: Option<u64>,
    #[serde(default)]
    pub record_identifier: Option<String>,
    #[serde(default)]
    pub source_sha256: Option<String>,
    pub physical_offset_available: bool,
    #[serde(default)]
    pub coordinate_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParserProvenance {
    pub execution_id: i64,
    pub name: String,
    pub version: String,
    pub schema_version: String,
    #[serde(default)]
    pub implementation_sha256: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCitation {
    pub case_generation: i64,
    pub artifact_id: i64,
    pub evidence_id: i64,
    pub artifact_kind: String,
    #[serde(default)]
    pub record_key: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub artifact_time_utc: Option<String>,
    pub parser: ParserProvenance,
    pub sources: Vec<SourceCoordinate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    ObservedFact,
    DerivedFact,
    ModelInference,
    Hypothesis,
    Limitation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Workflow {
    SelectedArtifacts,
    ArtifactQuery,
    Timeline,
    ArtifactExplanation,
    FindingDraft,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelClaim {
    pub claim_id: String,
    pub kind: ClaimKind,
    pub text: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub model_confidence: Option<ModelConfidence>,
    #[serde(default)]
    pub citation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelCitationReference {
    pub citation_id: String,
    pub context_handle: String,
}

/// The only model-authored response accepted by the broker. It has no fields
/// for artifact ids, paths, offsets, parser identity, SQL, tools, or files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelDraft {
    pub schema_version: String,
    pub request_id: String,
    pub case_generation: i64,
    #[serde(default)]
    pub headline: Option<String>,
    pub claims: Vec<ModelClaim>,
    pub citation_references: Vec<ModelCitationReference>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default)]
    pub suggested_next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExaminerNextStep {
    pub description: String,
    pub requires_examiner_action: bool,
    #[serde(default)]
    pub proposed_scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationProvenance {
    pub local: bool,
    pub offline_enforced: bool,
    pub runtime_name: String,
    pub runtime_version: String,
    pub runtime_executable_sha256: String,
    pub model_id: String,
    pub model_sha256: String,
    pub model_manifest_sha256: String,
    pub prompt_template_sha256: String,
    pub response_schema_version: String,
    #[serde(default)]
    pub seed: Option<i64>,
    pub temperature_millis: u16,
    pub context_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCitation {
    pub citation_id: String,
    pub context_handle: String,
    pub resolution_status: String,
    pub artifact_id: i64,
    pub evidence_id: i64,
    pub artifact_kind: String,
    pub record_key: Option<String>,
    pub display_name: Option<String>,
    pub artifact_time_utc: Option<String>,
    pub parser: ParserProvenance,
    pub sources: Vec<SourceCoordinate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnswerStatus {
    Answered,
    Partial,
    InsufficientEvidence,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroundedAnswer {
    pub schema_version: String,
    pub request_id: String,
    pub case_generation: i64,
    pub workflow: Workflow,
    pub status: AnswerStatus,
    pub headline: Option<String>,
    pub claims: Vec<ModelClaim>,
    pub resolved_citations: Vec<ResolvedCitation>,
    pub coverage: RetrievalCoverage,
    pub limitations: Vec<String>,
    pub suggested_next_steps: Vec<ExaminerNextStep>,
    pub generation: GenerationProvenance,
}

/// Broker-owned mapping from opaque prompt handles to canonical provenance.
/// Only this mapping can populate `ResolvedCitation` fields.
#[derive(Debug)]
pub struct CitationBroker {
    request_id: String,
    case_generation: i64,
    workflow: Workflow,
    allowed_artifact_ids: BTreeSet<i64>,
    citations: BTreeMap<String, CanonicalCitation>,
    next_handle: u64,
}

impl CitationBroker {
    pub fn new(
        request_id: impl Into<String>,
        case_generation: i64,
        workflow: Workflow,
        allowed_artifact_ids: impl IntoIterator<Item = i64>,
    ) -> Result<Self> {
        let request_id = request_id.into();
        if request_id.is_empty()
            || request_id.len() > 128
            || request_id.contains('\0')
            || case_generation < 0
        {
            return Err(citation_error(
                "request id or frozen case generation is invalid",
            ));
        }
        let allowed_artifact_ids = allowed_artifact_ids.into_iter().collect::<BTreeSet<_>>();
        if allowed_artifact_ids.iter().any(|id| *id <= 0) {
            return Err(citation_error("allowed artifact ids must be positive"));
        }
        Ok(Self {
            request_id,
            case_generation,
            workflow,
            allowed_artifact_ids,
            citations: BTreeMap::new(),
            next_handle: 1,
        })
    }

    pub fn register(&mut self, citation: CanonicalCitation) -> Result<String> {
        citation.validate()?;
        if citation.case_generation != self.case_generation {
            return Err(citation_error(
                "citation case generation is outside the frozen request",
            ));
        }
        if !self.allowed_artifact_ids.contains(&citation.artifact_id) {
            return Err(citation_error(format!(
                "artifact {} is outside the frozen request scope",
                citation.artifact_id
            )));
        }
        if self
            .citations
            .values()
            .any(|existing| existing.artifact_id == citation.artifact_id)
        {
            return Err(citation_error(format!(
                "artifact {} was registered twice",
                citation.artifact_id
            )));
        }
        let handle = format!("ctx-{:06}", self.next_handle);
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or_else(|| citation_error("context-handle sequence overflowed"))?;
        self.citations.insert(handle.clone(), citation);
        Ok(handle)
    }

    pub fn finalize(
        &self,
        draft: ModelDraft,
        retrieval: &BoundedRetrievalResponse,
        generation: GenerationProvenance,
    ) -> Result<GroundedAnswer> {
        retrieval.validate()?;
        if draft.request_id != self.request_id || draft.case_generation != self.case_generation {
            return Err(citation_error(
                "model draft does not match the frozen request",
            ));
        }
        generation.validate()?;
        validate_draft(&draft)?;
        if retrieval.request_id != self.request_id
            || retrieval.case_generation != self.case_generation
        {
            return Err(citation_error(
                "retrieval response does not match the frozen request",
            ));
        }
        let retrieval_handles = retrieval
            .records
            .iter()
            .map(|record| (record.context_handle.as_str(), record))
            .collect::<BTreeMap<_, _>>();

        let mut references = BTreeMap::new();
        for reference in &draft.citation_references {
            if !valid_citation_id(&reference.citation_id) {
                return Err(citation_error("invalid citation id"));
            }
            let Some(canonical) = self.citations.get(&reference.context_handle) else {
                return Err(citation_error(format!(
                    "unknown or out-of-scope context handle {:?}",
                    reference.context_handle
                )));
            };
            let Some(context_record) = retrieval_handles.get(reference.context_handle.as_str())
            else {
                return Err(citation_error(format!(
                    "context handle {:?} was not present in the bounded prompt",
                    reference.context_handle
                )));
            };
            if context_record.artifact_id != canonical.artifact_id
                || context_record.evidence_id != canonical.evidence_id
                || context_record.artifact_kind != canonical.artifact_kind
            {
                return Err(citation_error(format!(
                    "context handle {:?} does not match canonical artifact identity",
                    reference.context_handle
                )));
            }
            if references
                .insert(&reference.citation_id, &reference.context_handle)
                .is_some()
            {
                return Err(citation_error("citation ids must be unique"));
            }
        }

        let mut used_citation_ids = BTreeSet::new();
        for claim in &draft.claims {
            for citation_id in &claim.citation_ids {
                if !references.contains_key(citation_id) {
                    return Err(citation_error(format!(
                        "claim references unresolved citation id {citation_id:?}"
                    )));
                }
                used_citation_ids.insert(citation_id.as_str());
            }
        }
        if references
            .keys()
            .any(|citation_id| !used_citation_ids.contains(citation_id.as_str()))
        {
            return Err(citation_error("model supplied unused citation references"));
        }

        let mut resolved_citations = Vec::with_capacity(references.len());
        for reference in &draft.citation_references {
            let canonical = self
                .citations
                .get(&reference.context_handle)
                .ok_or_else(|| citation_error("context handle disappeared during resolution"))?;
            resolved_citations.push(ResolvedCitation {
                citation_id: reference.citation_id.clone(),
                context_handle: reference.context_handle.clone(),
                resolution_status: "verified".to_string(),
                artifact_id: canonical.artifact_id,
                evidence_id: canonical.evidence_id,
                artifact_kind: canonical.artifact_kind.clone(),
                record_key: canonical.record_key.clone(),
                display_name: canonical.display_name.clone(),
                artifact_time_utc: canonical.artifact_time_utc.clone(),
                parser: canonical.parser.clone(),
                sources: canonical.sources.clone(),
            });
        }

        let coverage = retrieval.coverage.clone();
        let coverage_complete = coverage.query_complete
            && !coverage.truncated
            && coverage.parser_jobs_incomplete.is_empty()
            && coverage.omitted_artifacts == Some(0)
            && coverage.eligible_artifacts == Some(u64::from(coverage.retrieved_artifacts));
        let mut limitations = draft.limitations;
        if !coverage.query_complete {
            limitations.push("The artifact query did not complete over the declared scope.".into());
        }
        if coverage.truncated {
            limitations.push(format!(
                "The context was truncated: {}.",
                truncation_labels(&coverage.truncation_reasons).join(", ")
            ));
        }
        if !coverage.parser_jobs_incomplete.is_empty() {
            limitations.push(format!(
                "Incomplete parser jobs affect coverage: {:?}.",
                coverage.parser_jobs_incomplete
            ));
        }
        if limitations.is_empty() {
            limitations.push(
                "No retrieval limitations were recorded for the declared scope; model output still requires examiner validation."
                    .to_string(),
            );
        }

        let status = if !draft
            .claims
            .iter()
            .any(|claim| claim.kind != ClaimKind::Limitation)
        {
            AnswerStatus::InsufficientEvidence
        } else if coverage_complete {
            AnswerStatus::Answered
        } else {
            AnswerStatus::Partial
        };
        Ok(GroundedAnswer {
            schema_version: "1.0.0".to_string(),
            request_id: draft.request_id,
            case_generation: draft.case_generation,
            workflow: self.workflow,
            status,
            headline: draft.headline,
            claims: draft.claims,
            resolved_citations,
            coverage,
            limitations,
            suggested_next_steps: draft
                .suggested_next_steps
                .into_iter()
                .map(|description| ExaminerNextStep {
                    description,
                    requires_examiner_action: true,
                    proposed_scope: None,
                })
                .collect(),
            generation,
        })
    }
}

impl CanonicalCitation {
    fn validate(&self) -> Result<()> {
        if self.case_generation < 0
            || self.artifact_id <= 0
            || self.evidence_id <= 0
            || self.artifact_kind.is_empty()
            || self.artifact_kind.len() > 256
            || !self.artifact_kind.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-' | b'.')
            })
            || self.sources.is_empty()
            || self.sources.len() > 100
            || self
                .record_key
                .as_ref()
                .is_some_and(|value| value.len() > 2_048 || value.contains('\0'))
            || self
                .display_name
                .as_ref()
                .is_some_and(|value| value.len() > 4_096 || value.contains('\0'))
            || self.artifact_time_utc.as_deref().is_some_and(|value| {
                value.len() > 64
                    || chrono::DateTime::parse_from_rfc3339(value)
                        .map_or(true, |time| time.offset().local_minus_utc() != 0)
            })
        {
            return Err(citation_error("canonical citation bounds are invalid"));
        }
        self.parser.validate()?;
        for source in &self.sources {
            source.validate()?;
        }
        Ok(())
    }
}

impl ParserProvenance {
    fn validate(&self) -> Result<()> {
        if self.execution_id <= 0
            || self.name.is_empty()
            || self.name.len() > 256
            || self.version.is_empty()
            || self.version.len() > 256
            || self.schema_version.is_empty()
            || self.schema_version.len() > 256
            || self.name.contains('\0')
            || self.version.contains('\0')
            || self.schema_version.contains('\0')
            || !matches!(
                self.status.as_str(),
                "running" | "completed" | "completed_with_diagnostics" | "failed" | "cancelled"
            )
            || self
                .implementation_sha256
                .as_deref()
                .is_some_and(|hash| !is_sha256(hash))
        {
            return Err(citation_error("parser provenance is invalid"));
        }
        Ok(())
    }
}

impl SourceCoordinate {
    fn validate(&self) -> Result<()> {
        if self.role.is_empty()
            || self.role.len() > 128
            || self.role.contains('\0')
            || self.source_entry_id.is_some_and(|id| id <= 0)
            || self
                .source_path
                .as_ref()
                .is_some_and(|path| path.is_empty() || path.len() > 16_384 || path.contains('\0'))
            || self.record_identifier.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 4_096 || value.contains('\0')
            })
            || self
                .source_sha256
                .as_deref()
                .is_some_and(|hash| !is_sha256(hash))
            || self
                .coordinate_note
                .as_ref()
                .is_some_and(|note| note.is_empty() || note.len() > 4_000 || note.contains('\0'))
            || (self.source_entry_id.is_none() && self.source_path.is_none())
        {
            return Err(citation_error("source coordinate is invalid"));
        }
        let byte_coordinate = matches!(
            self.coordinate_system,
            CoordinateSystem::PhysicalMediaBytes
                | CoordinateSystem::PartitionLogicalBytes
                | CoordinateSystem::DecryptedBitlockerVolumeLogicalBytes
                | CoordinateSystem::FilesystemFileBytes
                | CoordinateSystem::RegistryHiveBytes
                | CoordinateSystem::EvtxFileBytes
                | CoordinateSystem::SqliteDatabaseBytes
        );
        if byte_coordinate && (self.offset_bytes.is_none() || self.length_bytes.is_none()) {
            return Err(citation_error(
                "byte-based source coordinates require explicit offset and length",
            ));
        }
        if matches!(
            self.coordinate_system,
            CoordinateSystem::FilesystemRecord | CoordinateSystem::SqliteRow
        ) && self.record_identifier.is_none()
        {
            return Err(citation_error(
                "record-based source coordinates require a record identifier",
            ));
        }
        match self.coordinate_system {
            CoordinateSystem::PhysicalMediaBytes if !self.physical_offset_available => {
                return Err(citation_error(
                    "physical-media coordinates must mark the physical offset available",
                ));
            }
            CoordinateSystem::PartitionLogicalBytes if self.partition_index.is_none() => {
                return Err(citation_error(
                    "partition-logical coordinates require a partition index",
                ));
            }
            CoordinateSystem::DecryptedBitlockerVolumeLogicalBytes
                if self.volume_index.is_none()
                    || self.physical_offset_available
                    || self.coordinate_note.is_none() =>
            {
                return Err(citation_error(
                    "decrypted BitLocker coordinates require a volume index, unavailable physical offset, and explanatory note",
                ));
            }
            _ => {}
        }
        if !self.physical_offset_available && self.coordinate_note.is_none() {
            return Err(citation_error(
                "coordinates without a physical-media offset require an explanatory note",
            ));
        }
        Ok(())
    }
}

impl GenerationProvenance {
    fn validate(&self) -> Result<()> {
        if !self.local
            || !self.offline_enforced
            || self.runtime_name.is_empty()
            || self.runtime_name.len() > 256
            || self.runtime_version.is_empty()
            || self.runtime_version.len() > 256
            || self.model_id.is_empty()
            || self.model_id.len() > 1_024
            || !is_sha256(&self.runtime_executable_sha256)
            || !is_sha256(&self.model_sha256)
            || !is_sha256(&self.model_manifest_sha256)
            || !is_sha256(&self.prompt_template_sha256)
            || self.response_schema_version != "1.0.0"
            || self.temperature_millis > 2_000
            || self.context_tokens == 0
        {
            return Err(citation_error(
                "local generation provenance is incomplete or not offline",
            ));
        }
        Ok(())
    }
}

fn validate_draft(draft: &ModelDraft) -> Result<()> {
    if draft.schema_version != "1.0.0"
        || draft.headline.as_ref().is_some_and(|headline| {
            headline.is_empty() || headline.len() > 500 || headline.contains('\0')
        })
        || draft.claims.len() > 500
        || draft.citation_references.len() > 2_000
        || draft.limitations.len() > 100
        || draft.suggested_next_steps.len() > 50
    {
        return Err(citation_error("model draft exceeds collection limits"));
    }
    let mut claim_ids = BTreeSet::new();
    for claim in &draft.claims {
        let unique_citations = claim.citation_ids.iter().collect::<BTreeSet<_>>();
        if !valid_claim_id(&claim.claim_id)
            || !claim_ids.insert(claim.claim_id.as_str())
            || claim.text.is_empty()
            || claim.text.len() > 12_000
            || claim.text.contains('\0')
            || claim.citation_ids.len() > 100
            || unique_citations.len() != claim.citation_ids.len()
            || claim.method.as_ref().is_some_and(|method| {
                method.is_empty() || method.len() > 4_000 || method.contains('\0')
            })
        {
            return Err(citation_error("model claim failed bounds or uniqueness"));
        }
        let requires_citation = claim.kind != ClaimKind::Limitation;
        if requires_citation && claim.citation_ids.is_empty() {
            return Err(citation_error(
                "every evidential claim requires at least one citation",
            ));
        }
        match claim.kind {
            ClaimKind::DerivedFact if claim.method.as_deref().is_none_or(str::is_empty) => {
                return Err(citation_error("derived facts require a method"));
            }
            ClaimKind::ModelInference | ClaimKind::Hypothesis
                if claim.model_confidence.is_none() =>
            {
                return Err(citation_error(
                    "model inferences and hypotheses require model confidence",
                ));
            }
            ClaimKind::ObservedFact | ClaimKind::DerivedFact | ClaimKind::Limitation
                if claim.model_confidence.is_some() =>
            {
                return Err(citation_error(
                    "model confidence is forbidden for facts and limitations",
                ));
            }
            _ => {}
        }
    }
    if draft
        .limitations
        .iter()
        .any(|value| value.is_empty() || value.len() > 4_000 || value.contains('\0'))
        || draft
            .suggested_next_steps
            .iter()
            .any(|value| value.is_empty() || value.len() > 4_000 || value.contains('\0'))
    {
        return Err(citation_error(
            "limitation or next-step text exceeds bounds",
        ));
    }
    Ok(())
}

fn truncation_labels(reasons: &[TruncationReason]) -> Vec<&'static str> {
    reasons
        .iter()
        .map(|reason| match reason {
            TruncationReason::RowLimit => "row limit",
            TruncationReason::ByteLimit => "byte limit",
            TruncationReason::TokenLimit => "token limit",
            TruncationReason::TimeLimit => "time limit",
            TruncationReason::Cancelled => "cancelled",
            TruncationReason::ParserIncomplete => "parser incomplete",
            TruncationReason::UnsupportedSource => "unsupported source",
            TruncationReason::DiagnosticOmission => "diagnostic omission",
        })
        .collect()
}

fn valid_claim_id(value: &str) -> bool {
    valid_prefixed_identifier(value, "claim-")
}

fn valid_citation_id(value: &str) -> bool {
    valid_prefixed_identifier(value, "cite-")
}

fn valid_prefixed_identifier(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| !suffix.is_empty() && value.len() <= 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn citation_error(message: impl Into<String>) -> BrokerError {
    BrokerError::Citation(message.into())
}
