#![forbid(unsafe_code)]

//! Offline-only foundation for KDFT's forensic AI broker.
//!
//! This crate verifies examiner-supplied local model/runtime files, defines
//! bounded, provenance-preserving message contracts, and deliberately contains
//! no model downloader, cloud or Hugging Face client, SQL interface, shell
//! execution path, or evidence filesystem reader. An unfinished local runtime
//! bridge exists behind the non-default `llama-runtime` development feature and
//! is not part of normal forensic builds.

mod citation;
mod manifest;
mod prompt;
mod retrieval;
#[cfg(feature = "llama-runtime")]
mod runtime;
mod verification;

pub use citation::{
    AnswerStatus, CanonicalCitation, CitationBroker, ClaimKind, CoordinateSystem, ExaminerNextStep,
    GenerationProvenance, GroundedAnswer, ModelCitationReference, ModelClaim, ModelConfidence,
    ModelDraft, ParserProvenance, ResolvedCitation, SourceCoordinate, Workflow,
};
pub use manifest::{
    AdapterId, CompatibleAdapter, InstalledModelManifest, LicenseReview, LicenseReviewStatus,
    ManifestFile, ManifestFileRole, ModelDescription, ModelFormat, ModelSource,
    VerificationAttestation, MANIFEST_SCHEMA_VERSION,
};
pub use prompt::{
    build_prompt_envelope, PromptEnvelope, FINAL_RESPONSE_SCHEMA_JSON, MAX_EXAMINER_QUESTION_BYTES,
    MAX_PROMPT_BYTES, MODEL_DRAFT_SCHEMA_JSON, SYSTEM_INSTRUCTIONS,
};
pub use retrieval::{
    ArtifactContextRecord, ArtifactSearchFilter, BoundedRetrievalRequest, BoundedRetrievalResponse,
    RetrievalCoverage, RetrievalCursor, RetrievalLimits, TruncationReason, DEFAULT_CONTEXT_BYTES,
    DEFAULT_RETRIEVAL_ROWS, MAX_CONTEXT_BYTES, MAX_ITEM_BYTES, MAX_RETRIEVAL_ROWS,
};
#[cfg(feature = "llama-runtime")]
pub use runtime::{
    minimal_offline_environment, render_runtime_stdin, validate_llama_cpp_argv, CancellationToken,
    GroundedInferenceResponse, LlamaCppCliRuntime, LlamaCppCommandPlan, LlamaCppRuntimePolicy,
    NetworkIsolationMode, PromptPersistencePolicy, RuntimeCapabilityDisclosure,
    RuntimeExecutionAudit, DEFAULT_RUNTIME_CONTEXT_TOKENS, DEFAULT_RUNTIME_MAX_OUTPUT_TOKENS,
    DEFAULT_RUNTIME_STDERR_BYTES, DEFAULT_RUNTIME_STDOUT_BYTES, DEFAULT_RUNTIME_THREADS,
    DEFAULT_RUNTIME_TIMEOUT_MS, MAX_RUNTIME_CONTEXT_TOKENS, MAX_RUNTIME_GPU_LAYERS,
    MAX_RUNTIME_OUTPUT_TOKENS, MAX_RUNTIME_STDERR_BYTES, MAX_RUNTIME_STDOUT_BYTES,
    MAX_RUNTIME_THREADS, MAX_RUNTIME_TIMEOUT_MS, RUNTIME_STDIN_HEADER,
};
pub use verification::{
    prepare_local_model, verify_config_file, LocalModelVerificationConfig, PreparedLocalModel,
    RuntimeVerificationConfig, VerifiedFile, MAX_CONFIG_BYTES, MAX_MANIFEST_BYTES,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("invalid local-AI configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid installed-model manifest: {0}")]
    InvalidManifest(String),
    #[error("local file verification failed: {0}")]
    Verification(String),
    #[error("bounded retrieval contract rejected: {0}")]
    Retrieval(String),
    #[error("citation validation failed: {0}")]
    Citation(String),
    #[error("prompt construction rejected: {0}")]
    Prompt(String),
    #[error("local runtime execution failed: {0}")]
    Runtime(String),
    #[error("local runtime timed out: {0}")]
    Timeout(String),
    #[error("local runtime cancelled: {0}")]
    Cancelled(String),
    #[error("I/O error while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error while {operation}: {source}")]
    Json {
        operation: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, BrokerError>;

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn is_commit_hash(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
