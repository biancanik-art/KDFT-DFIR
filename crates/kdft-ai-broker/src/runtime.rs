use crate::citation::{CitationBroker, GenerationProvenance, GroundedAnswer, ModelDraft, Workflow};
use crate::manifest::{AdapterId, InstalledModelManifest, ManifestFileRole, ModelFormat};
use crate::prompt::{
    build_prompt_envelope, contains_obvious_secret, PromptEnvelope, MAX_PROMPT_BYTES,
    MODEL_DRAFT_SCHEMA_JSON,
};
use crate::retrieval::BoundedRetrievalResponse;
use crate::verification::{
    canonical_regular_directory, prepare_local_model, read_bounded, reject_symlink,
    require_digest_match, resolve_verified_model_file, sha256_bytes, sha256_file,
    LocalModelVerificationConfig, PreparedLocalModel, MAX_MANIFEST_BYTES,
};
use crate::{BrokerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_RUNTIME_CONTEXT_TOKENS: u32 = 4_096;
pub const MAX_RUNTIME_CONTEXT_TOKENS: u32 = 65_536;
pub const DEFAULT_RUNTIME_MAX_OUTPUT_TOKENS: u32 = 1_024;
pub const MAX_RUNTIME_OUTPUT_TOKENS: u32 = 8_192;
pub const DEFAULT_RUNTIME_THREADS: u16 = 1;
pub const MAX_RUNTIME_THREADS: u16 = 64;
pub const MAX_RUNTIME_GPU_LAYERS: u16 = 256;
pub const DEFAULT_RUNTIME_TIMEOUT_MS: u64 = 30_000;
pub const MAX_RUNTIME_TIMEOUT_MS: u64 = 300_000;
pub const DEFAULT_RUNTIME_STDOUT_BYTES: usize = 128 * 1_024;
pub const MAX_RUNTIME_STDOUT_BYTES: usize = 256 * 1_024;
pub const DEFAULT_RUNTIME_STDERR_BYTES: usize = 32 * 1_024;
pub const MAX_RUNTIME_STDERR_BYTES: usize = 64 * 1_024;
pub const RUNTIME_STDIN_HEADER: &str = "KDFT_LOCAL_RUNTIME_INPUT_V1";

const MAX_STDERR_DIAGNOSTIC_CHARS: usize = 256;
const POLL_INTERVAL_MS: u64 = 5;

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum PromptPersistencePolicy {
    #[default]
    MemoryOnly,
    ExplicitAuditFile {
        path: PathBuf,
        examiner_acknowledged: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlamaCppRuntimePolicy {
    #[serde(default)]
    pub model_weights_relative_path: Option<String>,
    pub context_tokens: u32,
    pub max_output_tokens: u32,
    pub seed: i64,
    pub temperature_millis: u16,
    pub threads: u16,
    pub n_gpu_layers: u16,
    pub max_prompt_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub timeout_ms: u64,
    #[serde(default)]
    pub extra_flags: Vec<String>,
    #[serde(default)]
    pub prompt_persistence: PromptPersistencePolicy,
}

impl Default for LlamaCppRuntimePolicy {
    fn default() -> Self {
        Self {
            model_weights_relative_path: None,
            context_tokens: DEFAULT_RUNTIME_CONTEXT_TOKENS,
            max_output_tokens: DEFAULT_RUNTIME_MAX_OUTPUT_TOKENS,
            seed: 1,
            temperature_millis: 0,
            threads: DEFAULT_RUNTIME_THREADS,
            n_gpu_layers: 0,
            max_prompt_bytes: MAX_PROMPT_BYTES,
            max_stdout_bytes: DEFAULT_RUNTIME_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_RUNTIME_STDERR_BYTES,
            timeout_ms: DEFAULT_RUNTIME_TIMEOUT_MS,
            extra_flags: Vec::new(),
            prompt_persistence: PromptPersistencePolicy::MemoryOnly,
        }
    }
}

impl LlamaCppRuntimePolicy {
    pub fn validate(&self) -> Result<()> {
        if let Some(path) = self.model_weights_relative_path.as_deref() {
            crate::manifest::validate_relative_path(path)?;
        }
        if self.context_tokens == 0 || self.context_tokens > MAX_RUNTIME_CONTEXT_TOKENS {
            return Err(BrokerError::InvalidConfig(format!(
                "context_tokens must be 1..={MAX_RUNTIME_CONTEXT_TOKENS}"
            )));
        }
        if self.max_output_tokens == 0
            || self.max_output_tokens > MAX_RUNTIME_OUTPUT_TOKENS
            || self.max_output_tokens > self.context_tokens
        {
            return Err(BrokerError::InvalidConfig(format!(
                "max_output_tokens must be 1..={MAX_RUNTIME_OUTPUT_TOKENS} and no larger than context_tokens"
            )));
        }
        if self.seed < 0 || self.seed > i64::from(u32::MAX) {
            return Err(BrokerError::InvalidConfig(
                "seed must be a deterministic non-negative 32-bit integer".to_string(),
            ));
        }
        if self.temperature_millis != 0 {
            return Err(BrokerError::InvalidConfig(
                "temperature_millis must be 0 for deterministic local-only inference".to_string(),
            ));
        }
        if self.threads == 0 || self.threads > MAX_RUNTIME_THREADS {
            return Err(BrokerError::InvalidConfig(format!(
                "threads must be 1..={MAX_RUNTIME_THREADS}"
            )));
        }
        if self.n_gpu_layers > MAX_RUNTIME_GPU_LAYERS {
            return Err(BrokerError::InvalidConfig(format!(
                "n_gpu_layers must be 0..={MAX_RUNTIME_GPU_LAYERS}"
            )));
        }
        if self.max_prompt_bytes == 0 || self.max_prompt_bytes > MAX_PROMPT_BYTES {
            return Err(BrokerError::InvalidConfig(format!(
                "max_prompt_bytes must be 1..={MAX_PROMPT_BYTES}"
            )));
        }
        if self.max_stdout_bytes == 0 || self.max_stdout_bytes > MAX_RUNTIME_STDOUT_BYTES {
            return Err(BrokerError::InvalidConfig(format!(
                "max_stdout_bytes must be 1..={MAX_RUNTIME_STDOUT_BYTES}"
            )));
        }
        if self.max_stderr_bytes == 0 || self.max_stderr_bytes > MAX_RUNTIME_STDERR_BYTES {
            return Err(BrokerError::InvalidConfig(format!(
                "max_stderr_bytes must be 1..={MAX_RUNTIME_STDERR_BYTES}"
            )));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_RUNTIME_TIMEOUT_MS {
            return Err(BrokerError::InvalidConfig(format!(
                "timeout_ms must be 1..={MAX_RUNTIME_TIMEOUT_MS}"
            )));
        }
        validate_extra_flags(&self.extra_flags)?;
        self.prompt_persistence.validate()?;
        Ok(())
    }
}

impl PromptPersistencePolicy {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::MemoryOnly => Ok(()),
            Self::ExplicitAuditFile {
                path,
                examiner_acknowledged,
            } => {
                if !examiner_acknowledged {
                    return Err(BrokerError::InvalidConfig(
                        "persisting prompts containing evidence requires explicit examiner_acknowledged=true"
                            .to_string(),
                    ));
                }
                let path_str = path.to_string_lossy();
                if path.as_os_str().is_empty() || path_str.contains('\0') {
                    return Err(BrokerError::InvalidConfig(
                        "explicit prompt audit file path must be non-empty and contain no NUL"
                            .to_string(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkIsolationMode {
    ArgvAndClearedEnvironmentOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapabilityDisclosure {
    pub offline_only: bool,
    pub network_client_present: bool,
    pub shell_execution_used: bool,
    pub environment_cleared: bool,
    pub raw_sql_tools_exposed: bool,
    pub raw_filesystem_tools_exposed: bool,
    pub os_network_sandbox_enforced: bool,
    pub os_filesystem_sandbox_enforced: bool,
    pub isolation_mode: NetworkIsolationMode,
    pub disclosures: Vec<String>,
}

impl RuntimeCapabilityDisclosure {
    pub fn llama_cpp_cli() -> Self {
        Self {
            offline_only: true,
            network_client_present: false,
            shell_execution_used: false,
            environment_cleared: true,
            raw_sql_tools_exposed: false,
            raw_filesystem_tools_exposed: false,
            os_network_sandbox_enforced: false,
            os_filesystem_sandbox_enforced: false,
            isolation_mode: NetworkIsolationMode::ArgvAndClearedEnvironmentOnly,
            disclosures: vec![
                "Local inference enforces hash-verified files, discrete allowlisted argv (no shell), and a cleared environment with HF_HUB_OFFLINE=1, but std::process::Command does not attach an OS kernel network namespace, firewall rule, or filesystem sandbox to the child process."
                    .to_string(),
                "No model downloader, Hugging Face client, cloud endpoint, raw SQL interface, or evidence filesystem tool is exposed to the model."
                    .to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlamaCppCommandPlan {
    pub executable_path: PathBuf,
    pub executable_sha256: String,
    pub working_directory: PathBuf,
    pub model_weights_path: PathBuf,
    pub model_weights_sha256: String,
    pub argv: Vec<String>,
    pub env_cleared: bool,
    pub environment: BTreeMap<String, String>,
    pub stdin_prompt_bytes: usize,
    pub stdin_prompt_sha256: String,
    pub capabilities: RuntimeCapabilityDisclosure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeExecutionAudit {
    pub request_id: String,
    pub case_generation: i64,
    pub runtime_executable_sha256: String,
    pub model_manifest_sha256: String,
    pub model_weights_sha256: String,
    pub prompt_template_sha256: String,
    pub stdin_prompt_sha256: String,
    pub stdin_prompt_bytes: usize,
    pub stdout_sha256: String,
    pub stdout_bytes: usize,
    pub stderr_sha256: String,
    pub stderr_bytes: usize,
    pub exit_code: i32,
    pub elapsed_ms: u64,
    pub argv: Vec<String>,
    pub env_cleared: bool,
    pub environment_keys: Vec<String>,
    pub prompt_persisted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroundedInferenceResponse {
    pub answer: GroundedAnswer,
    pub prepared_model: PreparedLocalModel,
    pub capabilities: RuntimeCapabilityDisclosure,
    pub audit: RuntimeExecutionAudit,
}

#[derive(Debug, Clone)]
struct VerifiedLlamaCppTarget {
    prepared: PreparedLocalModel,
    manifest: InstalledModelManifest,
    model_directory: PathBuf,
    model_weights_path: PathBuf,
    model_weights_sha256: String,
    runtime_executable_path: PathBuf,
    runtime_executable_sha256: String,
}

#[derive(Debug, Clone)]
pub struct LlamaCppCliRuntime {
    verification_config: LocalModelVerificationConfig,
    policy: LlamaCppRuntimePolicy,
}

impl LlamaCppCliRuntime {
    pub fn new(
        verification_config: LocalModelVerificationConfig,
        policy: LlamaCppRuntimePolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let runtime = Self {
            verification_config,
            policy,
        };
        let _ = runtime.verify_target_internal()?;
        Ok(runtime)
    }

    pub fn policy(&self) -> &LlamaCppRuntimePolicy {
        &self.policy
    }

    pub fn capability_disclosure(&self) -> RuntimeCapabilityDisclosure {
        RuntimeCapabilityDisclosure::llama_cpp_cli()
    }

    pub fn verify_target(&self) -> Result<PreparedLocalModel> {
        Ok(self.verify_target_internal()?.prepared)
    }

    pub fn plan_invocation(&self, prompt: &PromptEnvelope) -> Result<LlamaCppCommandPlan> {
        let (plan, _, _) = self.plan_invocation_internal(prompt)?;
        Ok(plan)
    }

    pub fn generate_draft(
        &self,
        prompt: &PromptEnvelope,
        cancel: &CancellationToken,
    ) -> Result<(ModelDraft, PreparedLocalModel, RuntimeExecutionAudit)> {
        if cancel.is_cancelled() {
            return Err(BrokerError::Cancelled(
                "local runtime cancelled before process launch".to_string(),
            ));
        }

        let (plan, mut target, rendered_stdin) = self.plan_invocation_internal(prompt)?;
        let prompt_persisted = self.persist_prompt_if_configured(&rendered_stdin)?;

        // Re-verify executable and model weight digests immediately prior to spawning
        // so on-disk tampering between plan creation and execution fails closed.
        reject_symlink(&target.runtime_executable_path, "runtime executable")?;
        let actual_exec_sha = sha256_file(&target.runtime_executable_path)?;
        require_digest_match(
            "runtime executable",
            &target.runtime_executable_sha256,
            &actual_exec_sha,
        )?;
        reject_symlink(&target.model_weights_path, "model file")?;
        let actual_model_sha = sha256_file(&target.model_weights_path)?;
        require_digest_match(
            "model weights",
            &target.model_weights_sha256,
            &actual_model_sha,
        )?;

        let started_at = Instant::now();
        let deadline = started_at + Duration::from_millis(self.policy.timeout_ms);

        let mut command = Command::new(&plan.executable_path);
        command
            .args(&plan.argv)
            .current_dir(&plan.working_directory)
            .env_clear()
            .envs(&plan.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|source| BrokerError::Io {
            operation: "spawning verified llama.cpp runtime executable",
            source,
        })?;

        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| BrokerError::Runtime("failed to open child stdin pipe".to_string()))?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| BrokerError::Runtime("failed to open child stdout pipe".to_string()))?;
        let child_stderr = child
            .stderr
            .take()
            .ok_or_else(|| BrokerError::Runtime("failed to open child stderr pipe".to_string()))?;

        let stdin_bytes = rendered_stdin.into_bytes();
        let stdin_handle = thread::spawn(move || -> std::io::Result<()> {
            let mut pipe = child_stdin;
            match pipe.write_all(&stdin_bytes) {
                Ok(()) => pipe.flush(),
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                Err(err) => Err(err),
            }
        });

        let max_stdout = self.policy.max_stdout_bytes;
        let stdout_overflow_flag = Arc::new(AtomicBool::new(false));
        let stdout_overflow_writer = Arc::clone(&stdout_overflow_flag);
        let stdout_handle = thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buffer = Vec::new();
            let mut bounded = child_stdout.take((max_stdout as u64) + 1);
            bounded.read_to_end(&mut buffer)?;
            if buffer.len() > max_stdout {
                stdout_overflow_writer.store(true, Ordering::SeqCst);
            }
            Ok(buffer)
        });

        let max_stderr = self.policy.max_stderr_bytes;
        let stderr_overflow_flag = Arc::new(AtomicBool::new(false));
        let stderr_overflow_writer = Arc::clone(&stderr_overflow_flag);
        let stderr_handle = thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buffer = Vec::new();
            let mut bounded = child_stderr.take((max_stderr as u64) + 1);
            bounded.read_to_end(&mut buffer)?;
            if buffer.len() > max_stderr {
                stderr_overflow_writer.store(true, Ordering::SeqCst);
            }
            Ok(buffer)
        });

        let exit_status = loop {
            if cancel.is_cancelled() {
                terminate_child(&mut child);
                let _ = stdin_handle.join();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(BrokerError::Cancelled(
                    "local runtime cancelled during inference".to_string(),
                ));
            }
            if stdout_overflow_flag.load(Ordering::SeqCst) {
                terminate_child(&mut child);
                let _ = stdin_handle.join();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(BrokerError::Runtime(format!(
                    "runtime stdout exceeded maximum bound of {} bytes",
                    self.policy.max_stdout_bytes
                )));
            }
            if stderr_overflow_flag.load(Ordering::SeqCst) {
                terminate_child(&mut child);
                let _ = stdin_handle.join();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(BrokerError::Runtime(format!(
                    "runtime stderr exceeded maximum bound of {} bytes",
                    self.policy.max_stderr_bytes
                )));
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        terminate_child(&mut child);
                        let _ = stdin_handle.join();
                        let _ = stdout_handle.join();
                        let _ = stderr_handle.join();
                        return Err(BrokerError::Timeout(format!(
                            "local runtime exceeded {} ms timeout",
                            self.policy.timeout_ms
                        )));
                    }
                    thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
                }
                Err(source) => {
                    terminate_child(&mut child);
                    let _ = stdin_handle.join();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(BrokerError::Io {
                        operation: "waiting on local runtime child process",
                        source,
                    });
                }
            }
        };

        let elapsed_ms = started_at.elapsed().as_millis() as u64;

        let stdin_result = stdin_handle
            .join()
            .map_err(|_| BrokerError::Runtime("stdin writer thread panicked".to_string()))?;
        let stdout_bytes = stdout_handle
            .join()
            .map_err(|_| BrokerError::Runtime("stdout reader thread panicked".to_string()))?
            .map_err(|source| BrokerError::Io {
                operation: "reading local runtime stdout",
                source,
            })?;
        let stderr_bytes = stderr_handle
            .join()
            .map_err(|_| BrokerError::Runtime("stderr reader thread panicked".to_string()))?
            .map_err(|source| BrokerError::Io {
                operation: "reading local runtime stderr",
                source,
            })?;

        if stdout_bytes.len() > self.policy.max_stdout_bytes {
            return Err(BrokerError::Runtime(format!(
                "runtime stdout exceeded maximum bound of {} bytes",
                self.policy.max_stdout_bytes
            )));
        }
        if stderr_bytes.len() > self.policy.max_stderr_bytes {
            return Err(BrokerError::Runtime(format!(
                "runtime stderr exceeded maximum bound of {} bytes",
                self.policy.max_stderr_bytes
            )));
        }

        let stderr_text = String::from_utf8_lossy(&stderr_bytes);
        if contains_obvious_secret(&stderr_text) {
            return Err(BrokerError::Runtime(
                "runtime stderr failed the broker's secret canary scan".to_string(),
            ));
        }

        if !exit_status.success() {
            let code = exit_status.code().unwrap_or(-1);
            let diagnostic = sanitize_stderr_diagnostic(&stderr_text);
            return Err(BrokerError::Runtime(format!(
                "runtime process exited with status {code}: {diagnostic}"
            )));
        }

        if let Err(source) = stdin_result {
            if source.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(BrokerError::Io {
                    operation: "writing bounded prompt to runtime stdin",
                    source,
                });
            }
        }

        if stdout_bytes.contains(&0) {
            return Err(BrokerError::Runtime(
                "runtime stdout contains forbidden NUL byte".to_string(),
            ));
        }
        let stdout_text = String::from_utf8(stdout_bytes.clone())
            .map_err(|_| BrokerError::Runtime("runtime stdout is not valid UTF-8".to_string()))?;
        if contains_obvious_secret(&stdout_text) {
            return Err(BrokerError::Runtime(
                "runtime stdout failed the broker's secret canary scan".to_string(),
            ));
        }
        let trimmed_stdout = stdout_text.trim();
        if trimmed_stdout.is_empty() {
            return Err(BrokerError::Runtime(
                "runtime produced empty stdout".to_string(),
            ));
        }

        let draft: ModelDraft = serde_json::from_str(trimmed_stdout).map_err(|source| {
            BrokerError::Runtime(format!(
                "runtime output is not a valid ModelDraft JSON object: {source}"
            ))
        })?;
        reject_secrets_in_draft(&draft)?;

        target.prepared.runtime_started = true;
        target
            .prepared
            .limitations
            .retain(|item| !item.contains("the runtime was not launched"));
        for disclosure in &plan.capabilities.disclosures {
            if !target.prepared.limitations.contains(disclosure) {
                target.prepared.limitations.push(disclosure.clone());
            }
        }

        let audit = RuntimeExecutionAudit {
            request_id: draft.request_id.clone(),
            case_generation: draft.case_generation,
            runtime_executable_sha256: target.runtime_executable_sha256,
            model_manifest_sha256: target.prepared.manifest_sha256.clone(),
            model_weights_sha256: target.model_weights_sha256,
            prompt_template_sha256: prompt.prompt_template_sha256.clone(),
            stdin_prompt_sha256: plan.stdin_prompt_sha256,
            stdin_prompt_bytes: plan.stdin_prompt_bytes,
            stdout_sha256: sha256_bytes(&stdout_bytes),
            stdout_bytes: stdout_bytes.len(),
            stderr_sha256: sha256_bytes(&stderr_bytes),
            stderr_bytes: stderr_bytes.len(),
            exit_code: exit_status.code().unwrap_or(0),
            elapsed_ms,
            argv: plan.argv,
            env_cleared: plan.env_cleared,
            environment_keys: plan.environment.keys().cloned().collect(),
            prompt_persisted,
        };

        Ok((draft, target.prepared, audit))
    }

    pub fn execute_grounded(
        &self,
        workflow: Workflow,
        examiner_question: &str,
        retrieval: &BoundedRetrievalResponse,
        citation_broker: &CitationBroker,
        cancel: &CancellationToken,
    ) -> Result<GroundedInferenceResponse> {
        let prompt = build_prompt_envelope(workflow, examiner_question, retrieval)?;
        let (draft, prepared_model, audit) = self.generate_draft(&prompt, cancel)?;
        let capabilities = self.capability_disclosure();

        let generation = GenerationProvenance {
            local: true,
            offline_enforced: true,
            runtime_name: "llama.cpp".to_string(),
            runtime_version: prepared_model.declared_runtime_version.clone(),
            runtime_executable_sha256: audit.runtime_executable_sha256.clone(),
            model_id: prepared_model.model_id.clone(),
            model_sha256: audit.model_weights_sha256.clone(),
            model_manifest_sha256: audit.model_manifest_sha256.clone(),
            prompt_template_sha256: prompt.prompt_template_sha256.clone(),
            response_schema_version: prompt.response_schema_version.clone(),
            seed: Some(self.policy.seed),
            temperature_millis: self.policy.temperature_millis,
            context_tokens: self.policy.context_tokens,
        };

        let mut answer = citation_broker.finalize(draft, retrieval, generation)?;
        for disclosure in &capabilities.disclosures {
            if answer.limitations.len() < 100 && !answer.limitations.contains(disclosure) {
                answer.limitations.push(disclosure.clone());
            }
        }
        if audit.prompt_persisted && answer.limitations.len() < 100 {
            let persistence_note =
                "Bounded prompt containing evidence was persisted to an explicit examiner-acknowledged audit file."
                    .to_string();
            if !answer.limitations.contains(&persistence_note) {
                answer.limitations.push(persistence_note);
            }
        }

        Ok(GroundedInferenceResponse {
            answer,
            prepared_model,
            capabilities,
            audit,
        })
    }

    fn verify_target_internal(&self) -> Result<VerifiedLlamaCppTarget> {
        self.policy.validate()?;
        let prepared = prepare_local_model(&self.verification_config)?;
        if self.verification_config.runtime.adapter_id != AdapterId::LlamaCpp {
            return Err(BrokerError::InvalidConfig(format!(
                "llama.cpp CLI runtime requires adapter_id=llama_cpp, got {:?}",
                self.verification_config.runtime.adapter_id
            )));
        }

        let runtime_path = &self.verification_config.runtime.executable_path;
        if is_forbidden_shell_executable(runtime_path) {
            return Err(BrokerError::InvalidConfig(format!(
                "runtime executable must not be a shell or script interpreter: {}",
                runtime_path.display()
            )));
        }

        let manifest_bytes = read_bounded(
            &self.verification_config.manifest_path,
            MAX_MANIFEST_BYTES,
            "reading installed-model manifest",
        )?;
        let manifest: InstalledModelManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|source| BrokerError::Json {
                operation: "parsing installed-model manifest",
                source,
            })?;
        manifest.validate()?;
        if manifest.model.format != ModelFormat::Gguf {
            return Err(BrokerError::InvalidConfig(format!(
                "llama.cpp CLI runtime requires model format gguf, got {:?}",
                manifest.model.format
            )));
        }
        if u64::from(self.policy.context_tokens) > manifest.model.declared_context_tokens {
            return Err(BrokerError::InvalidConfig(format!(
                "policy context_tokens ({}) exceeds manifest declared_context_tokens ({})",
                self.policy.context_tokens, manifest.model.declared_context_tokens
            )));
        }

        let weights_file = match self.policy.model_weights_relative_path.as_deref() {
            Some(requested) => manifest
                .files
                .iter()
                .find(|file| {
                    file.role == ManifestFileRole::ModelWeights && file.relative_path == requested
                })
                .ok_or_else(|| {
                    BrokerError::InvalidConfig(format!(
                        "manifest does not contain a model_weights entry at {requested:?}"
                    ))
                })?,
            None => {
                let mut weights = manifest
                    .files
                    .iter()
                    .filter(|file| file.role == ManifestFileRole::ModelWeights);
                let Some(first) = weights.next() else {
                    return Err(BrokerError::InvalidManifest(
                        "at least one model_weights file is required".to_string(),
                    ));
                };
                if weights.next().is_some() {
                    return Err(BrokerError::InvalidConfig(
                        "manifest declares multiple model_weights files; set model_weights_relative_path explicitly"
                            .to_string(),
                    ));
                }
                first
            }
        };

        let model_directory =
            canonical_regular_directory(&self.verification_config.model_directory)?;
        let model_weights_path =
            resolve_verified_model_file(&model_directory, &weights_file.relative_path)?;
        let actual_weights_sha256 = sha256_file(&model_weights_path)?;
        require_digest_match(
            &weights_file.relative_path,
            &weights_file.sha256,
            &actual_weights_sha256,
        )?;

        let runtime_executable_sha256 = sha256_file(runtime_path)?;
        require_digest_match(
            "runtime executable",
            &self.verification_config.runtime.expected_sha256,
            &runtime_executable_sha256,
        )?;

        Ok(VerifiedLlamaCppTarget {
            prepared,
            manifest,
            model_directory,
            model_weights_path,
            model_weights_sha256: actual_weights_sha256,
            runtime_executable_path: runtime_path.clone(),
            runtime_executable_sha256,
        })
    }

    fn plan_invocation_internal(
        &self,
        prompt: &PromptEnvelope,
    ) -> Result<(LlamaCppCommandPlan, VerifiedLlamaCppTarget, String)> {
        let target = self.verify_target_internal()?;
        let _ = &target.manifest;
        let rendered_stdin = render_runtime_stdin(prompt, self.policy.max_prompt_bytes)?;
        let stdin_prompt_sha256 = sha256_bytes(rendered_stdin.as_bytes());

        let model_path_str = target.model_weights_path.to_str().ok_or_else(|| {
            BrokerError::InvalidConfig("model weights path must be valid UTF-8".to_string())
        })?;
        let mut argv = vec![
            "--model".to_string(),
            model_path_str.to_string(),
            "--ctx-size".to_string(),
            self.policy.context_tokens.to_string(),
            "--predict".to_string(),
            self.policy.max_output_tokens.to_string(),
            "--temp".to_string(),
            "0.000".to_string(),
            "--top-k".to_string(),
            "1".to_string(),
            "--top-p".to_string(),
            "1.000".to_string(),
            "--seed".to_string(),
            self.policy.seed.to_string(),
            "--threads".to_string(),
            self.policy.threads.to_string(),
            "--n-gpu-layers".to_string(),
            self.policy.n_gpu_layers.to_string(),
            "--no-display-prompt".to_string(),
            "--simple-io".to_string(),
            "--no-warmup".to_string(),
            "--log-disable".to_string(),
            "--json-schema".to_string(),
            MODEL_DRAFT_SCHEMA_JSON.to_string(),
        ];
        argv.extend(self.policy.extra_flags.iter().cloned());
        validate_llama_cpp_argv(&argv, &target.model_weights_path)?;

        let environment = minimal_offline_environment();
        validate_minimal_environment(&environment)?;

        let plan = LlamaCppCommandPlan {
            executable_path: target.runtime_executable_path.clone(),
            executable_sha256: target.runtime_executable_sha256.clone(),
            working_directory: target.model_directory.clone(),
            model_weights_path: target.model_weights_path.clone(),
            model_weights_sha256: target.model_weights_sha256.clone(),
            argv,
            env_cleared: true,
            environment,
            stdin_prompt_bytes: rendered_stdin.len(),
            stdin_prompt_sha256,
            capabilities: self.capability_disclosure(),
        };
        Ok((plan, target, rendered_stdin))
    }

    fn persist_prompt_if_configured(&self, rendered_stdin: &str) -> Result<bool> {
        self.policy.prompt_persistence.validate()?;
        match &self.policy.prompt_persistence {
            PromptPersistencePolicy::MemoryOnly => Ok(false),
            PromptPersistencePolicy::ExplicitAuditFile {
                path,
                examiner_acknowledged,
            } => {
                if !examiner_acknowledged {
                    return Err(BrokerError::InvalidConfig(
                        "persisting prompts containing evidence requires explicit examiner_acknowledged=true"
                            .to_string(),
                    ));
                }
                if contains_obvious_secret(rendered_stdin) {
                    return Err(BrokerError::Prompt(
                        "rendered prompt failed the broker's secret canary scan".to_string(),
                    ));
                }
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() && parent.exists() {
                        reject_symlink(parent, "prompt audit directory")?;
                    }
                }
                if path.exists() {
                    reject_symlink(path, "prompt audit file")?;
                }
                fs::write(path, rendered_stdin.as_bytes()).map_err(|source| BrokerError::Io {
                    operation: "writing explicitly configured prompt audit file",
                    source,
                })?;
                Ok(true)
            }
        }
    }
}

/// Render the bounded prompt payload piped to the local runtime's stdin.
pub fn render_runtime_stdin(prompt: &PromptEnvelope, max_prompt_bytes: usize) -> Result<String> {
    prompt.validate()?;
    if max_prompt_bytes == 0 || max_prompt_bytes > MAX_PROMPT_BYTES {
        return Err(BrokerError::InvalidConfig(format!(
            "max_prompt_bytes must be 1..={MAX_PROMPT_BYTES}"
        )));
    }
    let rendered = format!(
        "{RUNTIME_STDIN_HEADER}\nBEGIN_SYSTEM_INSTRUCTIONS\n{}\nEND_SYSTEM_INSTRUCTIONS\nBEGIN_RESPONSE_SCHEMA_JSON\n{}\nEND_RESPONSE_SCHEMA_JSON\nBEGIN_USER_MESSAGE\n{}\nEND_USER_MESSAGE\n",
        prompt.system_message, prompt.response_schema_json, prompt.user_message
    );
    if rendered.contains('\0') {
        return Err(BrokerError::Prompt(
            "rendered runtime prompt must not contain NUL bytes".to_string(),
        ));
    }
    if rendered.len() > max_prompt_bytes || rendered.len() > MAX_PROMPT_BYTES {
        return Err(BrokerError::Prompt(format!(
            "rendered runtime prompt ({} bytes) exceeds maximum bound ({} bytes)",
            rendered.len(),
            max_prompt_bytes.min(MAX_PROMPT_BYTES)
        )));
    }
    if contains_obvious_secret(&rendered) {
        return Err(BrokerError::Prompt(
            "rendered runtime prompt failed the broker's secret canary scan".to_string(),
        ));
    }
    Ok(rendered)
}

/// Validate a discrete `llama.cpp` CLI argument vector against KDFT's strict
/// offline allowlist. No shell syntax, network/Hugging Face flags, prompt-cache
/// persistence flags, external file flags, or unverified model paths are allowed.
pub fn validate_llama_cpp_argv(argv: &[String], expected_model_path: &Path) -> Result<()> {
    if argv.is_empty() || argv.len() > 64 {
        return Err(BrokerError::InvalidConfig(
            "runtime argv must contain 1..=64 discrete arguments".to_string(),
        ));
    }
    let expected_model = expected_model_path.to_str().ok_or_else(|| {
        BrokerError::InvalidConfig("expected model path must be valid UTF-8".to_string())
    })?;

    let mut seen_flags = BTreeSet::new();
    let mut index = 0;
    while index < argv.len() {
        let flag = &argv[index];
        validate_arg_common(flag)?;
        if !flag.starts_with("--") || flag.contains('=') {
            return Err(BrokerError::InvalidConfig(format!(
                "runtime argv token {flag:?} is not a discrete allowlisted long flag"
            )));
        }
        if is_forbidden_flag(flag) {
            return Err(BrokerError::InvalidConfig(format!(
                "runtime flag {flag:?} is forbidden by offline/no-persistence policy"
            )));
        }
        if !seen_flags.insert(flag.as_str()) {
            return Err(BrokerError::InvalidConfig(format!(
                "duplicate runtime flag {flag:?} is not allowed"
            )));
        }

        match flag.as_str() {
            "--model" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_path_arg(value)?;
                if value != expected_model {
                    return Err(BrokerError::InvalidConfig(
                        "--model argument does not match the exact hash-verified model path"
                            .to_string(),
                    ));
                }
            }
            "--ctx-size" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let parsed: u32 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig("--ctx-size must be a positive integer".to_string())
                })?;
                if parsed == 0 || parsed > MAX_RUNTIME_CONTEXT_TOKENS {
                    return Err(BrokerError::InvalidConfig(format!(
                        "--ctx-size must be 1..={MAX_RUNTIME_CONTEXT_TOKENS}"
                    )));
                }
            }
            "--predict" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let parsed: u32 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig("--predict must be a positive integer".to_string())
                })?;
                if parsed == 0 || parsed > MAX_RUNTIME_OUTPUT_TOKENS {
                    return Err(BrokerError::InvalidConfig(format!(
                        "--predict must be 1..={MAX_RUNTIME_OUTPUT_TOKENS}"
                    )));
                }
            }
            "--temp" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                if !matches!(value.as_str(), "0" | "0.0" | "0.00" | "0.000") {
                    return Err(BrokerError::InvalidConfig(
                        "--temp must be 0.000 for deterministic local-only inference".to_string(),
                    ));
                }
            }
            "--top-k" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                if value != "1" {
                    return Err(BrokerError::InvalidConfig(
                        "--top-k must be 1 for deterministic local-only inference".to_string(),
                    ));
                }
            }
            "--top-p" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                if !matches!(value.as_str(), "1" | "1.0" | "1.00" | "1.000") {
                    return Err(BrokerError::InvalidConfig(
                        "--top-p must be 1.000 for deterministic local-only inference".to_string(),
                    ));
                }
            }
            "--seed" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let _: u32 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig(
                        "--seed must be a non-negative 32-bit integer".to_string(),
                    )
                })?;
            }
            "--threads" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let parsed: u16 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig("--threads must be a positive integer".to_string())
                })?;
                if parsed == 0 || parsed > MAX_RUNTIME_THREADS {
                    return Err(BrokerError::InvalidConfig(format!(
                        "--threads must be 1..={MAX_RUNTIME_THREADS}"
                    )));
                }
            }
            "--n-gpu-layers" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let parsed: u16 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig(
                        "--n-gpu-layers must be a non-negative integer".to_string(),
                    )
                })?;
                if parsed > MAX_RUNTIME_GPU_LAYERS {
                    return Err(BrokerError::InvalidConfig(format!(
                        "--n-gpu-layers must be 0..={MAX_RUNTIME_GPU_LAYERS}"
                    )));
                }
            }
            "--batch-size" | "--ubatch-size" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let parsed: u16 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig(format!("{flag} must be a positive integer"))
                })?;
                if parsed == 0 || parsed > 16_384 {
                    return Err(BrokerError::InvalidConfig(format!(
                        "{flag} must be 1..=16384"
                    )));
                }
            }
            "--json-schema" => {
                let value = next_flag_value(argv, &mut index, flag)?;
                if value != MODEL_DRAFT_SCHEMA_JSON {
                    return Err(BrokerError::InvalidConfig(
                        "--json-schema must match KDFT's canonical untrusted ModelDraft schema"
                            .to_string(),
                    ));
                }
            }
            "--no-display-prompt"
            | "--simple-io"
            | "--no-warmup"
            | "--log-disable"
            | "--no-mmap"
            | "--no-kv-offload"
            | "--no-cnv"
            | "--no-conversation"
            | "--single-turn" => {}
            _ => {
                return Err(BrokerError::InvalidConfig(format!(
                    "runtime flag {flag:?} is not in the discrete llama.cpp allowlist"
                )));
            }
        }
        index += 1;
    }

    for required in [
        "--model",
        "--ctx-size",
        "--predict",
        "--temp",
        "--top-k",
        "--top-p",
        "--seed",
        "--threads",
        "--n-gpu-layers",
        "--no-display-prompt",
        "--simple-io",
        "--no-warmup",
        "--log-disable",
        "--json-schema",
    ] {
        if !seen_flags.contains(required) {
            return Err(BrokerError::InvalidConfig(format!(
                "locked runtime argv is missing required deterministic flag {required:?}"
            )));
        }
    }

    Ok(())
}

fn validate_extra_flags(extra_flags: &[String]) -> Result<()> {
    if extra_flags.len() > 16 {
        return Err(BrokerError::InvalidConfig(
            "extra_flags may contain at most 16 entries".to_string(),
        ));
    }
    let mut index = 0;
    let mut seen = BTreeSet::new();
    while index < extra_flags.len() {
        let flag = &extra_flags[index];
        validate_arg_common(flag)?;
        validate_scalar_arg(flag)?;
        if !flag.starts_with("--") || flag.contains('=') {
            return Err(BrokerError::InvalidConfig(format!(
                "extra flag {flag:?} is not a discrete allowlisted long flag"
            )));
        }
        if is_forbidden_flag(flag) {
            return Err(BrokerError::InvalidConfig(format!(
                "extra flag {flag:?} is forbidden by offline/no-persistence policy"
            )));
        }
        if !seen.insert(flag.as_str()) {
            return Err(BrokerError::InvalidConfig(format!(
                "duplicate extra flag {flag:?}"
            )));
        }
        match flag.as_str() {
            "--batch-size" | "--ubatch-size" => {
                let value = next_flag_value(extra_flags, &mut index, flag)?;
                validate_scalar_arg(value)?;
                let parsed: u16 = value.parse().map_err(|_| {
                    BrokerError::InvalidConfig(format!("{flag} must be a positive integer"))
                })?;
                if parsed == 0 || parsed > 16_384 {
                    return Err(BrokerError::InvalidConfig(format!(
                        "{flag} must be 1..=16384"
                    )));
                }
            }
            "--no-mmap" | "--no-kv-offload" | "--no-cnv" | "--no-conversation"
            | "--single-turn" => {}
            _ => {
                return Err(BrokerError::InvalidConfig(format!(
                    "extra flag {flag:?} is not in the discrete llama.cpp allowlist"
                )));
            }
        }
        index += 1;
    }
    Ok(())
}

fn next_flag_value<'a>(argv: &'a [String], index: &mut usize, flag: &str) -> Result<&'a String> {
    *index += 1;
    let Some(value) = argv.get(*index) else {
        return Err(BrokerError::InvalidConfig(format!(
            "runtime flag {flag:?} requires a discrete value argument"
        )));
    };
    validate_arg_common(value)?;
    Ok(value)
}

fn validate_arg_common(arg: &str) -> Result<()> {
    if arg.is_empty() || arg.len() > 16_384 || arg.contains('\0') {
        return Err(BrokerError::InvalidConfig(
            "runtime argument must be 1..=16384 bytes and contain no NUL".to_string(),
        ));
    }
    let lower = arg.to_ascii_lowercase();
    for scheme in [
        "http://", "https://", "hf://", "ftp://", "ws://", "wss://", "file://", "tcp://",
    ] {
        if lower.contains(scheme) {
            return Err(BrokerError::InvalidConfig(format!(
                "runtime argument must not contain URL scheme {scheme:?}"
            )));
        }
    }
    Ok(())
}

fn validate_scalar_arg(arg: &str) -> Result<()> {
    if arg.chars().any(|ch| {
        matches!(
            ch,
            ';' | '|' | '&' | '`' | '$' | '<' | '>' | '\n' | '\r' | '\'' | '"'
        )
    }) {
        return Err(BrokerError::InvalidConfig(format!(
            "runtime argument {arg:?} contains forbidden shell or control characters"
        )));
    }
    Ok(())
}

fn validate_path_arg(arg: &str) -> Result<()> {
    if arg
        .chars()
        .any(|ch| matches!(ch, ';' | '|' | '`' | '$' | '<' | '>' | '\n' | '\r'))
    {
        return Err(BrokerError::InvalidConfig(
            "model path argument contains forbidden shell or control characters".to_string(),
        ));
    }
    Ok(())
}

fn is_forbidden_flag(flag: &str) -> bool {
    let lower = flag.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "-hf"
            | "--hf-repo"
            | "-hff"
            | "--hf-file"
            | "-hft"
            | "--hf-token"
            | "-mu"
            | "--model-url"
            | "--host"
            | "--port"
            | "--api-key"
            | "--api-key-file"
            | "--webui"
            | "--metrics"
            | "--rpc"
            | "--prompt-cache"
            | "--prompt-cache-all"
            | "--prompt-cache-ro"
            | "--session"
            | "-f"
            | "--file"
            | "-bf"
            | "--binary-file"
            | "--json-schema-file"
            | "--grammar-file"
            | "--lora"
            | "--lora-scaled"
            | "--control-vector"
            | "--log-file"
            | "--logdir"
            | "-ld"
            | "-c"
            | "/c"
    )
}

fn is_forbidden_shell_executable(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|os| os.to_str()) else {
        return true;
    };
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    matches!(
        stem,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "wsl"
            | "mshta"
            | "wscript"
            | "cscript"
            | "rundll32"
            | "env"
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
    )
}

pub fn minimal_offline_environment() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("GGML_NO_BACKTRACE".to_string(), "1".to_string());
    env.insert("HF_HUB_OFFLINE".to_string(), "1".to_string());
    env.insert("NO_PROXY".to_string(), "*".to_string());
    env.insert("TRANSFORMERS_OFFLINE".to_string(), "1".to_string());
    env
}

fn validate_minimal_environment(env: &BTreeMap<String, String>) -> Result<()> {
    const ALLOWED_KEYS: &[&str] = &[
        "GGML_NO_BACKTRACE",
        "HF_HUB_OFFLINE",
        "NO_PROXY",
        "TRANSFORMERS_OFFLINE",
    ];
    if env.get("HF_HUB_OFFLINE").map(String::as_str) != Some("1")
        || env.get("TRANSFORMERS_OFFLINE").map(String::as_str) != Some("1")
        || env.get("NO_PROXY").map(String::as_str) != Some("*")
    {
        return Err(BrokerError::InvalidConfig(
            "minimal runtime environment is missing mandatory offline variables".to_string(),
        ));
    }
    for (key, value) in env {
        if !ALLOWED_KEYS.contains(&key.as_str())
            || key.contains('\0')
            || value.contains('\0')
            || contains_obvious_secret(value)
        {
            return Err(BrokerError::InvalidConfig(format!(
                "runtime environment variable {key:?} is not permitted in cleared offline mode"
            )));
        }
    }
    Ok(())
}

fn reject_secrets_in_draft(draft: &ModelDraft) -> Result<()> {
    if let Some(headline) = draft.headline.as_deref() {
        if contains_obvious_secret(headline) {
            return Err(BrokerError::Runtime(
                "model draft headline failed the broker's secret canary scan".to_string(),
            ));
        }
    }
    for claim in &draft.claims {
        if contains_obvious_secret(&claim.text)
            || claim.method.as_deref().is_some_and(contains_obvious_secret)
        {
            return Err(BrokerError::Runtime(
                "model draft claim failed the broker's secret canary scan".to_string(),
            ));
        }
    }
    for item in draft
        .limitations
        .iter()
        .chain(draft.suggested_next_steps.iter())
    {
        if contains_obvious_secret(item) {
            return Err(BrokerError::Runtime(
                "model draft metadata failed the broker's secret canary scan".to_string(),
            ));
        }
    }
    Ok(())
}

fn sanitize_stderr_diagnostic(stderr_text: &str) -> String {
    let collapsed = stderr_text
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, ' ' | '\t'))
        .collect::<String>();
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        return "no stderr output".to_string();
    }
    let mut out = String::new();
    for ch in trimmed.chars().take(MAX_STDERR_DIAGNOSTIC_CHARS) {
        out.push(ch);
    }
    if trimmed.chars().count() > MAX_STDERR_DIAGNOSTIC_CHARS {
        out.push_str("...");
    }
    out
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
