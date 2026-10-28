# Local forensic AI copilot architecture

Status: foundation implemented; inference integration remains design-only. The
copilot is optional and must not be used as an evidence parser or as an
authority for forensic conclusions.

An experimental `llama.cpp` CLI bridge is retained in source behind the
non-default `llama-runtime` Cargo feature for continued hardening. Normal and
forensic test builds do not compile or expose it. It is not a product feature:
it has no runtime tests, no OS-enforced memory limit, and no Windows Job Object
or equivalent network/filesystem sandbox yet.

### Current implementation boundary

The `kdft-ai-broker` crate currently implements and tests:

- bounded parsing and verification of a hash-pinned installed-model manifest,
  every declared model/license file, and a hash-pinned local runtime file;
- immutable Hugging Face revision validation, normalized relative model paths,
  symlink/traversal rejection, adapter/format compatibility, and explicit
  recognized-versus-examiner-acknowledged license state;
- strict typed retrieval envelopes with 200-row, 64-KiB context, and 32-KiB
  per-item ceilings; frozen-generation cursors; exact coverage reconciliation;
  and fail-closed typed-scope/identity checks;
- separate JSON contracts for the untrusted model-authored draft and the final
  broker-owned response, so a model cannot author canonical provenance;
- trusted examiner/request metadata separated from delimited, JSON-encoded
  `UNTRUSTED EVIDENCE DATA`, plus a defense-in-depth canary scan for several
  obvious secret forms and secret-bearing typed fields;
- broker resolution of opaque handles to bounded canonical artifact, parser,
  source-coordinate, and hash provenance, including truthful BitLocker logical
  coordinate limitations; and
- automatic partial/insufficient status and visible limitations when query,
  parser, omission, or truncation coverage is incomplete.

The following are **not implemented yet** and must not be represented as
available product features:

- no model download, model manager, Hugging Face token handling, or bundled
  model exists;
- no runtime is launched or version-probed in a default build, and no
  examiner-ready OS sandbox or network-deny policy is yet enforced around
  inference (the current verifier only hashes a selected runtime file and
  reports that limitation);
- no local runtime, coordinator, preflight resource probe, or inference audit
  ledger is wired into either UI; the feature-gated development bridge is not
  supported for case work;
- no case-database `TypedEvidenceTools` dispatcher or normalized-artifact query
  service is connected to this crate; callers currently construct already
  bounded/redacted projections; and
- the canary scan is not a complete secret-classification/redaction engine,
  renderer escaping remains a UI responsibility, and million-artifact/OOM/
  hostile-model validation gates have not yet been executed.

## Purpose

KDFT can add a local AI copilot without turning evidence into an unbounded chat
prompt or silently sending case material to a third party. The copilot helps an
examiner ask questions, summarize already-decoded artifacts, explore a timeline,
and draft findings. The artifact parsers, normalized artifact store, hashes,
coordinates, and examiner remain authoritative.

The same copilot core serves both a future native desktop shell and the existing
browser workbench. The front end is replaceable; the evidence, query, provenance,
and inference boundaries are not.

## Non-negotiable invariants

1. **Local by default and by construction.** Inference uses a local child
   process. Official forensic builds contain no remote-inference adapter. Model
   download is a separate, examiner-initiated operation and is the only feature
   in this subsystem permitted to use the network.
2. **No direct model access to evidence.** The runtime cannot open the case
   database, evidence images, exported files, or recovery credentials. KDFT
   passes only bounded context through the broker.
3. **No parser-by-prompt.** An LLM does not replace EVTX, registry, browser,
   NTFS, or other deterministic parsers. It reasons over normalized artifacts
   emitted by versioned parsers.
4. **Every evidential claim is grounded.** Claims reference citation handles.
   KDFT resolves each handle to the canonical artifact id, source entry/path,
   coordinate system, coordinates, source hash when available, and parser
   execution provenance. The model is not trusted to reproduce those fields.
5. **Fact and inference are visibly different.** The UI and exports label
   observations, deterministic derivations, model inferences, hypotheses, and
   limitations separately.
6. **Coverage is part of every answer.** The response states the selected
   scope, eligible and retrieved counts, incomplete parser jobs, truncation,
   and omitted records. "No evidence found" is allowed only when the relevant
   query completed over the declared scope.
7. **No silent truncation.** Token, row, byte, or time limits produce a visible
   partial-results banner and machine-readable coverage fields.
8. **Secrets never enter the prompt.** Recovery keys, passwords, authentication
   tokens, raw cookies, and equivalent secrets are removed before context
   construction. Secret-bearing values require an explicit specialized viewer,
   not the general copilot.
9. **Model output is untrusted data.** It is schema-validated, citation-checked,
   escaped for display, and never executed as SQL, shell, code, or a filesystem
   path.
10. **Examiner control is mandatory.** The model may propose bookmarks,
    findings, or report text, but only an examiner action can persist or export
    them as case work product.

## Relationship to the KDFT evidence model

The copilot consumes `semantic_artifacts`, not arbitrary rows from
`filesystem_entries`. A context item is assembled from:

- `semantic_artifacts.id`, kind, record key, display name, canonical time, and
  typed attributes;
- `artifact_source_coordinates`, including the exact named coordinate system;
- `parser_executions`, including parser name/version/schema, executable hash
  when applicable, status, and diagnostics;
- category memberships and classification confidence;
- the evidence and parser coverage records for the selected case scope.

For a decrypted BitLocker volume, a plaintext logical coordinate remains
`decrypted_bitlocker_volume_logical_bytes`. It is not converted to an encrypted
media offset. The citation must explicitly say that a physical ciphertext
offset is unavailable when that is the truth.

Raw filesystem objects can be shown as **source candidates** but cannot be
described as decoded artifacts. For example, an `.etl` source file is not a
decoded Windows event, and a file named `manifest.db` is not an iOS backup
without the required structure and parser validation.

## Process architecture

```text
native desktop UI / existing browser UI
                  |
                  v
        CopilotCoordinator (Rust)
          |       |         |
          |       |         +--> audit metadata (no raw transcript by default)
          |       +------------> ResponseValidator + CitationResolver
          v
    TypedEvidenceTools -----------------> read-only case connection
          |
          v
   ContextPackBuilder (bounded, redacted, coverage-aware)
          |
          v
     LocalRuntimeAdapter
          |
          v
 sandboxed local inference child process (no evidence-file permission)
```

### `CopilotCoordinator`

The coordinator owns a request state machine:

1. freeze a case generation and examiner-selected scope;
2. classify the request into a supported workflow;
3. execute only allow-listed, typed, read-only tools;
4. build a bounded context pack and coverage statement;
5. request schema-constrained output from the local runtime;
6. validate every claim and citation handle;
7. resolve canonical provenance from the database;
8. render labels, citations, coverage, and limitations;
9. retain the conversation in memory unless the examiner explicitly saves it.

Cancellation propagates through query, context building, and inference. A
request that outlives its case generation is cancelled and must be rerun; it
must not combine pages from two generations.

### Typed evidence tools

The model never sends SQL and never supplies an operating-system path. Initial
read-only tools are:

| Tool | Purpose | Mandatory bounds |
| --- | --- | --- |
| `coverage.get` | Parser status, omissions, and source coverage | One frozen case generation |
| `artifact.search` | Typed filters over normalized artifacts | Keyset paging; maximum rows and fields |
| `artifact.get` | Fetch one artifact and canonical provenance | Existing artifact id only |
| `artifact.aggregate` | Counts/groups/time buckets | Declared dimensions and maximum buckets |
| `timeline.query` | Time-bounded artifact query | UTC range, kinds, deterministic sort |
| `parser_execution.get` | Parser identity and diagnostics | Existing execution id only |
| `source.read_bounded` | Optional raw corroboration | Explicit examiner action, byte cap, no secrets |

The tool dispatcher deserializes arguments into Rust types and rejects unknown
fields, SQL fragments, path traversal, arbitrary category names, excessive
limits, and stale cursors. Tool results receive opaque citation handles such as
`ctx-000014`; only KDFT can map a handle back to a case row.

Write operations are deliberately absent. `Bookmark`, `Save as finding`, and
`Add to report` are ordinary UI actions requiring examiner confirmation after
the answer has rendered.

### Retrieval and context packs

Large cases are never materialized in RAM for AI. Retrieval uses normalized,
indexed, paged queries and streams only the selected projection into a context
budget. Version 1 should use deterministic field and full-text search. Optional
local embeddings can follow only after the normalized artifact pipeline is
stable.

A context pack contains:

- request id, case generation, scope, and display timezone;
- parser coverage and omissions before any artifact text;
- a schema version and a statement that evidence text is untrusted data;
- compact artifact records, each prefixed by its citation handle;
- deterministic aggregates computed by KDFT, not estimated by the model;
- row/byte/token counts, sampling method, and truncation reason;
- the response JSON schema and workflow-specific instructions.

Default limits are configuration, not hidden behavior. A sensible starting
profile is 200 result rows, 64 KiB of decoded text, 32 KiB from any one source,
and no raw-byte read without a second examiner action. The UI must show those
actual limits. Raising them does not remove the requirement to disclose
coverage.

When all matching records do not fit, KDFT should first provide exact
aggregates, then deterministic samples ordered by a declared tuple such as
`(artifact_time_utc, id)`. It must not claim a random or first-page sample is
representative.

### Fact, inference, and hypothesis labels

Each response claim has one of these kinds:

- `observed_fact`: a field or relationship directly present in cited artifacts;
- `derived_fact`: a deterministic KDFT calculation, with method and inputs;
- `model_inference`: a plausible interpretation requiring examiner judgment;
- `hypothesis`: a lead and proposed validation steps, never a conclusion;
- `limitation`: missing, failed, unsupported, or truncated coverage.

Observed and derived facts are not assigned probabilistic model confidence.
Inference and hypothesis claims carry `low`, `medium`, or `high` model
confidence, which is not parser confidence and is never presented as a
probability. All evidential claims require at least one verified citation.

The renderer uses the structured claims as the source of truth. It does not
accept an uncited free-form essay from the model. A response with a nonexistent
artifact id, an out-of-scope handle, a mismatched case generation, or an
unsupported claim is rejected or reduced to a limitation.

The untrusted model output contract is defined separately in
[`schemas/forensic-ai-model-draft.schema.json`](schemas/forensic-ai-model-draft.schema.json).
The final broker-owned response envelope is defined in
[`schemas/forensic-ai-response.schema.json`](schemas/forensic-ai-response.schema.json).
The model emits only claim text and opaque citation handles; the broker adds canonical
`resolved_citations` after validation. Canonical path, coordinate, and parser
fields therefore cannot be forged by the model.

## Local runtime boundary

Define a narrow adapter instead of linking the first model runtime throughout
the application:

```rust
trait LocalInferenceRuntime {
    fn probe(&self) -> Result<RuntimeCapabilities>;
    fn load(&mut self, model: &InstalledModel, limits: RuntimeLimits) -> Result<()>;
    fn generate_json(
        &mut self,
        request: GroundedChatRequest,
        response_schema: &serde_json::Value,
        cancel: &CancellationToken,
    ) -> Result<RuntimeResponse>;
    fn unload(&mut self) -> Result<()>;
}
```

The adapter records runtime name/version, executable SHA-256, model manifest
digest, model-file SHA-256, prompt-template digest, sampling settings, seed,
context limit, and response-schema version for every request. It records no
recovery credential and no raw evidence excerpt in the audit log.

### Recommended first runtime: `llama.cpp`

`llama.cpp` is the best first adapter because it is MIT-licensed, supports
local CPU/GPU inference, requires GGUF model files, provides builds/install
paths for Windows, macOS, and Linux, and its local server exposes compatible
chat routes plus schema-constrained JSON output. See the official
[`llama.cpp` README](https://github.com/ggml-org/llama.cpp/blob/master/README.md),
[`llama-server` documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md),
[model-format documentation](https://github.com/ggml-org/llama.cpp/blob/master/docs/models.md),
[platform installation table](https://github.com/ggml-org/llama.cpp/blob/master/docs/install.md),
and [MIT license](https://github.com/ggml-org/llama.cpp/blob/master/LICENSE).

KDFT must launch a pinned, hash-verified executable with a verified local model
path. It must not use the runtime's `-hf` download option during inference.
Network download belongs only to the Model Manager described below. Bind an
HTTP-based child to `127.0.0.1` on a random port, never `0.0.0.0`, and place a
KDFT-owned broker in front of it. Prefer authenticated stdio, a named pipe, or
a Unix-domain socket if the selected runtime exposes one in a stable release.

The runtime child receives prompt bytes but no case-file path. Use platform
sandboxing where available:

- Windows: restricted token, Job Object limits, and no inherited handles;
- macOS: hardened runtime/sandbox profile and no case-directory entitlement;
- Linux: separate process with namespace/seccomp restrictions and a read-only
  model directory.

The CPU build is the baseline. Hardware-specific CUDA, Vulkan, Metal, HIP, or
other bundles are optional runtime packages and not a different KDFT evidence
format. Model execution can crash or be killed without corrupting the case.

### Additional adapters

- **[ONNX Runtime GenAI](https://github.com/microsoft/onnxruntime-genai)** can
  be investigated after the GGUF path. Its upstream project is MIT-licensed,
  but it uses a different model packaging and hardware matrix. Do not introduce
  it until the same schema/citation tests pass.
- **Ollama** may be a developer convenience adapter, not the production
  default. Its official local API does not require authentication, so KDFT
  cannot assume it is private from other local processes. Cloud-capable model
  names and sign-in behavior also make a strict offline allow-list essential.
  See its [OpenAPI server definition](https://github.com/ollama/ollama/blob/main/docs/openapi.yaml),
  [authentication documentation](https://github.com/ollama/ollama/blob/main/docs/api/authentication.mdx),
  and [MIT license](https://github.com/ollama/ollama/blob/main/LICENSE).

An adapter advertising a remote base URL is rejected by forensic builds. A
future remote-analysis feature, if ever added, must be a different product mode
with a persistent warning, explicit per-request authorization, data minimization,
and audit evidence. It must never be enabled by a model setting alone.

## Model Manager and Hugging Face downloads

"GPT" is used here only as a generic chatbot description. OpenAI GPT model
weights are not assumed to be downloadable. KDFT supports compatible
**open-weight instruction models** whose actual weight license permits the
examiner's use and distribution scenario.

The Model Manager is disabled until an examiner opens it and chooses either:

1. **Import local model**: select an existing GGUF file; or
2. **Download from Hugging Face**: select a repository, immutable commit
   revision, exact allow-listed files, and destination.

Download and inference are separate processes. The manager:

- fetches the repository metadata and model card before weights;
- requires a recognized license id or an examiner acknowledgement of a custom
  license;
- pins a full commit hash, never mutable `main` alone;
- downloads only declared files and verifies SHA-256 and expected size;
- stores the model outside the case and writes an installed-model manifest;
- retains the model card and license text/digests with that manifest;
- uses the OS credential store for a Hugging Face token and never a case DB;
- supports import/export of a manifest for an air-gapped workstation;
- switches inference to offline mode after installation.

Hugging Face documents commit-aware caching and failure for incomplete offline
snapshots in its [cache guide](https://huggingface.co/docs/huggingface_hub/en/guides/manage-cache).
Its `HF_HUB_OFFLINE=1` setting disables Hub HTTP calls and restricts access to
cached material, as documented in the official
[environment-variable reference](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables).
Model cards can declare licenses, libraries, base models, and evaluation
metadata; KDFT must preserve but independently validate those fields. See the
official [model-card documentation](https://huggingface.co/docs/hub/model-cards).

The license of the runtime does not license the weights. Every installed model
manifest records at least:

- Hub repository id and immutable revision, or `local_import`;
- exact relative filenames, sizes, and SHA-256 digests;
- GGUF architecture, quantization, and declared context length;
- model-card and license-text hashes;
- declared license id/link and acceptance timestamp;
- compatible runtime adapter and minimum tested version;
- installation source and verification status.

The concrete installed-model manifest contract is defined in
[`schemas/local-model-manifest.schema.json`](schemas/local-model-manifest.schema.json).
Paths in that manifest are relative to the managed model directory; an imported
model's former absolute path is not persisted.

KDFT is Apache-2.0. MIT runtime code is generally compatible when required
notices are preserved, but model licenses vary and must not be treated as
Apache-2.0 merely because the files are hosted on Hugging Face. Bundled runtime
components and model weights require entries in `THIRD_PARTY_NOTICES` or an
equivalent installed-components ledger.

## Network and privacy controls

The AI subsystem has three explicit states:

- `disabled`: no runtime process and no model loaded;
- `local_offline`: local runtime loaded; all AI-network operations denied;
- `model_download`: a foreground examiner-authorized download with visible
  repository, revision, file list, size, and destination.

There is no automatic transition from `local_offline` to `model_download`.
Inference fails closed if a selected model is absent. It does not fetch a model,
tokenizer, template, adapter, or update in the background.

The UI always displays `LOCAL INFERENCE`, model id, model digest prefix,
runtime version, and offline status. Any inability to enforce offline mode is a
blocking error, not a dismissible warning.

Conversation history is memory-only by default. The audit trail stores request
id, timestamp, case generation, scope, tool names and canonical arguments,
artifact ids, coverage, model/runtime/prompt/schema digests, response hash,
validation outcome, and timings. It does not store raw evidence excerpts or
the free-form transcript unless the examiner explicitly saves the answer as a
case note or finding.

## Resource isolation and large-case behavior

AI must not bring browser-style case materialization into the native app. The
desktop UI, case query service, and model runtime are separate processes or
bounded components:

- SQLite pages and artifact projections are streamed; a million-row case is
  not a million-row JavaScript object;
- one configurable inference request runs per local model slot by default;
- a preflight check estimates model weights, KV cache, prompt buffers, and
  safety headroom before load;
- memory and CPU/GPU limits are shown before the examiner starts the model;
- the runtime can unload after an idle period without closing the case;
- model OOM or termination becomes an AI diagnostic, not a case failure;
- context length is a presentation/reasoning limit, never an artifact-query
  limit;
- retrieval resumes by deterministic cursor, but a single answer discloses the
  exact pages and counts it used.

Suggested hardware profiles are selected from measured runtime probes rather
than hard-coded marketing names. A small quantized instruct model can provide a
low-memory baseline; larger models are optional. KDFT must benchmark each
approved model/runtime pair before calling it supported.

## Prompt-injection and hostile-model controls

Evidence can contain web pages, emails, scripts, or documents telling an AI to
ignore instructions. Context records are delimited and marked `UNTRUSTED
EVIDENCE DATA`. Text from evidence never becomes a system or developer message.

The model cannot:

- add tools or change their schemas;
- run shell commands, code, SQL, or URLs;
- choose a remote runtime;
- read arbitrary offsets or files;
- persist a bookmark, finding, or report;
- assert a canonical path/offset/parser identity without broker resolution.

The runtime and model files are also untrusted inputs. Verify their hashes,
parse manifests before load, cap model/context dimensions, use a sandboxed
child, and provide a kill timeout. A malformed model must not share address
space with evidence parsers in the first implementation.

## User workflows

### Ask about selected artifacts

The examiner selects records, then asks a question. Scope is the explicit id
set. KDFT can truthfully say it examined all selected artifacts when every id
was retrieved and validated.

### Ask about a category or time range

The scope is a frozen typed query. KDFT computes counts and coverage first,
retrieves a deterministic subset within limits, and renders a prominent banner
if the answer did not use all matching records.

### Draft an incident finding

The model returns labeled claims and suggested validation steps. KDFT renders
citations and coverage. The examiner edits the draft and explicitly saves it.
The saved finding records the response envelope hash, model manifest, and cited
artifact ids, while the finding remains examiner-authored work product.

### Explain an artifact

Definitions and parser field descriptions should come from versioned local KDFT
documentation, not model memory. Evidence-specific statements still require
artifact citations.

## Phased implementation

### Phase 0 — contracts and a non-AI demonstrator

- Adopt the response schema and citation-handle rules.
- Implement typed read-only tools over `semantic_artifacts`.
- Build context packs, coverage statements, canonical citation resolution, and
  the fact/inference renderer.
- Use a deterministic fake runtime in tests; do not download a model.

Exit gate: a forged or missing citation cannot reach the UI, and incomplete
coverage is always visible.

### Phase 1 — local GGUF runtime

- Add the `LocalInferenceRuntime` boundary and a pinned `llama.cpp` process
  adapter.
- Add hardware probing, resource limits, cancellation, crash isolation, and
  schema-constrained generation.
- Add local-file model import and installed-model manifests.

Exit gate: Windows, macOS, and Linux smoke tests run completely offline and
produce the same validated envelope shape.

### Phase 2 — explicit Model Manager download

- Add Hugging Face metadata/license review, immutable revision pinning,
  allow-listed download, progress, cancellation, and hash verification.
- Add air-gap manifest import/export and `local_offline` enforcement.
- Populate third-party notices for any bundled runtime.

Exit gate: packet-capture tests show zero network during inference, and an
incomplete or hash-mismatched model cannot load.

### Phase 3 — examiner workflows

- Add selected-artifact, category/time-range, timeline, and report-draft modes.
- Add explicit save/bookmark/report actions outside the model tool set.
- Add local full-text retrieval and parser-documentation lookup.

Exit gate: answers remain bounded and responsive on a million-artifact fixture,
with counts and truncation reconciling to the underlying query.

### Phase 4 — optional local embeddings and model qualification

- Add a replaceable, model-versioned derived embedding index.
- Keep exact keyword/field filters available and show which retriever selected
  each item.
- Qualify approved model/runtime/quantization profiles against the forensic
  evaluation suite.

Exit gate: embedding removal/rebuild never changes canonical artifacts, and no
unsupported model is labeled examiner-ready.

## Required tests and evaluations

### Contract and security tests

- Reject unknown artifact ids, out-of-scope handles, stale case generations,
  and model-authored canonical provenance.
- Require citations for every observed fact, derived fact, inference, and
  hypothesis.
- Preserve exact coordinate-system labels, including decrypted BitLocker
  logical coordinates and explicit physical-offset unavailability.
- Redact recovery keys, passwords, tokens, and cookies from prompts, diagnostics,
  audit records, crash reports, and saved answers.
- Treat evidence text containing prompt-injection instructions as data.
- Reject model tool calls containing SQL, paths, URLs, unknown fields, or limits
  beyond policy.
- Escape Markdown/HTML and never execute model output.
- Kill a hung runtime and prove the case database remains valid.

### Grounding evaluations

Maintain a versioned corpus of examiner questions with expected artifact ids,
fields, coordinates, parser executions, and acceptable claim kinds. Include:

- browser visits/downloads with synchronized and local-origin records;
- EVTX records versus ETL source containers;
- UserAssist, Shellbags, Services, Accounts, AmCache, MFT/USN, LNK, Prefetch,
  Jump Lists, and registry values;
- deleted/recovered artifacts;
- conflicting timestamps and time-zone conversions;
- decrypted BitLocker logical coordinates;
- an empty result with complete coverage;
- an empty result with incomplete parser coverage;
- adversarial email/web/document content containing fake instructions and fake
  citation ids.

Release metrics include:

- 100% of displayed evidential claims have broker-verified citations;
- 0 accepted citations resolve outside the frozen request scope;
- 0 network connections during offline inference;
- 0 secrets in a seeded canary scan of prompts/logs/reports;
- exact reconciliation of eligible, retrieved, omitted, and displayed counts;
- claim-kind accuracy and examiner-rated usefulness reported per model profile;
- unsupported-answer rate rather than rewarding plausible hallucinations.

### Resource and cross-platform tests

- Run the same fixture on supported Windows, macOS, and Linux packages.
- Exercise CPU-only operation and each advertised accelerator bundle.
- Verify preflight refusal under insufficient memory and clean recovery after
  runtime OOM/termination.
- Verify bounded resident memory while querying at least one million normalized
  artifacts.
- Verify cancellation during query, prompt construction, first-token wait, and
  streaming generation.
- Verify model unload removes the child process and releases file handles so the
  model directory can be updated or removed.

## Definition of examiner-ready

The copilot is examiner-ready only when it can answer a supported question with
broker-verified citations and complete coverage disclosure, while fully offline,
and an independent examiner can follow each citation through artifact id, path,
coordinate system, parser execution, and source evidence. Fluency, model size,
or a convincing narrative cannot substitute for that chain.
