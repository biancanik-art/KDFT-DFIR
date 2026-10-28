# Forensic parser adapter architecture

Status: implementation design
Audit date: 2026-10-15
Scope: Registry, NTFS metadata, EVTX, LNK, and desktop browser artifacts

## Decision

KDFT should keep its native parsers as the primary evidence readers and add
locked, offline adapters for specialist parsers. Imported results must not be
flattened into filename categories or represented as physical offsets when the
upstream format does not expose one. Every observation must retain its parser,
input hash, output hash, coordinate system, and derivation.

The first implementation wave is:

1. **MFTECmd structured adapter** for `$MFT`, `$J`, `$LogFile`, `$Boot`, and
   `$SDS`.
2. **RECmd/RLA structured adapter** for semantic Registry artifacts and
   transaction-log-aware replay.
3. **EvtxECmd adapter migration and hardening** using the common runner and
   provenance contract.

LECmd is fourth. Browser normalization follows before adding another external
browser parser. RegRipper may remain an optional, examiner-supplied comparison
tool, but its license prevents redistribution or code reuse in KDFT.

## Evidence rules

- A source byte offset is useful only with a named coordinate system. Examples
  include `standalone_mft_source_stream`, `registry_hive_file`, and
  `decrypted_partition_logical`.
- Never manufacture a physical-disk offset. A SQLite row ID, EVTX event record
  ID, Registry cell offset, and MFT file-record offset are different kinds of
  coordinates.
- An artifact is an observation produced by a parser. Native and external
  observations of the same source object remain independently auditable and
  are linked by an explicit agreement/conflict record; they are not silently
  merged or double-counted.
- Parsers run on staged, hashed copies. They never update themselves, download
  maps, or access the evidence source directly.
- Parser absence or failure must not disable native processing.
- Classification confidence is separate from parser confidence. A file merely
  named `manifest.db`, for example, is not an iOS backup without confirming the
  schema and backup layout.

## Current-state audit

| Domain | Current implementation | What is already usable | Gaps and risks |
| --- | --- | --- | --- |
| Registry | `notatin 1.0.1` plus KDFT derivations; optional RegRipper line importer | Allocated key/value records, key last-write time, value type/data, hive-relative key/value offsets; Amcache, UserAssist, Shellbags, RecentDocs, RunMRU, TypedPaths, search queries, network drives, MountPoints, MUI cache, startup, Shimcache, and SRUM derivations | No native transaction-log replay or deleted/slack recovery. RegRipper stdout is imported as untyped lines and is not suitable as the canonical artifact model. Semantic result provenance needs a normalized schema. |
| NTFS metadata | `mft 0.7.0`, `ntfs 0.4.0`, and KDFT standalone `$MFT` reconstruction | Allocated/deleted file records, standard-information and file-name timestamps, parent references, path reconstruction, resident data, file-record stream offsets, and explicit coordinate metadata | Broader `$J`, `$LogFile`, `$Boot`, and `$SDS` semantics need a specialist adapter. Non-resident extents and physical offsets must remain explicit and non-invented, especially for decrypted BitLocker logical views. |
| EVTX | `evtx 0.12.2`; optional EvtxECmd JSON enrichment | Event record ID, time, event ID, provider, channel, computer, user/process/correlation fields, payload fields, and rendered JSON | Existing adapter has binary hashing and bounded execution but lacks a locked allowlist, version/companion-map hashing, and shared run manifest. Native parsing does not expose a reliable record byte offset, so event-record ID/chunk coordinates must be used honestly. ETL is a different format and is not parsed by this adapter. |
| LNK | KDFT native `lnk.rs` | Header times, target size/flags, VolumeID/serial/label, local/network paths, strings/arguments, tracker machine and Droid GUIDs, ExtraData inventory, canonical target, and section-relative source offsets | PropertyStore values and some shell-item payloads remain structural rather than semantic. LECmd is appropriate for cross-validation and enrichment. |
| Chromium/Firefox/Safari | `rusqlite 0.31`, `chrome-cache-parser 0.2.5`, KDFT profile parsers | Chromium visits, URLs, searches, downloads/chains, bookmarks, preferences, omnibox, autofill, login summaries, cookies, cache, and sync/origin fields; Firefox visits, URLs, bookmarks, form/search, downloads, logins, cookies; Safari visits/URLs | Normalize source DB/WAL hashes, table/schema, row ID/primary key, profile/device-origin fields, and import status. These are logical database coordinates, not evidence-byte offsets. Safari bookmark/download plist support is incomplete. Sensitive values should remain controlled and not be blindly imported from another tool. |

The native dependency licenses currently declared or resolved by this tree are
compatible with KDFT's Apache-2.0 distribution: `evtx` and `mft` are
MIT/Apache-2.0, `notatin` is Apache-2.0, `ntfs` and
`chrome-cache-parser` are MIT OR Apache-2.0, and `rusqlite` is MIT.

## Adapter boundary

The adapter subsystem should live below case orchestration and above individual
tool importers:

```text
evidence reader
  -> source detector
  -> private staging directory + companion discovery
  -> SHA-256 input manifest
  -> locked adapter selection
  -> offline bounded process runner
  -> raw output capture + SHA-256 output manifest
  -> streaming tool-specific importer
  -> normalized observations and coordinates
  -> native/external reconciliation
  -> UI/search/timeline/report projections
```

Suggested modules:

```text
crates/kdft-case/src/adapters/
  mod.rs
  contract.rs
  runner.rs
  lockfile.rs
  reconcile.rs
  mftecmd.rs
  recmd.rs
  evtxecmd.rs
  lecmd.rs
schemas/parser-tool-lock.schema.json
```

Do not make tool-specific columns part of the generic runner. The runner owns
staging, resource limits, execution, capture, and provenance. Each importer owns
detection, command construction, schema validation, field mapping, and
coordinates.

### Rust contract sketch

```rust
pub trait ParserAdapter: Send + Sync {
    fn descriptor(&self) -> &'static AdapterDescriptor;
    fn detect(&self, source: &SourceObject) -> Result<Detection>;
    fn stage(&self, source: &SourceObject, ctx: &StageContext)
        -> Result<StagedInputs>;
    fn command(&self, staged: &StagedInputs, output: &Path)
        -> Result<LockedCommand>;
    fn import(&self, run: &CompletedRun, sink: &mut dyn ObservationSink)
        -> Result<ImportSummary>;
}

pub struct ToolLock {
    pub adapter_id: String,
    pub parser_version: String,
    pub source_repository: String,
    pub source_commit: String,
    pub executable_sha256: String,
    pub companion_sha256: BTreeMap<String, String>,
    pub allowed_argument_prefixes: Vec<String>,
    pub network_allowed: bool,
}

pub struct ParserRunManifest {
    pub run_id: Uuid,
    pub adapter_id: String,
    pub parser_version_reported: Option<String>,
    pub executable_path: PathBuf,
    pub executable_sha256: String,
    pub companion_sha256: BTreeMap<String, String>,
    pub input_sha256: BTreeMap<String, String>,
    pub argv: Vec<String>,
    pub working_directory: PathBuf,
    pub started_utc: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub output_sha256: BTreeMap<String, String>,
    pub importer_schema: String,
    pub diagnostics: Vec<String>,
}

pub struct ArtifactCoordinate {
    pub coordinate_system: String,
    pub container_source_object_id: Uuid,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub record_id: Option<String>,
    pub extent_index: Option<u32>,
    pub derivation: String,
    pub quality: CoordinateQuality, // Exact, Derived, IdentifierOnly, Unavailable
    pub verified: bool,
    pub unavailable_reason: Option<String>,
}
```

`LockedCommand` must contain a program path and an argument vector, never a
shell string. It should reject unrecognized switches before launch.

## Runner hardening

The existing `external_tools.rs` already avoids shell invocation, computes an
executable SHA-256, applies a timeout, and bounds captured output. The common
runner should retain those properties and add:

1. An explicit tool lock. PATH discovery may be offered for setup, but an
   executable is not runnable until the examiner accepts and records its hash.
2. Parser version capture and comparison with the locked version.
3. Hashing of maps, batch files, DLLs, templates, and other tool inputs that can
   change the result.
4. A fresh per-run staging/output directory with restrictive permissions.
5. A minimal environment and a declared `network_allowed: false` policy. Never
   pass `--sync` or any updater option during evidence processing.
6. Tool-specific time, memory, stdout/stderr, output-file-count, and
   output-byte limits. Ten minutes is not appropriate for every disk artifact.
7. Process-tree termination on timeout/cancel.
8. Streaming import with schema and row-count validation; never load an
   unbounded JSON result wholly into memory.
9. Preservation of raw parser output and logs, hashed and linked to the run.
10. A failure state that leaves native observations intact and makes incomplete
    coverage visible in the UI/report.

## Normalized observation model

The physical database design should align with
`docs/normalized-artifact-query-design.md`. At minimum it needs:

- `source_objects`: evidence ID, canonical/internal path, source kind, size,
  SHA-256, parent/container relation, acquisition coordinate system.
- `parser_runs`: complete `ParserRunManifest` and coverage state.
- `artifacts`: stable observation ID, artifact kind/schema version, source
  object, parser run, deletion/recovery state, confidence, canonical display
  name, and searchable text.
- `artifact_fields`: typed name/value rows or validated schema payloads; raw
  and decoded values are separate fields.
- `artifact_times`: UTC value, original value, source field, semantics
  (`key_last_write`, `visit_time`, `standard_information_modified`, etc.),
  timezone basis, precision, and validation state.
- `artifact_coordinates`: one or more `ArtifactCoordinate` rows.
- `category_memberships`: rule ID/version and confidence. A category count is
  the count of current query results, not the unfiltered evidence total.
- `observation_links`: same-source/agreement/conflict links between native and
  external observations.
- `diagnostics`: parsing warnings, truncation, unsupported structures, and
  explicit unavailable reasons.

### Fields required for every observation

1. Artifact kind and schema version.
2. Exact source object path and SHA-256; relevant companion hashes.
3. Parser ID/version, executable/source identity, parser-run ID, and importer
   schema version.
4. Structured fields and separately generated search text.
5. Every time with field semantics, precision, and timezone basis.
6. Allocated/deleted/recovered status and how it was derived.
7. At least one source coordinate or an explicit reason why none is exposed.
8. Parser confidence and classification confidence as separate values.
9. Complete/incomplete/error coverage status.

## Domain contracts

### NTFS metadata

Required fields include file-record number and sequence, parent reference,
namespace, allocated/deleted/in-use state, flags, all available 0x10 and 0x30
timestamps, attribute type/ID/name, resident/non-resident state, logical and
allocated size, data-run/extents, reparse/security IDs, path candidates, and
path-reconstruction warnings.

Coordinates must distinguish:

- `standalone_mft_source_stream`: exact `record_number * record_size` when the
  source object is an exported `$MFT`.
- `ntfs_volume_logical`: logical cluster/byte extents inside an NTFS volume.
- `decrypted_partition_logical`: plaintext coordinates produced by a BitLocker
  reader; these are not claimed as one-to-one physical-image bytes.
- `evidence_physical`: only when independently mapped to the source image.

A resident value may point to a record-relative range after update-sequence
fixup only if the importer also retains the raw-source relationship and notes
that post-fixup bytes are a derived view. Non-resident content requires all
extents, not a single misleading offset.

### Registry

Required fields include hive type/path/hash, replay state and log hashes, key
path, value name/type, raw bytes or raw hash, decoded value, key last-write
time, allocated/deleted/recovered state, parser/plugin/rule name, and semantic
artifact schema. Coordinates are cell- or file-relative ranges in the staged
hive and must identify whether they refer to the key cell, value cell, value
data cell, or replayed/log-derived state. A replayed observation without a
stable base-hive byte range must say so.

Native generic keys/values and RECmd semantic artifacts are complementary. Do
not replace the generic view with plugin rows.

### EVTX

Required fields include source file/hash, event record ID, record number/ordinal
if exposed, time created, event ID, level, provider, channel, computer, user
SID/name, process/thread IDs, correlation IDs, keywords, map description, and
structured payload. Preserve the source XML/rendered JSON separately.

If a parser exposes verified chunk number or extra-data offset, retain it with
that exact coordinate name. Otherwise use event-record ID as
`IdentifierOnly`; do not label it a byte offset. `.etl` files are ETW trace
containers and must remain unparsed source objects until a separate ETL adapter
is validated.

### LNK

Required fields include LNK header fields and times, target size, local and
network target paths, relative/working/icon paths, arguments, VolumeID/serial/
label, network provider/share, tracker machine ID and Droid GUIDs, known-folder
and special-folder identifiers, property-store values, shell-item sequence,
ExtraData blocks, and parse warnings. Preserve source-file-relative section and
block offsets. LNK target paths are assertions stored in the link; they are not
proof the target still exists.

### Browser

Required source identity includes browser, profile, database/plist/cache source
hash, and WAL/journal hash. Record coordinates include table/schema and row ID
or primary-key tuple; optional SQLite page/cell coordinates may be retained only
when independently validated. Core fields include URL, title, visit time/type,
referrer/transition, download path/URL chain/state, search term, bookmark
folder, cookie domain/path/expiry/security flags, cache metadata, and
originator/device/sync fields such as Chromium visit source and originator cache
GUID.

Database row IDs are logical identifiers, not physical disk offsets. Password,
cookie, and token material requires a controlled sensitive-data schema and
access policy; a filename or GUID is not itself a credential.

## Compatibility and distribution matrix

| Component | Official source and audited reference | License | KDFT use | Redistribution decision |
| --- | --- | --- | --- | --- |
| KDFT native `mft 0.7.0` | Cargo lock/metadata; [omerbenamram/mft](https://github.com/omerbenamram/mft) | MIT OR Apache-2.0 | Native primary `$MFT` reader | Source/library integration allowed with notices |
| KDFT native `notatin 1.0.1` | Cargo lock/metadata; [strozfriedberg/notatin](https://github.com/strozfriedberg/notatin) | Apache-2.0 | Native primary Registry reader | Source/library integration allowed with notices |
| KDFT native `evtx 0.12.2` | Cargo lock/metadata; [omerbenamram/EVTX](https://github.com/omerbenamram/evtx) | MIT OR Apache-2.0 | Native primary EVTX reader | Source/library integration allowed with notices |
| KDFT native `ntfs 0.4.0` | Cargo lock/metadata; [ColinFinck/ntfs](https://github.com/ColinFinck/ntfs) | MIT OR Apache-2.0 | Filesystem metadata/stream access | Source/library integration allowed with notices |
| MFTECmd | [official repo](https://github.com/EricZimmerman/MFTECmd), source commit `6aadd87ae0526efca95dd5a59e62e186806cd4c8`, project version observed `2026.5.0` | MIT | Structured specialist adapter | Initially examiner-supplied external invocation. A curated toolpack is possible only after locking the built binary and all transitive notices/SBOM. |
| RECmd and RLA | [official repo](https://github.com/EricZimmerman/RECmd), source commit `bcd0ac33ed98de61ea6de551eef96052bddbbd49`, project version observed `2026.5.0` | MIT | Semantic Registry batch output and transaction-log replay | Initially examiner-supplied external invocation. Lock executable, batch/map, DLL, and license hashes. Curated redistribution only after transitive review/SBOM. |
| EvtxECmd | [official repo](https://github.com/EricZimmerman/evtx), source commit `03a7a1fba32760f20841bea3c12099169f9ecf2d`, project version observed `2026.5.0` | MIT | EVTX cross-validation and map enrichment | Existing examiner-supplied external model is appropriate; migrate to locked common runner. Curated redistribution requires dependency/SBOM review. |
| LECmd | [official repo](https://github.com/EricZimmerman/LECmd), source commit `e39bb495aa65c08f545dac4cecaee946e58704b4`, project version observed `2026.10.0` | MIT | LNK cross-validation and semantic enrichment | Initially examiner-supplied external invocation; curated redistribution only after locking binaries and transitive notices/SBOM. |
| RegRipper 4 | [official repo](https://github.com/keydet89/RegRipper4.0), source commit `f925c0965db202eed46071b3e68f6d3a49b41a31` | Restricted: official README limits use to personal/academic and prohibits vendor-product/vendor-training/distribution inclusion | Optional comparison only | **Do not redistribute, vendor, or copy code into KDFT.** Permit explicit examiner-supplied invocation only after showing the license scope. Disable by default. |
| Hindsight | [official repo](https://github.com/RyanDFIR/hindsight) | Apache-2.0 | Future browser cross-validation | External later. Review/pin Python dependency graph and sensitive-output handling before any bundle. Native browser parsing remains primary. |

The source commits above are audit anchors, not executable identities. KDFT must
record the SHA-256 of the exact executable installed by the examiner. Do not
guess or infer a release-binary hash from a source commit or version number.

## Tool lock and provenance

An accepted tool installation should create a case-independent lock entry such
as:

```json
{
  "adapter_id": "mftecmd-json-v1",
  "parser_name": "MFTECmd",
  "parser_version": "2026.5.0",
  "source_repository": "https://github.com/EricZimmerman/MFTECmd",
  "source_commit": "6aadd87ae0526efca95dd5a59e62e186806cd4c8",
  "executable_sha256": "REQUIRED_AT_INTAKE",
  "companion_sha256": {},
  "network_allowed": false,
  "allowed_arguments": ["-f", "--json", "--jsonf"]
}
```

The installation workflow computes the binary hash, obtains the reported
version, displays the license/source identity, and requires examiner acceptance.
At run time, a mismatch refuses external execution and records a diagnostic;
native analysis continues.

## First implementation wave

### 1. MFTECmd structured adapter

**Purpose.** Close the largest semantic gap for standalone NTFS metadata while
cross-validating native `$MFT` observations.

**Baseline command.** Run in a fresh private output directory:

```text
MFTECmd -f <staged-source> --json <output-directory> --jsonf mftecmd.json
```

Use separate run manifests for `$MFT`, `$J`, `$LogFile`, `$Boot`, and `$SDS`.
Discover source type by signature and content, not filename alone. Optional
flags, such as outputting all available 0x30 timestamp sets, belong in a
versioned adapter profile and its acceptance corpus rather than being silently
changed.

**Importer.** Stream JSON rows; validate required keys and type conversions;
map record/entry numbers, sequences, timestamps, attributes, paths, deleted
state, and data-run/extents into the domain contract. Preserve unknown upstream
fields in a namespaced payload. Record imported/rejected row counts and the raw
output hash.

**Reconciliation key.** Source hash + MFT entry/sequence + attribute identity,
with path only as a non-authoritative comparison field.

**Acceptance.** Corpus includes allocated, deleted, reused sequence, multiple
0x30 names, resident data, sparse/compressed/non-resident extents, orphaned
parents, malformed USA, and BitLocker logical-coordinate cases. Exact offsets
must agree where both parsers expose the same coordinate system.

### 2. RECmd/RLA structured adapter

**Purpose.** Add semantic Registry artifacts, log-aware recovery, and structured
plugin output without replacing the native key/value tree.

**Baseline semantic command.** Co-stage the hive and validated `.LOG1`, `.LOG2`,
and related transaction logs; hash each one. Run a locked, KDFT-reviewed batch:

```text
RECmd --f <staged-hive> --bn <locked-DFIRBatch.yaml> \
  --csv <output-directory> --csvf recmd.csv --recover true
```

Do not use `--sync`. Do not use `--nl` when replay is required. If standalone
RLA is needed for a damaged/replay scenario, make it a distinct run with its
own inputs, outputs, and derivation; never overwrite the staged original hive.

**Importer.** Parse RFC-compatible CSV defensively and retain at least hive
path/type, category, description, key path, value name/type/data fields,
deleted state, last-write time, plugin/rule, and recovery status. Hash the batch
file and any maps. A plugin result is a semantic observation linked to the
native key/value cells it cites; it is not a substitute for them.

**Reconciliation key.** Source hive hash + normalized key path + value name +
plugin/rule identity, with replay state included. Conflicts remain visible.

**Acceptance.** SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER.DAT/UsrClass.dat corpus;
valid and damaged transaction logs; allocated and recovered keys/values;
duplicate value names; binary/multi-string data; timezone-neutral timestamps;
known UserAssist, Shellbags, RecentDocs, RunMRU, TypedPaths, and Amcache cases.

### 3. EvtxECmd migration and hardening

**Purpose.** Preserve the existing useful enrichment while giving it the same
locking, companion-map, output, and reconciliation guarantees as new adapters.

**Current-compatible command.** Keep the existing offline shape:

```text
EvtxECmd -f <staged.evtx> --json <output-directory> \
  --jsonf kdft-evtxecmd.json --fj true
```

Never pass `--sync`. Hash the executable, every supplied map/template input,
the staged EVTX, and every output. Capture the reported version. Keep the native
`evtx` observation authoritative when enrichment cannot be matched.

**Importer/reconciliation.** Stream JSON; match source hash + event record ID.
Retain unmatched external-only observations with that provenance rather than
discarding them. Record duplicate IDs, missing IDs, parse failures, and map
coverage. Use event-record ID/chunk metadata as identifiers unless a verified
byte coordinate is actually exposed.

**Acceptance.** Corrupt chunks, duplicate/missing record IDs, provider payloads,
maps present/absent, very large logs, output truncation/timeout, and event-field
disagreement. Confirm `.etl` files are not mislabeled as parsed EVTX events.

## Next adapters

1. **LECmd JSON** after the first wave. Baseline:
   `LECmd -f <staged.lnk> --json <output-directory> --pretty --mp`. Import from a
   private output directory, hash the result, and match by staged source hash,
   not by the link target path.
2. **Browser normalization** before Hindsight. Finish uniform record coordinates,
   WAL/journal source identity, sync/origin fields, and sensitive-data handling.
3. **Hindsight external cross-validation** only after Python dependencies and
   output handling are pinned and reviewed.
4. **ETL adapter** as an independent project. ETL must not be routed through the
   EVTX category merely because both contain Windows events.

## Required tests and release gates

- A committed forensic corpus contains expected artifact counts, typed fields,
  timestamp semantics, source hashes, and coordinate-system-qualified offsets.
- Repeated runs with the same locked inputs produce the same imported canonical
  rows or a documented nondeterministic field exclusion.
- A binary, map, batch, DLL, or input hash mismatch prevents external execution.
- A missing external tool leaves native results available and reports partial
  cross-validation coverage.
- Malformed, enormous, or adversarial tool output is bounded and cannot inject
  UI markup, SQL, shell arguments, or a path outside the run directory.
- Output counts reconcile: emitted, imported, rejected, duplicated, and linked
  counts are reported separately. No full page or query result is silently
  truncated.
- Native/external disagreements are queryable and appear in the technical
  report.
- Every released bundled component has a license notice and SBOM entry. Tools
  marked examiner-supplied are absent from the distribution archive.
- Reports identify parser name/version/hash, rule or batch version/hash, source
  and companion hashes, arguments, time, exit status, coverage, and coordinate
  semantics.

This architecture makes external tools replaceable validation components while
keeping KDFT's evidence model, provenance, and examiner-facing conclusions
independent of any one vendor output.
