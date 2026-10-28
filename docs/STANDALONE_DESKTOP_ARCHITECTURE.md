# KDFT standalone desktop architecture

## Decision

KDFT will ship two front ends over one Rust application core:

- **KDFT Desktop** is the primary examiner application. Its first working
  shell is a fully native Rust `eframe`/`egui` executable that calls the case
  backend in process. It does not bind a TCP port or embed a browser.
- **KDFT Web Workbench** remains available for deployments that prefer the
  current loopback-only browser workflow.

Moving the window out of a general-purpose browser does not by itself make a
million-row case small. The memory fix is architectural: the UI must never own
the case. SQLite and bounded parser workers own data; every grid uses keyset
paging and virtualized rows; large bytes, metadata JSON, logs and previews are
loaded only for the selected record. The desktop shell then removes the extra
browser tabs, public HTTP surface and accidental full-response retention.

`kdft-desktop-core` is the transport-neutral application boundary. It opens an existing
case read-only, accepts typed commands directly, returns bounded pages, rejects
stale cursors, and attaches a coverage banner to every page. It contains no
HTTP server or GUI dependency. `kdft-desktop` is now a compile-tested native
client of that boundary, so adding it does not replace or destabilize the
current workbench.

## Current native checkpoint

The `kdft-desktop` workspace executable can be run from source with either a
native file chooser or an optional initial case path:

```text
cargo run -p kdft-desktop
cargo run -p kdft-desktop -- /path/to/case.kdft.sqlite
```

The implemented checkpoint:

- opens the case database through read-only/query-only SQLite connections;
- never starts localhost, HTTP, or a WebView;
- keeps at most one bounded 200-row artifact page in the GUI state;
- advances with generation-bound keyset cursors instead of row offsets;
- performs case and page reads on background threads so a locked or slow case
  does not freeze the native event loop;
- shows the conservative completeness/coverage banner above every result page;
- exposes the current page, loaded row count, snapshot generation, job status,
  stale-cursor errors, and retry guidance.

This is a functional development executable, not yet a signed release. Windows
compilation and bounded-page tests are automated in the current checkpoint;
macOS/Linux build jobs, application icons, signed installers, update metadata,
SBOM generation, and release smoke tests remain packaging gates.

## Process and crate layout

The target layout is:

```text
kdft-case                 evidence I/O, parsers, normalized artifact store
kdft-application          typed use-cases, job control, paged queries, exports
  |-- kdft-desktop-core   direct/private IPC adapter (foundation exists)
  |-- kdft-ui             loopback HTTP adapter (kept)
  `-- kdft-cli            command-line adapter (kept)

kdft-desktop              packaged shell and signed installers
kdft-parser-worker        isolated parser process with bounded memory/jobs
kdft-ai-worker            optional offline model process, disabled by default
```

Both front ends must call the same `kdft-application` commands. Business rules
must not be reimplemented in JavaScript, HTTP handlers or desktop callbacks.

## Desktop shell

The first shell uses `eframe`/`egui` with native operating-system windows and a
small OpenGL renderer. This avoids both a general-purpose browser and a WebView
IPC layer. The browser workbench remains available separately. A future
packaging review may still select Tauri/Wry for views where reusing packaged web
assets materially reduces migration risk, but it is no longer required for the
bounded artifact viewer.

The native executable is an application window, not an externally navigable
web server:

- no `127.0.0.1` listener;
- no remote navigation, developer tools or arbitrary shell commands in release
  builds;
- a native file dialog returns a path directly to Rust;
- evidence operations occur in Rust, never in the WebView;
- credentials and recovery keys are passed to one command, held only for the
  active operation and never serialized into UI state, logs or case data.

The existing HTML/CSS interaction design stays in the separate browser client.
Native high-volume views use native widgets over the same backend contract.

## Bounded data and RAM contract

Every collection command must declare and enforce a maximum page size. The
initial desktop foundation defaults to 200 rows and refuses more than 1,000.
It queries only display columns, fetches one extra row to prove continuation,
and never selects `content_head`, binary blobs, parser text or unrestricted
metadata JSON for a grid. Private IPC command envelopes are rejected above 64
KiB before JSON parsing.

Continuation is a keyset cursor plus the case mutation generation. If the case
changes, the backend rejects the cursor rather than mixing two snapshots.
Expensive totals and facets are separate indexed queries; they are never a
reason to materialize all matching rows. Exports are backend jobs over the
canonical query, not concatenated UI pages.

SQLite desktop read sessions use:

- read-only/query-only connections;
- short-lived stable transactions;
- a bounded page cache;
- no large memory map;
- file-backed temporary operations where a query cannot remain index-only.

Parser workers get explicit per-job byte, row, diagnostic and memory budgets.
One parser failure must not terminate the desktop process or invalidate already
committed results.

## Completeness and truncation

KDFT must never make a bounded response look like a bounded examination. Every
result view shows one of:

- **not processed** — no relevant parser execution exists;
- **in progress** — results may still change;
- **complete** — an explicit processor coverage plan exists and every required
  job completed without diagnostics;
- **partial** — a limit, unsupported source, cancellation, parser diagnostic
  or preserved prior generation exists;
- **failed** — processing produced no complete/partial result for the scope.

Merely seeing successful recorded jobs is not proof that every relevant parser
was requested, so the foundation conservatively remains partial until the
normalized execution store supplies that plan. The banner links to per-parser
coverage: processed, decoded, skipped, failed, omitted, limits, versions and
diagnostic details. UI pages may be paged but not silently truncated. A hard
result limit changes the evidence-processing status to partial and is carried
into exports and reports.

## Cross-platform packaging

CI produces signed/versioned artifacts from one source revision:

- Windows x64/arm64: MSI or MSIX plus portable ZIP;
- macOS arm64/x64: notarized DMG or PKG;
- Linux x64/arm64: AppImage plus distribution packages where maintained.

Each release publishes SHA-256 checksums, an SBOM, third-party notices, parser
and schema versions, and a reproducible build manifest. Native dependencies and
external parser adapters are installed per platform and capability-detected;
an unavailable parser is reported, never silently skipped.

## Offline AI boundary

The internal assistant is a later, optional worker—not a forensic parser and
not a dependency of opening a case. It may use an examiner-selected,
license-compatible GGUF model from a local path. KDFT records the model file
hash, runtime version and prompt template; it never downloads a model or sends
case content to a network service without an explicit separate feature and
examiner action.

The assistant receives retrieved, bounded artifact projections and must cite
artifact IDs, source records and parser provenance in every factual answer.
Its output is labelled **AI-generated examiner assistance**, is never promoted
to a finding automatically, and cannot claim a result is complete. Model
execution runs in `kdft-ai-worker` with resource limits and cancellation so a
large context or failed model cannot exhaust the case UI.

## Delivery sequence

1. Keep `kdft-ui` operational; land `kdft-desktop-core` paging/coverage tests.
2. Extract transport-neutral use-cases from `kdft-ui` into
   `kdft-application`; characterize old and new responses against the same
   case fixture.
3. Package a no-listener native shell using the private command bridge.
4. Move artifact/category/timeline views to normalized indexed queries and
   virtualized pages.
5. Add parser-worker isolation and release memory budgets.
6. Build and sign Windows, macOS and Linux packages.
7. Add the optional local AI worker only after provenance-linked retrieval,
   model licensing, resource controls and deterministic non-AI reports pass
   review.

## Acceptance gates for the first desktop release

- Opening a one-million-row fixture does not load one million Rust or UI row
  objects; a memory test verifies the bounded page contract.
- No listening socket exists in desktop mode.
- Every grid and export exposes completeness and parser coverage.
- Page cursors cannot mix case generations and exports cannot stop at a UI
  page boundary.
- Windows, macOS and Linux smoke tests open the same case and return identical
  record IDs and provenance.
- Browser and desktop adapters pass the same application-contract tests.
- Original evidence remains read-only and no credential or decrypted secret is
  persisted or logged.
