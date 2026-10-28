# KDFT forensic maturity roadmap

This roadmap turns the current filesystem-first index into an examiner-grade
artifact platform. It is deliberately additive: existing case files and raw
filesystem records remain readable while normalized artifacts are introduced.

## Evidence model

KDFT must keep four layers distinct:

1. **Evidence containers** — E01, raw images, VHD/VHDX, folders and standalone
   files, including verification hashes and acquisition identity.
2. **Filesystem objects** — volumes, files, directories, alternate streams,
   deleted records, unallocated ranges and filesystem metadata.
3. **Decoded forensic artifacts** — EVTX records, browser visits/downloads,
   registry-derived UserAssist/Shellbags/Services/Accounts, LNK, Prefetch,
   Jump Lists, MFT/USN records and similar typed records.
4. **Derived entities and findings** — people, accounts, hosts, devices, URLs,
   credentials *candidates*, correlations and examiner findings. Derived rows
   always link back to the decoded records that support them.

Counts and UI labels must identify which layer they describe. A source file or
candidate container is never counted as a decoded artifact merely because its
name or extension matched a rule.

## Mandatory provenance contract

Every decoded artifact records:

- case and evidence source identifiers;
- source filesystem entry and exact source path;
- source snapshot/restore-point identity when applicable;
- parser identifier, version, configuration fingerprint and execution id;
- parse status, diagnostics and recovery method;
- deleted/recovered state;
- typed fields plus canonical UTC timestamps and their original representation;
- a named coordinate system and coordinates appropriate to the source;
- confidence in parser success separately from confidence in classification.

Supported coordinate systems include decoded evidence-media bytes, partition
or volume logical bytes, decrypted BitLocker volume logical bytes, filesystem
record/attribute coordinates, and source-record coordinates such as EVTX record
ID or registry hive cell offset. KDFT must never relabel a decrypted logical
offset as an encrypted-media physical offset.

## Parser execution contract

Each processor is an independently auditable job with:

- supported input signatures and candidate-selection rules;
- an immutable configuration and tool/version manifest;
- processed, decoded, skipped, failed and omitted counts;
- bounded diagnostic samples plus the exact omitted-diagnostic count;
- deterministic replacement of records from the same source and parser version;
- cancellation and partial-coverage semantics;
- no silent record limit or output truncation.

External tools may be used only through explicit adapters. The adapter pins the
tool version and executable hash, records the command/options without secrets,
imports structured output, maps fields into KDFT's provenance contract, and
keeps evidence processing local. Source code is incorporated only when its
license is compatible and its notices and attribution requirements are met.

## Priority implementation sequence

### P0 — trustworthy byte access and storage

- Add normalized artifact, provenance, parser-execution and category-membership
  tables without removing `filesystem_entries`.
- Make every parser read through a source-aware byte provider.
- Support decrypted BitLocker NTFS reads for follow-up processors while the
  examiner-supplied credential remains memory-only.
- Preserve truthful decrypted-volume coordinates and explicit physical-offset
  unavailability.
- Replace JSON-scanning category queries with indexed, paged membership queries.

### P1 — core Windows and browser evidence

- Registry tree/value browsing with hive/key/value provenance.
- Semantic registry processors: accounts/profiles, Services, UserAssist,
  Shellbags, AmCache, ShimCache, MRUs, Run keys and mount points.
- Record-level EVTX parsing; ETL containers remain a separate artifact family.
- MFT, USN, `$LogFile`, LNK, Jump Lists, Prefetch and Scheduled Tasks.
- Chromium and Firefox visits, URLs, downloads, searches, cookies, bookmarks
  and sync-origin fields with original-device attribution where supported.

### P2 — examiner workflow

- Fast facets, date ranges, global field search and parser-aware filters.
- Artifact-detail views with decoded fields, raw source, diagnostics and exact
  provenance.
- Timeline filters and deterministic CSV/JSON/HTML/PDF exports.
- Report manifests that state evidence hashes, selected scope, parser coverage,
  omissions, timezone and all partial/failed processors.

### P3 — extended coverage

- Validated mobile-backup root detection (never filename-only `manifest.db`).
- Email, archive, document, cloud and application-database processors.
- Entity correlation and connection views with confidence and source back-links.

## Release gates

A release described as examiner-ready must pass all of these gates:

1. A supported parser fixture produces expected typed records and field values.
2. Each record resolves to its exact source and truthful coordinates.
3. Category counts reconcile with paged queries and exports.
4. Filters and exports do not silently omit later pages.
5. Parser failures are isolated and reported as partial coverage.
6. Existing cases migrate without destructive rewrites.
7. Credentials, recovery keys and decrypted plaintext are not persisted by
   default and never appear in logs, commands, reports or audit details.
