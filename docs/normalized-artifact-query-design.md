# Normalized artifact browsing and export design

## Problem

The workbench currently stores category fields inside each filesystem entry's
`metadata_json`. Category counts and category pages therefore require JSON
extraction over a case that can contain close to a million rows. The resulting
scan is slow, category counts describe source files and parser records
interchangeably, and a client-side export cannot prove that it exported the
same result set the examiner filtered.

This document defines the storage/query boundary that `kdft-ui::artifact_view`
is intended to consume. It does not alter an existing case schema yet.

## Separate source objects from semantic artifacts

`filesystem_entries` remains the canonical inventory of acquired containers
and filesystem objects. A `.evtx`, `.etl`, registry hive, browser database, or
`$MFT` is a source container, not automatically a parsed forensic artifact.

`semantic_artifacts` represents parser-emitted records such as an EVTX event,
browser visit, registry value, MFT record, shellbag, or UserAssist execution
record. Every artifact references a `parser_executions` row and reaches its
source container through one or more `artifact_source_coordinates` rows. It
records:

- a stable artifact kind and schema version;
- parser name, parser version, execution id, and parser status;
- display name and canonical artifact time;
- structured fields in a versioned payload;
- deleted/recovered state and confidence;
- exact source-coordinate system, offset/range or record identifier;
- provenance context when an exact byte coordinate is unavailable.

`semantic_categories` and `artifact_category_memberships` form the normalized
many-to-many taxonomy. Membership stores a stable `category_key`, classifier
version, confidence, and classification basis. This prevents an ETL container
from being presented as a decoded Windows event and allows one artifact to
appear in several examiner views without duplication.

The additive schema is owned by `kdft_case::semantic_artifacts`:

```sql
CREATE TABLE semantic_artifacts (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL,
    parser_execution_id INTEGER NOT NULL,
    artifact_kind TEXT NOT NULL,
    record_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    artifact_time_utc TEXT,
    attributes_json TEXT NOT NULL
);

CREATE TABLE artifact_source_coordinates (
    artifact_id INTEGER NOT NULL,
    source_entry_id INTEGER,
    coordinate_system TEXT NOT NULL,
    offset_bytes INTEGER,
    length_bytes INTEGER,
    record_identifier TEXT,
    provenance_json TEXT NOT NULL
);

CREATE TABLE artifact_category_memberships (
    artifact_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    classification_basis TEXT NOT NULL,
    classifier_name TEXT NOT NULL,
    classifier_version TEXT NOT NULL,
    PRIMARY KEY (artifact_id, category_id)
);
```

## Query and index contract

The category endpoint must query normalized columns first and join payload
fields only for the requested page. At minimum, indexes should cover:

```sql
CREATE INDEX ix_semantic_artifacts_evidence_kind_id
    ON semantic_artifacts(evidence_id, artifact_kind, id);
CREATE INDEX ix_semantic_artifacts_time
    ON semantic_artifacts(artifact_time_utc, id);
CREATE INDEX ix_artifact_source_coordinates_entry_artifact
    ON artifact_source_coordinates(source_entry_id, artifact_id);
CREATE INDEX ix_artifact_category_memberships_category_artifact
    ON artifact_category_memberships(category_id, artifact_id);
```

Frequently filtered fields such as event id/provider, URL host, registry key,
username, hash, filename, and extension should be typed columns in artifact
kind-specific projection tables or a controlled indexed field table. They
must not depend on unrestricted `json_extract(payload_json, ...)` scans.

Paging should use a deterministic keyset cursor. The initial compatibility
cursor is `(logical_path, id)`; artifact projections should move to a declared
sort tuple such as `(artifact_time_utc, id)` or `(normalized_name, id)`. The API
returns the sort tuple and a case mutation generation with every page. A
continuation from a different generation must be rejected or restarted, never
silently mixed.

Counts use the same membership predicate as rows:

- **source count**: distinct source objects matching the taxonomy;
- **artifact count**: semantic parser records matching the taxonomy;
- **diagnostic count**: failed, unsupported, truncated, or omitted parser
  units.

The UI must label these separately instead of displaying one ambiguous total.

## Filter and export consistency

The first normalized API uses `SemanticArtifactQuery` and stable `category_key`
values (for example `operating_system.event_logs.records`). It must grow into
one typed query used by count, page, bookmark, timeline, and export operations.
That shared query includes evidence scope, category keys, artifact kinds, typed
field filters, time range, deleted/recovered state, parser status, sort order,
and a case-generation snapshot.

Exports are server-side jobs over that exact query. Their manifest records:

- canonical query and sort order;
- case/evidence ids and case mutation generation;
- selected row ids or the explicit full-query scope;
- row count requested, written, skipped, and failed;
- parser/classifier schema versions;
- output format, path, SHA-256, start/end times, and diagnostics.

CSV/TSV/XLSX columns come from a versioned artifact-kind projection. JSON keeps
the complete structured payload plus provenance. HTML/PDF reports render the
same projection and link each finding back to its source object and coordinate.
No export may silently truncate a page-sized browser result.

## Migration sequence

1. Keep the current endpoint contract behind `artifact_view` and add query
   characterization tests (implemented in the first extraction).
2. Add normalized tables additively and dual-write parser records.
3. Backfill taxonomy memberships with classifier version and basis.
4. Switch count/page queries behind the module boundary and compare old/new
   result sets in tests.
5. Move bookmark, timeline, and export to the shared typed query.
6. Stop deriving category membership from arbitrary metadata JSON only after
   migrated cases pass reconciliation checks.
