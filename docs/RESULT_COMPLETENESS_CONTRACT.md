# Result completeness and truncation contract

## Purpose

An operation returning rows is not proof that it examined the requested
forensic scope. KDFT must attach one `ResultCompleteness` object to every parser
result, category/count query, search page, timeline page, export, report, and
AI context bundle. The Rust source of truth is
`kdft_case::result_completeness`; the language-neutral representation is
`schemas/result-completeness-v1.schema.json`.

The contract is presentation-independent. The desktop application, retained
browser interface, CLI, exports, reports, and local AI must preserve the same
status and counts.

## Status semantics

| Status | Meaning | Required examiner treatment |
| --- | --- | --- |
| `complete` | The entire declared scope was processed and every known matching output was emitted. No continuation or known gap exists. | Normal success indicator. |
| `partial` | Usable results exist, but source coverage is incomplete because of failures, skips, cancellation, unreadable input, unsupported structures, or another documented gap. | Persistent warning with reasons and affected counts. Never phrase as a complete negative finding. |
| `truncated` | The representation was cut by paging, row/byte/time/resource limits, even if underlying processing was complete. | Persistent warning and continuation action when available. Show emitted versus omitted/matched counts. |
| `failed` | No trustworthy result for the requested operation was produced. | Error disclosure. Do not render stale or provisional rows as this operation's output. |
| `skipped` | The operation was intentionally not run. | State why it was not requested, was disabled, or was inapplicable. Do not display zero as a negative finding. |
| `unknown` | Legacy data or missing provenance prevents a coverage determination. | Prominent uncertainty disclosure. Never promote to `complete`. |

`partial` and `truncated` are deliberately different. A fully indexed result
page may be `truncated` because only 200 of 725 matching rows were returned. A
parser that emitted all records it could decode but could not read one source
is `partial`. Both conditions may exist; the outer operation reports the more
immediate `truncated` status and includes an upstream partial reason, or a
composite report records child contracts for every section.

Every non-`complete` contract has at least one structured reason. Continuation
alone is not an explanation.

## Counts

Input and output units are separate because one source can emit many artifacts.
For example:

```json
{
  "input_unit": "history_database",
  "input_total": 2,
  "input_processed": 1,
  "input_skipped": 0,
  "input_failed": 1,
  "output_unit": "browser_visit",
  "output_matched": 725,
  "output_emitted": 200,
  "output_omitted": 525
}
```

`null` means unknown. It must never be converted to zero. Counts describe only
the declared scope and generation in the same contract.

## Scope and continuation

`scope.canonical_request` is the exact typed filter, parser selection, timeline
range, or report selection used by the operation. It must be redacted before
persistence; credentials, BitLocker keys, tokens, cookies, and secrets are
forbidden.

Keyset cursors bind to `scope.case_generation`. A cursor from another case
generation must be rejected, not silently resumed against a changed index.
Continuation is always explicit:

- `none`: terminal and complete for the declared output;
- `cursor`: resume the same snapshot using an opaque token;
- `retry`: resume or retry a failed/partial unit;
- `restart`: no stable checkpoint exists, but the operation can be rerun;
- `unavailable`: omitted data cannot be recovered by this operation.

Absence of a token never implies completeness.

## Parser and job provenance

`producer.parser_jobs` references the evidence job and normalized parser
execution that supplied the result. Aggregated queries list every contributing
parser execution. The producing component and version identify the KDFT layer
that assessed completeness. `assessed_at_utc` is an RFC 3339 UTC timestamp.

When semantic artifacts have not yet been migrated to normalized parser
executions, use `unknown` with `legacy_unknown` rather than manufacturing a job
reference.

## API envelope

Every result-bearing endpoint should use this shape:

```json
{
  "data": [],
  "completeness": {
    "schema_version": 1,
    "status": "truncated",
    "counts": {},
    "scope": {},
    "continuation": {},
    "reasons": [],
    "producer": {},
    "assessed_at_utc": "2026-10-16T01:02:03Z"
  }
}
```

HTTP success describes transport/API success only. Consumers must inspect
`completeness.status` before interpreting `data`.

## UI and banner rules

1. Every non-`complete` status displays a persistent, non-dismissable status
   strip in the result pane and inspector.
2. Count labels say exactly what they count: sources, artifacts, records, rows,
   or bytes. Do not use an ambiguous `Entries` total.
3. `partial`, `failed`, `skipped`, and `unknown` must survive navigation and
   appear in bookmarks made from affected results.
4. `truncated` shows `emitted / matched` and a Continue/Load more action when
   possible. Copy, select-all, and export operate on an explicitly labelled
   page or on a server-side full-query job, never an implicit browser page.
5. A zero-result view is a valid negative finding only when status is
   `complete`. Otherwise display `No results in the covered portion`.
6. Generated reports include a completeness appendix and section-level status.

## Export and report rules

An export re-evaluates or snapshots the canonical query server-side. Its
manifest embeds the final contract, output file hash, output format, case
generation, and exact artifact identifiers. If one row cannot be written, the
export is `partial`; if a configured limit cuts rows, it is `truncated`.

HTML/PDF/CSV/JSON exports must not strip the contract. Formats unable to embed
structured metadata receive a sidecar `<name>.completeness.json` covered by the
export manifest hash set.

## Local AI rules

The local model receives the completeness object with every retrieval result.
Prompt assembly must not remove reasons or counts to save context. The model:

- may summarize only the emitted records;
- must state incomplete/truncated coverage before conclusions;
- must not convert missing, skipped, unsupported, or unparsed data into an
  absence finding;
- must cite parser jobs and source coordinates for factual claims;
- cannot override a non-complete status. A deterministic KDFT banner is the
  authority even if generated prose is wrong.

## Integration sequence

1. Wrap new normalized artifact queries and exports in this contract.
2. Map existing bounded parser outcomes to `partial` or `truncated` and retain
   their diagnostics as reasons.
3. Add contract persistence to parser/export/report job manifests.
4. Make UI view models require completeness instead of accepting it as an
   optional field.
5. Backfill legacy cases as `unknown`; never infer complete from an old
   `completed` job string alone.
6. Add release tests proving that limits, cancellation, parser errors, and
   missing dependencies cannot render a green/complete result.
