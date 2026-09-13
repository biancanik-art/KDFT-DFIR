# Forensic validation corpus

KDFT's golden corpus is a set of documented, reproducible test datasets whose
expected properties are known before KDFT examines them. The JSON schema at
`schemas/golden-corpus-manifest.schema.json` is the normative manifest shape.
Corpus validation supplements unit and integration tests; it does not replace
independent verification with other forensic tools.

## Validation levels

1. **Manifest and source integrity** validates the implemented typed manifest
   contract, resolves a local source relative to its manifest, and streams the
   source to verify its exact byte length and SHA-256 digest. The command is:

   ```text
   kdft corpus validate --manifest <manifest.json> [--json]
   ```

   At this level, a dataset can pass only when it has a verified, single-file
   local source and declares no parser, filesystem, artifact, search, or report
   expectations in the manifest's `expected` object. Root-level corruption and
   known-unsupported entries remain descriptive at this level; they are not
   evaluated outcomes. A pass means only
   `manifest_and_source_integrity_only`, and `expectations_checked` remains 0.

2. **Parser assertion validation** will compare KDFT output with every declared
   expectation. Until that evaluator exists, a manifest containing any
   expectation is reported as `incomplete`, with every affected expectation
   class listed as unsupported/unverified.

3. **Independent forensic verification** compares the same documented source
   and expected offsets or artifacts in another forensic product and records
   the procedure and result. This is required before making broad accuracy
   claims about physical-offset provenance.

## NTFS milestones

The first in-code NTFS oracle is a tiny, generated-at-test-time standalone
`$MFT` containing known resident data, alternate data stream metadata, a
same-name deleted resident record, reconstructed hierarchy, and known MFT
source-stream offsets. Its resident payload deliberately crosses an NTFS
update-sequence trailer, and its named stream uses a quadword-aligned value
offset. The oracle verifies the fixup-decoded bytes and SHA-256, proves that
live/deleted path collisions retain both records, and does not expose an
extracted-stream position as an evidence-media physical offset. Because
fixup-decoded content may not be one contiguous raw-source range, KDFT records
both the decoded-record offset and raw-source-contiguity state. Publishing that
oracle through the manifest evaluator remains a separate milestone; a large
binary fixture does not belong in git.

A standalone `$MFT` can validate record parsing and MFT-relative provenance,
but it cannot prove decoded-media physical offsets for nonresident content.
That claim requires a later generated whole-volume NTFS image with known data
runs, partition offsets, cluster geometry, and independently checked byte
locations.

## Corpus handling rules

- Keep fixtures tiny or generate them deterministically at test time.
- Store larger images externally and record immutable SHA-256 and size values.
- Never silently convert unavailable, unsupported, or unchecked expectations
  into a pass.
- Keep limitations factual and scoped to the validation level; do not turn a
  parser diagnostic into a claim that all evidence is unreliable.
- Do not modify or mount evidence during validation.
