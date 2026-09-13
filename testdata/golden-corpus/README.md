# KDFT Golden Corpus Testdata

This directory is for tiny fixtures and manifest examples only.

Large generated images do not belong in git by default. Store larger mini/full
forensic images externally or generate them from scripts, then record their
SHA-256 and expected results in a manifest that conforms to:

`../../schemas/golden-corpus-manifest.schema.json`

See `../../docs/FORENSIC_VALIDATION_CORPUS.md` for the validation policy and
first dataset milestone list.

Validate a manifest and an available local source with:

```text
kdft corpus validate --manifest testdata/golden-corpus/<manifest.json> --json
```

The example manifest intentionally references unavailable external data and
declares expectations, so validation reports it as `incomplete`, not passed.
