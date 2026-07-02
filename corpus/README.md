# corpus — golden test corpus

Curated vulnerable + clean repositories with **ground-truth labels**, used by the
CI regression gate to measure precision/recall (headline metric: false-positive
rate < 5%, §15/§19). Owned by **WS-P**.

## Wave 0 seed

The seed corpus lives in `@montr/fixtures`:

- `packages/fixtures/sample-repos/vulnerable-nextjs/` — 5 known vulns (SQLi, XSS,
  hard-coded secret, vulnerable dependency, permissive CORS).
- `packages/fixtures/sample-repos/clean-nextjs/` — the safe counterpart (must
  yield zero confirmed findings).
- Ground truth: `packages/fixtures/sample-repos/ground-truth.manifest.json` and
  the typed `groundTruthManifest` export.

## WS-P expands this into

- More OWASP-Top-10 representative cases (and, in Phase 3, Python + JVM repos).
- A precision/recall scorer against ground truth + an FP-rate reporter.
- A CI regression gate that blocks releases on precision/recall regressions.
- A model-variance harness (runs the corpus per provider/model).
