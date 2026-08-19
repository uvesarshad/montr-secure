# corpus — golden test corpus (WS-P)

Curated **vulnerable + clean** Next.js/Prisma repositories with machine-readable
**ground-truth labels**. The CI regression gate scores a scan's confirmed
findings against these labels to measure precision/recall and the headline
**false-positive rate (< 5%)** (PRD §15/§19, build-plan §4.7).

## Layout

```
corpus/
  ground-truth.manifest.json   machine-readable labels for the repos below
  baseline.json                committed regression thresholds (the gate reads this)
  repos/
    vulnerable-nextjs-owasp/   SSRF, IDOR, broken access control, insecure cookie
    clean-nextjs-owasp/        the secured counterpart (0 confirmed findings)
```

The corpus is the **union** of these repos and the `@montr/fixtures` seed repos
(`vulnerable-nextjs`, `clean-nextjs`), merged at load time by
`loadCorpus()` in `@montr/qa`. Fixtures contribute SQLi, XSS, hard-coded secret,
vulnerable dependency, and permissive CORS; this directory expands coverage to
the remaining requested OWASP-Top-10 representatives.

| Category                | CWE      | OWASP    | Source   | Exploitable | Expected fix class |
| ----------------------- | -------- | -------- | -------- | ----------- | ------------------ |
| `sql_injection`         | CWE-89   | A03:2021 | fixtures | yes         | auto-eligible      |
| `xss`                   | CWE-79   | A03:2021 | fixtures | yes         | auto-eligible      |
| `hardcoded_secret`      | CWE-798  | A07:2021 | fixtures | yes         | human-required     |
| `vulnerable_dependency` | CWE-1321 | A06:2021 | fixtures | no (demote) | auto-eligible      |
| `permissive_cors`       | CWE-942  | A05:2021 | fixtures | no (demote) | auto-eligible      |
| `ssrf`                  | CWE-918  | A10:2021 | corpus   | yes         | auto-eligible      |
| `idor`                  | CWE-639  | A01:2021 | corpus   | yes         | human-required     |
| `broken_access_control` | CWE-284  | A01:2021 | corpus   | yes         | human-required     |
| `insecure_cookie`       | CWE-614  | A05:2021 | corpus   | yes         | auto-eligible      |

`exploitable: false` cases must be **demoted to the appendix** (present, not
confirmed) — confirming one is a false positive. Access-control fixes
(`idor`, `broken_access_control`) are labelled `human-required` per golden rule #3.

## Running the gate

```bash
# 1. Run the REAL apps/worker pipeline over every corpus repo (real App Map,
#    real semgrep/gitleaks discovery, real correlation + static confirmation;
#    FAKE in-process LLM gateway, so no live LLM credentials needed) and write
#    the aggregated confirmed findings to scan.json:
pnpm corpus:scan                                             # == node scripts/corpus-scan.mjs --out scan.json

# 2. Score that REAL scan against ground truth — THIS is the release gate:
pnpm --filter @montr/qa qa:corpus -- --findings scan.json

# Synthetic self-check (perfectScanner echoes ground truth back at itself —
# precision/FP-rate are tautologically perfect; proves the corpus/scorer/
# baseline/exit-code PLUMBING works, nothing about detection quality). NOT the
# release gate — that always requires --findings from a real scan (above).
pnpm --filter @montr/qa qa:corpus:selfcheck

pnpm --filter @montr/qa qa:variance               # model-variance matrix (fake adapter)
```

Exit codes: `0` OK · `1` REGRESSION · `2` USAGE · `3` CORPUS_ERROR · `4` RUNTIME_ERROR.
CI (`.github/workflows/ci.yml`'s `golden-corpus` job) runs both steps above in
order and blocks a release on any non-zero code from `qa:corpus`.

## Adding a case

1. Add the repo under `corpus/repos/<name>/` (intentionally vulnerable or clean).
2. Declare it + its findings in `ground-truth.manifest.json` (validated against
   `GroundTruthManifestSchema` from `@montr/fixtures`).
3. `loadCorpus()` auto-discovers `corpus/repos/*` and warns on any repo that is
   present on disk but not declared (and errors on a declared repo that is missing).

> These repos contain **intentionally vulnerable code**. Like
> `packages/fixtures/sample-repos/**`, `corpus/repos/**` must be excluded from
> lint/format/typecheck (see the integration note in the WS-P handoff).
