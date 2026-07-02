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
pnpm --filter @montr/qa qa:corpus                 # self-check (perfect scanner) — wiring smoke test
pnpm --filter @montr/qa qa:corpus -- --findings scan.json   # score real Layer-3 output
pnpm --filter @montr/qa qa:variance               # model-variance matrix (fake adapter)
```

Exit codes: `0` OK · `1` REGRESSION · `2` USAGE · `3` CORPUS_ERROR · `4` RUNTIME_ERROR.
CI blocks a release on any non-zero code from `qa:corpus`.

## Adding a case

1. Add the repo under `corpus/repos/<name>/` (intentionally vulnerable or clean).
2. Declare it + its findings in `ground-truth.manifest.json` (validated against
   `GroundTruthManifestSchema` from `@montr/fixtures`).
3. `loadCorpus()` auto-discovers `corpus/repos/*` and warns on any repo that is
   present on disk but not declared (and errors on a declared repo that is missing).

> These repos contain **intentionally vulnerable code**. Like
> `packages/fixtures/sample-repos/**`, `corpus/repos/**` must be excluded from
> lint/format/typecheck (see the integration note in the WS-P handoff).
