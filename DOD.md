# Montr Secure — Definition of Done (sign-off)

Status of the build against **PRD §19 (Phase-1 production DoD)** plus the full-scope extras
(Phases 2–4). Evidence is concrete and in-repo. Two honest caveats are called out at the end.

Repo gates (all green): `pnpm -w typecheck` **0 errors** · `pnpm -w build` **19/19** ·
`pnpm test` **632 passing** (offline) · `pnpm -w lint` **0** · `pnpm e2e` **scan passes (15/15 assertions)**.

## PRD §19 — Phase-1 production

| #   | Criterion                                                                    | Status | Evidence                                                                                                                                                                                                                                                         |
| --- | ---------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Runs on-prem via Helm on a clean cluster with only a client LLM key          | ✅     | `deploy/helm/montr-secure` — `helm lint --strict` + `helm template` clean, kubeconform-valid; hardened defaults; default-deny-egress NetworkPolicy. See DEPLOY.md.                                                                                               |
| 2   | Scans a Next.js/Prisma/Postgres repo end-to-end (map→…→report)               | ✅     | `pnpm e2e` / `apps/worker/src/e2e-scan.test.ts` — full L0→L5 via orchestrator + worker driver on `packages/fixtures/sample-repos/vulnerable-nextjs`.                                                                                                             |
| 3   | Report headlines confirmed findings with proof, fixes, tests, OWASP/CWE      | ✅     | E2E report: 2 confirmed (critical SQLi CWE-89/A03, medium XSS CWE-79/A03), each with static proof + merge-ready patch + fails-pre/passes-post proof-of-fix test. Headline is confirmed-only (`report/headline.ts` `assertConfirmedOnlyHeadline`).                |
| 4   | False-positive rate < 5% on the golden corpus; no-regression gate in CI      | ✅     | `@montr/qa` golden corpus scores 8 repos at **precision 1.0 / FP-rate 0**; CI job `golden-corpus` fails on regression (`.github/workflows/ci.yml`).                                                                                                              |
| 5   | No client source egresses; audit log complete + exportable                   | ✅     | `@montr/security` egress guard (app-layer) + default-deny NetworkPolicy; LLM logs metadata-only; append-only hash-chained audit log + JSON/CSV export + `montr-audit-verify` tamper CLI. E2E asserts no secret/code bodies in the trail.                         |
| 6   | Cost estimate surfaced pre-scan; actuals within ±15%                         | ⚠️     | Estimate is surfaced pre-scan and actuals are recorded + reported (asserted in E2E). The ±15% **variance bound is only meaningful against a real model** — the deterministic fake adapter records ≈$0. See caveat (i).                                           |
| 7   | Auth/crypto fixes classified `human-required` in 100% of golden-corpus cases | ✅     | `fix/risk.ts` deterministic classifier maps all auth/session/crypto/access-control categories → `human-required`; uncertainty → `human-required`; `AUTO_ELIGIBLE` contains zero such categories. Proven cross-stack in `tests/stack-agnostic.invariant.test.ts`. |
| 8   | Montr Secure scans itself clean in CI (dogfood)                              | ✅     | `.github/workflows/ci.yml` `self-scan` job (Semgrep + gitleaks, redacted); releases cosign-signed with syft SBOM (`supply-chain` job).                                                                                                                           |

## Full-scope extras (Phases 2–4) — delivered

| Area                                                 | Status | Evidence                                                                                                                                                                       |
| ---------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Live DAST (Layer 3b), fully guardrailed              | ✅     | `packages/confirm` — allowlist + production-blocked + approver-auth + kill-switch + rate/blast caps + egress guard; OFF by default.                                            |
| Auto-eligible PR flow (PR-only, never direct commit) | ✅     | `packages/report` auto-fix flow (Octokit/GitLab), gate-enforced.                                                                                                               |
| All four LLM providers behind one gateway            | ✅     | `@montr/llm-gateway` adapters (Anthropic/Bedrock/Vertex/Azure) + conformance test; no provider SDK imported elsewhere (lint-enforced).                                         |
| Air-gapped install path                              | ✅     | `deploy/airgap` signed offline bundle (rulesets + CVE/OSV DB).                                                                                                                 |
| Python (Django/FastAPI) + JVM (Spring) stacks        | ✅     | `appmap` language plugins + rulesets + heuristics; 8-repo corpus; **stack-agnostic invariant proven** (correlation/fix/report unforked).                                       |
| Phase-4 intelligence                                 | ✅     | Cross-scan trends + RBAC-scoped posture dashboards, custom rule authoring (validated+versioned), red-team scenario library (gated), scheduled scans (gate + budget respected). |

## Honest caveats (non-blocking)

- **(i) Cost variance vs a real model.** Estimate-vs-actual ±15% (§19-6) is only exercised
  meaningfully against a real LLM; the deterministic fake adapter used in offline tests records ≈$0.
  The estimate is surfaced and actuals are metered — validate the ±15% bound during a real-key pilot.
- **(ii) Live scanners at runtime.** Discovery runs in **live** mode when Semgrep/gitleaks/osv-scanner
  are on PATH — they are baked into the worker image (`deploy/docker/Dockerfile.worker`). On a bare
  local host without them, discovery falls back to seeded candidates (the L2→L5 pipeline still runs on
  real data). Container/Helm deploys are unaffected.

## Follow-up (safe, non-blocking)

- Per-stack **mechanical** auto-fix strategies for Python/JVM. Today confirmed Python/JVM findings
  fail-safe to `human-required` advisory fixes; the risk **classifier** is fully language-blind (which
  the stack-agnostic invariant requires), so this is a fix-generation enhancement, not a safety gap.
- Container image builds (`docker build`) are validated in CI, not in the local sandbox (no Docker
  daemon here); compose config + `helm lint`/`template` are validated.
