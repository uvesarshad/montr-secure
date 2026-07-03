# Montr Secure — Session Handoff

Handoff for continuing this build in a **fresh Claude Code session on another machine**. The prior
session's context does not transfer; everything you need is in the repo + this file.

---

## TL;DR

**Montr Secure is BUILT and COMMITTED.** An on-prem AI security orchestration platform (per
`docs/plan/montr-secure-prd.md`): a 6-layer pipeline (map → discovery → correlation → confirm → fix →
report) that consolidates SAST/SCA/secrets/DAST, correlates + confirms findings, and emits an
exploit-validated report with gated, merge-ready fixes. Stacks: **Node/Next.js, Python, JVM**.

- **7 commits**, clean tree. Last verified green: `typecheck 0 · build 19/19 · 632 tests · lint 0 ·
pnpm e2e scan passes (15/15)`.
- **What remains is validation on real infra/keys** (no Docker daemon / cluster / real LLM key /
  staging existed in the build sandbox), plus one optional feature follow-up. See §5.

---

## 1. First steps on the new machine

```bash
cd security-sentinel
pnpm install
pnpm -w typecheck        # expect 0 errors
pnpm -w build            # expect 19/19
pnpm test                # expect 632 passing (offline)
pnpm e2e                 # expect a printed report: 2 confirmed (SQLi+XSS), 15/15 assertions
```

Toolchain: Node 20 (`.nvmrc`; local Node 24 also works), pnpm + Turborepo, TypeScript strict.
If `pnpm test`/`build` fail on first run, it's almost always a missing workspace link — re-run
`pnpm install` (this exact thing bit us once: a package.json gained a `@montr/*` dep but the symlink
wasn't created until `pnpm install` re-ran).

---

## 2. Git history — what each commit contains

```
fc72aaf  final     deploy hardening (web standalone Dockerfile, worker scanners) + README/DEPLOY/RUNBOOK/DOD
2341ab0  Wave 5    Phase-4: posture dashboards, custom rules, red-team lib, scheduled scans
e9f0020  Wave 4    Phase-3 breadth: Python + JVM plugins; stack-agnostic invariant proven
2d4f057  Integ.    pipeline wired end-to-end; E2E scan passing (the DoD milestone)
5ea36ba  Wave 3    compliance exports (SARIF/SOC2/ISO/OWASP), report UI, FP-feedback loop
b6e1d8b  Waves 1-2 cross-cutting platform + full L0-L5 pipeline
9a78541  Wave 0    monorepo + frozen @montr/contracts spine + config + prisma + fixtures + CI
```

(HEAD may be one further if this HANDOFF commit landed — run `git log --oneline`.)

---

## 3. Repo map

```
packages/  contracts(the spine) config telemetry llm-gateway cost-meter state-store orchestrator
           appmap(L0) discovery(L1) correlation(L2) confirm(L3) fix(L4) report(L5) qa security fixtures
apps/      api(Fastify+RBAC)  worker(BullMQ + in-process driver)  web(Next.js console + dashboards)
deploy/    docker(Dockerfiles+compose)  helm(hardened chart)  airgap(signed bundle)
corpus/    8 vuln/clean repos (TS/JS + Python + JVM) with ground truth
tests/     top-level vitest suites (incl. e2e-scan, stack-agnostic.invariant)
```

Read `README.md`, `DEPLOY.md`, `RUNBOOK.md`, `DOD.md` (repo root) and `CONTRIBUTING.md`.

## The 10 golden rules (NON-NEGOTIABLE — build-plan §0 / PRD §11)

1. ⛔ No code egress — client source only leaves the perimeter inside a call to the client's own LLM
   key; logs are metadata-only.
2. ⛔ No provider SDK imported outside `@montr/llm-gateway` (lint-enforced).
3. ⛔ Auth/session/crypto/access-control fixes are ALWAYS `human-required`.
4. ⛔ Uncertainty resolves toward less autonomy (fail-safe).
5. ⛔ Code changes via PR only, never direct commit; only `auto-eligible` fixes that pass the gate.
6. Deterministic tools detect; LLM only triages/correlates/confirms/fixes. No LLM before the App Map.
7. Everything audit-logged (append-only, hash-chained, tamper-evident).
8. Cost is a first-class output (estimate → meter → hard-halt).
9. Own your package; build against `@montr/contracts` + `@montr/fixtures`, not others' live code.
10. Every finding tier / layer boundary uses the exact `@montr/contracts` types.

Hardened defaults: auto-fix OFF · DAST OFF · budget hard-halt ON · telemetry OFF · egress default-deny.

---

## 4. Known gotchas / decisions (a fresh session MUST know these)

- **Next.js 16 Turbopack cannot resolve this repo's `.js`-extension TS import convention.** Use the
  webpack builder: `pnpm --filter @montr/web build:next` (`Dockerfile.web` already does this via the
  `standalone` output). Bare `next build` will fail.
- **Prisma pinned to ^5.22** — Prisma 7 removed the `prisma-client-js` generator the schema uses.
- **undici ^7 / puppeteer-core ^24 / playwright-core** pinned to Node-20-compatible majors.
- **Worker image is slim, NOT distroless** (`Dockerfile.worker`): Semgrep needs a Python runtime, so
  the worker bundles semgrep+gitleaks+osv-scanner; hardened via non-root + read-only FS + NetworkPolicy.
- **Scanner binary versions in `Dockerfile.worker`** (`GITLEAKS_VERSION`, `OSV_SCANNER_VERSION`) and the
  **standalone COPY paths in `Dockerfile.web`** were written correct-by-construction but **never
  `docker build`-ed** (no Docker daemon in the sandbox). Verify on the first real build; the release
  asset filenames may need a tweak.
- **E2E discovery ran in `seeded-candidates` mode** locally (no semgrep/gitleaks on host). With the
  scanners on PATH (they're in the worker image) it auto-switches to `live-scanners`.
- **The offline tests use a deterministic FAKE LLM adapter** (`@montr/fixtures`) → cost actuals ≈ $0,
  so the ±15% cost-variance metric is unvalidated until a real key is used.
- **docs/ is git-IGNORED.** The PRD + build-plan (`docs/plan/*`) do NOT travel via `git clone`. If you
  cloned, copy `docs/` over manually, or they're gone. This HANDOFF + README/DEPLOY/RUNBOOK/DOD ARE
  committed and self-sufficient.

---

## 5. What REMAINS

**A. Real-infra/real-key validation (10 build-plan boxes, all "execute", not "build"):**

1. `docker compose -f deploy/docker/docker-compose.yml build && up` — confirm all 5 services come up
   (api, worker, web, postgres, redis) and the web standalone image + worker scanner image build.
2. `helm install` on a real k8s cluster; confirm hardened defaults + default-deny egress.
3. Run a scan **with a real enterprise LLM key** against a real Next.js/Prisma repo → validates the
   cost estimate-vs-actual **±15%** bound AND that discovery runs in **live-scanners** mode.
4. A real **DAST** run against an authorized/allowlisted **staging** target (DAST is OFF by default).
5. A real **CI push** so the `self-scan` (dogfood) + golden-corpus + docker + helm jobs execute.
6. Execute the **air-gap** signed-bundle build+import (`deploy/airgap/`).

**B. Optional feature follow-up (safe, non-blocking):**

- Per-stack **mechanical** auto-fix strategies for Python/JVM. Today confirmed Python/JVM findings
  fail-safe to `human-required` advisory fixes (`packages/fix/src/strategies.ts` is TS/JS-only); the
  risk _classifier_ is correctly language-blind, so this is a fix-generation enhancement, not a gap.

`DOD.md` maps every PRD §19 criterion to evidence and lists the same caveats.

---

## 6. How this was built (so you can continue in the same style)

- Built in **waves** via the `Workflow` tool: a serial setup/provision → parallel package agents (each
  owns distinct dirs to avoid file races) → a serial consolidate/verify that runs the full gate and a
  golden-rules audit. Each wave ended green and got **one commit** (owner rule: commit after each wave).
- **Usage cadence:** there's a ~**5-hour rolling usage cap**. Subagent-heavy waves can exhaust it
  mid-run. Recovery is cheap and proven: on cap, the on-disk work persists → `git stash -u` any broken
  partials to restore the last green commit (or keep them if green) → relaunch/resume the wave next
  window. Never re-run from scratch what's already committed green.
- The build-plan (`docs/plan/montr-secure-build-plan.md`) is the exhaustive checklist: **188/198 boxes
  done**; the 10 open ones are exactly §5.A above.

---

## 7. Resume prompt (paste into a fresh Claude Code session on the new machine)

> I'm resuming the **Montr Secure** build — an on-prem AI security orchestration platform. It's already
> built and committed (7 commits, clean tree). **Read `HANDOFF.md` first, then `README.md`, `DOD.md`,
> and `CONTRIBUTING.md`.** Then verify green: `pnpm install && pnpm -w typecheck && pnpm -w build &&
pnpm test && pnpm e2e` (expect 632 tests + a passing e2e scan). Honor the 10 golden rules
> (`HANDOFF.md` §3 / build-plan §0) — especially: no code egress, no provider SDK outside
> `@montr/llm-gateway`, auth/crypto fixes always `human-required`, PR-only auto-fix. Commit after each
> meaningful green chunk. Note the ~5h rolling usage cap (`HANDOFF.md` §6) and pace accordingly.
>
> The remaining work is **validation on real hardware/keys** (`HANDOFF.md` §5): (1) `docker compose
build && up` the full stack, (2) `helm install` on a cluster, (3) run a real scan with my LLM key to
> validate the ±15% cost bound + live scanners, (4) a DAST run against my authorized staging target,
> (5) a CI push for the self-scan/golden-corpus/docker/helm jobs, (6) the air-gap bundle. Watch the
> known gotchas in `HANDOFF.md` §4 (Next.js webpack build, worker scanner image, unbuilt Dockerfiles).
> Start by verifying green, then let's do `docker compose build` and fix whatever the first real image
> build surfaces. Optional stretch: per-stack mechanical auto-fix strategies for Python/JVM.

---

_Generated at handoff. Product complete; remaining = validate on real infra + optional Python/JVM fix strategies._
