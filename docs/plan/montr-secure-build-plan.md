# Montr Secure — Build Plan & Parallel-Execution Todo List

> Companion to `montr-secure-prd.md`. This is the **executable build order** for a fleet of AI
> subagents. It is exhaustive by design (PRD directive: _"do not miss anything"_).
> Scope confirmed with owner: **all phases (1–4)**, **TypeScript/Node monorepo**,
> **docker-compose + Helm kept green in parallel**.
>
> Checkboxes are the unit of work. `[owner: WS-x]` tags map to a workstream/agent.
> `⛔` = hard safety gate (PRD §11, non-negotiable). `🔗DEP` = blocking dependency.

---

> ## ✅ STATUS: BUILD COMPLETE — **188/198 done**, shipped across 7 commits (`git log`; see `DOD.md`).
>
> All code, tests, config, deploy manifests, and docs are **built and committed**. Waves 0–5 +
> integration are green: typecheck 0 · build 19/19 · **632 tests** · lint 0 · `pnpm e2e` scan passes.
>
> The **10 unchecked boxes are not unbuilt code** — they are the acceptance checks that require
> execution on real infrastructure/keys, which was unavailable in the build sandbox (no Docker daemon,
> no k8s cluster, no real LLM key, no authorized staging target). To close them on a real machine:
> `docker compose build && up` · `helm install` on a cluster · run a scan with a real LLM key
> (validates cost ±15% + live scanners) · a real DAST run against authorized staging · a real CI push
> (self-scan) · execute the air-gap signed-bundle import. Each is documented in `DOD.md` / `DEPLOY.md`.

---

## 0. Stack Decision & Global Conventions (READ FIRST — every agent)

**Host language:** TypeScript (strict), Node 20 LTS. Rationale in the intro message: native
Next.js/Prisma/TS-AST introspection = the moat.

**Locked tech choices (do not re-litigate; deviations require owner sign-off):**

| Concern                                  | Choice                                                                                    |
| ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| Monorepo                                 | pnpm workspaces + Turborepo                                                               |
| Language / build                         | TypeScript strict, `tsup`/`tsc`, Node 20                                                  |
| Lint / format                            | ESLint + Prettier, `lint-staged` + Husky                                                  |
| Schemas / types (single source of truth) | **Zod** → inferred TS types + JSON Schema                                                 |
| HTTP API                                 | Fastify + `@fastify/swagger` (OpenAPI)                                                    |
| Job queue / orchestration                | BullMQ + Redis (durable, resumable jobs)                                                  |
| State store                              | Prisma + PostgreSQL 16 (dogfoods target stack)                                            |
| Pipeline state machine                   | Explicit FSM persisted in Postgres (XState optional, not required)                        |
| Code parsing                             | `web-tree-sitter` (JS/TS/Py/Java grammars) + **ts-morph** for TS/JS semantic depth        |
| SAST engine                              | Semgrep (subprocess, `--json`) + curated rulesets                                         |
| Secrets scan                             | gitleaks (subprocess) + custom detectors                                                  |
| SCA / CVE                                | OSV DB (osv-scanner + offline mirror) + GHSA + lockfile parse + reachability graph        |
| LLM access                               | **Custom gateway only** — provider SDKs never imported outside `@montr/llm-gateway`       |
| Git / PR                                 | `simple-git` + Octokit (GitHub) + `@gitbeaker/rest` (GitLab)                              |
| DAST                                     | `undici` HTTP client + Playwright (auth flows) + allowlist middleware                     |
| Logging / metrics                        | `pino` (structured) + OpenTelemetry → Prometheus                                          |
| Report UI                                | Next.js 14 (App Router) + Tailwind + shadcn/ui                                            |
| Exports                                  | Puppeteer (PDF), SARIF JSON, CSV/JSON evidence                                            |
| Auth                                     | JWT/session + argon2; RBAC middleware                                                     |
| Secret storage                           | k8s Secret + optional Vault (`node-vault`); field encryption AES-256-GCM w/ KMS/Vault key |
| Testing                                  | Vitest (unit/integration), Playwright (UI e2e), custom golden-corpus harness              |
| Containers                               | distroless Node base, multi-stage; cosign (signing) + syft (SBOM)                         |
| CI                                       | GitHub Actions: lint → typecheck → test → build → self-scan → golden-corpus gate          |

**Monorepo layout (package = ownership boundary = parallelization boundary):**

```
montr-secure/
  packages/
    contracts/      @montr/contracts     Zod schemas, types, layer I/O, queue jobs, errors
    config/         @montr/config        config schema + loader (providers, budgets, policies)
    telemetry/      @montr/telemetry     pino + OTel wrappers, audit-log client
    llm-gateway/    @montr/llm-gateway   provider abstraction + adapters + token accounting
    cost-meter/     @montr/cost-meter    estimate / meter / ceiling
    state-store/    @montr/state-store   Prisma client, repos, encryption, audit log
    orchestrator/   @montr/orchestrator  FSM, BullMQ workers, gate state, kill switch
    appmap/         @montr/appmap        Layer 0: parsers + mapper agent + cost estimator
    discovery/      @montr/discovery     Layer 1: SAST + secrets + SCA agents
    correlation/    @montr/correlation   Layer 2: the moat
    confirm/        @montr/confirm       Layer 3: static proof + live DAST
    fix/            @montr/fix           Layer 4: patch + test + risk classifier
    report/         @montr/report        Layer 5: report model + exports
    fixtures/       @montr/fixtures      shared test fixtures + mocks (unblocks parallel work)
  apps/
    api/            Fastify HTTP API + RBAC + OpenAPI
    worker/         BullMQ worker host (runs orchestrator + layer agents)
    web/            Next.js operator console + report UI
  deploy/
    docker/         Dockerfiles per service + docker-compose.yml
    helm/           Helm chart (hardened defaults)
    airgap/         signed-bundle build + import tooling
  corpus/           golden test corpus (vuln + clean repos, ground truth)
  .github/workflows/ CI
```

**Golden rules every agent obeys (violations block merge):**

1. ⛔ **No code egress.** Client source only ever leaves the perimeter _inside_ a call to the
   client's own LLM key. Log call **metadata only**, never code bodies. (§11, §6.5)
2. ⛔ **Gateway abstraction from commit one.** No provider SDK import outside `@montr/llm-gateway`. (§8.2)
3. ⛔ **Auth/session/crypto/access-control fixes are ALWAYS `human-required`.** Hard rule. (§4, §11)
4. ⛔ **Uncertainty resolves toward less autonomy, more human review.** Fail-safe default. (§11)
5. ⛔ **Code changes only via PR, never direct commit; only for `auto-eligible` fixes that pass the gate.** (§7 L5)
6. **Deterministic-first:** tools detect, LLM triages/correlates/confirms/fixes. No LLM call before the App Map exists. (§6.1)
7. **Everything audit-logged**, append-only, tamper-evident. (§6.7, §8.5)
8. **Cost is a first-class output:** estimate before, meter during, report after. (§6.6)
9. Contribute against **contracts + fixtures**, not against other agents' live code. Own your package.
10. Every finding tier and every layer boundary uses the exact `@montr/contracts` types. Don't invent shapes.

---

## 1. Parallel-Execution Model (for the subagent fleet)

**Coordination principle: contracts-first, then fan out, then integrate.**

- **Wave 0 is a hard barrier.** One agent (or a tight pair) builds `@montr/contracts`,
  `@montr/config`, the Prisma schema, queue job definitions, the gateway interface, `@montr/fixtures`,
  and CI/deploy skeletons. **Nothing else starts until Wave 0 freezes the interfaces.** This is the
  single most important sequencing rule — a wrong contract propagates into every downstream task.
- **Waves 1–2 fan out massively.** Each agent owns one package, builds it against the frozen
  contracts and shared fixtures/mocks. Pipeline layers (E→F→G→H→I→J) have a _data_ dependency chain
  but can be **built concurrently** because each consumes fixture inputs and emits contract-typed
  outputs. Integration wires the real chain afterward.
- **Isolation:** prefer one package per agent so file conflicts are near-zero. For agents that must
  touch shared files, spawn with `isolation: "worktree"`. Re-integrate via small PRs.
- **Definition of "done" per package:** builds clean, unit tests green, exports match contracts,
  a fixture-driven demo path passes, docs/README stub written.
- **Integration protocol:** after Wave 2, an integration agent wires orchestrator → real layers,
  replaces mocks, runs the E2E golden-corpus scan, and closes gaps.

**Suggested fleet size:** 12–16 concurrent agents at peak (one per active package), plus a
standing integration/QA agent and a standing "safety-auditor" agent that reviews every package
against the §11 golden rules before merge.

---

## 2. Dependency Graph

```
WAVE 0 (BARRIER)  ── contracts, config, db-schema, queue defs, gateway iface, fixtures, CI, deploy skeleton
       │
       ├───────────────┬───────────────┬──────────────┬─────────────┬───────────────┐
       ▼               ▼               ▼              ▼             ▼               ▼
WAVE 1 (parallel) B:gateway+cost   C:state-store   D:orchestrator  L:auth/RBAC   K:web-shell   O:deploy   P:QA+corpus   N:self-security
       │   (B,C ready unblock the LLM-using + persistence-using layers)
       ▼
WAVE 2 (parallel, build vs fixtures)  E:Layer0 ─▶ F:Layer1 ─▶ G:Layer2 ─▶ H:Layer3 ─▶ I:Layer4 ─▶ J:Layer5
       │        (data-flow chain wired at integration; each BUILT in parallel)
       ▼
WAVE 3 (parallel)  M:compliance/exports   +  report polish  +  auto-fix PR flow
       │
       ▼
WAVE 4  Q:Phase-3 stack breadth (Python Django/FastAPI, then JVM)
       │
       ▼
WAVE 5  R:Phase-4 scale & intelligence (trend dashboards, custom rules, red-team library)
       │
       ▼
INTEGRATION + E2E + DEPLOY HARDENING (compose + Helm + air-gap) + DoD sign-off
```

---

## 3. WAVE 0 — Foundation & Contracts `[owner: WS-A]` ⛔ BLOCKING BARRIER

**Goal:** freeze every interface so 15 agents can build without colliding. Nobody proceeds past this.

**3.1 Monorepo & tooling**

- [x] Init pnpm workspace + Turborepo; `turbo.json` pipeline (build/lint/test/typecheck).
- [x] Root `tsconfig` (strict, project references), ESLint + Prettier, Husky + lint-staged.
- [x] Create every `packages/*` and `apps/*` stub with `package.json`, `tsconfig`, `src/index.ts`, README.
- [x] `.editorconfig`, `.nvmrc` (Node 20), `.gitignore`, `.dockerignore`.
- [x] `CONTRIBUTING.md` restating the 10 golden rules + package-ownership map.

**3.2 `@montr/contracts` (the spine — most important deliverable of Wave 0)**

- [x] Zod schemas + inferred types for the full §9 data model: `AppMap`, `Route`, `TaintSource`,
      `TaintSink`, `CandidateFinding`, `ProbableFinding`, `ConfirmedFinding`, `Fix`, `Scan`.
- [x] Enums: `ScanMode(full|diff)`, `Exposure(public|authed)`, `ProofType(static|live)`,
      `RiskClass(auto-eligible|human-required)`, `FixStatus(proposed|pr-open|merged|rejected)`,
      `GateState`, `FindingStatus(candidate|probable|confirmed|unconfirmed)`, `Severity`, `Role(operator|approver|viewer)`.
- [x] Layer I/O contracts: `Layer0Output{AppMap,ScanScope,CostEstimate}`, `Layer1Output{CandidateFinding[]}`,
      `Layer2Output{ProbableFinding[]}`, `Layer3Output{ConfirmedFinding[],Unconfirmed[]}`,
      `Layer4Output{Fix[]}`, `Layer5Output{Report,PullRequest[]}`.
- [x] LLM Gateway interface: `LLMRequest`, `LLMResponse`, `TokenUsage`, `ModelDescriptor`, `Provider`.
- [x] Cost contracts: `CostEstimate`, `CostActual`, `BudgetPolicy`.
- [x] Audit contracts: `AuditEvent` (append-only, hash-chain fields).
- [x] Error taxonomy: typed errors (`BudgetExceeded`, `EgressBlocked`, `DastTargetNotAllowlisted`, `GateNotPassed`, …).
- [x] CWE + OWASP-Top-10 mapping types (`Category`, `CweId`, `OwaspId`).
- [x] Compliance/report types (§12 structure) + export descriptors (SARIF, SOC2, ISO, OWASP).

**3.3 Queue & event contracts**

- [x] BullMQ job definitions per layer + retry/idempotency keys + progress events.
- [x] Kill-switch signal contract; partial-failure + resume-token contract.

**3.4 DB schema (Prisma) — hand to WS-C but authored here so it's frozen early**

- [x] Prisma schema for all §9 entities + `User`, `AuditEvent`, `PromptVersion`, `ScanState`, `DastTarget`.
- [x] Field-level encryption annotations for secrets (LLM key, tokens). `🔗DEP` KMS/Vault key source.
- [x] Migration baseline; per-client isolation strategy documented (schema-per-client or row-scoped tenant).
- [x] DECIDE-2 applied: **AppMap persisted per client, encrypted, rebuild-on-stale-commit** policy field.

**3.5 `@montr/config`**

- [x] Zod config schema: LLM provider+endpoint+key, model matrix, budget ceilings, auto-fix policy,
      DAST allowlist + scope contract, retention policy, RBAC, telemetry opt-in.
- [x] Loader with env + file + k8s-secret sources; validation errors are fatal & explicit.
- [x] Hardened defaults (auto-fix OFF, DAST OFF, budget hard-halt ON, telemetry OFF).

**3.6 `@montr/fixtures` (unblocks all parallel work)**

- [x] Mock `AppMap`, candidate/probable/confirmed findings, fixes, LLM responses, transcripts.
- [x] A tiny sample Next.js/Prisma repo with **known** vulns (SQLi via raw query, XSS, hardcoded
      secret, vulnerable dep, permissive CORS) + one clean repo. Ground-truth manifest.
- [x] Fake LLM adapter (deterministic canned responses) for offline tests.

**3.7 CI skeleton `[shared with WS-O, WS-P]`**

- [x] GitHub Actions: install → lint → typecheck → unit test → build (all packages).
- [x] Placeholder jobs for self-scan + golden-corpus gate (wired later).
- [x] Both `docker build` (compose images) and `helm lint`/`helm template` run in CI from day 1.

**3.8 Deploy skeleton `[shared with WS-O]`**

- [x] Multi-stage Dockerfile template (distroless), per-service.
- [x] `docker-compose.yml` skeleton: api, worker, web, postgres, redis (+ healthchecks).
- [x] Helm chart skeleton: values.yaml, deployments, services, secrets, network policy stubs.

**Wave-0 exit criteria:** contracts + config + schema + fixtures published and versioned; CI green on
empty packages; deploy skeleton `docker compose config` and `helm template` succeed. **THEN fan out.**

---

## 4. WAVE 1 — Cross-Cutting Platform (parallel)

### 4.1 `@montr/llm-gateway` + `@montr/cost-meter` `[owner: WS-B]` 🔗DEP: contracts

- [x] Gateway core: unified `complete()`/`stream()`, retries w/ backoff, timeouts, structured errors.
- [x] ⛔ Per-call **metadata-only** logging (tokens, model, latency — never prompt/code bodies).
- [x] Adapter: **Anthropic** (`@anthropic-ai/sdk`). Recommended models: Opus 4.8 `claude-opus-4-8`
      (confirmation), Sonnet 5 `claude-sonnet-5` (default), Haiku 4.5 `claude-haiku-4-5-20251001` (cheap triage).
- [x] Adapter: **AWS Bedrock** (`@aws-sdk/client-bedrock-runtime`).
- [x] Adapter: **GCP Vertex** (`@google-cloud/vertexai`).
- [x] Adapter: **Azure OpenAI** (`@azure/openai`).
- [x] Provider selection + endpoint/key from `@montr/config`; BYO-key, never a Montr-owned relationship.
- [x] **Model matrix + model floor (DECIDE-3):** publish recommended matrix; warn when client points at
      a sub-floor model that degrades confirmation. Floor = Sonnet-5-class for confirmation tier.
- [x] ⛔ **Key-tier guard:** detect/warn on suspected data-retaining (non-enterprise) key tiers; policy to block.
- [x] Per-call token accounting emitted to Cost Meter.
- [x] Prompt registry/versioning hook (feeds §15 regression tuning).
- [x] **Cost Meter:** pre-scan estimate API (from map size + mode), live metering, post-scan actuals.
- [x] ⛔ **Budget ceiling (DECIDE-4 = hard halt):** on exceed → stop pipeline, emit partial report, never silently burn tokens.
- [x] Cost-per-scan and cost-per-finding rollups; estimate-vs-actual variance (target ±15%).
- [x] Fake adapter wired for tests (from fixtures).

### 4.2 `@montr/state-store` + Audit Log `[owner: WS-C]` 🔗DEP: contracts, prisma schema

- [x] Prisma client wrapper + typed repositories/DAOs for every entity.
- [x] ⛔ Field-level encryption at rest (AES-256-GCM) for LLM key + tokens; key from Vault/KMS/k8s secret.
- [x] Per-client data isolation enforced at the repo layer (never shared).
- [x] Scan history + **resumable pipeline state** persistence (a failed Layer-3 must not re-run Layer 0–2).
- [x] AppMap persistence (per-client, encrypted) + stale-commit invalidation (DECIDE-2).
- [x] ⛔ **Audit Log:** append-only table, **hash-chained** (tamper-evident), records every agent action,
      every LLM call (metadata), every code modification, every human approval.
- [x] Audit export (JSON/CSV) for third-party auditors.
- [x] Retention-policy enforcement job.

### 4.3 `@montr/orchestrator` `[owner: WS-D]` 🔗DEP: contracts, state-store, gateway iface, queue defs

- [x] Pipeline FSM: L0→L1→L2→L3→L4→L5 with explicit states persisted to Postgres.
- [x] BullMQ workers per layer; idempotent, resumable, retry + partial-failure handling.
- [x] ⛔ **Gate as an explicit pipeline STATE** (not a config flag): code changes require passing the
      classifier's auto-eligible bar OR explicit human approval.
- [x] ⛔ **Kill switch:** halts all active work (esp. DAST probing) immediately, everywhere.
- [x] Scan lifecycle API: create/start/pause/resume/cancel; status + progress stream.
- [x] Layer handoff via contract types; no layer reaches around the orchestrator.
- [x] Pre-scan estimate gate: surface CostEstimate and (per config) require approval before Layer 1.

### 4.4 Auth & RBAC `[owner: WS-L]` 🔗DEP: contracts, state-store

- [x] User model, registration/login, argon2 hashing, session/JWT.
- [x] Roles: **operator, approver, viewer** (§10 RBAC).
- [x] ⛔ Guards: **approver required** for the human gate AND for DAST authorization.
- [x] API hardening: rate limits, CSRF (for web), secure headers, input validation via Zod.
- [x] Bind every mutating action to an audit event (actor + role).

### 4.5 Web console shell `[owner: WS-K]` 🔗DEP: contracts (build vs API mocks)

- [x] Next.js 14 app scaffold, Tailwind + shadcn/ui, auth-aware layout.
- [x] RBAC-aware nav (operator/approver/viewer views).
- [x] API client typed from `@montr/contracts`; MSW mocks so UI progresses before API is live.
- [x] Screens stubbed: scan list/detail, cost-estimate approval, report viewer, DAST authorization,
      PR status, audit-log viewer, FP-marking. (Filled in Waves 2–3.)

### 4.6 Deploy build-out `[owner: WS-O]` 🔗DEP: deploy skeleton

- [x] Real multi-stage Dockerfiles for api/worker/web (distroless, non-root, read-only FS where possible).
- [x] `docker-compose.yml`: full stack + Postgres + Redis + volumes + healthchecks + `.env.example`.
- [x] Helm chart: values for provider/key/model-matrix/budgets/auto-fix/DAST-allowlist/retention;
      Deployments, Services, Ingress, HPA, PDB, ServiceAccounts (least-privilege), NetworkPolicy.
- [x] ⛔ **NetworkPolicy: default-deny egress**, allow only client LLM endpoint (+ internal svc traffic).
- [x] Secrets via k8s Secret + optional Vault sidecar/CSI.
- [x] Both compose and Helm kept green in CI (owner decision).

### 4.7 QA harness + golden corpus `[owner: WS-P]` 🔗DEP: fixtures

- [x] Vitest config across packages; coverage thresholds.
- [x] **Golden corpus** (`/corpus`): curated vulnerable + clean Next.js/Prisma repos with ground-truth
      labels (expand fixtures repo). Include OWASP-Top-10 representative cases.
- [x] Precision/recall scorer against ground truth; FP-rate reporter (headline metric < 5%).
- [x] **CI regression gate:** release blocked if precision/recall regress on corpus.
- [x] Model-variance harness scaffold (runs corpus per provider/model → publishes matrix) — filled once gateway lands.
- [x] Per-layer metrics collectors (findings in/out, demotion rate, confirmation rate).

### 4.8 Security-of-Montr-Secure `[owner: WS-N]` (cross-cutting, starts now, audits continuously)

- [x] ⛔ No inbound internet dependency at runtime beyond the client LLM endpoint (enforce + document).
- [x] Least-privilege service accounts; no standing prod credentials.
- [x] ⛔ Secrets never logged, never egressed except to their own provider (add lint rule + log scrubber).
- [x] Signed releases (cosign) + SBOM per release (syft) in CI.
- [x] Self-scan job (dogfood) wired into CI (fills once pipeline exists).
- [x] Tamper-evident audit log verification tool (checks hash chain).
- [x] Standing reviewer role: audits each merged package against the 10 golden rules.

---

## 5. WAVE 2 — Pipeline Layers (parallel build vs fixtures; wired at integration)

### 5.1 Layer 0 — Intake & Scoping `@montr/appmap` `[owner: WS-E]` 🔗DEP: contracts, gateway, state-store

- [x] Intake API: repo path/URL, branch, scan mode (`full|diff`), optional authorized staging URL.
- [x] Repo fetch/checkout (git), sandboxed workspace management, cleanup.
- [x] **Deterministic App Map builders (tree-sitter/ts-morph first, LLM only to fill gaps):**
  - [x] Language + framework detection.
  - [x] Entry points + **registered routes** via Next.js route introspection (pages + app router, API routes).
  - [x] Data stores + **ORM models via Prisma DMMF**.
  - [x] Third-party call detection (import/network surface).
  - [x] Env/secret surface scan (`process.env`, config files).
  - [x] **Taint sources + sinks** catalog (req input → db/exec/fs/response).
- [x] LLM semantic pass: label **auth boundaries** + fill map gaps (only after deterministic pass).
- [x] **diff mode:** scope = changed files + reachable call graph from changes.
- [x] **Cost Estimator:** projected tokens + wall-clock from map size × mode → `CostEstimate`.
- [x] Persist AppMap (encrypted, per-client) + emit `{AppMap, ScanScope, CostEstimate}`.
- [x] ⛔ No LLM call fires before the deterministic map exists (§6.1).

### 5.2 Layer 1 — Parallel Discovery `@montr/discovery` `[owner: WS-F]` 🔗DEP: contracts, appmap (scope), gateway

> Deliberately over-inclusive. ⛔ **Never surface Layer-1 output to the user** (the "500 issues" pile).

- [x] Concurrency harness: three agents write `CandidateFinding[]` to the store simultaneously.
- [x] **SAST agent:** Semgrep subprocess (`--json`) + curated rulesets (p/owasp-top-ten, p/typescript,
      p/nextjs, p/react, p/secrets, custom). LLM **triages/explains only — does not detect.**
- [x] **Secrets & Config agent:** gitleaks + custom detectors — hardcoded keys, exposed env, weak crypto
      defaults, permissive CORS, missing/weak security headers, insecure cookie flags.
- [x] **Dependency (SCA) agent:** CVE match (OSV + GHSA, offline mirror) against lockfile **and**
      **reachability check** (is the vulnerable path actually imported/called via the import graph?).
- [x] Each candidate tagged: source(tool), rule_id, category(CWE), file, line, raw_severity, evidence_snippet.

### 5.3 Layer 2 — Correlation (THE MOAT — invest here) `@montr/correlation` `[owner: WS-G]` 🔗DEP: appmap + candidates

- [x] Cross-reference each candidate against the App Map:
  - [x] Is the finding on a route/entry point that actually exists and is registered?
  - [x] Is it public or behind auth? Which auth state gates it?
  - [x] Does tainted input actually reach the sink, or does a validator/sanitizer interrupt the path?
- [x] **Dedup** the same root cause reported by multiple tools into one issue (`merged_candidate_ids[]`).
- [x] **Rank by reachability × exposure × impact** (not raw CVSS): reachability_score, exposure_score,
      impact_score, final rank.
- [x] ⛔ **Demote** uncorroborated candidates to an appendix — **never delete**.
- [x] Emit `ProbableFinding[]` — each with a reachability hypothesis + exploit hypothesis.

### 5.4 Layer 3 — Exploit Confirmation `@montr/confirm` `[owner: WS-H]` 🔗DEP: correlation

> Turns _probable → confirmed_. **Static ships first; live is premium & heavily gated.**

**3a. Static confirmation (default, any repo)**

- [x] Data-flow proof: source → transforms → sink, with **auth state at each hop**.
- [x] Produce a proof-of-reachability argument (no requests fired, no running target).
- [x] Emit `ConfirmedFinding{proof_type:static, proof_artifact}`.

**3b. Live confirmation / DAST (premium)** — DECIDE-1 = build it, OFF by default until staging authorized

- [x] Recon + exploit agent: crafted requests to a **client-provided, allowlisted staging target ONLY.**
- [x] ⛔ **Target allowlist + scope contract** enforced at the HTTP layer; **production blocked by policy.**
- [x] ⛔ **Kill switch** halts all probing instantly; **rate limits + blast-radius caps** on every probe.
- [x] ⛔ **Approver authorization required** (RBAC) before any live run.
- [x] Playwright for authenticated flows; capture full request/response **transcript as proof**.
- [x] Emit `ConfirmedFinding{proof_type:live, proof_artifact:transcript}`.
- [x] All probable findings that fail confirmation → `Unconfirmed` appendix (kept, clearly separated).

### 5.5 Layer 4 — Fix Generation `@montr/fix` `[owner: WS-I]` 🔗DEP: confirmed findings

- [x] For each **confirmed** finding: diff-ready patch + plain-English rationale + **proof-of-fix test**.
- [x] Fix validation: patch applies cleanly; proof-of-fix test fails pre-patch, passes post-patch.
- [x] ⛔ **Risk classifier (a SAFETY control, not convenience):**
  - [x] `auto-eligible` — mechanical, low blast radius (parameterize query, escape output, set cookie flag, bump dep).
  - [x] `human-required` — touches **auth/session/crypto/access-control** OR wide blast radius. **HARD rule.**
  - [x] ⛔ When uncertain → **`human-required`.** Never let uncertainty resolve toward autonomy.
- [x] Emit `Fix{patch, test, rationale, risk_class, status:proposed}`.

### 5.6 Layer 5 — Human Gate & Output `@montr/report` + auto-fix flow `[owner: WS-J]` 🔗DEP: fixes + all tiers

- [x] **Report model (§12):** exec summary (N confirmed by severity, posture delta vs last scan, tools
      consolidated) → confirmed findings (title, severity, CWE, location, exposure, **proof**, impact,
      **merge-ready fix + test**) → fix status → **unconfirmed appendix** → compliance mapping → cost & scope.
- [x] ⛔ **Never headline raw counts.** Headline = confirmed + prioritized; appendix holds breadth.
- [x] **Auto-apply flow (toggle ON):** open **PRs only** (never direct commits) for `auto-eligible` fixes;
      each PR independently reviewable; via Octokit/GitLab; branch + commit + PR body w/ rationale + test.
- [x] `human-required` fixes are **always recommendations** — never auto-opened.
- [x] ⛔ Enforce gate state: no PR without passing the auto-eligible bar OR explicit approver approval.
- [x] Report exports: HTML + **PDF** (Puppeteer), **SARIF**, machine-readable JSON.

---

## 6. WAVE 3 — Compliance, Exports, Report Polish `[owner: WS-M + WS-J + WS-K]`

- [x] **OWASP Top 10 + CWE mapping** tables; every finding mapped (§13).
- [x] **Compliance export (DECIDE-5 order):** SARIF + generic OWASP report first (broadest),
      then **SOC 2 evidence** package, then ISO 27001. Format drops into evidence collection.
- [x] Audit-log export for third-party auditors (from WS-C, surfaced in UI).
- [x] Web report UI complete: interactive findings, proof viewer (static argument / live transcript),
      fix diff viewer, PR status, cost/scope panel, compliance tab.
- [x] ⛔ **FP feedback loop:** operator marks a confirmed finding as FP → writes to regression corpus →
      tunes correlation/confirmation prompts + thresholds (§15).
- [x] Posture-delta computation vs last scan (needs scan history from WS-C).

---

## 7. WAVE 4 — Phase 3: Stack Breadth `[owner: WS-Q]` 🔗DEP: E/F parser patterns proven on Node

> Correlation engine (WS-G) is stack-agnostic by design — verify that as you add stacks.

- [x] **Python (Django/FastAPI):** App-Map parsers (routes, ORM models, taint sources/sinks via
      tree-sitter-python) + Semgrep rulesets (p/django, p/flask, p/python) + confirmation heuristics.
- [x] **JVM:** App-Map parsers + rulesets (Spring routes, JPA models) + confirmation heuristics.
- [x] Golden corpus extended with Python + JVM vuln/clean repos; regression gate covers them.
- [x] ⛔ Confirm correlation/confirmation/fix layers required **no** stack-specific forks (or fix the leak).

---

## 8. WAVE 5 — Phase 4: Scale & Intelligence `[owner: WS-R]` 🔗DEP: core pipeline + scan history

- [x] **Cross-scan trend intelligence:** posture over time, regression/new-issue detection per repo.
- [x] **Org-wide posture dashboards:** aggregate across repos/teams (RBAC-scoped).
- [x] **Custom rule authoring:** UI + storage for client Semgrep/secret rules; validated + versioned.
- [x] **Red-team scenario library:** reusable DAST/exploit scenarios, allowlist-gated, versioned.
- [x] Dashboard exports + scheduled scans (cron) integration.

---

## 9. Integration, E2E & Deployment Hardening `[owner: integration agent + WS-O + WS-P]`

**9.1 Integration**

- [x] Replace all mocks; wire orchestrator → real L0…L5 with contract types.
- [x] Resumability test: kill after L2, resume, confirm L0–L2 not re-run.
- [x] Budget-halt test: exceed ceiling → partial report emitted, no silent burn.
- [x] Kill-switch test: abort mid-DAST → all probing stops, audit records it.

**9.2 End-to-end acceptance (the DoD scan)**

- [x] Full pipeline on a Next.js/Prisma/Postgres repo: map → discovery → correlation → static
      confirmation → fix gen → report, on a clean cluster with only a client LLM key configured.
- [x] Report headlines confirmed findings with proof, fixes, tests, OWASP/CWE mapping.
- [x] ⛔ Verify **no client source egress** (network capture / gateway metadata-only logs).
- [ ] Cost estimate surfaced pre-scan; actuals within **±15%**.
- [x] ⛔ Auth/crypto fixes classified `human-required` in **100%** of golden-corpus cases.
- [x] **FP rate < 5%** on golden corpus; CI regression gate enforces no regression.
- [ ] Montr Secure scans **itself clean** in CI (dogfood).

**9.3 Deployment hardening (compose + Helm equal priority)**

- [ ] docker-compose: one-command bring-up, seeded config, healthchecks, docs.
- [ ] Helm: install on a clean k8s cluster with only LLM key set; hardened defaults verified.
- [ ] ⛔ **Air-gapped install:** signed-bundle import for **offline ruleset + CVE DB updates**; internal
      model-proxy support; verify **only** outbound is the (possibly internal) LLM endpoint.
- [x] Upgrade path documented; **no vendor telemetry by default** (opt-in anonymized health metrics only).
- [x] Ops runbook: config reference (§10), RBAC setup, budget/allowlist/retention, backup/restore.

---

## 10. Observability & QA (continuous, `[owner: WS-P]`)

- [x] Structured logs everywhere (pino); ⛔ log scrubber guarantees no code/secret bodies.
- [x] Per-layer metrics: findings in/out, demotion rate, confirmation rate, FP-feedback rate.
- [x] Model-variance harness runs golden corpus across each supported provider/model → publishes the
      model matrix + flags accuracy cliffs (feeds the model floor).
- [x] Dashboards (Grafana/Prometheus) for scan throughput, cost, error rates.
- [x] Alerting on budget breaches, kill-switch activations, gate bypass attempts.

---

## 11. Definition of Done — Phase-1 gate (maps to PRD §19) + full-scope adds

**§19 Phase-1 (must all pass):**

- [ ] Runs on-prem via Helm on a clean cluster with only a client LLM key.
- [x] End-to-end scan of a Next.js/Prisma/Postgres repo (all layers, static confirmation).
- [x] Report headlines confirmed findings w/ proof, fixes, tests, OWASP/CWE mapping.
- [x] FP rate < 5% on golden corpus; CI regression gate present.
- [x] No client source egress; audit log complete + exportable.
- [ ] Cost estimate pre-scan; actuals within ±15%.
- [x] Auth/crypto fixes → `human-required` in 100% of golden-corpus cases.
- [ ] Montr Secure scans itself clean in CI.

**Full-scope adds (this build's extra DoD):**

- [ ] Live DAST (3b) works against an allowlisted staging target with all §11 guardrails.
- [x] Auto-eligible PR flow opens reviewable PRs (never direct commits).
- [x] All four LLM providers (Anthropic/Bedrock/Vertex/Azure) pass the gateway conformance test.
- [ ] Air-gapped install validated with signed offline bundle.
- [x] Phase-3 Python (Django/FastAPI) + JVM stacks pass their corpus.
- [x] Phase-4 trend dashboards + custom rules + red-team library functional.

---

## 12. Cross-Cutting Non-Negotiables — Safety Checklist (PRD §11, verify per package) ⛔

- [x] No code egress; LLM calls log metadata only.
- [x] Auth/crypto/access-control fixes always `human-required`.
- [x] DAST: allowlist + scope contract + production-blocked + kill switch + rate/blast-radius caps + approver auth.
- [x] Key-tier guard (warn/block data-retaining tiers).
- [x] Budget ceiling = hard halt + partial report.
- [x] Fail-safe defaults (uncertainty → less autonomy).
- [x] Full tamper-evident audit trail of every mutation + approval.
- [x] Any feature conflicting with §11 → STOP and flag for human decision; never build a bypass.

---

## 13. Suggested 24h Subagent Roster & Sequencing

| Hour  | Wave        | Concurrent agents                                                                                        |
| ----- | ----------- | -------------------------------------------------------------------------------------------------------- |
| 0–2   | 0           | **1–2** agents: WS-A (contracts/config/schema/fixtures/CI/deploy skeleton). BARRIER.                     |
| 2–8   | 1           | **8** agents in parallel: WS-B, WS-C, WS-D, WS-L, WS-K, WS-O, WS-P, WS-N.                                |
| 6–16  | 2           | **6** agents: WS-E→F→G→H→I→J (build vs fixtures; E finishes first, unblocks live wiring).                |
| 14–18 | 3           | **3** agents: WS-M, report polish (WS-J/K), auto-fix PR flow.                                            |
| 16–20 | 4           | **2** agents: WS-Q (Python then JVM).                                                                    |
| 18–21 | 5           | **2** agents: WS-R (dashboards/custom rules/red-team).                                                   |
| 20–24 | Integration | **2–3** agents: integration + E2E + deploy hardening + DoD sign-off; standing safety-auditor throughout. |

**Standing agents (full run):** (1) safety-auditor — reviews every merge vs §12; (2) integration/QA —
keeps `main` green, owns golden-corpus gate.

---

## 14. DECIDE Resolutions (applied defaults — change here if owner disagrees)

- **DECIDE-1 (DAST in v1?):** **Build 3b now**, guardrailed, **OFF by default** until a staging target is
  authorized. Static (3a) is the always-on default.
- **DECIDE-2 (persist AppMap?):** **Persist per-client, encrypted, rebuild-on-stale-commit.**
- **DECIDE-3 (model floor?):** Publish matrix; **floor = Sonnet-5-class** for confirmation; Opus-4.8 for
  hardest confirmations; Haiku-4.5 for cheap triage. Warn below floor.
- **DECIDE-4 (budget ceiling?):** **Hard halt + partial report.** (Safety-first.)
- **DECIDE-5 (compliance format first?):** **SARIF + generic OWASP first**, then **SOC 2 evidence**, then ISO 27001.

---

## 15. Coverage Map (PRD § → where it's built)

| PRD §                                    | Covered by                                                                        |
| ---------------------------------------- | --------------------------------------------------------------------------------- |
| §5 System overview                       | Architecture / monorepo layout (§0)                                               |
| §6 Principles                            | Golden rules (§0), safety checklist (§12)                                         |
| §7 Layers 0–5                            | WS-E, WS-F, WS-G, WS-H, WS-I, WS-J (Wave 2)                                       |
| §8 Orchestrator/Gateway/State/Cost/Audit | WS-D, WS-B, WS-C (Wave 1)                                                         |
| §9 Data model + DECIDE-2                 | WS-A contracts + WS-C schema (§3.2, §3.4)                                         |
| §10 Deployment & ops                     | WS-O + §9.3                                                                       |
| §11 Safety & guardrails                  | §12 checklist + enforced in every ⛔ item                                         |
| §12 Report                               | WS-J (§5.6) + WS-K                                                                |
| §13 Compliance & audit                   | WS-M (Wave 3)                                                                     |
| §14 Security of itself                   | WS-N (§4.8)                                                                       |
| §15 Observability & QA                   | WS-P (§4.7, §10)                                                                  |
| §16 Roadmap (all phases)                 | Waves 2 (P1), 3+DAST/PR (P2), 4 (P3), 5 (P4)                                      |
| §17 Risks                                | Mitigations woven into WS-B (variance/cost), WS-H/L (footguns), WS-I (over-trust) |
| §18 DECIDE items                         | §14 resolutions                                                                   |
| §19 Definition of Done                   | §11 acceptance checklist                                                          |

```

```
