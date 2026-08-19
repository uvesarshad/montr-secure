# Audit — Montr Secure build state vs. PRD / build-plan / handoff

**Date:** 2026-08-17
**Scope:** `docs/plan/montr-secure-prd.md`, `docs/plan/montr-secure-build-plan.md`, `docs/plan/HANDOFF.md`
vs. the committed code at `632bf9b` (clean tree).
**Method:** full local gate run by the coordinator + six parallel verification subagents, one per
cluster (safety rules · L0–L2 · L3–L5 · cross-cutting platform · apps · deploy/CI · QA/phases).
Every P0 below was re-verified by the coordinator directly, not taken on a subagent's word.

---

## Where the build actually stands

**The gate is green exactly as documented.** Reproduced locally on Node 24 / pnpm 9.12:

```
typecheck 0 · build 19/19 · 632 tests passing (62 files) · lint 0 · pnpm e2e 15/15
```

The library layer is real. This is not a scaffold with `TODO` bodies — 321 source files, ~46k LOC,
and the packages that matter are genuinely implemented: Layer 0 uses real ts-morph/tree-sitter and
Prisma DMMF; Layer 2 is deterministic grounding + scoring with the LLM bounded to a ±delta nudge;
the risk classifier is a hard rule-first safety control; all four LLM adapters import real provider
SDKs; the audit log is genuinely hash-chained with a working tamper CLI. **All 11 golden
rules / §11 guardrails verified against real enforcement code**, not documentation. That cluster came
back the strongest in the whole audit.

**But the "188/198, only real-infra validation remains" framing is wrong.** The handoff says what
remains is _execution_ on real hardware. In fact three things that are checked off or claimed ✅ are
not built at all, and the product cannot currently run outside the test harness:

- Neither `apps/api` nor `apps/worker` has a runnable entrypoint. Both are library-only.
- The web console cannot talk to the API — different URL scheme, different auth mechanism.
- The headline `<5% false-positive` metric is measured by scoring ground truth against itself.

So the honest status is roughly: **excellent library + safety layer, unintegrated product.** The
188/198 count is credible for the package-level boxes and misleading for the system-level ones. The
10 unchecked boxes are honestly unchecked; the problem is a handful of _checked_ ones and several
`DOD.md` ✅ marks that the code contradicts.

---

## P0 — broken / at-risk

### A1 (P0) — `apps/api` and `apps/worker` have no runnable entrypoint; the containers boot nothing

`apps/api/src/index.ts` and `apps/worker/src/index.ts` are pure re-export barrels. Nothing anywhere
in the repo calls `createApiServer(...).listen()` or `worker.start()` at module scope — `app.listen`
appears exactly once, inside an uncalled factory (`apps/api/src/server.ts:109`). There is no
`main.ts`, no `bin`, and no `start` script in either `package.json`.

Both Dockerfiles do `CMD ["dist/index.js"]` (`Dockerfile.api:57`, `Dockerfile.worker:67`), so the
container runs a module whose only effect is defining exports, then exits. `docker compose up` cannot
work, and the compose `migrate` service passes `["dist/index.js", "--migrate"]` to a program with no
argv handling at all (no `process.argv` reference exists in either app).

The only realized wiring is `createInMemoryDeps()` (`apps/api/src/server.ts:136`), whose own comment
reads _"For local dev and unit tests only — never production"_, backed by `createStubOrchestrator`
(`apps/api/src/stub-orchestrator.ts:1-6`, _"performs NO pipeline work"_).

This invalidates build-plan §4.6 and makes the unchecked §9.3 compose/Helm boxes unreachable — they
are blocked on missing code, not on missing infrastructure.

### A2 (P0) — the golden-corpus CI gate scores ground truth against itself; the `<5% FP` headline is unvalidated

`.github/workflows/ci.yml:84` runs `pnpm --filter @montr/qa qa:corpus` with **no** `--findings`
argument. Per `packages/qa/src/cli.ts:142-149`, that path defaults to
`runCorpus(corpus, perfectScanner, ...)`, and `perfectScanner`
(`packages/qa/src/runner.ts:40` → `synthetic.ts:44`) reads the ground-truth manifest and emits
exactly those findings back as "confirmed." Precision 1.0 / FP-rate 0 is therefore tautological — the
gate cannot fail on any pipeline regression, only on its own plumbing breaking.

Nothing in the repo ever produces a `scan.json` to feed `--findings`; I grepped every workflow,
script and package manifest. The real pipeline is never scored against the corpus anywhere in CI.

`DOD.md` §19-4 presents this as ✅ with _"golden corpus scores 8 repos at precision 1.0 / FP-rate 0"_
— that number is an artifact of the synthetic scanner, and citing it as evidence of the PRD §4
headline metric is not defensible.

Partial mitigation: `apps/worker/src/e2e-scan.test.ts:464-478` does grade _real_ Layer-3 output and
asserts `fpRate < 0.05` — but on one repo yielding two true positives, which clears 5% trivially.

### A3 (P0) — the web console cannot talk to the real API; it is mock-only, not "mock-first"

Two independent, mutually incompatible contracts:

- **Paths.** Web calls `/api/v1/scans/:id/gate/estimate`, `/gate/fix`, `/kill`, `/progress`,
  `/appmap`, `/report`, `/fixes`, `/export`, `/me` (`apps/web/src/lib/api/config.ts:10-30`). The API
  registers unprefixed `/scans/:id/estimate/approve`, `/scans/:id/gate/approve`, `/scans/:id/status`,
  `/scans/:id/cancel` (`apps/api/src/routes/scans.ts`, `gate.ts`). Almost nothing lines up.
- **Auth.** Web authenticates with `x-montr-actor-id` / `x-montr-actor-role` headers
  (`config.ts:53-54`) — trivially spoofable, and `grep -rn "x-montr-actor" apps/api/src` returns
  **zero** hits. The API expects a JWT cookie/bearer.

MSW is on unless explicitly disabled (`apps/web/src/components/providers.tsx:10`:
`NEXT_PUBLIC_USE_MSW !== "false"`). The config file's own header admits _"Until then MSW mocks them."_
Closing this needs a real integration pass on one side or the other, not a config flag.

### A4 (P0) — `Dockerfile.worker` will fail to build: wrong osv-scanner asset filename

`deploy/docker/Dockerfile.worker:53-54` fetches
`osv-scanner_${OSV_SCANNER_VERSION}_linux_amd64`. Network-verified just now:

| URL                                        | Status  |
| ------------------------------------------ | ------- |
| `.../v1.9.1/osv-scanner_1.9.1_linux_amd64` | **404** |
| `.../v1.9.1/osv-scanner_linux_amd64`       | **200** |

The real asset carries no version in its filename. `curl -fsSL` fails → the `RUN` layer exits
non-zero → the worker image never builds, and the CI `docker` job (`ci.yml:155`) fails on every run.
This also means build-plan §4.6's _"Both compose and Helm kept green in CI"_ is false today.

(The sibling gitleaks URL at line 51 is correct — `gitleaks_8.21.2_linux_x64.tar.gz` matches the real
release asset.)

### A5 (P0) — the Helm web pod will crash-loop: wrong container args

`deploy/helm/montr-secure/templates/deployment-web.yaml:42` sets `args: ["dist/index.js"]`, which
overrides the image's `CMD ["apps/web/server.js"]` (`Dockerfile.web:57`; the distroless nodejs
ENTRYPOINT is bare `node`). The web image contains only the Next standalone tree — I ran
`pnpm --filter @montr/web build:next` successfully and confirmed the output is `apps/web/server.js`;
there is no `dist/index.js` in that image. The pod fails with `Cannot find module '/app/dist/index.js'`.

The api and worker deployments correctly use `args: ["dist/index.js"]`, matching their CMDs — only
web is wrong. `helm lint`/`template`/kubeconform all pass, because this is a runtime defect, not a
schema one.

---

## P1 — should fix

### A6 (P1) — `deploy/airgap/` has no tooling, but `DEPLOY.md` documents commands that don't exist

The directory contains only `README.md` and `manifest.schema.json`. Its own README states _"Nothing
here ships in Wave 0; this directory reserves the layout."_ Meanwhile `DEPLOY.md:88,91` instructs the
operator to run `deploy/airgap/build-bundle.sh --sign` and `deploy/airgap/import-bundle.sh <file>`.
Neither script exists. The build plan honestly leaves the air-gap box unchecked; `DOD.md` marks
_"Air-gapped install path ✅"_, contradicting both.

### A7 (P1) — the CI self-scan (dogfood) is a no-op, yet `DOD.md` marks it ✅

`ci.yml:95-129`: the Semgrep and gitleaks steps are both `continue-on-error: true` and non-blocking,
and the actual "Montr self-scan hook" only fires `if pnpm run | grep -qw selfscan`. No `selfscan`
script exists in any `package.json` in the repo, so the step prints _"No 'selfscan' script yet"_ and
exits. The product never scans itself with its own pipeline. Build-plan line 466 correctly leaves
this unchecked; `DOD.md` §19-8 claims ✅.

### A8 (P1) — the SCA "OSV + GHSA offline mirror" is a three-entry hardcoded array

`packages/discovery/src/advisories.ts:1-9` is a hand-authored seed list covering lodash, minimist and
axios, self-documented as a placeholder for the real signed bundle. The matcher and the import-graph
reachability check around it are real and good; the _data_ is effectively absent, so SCA coverage is
near-zero on any actual repo. Build-plan §5.2 claims "CVE match (OSV + GHSA, offline mirror)" as done.

### A9 (P1) — prompt registry / versioning is a Prisma model with no runtime code

`PromptVersion` exists in `schema.prisma`, but `grep -rn "PromptVersion" packages/state-store/src`
returns zero hits, and nothing in `packages/llm-gateway/src` reads or writes it. Build-plan §4.1
checks off "Prompt registry/versioning hook (feeds §15 regression tuning)"; the §15 tuning loop it is
supposed to feed therefore has no versioned prompt to tune against.

### A10 (P1) — `packages/cost-meter` has zero tests despite owning the budget hard-halt

`"test": "vitest run --passWithNoTests"` with no test files in the package. The hard-halt is a §11
non-negotiable (DECIDE-4) and the code that throws `BudgetExceededError` (`variance.ts:64-74`) is
untested at unit level. It is exercised indirectly via `tests/cost-meter.core.test.ts` and the
orchestrator budget-halt test, so this is a coverage gap rather than an unverified control — but for
a money-and-safety component it should own its own suite.

### A11 (P1) — dashboards and alerting are checked off with no corresponding files

Build-plan §10 lines 485-486 check _"Dashboards (Grafana/Prometheus)"_ and _"Alerting on budget
breaches, kill-switch activations, gate bypass attempts."_ The repo has a metrics exporter
(`packages/telemetry/src/otel.ts`, `metrics.ts` — real OTel counters) but **no** Grafana dashboard
JSON, no Prometheus recording/alert rules, no Alertmanager config, and no counters specific to
budget-breach / kill-switch / gate-bypass. Metrics exist to be dashboarded; nothing was built on top.

### A12 (P1) — the NetworkPolicy is not default-deny out of the box

`deploy/helm/montr-secure/templates/networkpolicy.yaml` is correctly structured (DNS +
intra-namespace + a single `ipBlock` for the LLM endpoint), but `values.yaml:242` ships
`cidr: "0.0.0.0/0"` on port 443. Installed with defaults, the cluster permits egress to any host on
443 — the opposite of the ⛔ guarantee in build-plan §4.6. The values file admits this in a comment.
It becomes default-deny only once an operator supplies a real CIDR.

### A13 (P1) — the Wave-5 posture dashboard page is a self-documented empty stub

`apps/web/src/app/dashboards/page.tsx` carries the comment _"STUB SEAM (WS-R fills)… intentionally
data-free so it builds against the empty stub endpoints."_ Build-plan §8 checks off "Org-wide posture
dashboards." The backing contracts and `PostureRepositoryImpl` are real; the UI is not. The `rules`,
`scenarios` and `schedules` pages likewise hit routes registered as declared "stub seams"
(`apps/api/src/routes/rules.ts` header comment).

### A14 (P1) — `AUTO_ELIGIBLE_CATEGORIES` overstates automation coverage 2×

`packages/fix/src/risk.ts:28-37` lists 8 auto-eligible categories; `FIX_STRATEGIES`
(`strategies.ts:155-160`) implements mechanical transforms for 4 (sql_injection, xss,
permissive_cors, hardcoded_secret). The other four (`nosql_injection`, `insecure_cookie`,
`missing_security_headers`, `vulnerable_dependency`, `open_redirect`) always fall through to
`generateAdvisory`, which hardcodes `uncertain: true` → `human-required`. Fails in the safe
direction, so not a safety defect — but the advertised auto-fix surface is half what it claims.

### A15 (P1) — no `/scans/:id/kill` HTTP route, though the UI and orchestrator both have kill

The orchestrator implements a real cross-process kill switch (Redis pub/sub + `AbortController`) and
the web client exposes `killSwitch: (scanId) => .../kill` (`config.ts:25`), but no such route is
registered in `apps/api/src/routes/`. The ⛔ kill switch is unreachable over HTTP. Given A1 and A3
this is currently moot, but it must land with the integration work.

### A16 (P1) — Semgrep/gitleaks JSON parsing has never run against the real binaries

Neither tool is on this host (verified), so the E2E ran in `seeded-candidates` mode, as documented.
The subprocess integration code is real and unit-tested, but only against hand-built fixture JSON —
so the parsers (`parseSemgrepJson`, `candidatesFromGitleaks`) have never seen real tool output, whose
shape could differ. Combined with A4 (the image that bundles those scanners doesn't build), the live
discovery path is entirely unexercised.

### A17 (P1) — the golden corpus is smoke-test sized for a `<5%` claim

8 repos (4 vulnerable / 4 clean) and 19 labelled findings total, across three stacks: 4 Next.js
(`corpus/ground-truth.manifest.json`) + 5 (`packages/fixtures/sample-repos/`) + 5 Python + 5 JVM.
Clean repos contribute 0 expected findings. At this sample size a single false positive swings the
metric by tens of points, and `corpus/baseline.json` demands `fpRateMax: 0` per category. The corpus
is fine for wiring and gross-regression smoke tests; it cannot support a production accuracy figure.
Separate from A2, which is about the gate not using it at all.

### A18 (P1) — vitest coverage thresholds are absent though the box is checked

`vitest.config.ts:33-37` configures a coverage provider and reporters but no `thresholds` key, and no
CI step enforces a floor. Build-plan §4.7 checks off "Vitest config across packages; coverage
thresholds." Coverage can drop silently.

---

## P2 — nice to have

- **A19 (P2)** — `pnpm -w build` reports 19/19 but `@montr/web`'s `build` script is just `tsc -b`;
  the real Next build only runs under `build:next`. The green build never covered the web app. I ran
  `build:next` manually and it succeeds (15 routes, webpack), so this is a reporting gap, not a break.
- **A20 (P2)** — Build plan §4.4 specifies argon2; `apps/api/src/auth/password.ts` uses `node:crypto`
  scrypt with constant-time compare. Fine cryptographically, but the plan is wrong.
- **A21 (P2)** — Build plan names `@azure/openai`; the adapter uses the `openai` package's
  `AzureOpenAI` class (`openai@^6.45.0`). Functionally equivalent, factually divergent.
- **A22 (P2)** — "Vault/KMS" key sourcing is env/file/secret-mount bytes only; no Vault or KMS client
  is integrated. It is a pluggable seam, not an implemented integration.
- **A23 (P2)** — Audit-log append-only is enforced at the application layer only. No DB trigger or
  revoked UPDATE/DELETE grant (`schema.prisma:519-539`), and `retention.ts:57-62` calls
  `auditEvent.deleteMany` when `auditImmutable` is set false. Tamper-_evidence_ (the hash chain) is
  solid; tamper-_prevention_ is a config toggle.
- **A24 (P2)** — Layer 2's "does taint reach the sink" is a same-file nearest-line proximity
  heuristic plus a sanitizer regex (`correlation/src/grounding.ts:174-196`), not interprocedural
  dataflow. Reasonable for a first-pass signal; weaker than the "moat" framing implies for cross-file
  flows. Worth noting sink descriptions are AST-derived (`appmap/.../taint.ts:89-140`), never
  LLM-authored — I checked, because the static proof keys off them.
- **A25 (P2)** — `exploitHypothesis` always cites `appMap.ormModels[0]` regardless of the model
  actually involved (`correlation/src/hypotheses.ts:105`).
- **A26 (P2)** — `validatePatch` (`fix/src/patch.ts:54-71`) evaluates the vulnerability predicate
  pre/post patch directly rather than running the emitted `.proof-of-fix.test.ts` through vitest.
  Logically equivalent (same regex), but "the proof-of-fix test is executed" isn't literally true.
- **A27 (P2)** — The red-team "scenario library" is storage + versioning + a well-gated execution
  engine with **no shipped scenario content**. Clients populate it from scratch.
- **A28 (P2)** — `docker-compose.yml:21,148` forces `user: "65532:65532"` on the worker, whose image
  is `node:20-bookworm-slim` chowned to `node` (~uid 1000). Probably works on world-readable files;
  untested and undocumented.
- **A29 (P2)** — Stale comment: `appmap/src/languages/registry.ts:22-23` still calls Python/JVM
  "pre-registered stubs." Both analyzers are fully implemented.
- **A30 (P2)** — `packages/contracts` and most of `llm-gateway` (retry/model-floor/keytier) have no
  own test suites; `llm-gateway` tests cover only egress guards.

---

## What held up well (so it isn't lost in the finding list)

- **All 11 golden rules / §11 guardrails verified against enforcement code**, with genuine
  (non-tautological) tests. Notably: the provider-SDK ban is really lint-enforced with a
  `packages/llm-gateway/**` carve-out and a clean repo-wide grep; `prOnly: z.literal(true)` and
  `dast.productionBlocked: z.literal(true)` are schema-locked so they _cannot_ be configured off; the
  auth/crypto → `human-required` rule cannot be overridden by config (options can only add
  restrictions); every uncertainty path resolves toward less autonomy.
- **The stack-agnostic invariant is real.** `tests/stack-agnostic.invariant.test.ts` structurally
  greps correlation/fix/report for framework tokens _and_ guards against a vacuous pass, then runs
  real Python and JVM App Maps through the real `correlate()`. Python/JVM parsing is genuine
  tree-sitter WASM, not regex.
- **Resumability, budget-halt and kill-switch tests are rigorous**
  (`tests/orchestrator.pipeline.test.ts:453-585`) — the resume test asserts L0–L2 call counts are
  literally 0 on a fresh controller.
- **All four LLM adapters import real provider SDKs**, and the model IDs match the plan
  (`claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5-20251001`).
- Layer 0's determinism ordering is structurally enforced, not merely documented: `appMapId` is a
  required field on the Layer-1 job schema, so L1 cannot even be scheduled without a persisted map.

---

## Feature suggestions, enhancements & upgrades

1. **Add real entrypoints** — `apps/api/src/main.ts` and `apps/worker/src/main.ts` with graceful
   shutdown, plus `start` scripts and corrected Docker CMDs. This is the single unblocking change.
2. **Wire the corpus gate to real output** — have the E2E emit `scan.json` and make CI run
   `qa:corpus -- --findings scan.json`. Until then the headline metric is decorative.
3. **Pick one web↔API contract and converge** — prefer versioning the API under `/api/v1` and moving
   the web client onto the JWT/cookie flow; delete the actor-header shim entirely.
4. **Ship the real OSV/GHSA offline mirror** with the signed-bundle importer, closing A8 and the
   air-gap DoD box together.
5. **Reconcile `DOD.md` with the code** — four ✅ marks (Helm-on-cluster, self-scan, air-gap,
   FP-rate) are not supported. A doc that overstates is worse than an unchecked box.
6. **Python/JVM mechanical fix strategies** (the handoff's existing follow-up) — and while there,
   close the A14 gap so the auto-eligible list matches implemented strategies.
7. **Upgrade Layer 2 to real interprocedural dataflow** for cross-file taint. This is the actual moat
   and currently the weakest link in the precision story.
8. **Grow the corpus toward real-world repos** with a documented sampling method, so the `<5%` claim
   can be defended rather than illustrated.
9. **Ship Grafana dashboards + Prometheus alert rules** for budget breach, kill-switch activation and
   gate-bypass attempts, with dedicated counters.
10. **Harden the audit log at the database layer** — revoke UPDATE/DELETE from the app role, or add a
    trigger, so immutability survives an application-layer compromise.
11. **Seed the red-team scenario library** with a starter catalogue mapped to OWASP Top 10.
12. **Add a real integration smoke test in CI** — compose up, hit `/health`, run one scan end to end.
    That single test would have caught A1, A3 and A5 before they were checked off.
