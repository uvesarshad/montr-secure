# Audit — Montr Secure: AI depth, autonomy & purple-team gaps

> Scope: whole product, audited against `docs/plan/montr-secure-prd.md` **and** against the stated
> product goal that supersedes it — _"purple teaming: red and blue teaming and testing any kind of
> software via AI agents, completely autonomous."_
> Method: full-repo read plus seven parallel verification agents, one per subsystem. Every finding
> below was read from source, not from docs. Claims that the docs make but the code does not keep
> are called out as such.

---

## Executive summary

**The engineering is real. The AI is not.**

This is not a vaporware audit. The deterministic half of this product is genuinely well built: real
`ts-morph` and `web-tree-sitter` AST engines across three languages, real Semgrep/gitleaks
subprocess integration proven against captured real-binary output, a real ~3,600-entry OSV/GHSA
offline mirror, real AES-256-GCM field encryption, a real hash-chained audit log with a Postgres
`BEFORE UPDATE OR DELETE` immutability trigger, real per-probe DAST guards, real Octokit/GitBeaker
PR automation, schema-valid SARIF, a blocking golden-corpus CI gate, and a blocking self-scan. There
are effectively **zero dangling TODO stubs** in the codebase. Prior audit cycles closed 42/42 items
and it shows.

The problem is the other half. Three numbers define this audit:

| Measure                                           | Value                  | Source                                   |
| ------------------------------------------------- | ---------------------- | ---------------------------------------- |
| LLM call sites in the entire product              | **5**                  | one per layer L0–L4; L5 has none         |
| Max LLM output tokens per call                    | **512 – 2,048**        | correlation gets 512, confirmation 1,024 |
| Measured recall on the golden corpus              | **25%** (TP=11, FN=33) | `corpus/baseline.json`                   |
| Measured recall on IDOR and broken access control | **0%**                 | `corpus/baseline.json`                   |

Every one of those five LLM calls is a single request/response. None can use a tool. None can loop.
None can see the codebase. And — this is the crux — **every one of them is architecturally clamped
so it can only ever reduce the finding set, never add to it**:

- Layer 0 may only fill `authState: "unknown"`; a known value is never overridden (`appmap/src/llm.ts:161`).
- Layer 1 triage may not add or remove a candidate, only annotate (`discovery/src/triage.ts:123-136`).
- Layer 2 may nudge a score by at most ±0.2 at 0.5 trust; demotion is decided before the LLM is
  consulted (`correlation/src/llm.ts:132-141`, `correlate.ts:132`).
- Layer 3 has **no code path that reads `confirmed === true`** — only the demotion branch exists
  (`confirm/src/static.ts:369`).
- Layer 4's patch must pass deterministic validation before it counts.

That design was a deliberate, defensible safety choice, and it worked exactly as intended: the
false-positive rate is 0%. But it also means **the ceiling of this product is precisely whatever
Semgrep and a few hundred regexes can find.** The AI cannot raise it. That is why recall is 25%, and
it is not a coincidence that the two categories sitting at 0% — IDOR and broken access control — are
the two that require semantic reasoning about ownership and roles rather than pattern matching.

The headline "false-positive rate < 5%" is therefore true but nearly vacuous: with only 11 confirmed
findings ever scored, a single false positive breaks it, and a scanner that confirms almost nothing
trivially achieves it. `DOD.md` marks this ✅ without surfacing the recall number.

**On the purple-team goal specifically:** there is no blue team. No MITRE ATT&CK mapping, no
detection-rule output, no threat modeling, no runtime/IAST. The red side is a fixed list of roughly
five payloads across four vulnerability classes. "Any kind of software" is three languages of source
code — no IaC, containers, cloud posture, SBOM, supply chain, mobile, binaries, API specs, or
LLM-application security. "Completely autonomous" has no trigger surface: no CLI, no GitHub App, no
PR check. And the pipeline is a hardcoded linear `switch` with no branching, no re-planning, and no
escalation.

A secondary systemic pattern is worth naming up front: **"built but unwired."** Several subsystems
that prior task lists marked _done_ are real, tested code with **zero production callers** — the
Vault key source, the prompt registry, the false-positive tuning loop, gateway streaming. The seams
exist; nothing injects them. See A10.

---

## P0 — broken / at-risk

### A1 (P0) — Cost metering silently prices unknown models at $0, defeating the budget hard-halt

`packages/cost-meter/src/pricing.ts:70` is `if (!rate) return 0;` — no warning, no metric, no error.
The rate card (`packages/contracts/src/llm.ts:212-232`) contains exactly **three** models, all
first-party Anthropic: `claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5-20251001`.

Missing: `claude-opus-5` (the current flagship), Fable 5, Opus 4.7/4.6, Sonnet 4.6, **every Azure
OpenAI model**, and the partner rates for Bedrock and Vertex — despite all four provider adapters
shipping and working. A client who points the gateway at any unlisted model runs the entire scan
with a meter reading $0. Consequences:

- The budget ceiling never fires. PRD §11 lists this as non-negotiable: _"Hard stop with partial
  report if exceeded; never silently burn client tokens."_ This does exactly that.
- The ±15% estimate-vs-actual metric (PRD §19, DOD item 6) is computed against zero.
- `DOD.md` item 6 already concedes actuals record "≈$0" under the fake adapter — the same code path
  produces ≈$0 against a _real_ provider on an unlisted model, which is far worse and undisclosed.

Fix: fail closed. An unknown model id must either raise or bill at a configured conservative
ceiling rate, and must emit a warning + metric either way.

### A2 (P0) — Budget is only evaluated between layers, never during one

`packages/orchestrator/src/controller.ts:446-465` runs `await this.executeLayer(...)` to completion
and _then_ calls `enforceBudget`. `LiveCostMeter.checkBudget` is a pure synchronous computation over
already-accumulated totals; there is no hook inside `gateway.complete()`/`stream()` that consults
remaining budget before or during a call. A single layer can therefore exceed the ceiling without
limit; the halt only prevents the _next_ layer from starting.

This is currently masked because each layer makes at most one LLM call — which is precisely the
property that every recommendation in this audit's enhancement section will change. Fix this before
deepening the AI, not after.

### A3 (P0) — Pipeline resumability is real but unreachable in production

The mechanism is correct: `controller.ts:821-838` appends each completed layer to a persisted
`ResumeToken` _after_ `persistLayerOutput` succeeds, and `resume()` (`controller.ts:267-309`)
correctly skips finished layers and re-checks gate state.

But **nothing in the shipped product ever calls it.** There is no `POST /scans/:id/resume` route,
and `apps/worker/src/main.ts` has no boot-time reconciliation that finds stuck `status: "running"`
scans. The only `resume` in `apps/api` is on `stub-orchestrator.ts:66`. A worker crash mid-layer
parks a scan as `running` forever.

It compounds: BullMQ workers are created with default stalled-job handling
(`bullmq-scheduler.ts:189-201` — no `maxStalledCount`/lock tuning), so a crash can trigger automatic
redelivery of the same job; `FindingRepo.bulkCreate` (`state-store/src/repositories.ts:234-238`) is a
bare `createMany` with no `skipDuplicates`, so the re-run throws a unique-constraint error →
`failScan` → the scan is now permanently `failed`, with no resume path to recover it.

PRD §8.1 requires "idempotent and resumable." The code is; the product isn't.

### A4 (P0) — Air-gapped installs silently produce zero SAST findings

Semgrep is invoked with **hosted registry pack IDs** — `p/owasp-top-ten`, `p/typescript`,
`p/nextjs`, `p/react`, `p/secrets` (`discovery/src/detectors/sast.ts:24-30`), plus `p/python`,
`p/django`, `p/flask`, `p/java`, `p/spring`. Resolving those requires network egress to Semgrep's
registry. The hardened NetworkPolicy permits only the LLM endpoint.

When Semgrep fails or is absent, `detectSast` logs a warning and returns `[]`
(`sast.ts:152-155`) — the scan proceeds, completes, and issues a confident report built on zero
static findings. There is no first-party rule content in this repo at all.

`deploy/airgap/build-bundle.sh` accepts `--semgrep-rules-dir` but its own comment states the
problem plainly: _"no runtime 'load rulesets from disk' path exists in packages/discovery."_ Verified
— there is no config key for a local ruleset directory anywhere in `packages/config/src/schema.ts`.

So the air-gap install path ships, imports a signed bundle, and then ignores it. Two fixes needed:
a `rulesetsDir` config that Semgrep is pointed at, and a **hard failure** (not a warning) when a
required detector is unavailable, so an empty scan can never masquerade as a clean one.

### A5 (P0) — The console's live layer progress is a facade with no backend

`apps/web/src/lib/api/hooks.ts:22-29` polls `GET /scans/:id/progress` every 4 seconds. **That route
does not exist** in `apps/api` — verified, zero matches across `apps/api/src/routes/`. The client's
own config file admits it (`apps/web/src/lib/api/config.ts:38-40`: _"NOT YET IMPLEMENTED
server-side… 404s until added"_).

Meanwhile the orchestrator _does_ emit a real event stream (`packages/orchestrator/src/events.ts`,
`EventBus.subscribe`) that `apps/api` never subscribes to. The scan detail page renders
`<LayerProgress events={progress ?? []} />`, so in production every layer displays `pending`
permanently. It only appears to work under the MSW mock handlers.

Same class, also 404: `/scans/:id/appmap`, the cross-scan `/pull-requests` aggregate, and
`authorizeDast`.

### A32 (P0) — Real-time cost metering was never wired into the production gateway

Discovered during implementation of A2 (pre-call budget guard). `apps/worker/src/main.ts`'s
`createLlmGateway` call constructs the shared `LLMGateway` with no `costMeter` option, and no layer
package (`appmap`, `discovery`, `correlation`, `confirm`, `fix`) ever passes `ctx.costMeter` into a
gateway call. `CostMeter.record()` — the function that turns a completed call's token usage into
accumulated spend — is therefore never invoked anywhere in the real pipeline. The between-layers
`enforceBudget` check (`controller.ts`) has consequently always been evaluating against
`spentUsd: 0`, regardless of how much was actually spent. A2's new pre-call estimate guard is real
and independent of this gap (it estimates the pending call's own cost against ceiling, not
cumulative recorded spend), but it is currently the _only_ live budget enforcement in production —
actual metered accumulation across a scan's calls is dead code. Wire `costMeter` through gateway
construction in `apps/worker/src/main.ts` and every real layer call site so recorded spend reflects
reality and `enforceBudget` has real numbers to check.

---

## P1 — should fix

### A6 (P1) — Recall is 25% and the Definition of Done doesn't say so

`corpus/baseline.json` records an honest real-pipeline measurement: **TP=11, FP=0, FN=33,
precision 100%, recall 25.0%, fpRate 0.0%** across 16 repos / 44 labelled exploitable findings. Per
category, `idor` and `broken_access_control` are both at **`recallMin: 0`** — the file states
outright that the confirmation pipeline "does not yet do" ownership/role reasoning for any stack.

Credit where due: the baseline file is unusually candid, and the CI gate that reads it is genuinely
blocking. The problem is presentation and statistical power:

- `DOD.md` item 4 is marked ✅ on "FP < 5%" without surfacing that the rate is 0% because the
  scanner confirms almost nothing. With n=11, one false positive breaks the headline metric.
- PRD §4 makes false-positive rate the headline metric and never sets a recall floor. A scanner that
  misses three of every four known vulnerabilities in its own curated corpus cannot be sold on
  "consolidate your tools" — it consolidates them into something that finds less than any one of them.

Recall needs to become a first-class, published metric with a real floor, and the DoD needs to state
both numbers together.

### A7 (P1) — The LLM is structurally incapable of finding a vulnerability

This is the direct answer to "the AI feels basic," and the root cause of A6.

Every LLM call is clamped to _subtract_. The clamps are listed in the executive summary above; the
decisive one is `confirm/src/static.ts:369`, where the `confirmed === true` branch **does not exist
in the code** — the deterministic engine must already have proven reachability before the model is
even consulted, and the model's only wired effect is demotion.

The consequence is arithmetic: the product's recall ceiling equals the recall of Semgrep plus ~27
first-party regexes plus a 1–2 hop TypeScript call graph. The LLM cannot lift it by design. IDOR and
broken access control sit at 0% because they need exactly the semantic reasoning the architecture
forbids.

The fix is _not_ to remove the safety rails — it is to change what earns autonomy. Let the model
**propose**, then require **executable evidence** (a failing test, a live probe transcript) before a
proposal reaches `confirmed`. Autonomy earned by proof, not granted by trust. See enhancements E1/E2.

### A8 (P1) — No agentic capability anywhere in the product

Confirmed exhaustively across all five call sites:

- **No tool use.** `llm-gateway/src/mapping.ts:5-8` states it outright: _"Tool/function-calling
  passthrough is intentionally out of scope… adapters ignore `request.tools`."_ The contracts define
  `LLMToolDefinitionSchema` and a `tools` field; nothing ever populates them.
- **No loop, planner, multi-agent, critique, or self-consistency.** Every call is build request →
  await → `JSON.parse` → clamp → done.
- **No memory across scans, no embeddings, no RAG, no codebase index.** Grepped for
  `embedding|vector|pgvector|retriev` — zero real hits.
- **No extended thinking**, no `effort`, no prompt caching sent (`cache_control` appears nowhere,
  though `cost-meter/pricing.ts:70-76` already prices cache reads/writes for a feature never used).
- **Streaming is implemented per-adapter and never called** by any layer.
- Output caps: 512 (correlation), 1,024 (appmap, confirmation), 2,048 (fix). The entire pipeline
  spends on the order of a few thousand output tokens of model reasoning per scan.
- All six prompts are zero-shot, 1–5 sentences, no examples, no chain-of-thought, and four of the
  five send **metadata only, never code**.

### A9 (P1) — Live DAST is four categories and roughly five payloads

`LIVE_CONFIRMABLE_CATEGORIES` (`confirm/src/live.ts:35-40`) is `sql_injection`, `nosql_injection`,
`xss`, `open_redirect` — 4 of ~23 categories in the taxonomy. `craftProbes` (`live.ts:118-173`) is a
`switch` producing 1 baseline + 1 payload each; everything else hits `default: return []`.

Notably, **NoSQL injection reuses the SQL string payload** `' OR '1'='1` (`live.ts:142`) rather than
a Mongo operator payload — it will essentially never fire. There are no SSRF, IDOR, authz, path
traversal, command injection, XXE, or deserialization probes. The oracle (`live.ts:197-256`) is fixed
string/status matching.

The transport and guards are genuinely good — real `undici` requests, real `playwright-core` login
flows, strict host-equality allowlist that defeats suffix bypass, per-probe kill-switch checks, real
sliding-window rate limiting, blast-radius counters. The engine is sound; it has almost no ammunition
and no ability to aim. There is zero LLM involvement in `live.ts` or `scenarios.ts`.

### A10 (P1) — "Built but unwired": real subsystems with zero production callers

A systemic pattern, and the reason several prior task-list items marked _done_ did not change
product behavior. Each of these is real, tested code that nothing in the shipped path injects:

| Subsystem                  | Evidence                                                                                                                                                                                                         | Previously marked |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Vault key source           | `config/src/key-source.ts` — `createKeySource`/`resolveFieldEncryptionKey` have **zero callers**; both `worker/src/main.ts:53-58` and `api/src/production-deps.ts:125-126` read `fieldEncryptionKeyRef` directly | A22 ✅            |
| Prompt registry            | `gateway.resolvePrompt` is never called by any of the five prompt sites; all pass hardcoded constants                                                                                                            | A9 ✅             |
| FP feedback tuning         | `fpTuning` is an optional param on `CorrelateInput`/`ConfirmDeps`; `apps/worker/src/runners.ts` never populates it. Operator FP marks are audited and stored but change nothing                                  | §15 loop          |
| Gateway streaming          | implemented in all four adapters, called by no layer                                                                                                                                                             | —                 |
| `report_synthesis` purpose | enum value in `contracts/src/llm.ts:34` with no caller; Layer 5 has no LLM at all                                                                                                                                | —                 |

Recommend a CI check that asserts each declared seam has at least one non-test caller, so "wired" is
verified rather than assumed.

### A11 (P1) — Model matrix is stale, and the top tier is no longer the top model

`contracts/src/llm.ts` pins `claude-opus-4-8` as the highest tier. The current flagship is
**`claude-opus-5`**. Also `claude-haiku-4-5-20251001` carries a date suffix that current model IDs
don't use (`claude-haiku-4-5`).

`modelRank()` (`llm-gateway/src/models.ts:21`) classifies by substring, so `claude-opus-5` would
rank correctly by accident via `includes("opus")` — but it has no rate-card entry, so it prices at
$0 (A1). The pricing that *is* listed is accurate ($5/$25 Opus, $3/$15 Sonnet 5 with the
introductory $2/$10 note, $1/$5 Haiku) — the table is correct, just incomplete and one generation
behind.

Also absent: any **fallback model**. A failing model is retried twice on itself and then the call
fails; there is no cascade to an alternate.

### A12 (P1) — SCA "reachability" is package-import presence, not call reachability

`discovery/src/sca.ts:191-248` computes `reachable = imported.has(pkg.name)`, where `imported` comes
from a regex scan of `import`/`require` statements. A package imported once anywhere and never used
on the vulnerable path is marked reachable.

PRD §7 Layer 1 promises _"reachability check (is the vulnerable path actually imported/called?)"_
and the module's doc comments imply function granularity. This is package granularity. The advisory
data itself is genuinely good (real OSV-derived mirror, ~3,600 entries) — only the reachability claim
overstates.

### A13 (P1) — No structured-output enforcement on three of four providers

Only Azure sets a response format (`adapters/azure.ts:52`, generic `json_object` — no schema).
Anthropic, Bedrock, and Vertex `buildBody()` send **nothing** for `responseFormat`; JSON is requested
in prose and validated by `try { JSON.parse() } catch`.

Every parse failure silently degrades to the deterministic path with no metric and no log — so the
LLM's contribution can quietly drop to zero across an entire deployment and nothing would surface it.
At minimum: emit a counter for LLM-response parse failures. Better: use real structured outputs
(`output_config.format`) and strict tool schemas.

### A14 (P1) — Fix generation cannot round-trip any real file

`fix/src/generate.ts:104` sets `maxTokens: 2048`, while the prompt (`generate.ts:59-63`) demands
`{"fixedSource": "<the full fixed file>"}` — the **entire file**, rewritten.

Any file over roughly 1,500 lines cannot fit in the response. The output truncates mid-string,
`JSON.parse` fails, `proposeFixWithLlm` returns `null`, and the fix silently degrades to a mechanical
strategy or an advisory. There is no error, no metric, no retry. LLM-authored fixes therefore only
ever work on small files, and nothing reports that.

Fix: emit a diff/edit rather than a whole-file rewrite, and raise the cap.

### A15 (P1) — No CLI and no CI-native surface, so "autonomous" has no trigger

The only entry points are the Fastify API and the Next console. There is no `montr scan .` CLI, no
GitHub App, no GitHub Action, no PR check annotation, no IDE integration, no webhook receiver.

PRD §7 specifies a `diff` mode scoped to changed files — genuinely implemented in
`appmap/src/diff.ts` with a real bidirectional import-graph BFS — but nothing can trigger it from a
pull request, which is its only natural trigger. For a product whose secondary user is "dev team lead
receiving fix PRs," the absence of a repo-side surface is a significant adoption gap.

### A16 (P1) — There is no blue team, so this is not yet purple teaming

Against the stated goal, the entire defensive half is missing. Grepped for
`MITRE|ATT&CK|sigma|detection.rule|threat.model|siem` — no implementation anywhere.

Absent: ATT&CK technique mapping per finding, detection-rule output (Sigma/OTel/SIEM queries),
threat modeling / abuse-case derivation, attack-path graphing, runtime or IAST instrumentation, and
any "here is what this exploit looks like in your logs" guidance. The product tells you what is
broken; it never tells you how you would have caught it. That is the half that makes a purple-team
product purple, and it is also the half that is hardest for competitors to copy.

### A17 (P1) — "Any kind of software" is currently three languages of source code

Verified absent across `packages/discovery` (grep returned zero matches): IaC / Terraform /
Dockerfile / Kubernetes / Helm scanning, SBOM generation (CycloneDX/SPDX), license scanning, and all
supply-chain checks (typosquatting, install-script risk, malicious-package heuristics). Also absent
product-wide: container image scanning, cloud posture, mobile, binaries, and OpenAPI/API-spec review.

Most conspicuous for an _AI security_ product: **no AI/LLM-application security scanning**. Nothing
checks a target for prompt injection, unsafe tool exposure, unescaped LLM output, or secrets leaking
into prompts. No `prompt_injection` category exists in the taxonomy. This is on-thesis, currently
underserved by competitors, and directly aligned with the PRD's "AI collapsed the cost of creating
software" framing.

Also within source scanning: Express and Fastify get framework _detection_ from `package.json` but
have **no route extractor** (`appmap/src/sources.ts:132-133`), so a plain Express API yields zero
routes; Go, Ruby, PHP and C# are label-only in `EXT_LANGUAGE` with no registered analyzer.

### A18 (P1) — AppMap never links routes to ORM models, which blocks the 0%-recall categories

`ormModels[]` and `routes[]` are separate arrays on the `AppMap` with no cross-reference; nothing in
`prisma.ts`, `routes.ts`, or the merge logic associates a route with the models its handler queries.
Only taint sources carry a `routeId`.

This is the specific structural gap under A6's worst number: you cannot reason about IDOR or broken
access control without knowing _which_ records a route touches and _whose_ they are. Fixing the
route→model→ownership edge is a prerequisite for lifting those categories off zero.

---

## P2 — nice to have

### A19 (P2) — Cost estimation is a hand-picked fudge formula

`cost-meter/src/estimate.ts:70-73` uses fixed per-unit constants (`files*300 + routes*250`, etc.)
with `outputRatio = 0.25` and `tokensPerSecond = 2000`. `gateway.ts:191-194`'s `estimateTokens` is
`Math.ceil(text.length / 4)` — no tokenizer. Actual billed accounting does correctly use provider
`usage` objects, so only the pre-scan estimate is synthetic. PRD §19 requires actuals within ±15% of
estimate; that bound has never been validated against a real provider (DOD item 6 concedes ≈$0).

### A20 (P2) — Auth boundary detection is identifier-text regex, not control-flow analysis

`typescript/routes.ts:16-17`, `python/routes.ts:35-38`, `java/extract.ts:71` match guard _names_
(`requireAuth|protect|auth|…`) against the route file's text. Auth enforced by a middleware stack
registered elsewhere, a wrapper HOC, or a runtime guard is invisible. It correctly defaults to
`unknown` (fail-safe), which is then handed to the LLM — but the LLM only gets route metadata, so it
is guessing too.

### A21 (P2) — Python and JVM confirmation have no call graph at all

Only TypeScript has `callgraph.ts` (587 lines, 1–2 hops, relative imports only, no dynamic dispatch,
class methods, barrel re-exports, closures, or destructured params — its own doc comment is
admirably explicit). `confirm/src/heuristics/{python,java}/index.ts` are lexical marker lists
matching substrings like `os.system` against sink descriptions, self-described in
`heuristics/registry.ts:18` as "pre-registered stubs." Python and JVM confirmation is therefore
same-file only, despite being marketed as supported stacks.

### A22 (P2) — The proof-of-fix test proves syntax, not behavior

The execution is genuinely real — a generated `.proof-of-fix.test.ts` is written to a `mkdtemp`
workspace and run through a real `vitest` subprocess twice (must fail pre-patch, pass post-patch),
with launch failures correctly distinguished from test failures (`fix/src/patch.ts:166-279`). But the
test body is a filesystem read plus a regex assertion (`expect(source).not.toMatch(vulnerable)`). It
proves the vulnerable _pattern_ is gone from the file, not that the application is secure at runtime.

### A23 (P2) — The model-variance harness can never detect variance

`qa/src/model-variance.ts` is well-typed scaffolding, but its only caller wires
`perfectConfirmedForRepo` (`qa/src/synthetic.ts:44-46`), which **ignores the `model` parameter** and
echoes ground truth — so all models always score identically at 100%. It is also not run in CI. PRD
§15 requires this harness to publish the model matrix and "catch accuracy cliffs"; it structurally
cannot.

### A24 (P2) — The strong scrubber is a test-time certifier, not a runtime gate

`packages/security/src/scrubber.ts` (420 lines, detects code bodies and 11 secret formats) is called
only from tests, where it certifies the telemetry scrubber. It does not gate the audit-write path.
`AuditEventInput.metadata` (`contracts/src/audit.ts:92`) is an unconstrained
`z.record(string, unknown)` held in check only by a code comment saying it "MUST be scrubbed." A
future caller could write a code diff into audit metadata with nothing stopping it.

### A25 (P2) — Sanitizer detection in correlation is a substring regex over description text

`correlation/src/grounding.ts:27` matches `/\b(validat|paramet|sanitiz|escap|encod|allowlist|…)/i`
against finding description text — brittle in both directions. It only applies on the same-file
fallback path (the resolved call-graph flow is preferred when available), which limits the blast
radius, but it is a heuristic sitting inside "the moat."

### A26 (P2) — Correlation's scoring constants are authored priors, not calibrated

`correlation/src/scoring.ts:27-99` — exposure weights (public 1.0, authenticated 0.5, role_gated
0.35), reachability weights, and the `0.6*category + 0.4*severity` impact blend are all hand-set
floats with no derivation from CVSS or empirical data. Reasonable domain judgment, but the PRD calls
ranking by "reachability × exposure × impact" the moat; the multiplication is real, the numbers are
guesses. The golden corpus is the obvious instrument to calibrate them.

### A27 (P2) — No per-tenant queue isolation

Queue names (`contracts/src/queue.ts:23-31`) are per-layer only (`montr.layer0`…`montr.layer5`); all
clients share six queues. Correct for the documented single-tenant on-prem model, and repository-layer
row-scoping by `clientId` is genuinely rigorous throughout — but it blocks any future multi-tenant
deployment and offers no noisy-neighbour isolation.

### A28 (P2) — Golden-corpus vulnerable repos are partial vendored subsets

The clean negatives are genuinely full-size (validator.js 117 files, gson 91 files, spring-petclinic
87 files). The vulnerable ones are excerpts: `dvna` 15 files, `pygoat` 18, `javaseccode` 7. Provenance
and pinned commits are documented, and 8 of 16 repos are synthetic by design — but "REAL:
appsecco/dvna" reads as the whole application when it is a slice of it. Worth labelling as excerpts.

### A29 (P2) — No benchmark against any external dataset or competing scanner

No OWASP Benchmark, Juliet, SecBench, or CVE-Bench. No head-to-head precision/recall against Semgrep
or CodeQL as _competitors_ (Semgrep appears only as an internal detector). PRD §4 sells "provably
fewer false positives"; there is currently no external instrument that could prove it to a buyer.

### A30 (P2) — Stale doc comments contradict the code

`appmap/src/languages/registry.ts:20-23` claims all three languages use "real `web-tree-sitter` WASM
parsing (not regex)" — TypeScript actually uses `ts-morph`/the TS Compiler API. `discovery/src/rulesets/registry.ts:18`
describes Python/Java rulesets as "pre-registered stubs" when they are implemented.
`apps/web/.../config.ts:73-75` marks `killSwitch` as unimplemented when the route exists at
`apps/api/src/routes/scans.ts:184`. Individually trivial; collectively they erode the ability to
trust doc comments during audit.

### A31 (P2) — No prompt caching or batching despite ideal conditions

System prompts and the App Map are perfectly stable prefixes — textbook cache candidates — and
`cost-meter/pricing.ts:70-76` already prices cache reads at 0.1× and writes at 1.25×. No adapter ever
sends `cache_control`. Triage batches all candidates into one prompt (good), but there is no use of
the Batch API for non-latency-sensitive work at 50% cost.

---

## Suggested enhancements, features & upgrades

The through-line: **stop using the LLM as a clamped annotator and start using it as an investigator,
while keeping every existing safety rail by making autonomy contingent on evidence rather than
trust.** Ordered roughly by leverage.

### E1 — An agentic investigation loop in Layer 3 (highest leverage single change)

Give confirmation a tool-using agent with read-only repo tools: `read_file`, `grep`, `find_definition`,
`query_call_graph`, `list_routes`, `get_orm_model`. Let it _investigate_ a probable finding across
files rather than receive pre-chewed metadata and a yes/no. Run it with adaptive thinking and a task
budget so cost stays bounded and predictable.

This is what lifts IDOR and broken access control off 0%: those require reading the handler, finding
the ownership check (or its absence), and following the query — exactly what a tool loop does and a
single 1,024-token metadata call cannot. Prerequisite: A18 (route→model linking) and gateway tool-use
support (E10).

### E2 — Let the LLM propose findings, gated by executable proof

Break the demote-only ceiling (A7) without loosening safety. Add an LLM discovery pass that may
_propose_ candidates the deterministic tools missed — but require any LLM-originated finding to carry
executable evidence before it can reach `confirmed`: a generated test that fails against the
vulnerable code, or a live probe transcript. Unproven proposals land in the existing appendix, which
is exactly what the appendix is for. Autonomy earned by proof, not granted by trust.

### E3 — Adaptive exploit agent for DAST

Replace `craftProbes`'s fixed `switch` (A9) with an agent loop: send a probe, read the response,
reason, adapt the next payload. Keep every existing guard unchanged — allowlist, production block,
kill switch, rate limit, blast-radius caps — as the sandbox the agent runs inside. The guards are
already excellent and per-probe enforced; they are exactly what makes an adaptive agent safe to
deploy here. Expand coverage to SSRF, IDOR, authz bypass, path traversal, command injection, and
deserialization, and fix the NoSQL payload to use Mongo operators.

### E4 — Multi-agent adversarial confirmation

Instead of one veto call, run N independent verifiers with _distinct lenses_ — exploitability,
reachability, business impact, "try to refute this" — and require a majority. This attacks the
precision/recall tradeoff directly rather than resolving it by declining to confirm, and it produces
a natural confidence score to drive E9's escalation.

### E5 — Semantic codebase index (RAG over the AST)

Add pgvector (or an on-prem equivalent) over AST-chunked code, built once per commit alongside the
App Map and reused by diff scans. It gives correlation and confirmation genuine cross-file context
without blowing the token budget, and enables "find every other place this pattern occurs" — which
turns one confirmed finding into a swept class of findings.

### E6 — A threat-model agent at Layer 0.5

From the App Map, derive trust boundaries, attack surface, and abuse cases for _this specific
application_ — then use that to **drive which rules and probes run**. This is the shift from "run
every rule and filter" to "hunt this app's actual risks," and it is the natural place for the LLM to
add value where it cannot produce false positives (it selects work; it doesn't confirm findings).

### E7 — The blue-team half: make it actually purple

Ship, per confirmed finding: MITRE ATT&CK technique mapping, generated detection rules (Sigma, plus
OTel/SIEM queries), the log signature the exploit would leave, and hardening recommendations
distinct from the code fix. Add an attack-path graph across findings ("public route → SSRF →
metadata endpoint → credentials"). This is the missing half of the stated product goal and the
strongest differentiator in the audit.

### E8 — Cross-scan memory

Persist per-repo learned facts — custom sanitizer names, framework idioms, confirmed false positives,
operator decisions — and inject them into later scans' prompts. This genuinely closes the PRD §15
feedback loop that A10 shows is currently dead code, and makes the product get better on a codebase
the more it runs, which is a real retention story.

### E9 — Dynamic model-tier escalation

The tier machinery (`triage`/`default`/`confirmation`) exists and nothing uses it adaptively. Run
cheap-model-first, escalate to a stronger model on low confidence or disagreement (pairs naturally
with E4's vote spread). Directly improves the cost/accuracy frontier that PRD §17 flags as an open
risk.

### E10 — Gateway modernization (unblocks most of the above)

Add: tool use / function calling (currently explicitly out of scope), real structured outputs with
JSON schema, prompt caching on the stable system+AppMap prefix, adaptive thinking with an `effort`
setting for confirmation, streaming wired through to the console, real token counting via
`count_tokens` instead of `length/4`, and model fallback. Refresh the model matrix to `claude-opus-5`
and complete the rate card including Azure and partner pricing (A1, A11).

### E11 — AI-application security ruleset

Scan _target_ applications for prompt injection, unsafe tool/function exposure, unescaped LLM output
rendered to users, secrets leaking into prompts, and missing output validation. Add a
`prompt_injection` category to the taxonomy. On-thesis for an AI security company, genuinely
underserved, and a strong wedge with AI-native buyers.

### E12 — Autonomy surface: CLI, GitHub App, continuous scanning

`montr scan .` for local and CI use; a GitHub App that runs diff-mode on every PR and posts findings
as review annotations; scheduled continuous scanning with delta-only reporting. The diff-mode engine
already exists and works — it just has no trigger. This is what "completely autonomous" requires in
practice.

### E13 — Real proof-of-fix in an ephemeral container

Upgrade A22's regex assertion to genuine evidence: stand the app up in a throwaway container, replay
the confirmed exploit, assert it now fails, and attach the transcript. This also gives E2 its
evidence mechanism and E3 its oracle — one investment, three payoffs.

### E14 — External benchmark harness

Score against OWASP Benchmark and Juliet, and publish a head-to-head against raw Semgrep and CodeQL
on the same corpus, per release. Without this, "provably fewer false positives" (PRD §4) is a claim
no buyer can verify — and with 25% recall (A6), the current story needs the recall axis published
alongside precision to stay honest.

### E15 — Eval-driven prompt optimization

Wire the dead prompt registry (A10) to the corpus scorer so prompt versions are automatically A/B'd
against ground truth, with regression gating per version. This turns §15's aspiration into a real
loop and makes every enhancement above measurable rather than assumed.

### E16 — Broaden target coverage

In rough priority order: IaC/Dockerfile/Kubernetes/Terraform scanning, SBOM (CycloneDX) generation,
supply-chain risk (typosquatting, install scripts, malicious packages), OpenAPI/API-spec review,
container image scanning, then cloud posture. Also close the Express/Fastify route-extraction gap
(A17), which is a small change that materially widens the Node addressable surface.
