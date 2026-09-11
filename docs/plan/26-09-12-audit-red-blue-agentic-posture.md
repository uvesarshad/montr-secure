# Audit — Red/Blue Team Coverage, Console Reachability & Agentic Depth

Date: 2026-09-12
Scope: What red-team and blue-team capability actually executes in production; what an operator can reach from the console; and an honest accounting of where LLM/agent reasoning is used versus deterministic pipeline code.
Method: Source verification only. Four parallel agents swept `packages/`, `apps/`, and the worker wiring; every P0 below was independently re-verified by hand against the named file before being written down. No claim here rests on a doc comment — several doc comments were found to be stale (A15).

---

## Executive summary

Both teams exist and both are real work, not vaporware. Every module inspected has genuine logic and genuine tests. The problem is not quality of construction, it is **terminal wiring**: a striking amount of finished, tested capability has no production caller, and in three cases the console tells an operator something happened that did not.

- **Red team**: the per-finding live exploit prober is real, wired, and correctly gated. The 13-scenario OWASP attack-playbook library **cannot execute at all** — no code path anywhere sends its requests (A1).
- **Blue team**: 2 of 6 report sections populate in a real scan. The other 4 are permanently empty because Layer 5 never receives the App Map (A2). The console tab renders blank panels.
- **Agentic depth**: ~80% of LLM use is single-shot annotation on top of deterministic findings; Layer 5 uses no LLM at all; the orchestrator never replans. The one genuine agentic capability in the codebase — a tool-using, multi-turn code investigator with two independent proof gates — **has no configuration field and no caller** (A3).

The headline consequence: the two capabilities that most differentiate this product commercially — autonomous attack execution and agentic exploit investigation — are both built, both tested, and both unreachable by any customer today.

A second, structural consequence worth naming: the recurring pattern across A1, A2, A3, A7, A8, A9, A13 is _"built, tested, real repository calls, no production caller yet"_ — a convention this codebase has explicitly adopted and documented (see `scripts/check-unwired-seams.mjs`). That convention worked as a scheduling tool during the build waves. It has now accumulated past the point where it is safe: the unwired-seam checker itself only tracks 6 declared seams and passes green, while at least 7 further unwired seams exist that it does not know about.

---

## P0 — Broken or at risk

### A1 (P0) — The red-team scenario library cannot execute; the console states otherwise

`apps/api/src/routes/scenarios.ts`'s `POST /scenarios/:id/run` calls `runScenario(...)` with an empty deps object. By that function's own contract (`packages/confirm/src/scenarios.ts`), omitting `transport` means every step is authorized and gate-checked but **nothing leaves the process**. The route's header comment is explicit and correct: _"this route NEVER probes from the API process (no transport is supplied — probing belongs to the worker)."_

The worker has no such capability. A full search of `apps/worker/src` (excluding tests) for `runScenario`, `RedTeamScenario`, `redTeamScenarios`, and `scenario` returns **zero matches**. There is no worker-side scenario execution path, no queue job, no runner.

The only code in the repository that supplies a real transport to `runScenario` is `packages/confirm/src/purple-loop.ts`, whose sole non-test callers live in `packages/qa/src/blue-team-corpus.ts` — a golden-corpus evaluation harness.

The console (`apps/web/src/app/scenarios/page.tsx`, `RunOutcome`) renders, on success, a green panel reading: _"Gate-checked; probing executes in the worker (the console never probes)."_ That sentence describes a handoff that does not exist. The operator is told the attack is running elsewhere. It is not running anywhere.

**Impact.** A headline Phase-4 feature — versioned, encrypted-at-rest, RBAC-gated, allowlist-bound attack playbooks covering all 10 OWASP categories — is inert. An approver can authorize a run, see a success panel, and find a `scenario.run` audit event in the tamper-evident log, with no attack having occurred. In a demo or a customer evaluation this reads as working. In an audit trail it is a record of an authorized action whose metadata (`probed: false`, `requestsSent: 0`) is the only signal that nothing happened — and that signal requires knowing to look for it.

**Fix direction.** Add a worker-side scenario execution path that supplies the real transport, behind the existing `assertScenarioAuthorized` + `ScopeGuard` gates (no new egress path is required — `purple-loop.ts` already demonstrates the exact call shape). Until that lands, change the console string to state plainly that probing is not yet executed, rather than deferring to a worker that has no such code.

---

### A2 (P0) — Four of six blue-team report sections are permanently empty in production

`packages/report/src/report-builder.ts`'s `buildBlueTeamReport` gates four of its six sections on optional inputs: `appMap` (detection coverage, attack paths, threat model) and `hardeningRecommendations` / `purpleTeamEntries` (the remaining two).

`apps/worker/src/runners.ts`'s `layer5` handler calls `buildReport({ scan, confirmed, unconfirmed, fixes, costRollup, autoApply, candidates, audit, logger, ... })`. It passes **none of those three**. Layers 1–3 all call `resolveAppMap(ctx)`; Layer 5 simply never does.

Consequently, in every real scan:

| Section                                 | State in production                        |
| --------------------------------------- | ------------------------------------------ |
| MITRE ATT&CK mapping                    | Populated (no App Map needed)              |
| Detection rules (Sigma / OTel / Splunk) | Populated (falls back to file-scoped rule) |
| Detection coverage                      | Always `[]`                                |
| Attack paths                            | Always `[]`                                |
| Threat model                            | Always `{ present: false }`                |
| Hardening recommendations               | Always `[]`                                |
| Purple-team results                     | Always `[]`                                |

The threat model case is the most wasteful: it **is** computed for real, with an optional LLM enrichment pass, at App Map build time (`packages/appmap/src/build.ts`), and it is sitting on the persisted AppMap record. The report just never reads it back, because it never receives the object.

`apps/web/src/app/scans/[scanId]/blue-team/page.tsx` renders all six panels unconditionally. Four of them are blank for every customer, every scan.

**Impact.** The entire blue-team half of the product — the differentiator against a plain SAST vendor — is invisible in real use. B10's integration wave is recorded as closed and B11's console wave is recorded as closed; both are true at the package level and both are defeated by one missing argument at the single call site that matters.

**Fix direction.** Layer 5 calls `resolveAppMap(ctx)` (already used identically in three other layers) and threads it into `buildReport`; hardening and purple-team entries wire as precomputed inputs per A13 and A8. All downstream logic already exists and is tested — this is plumbing, not feature work.

---

### A3 (P0) — The agentic investigation loop is unreachable in production: no config field exists

`packages/confirm/src/investigate.ts` implements a genuine agentic loop: the model receives read-only repository tools (`read_file`, `grep`, `find_definition`, `query_call_graph`, `list_routes`, `get_orm_model`, plus `submit_conclusion`) and traces a finding across files over multiple turns before concluding. It is well-bounded — soft cap of 6 turns, a hard structural ceiling of 8 that config cannot raise, ≤4 tool calls per turn, every tool read-only, budget exhaustion resolving to `inconclusive` rather than a confirmation. Reaching `confirmed_candidate` promotes nothing on its own: `packages/confirm/src/investigation-pipeline.ts` additionally requires E2 executable evidence (a real failing test or a live probe) **and** E4's adversarial majority vote.

It is gated on `deps.investigation?.enabled` (`investigation-pipeline.ts:101`). `ConfirmDeps.investigation` is optional and documented OFF by default (`packages/confirm/src/types.ts`).

`apps/worker/src/runners.ts`'s `layer3` handler constructs `ConfirmDeps` with `llm`, `signal`, `audit`, `logger`, `fpTuning`, `emitProgress`, `now` — and **never sets `investigation`**. There is also no configuration field: a search of `packages/config/src/` for `investigation` returns only a passing mention inside a comment on an unrelated schema. Unlike the Layer 4 fix loop (which at least has `MONTR_FIX_AGENT_LOOP_ENABLED`), there is no operator-facing switch at all.

This is not "off by default." It is **unreachable without a code change**. The type's own doc comment anticipates this exactly: _"Wiring a production default (e.g. a `config.confirmation.investigation.enabled` schema field read by `apps/worker/src/runners.ts`) is a natural follow-up outside this change's file scope."_ That follow-up was never taken.

The E4 adversarial verifier panel (`packages/confirm/src/adversarial.ts`) is reachable only through this same path, so it is dead in production for the same reason.

**Impact.** This is the single largest AI capability in the codebase and the only thing in it that meets a reasonable definition of "agentic." It was built specifically to address the categories with **0% recall** — IDOR and broken access control have no static data-flow proof at all (`packages/confirm/src/taxonomy.ts`'s `DATAFLOW_SINK_KINDS`). Those categories remain at zero today. The product's agentic positioning currently rests on code no customer can run.

**Fix direction.** Add `confirmation.investigation` to the config schema mirroring `FixAgentLoopConfigSchema`'s shape and caps, surface it via env vars, and populate `ConfirmDeps.investigation` in the Layer 3 runner. Cost and latency per unconfirmed finding rise materially — see the Decisions section.

---

### A4 (P0) — Golden-corpus precision gate is RED (carried over)

CI measures FP-rate 12.5% / precision 87.5% against `corpus/baseline.json`'s 5% / 90% thresholds. Two false positives (sql_injection, command_injection) have been present since the 2026-08-19 A17 recalibration. Recall improved (25.0% → 31.8%), so this is a precision regression, not a wholesale one. The baseline was correctly **not** loosened.

Already tracked in `docs/plan/26-09-09-tasks-july-line-divergence.md`; restated here because it directly constrains every recommendation in this audit. False-positive rate under 5% is the PRD's stated **headline metric** (§4).

**Impact on this audit's recommendations.** Increasing AI autonomy on top of a failing precision gate will degrade the headline metric before it improves it. Sequencing matters — see Decisions.

---

## P1 — Should fix

### A5 (P1) — Blue team has no top-level navigation and no cross-scan view

`apps/web/src/lib/rbac.ts`'s `NAV_SECTIONS` contains no blue-team entry. Red team gets two top-level items (`/dast`, `/scenarios`). Blue-team output is reachable only by opening a specific scan and selecting a tab (`apps/web/src/components/scan-tabs.tsx`) — two-plus clicks deep, and undiscoverable without already knowing it exists. The dashboard (`/`) links only to `/scans` and individual scan rows.

There is also no aggregate view: no cross-scan detection-rule inventory, no org-wide ATT&CK coverage, no detection-coverage trend. `/dashboards` covers findings posture only. For a buyer persona who is a security lead, ATT&CK coverage over time is arguably the most saleable screen in the product and it does not exist.

**Compounding with A2**: four of the six panels behind that buried tab are blank anyway.

---

### A6 (P1) — Console verification against mock data hid A2 entirely

`apps/web/src/mocks/data.ts`'s `blueTeam` fixture was deliberately populated with rich, finding-grounded sample data across all six sections (B11), and the tab was visually verified against the dev server with `NEXT_PUBLIC_USE_MSW=true`. That verification passed. It could not have failed: the mock populates precisely the fields production never populates.

`apps/web` has no vitest suite, so mock-backed visual checking is the only UI verification in place. This is a process defect, not a one-off: any future console work on a field the worker does not supply will pass verification the same way.

**Fix direction.** At minimum, add one end-to-end assertion that a real pipeline run produces a report whose blue-team sections are non-empty. The `pnpm e2e` scan path already produces a real report and would be the natural home.

---

### A7 (P1) — Detection coverage is computed but never persisted

`packages/appmap/src/coverage-analysis.ts`'s `persistDetectionCoverageForScan` makes real calls to the B1 `detectionCoverage` / `detectionRules` repositories. It has no caller in `apps/worker/src/runners.ts` — zero references to it or to `DetectionCoverage` anywhere in the worker.

The underlying analysis is good: a genuine tri-state verdict (detected / not detected / unknown) derived from whether the finding's route handler actually contains a structured-logging call, a bare `console.*` call, or nothing — with `"unknown"` earned only for genuinely ambiguous cases rather than used as a blanket default. That discipline is wasted while nothing runs it.

---

### A8 (P1) — Purple-team verification runs only inside the QA harness

`packages/confirm/src/purple-loop.ts` is the most interesting piece of blue-team work in the repository: it runs a real scenario through the existing gated engine, then parses the generated Sigma rule's own YAML back into a spec and evaluates it against the actual HTTP transcript to determine whether the rule would have fired. Its Sigma parser is an honest subset parser covering exactly the shapes the generator emits, not a fake.

Its own header states it plainly: _"Standalone: NOT called from any pipeline layer or report-assembly path."_ Confirmed — no references in the worker. The only real-transport callers are in `packages/qa/`.

This is the capability that makes the word "purple" defensible. Today it is exercised only by a test.

---

### A9 (P1) — The semantic code index is unwired, and unusable on 9 of 10 providers

Two compounding gaps:

1. `packages/semantic-index` (AST chunking, embedding, pgvector-backed retrieval) is complete and tested, and `scripts/check-unwired-seams.mjs` lists it as a known documented exception with no consumer.
2. `packages/llm-gateway/src/embeddings.ts`'s `createEmbeddingAdapter` implements **only** `azure`. All nine other providers — including `openai`, whose embeddings API is the same wire shape the Azure adapter already speaks — return `UnsupportedEmbeddingAdapter`.

**Impact.** Even if someone wired the index in tomorrow, it would be unusable for a customer on any provider but Azure. This matters more after A3: an investigator that can only `grep` is materially weaker than one that can retrieve by meaning across a large repository. The index is the retrieval substrate the agentic story needs, and it is two steps away from usable rather than one.

---

### A10 (P1) — Three of the 13 attack scenarios cannot prove anything, and body-keyed detection rules can never fire

`RedTeamStep` (`packages/contracts/src/phase4.ts`) carries no request-body field, and `runScenario` never sends one. Three catalogue scenarios (command_injection, insecure_deserialization, ssrf) place their confirming payload in a POST body, so even once A1 is fixed those scenarios will execute without ever delivering the payload that proves the finding.

The same structural gap breaks detection verification in the other direction: any generated Sigma rule whose condition depends on `cs-body|contains` can never match a scenario transcript. `purple-loop.ts` surfaces this explicitly in its reason string rather than silently returning `false`, and the blue-team corpus honestly labels those cases as structural misses rather than force-fitting them.

**Impact.** This is a prerequisite for A1 to be worth doing. Wiring scenario execution without adding a body field delivers a red-team engine that is structurally blind to roughly a quarter of its own catalogue.

---

### A11 (P1) — The orchestrator is a fixed sequence; nothing scopes, reorders, or replans

`packages/orchestrator/src/fsm.ts` hardcodes `LAYER_ORDER = [layer0..layer5]` and walks it identically every run. The only branching in `controller.ts` is a `switch` over which fixed layer just completed. What looks like decision-making — whether live DAST is permitted, whether auto-fix PRs open — is deterministic policy evaluation against config flags and allowlists.

Nothing anywhere adjusts scope, skips a layer, revisits an earlier layer, or allocates more effort to a promising finding based on what was actually found.

**Impact.** This is the structural reason the system reads as "not agentic" even where it uses an LLM heavily. The model never influences control flow, only content inside a slot the deterministic code already decided to fill. Note this is partly _by design_ and defensible — the PRD's §6 principle 1 is "broad & cheap first, precise & expensive last," and a predictable pipeline is easier to sell to a security buyer. It is listed as P1 because the cost is real (uniform effort across findings of wildly different value), not because the current design is wrong.

---

### A12 (P1) — Enabling the fix agent loop does not enable multi-file reading

`FixAgentLoopConfigSchema` (`packages/config/src/schema.ts`) defaults `maxToolCalls` to `0`, which exposes no `read_file` tool at all. An operator who sets `MONTR_FIX_AGENT_LOOP_ENABLED=true` gets a bounded retry loop with feedback, but **not** the sandboxed multi-file context that was A5's stated purpose.

Two knobs must be raised to get the advertised behavior, and nothing in the env var's name or the deployment docs signals that. Anyone enabling this will reasonably believe they turned on multi-file fixing and will not have.

---

### A13 (P1) — Hardening recommendations have no caller

`packages/hardening`'s `generateHardeningRecommendations` runs seven real detectors (security headers, CSP, cookie policy, rate limits, WAF rules, network policy, framework config), each grounded in an actual detected gap and each precision-tested to emit nothing when the gap is already closed. Its architectural boundary against Layer 4 is enforced by a real source-grepping test, not just documentation — genuinely careful work.

A search of `apps/worker/src` for `hardening` returns zero non-test matches. Nothing calls it. It needs a real `FileProvider` over the repo checkout, which is why `buildReport` takes it as a precomputed input rather than generating it — but no one precomputes it.

---

## P2 — Nice to have

### A14 (P2) — Gateway streaming has no consumer

Implemented in every adapter and verified end-to-end with a real adapter over a fake transport (`packages/llm-gateway/src/streaming.integration.test.ts`), but no layer calls `gateway.stream()`. Documented honestly as a known exception. Worth noting because A3's investigation loop is exactly the workload where streaming matters — a multi-turn loop the operator is watching in the console's progress view is the first real use case this feature has had.

### A15 (P2) — Stale "not wired / later wave" header comments on code that is now wired

`packages/report/src/detection-rules/`'s header still claims it is standalone and that wiring is "B10's job in a later wave." B10 landed; `report-builder.ts:256` calls it unconditionally. `packages/report/src/exports/mitre-attack.ts` carries the same stale claim while `report-builder.ts:251` calls it for real.

Minor in isolation, corrosive in aggregate: this audit had to verify every doc comment against source because several were wrong in both directions — some claiming unwired code that is wired (here), others claiming wiring that does not exist (A1's "probing belongs to the worker"). The comments can no longer be trusted as a map.

### A16 (P2) — Red-team payloads are entirely hardcoded; the model authors nothing

Every probe payload in `packages/confirm/src/live.ts` is a literal string. The one LLM-driven element (`chooseNextVariant`) selects an **id** from a small pre-written `PAYLOAD_VARIANTS` map, with the response validated against the allowed set and out-of-set choices discarded, capped at 3 adaptive rounds. This is correct and safe as built — but it means "AI-driven red teaming" currently describes a model picking one of three or four pre-authored strings.

### A17 (P2) — Structured output is used at exactly one call site

`responseSchema` is used only by the live-DAST variant picker, constrained to a closed enum. Every other JSON-returning call site asks for `responseFormat: "json"` and parses defensively. The defensive parsing is good practice, but schema-constrained decoding is implemented, tested, and available across all ten providers, and would remove a class of retry/parse-failure handling from six call sites.

### A18 (P2) — Layer 5 uses no LLM at all

`packages/report` contains zero gateway calls. Executive summaries, narrative, and prioritization rationale are template-assembled from structured data. This is defensible (deterministic reports are auditable and free), but it is worth stating plainly: the artifact the customer actually reads — the report — is the one part of the pipeline with no AI in it.

---

## Feature suggestions, enhancements & upgrades

Ordered by value-per-unit-of-work. The first four are recovery of capability already paid for; the rest are genuinely new.

**Turn on what already exists**

1. **Make the investigator reachable** (A3). Add the config field, wire it into the Layer 3 runner, and scope it initially to unconfirmed high/critical findings only. This is the single highest-value change available and it targets the 0%-recall categories directly.
2. **Fix the Layer 5 plumbing** (A2, A7, A8, A13). One argument unlocks four report sections; two more unlock the rest. Everything downstream is tested.
3. **Wire worker-side scenario execution** (A1), with the request-body field added first (A10). Closes the purple-team loop for real and removes a false statement from the console.
4. **Wire the semantic index and add an OpenAI embeddings adapter** (A9). The adapter is near-free — same wire shape as the existing Azure one. Then give the investigator semantic retrieval alongside `grep`.

**Make the blue team visible and saleable**

5. **Add a top-level Blue Team section** with cross-scan aggregation (A5): org-wide ATT&CK coverage over time, a detection-rule inventory with export-all, and a detection-coverage trend. For the security-lead buyer this is likely the most compelling screen in the product, and every input for it already exists once (2) lands.
6. **Ship detection rules as a real integration, not just a download.** Sigma / OTel / SPL content is already correct and pastable; a push integration (Splunk, Elastic, Sentinel) converts an advisory artifact into a product surface a SOC team touches weekly.
7. **Detection-coverage regression gating in CI**, mirroring the existing golden-corpus gate — fail a build when a newly confirmed finding lands on a route with no telemetry.

**Genuinely more agentic**

8. **Adaptive scoping and effort allocation** (A11). Let the orchestrator spend more turns on findings with high reachability × exposure × impact and skip expensive confirmation on findings the App Map already rules out. This is the first change that makes the model influence control flow rather than content, and it is also a _cost reduction_, not just a capability add.
9. **Payload authorship within guardrails** (A16). Let the model compose payloads that are then validated against a deterministic safety predicate (non-destructive, within blast-radius caps, allowlisted target) before send. The guardrail architecture to permit this safely already exists and is enforced at two independent layers.
10. **Cross-scan learning beyond false positives.** The learned-facts mechanism already works and is genuinely useful; today it carries operator FP marks, custom sanitizers, and framework idioms. Extend it to carry confirmed exploit shapes and per-repo sanitizer conventions so recall improves scan over scan rather than staying flat.
11. **Streaming the investigation narrative to the console** (A14). The progress-event sink is already threaded into the investigation loop; streaming turns a multi-minute opaque wait into a visible agent trace, which is both a UX win and the most effective possible demo of the agentic capability.

**Hygiene**

12. **Extend `check-unwired-seams.mjs` to cover every unwired seam**, not the six currently declared. It passes green today while at least seven further seams have no caller. A checker that is structurally incapable of catching the dominant defect class in this repository is worse than no checker, because it is trusted.
13. **Add one real end-to-end blue-team assertion** to the existing e2e scan path (A6), so mock-backed console verification can never again mask an empty production payload.
14. **Reconcile the stale header comments** (A15) in a single pass, and adopt the rule that a "not wired yet" comment must name the task that will wire it.

---

## Decisions that need an owner

These are judgment calls, not engineering questions. Recommendations given.

- **Sequencing against the red precision gate (A4).** Adding autonomy on top of a failing FP gate makes the headline metric worse before better. **Recommendation: fix precision first**, then land A3 behind a flag, measure the corpus before and after, and only then default it on. The investigator's two independent proof gates should _improve_ precision rather than degrade it — but that is a hypothesis until measured.
- **Cost and latency of the investigator (A3).** A multi-turn tool loop plus four verifier calls per unconfirmed finding is a materially larger spend profile than one metadata call. **Recommendation: default it on but scoped to high/critical unconfirmed findings only**, with the existing budget hard-halt as the backstop. Off-by-default repeats exactly the mistake this audit is documenting.
- **Whether autonomous attack execution is a product you want to ship (A1).** Wiring scenario execution means the tool genuinely attacks a customer's staging environment on a schedule. The guardrails are strong and layered, but this is a risk-appetite and possibly a contractual/insurance question, not a technical one. **Recommendation: ship it, gated behind explicit per-target written authorization** — the PRD already anticipates exactly this (§7 L3b, §11), and the capability is the product's clearest differentiator against a SAST vendor.
- **Whether Layer 5 should use an LLM (A18).** A generated executive narrative reads better to a buyer; a template is auditable and free. **Recommendation: keep the deterministic report as the artifact of record, and add an optional generated executive summary on top of it**, clearly labelled, never replacing the structured findings.

---

## Related

- `docs/plan/26-09-09-tasks-july-line-divergence.md` — A4 carried over from there; three items still open.
- `docs/plan/26-08-22-audit-ai-depth.md` — the E-series audit that specified E1/E5/E9; A3 and A9 are its unfinished terminal wiring.
- `docs/plan/montr-secure-prd.md` — §4 success metrics, §7 agent topology, §11 guardrails.
