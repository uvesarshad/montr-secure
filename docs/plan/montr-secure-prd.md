# PRD — Montr Secure: AI Security Orchestration Platform

**Product name:** Montr Secure
**Owner:** Uves / Montr AI Labs
**Status:** Draft v1.0 — build-ready
**Audience for this doc:** Claude Code / Codex CLI coding agents + human reviewers
**Deployment model:** On-prem container, bring-your-own LLM key, report-first with gated auto-fix

---

## AGENT DIRECTIVES (read first)

> **AGENT NOTE:** This is a security product. Correctness and safety beat cleverness everywhere. When two designs conflict, choose the one with fewer false positives and less autonomous code modification.
> **AVOID:** Building any layer that fires expensive LLM calls before the codebase map (Layer 0) exists. Broad scans are deterministic-tool-first, LLM-second.
> **AVOID:** Letting any agent modify auth, session, crypto, or access-control code autonomously — flag as `human-required` regardless of the auto-fix toggle.
> **AVOID:** Any network egress of client source code. The orchestration runs in the client's perimeter; the only outbound call is to the client's own LLM key.
> **SEE:** `§7 Agent Topology` for the core IP. `§11 Safety & Guardrails` is non-negotiable.
> **DECIDE (flagged inline):** Items tagged `DECIDE` need a human product call before or during build. They are collected in `§18`.

---

## 1. Problem & Thesis

AI collapsed the cost of _creating_ software but not the cost of _securing_ it. Vibe-coded and AI-generated apps ship faster than any human can audit them, and the volume grows as models get more capable. Enterprises don't lack security tools — they drown in them: separate SAST, DAST, SCA, secrets scanners, and a pen-test firm on retainer, none of which talk to each other, each producing its own pile of unprioritized, unvalidated findings.

**Thesis:** The winning product is not another scanner. It is an **orchestration layer** that runs all security disciplines (blue-team hardening, red-team probing, white-box SAST/SCA, black-box DAST), **correlates** their findings against a structural model of the app, **confirms** which issues are actually exploitable, and delivers a short, prioritized, exploit-validated report with **merge-ready fixes** — optionally auto-applied under strict, gated conditions.

**Wedge:** Deep on one stack first (Node/Next.js/Postgres/Prisma), report-first, static-confirmation-first, then expand. Consolidation + low false-positive rate is the value; the AI is the mechanism, not the pitch.

## 2. Goals & Non-Goals

**Goals**

- Consolidate SAST + SCA + secrets + DAST + red-team probing into one orchestrated pipeline.
- Cut false positives to the point where a report headline is _confirmed, prioritized_ issues, not raw counts.
- Produce diff-ready fixes with proof-of-fix tests for each confirmed finding.
- Deploy fully on-prem / in-VPC; no client code leaves their perimeter.
- Run against the client's own enterprise LLM key (provider-agnostic).
- Make token cost transparent and bounded before any expensive run.

**Non-Goals (v1)**

- Self-hosted / bundled LLM weights. Explicitly out — clients bring keys.
- Autonomous remediation of auth/crypto/access-control logic. Always human-gated.
- "Any language, any framework" on day one. Depth first, breadth later (`§16`).
- Production-target black-box pen testing. Live confirmation runs against client-authorized staging only.
- Managed SaaS hosting of client code. On-prem only for v1.

## 3. Target Users & Buyers

- **Primary buyer:** Enterprise security lead / AppSec team consolidating tool sprawl.
- **Primary user:** AppSec engineer running scans and triaging the report.
- **Secondary user:** Dev team lead receiving fix PRs.
- **Design partner / first customer:** Montr AI (multi-tenant SaaS: Next.js, PostgreSQL, Prisma, EC2/CloudPanel/PM2). Dogfood target.
- **Champion motivation:** Fewer tools, easier audits, provably fewer false positives, faster remediation.

## 4. Success Metrics

- **False-positive rate** on confirmed-tier findings: < 5% (headline metric).
- **Precision of exploit confirmation:** > 90% of "confirmed" findings reproducible by a human.
- **Mean time from scan to merge-ready fix:** target < 1 scan cycle.
- **Tool consolidation:** number of prior point tools retired per customer (sales/renewal signal).
- **Token cost predictability:** actual scan cost within ±15% of pre-scan estimate.
- **Adoption health:** auto-fix PRs merged / opened ratio (trust proxy).

---

## 5. System Overview

```
                 ┌──────────────────────────────────────────────┐
                 │        Client Perimeter (on-prem / VPC)       │
                 │                                              │
  Repo / PR ───► │  Layer 0  Intake & Scoping (app map, cost)   │
                 │      │                                        │
                 │      ▼                                        │
                 │  Layer 1  Parallel Discovery (SAST/SCA/       │
                 │           secrets) → candidate findings store │
                 │      │                                        │
                 │      ▼                                        │
                 │  Layer 2  Correlation (moat) → probable list  │
                 │      │                                        │
                 │      ▼                                        │
                 │  Layer 3  Exploit Confirmation                │
                 │           (static-proof │ live-DAST)          │
                 │      │                                        │
                 │      ▼                                        │
                 │  Layer 4  Fix Generation + risk classify      │
                 │      │                                        │
                 │      ▼                                        │
                 │  Layer 5  Human Gate → Report │ gated PRs     │
                 │                                              │
                 │  Cross-cutting: Orchestrator, State Store,    │
                 │  LLM Gateway (BYO-key), Cost Meter, Audit Log │
                 └───────────────┬──────────────────────────────┘
                                 │ (only outbound: client's own LLM key)
                                 ▼
                        Client's LLM provider
                (Anthropic / Bedrock / Vertex / Azure OpenAI)
```

## 6. Core Architectural Principles

1. **Broad & cheap first, precise & expensive last.** Deterministic tools do detection; LLM does triage, correlation, confirmation, and fixes.
2. **Nothing modifies code without passing the gate.** Auto-apply is a pipeline _state_, not a config flag.
3. **Confirmation before remediation.** Only confirmed findings reach fix generation.
4. **Provider-agnostic by necessity.** All LLM calls go through one gateway abstraction.
5. **No code egress.** Only the client's LLM key talks to the outside world.
6. **Cost is a first-class output.** Estimate before, meter during, report after.
7. **Every action is audit-logged.** Security buyers require a defensible trail.

---

## 7. Agent Topology (Core IP)

### Layer 0 — Intake & Scoping

**Purpose:** Build a structural model of the target before any expensive work; produce scope + cost estimate.

- **Orchestrator** ingests: repo path/URL, branch, scan mode (`full` | `diff`), optional authorized staging URL.
- **Mapper agent** produces the **App Map**: languages, framework(s), entry points, registered routes, auth boundaries, data stores, ORM models, third-party calls, env/secret surfaces, taint sources and sinks.
- For `diff` mode: scope = changed files + reachable call graph from those changes.
- **Cost Estimator** computes projected token spend and wall-clock from map size and scan mode. Emits a pre-scan estimate that must be surfaced (and, per config, approved) before Layer 1.

> **AGENT NOTE:** The App Map is the substrate for correlation. Persist it (`§9`) so `diff` scans are cheap. Prefer deterministic parsing (tree-sitter, framework route introspection) over LLM inference for the map; use the LLM only to fill gaps and label semantics.

**Output:** `AppMap` object + `ScanScope` + `CostEstimate`.

### Layer 1 — Parallel Discovery (broad, cheap, over-inclusive)

Three agents run concurrently, writing _candidate_ findings to a shared store. Deliberately noisy.

- **SAST agent** — wraps Semgrep + native analyzers. LLM triages/explains; it does **not** detect. Deterministic detection = precision; LLM = context.
- **Secrets & Config agent** — hardcoded keys, exposed env, weak crypto defaults, permissive CORS, misconfigured headers, insecure cookie flags.
- **Dependency (SCA) agent** — CVE match against lockfile **and** reachability check (is the vulnerable path actually imported/called?).

> **AVOID:** Surfacing Layer-1 output to the user. This is the "500 issues" pile that must never be a headline.

**Output:** `CandidateFinding[]` (unconfirmed, tagged with source, rule, location, raw severity).

### Layer 2 — Correlation (the moat — invest engineering here)

**Correlation agent** cross-references every candidate against the App Map:

- Is the finding on a route/entry point that actually exists and is registered?
- Is it public or behind auth? What auth state gates it?
- Does tainted input actually reach the sink, or does a validator/sanitizer interrupt the path?
- Deduplicate the same root cause reported by multiple tools into one issue.
- Rank by **reachability × exposure × impact**, not raw CVSS.

Candidates that can't be corroborated are **demoted to an appendix**, not deleted.

**Output:** `ProbableFinding[]` — each with a reachability hypothesis and an exploit hypothesis.

### Layer 3 — Exploit Confirmation (turns _probable_ → _confirmed_)

Two modes; **static ships first**, live is premium.

**3a. Static confirmation (default, works on any repo)**

- Data-flow proof: source → transforms → sink, with auth state at each hop.
- Produces a proof-of-reachability argument. No requests fired. No running target needed.

**3b. Live confirmation / DAST (premium, requires authorized staging)**

- Recon + exploit agent sends crafted requests to a **client-provided, allowlisted staging instance only — never production**.
- Observes response, captures transcript as proof.
- This is the black-box capability. Gated by `§11` guardrails: target allowlist, scope contract, kill switch, rate limits.

> **DECIDE-1:** Does the typical client (and Montr) have a staging instance the tool may hit? If not, static-only is the pragmatic default and 3b is a later paid add-on.

**Output:** `ConfirmedFinding[]` (with proof: static argument or live transcript) + `Unconfirmed` appendix.

### Layer 4 — Fix Generation

For each **confirmed** finding:

- Produce a **diff-ready patch**, a plain-English rationale, and a **proof-of-fix test**.
- **Risk-classify** the fix:
  - `auto-eligible` — mechanical, low blast radius (parameterize query, escape output, set cookie flag, bump dep).
  - `human-required` — touches auth, session, crypto, access control, or has wide blast radius. **Always** human-merged regardless of toggle.

> **AGENT NOTE:** The classifier is a _safety_ control, not a convenience. When uncertain, classify `human-required`. Never let uncertainty resolve toward autonomy.

**Output:** `Fix[]` (patch + test + rationale + risk class).

### Layer 5 — Human Gate & Output

- **Default:** report-first. Confirmed issues, proof, priority, each with merge-ready fix + test.
- **Auto-apply toggle ON:** opens **PRs** (never direct commits) for `auto-eligible` fixes only; each PR is independently reviewable.
- `human-required` fixes are always recommendations.
- The gate is an explicit pipeline **state**: code changes require passing the classifier's auto-eligible bar **or** explicit human approval.

**Output:** `Report` (see `§12`) + optional `PullRequest[]`.

---

## 8. Cross-Cutting Components

### 8.1 Orchestrator

Drives the pipeline as a state machine; manages layer handoffs, retries, partial failures, and the gate state. Idempotent and resumable (a failed Layer-3 run must not force re-running Layer 0–2).

### 8.2 LLM Gateway (BYO-key, provider-agnostic)

- Single abstraction over Anthropic, AWS Bedrock, GCP Vertex, Azure OpenAI.
- Client configures endpoint + key; Montr Secure never holds its own model relationship.
- **Model floor:** publish a recommended-model matrix; warn when a client points at a weaker model that degrades confirmation accuracy ("runs on X, best results on Y").
- **Key-tier guard:** detect / warn when a key appears to be a non-enterprise (data-retaining) tier, to protect the client from leaking source through their own misconfigured key. (`§11`.)
- Per-call token accounting fed to the Cost Meter.

> **AGENT NOTE:** Build against this abstraction from commit one. Never import a single provider SDK directly outside the gateway.

### 8.3 State Store

Persists AppMap, findings at each tier, scan history, audit log. On-prem datastore (Postgres). Encrypted at rest. Per-client, never shared.

### 8.4 Cost Meter

Pre-scan estimate, live metering, post-scan actuals. Enforces optional budget ceilings (halt + report partial if exceeded). Surfaces cost per scan and per finding.

### 8.5 Audit Log

Append-only record of every agent action, every LLM call (metadata, not code), every code modification, every human approval. Exportable for the client's auditors.

---

## 9. Data Model (indicative)

```
AppMap {
  id, repo, branch, commit_sha, created_at
  languages[], frameworks[]
  entrypoints[], routes[ { path, method, auth_state } ]
  data_stores[], orm_models[], third_party_calls[]
  taint_sources[], taint_sinks[]
}

CandidateFinding {
  id, scan_id, source(tool), rule_id, category(CWE)
  file, line, raw_severity, evidence_snippet, status=candidate
}

ProbableFinding {
  id, scan_id, root_cause_id, category
  reachability_hypothesis, exposure(public|authed), auth_gate
  reachability_score, exposure_score, impact_score, rank
  merged_candidate_ids[], status=probable
}

ConfirmedFinding {
  id, scan_id, category, severity(final)
  proof_type(static|live), proof_artifact
  location, exposure, status=confirmed
}

Fix {
  id, confirmed_finding_id, patch(diff), rationale
  proof_of_fix_test, risk_class(auto-eligible|human-required)
  status(proposed|pr-open|merged|rejected)
}

Scan {
  id, appmap_id, mode(full|diff), scope, cost_estimate, cost_actual
  started_at, finished_at, gate_state, operator
}
```

> **DECIDE-2:** Persist AppMap per-client for fast incremental `diff` scans (perf + cost win) vs. rebuild each run (less stored state). Recommendation: persist, encrypted, with a rebuild-on-stale-commit policy.

---

## 10. Deployment & Operations

- **Package:** container image + Helm chart. Hardened default config.
- **Modes:** on-prem k8s, single-VM docker-compose, air-gapped install.
- **Air-gapped:** deterministic tool rulesets and CVE DB must be updatable offline (signed bundle import). Only outbound call permitted is the client's LLM endpoint (which, in a true air-gap with an internal model proxy, may also be internal).
- **Config:** LLM provider + key, model matrix, budget ceilings, auto-fix policy, target allowlist for DAST, retention policy.
- **Upgrades:** versioned, no vendor telemetry by default. Optional opt-in anonymized health metrics.
- **RBAC:** operator, approver, viewer roles. Approver required for the human gate and DAST authorization.
- **Secrets:** client LLM key stored in-cluster (k8s secret / vault integration), never logged, never egressed except to its own provider.

## 11. Safety & Guardrails (non-negotiable)

- **No code egress.** Source never leaves the perimeter except as necessary context inside a call to the client's own LLM key. Log call metadata, never code bodies.
- **Auth/crypto/access-control fixes are always `human-required`.** Hard rule, not a heuristic default.
- **DAST target allowlist + scope contract.** Live confirmation may only hit explicitly authorized staging targets. Production is blocked by policy. A kill switch halts all active probing immediately.
- **Rate limiting & blast-radius caps** on any live probing.
- **Key-tier guard.** Warn/block on suspected data-retaining LLM key tiers.
- **Budget ceiling.** Hard stop with partial report if exceeded; never silently burn client tokens.
- **Fail-safe defaults.** Uncertainty always resolves toward _less_ autonomy and _more_ human review.
- **Full audit trail** of every mutation and approval.

> **AGENT NOTE:** If any requested feature conflicts with this section, stop and flag for human decision. Do not implement a bypass.

## 12. Report Specification

The report is the hero product. Structure:

1. **Executive summary** — N confirmed issues by severity; posture delta vs last scan; tools consolidated.
2. **Confirmed findings** — each: title, severity, category (CWE), location, exposure (public/authed), **proof** (static argument or live transcript), impact, and the **merge-ready fix + test**.
3. **Fix status** — which are auto-eligible (PRs opened), which are human-required (recommendations).
4. **Appendix: unconfirmed candidates** — demoted, for completeness, clearly separated.
5. **Compliance mapping** — findings mapped to OWASP Top 10 / CWE; export format aligned to what auditors expect (SOC 2 evidence, etc.).
6. **Cost & scope** — what was scanned, estimate vs actual token cost.

> **AGENT NOTE:** Never headline raw counts. Headline = confirmed + prioritized. The appendix is where breadth lives.

## 13. Compliance & Audit Wrapper

- Map every finding to OWASP Top 10 and CWE IDs.
- Export report in a format that drops into SOC 2 / ISO 27001 evidence collection.
- Audit log exportable for third-party auditors.
- Data residency: all processing on-prem satisfies most residency requirements by construction.

## 14. Security of Montr Secure Itself

A security tool is a high-value target. It must be exemplary:

- Least-privilege service accounts; no standing prod credentials.
- Signed releases; SBOM published per release.
- Montr Secure scans itself in CI (dogfood).
- No inbound internet dependency at runtime beyond the client LLM endpoint.
- Tamper-evident audit log.

## 15. Observability & QA

- Structured logs, per-layer metrics (findings in/out, demotion rate, confirmation rate, false-positive feedback loop).
- **False-positive feedback:** operators mark a confirmed finding as FP; this feeds a regression corpus that tunes correlation/confirmation prompts and thresholds.
- **Golden test corpus:** a fixed set of vulnerable + clean repos with known ground truth; every release must not regress precision/recall against it.
- Model-variance harness: run the golden corpus across each supported provider/model to publish the model matrix and catch accuracy cliffs.

## 16. Roadmap / Phasing (build order, not scope cut)

This is the **build sequence** for the full product — each phase ships production-grade, not throwaway.

- **Phase 1 — Foundation.** Layers 0–2 + 4–5 (report-first) on **Node/Next.js/Postgres/Prisma**. Static confirmation (3a). LLM Gateway with Anthropic + Bedrock. On-prem docker + Helm. Report + compliance mapping. Dogfood on Montr.
- **Phase 2 — Live confirmation & auto-fix.** DAST (3b) with allowlist/kill-switch. Auto-eligible PR flow. Vertex + Azure OpenAI in gateway. Air-gapped install path.
- **Phase 3 — Stack breadth.** Add Python (Django/FastAPI), then JVM. Each stack = new App-Map parsers + rulesets + confirmation heuristics; correlation engine is stack-agnostic by design.
- **Phase 4 — Scale & intelligence.** Cross-scan trend intelligence, org-wide posture dashboards, custom rule authoring, red-team scenario library.

> **AGENT NOTE:** "Full product" = the whole architecture built to production quality in this order. Do not interpret Phase 1 as an MVP that cuts corners on safety, audit, or the gateway abstraction — those are foundational and built correctly from Phase 1.

## 17. Open Risks

- **Model variance** degrading confirmation on client's cheaper model → model floor + variance harness.
- **Token cost surprise** on large monorepos → estimate + ceiling + diff mode.
- **Client footgun** (bad key tier, wrong DAST target) → guards + allowlist.
- **Deployment tax** across heterogeneous client infra → hardened Helm defaults, strict support matrix.
- **Over-trust in auto-fix** → risk classifier + PR-only + human-required rules.
- **Depth vs breadth pressure** from sales → hold the line: precision on supported stacks beats shallow universality.

## 18. Collected DECIDE Items

- **DECIDE-1:** Ship Layer 3 as static-only v1, or include live DAST if clients (and Montr) have authorized staging? → sets whether 3b is Phase 1 or Phase 2.
- **DECIDE-2:** Persist AppMap per client (recommended) vs rebuild per scan.
- **DECIDE-3:** Model matrix floor — minimum supported model for confirmation-tier accuracy; publish and enforce.
- **DECIDE-4:** Budget ceiling default behavior — hard halt vs warn-and-continue.
- **DECIDE-5:** Which compliance export format ships first (SOC 2 evidence vs ISO 27001 vs generic OWASP report).

---

## 19. Definition of Done (Phase 1, production)

- Runs on-prem via Helm on a clean cluster with only a client LLM key configured.
- Scans a Next.js/Prisma/Postgres repo end to end: map → discovery → correlation → static confirmation → fix generation → report.
- Report headlines confirmed findings with proof, fixes, tests, and OWASP/CWE mapping.
- False-positive rate < 5% on the golden corpus; no regression gate in CI.
- No client source egresses; audit log complete and exportable.
- Cost estimate surfaced pre-scan; actuals within ±15%.
- Auth/crypto fixes correctly classified `human-required` in 100% of golden-corpus cases.
- Montr Secure scans itself clean in CI.
