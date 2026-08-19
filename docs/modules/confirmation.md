# Module: Layer 3 Exploit Confirmation and DAST

Scope: Static interprocedural taint proofs, approver-gated live DAST execution, egress guards, and blast-radius controls.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Exploit Confirmation module executes Layer 3 of the analysis pipeline within packages/confirm. It proves whether correlated ProbableFinding records are genuinely exploitable. By default, it performs deterministic static data-flow proofs using high-capacity LLM confirmation models to trace taint paths from source to sink. When explicitly enabled and authorized by an Approver, it conducts live dynamic security testing (DAST) against allowlisted staging targets under strict egress and blast-radius rate limits.

Entry Points and Core Runners
Layer 3 Runner: packages/confirm/src/confirm.ts exports runLayer3Confirm, which evaluates probable findings through static or live proof engines.
Queue Execution: apps/worker/src/runners.ts pulls Layer 3 jobs from BullMQ and executes confirmation against probable findings.

Static Exploit Proof Engine
Static Solver: packages/confirm/src/static.ts uses the confirmation tier model (Claude Opus 4.8) via packages/llm-gateway to construct formal data-flow proofs.
Taint Path Analysis: The engine traces user inputs from Route entrypoints through intermediate variable assignments, function calls, and sanitizers down to dangerous TaintSinks.
Static Proof Artifact: Generates a structured ProofArtifact object detailing the exact source-to-sink variable path and sanitization gaps.

Live DAST Engine and Safety Guards
Live Prober: packages/confirm/src/live.ts executes targeted HTTP requests against deployed staging web applications to confirm exploitability.
DAST Guard: packages/confirm/src/guard.ts enforces non-negotiable safety policies:
Allowlist Enforcement: Probes are permitted exclusively against URLs registered in the DastTarget table.
Production Blocking: Production environments are blocked unconditionally by policy.
Approver Authorization: Live runs require explicit Approver role approval on POST /api/v1/scans/:id/dast/authorize.
Scope Contract Limits: Enforces strict caps on maximum total requests, concurrency limits, requests per second, and max mutating operations.
Network Egress Guard: All outbound HTTP requests route through packages/security/src/egress-guard.ts, which blocks connections to non-allowlisted network addresses.
Scenario Runner: packages/confirm/src/scenarios.ts decrypts and executes versioned multi-step RedTeamScenario playbooks.

Confirmed Finding Persistence
Confirmed Finding Entity: Successfully validated vulnerabilities are persisted as ConfirmedFinding rows in Postgres with attached ProofArtifact (static or live), severity classification, CWE identifiers, and OWASP tags.

Constraints and Edge Cases
AGENT NOTE: DAST is disabled by default. When enabled, live probing can be aborted instantly across all nodes by triggering the emergency kill switch.
AGENT AVOID: Never bypass allowlist checks or blast-radius rate limits in packages/confirm/src/guard.ts under any circumstances.

Update Triggers
Update this file when static verification heuristics change in packages/confirm/src/heuristics, when live DAST probing logic changes in packages/confirm/src/live.ts, or when DAST safety constraints evolve in packages/confirm/src/guard.ts.

Related Docs
docs/modules/correlation.md — Correlated probable findings input to Layer 3.
docs/modules/fix-generation.md — Confirmed findings passed to Layer 4 fix generation.
