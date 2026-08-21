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
Scope Contract Limits: Enforces strict caps on maximum total requests, concurrency limits, requests per second, and max mutating operations. The mutating-request cap defaults to zero, so any POST-based probe (XXE, insecure deserialization) is refused by policy unless an operator explicitly raises it.
Network Egress Guard: All outbound HTTP requests route through packages/security/src/egress-guard.ts, which blocks connections to non-allowlisted network addresses.
Scenario Runner: packages/confirm/src/scenarios.ts decrypts and executes versioned multi-step RedTeamScenario playbooks.

Live-Confirmable Categories and Probe Coverage
LIVE_CONFIRMABLE_CATEGORIES in packages/confirm/src/live.ts lists eleven categories with a safe, high-signal live oracle: sql_injection, nosql_injection, xss, open_redirect, ssrf, idor, broken_access_control, path_traversal, command_injection, xxe, and insecure_deserialization. craftProbes emits a baseline request plus a category-specific payload for each; the oracle function applies a fixed marker/status heuristic per category (error-string leaks for injection categories, cloud-metadata markers for ssrf, denial-marker absence plus a differing body for idor, a stripped-credentials request that still succeeds for broken_access_control, POSIX /etc/passwd disclosure markers for path_traversal and xxe, marker reflection for command_injection, and deserializer-error/type-echo markers for insecure_deserialization). nosql_injection sends a real Mongo/NoSQL bracket-notation operator payload (field[$ne]=value) rather than a SQL string. idor and broken_access_control have no static data-flow proof at all (absent from DATAFLOW_SINK_KINDS in packages/confirm/src/taxonomy.ts), so live DAST is currently the only path that can ever confirm them.
AGENT NOTE: xxe and insecure_deserialization are POST-based (their sinks only trigger on a parsed request body); the insecure_deserialization payload is a malformed/typed object that only ever proves the sink parses attacker-controlled data via an error or type-name echo — it never sends an executable gadget chain.

Confirmed Finding Persistence
Confirmed Finding Entity: Successfully validated vulnerabilities are persisted as ConfirmedFinding rows in Postgres with attached ProofArtifact (static or live), severity classification, CWE identifiers, and OWASP tags.
Executable-Evidence Promotion: packages/confirm/src/static.ts's LLM cross-check can only demote a statically-reachable finding to the Unconfirmed appendix — it has no branch that reads confirmed === true from a model verdict. The one path that promotes a finding on evidence rather than a model's word is a successful live-DAST probe (packages/confirm/src/live.ts's confirmLive, wired in packages/confirm/src/confirm.ts): a real HTTP request/response transcript proving exploitability outranks the static/LLM verdict and is attached as the finding's live ProofArtifact (target + transcript).

Constraints and Edge Cases
AGENT NOTE: DAST is disabled by default. When enabled, live probing can be aborted instantly across all nodes by triggering the emergency kill switch.
AGENT AVOID: Never bypass allowlist checks or blast-radius rate limits in packages/confirm/src/guard.ts under any circumstances.

Update Triggers
Update this file when static verification heuristics change in packages/confirm/src/heuristics, when live DAST probing logic changes in packages/confirm/src/live.ts, or when DAST safety constraints evolve in packages/confirm/src/guard.ts.

Related Docs
docs/modules/correlation.md — Correlated probable findings input to Layer 3.
docs/modules/fix-generation.md — Confirmed findings passed to Layer 4 fix generation.
