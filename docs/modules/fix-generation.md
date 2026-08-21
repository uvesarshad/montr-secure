# Module: Layer 4 Fix Generation and Risk Classification

Scope: Automated patch synthesis, proof-of-fix regression test generation, and safety risk classification.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Fix Generation module executes Layer 4 of the analysis pipeline within packages/fix. For every ConfirmedFinding identified in Layer 3, it synthesizes a minimal unified diff patch and a companion proof-of-fix regression test. The module applies a safety risk classifier to categorize each remediation as either auto-eligible or human-required. Remediations touching sensitive security domains are strictly classified as human-required, guaranteeing that critical application logic is never modified without engineer oversight.

Entry Points and Core Runners
Layer 4 Runner: packages/fix/src/generate.ts exports generateFixes, which iterates over confirmed findings to produce patches, regression tests, and safety classifications.
Queue Execution: apps/worker/src/runners.ts pulls Layer 4 jobs from BullMQ and executes fix synthesis for confirmed findings.

Key Components and Fix Strategies
LLM Fix Proposal: packages/fix/src/generate.ts asks the default tier model (Claude Sonnet 5) via packages/llm-gateway to propose a fix as a targeted, line-anchored edit list rather than a full-file rewrite (see LLM Fix Proposal Format below), then reconstructs the fixed source and hands it to the patch builder.
Patch Builder and Validator: packages/fix/src/patch.ts builds the unified diff from the original and reconstructed fixed source and validates it by actually executing the generated proof-of-fix test through a real vitest subprocess, once pre-patch and once post-patch.
Strategy Registry: packages/fix/src/strategies.ts provides category-specific remediation strategies including parameterized database queries for SQL injection, context-aware output encoding for XSS, strict URL parsing for SSRF, and manifest updates for vulnerable dependencies.
Proof-of-Fix Test Generator: packages/fix/src/generate.ts synthesizes automated regression test cases designed to fail against unpatched code and pass once the patch is applied.
Risk Classifier: packages/fix/src/risk.ts evaluates modified AST nodes and finding categories to assign a RiskClass (auto-eligible or human-required) with an explanatory rationale.

LLM Fix Proposal Format
Line-Anchored Edits: The model receives the vulnerable file with every line prefixed by its 1-based line number and returns a small JSON edit list, each entry a 1-based inclusive startLine/endLine range plus a replacement block, instead of the previous whole-file-rewrite contract. packages/fix/src/edits.ts parses, validates (rejects out-of-range, malformed, or overlapping ranges), and applies these edits to the original source before it flows into the existing patch builder unchanged.
AGENT NOTE: This closed audit finding A14. The prior contract asked for the entire fixed file back, which truncated and failed JSON parsing on any file past roughly 1,500 lines with no error or metric. Scoping the response to only the changed lines removes that ceiling.
Output Budget: The fix-generation call's token cap is 8192, four times the prior whole-file-rewrite cap, sized for several edit hunks of real code rather than an entire file.
Failure Visibility: An unparseable model response or a structurally invalid edit list is recorded via packages/telemetry's getMetrics().recordError with codes fix_generation.llm_response_unparseable and fix_generation.llm_edits_invalid respectively, and logged with the model id and stop reason (flagging a likely truncation when stopReason is max_tokens), so a fleet-wide collapse in LLM-proposed fix quality is observable rather than a silent, uncounted degrade to the mechanical strategy or advisory path. A deliberate model decline (an empty JSON object) is not treated as a failure and is not counted.

Safety Classification Rules
Auto-Eligible Classification: Assigned only to low-risk, self-contained modifications such as missing security response headers, strict cookie attributes, and simple dependency version bumps in package manifests.
Human-Required Classification: Hard rule enforced across all fixes touching authentication mechanisms, session management, cryptographic operations, access control, IDOR, or CSRF protections. These categories are permanently barred from automated merging.

Fix Persistence
Fix Entity: Synthesized remediations are saved as Fix rows in Postgres via packages/state-store, storing the unified diff string, rationale, proofOfFixTest JSON object, risk class, and risk rationale.

Constraints and Edge Cases
AGENT NOTE: Generated patches must be syntactically valid unified diffs. The module validates diff formatting before writing to the database.
AGENT AVOID: Never classify authentication, authorization, or crypto changes as auto-eligible, regardless of configuration settings.

Update Triggers
Update this file when fix strategies change in packages/fix/src/strategies.ts, when the risk classifier logic is modified in packages/fix/src/risk.ts, when the LLM edit-list format changes in packages/fix/src/edits.ts, or when the Fix schema changes in packages/contracts/src/fix.ts.

Related Docs
docs/modules/confirmation.md — Confirmed findings input to Layer 4.
docs/modules/reporting-vcs.md — Layer 5 report generation and pull request creation.
