# Module: Layer 4 Fix Generation and Risk Classification

Scope: Automated patch synthesis, proof-of-fix regression test generation, and safety risk classification.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Fix Generation module executes Layer 4 of the analysis pipeline within packages/fix. For every ConfirmedFinding identified in Layer 3, it synthesizes a minimal unified diff patch and a companion proof-of-fix regression test. The module applies a safety risk classifier to categorize each remediation as either auto-eligible or human-required. Remediations touching sensitive security domains are strictly classified as human-required, guaranteeing that critical application logic is never modified without engineer oversight.

Entry Points and Core Runners
Layer 4 Runner: packages/fix/src/generate.ts exports runLayer4Fix, which iterates over confirmed findings to produce patches, regression tests, and safety classifications.
Queue Execution: apps/worker/src/runners.ts pulls Layer 4 jobs from BullMQ and executes fix synthesis for confirmed findings.

Key Components and Fix Strategies
Patch Generator: packages/fix/src/patch.ts reads vulnerable source files and uses the default tier model (Claude Sonnet 5) via packages/llm-gateway to synthesize surgical, minimal unified diffs resolving the root vulnerability.
Strategy Registry: packages/fix/src/strategies.ts provides category-specific remediation strategies including parameterized database queries for SQL injection, context-aware output encoding for XSS, strict URL parsing for SSRF, and manifest updates for vulnerable dependencies.
Proof-of-Fix Test Generator: packages/fix/src/generate.ts synthesizes automated regression test cases designed to fail against unpatched code and pass once the patch is applied.
Risk Classifier: packages/fix/src/risk.ts evaluates modified AST nodes and finding categories to assign a RiskClass (auto-eligible or human-required) with an explanatory rationale.

Safety Classification Rules
Auto-Eligible Classification: Assigned only to low-risk, self-contained modifications such as missing security response headers, strict cookie attributes, and simple dependency version bumps in package manifests.
Human-Required Classification: Hard rule enforced across all fixes touching authentication mechanisms, session management, cryptographic operations, access control, IDOR, or CSRF protections. These categories are permanently barred from automated merging.

Fix Persistence
Fix Entity: Synthesized remediations are saved as Fix rows in Postgres via packages/state-store, storing the unified diff string, rationale, proofOfFixTest JSON object, risk class, and risk rationale.

Constraints and Edge Cases
AGENT NOTE: Generated patches must be syntactically valid unified diffs. The module validates diff formatting before writing to the database.
AGENT AVOID: Never classify authentication, authorization, or crypto changes as auto-eligible, regardless of configuration settings.

Update Triggers
Update this file when fix strategies change in packages/fix/src/strategies.ts, when the risk classifier logic is modified in packages/fix/src/risk.ts, or when the Fix schema changes in packages/contracts/src/fix.ts.

Related Docs
docs/modules/confirmation.md — Confirmed findings input to Layer 4.
docs/modules/reporting-vcs.md — Layer 5 report generation and pull request creation.
