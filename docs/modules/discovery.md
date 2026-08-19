# Module: Layer 1 Parallel Discovery

Scope: Multi-engine static analysis, secret detection, dependency reachability scanning, and custom rule execution.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Discovery module executes Layer 1 of the analysis pipeline within packages/discovery. It runs multiple security analysis engines concurrently against the target codebase to detect potential vulnerabilities, leaked secrets, vulnerable dependencies, and insecure configurations. Output from Layer 1 is normalized into raw CandidateFinding records. These candidate findings are intentionally treated as noisy intermediate evidence and are never surfaced directly in executive report headlines.

Entry Points and Core Runners
Layer 1 Runner: packages/discovery/src/index.ts exports runLayer1Discovery, which coordinates parallel execution of static analyzers, secret detectors, and dependency scanners.
Queue Execution: apps/worker/src/runners.ts pulls Layer 1 jobs from BullMQ and executes discovery against the local repository checkout.

Key Components and Detection Engines
SAST Engine: Located in packages/discovery/src/detectors. Executes Semgrep static analysis rulesets targeting code vulnerabilities across supported programming languages.
Secret Scanner: Executes Gitleaks to identify hardcoded API keys, private certificates, and credentials within source files and commit history.
Dependency Reachability Scanner: packages/discovery/src/advisories.ts and detectors query Open Source Vulnerabilities (OSV) databases and match manifest versions against published CVE and GHSA advisories.
Custom Rule Engine: packages/discovery/src/custom-rules.ts compiles and executes client-authored Semgrep YAML rules and regex secret detectors persisted in the CustomRule database table.
Triage Normalizer: packages/discovery/src/triage.ts uses the fast triage model (Claude Haiku 4.5) via packages/llm-gateway to normalize multi-tool outputs into standard CandidateFinding entities.
Persistence Helper: packages/discovery/src/persist.ts writes CandidateFinding rows to Postgres via packages/state-store.

Output Data and Candidate Normalization
Candidate Finding Entity: Every detected issue is recorded with source tool name, rule identifier, standardized Category enum, CWE list, file path, line number, raw severity, and code evidence snippet.
Golden Rule Guarantee: Candidate findings represent raw input for Layer 2 correlation. They are never displayed as finalized vulnerabilities or used for headline statistics without undergoing correlation and exploit confirmation.

Constraints and Edge Cases
AGENT NOTE: Scanner binaries (Semgrep, gitleaks) execute locally within the worker container environment. In air-gapped deployments, scanners run using offline rulesets bundled in deploy/airgap.
AGENT AVOID: Never surface raw CandidateFinding counts directly in the UI as confirmed vulnerabilities. Always filter through Layer 2 correlation and Layer 3 confirmation.

Update Triggers
Update this file when new scanner integrations are added to packages/discovery/src/detectors, when custom rule validation logic changes in packages/discovery/src/custom-rules.ts, or when the CandidateFinding contract changes in packages/contracts/src/findings.ts.

Related Docs
docs/architecture/data-flow.md — Pipeline flow from Layer 1 discovery to Layer 2 correlation.
docs/modules/correlation.md — Correlation engine processing candidate findings.
