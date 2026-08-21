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
SAST Engine: Located in packages/discovery/src/detectors/sast.ts. Executes Semgrep static analysis rulesets targeting code vulnerabilities across supported programming languages. Uses hosted Semgrep Registry pack IDs (p/owasp-top-ten, p/typescript, p/nextjs, p/react, p/secrets, plus per-language packs from packages/discovery/src/rulesets) by default, or a local ruleset directory when discovery.rulesetsDir is configured (air-gap mode, see Constraints below).
Secret Scanner: Executes Gitleaks to identify hardcoded API keys, private certificates, and credentials within source files and commit history.
Dependency Reachability Scanner: packages/discovery/src/detectors/sca.ts and packages/discovery/src/advisories.ts query Open Source Vulnerabilities (OSV) databases and match manifest versions against published CVE and GHSA advisories. Reachability is call-granularity on TypeScript/JavaScript (A12): collectCalledPackages runs a real ts-morph AST scan checking whether a binding imported from the vulnerable package is actually invoked (called, constructed, or JSX-rendered) anywhere, not merely present in an import/require statement; collectImportedPackages's plain import-presence regex remains only as the fallback when nothing parses as TS/JS.
Custom Rule Engine: packages/discovery/src/custom-rules.ts compiles and executes client-authored Semgrep YAML rules and regex secret detectors persisted in the CustomRule database table.
Triage Normalizer: packages/discovery/src/triage.ts uses the fast triage model (Claude Haiku 4.5) via packages/llm-gateway to normalize multi-tool outputs into standard CandidateFinding entities. Cross-Scan Memory (E8): triage.ts itself is unchanged — apps/worker/src/runners.ts wraps the gateway instance it hands to Layer 1's DiscoveryDeps so a triage request (metadata.purpose "triage") for this client's repo receives an additive learned-facts context block appended to its system prompt, sourced from packages/state-store's LearnedFact rows (custom sanitizer names, framework idioms, operator decisions recorded on an earlier scan of the same repo) — see docs/modules/llm-gateway.md's Cross-Scan Memory Injection section and docs/api/database.md's Cross-Scan Memory section for the full mechanism and its bounded-size cap.
Threat-Model Scope Consumer (E6): packages/discovery/src/threat-model-scope.ts's applyThreatModelScopeHints reads the App Map's threatModel.scopeHints (see docs/modules/appmap.md) after triage and annotates any candidate whose category is a priority category, or whose file belongs to a priority route, with metadata.threatModelPriority, then stable-sorts annotated candidates to the front of the returned list. It never removes a candidate or changes the candidate count — every candidate the deterministic detectors and triage already produced still ships, in the same set, only reordered and annotated.
Persistence Helper: packages/discovery/src/persist.ts writes CandidateFinding rows to Postgres via packages/state-store.

Output Data and Candidate Normalization
Candidate Finding Entity: Every detected issue is recorded with source tool name, rule identifier, standardized Category enum, CWE list, file path, line number, raw severity, and code evidence snippet.
Golden Rule Guarantee: Candidate findings represent raw input for Layer 2 correlation. They are never displayed as finalized vulnerabilities or used for headline statistics without undergoing correlation and exploit confirmation.

Constraints and Edge Cases
AGENT NOTE: Scanner binaries (Semgrep, gitleaks) execute locally within the worker container environment. In air-gapped deployments, Semgrep runs against a local ruleset directory set via the discovery.rulesetsDir config key (env MONTR_DISCOVERY_RULESETS_DIR), populated by deploy/airgap/build-bundle.sh --semgrep-rules-dir and deploy/airgap/import-bundle.sh (installed under <dest-dir>/semgrep). Unset, SAST is unchanged and uses the hosted Semgrep Registry packs.
AGENT NOTE: SAST is a required detector. detectSast throws RequiredDetectorUnavailableError (packages/contracts/src/errors.ts) instead of degrading to an empty result when Semgrep is missing, errors, or a configured rulesetsDir is missing or has no rule files. The throw propagates through runDiscovery to the Layer 1 orchestrator runner and fails the scan via packages/orchestrator/src/controller.ts failScan, so a scan can never complete successfully with silent zero SAST coverage. Gitleaks and the SCA/dependency detector are unaffected and keep degrading gracefully with a warning.
AGENT AVOID: Never surface raw CandidateFinding counts directly in the UI as confirmed vulnerabilities. Always filter through Layer 2 correlation and Layer 3 confirmation.
AGENT NOTE: SCA call-site reachability (collectCalledPackages, packages/discovery/src/detectors/sca.ts) is TypeScript/JavaScript only and is a same-project AST call-site check, not full interprocedural call-graph reachability from an HTTP entry point — it does not trace through intermediate helper functions. It does NOT reuse packages/appmap/src/languages/typescript/callgraph.ts (scanTaintFlows): that resolver explicitly excludes bare/package specifiers (npm imports) by design, so it cannot answer "was this package's export called" at all. Python/PyPI and JVM/Maven manifests are not yet resolved by this detector; if that changes, their reachability must not silently inherit the TS/JS call-level claim (tracked as A21).
AGENT NOTE: applyThreatModelScopeHints is purely a prioritization/annotation signal, never a filter. Its zeroSurfaceCategories input (categories the threat model rated as having no plausible attack surface, for example xxe on an app with no deserialize-kind taint sink) is deliberately NOT consumed to skip a detector or drop a candidate here — every category still runs unchanged. A future consumer that wants to actually narrow detector execution on a genuine zero-surface case must make that an explicit, separately-reviewed change, not an implicit consequence of this signal.

Update Triggers
Update this file when new scanner integrations are added to packages/discovery/src/detectors, when custom rule validation logic changes in packages/discovery/src/custom-rules.ts, or when the CandidateFinding contract changes in packages/contracts/src/findings.ts.

Related Docs
docs/architecture/data-flow.md — Pipeline flow from Layer 1 discovery to Layer 2 correlation.
docs/modules/correlation.md — Correlation engine processing candidate findings.
