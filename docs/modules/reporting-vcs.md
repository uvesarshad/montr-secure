# Module: Layer 5 Reporting, Compliance, and VCS Integration

Scope: Final report assembly, executive summaries, compliance mapping (SARIF, SOC2, ISO, OWASP), and automated pull request generation.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Reporting and VCS module executes Layer 5 of the analysis pipeline within packages/report. It aggregates confirmed findings, exploit proof artifacts, synthesized diff patches, and cost accounting data into a unified, audit-grade Report document. Layer 5 produces compliance mappings across standard regulatory frameworks (SARIF, SOC2 Type II, ISO27001, OWASP Top 10) and, when authorized by an Approver, opens automated remediation pull requests on GitHub or GitLab for auto-eligible fixes.

Entry Points and Core Runners
Layer 5 Runner: packages/report/src/report-builder.ts exports runLayer5Report, which constructs the finalized report document, records posture snapshots, and triggers automated PR workflows.
Queue Execution: apps/worker/src/runners.ts pulls Layer 5 jobs from BullMQ and executes report generation upon completion of Layer 4.

Key Components and Exporters
Report Builder: packages/report/src/report-builder.ts compiles confirmed findings, proof traces, generated patches, unconfirmed finding appendixes, and token metrics into a monolithic JSON Report persisted in Postgres.
Headline Formatter: packages/report/src/headline.ts generates clear executive summaries highlighting exploit-confirmed issues while explicitly omitting raw candidate counts.
Compliance Exporters: Located in packages/report/src/exports:
SARIF Exporter: Transforms findings into OASIS Static Analysis Results Interchange Format (SARIF v2.1.0) JSON for CI/CD integration.
SOC2 Exporter: Maps confirmed vulnerabilities to SOC2 Common Criteria security and availability controls.
ISO27001 Exporter: Maps findings to ISO/IEC 27001:2022 Annex A security controls.
OWASP Mapper: Maps findings to OWASP Top 10 2021 categories.
Posture Snapshotter: Derives a PostureSnapshot record from confirmed findings, tracking security posture trends over time.

Automated Pull Request Flow in packages/report/src/vcs.ts and auto-fix.ts
Auto-Fix Controller: packages/report/src/auto-fix.ts evaluates the scan gateState. If auto-fix is enabled, the fix gate is approved, and fixes are marked auto-eligible, it invokes the VCS provider.
VCS Provider: packages/report/src/vcs.ts supports GitHub and GitLab. It creates a dedicated remediation git branch (such as montr/fix-scan-id), applies unified diff patches, commits changes, and opens a formal Pull Request with an explanatory description and proof-of-fix test summaries.
Pull Request Tracking: Creates a PullRequest record in Postgres linked to the parent Scan and updated Fix records.

Constraints and Edge Cases
AGENT NOTE: Auto-fix is strictly PR-only. Direct commits to base branches are permanently blocked by design.
AGENT AVOID: Never include unconfirmed candidate counts in executive summary headlines.

Update Triggers
Update this file when report schemas change in packages/contracts/src/report.ts, when compliance mapping rules evolve in packages/report/src/exports, or when VCS provider adapters are updated in packages/report/src/vcs.ts.

Related Docs
docs/modules/fix-generation.md — Fixes and risk classifications consumed during report assembly.
docs/api/route-handlers.md — API endpoints serving report downloads and compliance exports.
