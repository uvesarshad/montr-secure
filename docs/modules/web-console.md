# Module: Operator Web Console

Scope: Next.js 14 operator console views, real-time scan monitoring, gate approval interfaces, DAST management, and dashboards.
Rendering context: Client
Project tier: 4
Last updated: auto

Overview
The Operator Web Console is a specialized security operations frontend built with Next.js 14 in apps/web. It provides security engineers and platform operators with real-time visibility into running scans, interactive finding review, static and dynamic proof inspection, diff patch evaluation, gate approval controls, and compliance reporting. The console communicates with the Fastify REST API using React Query hooks and provides responsive, dark-mode interfaces designed for dense data analysis.

Primary Route Consoles in apps/web/src/app
Scan Management Console: apps/web/src/app/page.tsx renders the primary dashboard displaying active scans, repository filters, execution statuses, and the trigger scan action.
Scan Detail and Sub-Views: apps/web/src/app/scans/[scanId] contains dedicated sub-tabs:
Overview Tab: Renders the 6-stage LayerProgress stepper and AppMapSummary.
Estimate Tab: Renders the EstimatePanel displaying pre-scan token projections and the approve estimate button.
Report Tab: Renders the FindingCard collection, vulnerability severity filters, proof viewers, and compliance tables. AI-Generated Summary (A18): apps/web/src/components/generated-executive-summary.tsx's `GeneratedExecutiveSummaryPanel` renders directly below the (deterministic) ExecSummary card, ONLY when `Report.generatedExecutiveSummary` is present (`reporting.executiveSummary.enabled` was on for that scan AND generation succeeded — off by default, see docs/infra/environment.md) — a dashed-border, "AI-GENERATED"-badged card carrying the schema's own fixed disclaimer, the generated narrative, optional "Suggested focus areas" bullets, and model/provider/timestamp provenance. Deliberately visually distinct from ExecSummary and never restructures the existing tab.
Blue Team Tab: apps/web/src/app/scans/[scanId]/blue-team/page.tsx (B11). Six nested sub-tabs over `Report.blueTeam` (B10): Detection Rules (DetectionRulesPanel — generated Sigma/OTel/SIEM rules per confirmed finding, MITRE tags, log-signature narrative, per-rule and export-all download), ATT&CK Matrix (AttackHeatMap — a real tactics-as-columns/techniques-as-cells MITRE heat map, cell intensity reusing the severity color scale), Attack Paths (AttackPathsPanel — ordered kill-chain step cards with feasibility score), Purple Team (PurpleTeamPanel — detected/undetected scenario verification results with "why not" reasoning), Threat Model (ThreatModelPanel — B7's rendered markdown artifact), and Hardening (HardeningPanel — B9's advisory-only config/infra recommendations). Viewer-visible like the Report tab (read-only report data, no mutations).
Fixes Tab: Renders FixDetails cards, the DiffViewer component, proof-of-fix test code, and the approve fix gate button.
DAST Tab: Renders the DastPanel for staging target selection, scope contract configuration, and live probe logs.
Pull Requests Console: apps/web/src/app/pull-requests/page.tsx lists automated remediation pull requests opened on GitHub or GitLab.
Audit Log Console: apps/web/src/app/audit/page.tsx displays the cryptographic hash-chained audit log with sequence verification indicators.
Security Dashboards: apps/web/src/app/dashboards/page.tsx visualizes historical posture trends, vulnerability distributions, and mean-time-to-remediate metrics.
Blue Team Console: apps/web/src/app/blue-team/page.tsx (A5) is the top-level, cross-scan aggregate of the per-scan Blue Team tab above — the `NAV_SECTIONS` "Blue Team" entry in apps/web/src/lib/rbac.ts is viewer-visible (`view_reports_and_audit`, same roles as Dashboard/Scans/Dashboards). Three sections, all sourced from `GET /analytics/blue-team`: org-wide ATT&CK coverage merged across every scan's `Report.blueTeam.mitreAttack.coverage`, reusing the AttackHeatMap component directly, plus a chronological coverage-growth table; a detection-rule inventory deduped by (format, content) across the real, persisted (A7) `DetectionRule` rows, with per-rule and export-all downloads reusing lib/exports.ts's `downloadDetectionRule`/`downloadDetectionRuleBundle` (B11) — no new export mechanism; and a detection-coverage trend built from the real, persisted (A7) `DetectionCoverage` tri-state verdicts, one row per scan. Self-contained data hook (apps/web/src/app/blue-team/hooks.ts) mirrors app/dashboards/hooks.ts's real-API-only pattern — no MSW handler.
Management Consoles: Specialized views under apps/web/src/app/rules, apps/web/src/app/scenarios, and apps/web/src/app/schedules allow operators to manage custom Semgrep rules, red-team attack scenarios, and recurring scan cron jobs.

Interactive Operations and Role Actions
Gate Approval Actions: Operators approve Layer 0 cost estimates via useApproveEstimate; Approvers authorize automated PR generation via useApproveFixGate.
Live DAST Authorization: Approvers authorize dynamic staging testing via useAuthorizeDast in DastPanel.
Emergency Abort: Operators and Approvers can trigger instant scan cancellation using the KillSwitchButton component.
False Positive Marking: Operators can mark individual findings as false positives with rationale strings via useMarkFalsePositive.
Compliance Downloads: Operators can export SARIF v2.1.0, raw JSON reports, and SOC2/ISO control matrices using ExportButtons.

Role Context and Simulation
Role Switcher: apps/web/src/components/role-context.tsx and the navigation header allow operators to switch the active simulated actor role (Viewer, Operator, Approver) to verify UI permission states and gate constraints.

Update Triggers
Update this file when new page routes are added to apps/web/src/app, when interactive gate operations change in apps/web/src/components, when dashboard visualizers are updated in apps/web/src/app/dashboards, or when the Report tab's generated-summary rendering changes in apps/web/src/components/generated-executive-summary.tsx.

Related Docs
docs/architecture/rendering-strategy.md — Client rendering and App Router architecture.
docs/ui/component-library.md — Component primitives and widgets used in console views.
