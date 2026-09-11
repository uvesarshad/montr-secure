# Authorization and Role-Based Access Control

Scope: Role definitions, permission matrices, gate approval restrictions, and DAST authorization rules.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure enforces strict role-based access control across all API endpoints and user console views. User accounts are assigned one of three hierarchical roles: Viewer, Operator, or Approver. Authorization middleware in apps/api/src/plugins/auth-plugin.ts verifies role assignments before executing sensitive operations, ensuring that high-consequence actions such as automated code modification and live dynamic network testing require explicit approval from authorized security principals.

Role Hierarchy and Permission Model
Viewer: Read-only access tier. Viewers can list and inspect scans, view vulnerability reports, inspect static and live proof artifacts, read audit log trails, and view configured DAST targets and schedules. Viewers cannot trigger scans, modify rules, or approve gates.
Operator: Execution tier. Operators inherit all Viewer capabilities and can create new scans, cancel running scans, trigger the emergency kill switch, approve pre-scan Layer 0 cost estimates, mark findings as false positives, and manage custom detection rules and cron schedules.
Approver: Elevated governance tier. Approvers inherit all Operator capabilities and hold exclusive authority to approve the Layer 4 Fix Gate (authorizing automated PR creation for auto-eligible fixes), register allowlisted DAST staging targets with rate-limit scope contracts, and authorize live DAST exploit testing against staging URLs.

Permission Matrix by Action
Action create_scan: Permitted for Operator and Approver.
Action cancel_scan: Permitted for Operator and Approver.
Action activate_kill_switch: Permitted for Operator and Approver to ensure immediate access during emergencies.
Action approve_estimate_gate: Permitted for Operator and Approver.
Action approve_fix_gate: Strictly restricted to Approver role.
Action register_dast_target: Strictly restricted to Approver role.
Action authorize_live_dast: Strictly restricted to Approver role.
Action authorize_scenario_live_run: Strictly restricted to Approver role — see the Scenario Written Authorization section below.
Action run_red_team_scenario: Strictly restricted to Approver role.
Action mark_false_positive: Permitted for Operator and Approver.
Action manage_custom_rules: Permitted for Operator and Approver.
Action view_reports_and_audit: Permitted for Viewer, Operator, and Approver.
Action configure_detection_rule_push_target: Strictly restricted to Approver role (suggested enhancement, 2026-09-12 red/blue agentic-posture audit) — configuring or removing the client's Splunk HEC push destination stores/deletes a live, reversible outbound credential, the same sensitivity class as register_dast_target.
Action push_detection_rule: Permitted for Operator and Approver — an operational action once an Approver has configured the push target, mirroring manage_custom_rules.

Gate Enforcement and Security Guards
Fix Gate Protection: Automated remediation pull request generation is guarded by the requireRole approver check on POST /api/v1/scans/:id/gate/fix. Even when auto-fix is globally enabled, pull requests are never opened without explicit Approver authorization.
Live DAST Protection: Probing staging environments with active exploit payloads is guarded by the requireApprover hard check on POST /api/v1/scans/:id/dast/authorize, a scan-scoped convenience wrapper apps/api/src/routes/dast.ts implements around the target-based POST /dast/targets/:id/authorize flow. It runs the identical production-blocked and allowlist checks, find-or-registers a DastTarget for the given staging URL, authorizes it, and additionally writes the staging URL and the acting approver onto the scan itself, since the orchestrator's live-DAST gate (packages/orchestrator/src/fsm.ts computeAllowLive) reads Scan.scope.stagingUrl and Scan.approver directly and has no knowledge of DastTarget rows.
Emergency Kill Switch Access: The kill switch endpoint POST /api/v1/scans/:id/kill is intentionally permitted for both Operator and Approver roles to allow immediate scan halting without administrative bottleneck.

Scenario Written Authorization (A1, 2026-09-12 red/blue agentic-posture audit)
Running a red-team scenario for real (apps/worker/src/scenario-runs genuinely probing a customer staging target) requires more than the Approver role and the allowlist: POST /api/v1/scenarios/:id/authorize (approver-only, CSRF-protected, mirrors dast.ts's POST /dast/targets/:id/authorize pattern) records an explicit, auditable written authorization — a required, non-empty free-text authorizationReference (a ticket number or signed agreement reference) plus the approver's id and a timestamp, bound to the scenario's exact current version. This is additive on top of every existing DAST guardrail (production block, allowlist, kill switch, blast-radius caps, egress guard) — none of them are relaxed by it. POST /api/v1/scenarios/:id/run still requires the Approver role exactly as before, but now ALSO requires this written authorization to be present and current before it will enqueue real worker-side execution; a missing or stale (edited-since-authorized) authorization is refused with a 403 explaining exactly what is missing, never a silent no-op. Any edit to the scenario (PUT /api/v1/scenarios/:id) invalidates a prior authorization outright — the approver must re-authorize the edited version explicitly. packages/contracts/src/phase4.ts's hasLiveRunAuthorization is the one predicate the route, the worker consumer, and the console's status badge all evaluate, so authorization state can never read differently in one place than another.

Detection-Rule Push Target Authorization (suggested enhancement, 2026-09-12 red/blue agentic-posture audit)
POST/DELETE /api/v1/detection-rules/push-targets (apps/api/src/routes/detection-rules.ts) require the strict Approver role via requireApprover, mirroring register_dast_target's precedent — the endpoint is operator-entered and the token is a live, reversible outbound secret. GET (metadata only, never the token) and both push routes (POST /detection-rules/push, POST /detection-rules/push-bundle) require Operator or Approver via requireRole. A push additionally re-enforces the platform's default-deny egress policy (packages/security/src/egress-guard.ts) against the configured endpoint before any outbound call — an operator must add the target host to MONTR_ALLOWED_EGRESS_HOSTS before a push can succeed, regardless of RBAC.

Update Triggers
Update this file when roles are added or modified in packages/contracts/src/enums.ts, when role checking middleware changes in apps/api/src/plugins/auth-plugin.ts, or when gate permission boundaries are altered.

Related Docs
docs/auth/auth-flow.md — Authentication, session tokens, and user identity resolution.
docs/api/route-handlers.md — Route handlers enforcing role-based pre-handler checks.
