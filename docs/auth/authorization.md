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
Action mark_false_positive: Permitted for Operator and Approver.
Action manage_custom_rules: Permitted for Operator and Approver.
Action view_reports_and_audit: Permitted for Viewer, Operator, and Approver.

Gate Enforcement and Security Guards
Fix Gate Protection: Automated remediation pull request generation is guarded by the requireRole approver check on POST /api/v1/scans/:id/gate/fix. Even when auto-fix is globally enabled, pull requests are never opened without explicit Approver authorization.
Live DAST Protection: Probing staging environments with active exploit payloads is guarded by the requireRole approver check on POST /api/v1/scans/:id/dast/authorize. The backend verifies that the target URL exists on the approved DastTarget allowlist and matches strict hostname patterns before executing tests.
Emergency Kill Switch Access: The kill switch endpoint POST /api/v1/scans/:id/kill is intentionally permitted for both Operator and Approver roles to allow immediate scan halting without administrative bottleneck.

Update Triggers
Update this file when roles are added or modified in packages/contracts/src/enums.ts, when role checking middleware changes in apps/api/src/plugins/auth-plugin.ts, or when gate permission boundaries are altered.

Related Docs
docs/auth/auth-flow.md — Authentication, session tokens, and user identity resolution.
docs/api/route-handlers.md — Route handlers enforcing role-based pre-handler checks.
