# API Route Handlers

Scope: HTTP REST endpoints, URL paths, request validation, authentication, authorization roles, and response contracts.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure exposes a versioned REST API built with Fastify in apps/api/src/server.ts. Unprefixed endpoints handle system liveness probes, while all domain operations are mounted under the /api/v1 route prefix registered in apps/api/src/routes/index.ts. Every route enforces row-scoped multitenancy, role-based access control, CSRF verification for state mutations, and Zod schema validation.

System and Authentication Endpoints
GET /health: Unauthenticated system liveness probe returning an object with status ok. Used by Docker and Kubernetes healthchecks.
POST /api/v1/auth/register: Public endpoint creating a new User and Client. Accepts email, password, and role. Returns auth token, user profile, and client record.
POST /api/v1/auth/login: Public authentication endpoint. Accepts email, password, and clientId. Validates credentials via Argon2, sets the montr_session HTTP-only cookie, and returns a Bearer JWT token with user and client models.
POST /api/v1/auth/logout: Authenticated endpoint clearing the session cookie and invalidating the active session.
GET /api/v1/auth/me: Authenticated endpoint returning the current user identity, role, and tenant client details.
GET /api/v1/auth/csrf: Public endpoint providing a cryptographic CSRF token for subsequent mutating requests.

Scan Lifecycle Endpoints in apps/api/src/routes/scans.ts
POST /api/v1/scans: Creates and enqueues a new scan. Requires operator or approver role and CSRF header. Accepts repository name, branch, scan mode (full or diff), optional scan scope, and budget policy. Persists the scan, enqueues Layer 0, records an audit event, and returns the scan entity.
GET /api/v1/scans: Authenticated endpoint returning a list of all scans belonging to the caller client tenant.
GET /api/v1/scans/:id: Authenticated endpoint returning full details of a specific scan by unique ID.
GET /api/v1/scans/:id/status: Returns real-time execution status, gate state, cost estimate, and actual token costs.
POST /api/v1/scans/:id/cancel: Requires operator or approver role and CSRF header. Transitions scan status to cancelled.
POST /api/v1/scans/:id/kill: Emergency kill switch endpoint. Requires operator or approver role and CSRF header. Accepts a mandatory cancellation reason string, broadcasts an abort signal across Redis, halts active workers, and records a security audit log event.

Gate and Authorization Endpoints in apps/api/src/routes/gate.ts and dast.ts
POST /api/v1/scans/:id/gate/estimate: Approves the Layer 0 cost estimate. Requires operator or approver role. Transitions gate state from estimate_pending to estimate_approved and enqueues Layer 1.
POST /api/v1/scans/:id/gate/fix: Approves automated remediation pull requests. Requires strict approver role. Authorizes opening PRs for all auto-eligible fixes.
GET /api/v1/dast/targets: Returns allowlisted staging URLs and active scope contracts.
POST /api/v1/dast/targets: Registers a new allowlisted staging URL with request rate and blast-radius constraints. Requires approver role.
POST /api/v1/scans/:id/dast/authorize: Authorizes live dynamic exploit testing against an allowlisted staging target for a specific scan. Requires strict approver role.

Findings, Reports, and Audit Endpoints
GET /api/v1/scans/:id/candidates: Returns raw Layer 1 candidate findings.
GET /api/v1/scans/:id/probable: Returns correlated Layer 2 probable findings.
GET /api/v1/scans/:id/confirmed: Returns exploit-verified Layer 3 confirmed findings with static or live proof artifacts.
GET /api/v1/scans/:id/fixes: Returns synthesized Layer 4 patches, risk classifications, and proof-of-fix tests.
GET /api/v1/scans/:id/report: Returns the monolithic Layer 5 security report document.
GET /api/v1/scans/:id/report/sarif: Returns standard OASIS SARIF JSON output.
GET /api/v1/scans/:id/report/compliance: Returns structured SOC2, ISO27001, and OWASP Top 10 compliance mappings.
POST /api/v1/findings/:id/false-positive: Marks a finding as a false positive with an operator rationale. Requires operator or approver role.
GET /api/v1/audit: Queries append-only audit events with sequence numbers, actors, and cryptographic verification status.
GET /api/v1/audit/verify: Verifies hash-chain integrity across all client audit events.

Management and Automation Endpoints
GET and POST /api/v1/rules: Lists and creates custom Semgrep and secret detection rules. Validates syntax before saving.
GET and POST /api/v1/scenarios: Lists and creates versioned red-team DAST attack scenarios with encrypted step sequences.
GET and POST /api/v1/schedules: Manages cron scan schedules with mandatory per-run budget ceiling policies.
GET /api/v1/analytics/posture: Returns historical posture snapshots and vulnerability trends over time.

Update Triggers
Update this file when Fastify route handlers are added, removed, or modified in apps/api/src/routes, when URL parameters change, or when role permission requirements are adjusted.

Related Docs
docs/auth/authorization.md — Role permissions and gate guard requirements.
docs/api/database.md — Underlying models and repositories queried by route handlers.
