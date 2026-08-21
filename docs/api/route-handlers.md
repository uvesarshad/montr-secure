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
POST /api/v1/scans/:id/resume: Requires operator or approver role and CSRF header. Calls the orchestrator's resume lifecycle method, which skips already-completed layers via the persisted resume checkpoint and re-checks gate state before scheduling the next layer. A completed or cancelled scan is a no-op. Records a scan.resumed audit event. apps/worker also calls this same orchestrator method automatically at boot time for scans found stuck at status running with a stale checkpoint; this route is the operator-triggered counterpart.
POST /api/v1/scans/:id/kill: Emergency kill switch endpoint. Requires operator or approver role and CSRF header. Accepts a mandatory cancellation reason string, broadcasts an abort signal across Redis, halts active workers, and records a security audit log event.
GET /api/v1/scans/:id/progress: Returns a polled snapshot of layer-progress events for a scan as a plain array, matching the operator console's four-second poll. Drains the orchestrator's replay-then-live event stream without blocking on future events, and maps progress, layer-started, and layer-completed lifecycle events onto the narrower progress-event shape the console consumes.
GET /api/v1/scans/:id/appmap: Returns the bare App Map built for a scan by resolving the scan's appMapId reference. Returns not found until Layer 0 has completed.

Gate and Authorization Endpoints in apps/api/src/routes/gate.ts and dast.ts
POST /api/v1/scans/:id/gate/estimate: Approves the Layer 0 cost estimate. Requires operator or approver role. Transitions gate state from estimate_pending to estimate_approved and enqueues Layer 1.
POST /api/v1/scans/:id/gate/fix: Approves automated remediation pull requests. Requires strict approver role. Authorizes opening PRs for all auto-eligible fixes.
GET /api/v1/dast/targets: Returns allowlisted staging URLs and active scope contracts.
POST /api/v1/dast/targets: Registers a new allowlisted staging URL with request rate and blast-radius constraints. Requires operator or approver role.
POST /api/v1/dast/targets/:id/authorize: Authorizes a registered DAST target by id after checking the production-blocked policy and the configured allowlist. Requires strict approver role.
POST /api/v1/scans/:id/dast/authorize: Scan-scoped convenience wrapper around the target-based flow above, matching the path and body shape the operator console has always sent. Requires strict approver role. Enforces the identical production-blocked and allowlist checks as the target route, find-or-registers a DastTarget for the given staging URL, and authorizes it. It also writes the staging URL and the acting approver onto the scan itself (scope.stagingUrl and approver), because the orchestrator's live-DAST gate reads those two scan fields directly and has no knowledge of DastTarget rows.

Findings, Reports, and Audit Endpoints
GET /api/v1/scans/:id/candidates: Returns raw Layer 1 candidate findings.
GET /api/v1/scans/:id/probable: Returns correlated Layer 2 probable findings.
GET /api/v1/scans/:id/confirmed: Returns exploit-verified Layer 3 confirmed findings with static or live proof artifacts.
GET /api/v1/scans/:id/fixes: Returns synthesized Layer 4 patches, risk classifications, and proof-of-fix tests.
GET /api/v1/scans/:id/report: Returns the monolithic Layer 5 security report document.
GET /api/v1/scans/:id/report/sarif: Returns standard OASIS SARIF JSON output.
GET /api/v1/scans/:id/report/compliance: Returns structured SOC2, ISO27001, and OWASP Top 10 compliance mappings.
GET /api/v1/pull-requests: Cross-scan aggregate of every pull request opened for the authenticated client, not scoped to a single scan. Returns a bare array. The scan-scoped equivalent remains client-derived from the Report's fixStatus.
POST /api/v1/findings/:id/false-positive: Marks a finding as a false positive with an operator rationale. Requires operator or approver role.
GET /api/v1/learned-facts: Returns this client's accumulated learned facts (custom sanitizer names, framework idioms, operator decisions) for a repo, newest first. Accepts a required repo query parameter and an optional limit. Any authenticated role may read (§15 cross-scan memory, E8).
POST /api/v1/learned-facts: Records a durable learned fact about a repo (apps/api/src/routes/learned-facts.ts). Requires operator or approver role and CSRF header. Accepts repo, a type (custom_sanitizer, framework_idiom, or operator_decision), and a free-form, size-capped content object. Records a learned_fact.recorded audit event. A later scan of the same client and repo injects these facts as additive context into that scan's Layer 1, 2, and 3 LLM prompts (see docs/modules/llm-gateway.md and docs/modules/discovery.md) — never a substitute for the deterministic pipeline. Confirmed-false-positive facts are not recorded here; they remain owned by POST /findings/:id/false-positive and are merged in at read time.
GET /api/v1/audit: Queries append-only audit events with sequence numbers, actors, and cryptographic verification status.
GET /api/v1/audit/verify: Verifies hash-chain integrity across all client audit events.

Webhook Trigger Endpoint in apps/api/src/routes/webhooks.ts
POST /api/v1/webhooks/scan-trigger: Provider-agnostic, unauthenticated-by-session scan trigger (A15). Verifies a GitHub-compatible X-Hub-Signature-256 HMAC header (apps/api/src/auth/webhook-signature.ts, constant-time comparison) over the raw request body instead of a JWT/cookie principal, then creates and starts a scan through the same orchestrator.createScan/start path POST /scans uses. Accepts repo, branch, mode (full or diff, defaulting to diff), an optional scope (reuses ScanScopeSchema, e.g. changedFiles for diff mode), and an optional pullRequest owner/repo/number. Disabled (503 WEBHOOK_NOT_CONFIGURED) unless the deployment sets MONTR_WEBHOOK_SECRET and MONTR_WEBHOOK_OPERATOR_EMAIL; the resulting scan is attributed to that named operator/approver account since Scan.operator has a required foreign key to User and the caller carries no session. When MONTR_WEBHOOK_GITHUB_TOKEN is set and the payload includes pullRequest, best-effort posts a single acknowledgement comment on that PR via packages/report's postGitHubComment (never blocks or fails scan creation on a post failure). This is the concrete "PR opened -> scan runs" trigger surface ahead of a full GitHub App (manifest registration and OAuth installation remain out of scope).

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
