# Database Architecture and Models

Scope: Relational database schema, Prisma ORM models, multitenancy design, field encryption, and hash-chain audit storage.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure persists data in PostgreSQL using the Prisma ORM managed in packages/state-store. The database implements strict row-scoped multitenancy, where all entities carry a client identifier and queries are explicitly scoped in repository layer wrappers. Sensitive fields are encrypted at rest using AES-256-GCM, and security audit events are stored in an append-only, cryptographic hash-chained table.

Multitenancy and Tenant Isolation
Row-Scoped Isolation: Every database model contains a clientId foreign key indexed for rapid tenant filtering. All query operations in packages/state-store/src/prisma-store.ts automatically enforce clientId scoping to prevent cross-tenant data leakage.
Single-Tenant and Air-Gap Mode: For high-isolation deployments, dedicated Postgres database schemas or isolated database instances can be provisioned per client without schema modifications.

Field-Level Encryption at Rest
Encrypted Columns: High-sensitivity columns including LlmCredential apiKey and refreshToken, as well as RedTeamScenario steps, are annotated with encryption directives and transformed via AES-256-GCM before writing to Postgres.
Key Resolution: Encryption keys are supplied via environment variables, Kubernetes secret mounts, or HashiCorp Vault KV v2 lookups resolved at server startup.

Core Relational Models in packages/state-store/prisma/schema.prisma
Client: Represents a tenant organization owning users, scans, application maps, audit logs, DAST targets, and credentials.
User: Represents an authenticated operator, approver, or viewer carrying an Argon2 password hash and role designation.
LlmCredential: BYO-key configuration storing encrypted provider credentials, provider type, and verified key tier.
AppMap: Structural snapshot of a repository commit containing routes, entry points, data stores, ORM models, and taint flow graphs.
Route, TaintSource, TaintSink: Structural application elements linked to AppMap representing HTTP paths, input sources, and database/command sinks.
Scan: Primary execution entity recording repository target, branch, scan mode, status, gate state, cost estimates, and actual costs.
ScanState: Checkpoint entity recording active layer, completed layer history, and resume tokens enabling pipeline pause and resume.
CandidateFinding: Raw, unverified issues captured during Layer 1 discovery, linked to source tools (Semgrep, gitleaks, OSV).
ProbableFinding: Correlated findings generated in Layer 2 with reachability, exposure, and impact scores, linked to root causes.
ConfirmedFinding: Exploit-verified vulnerabilities generated in Layer 3 with attached static or live ProofArtifact JSON.
Fix: Remediation entity generated in Layer 4 containing unified diff patches, proof-of-fix tests, and auto-eligible or human-required risk classifications.
PullRequest: Version control tracking record storing PR URLs, branches, status, and associated fix IDs.
Report: Monolithic document entity storing the finalized Layer 5 security report and compliance mappings.
DastTarget: Allowlisted staging URLs with approved rate limits and concurrency contracts.
AuditEvent: Immutable, append-only log record storing sequential actions, actor metadata, previous hash, and SHA-256 hash chaining.
CustomRule, RedTeamScenario, ScanSchedule, PostureSnapshot: Scale and intelligence entities managing custom detection rules, attack playbooks, cron schedules, and historical trend snapshots.

Audit Log Scrub Gate
`PrismaAuditLogClient.append` in packages/state-store/src/audit.ts is the single write chokepoint for every AuditEvent, reached by all callers across apps/api and apps/worker. It unconditionally runs both free-form text fields — `metadata` and `summary` — through @montr/security's content-aware `redactSensitive` before hashing/persisting, then re-verifies the redacted output with that package's independent `findLogViolations` verifier as defense in depth. This promotes @montr/security's scrubber (previously exercised only by tests certifying @montr/telemetry's separate hot-path log scrubber) into a real runtime gate on the persistence path itself, closing the gap where AuditEventInput.metadata's Zod type (`z.record(z.string(), z.unknown())`) could not enforce "MUST be scrubbed" beyond a code comment. The gate is fail-safe rather than fail-closed: on the residual case where content still trips the verifier after redaction, the event is still persisted with an anomaly-marker payload rather than being rejected, so a safety-relevant write (e.g. a kill-switch event) is never silently lost.

Migration Strategy
Schema Migrations: Schema modifications are authored in packages/state-store/prisma/schema.prisma and validated using pnpm prisma:validate and pnpm prisma:format.
Generation: Client code generation is triggered via pnpm prisma:generate during root postinstall hooks.

Update Triggers
Update this file when Prisma models, fields, enums, or relationships are modified in packages/state-store/prisma/schema.prisma, or when repository access patterns change in packages/state-store.

Related Docs
docs/api/route-handlers.md — API endpoints querying and mutating database models.
docs/state/server-state.md — Server-side persistence and checkpoint management.
