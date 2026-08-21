# Environment Configuration

Scope: Complete catalog of environment variables, defaults, exposure levels, and consuming modules.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure is configured through environment variables loaded by packages/config/src/loader.ts and merged with hardened baseline defaults defined in packages/config/src/schema.ts. All security controls operate with hardened defaults where auto-fix is off, dynamic testing is off, budget enforcement is set to hard halt, telemetry is disabled, and network egress is locked to default deny.

Database and Infrastructure Variables
DATABASE_URL: PostgreSQL connection URI with schema parameter. Consumed by packages/state-store and Prisma client. Required.
REDIS_URL: Redis connection URI for BullMQ job queues and cross-process event broadcasting. Consumed by packages/orchestrator, apps/worker, and apps/api. Required.
MONTR_CLIENT_ID: Tenant identifier for row-scoped multitenant isolation. Defaults to default. Consumed by packages/config and packages/state-store.
MONTR_STUCK_SCAN_THRESHOLD_MS: Milliseconds a running scan's resume checkpoint may go unchanged before apps/worker's boot-time reconciliation presumes it was abandoned by a crashed worker process and calls the orchestrator's resume() on it. Defaults to 600000 (10 minutes). Consumed by apps/worker/src/main.ts via apps/worker/src/reconcile.ts.

API and Authentication Variables
JWT_SECRET: High-entropy secret string minimum thirty-two characters used to sign user session tokens. Consumed exclusively by apps/api/src/production-deps.ts. Server-side only. Required for API startup.
CSRF_SECRET: Secret string minimum sixteen characters used to generate and verify CSRF protection tokens. Consumed by apps/api/src/production-deps.ts. Server-side only. Required for API startup.
MONTR_API_CORS_ORIGINS: Comma-separated list of allowed web console origins. Defaults to empty which blocks all cross-origin browser traffic. Consumed by apps/api.
MONTR_WEBHOOK_SECRET: HMAC secret verifying the X-Hub-Signature-256 header on inbound POST /api/v1/webhooks/scan-trigger requests (A15). Unset by default, which disables the route (503) — the hardened, fail-closed default. Consumed by apps/api/src/routes/webhooks.ts via apps/api/src/production-deps.ts.
MONTR_WEBHOOK_OPERATOR_EMAIL: Email of an existing operator- or approver-role user that webhook-triggered scans are attributed to (Scan.operator has a required foreign key to User and the webhook request carries no session). Required alongside MONTR_WEBHOOK_SECRET for the webhook route to serve requests. Consumed by apps/api/src/routes/webhooks.ts.
MONTR_WEBHOOK_GITHUB_TOKEN: Optional GitHub token used only to post a single best-effort acknowledgement comment on the originating PR when the webhook payload includes pullRequest owner/repo/number. Unset by default (no comment posted). Consumed by apps/api/src/routes/webhooks.ts via packages/report's postGitHubComment.
MONTR_API_URL: Base URL of the apps/api server the montr CLI (apps/cli) talks to. Defaults to http://localhost:3001. Consumed by apps/cli.
MONTR_API_TOKEN: Bearer JWT the montr CLI sends as Authorization, as an alternative to --token. Consumed by apps/cli.
MONTR_API_EMAIL / MONTR_API_PASSWORD: Login credentials the montr CLI exchanges for a bearer token via POST /auth/login when no token is supplied, as an alternative to --email/--password. Consumed by apps/cli.

Web Console Client Variables
NEXT_PUBLIC_API_BASE_URL: HTTP URL of the backend Fastify API reachable by user browser clients. Consumed at build time by apps/web/src/lib/api/config.ts. Client-side exposed. Defaults to http://localhost:3001.

LLM Gateway and Model Matrix Variables
MONTR_LLM_PROVIDER: Identifier of the upstream LLM provider. Permitted values are anthropic, bedrock, vertex, or azure. Defaults to anthropic. Consumed by packages/llm-gateway.
MONTR_LLM_API_KEY: Secret API key for the chosen LLM provider. Read directly by packages/config/src/loader.ts or resolved via key sources. Server-side only.
MONTR_LLM_API_KEY_REF: Name of the environment variable or secret reference holding the LLM key in secret stores.
MONTR_LLM_ENDPOINT: Custom HTTPS endpoint URL for internal model proxies or air-gapped LLM gateways.
MONTR_LLM_KEY_TIER_GUARD: Mode for flagging non-enterprise data-retaining API tiers. Values are warn, block, or off. Defaults to warn. Consumed by packages/llm-gateway.
MONTR_MODEL_TRIAGE: Model identifier used for fast filtering and candidate triage in Layer 1 and Layer 2. Defaults to claude-haiku-4-5 (A11; undated canonical id — was claude-haiku-4-5-20251001).
MONTR_MODEL_DEFAULT: Model identifier used for Layer 0 AST extraction and Layer 4 fix synthesis. Defaults to claude-sonnet-5.
MONTR_MODEL_CONFIRMATION: Model identifier used for Layer 3 static taint verification and exploit proofs. Defaults to claude-opus-5 (A11; current flagship — was claude-opus-4-8, which remains a valid, priced model and can still be set explicitly).
MONTR_LLM_FALLBACK_MODEL: Model identifier retried, exactly once, after the resolved primary model's retry budget is exhausted (A11). Applies across every tier (triage/default/confirmation) — e.g. set to a Sonnet-class id so an Opus confirmation call that keeps failing falls back rather than failing the layer outright. Unset by default, which preserves today's fail-outright-after-retries behavior. Consumed by packages/llm-gateway/src/gateway.ts and packages/llm-gateway/src/retry.ts via packages/config schema key llm.fallbackModel.

Budget and Enforcement Variables
MONTR_BUDGET_MAX_USD: Numeric dollar limit per scan run. When exceeded, the pipeline terminates immediately with a partial report. Consumed by packages/cost-meter.
MONTR_BUDGET_MAX_TOKENS: Total cumulative token limit per scan run. Consumed by packages/cost-meter.
MONTR_BUDGET_ENFORCEMENT: Enforcement action upon ceiling breach. Values are hard_halt or warn. Defaults to hard_halt. Consumed by packages/cost-meter and packages/orchestrator.

Feature Toggles and DAST Controls
MONTR_AUTOFIX_ENABLED: Global toggle for automated pull request generation. Defaults to false. Consumed by packages/report and packages/fix.
MONTR_DAST_ENABLED: Global toggle for live dynamic exploit testing. Defaults to false. Consumed by packages/confirm.
MONTR_DAST_ALLOWLIST: Comma-separated list of pre-approved staging URLs permitted for live verification. Defaults to empty. Consumed by packages/confirm.
MONTR_TELEMETRY_ENABLED: Toggle for anonymized operational metrics. Defaults to false. Consumed by packages/telemetry.

Discovery and Scanner Variables
MONTR_DISCOVERY_RULESETS_DIR: Local filesystem path to a directory of Semgrep rule YAML files, used in place of the hosted p/... Semgrep Registry packs. Required for air-gapped deployments (the default-deny egress policy blocks the Semgrep Registry); set to the semgrep subdirectory produced by deploy/airgap/import-bundle.sh (default /opt/montr/airgap/semgrep). Unset by default, which preserves the hosted-registry behavior unchanged. Consumed by packages/discovery/src/detectors/sast.ts via packages/config schema key discovery.rulesetsDir. SAST is a required detector: once set, a missing or empty directory at scan time fails the scan rather than degrading silently.

Security and Secret Management Variables
MONTR_FIELD_ENCRYPTION_KEY_REF: Base64-encoded 256-bit AES key used for encrypting credentials and sensitive fields in Postgres. Consumed by packages/state-store, via the key source selected by MONTR_KEY_SOURCE below (this is the raw value for the "env"/"file" sources; ignored when MONTR_KEY_SOURCE=vault).
MONTR_KEY_SOURCE: Selects which backend resolves the field-encryption key bytes — env, file, or vault. Defaults to env (the pre-existing behavior: MONTR_FIELD_ENCRYPTION_KEY_REF's value is used as-is). Consumed by packages/config/src/key-source.ts's createKeySource/resolveFieldEncryptionKey (A10), called from apps/worker/src/main.ts and apps/api/src/production-deps.ts before constructing the state store — both now go through this pluggable resolver instead of reading MONTR_FIELD_ENCRYPTION_KEY_REF directly, so vault is a genuine drop-in.
MONTR_ALLOWED_EGRESS_HOSTS: Comma-separated list of additional outbound network hosts permitted by the egress firewall. Consumed by packages/security.
VAULT_ADDR: HTTPS URL of the HashiCorp Vault server. Required when MONTR_KEY_SOURCE=vault. Consumed by packages/config/src/key-source.ts.
VAULT_TOKEN: Static authentication token for HashiCorp Vault. Alternative to VAULT_ROLE_ID/VAULT_SECRET_ID (AppRole) — one of the two auth modes is required when MONTR_KEY_SOURCE=vault. Consumed by packages/config/src/key-source.ts.
VAULT_ROLE_ID: AppRole Role ID for HashiCorp Vault authentication. Consumed by packages/config/src/key-source.ts.
VAULT_SECRET_ID: AppRole Secret ID for HashiCorp Vault authentication. Consumed by packages/config/src/key-source.ts.
VAULT_NAMESPACE: Vault Enterprise namespace, if any. Optional. Consumed by packages/config/src/key-source.ts.
VAULT_KV_MOUNT: KV v2 secrets engine mount point. Defaults to secret. Consumed by packages/config/src/key-source.ts.
VAULT_SECRET_PATH: Path within the KV mount holding the field-encryption key (e.g. montr/field-encryption-key). Required when MONTR_KEY_SOURCE=vault. Consumed by packages/config/src/key-source.ts.
VAULT_KV_FIELD: Field name inside the secret's data object holding the key bytes. Defaults to value. Consumed by packages/config/src/key-source.ts.
VAULT_REQUEST_TIMEOUT_MS: Request timeout in milliseconds for Vault HTTP calls (login + secret read). Defaults to 5000. Consumed by packages/config/src/key-source.ts.
MONTR_CONFIG_FILE: Absolute filesystem path to a JSON configuration file providing fine-grained retention, rate limits, and RBAC policies.

Update Triggers
Update this file when a new environment variable is added to packages/config/src/schema.ts or apps/api/src/production-deps.ts, when default values change, or when variables are deprecated.

Related Docs
docs/infra/deployment.md — Deployment configurations where environment variables are injected.
docs/modules/llm-gateway.md — LLM provider credentials and model selection configuration.
