import { z } from "zod";
import {
  ProviderSchema,
  BudgetEnforcementSchema,
  RiskClassSchema,
  CategorySchema,
  RECOMMENDED_MODEL_MATRIX,
} from "@montr/contracts";

/**
 * Montr Secure configuration schema (§3.5, §10).
 *
 * HARDENED, SAFETY-FIRST DEFAULTS (§11):
 *   - auto-fix OFF
 *   - DAST OFF
 *   - budget hard-halt ON
 *   - telemetry OFF
 *   - egress default-deny
 * Every default below is chosen so an unconfigured deployment is the safe one.
 */

export const KeyTierGuardModeSchema = z.enum(["warn", "block", "off"]);
export type KeyTierGuardMode = z.infer<typeof KeyTierGuardModeSchema>;

export const ModelMatrixSchema = z.object({
  triage: z.string().min(1),
  default: z.string().min(1),
  confirmation: z.string().min(1),
});
export type ModelMatrix = z.infer<typeof ModelMatrixSchema>;

export const LlmConfigSchema = z.object({
  provider: ProviderSchema.default("anthropic"),
  /** Optional custom endpoint (internal proxy / air-gapped model gateway). */
  endpoint: z.string().url().optional(),
  /** Name of the secret holding the key (env var / k8s secret key). BYO-key. */
  apiKeyRef: z.string().optional(),
  /** Resolved key — injected by the loader from a secret source, never a config file. */
  apiKey: z.string().optional(),
  modelMatrix: ModelMatrixSchema.default(() => ({
    triage: RECOMMENDED_MODEL_MATRIX.triage.modelId,
    default: RECOMMENDED_MODEL_MATRIX.default.modelId,
    confirmation: RECOMMENDED_MODEL_MATRIX.confirmation.modelId,
  })),
  /**
   * BYO fallback model id (A11). When the gateway's retry budget on the
   * request's resolved primary model is exhausted (or it fails immediately
   * on a non-retriable error), the SAME request is retried exactly once
   * against this model before the call fails outright — e.g. Opus falling
   * back to Sonnet. Applies across every tier. Unset (default): today's
   * behavior is unchanged — a failing model fails outright after its own
   * retries, with no cascade.
   */
  fallbackModel: z.string().min(1).optional(),
  /** ⛔ Key-tier guard — warn (default) or block suspected data-retaining tiers. */
  keyTierGuard: KeyTierGuardModeSchema.default("warn"),
  /** Warn/refuse confirmation on a sub-floor model (DECIDE-3). */
  enforceModelFloor: z.boolean().default(true),
});
export type LlmConfig = z.infer<typeof LlmConfigSchema>;

export const BudgetConfigSchema = z.object({
  maxUsdPerScan: z.number().positive().optional(),
  maxTokensPerScan: z.number().int().positive().optional(),
  /** DECIDE-4: hard halt by default. */
  enforcement: BudgetEnforcementSchema.default("hard_halt"),
  requireEstimateApproval: z.boolean().default(true),
  warnThresholdPct: z.number().min(0).max(1).default(0.8),
});
export type BudgetConfig = z.infer<typeof BudgetConfigSchema>;

export const AutoFixConfigSchema = z.object({
  /** ⛔ OFF by default. Even ON, only auto-eligible fixes open PRs. */
  enabled: z.boolean().default(false),
  /** Locked: code changes are PRs only, never direct commits (golden rule #5). */
  prOnly: z.literal(true).default(true),
  allowedRiskClasses: z.array(RiskClassSchema).default(["auto-eligible"]),
  /** Categories ALWAYS routed to human review regardless of the toggle (§11). */
  humanRequiredCategoriesAlways: z
    .array(CategorySchema)
    .default(["broken_access_control", "broken_authentication", "weak_crypto", "idor", "csrf"]),
});
export type AutoFixConfig = z.infer<typeof AutoFixConfigSchema>;

export const DastScopeContractSchema = z.object({
  maxRequestsPerScan: z.number().int().positive().default(500),
  maxConcurrentRequests: z.number().int().positive().default(2),
  maxRequestsPerSecond: z.number().positive().default(5),
  /** Blast-radius cap: max distinct destructive actions per run. */
  maxMutatingRequests: z.number().int().nonnegative().default(0),
});
export type DastScopeContract = z.infer<typeof DastScopeContractSchema>;

export const DastConfigSchema = z.object({
  /** ⛔ OFF by default (DECIDE-1). Live confirmation only after staging authorized. */
  enabled: z.boolean().default(false),
  /** Explicit staging target allowlist. Empty = nothing may be probed. */
  allowlist: z.array(z.string()).default([]),
  /** ⛔ Locked: production is blocked by policy. */
  productionBlocked: z.literal(true).default(true),
  scope: DastScopeContractSchema.default({}),
  /** ⛔ Kill switch always available. */
  killSwitchEnabled: z.literal(true).default(true),
  /** ⛔ Approver authorization required before any live run. */
  requireApprover: z.boolean().default(true),
});
export type DastConfig = z.infer<typeof DastConfigSchema>;

export const RetentionConfigSchema = z.object({
  scanDays: z.number().int().positive().default(90),
  appMapDays: z.number().int().positive().default(30),
  auditDays: z.number().int().positive().default(3650),
  /** Audit log is append-only / immutable by default. */
  auditImmutable: z.boolean().default(true),
});
export type RetentionConfig = z.infer<typeof RetentionConfigSchema>;

export const RbacConfigSchema = z.object({
  approverRequiredForGate: z.boolean().default(true),
  approverRequiredForDast: z.boolean().default(true),
  sessionTtlMinutes: z.number().int().positive().default(60),
});
export type RbacConfig = z.infer<typeof RbacConfigSchema>;

export const TelemetryConfigSchema = z.object({
  /** OFF by default — no vendor telemetry (§10). */
  enabled: z.boolean().default(false),
  endpoint: z.string().url().optional(),
  anonymized: z.boolean().default(true),
});
export type TelemetryConfig = z.infer<typeof TelemetryConfigSchema>;

/**
 * Which backend resolves the AES-256-GCM field-encryption key:
 *   - "env"/"file": the key bytes are already sitting in `fieldEncryptionKeyRef`,
 *     placed there synchronously by the loader's env/secret-mount overlays.
 *   - "vault": the key bytes are fetched at runtime from a HashiCorp Vault KV v2
 *     secrets engine over HTTP (see {@link VaultKeySourceConfigSchema} and
 *     `./key-source.ts`).
 */
export const KeySourceKindSchema = z.enum(["env", "file", "vault"]);
export type KeySourceKind = z.infer<typeof KeySourceKindSchema>;

/**
 * HashiCorp Vault connection config for the "vault" key source. Populated from
 * `VAULT_*` env vars by the loader (§ envOverlay). Auth is either a static
 * token (`token`) or AppRole (`roleId` + `secretId`) — never both required.
 */
export const VaultKeySourceConfigSchema = z.object({
  /** Vault server address, e.g. "https://vault.internal:8200". */
  addr: z.string().url().optional(),
  /** Static Vault token (`VAULT_TOKEN`). Prefer AppRole in production. */
  token: z.string().optional(),
  /** Vault Enterprise namespace, if any. */
  namespace: z.string().optional(),
  /** AppRole RoleID (`VAULT_ROLE_ID`) — alternative to a static token. */
  roleId: z.string().optional(),
  /** AppRole SecretID (`VAULT_SECRET_ID`) — alternative to a static token. */
  secretId: z.string().optional(),
  /** KV v2 mount point (default "secret"). */
  kvMount: z.string().min(1).default("secret"),
  /** Path within the KV mount holding the key, e.g. "montr/field-encryption-key". */
  secretPath: z.string().optional(),
  /** Field name inside the secret's `data` object holding the key bytes. */
  field: z.string().min(1).default("value"),
  requestTimeoutMs: z.number().int().positive().default(5000),
});
export type VaultKeySourceConfig = z.infer<typeof VaultKeySourceConfigSchema>;

/**
 * Layer 1 discovery / SAST engine configuration.
 *
 * `rulesetsDir` is the air-gap escape hatch for A4: hosted Semgrep Registry
 * pack IDs (`p/owasp-top-ten`, `p/typescript`, …) require network egress to
 * Semgrep's registry, which the hardened air-gap NetworkPolicy forbids. When
 * set, `detectSast` (packages/discovery/src/detectors/sast.ts) invokes
 * Semgrep against this LOCAL directory of rule YAML instead — the shape
 * `deploy/airgap/import-bundle.sh` installs artifacts into (flat files under
 * `<dest-dir>/semgrep/`, built by `build-bundle.sh --semgrep-rules-dir`).
 * Unset (default): non-air-gapped installs are unchanged and keep using the
 * hosted registry packs.
 */
export const DiscoveryConfigSchema = z.object({
  /** Local filesystem path to a directory of Semgrep rule YAML files. */
  rulesetsDir: z.string().optional(),
});
export type DiscoveryConfig = z.infer<typeof DiscoveryConfigSchema>;

/**
 * A5 — the bounded agentic fix loop (`proposeFixWithAgent` in
 * packages/fix/src/generate.ts's `FixGenerationContext.agentLoop`). ⛔ OFF by
 * default, mirroring the constructor-opt-in convention `FixGenerationContext`
 * itself documents for `containerProof`/`ConfirmDeps.investigation`/`escalation`:
 * an unconfigured deployment gets the EXACT single-shot fix-generation call
 * unchanged (no retries, no tool use, no extra token spend or latency).
 *
 * `maxIterations` bounds real proposal attempts (each is one additional model
 * round-trip — cost and latency scale directly with it); `maxToolCalls`
 * bounds `read_file` tool round-trips separately. Both default to a small
 * non-zero value (A12) so an operator who flips `enabled` to true gets this
 * feature's actual stated purpose — bounded retries WITH sandboxed
 * multi-file context — rather than retries alone; an operator who wants
 * retries-only can still set `maxToolCalls: 0` explicitly. Both are capped
 * well below any plausible legitimate value so a config typo (an extra
 * zero) cannot turn into runaway spend.
 */
export const FixAgentLoopConfigSchema = z.object({
  /** ⛔ OFF by default (A5). */
  enabled: z.boolean().default(false),
  /** Real proposal attempts, NOT tool round-trips. 1–10; each is a model round-trip. */
  maxIterations: z.number().int().nonnegative().max(10).default(3),
  /** `read_file` tool round-trips. Defaults to 3 (A12) so enabling the loop exposes the tool; 0 disables it. 0–20. */
  maxToolCalls: z.number().int().nonnegative().max(20).default(3),
});
export type FixAgentLoopConfig = z.infer<typeof FixAgentLoopConfigSchema>;

/** Layer 4 (fix generation) configuration (§7 L4). */
export const FixGenerationConfigSchema = z.object({
  agentLoop: FixAgentLoopConfigSchema.default({}),
});
export type FixGenerationConfig = z.infer<typeof FixGenerationConfigSchema>;

/**
 * A9 — the semantic codebase index (`@montr/semantic-index`'s
 * `buildSemanticIndex`), built as an additional Layer 0 step alongside the
 * App Map (`packages/appmap/src/build.ts`, `apps/worker/src/runners.ts`).
 * ⛔ OFF by default, mirroring `FixAgentLoopConfigSchema`'s constructor-opt-in
 * convention: an unconfigured deployment gets today's exact Layer 0 behavior
 * unchanged — no embedding calls, no pgvector writes, no extra latency.
 *
 * Enabling this alone is not sufficient for the index to actually build —
 * the worker only builds it when, IN ADDITION, the configured `llm.provider`
 * has a real embeddings adapter (`azure` or, as of A9, `openai` — see
 * `packages/llm-gateway/src/embeddings.ts`) AND a pgvector-backed
 * `CodeChunkRepository` was constructed (requires the `pgvector` Postgres
 * extension — see docs/modules/semantic-index.md's AGENT NOTE). Any other
 * combination degrades to a skip with a logged reason, never a failed scan.
 */
export const SemanticIndexConfigSchema = z.object({
  /** ⛔ OFF by default (A9). */
  enabled: z.boolean().default(false),
  /** Embedding model / deployment name passed to the embeddings adapter. */
  embeddingModel: z.string().min(1).default("text-embedding-3-small"),
});
export type SemanticIndexConfig = z.infer<typeof SemanticIndexConfigSchema>;

/**
 * Per-tenant BullMQ queue isolation (A27). `perTenantIsolation` is OFF by
 * default: today's six shared per-layer queues (`montr.layer0`…`montr.layer5`,
 * packages/contracts/src/queue.ts's QUEUE_NAMES) are unchanged — correct for
 * the documented single-tenant on-prem deployment model (one worker process
 * per client, apps/worker/src/main.ts). When enabled, each layer gets one
 * queue PER CLIENT (`montr.layer0.<clientId>`, via `resolveQueueName`) and the
 * worker/API producer fan out one BullMQ Queue + Worker per (layer, client)
 * pair, each independently polling Redis — so a large backlog on one
 * client's queue cannot block a newly-queued job on another client's queue
 * for the same layer.
 *
 * `tenantIds` lists which clients to fan out queues/workers for; empty
 * (default) resolves to just this deployment's own `clientId`, so turning
 * isolation on with no other config is a same-tenant no-op rename — useful
 * to validate the mechanism before a deployment actually serves more than
 * one tenant.
 *
 * Not recommended past a modest tenant count per worker process: this repo
 * ships plain (non-Pro) BullMQ, which has no group-based fair-scheduling
 * primitive, so enabling this multiplies physical queues, BullMQ Workers, and
 * Redis connections linearly with `tenantIds.length × 6`. A hosted
 * multi-tenant deployment with many clients should shard tenants across
 * several worker processes/pools rather than growing this list unbounded.
 */
export const QueueConfigSchema = z.object({
  perTenantIsolation: z.boolean().default(false),
  tenantIds: z.array(z.string().min(1)).default([]),
});
export type QueueConfig = z.infer<typeof QueueConfigSchema>;

export const SecurityConfigSchema = z.object({
  /** Reference to the AES-256-GCM field-encryption key (KMS/Vault/k8s secret). */
  fieldEncryptionKeyRef: z.string().optional(),
  /** Which backend resolves the field-encryption key. Default: env/file bytes. */
  keySource: KeySourceKindSchema.default("env"),
  /** Vault connection config, used only when `keySource` is "vault". */
  vault: VaultKeySourceConfigSchema.default({}),
  /** ⛔ Default-deny egress; only the client's LLM endpoint is allowed. */
  egressPolicy: z.literal("default-deny").default("default-deny"),
  allowedEgressHosts: z.array(z.string()).default([]),
});
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;

/** Row-scoped tenant identifier for per-client isolation. */
export const MontrConfigSchema = z.object({
  clientId: z.string().min(1).default("default"),
  llm: LlmConfigSchema.default({}),
  budget: BudgetConfigSchema.default({}),
  autoFix: AutoFixConfigSchema.default({}),
  dast: DastConfigSchema.default({}),
  retention: RetentionConfigSchema.default({}),
  rbac: RbacConfigSchema.default({}),
  telemetry: TelemetryConfigSchema.default({}),
  security: SecurityConfigSchema.default({}),
  discovery: DiscoveryConfigSchema.default({}),
  queue: QueueConfigSchema.default({}),
  fixGeneration: FixGenerationConfigSchema.default({}),
  semanticIndex: SemanticIndexConfigSchema.default({}),
});
export type MontrConfig = z.infer<typeof MontrConfigSchema>;

/** The fully-defaulted, hardened baseline config (nothing configured). */
export function getHardenedDefaults(): MontrConfig {
  return MontrConfigSchema.parse({});
}
