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
});
export type MontrConfig = z.infer<typeof MontrConfigSchema>;

/** The fully-defaulted, hardened baseline config (nothing configured). */
export function getHardenedDefaults(): MontrConfig {
  return MontrConfigSchema.parse({});
}
