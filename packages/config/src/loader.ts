import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { ConfigValidationError } from "@montr/contracts";
import { MontrConfigSchema, type MontrConfig } from "./schema.js";

/**
 * Config loader (§3.5). Sources, in increasing precedence:
 *   defaults (schema)  <  file (JSON)  <  env vars  <  k8s secret files  <  explicit overrides
 * Validation errors are FATAL and EXPLICIT (ConfigValidationError carries the
 * Zod issues). Secrets are only ever read from env/secret files — never a
 * committed config file.
 */

export interface LoadConfigOptions {
  /** Path to a JSON config file. Falls back to $MONTR_CONFIG_FILE. */
  filePath?: string;
  /** Directory of mounted k8s secret files (one value per file). Falls back to $MONTR_SECRETS_DIR. */
  secretsDir?: string;
  /** Environment source (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** Highest-precedence explicit overrides (used in tests). */
  overrides?: Record<string, unknown>;
}

type Obj = Record<string, unknown>;

function isPlainObject(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function deepMerge(base: Obj, overlay: Obj): Obj {
  const out: Obj = { ...base };
  for (const [k, v] of Object.entries(overlay)) {
    if (v === undefined) continue;
    const existing = out[k];
    if (isPlainObject(existing) && isPlainObject(v)) {
      out[k] = deepMerge(existing, v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function setPath(target: Obj, path: readonly string[], value: unknown): void {
  let cur: Obj = target;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i] as string;
    const next = cur[key];
    if (!isPlainObject(next)) cur[key] = {};
    cur = cur[key] as Obj;
  }
  cur[path[path.length - 1] as string] = value;
}

function parseBool(v: string): boolean {
  return ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

function parseNum(v: string): number | undefined {
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function parseList(v: string): string[] {
  return v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Map known env vars into a nested config overlay. */
function envOverlay(env: NodeJS.ProcessEnv): Obj {
  const o: Obj = {};
  const set = (name: string, path: string[], transform: (v: string) => unknown = (x) => x) => {
    const raw = env[name];
    if (raw !== undefined && raw !== "") setPath(o, path, transform(raw));
  };

  set("MONTR_CLIENT_ID", ["clientId"]);
  set("MONTR_LLM_PROVIDER", ["llm", "provider"]);
  set("MONTR_LLM_ENDPOINT", ["llm", "endpoint"]);
  set("MONTR_LLM_API_KEY", ["llm", "apiKey"]);
  set("MONTR_LLM_API_KEY_REF", ["llm", "apiKeyRef"]);
  set("MONTR_LLM_KEY_TIER_GUARD", ["llm", "keyTierGuard"]);
  set("MONTR_MODEL_TRIAGE", ["llm", "modelMatrix", "triage"]);
  set("MONTR_MODEL_DEFAULT", ["llm", "modelMatrix", "default"]);
  set("MONTR_MODEL_CONFIRMATION", ["llm", "modelMatrix", "confirmation"]);
  // Model-fallback cascade (A11): retried once, after the primary model's
  // retry budget is exhausted. See packages/llm-gateway/src/retry.ts.
  set("MONTR_LLM_FALLBACK_MODEL", ["llm", "fallbackModel"]);
  set("MONTR_BUDGET_MAX_USD", ["budget", "maxUsdPerScan"], parseNum);
  set("MONTR_BUDGET_MAX_TOKENS", ["budget", "maxTokensPerScan"], parseNum);
  set("MONTR_BUDGET_ENFORCEMENT", ["budget", "enforcement"]);
  set("MONTR_AUTOFIX_ENABLED", ["autoFix", "enabled"], parseBool);
  set("MONTR_DAST_ENABLED", ["dast", "enabled"], parseBool);
  set("MONTR_DAST_ALLOWLIST", ["dast", "allowlist"], parseList);
  set("MONTR_TELEMETRY_ENABLED", ["telemetry", "enabled"], parseBool);
  set("MONTR_FIELD_ENCRYPTION_KEY_REF", ["security", "fieldEncryptionKeyRef"]);
  set("MONTR_ALLOWED_EGRESS_HOSTS", ["security", "allowedEgressHosts"], parseList);
  set("MONTR_KEY_SOURCE", ["security", "keySource"]);
  // Air-gap SAST (A4): local Semgrep ruleset dir, in place of hosted `p/...`
  // registry packs. See packages/discovery/src/detectors/sast.ts.
  set("MONTR_DISCOVERY_RULESETS_DIR", ["discovery", "rulesetsDir"]);
  // Per-tenant BullMQ queue isolation (A27). OFF by default — see
  // QueueConfigSchema's doc comment (packages/config/src/schema.ts) and
  // packages/orchestrator/src/bullmq-scheduler.ts.
  set("MONTR_QUEUE_PER_TENANT_ISOLATION", ["queue", "perTenantIsolation"], parseBool);
  set("MONTR_QUEUE_TENANT_IDS", ["queue", "tenantIds"], parseList);
  // A5 — bounded agentic fix loop. OFF by default — see FixAgentLoopConfigSchema's
  // doc comment (packages/config/src/schema.ts) and packages/fix/src/generate.ts's
  // `FixGenerationContext.agentLoop`.
  set("MONTR_FIX_AGENT_LOOP_ENABLED", ["fixGeneration", "agentLoop", "enabled"], parseBool);
  set(
    "MONTR_FIX_AGENT_LOOP_MAX_ITERATIONS",
    ["fixGeneration", "agentLoop", "maxIterations"],
    parseNum,
  );
  set(
    "MONTR_FIX_AGENT_LOOP_MAX_TOOL_CALLS",
    ["fixGeneration", "agentLoop", "maxToolCalls"],
    parseNum,
  );
  // A9 — semantic codebase index, built alongside the App Map in Layer 0. OFF
  // by default — see SemanticIndexConfigSchema's doc comment (schema.ts) and
  // apps/worker/src/runners.ts's Layer 0 wiring.
  set("MONTR_SEMANTIC_INDEX_ENABLED", ["semanticIndex", "enabled"], parseBool);
  set("MONTR_SEMANTIC_INDEX_EMBEDDING_MODEL", ["semanticIndex", "embeddingModel"]);
  // A3 (2026-09-12) — E1/E2/E4 agentic investigation loop + adversarial
  // verifier panel, surfaced as config for the first time. ON by default —
  // see ConfirmationInvestigationConfigSchema's doc comment (schema.ts) for
  // why this deliberately deviates from every other agentic-loop toggle's
  // off-by-default precedent, and apps/worker/src/runners.ts's Layer 3
  // wiring.
  set(
    "MONTR_CONFIRMATION_INVESTIGATION_ENABLED",
    ["confirmation", "investigation", "enabled"],
    parseBool,
  );
  set(
    "MONTR_CONFIRMATION_INVESTIGATION_MAX_TURNS",
    ["confirmation", "investigation", "maxTurns"],
    parseNum,
  );
  set(
    "MONTR_CONFIRMATION_INVESTIGATION_VERIFIER_COUNT",
    ["confirmation", "investigation", "verifierCount"],
    parseNum,
  );
  set(
    "MONTR_CONFIRMATION_INVESTIGATION_SEVERITIES",
    ["confirmation", "investigation", "severities"],
    parseList,
  );
  // HashiCorp Vault connection (only consulted when MONTR_KEY_SOURCE=vault).
  set("VAULT_ADDR", ["security", "vault", "addr"]);
  set("VAULT_TOKEN", ["security", "vault", "token"]);
  set("VAULT_NAMESPACE", ["security", "vault", "namespace"]);
  set("VAULT_ROLE_ID", ["security", "vault", "roleId"]);
  set("VAULT_SECRET_ID", ["security", "vault", "secretId"]);
  set("VAULT_KV_MOUNT", ["security", "vault", "kvMount"]);
  set("VAULT_SECRET_PATH", ["security", "vault", "secretPath"]);
  set("VAULT_KV_FIELD", ["security", "vault", "field"]);
  set("VAULT_REQUEST_TIMEOUT_MS", ["security", "vault", "requestTimeoutMs"], parseNum);
  return o;
}

/** k8s secret files: file name -> config path. */
const SECRET_FILE_MAP: Record<string, string[]> = {
  "llm-api-key": ["llm", "apiKey"],
  "field-encryption-key": ["security", "fieldEncryptionKeyRef"],
};

function secretsOverlay(dir: string): Obj {
  const o: Obj = {};
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return o;
  for (const file of readdirSync(dir)) {
    const path = SECRET_FILE_MAP[file];
    if (!path) continue;
    const full = join(dir, file);
    if (!statSync(full).isFile()) continue;
    setPath(o, path, readFileSync(full, "utf8").trim());
  }
  return o;
}

function readFileOverlay(filePath: string): Obj {
  let text: string;
  try {
    text = readFileSync(filePath, "utf8");
  } catch (cause) {
    throw new ConfigValidationError(`Cannot read config file: ${filePath}`, {
      cause: String(cause),
    });
  }
  try {
    const parsed: unknown = JSON.parse(text);
    if (!isPlainObject(parsed)) {
      throw new ConfigValidationError(`Config file must be a JSON object: ${filePath}`);
    }
    return parsed;
  } catch (cause) {
    if (cause instanceof ConfigValidationError) throw cause;
    throw new ConfigValidationError(`Config file is not valid JSON: ${filePath}`, {
      cause: String(cause),
    });
  }
}

/** Validate an already-assembled raw config object. Throws on failure. */
export function parseConfig(raw: unknown): MontrConfig {
  const result = MontrConfigSchema.safeParse(raw ?? {});
  if (!result.success) {
    throw new ConfigValidationError("Invalid Montr configuration", {
      details: { issues: result.error.issues },
    });
  }
  return result.data;
}

/** Load, merge, and validate the full configuration from all sources. */
export function loadConfig(opts: LoadConfigOptions = {}): MontrConfig {
  const env = opts.env ?? process.env;
  let merged: Obj = {};

  const filePath = opts.filePath ?? env.MONTR_CONFIG_FILE;
  if (filePath && existsSync(filePath)) {
    merged = deepMerge(merged, readFileOverlay(filePath));
  }

  merged = deepMerge(merged, envOverlay(env));

  const secretsDir = opts.secretsDir ?? env.MONTR_SECRETS_DIR;
  if (secretsDir) {
    merged = deepMerge(merged, secretsOverlay(secretsDir));
  }

  if (opts.overrides) merged = deepMerge(merged, opts.overrides);

  return parseConfig(merged);
}
