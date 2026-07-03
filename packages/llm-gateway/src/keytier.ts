import { KeyTierRejectedError, type KeyTier, type Provider } from "@montr/contracts";
import type { KeyTierGuardMode } from "@montr/config";
import type { Logger } from "@montr/telemetry";

/**
 * ⛔ Key-tier guard (§11). Warn or block on suspected data-retaining
 * (non-enterprise) LLM key tiers, so client code is never sent to a key whose
 * provider may retain it for training. We cannot positively confirm an
 * Anthropic-direct key's tier from the key alone, so the fail-safe default is
 * "unknown" → warn (golden rule #4: uncertainty resolves toward less autonomy).
 */

export interface DetectKeyTierInput {
  provider: Provider;
  /** Explicit operator-declared tier (highest confidence signal), if available. */
  declaredTier?: KeyTier;
  apiKey?: string;
}

/**
 * Providers whose DEFAULT/consumer tier is known to retain prompts (often for
 * training) unless an enterprise/zero-retention contract is in place. Because a
 * scan sends client source as prompt context, these are classified
 * `data_retaining` and BLOCKED unless the operator declares an enterprise tier —
 * a security product must not silently ship client code to a training-retaining
 * key (golden rule #1 / #4).
 */
const DATA_RETAINING_DEFAULT: ReadonlySet<Provider> = new Set(["moonshot", "zhipu", "deepseek"]);

/**
 * Classify the likely retention tier of the configured key.
 * - An operator-declared tier always wins (they can attest a zero-retention deal).
 * - Cloud providers (Bedrock/Vertex/Azure) run in the client's own enterprise
 *   tenancy under a BAA/DPA with no model-training retention → `enterprise`.
 * - Consumer/CN providers (Moonshot/Zhipu/DeepSeek) default to `data_retaining`.
 * - Any other direct key cannot be confirmed from the key string → `unknown`.
 */
export function detectKeyTier(input: DetectKeyTierInput): KeyTier {
  if (input.declaredTier) return input.declaredTier;
  if (input.provider === "bedrock" || input.provider === "vertex" || input.provider === "azure") {
    return "enterprise";
  }
  if (DATA_RETAINING_DEFAULT.has(input.provider)) return "data_retaining";
  return "unknown";
}

export interface KeyTierGuardResult {
  tier: KeyTier;
  /** True when the tier is suspected data-retaining (not enterprise-confirmed). */
  suspect: boolean;
  action: "allowed" | "warned" | "blocked";
}

/**
 * Apply the configured guard policy. `block` mode throws `KeyTierRejectedError`
 * for suspect tiers; `warn` mode logs metadata-only; `off` disables the guard.
 */
export function applyKeyTierGuard(
  tier: KeyTier,
  mode: KeyTierGuardMode,
  provider: Provider,
  logger?: Logger,
): KeyTierGuardResult {
  const suspect = tier !== "enterprise";
  if (mode === "off" || !suspect) {
    return { tier, suspect, action: "allowed" };
  }
  const details = { provider, keyTier: tier };
  // `data_retaining` is blocked even under `warn`: these providers retain prompts
  // (= client source) by default, so allowing them requires an explicit operator
  // action (declare an enterprise tier, or disable the guard entirely with `off`).
  if (mode === "block" || tier === "data_retaining") {
    throw new KeyTierRejectedError(
      `Suspected data-retaining key tier "${tier}" blocked by policy (${provider}). ` +
        `Declare an enterprise/zero-retention tier (llm.keyTier) to override.`,
      details,
    );
  }
  logger?.warn("llm.key_tier_suspect", {
    ...details,
    guidance:
      "Confirm an enterprise / zero-retention key tier, or set llm.keyTierGuard=block to hard-fail.",
  });
  return { tier, suspect, action: "warned" };
}
