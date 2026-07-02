import { MODEL_COST_RATES, type ModelCostRate, type TokenUsage } from "@montr/contracts";

/**
 * Deterministic pricing from the reference rate card (§8.4). Pure functions —
 * no network, no clock, no randomness.
 */

/** Round to micro-dollars to keep floating-point noise out of comparisons. */
export function roundUsd(usd: number): number {
  return Math.round(usd * 1_000_000) / 1_000_000;
}

/** A zero-valued token usage. */
export function zeroUsage(): TokenUsage {
  return { inputTokens: 0, outputTokens: 0, totalTokens: 0 };
}

/** Sum two token-usage records (cache fields preserved when present). */
export function addUsage(a: TokenUsage, b: TokenUsage): TokenUsage {
  const cacheRead = (a.cacheReadTokens ?? 0) + (b.cacheReadTokens ?? 0);
  const cacheWrite = (a.cacheWriteTokens ?? 0) + (b.cacheWriteTokens ?? 0);
  const out: TokenUsage = {
    inputTokens: a.inputTokens + b.inputTokens,
    outputTokens: a.outputTokens + b.outputTokens,
    totalTokens: a.totalTokens + b.totalTokens,
  };
  if (cacheRead > 0) out.cacheReadTokens = cacheRead;
  if (cacheWrite > 0) out.cacheWriteTokens = cacheWrite;
  return out;
}

/**
 * Normalize a provider-specific model id to the first-party form used by the
 * reference rate card: strips a `publishers/…/models/` path, the Bedrock
 * `anthropic.` prefix, a Vertex `@date` snapshot suffix, and a `-fast` suffix.
 */
export function normalizeModelId(modelId: string): string {
  let id = modelId.trim();
  const slash = id.lastIndexOf("/");
  if (slash >= 0) id = id.slice(slash + 1);
  if (id.startsWith("anthropic.")) id = id.slice("anthropic.".length);
  const at = id.indexOf("@");
  if (at >= 0) id = id.slice(0, at);
  if (id.endsWith("-fast")) id = id.slice(0, -"-fast".length);
  // Strip a trailing dated-snapshot suffix ("-YYYYMMDD", e.g.
  // "claude-haiku-4-5-20251001" → "claude-haiku-4-5") so the canonical
  // model-floor id (DECIDE-3) resolves to its dated rate-card entry and cache
  // reads are priced instead of silently billing $0.
  id = id.replace(/-20\d{6}$/, "");
  return id;
}

/** Look up the reference rate for a (possibly provider-prefixed) model id. */
export function findModelRate(modelId: string): ModelCostRate | undefined {
  const norm = normalizeModelId(modelId);
  return (
    MODEL_COST_RATES.find((r) => r.modelId === modelId) ??
    MODEL_COST_RATES.find((r) => r.modelId === norm) ??
    MODEL_COST_RATES.find((r) => normalizeModelId(r.modelId) === norm)
  );
}

/**
 * Deterministic USD price for a token usage against a model's reference rate.
 * Cache reads bill at ~0.1× and cache writes at ~1.25× the input rate (matching
 * the platform's prompt-cache economics). Returns 0 for an unknown model id.
 */
export function priceUsageUsd(usage: TokenUsage, modelId: string): number {
  const rate = findModelRate(modelId);
  if (!rate) return 0;
  const cacheRead = usage.cacheReadTokens ?? 0;
  const cacheWrite = usage.cacheWriteTokens ?? 0;
  const usd =
    (usage.inputTokens / 1_000_000) * rate.inputPerMillionUsd +
    (cacheRead / 1_000_000) * rate.inputPerMillionUsd * 0.1 +
    (cacheWrite / 1_000_000) * rate.inputPerMillionUsd * 1.25 +
    (usage.outputTokens / 1_000_000) * rate.outputPerMillionUsd;
  return roundUsd(usd);
}
