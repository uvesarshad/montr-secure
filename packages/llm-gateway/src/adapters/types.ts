import type {
  LLMRequest,
  LLMStreamEvent,
  Provider,
  StopReason,
  TokenUsage,
} from "@montr/contracts";

/**
 * The internal adapter contract. Each provider adapter maps the unified
 * LLMRequest to its SDK and back to these normalized shapes. The gateway core
 * adds latency, retries, timeouts, metadata logging, and cost accounting — so
 * adapters stay thin and focused on wire mapping.
 */

/** Normalized completion (latency is added by the gateway core). */
export interface AdapterCompletion {
  id: string;
  model: string;
  content: string;
  stopReason: StopReason;
  usage: TokenUsage;
}

export interface ProviderAdapter {
  readonly provider: Provider;
  /** Resolve the provider-native model id from the gateway's logical model id. */
  resolveModelId(modelId: string): string;
  complete(request: LLMRequest, modelId: string, signal?: AbortSignal): Promise<AdapterCompletion>;
  stream(request: LLMRequest, modelId: string, signal?: AbortSignal): AsyncIterable<LLMStreamEvent>;
}

/** Build a normalized TokenUsage, filling `totalTokens` when the provider omits it. */
export function makeUsage(
  inputTokens: number,
  outputTokens: number,
  extra: { totalTokens?: number; cacheReadTokens?: number; cacheWriteTokens?: number } = {},
): TokenUsage {
  const usage: TokenUsage = {
    inputTokens: Math.max(0, Math.round(inputTokens)),
    outputTokens: Math.max(0, Math.round(outputTokens)),
    totalTokens: Math.max(0, Math.round(extra.totalTokens ?? inputTokens + outputTokens)),
  };
  if (extra.cacheReadTokens) usage.cacheReadTokens = Math.max(0, Math.round(extra.cacheReadTokens));
  if (extra.cacheWriteTokens)
    usage.cacheWriteTokens = Math.max(0, Math.round(extra.cacheWriteTokens));
  return usage;
}
