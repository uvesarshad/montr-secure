import type {
  LLMRequest,
  LLMStreamEvent,
  LLMToolCall,
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
  /** Tool/function calls the model made (A8) — present when `stopReason === "tool_use"`. */
  toolCalls?: LLMToolCall[];
}

/** One item submitted to {@link ProviderAdapter.submitBatch} (A31, Batch API). */
export interface AdapterBatchSubmitItem {
  customId: string;
  request: LLMRequest;
  modelId: string;
}

/** Handle returned by {@link ProviderAdapter.submitBatch}. */
export interface AdapterBatchHandle {
  batchId: string;
  processingStatus: string;
}

/** Per-status request counts returned by {@link ProviderAdapter.pollBatch}. */
export interface AdapterBatchCounts {
  processing: number;
  succeeded: number;
  errored: number;
  canceled: number;
  expired: number;
}

export interface AdapterBatchStatus extends AdapterBatchHandle {
  counts: AdapterBatchCounts;
}

/** One row of {@link ProviderAdapter.getBatchResults}'s streamed results. */
export type AdapterBatchResultItem =
  | { customId: string; status: "succeeded"; completion: AdapterCompletion }
  | { customId: string; status: "errored"; errorType: string; message: string }
  | { customId: string; status: "canceled" }
  | { customId: string; status: "expired" };

export interface ProviderAdapter {
  readonly provider: Provider;
  /** Resolve the provider-native model id from the gateway's logical model id. */
  resolveModelId(modelId: string): string;
  complete(request: LLMRequest, modelId: string, signal?: AbortSignal): Promise<AdapterCompletion>;
  stream(request: LLMRequest, modelId: string, signal?: AbortSignal): AsyncIterable<LLMStreamEvent>;
  /**
   * Real provider-side token count for `request` (A19), used by
   * `MontrLlmGateway.countTokens()` — NOT by the pre-call budget guard, which
   * stays on the fast local heuristic (`estimateTokens`) for latency reasons
   * (see gateway.ts). Optional: adapters without a real counting endpoint
   * (Bedrock/Vertex/Azure today) omit this and the gateway falls back to the
   * heuristic.
   */
  countTokens?(request: LLMRequest, modelId: string, signal?: AbortSignal): Promise<number>;
  /**
   * Submit a Batch API job (A31) — async, queued, 50% discounted. Optional:
   * only the Anthropic adapter implements this today (see anthropic.ts);
   * other adapters omit it and the gateway throws `NotImplementedError`.
   */
  submitBatch?(items: AdapterBatchSubmitItem[], signal?: AbortSignal): Promise<AdapterBatchHandle>;
  /** Poll a submitted batch's processing status + per-outcome counts. */
  pollBatch?(batchId: string, signal?: AbortSignal): Promise<AdapterBatchStatus>;
  /** Stream a completed (or partially completed) batch's per-request results. */
  getBatchResults?(batchId: string, signal?: AbortSignal): AsyncIterable<AdapterBatchResultItem>;
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
