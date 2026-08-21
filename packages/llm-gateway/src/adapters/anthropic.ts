import {
  NotImplementedError,
  ProviderNotConfiguredError,
  type LLMRequest,
  type LLMStreamEvent,
  type LLMToolCall,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import {
  buildAnthropicCountTokensBody,
  buildAnthropicStyleFields,
  mapAnthropicStopReason,
} from "../mapping.js";
import {
  makeUsage,
  type AdapterBatchHandle,
  type AdapterBatchResultItem,
  type AdapterBatchStatus,
  type AdapterBatchSubmitItem,
  type AdapterCompletion,
  type ProviderAdapter,
} from "./types.js";
import { resolveOutboundTarget, type AdapterEgress } from "./egress.js";

/** Anthropic's default API host, contacted when no `llm.endpoint` is configured. */
export const ANTHROPIC_DEFAULT_ENDPOINT = "https://api.anthropic.com";

/**
 * Anthropic adapter (`@anthropic-ai/sdk`). Recommended matrix: Opus 4.8
 * (confirmation), Sonnet 5 (default), Haiku 4.5 (triage). Sampling params are
 * dropped for models that reject them (Opus 4.7/4.8, Sonnet 5, Fable 5).
 *
 * The real SDK is loaded via a lazy dynamic import inside the default client
 * factory only — injected-client tests never touch the SDK or the network. The
 * Anthropic message/stream shape is shared with Bedrock, so the mapping helpers
 * below are exported for reuse.
 */

export interface AnthropicContentBlockLike {
  type: string;
  text?: string;
  /** `type: "tool_use"` fields (A8). */
  id?: string;
  name?: string;
  input?: unknown;
}

export interface AnthropicMessageLike {
  id?: string;
  model?: string;
  content?: AnthropicContentBlockLike[];
  stop_reason?: string | null;
  usage?: {
    input_tokens?: number | null;
    output_tokens?: number | null;
    cache_creation_input_tokens?: number | null;
    cache_read_input_tokens?: number | null;
  };
}

export type AnthropicStreamEventLike =
  | {
      type: "message_start";
      message?: {
        id?: string;
        usage?: {
          input_tokens?: number | null;
          cache_read_input_tokens?: number | null;
          cache_creation_input_tokens?: number | null;
        };
      };
    }
  | { type: "content_block_start" }
  | { type: "content_block_delta"; delta?: { type?: string; text?: string } }
  | { type: "content_block_stop" }
  | {
      type: "message_delta";
      delta?: { stop_reason?: string | null };
      usage?: { output_tokens?: number | null };
    }
  | { type: "message_stop" }
  | { type: "ping" };

/** Result of `messages.countTokens` (A19) — only `input_tokens` is used. */
export interface AnthropicCountTokensResultLike {
  input_tokens: number;
}

/** One request row of a `messages.batches.create` submission (A31). */
export interface AnthropicBatchRequestLike {
  custom_id: string;
  params: Record<string, unknown>;
}

/** Shape of `messages.batches.create`/`.retrieve` (A31). */
export interface AnthropicBatchLike {
  id: string;
  processing_status: string;
  request_counts: {
    processing: number;
    succeeded: number;
    errored: number;
    canceled: number;
    expired: number;
  };
}

/** One row of `messages.batches.results` (A31). */
export interface AnthropicBatchResultLike {
  custom_id: string;
  result:
    | { type: "succeeded"; message: AnthropicMessageLike }
    | { type: "errored"; error: { type: string; message?: string } }
    | { type: "canceled" }
    | { type: "expired" };
}

/** `messages.batches` sub-client (A31, Batch API). Optional — only Anthropic wires this today. */
export interface AnthropicBatchesLike {
  create(body: { requests: AnthropicBatchRequestLike[] }): Promise<AnthropicBatchLike>;
  retrieve(batchId: string): Promise<AnthropicBatchLike>;
  results(batchId: string): Promise<AsyncIterable<AnthropicBatchResultLike>>;
}

export interface AnthropicMessagesLike {
  create(
    body: Record<string, unknown>,
    options?: { signal?: AbortSignal },
  ): Promise<AnthropicMessageLike | AsyncIterable<AnthropicStreamEventLike>>;
  /** Real token-counting endpoint (A19). Optional — injected test clients may omit it. */
  countTokens?(
    body: Record<string, unknown>,
    options?: { signal?: AbortSignal },
  ): Promise<AnthropicCountTokensResultLike>;
  /** Batch API (A31). Optional — injected test clients may omit it. */
  batches?: AnthropicBatchesLike;
}

export interface AnthropicClientLike {
  messages: AnthropicMessagesLike;
}

/** Concatenate the text blocks of an Anthropic-shaped message into one string. */
export function anthropicText(msg: AnthropicMessageLike): string {
  return (msg.content ?? [])
    .filter((b) => b.type === "text")
    .map((b) => b.text ?? "")
    .join("");
}

/** Extract `tool_use` content blocks from an Anthropic-shaped message (A8). */
export function anthropicToolCalls(msg: AnthropicMessageLike): LLMToolCall[] | undefined {
  const blocks = (msg.content ?? []).filter(
    (b): b is AnthropicContentBlockLike & { id: string; name: string } =>
      b.type === "tool_use" && typeof b.id === "string" && typeof b.name === "string",
  );
  if (blocks.length === 0) return undefined;
  return blocks.map((b) => ({
    id: b.id,
    name: b.name,
    input: (b.input && typeof b.input === "object" ? b.input : {}) as Record<string, unknown>,
  }));
}

/** Map an Anthropic-shaped message (native or Bedrock) to a normalized completion. */
export function mapAnthropicMessage(
  msg: AnthropicMessageLike,
  fallbackModel: string,
): AdapterCompletion {
  const usage = makeUsage(msg.usage?.input_tokens ?? 0, msg.usage?.output_tokens ?? 0, {
    cacheReadTokens: msg.usage?.cache_read_input_tokens ?? 0,
    cacheWriteTokens: msg.usage?.cache_creation_input_tokens ?? 0,
  });
  const toolCalls = anthropicToolCalls(msg);
  return {
    id: msg.id ?? `${fallbackModel}:response`,
    model: msg.model ?? fallbackModel,
    content: anthropicText(msg),
    stopReason: mapAnthropicStopReason(msg.stop_reason),
    usage,
    ...(toolCalls ? { toolCalls } : {}),
  };
}

/** Re-yield an Anthropic-shaped SSE stream as contract stream events + final usage. */
export async function* mapAnthropicStream(
  events: AsyncIterable<AnthropicStreamEventLike>,
): AsyncGenerator<LLMStreamEvent, void, unknown> {
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheRead = 0;
  let cacheWrite = 0;
  let stopReason: string | null = null;

  for await (const ev of events) {
    if (ev.type === "message_start") {
      const u = ev.message?.usage;
      inputTokens = u?.input_tokens ?? inputTokens;
      cacheRead = u?.cache_read_input_tokens ?? cacheRead;
      cacheWrite = u?.cache_creation_input_tokens ?? cacheWrite;
    } else if (ev.type === "content_block_delta") {
      if (ev.delta?.type === "text_delta" && typeof ev.delta.text === "string") {
        yield { type: "text_delta", text: ev.delta.text };
      }
    } else if (ev.type === "message_delta") {
      stopReason = ev.delta?.stop_reason ?? stopReason;
      outputTokens = ev.usage?.output_tokens ?? outputTokens;
    }
  }

  yield {
    type: "message_done",
    usage: makeUsage(inputTokens, outputTokens, {
      cacheReadTokens: cacheRead,
      cacheWriteTokens: cacheWrite,
    }),
    stopReason: mapAnthropicStopReason(stopReason),
  };
}

function buildBody(request: LLMRequest, modelId: string): Record<string, unknown> {
  return { model: modelId, ...buildAnthropicStyleFields(request, modelId) };
}

export interface AnthropicAdapterOptions {
  config: MontrConfig;
  /** Injectable client (tests). Defaults to a real `@anthropic-ai/sdk` client. */
  client?: AnthropicClientLike;
  /** ⛔ Egress guard asserted before every outbound request (golden rule #1). */
  egress?: AdapterEgress;
}

export class AnthropicAdapter implements ProviderAdapter {
  readonly provider = "anthropic" as const;
  private client?: AnthropicClientLike;

  constructor(private readonly options: AnthropicAdapterOptions) {
    this.client = options.client;
  }

  private async getClient(): Promise<AnthropicClientLike> {
    if (!this.client) this.client = await createDefaultAnthropicClient(this.options.config);
    return this.client;
  }

  /** ⛔ Assert the outbound LLM host is the configured endpoint before dispatch. */
  private assertEgress(): void {
    this.options.egress?.assert(
      resolveOutboundTarget(this.options.config.llm.endpoint, ANTHROPIC_DEFAULT_ENDPOINT),
    );
  }

  resolveModelId(modelId: string): string {
    return modelId;
  }

  async complete(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): Promise<AdapterCompletion> {
    this.assertEgress();
    const client = await this.getClient();
    const result = (await client.messages.create(
      { ...buildBody(request, modelId), stream: false },
      signal ? { signal } : undefined,
    )) as AnthropicMessageLike;
    return mapAnthropicMessage(result, modelId);
  }

  async *stream(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): AsyncGenerator<LLMStreamEvent> {
    this.assertEgress();
    const client = await this.getClient();
    const events = (await client.messages.create(
      { ...buildBody(request, modelId), stream: true },
      signal ? { signal } : undefined,
    )) as AsyncIterable<AnthropicStreamEventLike>;
    yield* mapAnthropicStream(events);
  }

  /**
   * Real token count via Anthropic's `messages.countTokens` (A19) — see
   * {@link buildAnthropicCountTokensBody}. Not used by the pre-call budget
   * guard (`gateway.ts`'s `estimateTokens` stays a fast local heuristic for
   * that hot path) — this is for callers that want a precise, provider-
   * verified count and can afford the extra round-trip.
   */
  async countTokens(request: LLMRequest, modelId: string, signal?: AbortSignal): Promise<number> {
    this.assertEgress();
    const client = await this.getClient();
    if (!client.messages.countTokens) {
      throw new NotImplementedError(
        "Anthropic client has no countTokens — real token counting unavailable",
        { provider: "anthropic" },
      );
    }
    const result = await client.messages.countTokens(
      buildAnthropicCountTokensBody(request, modelId),
      signal ? { signal } : undefined,
    );
    return result.input_tokens;
  }

  /** Submit a Batch API job (A31). Requires `messages.batches` on the injected/real client. */
  async submitBatch(items: AdapterBatchSubmitItem[]): Promise<AdapterBatchHandle> {
    this.assertEgress();
    const client = await this.getClient();
    if (!client.messages.batches) {
      throw new NotImplementedError("Anthropic client has no batches API", {
        provider: "anthropic",
      });
    }
    const requests = items.map((item): AnthropicBatchRequestLike => ({
      custom_id: item.customId,
      params: buildBody(item.request, item.modelId),
    }));
    const batch = await client.messages.batches.create({ requests });
    return { batchId: batch.id, processingStatus: batch.processing_status };
  }

  /** Poll a submitted batch's status + per-outcome counts (A31). */
  async pollBatch(batchId: string): Promise<AdapterBatchStatus> {
    this.assertEgress();
    const client = await this.getClient();
    if (!client.messages.batches) {
      throw new NotImplementedError("Anthropic client has no batches API", {
        provider: "anthropic",
      });
    }
    const batch = await client.messages.batches.retrieve(batchId);
    return {
      batchId: batch.id,
      processingStatus: batch.processing_status,
      counts: { ...batch.request_counts },
    };
  }

  /** Stream a completed (or partially completed) batch's per-request results (A31). */
  async *getBatchResults(batchId: string): AsyncGenerator<AdapterBatchResultItem> {
    this.assertEgress();
    const client = await this.getClient();
    if (!client.messages.batches) {
      throw new NotImplementedError("Anthropic client has no batches API", {
        provider: "anthropic",
      });
    }
    const results = await client.messages.batches.results(batchId);
    for await (const row of results) {
      if (row.result.type === "succeeded") {
        yield {
          customId: row.custom_id,
          status: "succeeded",
          completion: mapAnthropicMessage(row.result.message, batchId),
        };
      } else if (row.result.type === "errored") {
        yield {
          customId: row.custom_id,
          status: "errored",
          errorType: row.result.error.type,
          message: row.result.error.message ?? "batch request errored",
        };
      } else if (row.result.type === "canceled") {
        yield { customId: row.custom_id, status: "canceled" };
      } else {
        yield { customId: row.custom_id, status: "expired" };
      }
    }
  }
}

/** Build a real Anthropic SDK client. Requires a configured BYO key. */
async function createDefaultAnthropicClient(config: MontrConfig): Promise<AnthropicClientLike> {
  const apiKey = config.llm.apiKey;
  if (!apiKey) {
    throw new ProviderNotConfiguredError("Anthropic API key not configured (llm.apiKey)", {
      provider: "anthropic",
    });
  }
  const mod = (await import("@anthropic-ai/sdk")) as unknown as {
    default: new (opts: Record<string, unknown>) => {
      messages: {
        create: (body: unknown, options?: unknown) => unknown;
        countTokens: (body: unknown, options?: unknown) => unknown;
        batches: {
          create: (body: unknown) => unknown;
          retrieve: (batchId: string) => unknown;
          results: (batchId: string) => unknown;
        };
      };
    };
  };
  const client = new mod.default({
    apiKey,
    ...(config.llm.endpoint ? { baseURL: config.llm.endpoint } : {}),
    maxRetries: 0,
  });
  return {
    messages: {
      create: (body, options) =>
        client.messages.create(body, options) as Promise<
          AnthropicMessageLike | AsyncIterable<AnthropicStreamEventLike>
        >,
      // A19: real token counting. Older `@anthropic-ai/sdk` releases may not
      // expose `messages.countTokens` — guarded so a stale SDK version
      // degrades to the gateway's heuristic fallback instead of throwing at
      // client-construction time.
      ...(typeof client.messages.countTokens === "function"
        ? {
            countTokens: (body, options) =>
              client.messages.countTokens(body, options) as Promise<AnthropicCountTokensResultLike>,
          }
        : {}),
      // A31: Batch API. Same guard as above for SDK-version safety.
      ...(client.messages.batches
        ? {
            batches: {
              create: (body) => client.messages.batches.create(body) as Promise<AnthropicBatchLike>,
              retrieve: (batchId) =>
                client.messages.batches.retrieve(batchId) as Promise<AnthropicBatchLike>,
              results: (batchId) =>
                client.messages.batches.results(batchId) as Promise<
                  AsyncIterable<AnthropicBatchResultLike>
                >,
            },
          }
        : {}),
    },
  };
}
