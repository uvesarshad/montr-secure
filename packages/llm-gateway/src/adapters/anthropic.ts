import {
  ProviderNotConfiguredError,
  type LLMRequest,
  type LLMStreamEvent,
  type LLMToolCall,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { buildAnthropicStyleFields, mapAnthropicStopReason } from "../mapping.js";
import { makeUsage, type AdapterCompletion, type ProviderAdapter } from "./types.js";
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

export interface AnthropicMessagesLike {
  create(
    body: Record<string, unknown>,
    options?: { signal?: AbortSignal },
  ): Promise<AnthropicMessageLike | AsyncIterable<AnthropicStreamEventLike>>;
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
      messages: { create: (body: unknown, options?: unknown) => unknown };
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
    },
  };
}
