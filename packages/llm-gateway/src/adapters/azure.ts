import {
  ProviderNotConfiguredError,
  type LLMRequest,
  type LLMStreamEvent,
  type LLMToolCall,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { mapOpenAiFinishReason, toOpenAiMessages, toOpenAiTools } from "../mapping.js";
import { resolveStructuredOutputSchema } from "../structured-output.js";
import { makeUsage, type AdapterCompletion, type ProviderAdapter } from "./types.js";
import { type AdapterEgress } from "./egress.js";

/**
 * Azure OpenAI adapter via the `openai` SDK's Azure support (`AzureOpenAI`).
 * The gateway's logical model id is the Azure deployment name. Endpoint + key
 * come from @montr/config; API version from `AZURE_OPENAI_API_VERSION`.
 */

const DEFAULT_AZURE_API_VERSION = "2024-10-21";

interface OpenAiUsageLike {
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
}

interface OpenAiToolCallLike {
  id?: string;
  type?: string;
  function?: { name?: string; arguments?: string };
}

export interface OpenAiChatCompletionLike {
  id?: string;
  model?: string;
  choices?: Array<{
    message?: { content?: string | null; tool_calls?: OpenAiToolCallLike[] | null };
    finish_reason?: string | null;
  }>;
  usage?: OpenAiUsageLike | null;
}

/** A `delta.tool_calls[]` fragment (A14) — `arguments` arrives incrementally across chunks, keyed by `index`. */
export interface OpenAiToolCallDeltaLike {
  index: number;
  id?: string;
  function?: { name?: string; arguments?: string };
}

export interface OpenAiChatChunkLike {
  id?: string;
  model?: string;
  choices?: Array<{
    delta?: { content?: string | null; tool_calls?: OpenAiToolCallDeltaLike[] | null };
    finish_reason?: string | null;
  }>;
  usage?: OpenAiUsageLike | null;
}

export interface OpenAiClientLike {
  chat: {
    completions: {
      create(
        body: Record<string, unknown>,
        options?: { signal?: AbortSignal },
      ): Promise<OpenAiChatCompletionLike | AsyncIterable<OpenAiChatChunkLike>>;
    };
  };
}

/**
 * Build an OpenAI Chat-Completions-shaped request body (A8: tools; A13:
 * structured output). Shared by every adapter that speaks this wire format —
 * Azure OpenAI here, plus the generic {@link OpenAiCompatibleAdapter}
 * (packages/llm-gateway/src/adapters/openai-compatible.ts, A3) for `openai`,
 * `google`, `xai`, `moonshot`, `zhipu`, `deepseek`. Exported (not private, as
 * in the July line's port target) so it stays the SINGLE body-builder for
 * every OpenAI-wire-format provider rather than forking into two copies with
 * drifting capabilities — see this function's `responseFormat` branch, the
 * one part of current's body-building that July's adapter never had.
 */
export function buildBody(request: LLMRequest, modelId: string): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model: modelId,
    max_tokens: request.maxTokens,
    messages: toOpenAiMessages(request),
  };
  if (request.temperature !== undefined) body.temperature = request.temperature;
  const tools = toOpenAiTools(request);
  if (tools) body.tools = tools;
  if (request.responseFormat === "json") {
    // A13: real JSON-schema-constrained output (OpenAI `response_format:
    // json_schema`) when a schema is resolved for this call's purpose;
    // otherwise fall back to the prior prose-JSON `json_object` mode.
    const schema = resolveStructuredOutputSchema(request);
    body.response_format = schema
      ? {
          type: "json_schema",
          json_schema: { name: request.metadata.purpose, schema, strict: true },
        }
      : { type: "json_object" };
  }
  // Effort/extended-thinking has no Azure OpenAI equivalent surfaced here
  // (deployment-name-opaque models per @montr/llm-gateway's egress model) —
  // no-op cleanly rather than erroring (A8).
  return body;
}

/**
 * Extract OpenAI-shaped tool calls from a chat-completion choice (A8).
 * Exported alongside {@link buildBody} so the generic OpenAI-compatible
 * adapter (A3) shares the SAME parsing rather than a second copy.
 */
export function openAiToolCalls(
  toolCalls: OpenAiToolCallLike[] | null | undefined,
): LLMToolCall[] | undefined {
  if (!toolCalls || toolCalls.length === 0) return undefined;
  const mapped = toolCalls
    .filter(
      (tc): tc is OpenAiToolCallLike & { id: string; function: { name: string } } =>
        typeof tc.id === "string" && typeof tc.function?.name === "string",
    )
    .map((tc) => {
      let input: Record<string, unknown> = {};
      try {
        const parsed: unknown = tc.function.arguments ? JSON.parse(tc.function.arguments) : {};
        if (parsed && typeof parsed === "object") input = parsed as Record<string, unknown>;
      } catch {
        // Malformed tool-call argument JSON — return the call with empty
        // input rather than dropping it; the caller (E1's future loop) can
        // still see the tool the model tried to invoke.
      }
      return { id: tc.id, name: tc.function.name, input };
    });
  return mapped.length > 0 ? mapped : undefined;
}

/**
 * Re-yield an OpenAI Chat-Completions SSE chunk stream as contract stream
 * events + final usage (A14). Shared by {@link AzureAdapter.stream} and the
 * generic {@link OpenAiCompatibleAdapter}'s stream (`./openai-compatible.js`)
 * — both speak the identical wire shape, same precedent as {@link buildBody}/
 * {@link openAiToolCalls} above. A tool call's `function.arguments` JSON
 * string arrives fragmented across chunks, keyed by `index`; it is only
 * complete once the chunk stream ends, so — unlike Anthropic's per-block
 * `content_block_stop` — every accumulated tool call is emitted once, after
 * the loop, right before `message_done`.
 */
export async function* mapOpenAiChunks(
  chunks: AsyncIterable<OpenAiChatChunkLike>,
): AsyncGenerator<LLMStreamEvent, void, unknown> {
  let promptTokens = 0;
  let completionTokens = 0;
  let totalTokens: number | undefined;
  let finishReason: string | null | undefined;
  const toolCalls = new Map<number, { id: string; name: string; args: string }>();

  for await (const chunk of chunks) {
    const choice = chunk.choices?.[0];
    const text = choice?.delta?.content;
    if (typeof text === "string" && text.length > 0) yield { type: "text_delta", text };
    for (const tc of choice?.delta?.tool_calls ?? []) {
      const existing = toolCalls.get(tc.index);
      const id = tc.id ?? existing?.id;
      const name = tc.function?.name ?? existing?.name;
      const args = (existing?.args ?? "") + (tc.function?.arguments ?? "");
      if (id && name) toolCalls.set(tc.index, { id, name, args });
    }
    if (choice?.finish_reason) finishReason = choice.finish_reason;
    const u = chunk.usage;
    if (u) {
      promptTokens = u.prompt_tokens ?? promptTokens;
      completionTokens = u.completion_tokens ?? completionTokens;
      totalTokens = u.total_tokens ?? totalTokens;
    }
  }

  for (const [, call] of [...toolCalls].sort(([a], [b]) => a - b)) {
    let input: Record<string, unknown> = {};
    try {
      const parsed: unknown = call.args.trim().length > 0 ? JSON.parse(call.args) : {};
      if (parsed && typeof parsed === "object") input = parsed as Record<string, unknown>;
    } catch {
      // Malformed tool-call argument JSON — yield the call with empty input
      // rather than dropping it silently (mirrors openAiToolCalls above).
    }
    yield { type: "tool_use", id: call.id, name: call.name, input };
  }

  yield {
    type: "message_done",
    usage: makeUsage(promptTokens, completionTokens, { totalTokens }),
    stopReason: mapOpenAiFinishReason(finishReason),
  };
}

export interface AzureAdapterOptions {
  config: MontrConfig;
  /** Injectable client (tests). Defaults to a real `AzureOpenAI` client. */
  client?: OpenAiClientLike;
  /** ⛔ Egress guard asserted before every outbound request (golden rule #1). */
  egress?: AdapterEgress;
}

export class AzureAdapter implements ProviderAdapter {
  readonly provider = "azure" as const;
  private client?: OpenAiClientLike;

  constructor(private readonly options: AzureAdapterOptions) {
    this.client = options.client;
  }

  private async getClient(): Promise<OpenAiClientLike> {
    if (!this.client) this.client = await createDefaultAzureClient(this.options.config);
    return this.client;
  }

  /**
   * ⛔ Assert the outbound Azure host is the configured endpoint before dispatch.
   * Azure has no generic default host; when no endpoint is set, `getClient()`
   * throws ProviderNotConfiguredError before any request is attempted.
   */
  private assertEgress(): void {
    const endpoint = this.options.config.llm.endpoint;
    if (endpoint) this.options.egress?.assert(endpoint);
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
    const result = (await client.chat.completions.create(
      { ...buildBody(request, modelId), stream: false },
      signal ? { signal } : undefined,
    )) as OpenAiChatCompletionLike;
    const choice = result.choices?.[0];
    const u = result.usage ?? undefined;
    const toolCalls = openAiToolCalls(choice?.message?.tool_calls);
    return {
      id: result.id ?? `${modelId}:response`,
      model: result.model ?? modelId,
      content: choice?.message?.content ?? "",
      stopReason: mapOpenAiFinishReason(choice?.finish_reason),
      usage: makeUsage(u?.prompt_tokens ?? 0, u?.completion_tokens ?? 0, {
        totalTokens: u?.total_tokens,
      }),
      ...(toolCalls ? { toolCalls } : {}),
    };
  }

  async *stream(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): AsyncGenerator<LLMStreamEvent> {
    this.assertEgress();
    const client = await this.getClient();
    const chunks = (await client.chat.completions.create(
      { ...buildBody(request, modelId), stream: true, stream_options: { include_usage: true } },
      signal ? { signal } : undefined,
    )) as AsyncIterable<OpenAiChatChunkLike>;
    yield* mapOpenAiChunks(chunks);
  }
}

async function createDefaultAzureClient(config: MontrConfig): Promise<OpenAiClientLike> {
  const apiKey = config.llm.apiKey;
  const endpoint = config.llm.endpoint;
  if (!apiKey) {
    throw new ProviderNotConfiguredError("Azure OpenAI API key not configured (llm.apiKey)", {
      provider: "azure",
    });
  }
  if (!endpoint) {
    throw new ProviderNotConfiguredError("Azure OpenAI endpoint not configured (llm.endpoint)", {
      provider: "azure",
    });
  }
  const apiVersion =
    process.env.AZURE_OPENAI_API_VERSION ??
    process.env.OPENAI_API_VERSION ??
    DEFAULT_AZURE_API_VERSION;
  const mod = (await import("openai")) as unknown as {
    AzureOpenAI: new (opts: Record<string, unknown>) => {
      chat: { completions: { create: (body: unknown, options?: unknown) => unknown } };
    };
  };
  const client = new mod.AzureOpenAI({ apiKey, endpoint, apiVersion, maxRetries: 0 });
  return {
    chat: {
      completions: {
        create: (body, options) =>
          client.chat.completions.create(body, options) as Promise<
            OpenAiChatCompletionLike | AsyncIterable<OpenAiChatChunkLike>
          >,
      },
    },
  };
}
