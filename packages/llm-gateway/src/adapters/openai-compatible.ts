import {
  ProviderNotConfiguredError,
  type LLMRequest,
  type LLMStreamEvent,
  type Provider,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { mapOpenAiFinishReason } from "../mapping.js";
import { makeUsage, type AdapterCompletion, type ProviderAdapter } from "./types.js";
import { resolveOutboundTarget, type AdapterEgress } from "./egress.js";
import {
  buildBody,
  openAiToolCalls,
  type OpenAiChatChunkLike,
  type OpenAiChatCompletionLike,
  type OpenAiClientLike,
} from "./azure.js";

/**
 * Generic OpenAI **Chat Completions**-compatible adapter (A3). One adapter
 * covers every BYO-key provider that speaks the OpenAI wire format: `openai`
 * (direct GPT), `xai` (Grok), `moonshot` (Kimi), `zhipu` (GLM), `deepseek`,
 * and `google` via Gemini's OpenAI-compatibility endpoint. Azure keeps its
 * own adapter (tenancy client + api-version) — this one is the `openai` SDK
 * with a per-provider `baseURL` + Bearer key instead.
 *
 * Deliberately reuses Azure's {@link buildBody}/{@link openAiToolCalls}
 * (./azure.js) rather than a second, drifting copy: both adapters speak the
 * identical OpenAI Chat-Completions wire shape, and `buildBody` already
 * carries current's structured-output (A13), tool-calling (A8), and
 * tool-round-tripping (A4) logic — porting July's simpler stand-alone
 * body-builder here would have silently regressed all three for six
 * providers the moment they shipped.
 */
export interface OpenAiCompatibleAdapterOptions {
  /** Which provider this instance represents (drives `provider` + key-tier). */
  provider: Provider;
  /** Provider default base URL, used when `config.llm.endpoint` is unset. */
  defaultBaseUrl: string;
  /** Provider default host, used for the egress assertion when no endpoint is set. */
  defaultHost: string;
  config: MontrConfig;
  /** Injectable client (tests). Defaults to a real `OpenAI` client. */
  client?: OpenAiClientLike;
  /** ⛔ Egress guard asserted before every outbound request (golden rule #1). */
  egress?: AdapterEgress;
}

export class OpenAiCompatibleAdapter implements ProviderAdapter {
  readonly provider: Provider;
  private client?: OpenAiClientLike;

  constructor(private readonly options: OpenAiCompatibleAdapterOptions) {
    this.provider = options.provider;
    this.client = options.client;
  }

  private baseUrl(): string {
    return this.options.config.llm.endpoint ?? this.options.defaultBaseUrl;
  }

  /** ⛔ Assert the outbound host (configured endpoint, else the provider default). */
  private assertEgress(): void {
    this.options.egress?.assert(
      resolveOutboundTarget(this.options.config.llm.endpoint, this.options.defaultHost),
    );
  }

  private async getClient(): Promise<OpenAiClientLike> {
    if (!this.client) {
      this.client = await createOpenAiClient(this.options.config, this.baseUrl(), this.provider);
    }
    return this.client;
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

    let promptTokens = 0;
    let completionTokens = 0;
    let totalTokens: number | undefined;
    let finishReason: string | null | undefined;

    for await (const chunk of chunks) {
      const choice = chunk.choices?.[0];
      const text = choice?.delta?.content;
      if (typeof text === "string" && text.length > 0) yield { type: "text_delta", text };
      if (choice?.finish_reason) finishReason = choice.finish_reason;
      const u = chunk.usage;
      if (u) {
        promptTokens = u.prompt_tokens ?? promptTokens;
        completionTokens = u.completion_tokens ?? completionTokens;
        totalTokens = u.total_tokens ?? totalTokens;
      }
    }

    yield {
      type: "message_done",
      usage: makeUsage(promptTokens, completionTokens, { totalTokens }),
      stopReason: mapOpenAiFinishReason(finishReason),
    };
  }
}

async function createOpenAiClient(
  config: MontrConfig,
  baseURL: string,
  provider: Provider,
): Promise<OpenAiClientLike> {
  const apiKey = config.llm.apiKey;
  if (!apiKey) {
    throw new ProviderNotConfiguredError(`${provider} API key not configured (llm.apiKey)`, {
      provider,
    });
  }
  const mod = (await import("openai")) as unknown as {
    OpenAI?: new (opts: Record<string, unknown>) => {
      chat: { completions: { create: (body: unknown, options?: unknown) => unknown } };
    };
    default?: new (opts: Record<string, unknown>) => {
      chat: { completions: { create: (body: unknown, options?: unknown) => unknown } };
    };
  };
  const OpenAI = mod.OpenAI ?? mod.default;
  if (!OpenAI) throw new ProviderNotConfiguredError("openai SDK unavailable", { provider });
  const client = new OpenAI({ apiKey, baseURL, maxRetries: 0 });
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
