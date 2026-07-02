import { ProviderNotConfiguredError, type LLMRequest, type LLMStreamEvent } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { mapOpenAiFinishReason, toOpenAiMessages } from "../mapping.js";
import { makeUsage, type AdapterCompletion, type ProviderAdapter } from "./types.js";

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

export interface OpenAiChatCompletionLike {
  id?: string;
  model?: string;
  choices?: Array<{ message?: { content?: string | null }; finish_reason?: string | null }>;
  usage?: OpenAiUsageLike | null;
}

export interface OpenAiChatChunkLike {
  id?: string;
  model?: string;
  choices?: Array<{ delta?: { content?: string | null }; finish_reason?: string | null }>;
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

function buildBody(request: LLMRequest, modelId: string): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model: modelId,
    max_tokens: request.maxTokens,
    messages: toOpenAiMessages(request),
  };
  if (request.temperature !== undefined) body.temperature = request.temperature;
  if (request.responseFormat === "json") body.response_format = { type: "json_object" };
  return body;
}

export interface AzureAdapterOptions {
  config: MontrConfig;
  /** Injectable client (tests). Defaults to a real `AzureOpenAI` client. */
  client?: OpenAiClientLike;
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

  resolveModelId(modelId: string): string {
    return modelId;
  }

  async complete(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): Promise<AdapterCompletion> {
    const client = await this.getClient();
    const result = (await client.chat.completions.create(
      { ...buildBody(request, modelId), stream: false },
      signal ? { signal } : undefined,
    )) as OpenAiChatCompletionLike;
    const choice = result.choices?.[0];
    const u = result.usage ?? undefined;
    return {
      id: result.id ?? `${modelId}:response`,
      model: result.model ?? modelId,
      content: choice?.message?.content ?? "",
      stopReason: mapOpenAiFinishReason(choice?.finish_reason),
      usage: makeUsage(u?.prompt_tokens ?? 0, u?.completion_tokens ?? 0, {
        totalTokens: u?.total_tokens,
      }),
    };
  }

  async *stream(
    request: LLMRequest,
    modelId: string,
    signal?: AbortSignal,
  ): AsyncGenerator<LLMStreamEvent> {
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
