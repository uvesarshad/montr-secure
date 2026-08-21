/**
 * Embeddings capability (E5 — semantic codebase index). Genuinely additive: a
 * separate request/response shape and adapter interface from the chat
 * `ProviderAdapter`/`complete()`/`stream()` path in gateway.ts — embeddings
 * are a different API (`POST /embeddings`, no messages/system/tools/effort),
 * so bolting them onto `LLMRequest` would be a lie about the shape of the
 * call. Nothing in tool-use, structured-output, or prompt-caching logic is
 * touched by this file.
 *
 * ⛔ PROVIDER DECISION (documented per this task's instructions, since it is a
 * real product choice and not an implementation detail):
 *
 * Anthropic does not serve an embeddings endpoint at all — there is no
 * first-party model to call. That leaves Bedrock, Vertex, and Azure as the
 * three BYO-key providers this gateway already speaks. This file implements
 * ONLY Azure OpenAI today (`AzureEmbeddingAdapter`, mirroring
 * `adapters/azure.ts`'s existing use of the `openai` SDK's `AzureOpenAI`
 * client) because:
 *
 *   1. It reuses an SDK already a dependency of this package (no new
 *      provider SDK import, honoring golden rule #2 — @montr/llm-gateway is
 *      the only package allowed to import a provider SDK, and only from
 *      inside its own adapters).
 *   2. Azure's `/embeddings` endpoint is the OpenAI wire format — the exact
 *      shape `client.embeddings.create({ model, input })` — so there is no
 *      provider-specific request/response mapping to invent; `azure.ts`'s
 *      `createDefaultAzureClient` pattern for resolving endpoint/key from
 *      `@montr/config` applies unchanged.
 *   3. Bedrock and Vertex DO offer real embedding models (Titan Embeddings,
 *      Cohere-on-Bedrock, and Vertex's `text-embedding-*` family
 *      respectively) — but each is a genuinely different wire protocol from
 *      this package's existing Bedrock/Vertex chat adapters (different
 *      request/response JSON shape, not a superset of the chat API), so
 *      adding them is real, protocol-specific adapter work, not a
 *      copy-paste of this file. That work is a documented follow-up, not
 *      done here — see the `NotImplementedError` thrown by
 *      `bedrock`/`vertex`/`anthropic` below, which mirrors exactly how
 *      `submitBatch`/`pollBatch`/`getBatchResults` already signal
 *      per-provider capability gaps elsewhere in this package.
 *
 * A deployer without Azure configured has no embeddings path today — that is
 * an honest limitation of a same-day BYO-multi-provider product decision, not
 * a bug. `packages/semantic-index` depends on an injected
 * `EmbeddingProviderAdapter` rather than hardcoding Azure, so a Bedrock/Vertex
 * (or fully offline/local) implementation is a drop-in addition later.
 */
import { NotImplementedError, ProviderNotConfiguredError, type Provider } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { AdapterEgress } from "./adapters/egress.js";

/** Non-code metadata attached to every embedding call — logged, never the input text bodies. */
export interface EmbeddingCallMetadata {
  clientId?: string;
  scanId?: string;
  /** Free-text purpose tag (e.g. "semantic_index_build", "semantic_index_query") — not the fixed LLMPurpose enum, since embeddings are not an LLMPurpose. */
  purpose: string;
}

export interface EmbeddingRequest {
  /** Batch of input texts (provider-batched in one call where supported). */
  input: string[];
  /** Provider-native embedding model id / Azure deployment name (explicit — no tier resolution, mirroring `resolveModel`'s explicit-id path). */
  model: string;
  metadata: EmbeddingCallMetadata;
}

export interface EmbeddingResult {
  /** One vector per `request.input` entry, same order. */
  embeddings: number[][];
  model: string;
  usage: { inputTokens: number };
}

export interface EmbeddingProviderAdapter {
  readonly provider: Provider;
  embed(request: EmbeddingRequest, signal?: AbortSignal): Promise<EmbeddingResult>;
}

export interface CreateEmbeddingAdapterOptions {
  config: MontrConfig;
  /** ⛔ Egress guard asserted before every outbound request (golden rule #1), threaded exactly like the chat adapters. */
  egress?: AdapterEgress;
  /** Injectable client (tests). */
  client?: AzureEmbeddingClientLike;
}

/** Minimal shape of the `openai` SDK surface this adapter needs — mirrors `OpenAiClientLike` in adapters/azure.ts. */
export interface AzureEmbeddingClientLike {
  embeddings: {
    create(
      body: { model: string; input: string[] },
      options?: { signal?: AbortSignal },
    ): Promise<{
      data?: Array<{ embedding?: number[] }>;
      model?: string;
      usage?: { prompt_tokens?: number; total_tokens?: number };
    }>;
  };
}

const DEFAULT_AZURE_API_VERSION = "2024-10-21";

export class AzureEmbeddingAdapter implements EmbeddingProviderAdapter {
  readonly provider = "azure" as const;
  private client?: AzureEmbeddingClientLike;

  constructor(private readonly options: CreateEmbeddingAdapterOptions) {
    this.client = options.client;
  }

  private assertEgress(): void {
    const endpoint = this.options.config.llm.endpoint;
    if (endpoint) this.options.egress?.assert(endpoint);
  }

  private async getClient(): Promise<AzureEmbeddingClientLike> {
    if (!this.client) this.client = await createDefaultAzureEmbeddingClient(this.options.config);
    return this.client;
  }

  async embed(request: EmbeddingRequest, signal?: AbortSignal): Promise<EmbeddingResult> {
    if (request.input.length === 0) {
      return { embeddings: [], model: request.model, usage: { inputTokens: 0 } };
    }
    this.assertEgress();
    const client = await this.getClient();
    const result = await client.embeddings.create(
      { model: request.model, input: request.input },
      signal ? { signal } : undefined,
    );
    const embeddings = (result.data ?? []).map((row) => row.embedding ?? []);
    if (embeddings.length !== request.input.length) {
      throw new Error(
        `Embeddings adapter returned ${embeddings.length} vectors for ${request.input.length} inputs`,
      );
    }
    return {
      embeddings,
      model: result.model ?? request.model,
      usage: { inputTokens: result.usage?.prompt_tokens ?? result.usage?.total_tokens ?? 0 },
    };
  }
}

async function createDefaultAzureEmbeddingClient(
  config: MontrConfig,
): Promise<AzureEmbeddingClientLike> {
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
    AzureOpenAI: new (opts: Record<string, unknown>) => AzureEmbeddingClientLike;
  };
  return new mod.AzureOpenAI({ apiKey, endpoint, apiVersion, maxRetries: 0 });
}

/** Unsupported-provider stub — see this file's doc comment for why only Azure is implemented today. */
class UnsupportedEmbeddingAdapter implements EmbeddingProviderAdapter {
  constructor(readonly provider: Provider) {}

  async embed(): Promise<EmbeddingResult> {
    throw new NotImplementedError(`Embeddings not implemented for provider '${this.provider}'`, {
      provider: this.provider,
    });
  }
}

/**
 * Adapter factory — mirrors `adapters/index.ts`'s `createAdapter`. Selecting
 * the provider from `@montr/config` is the only place a concrete embeddings
 * adapter is constructed.
 */
export function createEmbeddingAdapter(
  provider: Provider,
  config: MontrConfig,
  egress?: AdapterEgress,
): EmbeddingProviderAdapter {
  switch (provider) {
    case "azure":
      return new AzureEmbeddingAdapter({ config, egress });
    case "anthropic":
    case "bedrock":
    case "vertex":
      return new UnsupportedEmbeddingAdapter(provider);
    default: {
      const exhaustive: never = provider;
      throw new Error(`Unknown LLM provider: ${String(exhaustive)}`);
    }
  }
}
