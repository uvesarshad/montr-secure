import type { Provider } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { AnthropicAdapter } from "./anthropic.js";
import { BedrockAdapter } from "./bedrock.js";
import { VertexAdapter } from "./vertex.js";
import { AzureAdapter } from "./azure.js";
import { OpenAiCompatibleAdapter } from "./openai-compatible.js";
import type { ProviderAdapter } from "./types.js";
import type { AdapterEgress } from "./egress.js";

/**
 * Per-provider defaults for the OpenAI Chat-Completions-compatible adapter. The
 * host must match `PROVIDER_DEFAULT_HOSTS` in @montr/security so the egress guard
 * permits it when no explicit `llm.endpoint` is set. Operators override the base
 * URL via `llm.endpoint` (e.g. a regional/`.cn` or private-proxy host).
 */
const OPENAI_COMPATIBLE: Partial<Record<Provider, { baseUrl: string; host: string }>> = {
  openai: { baseUrl: "https://api.openai.com/v1", host: "api.openai.com" },
  google: {
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai/",
    host: "generativelanguage.googleapis.com",
  },
  xai: { baseUrl: "https://api.x.ai/v1", host: "api.x.ai" },
  moonshot: { baseUrl: "https://api.moonshot.ai/v1", host: "api.moonshot.ai" },
  zhipu: { baseUrl: "https://open.bigmodel.cn/api/paas/v4/", host: "open.bigmodel.cn" },
  deepseek: { baseUrl: "https://api.deepseek.com", host: "api.deepseek.com" },
};

/**
 * Adapter factory. Selecting the provider from @montr/config is the ONLY place
 * a concrete provider adapter is constructed. Each adapter lazily instantiates
 * its SDK on first use (golden rule #2: SDKs never imported outside this package).
 *
 * ⛔ The `egress` guard (golden rule #1) is threaded into every adapter so each
 * asserts the outbound LLM host before dispatching a request (defense-in-depth
 * atop the gateway-level guard and the k8s default-deny NetworkPolicy).
 */
export function createAdapter(
  provider: Provider,
  config: MontrConfig,
  egress?: AdapterEgress,
): ProviderAdapter {
  switch (provider) {
    case "anthropic":
      return new AnthropicAdapter({ config, egress });
    case "bedrock":
      return new BedrockAdapter({ config, egress });
    case "vertex":
      return new VertexAdapter({ config, egress });
    case "azure":
      return new AzureAdapter({ config, egress });
    case "openai":
    case "google":
    case "xai":
    case "moonshot":
    case "zhipu":
    case "deepseek": {
      const d = OPENAI_COMPATIBLE[provider];
      if (!d) throw new Error(`No OpenAI-compatible defaults for provider: ${provider}`);
      return new OpenAiCompatibleAdapter({
        provider,
        defaultBaseUrl: d.baseUrl,
        defaultHost: d.host,
        config,
        egress,
      });
    }
    default: {
      const exhaustive: never = provider;
      throw new Error(`Unknown LLM provider: ${String(exhaustive)}`);
    }
  }
}

export {
  AnthropicAdapter,
  type AnthropicAdapterOptions,
  type AnthropicClientLike,
  type AnthropicMessageLike,
  type AnthropicStreamEventLike,
} from "./anthropic.js";
export { BedrockAdapter, type BedrockAdapterOptions, type BedrockTransport } from "./bedrock.js";
export {
  VertexAdapter,
  type VertexAdapterOptions,
  type VertexTransport,
  type VertexResponseLike,
  type VertexGenerateRequest,
} from "./vertex.js";
export {
  AzureAdapter,
  type AzureAdapterOptions,
  type OpenAiClientLike,
  type OpenAiChatCompletionLike,
  type OpenAiChatChunkLike,
} from "./azure.js";
export {
  OpenAiCompatibleAdapter,
  type OpenAiCompatibleAdapterOptions,
} from "./openai-compatible.js";
export { type ProviderAdapter, type AdapterCompletion, makeUsage } from "./types.js";
export { type AdapterEgress, resolveOutboundTarget } from "./egress.js";
