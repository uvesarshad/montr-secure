import type { Provider } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { AnthropicAdapter } from "./anthropic.js";
import { BedrockAdapter } from "./bedrock.js";
import { VertexAdapter } from "./vertex.js";
import { AzureAdapter } from "./azure.js";
import type { ProviderAdapter } from "./types.js";

/**
 * Adapter factory. Selecting the provider from @montr/config is the ONLY place
 * a concrete provider adapter is constructed. Each adapter lazily instantiates
 * its SDK on first use (golden rule #2: SDKs never imported outside this package).
 */
export function createAdapter(provider: Provider, config: MontrConfig): ProviderAdapter {
  switch (provider) {
    case "anthropic":
      return new AnthropicAdapter({ config });
    case "bedrock":
      return new BedrockAdapter({ config });
    case "vertex":
      return new VertexAdapter({ config });
    case "azure":
      return new AzureAdapter({ config });
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
export { type ProviderAdapter, type AdapterCompletion, makeUsage } from "./types.js";
