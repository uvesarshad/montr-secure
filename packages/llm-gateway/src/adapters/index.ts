import type { Provider } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { AnthropicAdapter } from "./anthropic.js";
import { BedrockAdapter } from "./bedrock.js";
import { VertexAdapter } from "./vertex.js";
import { AzureAdapter } from "./azure.js";
import type { ProviderAdapter } from "./types.js";
import type { AdapterEgress } from "./egress.js";

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
  type AnthropicContentBlockLike,
  type AnthropicStreamEventLike,
  type AnthropicCountTokensResultLike,
  type AnthropicBatchesLike,
  type AnthropicBatchRequestLike,
  type AnthropicBatchLike,
  type AnthropicBatchResultLike,
} from "./anthropic.js";
export { BedrockAdapter, type BedrockAdapterOptions, type BedrockTransport } from "./bedrock.js";
export {
  VertexAdapter,
  type VertexAdapterOptions,
  type VertexTransport,
  type VertexResponseLike,
  type VertexGenerateRequest,
  type VertexPartLike,
} from "./vertex.js";
export {
  AzureAdapter,
  type AzureAdapterOptions,
  type OpenAiClientLike,
  type OpenAiChatCompletionLike,
  type OpenAiChatChunkLike,
} from "./azure.js";
export {
  type ProviderAdapter,
  type AdapterCompletion,
  type AdapterBatchSubmitItem,
  type AdapterBatchHandle,
  type AdapterBatchCounts,
  type AdapterBatchStatus,
  type AdapterBatchResultItem,
  makeUsage,
} from "./types.js";
export { type AdapterEgress, resolveOutboundTarget } from "./egress.js";
