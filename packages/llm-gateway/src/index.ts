/**
 * @montr/llm-gateway — the ONLY package permitted to import a provider SDK
 * (golden rule #2, §8.2). Provides the unified LLMGateway over Anthropic, AWS
 * Bedrock, GCP Vertex, and Azure OpenAI adapters, with retries+backoff, per-call
 * timeouts, structured errors, ⛔ metadata-only logging (golden rule #1), the ⛔
 * key-tier guard (§11), the model-floor warning (DECIDE-3), and per-call token
 * accounting emitted to @montr/cost-meter (golden rule #8). Provider + endpoint
 * + key are BYO, sourced from @montr/config.
 */
export {
  MontrLlmGateway,
  createLlmGateway,
  DEFAULT_TIMEOUT_MS,
  type CreateGatewayOptions,
} from "./gateway.js";

export {
  createAdapter,
  AnthropicAdapter,
  BedrockAdapter,
  VertexAdapter,
  AzureAdapter,
  OpenAiCompatibleAdapter,
  makeUsage,
  type ProviderAdapter,
  type AdapterCompletion,
  type OpenAiCompatibleAdapterOptions,
  type AnthropicAdapterOptions,
  type AnthropicClientLike,
  type AnthropicMessageLike,
  type AnthropicStreamEventLike,
  type BedrockAdapterOptions,
  type BedrockTransport,
  type VertexAdapterOptions,
  type VertexTransport,
  type VertexResponseLike,
  type VertexGenerateRequest,
  type AzureAdapterOptions,
  type OpenAiClientLike,
  type OpenAiChatCompletionLike,
  type OpenAiChatChunkLike,
} from "./adapters/index.js";

export {
  buildDescriptors,
  resolveDescriptor,
  assertModelFloor,
  checkModelFloor,
  isBelowFloor,
  modelRank,
  FLOOR_RANK,
  type ModelFloorCheck,
  type AssertModelFloorOptions,
} from "./models.js";

export {
  detectKeyTier,
  applyKeyTierGuard,
  type DetectKeyTierInput,
  type KeyTierGuardResult,
} from "./keytier.js";

export { isRetriableProviderError, toGatewayError, timeoutError } from "./errors.js";

export {
  withRetry,
  withIteratorTimeout,
  runWithTimeout,
  defaultSleep,
  DEFAULT_RETRY_POLICY,
  type RetryPolicy,
  type SleepFn,
} from "./retry.js";

export { buildCallLog, callLogFields, logCall, type BuildCallLogInput } from "./logging.js";

export {
  contentToString,
  collectSystem,
  anthropicRejectsSampling,
  mapAnthropicStopReason,
  mapVertexFinishReason,
  mapOpenAiFinishReason,
  toOpenAiTools,
  toAnthropicTools,
  toVertexTools,
  extractOpenAiToolCalls,
  extractAnthropicToolCalls,
  extractVertexToolCalls,
} from "./mapping.js";
