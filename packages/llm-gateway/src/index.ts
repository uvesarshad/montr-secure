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

// A31 — Batch API types (submitBatch/pollBatch/getBatchResults are additive
// methods on MontrLlmGateway; see gateway.ts and docs/modules/llm-gateway.md).
export {
  type LLMBatchRequestItem,
  type LLMBatchHandle,
  type LLMBatchProcessingStatus,
  type LLMBatchCounts,
  type LLMBatchStatus,
  type LLMBatchResultItem,
  type LLMBatchResultsOptions,
} from "./batch.js";

// Re-exported for convenience: callers wiring `budgetRegistry` (A2 pre-call
// budget guard) into `createLlmGateway` shouldn't need a direct
// `@montr/cost-meter` import just for the type.
export { createBudgetRegistry, type BudgetContext, type BudgetRegistry } from "@montr/cost-meter";

export {
  resolvePromptTemplate,
  type PromptVersionSource,
  type PromptVersionSourceRecord,
  type ResolvePromptOptions,
} from "./prompts.js";

export {
  createAdapter,
  AnthropicAdapter,
  BedrockAdapter,
  VertexAdapter,
  AzureAdapter,
  makeUsage,
  type ProviderAdapter,
  type AdapterCompletion,
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
  anthropicSupportsEffort,
  mapAnthropicStopReason,
  mapVertexFinishReason,
  mapOpenAiFinishReason,
  toAnthropicTools,
  toVertexTools,
  toOpenAiTools,
  buildAnthropicStyleFields,
  buildAnthropicCountTokensBody,
  type AnthropicToolLike,
  type VertexToolLike,
  type VertexFunctionDeclaration,
  type OpenAiToolLike,
} from "./mapping.js";

export {
  resolveStructuredOutputSchema,
  resolveAnthropicOutputFormat,
  type JsonSchemaOutputFormat,
} from "./structured-output.js";
