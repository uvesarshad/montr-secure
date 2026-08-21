import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { LayerIdSchema } from "./enums.js";

/**
 * LLM Gateway INTERFACE (§8.2). Types + reference data only — NO provider SDK is
 * imported here or anywhere outside @montr/llm-gateway (golden rule #2).
 * Client source only ever leaves the perimeter inside a call to the client's own
 * key; per-call logging is metadata-only (golden rule #1).
 */

/** Supported providers (BYO-key). Montr never holds its own model relationship. */
export const ProviderSchema = z.enum(["anthropic", "bedrock", "vertex", "azure"]);
export type Provider = z.infer<typeof ProviderSchema>;

/** Model tiers mapped to the recommended matrix (DECIDE-3). */
export const ModelTierSchema = z.enum(["triage", "default", "confirmation"]);
export type ModelTier = z.infer<typeof ModelTierSchema>;

/** Key-tier guard classification (§11) — warn/block suspected data-retaining tiers. */
export const KeyTierSchema = z.enum(["enterprise", "unknown", "data_retaining"]);
export type KeyTier = z.infer<typeof KeyTierSchema>;

export const LLMRoleSchema = z.enum(["system", "user", "assistant", "tool"]);
export type LLMRole = z.infer<typeof LLMRoleSchema>;

/** What a given LLM call is for. Logged as metadata; drives model-tier routing. */
export const LLMPurposeSchema = z.enum([
  "appmap_labeling",
  "triage",
  "correlation",
  "confirmation",
  "fix_generation",
  "report_synthesis",
  "other",
]);
export type LLMPurpose = z.infer<typeof LLMPurposeSchema>;

export const TextBlockSchema = z.object({ type: z.literal("text"), text: z.string() });
export type TextBlock = z.infer<typeof TextBlockSchema>;

export const LLMMessageSchema = z.object({
  role: LLMRoleSchema,
  content: z.union([z.string(), z.array(TextBlockSchema)]),
  /** For tool-result messages. */
  toolCallId: z.string().optional(),
  name: z.string().optional(),
});
export type LLMMessage = z.infer<typeof LLMMessageSchema>;

/** Per-call token accounting emitted to the Cost Meter. */
export const TokenUsageSchema = z.object({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cacheReadTokens: z.number().int().nonnegative().optional(),
  cacheWriteTokens: z.number().int().nonnegative().optional(),
  totalTokens: z.number().int().nonnegative(),
});
export type TokenUsage = z.infer<typeof TokenUsageSchema>;

/** A tool the model may call (JSON-schema parameters). */
export const LLMToolDefinitionSchema = z.object({
  name: z.string(),
  description: z.string(),
  parameters: z.record(z.string(), z.unknown()),
});
export type LLMToolDefinition = z.infer<typeof LLMToolDefinitionSchema>;

/** Static description of a model available through the gateway. */
export const ModelDescriptorSchema = z.object({
  provider: ProviderSchema,
  modelId: z.string(),
  tier: ModelTierSchema,
  contextWindow: z.number().int().positive(),
  maxOutputTokens: z.number().int().positive(),
  supportsTools: z.boolean().default(true),
  supportsStreaming: z.boolean().default(true),
  /** True if this model is below the confirmation floor (degrades accuracy). */
  belowFloor: z.boolean().default(false),
});
export type ModelDescriptor = z.infer<typeof ModelDescriptorSchema>;

/** Non-code metadata attached to every request; this — never the bodies — is logged. */
export const LLMCallMetadataSchema = z.object({
  scanId: IdSchema.optional(),
  clientId: IdSchema.optional(),
  layer: LayerIdSchema.optional(),
  purpose: LLMPurposeSchema,
});
export type LLMCallMetadata = z.infer<typeof LLMCallMetadataSchema>;

export const ResponseFormatSchema = z.enum(["text", "json"]);
export type ResponseFormat = z.infer<typeof ResponseFormatSchema>;

/** A unified request to the gateway. Either a concrete `model` or a `tier` to resolve. */
export const LLMRequestSchema = z.object({
  model: z.string().optional(),
  tier: ModelTierSchema.optional(),
  system: z.string().optional(),
  messages: z.array(LLMMessageSchema).min(1),
  maxTokens: z.number().int().positive(),
  temperature: z.number().min(0).max(2).optional(),
  tools: z.array(LLMToolDefinitionSchema).optional(),
  responseFormat: ResponseFormatSchema.default("text"),
  stream: z.boolean().default(false),
  metadata: LLMCallMetadataSchema,
});
export type LLMRequest = z.infer<typeof LLMRequestSchema>;

export const StopReasonSchema = z.enum([
  "end_turn",
  "max_tokens",
  "stop_sequence",
  "tool_use",
  "refusal",
  "error",
]);
export type StopReason = z.infer<typeof StopReasonSchema>;

export const LLMResponseSchema = z.object({
  id: z.string(),
  provider: ProviderSchema,
  model: z.string(),
  content: z.string(),
  stopReason: StopReasonSchema,
  usage: TokenUsageSchema,
  latencyMs: z.number().nonnegative(),
});
export type LLMResponse = z.infer<typeof LLMResponseSchema>;

/** Streaming event union. */
export const LLMStreamEventSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("text_delta"), text: z.string() }),
  z.object({
    type: z.literal("message_done"),
    usage: TokenUsageSchema,
    stopReason: StopReasonSchema,
  }),
  z.object({ type: z.literal("error"), message: z.string() }),
]);
export type LLMStreamEvent = z.infer<typeof LLMStreamEventSchema>;

/** Metadata-only audit record for a completed LLM call (golden rule #1, §8.5). */
export const LLMCallLogSchema = z.object({
  provider: ProviderSchema,
  model: z.string(),
  usage: TokenUsageSchema,
  latencyMs: z.number().nonnegative(),
  metadata: LLMCallMetadataSchema,
  at: IsoDateTimeSchema,
});
export type LLMCallLog = z.infer<typeof LLMCallLogSchema>;

/**
 * The gateway contract every adapter implements (@montr/llm-gateway).
 * `complete`/`stream`, model resolution, and optional token estimation.
 */
export interface LLMGateway {
  complete(request: LLMRequest): Promise<LLMResponse>;
  stream(request: LLMRequest): AsyncIterable<LLMStreamEvent>;
  listModels(): ModelDescriptor[];
  resolveModel(tierOrId: ModelTier | string): ModelDescriptor;
  estimateTokens?(request: LLMRequest): Promise<number>;
}

/**
 * Recommended model matrix (build-plan §4.1, DECIDE-3). Encoded as DATA only.
 * Model IDs verified against the current Anthropic catalog. WS-B (gateway) may
 * refine per provider; clients BYO-key.
 */
export const RECOMMENDED_MODEL_MATRIX: Record<
  ModelTier,
  { provider: Provider; modelId: string; note: string }
> = {
  triage: {
    provider: "anthropic",
    modelId: "claude-haiku-4-5-20251001",
    note: "Cheap, fast triage/labeling.",
  },
  default: {
    provider: "anthropic",
    modelId: "claude-sonnet-5",
    note: "Default correlation/reasoning tier.",
  },
  confirmation: {
    provider: "anthropic",
    modelId: "claude-opus-4-8",
    note: "Hardest exploit confirmations.",
  },
};

/**
 * Model floor (DECIDE-3): confirmation-tier accuracy requires a Sonnet-5-class
 * model or better. The gateway warns when a client points below this.
 */
export const MODEL_FLOOR = {
  confirmationTier: {
    minModelId: "claude-sonnet-5",
    reason: "Below Sonnet-5-class, exploit confirmation accuracy degrades materially.",
  },
} as const;

/** Reference per-million-token USD rates for the cost meter (BYO-key defaults). */
export interface ModelCostRate {
  readonly provider: Provider;
  readonly modelId: string;
  readonly inputPerMillionUsd: number;
  readonly outputPerMillionUsd: number;
  readonly note?: string;
}

export const MODEL_COST_RATES: readonly ModelCostRate[] = [
  {
    provider: "anthropic",
    modelId: "claude-opus-5",
    inputPerMillionUsd: 5,
    outputPerMillionUsd: 25,
  },
  {
    provider: "anthropic",
    modelId: "claude-opus-4-8",
    inputPerMillionUsd: 5,
    outputPerMillionUsd: 25,
  },
  {
    provider: "anthropic",
    modelId: "claude-fable-5",
    inputPerMillionUsd: 10,
    outputPerMillionUsd: 50,
    note: "Anthropic's most capable widely released model (Project Glasswing/Mythos-5 pricing parity).",
  },
  {
    provider: "anthropic",
    modelId: "claude-sonnet-5",
    inputPerMillionUsd: 3,
    outputPerMillionUsd: 15,
    note: "Introductory $2/$10 through 2026-08-31.",
  },
  {
    provider: "anthropic",
    modelId: "claude-haiku-4-5-20251001",
    inputPerMillionUsd: 1,
    outputPerMillionUsd: 5,
  },
];

/**
 * Conservative ceiling rate for a model id absent from {@link MODEL_COST_RATES}
 * (audit A1). Deliberately set to the highest input/output rate on the whole
 * card (currently `claude-fable-5`'s $10/$50) so an unlisted BYO model is
 * NEVER cheaper to meter than the priciest known model — an unrecognized
 * model id must not be able to defeat the budget hard-halt (DECIDE-4) by
 * pricing at $0. Not a real billable model — `findModelRate` never returns
 * this row; only `priceUsageUsd`'s fail-closed fallback path uses it.
 */
export const UNKNOWN_MODEL_FALLBACK_RATE: ModelCostRate = {
  provider: "anthropic",
  modelId: "__unknown_model_fallback__",
  inputPerMillionUsd: 10,
  outputPerMillionUsd: 50,
  note: "Fail-closed ceiling rate for unrecognized model ids (A1) — matches the highest rate on the card, not a real billable model.",
};
