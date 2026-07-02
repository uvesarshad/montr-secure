/**
 * @montr/llm-gateway — the ONLY package permitted to import a provider SDK
 * (golden rule #2, §8.2). In Wave 0 NO SDK is imported yet: this is the gateway
 * interface + a typed stub. WS-B adds the Anthropic/Bedrock/Vertex/Azure
 * adapters, retries/backoff, per-call METADATA-ONLY logging (golden rule #1),
 * the key-tier guard, the model-floor warning, and token accounting to the Cost
 * Meter.
 */
import {
  NotImplementedError,
  RECOMMENDED_MODEL_MATRIX,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type ModelDescriptor,
  type ModelTier,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

export interface CreateGatewayOptions {
  config: MontrConfig;
}

/** Model descriptors derived from the recommended matrix (DECIDE-3). */
function defaultDescriptors(): ModelDescriptor[] {
  return [
    {
      provider: RECOMMENDED_MODEL_MATRIX.triage.provider,
      modelId: RECOMMENDED_MODEL_MATRIX.triage.modelId,
      tier: "triage",
      contextWindow: 200_000,
      maxOutputTokens: 64_000,
      supportsTools: true,
      supportsStreaming: true,
      belowFloor: true,
    },
    {
      provider: RECOMMENDED_MODEL_MATRIX.default.provider,
      modelId: RECOMMENDED_MODEL_MATRIX.default.modelId,
      tier: "default",
      contextWindow: 1_000_000,
      maxOutputTokens: 128_000,
      supportsTools: true,
      supportsStreaming: true,
      belowFloor: false,
    },
    {
      provider: RECOMMENDED_MODEL_MATRIX.confirmation.provider,
      modelId: RECOMMENDED_MODEL_MATRIX.confirmation.modelId,
      tier: "confirmation",
      contextWindow: 1_000_000,
      maxOutputTokens: 128_000,
      supportsTools: true,
      supportsStreaming: true,
      belowFloor: false,
    },
  ];
}

/**
 * Wave 0 stub. Signatures match the frozen @montr/contracts LLMGateway so
 * downstream layers (appmap/discovery/confirm/fix) have an exact target. The
 * real completion/streaming paths land in WS-B; no provider SDK is imported.
 */
export class StubLlmGateway implements LLMGateway {
  private readonly descriptors = defaultDescriptors();

  constructor(private readonly config: MontrConfig) {}

  listModels(): ModelDescriptor[] {
    return [...this.descriptors];
  }

  resolveModel(tierOrId: ModelTier | string): ModelDescriptor {
    const byTier = this.descriptors.find((d) => d.tier === tierOrId);
    if (byTier) return byTier;
    const byId = this.descriptors.find((d) => d.modelId === tierOrId);
    if (byId) return byId;
    throw new NotImplementedError(`Unknown model or tier: ${tierOrId}`, {
      configuredProvider: this.config.llm.provider,
    });
  }

  complete(_request: LLMRequest): Promise<LLMResponse> {
    throw new NotImplementedError("LLMGateway.complete — WS-B (provider adapters)");
  }

  stream(_request: LLMRequest): AsyncIterable<LLMStreamEvent> {
    throw new NotImplementedError("LLMGateway.stream — WS-B (provider adapters)");
  }
}

export function createLlmGateway(opts: CreateGatewayOptions): LLMGateway {
  return new StubLlmGateway(opts.config);
}
