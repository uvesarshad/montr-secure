import {
  LLMResponseSchema,
  RECOMMENDED_MODEL_MATRIX,
  type HttpExchange,
  type LLMGateway,
  type LLMPurpose,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type ModelDescriptor,
  type ModelTier,
} from "@montr/contracts";

/**
 * Deterministic FAKE LLM adapter for offline tests. Implements the real
 * @montr/contracts LLMGateway interface with canned, reproducible responses.
 * NO provider SDK, no network, no Date.now()/random.
 */

function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/** Deterministic FNV-1a hash (hex) — used for stable fake message ids. */
function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

const DESCRIPTORS: ModelDescriptor[] = [
  {
    provider: "anthropic",
    modelId: RECOMMENDED_MODEL_MATRIX.triage.modelId,
    tier: "triage",
    contextWindow: 200_000,
    maxOutputTokens: 64_000,
    supportsTools: true,
    supportsStreaming: true,
    belowFloor: true,
  },
  {
    provider: "anthropic",
    modelId: RECOMMENDED_MODEL_MATRIX.default.modelId,
    tier: "default",
    contextWindow: 1_000_000,
    maxOutputTokens: 128_000,
    supportsTools: true,
    supportsStreaming: true,
    belowFloor: false,
  },
  {
    provider: "anthropic",
    modelId: RECOMMENDED_MODEL_MATRIX.confirmation.modelId,
    tier: "confirmation",
    contextWindow: 1_000_000,
    maxOutputTokens: 128_000,
    supportsTools: true,
    supportsStreaming: true,
    belowFloor: false,
  },
];

export interface FakeLlmOptions {
  /** Canned response text keyed by call purpose. */
  cannedByPurpose?: Partial<Record<LLMPurpose, string>>;
  /** Fallback response text when no purpose-specific canned response is set. */
  defaultResponse?: string;
}

export class FakeLlmAdapter implements LLMGateway {
  constructor(private readonly options: FakeLlmOptions = {}) {}

  resolveModel(tierOrId: ModelTier | string): ModelDescriptor {
    const byTier = DESCRIPTORS.find((d) => d.tier === tierOrId);
    if (byTier) return byTier;
    const byId = DESCRIPTORS.find((d) => d.modelId === tierOrId);
    if (byId) return byId;
    return DESCRIPTORS[1] as ModelDescriptor; // default tier fallback
  }

  listModels(): ModelDescriptor[] {
    return [...DESCRIPTORS];
  }

  private pick(request: LLMRequest): string {
    const purpose = request.metadata.purpose;
    const canned = this.options.cannedByPurpose?.[purpose];
    if (canned !== undefined) return canned;
    if (request.responseFormat === "json") return "{}";
    return this.options.defaultResponse ?? "FAKE_LLM_RESPONSE";
  }

  complete(request: LLMRequest): Promise<LLMResponse> {
    const modelId = request.model ?? this.resolveModel(request.tier ?? "default").modelId;
    const content = this.pick(request);
    const promptText = (request.system ?? "") + JSON.stringify(request.messages);
    const inputTokens = estimateTokens(promptText);
    const outputTokens = estimateTokens(content);
    const response: LLMResponse = {
      id: `fake_${fnv1a(promptText + request.metadata.purpose)}`,
      provider: "anthropic",
      model: modelId,
      content,
      stopReason: "end_turn",
      usage: { inputTokens, outputTokens, totalTokens: inputTokens + outputTokens },
      latencyMs: 42,
    };
    return Promise.resolve(response);
  }

  async *stream(request: LLMRequest): AsyncGenerator<LLMStreamEvent, void, unknown> {
    const response = await this.complete(request);
    yield { type: "text_delta", text: response.content };
    yield { type: "message_done", usage: response.usage, stopReason: response.stopReason };
  }

  estimateTokens(request: LLMRequest): Promise<number> {
    const promptText = (request.system ?? "") + JSON.stringify(request.messages);
    return Promise.resolve(estimateTokens(promptText));
  }
}

/** Ready-made fake gateway with canned per-purpose responses for the pipeline. */
export function createFakeLlmGateway(options: FakeLlmOptions = {}): LLMGateway {
  return new FakeLlmAdapter({
    cannedByPurpose: {
      appmap_labeling: '{"authBoundaries":[{"route":"/api/users","authState":"public"}]}',
      triage: '{"keep":true,"reason":"reachable public sink"}',
      correlation:
        '{"rank":1,"reachabilityScore":0.95,"exposureScore":1,"impactScore":0.9,"hypothesis":"tainted q reaches raw query"}',
      confirmation: '{"confirmed":true,"proofType":"static","argument":"tainted q reaches sink"}',
      fix_generation:
        '{"patch":"...","rationale":"parameterize query","riskClass":"auto-eligible"}',
      report_synthesis: '{"summary":"2 confirmed findings"}',
      ...options.cannedByPurpose,
    },
    defaultResponse: options.defaultResponse ?? "FAKE_LLM_RESPONSE",
  });
}

/** A single, validated sample LLM response. */
export const mockLlmResponse: LLMResponse = LLMResponseSchema.parse({
  id: "fake_deadbeef",
  provider: "anthropic",
  model: RECOMMENDED_MODEL_MATRIX.default.modelId,
  content: '{"confirmed":true}',
  stopReason: "end_turn",
  usage: { inputTokens: 1200, outputTokens: 40, totalTokens: 1240 },
  latencyMs: 42,
});

/** A DAST request/response transcript fixture (live-proof shape). */
export const mockDastTranscript: HttpExchange[] = [
  {
    request: {
      method: "GET",
      url: "https://staging.example.internal/api/users?q=%27%20OR%20%271%27%3D%271",
      headers: { accept: "application/json" },
    },
    response: {
      status: 200,
      bodySnippet: '[{"id":1},{"id":2},{"id":3}] (all rows returned)',
    },
    note: "Boolean-based SQLi returned the full table against the authorized staging target.",
  },
];
