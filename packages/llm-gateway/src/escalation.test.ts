import { describe, it, expect, vi } from "vitest";
import type { LLMRequest, ModelTier, Provider } from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import { getMetrics, type Logger } from "@montr/telemetry";
import { MontrLlmGateway, type CreateGatewayOptions } from "./gateway.js";
import { evaluateConfidence, type ConfidenceSignal } from "./escalation.js";
import { makeUsage, type AdapterCompletion, type ProviderAdapter } from "./adapters/index.js";

/**
 * Dynamic model-tier escalation (E9). The `triage`/`default`/`confirmation`
 * tier machinery has existed since day one but nothing used it ADAPTIVELY —
 * a layer's tier was fixed at call time. This suite covers both halves:
 * `evaluateConfidence`'s pure signal extraction (escalation.ts), and the
 * gateway's `complete()` wiring (gateway.ts) — escalating on low confidence,
 * NOT escalating on high confidence (cost control), the escalation cap, never
 * escalating past the top configured tier, and the OFF-by-default regression
 * guarantee.
 */

function spyLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn(() => logger),
  };
  return logger;
}

function baseConfig(overrides: Record<string, unknown> = {}): MontrConfig {
  return parseConfig({
    llm: { apiKey: "sk-test", provider: "anthropic", ...overrides },
  });
}

const noSleep = async () => {};

// Default modelMatrix (packages/config/src/schema.ts, from RECOMMENDED_MODEL_MATRIX).
const TRIAGE_MODEL = "claude-haiku-4-5";
const DEFAULT_MODEL = "claude-sonnet-5";
const CONFIRMATION_MODEL = "claude-opus-5";

function req(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return {
    messages: [{ role: "user", content: "hi" }],
    maxTokens: 64,
    metadata: { purpose: "triage" },
    responseFormat: "text",
    stream: false,
    ...overrides,
  } as LLMRequest;
}

/** Routes completion behavior by the resolved model id — one entry per tier. */
class TierRoutedFakeAdapter implements ProviderAdapter {
  calls: string[] = [];

  constructor(
    private readonly behavior: (modelId: string) => AdapterCompletion | Error,
    readonly provider: Provider = "anthropic",
  ) {}

  resolveModelId(modelId: string): string {
    return modelId;
  }

  async complete(_request: LLMRequest, modelId: string): Promise<AdapterCompletion> {
    this.calls.push(modelId);
    const outcome = this.behavior(modelId);
    if (outcome instanceof Error) throw outcome;
    return outcome;
  }

  // eslint-disable-next-line require-yield -- fake adapter's stream() is never exercised by these tests
  async *stream(): AsyncGenerator<never, void, unknown> {
    throw new Error("not used in these tests");
  }
}

function refusal(modelId: string): AdapterCompletion {
  return { id: "r", model: modelId, content: "", stopReason: "refusal", usage: makeUsage(10, 5) };
}

function unparseableJson(modelId: string): AdapterCompletion {
  return {
    id: "u",
    model: modelId,
    content: "not valid json {",
    stopReason: "end_turn",
    usage: makeUsage(10, 5),
  };
}

function confidentOk(modelId: string, content = "final answer"): AdapterCompletion {
  return { id: "ok", model: modelId, content, stopReason: "end_turn", usage: makeUsage(10, 5) };
}

function selfReportedConfidence(modelId: string, confidence: number): AdapterCompletion {
  return {
    id: "sr",
    model: modelId,
    content: JSON.stringify({ answer: "x", confidence }),
    stopReason: "end_turn",
    usage: makeUsage(10, 5),
  };
}

function makeGateway(
  adapter: ProviderAdapter,
  opts: Partial<CreateGatewayOptions> = {},
): MontrLlmGateway {
  return new MontrLlmGateway({
    config: opts.config ?? baseConfig(),
    adapter,
    sleep: noSleep,
    logger: spyLogger(),
    ...opts,
  }) as MontrLlmGateway;
}

describe("evaluateConfidence (E9 confidence-signal extraction)", () => {
  const THRESHOLD = 0.5;

  it("prefers a self-reported numeric confidence field in a JSON body", () => {
    const signal = evaluateConfidence(
      "json",
      JSON.stringify({ confidence: 0.3 }),
      "end_turn",
      THRESHOLD,
    );
    expect(signal).toEqual({ confidence: 0.3, low: true, source: "self_reported" });
  });

  it("treats a self-reported confidence AT/ABOVE threshold as high confidence", () => {
    const signal = evaluateConfidence(
      "json",
      JSON.stringify({ confidence: 0.5 }),
      "end_turn",
      THRESHOLD,
    );
    expect(signal.low).toBe(false);
    expect(signal.confidence).toBe(0.5);
  });

  it("maps a qualitative self-reported confidence string (low/medium/high)", () => {
    expect(
      evaluateConfidence("json", JSON.stringify({ confidence: "low" }), "end_turn", THRESHOLD).low,
    ).toBe(true);
    expect(
      evaluateConfidence("json", JSON.stringify({ confidence: "high" }), "end_turn", THRESHOLD).low,
    ).toBe(false);
  });

  it("falls back to the refusal proxy signal when stopReason is 'refusal'", () => {
    const signal = evaluateConfidence("text", "", "refusal", THRESHOLD);
    expect(signal).toEqual({ low: true, source: "refusal" });
  });

  it("falls back to the unparseable-JSON proxy signal in JSON mode with no self-reported field", () => {
    const signal = evaluateConfidence("json", "not valid json {", "end_turn", THRESHOLD);
    expect(signal).toEqual({ low: true, source: "unparseable_json" });
  });

  it("is high-confidence (source: none) for a normal, valid, non-refusal response", () => {
    const signal = evaluateConfidence("json", '{"ok":true}', "end_turn", THRESHOLD);
    expect(signal).toEqual({ low: false, source: "none" });
  });

  it("is high-confidence (source: none) for normal text-mode content", () => {
    const signal = evaluateConfidence("text", "a perfectly ordinary answer", "end_turn", THRESHOLD);
    expect(signal).toEqual({ low: false, source: "none" });
  });

  it("ignores an out-of-range or malformed self-reported confidence value and falls through to proxy signals", () => {
    // confidence: 5 is out of [0,1] — coerceReportedConfidence rejects it, so this
    // falls through to the proxy checks; end_turn + valid JSON ⇒ high confidence.
    const signal = evaluateConfidence(
      "json",
      JSON.stringify({ confidence: 5 }),
      "end_turn",
      THRESHOLD,
    );
    expect(signal).toEqual({ low: false, source: "none" });
  });
});

describe("gateway.complete() escalation is OFF by default (regression safety)", () => {
  it("does NOT escalate, and never populates response.confidence, when escalation isn't configured — even on a refusal", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => refusal(modelId));
    const gateway = makeGateway(adapter); // no `escalation` option at all
    const response = await gateway.complete(req({ tier: "triage" }));
    expect(adapter.calls).toEqual([TRIAGE_MODEL]);
    expect(response.confidence).toBeUndefined();
  });

  it("does NOT escalate when escalation.enabled is explicitly false", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => refusal(modelId));
    const gateway = makeGateway(adapter, { escalation: { enabled: false } });
    const response = await gateway.complete(req({ tier: "triage" }));
    expect(adapter.calls).toEqual([TRIAGE_MODEL]);
    expect(response.confidence).toBeUndefined();
  });
});

describe("gateway.complete() escalation (E9, opted in)", () => {
  it("escalates triage → default on a low-confidence (refusal) triage response, and returns the escalated response", async () => {
    const logger = spyLogger();
    const adapter = new TierRoutedFakeAdapter((modelId) =>
      modelId === TRIAGE_MODEL ? refusal(modelId) : confidentOk(modelId, "default tier answer"),
    );
    const gateway = makeGateway(adapter, { logger, escalation: { enabled: true } });

    const response = await gateway.complete(req({ tier: "triage" }));

    expect(adapter.calls).toEqual([TRIAGE_MODEL, DEFAULT_MODEL]);
    expect(response.content).toBe("default tier answer");
    expect(response.model).toBe(DEFAULT_MODEL);
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.model_escalation",
      expect.objectContaining({ fromTier: "triage", toTier: "default", reason: "refusal" }),
    );
  });

  it("escalates all the way to confirmation when both triage and default stay low-confidence", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) =>
      modelId === CONFIRMATION_MODEL
        ? confidentOk(modelId, "confirmation tier answer")
        : refusal(modelId),
    );
    const gateway = makeGateway(adapter, { escalation: { enabled: true, maxEscalations: 2 } });

    const response = await gateway.complete(req({ tier: "triage" }));

    expect(adapter.calls).toEqual([TRIAGE_MODEL, DEFAULT_MODEL, CONFIRMATION_MODEL]);
    expect(response.content).toBe("confirmation tier answer");
  });

  it("does NOT escalate on a high-confidence response (cost control) — exactly one gateway call", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => confidentOk(modelId, "good enough"));
    const gateway = makeGateway(adapter, { escalation: { enabled: true } });

    const response = await gateway.complete(req({ tier: "triage" }));

    expect(adapter.calls).toEqual([TRIAGE_MODEL]);
    expect(response.content).toBe("good enough");
  });

  it("uses self-reported confidence over the proxy signals when present, and attaches it to the returned response", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) =>
      modelId === TRIAGE_MODEL
        ? selfReportedConfidence(modelId, 0.1)
        : selfReportedConfidence(modelId, 0.95),
    );
    const gateway = makeGateway(adapter, {
      escalation: { enabled: true, confidenceThreshold: 0.5 },
    });

    const response = await gateway.complete(req({ tier: "triage", responseFormat: "json" }));

    expect(adapter.calls).toEqual([TRIAGE_MODEL, DEFAULT_MODEL]);
    expect(response.confidence).toBe(0.95);
  });

  it("enforces the escalation cap: stops after maxEscalations even if the response is still low-confidence", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => refusal(modelId)); // every tier refuses
    const gateway = makeGateway(adapter, { escalation: { enabled: true, maxEscalations: 1 } });

    const response = await gateway.complete(req({ tier: "triage" }));

    // 1 initial (triage) + 1 escalation (default) = 2 calls, capped before reaching confirmation.
    expect(adapter.calls).toEqual([TRIAGE_MODEL, DEFAULT_MODEL]);
    expect(response.model).toBe(DEFAULT_MODEL);
  });

  it("never escalates past the top configured tier (confirmation), even with escalation budget remaining", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => refusal(modelId)); // every tier refuses
    const gateway = makeGateway(adapter, { escalation: { enabled: true, maxEscalations: 10 } });

    const response = await gateway.complete(req({ tier: "confirmation" }));

    // Already at the top tier — nextTier("confirmation") is undefined, so no escalation happens.
    expect(adapter.calls).toEqual([CONFIRMATION_MODEL]);
    expect(response.model).toBe(CONFIRMATION_MODEL);
  });

  it("does NOT escalate a request pinned to an explicit model, even on low confidence", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => refusal(modelId));
    const gateway = makeGateway(adapter, { escalation: { enabled: true } });

    const response = await gateway.complete(req({ model: "claude-haiku-4-5" }));

    expect(adapter.calls).toEqual(["claude-haiku-4-5"]);
    expect(response.model).toBe("claude-haiku-4-5");
  });

  it("does NOT escalate a request with neither an explicit tier nor an explicit model", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) => refusal(modelId));
    const gateway = makeGateway(adapter, { escalation: { enabled: true } });

    // No `tier` field at all ⇒ resolveModelId defaults to "default" internally,
    // but `isEligibleForEscalation` requires an EXPLICIT `tier` on the request.
    const response = await gateway.complete(req());

    expect(adapter.calls).toEqual([DEFAULT_MODEL]);
    expect(response.model).toBe(DEFAULT_MODEL);
  });

  it("also escalates on the unparseable-JSON proxy signal", async () => {
    const adapter = new TierRoutedFakeAdapter((modelId) =>
      modelId === TRIAGE_MODEL ? unparseableJson(modelId) : confidentOk(modelId, "{}"),
    );
    const gateway = makeGateway(adapter, { escalation: { enabled: true } });

    const response = await gateway.complete(req({ tier: "triage", responseFormat: "json" }));

    expect(adapter.calls).toEqual([TRIAGE_MODEL, DEFAULT_MODEL]);
    expect(response.model).toBe(DEFAULT_MODEL);
  });

  it("invokes onEscalate and records the llm_gateway.model_escalation metric", async () => {
    const onEscalate = vi.fn();
    const adapter = new TierRoutedFakeAdapter((modelId) =>
      modelId === TRIAGE_MODEL ? refusal(modelId) : confidentOk(modelId),
    );
    const gateway = makeGateway(adapter, { escalation: { enabled: true, onEscalate } });

    const before = getMetrics().snapshot().errors;
    await gateway.complete(req({ tier: "triage" }));
    const after = getMetrics().snapshot().errors;

    expect(after).toBeGreaterThan(before);
    expect(onEscalate).toHaveBeenCalledWith(
      "triage" as ModelTier,
      "default" as ModelTier,
      expect.objectContaining({ source: "refusal" } satisfies Partial<ConfidenceSignal>),
    );
  });

  it("escalation composes with the existing retry policy: a retried-then-succeeding triage call that is still low-confidence still escalates", async () => {
    let triageAttempts = 0;
    const adapter = new TierRoutedFakeAdapter((modelId) => {
      if (modelId === TRIAGE_MODEL) {
        triageAttempts++;
        // First triage attempt is a retriable failure; second succeeds but refuses.
        if (triageAttempts === 1) return Object.assign(new Error("rate limited"), { status: 429 });
        return refusal(modelId);
      }
      return confidentOk(modelId, "default tier answer");
    });
    const gateway = makeGateway(adapter, {
      maxRetries: 2,
      escalation: { enabled: true },
    });

    const response = await gateway.complete(req({ tier: "triage" }));

    expect(adapter.calls).toEqual([TRIAGE_MODEL, TRIAGE_MODEL, DEFAULT_MODEL]);
    expect(response.content).toBe("default tier answer");
  });
});
