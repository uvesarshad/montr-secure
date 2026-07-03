import { describe, it, expect } from "vitest";
import {
  isMontrError,
  LLMRequestSchema,
  MODEL_FLOOR,
  type LLMRequest,
  type Provider,
} from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import { createNullLogger, type Logger, type LogFields } from "@montr/telemetry";
import {
  applyKeyTierGuard,
  createLlmGateway,
  detectKeyTier,
  isBelowFloor,
  makeUsage,
  MontrLlmGateway,
  type ProviderAdapter,
} from "@montr/llm-gateway";

const NOW = () => new Date("2026-07-02T00:00:00.000Z");

function adapter(provider: Provider): ProviderAdapter {
  return {
    provider,
    resolveModelId: (m) => m,
    complete: async (_req, modelId) => ({
      id: "x",
      model: modelId,
      content: "hi",
      stopReason: "end_turn",
      usage: makeUsage(5, 5),
    }),
    stream: async function* () {
      yield { type: "message_done", usage: makeUsage(5, 5), stopReason: "end_turn" };
    },
  };
}

function captureLogger(sink: Array<{ msg: string; fields: LogFields }>): Logger {
  const make = (): Logger => ({
    debug: (msg, fields) => sink.push({ msg, fields: fields ?? {} }),
    info: (msg, fields) => sink.push({ msg, fields: fields ?? {} }),
    warn: (msg, fields) => sink.push({ msg, fields: fields ?? {} }),
    error: (msg, fields) => sink.push({ msg, fields: fields ?? {} }),
    child: () => make(),
  });
  return make();
}

function config(over: Record<string, unknown> = {}): MontrConfig {
  return parseConfig({ llm: { apiKey: "sk-test", ...over } });
}

const REQ: LLMRequest = LLMRequestSchema.parse({
  messages: [{ role: "user", content: "x" }],
  maxTokens: 64,
  metadata: { purpose: "confirmation" },
});

describe("⛔ key-tier guard (§11)", () => {
  it("classifies cloud providers as enterprise and Anthropic-direct as unknown", () => {
    expect(detectKeyTier({ provider: "bedrock" })).toBe("enterprise");
    expect(detectKeyTier({ provider: "vertex" })).toBe("enterprise");
    expect(detectKeyTier({ provider: "azure" })).toBe("enterprise");
    expect(detectKeyTier({ provider: "anthropic" })).toBe("unknown");
    expect(detectKeyTier({ provider: "anthropic", declaredTier: "enterprise" })).toBe("enterprise");
  });

  it("classifies consumer/CN providers as data_retaining unless declared enterprise", () => {
    expect(detectKeyTier({ provider: "moonshot" })).toBe("data_retaining");
    expect(detectKeyTier({ provider: "zhipu" })).toBe("data_retaining");
    expect(detectKeyTier({ provider: "deepseek" })).toBe("data_retaining");
    // A direct OpenAI/Google/xAI key is unknown (warned), not auto-data-retaining.
    expect(detectKeyTier({ provider: "openai" })).toBe("unknown");
    expect(detectKeyTier({ provider: "xai" })).toBe("unknown");
    // The operator can attest a zero-retention deal to override.
    expect(detectKeyTier({ provider: "deepseek", declaredTier: "enterprise" })).toBe("enterprise");
  });

  it("warn mode allows but flags a suspect tier; block mode throws", () => {
    expect(applyKeyTierGuard("unknown", "warn", "anthropic").action).toBe("warned");
    expect(() => applyKeyTierGuard("unknown", "block", "anthropic")).toThrow();
    expect(applyKeyTierGuard("enterprise", "block", "bedrock").action).toBe("allowed");
    expect(applyKeyTierGuard("unknown", "off", "anthropic").action).toBe("allowed");
  });

  it("BLOCKS data_retaining even under warn mode; only off (or enterprise) allows it", () => {
    // "block by default" for retention-risky providers regardless of warn/block config.
    expect(() => applyKeyTierGuard("data_retaining", "warn", "moonshot")).toThrow();
    expect(() => applyKeyTierGuard("data_retaining", "block", "zhipu")).toThrow();
    // An explicit `off` (operator accepts the risk) still disables the guard.
    expect(applyKeyTierGuard("data_retaining", "off", "deepseek").action).toBe("allowed");
    // Declaring enterprise removes the suspect classification entirely.
    expect(applyKeyTierGuard("enterprise", "warn", "moonshot").action).toBe("allowed");
  });

  it("block policy rejects an unknown-tier Anthropic key at construction", () => {
    expect(() =>
      createLlmGateway({
        config: config({ keyTierGuard: "block" }),
        adapter: adapter("anthropic"),
        logger: createNullLogger(),
        now: NOW,
      }),
    ).toThrow();
  });

  it("block policy allows an enterprise cloud key; declaredKeyTier overrides", () => {
    expect(() =>
      createLlmGateway({
        config: config({ provider: "bedrock", keyTierGuard: "block" }),
        adapter: adapter("bedrock"),
        logger: createNullLogger(),
        now: NOW,
      }),
    ).not.toThrow();

    const gw = new MontrLlmGateway({
      config: config({ keyTierGuard: "block" }),
      adapter: adapter("anthropic"),
      declaredKeyTier: "enterprise",
      logger: createNullLogger(),
      now: NOW,
    });
    expect(gw.keyTier).toBe("enterprise");
  });
});

describe("model floor (DECIDE-3)", () => {
  it("ranks Haiku below the Sonnet-5 confirmation floor", () => {
    expect(isBelowFloor("claude-haiku-4-5")).toBe(true);
    expect(isBelowFloor(MODEL_FLOOR.confirmationTier.minModelId)).toBe(false);
    expect(isBelowFloor("claude-opus-4-8")).toBe(false);
    // Unrecognized (non-Claude BYO) models are not flagged.
    expect(isBelowFloor("gpt-4o")).toBe(false);
  });

  it("warns at construction when the configured confirmation model is sub-floor", () => {
    const sink: Array<{ msg: string; fields: LogFields }> = [];
    createLlmGateway({
      config: config({
        modelMatrix: {
          triage: "claude-haiku-4-5",
          default: "claude-sonnet-5",
          confirmation: "claude-haiku-4-5",
        },
      }),
      adapter: adapter("anthropic"),
      logger: captureLogger(sink),
      now: NOW,
    });
    expect(sink.some((e) => e.msg === "llm.model_below_floor")).toBe(true);
  });

  it("strictModelFloor throws ModelBelowFloorError instead of warning", () => {
    let err: unknown;
    try {
      createLlmGateway({
        config: config({
          modelMatrix: {
            triage: "claude-haiku-4-5",
            default: "claude-sonnet-5",
            confirmation: "claude-haiku-4-5",
          },
        }),
        adapter: adapter("anthropic"),
        strictModelFloor: true,
        logger: createNullLogger(),
        now: NOW,
      });
    } catch (e) {
      err = e;
    }
    expect(isMontrError(err) && err.code).toBe("MODEL_BELOW_FLOOR");
  });

  it("warns once per below-floor model on a confirmation-purpose call", async () => {
    const sink: Array<{ msg: string; fields: LogFields }> = [];
    const gw = createLlmGateway({
      config: config(), // confirmation = sonnet-5 (at floor): no construction warning
      adapter: adapter("anthropic"),
      logger: captureLogger(sink),
      now: NOW,
    });
    // Override the model to a sub-floor one for a confirmation call.
    const belowFloorReq = LLMRequestSchema.parse({
      model: "claude-haiku-4-5",
      messages: [{ role: "user", content: "x" }],
      maxTokens: 64,
      metadata: { purpose: "confirmation" },
    });
    await gw.complete(belowFloorReq);
    await gw.complete(belowFloorReq);
    expect(sink.filter((e) => e.msg === "llm.model_below_floor").length).toBe(1);
    void REQ;
  });
});
