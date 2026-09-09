import { describe, it, expect } from "vitest";
import {
  ProviderSchema,
  ModelTierSchema,
  KeyTierSchema,
  TokenUsageSchema,
  LLMRequestSchema,
  LLMCallMetadataSchema,
  ModelDescriptorSchema,
  MODEL_FLOOR,
  RECOMMENDED_MODEL_MATRIX,
} from "./llm.js";

/**
 * The LLM gateway interface (§8.2). `KeyTierSchema` directly backs the
 * ⛔ key-tier guard (@montr/llm-gateway) that warns/blocks suspected
 * data-retaining keys — a safety-critical enum. `LLMRequestSchema` is the
 * single entry point every gateway call validates against.
 */

describe("ProviderSchema / ModelTierSchema", () => {
  it("Provider accepts the original four BYO-key providers", () => {
    for (const p of ["anthropic", "bedrock", "vertex", "azure"]) {
      expect(ProviderSchema.parse(p)).toBe(p);
    }
  });

  it("Provider accepts the six A3 OpenAI-compatible providers", () => {
    for (const p of ["openai", "google", "xai", "moonshot", "zhipu", "deepseek"]) {
      expect(ProviderSchema.parse(p)).toBe(p);
    }
  });

  it("Provider rejects an unsupported provider", () => {
    expect(() => ProviderSchema.parse("mistral")).toThrow();
  });

  it("ModelTier accepts triage/default/confirmation and rejects others", () => {
    for (const t of ["triage", "default", "confirmation"]) {
      expect(ModelTierSchema.parse(t)).toBe(t);
    }
    expect(() => ModelTierSchema.parse("premium")).toThrow();
  });
});

describe("KeyTierSchema (⛔ key-tier guard classification)", () => {
  it("accepts enterprise, unknown, data_retaining", () => {
    for (const t of ["enterprise", "unknown", "data_retaining"]) {
      expect(KeyTierSchema.parse(t)).toBe(t);
    }
  });

  it("rejects an unrecognized tier", () => {
    expect(() => KeyTierSchema.parse("personal")).toThrow();
  });
});

describe("TokenUsageSchema", () => {
  it("accepts usage with only required fields", () => {
    const usage = { inputTokens: 10, outputTokens: 5, totalTokens: 15 };
    expect(TokenUsageSchema.parse(usage)).toEqual(usage);
  });

  it("accepts usage with optional cache token fields", () => {
    const usage = {
      inputTokens: 10,
      outputTokens: 5,
      totalTokens: 15,
      cacheReadTokens: 3,
      cacheWriteTokens: 1,
    };
    expect(TokenUsageSchema.parse(usage)).toEqual(usage);
  });

  it("rejects negative token counts", () => {
    expect(() =>
      TokenUsageSchema.parse({ inputTokens: -1, outputTokens: 5, totalTokens: 4 }),
    ).toThrow();
  });

  it("rejects non-integer token counts", () => {
    expect(() =>
      TokenUsageSchema.parse({ inputTokens: 1.5, outputTokens: 5, totalTokens: 6.5 }),
    ).toThrow();
  });
});

describe("LLMRequestSchema (single validated entry point into the gateway)", () => {
  const base = {
    messages: [{ role: "user", content: "hi" }],
    maxTokens: 100,
    metadata: { purpose: "triage" },
  };

  it("accepts a minimal request, applying defaults (responseFormat/stream)", () => {
    const parsed = LLMRequestSchema.parse(base);
    expect(parsed.responseFormat).toBe("text");
    expect(parsed.stream).toBe(false);
  });

  it("rejects an empty messages array (min(1))", () => {
    expect(() => LLMRequestSchema.parse({ ...base, messages: [] })).toThrow();
  });

  it("rejects a non-positive maxTokens", () => {
    expect(() => LLMRequestSchema.parse({ ...base, maxTokens: 0 })).toThrow();
  });

  it("rejects a temperature outside [0, 2]", () => {
    expect(() => LLMRequestSchema.parse({ ...base, temperature: 2.5 })).toThrow();
  });

  it("rejects a missing metadata.purpose", () => {
    expect(() => LLMRequestSchema.parse({ ...base, metadata: {} })).toThrow();
  });

  it("rejects an invalid message role", () => {
    expect(() =>
      LLMRequestSchema.parse({ ...base, messages: [{ role: "narrator", content: "x" }] }),
    ).toThrow();
  });

  it("accepts structured text-block content as an alternative to a plain string", () => {
    const req = {
      ...base,
      messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }],
    };
    expect(LLMRequestSchema.parse(req).messages[0]!.content).toEqual([
      { type: "text", text: "hi" },
    ]);
  });
});

describe("LLMCallMetadataSchema", () => {
  it("requires 'purpose' but leaves scanId/clientId/layer optional", () => {
    expect(LLMCallMetadataSchema.parse({ purpose: "confirmation" })).toEqual({
      purpose: "confirmation",
    });
  });

  it("rejects an invalid purpose", () => {
    expect(() => LLMCallMetadataSchema.parse({ purpose: "chit_chat" })).toThrow();
  });

  it("rejects an invalid layer id", () => {
    expect(() => LLMCallMetadataSchema.parse({ purpose: "triage", layer: "layer9" })).toThrow();
  });
});

describe("ModelDescriptorSchema", () => {
  const base = {
    provider: "anthropic",
    modelId: "claude-sonnet-5",
    tier: "default",
    contextWindow: 1_000_000,
    maxOutputTokens: 64_000,
  };

  it("defaults supportsTools/supportsStreaming to true and belowFloor to false", () => {
    const parsed = ModelDescriptorSchema.parse(base);
    expect(parsed.supportsTools).toBe(true);
    expect(parsed.supportsStreaming).toBe(true);
    expect(parsed.belowFloor).toBe(false);
  });

  it("rejects a non-positive contextWindow", () => {
    expect(() => ModelDescriptorSchema.parse({ ...base, contextWindow: 0 })).toThrow();
  });
});

describe("MODEL_FLOOR / RECOMMENDED_MODEL_MATRIX (DECIDE-3 reference data)", () => {
  it("defines a confirmation-tier floor model id", () => {
    expect(MODEL_FLOOR.confirmationTier.minModelId).toBe("claude-sonnet-5");
  });

  it("defines a recommended model for every tier", () => {
    for (const tier of ["triage", "default", "confirmation"] as const) {
      expect(RECOMMENDED_MODEL_MATRIX[tier].modelId.length).toBeGreaterThan(0);
    }
  });

  it("pins the confirmation tier to the current flagship claude-opus-5 (A11)", () => {
    expect(RECOMMENDED_MODEL_MATRIX.confirmation.modelId).toBe("claude-opus-5");
  });

  it("pins the triage tier to the undated claude-haiku-4-5 (A11)", () => {
    expect(RECOMMENDED_MODEL_MATRIX.triage.modelId).toBe("claude-haiku-4-5");
  });
});
