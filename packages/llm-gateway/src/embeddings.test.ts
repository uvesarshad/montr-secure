import { describe, it, expect } from "vitest";
import { parseConfig, type MontrConfig } from "@montr/config";
import {
  createEmbeddingAdapter,
  AzureEmbeddingAdapter,
  type AzureEmbeddingClientLike,
  type EmbeddingRequest,
} from "./embeddings.js";

/**
 * Embeddings capability (E5) round-trip coverage: request -> provider wire
 * payload -> parsed response, offline with an injected client — same pattern
 * as adapters/egress.test.ts and adapters/capabilities.test.ts. Also covers
 * the documented per-provider capability gap (Anthropic/Bedrock/Vertex throw
 * NotImplementedError today — see embeddings.ts's doc comment).
 */

function cfg(provider: MontrConfig["llm"]["provider"] = "azure"): MontrConfig {
  return parseConfig({
    llm: {
      apiKey: "sk-test",
      provider,
      ...(provider === "azure" ? { endpoint: "https://x.openai.azure.com" } : {}),
    },
  });
}

function req(input: string[]): EmbeddingRequest {
  return { input, model: "text-embedding-3-small", metadata: { purpose: "semantic_index_build" } };
}

describe("AzureEmbeddingAdapter", () => {
  it("builds the OpenAI-shaped embeddings request and parses the vectors back in order", async () => {
    let capturedBody: unknown;
    const client: AzureEmbeddingClientLike = {
      embeddings: {
        create: async (body) => {
          capturedBody = body;
          return {
            model: "text-embedding-3-small",
            data: [{ embedding: [0.1, 0.2] }, { embedding: [0.3, 0.4] }],
            usage: { prompt_tokens: 12, total_tokens: 12 },
          };
        },
      },
    };
    const adapter = new AzureEmbeddingAdapter({ config: cfg(), client });
    const result = await adapter.embed(req(["const a = 1;", "function b() {}"]));

    expect(capturedBody).toEqual({
      model: "text-embedding-3-small",
      input: ["const a = 1;", "function b() {}"],
    });
    expect(result.embeddings).toEqual([
      [0.1, 0.2],
      [0.3, 0.4],
    ]);
    expect(result.model).toBe("text-embedding-3-small");
    expect(result.usage.inputTokens).toBe(12);
  });

  it("returns an empty result without calling the provider for empty input", async () => {
    let called = false;
    const client: AzureEmbeddingClientLike = {
      embeddings: {
        create: async () => {
          called = true;
          return { data: [] };
        },
      },
    };
    const adapter = new AzureEmbeddingAdapter({ config: cfg(), client });
    const result = await adapter.embed(req([]));

    expect(called).toBe(false);
    expect(result.embeddings).toEqual([]);
  });

  it("throws when the provider returns a vector count mismatched with the input count", async () => {
    const client: AzureEmbeddingClientLike = {
      embeddings: {
        create: async () => ({ data: [{ embedding: [0.1] }] }),
      },
    };
    const adapter = new AzureEmbeddingAdapter({ config: cfg(), client });
    await expect(adapter.embed(req(["a", "b"]))).rejects.toThrow(/returned 1 vectors/);
  });

  it("asserts egress against the configured endpoint before dispatch", async () => {
    const targets: string[] = [];
    const client: AzureEmbeddingClientLike = {
      embeddings: { create: async () => ({ data: [{ embedding: [0.1] }] }) },
    };
    const adapter = new AzureEmbeddingAdapter({
      config: cfg(),
      client,
      egress: { assert: (t) => targets.push(t) },
    });
    await adapter.embed(req(["a"]));
    expect(targets).toEqual(["https://x.openai.azure.com"]);
  });
});

describe("createEmbeddingAdapter — provider capability gate", () => {
  it("returns an AzureEmbeddingAdapter for azure", () => {
    const adapter = createEmbeddingAdapter("azure", cfg("azure"));
    expect(adapter.provider).toBe("azure");
    expect(adapter).toBeInstanceOf(AzureEmbeddingAdapter);
  });

  it.each(["anthropic", "bedrock", "vertex"] as const)(
    "throws NotImplementedError for %s (documented follow-up — see embeddings.ts)",
    async (provider) => {
      const adapter = createEmbeddingAdapter(provider, cfg(provider));
      expect(adapter.provider).toBe(provider);
      await expect(adapter.embed(req(["a"]))).rejects.toThrow(/not implemented/i);
    },
  );
});
