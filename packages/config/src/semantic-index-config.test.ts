import { describe, it, expect } from "vitest";
import { parseConfig, loadConfig } from "./loader.js";
import { getHardenedDefaults, SemanticIndexConfigSchema } from "./schema.js";

/**
 * A9 — semantic codebase index config (opt-in, OFF by default). See
 * `SemanticIndexConfigSchema`'s doc comment (packages/config/src/schema.ts)
 * and apps/worker/src/main.ts's `resolveSemanticIndexOptions`, which this
 * config gates, alongside packages/appmap/src/build.ts's `semanticIndex`
 * Layer 0 build hook and packages/confirm/src/investigate.ts's
 * `semantic_search` investigation tool.
 */

describe("SemanticIndexConfigSchema defaults (A9)", () => {
  it("defaults to disabled with the Azure text-embedding-3-small model id", () => {
    const parsed = SemanticIndexConfigSchema.parse({});
    expect(parsed).toEqual({ enabled: false, embeddingModel: "text-embedding-3-small" });
  });

  it("the hardened baseline config carries the same off-by-default semantic-index config", () => {
    const defaults = getHardenedDefaults();
    expect(defaults.semanticIndex).toEqual({
      enabled: false,
      embeddingModel: "text-embedding-3-small",
    });
  });

  it("rejects an empty embeddingModel", () => {
    expect(() => SemanticIndexConfigSchema.parse({ embeddingModel: "" })).toThrow();
  });

  it("accepts an explicit enabled config with a custom model id", () => {
    const parsed = SemanticIndexConfigSchema.parse({
      enabled: true,
      embeddingModel: "text-embedding-3-large",
    });
    expect(parsed).toEqual({ enabled: true, embeddingModel: "text-embedding-3-large" });
  });
});

describe("loadConfig — MONTR_SEMANTIC_INDEX_* env overlay (A9)", () => {
  it("leaves the semantic-index config at its off-by-default values when unset (regression safety)", () => {
    const config = parseConfig({});
    expect(config.semanticIndex).toEqual({
      enabled: false,
      embeddingModel: "text-embedding-3-small",
    });
  });

  it("MONTR_SEMANTIC_INDEX_ENABLED=true flips semanticIndex.enabled on", () => {
    const config = loadConfig({ env: { MONTR_SEMANTIC_INDEX_ENABLED: "true" } });
    expect(config.semanticIndex.enabled).toBe(true);
  });

  it("MONTR_SEMANTIC_INDEX_EMBEDDING_MODEL overrides the model id", () => {
    const config = loadConfig({
      env: {
        MONTR_SEMANTIC_INDEX_ENABLED: "true",
        MONTR_SEMANTIC_INDEX_EMBEDDING_MODEL: "text-embedding-3-large",
      },
    });
    expect(config.semanticIndex).toEqual({
      enabled: true,
      embeddingModel: "text-embedding-3-large",
    });
  });

  it("an unset MONTR_SEMANTIC_INDEX_* env leaves the rest of the config untouched", () => {
    const config = loadConfig({ env: { MONTR_CLIENT_ID: "acme" } });
    expect(config.clientId).toBe("acme");
    expect(config.semanticIndex).toEqual({
      enabled: false,
      embeddingModel: "text-embedding-3-small",
    });
  });
});
