/**
 * embedChunks (E5) — request/response shape against a mocked embeddings
 * adapter (the adapter's own wire mapping is covered by
 * packages/llm-gateway/src/embeddings.test.ts; this tests the batching +
 * per-chunk assembly logic on top of it).
 */
import { describe, expect, it } from "vitest";
import type { EmbeddingProviderAdapter, EmbeddingRequest } from "@montr/llm-gateway";
import { DEFAULT_EMBED_BATCH_SIZE, embedChunks } from "./embed.js";
import type { CodeChunkDraft } from "./types.js";

function draft(id: string, content = `content-${id}`): CodeChunkDraft {
  return {
    file: `src/${id}.ts`,
    startLine: 1,
    endLine: 3,
    language: "typescript",
    kind: "function",
    symbolName: id,
    content,
    contentHash: `hash-${id}`,
  };
}

function fakeAdapter(onRequest?: (req: EmbeddingRequest) => void): EmbeddingProviderAdapter {
  return {
    provider: "azure",
    embed: async (req) => {
      onRequest?.(req);
      return {
        embeddings: req.input.map((text) => [text.length, 1, 2]),
        model: "text-embedding-3-small",
        usage: { inputTokens: req.input.length * 4 },
      };
    },
  };
}

describe("embedChunks", () => {
  it("returns one embedded chunk per input, preserving content + attaching the model id", async () => {
    const chunks = [draft("a"), draft("b")];
    const result = await embedChunks(fakeAdapter(), "text-embedding-3-small", chunks, {
      metadata: { purpose: "semantic_index_build" },
    });

    expect(result).toHaveLength(2);
    expect(result.map((c) => c.symbolName).sort()).toEqual(["a", "b"]);
    expect(result[0]?.embeddingModel).toBe("text-embedding-3-small");
    expect(result.find((c) => c.symbolName === "a")?.embedding).toEqual(["content-a".length, 1, 2]);
  });

  it("batches requests at the configured batch size", async () => {
    const requestSizes: number[] = [];
    const chunks = Array.from({ length: 5 }, (_, i) => draft(`c${i}`));
    const result = await embedChunks(
      fakeAdapter((req) => requestSizes.push(req.input.length)),
      "m",
      chunks,
      { batchSize: 2, metadata: { purpose: "semantic_index_build" } },
    );

    expect(requestSizes).toEqual([2, 2, 1]);
    expect(result).toHaveLength(5);
  });

  it("uses a sane default batch size", async () => {
    const requestSizes: number[] = [];
    const chunks = Array.from({ length: DEFAULT_EMBED_BATCH_SIZE + 5 }, (_, i) => draft(`c${i}`));
    await embedChunks(
      fakeAdapter((req) => requestSizes.push(req.input.length)),
      "m",
      chunks,
      {
        metadata: { purpose: "semantic_index_build" },
      },
    );
    expect(requestSizes).toEqual([DEFAULT_EMBED_BATCH_SIZE, 5]);
  });

  it("returns an empty array for an empty input without calling the adapter", async () => {
    let called = false;
    const adapter: EmbeddingProviderAdapter = {
      provider: "azure",
      embed: async () => {
        called = true;
        return { embeddings: [], model: "m", usage: { inputTokens: 0 } };
      },
    };
    const result = await embedChunks(adapter, "m", [], { metadata: { purpose: "x" } });
    expect(result).toEqual([]);
    expect(called).toBe(false);
  });

  it("drops a failed batch (reporting via onError) without throwing or losing other batches", async () => {
    const errors: Array<{ id: string | undefined; error: unknown }> = [];
    let call = 0;
    const adapter: EmbeddingProviderAdapter = {
      provider: "azure",
      embed: async (req) => {
        call += 1;
        if (call === 1) throw new Error("provider timeout");
        return {
          embeddings: req.input.map(() => [1, 2, 3]),
          model: "m",
          usage: { inputTokens: 1 },
        };
      },
    };
    const chunks = [draft("bad"), draft("good")];
    const result = await embedChunks(adapter, "m", chunks, {
      batchSize: 1,
      metadata: { purpose: "semantic_index_build" },
      onError: (chunk, error) => errors.push({ id: chunk.symbolName, error }),
    });

    expect(result.map((c) => c.symbolName)).toEqual(["good"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.id).toBe("bad");
  });
});
