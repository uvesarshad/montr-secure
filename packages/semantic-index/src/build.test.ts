/**
 * buildSemanticIndex / querySemanticIndex (E5) — end-to-end through the real
 * chunker + real embedder-batching against a temp fixture repo, with a fake
 * `EmbeddingProviderAdapter` (no network) and a fake `CodeChunkRepository`
 * (no live Postgres — mirrors @montr/state-store's own fake-delegate test
 * convention) so the wiring between the three stages is genuinely exercised.
 */
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { EmbeddingProviderAdapter } from "@montr/llm-gateway";
import type {
  CodeChunkInput,
  CodeChunkMatch,
  CodeChunkRepository,
  QuerySimilarOptions,
} from "@montr/state-store";
import { buildSemanticIndex, querySemanticIndex } from "./build.js";
import { cosineSimilarity } from "./query.js";

const TS_SOURCE = `
export function getUser(id: string) {
  return db.user.findUnique({ where: { id } });
}

export function listOrders(userId: string) {
  return db.order.findMany({ where: { userId } });
}
`;

/** Deterministic fake embedding: a short vector derived from text length + char sum, so distinct texts get distinct (but reproducible) vectors. */
function fakeEmbeddingAdapter(dim = 8): EmbeddingProviderAdapter {
  return {
    provider: "azure",
    embed: async (req) => ({
      embeddings: req.input.map((text) => {
        let sum = 0;
        for (let i = 0; i < text.length; i++) sum += text.charCodeAt(i);
        return Array.from({ length: dim }, (_, i) => Math.sin(sum + i));
      }),
      model: "text-embedding-3-small",
      usage: { inputTokens: req.input.join("").length },
    }),
  };
}

/** In-memory fake repository — real insert/query logic, no Postgres. */
function fakeRepository(): CodeChunkRepository & { rows: CodeChunkInput[] } {
  const rows: CodeChunkInput[] = [];
  return {
    rows,
    insertMany: async (chunks) => {
      rows.push(...chunks);
      return chunks.length;
    },
    querySimilar: async (queryEmbedding, opts: QuerySimilarOptions): Promise<CodeChunkMatch[]> => {
      const scoped = rows.filter(
        (r) =>
          r.clientId === opts.clientId &&
          r.repo === opts.repo &&
          (opts.commitSha ? r.commitSha === opts.commitSha : true),
      );
      return scoped
        .map((r) => ({
          id: r.id,
          clientId: r.clientId,
          appMapId: r.appMapId,
          repo: r.repo,
          commitSha: r.commitSha,
          file: r.file,
          startLine: r.startLine,
          endLine: r.endLine,
          language: r.language,
          kind: r.kind,
          symbolName: r.symbolName ?? null,
          contentHash: r.contentHash,
          content: r.content,
          embeddingModel: r.embeddingModel,
          createdAt: new Date(),
          // pgvector's <=> is a DISTANCE — lower is more similar — matching
          // what the real Postgres query returns (see query.ts's doc comment).
          distance: 1 - cosineSimilarity(queryEmbedding, r.embedding),
        }))
        .sort((a, b) => a.distance - b.distance)
        .slice(0, opts.topK ?? 10);
    },
    deleteForAppMap: async (appMapId) => {
      const before = rows.length;
      const kept = rows.filter((r) => r.appMapId !== appMapId);
      rows.length = 0;
      rows.push(...kept);
      return before - kept.length;
    },
  };
}

describe("buildSemanticIndex + querySemanticIndex — end to end", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "semantic-index-build-"));
    await mkdir(join(dir, "src"), { recursive: true });
    await writeFile(join(dir, "src", "users.ts"), TS_SOURCE, "utf8");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("chunks, embeds, and persists every function in the fixture repo", async () => {
    const repository = fakeRepository();
    const result = await buildSemanticIndex({
      dir,
      clientId: "client_1",
      appMapId: "appmap_1",
      repo: "org/repo",
      commitSha: "deadbeef",
      embeddingAdapter: fakeEmbeddingAdapter(),
      embeddingModel: "text-embedding-3-small",
      repository,
    });

    expect(result.filesScanned).toBe(1);
    expect(result.chunksDrafted).toBe(2);
    expect(result.chunksEmbedded).toBe(2);
    expect(result.chunksIndexed).toBe(2);
    expect(repository.rows).toHaveLength(2);
    expect(repository.rows.every((r) => r.clientId === "client_1")).toBe(true);
    expect(repository.rows.every((r) => r.embedding.length === 8)).toBe(true);
    expect(repository.rows.map((r) => r.symbolName).sort()).toEqual(["getUser", "listOrders"]);
  });

  it("query returns the more textually-similar chunk first (real embedding math end to end)", async () => {
    const repository = fakeRepository();
    await buildSemanticIndex({
      dir,
      clientId: "client_1",
      appMapId: "appmap_1",
      repo: "org/repo",
      commitSha: "deadbeef",
      embeddingAdapter: fakeEmbeddingAdapter(),
      embeddingModel: "text-embedding-3-small",
      repository,
    });

    // The fake adapter derives a vector purely from the query text's own
    // characters — querying with the EXACT text of one indexed chunk must
    // return that chunk as the top (and here, only sensible) match.
    const matches = await querySemanticIndex({
      queryText: repository.rows[0]!.content,
      clientId: "client_1",
      repo: "org/repo",
      commitSha: "deadbeef",
      embeddingAdapter: fakeEmbeddingAdapter(),
      embeddingModel: "text-embedding-3-small",
      repository,
      topK: 5,
    });

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]!.symbolName).toBe(repository.rows[0]!.symbolName);
    expect(matches[0]!.similarity).toBeCloseTo(1, 6);
    // Similarity is sorted descending.
    for (let i = 1; i < matches.length; i++) {
      expect(matches[i - 1]!.similarity).toBeGreaterThanOrEqual(matches[i]!.similarity);
    }
  });

  it("scopes queries by commitSha — a different commit's index is invisible", async () => {
    const repository = fakeRepository();
    await buildSemanticIndex({
      dir,
      clientId: "client_1",
      appMapId: "appmap_1",
      repo: "org/repo",
      commitSha: "commit-a",
      embeddingAdapter: fakeEmbeddingAdapter(),
      embeddingModel: "text-embedding-3-small",
      repository,
    });

    const matches = await querySemanticIndex({
      queryText: "getUser",
      clientId: "client_1",
      repo: "org/repo",
      commitSha: "commit-b", // different commit — nothing indexed there
      embeddingAdapter: fakeEmbeddingAdapter(),
      embeddingModel: "text-embedding-3-small",
      repository,
    });

    expect(matches).toEqual([]);
  });
});
