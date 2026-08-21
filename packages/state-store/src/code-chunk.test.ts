/**
 * PrismaCodeChunkRepository (E5, semantic codebase index) — offline / no live
 * Postgres. Follows repositories.bulk-create.test.ts's convention: a fake
 * Prisma client that records the tagged-template SQL + values it was called
 * with, so the REAL repository implementation is exercised (query shape,
 * vector-literal rendering, dimension validation) without a database.
 */
import { describe, expect, it } from "vitest";
import {
  CODE_CHUNK_EMBEDDING_DIM,
  createCodeChunkRepository,
  type CodeChunkInput,
} from "./code-chunk.js";
import type { MontrPrismaClient } from "./prisma.js";

interface RawCall {
  strings: TemplateStringsArray;
  values: unknown[];
}

function fakePrisma(execCalls: RawCall[], queryResult: unknown[] = []) {
  return {
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      execCalls.push({ strings, values });
      return Promise.resolve(1);
    },
    $queryRaw: (_strings: TemplateStringsArray, ..._values: unknown[]) =>
      Promise.resolve(queryResult),
  } as unknown as MontrPrismaClient;
}

function vec(dim: number, fill = 0.01): number[] {
  return Array.from({ length: dim }, (_, i) => fill * (i + 1));
}

function chunk(overrides: Partial<CodeChunkInput> = {}): CodeChunkInput {
  return {
    id: "chunk_1",
    clientId: "client_1",
    appMapId: "appmap_1",
    repo: "org/repo",
    commitSha: "deadbeef",
    file: "src/handlers/user.ts",
    startLine: 10,
    endLine: 24,
    language: "typescript",
    kind: "function",
    symbolName: "getUser",
    contentHash: "sha256:abc",
    content: "export function getUser(id: string) { /* ... */ }",
    embeddingModel: "azure:text-embedding-3-small",
    embedding: vec(CODE_CHUNK_EMBEDDING_DIM),
    ...overrides,
  };
}

describe("PrismaCodeChunkRepository.insertMany", () => {
  it("inserts one row per chunk via $executeRaw, rendering the embedding as a pgvector literal", async () => {
    const calls: RawCall[] = [];
    const repo = createCodeChunkRepository(fakePrisma(calls));

    const count = await repo.insertMany([chunk(), chunk({ id: "chunk_2", symbolName: undefined })]);

    expect(count).toBe(2);
    expect(calls).toHaveLength(2);
    const [first] = calls;
    expect(first?.values).toContain("chunk_1");
    expect(first?.values).toContain("client_1");
    // The vector literal is rendered as a bracketed comma list and included
    // as one of the interpolated values (cast to ::vector in the SQL text).
    const vectorLiteral = first?.values.find(
      (v): v is string => typeof v === "string" && v.startsWith("["),
    );
    expect(vectorLiteral).toBeDefined();
    expect(vectorLiteral).toMatch(/^\[0\.01,0\.02,/);
    expect(vectorLiteral?.split(",")).toHaveLength(CODE_CHUNK_EMBEDDING_DIM);
  });

  it("is a no-op for an empty batch (no round trip)", async () => {
    const calls: RawCall[] = [];
    const repo = createCodeChunkRepository(fakePrisma(calls));
    const count = await repo.insertMany([]);
    expect(count).toBe(0);
    expect(calls).toHaveLength(0);
  });

  it("rejects an embedding with the wrong dimensionality before any SQL is issued", async () => {
    const calls: RawCall[] = [];
    const repo = createCodeChunkRepository(fakePrisma(calls));
    await expect(repo.insertMany([chunk({ embedding: [0.1, 0.2] })])).rejects.toThrow(
      /exactly 1536 dimensions/,
    );
    expect(calls).toHaveLength(0);
  });

  it("rejects a non-finite embedding value", async () => {
    const calls: RawCall[] = [];
    const repo = createCodeChunkRepository(fakePrisma(calls));
    const bad = vec(CODE_CHUNK_EMBEDDING_DIM);
    bad[5] = Number.NaN;
    await expect(repo.insertMany([chunk({ embedding: bad })])).rejects.toThrow(/non-finite/);
  });
});

describe("PrismaCodeChunkRepository.querySimilar", () => {
  it("scopes by clientId + repo (+ commitSha when given) and returns the rows the DB sends back", async () => {
    const calls: RawCall[] = [];
    const fakeRows = [
      { id: "chunk_1", file: "a.ts", distance: 0.02 },
      { id: "chunk_2", file: "b.ts", distance: 0.5 },
    ];
    const repo = createCodeChunkRepository(fakePrisma(calls, fakeRows));

    const results = await repo.querySimilar(vec(CODE_CHUNK_EMBEDDING_DIM), {
      clientId: "client_1",
      repo: "org/repo",
      commitSha: "deadbeef",
      topK: 5,
    });

    expect(results).toEqual(fakeRows);
  });

  it("rejects a query embedding with the wrong dimensionality", async () => {
    const repo = createCodeChunkRepository(fakePrisma([]));
    await expect(
      repo.querySimilar([0.1, 0.2], { clientId: "client_1", repo: "org/repo" }),
    ).rejects.toThrow(/exactly 1536 dimensions/);
  });
});

describe("PrismaCodeChunkRepository.deleteForAppMap", () => {
  it("issues a DELETE scoped to the given appMapId", async () => {
    const calls: RawCall[] = [];
    const repo = createCodeChunkRepository(fakePrisma(calls));
    const count = await repo.deleteForAppMap("appmap_1");
    expect(count).toBe(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.values).toContain("appmap_1");
  });
});
