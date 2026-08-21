/**
 * Top-level index-build + index-query entry points (E5). `buildSemanticIndex`
 * is meant to be called once per commit, alongside the App Map build (Layer
 * 0) — see docs/modules/semantic-index.md for the intended call site and why
 * it isn't wired there yet. `querySemanticIndex` is the retrieval path a
 * future correlation/confirmation consumer would call.
 */
import { randomUUID } from "node:crypto";
import type { EmbeddingProviderAdapter } from "@montr/llm-gateway";
import type { CodeChunkRepository } from "@montr/state-store";
import { chunkRepo } from "./chunk.js";
import { embedChunks, type EmbedChunksOptions } from "./embed.js";
import { distanceToSimilarity } from "./query.js";
import type { SemanticMatch } from "./types.js";

export interface BuildSemanticIndexInput {
  /** Local checkout directory to chunk (same convention as AppMap's `workspace.dir`). */
  dir: string;
  clientId: string;
  /** The AppMap this index build is associated with — FK target, cascade-deletes with it. */
  appMapId: string;
  repo: string;
  commitSha: string;
  embeddingAdapter: EmbeddingProviderAdapter;
  embeddingModel: string;
  repository: CodeChunkRepository;
  batchSize?: number;
  onEmbedError?: EmbedChunksOptions["onError"];
}

export interface BuildSemanticIndexResult {
  filesScanned: number;
  chunksDrafted: number;
  chunksEmbedded: number;
  chunksIndexed: number;
}

/**
 * Chunk `dir`, embed every chunk, and persist the result. Idempotent at the
 * AppMap level in the common case (a new commit gets a new `appMapId`, so
 * nothing to clean up first) — see `CodeChunkRepository.deleteForAppMap` for
 * the in-place-rebuild case.
 */
export async function buildSemanticIndex(
  input: BuildSemanticIndexInput,
): Promise<BuildSemanticIndexResult> {
  const { chunks, filesScanned } = await chunkRepo(input.dir);

  const embedded = await embedChunks(input.embeddingAdapter, input.embeddingModel, chunks, {
    batchSize: input.batchSize,
    metadata: { clientId: input.clientId, purpose: "semantic_index_build" },
    onError: input.onEmbedError,
  });

  const chunksIndexed = await input.repository.insertMany(
    embedded.map((c) => ({
      id: randomUUID(),
      clientId: input.clientId,
      appMapId: input.appMapId,
      repo: input.repo,
      commitSha: input.commitSha,
      file: c.file,
      startLine: c.startLine,
      endLine: c.endLine,
      language: c.language,
      kind: c.kind,
      symbolName: c.symbolName,
      contentHash: c.contentHash,
      content: c.content,
      embeddingModel: c.embeddingModel,
      embedding: c.embedding,
    })),
  );

  return {
    filesScanned,
    chunksDrafted: chunks.length,
    chunksEmbedded: embedded.length,
    chunksIndexed,
  };
}

export interface QuerySemanticIndexInput {
  /** A finding's code snippet, or a natural-language description of what to find. */
  queryText: string;
  clientId: string;
  repo: string;
  /** Restrict to one commit's index — see `CodeChunkRepository.querySimilar`'s doc comment. */
  commitSha?: string;
  topK?: number;
  embeddingAdapter: EmbeddingProviderAdapter;
  embeddingModel: string;
  repository: CodeChunkRepository;
}

/**
 * Embed `queryText` and retrieve the top-K most similar indexed chunks,
 * scoped to `clientId`/`repo`(/`commitSha`). This is the path a future
 * correlation/confirmation consumer calls — see docs/modules/semantic-index.md.
 */
export async function querySemanticIndex(input: QuerySemanticIndexInput): Promise<SemanticMatch[]> {
  const embedResult = await input.embeddingAdapter.embed({
    input: [input.queryText],
    model: input.embeddingModel,
    metadata: { clientId: input.clientId, purpose: "semantic_index_query" },
  });
  const queryEmbedding = embedResult.embeddings[0];
  if (!queryEmbedding) return [];

  const rows = await input.repository.querySimilar(queryEmbedding, {
    clientId: input.clientId,
    repo: input.repo,
    commitSha: input.commitSha,
    topK: input.topK,
  });

  return rows.map((r) => ({
    id: r.id,
    file: r.file,
    startLine: r.startLine,
    endLine: r.endLine,
    language: r.language,
    kind: r.kind,
    symbolName: r.symbolName,
    content: r.content,
    similarity: distanceToSimilarity(r.distance),
  }));
}
