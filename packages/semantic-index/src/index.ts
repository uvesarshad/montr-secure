/**
 * @montr/semantic-index — E5: a semantic codebase index (pgvector-backed)
 * over AST-chunked code, meant to be built once per commit alongside the App
 * Map and reused by diff scans. Gives correlation/confirmation genuine
 * cross-file context without blowing the token budget, and enables "find
 * every other place this pattern occurs" — turning one confirmed finding
 * into a swept class of findings.
 *
 * STATUS (be honest — see docs/modules/semantic-index.md for the full
 * picture): this package is a complete, tested library — AST chunking
 * (chunk.ts, reusing @montr/appmap's parsers), embedding generation (embed.ts,
 * via @montr/llm-gateway's new Azure-only embeddings adapter), pgvector
 * storage + cosine-similarity retrieval (@montr/state-store's
 * `CodeChunkRepository`), and the two top-level entry points below. It is
 * NOT wired into any pipeline layer — `packages/correlation` and
 * `packages/confirm` were off-limits for this change (other work was
 * concurrently touching them) and the required Postgres `pgvector` extension
 * is not yet in this repo's bundled Docker/Helm Postgres images. Both gaps
 * are documented, not silently dropped.
 */
export {
  buildSemanticIndex,
  querySemanticIndex,
  type BuildSemanticIndexInput,
  type BuildSemanticIndexResult,
  type QuerySemanticIndexInput,
} from "./build.js";

export {
  chunkRepo,
  chunkTypeScriptFile,
  chunkTypeScriptProject,
  chunkPythonSource,
  chunkJavaSource,
  MAX_CHUNK_CHARS,
  type ChunkRepoResult,
} from "./chunk.js";

export { embedChunks, DEFAULT_EMBED_BATCH_SIZE, type EmbedChunksOptions } from "./embed.js";

export {
  cosineSimilarity,
  cosineDistance,
  distanceToSimilarity,
  rankBySimilarity,
  type Embeddable,
} from "./query.js";

export type { ChunkKind, CodeChunkDraft, EmbeddedCodeChunk, SemanticMatch } from "./types.js";
