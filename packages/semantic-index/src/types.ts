/**
 * Shared types for the semantic codebase index (E5). Kept local to this
 * package rather than added to @montr/contracts — this task's scope is
 * deliberately limited to a standalone, well-tested library (see the package
 * README-style header in index.ts); promoting these to the shared contracts
 * spine is a natural follow-up once a real consumer (correlation/confirm)
 * settles on the exact shape it wants.
 */

/** Granularity this chunker cuts source into — see chunk.ts's doc comment for the reasoning. */
export type ChunkKind = "function" | "method" | "class";

/** One AST-chunked unit of source, before embedding. */
export interface CodeChunkDraft {
  /** Repo-relative POSIX path. */
  file: string;
  /** 1-based, inclusive. */
  startLine: number;
  /** 1-based, inclusive. */
  endLine: number;
  language: "typescript" | "python" | "java";
  kind: ChunkKind;
  /** Function/method/class name, when the AST gives one (always does except rare anonymous cases). */
  symbolName?: string;
  /** Chunk source text, possibly truncated — see chunk.ts's MAX_CHUNK_CHARS. */
  content: string;
  /** sha256(content), hex-encoded. */
  contentHash: string;
}

/** A chunk with its embedding attached — the unit `embed.ts` produces and the repository stores. */
export interface EmbeddedCodeChunk extends CodeChunkDraft {
  embedding: number[];
  embeddingModel: string;
}

/** A retrieval result — a stored chunk plus how similar it was to the query. */
export interface SemanticMatch {
  id: string;
  file: string;
  startLine: number;
  endLine: number;
  language: string;
  kind: string;
  symbolName: string | null;
  content: string;
  /** 0..1, higher = more similar (derived from pgvector's cosine distance — see query.ts). */
  similarity: number;
}
