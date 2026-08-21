/**
 * Semantic codebase index repository (E5) — pgvector-backed `CodeChunk`
 * storage + cosine-similarity retrieval. See packages/semantic-index for the
 * AST chunker + embedding pipeline that populates rows here, and
 * `schema.prisma`'s `CodeChunk` doc comment for why every read/write of the
 * `embedding` column goes through raw SQL rather than the generated Prisma
 * delegate (pgvector has no native Prisma column type — the field is declared
 * `Unsupported("vector(1536)")`).
 *
 * ⛔ Deliberately kept OUT of the main `StateStore` aggregate (types.ts /
 * state-store.ts): those are the two most central, most fluid files in this
 * package, and this capability's only consumer today is
 * @montr/semantic-index — nothing in apps/api or apps/worker constructs a
 * `StateStore` and expects a `.codeChunks` property yet (E5 ships the
 * indexing library; wiring a pipeline layer to consume it is explicitly a
 * follow-up — see docs/plan). A future consumer that wants this alongside a
 * full `StateStore` can call {@link createCodeChunkRepository} with that
 * store's own Prisma client directly; folding it into the aggregate then is a
 * small, low-risk addition once there is a real caller.
 */
import type { MontrPrismaClient } from "./prisma.js";

/** Fixed pgvector column width — see the migration + schema doc comment. */
export const CODE_CHUNK_EMBEDDING_DIM = 1536;

export interface CodeChunkInput {
  id: string;
  clientId: string;
  appMapId: string;
  repo: string;
  commitSha: string;
  file: string;
  startLine: number;
  endLine: number;
  language: string;
  kind: string;
  symbolName?: string;
  /** sha256(content) — lets a rebuild skip re-embedding an unchanged chunk. */
  contentHash: string;
  content: string;
  embeddingModel: string;
  /** Must have exactly {@link CODE_CHUNK_EMBEDDING_DIM} elements, all finite. */
  embedding: number[];
}

export interface CodeChunkRow {
  id: string;
  clientId: string;
  appMapId: string;
  repo: string;
  commitSha: string;
  file: string;
  startLine: number;
  endLine: number;
  language: string;
  kind: string;
  symbolName: string | null;
  contentHash: string;
  content: string;
  embeddingModel: string;
  createdAt: Date;
}

export interface CodeChunkMatch extends CodeChunkRow {
  /**
   * pgvector cosine distance (`<=>`): 0 = identical direction, 1 =
   * orthogonal, 2 = opposite. LOWER is MORE similar — this is a distance, not
   * a similarity score; callers wanting a 0..1 similarity can use
   * `1 - distance / 2` (see packages/semantic-index/src/query.ts).
   */
  distance: number;
}

export interface QuerySimilarOptions {
  clientId: string;
  repo: string;
  /**
   * Restrict to one commit's index — typical usage: the AppMap the current
   * scan is running against. Omitted searches every indexed commit for the
   * repo, which is usually broader than intended since old commits' chunks
   * are never pruned automatically (see {@link CodeChunkRepository.deleteForAppMap}).
   */
  commitSha?: string;
  /** Default 10. */
  topK?: number;
}

/** Validate + render an embedding as pgvector's bracketed literal syntax, e.g. `[0.1,0.2,0.3]`. */
function toVectorLiteral(embedding: number[]): string {
  if (embedding.length !== CODE_CHUNK_EMBEDDING_DIM) {
    throw new Error(
      `CodeChunk embedding must have exactly ${CODE_CHUNK_EMBEDDING_DIM} dimensions ` +
        `(got ${embedding.length}) — the schema's vector(${CODE_CHUNK_EMBEDDING_DIM}) column ` +
        `is fixed-width; see schema.prisma's CodeChunk doc comment.`,
    );
  }
  for (const v of embedding) {
    if (!Number.isFinite(v)) {
      throw new Error("CodeChunk embedding contains a non-finite value (NaN/Infinity)");
    }
  }
  return `[${embedding.join(",")}]`;
}

export interface CodeChunkRepository {
  /**
   * Insert one batch of chunks (typically: one AppMap build's whole chunk
   * set). Not idempotent by itself — a caller re-indexing the SAME appMapId
   * in place should {@link deleteForAppMap} first; re-indexing a new commit
   * naturally gets a fresh `appMapId` (AppMap rows are themselves per-commit,
   * DECIDE-2), so this is the common case and needs no cleanup.
   */
  insertMany(chunks: CodeChunkInput[]): Promise<number>;
  /** Cosine-similarity top-K search, scoped to a client (+ optionally one repo/commit). */
  querySimilar(queryEmbedding: number[], opts: QuerySimilarOptions): Promise<CodeChunkMatch[]>;
  /** Remove every chunk belonging to one AppMap (e.g. before re-indexing a commit in place). */
  deleteForAppMap(appMapId: string): Promise<number>;
}

export class PrismaCodeChunkRepository implements CodeChunkRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async insertMany(chunks: CodeChunkInput[]): Promise<number> {
    if (chunks.length === 0) return 0;
    let inserted = 0;
    // One INSERT per chunk rather than a multi-row VALUES list: each row's
    // vector literal is a distinct-length string, and Prisma's tagged-template
    // `$executeRaw` parameterizes every value safely without hand-rolled
    // escaping. Chunk counts per commit are hundreds-to-low-thousands (one
    // AppMap build, not a request-hot-path), so per-row round trips are an
    // acceptable simplicity trade here — batching is a straightforward
    // follow-up if a real deployment's chunk volume makes it worth it.
    for (const c of chunks) {
      const vectorLiteral = toVectorLiteral(c.embedding);
      await this.prisma.$executeRaw`
        INSERT INTO "CodeChunk"
          ("id","clientId","appMapId","repo","commitSha","file","startLine","endLine",
           "language","kind","symbolName","contentHash","content","embeddingModel","embedding")
        VALUES
          (${c.id},${c.clientId},${c.appMapId},${c.repo},${c.commitSha},${c.file},
           ${c.startLine},${c.endLine},${c.language},${c.kind},${c.symbolName ?? null},
           ${c.contentHash},${c.content},${c.embeddingModel},${vectorLiteral}::vector)
      `;
      inserted += 1;
    }
    return inserted;
  }

  async querySimilar(
    queryEmbedding: number[],
    opts: QuerySimilarOptions,
  ): Promise<CodeChunkMatch[]> {
    const vectorLiteral = toVectorLiteral(queryEmbedding);
    const topK = opts.topK ?? 10;
    const rows = opts.commitSha
      ? await this.prisma.$queryRaw<CodeChunkMatch[]>`
          SELECT "id","clientId","appMapId","repo","commitSha","file","startLine","endLine",
                 "language","kind","symbolName","contentHash","content","embeddingModel","createdAt",
                 ("embedding" <=> ${vectorLiteral}::vector) AS distance
          FROM "CodeChunk"
          WHERE "clientId" = ${opts.clientId} AND "repo" = ${opts.repo}
            AND "commitSha" = ${opts.commitSha}
          ORDER BY "embedding" <=> ${vectorLiteral}::vector
          LIMIT ${topK}
        `
      : await this.prisma.$queryRaw<CodeChunkMatch[]>`
          SELECT "id","clientId","appMapId","repo","commitSha","file","startLine","endLine",
                 "language","kind","symbolName","contentHash","content","embeddingModel","createdAt",
                 ("embedding" <=> ${vectorLiteral}::vector) AS distance
          FROM "CodeChunk"
          WHERE "clientId" = ${opts.clientId} AND "repo" = ${opts.repo}
          ORDER BY "embedding" <=> ${vectorLiteral}::vector
          LIMIT ${topK}
        `;
    return rows;
  }

  async deleteForAppMap(appMapId: string): Promise<number> {
    const result = await this.prisma
      .$executeRaw`DELETE FROM "CodeChunk" WHERE "appMapId" = ${appMapId}`;
    return typeof result === "number" ? result : Number(result);
  }
}

export function createCodeChunkRepository(prisma: MontrPrismaClient): CodeChunkRepository {
  return new PrismaCodeChunkRepository(prisma);
}
