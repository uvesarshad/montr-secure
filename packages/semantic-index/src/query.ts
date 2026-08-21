/**
 * Pure, deterministic vector-similarity math (E5) — no DB, no network. This is
 * the same math pgvector's `<=>` cosine-distance operator implements, kept
 * here as a real (not mocked) in-process implementation so:
 *   1. the retrieval-ranking behavior is unit-testable without a live
 *      Postgres + pgvector instance (see query.test.ts's synthetic index), and
 *   2. a caller with no live pgvector available yet (see the migration's
 *      documented extension-availability gap) has a working, if unindexed,
 *      in-memory fallback — `rankBySimilarity` over a plain array of
 *      `{embedding}` records — rather than nothing.
 */

/** Cosine similarity in [-1, 1]; 1 = identical direction, 0 = orthogonal, -1 = opposite. */
export function cosineSimilarity(a: readonly number[], b: readonly number[]): number {
  if (a.length !== b.length) {
    throw new Error(`Vector length mismatch: ${a.length} vs ${b.length}`);
  }
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    dot += av * bv;
    normA += av * av;
    normB += bv * bv;
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

/** pgvector's `<=>` cosine DISTANCE (0 = identical, 2 = opposite) — `1 - cosineSimilarity`. */
export function cosineDistance(a: readonly number[], b: readonly number[]): number {
  return 1 - cosineSimilarity(a, b);
}

/** Convert a pgvector cosine distance (0..2, lower = more similar) to a 0..1 similarity score (higher = more similar). */
export function distanceToSimilarity(distance: number): number {
  return 1 - distance / 2;
}

/** An in-memory item this module can rank — anything carrying an embedding vector. */
export interface Embeddable {
  embedding: readonly number[];
}

/**
 * Rank `items` by cosine similarity to `queryEmbedding`, descending, top-K.
 * The real, deterministic ranking primitive both `build.ts`'s
 * `querySemanticIndex` (via pgvector) and any in-memory/offline caller can
 * rely on — see this module's doc comment.
 */
export function rankBySimilarity<T extends Embeddable>(
  queryEmbedding: readonly number[],
  items: readonly T[],
  topK = 10,
): Array<T & { similarity: number }> {
  return items
    .map((item) => ({ ...item, similarity: cosineSimilarity(queryEmbedding, item.embedding) }))
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, Math.max(0, topK));
}
