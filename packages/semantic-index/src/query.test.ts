/**
 * Similarity ranking (E5) — real, deterministic cosine-similarity math over a
 * small synthetic in-memory index (no mocked ranking, no DB).
 */
import { describe, expect, it } from "vitest";
import {
  cosineDistance,
  cosineSimilarity,
  distanceToSimilarity,
  rankBySimilarity,
} from "./query.js";

describe("cosineSimilarity", () => {
  it("is 1 for identical vectors", () => {
    expect(cosineSimilarity([1, 2, 3], [1, 2, 3])).toBeCloseTo(1, 10);
  });

  it("is 0 for orthogonal vectors", () => {
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0, 10);
  });

  it("is -1 for opposite vectors", () => {
    expect(cosineSimilarity([1, 2], [-1, -2])).toBeCloseTo(-1, 10);
  });

  it("is scale-invariant (only direction matters)", () => {
    const a = cosineSimilarity([1, 2, 3], [2, 4, 6]);
    const b = cosineSimilarity([1, 2, 3], [4, 8, 12]);
    expect(a).toBeCloseTo(1, 10);
    expect(b).toBeCloseTo(1, 10);
  });

  it("throws on mismatched dimensions", () => {
    expect(() => cosineSimilarity([1, 2], [1, 2, 3])).toThrow(/length mismatch/);
  });

  it("returns 0 for a zero vector rather than NaN", () => {
    expect(cosineSimilarity([0, 0, 0], [1, 2, 3])).toBe(0);
  });
});

describe("cosineDistance / distanceToSimilarity", () => {
  it("distance is 1 - similarity, and round-trips back through distanceToSimilarity", () => {
    const a = [0.5, 0.1, -0.2];
    const b = [0.4, -0.3, 0.9];
    const sim = cosineSimilarity(a, b);
    const dist = cosineDistance(a, b);
    expect(dist).toBeCloseTo(1 - sim, 10);
    // distanceToSimilarity maps pgvector's 0..2 cosine-distance range onto a
    // 0..1 similarity score — check its two fixed points directly.
    expect(distanceToSimilarity(0)).toBe(1);
    expect(distanceToSimilarity(2)).toBe(0);
    expect(distanceToSimilarity(1)).toBe(0.5);
  });
});

describe("rankBySimilarity — synthetic index, real ranking math", () => {
  // Three orthogonal-ish "topics" in a small vector space, mimicking distinct
  // code patterns (e.g. "raw SQL string concatenation" vs "parameterized
  // query" vs "unrelated logging helper").
  const rawSqlConcat = { id: "raw-sql", embedding: [1, 0, 0, 0] };
  const parameterizedQuery = { id: "param-query", embedding: [0.9, 0.1, 0, 0] }; // close to rawSqlConcat
  const loggingHelper = { id: "logging", embedding: [0, 0, 1, 0] }; // orthogonal
  const unrelatedMath = { id: "math-util", embedding: [-1, 0, 0, 0] }; // opposite

  const index = [parameterizedQuery, loggingHelper, unrelatedMath, rawSqlConcat];

  it("ranks the nearest-neighbor topic first, in strictly descending similarity order", () => {
    const query = [1, 0, 0, 0]; // "find things like raw SQL concatenation"
    const ranked = rankBySimilarity(query, index, 10);

    expect(ranked.map((r) => r.id)).toEqual(["raw-sql", "param-query", "logging", "math-util"]);
    for (let i = 1; i < ranked.length; i++) {
      expect(ranked[i - 1]!.similarity).toBeGreaterThanOrEqual(ranked[i]!.similarity);
    }
    expect(ranked[0]!.similarity).toBeCloseTo(1, 10);
    expect(ranked.at(-1)!.similarity).toBeCloseTo(-1, 10);
  });

  it("respects topK", () => {
    const ranked = rankBySimilarity([1, 0, 0, 0], index, 2);
    expect(ranked).toHaveLength(2);
    expect(ranked.map((r) => r.id)).toEqual(["raw-sql", "param-query"]);
  });

  it("is a pure function — same query + index always yields the same order", () => {
    const query = [0.3, 0.1, 0.9, 0];
    const first = rankBySimilarity(query, index).map((r) => r.id);
    const second = rankBySimilarity(query, index).map((r) => r.id);
    expect(first).toEqual(second);
  });
});
