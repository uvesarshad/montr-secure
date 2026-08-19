import { describe, it, expect } from "vitest";
import type { TokenUsage } from "@montr/contracts";
import {
  addUsage,
  findModelRate,
  normalizeModelId,
  priceUsageUsd,
  roundUsd,
  zeroUsage,
} from "./pricing.js";

/**
 * Package-local unit suite for the pricing primitives (§8.4). The root-level
 * `tests/cost-meter.core.test.ts` exercises known-model pricing, a basic
 * provider-prefix + snapshot normalization, unknown-model $0, and cache-read
 * discount — this file owns the rest of the formula's unit-level correctness:
 * zero/large-input edges, `addUsage`/`zeroUsage`/`roundUsd` in isolation, the
 * full normalizeModelId strip pipeline, and `findModelRate`'s match priority.
 */

describe("roundUsd", () => {
  it("rounds to micro-dollars (6 decimal places)", () => {
    expect(roundUsd(1.234567891)).toBe(1.234568);
    expect(roundUsd(0.1 + 0.2)).toBe(0.3);
  });

  it("returns exactly 0 for 0", () => {
    expect(roundUsd(0)).toBe(0);
  });
});

describe("zeroUsage", () => {
  it("returns an all-zero usage record with no cache fields", () => {
    const u = zeroUsage();
    expect(u).toEqual({ inputTokens: 0, outputTokens: 0, totalTokens: 0 });
    expect(u.cacheReadTokens).toBeUndefined();
    expect(u.cacheWriteTokens).toBeUndefined();
  });
});

describe("addUsage", () => {
  it("sums input/output/total tokens", () => {
    const a: TokenUsage = { inputTokens: 100, outputTokens: 20, totalTokens: 120 };
    const b: TokenUsage = { inputTokens: 50, outputTokens: 5, totalTokens: 55 };
    expect(addUsage(a, b)).toEqual({ inputTokens: 150, outputTokens: 25, totalTokens: 175 });
  });

  it("omits cache fields entirely when neither side has them", () => {
    const sum = addUsage(zeroUsage(), zeroUsage());
    expect(sum.cacheReadTokens).toBeUndefined();
    expect(sum.cacheWriteTokens).toBeUndefined();
  });

  it("sums cache fields present on only one side", () => {
    const a: TokenUsage = { inputTokens: 0, outputTokens: 0, totalTokens: 10, cacheReadTokens: 10 };
    const b: TokenUsage = { inputTokens: 0, outputTokens: 0, totalTokens: 0 };
    const sum = addUsage(a, b);
    expect(sum.cacheReadTokens).toBe(10);
    expect(sum.cacheWriteTokens).toBeUndefined();
  });

  it("sums cache fields present on both sides", () => {
    const a: TokenUsage = {
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 30,
      cacheReadTokens: 10,
      cacheWriteTokens: 5,
    };
    const b: TokenUsage = {
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 30,
      cacheReadTokens: 20,
      cacheWriteTokens: 15,
    };
    const sum = addUsage(a, b);
    expect(sum.cacheReadTokens).toBe(30);
    expect(sum.cacheWriteTokens).toBe(20);
  });
});

describe("normalizeModelId", () => {
  it("strips a publishers/…/models/ style path prefix", () => {
    expect(normalizeModelId("publishers/anthropic/models/claude-opus-4-8")).toBe("claude-opus-4-8");
  });

  it("strips the Bedrock anthropic. prefix", () => {
    expect(normalizeModelId("anthropic.claude-sonnet-5")).toBe("claude-sonnet-5");
  });

  it("strips a Vertex @date snapshot suffix", () => {
    expect(normalizeModelId("claude-opus-4-8@20260101")).toBe("claude-opus-4-8");
  });

  it("strips a trailing -fast suffix", () => {
    expect(normalizeModelId("claude-haiku-4-5-fast")).toBe("claude-haiku-4-5");
  });

  it("strips a trailing dated-snapshot suffix (-YYYYMMDD)", () => {
    expect(normalizeModelId("claude-haiku-4-5-20251001")).toBe("claude-haiku-4-5");
  });

  it("strips path + provider prefix + snapshot + dated suffix all at once", () => {
    expect(
      normalizeModelId("publishers/anthropic/models/anthropic.claude-haiku-4-5-20251001@20260101"),
    ).toBe("claude-haiku-4-5");
  });

  it("leaves an already-canonical id untouched", () => {
    expect(normalizeModelId("claude-sonnet-5")).toBe("claude-sonnet-5");
  });

  it("trims surrounding whitespace", () => {
    expect(normalizeModelId("  claude-sonnet-5  ")).toBe("claude-sonnet-5");
  });
});

describe("findModelRate", () => {
  it("prefers an exact modelId match over normalization", () => {
    // The dated haiku id is an EXACT entry in the rate card, so it must resolve
    // directly rather than via the normalized "claude-haiku-4-5" fallback.
    const rate = findModelRate("claude-haiku-4-5-20251001");
    expect(rate?.modelId).toBe("claude-haiku-4-5-20251001");
  });

  it("falls back to matching the normalized query against a canonical rate-card id", () => {
    const rate = findModelRate("anthropic.claude-sonnet-5@20260101");
    expect(rate?.modelId).toBe("claude-sonnet-5");
  });

  it("falls back to normalizing rate-card entries when the query itself needs no normalization", () => {
    // "claude-haiku-4-5" (no dated suffix) isn't a literal rate-card entry, but
    // normalizing the card's "claude-haiku-4-5-20251001" entry matches it.
    const rate = findModelRate("claude-haiku-4-5");
    expect(rate?.inputPerMillionUsd).toBe(1);
  });

  it("returns undefined for a model id absent from the rate card entirely", () => {
    expect(findModelRate("gpt-4o")).toBeUndefined();
    expect(findModelRate("")).toBeUndefined();
  });
});

describe("priceUsageUsd", () => {
  it("prices zero usage at exactly $0 for a known model", () => {
    expect(priceUsageUsd(zeroUsage(), "claude-sonnet-5")).toBe(0);
  });

  it("prices a very large usage without overflow or precision blowup", () => {
    const huge: TokenUsage = {
      inputTokens: 1_000_000_000,
      outputTokens: 1_000_000_000,
      totalTokens: 2_000_000_000,
    };
    // Opus 4.8: $5/M in, $25/M out → 1000 * 5 + 1000 * 25 = $30,000.
    expect(priceUsageUsd(huge, "claude-opus-4-8")).toBe(30_000);
  });

  it("bills cache writes at ~1.25× the input rate", () => {
    const usage: TokenUsage = {
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 1_000_000,
      cacheWriteTokens: 1_000_000,
    };
    // Sonnet-5 input $3/M, cache write 1.25× → $3.75.
    expect(priceUsageUsd(usage, "claude-sonnet-5")).toBeCloseTo(3.75, 6);
  });

  it("sums input + output + cache-read + cache-write components", () => {
    const usage: TokenUsage = {
      inputTokens: 1_000_000,
      outputTokens: 500_000,
      totalTokens: 2_500_000,
      cacheReadTokens: 1_000_000,
      cacheWriteTokens: 1_000_000,
    };
    // Sonnet-5: in $3/M, out $15/M.
    // fresh input: 3, output: 0.5*15=7.5, cache read: 3*0.1=0.3, cache write: 3*1.25=3.75
    expect(priceUsageUsd(usage, "claude-sonnet-5")).toBeCloseTo(3 + 7.5 + 0.3 + 3.75, 6);
  });
});
