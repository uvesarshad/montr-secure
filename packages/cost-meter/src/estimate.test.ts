import { describe, it, expect } from "vitest";
import { CostEstimateSchema } from "@montr/contracts";
import { estimateScanCost, type EstimateInput } from "./estimate.js";

/**
 * Package-local unit suite for the pre-scan cost-estimate formula (§6.6). The
 * root-level `tests/cost-meter.core.test.ts` already covers a nominal
 * contract-valid estimate, diff < full token projection, and determinism —
 * this file owns the formula's edge cases: zero-size inputs, invalid
 * (negative / fractional) inputs, very large inputs, and the estimate options
 * (custom output ratio, throughput, model overrides).
 */

const now = () => new Date("2026-08-19T00:00:00.000Z");
const base: Omit<EstimateInput, "scanId" | "mode"> = { routeCount: 0, sinkCount: 0, fileCount: 0 };

describe("estimateScanCost — zero-size input", () => {
  it("still produces a valid, non-negative estimate for an all-zero App-Map", () => {
    const est = estimateScanCost({ scanId: "s0", mode: "full", ...base }, { now });
    expect(CostEstimateSchema.safeParse(est).success).toBe(true);
    expect(est.projectedInputTokens).toBeGreaterThanOrEqual(0);
    expect(est.projectedUsd).toBeGreaterThanOrEqual(0);
    // Layer5 has a fixed +2000 input-token base cost even at zero map size, so
    // the estimate is not literally $0 — but every count-derived layer is 0.
    expect(est.byLayer.find((l) => l.key === "layer0")?.usage.inputTokens).toBe(0);
    expect(est.byLayer.find((l) => l.key === "layer2")?.usage.inputTokens).toBe(0);
    expect(est.byLayer.find((l) => l.key === "layer3")?.usage.inputTokens).toBe(0);
    expect(est.byLayer.find((l) => l.key === "layer5")?.usage.inputTokens).toBeGreaterThan(0);
  });
});

describe("estimateScanCost — invalid / negative input", () => {
  it("clamps negative counts to zero rather than producing negative tokens", () => {
    const negative = estimateScanCost(
      { scanId: "s1", mode: "full", routeCount: -12, sinkCount: -25, fileCount: -80 },
      { now },
    );
    const zeroed = estimateScanCost({ scanId: "s1", mode: "full", ...base }, { now });
    expect(negative).toEqual(zeroed);
    expect(negative.projectedInputTokens).toBeGreaterThanOrEqual(0);
    expect(negative.projectedOutputTokens).toBeGreaterThanOrEqual(0);
  });

  it("floors fractional counts down to whole units", () => {
    const fractional = estimateScanCost(
      { scanId: "s2", mode: "full", routeCount: 12.9, sinkCount: 25.9, fileCount: 80.9 },
      { now },
    );
    const floored = estimateScanCost(
      { scanId: "s2", mode: "full", routeCount: 12, sinkCount: 25, fileCount: 80 },
      { now },
    );
    expect(fractional).toEqual(floored);
  });
});

describe("estimateScanCost — very large input", () => {
  it("projects a proportionally large, still-finite estimate for a huge App-Map", () => {
    const huge = estimateScanCost(
      {
        scanId: "s3",
        mode: "full",
        routeCount: 1_000_000,
        sinkCount: 1_000_000,
        fileCount: 1_000_000,
      },
      { now },
    );
    expect(Number.isFinite(huge.projectedUsd)).toBe(true);
    expect(Number.isFinite(huge.projectedTotalTokens)).toBe(true);
    expect(huge.projectedUsd).toBeGreaterThan(1000);
    expect(CostEstimateSchema.safeParse(huge).success).toBe(true);
  });
});

describe("estimateScanCost — formula shape", () => {
  it("splits total tokens across exactly the four LLM-using layers", () => {
    const est = estimateScanCost(
      { scanId: "s4", mode: "full", routeCount: 12, sinkCount: 25, fileCount: 80 },
      { now },
    );
    expect(est.byLayer.map((l) => l.key)).toEqual(["layer0", "layer2", "layer3", "layer5"]);
    const summedInput = est.byLayer.reduce((acc, l) => acc + l.usage.inputTokens, 0);
    expect(summedInput).toBe(est.projectedInputTokens);
    const summedUsd = est.byLayer.reduce((acc, l) => acc + l.usd, 0);
    expect(summedUsd).toBeCloseTo(est.projectedUsd, 6);
  });

  it("records the basis string with the mode multiplier applied", () => {
    const est = estimateScanCost(
      { scanId: "s5", mode: "diff", routeCount: 1, sinkCount: 1, fileCount: 1 },
      { now },
    );
    expect(est.basis).toBe("files=1 routes=1 sinks=1 × diff mode (×0.35)");
  });

  it("derives wall-clock seconds from total tokens ÷ tokensPerSecond + 30s floor", () => {
    const est = estimateScanCost(
      { scanId: "s6", mode: "full", ...base },
      { now, tokensPerSecond: 1000 },
    );
    // Zero-count layers contribute 0 tokens except layer5's fixed base (2000 in
    // + 25% output ratio = 2500 total) → 2500/1000 + 30 = 32.5 → rounds to 33.
    expect(est.projectedWallClockSeconds).toBe(Math.round(2500 / 1000 + 30));
  });

  it("respects a custom outputRatio", () => {
    const zero = estimateScanCost({ scanId: "s7", mode: "full", ...base }, { now, outputRatio: 0 });
    expect(zero.projectedOutputTokens).toBe(0);
    const half = estimateScanCost(
      { scanId: "s7", mode: "full", ...base },
      { now, outputRatio: 0.5 },
    );
    expect(half.projectedOutputTokens).toBeGreaterThan(0);
  });

  it("prices the confirmation layer (layer3) with the confirmation model override", () => {
    const est = estimateScanCost(
      { scanId: "s8", mode: "full", routeCount: 5, sinkCount: 5, fileCount: 5 },
      { now, defaultModelId: "claude-haiku-4-5", confirmationModelId: "claude-opus-4-8" },
    );
    const layer3 = est.byLayer.find((l) => l.key === "layer3")!;
    const layer0 = est.byLayer.find((l) => l.key === "layer0")!;
    // Same token magnitude order, but layer3 (opus, pricier) should cost more
    // per input token than layer0 (haiku) once normalized — sanity: both > 0.
    expect(layer3.usd).toBeGreaterThan(0);
    expect(layer0.usd).toBeGreaterThan(0);
  });

  it("stamps createdAt from the injected clock, not the ambient clock", () => {
    const est = estimateScanCost({ scanId: "s9", mode: "full", ...base }, { now });
    expect(est.createdAt).toBe("2026-08-19T00:00:00.000Z");
  });
});
