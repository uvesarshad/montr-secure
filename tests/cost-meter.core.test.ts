import { describe, it, expect } from "vitest";
import {
  BudgetExceededError,
  BudgetPolicySchema,
  CostEstimateSchema,
  CostRollupSchema,
  isMontrError,
  type TokenUsage,
} from "@montr/contracts";
import {
  buildCostRollup,
  computeVariancePct,
  costPerFindingUsd,
  createCostMeter,
  enforceBudget,
  estimateScanCost,
  isWithinVarianceTarget,
  normalizeModelId,
  priceUsageUsd,
} from "@montr/cost-meter";

const oneMillionEach: TokenUsage = {
  inputTokens: 1_000_000,
  outputTokens: 1_000_000,
  totalTokens: 2_000_000,
};

describe("@montr/cost-meter pricing", () => {
  it("prices known models from the reference rate card", () => {
    // Opus 4.8: $5 in / $25 out per 1M.
    expect(priceUsageUsd(oneMillionEach, "claude-opus-4-8")).toBe(30);
    // Haiku 4.5: $1 in / $5 out per 1M.
    expect(priceUsageUsd(oneMillionEach, "claude-haiku-4-5-20251001")).toBe(6);
  });

  it("normalizes provider-prefixed and snapshot model ids", () => {
    expect(normalizeModelId("anthropic.claude-opus-4-8")).toBe("claude-opus-4-8");
    expect(normalizeModelId("claude-sonnet-5@20260101")).toBe("claude-sonnet-5");
    expect(priceUsageUsd(oneMillionEach, "anthropic.claude-opus-4-8")).toBe(30);
  });

  it("returns 0 for an unknown (BYO) model rather than guessing", () => {
    expect(priceUsageUsd(oneMillionEach, "gpt-4o")).toBe(0);
  });

  it("bills cache reads cheaper than fresh input", () => {
    const cached: TokenUsage = {
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 1_000_000,
      cacheReadTokens: 1_000_000,
    };
    // Haiku input $1/M, cache read ~0.1× → $0.10.
    expect(priceUsageUsd(cached, "claude-haiku-4-5")).toBeCloseTo(0.1, 6);
  });
});

describe("@montr/cost-meter pre-scan estimate", () => {
  const now = () => new Date("2026-07-02T00:00:00.000Z");

  it("projects a contract-valid estimate from map size × mode", () => {
    const est = estimateScanCost(
      { scanId: "scan_1", mode: "full", routeCount: 12, sinkCount: 25, fileCount: 80 },
      { now },
    );
    expect(CostEstimateSchema.safeParse(est).success).toBe(true);
    expect(est.projectedTotalTokens).toBe(est.projectedInputTokens + est.projectedOutputTokens);
    expect(est.projectedUsd).toBeGreaterThan(0);
    expect(est.byLayer.length).toBeGreaterThan(0);
    expect(est.createdAt).toBe("2026-07-02T00:00:00.000Z");
  });

  it("diff mode projects strictly fewer tokens than full mode", () => {
    const input = { routeCount: 12, sinkCount: 25, fileCount: 80 };
    const full = estimateScanCost({ scanId: "s", mode: "full", ...input }, { now });
    const diff = estimateScanCost({ scanId: "s", mode: "diff", ...input }, { now });
    expect(diff.projectedTotalTokens).toBeLessThan(full.projectedTotalTokens);
  });

  it("is deterministic", () => {
    const a = estimateScanCost(
      { scanId: "s", mode: "full", routeCount: 3, sinkCount: 3, fileCount: 3 },
      { now },
    );
    const b = estimateScanCost(
      { scanId: "s", mode: "full", routeCount: 3, sinkCount: 3, fileCount: 3 },
      { now },
    );
    expect(a).toEqual(b);
  });
});

describe("@montr/cost-meter live metering", () => {
  it("accumulates per-call usage by model and layer", () => {
    const meter = createCostMeter("scan_1", { now: () => new Date("2026-07-02T00:00:00.000Z") });
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 1000, outputTokens: 200, totalTokens: 1200 },
      layer: "layer2",
    });
    meter.record({
      modelId: "claude-opus-4-8",
      usage: { inputTokens: 500, outputTokens: 100, totalTokens: 600 },
      layer: "layer3",
    });
    const actual = meter.actual();
    expect(actual.usage.totalTokens).toBe(1800);
    expect(actual.byModel.length).toBe(2);
    expect(actual.byLayer.map((l) => l.key).sort()).toEqual(["layer2", "layer3"]);
    expect(actual.actualUsd).toBeGreaterThan(0);
  });

  it("measures wall-clock from an injected clock", () => {
    let call = 0;
    const base = new Date("2026-07-02T00:00:00.000Z").getTime();
    const meter = createCostMeter("scan_1", {
      now: () => new Date(call++ === 0 ? base : base + 5000),
    });
    expect(meter.actual().wallClockSeconds).toBe(5);
  });
});

describe("@montr/cost-meter budget hard-halt (DECIDE-4)", () => {
  it("flags exceeded and warns below the ceiling", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-opus-4-8",
      usage: { inputTokens: 1_000_000, outputTokens: 0, totalTokens: 1_000_000 },
    });
    // Spent $5. Ceiling $4 → exceeded.
    const exceeded = meter.checkBudget(BudgetPolicySchema.parse({ maxUsd: 4 }));
    expect(exceeded.exceeded).toBe(true);
    expect(exceeded.withinBudget).toBe(false);
    // Ceiling $6, warn at 80% ($4.80); spent $5 → warn (not exceeded).
    const warn = meter.checkBudget(BudgetPolicySchema.parse({ maxUsd: 6 }));
    expect(warn.exceeded).toBe(false);
    expect(warn.warn).toBe(true);
  });

  it("hard-halt throws BudgetExceededError; warn enforcement does not", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-opus-4-8",
      usage: { inputTokens: 2_000_000, outputTokens: 0, totalTokens: 2_000_000 },
    });
    const hardHalt = BudgetPolicySchema.parse({ maxUsd: 1, enforcement: "hard_halt" });
    try {
      enforceBudget(meter.checkBudget(hardHalt), hardHalt);
      throw new Error("expected hard halt");
    } catch (err) {
      expect(err).toBeInstanceOf(BudgetExceededError);
      expect(isMontrError(err) && err.code).toBe("BUDGET_EXCEEDED");
    }
    const warnPolicy = BudgetPolicySchema.parse({ maxUsd: 1, enforcement: "warn" });
    expect(() => enforceBudget(meter.checkBudget(warnPolicy), warnPolicy)).not.toThrow();
  });
});

describe("@montr/cost-meter variance (±15% target)", () => {
  const now = () => new Date("2026-07-02T00:00:00.000Z");

  it("computes signed variance and the ±15% band", () => {
    const estimate = estimateScanCost(
      { scanId: "scan_1", mode: "full", routeCount: 12, sinkCount: 25, fileCount: 80 },
      { now },
    );
    const meter = createCostMeter("scan_1", { now });
    // Spend within ~10% of the estimate.
    meter.record({
      modelId: "claude-sonnet-5",
      usage: {
        inputTokens: estimate.projectedInputTokens,
        outputTokens: estimate.projectedOutputTokens,
        totalTokens: estimate.projectedTotalTokens,
      },
    });
    const actual = meter.actual();
    const variance = computeVariancePct(estimate, actual);
    expect(Number.isFinite(variance)).toBe(true);
    expect(isWithinVarianceTarget(0.1)).toBe(true);
    expect(isWithinVarianceTarget(0.2)).toBe(false);

    const rollup = buildCostRollup("scan_1", estimate, actual, 4);
    expect(CostRollupSchema.safeParse(rollup).success).toBe(true);
    expect(rollup.costPerFindingUsd).toBe(costPerFindingUsd(actual.actualUsd, 4));
  });

  it("omits cost-per-finding when there are no findings", () => {
    expect(costPerFindingUsd(1.23, 0)).toBeUndefined();
  });
});
