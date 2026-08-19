import { describe, it, expect } from "vitest";
import {
  BudgetExceededError,
  BudgetPolicySchema,
  CostRollupSchema,
  isMontrError,
  type CostActual,
  type CostEstimate,
} from "@montr/contracts";
import { createCostMeter } from "./meter.js";
import {
  VARIANCE_TARGET_PCT,
  buildCostRollup,
  computeVariancePct,
  costPerFindingUsd,
  enforceBudget,
  isWithinVarianceTarget,
} from "./variance.js";

/**
 * Package-local unit suite for estimate-vs-actual variance and the DECIDE-4
 * hard-halt (§4.1, §11 — a non-negotiable safety control). The root-level
 * `tests/cost-meter.core.test.ts` covers a nominal variance computation, the
 * 10%-in/20%-out sanity check, one hard-halt throw + one warn no-throw, and
 * cost-rollup assembly — this file owns: the exact ±15% boundary (14.9% /
 * 15.0% / 15.1%, proving `<=` not `<`), sign symmetry, the div-by-zero guard,
 * and that the hard-halt is genuinely hard (fires exactly at the crossing,
 * never for `warn` enforcement, and carries the real spend in its details).
 */

const now = () => new Date("2026-08-19T00:00:00.000Z");

function estimateOf(usd: number): CostEstimate {
  return {
    mode: "full",
    projectedInputTokens: 0,
    projectedOutputTokens: 0,
    projectedTotalTokens: 0,
    projectedUsd: usd,
    projectedWallClockSeconds: 0,
    basis: "test",
    byLayer: [],
    createdAt: now().toISOString(),
  };
}

function actualOf(usd: number): CostActual {
  return {
    scanId: "scan_1",
    usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    actualUsd: usd,
    wallClockSeconds: 0,
    byLayer: [],
    byModel: [],
    updatedAt: now().toISOString(),
  };
}

describe("computeVariancePct", () => {
  it("computes a positive (over-budget) variance", () => {
    expect(computeVariancePct(estimateOf(100), actualOf(115))).toBeCloseTo(0.15, 10);
  });

  it("computes a negative (under-budget) variance", () => {
    expect(computeVariancePct(estimateOf(100), actualOf(85))).toBeCloseTo(-0.15, 10);
  });

  it("is exactly 0 when actual matches the estimate", () => {
    expect(computeVariancePct(estimateOf(100), actualOf(100))).toBe(0);
  });

  it("returns 0 (does not divide by zero) when the estimate projected $0", () => {
    expect(computeVariancePct(estimateOf(0), actualOf(50))).toBe(0);
  });
});

describe("isWithinVarianceTarget — ±15% boundary (`<=` not `<`)", () => {
  it("14.9% is within the target band", () => {
    expect(isWithinVarianceTarget(0.149)).toBe(true);
  });

  it("15.0% is exactly on the boundary and counts as within", () => {
    expect(isWithinVarianceTarget(0.15)).toBe(true);
    expect(isWithinVarianceTarget(VARIANCE_TARGET_PCT)).toBe(true);
  });

  it("15.1% is outside the target band", () => {
    expect(isWithinVarianceTarget(0.151)).toBe(false);
  });

  it("the boundary is symmetric for under-budget variance (-14.9% / -15.0% / -15.1%)", () => {
    expect(isWithinVarianceTarget(-0.149)).toBe(true);
    expect(isWithinVarianceTarget(-0.15)).toBe(true);
    expect(isWithinVarianceTarget(-0.151)).toBe(false);
  });

  it("honors a custom target override", () => {
    expect(isWithinVarianceTarget(0.2, 0.25)).toBe(true);
    expect(isWithinVarianceTarget(0.3, 0.25)).toBe(false);
  });
});

describe("costPerFindingUsd", () => {
  it("divides actual spend by finding count", () => {
    expect(costPerFindingUsd(10, 4)).toBe(2.5);
  });

  it("is undefined for zero findings", () => {
    expect(costPerFindingUsd(10, 0)).toBeUndefined();
  });

  it("is undefined for a negative finding count", () => {
    expect(costPerFindingUsd(10, -1)).toBeUndefined();
  });
});

describe("buildCostRollup", () => {
  it("omits actual/variance/cost-per-finding when there are no actuals yet (pre-scan)", () => {
    const rollup = buildCostRollup("scan_1", estimateOf(100));
    expect(CostRollupSchema.safeParse(rollup).success).toBe(true);
    expect(rollup.actual).toBeUndefined();
    expect(rollup.variancePct).toBeUndefined();
    expect(rollup.costPerFindingUsd).toBeUndefined();
  });

  it("includes variance but omits cost-per-finding when findingCount is not supplied", () => {
    const rollup = buildCostRollup("scan_1", estimateOf(100), actualOf(110));
    expect(rollup.variancePct).toBeCloseTo(0.1, 10);
    expect(rollup.costPerFindingUsd).toBeUndefined();
  });
});

describe("enforceBudget — DECIDE-4 hard-halt", () => {
  const details = { spentUsd: 5, spentTokens: 1000 };

  it("throws BudgetExceededError with the real spend in its details when exceeded + hard_halt", () => {
    const policy = BudgetPolicySchema.parse({ maxUsd: 4, enforcement: "hard_halt" });
    const check = { withinBudget: false, exceeded: true, warn: false, ...details };
    expect(() => enforceBudget(check, policy)).toThrow(BudgetExceededError);
    try {
      enforceBudget(check, policy);
      throw new Error("expected enforceBudget to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(BudgetExceededError);
      expect(isMontrError(err) && err.code).toBe("BUDGET_EXCEEDED");
      expect(isMontrError(err) && err.details?.spentUsd).toBe(5);
      expect(isMontrError(err) && err.details?.spentTokens).toBe(1000);
      expect(isMontrError(err) && err.details?.maxUsd).toBe(4);
    }
  });

  it("does NOT throw when exceeded but enforcement is 'warn' — returns the check unchanged", () => {
    const policy = BudgetPolicySchema.parse({ maxUsd: 4, enforcement: "warn" });
    const check = { withinBudget: false, exceeded: true, warn: false, ...details };
    expect(enforceBudget(check, policy)).toBe(check);
  });

  it("does NOT throw when not exceeded, even under hard_halt enforcement", () => {
    const policy = BudgetPolicySchema.parse({ maxUsd: 100, enforcement: "hard_halt" });
    const check = {
      withinBudget: true,
      exceeded: false,
      warn: false,
      spentUsd: 1,
      spentTokens: 10,
    };
    expect(() => enforceBudget(check, policy)).not.toThrow();
    expect(enforceBudget(check, policy)).toBe(check);
  });

  it("end-to-end: fires exactly when live spend crosses the ceiling, not one call before", () => {
    const meter = createCostMeter("scan_1", { now });
    const policy = BudgetPolicySchema.parse({ maxUsd: 3, enforcement: "hard_halt" });

    // Spend exactly $3 (1,000,000 sonnet-5 input tokens @ $3/M) — on the
    // ceiling, must NOT halt yet.
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 1_000_000, outputTokens: 0, totalTokens: 1_000_000 },
    });
    expect(() => enforceBudget(meter.checkBudget(policy), policy)).not.toThrow();

    // One more token of spend crosses the ceiling — must halt now, hard.
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 1, outputTokens: 0, totalTokens: 1 },
    });
    let threw = false;
    try {
      enforceBudget(meter.checkBudget(policy), policy);
    } catch (err) {
      threw = true;
      expect(err).toBeInstanceOf(BudgetExceededError);
    }
    expect(threw).toBe(true);
  });

  it("the halt is genuinely hard: the meter keeps no special 'halted' state, so callers must react to the thrown error itself, not a flag", () => {
    // There is no isHalted()/wasHalted() on CostMeter — checkBudget/enforceBudget
    // are the only halt signal, and they must be re-derived from live spend on
    // every call rather than latched, so a caller can't accidentally read a
    // stale "ok" state after the throw.
    const meter = createCostMeter("scan_1", { now });
    const policy = BudgetPolicySchema.parse({ maxUsd: 1, enforcement: "hard_halt" });
    meter.record({
      modelId: "claude-opus-4-8",
      usage: { inputTokens: 1_000_000, outputTokens: 0, totalTokens: 1_000_000 },
    });
    expect(() => enforceBudget(meter.checkBudget(policy), policy)).toThrow(BudgetExceededError);
    // Checking again (as an orchestrator retry loop would) still throws —
    // there's no silent one-shot suppression of the halt.
    expect(() => enforceBudget(meter.checkBudget(policy), policy)).toThrow(BudgetExceededError);
  });
});
