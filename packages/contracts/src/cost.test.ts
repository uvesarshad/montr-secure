import { describe, it, expect } from "vitest";
import {
  BudgetEnforcementSchema,
  CostLineItemSchema,
  CostEstimateSchema,
  CostActualSchema,
  BudgetPolicySchema,
  CostRollupSchema,
} from "./cost.js";

/**
 * Cost is a first-class, budget-gating output (§8.4, DECIDE-4: default budget
 * behavior is a HARD HALT). These schemas are safety-critical: a malformed
 * BudgetPolicy or a negative/NaN cost figure must be rejected, never silently
 * coerced, since it drives whether the pipeline halts.
 */

const NOW = "2026-08-19T00:00:00.000Z";

const usage = {
  inputTokens: 100,
  outputTokens: 50,
  totalTokens: 150,
};

describe("BudgetEnforcementSchema (DECIDE-4)", () => {
  it("accepts 'hard_halt' and 'warn'", () => {
    expect(BudgetEnforcementSchema.parse("hard_halt")).toBe("hard_halt");
    expect(BudgetEnforcementSchema.parse("warn")).toBe("warn");
  });

  it("rejects any other value (no silent 'ignore' mode)", () => {
    expect(() => BudgetEnforcementSchema.parse("ignore")).toThrow();
  });
});

describe("CostLineItemSchema", () => {
  it("accepts a well-formed line item", () => {
    const item = { key: "layer1", usage, usd: 0.42 };
    expect(CostLineItemSchema.parse(item)).toEqual(item);
  });

  it("rejects a negative USD amount", () => {
    expect(() => CostLineItemSchema.parse({ key: "layer1", usage, usd: -1 })).toThrow();
  });

  it("rejects a missing usage block", () => {
    expect(() => CostLineItemSchema.parse({ key: "layer1", usd: 1 })).toThrow();
  });
});

describe("CostEstimateSchema", () => {
  const base = {
    mode: "full",
    projectedInputTokens: 1000,
    projectedOutputTokens: 500,
    projectedTotalTokens: 1500,
    projectedUsd: 1.23,
    projectedWallClockSeconds: 60,
    basis: "routes×sinks × mode multiplier",
    createdAt: NOW,
  };

  it("accepts a well-formed estimate, defaulting byLayer to []", () => {
    const parsed = CostEstimateSchema.parse(base);
    expect(parsed.byLayer).toEqual([]);
    expect(parsed.mode).toBe("full");
  });

  it("rejects a negative projected token count", () => {
    expect(() => CostEstimateSchema.parse({ ...base, projectedInputTokens: -1 })).toThrow();
  });

  it("rejects a non-integer token count", () => {
    expect(() => CostEstimateSchema.parse({ ...base, projectedTotalTokens: 10.5 })).toThrow();
  });

  it("rejects a negative projected USD amount", () => {
    expect(() => CostEstimateSchema.parse({ ...base, projectedUsd: -0.01 })).toThrow();
  });

  it("rejects an invalid scan mode", () => {
    expect(() => CostEstimateSchema.parse({ ...base, mode: "quick" })).toThrow();
  });

  it("rejects a missing required 'basis'", () => {
    const { basis: _basis, ...rest } = base;
    expect(() => CostEstimateSchema.parse(rest)).toThrow();
  });
});

describe("CostActualSchema", () => {
  const base = {
    scanId: "scan_1",
    usage,
    actualUsd: 2.5,
    wallClockSeconds: 120,
    updatedAt: NOW,
  };

  it("accepts a well-formed actual, defaulting byLayer/byModel to []", () => {
    const parsed = CostActualSchema.parse(base);
    expect(parsed.byLayer).toEqual([]);
    expect(parsed.byModel).toEqual([]);
  });

  it("rejects a negative actualUsd", () => {
    expect(() => CostActualSchema.parse({ ...base, actualUsd: -5 })).toThrow();
  });

  it("rejects a missing scanId", () => {
    const { scanId: _scanId, ...rest } = base;
    expect(() => CostActualSchema.parse(rest)).toThrow();
  });
});

describe("BudgetPolicySchema (DECIDE-4 defaults)", () => {
  it("defaults enforcement to 'hard_halt' when unspecified", () => {
    const parsed = BudgetPolicySchema.parse({});
    expect(parsed.enforcement).toBe("hard_halt");
  });

  it("defaults requireEstimateApproval to true", () => {
    const parsed = BudgetPolicySchema.parse({});
    expect(parsed.requireEstimateApproval).toBe(true);
  });

  it("defaults warnThresholdPct to 0.8", () => {
    const parsed = BudgetPolicySchema.parse({});
    expect(parsed.warnThresholdPct).toBe(0.8);
  });

  it("accepts an explicit 'warn' enforcement override", () => {
    expect(BudgetPolicySchema.parse({ enforcement: "warn" }).enforcement).toBe("warn");
  });

  it("rejects a non-positive maxUsd ceiling", () => {
    expect(() => BudgetPolicySchema.parse({ maxUsd: 0 })).toThrow();
    expect(() => BudgetPolicySchema.parse({ maxUsd: -10 })).toThrow();
  });

  it("rejects a non-positive maxTotalTokens ceiling", () => {
    expect(() => BudgetPolicySchema.parse({ maxTotalTokens: 0 })).toThrow();
  });

  it("rejects a warnThresholdPct outside [0, 1]", () => {
    expect(() => BudgetPolicySchema.parse({ warnThresholdPct: 1.5 })).toThrow();
    expect(() => BudgetPolicySchema.parse({ warnThresholdPct: -0.1 })).toThrow();
  });

  it("rejects an invalid enforcement value", () => {
    expect(() => BudgetPolicySchema.parse({ enforcement: "soft_halt" })).toThrow();
  });
});

describe("CostRollupSchema (estimate-vs-actual variance)", () => {
  const estimate = CostEstimateSchema.parse({
    mode: "full",
    projectedInputTokens: 1000,
    projectedOutputTokens: 500,
    projectedTotalTokens: 1500,
    projectedUsd: 1.0,
    projectedWallClockSeconds: 60,
    basis: "basis",
    createdAt: NOW,
  });

  it("accepts a rollup with only the estimate (actual not yet available)", () => {
    const parsed = CostRollupSchema.parse({ scanId: "scan_1", estimate });
    expect(parsed.actual).toBeUndefined();
  });

  it("accepts a rollup with estimate + actual + variance", () => {
    const actual = CostActualSchema.parse({
      scanId: "scan_1",
      usage,
      actualUsd: 1.1,
      wallClockSeconds: 65,
      updatedAt: NOW,
    });
    const parsed = CostRollupSchema.parse({
      scanId: "scan_1",
      estimate,
      actual,
      costPerFindingUsd: 0.5,
      variancePct: 0.1,
    });
    expect(parsed.variancePct).toBe(0.1);
  });

  it("rejects a rollup missing the required estimate", () => {
    expect(() => CostRollupSchema.parse({ scanId: "scan_1" })).toThrow();
  });

  it("rejects a negative costPerFindingUsd", () => {
    expect(() =>
      CostRollupSchema.parse({ scanId: "scan_1", estimate, costPerFindingUsd: -1 }),
    ).toThrow();
  });
});
