import { describe, it, expect } from "vitest";
import { BudgetPolicySchema } from "@montr/contracts";
import { createNullLogger, type Logger, type LogFields } from "@montr/telemetry";
import { createCostMeter } from "./meter.js";

/**
 * Package-local unit suite for the live cost meter (§8.4). The root-level
 * `tests/cost-meter.core.test.ts` covers a nominal accumulate-by-model/layer
 * case, injected-clock wall-clock measurement, and a basic exceeded/warn
 * budget check — this file owns: running-total accuracy across many events,
 * the "unattributed" bucket, `estimate()` delegation, and the exact `>` (not
 * `>=`) boundary in `checkBudget` that DECIDE-4's hard-halt depends on.
 */

describe("live cost meter — running total accuracy", () => {
  it("accumulates the running total correctly as usage events stream in one at a time", () => {
    const meter = createCostMeter("scan_1", { now: () => new Date("2026-08-19T00:00:00.000Z") });
    let expectedTokens = 0;
    for (let i = 1; i <= 10; i++) {
      meter.record({
        modelId: "claude-sonnet-5",
        usage: { inputTokens: i * 100, outputTokens: i * 10, totalTokens: i * 110 },
      });
      expectedTokens += i * 110;
      expect(meter.actual().usage.totalTokens).toBe(expectedTokens);
    }
    expect(meter.actual().usage.totalTokens).toBe(6050);
  });

  it("reports zero usage/cost before any call is recorded", () => {
    const meter = createCostMeter("scan_1");
    const actual = meter.actual();
    expect(actual.usage.totalTokens).toBe(0);
    expect(actual.actualUsd).toBe(0);
    expect(actual.byLayer).toEqual([]);
    expect(actual.byModel).toEqual([]);
  });

  it("buckets entries with no layer under 'unattributed'", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 100, outputTokens: 10, totalTokens: 110 },
    });
    expect(meter.actual().byLayer.map((l) => l.key)).toEqual(["unattributed"]);
  });

  it("merges repeated calls to the same layer/model bucket rather than duplicating entries", () => {
    const meter = createCostMeter("scan_1");
    for (let i = 0; i < 3; i++) {
      meter.record({
        modelId: "claude-sonnet-5",
        usage: { inputTokens: 1000, outputTokens: 100, totalTokens: 1100 },
        layer: "layer2",
      });
    }
    const actual = meter.actual();
    expect(actual.byLayer.length).toBe(1);
    expect(actual.byLayer[0]!.usage.totalTokens).toBe(3300);
    expect(actual.byModel.length).toBe(1);
    expect(actual.byModel[0]!.usage.totalTokens).toBe(3300);
  });

  it("fails closed and warns through the injected logger when recording an unknown model (A1)", () => {
    const calls: Array<{ message: string; fields?: LogFields }> = [];
    const warn: Logger["warn"] = (message, fields) => {
      calls.push({ message, fields });
    };
    const logger: Logger = { ...createNullLogger(), warn };
    const meter = createCostMeter("scan_1", { logger });
    meter.record({
      modelId: "gpt-4o",
      usage: { inputTokens: 1_000_000, outputTokens: 1_000_000, totalTokens: 2_000_000 },
    });
    // Never $0 — bills the conservative fallback ceiling.
    expect(meter.actual().actualUsd).toBeGreaterThan(0);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.message).toBe("cost_meter.unknown_model_rate");
    expect(calls[0]!.fields).toMatchObject({ modelId: "gpt-4o" });
  });

  it("delegates estimate() to the pre-scan estimator using the meter's own clock + model options", () => {
    const now = () => new Date("2026-08-19T00:00:00.000Z");
    const meter = createCostMeter("scan_1", {
      now,
      estimate: { defaultModelId: "claude-haiku-4-5", confirmationModelId: "claude-opus-4-8" },
    });
    const est = meter.estimate({
      scanId: "scan_1",
      mode: "full",
      routeCount: 1,
      sinkCount: 1,
      fileCount: 1,
    });
    expect(est.createdAt).toBe("2026-08-19T00:00:00.000Z");
    expect(est.scanId).toBe("scan_1");
  });
});

describe("live cost meter — checkBudget boundary (DECIDE-4)", () => {
  it("does NOT flag exceeded when spend lands exactly on the USD ceiling", () => {
    const meter = createCostMeter("scan_1");
    // Sonnet-5 input $3/M: 1,000,000 input tokens → exactly $3.00.
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 1_000_000, outputTokens: 0, totalTokens: 1_000_000 },
    });
    const check = meter.checkBudget(BudgetPolicySchema.parse({ maxUsd: 3 }));
    expect(check.spentUsd).toBe(3);
    expect(check.exceeded).toBe(false);
    expect(check.withinBudget).toBe(true);
  });

  it("flags exceeded the instant spend crosses one cent past the USD ceiling", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 1_000_001, outputTokens: 0, totalTokens: 1_000_001 },
    });
    const check = meter.checkBudget(BudgetPolicySchema.parse({ maxUsd: 3 }));
    expect(check.spentUsd).toBeGreaterThan(3);
    expect(check.exceeded).toBe(true);
    expect(check.withinBudget).toBe(false);
  });

  it("does NOT flag exceeded when spend lands exactly on the token ceiling", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 500, outputTokens: 500, totalTokens: 1000 },
    });
    const check = meter.checkBudget(BudgetPolicySchema.parse({ maxTotalTokens: 1000 }));
    expect(check.exceeded).toBe(false);
  });

  it("flags exceeded the instant spend crosses one token past the token ceiling", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 500, outputTokens: 501, totalTokens: 1001 },
    });
    const check = meter.checkBudget(BudgetPolicySchema.parse({ maxTotalTokens: 1000 }));
    expect(check.exceeded).toBe(true);
  });

  it("is exceeded if EITHER the USD or the token ceiling is crossed", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 2_000_000, outputTokens: 0, totalTokens: 2_000_000 },
    });
    // Under the USD ceiling but over the token ceiling.
    const check = meter.checkBudget(
      BudgetPolicySchema.parse({ maxUsd: 100, maxTotalTokens: 1_000_000 }),
    );
    expect(check.exceeded).toBe(true);
  });

  it("warns at the configured warnThresholdPct but never once exceeded (warn and exceeded are exclusive)", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 900_000, outputTokens: 0, totalTokens: 900_000 },
    });
    // Spent $2.70. Ceiling $3, warn at 90% ($2.70) → warn, not exceeded.
    const check = meter.checkBudget(BudgetPolicySchema.parse({ maxUsd: 3, warnThresholdPct: 0.9 }));
    expect(check.spentUsd).toBe(2.7);
    expect(check.warn).toBe(true);
    expect(check.exceeded).toBe(false);
  });

  it("never exceeds or warns when no ceiling is configured at all", () => {
    const meter = createCostMeter("scan_1");
    meter.record({
      modelId: "claude-opus-4-8",
      usage: { inputTokens: 10_000_000, outputTokens: 10_000_000, totalTokens: 20_000_000 },
    });
    const check = meter.checkBudget(BudgetPolicySchema.parse({}));
    expect(check.exceeded).toBe(false);
    expect(check.warn).toBe(false);
    expect(check.withinBudget).toBe(true);
  });
});
