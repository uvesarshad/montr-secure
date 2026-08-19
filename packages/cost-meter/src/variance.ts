import {
  BudgetExceededError,
  CostRollupSchema,
  type BudgetPolicy,
  type CostActual,
  type CostEstimate,
  type CostRollup,
} from "@montr/contracts";
import { getMetrics } from "@montr/telemetry";
import { roundUsd } from "./pricing.js";
import type { BudgetCheck } from "./meter.js";

/**
 * Estimate-vs-actual reconciliation + the hard-halt enforcement helper
 * (build-plan §4.1, DECIDE-4). The variance target is ±15%.
 */

export const VARIANCE_TARGET_PCT = 0.15;

/** (actual − estimate) / estimate, as a signed fraction. 0 when no estimate. */
export function computeVariancePct(estimate: CostEstimate, actual: CostActual): number {
  if (estimate.projectedUsd <= 0) return 0;
  return (actual.actualUsd - estimate.projectedUsd) / estimate.projectedUsd;
}

/** True when the estimate landed within the ±target band of the actuals. */
export function isWithinVarianceTarget(
  variancePct: number,
  target: number = VARIANCE_TARGET_PCT,
): boolean {
  return Math.abs(variancePct) <= target;
}

/** Cost per confirmed finding; `undefined` when there were no findings. */
export function costPerFindingUsd(actualUsd: number, findingCount: number): number | undefined {
  if (findingCount <= 0) return undefined;
  return roundUsd(actualUsd / findingCount);
}

/** Assemble the report-surfaced estimate-vs-actual rollup (§12 cost & scope). */
export function buildCostRollup(
  scanId: string,
  estimate: CostEstimate,
  actual?: CostActual,
  findingCount?: number,
): CostRollup {
  const rollup: Record<string, unknown> = { scanId, estimate };
  if (actual) {
    rollup.actual = actual;
    rollup.variancePct = computeVariancePct(estimate, actual);
    if (findingCount !== undefined) {
      const perFinding = costPerFindingUsd(actual.actualUsd, findingCount);
      if (perFinding !== undefined) rollup.costPerFindingUsd = perFinding;
    }
  }
  return CostRollupSchema.parse(rollup);
}

/**
 * ⛔ Hard-halt enforcement (DECIDE-4). When the ceiling is exceeded and the
 * policy is `hard_halt`, throw `BudgetExceededError` so the orchestrator stops
 * the pipeline and emits a partial report — never silently burns more tokens.
 * `warn` enforcement returns the check unchanged for the caller to surface.
 */
export function enforceBudget(check: BudgetCheck, policy: BudgetPolicy): BudgetCheck {
  if (check.exceeded && policy.enforcement === "hard_halt") {
    // Observability: the headline budget-breach counter (§10 alerting).
    getMetrics().recordBudgetBreach(1, { enforcement: policy.enforcement });
    throw new BudgetExceededError("Budget ceiling exceeded — hard halt", {
      spentUsd: check.spentUsd,
      spentTokens: check.spentTokens,
      maxUsd: policy.maxUsd,
      maxTotalTokens: policy.maxTotalTokens,
    });
  }
  return check;
}
