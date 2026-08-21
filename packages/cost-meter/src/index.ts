/**
 * @montr/cost-meter — cost is a first-class output (golden rule #8): pre-scan
 * estimate (from App-Map size × scan mode), live per-call metering, post-scan
 * actuals, cost-per-scan / cost-per-finding rollups, estimate-vs-actual variance
 * (±15% target), and a HARD-HALT budget ceiling (DECIDE-4). Deterministic and
 * offline — no network, no ambient clock unless one is injected.
 */
export {
  priceUsageUsd,
  findModelRate,
  normalizeModelId,
  addUsage,
  zeroUsage,
  roundUsd,
} from "./pricing.js";
export { UNKNOWN_MODEL_FALLBACK_RATE } from "@montr/contracts";

export { estimateScanCost, type EstimateInput, type EstimateOptions } from "./estimate.js";

export {
  createCostMeter,
  type CostMeter,
  type CostMeterOptions,
  type MeterEntry,
  type BudgetCheck,
} from "./meter.js";

export {
  buildCostRollup,
  computeVariancePct,
  costPerFindingUsd,
  enforceBudget,
  isWithinVarianceTarget,
  VARIANCE_TARGET_PCT,
} from "./variance.js";

export { createBudgetRegistry, type BudgetContext, type BudgetRegistry } from "./registry.js";
