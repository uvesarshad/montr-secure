/**
 * @montr/cost-meter — pre-scan estimate, live metering, post-scan actuals, and
 * hard-halt budget enforcement (§8.4, DECIDE-4).
 *
 * Wave 0: `priceUsageUsd` is real (deterministic pricing from the reference
 * rate card). The CostMeter accumulator/estimator is a typed stub (WS-B).
 */
import {
  MODEL_COST_RATES,
  NotImplementedError,
  type BudgetPolicy,
  type CostActual,
  type CostEstimate,
  type LayerId,
  type ScanMode,
  type TokenUsage,
} from "@montr/contracts";

/** Deterministic USD price for a token usage against a model's reference rate. */
export function priceUsageUsd(usage: TokenUsage, modelId: string): number {
  const rate = MODEL_COST_RATES.find((r) => r.modelId === modelId);
  if (!rate) return 0;
  return (
    (usage.inputTokens / 1_000_000) * rate.inputPerMillionUsd +
    (usage.outputTokens / 1_000_000) * rate.outputPerMillionUsd
  );
}

export interface EstimateInput {
  scanId: string;
  mode: ScanMode;
  routeCount: number;
  sinkCount: number;
  fileCount: number;
}

export interface MeterEntry {
  modelId: string;
  usage: TokenUsage;
  layer?: LayerId;
}

export interface BudgetCheck {
  withinBudget: boolean;
  exceeded: boolean;
  warn: boolean;
  spentUsd: number;
  spentTokens: number;
}

/** Live cost accumulator + estimator + budget guard for a single scan. */
export interface CostMeter {
  estimate(input: EstimateInput): CostEstimate;
  record(entry: MeterEntry): void;
  actual(): CostActual;
  /** ⛔ Budget ceiling check — drives the hard halt (DECIDE-4). */
  checkBudget(policy: BudgetPolicy): BudgetCheck;
}

export function createCostMeter(_scanId: string): CostMeter {
  throw new NotImplementedError("createCostMeter — WS-B");
}
