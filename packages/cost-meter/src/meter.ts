import type {
  BudgetPolicy,
  CostActual,
  CostEstimate,
  CostLineItem,
  LayerId,
  TokenUsage,
} from "@montr/contracts";
import { addUsage, priceUsageUsd, roundUsd, zeroUsage } from "./pricing.js";
import { estimateScanCost, type EstimateInput, type EstimateOptions } from "./estimate.js";

/**
 * Live cost meter (§8.4): estimate before, meter during, report after. Accumulates
 * per-call token accounting emitted by the LLM gateway and answers the hard-halt
 * budget check (DECIDE-4). Pure/deterministic given an injected clock.
 */

/** A single metered LLM call, emitted by the gateway after each request. */
export interface MeterEntry {
  modelId: string;
  usage: TokenUsage;
  layer?: LayerId;
}

/** Result of a budget-ceiling check. `exceeded` drives the hard halt. */
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

export interface CostMeterOptions {
  /** Injectable clock for deterministic wall-clock + timestamps. */
  now?: () => Date;
  /** Pricing models passed through to the pre-scan estimator. */
  estimate?: Pick<EstimateOptions, "defaultModelId" | "confirmationModelId">;
}

interface Bucket {
  usage: TokenUsage;
  usd: number;
}

function toLineItems(map: Map<string, Bucket>): CostLineItem[] {
  return [...map.entries()].map(([key, b]) => ({ key, usage: b.usage, usd: roundUsd(b.usd) }));
}

class LiveCostMeter implements CostMeter {
  private readonly now: () => Date;
  private readonly startedAt: number;
  private readonly byLayer = new Map<string, Bucket>();
  private readonly byModel = new Map<string, Bucket>();
  private total: TokenUsage = zeroUsage();
  private totalUsd = 0;

  constructor(
    private readonly scanId: string,
    private readonly options: CostMeterOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.startedAt = this.now().getTime();
  }

  estimate(input: EstimateInput): CostEstimate {
    return estimateScanCost(input, { now: this.now, ...this.options.estimate });
  }

  record(entry: MeterEntry): void {
    const usd = priceUsageUsd(entry.usage, entry.modelId);
    this.total = addUsage(this.total, entry.usage);
    this.totalUsd = roundUsd(this.totalUsd + usd);
    this.merge(this.byLayer, entry.layer ?? "unattributed", entry.usage, usd);
    this.merge(this.byModel, entry.modelId, entry.usage, usd);
  }

  private merge(map: Map<string, Bucket>, key: string, usage: TokenUsage, usd: number): void {
    const prev = map.get(key);
    if (prev) {
      prev.usage = addUsage(prev.usage, usage);
      prev.usd = roundUsd(prev.usd + usd);
    } else {
      map.set(key, { usage: { ...usage }, usd });
    }
  }

  actual(): CostActual {
    return {
      scanId: this.scanId,
      usage: this.total,
      actualUsd: roundUsd(this.totalUsd),
      wallClockSeconds: Math.max(0, (this.now().getTime() - this.startedAt) / 1000),
      byLayer: toLineItems(this.byLayer),
      byModel: toLineItems(this.byModel),
      updatedAt: this.now().toISOString(),
    };
  }

  checkBudget(policy: BudgetPolicy): BudgetCheck {
    const spentUsd = roundUsd(this.totalUsd);
    const spentTokens = this.total.totalTokens;
    let exceeded = false;
    let warn = false;

    if (policy.maxUsd !== undefined) {
      if (spentUsd > policy.maxUsd) exceeded = true;
      else if (spentUsd >= policy.maxUsd * policy.warnThresholdPct) warn = true;
    }
    if (policy.maxTotalTokens !== undefined) {
      if (spentTokens > policy.maxTotalTokens) exceeded = true;
      else if (spentTokens >= policy.maxTotalTokens * policy.warnThresholdPct) warn = true;
    }

    return { withinBudget: !exceeded, exceeded, warn: warn && !exceeded, spentUsd, spentTokens };
  }
}

/** Create a live cost meter for a scan. */
export function createCostMeter(scanId: string, options: CostMeterOptions = {}): CostMeter {
  return new LiveCostMeter(scanId, options);
}
