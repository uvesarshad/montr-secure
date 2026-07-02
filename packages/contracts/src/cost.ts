import { z } from "zod";
import { IdSchema, IsoDateTimeSchema } from "./primitives.js";
import { ScanModeSchema } from "./enums.js";
import { TokenUsageSchema } from "./llm.js";

/**
 * Cost contracts (§8.4). Cost is a first-class output: estimate before, meter
 * during, report after. Budget ceiling = hard halt + partial report (DECIDE-4).
 */

/** DECIDE-4: default budget behavior is a hard halt (never silently burn tokens). */
export const BudgetEnforcementSchema = z.enum(["hard_halt", "warn"]);
export type BudgetEnforcement = z.infer<typeof BudgetEnforcementSchema>;

/** A single line in a cost breakdown (per layer, per model, ...). */
export const CostLineItemSchema = z.object({
  key: z.string(),
  usage: TokenUsageSchema,
  usd: z.number().nonnegative(),
});
export type CostLineItem = z.infer<typeof CostLineItemSchema>;

/** Pre-scan projection from map size × scan mode (Layer 0 output). */
export const CostEstimateSchema = z.object({
  scanId: IdSchema.optional(),
  mode: ScanModeSchema,
  projectedInputTokens: z.number().int().nonnegative(),
  projectedOutputTokens: z.number().int().nonnegative(),
  projectedTotalTokens: z.number().int().nonnegative(),
  projectedUsd: z.number().nonnegative(),
  projectedWallClockSeconds: z.number().nonnegative(),
  /** How the estimate was derived (e.g. "routes×sinks × mode multiplier"). */
  basis: z.string(),
  byLayer: z.array(CostLineItemSchema).default([]),
  createdAt: IsoDateTimeSchema,
});
export type CostEstimate = z.infer<typeof CostEstimateSchema>;

/** Metered actuals accumulated during and after the scan. */
export const CostActualSchema = z.object({
  scanId: IdSchema,
  usage: TokenUsageSchema,
  actualUsd: z.number().nonnegative(),
  wallClockSeconds: z.number().nonnegative(),
  byLayer: z.array(CostLineItemSchema).default([]),
  byModel: z.array(CostLineItemSchema).default([]),
  updatedAt: IsoDateTimeSchema,
});
export type CostActual = z.infer<typeof CostActualSchema>;

/** Optional per-scan budget ceiling. */
export const BudgetPolicySchema = z.object({
  maxUsd: z.number().positive().optional(),
  maxTotalTokens: z.number().int().positive().optional(),
  enforcement: BudgetEnforcementSchema.default("hard_halt"),
  /** Require operator/approver to accept the estimate before Layer 1. */
  requireEstimateApproval: z.boolean().default(true),
  /** Emit a budget warning at this fraction of the ceiling (0..1). */
  warnThresholdPct: z.number().min(0).max(1).default(0.8),
});
export type BudgetPolicy = z.infer<typeof BudgetPolicySchema>;

/** Estimate-vs-actual rollup surfaced in the report (variance target ±15%). */
export const CostRollupSchema = z.object({
  scanId: IdSchema,
  estimate: CostEstimateSchema,
  actual: CostActualSchema.optional(),
  costPerFindingUsd: z.number().nonnegative().optional(),
  /** (actual - estimate) / estimate, as a fraction. */
  variancePct: z.number().optional(),
});
export type CostRollup = z.infer<typeof CostRollupSchema>;
