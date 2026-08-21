import type { BudgetPolicy } from "@montr/contracts";
import type { CostMeter } from "./meter.js";

/**
 * Cross-package seam for the PRE-call budget guard (A2, DECIDE-4).
 *
 * `LiveCostMeter.checkBudget` is a pure computation over already-accumulated
 * totals — nothing stopped a single in-flight layer from issuing one LLM call
 * whose cost alone blew past the ceiling, because `@montr/orchestrator` only
 * consulted the meter BETWEEN layers (`controller.ts`'s `enforceBudget`, after
 * `executeLayer` resolves). This registry lets the orchestrator REGISTER each
 * running scan's live `CostMeter` + effective `BudgetPolicy` the moment a layer
 * starts, and lets `@montr/llm-gateway` READ that same pair (keyed by
 * `LLMRequest.metadata.scanId`) to refuse a call BEFORE it is dispatched to a
 * provider, when its estimated cost would push spend past the ceiling.
 *
 * Both packages already depend on `@montr/cost-meter`, so this is the natural
 * shared home — it adds no new inter-package dependency and reuses the SAME
 * `CostMeter` instance `enforceBudget` reads, rather than inventing a parallel
 * budget-tracking mechanism.
 */

/** The live budget state for one running scan: its meter + the ceiling in effect. */
export interface BudgetContext {
  readonly meter: CostMeter;
  readonly policy: BudgetPolicy;
}

export interface BudgetRegistry {
  /** Called once a layer begins executing for `scanId` (or its policy changes). */
  register(scanId: string, meter: CostMeter, policy: BudgetPolicy): void;
  /** Called when the scan reaches a terminal state / is cleaned up. */
  unregister(scanId: string): void;
  /** Read the current budget context for `scanId`, if any is registered. */
  get(scanId: string): BudgetContext | undefined;
}

/** In-memory `BudgetRegistry` — one per worker process, shared by the gateway. */
export function createBudgetRegistry(): BudgetRegistry {
  const byScan = new Map<string, BudgetContext>();
  return {
    register(scanId, meter, policy) {
      byScan.set(scanId, { meter, policy });
    },
    unregister(scanId) {
      byScan.delete(scanId);
    },
    get(scanId) {
      return byScan.get(scanId);
    },
  };
}
