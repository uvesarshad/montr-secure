/**
 * Pure pipeline state-machine logic (no I/O). The orchestrator is an explicit
 * FSM: L0→L1→L2→L3→L4→L5 with the gate modelled as a real pipeline STATE, never
 * a config flag (golden rule #5, PRD §6.2). Keeping these decisions pure makes
 * the whole flow deterministic and unit-testable offline.
 */
import {
  BudgetPolicySchema,
  type BudgetPolicy,
  type Fix,
  type LayerId,
  type Scan,
  type ScanStatus,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

/** Canonical layer execution order. */
export const LAYER_ORDER: readonly LayerId[] = [
  "layer0",
  "layer1",
  "layer2",
  "layer3",
  "layer4",
  "layer5",
] as const;

/** The next layer to run given the set of already-completed layers, or null when done. */
export function nextLayer(completed: readonly LayerId[]): LayerId | null {
  const done = new Set(completed);
  for (const layer of LAYER_ORDER) {
    if (!done.has(layer)) return layer;
  }
  return null;
}

/** The layer that follows `layer`, or null if `layer` is the last one. */
export function layerAfter(layer: LayerId): LayerId | null {
  const idx = LAYER_ORDER.indexOf(layer);
  if (idx < 0 || idx >= LAYER_ORDER.length - 1) return null;
  return LAYER_ORDER[idx + 1] ?? null;
}

/** Terminal scan statuses — the FSM never schedules further work from these. */
const TERMINAL_STATUSES: ReadonlySet<ScanStatus> = new Set<ScanStatus>([
  "completed",
  "failed",
  "cancelled",
  "partial",
]);

export function isTerminalStatus(status: ScanStatus): boolean {
  return TERMINAL_STATUSES.has(status);
}

/**
 * Resolve the effective budget ceiling for a scan: the per-scan override if
 * present, else the deployment default from config. DECIDE-4: hard-halt default.
 */
export function effectiveBudgetPolicy(scan: Scan, config: MontrConfig): BudgetPolicy {
  if (scan.budgetPolicy) return scan.budgetPolicy;
  return BudgetPolicySchema.parse({
    maxUsd: config.budget.maxUsdPerScan,
    maxTotalTokens: config.budget.maxTokensPerScan,
    enforcement: config.budget.enforcement,
    requireEstimateApproval: config.budget.requireEstimateApproval,
    warnThresholdPct: config.budget.warnThresholdPct,
  });
}

/**
 * Pre-scan estimate gate (§7 L0): surface the CostEstimate and, per policy,
 * require acknowledgement before Layer 1 fires any expensive work.
 */
export function estimateGateRequired(scan: Scan, config: MontrConfig): boolean {
  return effectiveBudgetPolicy(scan, config).requireEstimateApproval;
}

/** Outcome of evaluating the fix gate after Layer 4. */
export interface FixGateDecision {
  /** True when the pipeline would open PRs (auto-fix ON + auto-eligible fixes exist). */
  readonly wouldOpenPrs: boolean;
  /** IDs of fixes that passed the auto-eligible bar. */
  readonly autoEligibleFixIds: string[];
}

/**
 * ⛔ The fix gate is a SAFETY control (golden rule #5, §11). Code changes may
 * proceed ONLY for `auto-eligible` fixes that pass the classifier's bar and are
 * permitted by policy. `human-required` fixes are NEVER auto-opened — they stay
 * recommendations. Uncertainty resolves toward LESS autonomy (golden rule #4):
 * anything not provably auto-eligible is excluded here.
 */
export function evaluateFixGate(fixes: readonly Fix[], config: MontrConfig): FixGateDecision {
  const allowed = new Set(config.autoFix.allowedRiskClasses);
  const autoEligible = fixes.filter(
    (f) => f.riskClass === "auto-eligible" && allowed.has(f.riskClass),
  );
  return {
    wouldOpenPrs: config.autoFix.enabled && autoEligible.length > 0,
    autoEligibleFixIds: autoEligible.map((f) => f.id),
  };
}

/**
 * ⛔ Whether live DAST (Layer 3b) may fire for this scan. Fail-safe: defaults to
 * FALSE and only flips true when EVERY guardrail is satisfied — DAST enabled, a
 * staging target that is on the allowlist, production blocked, and (per policy)
 * an approver on record (§11, DECIDE-1). Static confirmation is the default.
 */
export function computeAllowLive(scan: Scan, config: MontrConfig): boolean {
  const dast = config.dast;
  if (!dast.enabled) return false;
  const url = scan.scope.stagingUrl;
  if (!url) return false;
  if (dast.allowlist.length === 0) return false;
  const allowlisted = dast.allowlist.some((entry) => url === entry || url.startsWith(entry));
  if (!allowlisted) return false;
  if (dast.requireApprover && !scan.approver) return false;
  return true;
}
