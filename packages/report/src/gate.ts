/**
 * ⛔ PR GATE (golden rule #5, build-plan §5.6, PRD §7 L5).
 *
 * "No PR without passing the auto-eligible bar OR explicit approver approval."
 * The gate is an explicit PIPELINE STATE on the Scan (not a config flag). This
 * module is the single, deterministic authority that decides whether a given
 * fix may become a pull request, and throws a typed {@link GateNotPassedError}
 * when a caller tries to open a PR that the gate does not permit.
 *
 * Fail-safe: anything not clearly permitted is denied (golden rule #4).
 */
import { GateNotPassedError, type Fix, type GateState } from "@montr/contracts";
import { GATE_PASSED_STATES } from "./types.js";

/** Why a fix is or is not eligible to become a PR. */
export type PrGateReason = "ok" | "auto-apply-disabled" | "gate-not-passed" | "not-auto-eligible";

export interface PrGateContext {
  /** The auto-apply toggle for this run (from the Layer-5 job / config). */
  autoApply: boolean;
  /** The scan's current gate state (source of truth). */
  gateState: GateState;
}

export interface PrGateDecision {
  eligible: boolean;
  reason: PrGateReason;
}

/** True iff the pipeline gate has passed (auto-eligible bar OR approver). */
export function isGatePassed(gateState: GateState): boolean {
  return GATE_PASSED_STATES.includes(gateState);
}

/**
 * Decide whether `fix` may be opened as a PR under `ctx`. Pure and total — every
 * branch returns a concrete reason so callers can surface WHY a fix stayed a
 * recommendation. `human-required` fixes are NEVER PR-eligible (hard rule, §11).
 */
export function prGateDecision(ctx: PrGateContext, fix: Fix): PrGateDecision {
  if (!ctx.autoApply) return { eligible: false, reason: "auto-apply-disabled" };
  // Hard rule: auth/session/crypto/access-control (and any human-required fix)
  // are always recommendations, never auto-opened — even with approver approval.
  if (fix.riskClass !== "auto-eligible") {
    return { eligible: false, reason: "not-auto-eligible" };
  }
  if (!isGatePassed(ctx.gateState)) return { eligible: false, reason: "gate-not-passed" };
  return { eligible: true, reason: "ok" };
}

/**
 * ⛔ Assert `fix` may be opened as a PR — throws {@link GateNotPassedError}
 * otherwise. Defense-in-depth: the PR flow filters non-eligible fixes up front,
 * and every opener path re-asserts here before any network call.
 */
export function assertPrGate(ctx: PrGateContext, fix: Fix): void {
  const decision = prGateDecision(ctx, fix);
  if (!decision.eligible) {
    throw new GateNotPassedError(
      `Fix ${fix.id} is not permitted to open a PR: ${decision.reason}`,
      {
        fixId: fix.id,
        reason: decision.reason,
        gateState: ctx.gateState,
        autoApply: ctx.autoApply,
        riskClass: fix.riskClass,
      },
    );
  }
}
