/**
 * Layer 3 orchestration — turns probable → confirmed, appending the rest.
 *
 * Static confirmation (3a) runs for EVERY probable finding and is the floor.
 * Live DAST (3b) is attempted only when an approver authorized it and every
 * guardrail passes; a live proof upgrades a finding, but a failed live attempt
 * never discards the static proof. The kill switch halts probing instantly.
 * Findings that neither mode confirms are kept in the Unconfirmed appendix.
 */
import {
  KillSwitchActivatedError,
  Layer3OutputSchema,
  type ConfirmedFinding,
  type Layer3Output,
  type UnconfirmedFinding,
} from "@montr/contracts";
import { confirmStatic, toUnconfirmed } from "./static.js";
import { confirmLive, isLiveEligible } from "./live.js";
import { ScopeGuard, assertLiveAuthorized, buildDefaultEgressGuard } from "./guard.js";
import { agentAudit, msg, safeAppend } from "./audit.js";
import type { ConfirmDeps, ConfirmInput, EgressGuardLike } from "./types.js";

function throwIfKilled(deps: ConfirmDeps): void {
  const sig = deps.signal;
  if (sig?.aborted) {
    const reason = sig.reason;
    throw reason instanceof KillSwitchActivatedError
      ? reason
      : new KillSwitchActivatedError("kill switch activated — halting Layer 3");
  }
}

function hostOfSafe(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/**
 * Confirm a batch of probable findings. Emits the frozen `Layer3Output`
 * (ConfirmedFinding[] + Unconfirmed appendix). Fully offline with no `deps`:
 * pure static confirmation, no live target touched.
 */
export async function confirmFindings(
  input: ConfirmInput,
  deps: ConfirmDeps = {},
): Promise<Layer3Output> {
  // Highest-priority findings first (rank 1 = highest) so caps favor severe issues.
  const probable = [...input.probable].sort((a, b) => a.rank - b.rank);
  const confirmed: ConfirmedFinding[] = [];
  const unconfirmed: UnconfirmedFinding[] = [];

  /* --------------------- ⛔ Live DAST authorization (gated) --------------------- */
  let guard: ScopeGuard | undefined;
  let target: string | undefined;
  const wantLive = input.allowLive && input.config.dast.enabled;
  if (wantLive) {
    try {
      // Re-enforce EVERY guardrail here regardless of the orchestrator (defense in depth).
      target = assertLiveAuthorized({
        config: input.config,
        allowLive: input.allowLive,
        ...(input.stagingUrl !== undefined ? { stagingUrl: input.stagingUrl } : {}),
      });
      const egressGuard: EgressGuardLike =
        deps.egressGuard ?? (await buildDefaultEgressGuard(input.config));
      guard = new ScopeGuard({
        config: input.config,
        egressGuard,
        ...(deps.signal ? { signal: deps.signal } : {}),
        ...(deps.clockMs ? { clockMs: deps.clockMs } : {}),
        ...(deps.sleep ? { sleep: deps.sleep } : {}),
        ...(deps.logger ? { logger: deps.logger } : {}),
      });
      await safeAppend(
        deps,
        agentAudit(input, "dast.authorized", "Live DAST authorized against allowlisted staging.", {
          host: hostOfSafe(target),
          allowlistCount: input.config.dast.allowlist.length,
          scope: input.config.dast.scope,
        }),
      );
      deps.logger?.info?.("layer3: live DAST authorized", { host: hostOfSafe(target) });
    } catch (err) {
      // Authorization/guardrail failure ⇒ NO probing; static confirmation still runs. (Fail-safe.)
      guard = undefined;
      target = undefined;
      deps.logger?.warn?.("layer3: live DAST not authorized; static-only", { reason: msg(err) });
    }
  }

  /* ------------------------------ per-finding loop ----------------------------- */
  for (const finding of probable) {
    throwIfKilled(deps); // ⛔ kill switch halts between findings

    const staticOutcome = await confirmStatic(finding, input, deps);

    let live: Awaited<ReturnType<typeof confirmLive>> | undefined;
    if (guard && target && isLiveEligible(finding.category)) {
      // confirmLive throws KillSwitchActivatedError on abort ⇒ propagate (halt everything).
      live = await confirmLive(finding, input, target, guard, deps);
    }

    if (live?.confirmed && live.finding) {
      confirmed.push(live.finding);
      await safeAppend(
        deps,
        agentAudit(
          input,
          "finding.confirmed",
          `Confirmed (live): ${live.finding.title}`,
          { proofType: "live", category: finding.category, severity: live.finding.severity },
          finding.id,
        ),
      );
    } else if (staticOutcome.kind === "confirmed" && staticOutcome.finding) {
      confirmed.push(staticOutcome.finding);
      await safeAppend(
        deps,
        agentAudit(
          input,
          "finding.confirmed",
          `Confirmed (static): ${staticOutcome.finding.title}`,
          {
            proofType: "static",
            category: finding.category,
            severity: staticOutcome.finding.severity,
          },
          finding.id,
        ),
      );
    } else {
      const reason =
        [staticOutcome.reason, live?.reason].filter((r): r is string => Boolean(r)).join(" | ") ||
        "not confirmed";
      unconfirmed.push(toUnconfirmed(finding, reason));
    }
  }

  // Validate the exact Layer 3 output contract before handing back to the orchestrator.
  return Layer3OutputSchema.parse({ confirmed, unconfirmed });
}
