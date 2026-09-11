/**
 * Layer 3 orchestration — turns probable → confirmed, appending the rest.
 *
 * Static confirmation (3a) runs for EVERY probable finding and is the floor.
 * Live DAST (3b) is attempted only when an approver authorized it and every
 * guardrail passes; a live proof upgrades a finding, but a failed live attempt
 * never discards the static proof. The kill switch halts probing instantly.
 *
 * A THIRD path (E1 + E2 + E4, `investigation-pipeline.ts`) is tried only when
 * BOTH of the above miss: an agentic, tool-using investigation loop may
 * propose the finding is exploitable, but that proposal can only become a
 * real confirmation after it clears an executable-evidence gate (a real
 * failing test found in the repo) AND an adversarial multi-verifier majority.
 * OFF by default (`ConfirmDeps.investigation.enabled`) — see that file's
 * header comment for the exact three-gate invariant.
 *
 * Findings that no mode confirms are kept in the Unconfirmed appendix.
 */
import {
  KillSwitchActivatedError,
  Layer3OutputSchema,
  type ConfirmedFinding,
  type Layer3Output,
  type ProbableFinding,
  type UnconfirmedFinding,
} from "@montr/contracts";
import { confirmStatic, toUnconfirmed } from "./static.js";
import { confirmLive, isLiveEligible } from "./live.js";
import { ScopeGuard, assertLiveAuthorized, buildDefaultEgressGuard } from "./guard.js";
import { agentAudit, msg, safeAppend } from "./audit.js";
import { attemptInvestigationConfirmation } from "./investigation-pipeline.js";
import { baseSeverityForCategory } from "./taxonomy.js";
import { structuralConfirmationGate } from "./structural-gate.js";
import type { ConfirmDeps, ConfirmInput, EgressGuardLike } from "./types.js";

/**
 * A3 scoping gate: is this not-yet-confirmed finding eligible for the E1/E2/E4
 * agentic investigation loop? `ConfirmDeps.investigation.severities`
 * (populated in production from `config.confirmation.investigation.severities`,
 * owner default `["high", "critical"]`) restricts the loop to the findings it
 * exists to help — see `types.ts`'s `InvestigationConfig.severities` doc
 * comment. Deliberately uses `baseSeverityForCategory` (the category's class
 * severity), not the exposure-discounted `deriveSeverity` a *confirmed*
 * finding gets: idor/broken_access_control are both base "high" but have
 * zero static data-flow proof at all (this loop is the only static-scan path
 * that can ever confirm them), and the overwhelmingly common real-world
 * instance of either is authenticated-only, not anonymous-public. Gating
 * eligibility on the exposure-discounted severity would downgrade that
 * common case to "medium" and silently exclude it from the default
 * high/critical scope — defeating the reason this loop was built. Absent
 * `severities` ⇒ no restriction (every existing caller that doesn't set it
 * is unaffected).
 */
function isEligibleForInvestigation(finding: ProbableFinding, deps: ConfirmDeps): boolean {
  const severities = deps.investigation?.severities;
  if (!severities || severities.length === 0) return true;
  return severities.includes(baseSeverityForCategory(finding.category));
}

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

    // ⛔ §15 FP loop: a known operator-marked false positive is suppressed to the
    // Unconfirmed appendix (kept, never deleted) BEFORE any confirmation work.
    // Fail-safe: this can only withhold a confirmation, never create one.
    if (
      deps.fpTuning?.isKnownFalsePositive({
        category: finding.category,
        file: finding.location.file,
        line: finding.location.line,
      })
    ) {
      unconfirmed.push(
        toUnconfirmed(
          finding,
          "Matches a known false positive in the regression corpus (§15); suppressed to the appendix pending re-review (fail-safe).",
        ),
      );
      await safeAppend(
        deps,
        agentAudit(
          input,
          "finding.demoted",
          `Suppressed known false positive (static): ${finding.category}`,
          {
            category: finding.category,
            exposure: finding.exposure,
            reason: "known_false_positive",
          },
          finding.id,
        ),
      );
      continue;
    }

    // A11: bounded, deterministic pre-confirmation structural gate — see
    // structural-gate.ts's header comment. Fires ONLY when the App Map being
    // confirmed against no longer registers the exact route this finding was
    // grounded to at correlation time (a hard existence check, never a score
    // or threshold judgment) — so no static proof, live DAST, or agentic
    // investigation effort is spent on a location that has provably
    // disappeared from the app being scanned.
    const structuralGate = structuralConfirmationGate(finding, input.appMap);
    if (structuralGate.ruledOut) {
      unconfirmed.push(toUnconfirmed(finding, structuralGate.reason as string));
      await safeAppend(
        deps,
        agentAudit(
          input,
          "finding.demoted",
          `Structurally ruled out before confirmation: ${finding.category}`,
          {
            category: finding.category,
            exposure: finding.exposure,
            reason: "structurally_ruled_out",
            detail: structuralGate.reason,
            routeId: finding.routeId,
          },
          finding.id,
        ),
      );
      continue;
    }

    const staticOutcome = await confirmStatic(finding, input, deps);

    let live: Awaited<ReturnType<typeof confirmLive>> | undefined;
    if (guard && target && isLiveEligible(finding.category)) {
      // confirmLive throws KillSwitchActivatedError on abort ⇒ propagate (halt everything).
      live = await confirmLive(finding, input, target, guard, deps);
    }

    // A7: the ONE path that may PROMOTE a finding to confirmed on evidence
    // rather than demote it — a successful live-DAST exploit is executable
    // proof (a real HTTP request/response transcript), not a model guess, so
    // it outranks (and can stand without) a static/LLM verdict. Everything
    // else in Layer 3 (the LLM review above) may only veto, never promote.
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
      // E1 + E2 + E4: neither the deterministic taint-proof path nor live
      // DAST confirmed this finding. When explicitly enabled (see
      // ConfirmDeps.investigation — production defaults this ON, scoped by
      // severity, as of A3), give the agentic investigation loop a shot —
      // but it can ONLY promote this finding when its candidate verdict
      // clears BOTH E2's executable-evidence gate AND E4's adversarial
      // majority (see investigation-pipeline.ts's header comment for the
      // full invariant). Any miss falls through unchanged to the exact same
      // unconfirmed-appendix path this code always took.
      //
      // A3 scoping: a finding outside `deps.investigation.severities` (e.g.
      // low/medium under the production default) never even reaches
      // attemptInvestigationConfirmation — this is a cost gate, not just a
      // confirmation-outcome gate, so ineligible findings spend zero extra
      // LLM budget.
      const investigated = isEligibleForInvestigation(finding, deps)
        ? await attemptInvestigationConfirmation(finding, input, deps, staticOutcome.reason)
        : undefined;
      if (investigated) {
        confirmed.push(investigated.finding);
        await safeAppend(
          deps,
          agentAudit(
            input,
            "finding.confirmed",
            `Confirmed (investigation): ${investigated.finding.title}`,
            {
              proofType: "static",
              investigationProof: true,
              category: finding.category,
              severity: investigated.finding.severity,
              adversarialVotes: `${investigated.adversarial.confirmVotes}/${investigated.adversarial.totalVerifiers}`,
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
  }

  // Validate the exact Layer 3 output contract before handing back to the orchestrator.
  return Layer3OutputSchema.parse({ confirmed, unconfirmed });
}
