/**
 * A11 (26-09-12 red/blue agentic-posture audit) — bounded, deterministic
 * pre-confirmation structural gate for Layer 3.
 *
 * Layer 2's grounding (`packages/correlation/src/grounding.ts`) already
 * demotes every candidate it cannot corroborate against the App Map BEFORE
 * it is ever promoted to `probable` (see `groundCandidate`'s `demote`
 * verdict, acted on in `packages/correlation/src/correlate.ts`) — so a
 * `ProbableFinding` reaching Layer 3 was, at correlation time, anchored to a
 * real route/sink/entrypoint/secret-surface/import in that exact App Map
 * instance. This module handles the one case Layer 2 cannot rule out for us:
 * the App Map Layer 3 confirms against can be a DIFFERENT instance than the
 * one that grounded the finding. `apps/worker/src/runners.ts`'s
 * `resolveAppMap` re-resolves the App Map fresh per layer (in-process cache,
 * else the persisted map), and `AppMap.rebuildPolicy`/`stale`
 * (`packages/contracts/src/appmap.ts`) mean a scan paused at a gate (estimate
 * or fix review — see `docs/modules/orchestration.md`) can genuinely resume
 * against a rebuilt map. When a finding's own registered route has vanished
 * from that map, its anchor is now PROVABLY gone — not merely low-scoring —
 * so spending static-proof, live-DAST, or agentic-investigation effort on it
 * would burn real LLM/DAST cost confirming something that structurally
 * cannot exist in the app being scanned right now.
 *
 * Deliberately narrow: this checks ONLY route existence, never a score or
 * threshold. A finding with no `routeId` (off-route: secrets, vulnerable
 * dependencies, cron/webhook/job entrypoints corroborated some other way —
 * see `Grounding.corroborationBasis` in grounding.ts) is never touched here.
 * Layer 2's own corroboration already vouches for those via a different
 * structural surface (an import-graph hit, a secret surface, a non-route
 * entrypoint), and those surfaces are not indexed by file the same way
 * routes are — re-deriving a generic "is this finding's file present
 * anywhere in the App Map" check would risk false-positiving exactly the
 * categories that are legitimately corroborated without ever touching a
 * route, which is precisely the "wrongly skip a real vulnerability" failure
 * mode this gate exists to avoid. So that broader check is intentionally out
 * of scope here — see docs/modules/confirmation.md for the full rationale.
 */
import type { AppMap, ProbableFinding } from "@montr/contracts";

export interface StructuralGateVerdict {
  /** True when this finding's own App Map anchor has provably disappeared. */
  ruledOut: boolean;
  /** Present only when `ruledOut` — the concrete, auditable reason. */
  reason?: string;
}

/**
 * Hard existence check: does the route this finding was grounded against at
 * correlation time still exist in the App Map Layer 3 is confirming against?
 * A finding with no `routeId` is always left alone (`ruledOut: false`).
 */
export function structuralConfirmationGate(
  finding: ProbableFinding,
  appMap: AppMap,
): StructuralGateVerdict {
  if (!finding.routeId) return { ruledOut: false };

  const stillRegistered = appMap.routes.some((r) => r.id === finding.routeId);
  if (stillRegistered) return { ruledOut: false };

  return {
    ruledOut: true,
    reason:
      `structurally ruled out: route ${finding.routeId} that this finding was grounded against ` +
      `at correlation time is no longer registered in the App Map being confirmed against — the ` +
      `route was removed, or the App Map was rebuilt, since correlation ran, so this location is ` +
      `not reachable in the application as currently mapped (a hard existence check against the ` +
      `App Map's own route registry — no scoring or threshold judgment involved)`,
  };
}
