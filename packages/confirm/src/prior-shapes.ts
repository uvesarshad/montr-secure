/**
 * E8 extension — confirmed-exploit-shape priors for Layer 3 (2026-09-12
 * red/blue agentic-posture audit's "extend cross-scan learning beyond false
 * positives" suggested enhancement).
 *
 * A small, well-typed seam — byte-identical to
 * `packages/correlation/src/prior-shapes.ts`'s copy of this file, mirroring
 * `./tuning.ts`'s existing cross-package duplication convention — so
 * `apps/worker/src/runners.ts` can build ONE runtime object (from
 * `@montr/state-store`'s `confirmed_exploit_shape` learned facts,
 * `packages/state-store/src/learned-facts.ts`) that satisfies both this
 * package's `ConfirmDeps.priorConfirmedShapes` and
 * `@montr/correlation`'s `CorrelateInput.priorConfirmedShapes` without either
 * package taking a build-time dependency on `@montr/state-store` or on each
 * other (golden rule #9).
 *
 * ⛔ Consulted in exactly ONE place, `confirm.ts`'s `isEligibleForInvestigation`:
 * a match may only WIDEN which not-yet-confirmed findings get a shot at the
 * E1/E2/E4 agentic investigation loop when the finding's category falls
 * outside `ConfirmDeps.investigation.severities`' configured scope. It can
 * NEVER itself confirm a finding, skip E2's real executable-evidence gate, or
 * skip E4's adversarial majority — every existing invariant in
 * `investigation-pipeline.ts` still applies in full; this only changes
 * whether the attempt is made at all. Absent (every existing caller/test) ⇒
 * byte-identical to before this feature.
 */
import type { Category } from "@montr/contracts";

/** The finding shape a prior confirmed-exploit signature is matched against — metadata only. */
export interface ConfirmedShapeSignal {
  category: Category;
  file: string;
}

/** Injected confirmed-exploit-shape priors. Consumers may only widen investigation
 * eligibility — see this file's header for the full contract. */
export interface PriorConfirmedShapes {
  /** True when this signal structurally matches a shape this repo has
   * previously, genuinely confirmed exploitable (same category, same coarse
   * directory — see `apps/worker/src/runners.ts`'s `filePatternOf`). */
  matches(signal: ConfirmedShapeSignal): boolean;
}
