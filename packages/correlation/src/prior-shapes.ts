/**
 * E8 extension — confirmed-exploit-shape priors for Layer 2 (2026-09-12
 * red/blue agentic-posture audit's "extend cross-scan learning beyond false
 * positives" suggested enhancement).
 *
 * A small, well-typed seam — structurally identical to `./tuning.ts`'s
 * `FalsePositiveTuning`, and to `packages/confirm/src/prior-shapes.ts`'s copy
 * of THIS file — so `apps/worker/src/runners.ts` can build ONE runtime object
 * (from `@montr/state-store`'s `confirmed_exploit_shape` learned facts,
 * `packages/state-store/src/learned-facts.ts`) that satisfies both packages'
 * seams without either package taking a build-time dependency on
 * `@montr/state-store` or on each other (golden rule #9).
 *
 * ⛔ Polarity is the OPPOSITE of `FalsePositiveTuning`, and the contract is
 * correspondingly narrower: a match may only ADD a purely informational
 * sentence to a finding's reachability hypothesis and break a tie in RANK
 * ORDER among findings otherwise perfectly equal on every corpus-calibrated
 * score (`combinedScore`, `impactScore`, `reachabilityScore`, severity — see
 * `scoring.ts` and `correlate.ts`'s `comparePending`). It NEVER changes the
 * persisted `reachabilityScore` / `exposureScore` / `impactScore` values
 * themselves — those stay exactly what the deterministic App Map grounding
 * (plus the existing bounded LLM nudge) computes, since that formula is
 * calibrated against the golden corpus (see `taxonomy.ts`'s AGENT NOTE on
 * `CATEGORY_IMPACT_BASE`) and a repo-specific prior is not a corpus-validated
 * scoring signal. A match can never promote a candidate the App Map grounding
 * would otherwise demote, and it can never suppress/skip the LLM enrichment
 * or semantic-grounding steps that already run. Absent (every existing
 * caller/test) ⇒ byte-identical to before this feature.
 */
import type { Category } from "@montr/contracts";

/** The finding shape a prior confirmed-exploit signature is matched against — metadata only. */
export interface ConfirmedShapeSignal {
  category: Category;
  file: string;
}

/** Injected confirmed-exploit-shape priors. Consumers may only add informational
 * context and break rank ties — see this file's header for the full contract. */
export interface PriorConfirmedShapes {
  /** True when this signal structurally matches a shape this repo has
   * previously, genuinely confirmed exploitable (same category, same coarse
   * directory — see `apps/worker/src/runners.ts`'s `filePatternOf`). */
  matches(signal: ConfirmedShapeSignal): boolean;
}
