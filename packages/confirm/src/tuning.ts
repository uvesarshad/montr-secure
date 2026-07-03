/**
 * §15 False-positive tuning hook for Layer 3.
 *
 * A small, well-typed seam so the regression corpus (operator-marked false
 * positives, owned by @montr/qa) can tune confirmation WITHOUT this package
 * taking a build-time dependency on the QA harness (golden rule #9). @montr/qa's
 * `buildFalsePositiveTuning(...)` returns a structurally-compatible object,
 * injected via `ConfirmDeps.fpTuning`.
 *
 * ⛔ Additive + fail-safe by contract: a match may only SKIP confirmation and
 * route the finding to the Unconfirmed appendix (kept, never deleted). It can
 * never confirm a finding and never relax a guardrail — a stale corpus only makes
 * Layer 3 MORE conservative. Metadata only — the signal carries category +
 * location, never a code body (golden rule #1).
 */
import type { Category } from "@montr/contracts";

/** The finding location the tuning set is matched against — metadata only. */
export interface FalsePositiveSignal {
  category: Category;
  file: string;
  line: number;
  ruleId?: string;
}

/** Injected regression-corpus tuning. Consumers may only skip/demote a match. */
export interface FalsePositiveTuning {
  /** True when this signal matches an operator-marked known false positive. */
  isKnownFalsePositive(signal: FalsePositiveSignal): boolean;
}
