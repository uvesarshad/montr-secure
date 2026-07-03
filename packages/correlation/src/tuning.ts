/**
 * §15 False-positive tuning hook for Layer 2.
 *
 * A small, well-typed seam so the regression corpus (operator-marked false
 * positives, owned by @montr/qa) can tune correlation WITHOUT this package taking
 * a build-time dependency on the QA harness (golden rule #9). @montr/qa's
 * `buildFalsePositiveTuning(...)` returns a structurally-compatible object that
 * is injected via `CorrelateInput.fpTuning`.
 *
 * ⛔ Additive + fail-safe by contract: a match may only DOWN-RANK / DEMOTE a
 * candidate to the appendix (never delete it, never promote it, never relax a
 * guardrail). A stale corpus can therefore only make correlation MORE
 * conservative. Metadata only — the signal carries category + location, never a
 * code body (golden rule #1).
 */
import type { Category } from "@montr/contracts";

/** The finding location the tuning set is matched against — metadata only. */
export interface FalsePositiveSignal {
  category: Category;
  file: string;
  line: number;
  ruleId?: string;
}

/** Injected regression-corpus tuning. Consumers may only down-rank/skip a match. */
export interface FalsePositiveTuning {
  /** True when this signal matches an operator-marked known false positive. */
  isKnownFalsePositive(signal: FalsePositiveSignal): boolean;
}
