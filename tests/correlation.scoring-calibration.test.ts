import { describe, it, expect } from "vitest";
import type { CandidateFinding } from "@montr/contracts";
import { classifyCategory, impactScoreFor, type Grounding } from "@montr/correlation";
import { loadCorpus } from "../packages/qa/src/corpus";

/**
 * A26 — calibration regression guard for `packages/correlation/src/scoring.ts`
 * and `packages/correlation/src/taxonomy.ts`'s `CATEGORY_IMPACT_BASE`.
 *
 * Methodology (documented per the audit's ask): the golden corpus has only 44
 * labelled ground-truth findings (11 of them currently confirmed end-to-end by
 * the real pipeline) — too thin for a real statistical fit (a logistic
 * regression over n=44, spread across 20+ categories, would overfit and its
 * coefficients would not be meaningful). Instead this is a DEFENSIBLE, MANUAL
 * recalibration: the corpus's real `severity` labels (several externally
 * sourced — e.g. `corpus/log4shell-vulnerable-app` is literally CVE-2021-44228)
 * were checked against `impactScoreFor`'s ranking, one concrete mis-ranking was
 * found and fixed (see the AGENT NOTE on `CATEGORY_IMPACT_BASE.vulnerable_dependency`
 * in taxonomy.ts), and this test locks the corrected invariant in as a
 * permanent regression guard — this IS the calibration, not a separate step.
 *
 * What's asserted, and why only this much: within a single category, impact is
 * trivially monotonic in severity by construction (0.6*base is constant, only
 * 0.4*severity varies) — asserting that would test arithmetic, not calibration.
 * The real cross-category invariant worth locking in is the one the corpus
 * actually falsified before the fix: a `critical`-severity confirmed-exploitable
 * finding must never be outranked by a merely `high`-severity one, and `high`
 * must never be outranked by `medium` — regardless of category. A stricter
 * `medium` vs `low` boundary is deliberately NOT asserted: at that end of the
 * scale, category-intrinsic impact priors legitimately dominate the tool-
 * assigned severity ladder (e.g. a `low`-severity `weak_crypto` finding can
 * reasonably outscore a `medium`-severity `insecure_cookie` finding — cookie
 * flags have a lower ceiling than a broken crypto primitive even at "medium"),
 * and the corpus gives no evidence that's wrong.
 */

/** Build a minimal Grounding holding reachability/exposure/secrets constant so
 * only `cand.category` + `cand.rawSeverity` drive the comparison. */
function neutralGrounding(category: CandidateFinding["category"]): Grounding {
  const klass = classifyCategory(category);
  return {
    klass,
    authState: "unknown",
    exposure: "public",
    taintFlowKind: klass === "injection" ? "same-file-heuristic" : "none",
    sanitizerInterrupts: false,
    taintReaches: klass === "injection",
    corroborated: true,
    corroborationBasis: "test fixture",
    demote: false,
  };
}

describe("@montr/correlation — scoring calibration against the golden corpus (A26)", () => {
  it("ranks CRITICAL confirmed findings at or above HIGH, and HIGH at or above MEDIUM, across categories", async () => {
    const corpus = await loadCorpus();
    const exploitable = corpus.repos
      .flatMap((r) => r.expectedFindings)
      .filter((f) => f.exploitable);

    // Sanity: the corpus must actually exercise every severity tier we assert
    // across, or this test would pass vacuously.
    const bySeverity: Record<string, number[]> = {};
    for (const f of exploitable) {
      const cand = { category: f.category, rawSeverity: f.severity } as CandidateFinding;
      const impact = impactScoreFor(cand, neutralGrounding(f.category));
      (bySeverity[f.severity] ??= []).push(impact);
    }
    expect(bySeverity.critical?.length ?? 0).toBeGreaterThan(0);
    expect(bySeverity.high?.length ?? 0).toBeGreaterThan(0);
    expect(bySeverity.medium?.length ?? 0).toBeGreaterThan(0);

    const min = (xs: number[]) => Math.min(...xs);
    const max = (xs: number[]) => Math.max(...xs);

    // The concrete case this fixes: corpus/log4shell-vulnerable-app's
    // `vulnerable_dependency` finding is `critical` (CVE-2021-44228) — before
    // the A26 fix it scored 0.70, below several `high` findings (0.72-0.81).
    expect(min(bySeverity.critical!)).toBeGreaterThanOrEqual(max(bySeverity.high!));
    expect(min(bySeverity.high!)).toBeGreaterThanOrEqual(max(bySeverity.medium!));
  });

  it("the log4shell critical dependency finding now outranks every high-severity finding in the corpus", async () => {
    const corpus = await loadCorpus();
    const log4shell = corpus.repos
      .flatMap((r) => r.expectedFindings)
      .find((f) => f.category === "vulnerable_dependency" && f.severity === "critical");
    expect(log4shell, "corpus must still contain the Log4Shell ground-truth finding").toBeDefined();

    const log4shellImpact = impactScoreFor(
      { category: log4shell!.category, rawSeverity: log4shell!.severity } as CandidateFinding,
      neutralGrounding(log4shell!.category),
    );

    const highImpacts = corpus.repos
      .flatMap((r) => r.expectedFindings)
      .filter((f) => f.exploitable && f.severity === "high")
      .map((f) =>
        impactScoreFor(
          { category: f.category, rawSeverity: f.severity } as CandidateFinding,
          neutralGrounding(f.category),
        ),
      );

    for (const h of highImpacts) expect(log4shellImpact).toBeGreaterThanOrEqual(h);
  });
});
