import type { Category } from "@montr/contracts";

/**
 * Detection-coverage regression gate (mirrors `packages/qa/src/scorer.ts` /
 * `blue-team-corpus.ts`'s scoring shape) — measures whether a CONFIRMED
 * finding from the golden corpus lands on a route with real telemetry. Feeds
 * A7's tri-state `DetectionCoverage.detected` verdict
 * (`packages/appmap/src/coverage-analysis.ts`'s `evaluateCoverageForFinding`),
 * now persisted for real per confirmed finding via
 * `persistDetectionCoverageForScan`, wired into `apps/worker/src/runners.ts`'s
 * Layer 3 runner.
 *
 * `detected` is a tri-state verdict, and the three states carry very
 * different weight for a regression gate:
 *   - `false`  — a GENUINE gap: the route was resolved and analyzed for
 *     telemetry, and it either has no logging call at all, or has logging but
 *     no detection rule covering this finding yet. This is exactly the "a
 *     newly confirmed finding lands on a route with no telemetry" case the
 *     task brief names, and the ONLY state this gate's threshold is built
 *     from.
 *   - `"unknown"` — genuinely ambiguous (the route could not be linked at
 *     all, the route was never analyzed for per-route logging presence, or
 *     logging exists but is console-only with no structured fields to
 *     evaluate). Never treated as a real regression signal by itself —
 *     surfaced only as an informational rate, mirroring the blue-team-corpus
 *     gate's discipline of never letting ambiguity masquerade as a real
 *     signal (see `docs/infra/testing.md`'s Blue-Team Detection Corpus
 *     section on `detectionPrecisionMin` being a dormant, not a live, floor).
 *   - `true`   — covered: real telemetry AND a real detection rule exist for
 *     this finding.
 */
export interface DetectionCoverageEntry {
  repo: string;
  findingId: string;
  category: Category;
  detected: boolean | "unknown";
  reasoning: string;
}

/** Per-repo breakdown of the same tri-state counts. */
export interface PerRepoDetectionCoverage {
  repo: string;
  totalConfirmedFindings: number;
  detectedTrue: number;
  detectedFalse: number;
  detectedUnknown: number;
}

/** Aggregate score across every confirmed finding a real run produced coverage for. */
export interface DetectionCoverageScore {
  totalConfirmedFindings: number;
  detectedTrue: number;
  detectedFalse: number;
  detectedUnknown: number;
  /**
   * detectedFalse / totalConfirmedFindings — the ONLY metric this gate's
   * baseline threshold is built from (a real, unambiguous telemetry gap).
   * 0 when there are no confirmed findings to grade (vacuously no gaps).
   */
  gapRate: number;
  /** detectedUnknown / totalConfirmedFindings — informational only, never gates. */
  unknownRate: number;
  /** detectedTrue / totalConfirmedFindings — informational only. */
  coverageRate: number;
  /** Number of distinct repos that contributed at least one confirmed finding. */
  reposScored: number;
  perRepo: PerRepoDetectionCoverage[];
}

/** Pure scorer — no I/O. Aggregates already-measured per-finding coverage entries. */
export function scoreDetectionCoverage(
  entries: readonly DetectionCoverageEntry[],
): DetectionCoverageScore {
  const perRepoMap = new Map<string, PerRepoDetectionCoverage>();
  let detectedTrue = 0;
  let detectedFalse = 0;
  let detectedUnknown = 0;

  for (const e of entries) {
    let repoStat = perRepoMap.get(e.repo);
    if (!repoStat) {
      repoStat = {
        repo: e.repo,
        totalConfirmedFindings: 0,
        detectedTrue: 0,
        detectedFalse: 0,
        detectedUnknown: 0,
      };
      perRepoMap.set(e.repo, repoStat);
    }
    repoStat.totalConfirmedFindings++;
    if (e.detected === true) {
      detectedTrue++;
      repoStat.detectedTrue++;
    } else if (e.detected === false) {
      detectedFalse++;
      repoStat.detectedFalse++;
    } else {
      detectedUnknown++;
      repoStat.detectedUnknown++;
    }
  }

  const total = entries.length;
  return {
    totalConfirmedFindings: total,
    detectedTrue,
    detectedFalse,
    detectedUnknown,
    gapRate: total === 0 ? 0 : detectedFalse / total,
    unknownRate: total === 0 ? 0 : detectedUnknown / total,
    coverageRate: total === 0 ? 1 : detectedTrue / total,
    reposScored: perRepoMap.size,
    perRepo: [...perRepoMap.values()],
  };
}
