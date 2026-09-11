import type { DetectionCoverageScore } from "./detection-coverage-scorer.js";
import type {
  DetectionCoverageRegressionResult,
  DetectionCoverageViolation,
} from "./detection-coverage-baseline.js";

/**
 * Human- and machine-readable renderers for the detection-coverage gate.
 * Mirrors `report.ts`/`blue-team-report.ts`'s conventions exactly — metadata
 * only (repo/category/finding ids and the coverage verdict's own reasoning
 * text; never a code/secret body, golden rule #1).
 */

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function pad(value: string | number, width: number): string {
  return String(value).padEnd(width);
}

/** Render an overall + per-repo score table. */
export function formatDetectionCoverageScore(score: DetectionCoverageScore): string {
  const lines: string[] = [];
  lines.push("Detection-coverage score");
  lines.push("=========================");
  lines.push(
    `  gap rate:      ${pct(score.gapRate)}   (headline; detectedFalse=${score.detectedFalse} of ${score.totalConfirmedFindings} confirmed findings — a genuine telemetry gap, never "unknown")`,
  );
  lines.push(`  covered rate:  ${pct(score.coverageRate)}   (detectedTrue=${score.detectedTrue})`);
  lines.push(
    `  unknown rate:  ${pct(score.unknownRate)}   (detectedUnknown=${score.detectedUnknown} — ambiguous, informational only, never gates)`,
  );
  lines.push(`  repos scored:  ${score.reposScored}`);

  if (score.perRepo.length > 0) {
    lines.push("");
    lines.push(`  ${pad("repo", 28)}${pad("total", 8)}${pad("true", 8)}${pad("false", 8)}unknown`);
    for (const r of score.perRepo) {
      lines.push(
        `  ${pad(r.repo, 28)}${pad(r.totalConfirmedFindings, 8)}${pad(r.detectedTrue, 8)}${pad(
          r.detectedFalse,
          8,
        )}${r.detectedUnknown}`,
      );
    }
  }
  return lines.join("\n");
}

function formatViolation(v: DetectionCoverageViolation): string {
  const cmp = v.direction === "max" ? ">" : "<";
  const isRateMetric = v.metric === "gapRate";
  const actual = isRateMetric ? pct(v.actual) : String(v.actual);
  const threshold = isRateMetric ? pct(v.threshold) : String(v.threshold);
  return `  [${v.metric}] ${actual} ${cmp} ${threshold} (${v.direction})`;
}

/** Render the pass/fail regression verdict against the committed baseline. */
export function formatDetectionCoverageRegression(
  result: DetectionCoverageRegressionResult,
): string {
  if (result.passed) {
    return `Detection-coverage baseline gate: PASS (gapRateMax=${pct(result.baseline.gapRateMax)})`;
  }
  return [
    `Detection-coverage baseline gate: FAIL — ${result.violations.length} threshold(s) breached:`,
    ...result.violations.map(formatViolation),
  ].join("\n");
}

/** Build a machine-readable JSON report (for CI artifacts / --json). Metadata only. */
export function toDetectionCoverageJsonReport(
  score: DetectionCoverageScore,
  regression: DetectionCoverageRegressionResult,
): Record<string, unknown> {
  return {
    passed: regression.passed,
    headline: {
      gapRate: score.gapRate,
      coverageRate: score.coverageRate,
      unknownRate: score.unknownRate,
    },
    counts: {
      totalConfirmedFindings: score.totalConfirmedFindings,
      detectedTrue: score.detectedTrue,
      detectedFalse: score.detectedFalse,
      detectedUnknown: score.detectedUnknown,
    },
    reposScored: score.reposScored,
    perRepo: score.perRepo,
    baseline: regression.baseline,
    violations: regression.violations,
  };
}
