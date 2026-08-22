import type { BlueTeamCorpusScore } from "./blue-team-corpus.js";
import type { BlueTeamRegressionResult, BlueTeamViolation } from "./blue-team-baseline.js";

/**
 * Human- and machine-readable renderers for the blue-team detection gate.
 * Mirrors `report.ts`'s conventions exactly — metadata only (scenario keys,
 * categories, fired/expected booleans, and the evaluator's own reason text;
 * never a live-DAST transcript body beyond what purple-loop.ts already
 * truncates, golden rule #1).
 */

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function pad(value: string | number, width: number): string {
  return String(value).padEnd(width);
}

/** Render an overall score + per-scenario breakdown. */
export function formatBlueTeamScore(score: BlueTeamCorpusScore): string {
  const lines: string[] = [];
  lines.push("Blue-team detection-corpus score");
  lines.push("=================================");
  lines.push(`  detection precision: ${pct(score.detectionPrecision)}`);
  lines.push(`  detection recall:    ${pct(score.detectionRecall)}`);
  lines.push(`  accuracy:            ${pct(score.accuracy)}`);
  lines.push(
    `  counts: TP=${score.truePositives} FP=${score.falsePositives} FN=${score.falseNegatives} TN=${score.trueNegatives}` +
      ` (expected positives=${score.expectedPositives}, expected negatives=${score.expectedNegatives}, total=${score.totalScenarios})`,
  );
  lines.push("");
  lines.push(
    `  ${pad("scenario", 42)}${pad("category", 26)}${pad("expected", 10)}${pad("actual", 10)}status`,
  );
  for (const s of score.perScenario) {
    const correct = s.expectedFired === s.actualFired;
    lines.push(
      `  ${pad(s.templateKey, 42)}${pad(s.findingCategory, 26)}${pad(String(s.expectedFired), 10)}${pad(
        String(s.actualFired),
        10,
      )}${correct ? "OK" : "MISMATCH"}`,
    );
  }
  const mismatches = score.perScenario.filter((s) => s.expectedFired !== s.actualFired);
  if (mismatches.length > 0) {
    lines.push("");
    lines.push("  Mismatches (ground truth vs. real measured run):");
    for (const m of mismatches) {
      lines.push(
        `    [${m.templateKey}] expected=${m.expectedFired} actual=${m.actualFired} — evidence: ${m.evidence}`,
      );
    }
  }
  return lines.join("\n");
}

function formatViolation(v: BlueTeamViolation): string {
  const actual = v.metric === "scenariosScored" ? String(v.actual) : pct(v.actual);
  const threshold = v.metric === "scenariosScored" ? String(v.threshold) : pct(v.threshold);
  return `  [${v.metric}] ${actual} < ${threshold} (min)`;
}

/** Render the pass/fail regression verdict against the committed baseline. */
export function formatBlueTeamRegression(result: BlueTeamRegressionResult): string {
  if (result.passed) {
    return `Blue-team baseline gate: PASS (detectionPrecisionMin=${pct(
      result.baseline.detectionPrecisionMin,
    )}, detectionRecallMin=${pct(result.baseline.detectionRecallMin)})`;
  }
  return [
    `Blue-team baseline gate: FAIL — ${result.violations.length} threshold(s) breached:`,
    ...result.violations.map(formatViolation),
  ].join("\n");
}

/** Build a machine-readable JSON report (for CI artifacts / --json). Metadata only. */
export function toBlueTeamJsonReport(
  score: BlueTeamCorpusScore,
  regression: BlueTeamRegressionResult,
): Record<string, unknown> {
  return {
    passed: regression.passed,
    headline: {
      detectionPrecision: score.detectionPrecision,
      detectionRecall: score.detectionRecall,
      accuracy: score.accuracy,
    },
    counts: {
      truePositives: score.truePositives,
      falsePositives: score.falsePositives,
      falseNegatives: score.falseNegatives,
      trueNegatives: score.trueNegatives,
      expectedPositives: score.expectedPositives,
      expectedNegatives: score.expectedNegatives,
      totalScenarios: score.totalScenarios,
    },
    perScenario: score.perScenario,
    baseline: regression.baseline,
    violations: regression.violations,
  };
}
