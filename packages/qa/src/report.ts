import type { RegressionResult, Violation } from "./baseline.js";
import type { PipelineMetrics } from "./layer-metrics.js";
import type { ModelMatrix } from "./model-variance.js";
import type { CorpusScore } from "./types.js";

/**
 * Human- and machine-readable renderers for the QA gate. STRICTLY metadata only
 * — counts, rates, categories, ids, and file:line locations. Never proof
 * artifacts, evidence snippets, or any code/secret body (golden rule #1).
 */

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function pad(value: string | number, width: number): string {
  return String(value).padEnd(width);
}

function padStart(value: string | number, width: number): string {
  return String(value).padStart(width);
}

/** Render an overall + per-category score table. */
export function formatCorpusScore(score: CorpusScore): string {
  const lines: string[] = [];
  lines.push("Golden-corpus score");
  lines.push("===================");
  lines.push(
    `  FP-rate:   ${pct(score.fpRate)}   (headline; TP+FP=${score.truePositives + score.falsePositives})`,
  );
  lines.push(`  precision: ${pct(score.precision)}`);
  lines.push(`  recall:    ${pct(score.recall)}`);
  lines.push(`  F1:        ${pct(score.f1)}`);
  lines.push(
    `  counts:    TP=${score.truePositives} FP=${score.falsePositives} FN=${score.falseNegatives} over-confirmed=${score.overConfirmed}`,
  );
  lines.push(
    `  corpus:    ${score.reposWithResults}/${score.reposScored} repos scored with results` +
      (score.unknownRepoResults > 0
        ? `, ${score.unknownRepoResults} finding(s) for unknown repos (ignored)`
        : ""),
  );

  if (score.perCategory.length > 0) {
    lines.push("");
    lines.push(
      `  ${pad("category", 24)}${padStart("TP", 4)}${padStart("FP", 4)}${padStart("FN", 4)}  ${pad("prec", 8)}${pad("recall", 8)}${pad("fpRate", 8)}`,
    );
    for (const c of score.perCategory) {
      lines.push(
        `  ${pad(c.category, 24)}${padStart(c.truePositives, 4)}${padStart(c.falsePositives, 4)}${padStart(c.falseNegatives, 4)}  ${pad(pct(c.precision), 8)}${pad(pct(c.recall), 8)}${pad(pct(c.fpRate), 8)}`,
      );
    }
  }

  // Notable misses/false-positives (metadata only: category + file:line + note).
  const notable = score.perRepo
    .flatMap((r) => r.outcomes.map((o) => ({ repo: r.repo, ...o })))
    .filter((o) => o.kind !== "true_positive");
  if (notable.length > 0) {
    lines.push("");
    lines.push("  Misclassifications:");
    for (const o of notable) {
      const loc = o.file ? ` ${o.file}:${o.line ?? 0}` : "";
      const tag = o.kind === "false_positive" ? "FP" : "FN";
      lines.push(`    [${tag}] ${o.repo} ${o.category}${loc} — ${o.note ?? ""}`);
    }
  }
  return lines.join("\n");
}

function formatViolation(v: Violation): string {
  const cmp = v.direction === "max" ? ">" : "<";
  const isRateMetric = v.metric !== "reposScored";
  const actual = isRateMetric ? pct(v.actual) : String(v.actual);
  const threshold = isRateMetric ? pct(v.threshold) : String(v.threshold);
  return `  [${v.scope}] ${v.metric} ${actual} ${cmp} ${threshold} (${v.direction})`;
}

/** Render the pass/fail regression verdict against the committed baseline. */
export function formatRegression(result: RegressionResult): string {
  if (result.passed) {
    return `Baseline gate: PASS (fpRateMax=${pct(result.baseline.fpRateMax)}, precisionMin=${pct(
      result.baseline.precisionMin,
    )}, recallMin=${pct(result.baseline.recallMin)})`;
  }
  return [
    `Baseline gate: FAIL — ${result.violations.length} threshold(s) breached:`,
    ...result.violations.map(formatViolation),
  ].join("\n");
}

/** Render the model-variance matrix. */
export function formatModelMatrix(matrix: ModelMatrix): string {
  const lines: string[] = [];
  lines.push(
    `Model-variance matrix (corpus v${matrix.corpusVersion}, generated ${matrix.generatedAt})`,
  );
  lines.push(
    `  ${pad("model", 34)}${pad("tier", 14)}${pad("floor", 7)}${pad("prec", 8)}${pad("recall", 8)}${pad("fpRate", 8)}${pad("gate", 6)}cliff`,
  );
  for (const row of matrix.rows) {
    lines.push(
      `  ${pad(row.modelId, 34)}${pad(row.tier, 14)}${pad(row.belowFloor ? "below" : "ok", 7)}${pad(
        pct(row.score.precision),
        8,
      )}${pad(pct(row.score.recall), 8)}${pad(pct(row.score.fpRate), 8)}${pad(
        row.regression.passed ? "pass" : "FAIL",
        6,
      )}${row.accuracyCliff ? "YES" : "-"}`,
    );
  }
  return lines.join("\n");
}

/** Render per-layer pipeline metrics (findings in/out, demotion/confirmation rates). */
export function formatPipelineMetrics(m: PipelineMetrics): string {
  const lines: string[] = [];
  lines.push("Per-layer metrics");
  lines.push(
    `  candidates=${m.candidates} probable=${m.probable} confirmed=${m.confirmed} unconfirmed=${m.unconfirmed}`,
  );
  lines.push(
    `  dedupRate=${pct(m.dedupRate)} confirmationRate=${pct(m.confirmationRate)} demotionRate=${pct(m.demotionRate)}`,
  );
  for (const f of m.flows) {
    lines.push(
      `  ${pad(f.layer, 8)} in=${padStart(f.in, 4)} out=${padStart(f.out, 4)} demoted=${padStart(f.demoted, 4)}`,
    );
  }
  return lines.join("\n");
}

/** Build a machine-readable JSON report (for CI artifacts / --json). Metadata only. */
export function toJsonReport(
  score: CorpusScore,
  regression: RegressionResult,
  extra: { corpusVersion?: string; warnings?: string[] } = {},
): Record<string, unknown> {
  return {
    passed: regression.passed,
    corpusVersion: extra.corpusVersion,
    headline: {
      fpRate: score.fpRate,
      precision: score.precision,
      recall: score.recall,
      f1: score.f1,
    },
    counts: {
      truePositives: score.truePositives,
      falsePositives: score.falsePositives,
      falseNegatives: score.falseNegatives,
      overConfirmed: score.overConfirmed,
    },
    corpus: {
      reposScored: score.reposScored,
      reposWithResults: score.reposWithResults,
      unknownRepoResults: score.unknownRepoResults,
    },
    perCategory: score.perCategory,
    perRepo: score.perRepo.map((r) => ({
      repo: r.repo,
      kind: r.kind,
      truePositives: r.truePositives,
      falsePositives: r.falsePositives,
      falseNegatives: r.falseNegatives,
      overConfirmed: r.overConfirmed,
    })),
    baseline: regression.baseline,
    violations: regression.violations,
    warnings: extra.warnings ?? [],
  };
}
