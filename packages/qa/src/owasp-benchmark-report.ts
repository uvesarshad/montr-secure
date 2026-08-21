import type { OwaspBenchmarkScore } from "./owasp-benchmark.js";

/**
 * Human- and machine-readable renderers for the OWASP Benchmark harness
 * (E14/A29), mirroring `report.ts`'s conventions (`pct`/`pad` helpers, a text
 * table + a metadata-only JSON shape) but kept in a sibling file rather than
 * added to `report.ts` itself — `report.ts` renders the INTERNAL golden-corpus
 * gate; this renders scores against an EXTERNAL, independently-curated
 * benchmark, which is deliberately never merged into that report so a reader
 * cannot mistake one for the other.
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

/** Render one tool's OWASP Benchmark score as a text table. */
export function formatOwaspBenchmarkScore(score: OwaspBenchmarkScore): string {
  const lines: string[] = [];
  lines.push(`OWASP Benchmark score — ${score.toolName}`);
  lines.push("=".repeat(24 + score.toolName.length));
  lines.push(
    `  TPR (recall):        ${pct(score.tpr)}   (TP=${score.truePositives} FN=${score.falseNegatives})`,
  );
  lines.push(
    `  FPR:                 ${pct(score.fpr)}   (FP=${score.falsePositives} TN=${score.trueNegatives})`,
  );
  lines.push(`  precision:           ${pct(score.precision)}`);
  lines.push(
    `  Benchmark score:     ${(score.benchmarkScore * 100).toFixed(1)} pts   (OWASP's own TPR-FPR headline metric)`,
  );
  lines.push(
    `  cases scored:        ${score.casesScored}` +
      (score.casesExcluded > 0
        ? ` (${score.casesExcluded} excluded — categories not in this tool's taxonomy: ${score.excludedCategories.join(", ")})`
        : ""),
  );
  return lines.join("\n");
}

/** Render a side-by-side comparison table across multiple tools scored on the SAME subset. */
export function formatOwaspBenchmarkComparison(scores: readonly OwaspBenchmarkScore[]): string {
  const lines: string[] = [];
  lines.push("OWASP Benchmark head-to-head (same vendored subset, same ground truth)");
  lines.push(
    `  ${pad("tool", 20)}${padStart("scored", 8)}${padStart("TP", 4)}${padStart("FP", 4)}${padStart("TN", 4)}${padStart("FN", 4)}  ${pad("TPR", 8)}${pad("FPR", 8)}${pad("precision", 11)}${pad("score", 8)}`,
  );
  for (const s of scores) {
    lines.push(
      `  ${pad(s.toolName, 20)}${padStart(s.casesScored, 8)}${padStart(s.truePositives, 4)}${padStart(
        s.falsePositives,
        4,
      )}${padStart(s.trueNegatives, 4)}${padStart(s.falseNegatives, 4)}  ${pad(pct(s.tpr), 8)}${pad(
        pct(s.fpr),
        8,
      )}${pad(pct(s.precision), 11)}${pad((s.benchmarkScore * 100).toFixed(1), 8)}`,
    );
  }
  return lines.join("\n");
}

/** Machine-readable JSON report for CI artifacts. Metadata only (golden rule #1). */
export function toOwaspBenchmarkJsonReport(
  scores: readonly OwaspBenchmarkScore[],
): Record<string, unknown> {
  return {
    subset: "corpus/owasp-benchmark",
    tools: scores.map((s) => ({
      toolName: s.toolName,
      casesScored: s.casesScored,
      casesExcluded: s.casesExcluded,
      excludedCategories: s.excludedCategories,
      counts: {
        truePositives: s.truePositives,
        falsePositives: s.falsePositives,
        trueNegatives: s.trueNegatives,
        falseNegatives: s.falseNegatives,
      },
      tpr: s.tpr,
      fpr: s.fpr,
      precision: s.precision,
      benchmarkScore: s.benchmarkScore,
    })),
  };
}
