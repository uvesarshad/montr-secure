import { describe, it, expect } from "vitest";
import { scoreDetectionCoverage } from "../packages/qa/src/detection-coverage-scorer";
import { evaluateDetectionCoverageBaseline } from "../packages/qa/src/detection-coverage-baseline";
import {
  formatDetectionCoverageRegression,
  formatDetectionCoverageScore,
  toDetectionCoverageJsonReport,
} from "../packages/qa/src/detection-coverage-report";

/**
 * Detection-coverage regression gate (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md) — report renderer
 * tests. Mirrors tests/qa.report.test.ts's pattern.
 */

describe("formatDetectionCoverageScore / formatDetectionCoverageRegression / toDetectionCoverageJsonReport", () => {
  const score = scoreDetectionCoverage([
    {
      repo: "javaseccode",
      findingId: "f1",
      category: "sql_injection",
      detected: false,
      reasoning: "no rule",
    },
    {
      repo: "javaseccode",
      findingId: "f2",
      category: "sql_injection",
      detected: "unknown",
      reasoning: "console-only",
    },
    {
      repo: "pygoat",
      findingId: "f3",
      category: "xss",
      detected: true,
      reasoning: "structured + rule",
    },
  ]);

  it("renders a human-readable score table with the gap/covered/unknown split", () => {
    const text = formatDetectionCoverageScore(score);
    expect(text).toMatch(/gap rate:/);
    expect(text).toMatch(/covered rate:/);
    expect(text).toMatch(/unknown rate:/);
    expect(text).toMatch(/javaseccode/);
    expect(text).toMatch(/pygoat/);
  });

  it("renders PASS when within the baseline", () => {
    const regression = evaluateDetectionCoverageBaseline(score, { gapRateMax: 0.9 });
    expect(formatDetectionCoverageRegression(regression)).toMatch(/PASS/);
  });

  it("renders FAIL with the breached metric when over the ceiling", () => {
    const regression = evaluateDetectionCoverageBaseline(score, { gapRateMax: 0.1 });
    const text = formatDetectionCoverageRegression(regression);
    expect(text).toMatch(/FAIL/);
    expect(text).toMatch(/gapRate/);
  });

  it("builds a machine-readable JSON report", () => {
    const regression = evaluateDetectionCoverageBaseline(score, { gapRateMax: 0.9 });
    const json = toDetectionCoverageJsonReport(score, regression);
    expect(json.passed).toBe(true);
    expect((json.headline as Record<string, unknown>).gapRate).toBeCloseTo(1 / 3);
    expect((json.counts as Record<string, unknown>).totalConfirmedFindings).toBe(3);
  });
});
