import { describe, it, expect } from "vitest";
import {
  scoreDetectionCoverage,
  type DetectionCoverageEntry,
} from "../packages/qa/src/detection-coverage-scorer";

/**
 * Detection-coverage regression gate (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md) — scorer tests.
 * Mirrors tests/qa.scorer.test.ts's pattern for the golden-corpus scorer.
 */

function mkEntry(over: Partial<DetectionCoverageEntry> = {}): DetectionCoverageEntry {
  return {
    repo: "repo-a",
    findingId: "conf_1",
    category: "sql_injection",
    detected: true,
    reasoning: "test fixture",
    ...over,
  };
}

describe("scoreDetectionCoverage", () => {
  it("returns vacuous, non-blocking defaults for an empty run", () => {
    const score = scoreDetectionCoverage([]);
    expect(score.totalConfirmedFindings).toBe(0);
    expect(score.gapRate).toBe(0);
    expect(score.unknownRate).toBe(0);
    expect(score.coverageRate).toBe(1);
    expect(score.reposScored).toBe(0);
    expect(score.perRepo).toEqual([]);
  });

  it("counts detected:true/false/'unknown' into the right buckets", () => {
    const entries: DetectionCoverageEntry[] = [
      mkEntry({ findingId: "f1", detected: true }),
      mkEntry({ findingId: "f2", detected: false }),
      mkEntry({ findingId: "f3", detected: "unknown" }),
      mkEntry({ findingId: "f4", detected: false }),
    ];
    const score = scoreDetectionCoverage(entries);
    expect(score.totalConfirmedFindings).toBe(4);
    expect(score.detectedTrue).toBe(1);
    expect(score.detectedFalse).toBe(2);
    expect(score.detectedUnknown).toBe(1);
    expect(score.gapRate).toBe(0.5);
    expect(score.unknownRate).toBe(0.25);
    expect(score.coverageRate).toBe(0.25);
  });

  it("'unknown' never inflates gapRate — only detected:false counts as a genuine gap", () => {
    const allUnknown: DetectionCoverageEntry[] = [
      mkEntry({ findingId: "f1", detected: "unknown" }),
      mkEntry({ findingId: "f2", detected: "unknown" }),
    ];
    const score = scoreDetectionCoverage(allUnknown);
    expect(score.gapRate).toBe(0);
    expect(score.unknownRate).toBe(1);
  });

  it("aggregates a per-repo breakdown", () => {
    const entries: DetectionCoverageEntry[] = [
      mkEntry({ repo: "repo-a", findingId: "f1", detected: false }),
      mkEntry({ repo: "repo-a", findingId: "f2", detected: true }),
      mkEntry({ repo: "repo-b", findingId: "f3", detected: "unknown" }),
    ];
    const score = scoreDetectionCoverage(entries);
    expect(score.reposScored).toBe(2);
    const repoA = score.perRepo.find((r) => r.repo === "repo-a");
    const repoB = score.perRepo.find((r) => r.repo === "repo-b");
    expect(repoA).toEqual({
      repo: "repo-a",
      totalConfirmedFindings: 2,
      detectedTrue: 1,
      detectedFalse: 1,
      detectedUnknown: 0,
    });
    expect(repoB).toEqual({
      repo: "repo-b",
      totalConfirmedFindings: 1,
      detectedTrue: 0,
      detectedFalse: 0,
      detectedUnknown: 1,
    });
  });
});
