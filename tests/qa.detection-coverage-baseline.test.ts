import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { isMontrError } from "@montr/contracts";
import {
  DEFAULT_DETECTION_COVERAGE_BASELINE,
  evaluateDetectionCoverageBaseline,
  loadDetectionCoverageBaselineFile,
  parseDetectionCoverageBaseline,
} from "../packages/qa/src/detection-coverage-baseline";
import { findRepoRoot } from "../packages/qa/src/corpus";
import type { DetectionCoverageScore } from "../packages/qa/src/detection-coverage-scorer";

/**
 * Detection-coverage regression gate (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md) — baseline /
 * regression-gate tests. Mirrors tests/qa.baseline.test.ts's and
 * tests/qa.blue-team-baseline.test.ts's pattern exactly.
 */

function mkScore(over: Partial<DetectionCoverageScore> = {}): DetectionCoverageScore {
  return {
    totalConfirmedFindings: 16,
    detectedTrue: 0,
    detectedFalse: 10,
    detectedUnknown: 6,
    gapRate: 0.625,
    unknownRate: 0.375,
    coverageRate: 0,
    reposScored: 6,
    perRepo: [],
    ...over,
  };
}

describe("parseDetectionCoverageBaseline", () => {
  it("accepts a valid baseline", () => {
    const b = parseDetectionCoverageBaseline({ gapRateMax: 0.75, minConfirmedFindings: 10 });
    expect(b.gapRateMax).toBe(0.75);
    expect(b.minConfirmedFindings).toBe(10);
  });

  it("accepts a baseline with no minConfirmedFindings guard", () => {
    const b = parseDetectionCoverageBaseline({ gapRateMax: 1 });
    expect(b.gapRateMax).toBe(1);
    expect(b.minConfirmedFindings).toBeUndefined();
  });

  it("rejects out-of-range rates and bad shapes", () => {
    expect(() => parseDetectionCoverageBaseline({ gapRateMax: 1.5 })).toThrow();
    expect(() => parseDetectionCoverageBaseline({})).toThrow(); // missing gapRateMax
    expect(() =>
      parseDetectionCoverageBaseline({ gapRateMax: 0.5, minConfirmedFindings: -1 }),
    ).toThrow();
    expect(() => parseDetectionCoverageBaseline("nope")).toThrow();
    const err = (() => {
      try {
        parseDetectionCoverageBaseline({ gapRateMax: "x" });
      } catch (e) {
        return e;
      }
    })();
    expect(isMontrError(err) && err.code).toBe("CONFIG_VALIDATION");
  });
});

describe("evaluateDetectionCoverageBaseline", () => {
  it("passes when gapRate is within the ceiling", () => {
    const r = evaluateDetectionCoverageBaseline(
      mkScore({ gapRate: 0.3 }),
      DEFAULT_DETECTION_COVERAGE_BASELINE,
    );
    expect(r.passed).toBe(true);
    expect(r.violations).toEqual([]);
  });

  // The exact scenario the task brief asks for: a newly confirmed finding
  // landing on a route with no telemetry pushes gapRate over the ceiling.
  it("a gapRate above the ceiling FAILS the gate", () => {
    const r = evaluateDetectionCoverageBaseline(mkScore({ gapRate: 0.9 }), {
      gapRateMax: 0.75,
    });
    expect(r.passed).toBe(false);
    const violation = r.violations.find((v) => v.metric === "gapRate");
    expect(violation).toBeDefined();
    expect(violation?.direction).toBe("max");
    expect(violation?.threshold).toBe(0.75);
  });

  it("treats a gapRate exactly at the threshold as passing (epsilon)", () => {
    const r = evaluateDetectionCoverageBaseline(mkScore({ gapRate: 0.75 }), {
      gapRateMax: 0.75,
    });
    expect(r.passed).toBe(true);
  });

  it("enforces minConfirmedFindings (catches an empty/degraded run)", () => {
    const r = evaluateDetectionCoverageBaseline(mkScore({ totalConfirmedFindings: 1 }), {
      gapRateMax: 1,
      minConfirmedFindings: 10,
    });
    expect(r.violations.some((v) => v.metric === "confirmedFindingsScored")).toBe(true);
  });

  it("reports both violations at once when both breach", () => {
    const r = evaluateDetectionCoverageBaseline(
      mkScore({ gapRate: 0.95, totalConfirmedFindings: 2 }),
      { gapRateMax: 0.75, minConfirmedFindings: 10 },
    );
    expect(r.passed).toBe(false);
    const metrics = r.violations.map((v) => v.metric).sort();
    expect(metrics).toEqual(["confirmedFindingsScored", "gapRate"]);
  });
});

describe("loadDetectionCoverageBaselineFile — the committed detection-coverage baseline", () => {
  it("loads corpus/detection-coverage-baseline.json with real, non-trivial thresholds", async () => {
    const root = findRepoRoot(fileURLToPath(import.meta.url));
    const baseline = await loadDetectionCoverageBaselineFile(
      join(root, "corpus", "detection-coverage-baseline.json"),
    );
    expect(baseline.gapRateMax).toBeGreaterThan(0);
    expect(baseline.gapRateMax).toBeLessThanOrEqual(1);
    expect(baseline.minConfirmedFindings).toBeGreaterThanOrEqual(1);
  });

  it("the committed thresholds actually gate: a run above them fails the release gate", async () => {
    const root = findRepoRoot(fileURLToPath(import.meta.url));
    const baseline = await loadDetectionCoverageBaselineFile(
      join(root, "corpus", "detection-coverage-baseline.json"),
    );
    const aboveCeiling = evaluateDetectionCoverageBaseline(
      mkScore({ gapRate: Math.min(1, baseline.gapRateMax + 0.2) }),
      baseline,
    );
    expect(aboveCeiling.passed).toBe(false);

    // Sanity: at the committed real measurement (gapRate 62.5%, see
    // corpus/detection-coverage-baseline.json's $measurement), the gate still
    // passes today (guards against silently tightening past the real run).
    const atMeasurement = evaluateDetectionCoverageBaseline(
      mkScore({ gapRate: 0.625, totalConfirmedFindings: 16 }),
      baseline,
    );
    expect(atMeasurement.passed).toBe(true);
  });

  it("throws ConfigValidationError for a missing file", async () => {
    await expect(
      loadDetectionCoverageBaselineFile("/no/such/detection-coverage-baseline.json"),
    ).rejects.toThrow();
  });
});
