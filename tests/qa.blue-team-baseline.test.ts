import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { isMontrError } from "@montr/contracts";
import {
  DEFAULT_BLUE_TEAM_BASELINE,
  evaluateBlueTeamBaseline,
  loadBlueTeamBaselineFile,
  parseBlueTeamBaseline,
} from "../packages/qa/src/blue-team-baseline";
import { findRepoRoot } from "../packages/qa/src/corpus";
import type { BlueTeamCorpusScore } from "../packages/qa/src/blue-team-corpus";

/**
 * B12 — blue-team detection-corpus baseline / regression-gate tests. Mirrors
 * tests/qa.baseline.test.ts's pattern exactly for the golden-corpus gate.
 */

function mkScore(over: Partial<BlueTeamCorpusScore> = {}): BlueTeamCorpusScore {
  return {
    totalScenarios: 9,
    expectedPositives: 6,
    expectedNegatives: 3,
    truePositives: 6,
    falsePositives: 0,
    falseNegatives: 0,
    trueNegatives: 3,
    detectionPrecision: 1,
    detectionRecall: 1,
    accuracy: 1,
    perScenario: [],
    ...over,
  };
}

describe("parseBlueTeamBaseline", () => {
  it("accepts a valid baseline", () => {
    const b = parseBlueTeamBaseline({
      detectionPrecisionMin: 0.8,
      detectionRecallMin: 0.8,
      minScenariosScored: 9,
    });
    expect(b.detectionPrecisionMin).toBe(0.8);
    expect(b.minScenariosScored).toBe(9);
  });

  it("rejects out-of-range rates and bad shapes", () => {
    expect(() =>
      parseBlueTeamBaseline({ detectionPrecisionMin: 1.5, detectionRecallMin: 0.8 }),
    ).toThrow();
    expect(() => parseBlueTeamBaseline({ detectionRecallMin: 0.8 })).toThrow(); // missing precisionMin
    expect(() =>
      parseBlueTeamBaseline({
        detectionPrecisionMin: 0.8,
        detectionRecallMin: 0.8,
        minScenariosScored: -1,
      }),
    ).toThrow();
    expect(() => parseBlueTeamBaseline("nope")).toThrow();
    const err = (() => {
      try {
        parseBlueTeamBaseline({ detectionPrecisionMin: "x", detectionRecallMin: 0.8 });
      } catch (e) {
        return e;
      }
    })();
    expect(isMontrError(err) && err.code).toBe("CONFIG_VALIDATION");
  });
});

describe("evaluateBlueTeamBaseline", () => {
  it("passes when every metric meets the baseline", () => {
    const r = evaluateBlueTeamBaseline(
      mkScore({ detectionPrecision: 1, detectionRecall: 1 }),
      DEFAULT_BLUE_TEAM_BASELINE,
    );
    expect(r.passed).toBe(true);
    expect(r.violations).toEqual([]);
  });

  // The exact scenario the task brief asks for: a below-threshold detection
  // recall run fails the gate, mirroring evaluateBaseline's own recall test.
  it("a below-threshold detectionRecall run FAILS the gate", () => {
    const r = evaluateBlueTeamBaseline(
      mkScore({
        detectionRecall: 0.3,
        truePositives: 2,
        falseNegatives: 4,
        detectionPrecision: 1,
      }),
      DEFAULT_BLUE_TEAM_BASELINE,
    );
    expect(r.passed).toBe(false);
    const rec = r.violations.find((v) => v.metric === "detectionRecall");
    expect(rec).toBeDefined();
    expect(rec?.direction).toBe("min");
    expect(rec?.threshold).toBe(DEFAULT_BLUE_TEAM_BASELINE.detectionRecallMin);
  });

  it("a below-threshold detectionPrecision run FAILS the gate", () => {
    const r = evaluateBlueTeamBaseline(
      mkScore({ detectionPrecision: 0.2, truePositives: 1, falsePositives: 4 }),
      DEFAULT_BLUE_TEAM_BASELINE,
    );
    expect(r.passed).toBe(false);
    expect(r.violations.some((v) => v.metric === "detectionPrecision")).toBe(true);
  });

  it("fails and reports EVERY breached threshold at once", () => {
    const r = evaluateBlueTeamBaseline(
      mkScore({ detectionPrecision: 0.1, detectionRecall: 0.1 }),
      DEFAULT_BLUE_TEAM_BASELINE,
    );
    expect(r.passed).toBe(false);
    const metrics = r.violations.map((v) => v.metric).sort();
    expect(metrics).toEqual(["detectionPrecision", "detectionRecall"]);
  });

  it("treats a metric exactly at the threshold as passing (epsilon)", () => {
    const r = evaluateBlueTeamBaseline(
      mkScore({
        detectionPrecision: DEFAULT_BLUE_TEAM_BASELINE.detectionPrecisionMin,
        detectionRecall: DEFAULT_BLUE_TEAM_BASELINE.detectionRecallMin,
      }),
      DEFAULT_BLUE_TEAM_BASELINE,
    );
    expect(r.passed).toBe(true);
  });

  it("enforces minScenariosScored (catches an empty/truncated run)", () => {
    const r = evaluateBlueTeamBaseline(mkScore({ totalScenarios: 1 }), {
      ...DEFAULT_BLUE_TEAM_BASELINE,
      minScenariosScored: 9,
    });
    expect(r.violations.some((v) => v.metric === "scenariosScored")).toBe(true);
  });
});

describe("loadBlueTeamBaselineFile — the committed blue-team corpus baseline", () => {
  it("loads corpus/blue-team-baseline.json with real, non-trivial thresholds", async () => {
    const root = findRepoRoot(fileURLToPath(import.meta.url));
    const baseline = await loadBlueTeamBaselineFile(
      join(root, "corpus", "blue-team-baseline.json"),
    );
    expect(baseline.detectionPrecisionMin).toBeGreaterThan(0);
    expect(baseline.detectionPrecisionMin).toBeLessThanOrEqual(1);
    expect(baseline.detectionRecallMin).toBeGreaterThan(0);
    expect(baseline.detectionRecallMin).toBeLessThanOrEqual(1);
    expect(baseline.minScenariosScored).toBeGreaterThanOrEqual(9);
  });

  it("the committed thresholds actually gate: a run below them fails the release gate", async () => {
    const root = findRepoRoot(fileURLToPath(import.meta.url));
    const baseline = await loadBlueTeamBaselineFile(
      join(root, "corpus", "blue-team-baseline.json"),
    );
    const belowFloor = evaluateBlueTeamBaseline(
      mkScore({ detectionRecall: Math.max(0, baseline.detectionRecallMin - 0.2) }),
      baseline,
    );
    expect(belowFloor.passed).toBe(false);

    // Sanity: exactly at the committed real measurement (100%/100%, see
    // corpus/blue-team-baseline.json's $measurement), the gate still passes
    // today (guards against silently loosening the floor past the real run).
    const atMeasurement = evaluateBlueTeamBaseline(
      mkScore({ detectionPrecision: 1, detectionRecall: 1, totalScenarios: 9 }),
      baseline,
    );
    expect(atMeasurement.passed).toBe(true);
  });

  it("throws ConfigValidationError for a missing file", async () => {
    await expect(loadBlueTeamBaselineFile("/no/such/blue-team-baseline.json")).rejects.toThrow();
  });
});
