import { describe, it, expect } from "vitest";
import {
  BLUE_TEAM_GROUND_TRUTH,
  buildBlueTeamFindingAndAppMap,
  buildBlueTeamScenario,
  scoreBlueTeamResults,
  type BlueTeamScenarioResult,
} from "../packages/qa/src/blue-team-corpus";
import { REDTEAM_SCENARIO_CATALOGUE } from "@montr/state-store";

/**
 * B12 — blue-team detection corpus: ground-truth structural sanity + the
 * pure scorer (scoreBlueTeamResults). The REAL end-to-end evaluator run
 * (generateDetectionRules + runPurpleTeamScenario against every labelled
 * case) is scripts/blue-team-corpus-scan.run.test.ts's job, run via
 * `pnpm blue-team:scan` — not duplicated here (this file is fast/offline).
 */

describe("BLUE_TEAM_GROUND_TRUTH — labelled subset sanity", () => {
  it("is a real, honest, non-empty subset of the real catalogue (documented in blue-team-corpus.ts's header)", () => {
    expect(BLUE_TEAM_GROUND_TRUTH.length).toBeGreaterThan(0);
    expect(BLUE_TEAM_GROUND_TRUTH.length).toBeLessThan(REDTEAM_SCENARIO_CATALOGUE.length);
  });

  it("every labelled templateKey resolves to a REAL REDTEAM_SCENARIO_CATALOGUE template", () => {
    const catalogueKeys = new Set(REDTEAM_SCENARIO_CATALOGUE.map((t) => t.key));
    for (const c of BLUE_TEAM_GROUND_TRUTH) {
      expect(catalogueKeys.has(c.templateKey), `${c.templateKey} not in catalogue`).toBe(true);
    }
  });

  it("has no duplicate templateKeys", () => {
    const keys = BLUE_TEAM_GROUND_TRUTH.map((c) => c.templateKey);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("contains at least one expected-true and one expected-false case (not a trivially one-sided corpus)", () => {
    expect(BLUE_TEAM_GROUND_TRUTH.some((c) => c.expectedFired)).toBe(true);
    expect(BLUE_TEAM_GROUND_TRUTH.some((c) => !c.expectedFired)).toBe(true);
  });

  it("buildBlueTeamScenario reuses the catalogue template's REAL steps verbatim (never re-authored)", () => {
    for (const c of BLUE_TEAM_GROUND_TRUTH) {
      const template = REDTEAM_SCENARIO_CATALOGUE.find((t) => t.key === c.templateKey)!;
      const scenario = buildBlueTeamScenario(c);
      expect(scenario.steps).toEqual(template.steps);
      expect(scenario.category).toBe(template.category);
    }
  });

  it("buildBlueTeamFindingAndAppMap resolves a route matching the case's declared targetRoute", () => {
    for (const c of BLUE_TEAM_GROUND_TRUTH) {
      const { finding, appMap } = buildBlueTeamFindingAndAppMap(c);
      expect(finding.category).toBe(c.findingCategory);
      expect(finding.location.file).toBe(c.handlerFile);
      const route = appMap.routes.find((r) => r.handler?.file === finding.location.file);
      expect(route?.path).toBe(c.targetRoute.path);
      expect(route?.method).toBe(c.targetRoute.method);
    }
  });
});

function mkResult(over: Partial<BlueTeamScenarioResult> = {}): BlueTeamScenarioResult {
  return {
    templateKey: "t",
    scenarioName: "t",
    findingCategory: "sql_injection",
    expectedFired: true,
    actualFired: true,
    evidence: "",
    sigmaRulesEvaluated: 1,
    ...over,
  };
}

describe("scoreBlueTeamResults — pure detection-precision/recall scorer", () => {
  it("perfect agreement => precision=1, recall=1, accuracy=1", () => {
    const score = scoreBlueTeamResults([
      mkResult({ expectedFired: true, actualFired: true }),
      mkResult({ expectedFired: false, actualFired: false }),
    ]);
    expect(score.detectionPrecision).toBe(1);
    expect(score.detectionRecall).toBe(1);
    expect(score.accuracy).toBe(1);
    expect(score.truePositives).toBe(1);
    expect(score.trueNegatives).toBe(1);
  });

  it("a missed detection (expected true, actual false) hurts recall, not precision", () => {
    const score = scoreBlueTeamResults([
      mkResult({ expectedFired: true, actualFired: false }),
      mkResult({ expectedFired: true, actualFired: true }),
    ]);
    expect(score.falseNegatives).toBe(1);
    expect(score.detectionRecall).toBeCloseTo(0.5);
    expect(score.detectionPrecision).toBe(1); // no rule fired incorrectly
  });

  it("a spurious fire (expected false, actual true) hurts precision, not recall", () => {
    const score = scoreBlueTeamResults([
      mkResult({ expectedFired: false, actualFired: true }),
      mkResult({ expectedFired: true, actualFired: true }),
    ]);
    expect(score.falsePositives).toBe(1);
    expect(score.detectionPrecision).toBeCloseTo(0.5);
    expect(score.detectionRecall).toBe(1); // every expected-true case fired
  });

  it("precision/recall default to 1.0 (not NaN) when the denominator is empty", () => {
    const score = scoreBlueTeamResults([mkResult({ expectedFired: false, actualFired: false })]);
    expect(score.detectionPrecision).toBe(1);
    expect(score.detectionRecall).toBe(1);
    expect(score.detectionPrecision).not.toBeNaN();
    expect(score.detectionRecall).not.toBeNaN();
  });

  it("counts expectedPositives/expectedNegatives correctly", () => {
    const score = scoreBlueTeamResults([
      mkResult({ expectedFired: true, actualFired: true }),
      mkResult({ expectedFired: true, actualFired: false }),
      mkResult({ expectedFired: false, actualFired: false }),
    ]);
    expect(score.expectedPositives).toBe(2);
    expect(score.expectedNegatives).toBe(1);
    expect(score.totalScenarios).toBe(3);
  });
});
