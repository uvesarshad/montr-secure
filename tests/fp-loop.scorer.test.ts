import { describe, it, expect } from "vitest";
import type { ConfirmedFinding } from "@montr/contracts";
import type { GroundTruthManifest } from "@montr/fixtures";
import { mockConfirmedFindings } from "@montr/fixtures";
import { scoreScanResults, scoreFalsePositiveFeedback } from "../packages/qa/src/scorer";
import type { FalsePositiveMarker } from "../packages/qa/src/types";

/**
 * §15 — a marked false positive must count against precision and feed the
 * headline FP-rate (build-plan §6, PRD §15 target < 5%). Covers both the
 * ground-truth-free operator scorer and the corpus scorer's FP override.
 */

const sqli: ConfirmedFinding = mockConfirmedFindings[0]!; // sql_injection @ app/api/users/route.ts:9
const xss: ConfirmedFinding = mockConfirmedFindings[1]!; // xss @ app/search/page.tsx:8
const confirmed = [sqli, xss];

const SQLI_FP: FalsePositiveMarker = {
  category: "sql_injection",
  file: "app/api/users/route.ts",
  line: 9,
};

describe("scoreFalsePositiveFeedback — operator feedback (no ground truth)", () => {
  it("is perfect precision with no feedback", () => {
    const s = scoreFalsePositiveFeedback(confirmed, []);
    expect(s.confirmed).toBe(2);
    expect(s.falsePositives).toBe(0);
    expect(s.precision).toBe(1);
    expect(s.fpRate).toBe(0);
  });

  it("marking one confirmed finding FP shifts precision and FP-rate", () => {
    const before = scoreFalsePositiveFeedback(confirmed, []);
    const after = scoreFalsePositiveFeedback(confirmed, [SQLI_FP]);

    expect(after.falsePositives).toBe(1);
    expect(after.truePositives).toBe(1);
    expect(after.markedFindingIds).toEqual([sqli.id]);
    // The metric MOVES: precision drops, FP-rate rises.
    expect(after.precision).toBeLessThan(before.precision);
    expect(after.fpRate).toBeGreaterThan(before.fpRate);
    expect(after.precision).toBeCloseTo(0.5, 10);
    expect(after.fpRate).toBeCloseTo(0.5, 10);

    const cat = after.perCategory.find((c) => c.category === "sql_injection")!;
    expect(cat.falsePositives).toBe(1);
    expect(cat.fpRate).toBe(1);
  });

  it("is deterministic", () => {
    expect(scoreFalsePositiveFeedback(confirmed, [SQLI_FP])).toEqual(
      scoreFalsePositiveFeedback(confirmed, [SQLI_FP]),
    );
  });
});

describe("scoreScanResults — corpus scorer honors the FP override", () => {
  const manifest: GroundTruthManifest = {
    version: "test",
    repos: [
      {
        name: "vuln",
        kind: "vulnerable",
        path: "vuln",
        expectedFindings: [
          {
            id: "gt_sqli",
            category: "sql_injection",
            cwe: ["CWE-89"],
            owasp: "A03:2021",
            file: "app/api/users/route.ts",
            line: 9,
            severity: "critical",
            expectedRiskClass: "auto-eligible",
            exploitable: true,
            description: "sqli",
          },
        ],
      },
    ],
  };
  const results = [{ repo: "vuln", confirmed: [sqli] }];

  it("scores a matching confirmation as a true positive without feedback", () => {
    const s = scoreScanResults(results, manifest);
    expect(s.truePositives).toBe(1);
    expect(s.falsePositives).toBe(0);
    expect(s.precision).toBe(1);
    expect(s.fpRate).toBe(0);
  });

  it("an operator override reclassifies the TP as FP and suppresses the miss", () => {
    const s = scoreScanResults(results, manifest, { falsePositives: [SQLI_FP] });
    expect(s.truePositives).toBe(0);
    expect(s.falsePositives).toBe(1);
    expect(s.precision).toBe(0);
    expect(s.fpRate).toBe(1);
    // Human override says nothing exploitable is here — not counted as a miss.
    expect(s.falseNegatives).toBe(0);
    const outcome = s.perRepo[0]!.outcomes.find((o) => o.kind === "false_positive");
    expect(outcome?.note).toContain("operator-marked false positive");
  });
});
