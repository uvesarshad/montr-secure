import { describe, it, expect } from "vitest";
import { ConfirmedFindingSchema, type ConfirmedFinding } from "@montr/contracts";
import type { GroundTruthManifest } from "@montr/fixtures";
import { scoreRepo, scoreScanResults } from "../packages/qa/src/scorer";
import { groundTruthToConfirmed, perfectConfirmedForRepo } from "../packages/qa/src/synthetic";

/**
 * WS-P scorer unit tests — synthetic findings vs ground truth (build-plan §4.7:
 * "Unit-test the scorer with synthetic findings vs ground truth").
 */

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
          file: "app/a.ts",
          line: 10,
          severity: "critical",
          expectedRiskClass: "auto-eligible",
          exploitable: true,
          description: "sqli",
        },
        {
          id: "gt_xss",
          category: "xss",
          cwe: ["CWE-79"],
          owasp: "A03:2021",
          file: "app/b.tsx",
          line: 5,
          severity: "high",
          expectedRiskClass: "auto-eligible",
          exploitable: true,
          description: "xss",
        },
        {
          id: "gt_dep",
          category: "vulnerable_dependency",
          cwe: ["CWE-1104"],
          owasp: "A06:2021",
          file: "package.json",
          line: 3,
          severity: "medium",
          expectedRiskClass: "auto-eligible",
          exploitable: false, // present but should be DEMOTED, not confirmed
          description: "dep",
        },
      ],
    },
    { name: "clean", kind: "clean", path: "clean", expectedFindings: [] },
  ],
};

const vuln = manifest.repos[0]!;

function mkConfirmed(
  over: Partial<ConfirmedFinding> & Pick<ConfirmedFinding, "id" | "category" | "location">,
): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    scanId: "s",
    clientId: "c",
    title: "t",
    cwe: [],
    severity: "high",
    exposure: "public",
    impact: "i",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "a" },
    createdAt: "2026-01-15T10:00:00.000Z",
    ...over,
  });
}

describe("scoreRepo — synthetic findings vs ground truth", () => {
  it("perfect scan => TP for every exploitable finding, no FP/FN", () => {
    const rs = scoreRepo(vuln, perfectConfirmedForRepo(vuln));
    expect(rs.truePositives).toBe(2);
    expect(rs.falsePositives).toBe(0);
    expect(rs.falseNegatives).toBe(0);
    expect(rs.overConfirmed).toBe(0);
  });

  it("a missed exploitable finding is a false negative", () => {
    const rs = scoreRepo(vuln, [groundTruthToConfirmed(vuln.expectedFindings[0]!)]);
    expect(rs.truePositives).toBe(1);
    expect(rs.falseNegatives).toBe(1);
    expect(rs.falsePositives).toBe(0);
  });

  it("a spurious confirmation is a false positive (not matching any ground truth)", () => {
    const rs = scoreRepo(vuln, [
      ...perfectConfirmedForRepo(vuln),
      mkConfirmed({
        id: "x",
        category: "command_injection",
        location: { file: "app/z.ts", line: 1 },
      }),
    ]);
    expect(rs.truePositives).toBe(2);
    expect(rs.falsePositives).toBe(1);
    expect(rs.overConfirmed).toBe(0);
  });

  it("confirming a non-exploitable (should-be-demoted) finding is a false positive + over-confirmed", () => {
    const dep = vuln.expectedFindings[2]!;
    const rs = scoreRepo(vuln, [groundTruthToConfirmed(dep)]);
    expect(rs.falsePositives).toBe(1);
    expect(rs.overConfirmed).toBe(1);
    expect(rs.truePositives).toBe(0);
    // the two real exploitable findings were missed
    expect(rs.falseNegatives).toBe(2);
  });

  it("line tolerance controls matching", () => {
    const drifted = mkConfirmed({
      id: "d",
      category: "sql_injection",
      location: { file: "app/a.ts", line: 12 }, // gt line is 10
    });
    expect(scoreRepo(vuln, [drifted], { lineTolerance: 3 }).truePositives).toBe(1);
    const strict = scoreRepo(vuln, [drifted], { lineTolerance: 1 });
    expect(strict.truePositives).toBe(0);
    expect(strict.falsePositives).toBe(1);
  });
});

describe("scoreScanResults — corpus aggregate", () => {
  it("computes precision/recall/fpRate and per-category from a perfect scan", () => {
    const results = manifest.repos.map((r) => ({
      repo: r.name,
      confirmed: perfectConfirmedForRepo(r),
    }));
    const score = scoreScanResults(results, manifest);
    expect(score).toMatchObject({ truePositives: 2, falsePositives: 0, falseNegatives: 0 });
    expect(score.precision).toBe(1);
    expect(score.recall).toBe(1);
    expect(score.fpRate).toBe(0);
    expect(score.reposScored).toBe(2);
    expect(score.reposWithResults).toBe(2);
    const cats = new Set(score.perCategory.map((c) => c.category));
    expect(cats).toEqual(new Set(["sql_injection", "xss"]));
  });

  it("fpRate == 1 - precision; headline reflects a single spurious finding", () => {
    const results = [
      {
        repo: "vuln",
        confirmed: [
          ...perfectConfirmedForRepo(vuln),
          mkConfirmed({ id: "sp", category: "ssrf", location: { file: "x.ts", line: 1 } }),
        ],
      },
    ];
    const score = scoreScanResults(results, manifest);
    expect(score.truePositives).toBe(2);
    expect(score.falsePositives).toBe(1);
    expect(score.fpRate).toBeCloseTo(1 / 3, 10);
    expect(score.fpRate).toBeCloseTo(1 - score.precision, 10);
  });

  it("a confirmed finding on a CLEAN repo is a false positive", () => {
    const results = [
      {
        repo: "clean",
        confirmed: [
          mkConfirmed({ id: "c", category: "xss", location: { file: "a.tsx", line: 1 } }),
        ],
      },
    ];
    const score = scoreScanResults(results, manifest);
    expect(score.falsePositives).toBe(1);
    expect(score.fpRate).toBe(1);
  });

  it("empty scan of a clean-only manifest => precision/recall 1, fpRate 0 (no divide-by-zero)", () => {
    const cleanOnly: GroundTruthManifest = { version: "t", repos: [manifest.repos[1]!] };
    const score = scoreScanResults([], cleanOnly);
    expect(score.precision).toBe(1);
    expect(score.recall).toBe(1);
    expect(score.fpRate).toBe(0);
  });

  it("results for a repo not in the manifest are counted as unknown, not scored", () => {
    const score = scoreScanResults(
      [
        {
          repo: "ghost",
          confirmed: [mkConfirmed({ id: "g", category: "xss", location: { file: "a", line: 1 } })],
        },
      ],
      manifest,
    );
    expect(score.unknownRepoResults).toBe(1);
    expect(score.falsePositives).toBe(0); // not attributed as an FP against ground truth
    expect(score.falseNegatives).toBe(2); // vuln repo had no results
  });
});
