import { describe, it, expect } from "vitest";
import { ConfirmedFindingSchema, type ConfirmedFinding } from "@montr/contracts";
import type { GroundTruthFinding, GroundTruthManifest } from "@montr/fixtures";
import { gradeScanResults, gradeCorpus } from "./real-mode.js";
import { perfectScanner } from "./runner.js";
import { groundTruthToConfirmed } from "./synthetic.js";
import type { LoadedCorpus, LoadedRepo } from "./corpus.js";
import type { RepoScanResult } from "./types.js";

/**
 * Carry-over #4 (golden-corpus REAL mode). The gate must score a REAL pipeline's
 * ConfirmedFinding[] against ground truth (true precision / recall / FP-rate),
 * with the synthetic self-check kept as the fallback (build-plan §4.7, DoD §19).
 * Deterministic + offline: an inline corpus + hand-built confirmed findings.
 */

const gtSqli: GroundTruthFinding = {
  id: "gt_sqli",
  category: "sql_injection",
  cwe: ["CWE-89"],
  owasp: "A03:2021",
  file: "app/a.ts",
  line: 10,
  severity: "critical",
  expectedRiskClass: "auto-eligible",
  exploitable: true,
  description: "raw query sqli",
};
const gtXss: GroundTruthFinding = {
  id: "gt_xss",
  category: "xss",
  cwe: ["CWE-79"],
  owasp: "A03:2021",
  file: "app/b.tsx",
  line: 5,
  severity: "high",
  expectedRiskClass: "auto-eligible",
  exploitable: true,
  description: "reflected xss",
};
const gtDep: GroundTruthFinding = {
  id: "gt_dep",
  category: "vulnerable_dependency",
  cwe: ["CWE-1104"],
  owasp: "A06:2021",
  file: "package.json",
  line: 3,
  severity: "medium",
  expectedRiskClass: "auto-eligible",
  exploitable: false, // present but should be DEMOTED, not confirmed
  description: "unreachable CVE",
};

const manifest: GroundTruthManifest = {
  version: "test",
  repos: [
    { name: "vuln", kind: "vulnerable", path: "vuln", expectedFindings: [gtSqli, gtXss, gtDep] },
    { name: "clean", kind: "clean", path: "clean", expectedFindings: [] },
  ],
};

/** A spurious confirmed finding matching no ground-truth case (a false positive). */
function spurious(): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: "conf_spurious",
    scanId: "s",
    clientId: "c",
    title: "spurious",
    category: "xss",
    cwe: ["CWE-79"],
    owasp: "A03:2021",
    severity: "high",
    exposure: "public",
    location: { file: "app/z.ts", line: 99 },
    impact: "none",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "n/a", dataFlow: [], sanitizersBypassed: [] },
    createdAt: "2026-01-15T10:00:00.000Z",
  });
}

describe("gradeScanResults — REAL scan output vs ground truth", () => {
  it("a perfect real scan passes the baseline (precision/recall 1, fpRate 0)", () => {
    const results: RepoScanResult[] = [
      { repo: "vuln", confirmed: [groundTruthToConfirmed(gtSqli), groundTruthToConfirmed(gtXss)] },
      { repo: "clean", confirmed: [] },
    ];
    const { score, regression } = gradeScanResults(results, manifest);
    expect(regression.passed).toBe(true);
    expect(score.precision).toBe(1);
    expect(score.recall).toBe(1);
    expect(score.fpRate).toBe(0);
    expect(score.reposScored).toBe(2);
  });

  it("a MISSED exploitable finding fails the gate on recall", () => {
    const results: RepoScanResult[] = [
      { repo: "vuln", confirmed: [groundTruthToConfirmed(gtSqli)] }, // xss missed
    ];
    const { score, regression } = gradeScanResults(results, manifest);
    expect(regression.passed).toBe(false);
    expect(score.recall).toBeLessThan(0.9);
    expect(regression.violations.some((v) => v.metric === "recall")).toBe(true);
  });

  it("a SPURIOUS confirmation fails the gate on FP-rate (headline metric)", () => {
    const results: RepoScanResult[] = [
      {
        repo: "vuln",
        confirmed: [groundTruthToConfirmed(gtSqli), groundTruthToConfirmed(gtXss), spurious()],
      },
    ];
    const { score, regression } = gradeScanResults(results, manifest);
    expect(regression.passed).toBe(false);
    expect(score.fpRate).toBeGreaterThan(0.05);
    expect(regression.violations.some((v) => v.metric === "fpRate")).toBe(true);
  });

  it("OVER-CONFIRMING a demoted (non-exploitable) case counts as a false positive", () => {
    const results: RepoScanResult[] = [
      {
        repo: "vuln",
        confirmed: [
          groundTruthToConfirmed(gtSqli),
          groundTruthToConfirmed(gtXss),
          groundTruthToConfirmed(gtDep), // ground truth says this should stay demoted
        ],
      },
    ];
    const { score, regression } = gradeScanResults(results, manifest);
    expect(score.overConfirmed).toBe(1);
    expect(regression.passed).toBe(false);
  });
});

/** Build a minimal LoadedCorpus around the inline manifest (no disk access). */
function inlineCorpus(): LoadedCorpus {
  const repos: LoadedRepo[] = manifest.repos.map((r) => ({
    name: r.name,
    kind: r.kind,
    source: "corpus",
    path: r.path,
    expectedFindings: r.expectedFindings,
  }));
  return {
    version: "test",
    fixturesVersion: "test",
    repos,
    manifest,
    warnings: [],
    root: "/tmp/inline",
  };
}

describe("gradeCorpus — live scanner vs synthetic fallback", () => {
  it("grades a live scanner (real pipeline plug-in point) against the corpus", async () => {
    // A 'real' scanner that returns exactly the exploitable findings for each repo.
    const liveScanner = (repo: LoadedRepo): ConfirmedFinding[] =>
      repo.expectedFindings.filter((f) => f.exploitable).map((f) => groundTruthToConfirmed(f));
    const { regression, score, run } = await gradeCorpus(inlineCorpus(), liveScanner);
    expect(regression.passed).toBe(true);
    expect(score.recall).toBe(1);
    expect(run.results.length).toBe(2);
  });

  it("keeps the synthetic perfectScanner as a working fallback", async () => {
    const { regression } = await gradeCorpus(inlineCorpus(), perfectScanner);
    expect(regression.passed).toBe(true);
  });

  it("a live scanner that emits a false positive fails the gate", async () => {
    const noisyScanner = (repo: LoadedRepo): ConfirmedFinding[] =>
      repo.kind === "vulnerable"
        ? [
            ...repo.expectedFindings
              .filter((f) => f.exploitable)
              .map((f) => groundTruthToConfirmed(f)),
            spurious(),
          ]
        : [];
    const { regression } = await gradeCorpus(inlineCorpus(), noisyScanner);
    expect(regression.passed).toBe(false);
  });
});
