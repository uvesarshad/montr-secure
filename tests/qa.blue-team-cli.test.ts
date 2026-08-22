import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { run } from "../packages/qa/src/blue-team-cli";
import { QA_EXIT } from "../packages/qa/src/exit-codes";
import { BLUE_TEAM_GROUND_TRUTH } from "../packages/qa/src/blue-team-corpus";

/**
 * B12 — blue-team detection-corpus CLI exit-code contract tests. Mirrors
 * tests/qa.cli.test.ts's pattern exactly for `qa:blue-team-corpus`.
 */

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out: (s: string) => out.push(s),
    err: (s: string) => err.push(s),
    outText: () => out.join("\n"),
    errText: () => err.join("\n"),
  };
}

describe("qa:blue-team-corpus CLI exit codes", () => {
  it("--help => OK", async () => {
    const c = capture();
    const code = await run(["--help"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).toMatch(/Usage:/);
  });

  it("self-check (no args) => OK, tautologically PASSes, and says so", async () => {
    const c = capture();
    const code = await run([], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).toMatch(/SELF-CHECK MODE/);
    expect(c.outText()).toMatch(/Blue-team baseline gate: PASS/);
  });

  it("--json => OK with a machine-readable passing report", async () => {
    const c = capture();
    const code = await run(["--json"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    const report = JSON.parse(c.outText());
    expect(report.passed).toBe(true);
    expect(report.headline.detectionPrecision).toBe(1);
    expect(report.headline.detectionRecall).toBe(1);
  });

  it("--findings pointing at a real (non-tautological) run scores it for real and passes against the committed gate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "blue-team-findings-"));
    const path = join(dir, "findings.json");
    // A REAL run's shape: some fired, some didn't — matches
    // BLUE_TEAM_GROUND_TRUTH exactly (as scripts/blue-team-corpus-scan.mjs's
    // real invocation measured — see corpus/blue-team-baseline.json).
    writeFileSync(
      path,
      JSON.stringify({
        results: BLUE_TEAM_GROUND_TRUTH.map((c) => ({
          templateKey: c.templateKey,
          actualFired: c.expectedFired,
          evidence: "test fixture",
        })),
      }),
    );
    const c = capture();
    const code = await run(["--findings", path], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).not.toMatch(/SELF-CHECK MODE/);
    expect(c.outText()).toMatch(/Blue-team baseline gate: PASS/);
  });

  it("--findings with a real detection-recall regression fails the gate (REGRESSION)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "blue-team-findings-regression-"));
    const path = join(dir, "findings.json");
    // Every case reports actualFired:false — a total recall collapse (every
    // expected-true case is now a false negative).
    writeFileSync(
      path,
      JSON.stringify({
        results: BLUE_TEAM_GROUND_TRUTH.map((c) => ({
          templateKey: c.templateKey,
          actualFired: false,
          evidence: "synthetic regression fixture",
        })),
      }),
    );
    const c = capture();
    const code = await run(["--findings", path], c.out, c.err);
    expect(code).toBe(QA_EXIT.REGRESSION);
    expect(c.outText()).toMatch(/Blue-team baseline gate: FAIL/);
    expect(c.outText()).toMatch(/detectionRecall/);
  });

  it("--findings referencing an unknown templateKey => CORPUS_ERROR", async () => {
    const dir = mkdtempSync(join(tmpdir(), "blue-team-findings-bad-"));
    const path = join(dir, "findings.json");
    writeFileSync(
      path,
      JSON.stringify({ results: [{ templateKey: "not-a-real-key", actualFired: true }] }),
    );
    const c = capture();
    const code = await run(["--findings", path], c.out, c.err);
    expect(code).toBe(QA_EXIT.CORPUS_ERROR);
  });

  it("unknown option => USAGE", async () => {
    const c = capture();
    expect(await run(["--nope"], c.out, c.err)).toBe(QA_EXIT.USAGE);
    expect(c.errText()).toMatch(/unknown option/);
  });

  it("missing findings file => CORPUS_ERROR", async () => {
    const c = capture();
    const code = await run(["--findings", "/no/such/file.json"], c.out, c.err);
    expect(code).toBe(QA_EXIT.CORPUS_ERROR);
  });
});
