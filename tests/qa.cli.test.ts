import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { run } from "../packages/qa/src/cli";
import { QA_EXIT } from "../packages/qa/src/exit-codes";

/**
 * WS-P CLI exit-code contract tests (build-plan §4.7: "clear exit codes so CI
 * can gate on it"). `run()` returns the code instead of calling process.exit.
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

describe("qa:corpus CLI exit codes", () => {
  it("--help => OK", async () => {
    const c = capture();
    const code = await run(["--help"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).toMatch(/Usage:/);
  });

  it("self-check (no args) => OK and passes the committed gate", async () => {
    const c = capture();
    const code = await run([], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).toMatch(/SELF-CHECK MODE/);
    expect(c.outText()).toMatch(/Baseline gate: PASS/);
  });

  it("--json => OK with a machine-readable passing report", async () => {
    const c = capture();
    const code = await run(["--json"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    const report = JSON.parse(c.outText());
    expect(report.passed).toBe(true);
    expect(report.headline.fpRate).toBe(0);
  });

  it("--variance => OK, prints the REAL per-model matrix, and models genuinely differ (A23)", async () => {
    const c = capture();
    const code = await run(["--variance"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).toMatch(/VARIANCE MODE — real packages\/confirm/);
    expect(c.outText()).toMatch(/Model-variance matrix/);
    // The regression this whole harness exists to catch: every model scoring
    // an identical number. Assert the printed table is NOT that.
    const recallColumn = c
      .outText()
      .split("\n")
      .filter((line) => /^ {2}[a-z]/i.test(line) && /%/.test(line))
      .map((line) => line.trim().split(/\s+/)[1]);
    expect(new Set(recallColumn).size).toBeGreaterThan(1);
  });

  it("--variance --variance-selfcheck => OK and prints the OLD tautological self-check", async () => {
    const c = capture();
    const code = await run(["--variance", "--variance-selfcheck"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).toMatch(/VARIANCE SELF-CHECK MODE/);
    expect(c.outText()).toMatch(/Model-variance matrix/);
  });

  it("unknown option => USAGE", async () => {
    const c = capture();
    expect(await run(["--nope"], c.out, c.err)).toBe(QA_EXIT.USAGE);
    expect(c.errText()).toMatch(/unknown option/);
  });

  it("bad --line-tolerance => USAGE", async () => {
    const c = capture();
    expect(await run(["--line-tolerance", "-1"], c.out, c.err)).toBe(QA_EXIT.USAGE);
  });

  it("missing baseline file => CORPUS_ERROR", async () => {
    const c = capture();
    expect(await run(["--baseline", "/no/such/baseline.json"], c.out, c.err)).toBe(
      QA_EXIT.CORPUS_ERROR,
    );
  });

  it("findings that miss the corpus => REGRESSION (non-zero for CI)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "qa-cli-"));
    const path = join(dir, "findings.json");
    // Empty confirmed for the vulnerable repos => every exploitable finding is a false negative.
    writeFileSync(
      path,
      JSON.stringify({ results: [{ repo: "vulnerable-nextjs", confirmed: [] }] }),
    );
    const c = capture();
    const code = await run(["--findings", path], c.out, c.err);
    expect(code).toBe(QA_EXIT.REGRESSION);
    expect(c.outText()).toMatch(/Baseline gate: FAIL/);
  });
});
