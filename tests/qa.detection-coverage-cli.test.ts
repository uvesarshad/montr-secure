import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { run } from "../packages/qa/src/detection-coverage-cli";
import { QA_EXIT } from "../packages/qa/src/exit-codes";

/**
 * Detection-coverage regression gate (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md) — CLI exit-code
 * contract tests. Mirrors tests/qa.cli.test.ts's / tests/qa.blue-team-cli.test.ts's
 * pattern exactly for `qa:detection-coverage`.
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

describe("qa:detection-coverage CLI exit codes", () => {
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
    expect(c.outText()).toMatch(/Detection-coverage baseline gate: PASS/);
  });

  it("--json => OK with a machine-readable passing report", async () => {
    const c = capture();
    const code = await run(["--json"], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    const report = JSON.parse(c.outText());
    expect(report.passed).toBe(true);
    expect(report.headline.gapRate).toBe(0);
  });

  it("--findings pointing at a real gap-heavy run scores it for real and passes against a lenient baseline", async () => {
    const dir = mkdtempSync(join(tmpdir(), "detection-coverage-findings-"));
    const findingsPath = join(dir, "findings.json");
    const baselinePath = join(dir, "baseline.json");
    // A real run's shape: mostly detected:false (matches the actual
    // measured corpus run, see corpus/detection-coverage-baseline.json).
    writeFileSync(
      findingsPath,
      JSON.stringify({
        results: [
          { repo: "javaseccode", findingId: "f1", category: "sql_injection", detected: false },
          { repo: "javaseccode", findingId: "f2", category: "sql_injection", detected: false },
          {
            repo: "javaseccode",
            findingId: "f3",
            category: "command_injection",
            detected: "unknown",
          },
        ],
      }),
    );
    writeFileSync(baselinePath, JSON.stringify({ gapRateMax: 0.75 }));
    const c = capture();
    const code = await run(["--findings", findingsPath, "--baseline", baselinePath], c.out, c.err);
    expect(code).toBe(QA_EXIT.OK);
    expect(c.outText()).not.toMatch(/SELF-CHECK MODE/);
    expect(c.outText()).toMatch(/Detection-coverage baseline gate: PASS/);
  });

  it("--findings with a real gap-rate regression fails the gate (REGRESSION)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "detection-coverage-findings-regression-"));
    const findingsPath = join(dir, "findings.json");
    const baselinePath = join(dir, "baseline.json");
    // Every finding lands on a route with no telemetry — the exact scenario
    // this gate exists to catch.
    writeFileSync(
      findingsPath,
      JSON.stringify({
        results: [
          { repo: "javaseccode", findingId: "f1", category: "sql_injection", detected: false },
          { repo: "javaseccode", findingId: "f2", category: "sql_injection", detected: false },
        ],
      }),
    );
    writeFileSync(baselinePath, JSON.stringify({ gapRateMax: 0.1 }));
    const c = capture();
    const code = await run(["--findings", findingsPath, "--baseline", baselinePath], c.out, c.err);
    expect(code).toBe(QA_EXIT.REGRESSION);
    expect(c.outText()).toMatch(/Detection-coverage baseline gate: FAIL/);
    expect(c.outText()).toMatch(/gapRate/);
  });

  it("--findings referencing an invalid entry => CORPUS_ERROR", async () => {
    const dir = mkdtempSync(join(tmpdir(), "detection-coverage-findings-bad-"));
    const path = join(dir, "findings.json");
    writeFileSync(path, JSON.stringify({ results: [{ repo: "r1" }] }));
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
