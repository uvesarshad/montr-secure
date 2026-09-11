import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import {
  loadDetectionCoverageFindingsFile,
  parseDetectionCoverageFindings,
} from "../packages/qa/src/detection-coverage-findings-io";

/**
 * Detection-coverage regression gate (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md) — findings-file
 * parser tests. Mirrors tests covering findings-io.ts/blue-team-findings-io.ts.
 */

describe("parseDetectionCoverageFindings", () => {
  it("accepts the { results: [...] } shape with true/false/unknown detected", () => {
    const entries = parseDetectionCoverageFindings({
      results: [
        { repo: "r1", findingId: "f1", category: "sql_injection", detected: true },
        { repo: "r1", findingId: "f2", category: "xss", detected: false, reasoning: "no rule" },
        { repo: "r2", findingId: "f3", category: "ssrf", detected: "unknown" },
      ],
    });
    expect(entries).toHaveLength(3);
    expect(entries[0]).toMatchObject({ repo: "r1", findingId: "f1", detected: true });
    expect(entries[1]?.reasoning).toBe("no rule");
    expect(entries[2]?.detected).toBe("unknown");
  });

  it("accepts a bare array too", () => {
    const entries = parseDetectionCoverageFindings([
      { repo: "r1", findingId: "f1", category: "sql_injection", detected: true },
    ]);
    expect(entries).toHaveLength(1);
  });

  it("rejects a non-array/non-{results} shape", () => {
    expect(() => parseDetectionCoverageFindings({ nope: true })).toThrow();
    expect(() => parseDetectionCoverageFindings("nope")).toThrow();
  });

  it("rejects an entry missing repo/findingId", () => {
    expect(() =>
      parseDetectionCoverageFindings({
        results: [{ findingId: "f1", category: "sql_injection", detected: true }],
      }),
    ).toThrow();
    expect(() =>
      parseDetectionCoverageFindings({
        results: [{ repo: "r1", category: "sql_injection", detected: true }],
      }),
    ).toThrow();
  });

  it("rejects an invalid category", () => {
    expect(() =>
      parseDetectionCoverageFindings({
        results: [{ repo: "r1", findingId: "f1", category: "not_a_category", detected: true }],
      }),
    ).toThrow();
  });

  it("rejects a detected value that isn't true/false/'unknown'", () => {
    expect(() =>
      parseDetectionCoverageFindings({
        results: [{ repo: "r1", findingId: "f1", category: "sql_injection", detected: "maybe" }],
      }),
    ).toThrow();
  });
});

describe("loadDetectionCoverageFindingsFile", () => {
  it("reads and parses a real file from disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "detection-coverage-findings-"));
    const path = join(dir, "findings.json");
    writeFileSync(
      path,
      JSON.stringify({
        results: [{ repo: "r1", findingId: "f1", category: "sql_injection", detected: true }],
      }),
    );
    const entries = await loadDetectionCoverageFindingsFile(path);
    expect(entries).toHaveLength(1);
  });

  it("throws ConfigValidationError for a missing file", async () => {
    await expect(loadDetectionCoverageFindingsFile("/no/such/findings.json")).rejects.toThrow();
  });

  it("throws ConfigValidationError for invalid JSON", async () => {
    const dir = mkdtempSync(join(tmpdir(), "detection-coverage-findings-bad-"));
    const path = join(dir, "findings.json");
    writeFileSync(path, "{not json");
    await expect(loadDetectionCoverageFindingsFile(path)).rejects.toThrow();
  });
});
