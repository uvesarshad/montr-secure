import { describe, it, expect } from "vitest";
import { mockAppMap, mockCandidateFindings, CLIENT_ID, SCAN_ID, FIXED_NOW } from "@montr/fixtures";
import { Layer2OutputSchema } from "@montr/contracts";
import { correlate, type PriorConfirmedShapes } from "@montr/correlation";

/**
 * E8 extension (2026-09-12) — `CorrelateInput.priorConfirmedShapes`.
 * Informational hypothesis text + rank-tie-break only; NEVER touches the
 * persisted reachabilityScore/exposureScore/impactScore, which stay exactly
 * what the golden-corpus-calibrated deterministic formula computes. Absent
 * (every existing caller/test) ⇒ byte-identical to before this feature —
 * covered by every other correlation.*.test.ts file already passing
 * unmodified; this file covers the NEW behavior specifically.
 */

const base = { clientId: CLIENT_ID, scanId: SCAN_ID, now: FIXED_NOW } as const;

function matcherFor(category: string, filePattern: string): PriorConfirmedShapes {
  return {
    matches: (signal) => signal.category === category && signal.file.startsWith(filePattern),
  };
}

describe("E8 extension — confirmed-exploit-shape priors in correlate()", () => {
  it("appends an informational note to the hypothesis on a match, and leaves it untouched without one", async () => {
    const withoutPrior = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
    });
    const sqliBefore = withoutPrior.probable.find((p) => p.category === "sql_injection")!;
    expect(sqliBefore.reachabilityHypothesis).not.toMatch(
      /confirmed exploitable in an earlier scan/i,
    );

    const withPrior = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      priorConfirmedShapes: matcherFor("sql_injection", "app/api/users"),
    });
    const sqliAfter = withPrior.probable.find((p) => p.category === "sql_injection")!;
    expect(sqliAfter.reachabilityHypothesis).toMatch(/confirmed exploitable in an earlier scan/i);

    // ⛔ The safety-critical property: a matching prior NEVER changes the
    // persisted, corpus-calibrated scores — only the narrative text.
    expect(sqliAfter.reachabilityScore).toBe(sqliBefore.reachabilityScore);
    expect(sqliAfter.exposureScore).toBe(sqliBefore.exposureScore);
    expect(sqliAfter.impactScore).toBe(sqliBefore.impactScore);
    expect(sqliAfter.rank).toBe(sqliBefore.rank);
  });

  it("a non-matching prior (wrong category) changes nothing", async () => {
    const out = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      priorConfirmedShapes: matcherFor("xxe", "app/api/users"),
    });
    const sqli = out.probable.find((p) => p.category === "sql_injection")!;
    expect(sqli.reachabilityHypothesis).not.toMatch(/confirmed exploitable in an earlier scan/i);
  });

  it("still emits a contract-valid Layer2Output with a prior configured", async () => {
    const out = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      priorConfirmedShapes: matcherFor("sql_injection", "app/api/users"),
    });
    expect(() => Layer2OutputSchema.parse(out)).not.toThrow();
  });
});
