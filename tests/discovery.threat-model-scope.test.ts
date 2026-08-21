/**
 * E6 — Layer 1 consumption of the App Map's threat-model `ScopeHints`
 * (`packages/discovery/src/threat-model-scope.ts`). The single property this
 * suite exists to lock in: coverage never regresses. Every candidate the
 * deterministic detectors produce still ships — scope hints only annotate and
 * reorder, they never filter (see that module's doc comment and E6's own
 * safety framing in docs/plan/26-08-22-audit-ai-depth.md).
 */
import { describe, it, expect } from "vitest";
import type { AppMap, CandidateFinding } from "@montr/contracts";
import { mockAppMap } from "@montr/fixtures";
import { buildDeterministicThreatModel } from "@montr/appmap";
import { applyThreatModelScopeHints } from "@montr/discovery";

function candidate(overrides: Partial<CandidateFinding> = {}): CandidateFinding {
  return {
    id: overrides.id ?? `cand_${Math.random().toString(36).slice(2)}`,
    scanId: "scan_fixture_0001",
    clientId: "client_fixture_0001",
    source: "semgrep",
    ruleId: "rule.generic",
    category: "other",
    cwe: [],
    location: { file: "some/other/file.ts", line: 1 },
    rawSeverity: "medium",
    evidenceSnippet: "",
    status: "candidate",
    createdAt: "2026-01-15T10:00:00.000Z",
    ...overrides,
  };
}

describe("discovery — applyThreatModelScopeHints (E6)", () => {
  it("is a no-op when the App Map carries no threat model", () => {
    const appMap: AppMap = { ...mockAppMap, threatModel: undefined };
    const candidates = [candidate({ category: "sql_injection" }), candidate({ category: "xss" })];
    const result = applyThreatModelScopeHints(candidates, appMap);
    expect(result).toBe(candidates);
  });

  it("never changes the candidate count or drops a candidate id (coverage never regresses)", () => {
    const threatModel = buildDeterministicThreatModel(mockAppMap);
    const appMap: AppMap = { ...mockAppMap, threatModel };
    const candidates = [
      candidate({
        id: "c1",
        category: "sql_injection",
        location: { file: "app/api/users/route.ts", line: 9 },
      }),
      candidate({ id: "c2", category: "xss", location: { file: "app/search/page.tsx", line: 8 } }),
      candidate({
        id: "c3",
        category: "vulnerable_dependency",
        location: { file: "package.json", line: 1 },
      }),
      candidate({
        id: "c4",
        category: "missing_security_headers",
        location: { file: "unrelated.ts", line: 1 },
      }),
    ];
    const result = applyThreatModelScopeHints(candidates, appMap);

    expect(result).toHaveLength(candidates.length);
    expect(new Set(result.map((c) => c.id))).toEqual(new Set(candidates.map((c) => c.id)));
  });

  it("annotates candidates matching a priority category or a priority route's file", () => {
    const threatModel = buildDeterministicThreatModel(mockAppMap);
    // sql_injection is high-plausibility for the fixture — confirm it made the cut.
    expect(threatModel.scopeHints.priorityCategories.map((h) => h.category)).toContain(
      "sql_injection",
    );

    const appMap: AppMap = { ...mockAppMap, threatModel };
    const sqlCandidate = candidate({
      id: "sql-1",
      category: "sql_injection",
      location: { file: "app/api/users/route.ts", line: 9 },
    });
    const unrelatedCandidate = candidate({
      id: "unrelated-1",
      category: "missing_security_headers",
      location: { file: "unrelated.ts", line: 1 },
    });

    const result = applyThreatModelScopeHints([unrelatedCandidate, sqlCandidate], appMap);
    const annotated = result.find((c) => c.id === "sql-1");
    const untouched = result.find((c) => c.id === "unrelated-1");

    expect(
      (annotated?.metadata as { threatModelPriority?: { categoryMatch?: boolean } } | undefined)
        ?.threatModelPriority?.categoryMatch,
    ).toBe(true);
    expect(untouched?.metadata?.threatModelPriority).toBeUndefined();
  });

  it("stable-sorts priority-annotated candidates first without reordering within each group", () => {
    const threatModel = buildDeterministicThreatModel(mockAppMap);
    const appMap: AppMap = { ...mockAppMap, threatModel };
    const low1 = candidate({ id: "low-1", category: "missing_security_headers" });
    const low2 = candidate({ id: "low-2", category: "insufficient_logging" });
    const high1 = candidate({
      id: "high-1",
      category: "xss",
      location: { file: "app/search/page.tsx", line: 8 },
    });
    const high2 = candidate({
      id: "high-2",
      category: "sql_injection",
      location: { file: "app/api/users/route.ts", line: 9 },
    });

    const result = applyThreatModelScopeHints([low1, high1, low2, high2], appMap);
    const ids = result.map((c) => c.id);

    // Priority (high1, high2) float before non-priority (low1, low2); relative
    // order within each group is preserved (stable sort).
    expect(ids.indexOf("high-1")).toBeLessThan(ids.indexOf("low-1"));
    expect(ids.indexOf("high-2")).toBeLessThan(ids.indexOf("low-2"));
    expect(ids.indexOf("high-1")).toBeLessThan(ids.indexOf("high-2"));
    expect(ids.indexOf("low-1")).toBeLessThan(ids.indexOf("low-2"));
  });

  it("never mutates the input candidate objects", () => {
    const threatModel = buildDeterministicThreatModel(mockAppMap);
    const appMap: AppMap = { ...mockAppMap, threatModel };
    const original = candidate({
      id: "sql-1",
      category: "sql_injection",
      location: { file: "app/api/users/route.ts", line: 9 },
    });
    const before = JSON.parse(JSON.stringify(original));
    applyThreatModelScopeHints([original], appMap);
    expect(original).toEqual(before);
  });
});
