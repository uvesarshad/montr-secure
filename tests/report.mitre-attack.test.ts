/**
 * MITRE ATT&CK report surfacing (B2) — packages/report/src/exports/mitre-attack.ts.
 * Standalone module, tested the same way as the neighboring
 * tests/report.exports.test.ts (real @montr/fixtures data through buildReport).
 */
import { describe, it, expect, beforeAll } from "vitest";
import type { Report } from "@montr/contracts";
import {
  buildReport,
  buildMitreFindingMappings,
  buildMitreAttackSection,
  renderMitreAttackJson,
} from "@montr/report";
import {
  mockScan,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockFixes,
  mockCostRollup,
  FIXED_LATER,
} from "@montr/fixtures";

let report: Report;

beforeAll(async () => {
  const out = await buildReport({
    scan: mockScan,
    confirmed: mockConfirmedFindings,
    unconfirmed: mockUnconfirmedFindings,
    fixes: mockFixes,
    costRollup: mockCostRollup,
    autoApply: false,
    generatedAt: FIXED_LATER,
  });
  report = out.report;
});

describe("@montr/report MITRE ATT&CK surfacing (B2)", () => {
  it("maps every confirmed finding to its category's real technique ids", () => {
    const mappings = buildMitreFindingMappings(report);
    expect(mappings).toHaveLength(mockConfirmedFindings.length);

    const sqli = mappings.find((m) => m.category === "sql_injection");
    expect(sqli?.techniques.map((t) => t.id)).toEqual(["T1190", "T1213"]);
    expect(sqli?.techniques.map((t) => t.name)).toEqual([
      "Exploit Public-Facing Application",
      "Data from Information Repositories",
    ]);

    const xss = mappings.find((m) => m.category === "xss");
    expect(xss?.techniques.map((t) => t.id)).toEqual(["T1059.007", "T1539"]);
  });

  it("every mapped technique carries a non-empty tactic and a live-looking MITRE url", () => {
    for (const mapping of buildMitreFindingMappings(report)) {
      for (const technique of mapping.techniques) {
        expect(technique.tactic.length).toBeGreaterThan(0);
        expect(technique.url).toMatch(/^https:\/\/(attack|atlas)\.mitre\.org\//);
      }
    }
  });

  it("builds a coverage index — one row per referenced technique, findings attributed correctly", () => {
    const section = buildMitreAttackSection(report);
    expect(section.scanId).toBe(report.scanId);
    expect(section.clientId).toBe(report.clientId);

    const t1190 = section.coverage.find((c) => c.technique.id === "T1190");
    // Only sql_injection maps to T1190 in this fixture set (xss maps to T1059.007/T1539).
    expect(t1190?.findingCount).toBe(1);
    expect(t1190?.findingIds).toEqual([
      section.findings.find((f) => f.category === "sql_injection")!.findingId,
    ]);

    // Coverage is sorted by technique id.
    const ids = section.coverage.map((c) => c.technique.id);
    expect(ids).toEqual([...ids].sort());
  });

  it("renderMitreAttackJson produces valid, round-trippable JSON matching buildMitreAttackSection", () => {
    const json = renderMitreAttackJson(report);
    const parsed = JSON.parse(json);
    expect(parsed).toEqual(JSON.parse(JSON.stringify(buildMitreAttackSection(report))));
  });

  it("accepts a deterministic `now` override for generatedAt", () => {
    const section = buildMitreAttackSection(report, "2026-01-01T00:00:00.000Z");
    expect(section.generatedAt).toBe("2026-01-01T00:00:00.000Z");
  });
});
