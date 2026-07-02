import { describe, it, expect } from "vitest";
import {
  Layer5OutputSchema,
  ReportSchema,
  FixSchema,
  complianceForCategory,
  type Fix,
} from "@montr/contracts";
import {
  buildReport,
  buildExecutiveSummary,
  computePostureDelta,
  prioritize,
  findingFingerprint,
  buildComplianceMapping,
} from "@montr/report";
import {
  mockScan,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockFixes,
  mockCandidateFindings,
  mockCostRollup,
  FIXED_LATER,
  FIX_XSS_ID,
} from "@montr/fixtures";

const baseInput = () => ({
  scan: mockScan,
  confirmed: mockConfirmedFindings,
  unconfirmed: mockUnconfirmedFindings,
  fixes: mockFixes,
  costRollup: mockCostRollup,
  autoApply: false,
  generatedAt: FIXED_LATER,
});

describe("@montr/report buildReport — Layer5Output (§12)", () => {
  it("emits a schema-valid Layer5Output { report, pullRequests }", async () => {
    const out = await buildReport(baseInput());
    expect(Layer5OutputSchema.safeParse(out).success).toBe(true);
    expect(ReportSchema.safeParse(out.report).success).toBe(true);
  });

  it("defaults to a deterministic report id and carries scan identity", async () => {
    const out = await buildReport(baseInput());
    expect(out.report.id).toBe(`report_${mockScan.id}`);
    expect(out.report.scanId).toBe(mockScan.id);
    expect(out.report.clientId).toBe(mockScan.clientId);
    expect(out.report.generatedAt).toBe(FIXED_LATER);
  });

  it("executive summary counts CONFIRMED findings only (headline safety)", async () => {
    const out = await buildReport(baseInput());
    const es = out.report.executiveSummary;
    expect(es.totalConfirmed).toBe(mockConfirmedFindings.length);
    const sum = Object.values(es.confirmedBySeverity).reduce((a, b) => a + (b ?? 0), 0);
    expect(sum).toBe(es.totalConfirmed);
    expect(es.confirmedBySeverity.critical).toBe(1);
    expect(es.confirmedBySeverity.high).toBe(1);
  });

  it("derives consolidated tools from the candidate pile (excludes llm-triage)", async () => {
    const out = await buildReport({ ...baseInput(), candidates: mockCandidateFindings });
    expect(out.report.executiveSummary.toolsConsolidated).toEqual(["gitleaks", "osv", "semgrep"]);
  });

  it("prioritizes confirmed findings (critical before high) regardless of input order", async () => {
    const reversed = [...mockConfirmedFindings].reverse();
    const out = await buildReport({ ...baseInput(), confirmed: reversed });
    const severities = out.report.confirmedFindings.map((rf) => rf.finding.severity);
    expect(severities).toEqual(["critical", "high"]);
    // prioritize() is stable/pure
    expect(prioritize(reversed).map((f) => f.severity)).toEqual(["critical", "high"]);
  });

  it("embeds the merge-ready fix + per-finding compliance mapping", async () => {
    const out = await buildReport(baseInput());
    const sqli = out.report.confirmedFindings.find((rf) => rf.finding.category === "sql_injection");
    expect(sqli?.fix).toBeDefined();
    expect(sqli?.fix?.proofOfFixTest.code).toBeTruthy();
    expect(sqli?.compliance).toEqual(complianceForCategory("sql_injection"));
  });

  it("keeps the unconfirmed appendix (never deleted, clearly separated)", async () => {
    const out = await buildReport(baseInput());
    expect(out.report.unconfirmedAppendix).toEqual(mockUnconfirmedFindings);
    // Appendix items are NOT in the confirmed headline set.
    const confirmedIds = new Set(out.report.confirmedFindings.map((rf) => rf.finding.id));
    for (const u of out.report.unconfirmedAppendix) expect(confirmedIds.has(u.id)).toBe(false);
  });

  it("splits fix status into auto-eligible (PR-able) vs human-required (recommendations)", async () => {
    const humanFix: Fix = FixSchema.parse({
      ...mockFixes[1],
      id: FIX_XSS_ID,
      riskClass: "human-required",
      riskClassRationale: "Touches access-control — always human-required (§11).",
    });
    const fixes: Fix[] = [mockFixes[0]!, humanFix];
    const out = await buildReport({ ...baseInput(), fixes });
    expect(out.report.fixStatus.autoEligibleFixIds).toEqual([mockFixes[0]!.id]);
    expect(out.report.fixStatus.humanRequiredFixIds).toEqual([FIX_XSS_ID]);
  });

  it("dedupes the top-level compliance mapping by category", async () => {
    const out = await buildReport(baseInput());
    const cats = out.report.complianceMapping.map((m) => m.category);
    expect(new Set(cats).size).toBe(cats.length);
    expect(buildComplianceMapping(mockConfirmedFindings).map((m) => m.owasp)).toContain("A03:2021");
  });

  it("surfaces scope + cost rollup unchanged", async () => {
    const out = await buildReport(baseInput());
    expect(out.report.costAndScope.scope).toEqual(mockScan.scope);
    expect(out.report.costAndScope.cost).toEqual(mockCostRollup);
  });
});

describe("@montr/report posture delta (§12.1)", () => {
  it("is absent when no previous scan is supplied", async () => {
    const out = await buildReport(baseInput());
    expect(out.report.executiveSummary.postureDelta).toBeUndefined();
  });

  it("computes new/resolved/net vs the previous scan by stable fingerprint", () => {
    const previous = { scanId: "scan_prev", confirmed: [mockConfirmedFindings[0]!] }; // only SQLi last time
    const delta = computePostureDelta(mockConfirmedFindings, previous);
    expect(delta.previousScanId).toBe("scan_prev");
    expect(delta.newIssues).toBe(1); // XSS is new
    expect(delta.resolvedIssues).toBe(0);
    expect(delta.netDelta).toBe(1);
  });

  it("counts a dropped finding as resolved (negative net = improvement)", () => {
    const previous = { confirmed: mockConfirmedFindings };
    const delta = computePostureDelta([mockConfirmedFindings[0]!], previous);
    expect(delta.newIssues).toBe(0);
    expect(delta.resolvedIssues).toBe(1);
    expect(delta.netDelta).toBe(-1);
  });

  it("fingerprint is stable across line drift", () => {
    const drifted = {
      ...mockConfirmedFindings[0]!,
      location: { ...mockConfirmedFindings[0]!.location, line: 999 },
    };
    // same category+file+symbol → same fingerprint even though the line moved
    const a = findingFingerprint(mockConfirmedFindings[0]!);
    const b = findingFingerprint({
      ...drifted,
      location: { ...drifted.location, symbol: undefined },
    });
    // line differs and no symbol, so these differ — the guarantee is symbol-stability:
    const withSymbol = findingFingerprint({
      ...mockConfirmedFindings[0]!,
      location: { ...mockConfirmedFindings[0]!.location, symbol: "handler", line: 1 },
    });
    const withSymbolDrift = findingFingerprint({
      ...mockConfirmedFindings[0]!,
      location: { ...mockConfirmedFindings[0]!.location, symbol: "handler", line: 42 },
    });
    expect(withSymbol).toBe(withSymbolDrift);
    expect(a).not.toBe(b);
  });
});

describe("@montr/report buildExecutiveSummary", () => {
  it("honors an explicit toolsConsolidated override", () => {
    const es = buildExecutiveSummary({
      ...baseInput(),
      toolsConsolidated: ["semgrep", "trivy", "semgrep"],
    });
    expect(es.toolsConsolidated).toEqual(["semgrep", "trivy"]);
  });
});
