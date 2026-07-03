import { describe, it, expect } from "vitest";
import { SarifLogSchema, ReportSchema, CATEGORY_TAXONOMY } from "@montr/contracts";
import { mockReport } from "@montr/fixtures";
import {
  buildSarif,
  renderSarif,
  renderOwaspJson,
  renderSoc2Evidence,
  renderIso27001Evidence,
  renderCsv,
  renderJson,
  REPORT_EXPORTS,
  exportFilename,
  type ReportExportFormat,
} from "../apps/web/src/lib/exports";

/**
 * Web report exporters (Agent B, apps/web). These generate downloadable evidence
 * CLIENT-SIDE from the loaded report so the compliance tab works offline. SARIF
 * is validated against the SAME frozen contract @montr/report validates against,
 * keeping the two producers byte-compatible (golden rule #10).
 */

const confirmedCount = mockReport.confirmedFindings.length;

describe("SARIF export (§13, DECIDE-5 — ships first, broadest)", () => {
  it("produces a schema-valid SARIF 2.1.0 log, one result per confirmed finding", () => {
    const sarif = buildSarif(mockReport);
    expect(SarifLogSchema.safeParse(sarif).success).toBe(true);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]!.results).toHaveLength(confirmedCount);
    expect(sarif.runs[0]!.tool.driver.name).toBe("Montr Secure");
  });

  it("maps severity to SARIF level (critical → error)", () => {
    const sarif = buildSarif(mockReport);
    const crit = mockReport.confirmedFindings.find((rf) => rf.finding.severity === "critical");
    if (crit) {
      const result = sarif.runs[0]!.results.find((r) => r.ruleId === crit.finding.category);
      expect(result?.level).toBe("error");
    }
  });

  it("renderSarif emits parseable JSON that re-validates against the schema", () => {
    const parsed = JSON.parse(renderSarif(mockReport));
    expect(SarifLogSchema.safeParse(parsed).success).toBe(true);
  });
});

describe("OWASP-JSON export", () => {
  it("groups confirmed findings by OWASP Top 10 category", () => {
    const owasp = JSON.parse(renderOwaspJson(mockReport));
    expect(owasp.tool).toBe("Montr Secure");
    expect(owasp.totalConfirmed).toBe(mockReport.executiveSummary.totalConfirmed);
    expect(Array.isArray(owasp.owaspTop10)).toBe(true);
    expect(owasp.owaspTop10.some((g: { owasp: string }) => g.owasp === "A03:2021")).toBe(true);
  });
});

describe("SOC 2 / ISO 27001 evidence exports (§13)", () => {
  it("SOC 2 bundle maps every finding to a control and carries remediation status", () => {
    const soc2 = JSON.parse(renderSoc2Evidence(mockReport));
    expect(soc2.framework).toBe("SOC 2");
    expect(soc2.findings).toHaveLength(confirmedCount);
    expect(soc2.controlCoverage.length).toBeGreaterThan(0);
    for (const f of soc2.findings) {
      expect(Array.isArray(f.controls)).toBe(true);
      expect(f.controls.length).toBeGreaterThan(0);
      expect(f.remediation).toBeDefined();
    }
  });

  it("ISO 27001 bundle maps findings to Annex A controls", () => {
    const iso = JSON.parse(renderIso27001Evidence(mockReport));
    expect(iso.framework).toBe("ISO/IEC 27001:2022");
    expect(iso.annexAControlCoverage.length).toBeGreaterThan(0);
    expect(
      iso.annexAControlCoverage.every((c: { control: string }) => c.control.startsWith("A.")),
    ).toBe(true);
  });

  it("⛔ compliance evidence is metadata-only — no patch bodies leak into it", () => {
    // The raw report DOES contain fixes (patches); the evidence exports must not.
    expect(renderJson(mockReport)).toContain('"patch"');
    expect(renderSoc2Evidence(mockReport)).not.toContain('"patch"');
    expect(renderIso27001Evidence(mockReport)).not.toContain('"patch"');
    expect(renderSarif(mockReport)).not.toContain('"patch"');
    expect(renderOwaspJson(mockReport)).not.toContain('"patch"');
    expect(renderCsv(mockReport)).not.toContain("@@");
  });
});

describe("raw exports", () => {
  it("CSV has a header plus one row per confirmed finding", () => {
    const lines = renderCsv(mockReport).trim().split("\n");
    expect(lines[0]).toContain("severity");
    expect(lines).toHaveLength(confirmedCount + 1);
  });

  it("JSON round-trips back into a valid Report", () => {
    const parsed = JSON.parse(renderJson(mockReport));
    expect(ReportSchema.safeParse(parsed).success).toBe(true);
  });
});

describe("export descriptors (compliance tab)", () => {
  it("offers all six formats in DECIDE-5 order (SARIF+OWASP, then SOC2, ISO, then raw)", () => {
    const formats = REPORT_EXPORTS.map((e) => e.format);
    expect(formats).toEqual([
      "sarif",
      "owasp-json",
      "soc2-evidence",
      "iso27001",
      "csv",
      "json",
    ] satisfies ReportExportFormat[]);
  });

  it("every descriptor builds a non-empty string and a sensible filename", () => {
    for (const descriptor of REPORT_EXPORTS) {
      const content = descriptor.build(mockReport);
      expect(content.length).toBeGreaterThan(0);
      const name = exportFilename(mockReport, descriptor);
      expect(name).toContain(mockReport.scanId);
      expect(name.endsWith(descriptor.extension)).toBe(true);
    }
  });

  it("uses the shared taxonomy so titles match @montr/contracts", () => {
    const soc2 = JSON.parse(renderSoc2Evidence(mockReport));
    const first = mockReport.confirmedFindings[0]!;
    const evidence = soc2.findings.find((f: { id: string }) => f.id === first.finding.id);
    expect(evidence.category).toBe(CATEGORY_TAXONOMY[first.finding.category].title);
  });
});
