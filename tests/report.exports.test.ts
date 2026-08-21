import { describe, it, expect, beforeAll } from "vitest";
import {
  SarifLogSchema,
  ReportSchema,
  ExportArtifactSchema,
  NotImplementedError,
  type Report,
} from "@montr/contracts";
import {
  buildReport,
  exportReport,
  generateExport,
  registerExporter,
  toSarif,
  renderReportHtml,
  renderReportJson,
  renderReportCsv,
  renderReportOwaspJson,
  renderReportPdf,
  escapeHtml,
  PdfBrowserUnavailableError,
  buildCycloneDxSbom,
  renderCycloneDxSbom,
  inventoryFromReport,
  CYCLONEDX_SPEC_VERSION,
  type DependencyInventoryInput,
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

describe("@montr/report SARIF export (§13, DECIDE-5)", () => {
  it("produces a schema-valid SARIF 2.1.0 log with one result per confirmed finding", () => {
    const sarif = toSarif(report);
    expect(SarifLogSchema.safeParse(sarif).success).toBe(true);
    expect(sarif.runs[0]!.results).toHaveLength(mockConfirmedFindings.length);
    expect(sarif.runs[0]!.tool.driver.name).toBe("Montr Secure");
  });

  it("maps severity to SARIF level (critical → error)", () => {
    const sarif = toSarif(report);
    const sqli = sarif.runs[0]!.results.find((r) => r.ruleId === "sql_injection");
    expect(sqli?.level).toBe("error");
  });

  it("exportReport returns a schema-valid ExportArtifact descriptor", async () => {
    const artifact = await exportReport(report, "sarif");
    expect(ExportArtifactSchema.safeParse(artifact).success).toBe(true);
    expect(artifact.format).toBe("sarif");
    expect(artifact.filename.endsWith(".sarif")).toBe(true);
    expect(artifact.contentType).toBe("application/sarif+json");
    expect(artifact.sizeBytes).toBeGreaterThan(0);
  });
});

describe("@montr/report machine-readable exports", () => {
  it("JSON export round-trips back into a valid Report", () => {
    const parsed = JSON.parse(renderReportJson(report));
    expect(ReportSchema.safeParse(parsed).success).toBe(true);
  });

  it("CSV export has a header plus one row per confirmed finding", () => {
    const csv = renderReportCsv(report);
    const lines = csv.trim().split("\n");
    expect(lines[0]).toContain("severity");
    expect(lines).toHaveLength(mockConfirmedFindings.length + 1);
  });

  it("OWASP-JSON groups confirmed findings by OWASP category", () => {
    const owasp = JSON.parse(renderReportOwaspJson(report));
    expect(owasp.tool).toBe("Montr Secure");
    expect(Array.isArray(owasp.owaspTop10)).toBe(true);
    expect(owasp.owaspTop10.some((g: { owasp: string }) => g.owasp === "A03:2021")).toBe(true);
  });

  it("generateExport returns descriptor + bytes for json", async () => {
    const out = await generateExport(report, "json", { now: FIXED_LATER });
    expect(out.artifact.generatedAt).toBe(FIXED_LATER);
    expect(typeof out.content).toBe("string");
    expect(out.artifact.sizeBytes).toBe(Buffer.byteLength(out.content as string, "utf8"));
  });
});

describe("@montr/report HTML export is XSS-safe (the report tool must be exemplary)", () => {
  it("escapes finding text so a malicious title cannot inject markup", async () => {
    const evil = {
      ...mockConfirmedFindings[0]!,
      id: "conf_evil_0001",
      title: "<script>alert('xss')</script>",
    };
    const out = await buildReport({
      scan: mockScan,
      confirmed: [evil],
      unconfirmed: [],
      fixes: [],
      costRollup: mockCostRollup,
      autoApply: false,
      generatedAt: FIXED_LATER,
    });
    const html = renderReportHtml(out.report);
    expect(html).not.toContain("<script>alert('xss')</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("escapeHtml neutralizes the five significant characters", () => {
    expect(escapeHtml(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#39;");
  });

  it("renders the confirmed headline and every report section", () => {
    const html = renderReportHtml(report);
    expect(html).toContain("Executive Summary");
    expect(html).toContain("Confirmed Findings");
    expect(html).toContain("Appendix");
    expect(html).toContain("Compliance Mapping");
    expect(html).toContain("2 confirmed");
  });
});

describe("@montr/report PDF export — lazy + graceful (§13)", () => {
  it("renders via an injected renderer without a real browser", async () => {
    const bytes = await renderReportPdf(report, {
      renderer: async (html) => new TextEncoder().encode(`%PDF-1.4 ${html.length}`),
    });
    expect(bytes).toBeInstanceOf(Uint8Array);
    const out = await generateExport(report, "pdf", {
      pdf: { renderer: async () => new Uint8Array([37, 80, 68, 70]) },
    });
    expect(out.artifact.format).toBe("pdf");
    expect(out.artifact.contentType).toBe("application/pdf");
    expect(out.content).toBeInstanceOf(Uint8Array);
  });

  it("degrades GRACEFULLY (typed error, no crash) when no browser is configured", async () => {
    const prev = process.env["PUPPETEER_EXECUTABLE_PATH"];
    delete process.env["PUPPETEER_EXECUTABLE_PATH"];
    try {
      await expect(renderReportPdf(report)).rejects.toBeInstanceOf(PdfBrowserUnavailableError);
    } finally {
      if (prev !== undefined) process.env["PUPPETEER_EXECUTABLE_PATH"] = prev;
    }
  });
});

describe("@montr/report export registry — Wave-3 extension point", () => {
  it("implements the SOC 2 + ISO 27001 evidence formats (Wave 3); unknown formats still error", async () => {
    // Wave 3 (WS-M): these compliance formats are now implemented and reachable
    // via the frozen generateExport API (replaces the Wave-2 not-yet-implemented
    // assertion). Deep evidence-package coverage lives in compliance.exports.test.ts.
    const soc2 = await generateExport(report, "soc2-evidence");
    expect(JSON.parse(soc2.content as string).framework).toBe("soc2");
    const iso = await generateExport(report, "iso27001");
    expect(JSON.parse(iso.content as string).framework).toBe("iso27001");
    // A format with no registered exporter still fails cleanly (dispatcher path).
    await expect(generateExport(report, "not-a-format" as never)).rejects.toBeInstanceOf(
      NotImplementedError,
    );
  });

  it("registerExporter slots a new format in without touching the dispatcher", async () => {
    registerExporter("soc2-evidence", async (r) => ({
      content: JSON.stringify({ soc2: true, scanId: r.scanId }),
      contentType: "application/json",
      ext: "soc2.json",
    }));
    const out = await generateExport(report, "soc2-evidence");
    expect(out.contentType).toBe("application/json");
    expect(out.artifact.filename.endsWith(".soc2.json")).toBe(true);
  });
});

describe("@montr/report CycloneDX SBOM export (E16)", () => {
  const inventory: DependencyInventoryInput = {
    components: [
      { name: "lodash", version: "4.17.11", ecosystem: "npm", reachable: true },
      { name: "left-pad", version: "1.3.0", ecosystem: "npm", reachable: false },
      { name: "@scope/pkg", version: "2.0.0", ecosystem: "npm" }, // reachability unknown
    ],
    vulnerabilities: [
      {
        id: "GHSA-jf85-cpcp-j695",
        source: "ghsa",
        packageName: "lodash",
        packageVersion: "4.17.11",
        severity: "high",
        cwe: ["CWE-1321"],
        summary: "Prototype pollution in lodash.",
        fixedVersion: "4.17.12",
        aliases: ["CVE-2019-10744"],
        reachable: true,
      },
    ],
  };

  it("produces a schema-shaped CycloneDX 1.5 document — bomFormat/specVersion/serialNumber", () => {
    const bom = buildCycloneDxSbom(inventory, { now: FIXED_LATER, serialNumber: "urn:uuid:test" });
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe(CYCLONEDX_SPEC_VERSION);
    expect(bom.serialNumber).toBe("urn:uuid:test");
    expect(bom.version).toBe(1);
    expect(bom.metadata.timestamp).toBe(FIXED_LATER);
    expect(bom.metadata.tools.components[0]?.name).toBe("Montr Secure");
  });

  it("lists EVERY component, not just the vulnerable ones", () => {
    const bom = buildCycloneDxSbom(inventory);
    expect(bom.components).toHaveLength(3);
    expect(bom.components.map((c) => c.name).sort()).toEqual(["@scope/pkg", "left-pad", "lodash"]);
  });

  it("builds a correct PURL per component, percent-encoding scoped package '@'", () => {
    const bom = buildCycloneDxSbom(inventory);
    const lodash = bom.components.find((c) => c.name === "lodash");
    expect(lodash?.purl).toBe("pkg:npm/lodash@4.17.11");
    expect(lodash?.["bom-ref"]).toBe("pkg:npm/lodash@4.17.11");
    const scoped = bom.components.find((c) => c.name === "@scope/pkg");
    expect(scoped?.purl).toBe("pkg:npm/%40scope/pkg@2.0.0");
  });

  it("annotates real call-site reachability (A12) as a component property, only when known", () => {
    const bom = buildCycloneDxSbom(inventory);
    const lodash = bom.components.find((c) => c.name === "lodash");
    expect(lodash?.properties).toContainEqual({ name: "montr:reachable", value: "true" });
    const leftPad = bom.components.find((c) => c.name === "left-pad");
    expect(leftPad?.properties).toContainEqual({ name: "montr:reachable", value: "false" });
    const scoped = bom.components.find((c) => c.name === "@scope/pkg");
    expect(scoped?.properties).toEqual([]); // unknown reachability -> no property, not a guess
  });

  it("maps matched advisories to vulnerabilities[], referencing the component's bom-ref via affects", () => {
    const bom = buildCycloneDxSbom(inventory);
    expect(bom.vulnerabilities).toHaveLength(1);
    const vuln = bom.vulnerabilities[0]!;
    expect(vuln.id).toBe("GHSA-jf85-cpcp-j695");
    expect(vuln.source).toEqual({ name: "GHSA" });
    expect(vuln.ratings).toEqual([{ severity: "high", method: "other" }]);
    expect(vuln.cwes).toEqual([1321]); // "CWE-1321" -> numeric 1321 per the CycloneDX spec
    expect(vuln.affects).toEqual([{ ref: "pkg:npm/lodash@4.17.11" }]);
    expect(vuln.recommendation).toContain("4.17.12");
  });

  it("renderCycloneDxSbom produces valid, parseable JSON matching the built document", () => {
    const json = renderCycloneDxSbom(inventory, {
      now: FIXED_LATER,
      serialNumber: "urn:uuid:test",
    });
    const parsed = JSON.parse(json);
    expect(parsed).toEqual(
      buildCycloneDxSbom(inventory, { now: FIXED_LATER, serialNumber: "urn:uuid:test" }),
    );
  });

  it("an empty inventory still produces a schema-shaped, valid (empty) SBOM — never throws", () => {
    const bom = buildCycloneDxSbom({ components: [] });
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.components).toEqual([]);
    expect(bom.vulnerabilities).toEqual([]);
  });

  it("inventoryFromReport derives a partial inventory from a Report's own confirmed vulnerable_dependency findings", async () => {
    const depFinding = {
      ...mockConfirmedFindings[0]!,
      id: "conf_dep_0001",
      title: "Vulnerable dependency: lodash@4.17.11 (GHSA-jf85-cpcp-j695)",
      category: "vulnerable_dependency" as const,
      cwe: ["CWE-1321" as const],
      severity: "high" as const,
      impact: "Prototype pollution allows denial of service or property injection.",
      proofType: "static" as const,
      proofArtifact: {
        kind: "static" as const,
        argument: "Reachable, matched OSV advisory.",
        dataFlow: [],
        sanitizersBypassed: [],
      },
    };
    const out = await buildReport({
      scan: mockScan,
      confirmed: [depFinding],
      unconfirmed: [],
      fixes: [],
      costRollup: mockCostRollup,
      autoApply: false,
      generatedAt: FIXED_LATER,
    });
    const derived = inventoryFromReport(out.report);
    expect(derived.components).toEqual([{ name: "lodash", version: "4.17.11", ecosystem: "npm" }]);
    expect(derived.vulnerabilities).toHaveLength(1);
    expect(derived.vulnerabilities[0]).toMatchObject({
      id: "GHSA-jf85-cpcp-j695",
      source: "ghsa",
      packageName: "lodash",
      packageVersion: "4.17.11",
      severity: "high",
    });
  });

  it("generateExport(report, 'cyclonedx') works through the registry, falling back to inventoryFromReport when no explicit inventory is supplied", async () => {
    const out = await generateExport(report, "cyclonedx", { now: FIXED_LATER });
    expect(out.contentType).toBe("application/vnd.cyclonedx+json");
    expect(out.artifact.filename.endsWith(".cdx.json")).toBe(true);
    const parsed = JSON.parse(out.content as string);
    expect(parsed.bomFormat).toBe("CycloneDX");
    // `report` (mockConfirmedFindings) has no vulnerable_dependency finding ->
    // the fallback derivation is legitimately empty, not a throw.
    expect(parsed.components).toEqual([]);
  });

  it("generateExport(report, 'cyclonedx') prefers an explicitly supplied dependencyInventory over the Report-derived fallback", async () => {
    const out = await generateExport(report, "cyclonedx", { dependencyInventory: inventory });
    const parsed = JSON.parse(out.content as string);
    expect(parsed.components).toHaveLength(3);
  });
});
