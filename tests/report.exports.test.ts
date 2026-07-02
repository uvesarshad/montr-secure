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
  it("throws NotImplementedError for compliance formats not yet registered", async () => {
    await expect(generateExport(report, "soc2-evidence")).rejects.toBeInstanceOf(
      NotImplementedError,
    );
    await expect(generateExport(report, "iso27001")).rejects.toBeInstanceOf(NotImplementedError);
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
