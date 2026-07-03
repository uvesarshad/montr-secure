/**
 * Wave 3 (WS-M) — compliance mapping, evidence exports, posture delta, and the
 * audit-trail surfacing. Everything is exercised OFFLINE against @montr/fixtures'
 * confirmed findings plus a SYNTHETIC prior scan / fake state-store + audit log.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  CategorySchema,
  ConfirmedFindingSchema,
  ScanSchema,
  SarifLogSchema,
  OwaspIdSchema,
  complianceForCategory,
  type Category,
  type ConfirmedFinding,
  type Report,
  type Scan,
} from "@montr/contracts";
import {
  buildReport,
  generateExport,
  generateEvidencePackage,
  toSarif,
  renderReportSarif,
  SARIF_FINGERPRINT_KEY,
  renderReportOwaspJson,
  renderOwaspHtml,
  renderOwaspPdf,
  buildOwaspCoverage,
  OWASP_TOP_10,
  buildEvidencePackage,
  renderEvidenceCsv,
  remediationStateFor,
  controlsForCategory,
  controlCatalog,
  referencedControlIds,
  FRAMEWORK_LABEL,
  loadPreviousScanContext,
  computePostureDeltaDetail,
  exportAuditTrail,
  buildAuditTrailLink,
  exportAuditLog,
  renderHeadline,
  type ScanHistorySource,
  type AuditTrailAccess,
} from "@montr/report";
import {
  mockScan,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockFixes,
  mockCostRollup,
  CLIENT_ID,
  REPO_URL,
  BRANCH,
  OPERATOR_ID,
  FIXED_NOW,
  FIXED_LATER,
} from "@montr/fixtures";

/* ------------------------------- Test doubles ------------------------------ */

// A synthetic PRIOR scan: SQLi present but only "high" (current is "critical" →
// regressed), a CORS finding that is now gone (→ fixed), and NO XSS (current XSS
// → new). Matched across scans by fingerprint (category|file|symbol??line).
const prevScan: Scan = ScanSchema.parse({
  id: "scan_prev_0001",
  clientId: CLIENT_ID,
  repo: REPO_URL,
  branch: BRANCH,
  mode: "full",
  scope: { mode: "full" },
  status: "completed",
  operator: OPERATOR_ID,
  createdAt: "2026-01-14T09:00:00.000Z",
});

const prevSqliHigh: ConfirmedFinding = ConfirmedFindingSchema.parse({
  id: "conf_prev_sqli_0001",
  scanId: prevScan.id,
  clientId: CLIENT_ID,
  title: "SQL Injection in GET /api/users (q parameter)",
  category: "sql_injection",
  cwe: ["CWE-89"],
  severity: "high", // ← current is "critical": this is a REGRESSION
  exposure: "public",
  location: { file: "app/api/users/route.ts", line: 9 },
  impact: "Read of the User table.",
  proofType: "static",
  proofArtifact: { kind: "static", argument: "tainted q reaches raw query", dataFlow: [] },
  createdAt: "2026-01-14T09:00:00.000Z",
});

const prevCorsFixed: ConfirmedFinding = ConfirmedFindingSchema.parse({
  id: "conf_prev_cors_0001",
  scanId: prevScan.id,
  clientId: CLIENT_ID,
  title: "Permissive CORS on /api/users",
  category: "permissive_cors",
  cwe: ["CWE-942"],
  severity: "medium",
  exposure: "public",
  location: { file: "app/api/users/route.ts", line: 12 },
  impact: "Wildcard CORS.",
  proofType: "static",
  proofArtifact: { kind: "static", argument: "wildcard origin", dataFlow: [] },
  createdAt: "2026-01-14T09:00:00.000Z",
});

const previousConfirmed = [prevSqliHigh, prevCorsFixed];

const historyStore: ScanHistorySource = {
  scans: { list: async () => [mockScan, prevScan] }, // newest-first
  confirmed: {
    listByScan: async (_clientId: string, scanId: string) =>
      scanId === prevScan.id ? previousConfirmed : mockConfirmedFindings,
  },
};

// A fake tamper-evident audit log (satisfies the AuditTrailAccess surface).
const fakeAuditContent = JSON.stringify({
  clientId: CLIENT_ID,
  count: 2,
  chainVerified: true,
  events: [
    { sequence: 1, action: "scan.created" },
    { sequence: 2, action: "export.generated" },
  ],
});
const fakeAudit: AuditTrailAccess = {
  exportJson: async () => fakeAuditContent,
  exportCsv: async () => "sequence,action\n1,scan.created\n2,export.generated",
  verifyChain: async () => true,
};

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

/* ------------------------------ Control catalog ---------------------------- */

describe("compliance control catalog (SOC 2 CC-series / ISO 27001 Annex A)", () => {
  it("maps EVERY finding category to >=1 control for both frameworks", () => {
    for (const category of CategorySchema.options as Category[]) {
      expect(controlsForCategory("soc2", category).length).toBeGreaterThan(0);
      expect(controlsForCategory("iso27001", category).length).toBeGreaterThan(0);
    }
  });

  it("every referenced control id exists in the framework catalog (no dangling ids)", () => {
    for (const framework of ["soc2", "iso27001"] as const) {
      const catalogIds = new Set(controlCatalog(framework).map((c) => c.id));
      for (const id of referencedControlIds(framework)) {
        expect(catalogIds.has(id)).toBe(true);
      }
    }
  });

  it("uses the expected control families (CC-series for SOC 2, A.<n> for ISO)", () => {
    expect(controlsForCategory("soc2", "sql_injection").map((c) => c.id)).toContain("CC6.1");
    expect(controlsForCategory("iso27001", "sql_injection").map((c) => c.id)).toContain("A.8.28");
    expect(controlsForCategory("iso27001", "weak_crypto").map((c) => c.id)).toContain("A.8.24");
    expect(FRAMEWORK_LABEL.soc2).toContain("SOC 2");
  });
});

/* --------------------------------- SARIF ----------------------------------- */

describe("SARIF 2.1.0 export is valid + carries rule/CWE/OWASP metadata + fingerprints", () => {
  it("remains schema-valid 2.1.0 with one result per confirmed finding", () => {
    const sarif = toSarif(report);
    expect(SarifLogSchema.safeParse(sarif).success).toBe(true);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]!.results).toHaveLength(mockConfirmedFindings.length);
  });

  it("emits a reporting descriptor per category with CWE + OWASP tags and security-severity", () => {
    const sarif = toSarif(report);
    const rules = sarif.runs[0]!.tool.driver.rules;
    expect(rules).toHaveLength(2); // sql_injection, xss
    const sqliRule = rules.find((r) => r.id === "sql_injection")!;
    expect(sqliRule.name).toBe("SQL Injection");
    expect(sqliRule.properties.tags).toContain("external/cwe/cwe-89");
    expect(sqliRule.properties.tags).toContain("OWASP-A03:2021");
    expect(sqliRule.properties["security-severity"]).toBe("9.5"); // critical
    expect(sqliRule.helpUri).toContain("cwe.mitre.org/data/definitions/89");
  });

  it("each result has a ruleIndex, stable partial fingerprint, and CWE/OWASP properties", () => {
    const sarif = toSarif(report);
    const [r0, r1] = sarif.runs[0]!.results;
    for (const r of [r0!, r1!]) {
      expect(typeof r.ruleIndex).toBe("number");
      const fp = r.partialFingerprints[SARIF_FINGERPRINT_KEY]!;
      expect(fp).toMatch(/^[0-9a-f]{64}$/); // sha256 hex
      expect(r.properties.owasp).toMatch(/^A\d{2}:2021$/);
    }
    // Distinct findings → distinct fingerprints.
    expect(r0!.partialFingerprints[SARIF_FINGERPRINT_KEY]).not.toBe(
      r1!.partialFingerprints[SARIF_FINGERPRINT_KEY],
    );
  });

  it("serializes the rich metadata (survives JSON round-trip)", () => {
    const parsed = JSON.parse(renderReportSarif(report));
    expect(parsed.runs[0].results[0].partialFingerprints[SARIF_FINGERPRINT_KEY]).toBeDefined();
    expect(parsed.runs[0].tool.driver.rules[0].properties.cwe).toBeDefined();
  });
});

/* ---------------------------- Generic OWASP report ------------------------- */

describe("generic OWASP Top 10 (2021) report — full coverage + CWE per finding", () => {
  it("JSON lists ALL ten categories in coverage and maps every finding to CWE", () => {
    const owasp = JSON.parse(renderReportOwaspJson(report));
    expect(owasp.tool).toBe("Montr Secure");
    expect(owasp.standard).toBe("OWASP Top 10 (2021)");
    expect(owasp.coverage).toHaveLength(10);
    expect(new Set(owasp.coverage.map((c: { owasp: string }) => c.owasp)).size).toBe(10);
    const a03 = owasp.owaspTop10.find((g: { owasp: string }) => g.owasp === "A03:2021");
    expect(a03.count).toBe(2); // sqli + xss both A03 (Injection)
    for (const f of a03.findings) expect(f.cwe.length).toBeGreaterThan(0);
    expect(owasp.totalConfirmed).toBe(2);
  });

  it("buildOwaspCoverage returns all ten OWASP categories (present flag set correctly)", () => {
    const cov = buildOwaspCoverage(report);
    expect(cov).toHaveLength(OWASP_TOP_10.length);
    expect(cov.filter((g) => g.present).map((g) => g.owasp)).toEqual(["A03:2021"]);
  });

  it("renders human-readable HTML (XSS-safe) and PDF via the puppeteer seam", async () => {
    const html = renderOwaspHtml(report);
    expect(html).toContain("OWASP Top 10 (2021)");
    expect(html).toContain("A03:2021");
    const evilReport = { ...report, scanId: "<script>alert(1)</script>" } as Report;
    expect(renderOwaspHtml(evilReport)).not.toContain("<script>alert(1)</script>");

    const pdf = await renderOwaspPdf(report, {
      renderer: async (h) => new TextEncoder().encode(`%PDF ${h.length}`),
    });
    expect(pdf).toBeInstanceOf(Uint8Array);
  });
});

/* -------------------------- SOC 2 / ISO 27001 evidence --------------------- */

describe("SOC 2 evidence package (JSON + CSV) drops into evidence collection", () => {
  it("maps each confirmed finding to CC controls with status + remediation + timestamps + scope", async () => {
    const pkg = await buildEvidencePackage(report, "soc2", { auditLog: fakeAudit });
    expect(pkg.framework).toBe("soc2");
    expect(pkg.frameworkLabel).toContain("SOC 2");
    expect(pkg.evidence).toHaveLength(mockConfirmedFindings.length);

    const sqli = pkg.evidence.find((e) => e.category === "sql_injection")!;
    expect(sqli.status).toBe("confirmed");
    expect(sqli.controls.map((c) => c.id)).toContain("CC6.1");
    expect(sqli.owasp).toBe("A03:2021");
    expect(sqli.cwe).toContain("CWE-89");
    expect(sqli.remediationState).toBe("planned"); // proposed auto-eligible fix
    expect(sqli.detectedAt).toBe(FIXED_NOW);
    expect(sqli.fixId).toBeDefined();

    // Scan scope is carried for auditors.
    expect(pkg.scanScope.mode).toBe("full");
    expect(pkg.scanScope.fileCount).toBe(6);
    // Control coverage summary is populated.
    expect(pkg.summary.controlsCovered).toBe(pkg.controlCoverage.length);
    expect(pkg.controlCoverage.some((c) => c.control.id === "CC6.1")).toBe(true);
  });

  it("embeds a verified link to the tamper-evident audit trail", async () => {
    const pkg = await buildEvidencePackage(report, "soc2", { auditLog: fakeAudit });
    expect(pkg.auditTrail.available).toBe(true);
    expect(pkg.auditTrail.chainVerified).toBe(true);
    expect(pkg.auditTrail.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(pkg.auditTrail.filename).toBe(`audit-${CLIENT_ID}.json`);
  });

  it("is fail-safe without an audit accessor (link marked unavailable, still valid)", async () => {
    const pkg = await buildEvidencePackage(report, "soc2");
    expect(pkg.auditTrail.available).toBe(false);
    expect(pkg.auditTrail.note).toBeDefined();
  });

  it("CSV has a header + one row per finding, controls joined, and audit reference", async () => {
    const csv = await renderEvidenceCsv(report, "soc2", { auditLog: fakeAudit });
    const lines = csv.trim().split("\n");
    expect(lines[0]).toContain("controls");
    expect(lines[0]).toContain("remediationState");
    expect(lines).toHaveLength(mockConfirmedFindings.length + 1);
    expect(csv).toContain("CC6.1");
    expect(csv).toContain(`audit-${CLIENT_ID}.json`);
  });

  it("derives remediation state from the fix lifecycle (auditable)", () => {
    expect(remediationStateFor(undefined)).toBe("open");
    const base = mockFixes[0]!;
    expect(remediationStateFor({ ...base, status: "merged" })).toBe("remediated");
    expect(remediationStateFor({ ...base, status: "pr-open" })).toBe("in_progress");
    expect(remediationStateFor({ ...base, status: "proposed", riskClass: "auto-eligible" })).toBe(
      "planned",
    );
    expect(remediationStateFor({ ...base, status: "proposed", riskClass: "human-required" })).toBe(
      "recommended",
    );
  });
});

describe("ISO 27001 evidence package (Annex A control mapping)", () => {
  it("maps findings to Annex A controls in the same evidence shape", async () => {
    const pkg = await buildEvidencePackage(report, "iso27001", { auditLog: fakeAudit });
    expect(pkg.framework).toBe("iso27001");
    expect(pkg.frameworkLabel).toContain("27001");
    const sqli = pkg.evidence.find((e) => e.category === "sql_injection")!;
    expect(sqli.controls.map((c) => c.id)).toContain("A.8.28"); // Secure coding
    expect(sqli.controls.every((c) => c.id.startsWith("A."))).toBe(true);
  });
});

describe("evidence exports reachable via the frozen generateExport / package API", () => {
  it("generateExport returns evidence JSON for soc2-evidence and iso27001", async () => {
    const soc2 = await generateExport(report, "soc2-evidence", { now: FIXED_LATER });
    expect(soc2.artifact.format).toBe("soc2-evidence");
    expect(soc2.artifact.filename.endsWith(".soc2-evidence.json")).toBe(true);
    expect(JSON.parse(soc2.content as string).framework).toBe("soc2");

    const iso = await generateExport(report, "iso27001", { now: FIXED_LATER });
    expect(iso.artifact.filename.endsWith(".iso27001-evidence.json")).toBe(true);
  });

  it("generateEvidencePackage returns BOTH json + csv artifacts and audits (metadata only)", async () => {
    const events: string[] = [];
    const audit = {
      append: async (e: { action: string; metadata?: Record<string, unknown> }) => {
        events.push(e.action);
        // ⛔ metadata is filenames/sizes only — never a code/secret body.
        expect(JSON.stringify(e.metadata ?? {})).not.toContain("SELECT");
        return {} as never;
      },
      list: async () => [],
      verifyChain: async () => true,
    };
    const { json, csv } = await generateEvidencePackage(report, "soc2", {
      now: FIXED_LATER,
      auditLog: fakeAudit,
      audit: audit as never,
    });
    expect(json.artifact.filename.endsWith(".soc2-evidence.json")).toBe(true);
    expect(csv.artifact.filename.endsWith(".soc2-evidence.csv")).toBe(true);
    expect(csv.contentType).toBe("text/csv");
    expect(events).toEqual(["export.generated", "export.generated"]);
  });
});

/* --------------------------- Posture delta / history ----------------------- */

describe("posture delta vs last scan (reads scan history; never a raw-count headline)", () => {
  it("loadPreviousScanContext reads the prior completed scan's confirmed findings", async () => {
    const prev = await loadPreviousScanContext(historyStore, CLIENT_ID, mockScan.id);
    expect(prev).toBeDefined();
    expect(prev!.scanId).toBe(prevScan.id);
    expect(prev!.confirmed).toHaveLength(2);
  });

  it("returns undefined when there is no prior scan (first scan → no delta)", async () => {
    const onlyCurrent: ScanHistorySource = {
      scans: { list: async () => [mockScan] },
      confirmed: { listByScan: async () => [] },
    };
    expect(await loadPreviousScanContext(onlyCurrent, CLIENT_ID, mockScan.id)).toBeUndefined();
  });

  it("classifies new / fixed / regressed findings across scans (by fingerprint)", async () => {
    const prev = await loadPreviousScanContext(historyStore, CLIENT_ID, mockScan.id);
    const detail = computePostureDeltaDetail(mockConfirmedFindings, prev);
    expect(detail.isFirstScan).toBe(false);
    expect(detail.new.map((r) => r.findingId)).toEqual(["conf_xss_0001"]);
    expect(detail.fixed.map((r) => r.findingId)).toEqual(["conf_prev_cors_0001"]);
    // SQLi present in both but severity high→critical ⇒ regressed (not unchanged).
    expect(detail.regressed.map((r) => r.findingId)).toEqual(["conf_sqli_0001"]);
    expect(detail.regressed[0]!.previousSeverity).toBe("high");
    expect(detail.unchanged).toHaveLength(0);
    // Frozen summary numbers agree with the exec-summary computation.
    expect(detail.summary).toMatchObject({ newIssues: 1, resolvedIssues: 1, netDelta: 0 });
  });

  it("first-scan detail marks every current finding as new with a zeroed summary", () => {
    const detail = computePostureDeltaDetail(mockConfirmedFindings, undefined);
    expect(detail.isFirstScan).toBe(true);
    expect(detail.new).toHaveLength(mockConfirmedFindings.length);
    expect(detail.summary).toMatchObject({ newIssues: 0, resolvedIssues: 0, netDelta: 0 });
  });

  it("surfaces the posture delta in the exec summary WITHOUT leaking a raw count", async () => {
    const prev = await loadPreviousScanContext(historyStore, CLIENT_ID, mockScan.id);
    const out = await buildReport({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      unconfirmed: mockUnconfirmedFindings,
      fixes: mockFixes,
      costRollup: mockCostRollup,
      autoApply: false,
      generatedAt: FIXED_LATER,
      previous: prev!,
      // Candidate pile present — must NOT influence the headline (breadth stays in appendix).
      candidates: [],
    });
    expect(out.report.executiveSummary.postureDelta).toMatchObject({
      previousScanId: prevScan.id,
      newIssues: 1,
      resolvedIssues: 1,
      netDelta: 0,
    });
    const headline = renderHeadline(out.report);
    expect(headline).toContain("2 confirmed"); // confirmed-only headline
    expect(headline).toContain("1 new, 1 resolved");
  });
});

/* ------------------------- Audit-trail surfacing --------------------------- */

describe("third-party-auditor audit-trail export surfaced through the report layer", () => {
  it("exportAuditTrail returns content + integrity metadata (chain verified + sha256)", async () => {
    const out = await exportAuditTrail(fakeAudit, CLIENT_ID, "json");
    expect(out.content).toBe(fakeAuditContent);
    expect(out.chainVerified).toBe(true);
    expect(out.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(out.filename).toBe(`audit-${CLIENT_ID}.json`);
    const csv = await exportAuditTrail(fakeAudit, CLIENT_ID, "csv");
    expect(csv.contentType).toBe("text/csv");
  });

  it("buildAuditTrailLink flags a broken chain (fail-safe warning)", async () => {
    const tampered: AuditTrailAccess = { ...fakeAudit, verifyChain: async () => false };
    const link = await buildAuditTrailLink(CLIENT_ID, tampered);
    expect(link.chainVerified).toBe(false);
    expect(link.note).toContain("WARNING");
  });

  it("re-exports the raw @montr/state-store audit export helper", () => {
    expect(typeof exportAuditLog).toBe("function");
  });
});

/* ------------------------- Complementary framework map --------------------- */

describe("every OWASP category is a valid frozen code + taxonomy is internally consistent", () => {
  it("buildOwaspCoverage codes are all valid OwaspId enum members", () => {
    for (const g of buildOwaspCoverage(report)) {
      expect(OwaspIdSchema.safeParse(g.owasp).success).toBe(true);
      // Coverage title matches the taxonomy title for a representative finding.
      if (g.present) {
        const anyCat = report.confirmedFindings.find(
          (rf) => complianceForCategory(rf.finding.category).owasp === g.owasp,
        )!;
        expect(complianceForCategory(anyCat.finding.category).owaspTitle).toBe(g.owaspTitle);
      }
    }
  });
});
