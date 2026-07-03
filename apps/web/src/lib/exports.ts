import {
  SarifLogSchema,
  CATEGORY_TAXONOMY,
  type ConfirmedFinding,
  type OwaspId,
  type Report,
  type ReportFinding,
  type SarifLog,
  type SarifResult,
  type Severity,
} from "@montr/contracts";

/**
 * Client-side report exporters (§12.5 compliance tab, §13, DECIDE-5 order).
 *
 * These run entirely in the browser from the already-loaded `Report`, so the
 * compliance tab produces genuinely downloadable evidence with no round-trip and
 * no server dependency (important while the console is mock-first). `@montr/report`
 * is the server-side authority for the same formats, but it is deliberately NOT
 * imported here: its barrel pulls in Prisma (@montr/state-store), pino
 * (@montr/telemetry), Octokit, gitbeaker and puppeteer-core — none of which may
 * enter the browser bundle. SARIF is validated against the SAME frozen
 * {@link SarifLogSchema} contract that `@montr/report` validates against, so the
 * two producers stay byte-compatible (golden rule #10 — one source of truth).
 *
 * ⛔ Metadata only: exports carry finding locations, categories and remediation
 * STATUS — never code bodies or secrets (golden rule #1, §11).
 */

/* --------------------------------- SARIF 2.1.0 -------------------------------- */

const SARIF_TOOL_NAME = "Montr Secure";
const SARIF_INFO_URI = "https://montr.security/secure";

/** SARIF severity levels, per confirmed-finding severity (mirrors @montr/report). */
const SARIF_LEVEL: Record<Severity, SarifResult["level"]> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

function toSarifResult(finding: ConfirmedFinding): SarifResult {
  const line = finding.location.line;
  return {
    ruleId: finding.category,
    level: SARIF_LEVEL[finding.severity],
    message: { text: `${finding.title} — ${finding.impact}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.location.file },
          // Contract requires a positive startLine; omit the region for line 0.
          ...(line > 0 ? { region: { startLine: line } } : {}),
        },
      },
    ],
  };
}

/** Build a validated SARIF log from a report (one run, one Montr driver). */
export function buildSarif(report: Report): SarifLog {
  const confirmed = report.confirmedFindings.map((rf) => rf.finding);
  const ruleIds = [...new Set(confirmed.map((f) => f.category))];
  return SarifLogSchema.parse({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: SARIF_TOOL_NAME,
            informationUri: SARIF_INFO_URI,
            rules: ruleIds.map((id) => ({ id })),
          },
        },
        results: confirmed.map(toSarifResult),
      },
    ],
  });
}

export function renderSarif(report: Report): string {
  return JSON.stringify(buildSarif(report), null, 2);
}

/* ---------------------------------- OWASP JSON -------------------------------- */

/** Generic OWASP-Top-10 JSON (confirmed findings grouped by category). */
export function renderOwaspJson(report: Report): string {
  const groups = new Map<string, { owasp: string; title: string; findings: unknown[] }>();
  for (const rf of report.confirmedFindings) {
    const key = rf.compliance.owasp;
    let group = groups.get(key);
    if (!group) {
      group = { owasp: key, title: rf.compliance.owaspTitle, findings: [] };
      groups.set(key, group);
    }
    group.findings.push({
      id: rf.finding.id,
      title: rf.finding.title,
      severity: rf.finding.severity,
      cwe: rf.finding.cwe,
      location: rf.finding.location,
      exposure: rf.finding.exposure,
    });
  }
  return JSON.stringify(
    {
      tool: SARIF_TOOL_NAME,
      scanId: report.scanId,
      generatedAt: report.generatedAt,
      totalConfirmed: report.executiveSummary.totalConfirmed,
      owaspTop10: [...groups.values()],
    },
    null,
    2,
  );
}

/* ------------------------------ compliance evidence --------------------------- */

/**
 * Illustrative OWASP → SOC 2 Common Criteria references. The evidence bundle
 * cites which control each confirmed finding is evidence for, so it drops into a
 * SOC 2 evidence request (§13).
 */
const OWASP_TO_SOC2: Record<OwaspId, string[]> = {
  "A01:2021": ["CC6.1", "CC6.3"],
  "A02:2021": ["CC6.1", "CC6.7"],
  "A03:2021": ["CC7.1", "CC8.1"],
  "A04:2021": ["CC8.1"],
  "A05:2021": ["CC6.1", "CC7.1"],
  "A06:2021": ["CC7.1"],
  "A07:2021": ["CC6.1"],
  "A08:2021": ["CC7.1", "CC8.1"],
  "A09:2021": ["CC7.2", "CC7.3"],
  "A10:2021": ["CC6.6", "CC7.1"],
};

/** Illustrative OWASP → ISO/IEC 27001:2022 Annex A control references. */
const OWASP_TO_ISO27001: Record<OwaspId, string[]> = {
  "A01:2021": ["A.5.15", "A.8.3"],
  "A02:2021": ["A.8.24"],
  "A03:2021": ["A.8.28"],
  "A04:2021": ["A.8.25", "A.8.27"],
  "A05:2021": ["A.8.9"],
  "A06:2021": ["A.8.8"],
  "A07:2021": ["A.8.5"],
  "A08:2021": ["A.8.28", "A.5.23"],
  "A09:2021": ["A.8.15", "A.8.16"],
  "A10:2021": ["A.8.22", "A.8.28"],
};

function remediationFor(rf: ReportFinding): {
  status: string;
  riskClass?: string;
  autoEligible?: boolean;
  proofOfFixTest?: boolean;
} {
  if (!rf.fix) return { status: "no-fix-proposed" };
  return {
    status: rf.fix.status,
    riskClass: rf.fix.riskClass,
    autoEligible: rf.fix.riskClass === "auto-eligible",
    proofOfFixTest: rf.fix.proofOfFixTest.failsPrePatch && rf.fix.proofOfFixTest.passesPostPatch,
  };
}

function evidenceFinding(rf: ReportFinding, controls: Record<OwaspId, string[]>) {
  const f = rf.finding;
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    category: CATEGORY_TAXONOMY[f.category].title,
    cwe: f.cwe.length > 0 ? f.cwe : rf.compliance.cwe,
    owasp: rf.compliance.owasp,
    owaspTitle: rf.compliance.owaspTitle,
    controls: controls[rf.compliance.owasp],
    location: `${f.location.file}:${f.location.line}`,
    exposure: f.exposure,
    proofType: f.proofType,
    remediation: remediationFor(rf),
  };
}

/** Roll confirmed findings up by their mapped controls, for the control matrix. */
function controlCoverage(report: Report, controls: Record<OwaspId, string[]>) {
  const byControl = new Map<string, string[]>();
  for (const rf of report.confirmedFindings) {
    for (const control of controls[rf.compliance.owasp] ?? []) {
      const list = byControl.get(control) ?? [];
      list.push(rf.finding.id);
      byControl.set(control, list);
    }
  }
  return [...byControl.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([control, findingIds]) => ({ control, findingIds }));
}

/** SOC 2 evidence bundle (§13). Drops into a SOC 2 Type II evidence request. */
export function renderSoc2Evidence(report: Report): string {
  return JSON.stringify(
    {
      framework: "SOC 2",
      tool: SARIF_TOOL_NAME,
      scanId: report.scanId,
      clientId: report.clientId,
      generatedAt: report.generatedAt,
      summary: {
        totalConfirmed: report.executiveSummary.totalConfirmed,
        confirmedBySeverity: report.executiveSummary.confirmedBySeverity,
        toolsConsolidated: report.executiveSummary.toolsConsolidated,
      },
      controlCoverage: controlCoverage(report, OWASP_TO_SOC2),
      findings: report.confirmedFindings.map((rf) => evidenceFinding(rf, OWASP_TO_SOC2)),
      scope: report.costAndScope.scope,
      note: "Evidence is metadata only (locations, categories, remediation status); no source code bodies are included.",
    },
    null,
    2,
  );
}

/** ISO/IEC 27001:2022 evidence bundle (§13). Maps findings to Annex A controls. */
export function renderIso27001Evidence(report: Report): string {
  return JSON.stringify(
    {
      framework: "ISO/IEC 27001:2022",
      tool: SARIF_TOOL_NAME,
      scanId: report.scanId,
      clientId: report.clientId,
      generatedAt: report.generatedAt,
      summary: {
        totalConfirmed: report.executiveSummary.totalConfirmed,
        confirmedBySeverity: report.executiveSummary.confirmedBySeverity,
      },
      annexAControlCoverage: controlCoverage(report, OWASP_TO_ISO27001),
      findings: report.confirmedFindings.map((rf) => evidenceFinding(rf, OWASP_TO_ISO27001)),
      scope: report.costAndScope.scope,
      note: "Evidence is metadata only; processing is on-prem, satisfying data-residency by construction (§13).",
    },
    null,
    2,
  );
}

/* ------------------------------- raw / tabular -------------------------------- */

function csvField(value: unknown): string {
  return `"${String(value).replace(/"/g, '""')}"`;
}

/** Confirmed findings as CSV (one row per finding). */
export function renderCsv(report: Report): string {
  const header = [
    "id",
    "title",
    "severity",
    "category",
    "cwe",
    "owasp",
    "file",
    "line",
    "exposure",
    "proofType",
  ];
  const rows = report.confirmedFindings.map((rf) => {
    const f = rf.finding;
    return [
      f.id,
      f.title,
      f.severity,
      f.category,
      f.cwe.join(" "),
      rf.compliance.owasp,
      f.location.file,
      f.location.line,
      f.exposure,
      f.proofType,
    ]
      .map(csvField)
      .join(",");
  });
  return [header.map(csvField).join(","), ...rows].join("\n");
}

/** Machine-readable JSON — the full report as loaded. */
export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/* -------------------------------- descriptors -------------------------------- */

export type ReportExportFormat =
  "sarif" | "owasp-json" | "soc2-evidence" | "iso27001" | "csv" | "json";

export type ReportExportGroup = "scanner" | "compliance" | "raw";

export interface ReportExportDescriptor {
  format: ReportExportFormat;
  label: string;
  group: ReportExportGroup;
  description: string;
  extension: string;
  contentType: string;
  build: (report: Report) => string;
}

/**
 * The exports offered in the compliance tab, in DECIDE-5 order: SARIF + generic
 * OWASP first (broadest), then SOC 2 evidence, then ISO 27001, then raw formats.
 */
export const REPORT_EXPORTS: readonly ReportExportDescriptor[] = [
  {
    format: "sarif",
    label: "SARIF 2.1.0",
    group: "scanner",
    description: "Static Analysis Results Interchange Format — drops into any code-scanning UI.",
    extension: "sarif",
    contentType: "application/sarif+json",
    build: renderSarif,
  },
  {
    format: "owasp-json",
    label: "OWASP Top 10 (JSON)",
    group: "scanner",
    description: "Confirmed findings grouped by OWASP Top 10 (2021) category.",
    extension: "owasp.json",
    contentType: "application/json",
    build: renderOwaspJson,
  },
  {
    format: "soc2-evidence",
    label: "SOC 2 evidence",
    group: "compliance",
    description: "Control-mapped evidence bundle for a SOC 2 Type II request.",
    extension: "soc2.json",
    contentType: "application/json",
    build: renderSoc2Evidence,
  },
  {
    format: "iso27001",
    label: "ISO 27001 evidence",
    group: "compliance",
    description: "Findings mapped to ISO/IEC 27001:2022 Annex A controls.",
    extension: "iso27001.json",
    contentType: "application/json",
    build: renderIso27001Evidence,
  },
  {
    format: "csv",
    label: "CSV",
    group: "raw",
    description: "Confirmed findings as a spreadsheet (one row per finding).",
    extension: "csv",
    contentType: "text/csv;charset=utf-8",
    build: renderCsv,
  },
  {
    format: "json",
    label: "JSON",
    group: "raw",
    description: "The full machine-readable report model.",
    extension: "json",
    contentType: "application/json",
    build: renderJson,
  },
];

export function exportFilename(report: Report, descriptor: ReportExportDescriptor): string {
  return `montr-secure-${report.scanId}.${descriptor.extension}`;
}

/**
 * Build and download an export in the browser. Pure string generation happens in
 * the `build` functions above (unit-tested); this only wraps the Blob download,
 * so it must run in a browser (guarded by a `typeof document` check).
 */
export function downloadReportExport(report: Report, descriptor: ReportExportDescriptor): void {
  if (typeof document === "undefined") return;
  const content = descriptor.build(report);
  const blob = new Blob([content], { type: descriptor.contentType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = exportFilename(report, descriptor);
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
