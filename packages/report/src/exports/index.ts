/**
 * Report EXPORTS (§13, DECIDE-5 order). Ships now: SARIF, machine-readable JSON,
 * HTML, PDF, plus a generic OWASP-JSON and CSV. SOC 2 / ISO 27001 evidence
 * packaging lands in Wave 3 (WS-M) — this dispatcher is a REGISTRY so those slot
 * in via {@link registerExporter} with zero changes here (clean extension point).
 *
 * `exportReport` keeps the frozen Wave-0 signature (returns an {@link ExportArtifact}
 * descriptor). `generateExport` is the richer primitive that also returns the
 * bytes the caller persists (and can then set `uri` on).
 */
import {
  NotImplementedError,
  ReportSchema,
  type ExportArtifact,
  type ExportFormat,
  type Report,
} from "@montr/contracts";
import type { AuditLogClient } from "@montr/telemetry";
import { renderReportSarif } from "./sarif.js";
import { renderReportHtml } from "./html.js";
import { renderReportPdf, type PdfOptions } from "./pdf.js";

/** A produced export: the descriptor plus the actual bytes/string. */
export interface ReportExport {
  artifact: ExportArtifact;
  content: string | Uint8Array;
  contentType: string;
}

export interface GenerateExportOptions {
  /** Deterministic generation time (tests). Defaults to now. */
  now?: string;
  /** PDF engine options (executable path / injected renderer). */
  pdf?: PdfOptions;
  /** Audit sink — records `export.generated` (metadata only). */
  audit?: AuditLogClient;
}

interface ExporterResult {
  content: string | Uint8Array;
  contentType: string;
  ext: string;
}

type Exporter = (report: Report, opts: GenerateExportOptions) => Promise<ExporterResult>;

/** Machine-readable JSON — the report validated against its frozen schema. */
export function renderReportJson(report: Report): string {
  return JSON.stringify(ReportSchema.parse(report), null, 2);
}

function csvField(value: unknown): string {
  return `"${String(value).replace(/"/g, '""')}"`;
}

/** Confirmed findings as CSV (one row per finding). */
export function renderReportCsv(report: Report): string {
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

/** Generic OWASP-oriented JSON (findings grouped by OWASP Top 10 category). */
export function renderReportOwaspJson(report: Report): string {
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
      tool: "Montr Secure",
      scanId: report.scanId,
      generatedAt: report.generatedAt,
      totalConfirmed: report.executiveSummary.totalConfirmed,
      owaspTop10: [...groups.values()],
    },
    null,
    2,
  );
}

/**
 * Format registry (the extension point). Wave 3 registers "soc2-evidence" and
 * "iso27001" here without touching the dispatcher.
 */
const EXPORTERS: Partial<Record<ExportFormat, Exporter>> = {
  sarif: async (r) => ({
    content: renderReportSarif(r),
    contentType: "application/sarif+json",
    ext: "sarif",
  }),
  "owasp-json": async (r) => ({
    content: renderReportOwaspJson(r),
    contentType: "application/json",
    ext: "owasp.json",
  }),
  json: async (r) => ({
    content: renderReportJson(r),
    contentType: "application/json",
    ext: "json",
  }),
  csv: async (r) => ({ content: renderReportCsv(r), contentType: "text/csv", ext: "csv" }),
  html: async (r) => ({
    content: renderReportHtml(r),
    contentType: "text/html; charset=utf-8",
    ext: "html",
  }),
  pdf: async (r, opts) => ({
    content: await renderReportPdf(r, opts.pdf ?? {}),
    contentType: "application/pdf",
    ext: "pdf",
  }),
};

/** Register (or override) an exporter for a format — the Wave-3 seam. */
export function registerExporter(format: ExportFormat, exporter: Exporter): void {
  EXPORTERS[format] = exporter;
}

function byteLength(content: string | Uint8Array): number {
  return typeof content === "string" ? Buffer.byteLength(content, "utf8") : content.byteLength;
}

/**
 * Produce an export (descriptor + bytes). Throws {@link NotImplementedError} for
 * formats not yet registered (SOC 2 / ISO 27001 until Wave 3), with a clear message.
 */
export async function generateExport(
  report: Report,
  format: ExportFormat,
  opts: GenerateExportOptions = {},
): Promise<ReportExport> {
  const exporter = EXPORTERS[format];
  if (!exporter) {
    throw new NotImplementedError(`export format "${format}" not available yet (Wave 3 — WS-M)`, {
      format,
    });
  }
  const { content, contentType, ext } = await exporter(report, opts);
  const generatedAt = opts.now ?? new Date().toISOString();
  const artifact: ExportArtifact = {
    scanId: report.scanId,
    format,
    filename: `montr-${report.scanId}.${ext}`,
    contentType,
    sizeBytes: byteLength(content),
    generatedAt,
  };

  await opts.audit?.append({
    clientId: report.clientId,
    scanId: report.scanId,
    actor: { type: "agent", id: "montr-report" },
    action: "export.generated",
    targetType: "export",
    targetId: artifact.filename,
    summary: `Generated ${format} export (${artifact.sizeBytes} bytes)`,
    metadata: { format, filename: artifact.filename, sizeBytes: artifact.sizeBytes },
  });

  return { artifact, content, contentType };
}

/**
 * Frozen Wave-0 signature: export a report to a descriptor. Callers who need the
 * bytes use {@link generateExport} instead.
 */
export async function exportReport(report: Report, format: ExportFormat): Promise<ExportArtifact> {
  const { artifact } = await generateExport(report, format);
  return artifact;
}

export { renderReportSarif, toSarif, SARIF_TOOL_NAME } from "./sarif.js";
export { renderReportHtml, escapeHtml } from "./html.js";
export { renderReportPdf, PdfBrowserUnavailableError } from "./pdf.js";
export type { PdfOptions, PdfRenderer } from "./pdf.js";
