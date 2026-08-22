/**
 * Report EXPORTS (§13, DECIDE-5 order). SARIF + generic OWASP first (broadest),
 * then SOC 2 evidence, then ISO 27001 — all now implemented (Wave 3, WS-M) and
 * reachable through the frozen {@link generateExport} / {@link exportReport} API.
 * Machine-readable JSON, HTML, PDF, and confirmed-findings CSV round it out.
 *
 * The dispatcher is a REGISTRY: every format is one {@link Exporter}; new formats
 * slot in via {@link registerExporter} with zero changes to the dispatcher.
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
import { renderReportOwaspJson } from "./owasp.js";
import {
  renderCycloneDxSbom,
  inventoryFromReport,
  type DependencyInventoryInput,
} from "./cyclonedx.js";
import {
  renderSoc2EvidenceJson,
  renderSoc2EvidenceCsv,
  renderIso27001EvidenceJson,
  renderIso27001EvidenceCsv,
  type EvidenceOptions,
} from "./evidence.js";
import type { AuditTrailAccess } from "./audit-trail.js";
import type { ComplianceFramework } from "./controls.js";
import type { PreviousScanContext } from "../types.js";

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
  /**
   * Tamper-evident audit-trail accessor (@montr/state-store). When supplied, the
   * SOC 2 / ISO 27001 evidence packages embed a verified link to the trail.
   */
  auditLog?: AuditTrailAccess;
  /** Previous scan context (from scan history) for the posture delta in evidence. */
  previous?: PreviousScanContext;
  /**
   * E16: the full resolved dependency tree (e.g. from `@montr/discovery`'s
   * `buildDependencyInventory`) for the `"cyclonedx"` SBOM export — see
   * `cyclonedx.ts`'s module doc for why this can't be derived from `Report`
   * alone. Omit to fall back to the leaner `inventoryFromReport` derivation.
   */
  dependencyInventory?: DependencyInventoryInput;
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

/** Map the export options that evidence renderers consume. */
function evidenceOptions(opts: GenerateExportOptions): EvidenceOptions {
  return {
    ...(opts.now ? { now: opts.now } : {}),
    ...(opts.auditLog ? { auditLog: opts.auditLog } : {}),
    ...(opts.previous ? { previous: opts.previous } : {}),
  };
}

/**
 * Format registry (the extension point). SOC 2 + ISO 27001 evidence are
 * registered here (Wave 3); the CSV representations of each ship via
 * {@link generateEvidencePackage}.
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
  "soc2-evidence": async (r, opts) => ({
    content: await renderSoc2EvidenceJson(r, evidenceOptions(opts)),
    contentType: "application/json",
    ext: "soc2-evidence.json",
  }),
  iso27001: async (r, opts) => ({
    content: await renderIso27001EvidenceJson(r, evidenceOptions(opts)),
    contentType: "application/json",
    ext: "iso27001-evidence.json",
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
  cyclonedx: async (r, opts) => ({
    content: renderCycloneDxSbom(opts.dependencyInventory ?? inventoryFromReport(r), {
      ...(opts.now ? { now: opts.now } : {}),
      scanId: r.scanId,
    }),
    contentType: "application/vnd.cyclonedx+json",
    ext: "cdx.json",
  }),
};

/** Register (or override) an exporter for a format — the Wave-3 seam. */
export function registerExporter(format: ExportFormat, exporter: Exporter): void {
  EXPORTERS[format] = exporter;
}

function byteLength(content: string | Uint8Array): number {
  return typeof content === "string" ? Buffer.byteLength(content, "utf8") : content.byteLength;
}

/** Assemble the descriptor + audit a produced export (metadata only). */
async function finalizeExport(
  report: Report,
  format: ExportFormat,
  result: ExporterResult,
  opts: GenerateExportOptions,
): Promise<ReportExport> {
  const generatedAt = opts.now ?? new Date().toISOString();
  const artifact: ExportArtifact = {
    scanId: report.scanId,
    format,
    filename: `montr-${report.scanId}.${result.ext}`,
    contentType: result.contentType,
    sizeBytes: byteLength(result.content),
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

  return { artifact, content: result.content, contentType: result.contentType };
}

/**
 * Produce an export (descriptor + bytes). Throws {@link NotImplementedError} for
 * a format with no registered exporter (a clean signal, should not happen for the
 * eight frozen formats).
 */
export async function generateExport(
  report: Report,
  format: ExportFormat,
  opts: GenerateExportOptions = {},
): Promise<ReportExport> {
  const exporter = EXPORTERS[format];
  if (!exporter) {
    throw new NotImplementedError(`export format "${format}" has no registered exporter`, {
      format,
    });
  }
  return finalizeExport(report, format, await exporter(report, opts), opts);
}

/**
 * Frozen Wave-0 signature: export a report to a descriptor. Callers who need the
 * bytes use {@link generateExport} instead.
 */
export async function exportReport(report: Report, format: ExportFormat): Promise<ExportArtifact> {
  const { artifact } = await generateExport(report, format);
  return artifact;
}

/**
 * The full compliance-evidence PACKAGE for a framework: BOTH the JSON evidence
 * and the CSV drop-in, returned as two artifacts (the "JSON + CSV" package §13).
 */
export async function generateEvidencePackage(
  report: Report,
  framework: ComplianceFramework,
  opts: GenerateExportOptions = {},
): Promise<{ json: ReportExport; csv: ReportExport }> {
  const evOpts = evidenceOptions(opts);
  const format: ExportFormat = framework === "soc2" ? "soc2-evidence" : "iso27001";
  const base = framework === "soc2" ? "soc2-evidence" : "iso27001-evidence";
  const [jsonContent, csvContent] =
    framework === "soc2"
      ? await Promise.all([
          renderSoc2EvidenceJson(report, evOpts),
          renderSoc2EvidenceCsv(report, evOpts),
        ])
      : await Promise.all([
          renderIso27001EvidenceJson(report, evOpts),
          renderIso27001EvidenceCsv(report, evOpts),
        ]);
  const json = await finalizeExport(
    report,
    format,
    { content: jsonContent, contentType: "application/json", ext: `${base}.json` },
    opts,
  );
  const csv = await finalizeExport(
    report,
    format,
    { content: csvContent, contentType: "text/csv", ext: `${base}.csv` },
    opts,
  );
  return { json, csv };
}

export { renderReportSarif, toSarif, SARIF_TOOL_NAME, SARIF_FINGERPRINT_KEY } from "./sarif.js";
export type { RichSarifLog } from "./sarif.js";
export { renderReportHtml, escapeHtml } from "./html.js";
export { renderReportPdf, htmlToPdf, PdfBrowserUnavailableError } from "./pdf.js";
export type { PdfOptions, PdfRenderer } from "./pdf.js";

// CycloneDX 1.5 SBOM (E16) — full dependency tree + reachability + advisories.
export {
  buildCycloneDxSbom,
  renderCycloneDxSbom,
  inventoryFromReport,
  CYCLONEDX_SPEC_VERSION,
} from "./cyclonedx.js";
export type {
  CycloneDxBom,
  CycloneDxComponentInput,
  CycloneDxVulnerabilityInput,
  DependencyInventoryInput,
  BuildCycloneDxSbomOptions,
} from "./cyclonedx.js";

// Generic OWASP Top 10 (2021) report — JSON + human-readable HTML/PDF.
export {
  renderReportOwaspJson,
  renderOwaspHtml,
  renderOwaspPdf,
  buildOwaspCoverage,
  OWASP_TOP_10,
} from "./owasp.js";
export type { OwaspCategoryGroup, OwaspFindingRow } from "./owasp.js";

// SOC 2 + ISO 27001 evidence packages (JSON + CSV).
export {
  buildEvidencePackage,
  renderEvidenceJson,
  renderEvidenceCsv,
  renderSoc2EvidenceJson,
  renderSoc2EvidenceCsv,
  renderIso27001EvidenceJson,
  renderIso27001EvidenceCsv,
  remediationStateFor,
} from "./evidence.js";
export type {
  EvidencePackage,
  EvidenceRecord,
  EvidenceOptions,
  ControlCoverage,
  RemediationState,
} from "./evidence.js";

// Compliance control catalogs (SOC 2 CC-series / ISO 27001 Annex A).
export {
  controlsForCategory,
  controlCatalog,
  referencedControlIds,
  FRAMEWORK_LABEL,
  // B10 — detection/monitoring controls satisfiable by real B6 DetectionCoverage
  // evidence, not only the red-side per-category mapping (see ./controls.ts).
  detectionMonitoringControls,
  DETECTION_MONITORING_CONTROL_IDS,
} from "./controls.js";
export type { ControlDescriptor, ComplianceFramework } from "./controls.js";

// Posture delta from scan history (§12.1).
export { loadPreviousScanContext, computePostureDeltaDetail } from "./posture.js";
export type { ScanHistorySource, PostureDeltaDetail, PostureFindingRef } from "./posture.js";

// Third-party-auditor audit-trail export, surfaced through the report layer.
export { exportAuditTrail, buildAuditTrailLink } from "./audit-trail.js";
export type {
  AuditTrailAccess,
  AuditTrailExport,
  AuditTrailLink,
  AuditTrailFormat,
} from "./audit-trail.js";
// Surface the raw @montr/state-store audit export through the report layer too.
export { exportAuditLog } from "@montr/state-store";
export type { AuditExportFormat } from "@montr/state-store";

// MITRE ATT&CK report surfacing (B2) — standalone, not yet wired into the
// EXPORTERS registry above (no format enum slot exists for it yet; a later
// wave wires this in alongside the other blue-team capabilities).
export {
  buildMitreFindingMappings,
  buildMitreAttackSection,
  renderMitreAttackJson,
} from "./mitre-attack.js";
export type {
  MitreFindingMapping,
  MitreTechniqueCoverage,
  MitreAttackSection,
} from "./mitre-attack.js";
