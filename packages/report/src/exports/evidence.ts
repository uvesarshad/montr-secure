/**
 * SOC 2 + ISO 27001 EVIDENCE packages (§13, DECIDE-5: SOC 2 then ISO 27001).
 *
 * Produces an evidence bundle that drops straight into an auditor's collection:
 *   - control mapping (SOC 2 Common-Criteria "CC-series" / ISO 27001 Annex A),
 *   - finding status + remediation state (derived from the fix lifecycle),
 *   - timestamps (finding detection + report generation),
 *   - scan scope (what was in bounds),
 *   - a link to the tamper-evident audit trail (@montr/state-store audit export),
 *   - posture delta vs the last scan.
 *
 * Two representations from ONE model: JSON (structured) and CSV (one row per
 * finding, controls joined). Both are pure/deterministic given a fixed `now` and
 * an injected audit accessor — offline-testable, no live DB.
 */
import type { ComplianceMapping, Fix, Report, ReportFinding, ScanScope } from "@montr/contracts";
import { complianceForCategory } from "@montr/contracts";
import {
  controlsForCategory,
  detectionMonitoringControls,
  FRAMEWORK_LABEL,
  type ComplianceFramework,
  type ControlDescriptor,
} from "./controls.js";
import { buildAuditTrailLink, type AuditTrailAccess, type AuditTrailLink } from "./audit-trail.js";
import { computePostureDeltaDetail, type PostureDeltaDetail } from "./posture.js";
import type { PreviousScanContext } from "../types.js";

/** Remediation lifecycle of a confirmed finding, derived from its fix (if any). */
export type RemediationState =
  | "remediated" // fix merged
  | "in_progress" // PR open
  | "planned" // auto-eligible fix proposed (PR-ready)
  | "recommended" // human-required fix proposed (recommendation only)
  | "open"; // no fix / rejected

/** Derive the remediation state from a finding's fix + risk class (auditable). */
export function remediationStateFor(fix: Fix | undefined): RemediationState {
  if (!fix) return "open";
  switch (fix.status) {
    case "merged":
      return "remediated";
    case "pr-open":
      return "in_progress";
    case "rejected":
      return "open";
    case "proposed":
    default:
      return fix.riskClass === "auto-eligible" ? "planned" : "recommended";
  }
}

/** One evidence line — a confirmed finding mapped to framework controls. */
export interface EvidenceRecord {
  findingId: string;
  title: string;
  category: string;
  severity: string;
  exposure: string;
  status: "confirmed";
  proofType: string;
  owasp: string;
  owaspTitle: string;
  cwe: string[];
  controls: ControlDescriptor[];
  remediationState: RemediationState;
  fixId?: string;
  fixRiskClass?: string;
  pullRequestId?: string;
  location: { file: string; line: number };
  /** When the finding was detected (finding.createdAt). */
  detectedAt: string;
  /** `DetectionRule.id`s (B3/B4) generated for this finding, if any. */
  detectionRuleIds?: string[];
  /**
   * B10: whether this finding also has VERIFIED blue-team detection coverage
   * (B6's `DetectionCoverage.detected === true` — real, telemetry-grounded
   * evidence, never merely "a rule exists" or the tri-state "unknown"). Only
   * when `true` do the detection/monitoring controls
   * (`detectionMonitoringControls`, `./controls.ts`) get added to `controls`
   * above as genuine evidence, rather than only the red-side category
   * mapping — an honest bar, matching `DetectionCoverage`'s own tri-state
   * discipline (never overstating "unknown" as satisfied).
   */
  detectionCoverageVerified?: boolean;
}

/** Per-control coverage summary (how many findings touch each control). */
export interface ControlCoverage {
  control: ControlDescriptor;
  findingCount: number;
  findingIds: string[];
}

/** The full evidence package for one framework. */
export interface EvidencePackage {
  framework: ComplianceFramework;
  frameworkLabel: string;
  tool: "Montr Secure";
  scanId: string;
  clientId: string;
  generatedAt: string;
  scanScope: ScanScope;
  summary: {
    totalConfirmed: number;
    byRemediationState: Record<RemediationState, number>;
    controlsCovered: number;
  };
  controlCoverage: ControlCoverage[];
  evidence: EvidenceRecord[];
  auditTrail: AuditTrailLink;
  postureDelta: PostureDeltaDetail;
}

export interface EvidenceOptions {
  /** Deterministic generation time (tests). Defaults to `report.generatedAt`. */
  now?: string;
  /** Audit accessor — embeds a verified link to the tamper-evident trail. */
  auditLog?: AuditTrailAccess;
  /** Previous scan context for the posture delta (from scan history). */
  previous?: PreviousScanContext;
}

const REMEDIATION_STATES: readonly RemediationState[] = [
  "remediated",
  "in_progress",
  "planned",
  "recommended",
  "open",
];

/** Dedupe by control id, preserving first-seen order (a category's own mapping wins). */
function dedupeControls(controls: readonly ControlDescriptor[]): ControlDescriptor[] {
  const seen = new Set<string>();
  const out: ControlDescriptor[] = [];
  for (const c of controls) {
    if (seen.has(c.id)) continue;
    seen.add(c.id);
    out.push(c);
  }
  return out;
}

function evidenceRecord(
  framework: ComplianceFramework,
  rf: ReportFinding,
  detectionEngineering: Report["blueTeam"]["detectionEngineering"],
): EvidenceRecord {
  const f = rf.finding;
  const compliance: ComplianceMapping = rf.compliance ?? complianceForCategory(f.category);
  const cwe = f.cwe.length > 0 ? f.cwe : compliance.cwe;
  const remediationState = remediationStateFor(rf.fix);

  // B10: fold in real blue-team detection evidence — a generated DetectionRule
  // (B3/B4) and, when VERIFIED (detected === true), the detection/monitoring
  // controls this finding's coverage actually earns (see DETECTION_MONITORING_
  // CONTROL_IDS's doc comment in ./controls.ts).
  const findingRules = detectionEngineering.rules.filter((r) => r.findingId === f.id);
  const findingCoverage = detectionEngineering.coverage.find((c) => c.findingId === f.id);
  const detectionCoverageVerified = findingCoverage?.detected === true;
  const controls = detectionCoverageVerified
    ? dedupeControls([
        ...controlsForCategory(framework, f.category),
        ...detectionMonitoringControls(framework),
      ])
    : controlsForCategory(framework, f.category);

  return {
    findingId: f.id,
    title: f.title,
    category: f.category,
    severity: f.severity,
    exposure: f.exposure,
    status: "confirmed",
    proofType: f.proofType,
    owasp: compliance.owasp,
    owaspTitle: compliance.owaspTitle,
    cwe: [...cwe],
    controls,
    remediationState,
    ...(rf.fix ? { fixId: rf.fix.id, fixRiskClass: rf.fix.riskClass } : {}),
    ...(rf.fix?.pullRequestId ? { pullRequestId: rf.fix.pullRequestId } : {}),
    location: { file: f.location.file, line: f.location.line },
    detectedAt: f.createdAt,
    ...(findingRules.length > 0 ? { detectionRuleIds: findingRules.map((r) => r.id) } : {}),
    ...(findingCoverage ? { detectionCoverageVerified } : {}),
  };
}

function coverageOf(records: readonly EvidenceRecord[]): ControlCoverage[] {
  const byId = new Map<string, ControlCoverage>();
  for (const rec of records) {
    for (const control of rec.controls) {
      let cov = byId.get(control.id);
      if (!cov) {
        cov = { control, findingCount: 0, findingIds: [] };
        byId.set(control.id, cov);
      }
      cov.findingCount += 1;
      cov.findingIds.push(rec.findingId);
    }
  }
  return [...byId.values()].sort((a, b) => a.control.id.localeCompare(b.control.id));
}

/**
 * Build a SOC 2 / ISO 27001 evidence package from a finished report. Async
 * because it may verify + digest the tamper-evident audit trail.
 */
export async function buildEvidencePackage(
  report: Report,
  framework: ComplianceFramework,
  opts: EvidenceOptions = {},
): Promise<EvidencePackage> {
  const evidence = report.confirmedFindings.map((rf) =>
    evidenceRecord(framework, rf, report.blueTeam.detectionEngineering),
  );

  const byRemediationState = Object.fromEntries(REMEDIATION_STATES.map((s) => [s, 0])) as Record<
    RemediationState,
    number
  >;
  for (const rec of evidence) byRemediationState[rec.remediationState] += 1;

  const controlCoverage = coverageOf(evidence);
  const auditTrail = await buildAuditTrailLink(report.clientId, opts.auditLog);
  const postureDelta = computePostureDeltaDetail(
    report.confirmedFindings.map((rf) => rf.finding),
    opts.previous,
  );

  return {
    framework,
    frameworkLabel: FRAMEWORK_LABEL[framework],
    tool: "Montr Secure",
    scanId: report.scanId,
    clientId: report.clientId,
    generatedAt: opts.now ?? report.generatedAt,
    scanScope: report.costAndScope.scope,
    summary: {
      totalConfirmed: evidence.length,
      byRemediationState,
      controlsCovered: controlCoverage.length,
    },
    controlCoverage,
    evidence,
    auditTrail,
    postureDelta,
  };
}

/** Structured JSON evidence package. */
export async function renderEvidenceJson(
  report: Report,
  framework: ComplianceFramework,
  opts: EvidenceOptions = {},
): Promise<string> {
  return JSON.stringify(await buildEvidencePackage(report, framework, opts), null, 2);
}

function csvCell(value: unknown): string {
  const s = String(value ?? "");
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * CSV evidence — one row per confirmed finding, controls joined with ";". Ready
 * to drop into a spreadsheet-based evidence tracker.
 */
export async function renderEvidenceCsv(
  report: Report,
  framework: ComplianceFramework,
  opts: EvidenceOptions = {},
): Promise<string> {
  const pkg = await buildEvidencePackage(report, framework, opts);
  const header = [
    "findingId",
    "title",
    "category",
    "severity",
    "exposure",
    "status",
    "proofType",
    "owasp",
    "cwe",
    "controls",
    "controlTitles",
    "remediationState",
    "fixId",
    "pullRequestId",
    "file",
    "line",
    "detectedAt",
    "detectionRuleIds",
    "detectionCoverageVerified",
    "scanId",
    "generatedAt",
    "auditTrailFile",
    "auditChainVerified",
  ];
  const rows = pkg.evidence.map((r) =>
    [
      r.findingId,
      r.title,
      r.category,
      r.severity,
      r.exposure,
      r.status,
      r.proofType,
      r.owasp,
      r.cwe.join(" "),
      r.controls.map((c) => c.id).join(";"),
      r.controls.map((c) => c.title).join(";"),
      r.remediationState,
      r.fixId ?? "",
      r.pullRequestId ?? "",
      r.location.file,
      r.location.line,
      r.detectedAt,
      (r.detectionRuleIds ?? []).join(";"),
      r.detectionCoverageVerified ?? "",
      pkg.scanId,
      pkg.generatedAt,
      pkg.auditTrail.filename,
      pkg.auditTrail.chainVerified ?? "",
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.map(csvCell).join(","), ...rows].join("\n");
}

// Convenience aliases per framework (clearer call sites in the export registry).
export const renderSoc2EvidenceJson = (report: Report, opts?: EvidenceOptions): Promise<string> =>
  renderEvidenceJson(report, "soc2", opts);
export const renderSoc2EvidenceCsv = (report: Report, opts?: EvidenceOptions): Promise<string> =>
  renderEvidenceCsv(report, "soc2", opts);
export const renderIso27001EvidenceJson = (
  report: Report,
  opts?: EvidenceOptions,
): Promise<string> => renderEvidenceJson(report, "iso27001", opts);
export const renderIso27001EvidenceCsv = (
  report: Report,
  opts?: EvidenceOptions,
): Promise<string> => renderEvidenceCsv(report, "iso27001", opts);
