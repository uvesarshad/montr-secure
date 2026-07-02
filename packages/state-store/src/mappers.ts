/**
 * Row <-> contract mappers. The Prisma schema is frozen and diverges from the
 * @montr/contracts shapes in three ways this module reconciles:
 *
 *   1. Enum values with @map — `RiskClass`/`FixStatus` are stored as identifiers
 *      ("auto_eligible") but the contracts use hyphenated values ("auto-eligible").
 *   2. ISO strings vs Date — contracts use ISO-8601 strings; Prisma uses Date.
 *   3. Rich `SourceLocation` vs flat `file`/`line` columns on the finding tables.
 *      Candidate findings (which have a `metadata` Json column) preserve the full
 *      location + title losslessly under a reserved `__montr` key; probable /
 *      confirmed findings persist file+line (see notesForIntegration for the gap).
 */
import type {
  AppMap,
  AuthState,
  BudgetPolicy,
  CandidateFinding,
  Category,
  ConfirmedFinding,
  CostActual,
  CostEstimate,
  CweId,
  Fix,
  FixStatus,
  HttpMethod,
  LayerId,
  OwaspId,
  ProbableFinding,
  ProofArtifact,
  PullRequest,
  Report,
  ResumeToken,
  RiskClass,
  Route,
  Scan,
  ScanScope,
  SourceLocation,
  TaintSink,
  TaintSinkKind,
  TaintSource,
  TaintSourceKind,
  UnconfirmedFinding,
} from "@montr/contracts";
import type {
  AppMap as AppMapRow,
  CandidateFinding as CandidateRow,
  ConfirmedFinding as ConfirmedRow,
  Fix as FixRow,
  ProbableFinding as ProbableRow,
  PullRequest as PullRequestRow,
  Report as ReportRow,
  Route as RouteRow,
  Scan as ScanRow,
  ScanState as ScanStateRow,
  TaintSink as TaintSinkRow,
  TaintSource as TaintSourceRow,
} from "@prisma/client";
import { Prisma, fromJson, toJson, toJsonOrNull } from "./prisma.js";

/* ------------------------------ scalars ------------------------------ */

export const toDate = (iso: string): Date => new Date(iso);
export const toDateOpt = (iso?: string): Date | undefined => (iso ? new Date(iso) : undefined);
export const toIso = (d: Date): string => d.toISOString();
export const toIsoOpt = (d: Date | null | undefined): string | undefined =>
  d ? d.toISOString() : undefined;

/* ------------------------------ enums ------------------------------ */

type RiskClassRow = "auto_eligible" | "human_required";
type FixStatusRow = "proposed" | "pr_open" | "merged" | "rejected";

const RISK_CLASS_TO_ROW: Record<RiskClass, RiskClassRow> = {
  "auto-eligible": "auto_eligible",
  "human-required": "human_required",
};
const RISK_CLASS_TO_CONTRACT: Record<RiskClassRow, RiskClass> = {
  auto_eligible: "auto-eligible",
  human_required: "human-required",
};
const FIX_STATUS_TO_ROW: Record<FixStatus, FixStatusRow> = {
  proposed: "proposed",
  "pr-open": "pr_open",
  merged: "merged",
  rejected: "rejected",
};
const FIX_STATUS_TO_CONTRACT: Record<FixStatusRow, FixStatus> = {
  proposed: "proposed",
  pr_open: "pr-open",
  merged: "merged",
  rejected: "rejected",
};

export const riskClassToRow = (v: RiskClass): RiskClassRow => RISK_CLASS_TO_ROW[v];
export const riskClassToContract = (v: RiskClassRow): RiskClass => RISK_CLASS_TO_CONTRACT[v];
export const fixStatusToRow = (v: FixStatus): FixStatusRow => FIX_STATUS_TO_ROW[v];
export const fixStatusToContract = (v: FixStatusRow): FixStatus => FIX_STATUS_TO_CONTRACT[v];

/* ------------------------------ Scan ------------------------------ */

export function scanToCreate(clientId: string, s: Scan): Prisma.ScanUncheckedCreateInput {
  return {
    id: s.id,
    clientId,
    appMapId: s.appMapId ?? null,
    repo: s.repo,
    branch: s.branch,
    commitSha: s.commitSha ?? null,
    mode: s.mode,
    status: s.status,
    gateState: s.gateState,
    operatorId: s.operator,
    approverId: s.approver ?? null,
    scope: toJson(s.scope),
    budgetPolicy: toJsonOrNull(s.budgetPolicy),
    costEstimate: toJsonOrNull(s.costEstimate),
    costActual: toJsonOrNull(s.costActual),
    startedAt: toDateOpt(s.startedAt) ?? null,
    finishedAt: toDateOpt(s.finishedAt) ?? null,
    createdAt: toDate(s.createdAt),
  };
}

export function scanToUpdate(s: Scan): Prisma.ScanUncheckedUpdateManyInput {
  return {
    appMapId: s.appMapId ?? null,
    commitSha: s.commitSha ?? null,
    mode: s.mode,
    status: s.status,
    gateState: s.gateState,
    approverId: s.approver ?? null,
    scope: toJson(s.scope),
    budgetPolicy: toJsonOrNull(s.budgetPolicy),
    costEstimate: toJsonOrNull(s.costEstimate),
    costActual: toJsonOrNull(s.costActual),
    startedAt: toDateOpt(s.startedAt) ?? null,
    finishedAt: toDateOpt(s.finishedAt) ?? null,
  };
}

export function scanFromRow(row: ScanRow): Scan {
  return {
    id: row.id,
    clientId: row.clientId,
    appMapId: row.appMapId ?? undefined,
    repo: row.repo,
    branch: row.branch,
    commitSha: row.commitSha ?? undefined,
    mode: row.mode,
    scope: fromJson<ScanScope>(row.scope),
    status: row.status,
    gateState: row.gateState,
    operator: row.operatorId,
    approver: row.approverId ?? undefined,
    budgetPolicy: row.budgetPolicy ? fromJson<BudgetPolicy>(row.budgetPolicy) : undefined,
    costEstimate: row.costEstimate ? fromJson<CostEstimate>(row.costEstimate) : undefined,
    costActual: row.costActual ? fromJson<CostActual>(row.costActual) : undefined,
    startedAt: toIsoOpt(row.startedAt),
    finishedAt: toIsoOpt(row.finishedAt),
    createdAt: toIso(row.createdAt),
  };
}

/* ------------------------------ AppMap + relations ------------------------------ */

export function appMapScalarsToCreate(
  clientId: string,
  m: AppMap,
): Prisma.AppMapUncheckedCreateInput {
  return {
    id: m.id,
    clientId,
    repo: m.repo,
    branch: m.branch,
    commitSha: m.commitSha,
    languages: toJson(m.languages),
    frameworks: toJson(m.frameworks),
    entrypoints: toJson(m.entrypoints),
    dataStores: toJson(m.dataStores),
    ormModels: toJson(m.ormModels),
    thirdPartyCalls: toJson(m.thirdPartyCalls),
    envSecretSurfaces: toJson(m.envSecretSurfaces),
    stale: m.stale,
    rebuildPolicy: m.rebuildPolicy,
    createdAt: toDate(m.createdAt),
  };
}

export function routeToCreate(appMapId: string, r: Route): Prisma.RouteUncheckedCreateInput {
  return {
    ...(r.id ? { id: r.id } : {}),
    appMapId,
    path: r.path,
    method: r.method,
    authState: r.authState,
    isApiRoute: r.isApiRoute,
    authGate: r.authGate ?? null,
    handler: r.handler ? toJson(r.handler) : Prisma.DbNull,
  };
}

export function taintSourceToCreate(
  appMapId: string,
  t: TaintSource,
): Prisma.TaintSourceUncheckedCreateInput {
  return {
    ...(t.id ? { id: t.id } : {}),
    appMapId,
    kind: t.kind,
    location: toJson(t.location),
    description: t.description ?? null,
    routeId: t.routeId ?? null,
  };
}

export function taintSinkToCreate(
  appMapId: string,
  t: TaintSink,
): Prisma.TaintSinkUncheckedCreateInput {
  return {
    ...(t.id ? { id: t.id } : {}),
    appMapId,
    kind: t.kind,
    location: toJson(t.location),
    description: t.description ?? null,
  };
}

export function routeFromRow(row: RouteRow): Route {
  return {
    id: row.id,
    path: row.path,
    method: row.method as HttpMethod,
    authState: row.authState as AuthState,
    isApiRoute: row.isApiRoute,
    handler: row.handler ? fromJson<SourceLocation>(row.handler) : undefined,
    authGate: row.authGate ?? undefined,
  };
}

export function taintSourceFromRow(row: TaintSourceRow): TaintSource {
  return {
    id: row.id,
    kind: row.kind as TaintSourceKind,
    location: fromJson<SourceLocation>(row.location),
    description: row.description ?? undefined,
    routeId: row.routeId ?? undefined,
  };
}

export function taintSinkFromRow(row: TaintSinkRow): TaintSink {
  return {
    id: row.id,
    kind: row.kind as TaintSinkKind,
    location: fromJson<SourceLocation>(row.location),
    description: row.description ?? undefined,
  };
}

export function appMapFromRows(
  row: AppMapRow,
  routes: RouteRow[],
  sources: TaintSourceRow[],
  sinks: TaintSinkRow[],
): AppMap {
  return {
    id: row.id,
    clientId: row.clientId,
    repo: row.repo,
    branch: row.branch,
    commitSha: row.commitSha,
    createdAt: toIso(row.createdAt),
    languages: fromJson<AppMap["languages"]>(row.languages),
    frameworks: fromJson<AppMap["frameworks"]>(row.frameworks),
    entrypoints: fromJson<AppMap["entrypoints"]>(row.entrypoints),
    routes: routes.map(routeFromRow),
    dataStores: fromJson<AppMap["dataStores"]>(row.dataStores),
    ormModels: fromJson<AppMap["ormModels"]>(row.ormModels),
    thirdPartyCalls: fromJson<AppMap["thirdPartyCalls"]>(row.thirdPartyCalls),
    envSecretSurfaces: fromJson<AppMap["envSecretSurfaces"]>(row.envSecretSurfaces),
    taintSources: sources.map(taintSourceFromRow),
    taintSinks: sinks.map(taintSinkFromRow),
    stale: row.stale,
    rebuildPolicy: row.rebuildPolicy,
  };
}

/* ------------------------------ CandidateFinding ------------------------------ */

const RESERVED_META_KEY = "__montr";

interface CandidateExt {
  title?: string;
  location?: SourceLocation;
}

function locationHasExtras(loc: SourceLocation): boolean {
  return (
    loc.endLine !== undefined ||
    loc.column !== undefined ||
    loc.endColumn !== undefined ||
    loc.symbol !== undefined
  );
}

export function candidateToCreate(
  clientId: string,
  f: CandidateFinding,
): Prisma.CandidateFindingUncheckedCreateInput {
  const ext: CandidateExt = {};
  if (f.title !== undefined) ext.title = f.title;
  if (locationHasExtras(f.location)) ext.location = f.location;
  const metadata: Record<string, unknown> = { ...(f.metadata ?? {}) };
  if (Object.keys(ext).length > 0) metadata[RESERVED_META_KEY] = ext;
  return {
    id: f.id,
    clientId,
    scanId: f.scanId,
    source: f.source,
    ruleId: f.ruleId,
    category: f.category,
    cwe: toJson(f.cwe),
    file: f.location.file,
    line: f.location.line,
    rawSeverity: f.rawSeverity,
    evidenceSnippet: f.evidenceSnippet,
    status: "candidate",
    metadata: Object.keys(metadata).length > 0 ? toJson(metadata) : Prisma.DbNull,
    createdAt: toDate(f.createdAt),
  };
}

export function candidateFromRow(row: CandidateRow): CandidateFinding {
  const raw = (row.metadata ? fromJson<Record<string, unknown>>(row.metadata) : {}) ?? {};
  const ext = (raw[RESERVED_META_KEY] as CandidateExt | undefined) ?? {};
  const userMeta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) if (k !== RESERVED_META_KEY) userMeta[k] = v;
  return {
    id: row.id,
    scanId: row.scanId,
    clientId: row.clientId,
    source: row.source as CandidateFinding["source"],
    ruleId: row.ruleId,
    category: row.category as Category,
    cwe: fromJson<CweId[]>(row.cwe),
    location: ext.location ?? { file: row.file, line: row.line },
    rawSeverity: row.rawSeverity,
    evidenceSnippet: row.evidenceSnippet,
    ...(ext.title !== undefined ? { title: ext.title } : {}),
    status: "candidate",
    createdAt: toIso(row.createdAt),
    ...(Object.keys(userMeta).length > 0 ? { metadata: userMeta } : {}),
  };
}

/* ------------------------------ ProbableFinding / Unconfirmed ------------------------------ */

export function probableToCreate(
  clientId: string,
  f: ProbableFinding,
): Prisma.ProbableFindingUncheckedCreateInput {
  return {
    id: f.id,
    clientId,
    scanId: f.scanId,
    rootCauseId: f.rootCauseId,
    category: f.category,
    mergedCandidateIds: toJson(f.mergedCandidateIds),
    reachabilityHypothesis: f.reachabilityHypothesis,
    exploitHypothesis: f.exploitHypothesis,
    exposure: f.exposure,
    authGate: f.authGate ?? null,
    routeId: f.routeId ?? null,
    file: f.location.file,
    line: f.location.line,
    reachabilityScore: f.reachabilityScore,
    exposureScore: f.exposureScore,
    impactScore: f.impactScore,
    rank: f.rank,
    status: "probable",
    unconfirmedReason: null,
    createdAt: toDate(f.createdAt),
  };
}

export function unconfirmedToCreate(
  clientId: string,
  f: UnconfirmedFinding,
): Prisma.ProbableFindingUncheckedCreateInput {
  return {
    id: f.id,
    clientId,
    scanId: f.scanId,
    rootCauseId: f.rootCauseId,
    category: f.category,
    mergedCandidateIds: toJson(f.mergedCandidateIds),
    reachabilityHypothesis: f.reachabilityHypothesis,
    exploitHypothesis: f.exploitHypothesis,
    exposure: f.exposure,
    authGate: f.authGate ?? null,
    routeId: f.routeId ?? null,
    file: f.location.file,
    line: f.location.line,
    reachabilityScore: f.reachabilityScore,
    exposureScore: f.exposureScore,
    impactScore: f.impactScore,
    rank: f.rank,
    status: "unconfirmed",
    unconfirmedReason: f.unconfirmedReason,
    createdAt: toDate(f.createdAt),
  };
}

export function probableFromRow(row: ProbableRow): ProbableFinding {
  return {
    id: row.id,
    scanId: row.scanId,
    clientId: row.clientId,
    rootCauseId: row.rootCauseId,
    category: row.category as Category,
    mergedCandidateIds: fromJson<string[]>(row.mergedCandidateIds),
    reachabilityHypothesis: row.reachabilityHypothesis,
    exploitHypothesis: row.exploitHypothesis,
    exposure: row.exposure,
    authGate: row.authGate ?? undefined,
    routeId: row.routeId ?? undefined,
    location: { file: row.file, line: row.line },
    reachabilityScore: row.reachabilityScore,
    exposureScore: row.exposureScore,
    impactScore: row.impactScore,
    rank: row.rank,
    status: "probable",
    createdAt: toIso(row.createdAt),
  };
}

export function unconfirmedFromRow(row: ProbableRow): UnconfirmedFinding {
  return {
    id: row.id,
    scanId: row.scanId,
    clientId: row.clientId,
    rootCauseId: row.rootCauseId,
    category: row.category as Category,
    mergedCandidateIds: fromJson<string[]>(row.mergedCandidateIds),
    reachabilityHypothesis: row.reachabilityHypothesis,
    exploitHypothesis: row.exploitHypothesis,
    exposure: row.exposure,
    authGate: row.authGate ?? undefined,
    routeId: row.routeId ?? undefined,
    location: { file: row.file, line: row.line },
    reachabilityScore: row.reachabilityScore,
    exposureScore: row.exposureScore,
    impactScore: row.impactScore,
    rank: row.rank,
    status: "unconfirmed",
    unconfirmedReason: row.unconfirmedReason ?? "unconfirmed",
    createdAt: toIso(row.createdAt),
  };
}

/* ------------------------------ ConfirmedFinding ------------------------------ */

export function confirmedToCreate(
  clientId: string,
  f: ConfirmedFinding,
): Prisma.ConfirmedFindingUncheckedCreateInput {
  return {
    id: f.id,
    clientId,
    scanId: f.scanId,
    probableId: f.probableId ?? null,
    title: f.title,
    category: f.category,
    cwe: toJson(f.cwe),
    owasp: f.owasp ?? null,
    severity: f.severity,
    exposure: f.exposure,
    file: f.location.file,
    line: f.location.line,
    impact: f.impact,
    proofType: f.proofType,
    proofArtifact: toJson(f.proofArtifact),
    status: "confirmed",
    createdAt: toDate(f.createdAt),
  };
}

export function confirmedFromRow(row: ConfirmedRow): ConfirmedFinding {
  return {
    id: row.id,
    scanId: row.scanId,
    clientId: row.clientId,
    probableId: row.probableId ?? undefined,
    title: row.title,
    category: row.category as Category,
    cwe: fromJson<CweId[]>(row.cwe),
    owasp: (row.owasp as OwaspId | null) ?? undefined,
    severity: row.severity,
    exposure: row.exposure,
    location: { file: row.file, line: row.line },
    impact: row.impact,
    proofType: row.proofType,
    proofArtifact: fromJson<ProofArtifact>(row.proofArtifact),
    status: "confirmed",
    createdAt: toIso(row.createdAt),
  };
}

/* ------------------------------ Fix ------------------------------ */

export function fixToCreate(clientId: string, f: Fix): Prisma.FixUncheckedCreateInput {
  return {
    id: f.id,
    clientId,
    scanId: f.scanId,
    confirmedFindingId: f.confirmedFindingId,
    patch: f.patch,
    rationale: f.rationale,
    proofOfFixTest: toJson(f.proofOfFixTest),
    riskClass: riskClassToRow(f.riskClass),
    riskClassRationale: f.riskClassRationale,
    status: fixStatusToRow(f.status),
    pullRequestId: f.pullRequestId ?? null,
    createdAt: toDate(f.createdAt),
    ...(f.updatedAt ? { updatedAt: toDate(f.updatedAt) } : {}),
  };
}

export function fixToUpdate(f: Fix): Prisma.FixUncheckedUpdateManyInput {
  return {
    patch: f.patch,
    rationale: f.rationale,
    proofOfFixTest: toJson(f.proofOfFixTest),
    riskClass: riskClassToRow(f.riskClass),
    riskClassRationale: f.riskClassRationale,
    status: fixStatusToRow(f.status),
    pullRequestId: f.pullRequestId ?? null,
  };
}

export function fixFromRow(row: FixRow): Fix {
  return {
    id: row.id,
    scanId: row.scanId,
    clientId: row.clientId,
    confirmedFindingId: row.confirmedFindingId,
    patch: row.patch,
    rationale: row.rationale,
    proofOfFixTest: fromJson<Fix["proofOfFixTest"]>(row.proofOfFixTest),
    riskClass: riskClassToContract(row.riskClass as RiskClassRow),
    riskClassRationale: row.riskClassRationale,
    status: fixStatusToContract(row.status as FixStatusRow),
    pullRequestId: row.pullRequestId ?? undefined,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt),
  };
}

/* ------------------------------ PullRequest ------------------------------ */

export function pullRequestToCreate(
  clientId: string,
  p: PullRequest,
): Prisma.PullRequestUncheckedCreateInput {
  return {
    id: p.id,
    clientId,
    scanId: p.scanId,
    provider: p.provider,
    url: p.url ?? null,
    number: p.number ?? null,
    branch: p.branch,
    baseBranch: p.baseBranch,
    title: p.title,
    bodySummary: p.bodySummary,
    fixIds: toJson(p.fixIds),
    status: p.status,
    createdAt: toDate(p.createdAt),
  };
}

export function pullRequestFromRow(row: PullRequestRow): PullRequest {
  return {
    id: row.id,
    scanId: row.scanId,
    clientId: row.clientId,
    provider: row.provider,
    url: row.url ?? undefined,
    number: row.number ?? undefined,
    branch: row.branch,
    baseBranch: row.baseBranch,
    title: row.title,
    bodySummary: row.bodySummary,
    fixIds: fromJson<string[]>(row.fixIds),
    status: row.status,
    createdAt: toIso(row.createdAt),
  };
}

/* ------------------------------ Report ------------------------------ */

export function reportToCreate(clientId: string, r: Report): Prisma.ReportUncheckedCreateInput {
  return {
    id: r.id,
    clientId,
    scanId: r.scanId,
    generatedAt: toDate(r.generatedAt),
    document: toJson(r),
  };
}

export function reportFromRow(row: ReportRow): Report {
  // The full report is stored losslessly in `document`.
  return fromJson<Report>(row.document);
}

/* ------------------------------ ScanState / ResumeToken ------------------------------ */

export interface CheckpointBlob {
  checkpointRef?: string;
  data?: unknown;
}

export function resumeTokenFromState(row: ScanStateRow): ResumeToken {
  const checkpoint = row.checkpoint ? fromJson<CheckpointBlob>(row.checkpoint) : undefined;
  return {
    id: row.id,
    scanId: row.scanId,
    completedLayers: fromJson<LayerId[]>(row.completedLayers),
    lastCompletedLayer: row.layer,
    checkpointRef: checkpoint?.checkpointRef,
    updatedAt: toIso(row.updatedAt),
  };
}
