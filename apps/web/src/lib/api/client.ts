import type {
  Scan,
  AuditEvent,
  Report,
  AppMap,
  CostEstimate,
  Fix,
  PullRequest,
  ProgressEvent,
  ExportArtifact,
  ExportFormat,
} from "@montr/contracts";
import { endpoints, ACTOR_ID_HEADER, ACTOR_ROLE_HEADER } from "./config.js";
import type { SessionResponse, Actor, ScanMutationResult, FalsePositiveResult } from "./types.js";

/** A typed transport error carrying the server's ErrorEnvelope when present. */
export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function actorHeaders(actor?: Actor): Record<string, string> {
  if (!actor) return {};
  return { [ACTOR_ID_HEADER]: actor.id, [ACTOR_ROLE_HEADER]: actor.role };
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    });
  } catch (cause) {
    throw new ApiError(0, `Network error contacting ${url}`, "NETWORK");
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = body as { message?: string; code?: string } | undefined;
    throw new ApiError(res.status, env?.message ?? res.statusText, env?.code);
  }
  return body as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

async function mutate<T>(url: string, actor: Actor, payload?: unknown): Promise<T> {
  return request<T>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...actorHeaders(actor) },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
}

/* ----------------------------------- reads ----------------------------------- */

export const api = {
  getSession: (): Promise<SessionResponse> => request(endpoints.me()),
  listScans: (): Promise<Scan[]> => request(endpoints.scans()),
  getScan: (scanId: string): Promise<Scan> => request(endpoints.scan(scanId)),
  getProgress: (scanId: string): Promise<ProgressEvent[]> => request(endpoints.progress(scanId)),
  getAppMap: (scanId: string): Promise<AppMap> => request(endpoints.appMap(scanId)),
  getEstimate: (scanId: string): Promise<CostEstimate> => request(endpoints.estimate(scanId)),
  getReport: (scanId: string): Promise<Report> => request(endpoints.report(scanId)),
  getFixes: (scanId: string): Promise<Fix[]> => request(endpoints.fixes(scanId)),
  getScanPullRequests: (scanId: string): Promise<PullRequest[]> =>
    request(endpoints.scanPullRequests(scanId)),
  listPullRequests: (): Promise<PullRequest[]> => request(endpoints.pullRequests()),
  listAudit: (scanId?: string): Promise<AuditEvent[]> => {
    const url = scanId
      ? `${endpoints.audit()}?scanId=${encodeURIComponent(scanId)}`
      : endpoints.audit();
    return request(url);
  },

  /* --------------------------------- mutations --------------------------------- */

  approveEstimate: (scanId: string, actor: Actor): Promise<ScanMutationResult> =>
    mutate(endpoints.approveEstimate(scanId), actor),
  approveFixGate: (scanId: string, actor: Actor): Promise<ScanMutationResult> =>
    mutate(endpoints.approveFixGate(scanId), actor),
  authorizeDast: (scanId: string, actor: Actor, stagingUrl: string): Promise<ScanMutationResult> =>
    mutate(endpoints.authorizeDast(scanId), actor, { stagingUrl }),
  activateKillSwitch: (scanId: string, actor: Actor, reason: string): Promise<ScanMutationResult> =>
    mutate(endpoints.killSwitch(scanId), actor, { reason }),
  markFalsePositive: (
    scanId: string,
    findingId: string,
    actor: Actor,
    reason: string,
  ): Promise<FalsePositiveResult> =>
    mutate(endpoints.markFalsePositive(scanId, findingId), actor, { reason }),
  requestExport: (scanId: string, format: ExportFormat, actor: Actor): Promise<ExportArtifact> =>
    mutate(`${endpoints.export(scanId)}?format=${format}`, actor),
} as const;
