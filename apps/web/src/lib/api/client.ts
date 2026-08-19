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
import { endpoints } from "./config.js";
import { csrfHeaders, mockActorHeaders } from "./auth-headers.js";
import type {
  SessionResponse,
  RawSessionUser,
  Actor,
  ScanMutationResult,
  FalsePositiveResult,
} from "./types.js";
import type { CurrentUser } from "../rbac.js";

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

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      // The console always authenticates via the httpOnly session cookie
      // (apps/api/src/auth/session.ts) — every request must send it.
      credentials: "include",
      headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
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

/** POST/PUT/DELETE with CSRF (cookie-auth double-submit) + the MSW-only mock
 * actor hint (never sent against the real API — see auth-headers.ts). */
async function mutate<T>(
  url: string,
  actor?: Actor,
  payload?: unknown,
  method: "POST" | "PUT" | "DELETE" = "POST",
): Promise<T> {
  return request<T>(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...mockActorHeaders(actor),
      ...csrfHeaders(),
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
}

/** Derive a display name from an email local-part — the real API's user
 * record has no `name` field (see apps/api/src/auth/users.ts PublicUser). */
function deriveName(email: string): string {
  const local = email.split("@")[0] ?? email;
  return local
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

function toCurrentUser(u: RawSessionUser): CurrentUser {
  return { id: u.id, email: u.email, role: u.role, name: u.name ?? deriveName(u.email) };
}

/* ----------------------------------- reads ----------------------------------- */

export const api = {
  getSession: async (): Promise<SessionResponse> => {
    const body = await request<{ user: RawSessionUser; availableUsers?: RawSessionUser[] }>(
      endpoints.me(),
    );
    const user = toCurrentUser(body.user);
    const availableUsers =
      body.availableUsers && body.availableUsers.length > 0
        ? body.availableUsers.map(toCurrentUser)
        : [user];
    return { user, availableUsers };
  },

  login: (email: string, password: string): Promise<{ user: CurrentUser }> =>
    request<{ user: RawSessionUser }>(endpoints.login(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    }).then((r) => ({ user: toCurrentUser(r.user) })),

  logout: (): Promise<void> => request(endpoints.logout(), { method: "POST" }),

  listScans: (): Promise<Scan[]> =>
    request<{ scans: Scan[] }>(endpoints.scans()).then((r) => r.scans),
  getScan: (scanId: string): Promise<Scan> =>
    request<{ scan: Scan }>(endpoints.scan(scanId)).then((r) => r.scan),
  getProgress: (scanId: string): Promise<ProgressEvent[]> => request(endpoints.progress(scanId)),
  getAppMap: (scanId: string): Promise<AppMap> => request(endpoints.appMap(scanId)),
  /** No standalone GET-estimate route on the real API — derived from
   * `scan.costEstimate` (GET /scans/:id), which the MSW mock also carries. */
  getEstimate: (scanId: string): Promise<CostEstimate | undefined> =>
    request<{ scan: Scan }>(endpoints.scan(scanId)).then((r) => r.scan.costEstimate),
  getReport: (scanId: string): Promise<Report> =>
    request<{ report: Report }>(endpoints.report(scanId)).then((r) => r.report),
  /** No standalone fixes route — derived from the Report's confirmed findings. */
  getFixes: (scanId: string): Promise<Fix[]> =>
    request<{ report: Report }>(endpoints.report(scanId)).then((r) =>
      r.report.confirmedFindings.map((rf) => rf.fix).filter((f): f is Fix => Boolean(f)),
    ),
  /** No standalone pull-requests route — derived from the Report's fix status. */
  getScanPullRequests: (scanId: string): Promise<PullRequest[]> =>
    request<{ report: Report }>(endpoints.report(scanId)).then(
      (r) => r.report.fixStatus.pullRequests,
    ),
  listPullRequests: (): Promise<PullRequest[]> => request(endpoints.pullRequests()),
  listAudit: (scanId?: string): Promise<AuditEvent[]> => {
    const url = new URL(endpoints.audit());
    url.searchParams.set("format", "json");
    if (scanId) url.searchParams.set("scanId", scanId);
    return request(url.toString());
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
    findingId: string,
    actor: Actor,
    reason: string,
  ): Promise<FalsePositiveResult> =>
    mutate(endpoints.markFalsePositive(findingId), actor, { reason }),
  requestExport: (scanId: string, format: ExportFormat, actor: Actor): Promise<ExportArtifact> =>
    mutate(`${endpoints.export(scanId)}?format=${format}`, actor),
} as const;
