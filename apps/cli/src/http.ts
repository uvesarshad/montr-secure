/**
 * Thin HTTP client for the real `apps/api` server (A15 — `montr scan`).
 *
 * Deliberately reuses the DOMAIN types from `@montr/contracts` (`Scan`,
 * `ScanMode`, `ScanScope`, `ProgressEvent`, `ConfirmedFinding`,
 * `UnconfirmedFinding`) rather than re-declaring them, mirroring the same
 * request/response shapes `apps/web/src/lib/api/client.ts` uses against the
 * same routes (`POST /scans`, `GET /scans/:id`, `GET /scans/:id/progress`,
 * `GET /scans/:id/findings`) — see `apps/api/src/schemas.ts`
 * `CreateScanBodySchema` for the exact wire shape `createScan` below sends.
 * The wrapper itself (error envelope, fetch plumbing) intentionally mirrors
 * `apps/web/src/lib/api/client.ts`'s `request`/`ApiError` so the two HTTP
 * clients stay recognizably the same shape even though the CLI runs in
 * Node (Authorization header + no cookies) rather than the browser (cookie
 * session + CSRF double-submit).
 */
import type {
  ConfirmedFinding,
  Scan,
  ScanMode,
  ScanScope,
  ProgressEvent,
  UnconfirmedFinding,
} from "@montr/contracts";

/** A typed transport error carrying the server's ErrorEnvelope when present. */
export class CliApiError extends Error {
  readonly status: number;
  readonly code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "CliApiError";
    this.status = status;
    this.code = code;
  }
}

export interface HttpClientOptions {
  /** e.g. http://localhost:3001 (no trailing slash required). */
  baseUrl: string;
  /** Bearer JWT. Omitted only before `login()` establishes one. */
  token?: string;
  /** Injectable for tests; defaults to the global `fetch` (Node 20+). */
  fetchImpl?: typeof fetch;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

async function request<T>(opts: HttpClientOptions, path: string, init?: RequestInit): Promise<T> {
  const f = opts.fetchImpl ?? fetch;
  const url = `${opts.baseUrl.replace(/\/+$/, "")}${path}`;
  let res: Response;
  try {
    res = await f(url, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
        ...(init?.headers ?? {}),
      },
    });
  } catch (e) {
    throw new CliApiError(
      0,
      `Network error contacting ${url}: ${e instanceof Error ? e.message : String(e)}`,
      "NETWORK",
    );
  }
  const text = await res.text();
  const body: unknown = text ? safeJson(text) : undefined;
  if (!res.ok) {
    const env = body as { error?: { message?: string; code?: string } } | undefined;
    throw new CliApiError(res.status, env?.error?.message ?? res.statusText, env?.error?.code);
  }
  return body as T;
}

export interface CreateScanInput {
  repo: string;
  branch: string;
  mode: ScanMode;
  scope?: Partial<ScanScope>;
}

export interface FindingsResult {
  confirmed: ConfirmedFinding[];
  unconfirmed: UnconfirmedFinding[];
}

export interface MontrApiClient {
  /** POST /auth/login — returns the bearer token (also usable as a cookie session, unused here). */
  login(email: string, password: string): Promise<string>;
  /** POST /scans — creates AND starts a scan (mirrors the web console's two-call sequence server-side). */
  createScan(input: CreateScanInput): Promise<Scan>;
  getScan(scanId: string): Promise<Scan>;
  getProgress(scanId: string): Promise<ProgressEvent[]>;
  getFindings(scanId: string): Promise<FindingsResult>;
}

export function createApiClient(opts: HttpClientOptions): MontrApiClient {
  return {
    async login(email, password) {
      const body = await request<{ token: string }>(opts, "/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      return body.token;
    },
    async createScan(input) {
      const body = await request<{ scan: Scan }>(opts, "/api/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
      return body.scan;
    },
    async getScan(scanId) {
      const body = await request<{ scan: Scan }>(opts, `/api/v1/scans/${scanId}`);
      return body.scan;
    },
    getProgress(scanId) {
      return request<ProgressEvent[]>(opts, `/api/v1/scans/${scanId}/progress`);
    },
    getFindings(scanId) {
      return request<FindingsResult>(opts, `/api/v1/scans/${scanId}/findings`);
    },
  };
}
