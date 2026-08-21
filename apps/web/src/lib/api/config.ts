/**
 * API endpoint map. Talks to the real apps/api server, versioned under
 * `/api/v1` (see apps/api/src/routes/index.ts — `/health` is the only
 * unprefixed route, kept that way for k8s/docker-compose/Dockerfile probes).
 *
 * Paths below are aligned to the ACTUAL routes apps/api registers today
 * (apps/api/src/routes/*.ts). `progress`, `appMap`, cross-scan `pullRequests`,
 * and scan-scoped `dast/authorize` (A5) now have real backend routes — see
 * their inline notes below. Scan-scoped `export` is still forward-looking
 * (kept here so the client compiles and degrades gracefully — 404 → the UI's
 * existing empty/error states).
 *
 * MSW (src/mocks) mirrors `routePatterns` as an opt-in mock server — see
 * components/providers.tsx (`NEXT_PUBLIC_USE_MSW=true` to enable).
 */
export const API_BASE: string = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:3000";

/** Single source of truth for whether MSW mocking is active (opt-in — real API
 * by default). Mirrored by components/providers.tsx. */
export const isMswEnabled: boolean = process.env.NEXT_PUBLIC_USE_MSW === "true";

const v1 = `${API_BASE}/api/v1`;

export const endpoints = {
  // ---- auth (apps/api/src/routes/auth.ts) ----
  me: () => `${v1}/auth/me`,
  login: () => `${v1}/auth/login`,
  logout: () => `${v1}/auth/logout`,

  // ---- scans (apps/api/src/routes/scans.ts) ----
  scans: () => `${v1}/scans`,
  scan: (scanId: string) => `${v1}/scans/${scanId}`,
  scanStatus: (scanId: string) => `${v1}/scans/${scanId}/status`,
  cancelScan: (scanId: string) => `${v1}/scans/${scanId}/cancel`,

  // Implemented (A5.1) — GET /scans/:id/progress drains the orchestrator's
  // event stream non-blockingly and returns a plain `ProgressEvent[]` (see
  // apps/api/src/routes/scans.ts `drainProgress`/`toProgressEvent`).
  progress: (scanId: string) => `${v1}/scans/${scanId}/progress`,
  // Implemented (A5.2) — GET /scans/:id/appmap resolves the scan's `appMapId`
  // and returns the bare `AppMap` (apps/api/src/routes/scans.ts).
  appMap: (scanId: string) => `${v1}/scans/${scanId}/appmap`,
  // No standalone GET-estimate route exists; the client derives the estimate
  // from `scan.costEstimate` (GET /scans/:id) instead — see client.ts.
  estimate: (scanId: string) => `${v1}/scans/${scanId}/estimate`,

  // ---- gate (apps/api/src/routes/gate.ts) ----
  approveEstimate: (scanId: string) => `${v1}/scans/${scanId}/estimate/approve`,
  approveFixGate: (scanId: string) => `${v1}/scans/${scanId}/gate/approve`,

  // ---- findings / report (apps/api/src/routes/findings.ts) ----
  report: (scanId: string) => `${v1}/scans/${scanId}/report`,
  markFalsePositive: (findingId: string) => `${v1}/findings/${findingId}/false-positive`,
  // No standalone fixes/pull-requests routes; the client derives both from the
  // Report (`report.confirmedFindings[].fix`, `report.fixStatus.pullRequests`)
  // — see client.ts. Kept here only so MSW's mirrored mock handlers still work.
  fixes: (scanId: string) => `${v1}/scans/${scanId}/fixes`,
  scanPullRequests: (scanId: string) => `${v1}/scans/${scanId}/pull-requests`,
  // Implemented (A5.3) — GET /pull-requests is a real cross-scan aggregate,
  // client-scoped (apps/api/src/routes/findings.ts), sourced from the same
  // PullRequest rows the scan-scoped derivation above reads via the Report.
  pullRequests: () => `${v1}/pull-requests`,

  // ---- dast (apps/api/src/routes/dast.ts) ----
  // Implemented (A5.4) as a scan-scoped convenience wrapper — the real API
  // still models DAST authorization per TARGET (`POST /dast/targets` to
  // register, then `POST /dast/targets/:id/authorize`); this route
  // find-or-registers a DastTarget for `stagingUrl`, runs the identical
  // allowlist/production-blocked checks, authorizes it, AND writes
  // `scan.scope.stagingUrl` + `scan.approver` onto this scan — the two Scan
  // fields `computeAllowLive` (packages/orchestrator/src/fsm.ts) actually
  // reads to gate Layer 3 live DAST. See the route's doc comment in dast.ts.
  authorizeDast: (scanId: string) => `${v1}/scans/${scanId}/dast/authorize`,
  dastTargets: () => `${v1}/dast/targets`,
  authorizeDastTarget: (targetId: string) => `${v1}/dast/targets/${targetId}/authorize`,

  // Implemented — POST /scans/:id/kill (apps/api/src/routes/scans.ts) invokes
  // the orchestrator's cross-process kill switch (Redis pub/sub + DAST abort).
  killSwitch: (scanId: string) => `${v1}/scans/${scanId}/kill`,

  // ---- audit (apps/api/src/routes/audit.ts) ----
  // `/audit/export?format=json` doubles as the list endpoint (returns the raw
  // event array when format=json) — there's no separate `/audit` list route.
  // NOTE: server-side this requires operator/approver (`requireRole`); a
  // viewer hitting the audit-log nav item will get a 403 today — a known gap
  // (the API doesn't yet expose a viewer-readable audit listing).
  audit: () => `${v1}/audit/export`,
  auditVerify: () => `${v1}/audit/verify`,

  // NOT YET IMPLEMENTED — no per-scan compliance-export route. The compliance
  // tab already generates SARIF/OWASP/SOC2/ISO/CSV/JSON client-side from the
  // loaded Report (see lib/exports.ts) so this is currently unused dead
  // surface; kept only for API-shape parity.
  export: (scanId: string) => `${v1}/scans/${scanId}/export`,
} as const;

/** MSW handler patterns (path only, prefixed with API_BASE). Mirrors `endpoints`
 * for every path the client actually calls, plus a few legacy patterns kept so
 * existing mock handlers/fixtures keep compiling even though the real client no
 * longer fetches them directly (fixes/scanPullRequests/estimate — derived from
 * scan/report client-side instead, see client.ts). */
export const routePatterns = {
  me: `${v1}/auth/me`,
  login: `${v1}/auth/login`,
  logout: `${v1}/auth/logout`,
  scans: `${v1}/scans`,
  scan: `${v1}/scans/:scanId`,
  scanStatus: `${v1}/scans/:scanId/status`,
  progress: `${v1}/scans/:scanId/progress`,
  appMap: `${v1}/scans/:scanId/appmap`,
  estimate: `${v1}/scans/:scanId/estimate`,
  approveEstimate: `${v1}/scans/:scanId/estimate/approve`,
  approveFixGate: `${v1}/scans/:scanId/gate/approve`,
  report: `${v1}/scans/:scanId/report`,
  fixes: `${v1}/scans/:scanId/fixes`,
  scanPullRequests: `${v1}/scans/:scanId/pull-requests`,
  pullRequests: `${v1}/pull-requests`,
  authorizeDast: `${v1}/scans/:scanId/dast/authorize`,
  killSwitch: `${v1}/scans/:scanId/kill`,
  markFalsePositive: `${v1}/findings/:findingId/false-positive`,
  audit: `${v1}/audit/export`,
  export: `${v1}/scans/:scanId/export`,
} as const;

/**
 * CSRF header for cookie-authenticated mutations (double-submit pattern — see
 * apps/api/src/auth/csrf.ts). The API mirrors the JS-readable `montr_csrf`
 * cookie value back in this header on every mutating request.
 */
export const CSRF_HEADER = "x-csrf-token";
export const CSRF_COOKIE = "montr_csrf";

/**
 * Mock-only actor hint consumed EXCLUSIVELY by src/mocks/handlers.ts to drive
 * the dev role-switcher's simulated RBAC. Never sent when MSW is disabled
 * (guarded by `isMswEnabled` in lib/api/auth-headers.ts) and never trusted for
 * real authorization — the real API always derives the actor from the
 * verified session (JWT cookie / bearer token), never from a client header.
 * This replaces the old, spoofable `x-montr-actor-id` / `x-montr-actor-role`
 * headers that used to be sent on every request in both real and mock modes.
 */
export const MOCK_ACTOR_ID_HEADER = "x-montr-mock-actor-id";
export const MOCK_ACTOR_ROLE_HEADER = "x-montr-mock-actor-role";
