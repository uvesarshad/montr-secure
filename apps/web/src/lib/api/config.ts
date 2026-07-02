/**
 * API endpoint map. The web app is a thin, contract-typed client; `apps/api`
 * (WS-L / integration) implements these routes for real. Until then MSW mocks
 * them (see src/mocks). Client and mock handlers share `API_BASE` so a single
 * origin drives both the browser worker and the node (test) server.
 */
export const API_BASE: string = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:3000";

const v1 = `${API_BASE}/api/v1`;

export const endpoints = {
  me: () => `${v1}/me`,
  scans: () => `${v1}/scans`,
  scan: (scanId: string) => `${v1}/scans/${scanId}`,
  progress: (scanId: string) => `${v1}/scans/${scanId}/progress`,
  appMap: (scanId: string) => `${v1}/scans/${scanId}/appmap`,
  estimate: (scanId: string) => `${v1}/scans/${scanId}/estimate`,
  approveEstimate: (scanId: string) => `${v1}/scans/${scanId}/gate/estimate`,
  approveFixGate: (scanId: string) => `${v1}/scans/${scanId}/gate/fix`,
  report: (scanId: string) => `${v1}/scans/${scanId}/report`,
  fixes: (scanId: string) => `${v1}/scans/${scanId}/fixes`,
  scanPullRequests: (scanId: string) => `${v1}/scans/${scanId}/pull-requests`,
  pullRequests: () => `${v1}/pull-requests`,
  authorizeDast: (scanId: string) => `${v1}/scans/${scanId}/dast/authorize`,
  killSwitch: (scanId: string) => `${v1}/scans/${scanId}/kill`,
  markFalsePositive: (scanId: string, findingId: string) =>
    `${v1}/scans/${scanId}/findings/${findingId}/false-positive`,
  audit: () => `${v1}/audit`,
  export: (scanId: string) => `${v1}/scans/${scanId}/export`,
} as const;

/** MSW handler patterns (path only, prefixed with API_BASE). */
export const routePatterns = {
  me: `${v1}/me`,
  scans: `${v1}/scans`,
  scan: `${v1}/scans/:scanId`,
  progress: `${v1}/scans/:scanId/progress`,
  appMap: `${v1}/scans/:scanId/appmap`,
  estimate: `${v1}/scans/:scanId/estimate`,
  approveEstimate: `${v1}/scans/:scanId/gate/estimate`,
  approveFixGate: `${v1}/scans/:scanId/gate/fix`,
  report: `${v1}/scans/:scanId/report`,
  fixes: `${v1}/scans/:scanId/fixes`,
  scanPullRequests: `${v1}/scans/:scanId/pull-requests`,
  pullRequests: `${v1}/pull-requests`,
  authorizeDast: `${v1}/scans/:scanId/dast/authorize`,
  killSwitch: `${v1}/scans/:scanId/kill`,
  markFalsePositive: `${v1}/scans/:scanId/findings/:findingId/false-positive`,
  audit: `${v1}/audit`,
  export: `${v1}/scans/:scanId/export`,
} as const;

export const ACTOR_ID_HEADER = "x-montr-actor-id";
export const ACTOR_ROLE_HEADER = "x-montr-actor-role";
