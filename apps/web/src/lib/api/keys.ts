/** Centralised React Query keys (kept free of React so both the hooks module and
 * the role context can import them without a cycle). */
export const qk = {
  session: ["session"] as const,
  scans: ["scans"] as const,
  scan: (id: string) => ["scan", id] as const,
  progress: (id: string) => ["progress", id] as const,
  appMap: (id: string) => ["appMap", id] as const,
  estimate: (id: string) => ["estimate", id] as const,
  report: (id: string) => ["report", id] as const,
  fixes: (id: string) => ["fixes", id] as const,
  scanPullRequests: (id: string) => ["scanPullRequests", id] as const,
  pullRequests: ["pullRequests"] as const,
  audit: (id?: string) => ["audit", id ?? "all"] as const,
};
