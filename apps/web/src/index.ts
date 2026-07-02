/**
 * @montr/web — public, framework-agnostic surface of the operator console.
 *
 * The Next.js App Router UI lives under `src/app` and is served by `next dev` /
 * `next build`. This entry re-exports only the pure (no-React) helpers — RBAC
 * nav + capabilities, formatters, pipeline-progress derivation, the typed API
 * endpoint map, and query keys — so they can be imported/tested in isolation and
 * so `tsc -b` emits a stable `dist/index.js` for the package.
 */
export * from "./lib/rbac.js";
export * from "./lib/format.js";
export * from "./lib/progress.js";
export { API_BASE, endpoints, routePatterns } from "./lib/api/config.js";
export { qk } from "./lib/api/keys.js";
export type {
  SessionResponse,
  Actor,
  ScanMutationResult,
  FalsePositiveResult,
} from "./lib/api/types.js";

export const WEB_APP_NAME = "montr-secure-web" as const;
