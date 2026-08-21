/**
 * apps/api — Fastify HTTP API + AuthN/RBAC + OpenAPI (WS-L, build-plan §4.4).
 *
 * All request/response shapes come from @montr/contracts; every mutating action
 * binds to an audit event (actor + role); the approver role is a HARD requirement
 * for the human fix gate and for DAST authorization; passwords use node:crypto
 * scrypt with a constant-time compare; cookie auth is CSRF-protected; helmet,
 * CORS (locked down) and rate-limits harden the surface.
 */

// Server assembly
export {
  buildServer,
  createApiServer,
  createInMemoryDeps,
  type ApiServer,
  type InMemoryDepsOverrides,
} from "./server.js";

// Dependency-injection + request types
export type {
  ApiServerDeps,
  ResolvedDeps,
  AuthenticatedUser,
  AuthMethod,
  SessionClaims,
} from "./types.js";

// Persistence surface
export {
  createInMemoryApiStore,
  apiStoreFromStateStore,
  InMemoryAuditLogClient,
  type ApiStore,
  type StateStoreLike,
  type ReportStore,
  type DastTargetStore,
  type DastTarget,
  type Clock,
  type IdGen,
  type UserRecord,
  type InMemoryApiStoreOptions,
  // Phase-4 (Wave 5) — scale & intelligence stores.
  type CustomRuleStore,
  type RedTeamScenarioStore,
  type ScanScheduleStore,
  type PostureStore,
} from "./store.js";

// Users + auth primitives
export {
  InMemoryUserStore,
  toPublicUser,
  EmailSchema,
  PasswordSchema,
  type UserStore,
  type PublicUser,
} from "./auth/users.js";
export {
  hashPassword,
  verifyPassword,
  DEFAULT_SCRYPT_PARAMS,
  type ScryptParams,
} from "./auth/password.js";
export {
  issueCsrfToken,
  verifyCsrfToken,
  safeEqual,
  CSRF_HEADER,
  CSRF_COOKIE,
} from "./auth/csrf.js";
export { SESSION_COOKIE } from "./auth/session.js";

// Orchestrator stub — dev/tests only. Production wires the real orchestrator
// via production-deps.ts's createProductionDeps, not this stub.
export { createStubOrchestrator, type StubOrchestratorDeps } from "./stub-orchestrator.js";

// DAST allowlist helper (also enforced at the route layer)
export { isAllowlisted } from "./routes/dast.js";

// Errors
export { HttpError, montrErrorStatus } from "./errors.js";
