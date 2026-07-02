/**
 * Shared API types: dependency-injection surface, resolved runtime deps, the
 * JWT session claims, and Fastify type augmentation for our decorators.
 */
import type { preHandlerHookHandler } from "fastify";
import type { MontrConfig } from "@montr/config";
import type { Logger } from "@montr/telemetry";
import type { Orchestrator } from "@montr/orchestrator";
import type { Role } from "@montr/contracts";
import type { ApiStore, Clock, IdGen } from "./store.js";

/** How the current request authenticated. Drives CSRF enforcement. */
export type AuthMethod = "cookie" | "bearer";

/** Normalized authenticated principal attached to the request. */
export interface AuthenticatedUser {
  id: string;
  clientId: string;
  email: string;
  role: Role;
}

/** JWT payload. `sub` is the user id. */
export interface SessionClaims {
  sub: string;
  clientId: string;
  email: string;
  role: Role;
}

/** Dependencies required to build the API. Secrets are always injected (no defaults). */
export interface ApiServerDeps {
  config: MontrConfig;
  store: ApiStore;
  orchestrator: Orchestrator;
  /** HMAC secret for signing session JWTs. */
  jwtSecret: string;
  /** HMAC secret for CSRF tokens (distinct from jwtSecret). */
  csrfSecret: string;
  logger?: Logger;
  clock?: Clock;
  idgen?: IdGen;
  /** Set Secure attribute on cookies (default true; disable only for http dev/tests). */
  cookieSecure?: boolean;
  /** Serve the Swagger UI at /docs (default true). */
  enableSwaggerUi?: boolean;
  /** Honor X-Forwarded-* for client IP in rate limiting (default false). */
  trustProxy?: boolean;
  /**
   * Locked-down CORS allowlist. Empty/undefined => CORS disabled (same-origin
   * only), the safe default. Deploy sets the web console origin(s) here.
   */
  corsOrigins?: string[];
  /** Rate-limit overrides. */
  rateLimits?: {
    global?: { max: number; timeWindow: string | number };
    auth?: { max: number; timeWindow: string | number };
  };
}

/** Deps after defaults are applied. */
export interface ResolvedDeps {
  config: MontrConfig;
  store: ApiStore;
  orchestrator: Orchestrator;
  jwtSecret: string;
  csrfSecret: string;
  logger: Logger;
  clock: Clock;
  idgen: IdGen;
  cookieSecure: boolean;
  sessionTtlMinutes: number;
  /** Per-route rate limit applied to authentication endpoints. */
  authRate: { max: number; timeWindow: string | number };
}

declare module "fastify" {
  interface FastifyRequest {
    authUser?: AuthenticatedUser;
    authMethod?: AuthMethod;
  }
  interface FastifyInstance {
    deps: ResolvedDeps;
    /** preHandler: verify JWT (header or cookie) and attach `request.authUser`. */
    authenticate: preHandlerHookHandler;
    /** preHandler factory: require the caller to hold one of `roles`. */
    requireRole: (...roles: Role[]) => preHandlerHookHandler;
    /** ⛔ preHandler: hard-require the `approver` role (human gate + DAST auth). */
    requireApprover: preHandlerHookHandler;
    /** preHandler: enforce CSRF for cookie-authenticated mutating requests. */
    verifyCsrf: preHandlerHookHandler;
  }
}

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: SessionClaims;
    user: SessionClaims;
  }
}
