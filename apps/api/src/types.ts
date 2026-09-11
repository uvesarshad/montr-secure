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
import type { RegressionCorpusRecorder } from "./fp-corpus.js";
import type { ScenarioRunProducer } from "./scenario-run-producer.js";
import type { HecHttpClient } from "@montr/report";

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
  /**
   * §15 regression-corpus sink for false-positive feedback. Optional; defaults to
   * a fail-safe no-op (the audit log remains authoritative). Production injects
   * @montr/qa's `corpusRecorder(new FileRegressionCorpus(path))`.
   */
  regressionCorpus?: RegressionCorpusRecorder;
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
  /**
   * Webhook scan-trigger config (A15, `POST /webhooks/scan-trigger`). Unset =
   * the route is disabled (fail-closed default, consistent with every other
   * hardened default — see docs/infra/environment.md `MONTR_WEBHOOK_SECRET`).
   */
  webhook?: {
    /** HMAC secret verifying inbound `X-Hub-Signature-256` signatures. */
    secret: string;
    /**
     * Email of an existing operator/approver user, used to attribute
     * webhook-triggered scans (`Scan.operator` has a required FK to `User` —
     * there is no unauthenticated "system user" row to fall back to).
     */
    operatorEmail: string;
    /** Optional: post a PR summary comment when the payload carries PR info. */
    githubToken?: string;
  };
  /**
   * A1 (2026-09-12) — produce-only enqueue for real worker-side red-team
   * scenario execution (`POST /scenarios/:id/run`). Optional; defaults to a
   * fail-safe in-memory producer (dev/tests — see `createInMemoryDeps`).
   * Production injects `createBullMqScenarioRunProducer` (production-deps.ts).
   */
  scenarioRunProducer?: ScenarioRunProducer;
  /**
   * Suggested enhancement (2026-09-12 red/blue agentic-posture audit) —
   * injectable HTTP client for the Splunk HEC detection-rule push adapter
   * (`POST /detection-rules/push`). Optional; production leaves it unset, so
   * `createDetectionRulePusher` falls back to its real lazy `undici` import
   * (see packages/report/src/detection-rules/push/splunk-hec.ts). Tests
   * inject a fake here instead of mocking the `undici` module directly.
   */
  detectionRulePushHttpClient?: HecHttpClient;
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
  /** §15 regression-corpus sink (defaults to a fail-safe no-op). */
  regressionCorpus: RegressionCorpusRecorder;
  /** Webhook scan-trigger config (A15). Undefined = route disabled. */
  webhook?: ApiServerDeps["webhook"];
  /** A1 — real worker-side scenario-execution enqueue (see ApiServerDeps). */
  scenarioRunProducer: ScenarioRunProducer;
  /** Suggested enhancement — injectable HTTP client for the Splunk HEC push adapter (see ApiServerDeps). Undefined in production = the adapter's real lazy `undici` import. */
  detectionRulePushHttpClient?: HecHttpClient;
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
