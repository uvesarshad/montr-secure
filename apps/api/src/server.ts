/**
 * Server assembly. `buildServer` wires plugins + routes and returns a ready
 * Fastify instance (used directly by tests via `app.inject`). `createApiServer`
 * wraps it with listen/close. `createInMemoryDeps` provides a fully in-memory
 * dependency set (store + stub orchestrator + random secrets) for local dev and
 * unit tests.
 */
import { randomBytes, randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { ConfigValidationError } from "@montr/contracts";
import { getHardenedDefaults, type MontrConfig } from "@montr/config";
import { assertStartupEgress } from "@montr/security";
import { createLogger } from "@montr/telemetry";
import { registerSecurity } from "./plugins/security.js";
import { registerAuth } from "./plugins/auth-plugin.js";
import { registerSwagger } from "./plugins/swagger-plugin.js";
import { registerRoutes } from "./routes/index.js";
import { registerErrorHandler } from "./errors.js";
import { createInMemoryApiStore, type ApiStore, type Clock, type IdGen } from "./store.js";
import { createStubOrchestrator } from "./stub-orchestrator.js";
import { noopRegressionCorpus, type RegressionCorpusRecorder } from "./fp-corpus.js";
import type { ApiServerDeps, ResolvedDeps } from "./types.js";

const DEFAULT_GLOBAL_RATE = { max: 300, timeWindow: "1 minute" } as const;
const DEFAULT_AUTH_RATE = { max: 20, timeWindow: "1 minute" } as const;
const MIN_JWT_SECRET = 32;
const MIN_CSRF_SECRET = 16;

function resolveDeps(deps: ApiServerDeps): ResolvedDeps {
  if (!deps.jwtSecret || deps.jwtSecret.length < MIN_JWT_SECRET) {
    throw new ConfigValidationError(`jwtSecret must be at least ${MIN_JWT_SECRET} characters`);
  }
  if (!deps.csrfSecret || deps.csrfSecret.length < MIN_CSRF_SECRET) {
    throw new ConfigValidationError(`csrfSecret must be at least ${MIN_CSRF_SECRET} characters`);
  }
  const clock: Clock = deps.clock ?? { now: () => new Date() };
  const idgen: IdGen = deps.idgen ?? ((prefix = "id") => `${prefix}_${randomUUID()}`);
  return {
    config: deps.config,
    store: deps.store,
    orchestrator: deps.orchestrator,
    jwtSecret: deps.jwtSecret,
    csrfSecret: deps.csrfSecret,
    logger:
      deps.logger ??
      createLogger({ name: "montr-api", bindings: { clientId: deps.config.clientId } }),
    clock,
    idgen,
    cookieSecure: deps.cookieSecure ?? true,
    sessionTtlMinutes: deps.config.rbac.sessionTtlMinutes,
    authRate: deps.rateLimits?.auth ?? DEFAULT_AUTH_RATE,
    regressionCorpus: deps.regressionCorpus ?? noopRegressionCorpus,
  };
}

/** Build a ready-to-serve Fastify instance. */
export async function buildServer(deps: ApiServerDeps): Promise<FastifyInstance> {
  const resolved = resolveDeps(deps);
  const enableSwaggerUi = deps.enableSwaggerUi ?? true;

  const app = Fastify({
    logger: false,
    trustProxy: deps.trustProxy ?? false,
    bodyLimit: 1_000_000,
  });

  app.decorate("deps", resolved);

  await registerSecurity(app, {
    enableSwaggerUi,
    corsOrigins: deps.corsOrigins ?? [],
    globalRate: deps.rateLimits?.global ?? DEFAULT_GLOBAL_RATE,
  });
  await registerSwagger(app, { enableSwaggerUi });
  await registerAuth(app, resolved);

  registerRoutes(app, resolved);
  registerErrorHandler(app, resolved.logger);

  await app.ready();
  return app;
}

export interface ApiServer {
  /** The underlying Fastify instance (available after `listen`). */
  readonly app?: FastifyInstance;
  listen(port: number, host?: string): Promise<void>;
  close(): Promise<void>;
}

/** Wrap `buildServer` with listen/close for process hosting (deploy). */
export function createApiServer(deps: ApiServerDeps): ApiServer {
  let app: FastifyInstance | undefined;
  return {
    get app() {
      return app;
    },
    async listen(port: number, host = "0.0.0.0"): Promise<void> {
      // ⛔ Golden rule #1 / §4.8: validate the default-deny egress policy at real
      // process boot (not in buildServer, which unit tests drive via app.inject).
      // Throws on a non-default-deny policy or an unreachable LLM endpoint.
      const bootLogger =
        deps.logger ??
        createLogger({ name: "montr-api", bindings: { clientId: deps.config.clientId } });
      assertStartupEgress(deps.config, {
        onWarning: (message) => bootLogger.warn("egress.warning", { message }),
      });
      app = await buildServer(deps);
      await app.listen({ port, host });
    },
    async close(): Promise<void> {
      await app?.close();
    },
  };
}

export interface InMemoryDepsOverrides {
  config?: MontrConfig;
  store?: ApiStore;
  jwtSecret?: string;
  csrfSecret?: string;
  clock?: Clock;
  idgen?: IdGen;
  cookieSecure?: boolean;
  enableSwaggerUi?: boolean;
  corsOrigins?: string[];
  rateLimits?: ApiServerDeps["rateLimits"];
  /** §15 regression-corpus sink (defaults to a fail-safe no-op). */
  regressionCorpus?: RegressionCorpusRecorder;
}

/**
 * Build a fully in-memory ApiServerDeps (store + stub orchestrator + random
 * secrets). For local dev and unit tests only — never production.
 */
export function createInMemoryDeps(overrides: InMemoryDepsOverrides = {}): ApiServerDeps {
  const config = overrides.config ?? getHardenedDefaults();
  const clock: Clock = overrides.clock ?? { now: () => new Date() };
  const idgen: IdGen = overrides.idgen ?? ((prefix = "id") => `${prefix}_${randomUUID()}`);
  const store = overrides.store ?? createInMemoryApiStore({ clock, idgen });
  const orchestrator = createStubOrchestrator({ store, clock, idgen });
  return {
    config,
    store,
    orchestrator,
    jwtSecret: overrides.jwtSecret ?? randomBytes(32).toString("hex"),
    csrfSecret: overrides.csrfSecret ?? randomBytes(32).toString("hex"),
    clock,
    idgen,
    // http-friendly defaults for dev/tests; production defaults to secure cookies.
    cookieSecure: overrides.cookieSecure ?? false,
    enableSwaggerUi: overrides.enableSwaggerUi ?? false,
    ...(overrides.corsOrigins ? { corsOrigins: overrides.corsOrigins } : {}),
    ...(overrides.rateLimits ? { rateLimits: overrides.rateLimits } : {}),
    ...(overrides.regressionCorpus ? { regressionCorpus: overrides.regressionCorpus } : {}),
  };
}
