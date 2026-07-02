/**
 * API hardening: secure headers (@fastify/helmet), locked-down CORS
 * (@fastify/cors), and rate limiting (@fastify/rate-limit).
 */
import fastifyCors from "@fastify/cors";
import fastifyHelmet from "@fastify/helmet";
import fastifyRateLimit from "@fastify/rate-limit";
import type { FastifyInstance } from "fastify";
import { CSRF_HEADER } from "../auth/csrf.js";

export interface SecurityOptions {
  enableSwaggerUi: boolean;
  corsOrigins: string[];
  globalRate: { max: number; timeWindow: string | number };
}

export async function registerSecurity(app: FastifyInstance, opts: SecurityOptions): Promise<void> {
  await app.register(fastifyHelmet, {
    // When the Swagger UI is served, relax CSP just enough for its assets;
    // otherwise use helmet's strict defaults.
    contentSecurityPolicy: opts.enableSwaggerUi
      ? {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
          },
        }
      : undefined,
    // API responses are not embedded cross-origin; keep the rest of the strict
    // defaults (HSTS, noSniff, frameguard, referrerPolicy, ...).
  });

  // Locked down: no cross-origin access unless an explicit allowlist is set.
  await app.register(fastifyCors, {
    origin: opts.corsOrigins.length > 0 ? opts.corsOrigins : false,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["content-type", "authorization", CSRF_HEADER],
    maxAge: 600,
  });

  await app.register(fastifyRateLimit, {
    global: true,
    max: opts.globalRate.max,
    timeWindow: opts.globalRate.timeWindow,
    // Render the shared error-envelope shape for the 429 (status set by plugin).
    errorResponseBuilder: (_req, context) => ({
      error: {
        code: "RATE_LIMIT_EXCEEDED",
        message: `Too many requests. Retry after ${context.after}.`,
      },
    }),
  });
}
