/**
 * OpenAPI docs via @fastify/swagger (+ optional Swagger UI at /docs). Must be
 * registered BEFORE routes so the onRoute hook captures every path.
 */
import fastifySwagger from "@fastify/swagger";
import fastifySwaggerUi from "@fastify/swagger-ui";
import type { FastifyInstance } from "fastify";
import { CSRF_HEADER } from "../auth/csrf.js";
import { SESSION_COOKIE } from "../auth/session.js";

export async function registerSwagger(
  app: FastifyInstance,
  opts: { enableSwaggerUi: boolean },
): Promise<void> {
  await app.register(fastifySwagger, {
    openapi: {
      openapi: "3.1.0",
      info: {
        title: "Montr Secure API",
        description:
          "HTTP API for the Montr Secure platform: auth, scan lifecycle, cost/gate approval, " +
          "DAST authorization, findings/report retrieval, false-positive marking, and audit export.",
        version: "1.0.0",
      },
      components: {
        securitySchemes: {
          bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
          cookieAuth: { type: "apiKey", in: "cookie", name: SESSION_COOKIE },
          csrfToken: {
            type: "apiKey",
            in: "header",
            name: CSRF_HEADER,
            description: "Required for cookie-authenticated mutating requests.",
          },
        },
      },
      tags: [
        { name: "auth", description: "Registration, login, session, RBAC" },
        { name: "scans", description: "Scan lifecycle (create/list/get/status)" },
        { name: "gate", description: "Cost-estimate and human fix-gate approval" },
        { name: "dast", description: "Live-DAST target authorization (approver only)" },
        { name: "findings", description: "Confirmed/unconfirmed findings + report retrieval" },
        { name: "audit", description: "Tamper-evident audit-log export" },
        { name: "system", description: "Health and readiness" },
      ],
    },
  });

  if (opts.enableSwaggerUi) {
    await app.register(fastifySwaggerUi, {
      routePrefix: "/docs",
      uiConfig: { docExpansion: "list", deepLinking: true },
    });
  }
}
