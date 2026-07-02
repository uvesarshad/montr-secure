/**
 * HTTP error envelope + a Fastify error handler that maps typed Montr errors,
 * Zod validation failures, and plugin (JWT / rate-limit) errors to stable
 * responses. Error responses never leak stack traces or code/secret bodies.
 */
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { ZodError } from "zod";
import { isMontrError, type ErrorCode } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";

/** An error that carries an explicit HTTP status. Thrown from handlers/guards. */
export class HttpError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export const unauthorized = (message = "Authentication required") =>
  new HttpError(401, "UNAUTHENTICATED", message);
export const forbidden = (message = "Forbidden", details?: Record<string, unknown>) =>
  new HttpError(403, "FORBIDDEN", message, details);
export const notFound = (message = "Not found") => new HttpError(404, "NOT_FOUND", message);
export const badRequest = (message: string, details?: Record<string, unknown>) =>
  new HttpError(400, "BAD_REQUEST", message, details);
export const conflict = (message: string, details?: Record<string, unknown>) =>
  new HttpError(409, "CONFLICT", message, details);

/** Map a typed Montr error code to an HTTP status. */
export function montrErrorStatus(code: ErrorCode): number {
  switch (code) {
    case "CONFIG_VALIDATION":
      return 400;
    case "EGRESS_BLOCKED":
    case "DAST_TARGET_NOT_ALLOWLISTED":
    case "GATE_NOT_PASSED":
    case "KEY_TIER_REJECTED":
    case "HUMAN_APPROVAL_REQUIRED":
      return 403;
    case "BUDGET_EXCEEDED":
    case "MODEL_BELOW_FLOOR":
    case "KILL_SWITCH_ACTIVATED":
    case "SCAN_NOT_RESUMABLE":
    case "PROVIDER_NOT_CONFIGURED":
      return 409;
    case "RATE_LIMIT_EXCEEDED":
      return 429;
    case "NOT_IMPLEMENTED":
      return 501;
    case "INTERNAL":
    default:
      return 500;
  }
}

interface ErrorBody {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

function body(code: string, message: string, details?: Record<string, unknown>): ErrorBody {
  return { error: { code, message, ...(details ? { details } : {}) } };
}

export function registerErrorHandler(app: FastifyInstance, logger: Logger): void {
  app.setNotFoundHandler((req: FastifyRequest, reply: FastifyReply) => {
    reply.status(404).send(body("NOT_FOUND", `Route ${req.method} ${req.url} not found`));
  });

  app.setErrorHandler((err: FastifyError, req: FastifyRequest, reply: FastifyReply) => {
    if (err instanceof HttpError) {
      reply.status(err.statusCode).send(body(err.code, err.message, err.details));
      return;
    }
    if (err instanceof ZodError) {
      reply
        .status(400)
        .send(body("VALIDATION", "Request validation failed", { issues: err.issues }));
      return;
    }
    if (isMontrError(err)) {
      const status = montrErrorStatus(err.code);
      reply.status(status).send(body(err.code, err.message, err.details));
      return;
    }
    // @fastify/jwt raises FST_JWT_* with statusCode 401; @fastify/rate-limit 429.
    const status = typeof err.statusCode === "number" ? err.statusCode : 500;
    if (status >= 400 && status < 500) {
      reply.status(status).send(body(err.code ?? "BAD_REQUEST", err.message));
      return;
    }
    // Log message only — never the full error object (may reference request bodies).
    logger.error("unhandled_api_error", { name: err.name, msg: err.message, statusCode: status });
    reply.status(500).send(body("INTERNAL", "Internal server error"));
  });
}
