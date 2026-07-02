/**
 * Zod validation helpers. Every route validates its input with a
 * @montr/contracts (or contracts-derived) schema; failures become 400s with the
 * Zod issue list. Golden rule: validate at the boundary, trust nothing.
 */
import type { FastifyRequest } from "fastify";
import type { ZodTypeAny, z } from "zod";
import { badRequest } from "./errors.js";

function parse<S extends ZodTypeAny>(schema: S, value: unknown, where: string): z.infer<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw badRequest(`Invalid ${where}`, { issues: result.error.issues });
  }
  return result.data;
}

export function parseBody<S extends ZodTypeAny>(schema: S, req: FastifyRequest): z.infer<S> {
  return parse(schema, req.body, "request body");
}

export function parseParams<S extends ZodTypeAny>(schema: S, req: FastifyRequest): z.infer<S> {
  return parse(schema, req.params, "path parameters");
}

export function parseQuery<S extends ZodTypeAny>(schema: S, req: FastifyRequest): z.infer<S> {
  return parse(schema, req.query, "query string");
}
