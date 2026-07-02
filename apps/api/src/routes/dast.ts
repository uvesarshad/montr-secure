/**
 * Live-DAST target authorization (DECIDE-1, §11).
 *
 * ⛔ Guardrails enforced at the HTTP layer:
 *   - Authorization ALWAYS requires the approver role (hard, never a config flag).
 *   - The target URL must be on the configured allowlist; production is blocked
 *     by policy (empty allowlist ⇒ nothing is authorizable — the safe default).
 *   - Every authorization is bound to a `dast.authorized` audit event.
 * Registering a (disabled) candidate target is a lesser, operator-level action.
 */
import type { FastifyInstance } from "fastify";
import { DastTargetNotAllowlistedError } from "@montr/contracts";
import { forbidden, notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { CreateDastTargetBodySchema, DastTargetIdParamsSchema } from "../schemas.js";
import type { DastTarget } from "../store.js";
import type { ResolvedDeps } from "../types.js";

function hostOf(value: string): string | null {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).host;
  } catch {
    return null;
  }
}

/** A URL is authorizable only if explicitly allowlisted (production stays out). */
export function isAllowlisted(url: string, allowlist: readonly string[]): boolean {
  if (allowlist.length === 0) return false;
  const targetHost = hostOf(url);
  return allowlist.some((entry) => {
    if (!entry) return false;
    if (entry === url || url.startsWith(entry)) return true;
    const entryHost = hostOf(entry);
    return entryHost !== null && targetHost !== null && entryHost === targetHost;
  });
}

export function registerDastRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store, config } = deps;

  app.post(
    "/dast/targets",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["dast"],
        summary: "Register a (disabled) live-DAST target",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(CreateDastTargetBodySchema, req);

      const existing = await store.dastTargets.findByUrl(user.clientId, body.url);
      if (existing) return { target: existing };

      const target: DastTarget = {
        id: deps.idgen("dast"),
        clientId: user.clientId,
        url: body.url,
        enabled: false,
        scopeContract: { ...config.dast.scope, ...(body.scopeContract ?? {}) },
        createdAt: deps.clock.now().toISOString(),
      };
      const created = await store.dastTargets.create(target);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "config.changed",
        targetType: "dast_target",
        targetId: created.id,
        summary: `DAST target registered (disabled): ${body.url}`,
        metadata: { url: body.url },
      });

      reply.status(201);
      return { target: created };
    },
  );

  app.get(
    "/dast/targets",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["dast"],
        summary: "List live-DAST targets",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const targets = await store.dastTargets.list(user.clientId);
      return { targets };
    },
  );

  // ⛔ Approver-only. Enforces allowlist + production-blocked at the HTTP layer.
  app.post(
    "/dast/targets/:id/authorize",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["dast"],
        summary: "Authorize a live-DAST target (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(DastTargetIdParamsSchema, req);

      const target = await store.dastTargets.get(user.clientId, id);
      if (!target) throw notFound("DAST target not found");

      if (config.dast.productionBlocked !== true) {
        // Locked in config as literal true; never proceed if that invariant broke.
        throw forbidden("Production DAST is blocked by policy");
      }
      if (!isAllowlisted(target.url, config.dast.allowlist)) {
        throw new DastTargetNotAllowlistedError(
          "Target is not on the DAST allowlist (production is blocked by policy)",
          { url: target.url },
        );
      }

      const authorized: DastTarget = {
        ...target,
        enabled: true,
        approvedById: user.id,
        approvedAt: deps.clock.now().toISOString(),
      };
      const saved = await store.dastTargets.update(user.clientId, authorized);

      await recordAudit(store, {
        clientId: user.clientId,
        actor: actorFromUser(user),
        action: "dast.authorized",
        targetType: "dast_target",
        targetId: saved.id,
        summary: `Live-DAST target authorized by approver: ${saved.url}`,
        metadata: { url: saved.url, scopeContract: saved.scopeContract },
      });

      return { target: saved };
    },
  );
}
