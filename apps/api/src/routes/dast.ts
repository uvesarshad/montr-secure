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
import {
  AuthorizeScanDastBodySchema,
  CreateDastTargetBodySchema,
  DastTargetIdParamsSchema,
  ScanIdParamsSchema,
} from "../schemas.js";
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

  // ⛔ Scan-scoped convenience wrapper (A5.4) around the target-based flow
  // above. apps/web's DastPanel authorizes DAST per SCAN (the operator's
  // mental model: "authorize live DAST for this scan"), matching the path and
  // body shape it has always POSTed (`/scans/:id/dast/authorize`, `{
  // stagingUrl }`) — that request just had nowhere to land server-side. The
  // real backend model authorizes per TARGET (register once, approve once,
  // reuse across scans), deliberately decoupled from any one scan; this route
  // does NOT duplicate that logic or loosen its guardrails — it enforces the
  // EXACT SAME production-blocked + allowlist checks as
  // `POST /dast/targets/:id/authorize`, then find-or-registers a DastTarget for
  // the URL and authorizes it exactly as that route would.
  //
  // It does one thing the target route alone cannot: writes
  // `scan.scope.stagingUrl` (+ `scan.approver`) onto THIS scan. That matters
  // because `computeAllowLive` (packages/orchestrator/src/fsm.ts) — the
  // function that actually gates Layer 3 live DAST execution — reads those two
  // Scan fields directly; it has no knowledge of `DastTarget` at all. Without
  // this write, authorizing a target would update the DastTarget audit trail
  // but never actually unlock live confirmation for any scan — so this wrapper
  // closes that gap for the one path a scan can take to get there.
  app.post(
    "/scans/:id/dast/authorize",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["dast"],
        summary: "Authorize live DAST for a scan against a staging target (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);
      const body = parseBody(AuthorizeScanDastBodySchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      if (config.dast.productionBlocked !== true) {
        // Locked in config as literal true; never proceed if that invariant broke.
        throw forbidden("Production DAST is blocked by policy");
      }
      if (!isAllowlisted(body.stagingUrl, config.dast.allowlist)) {
        throw new DastTargetNotAllowlistedError(
          "Target is not on the DAST allowlist (production is blocked by policy)",
          { url: body.stagingUrl },
        );
      }

      let target = await store.dastTargets.findByUrl(user.clientId, body.stagingUrl);
      if (!target) {
        target = await store.dastTargets.create({
          id: deps.idgen("dast"),
          clientId: user.clientId,
          url: body.stagingUrl,
          enabled: false,
          scopeContract: { ...config.dast.scope },
          createdAt: deps.clock.now().toISOString(),
        });
      }
      const authorizedTarget = await store.dastTargets.update(user.clientId, {
        ...target,
        enabled: true,
        approvedById: user.id,
        approvedAt: deps.clock.now().toISOString(),
      });

      const updatedScan = await store.scans.update(user.clientId, {
        ...scan,
        scope: { ...scan.scope, stagingUrl: body.stagingUrl },
        approver: user.id,
      });

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "dast.authorized",
        targetType: "scan",
        targetId: id,
        summary: `Live-DAST authorized for scan ${id} against ${body.stagingUrl}`,
        metadata: { url: body.stagingUrl, dastTargetId: authorizedTarget.id },
      });

      return { scan: updatedScan };
    },
  );
}
