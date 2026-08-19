/**
 * Scan lifecycle routes: create / list / get / status / cancel.
 * Mutations call the orchestrator's lifecycle API and are bound to audit events.
 * Reads are client-scoped (per-client isolation — never cross-tenant).
 */
import type { FastifyInstance } from "fastify";
import { ScanScopeSchema } from "@montr/contracts";
import type { CreateScanInput } from "@montr/orchestrator";
import { notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { CreateScanBodySchema, KillScanBodySchema, ScanIdParamsSchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

export function registerScanRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store, orchestrator, clock } = deps;

  app.post(
    "/scans",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "Create a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const body = parseBody(CreateScanBodySchema, req);

      const scope = ScanScopeSchema.parse({ ...(body.scope ?? {}), mode: body.mode });
      const input: CreateScanInput = {
        clientId: user.clientId,
        repo: body.repo,
        branch: body.branch,
        mode: body.mode,
        scope,
        operator: user.id,
        ...(body.budgetPolicy ? { budgetPolicy: body.budgetPolicy } : {}),
      };

      const scan = await orchestrator.createScan(input);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: scan.id,
        actor: actorFromUser(user),
        action: "scan.created",
        targetType: "scan",
        targetId: scan.id,
        summary: `Scan created for ${body.repo}@${body.branch} (${body.mode})`,
        metadata: { repo: body.repo, branch: body.branch, mode: body.mode },
      });

      reply.status(201);
      return { scan };
    },
  );

  app.get(
    "/scans",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "List scans for the client",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const scans = await store.scans.list(user.clientId);
      return { scans };
    },
  );

  app.get(
    "/scans/:id",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "Get a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);
      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");
      return { scan };
    },
  );

  app.get(
    "/scans/:id/status",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["scans"],
        summary: "Scan status + gate state",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      let scan;
      try {
        scan = await orchestrator.status(id);
      } catch {
        throw notFound("Scan not found");
      }
      // Enforce per-client isolation — the lifecycle API is not tenant-scoped.
      if (scan.clientId !== user.clientId) throw notFound("Scan not found");

      return {
        scanId: scan.id,
        status: scan.status,
        gateState: scan.gateState,
        costEstimate: scan.costEstimate ?? null,
        costActual: scan.costActual ?? null,
      };
    },
  );

  app.post(
    "/scans/:id/cancel",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "Cancel a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.cancel(id);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "scan.cancelled",
        targetType: "scan",
        targetId: id,
        summary: `Scan ${id} cancelled`,
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );

  // ⛔ Kill switch — halts all active work for this scan immediately (esp. live
  // DAST probing), via the orchestrator's cross-process kill (Redis pub/sub +
  // AbortController, §11). Same role bar as cancel/create: operator or approver
  // (mirrors apps/web's canActivateKillSwitch) — a kill switch must stay easy to
  // reach for whoever is running the scan, not gated behind approver-only, which
  // is why this uses `requireRole` (not the hard `requireApprover` guard used
  // by the fix gate / DAST authorization routes).
  app.post(
    "/scans/:id/kill",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["scans"],
        summary: "⛔ Kill switch — halt a scan immediately",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);
      const body = parseBody(KillScanBodySchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.kill({
        scope: "scan",
        scanId: id,
        reason: body.reason,
        requestedBy: user.id,
        requestedByRole: user.role,
        at: clock.now().toISOString(),
      });

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "dast.kill_switch",
        targetType: "scan",
        targetId: id,
        summary: `Kill switch activated for scan ${id}: ${body.reason}`,
        metadata: { reason: body.reason },
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );
}
