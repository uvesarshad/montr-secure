/**
 * Gate approval routes.
 *
 *  - POST /scans/:id/estimate/approve  — accept the pre-scan cost estimate.
 *    Requires approver when config.rbac.approverRequiredForGate is set (default),
 *    otherwise operator or approver.
 *  - POST /scans/:id/gate/approve      — ⛔ the HUMAN FIX GATE. ALWAYS requires
 *    the approver role, regardless of config (§11, golden rule #3/#5). No code
 *    change proceeds without passing this gate.
 *
 * Both bind to audit events with the acting approver + role.
 */
import type { FastifyInstance, preHandlerHookHandler } from "fastify";
import { notFound, unauthorized } from "../errors.js";
import { parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { ScanIdParamsSchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

export function registerGateRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store, orchestrator } = deps;

  const estimateGuards: preHandlerHookHandler[] = deps.config.rbac.approverRequiredForGate
    ? [app.authenticate, app.verifyCsrf, app.requireApprover]
    : [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")];

  app.post(
    "/scans/:id/estimate/approve",
    {
      preHandler: estimateGuards,
      schema: {
        tags: ["gate"],
        summary: "Approve the pre-scan cost estimate",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.approveGate(id, "estimate", user.id);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "gate.estimate_approved",
        targetType: "scan",
        targetId: id,
        summary: `Cost estimate approved for scan ${id}`,
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );

  // ⛔ HARD approver guard — the human gate is never a config flag.
  app.post(
    "/scans/:id/gate/approve",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireApprover],
      schema: {
        tags: ["gate"],
        summary: "Approve the human fix gate (approver only)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      await orchestrator.approveGate(id, "fix", user.id);

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: id,
        actor: actorFromUser(user),
        action: "gate.fix_approved",
        targetType: "scan",
        targetId: id,
        summary: `Human fix gate approved for scan ${id}`,
      });

      const updated = await store.scans.get(user.clientId, id);
      return { scan: updated ?? scan };
    },
  );
}
