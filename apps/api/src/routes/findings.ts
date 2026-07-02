/**
 * Findings + report retrieval and false-positive marking.
 *
 * Only CONFIRMED findings and the clearly-separated UNCONFIRMED appendix are
 * exposed — Layer-1 candidates are never surfaced to users (§7 L1, golden rule).
 * Marking a confirmed finding as a false positive is an audited mutation that
 * feeds the §15 FP-feedback loop via the append-only audit log.
 */
import type { FastifyInstance } from "fastify";
import { notFound, unauthorized } from "../errors.js";
import { parseBody, parseParams } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import {
  FindingIdParamsSchema,
  MarkFalsePositiveBodySchema,
  ScanIdParamsSchema,
} from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

export function registerFindingRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  app.get(
    "/scans/:id/findings",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["findings"],
        summary: "Confirmed findings + unconfirmed appendix for a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      const [confirmed, unconfirmed] = await Promise.all([
        store.confirmed.listByScan(user.clientId, id),
        store.unconfirmed.listByScan(user.clientId, id),
      ]);
      return { confirmed, unconfirmed };
    },
  );

  app.get(
    "/scans/:id/report",
    {
      preHandler: app.authenticate,
      schema: {
        tags: ["findings"],
        summary: "Retrieve the report for a scan",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(ScanIdParamsSchema, req);

      const scan = await store.scans.get(user.clientId, id);
      if (!scan) throw notFound("Scan not found");

      const report = await store.reports.getByScan(user.clientId, id);
      if (!report) throw notFound("Report not available for this scan yet");
      return { report };
    },
  );

  // Operators and approvers may flag false positives; viewers may not.
  app.post(
    "/findings/:id/false-positive",
    {
      preHandler: [app.authenticate, app.verifyCsrf, app.requireRole("operator", "approver")],
      schema: {
        tags: ["findings"],
        summary: "Mark a confirmed finding as a false positive",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const { id } = parseParams(FindingIdParamsSchema, req);
      const body = parseBody(MarkFalsePositiveBodySchema, req);

      const finding = await store.confirmed.get(user.clientId, id);
      if (!finding) throw notFound("Confirmed finding not found");

      await recordAudit(store, {
        clientId: user.clientId,
        scanId: finding.scanId,
        actor: actorFromUser(user),
        action: "finding.marked_false_positive",
        targetType: "confirmed_finding",
        targetId: id,
        summary: `Finding '${finding.title}' marked as false positive`,
        metadata: { reason: body.reason, category: finding.category },
      });

      return { ok: true, findingId: id };
    },
  );
}
