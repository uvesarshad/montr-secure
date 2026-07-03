/**
 * Findings + report retrieval and false-positive marking.
 *
 * Only CONFIRMED findings and the clearly-separated UNCONFIRMED appendix are
 * exposed — Layer-1 candidates are never surfaced to users (§7 L1, golden rule).
 * Marking a confirmed finding as a false positive is an RBAC-guarded, audited
 * mutation that closes the §15 FP-feedback loop: it is recorded in the append-only
 * audit log (authoritative), written to the regression corpus (which tunes
 * correlation/confirmation), and fed to the precision / FP-rate metric.
 */
import type { FastifyInstance } from "fastify";
import { getMetrics } from "@montr/telemetry";
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

      const markedAt = deps.clock.now().toISOString();

      // 1. Audit FIRST — the append-only, hash-chained log is the authoritative,
      // tamper-evident record of the mutation (§8.5, golden rule #7). Metadata
      // ONLY (category/location/compliance ids) — never a proof or code body so
      // the corpus can be rebuilt from the audit trail (golden rule #1).
      await recordAudit(store, {
        clientId: user.clientId,
        scanId: finding.scanId,
        actor: actorFromUser(user),
        action: "finding.marked_false_positive",
        targetType: "confirmed_finding",
        targetId: id,
        summary: `Finding '${finding.title}' marked as false positive`,
        metadata: {
          reason: body.reason,
          category: finding.category,
          cwe: finding.cwe,
          ...(finding.owasp ? { owasp: finding.owasp } : {}),
          file: finding.location.file,
          line: finding.location.line,
          severity: finding.severity,
          exposure: finding.exposure,
          proofType: finding.proofType,
        },
      });

      // 2. Feed the §15 regression corpus (best-effort). The audit log above
      // already captured the decision durably and the corpus is rebuildable from
      // it, so a corpus write hiccup must NOT fail the mutation (fail-safe).
      try {
        await deps.regressionCorpus.record({
          clientId: user.clientId,
          scanId: finding.scanId,
          findingId: id,
          category: finding.category,
          cwe: finding.cwe,
          ...(finding.owasp ? { owasp: finding.owasp } : {}),
          file: finding.location.file,
          line: finding.location.line,
          severity: finding.severity,
          exposure: finding.exposure,
          proofType: finding.proofType,
          operator: { id: user.id, role: user.role },
          reason: body.reason,
          markedAt,
        });
      } catch (err) {
        deps.logger.warn("findings.fp_corpus_write_failed", {
          findingId: id,
          error: err instanceof Error ? err.message : String(err),
        });
      }

      // 3. Observability: the headline FP-feedback rate metric (§15).
      getMetrics().recordFalsePositiveFeedback(1, { category: finding.category });

      return { ok: true, findingId: id };
    },
  );
}
