/**
 * Audit-log export for third-party auditors (§13). The log is append-only and
 * hash-chained; a chain-verification endpoint proves tamper-evidence (§14).
 * Export itself is an audited action (`export.generated`).
 */
import type { FastifyInstance } from "fastify";
import type { AuditEvent } from "@montr/contracts";
import { unauthorized } from "../errors.js";
import { parseQuery } from "../validation.js";
import { actorFromUser, recordAudit } from "../audit.js";
import { AuditExportQuerySchema } from "../schemas.js";
import type { ResolvedDeps } from "../types.js";

const CSV_COLUMNS = [
  "sequence",
  "at",
  "action",
  "actorType",
  "actorId",
  "actorRole",
  "targetType",
  "targetId",
  "scanId",
  "summary",
  "prevHash",
  "hash",
] as const;

function csvCell(value: unknown): string {
  const s = value === undefined || value === null ? "" : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(events: AuditEvent[]): string {
  const header = CSV_COLUMNS.join(",");
  const rows = events.map((e) =>
    [
      e.sequence,
      e.at,
      e.action,
      e.actor.type,
      e.actor.id,
      e.actor.role ?? "",
      e.targetType ?? "",
      e.targetId ?? "",
      e.scanId ?? "",
      e.summary,
      e.prevHash,
      e.hash,
    ]
      .map(csvCell)
      .join(","),
  );
  return [header, ...rows].join("\r\n");
}

export function registerAuditRoutes(app: FastifyInstance, deps: ResolvedDeps): void {
  const { store } = deps;

  app.get(
    "/audit/export",
    {
      preHandler: [app.authenticate, app.requireRole("operator", "approver")],
      schema: {
        tags: ["audit"],
        summary: "Export the audit log (JSON or CSV)",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req, reply) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const q = parseQuery(AuditExportQuerySchema, req);

      const events = await store.audit.list(user.clientId, {
        ...(q.scanId ? { scanId: q.scanId } : {}),
        ...(q.limit !== undefined ? { limit: q.limit } : {}),
        ...(q.fromSequence !== undefined ? { fromSequence: q.fromSequence } : {}),
      });

      // Audit the export AFTER snapshotting the list (keeps the export event out
      // of its own output and avoids recursion).
      await recordAudit(store, {
        clientId: user.clientId,
        ...(q.scanId ? { scanId: q.scanId } : {}),
        actor: actorFromUser(user),
        action: "export.generated",
        targetType: "audit_log",
        summary: `Audit log exported (${q.format}, ${events.length} events)`,
        metadata: { format: q.format, count: events.length },
      });

      const suffix = q.scanId ? `-${q.scanId}` : "";
      reply.header(
        "content-disposition",
        `attachment; filename="audit-${user.clientId}${suffix}.${q.format}"`,
      );

      if (q.format === "csv") {
        reply.type("text/csv; charset=utf-8");
        return toCsv(events);
      }
      reply.type("application/json");
      return events;
    },
  );

  app.get(
    "/audit/verify",
    {
      preHandler: [app.authenticate, app.requireRole("operator", "approver")],
      schema: {
        tags: ["audit"],
        summary: "Verify the audit-log hash chain is intact",
        security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      },
    },
    async (req) => {
      const user = req.authUser;
      if (!user) throw unauthorized();
      const intact = await store.audit.verifyChain(user.clientId);
      return { intact };
    },
  );
}
