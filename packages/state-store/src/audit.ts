/**
 * Append-only, hash-chained audit log (§8.5, §14). Records every agent action,
 * every LLM call (metadata only — never code bodies, golden rule #1), every code
 * modification, and every human approval. Tamper-evident: each row's `hash`
 * covers the whole event plus the previous hash (see ./hash-chain).
 *
 * The append is transactional + serialized so per-client `sequence` numbers are
 * gap-free and monotonic; a concurrent writer that loses the (clientId, sequence)
 * unique race retries. Metadata is scrubbed on the way in (defense in depth) so a
 * caller can never persist a secret or code body.
 */
import { randomUUID } from "node:crypto";
import type { ActorType, AuditAction, AuditEvent, AuditEventInput } from "@montr/contracts";
import { scrubValue, type AuditListOptions, type AuditLogClient } from "@montr/telemetry";
import { hashAuditEvent, verifyChainRecords, type ChainVerification } from "./hash-chain.js";
import { Prisma, fromJson, toJson, type MontrPrismaClient } from "./prisma.js";
import { toIso } from "./mappers.js";

const MAX_APPEND_ATTEMPTS = 5;

interface AuditEventRow {
  id: string;
  clientId: string;
  sequence: number;
  scanId: string | null;
  actorType: string;
  actorId: string;
  actorRole: "operator" | "approver" | "viewer" | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  summary: string;
  metadata: Prisma.JsonValue;
  prevHash: string;
  hash: string;
  at: Date;
}

function rowToEvent(row: AuditEventRow): AuditEvent {
  return {
    id: row.id,
    clientId: row.clientId,
    sequence: row.sequence,
    scanId: row.scanId ?? undefined,
    actor: {
      type: row.actorType as ActorType,
      id: row.actorId,
      role: row.actorRole ?? undefined,
    },
    action: row.action as AuditAction,
    targetType: row.targetType ?? undefined,
    targetId: row.targetId ?? undefined,
    summary: row.summary,
    metadata: fromJson<Record<string, unknown>>(row.metadata) ?? {},
    prevHash: row.prevHash,
    hash: row.hash,
    at: toIso(row.at),
  };
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002";
}

export class PrismaAuditLogClient implements AuditLogClient {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async append(input: AuditEventInput): Promise<AuditEvent> {
    const scrubbedMetadata = scrubValue(input.metadata ?? {}) as Record<string, unknown>;

    for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
      try {
        return await this.prisma.$transaction(
          async (tx) => {
            const last = await tx.auditEvent.findFirst({
              where: { clientId: input.clientId },
              orderBy: { sequence: "desc" },
            });
            const sequence = (last?.sequence ?? 0) + 1;
            const prevHash = last?.hash ?? "";
            const id = randomUUID();
            const at = new Date();

            // Build the canonical draft, then hash it with the SAME payload
            // builder verifyChain uses — the two can never drift.
            const draft: AuditEvent = {
              id,
              clientId: input.clientId,
              sequence,
              scanId: input.scanId,
              actor: input.actor,
              action: input.action,
              targetType: input.targetType,
              targetId: input.targetId,
              summary: input.summary,
              metadata: scrubbedMetadata,
              prevHash,
              hash: "",
              at: at.toISOString(),
            };
            const hash = hashAuditEvent(draft, prevHash);

            const row = await tx.auditEvent.create({
              data: {
                id,
                clientId: input.clientId,
                sequence,
                scanId: input.scanId ?? null,
                actorType: input.actor.type,
                actorId: input.actor.id,
                actorRole: input.actor.role ?? null,
                action: input.action,
                targetType: input.targetType ?? null,
                targetId: input.targetId ?? null,
                summary: input.summary,
                metadata: toJson(scrubbedMetadata),
                prevHash,
                hash,
                at,
              },
            });
            return rowToEvent(row as unknown as AuditEventRow);
          },
          { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
        );
      } catch (err) {
        if (isUniqueViolation(err) && attempt < MAX_APPEND_ATTEMPTS - 1) continue;
        throw err;
      }
    }
    throw new Error("audit append failed: could not obtain a unique sequence after retries");
  }

  async list(clientId: string, opts?: AuditListOptions): Promise<AuditEvent[]> {
    const rows = await this.prisma.auditEvent.findMany({
      where: {
        clientId,
        ...(opts?.scanId ? { scanId: opts.scanId } : {}),
        ...(opts?.fromSequence ? { sequence: { gte: opts.fromSequence } } : {}),
      },
      orderBy: { sequence: "asc" },
      ...(opts?.limit ? { take: opts.limit } : {}),
    });
    return rows.map((r) => rowToEvent(r as unknown as AuditEventRow));
  }

  /** Ordered full chain for a client (used by verify + export). */
  private async fullChain(clientId: string): Promise<AuditEvent[]> {
    const rows = await this.prisma.auditEvent.findMany({
      where: { clientId },
      orderBy: { sequence: "asc" },
    });
    return rows.map((r) => rowToEvent(r as unknown as AuditEventRow));
  }

  async verifyChain(clientId: string): Promise<boolean> {
    return (await this.verifyChainDetailed(clientId)).ok;
  }

  /** Verify the chain and report where it broke (tamper location). */
  async verifyChainDetailed(clientId: string): Promise<ChainVerification> {
    return verifyChainRecords(await this.fullChain(clientId));
  }

  /** Export the audit trail as pretty JSON (for third-party auditors, §13). */
  async exportJson(clientId: string): Promise<string> {
    const events = await this.fullChain(clientId);
    const verification = verifyChainRecords(events);
    return JSON.stringify(
      {
        clientId,
        exportedAt: new Date().toISOString(),
        count: events.length,
        chainVerified: verification.ok,
        ...(verification.ok ? {} : { chainBrokenAt: verification.brokenAt }),
        events,
      },
      null,
      2,
    );
  }

  /** Export the audit trail as CSV. Metadata is emitted as a JSON string cell. */
  async exportCsv(clientId: string): Promise<string> {
    const events = await this.fullChain(clientId);
    const header = [
      "sequence",
      "at",
      "action",
      "actorType",
      "actorId",
      "actorRole",
      "scanId",
      "targetType",
      "targetId",
      "summary",
      "prevHash",
      "hash",
      "metadata",
    ];
    const lines = [header.join(",")];
    for (const e of events) {
      lines.push(
        [
          e.sequence,
          e.at,
          e.action,
          e.actor.type,
          e.actor.id,
          e.actor.role ?? "",
          e.scanId ?? "",
          e.targetType ?? "",
          e.targetId ?? "",
          e.summary,
          e.prevHash,
          e.hash,
          JSON.stringify(e.metadata),
        ]
          .map(csvCell)
          .join(","),
      );
    }
    return lines.join("\n");
  }
}

function csvCell(value: unknown): string {
  const s = String(value ?? "");
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

export type AuditExportFormat = "json" | "csv";

/** Convenience export dispatcher used by the API/report exporters. */
export async function exportAuditLog(
  client: PrismaAuditLogClient,
  clientId: string,
  format: AuditExportFormat,
): Promise<{ content: string; contentType: string; filename: string }> {
  if (format === "csv") {
    return {
      content: await client.exportCsv(clientId),
      contentType: "text/csv",
      filename: `audit-${clientId}.csv`,
    };
  }
  return {
    content: await client.exportJson(clientId),
    contentType: "application/json",
    filename: `audit-${clientId}.json`,
  };
}
