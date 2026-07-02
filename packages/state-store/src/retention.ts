/**
 * Retention-policy enforcement (§10). Deletes expired scans and App Maps per
 * client (row-scoped — a retention run never touches another client's data).
 *
 * The AUDIT log is append-only and immutable by DEFAULT (`auditImmutable`,
 * hardened default ON): retention leaves it untouched so the hash chain stays
 * verifiable end-to-end. Deleting audit rows is only attempted when a deployment
 * explicitly opts out of immutability, and is documented as chain-truncating —
 * export/archive before enabling it (see notesForIntegration).
 */
import type { MontrPrismaClient } from "./prisma.js";

/** Mirrors `@montr/config` RetentionConfig (kept local to avoid a config dep). */
export interface RetentionPolicy {
  scanDays: number;
  appMapDays: number;
  auditDays: number;
  auditImmutable: boolean;
}

export interface RetentionResult {
  scansDeleted: number;
  appMapsDeleted: number;
  auditEventsDeleted: number;
}

/** Scans in a terminal state are eligible for deletion once expired. */
const TERMINAL_SCAN_STATUSES = ["completed", "failed", "cancelled", "partial"] as const;

const DAY_MS = 24 * 60 * 60 * 1000;
const daysAgo = (now: Date, days: number): Date => new Date(now.getTime() - days * DAY_MS);

export class RetentionEnforcer {
  constructor(private readonly prisma: MontrPrismaClient) {}

  /** Enforce retention for a single client. */
  async enforce(
    clientId: string,
    policy: RetentionPolicy,
    now: Date = new Date(),
  ): Promise<RetentionResult> {
    // Expired scans (cascades to findings/fixes/PRs/states/report via the schema).
    const scans = await this.prisma.scan.deleteMany({
      where: {
        clientId,
        status: { in: [...TERMINAL_SCAN_STATUSES] },
        createdAt: { lt: daysAgo(now, policy.scanDays) },
      },
    });

    // Expired App Maps (Scan.appMapId is SET NULL by the schema on delete).
    const appMaps = await this.prisma.appMap.deleteMany({
      where: { clientId, createdAt: { lt: daysAgo(now, policy.appMapDays) } },
    });

    let auditEventsDeleted = 0;
    if (!policy.auditImmutable) {
      const audit = await this.prisma.auditEvent.deleteMany({
        where: { clientId, at: { lt: daysAgo(now, policy.auditDays) } },
      });
      auditEventsDeleted = audit.count;
    }

    return {
      scansDeleted: scans.count,
      appMapsDeleted: appMaps.count,
      auditEventsDeleted,
    };
  }

  /** Enforce retention across every client. */
  async enforceAll(
    policy: RetentionPolicy,
    now: Date = new Date(),
  ): Promise<Record<string, RetentionResult>> {
    const clients = await this.prisma.client.findMany({ select: { id: true } });
    const out: Record<string, RetentionResult> = {};
    for (const c of clients) {
      out[c.id] = await this.enforce(c.id, policy, now);
    }
    return out;
  }
}
