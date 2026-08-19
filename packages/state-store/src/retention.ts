/**
 * Retention-policy enforcement (§10). Deletes expired scans and App Maps per
 * client (row-scoped — a retention run never touches another client's data).
 *
 * The AUDIT log is append-only and immutable, ENFORCED AT THE DATABASE LAYER:
 * migration `3_audit_immutability_trigger` installs a Postgres trigger on
 * "AuditEvent" that rejects every UPDATE and DELETE, for every role, at the
 * engine level — not just when the application chooses not to issue one. That
 * makes deletion impossible regardless of which credential is asking, closing
 * the gap where a compromised application-layer DB credential could rewrite
 * history and defeat the hash chain's tamper-evidence.
 *
 * `auditImmutable` is therefore now a documented no-op: the field is kept on
 * `RetentionPolicy` for backward config compatibility (existing deployments
 * may still set it), but retention never attempts to delete audit rows, and
 * setting it to `false` does NOT permit deletion any more — the DB trigger is
 * the sole source of truth for that, not this flag. There is no legitimate
 * app-layer path to truncate the audit log; export/archive old rows instead
 * of deleting them if long-term storage growth becomes a concern.
 */
import type { MontrPrismaClient } from "./prisma.js";

/** Mirrors `@montr/config` RetentionConfig (kept local to avoid a config dep). */
export interface RetentionPolicy {
  scanDays: number;
  appMapDays: number;
  auditDays: number;
  /**
   * @deprecated No-op, kept only for backward config compatibility. Audit-row
   * deletion is now unconditionally rejected by a DB-level trigger (see the
   * module doc above) regardless of this flag's value — it no longer gates
   * anything in this class.
   */
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

    // Audit rows are never deleted here, regardless of `policy.auditImmutable`
    // (deprecated no-op — see module doc): a DB-level trigger from migration
    // `3_audit_immutability_trigger` rejects every UPDATE/DELETE on
    // "AuditEvent" unconditionally, so an attempt here could never succeed and
    // this dead code path has been removed rather than left to hard-fail.
    return {
      scansDeleted: scans.count,
      appMapsDeleted: appMaps.count,
      auditEventsDeleted: 0,
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
