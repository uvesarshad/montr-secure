/**
 * Prisma-backed production stores for the entities apps/api owns directly.
 *
 * `@montr/state-store`'s Prisma schema already defines `User` and `DastTarget`
 * (see packages/state-store/prisma/schema.prisma) and its own migrations create
 * the tables, but no repository class for either was ever added there — see the
 * header comment in ./auth/users.ts: "the canonical User entity lives in the
 * Prisma schema ... and will be surfaced by @montr/state-store; until then the
 * API depends on this narrow UserStore interface ... and ships an in-memory
 * implementation". That hand-off never landed. Rather than leave production
 * silently running on the in-memory stores (data lost on every restart) or
 * reach into @montr/state-store (out of this change's scope), this file queries
 * the already-existing tables directly through the shared Prisma client — real
 * production wiring against real, already-migrated infrastructure, not new
 * infrastructure.
 *
 * `reports` DOES have a real repository in @montr/state-store
 * (`ReportRepositoryImpl`); `ReportRepositoryAdapter` below just bridges its
 * `upsert`/`getByScan` shape to apps/api's `ReportStore` (`save`/`getByScan`).
 */
import type { Report, Role } from "@montr/contracts";
import { Prisma, type MontrPrismaClient } from "@montr/state-store";
import type { ReportRepository } from "@montr/state-store";
import type { UserRecord, UserStore } from "./auth/users.js";
import type { DastTarget, DastTargetStore, ReportStore } from "./store.js";

function toIso(d: Date): string {
  return d.toISOString();
}

/* --------------------------------------------------------------------------- *
 * Users
 * --------------------------------------------------------------------------- */

interface UserRow {
  id: string;
  clientId: string;
  email: string;
  passwordHash: string;
  role: string;
  createdAt: Date;
  updatedAt: Date;
}

function userFromRow(row: UserRow): UserRecord {
  return {
    id: row.id,
    clientId: row.clientId,
    email: row.email,
    passwordHash: row.passwordHash,
    role: row.role as Role,
    createdAt: toIso(row.createdAt),
    updatedAt: toIso(row.updatedAt),
  };
}

/** Real, Postgres-backed UserStore (see file header for why this lives here). */
export class PrismaUserStore implements UserStore {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async findByEmail(clientId: string, email: string): Promise<UserRecord | null> {
    const row = await this.prisma.user.findFirst({
      where: { clientId, email: email.trim().toLowerCase() },
    });
    return row ? userFromRow(row) : null;
  }

  async findById(clientId: string, id: string): Promise<UserRecord | null> {
    const row = await this.prisma.user.findFirst({ where: { clientId, id } });
    return row ? userFromRow(row) : null;
  }

  async create(user: UserRecord): Promise<UserRecord> {
    try {
      const row = await this.prisma.user.create({
        data: {
          id: user.id,
          clientId: user.clientId,
          email: user.email.trim().toLowerCase(),
          passwordHash: user.passwordHash,
          role: user.role,
        },
      });
      return userFromRow(row);
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        throw new Error("user with this email already exists for client");
      }
      throw err;
    }
  }

  async updateRole(clientId: string, id: string, role: Role): Promise<UserRecord | null> {
    const res = await this.prisma.user.updateMany({ where: { clientId, id }, data: { role } });
    if (res.count === 0) return null;
    return this.findById(clientId, id);
  }

  async countForClient(clientId: string): Promise<number> {
    return this.prisma.user.count({ where: { clientId } });
  }

  async list(clientId: string): Promise<UserRecord[]> {
    const rows = await this.prisma.user.findMany({
      where: { clientId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map(userFromRow);
  }
}

/* --------------------------------------------------------------------------- *
 * DAST targets
 * --------------------------------------------------------------------------- */

interface DastTargetRow {
  id: string;
  clientId: string;
  url: string;
  enabled: boolean;
  scopeContract: unknown;
  approvedById: string | null;
  approvedAt: Date | null;
  createdAt: Date;
}

function dastTargetFromRow(row: DastTargetRow): DastTarget {
  return {
    id: row.id,
    clientId: row.clientId,
    url: row.url,
    enabled: row.enabled,
    scopeContract: row.scopeContract as Record<string, unknown>,
    ...(row.approvedById ? { approvedById: row.approvedById } : {}),
    ...(row.approvedAt ? { approvedAt: toIso(row.approvedAt) } : {}),
    createdAt: toIso(row.createdAt),
  };
}

/** Real, Postgres-backed DastTargetStore (⛔ §11 allowlist + approval gate data). */
export class PrismaDastTargetStore implements DastTargetStore {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async create(target: DastTarget): Promise<DastTarget> {
    const row = await this.prisma.dastTarget.create({
      data: {
        id: target.id,
        clientId: target.clientId,
        url: target.url,
        enabled: target.enabled,
        scopeContract: target.scopeContract as Prisma.InputJsonValue,
        approvedById: target.approvedById ?? null,
        approvedAt: target.approvedAt ? new Date(target.approvedAt) : null,
      },
    });
    return dastTargetFromRow(row);
  }

  async get(clientId: string, id: string): Promise<DastTarget | null> {
    const row = await this.prisma.dastTarget.findFirst({ where: { clientId, id } });
    return row ? dastTargetFromRow(row) : null;
  }

  async findByUrl(clientId: string, url: string): Promise<DastTarget | null> {
    const row = await this.prisma.dastTarget.findFirst({ where: { clientId, url } });
    return row ? dastTargetFromRow(row) : null;
  }

  async list(clientId: string): Promise<DastTarget[]> {
    const rows = await this.prisma.dastTarget.findMany({
      where: { clientId },
      orderBy: { createdAt: "asc" },
    });
    return rows.map(dastTargetFromRow);
  }

  async update(clientId: string, target: DastTarget): Promise<DastTarget> {
    const res = await this.prisma.dastTarget.updateMany({
      where: { clientId, id: target.id },
      data: {
        url: target.url,
        enabled: target.enabled,
        scopeContract: target.scopeContract as Prisma.InputJsonValue,
        approvedById: target.approvedById ?? null,
        approvedAt: target.approvedAt ? new Date(target.approvedAt) : null,
      },
    });
    if (res.count === 0) throw new Error(`dastTarget ${target.id} not found for client`);
    const row = await this.get(clientId, target.id);
    if (!row) throw new Error(`dastTarget ${target.id} vanished after update`);
    return row;
  }
}

/* --------------------------------------------------------------------------- *
 * Reports — adapts the REAL @montr/state-store ReportRepository
 * --------------------------------------------------------------------------- */

/** Bridges state-store's `ReportRepository` (upsert/getByScan) to `ReportStore` (save/getByScan). */
export class ReportRepositoryAdapter implements ReportStore {
  constructor(private readonly repo: ReportRepository) {}

  async getByScan(clientId: string, scanId: string): Promise<Report | null> {
    return this.repo.getByScan(clientId, scanId);
  }

  async save(report: Report): Promise<Report> {
    return this.repo.upsert(report.clientId, report);
  }
}
