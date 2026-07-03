/**
 * Postgres-backed {@link UserStore} (production). Mirrors the in-memory store but
 * persists to the @montr/state-store `User` table, so `Scan.operatorId` /
 * `AuditEvent` foreign keys resolve. Client-scoped on every query.
 */
import type { MontrPrismaClient } from "@montr/state-store";
import type { Role } from "@montr/contracts";
import type { UserRecord, UserStore } from "./users.js";

interface UserRow {
  id: string;
  clientId: string;
  email: string;
  passwordHash: string;
  role: Role;
  createdAt: Date;
  updatedAt: Date;
}

function toRecord(u: UserRow): UserRecord {
  return {
    id: u.id,
    clientId: u.clientId,
    email: u.email,
    passwordHash: u.passwordHash,
    role: u.role,
    createdAt: u.createdAt.toISOString(),
    updatedAt: u.updatedAt.toISOString(),
  };
}

export class PrismaUserStore implements UserStore {
  constructor(private readonly prisma: MontrPrismaClient) {}

  async findByEmail(clientId: string, email: string): Promise<UserRecord | null> {
    const u = await this.prisma.user.findFirst({
      where: { clientId, email: email.trim().toLowerCase() },
    });
    return u ? toRecord(u as UserRow) : null;
  }

  async findById(clientId: string, id: string): Promise<UserRecord | null> {
    const u = await this.prisma.user.findFirst({ where: { clientId, id } });
    return u ? toRecord(u as UserRow) : null;
  }

  async create(user: UserRecord): Promise<UserRecord> {
    const u = await this.prisma.user.create({
      data: {
        id: user.id,
        clientId: user.clientId,
        email: user.email.trim().toLowerCase(),
        passwordHash: user.passwordHash,
        role: user.role,
      },
    });
    return toRecord(u as UserRow);
  }

  async updateRole(clientId: string, id: string, role: Role): Promise<UserRecord | null> {
    const existing = await this.prisma.user.findFirst({ where: { clientId, id } });
    if (!existing) return null;
    const u = await this.prisma.user.update({ where: { id }, data: { role } });
    return toRecord(u as UserRow);
  }

  async countForClient(clientId: string): Promise<number> {
    return this.prisma.user.count({ where: { clientId } });
  }

  async list(clientId: string): Promise<UserRecord[]> {
    const rows = await this.prisma.user.findMany({ where: { clientId } });
    return rows.map((u) => toRecord(u as UserRow));
  }
}
