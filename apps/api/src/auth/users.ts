/**
 * User model + persistence interface.
 *
 * The canonical User entity lives in the Prisma schema (owned by WS-C) and will
 * be surfaced by @montr/state-store; until then the API depends on this narrow
 * `UserStore` interface (mirroring the schema columns) and ships an in-memory
 * implementation for local dev + unit tests. Roles come from @montr/contracts.
 */
import { z } from "zod";
import { RoleSchema, type Role } from "@montr/contracts";

/** Persisted user record. `passwordHash` is a one-way scrypt hash (never egressed). */
export interface UserRecord {
  id: string;
  clientId: string;
  email: string;
  passwordHash: string;
  role: Role;
  createdAt: string;
  updatedAt: string;
}

/** User as returned over the wire — never includes the password hash. */
export interface PublicUser {
  id: string;
  clientId: string;
  email: string;
  role: Role;
  createdAt: string;
}

export function toPublicUser(u: UserRecord): PublicUser {
  return {
    id: u.id,
    clientId: u.clientId,
    email: u.email,
    role: u.role,
    createdAt: u.createdAt,
  };
}

export const EmailSchema = z.string().trim().toLowerCase().email().max(320);

/**
 * Password policy: min length 12 (NIST-aligned, length over composition),
 * capped to keep scrypt work bounded. Kept here so registration + reset reuse it.
 */
export const PasswordSchema = z.string().min(12).max(200);

/** Per-client user persistence. All methods are scoped by clientId (never shared). */
export interface UserStore {
  findByEmail(clientId: string, email: string): Promise<UserRecord | null>;
  findById(clientId: string, id: string): Promise<UserRecord | null>;
  create(user: UserRecord): Promise<UserRecord>;
  updateRole(clientId: string, id: string, role: Role): Promise<UserRecord | null>;
  countForClient(clientId: string): Promise<number>;
  list(clientId: string): Promise<UserRecord[]>;
}

export { RoleSchema };

/** Simple in-memory UserStore for local dev + unit tests (not for production). */
export class InMemoryUserStore implements UserStore {
  private readonly byId = new Map<string, UserRecord>();

  private key(clientId: string, id: string): string {
    return `${clientId}:${id}`;
  }

  async findByEmail(clientId: string, email: string): Promise<UserRecord | null> {
    const target = email.trim().toLowerCase();
    for (const u of this.byId.values()) {
      if (u.clientId === clientId && u.email === target) return { ...u };
    }
    return null;
  }

  async findById(clientId: string, id: string): Promise<UserRecord | null> {
    const u = this.byId.get(this.key(clientId, id));
    return u ? { ...u } : null;
  }

  async create(user: UserRecord): Promise<UserRecord> {
    const existing = await this.findByEmail(user.clientId, user.email);
    if (existing) {
      throw new Error("user with this email already exists for client");
    }
    const record: UserRecord = { ...user, email: user.email.trim().toLowerCase() };
    this.byId.set(this.key(record.clientId, record.id), record);
    return { ...record };
  }

  async updateRole(clientId: string, id: string, role: Role): Promise<UserRecord | null> {
    const u = this.byId.get(this.key(clientId, id));
    if (!u) return null;
    const updated: UserRecord = { ...u, role, updatedAt: new Date().toISOString() };
    this.byId.set(this.key(clientId, id), updated);
    return { ...updated };
  }

  async countForClient(clientId: string): Promise<number> {
    let n = 0;
    for (const u of this.byId.values()) if (u.clientId === clientId) n++;
    return n;
  }

  async list(clientId: string): Promise<UserRecord[]> {
    const out: UserRecord[] = [];
    for (const u of this.byId.values()) if (u.clientId === clientId) out.push({ ...u });
    return out;
  }
}
