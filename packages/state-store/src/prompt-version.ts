/**
 * Versioned LLM prompt templates (§8.2, §15 regression-tuning loop).
 *
 * `PromptVersion` existed in the schema with zero readers/writers — dead
 * schema. This module makes it real: a CRUD repository over the model so
 * @montr/llm-gateway can resolve a prompt's ACTIVE version at call time
 * instead of a hardcoded string constant, and so a future tuning loop (§15)
 * has somewhere real to write candidate versions before promoting one.
 *
 * Scoping: `clientId: null` is a global/shared version (the seeded default);
 * a non-null `clientId` is a per-client override or tuning candidate.
 * `version` is a monotonic counter PER `name` across ALL clients (mirrors the
 * DB's `@@unique([name, version])`) so a prompt's history reads as one
 * linear timeline regardless of which client authored which version.
 *
 * "Active" is an explicit flag (not "highest version wins") so a candidate
 * version can be created, evaluated, and left inactive until promoted —
 * exactly the create-then-promote shape a regression-tuning loop needs.
 * Prisma has no partial-unique-index syntax here, so "at most one active row
 * per (name, clientId) scope" is enforced in {@link markActive} via a
 * transaction, not a DB constraint.
 */
import type { LayerId } from "@montr/contracts";
import { RepositoryScopeError } from "./repositories.js";
import { toIso } from "./mappers.js";
import type { MontrPrismaClient } from "./prisma.js";
import type { PromptVersionInput, PromptVersionRecord, PromptVersionRepository } from "./types.js";

interface PromptVersionRow {
  id: string;
  clientId: string | null;
  name: string;
  version: number;
  layer: LayerId | null;
  template: string;
  isActive: boolean;
  createdAt: Date;
}

function fromRow(row: PromptVersionRow): PromptVersionRecord {
  return {
    id: row.id,
    clientId: row.clientId,
    name: row.name,
    version: row.version,
    layer: row.layer,
    template: row.template,
    isActive: row.isActive,
    createdAt: toIso(row.createdAt),
  };
}

export class PromptVersionRepositoryImpl implements PromptVersionRepository {
  constructor(private readonly prisma: MontrPrismaClient) {}

  /**
   * Create the next version for `name`: `version` = `max(version WHERE name)
   * + 1` (starting at 1), computed inside the transaction so concurrent
   * writers for the same `name` can't collide on the `[name, version]`
   * unique index. The new row starts INACTIVE — callers promote it
   * explicitly via {@link markActive} (create-then-promote, §15).
   */
  async createVersion(input: PromptVersionInput): Promise<PromptVersionRecord> {
    const clientId = input.clientId ?? null;
    return this.prisma.$transaction(async (tx) => {
      const last = await tx.promptVersion.findFirst({
        where: { name: input.name },
        orderBy: { version: "desc" },
      });
      const version = (last?.version ?? 0) + 1;
      const row = await tx.promptVersion.create({
        data: {
          name: input.name,
          version,
          template: input.template,
          layer: input.layer ?? null,
          clientId,
          isActive: false,
        },
      });
      return fromRow(row as PromptVersionRow);
    });
  }

  /**
   * All versions for `name`, newest first. When `clientId` is given, this
   * includes both that client's own versions AND the global (`clientId:
   * null`) versions — the same "own scope, then global" visibility
   * {@link getActive} resolves against.
   */
  async listVersions(name: string, clientId?: string | null): Promise<PromptVersionRecord[]> {
    const rows = await this.prisma.promptVersion.findMany({
      where: clientId ? { name, OR: [{ clientId }, { clientId: null }] } : { name, clientId: null },
      orderBy: { version: "desc" },
    });
    return rows.map((r) => fromRow(r as PromptVersionRow));
  }

  /**
   * The active version for `name`: prefers a `clientId`-scoped active row
   * (a client-specific override/tuning result); falls back to the global
   * (`clientId: null`) active row; returns `null` when neither exists (the
   * caller — llm-gateway — falls back to its hardcoded default template).
   */
  async getActive(name: string, clientId?: string | null): Promise<PromptVersionRecord | null> {
    if (clientId) {
      const own = await this.prisma.promptVersion.findFirst({
        where: { name, clientId, isActive: true },
      });
      if (own) return fromRow(own as PromptVersionRow);
    }
    const global = await this.prisma.promptVersion.findFirst({
      where: { name, clientId: null, isActive: true },
    });
    return global ? fromRow(global as PromptVersionRow) : null;
  }

  /**
   * Promote `id` to active, deactivating any other active row in the same
   * `(name, clientId)` scope first — all inside one transaction so a reader
   * never observes two simultaneously-active versions for the same scope.
   */
  async markActive(id: string): Promise<PromptVersionRecord> {
    return this.prisma.$transaction(async (tx) => {
      const target = await tx.promptVersion.findUnique({ where: { id } });
      if (!target) throw new RepositoryScopeError(`promptVersion ${id} not found`);
      await tx.promptVersion.updateMany({
        where: { name: target.name, clientId: target.clientId, isActive: true, id: { not: id } },
        data: { isActive: false },
      });
      const row = await tx.promptVersion.update({ where: { id }, data: { isActive: true } });
      return fromRow(row as PromptVersionRow);
    });
  }
}
