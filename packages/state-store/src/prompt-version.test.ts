import { describe, it, expect, beforeEach } from "vitest";
import { PromptVersionRepositoryImpl } from "./prompt-version.js";
import { RepositoryScopeError } from "./repositories.js";
import type { MontrPrismaClient } from "./prisma.js";

/**
 * In-memory fake for the `prisma.promptVersion` delegate — just enough of the
 * Prisma Client surface ({@link PromptVersionRepositoryImpl} actually calls)
 * to exercise the repository with NO live database, mirroring the
 * `FindingDelegate`-style fakes this package's other repos are built against.
 */
interface FakeRow {
  id: string;
  clientId: string | null;
  name: string;
  version: number;
  layer: string | null;
  template: string;
  isActive: boolean;
  createdAt: Date;
}

function matches(row: FakeRow, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([key, value]) => {
    if (key === "OR") {
      const clauses = value as Record<string, unknown>[];
      return clauses.some((clause) => matches(row, clause));
    }
    if (key === "id" && typeof value === "object" && value !== null && "not" in value) {
      return row.id !== (value as { not: string }).not;
    }
    return (row as unknown as Record<string, unknown>)[key] === value;
  });
}

function makeFakePrisma() {
  const rows: FakeRow[] = [];
  let seq = 0;

  const delegate = {
    async create({ data }: { data: Omit<FakeRow, "id" | "createdAt"> }) {
      const row: FakeRow = { ...data, id: `pv_${++seq}`, createdAt: new Date() };
      rows.push(row);
      return row;
    },
    async findFirst({
      where,
      orderBy,
    }: {
      where: Record<string, unknown>;
      orderBy?: { version?: "asc" | "desc" };
    }) {
      let matching = rows.filter((r) => matches(r, where));
      if (orderBy?.version) {
        matching = [...matching].sort((a, b) =>
          orderBy.version === "desc" ? b.version - a.version : a.version - b.version,
        );
      }
      return matching[0] ?? null;
    },
    async findMany({
      where,
      orderBy,
    }: {
      where: Record<string, unknown>;
      orderBy?: { version?: "asc" | "desc" };
    }) {
      let matching = rows.filter((r) => matches(r, where));
      if (orderBy?.version) {
        matching = [...matching].sort((a, b) =>
          orderBy.version === "desc" ? b.version - a.version : a.version - b.version,
        );
      }
      return matching;
    },
    async findUnique({ where }: { where: { id: string } }) {
      return rows.find((r) => r.id === where.id) ?? null;
    },
    async update({ where, data }: { where: { id: string }; data: Partial<FakeRow> }) {
      const row = rows.find((r) => r.id === where.id);
      if (!row) throw new Error("not found");
      Object.assign(row, data);
      return row;
    },
    async updateMany({ where, data }: { where: Record<string, unknown>; data: Partial<FakeRow> }) {
      const matching = rows.filter((r) => matches(r, where));
      for (const row of matching) Object.assign(row, data);
      return { count: matching.length };
    },
  };

  interface FakePrisma {
    promptVersion: typeof delegate;
    $transaction<T>(fn: (tx: FakePrisma) => Promise<T>): Promise<T>;
  }

  const prisma: FakePrisma = {
    promptVersion: delegate,
    async $transaction<T>(fn: (tx: FakePrisma) => Promise<T>): Promise<T> {
      return fn(prisma);
    },
  };

  return { prisma: prisma as unknown as MontrPrismaClient, rows };
}

describe("PromptVersionRepositoryImpl", () => {
  let ctx: ReturnType<typeof makeFakePrisma>;
  let repo: PromptVersionRepositoryImpl;

  beforeEach(() => {
    ctx = makeFakePrisma();
    repo = new PromptVersionRepositoryImpl(ctx.prisma);
  });

  it("creates version 1 for a brand-new prompt name, inactive by default", async () => {
    const v = await repo.createVersion({ name: "correlation.system", template: "v1 template" });
    expect(v.version).toBe(1);
    expect(v.isActive).toBe(false);
    expect(v.clientId).toBeNull();
    expect(v.template).toBe("v1 template");
  });

  it("increments the version monotonically per name, regardless of clientId", async () => {
    const v1 = await repo.createVersion({ name: "fix.system", template: "seed" });
    const v2 = await repo.createVersion({
      name: "fix.system",
      template: "client A candidate",
      clientId: "client_a",
    });
    const v3 = await repo.createVersion({ name: "fix.system", template: "global v3" });
    expect([v1.version, v2.version, v3.version]).toEqual([1, 2, 3]);
  });

  it("lists versions newest-first, scoped to a client's own + global rows", async () => {
    await repo.createVersion({ name: "triage.system", template: "global v1" });
    await repo.createVersion({
      name: "triage.system",
      template: "client v2",
      clientId: "client_a",
    });
    await repo.createVersion({
      name: "triage.system",
      template: "other client v3",
      clientId: "client_b",
    });

    const forA = await repo.listVersions("triage.system", "client_a");
    expect(forA.map((r) => r.version)).toEqual([2, 1]); // client_a's own + global, NOT client_b's
    expect(forA.every((r) => r.clientId === "client_a" || r.clientId === null)).toBe(true);

    const globalOnly = await repo.listVersions("triage.system");
    expect(globalOnly.map((r) => r.version)).toEqual([1]);
  });

  it("getActive returns null when nothing is active yet (llm-gateway falls back to hardcoded)", async () => {
    await repo.createVersion({ name: "fix.system", template: "candidate, not yet active" });
    expect(await repo.getActive("fix.system")).toBeNull();
    expect(await repo.getActive("fix.system", "client_a")).toBeNull();
  });

  it("markActive promotes exactly one version and deactivates the prior active one", async () => {
    const v1 = await repo.createVersion({ name: "fix.system", template: "v1" });
    const v2 = await repo.createVersion({ name: "fix.system", template: "v2" });

    const activated1 = await repo.markActive(v1.id);
    expect(activated1.isActive).toBe(true);
    expect((await repo.getActive("fix.system"))?.id).toBe(v1.id);

    const activated2 = await repo.markActive(v2.id);
    expect(activated2.isActive).toBe(true);
    const active = await repo.getActive("fix.system");
    expect(active?.id).toBe(v2.id);

    // v1 was deactivated by promoting v2 — only one active row per scope.
    const all = await repo.listVersions("fix.system");
    expect(all.filter((r) => r.isActive)).toHaveLength(1);
  });

  it("markActive scopes deactivation to the SAME (name, clientId) — a client override doesn't touch the global active row", async () => {
    const global = await repo.createVersion({ name: "fix.system", template: "global" });
    await repo.markActive(global.id);
    const override = await repo.createVersion({
      name: "fix.system",
      template: "client override",
      clientId: "client_a",
    });
    await repo.markActive(override.id);

    expect((await repo.getActive("fix.system"))?.id).toBe(global.id); // global scope untouched
    expect((await repo.getActive("fix.system", "client_a"))?.id).toBe(override.id); // client wins over global
  });

  it("getActive prefers a client-scoped active row over the global active row", async () => {
    const global = await repo.createVersion({ name: "triage.system", template: "global" });
    await repo.markActive(global.id);
    expect((await repo.getActive("triage.system", "client_a"))?.id).toBe(global.id);

    const override = await repo.createVersion({
      name: "triage.system",
      template: "override",
      clientId: "client_a",
    });
    await repo.markActive(override.id);
    expect((await repo.getActive("triage.system", "client_a"))?.id).toBe(override.id);
    // A different client still sees the global one.
    expect((await repo.getActive("triage.system", "client_b"))?.id).toBe(global.id);
  });

  it("markActive on an unknown id throws RepositoryScopeError", async () => {
    await expect(repo.markActive("does-not-exist")).rejects.toThrow(RepositoryScopeError);
  });
});
