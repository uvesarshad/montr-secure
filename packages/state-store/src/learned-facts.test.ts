import { describe, it, expect, beforeEach } from "vitest";
import { LearnedFactRepositoryImpl } from "./learned-facts.js";
import type { MontrPrismaClient } from "./prisma.js";

/**
 * In-memory fake for the `prisma.learnedFact` delegate — mirrors the
 * `FakeRow`-style fakes this package's other repos are built against
 * (prompt-version.test.ts), no live database required.
 */
interface FakeRow {
  id: string;
  clientId: string;
  repo: string;
  type: string;
  content: unknown;
  provenance: unknown;
  createdAt: Date;
}

function makeFakePrisma() {
  const rows: FakeRow[] = [];
  let seq = 0;

  const delegate = {
    async create({ data }: { data: Omit<FakeRow, "id" | "createdAt"> }) {
      const row: FakeRow = { ...data, id: `lf_${++seq}`, createdAt: new Date(Date.now() + seq) };
      rows.push(row);
      return row;
    },
    async findMany({
      where,
      orderBy,
      take,
    }: {
      where: { clientId: string; repo: string };
      orderBy?: { createdAt?: "asc" | "desc" };
      take?: number;
    }) {
      let matching = rows.filter((r) => r.clientId === where.clientId && r.repo === where.repo);
      if (orderBy?.createdAt) {
        matching = [...matching].sort((a, b) =>
          orderBy.createdAt === "desc"
            ? b.createdAt.getTime() - a.createdAt.getTime()
            : a.createdAt.getTime() - b.createdAt.getTime(),
        );
      }
      return take !== undefined ? matching.slice(0, take) : matching;
    },
  };

  const prisma = { learnedFact: delegate };
  return { prisma: prisma as unknown as MontrPrismaClient, rows };
}

const PROVENANCE = {
  source: "operator" as const,
  operatorId: "user_1",
  at: "2026-08-22T00:00:00.000Z",
};

describe("LearnedFactRepositoryImpl", () => {
  let ctx: ReturnType<typeof makeFakePrisma>;
  let repo: LearnedFactRepositoryImpl;

  beforeEach(() => {
    ctx = makeFakePrisma();
    repo = new LearnedFactRepositoryImpl(ctx.prisma);
  });

  it("records a fact and returns it with an id + createdAt", async () => {
    const fact = await repo.record({
      clientId: "client_1",
      repo: "github.com/acme/widgets",
      type: "custom_sanitizer",
      content: { sanitizerName: "acmeSanitizeHtml", importPath: "@acme/security" },
      provenance: PROVENANCE,
    });
    expect(fact.id).toBeTruthy();
    expect(fact.type).toBe("custom_sanitizer");
    expect(fact.content).toEqual({
      sanitizerName: "acmeSanitizeHtml",
      importPath: "@acme/security",
    });
    expect(fact.provenance).toEqual(PROVENANCE);
  });

  it("row-scoping: listByRepo never returns another client's facts, even for the same repo string", async () => {
    await repo.record({
      clientId: "client_1",
      repo: "github.com/acme/widgets",
      type: "framework_idiom",
      content: { note: "client 1's idiom" },
      provenance: PROVENANCE,
    });
    await repo.record({
      clientId: "client_2",
      repo: "github.com/acme/widgets",
      type: "framework_idiom",
      content: { note: "client 2's idiom" },
      provenance: PROVENANCE,
    });

    const client1Facts = await repo.listByRepo("client_1", "github.com/acme/widgets");
    const client2Facts = await repo.listByRepo("client_2", "github.com/acme/widgets");

    expect(client1Facts).toHaveLength(1);
    expect(client1Facts[0]?.content["note"]).toBe("client 1's idiom");
    expect(client2Facts).toHaveLength(1);
    expect(client2Facts[0]?.content["note"]).toBe("client 2's idiom");
  });

  it("scopes by repo too: a fact recorded for one repo is not returned for a different repo of the same client", async () => {
    await repo.record({
      clientId: "client_1",
      repo: "github.com/acme/widgets",
      type: "operator_decision",
      content: { decision: "not a vulnerability" },
      provenance: PROVENANCE,
    });

    const otherRepoFacts = await repo.listByRepo("client_1", "github.com/acme/other-repo");
    expect(otherRepoFacts).toHaveLength(0);
  });

  it("listByRepo returns newest first and honors the limit cap", async () => {
    for (let i = 0; i < 5; i++) {
      await repo.record({
        clientId: "client_1",
        repo: "github.com/acme/widgets",
        type: "operator_decision",
        content: { i },
        provenance: PROVENANCE,
      });
    }

    const capped = await repo.listByRepo("client_1", "github.com/acme/widgets", 2);
    expect(capped).toHaveLength(2);
    // Newest first: the last-recorded (i=4) fact comes back before i=3.
    expect(capped[0]?.content["i"]).toBe(4);
    expect(capped[1]?.content["i"]).toBe(3);
  });

  it("an empty repo/client with no prior facts returns an empty list (regression safety)", async () => {
    const facts = await repo.listByRepo("client_never_scanned", "github.com/nobody/nothing");
    expect(facts).toEqual([]);
  });
});
