/**
 * FindingRepo.bulkCreate — skipDuplicates (A3.3), offline / no live Postgres.
 *
 * `FindingRepo` (repositories.ts) accepts an injected Prisma delegate (see
 * prisma.ts's doc comment: "unit tests can pass an in-memory fake with NO live
 * database"), so this exercises the REAL `bulkCreate` implementation against a
 * fake `createMany` that just records the args it was called with — no schema,
 * no DB connection required.
 */
import { describe, expect, it } from "vitest";
import { CandidateFindingSchema, type CandidateFinding } from "@montr/contracts";
import { makeCandidateRepo, makeConfirmedRepo } from "./repositories.js";
import type { MontrPrismaClient } from "./prisma.js";

function candidate(id: string): CandidateFinding {
  return CandidateFindingSchema.parse({
    id,
    scanId: "scan_1",
    clientId: "client_1",
    source: "semgrep",
    ruleId: "rule.sql-injection",
    category: "sql_injection",
    cwe: ["CWE-89"],
    location: { file: "src/db.ts", line: 42 },
    rawSeverity: "high",
    evidenceSnippet: "db.query(sql)",
    createdAt: "2026-01-01T00:00:00.000Z",
  });
}

interface RecordedCall {
  data: unknown[];
  skipDuplicates?: boolean;
}

function fakeDelegate(calls: RecordedCall[]) {
  return {
    create: async () => {
      throw new Error("create() not used by this test");
    },
    createMany: async (args: RecordedCall) => {
      calls.push(args);
      return { count: args.data.length };
    },
    findFirst: async () => null,
    findMany: async () => [],
  };
}

describe("FindingRepo.bulkCreate — skipDuplicates", () => {
  it("passes skipDuplicates: true through to Prisma's createMany", async () => {
    const calls: RecordedCall[] = [];
    const fakePrisma = { candidateFinding: fakeDelegate(calls) } as unknown as MontrPrismaClient;
    const repo = makeCandidateRepo(fakePrisma);

    const findings = [candidate("cand_1"), candidate("cand_2")];
    const result = await repo.bulkCreate("client_1", findings);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.skipDuplicates).toBe(true);
    expect(calls[0]?.data).toHaveLength(2);
    // bulkCreate still returns the full input set (Prisma's createMany doesn't
    // return rows) regardless of how many were actually skipped as duplicates —
    // that's fine: what matters is the WRITE didn't throw.
    expect(result).toHaveLength(2);
  });

  it("is a no-op on an empty array — never calls createMany at all", async () => {
    const calls: RecordedCall[] = [];
    const fakePrisma = { candidateFinding: fakeDelegate(calls) } as unknown as MontrPrismaClient;
    const repo = makeCandidateRepo(fakePrisma);

    const result = await repo.bulkCreate("client_1", []);

    expect(result).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it("skipDuplicates is set for every FindingRepo instance (candidate AND confirmed), not just one hand-wired case", async () => {
    const calls: RecordedCall[] = [];
    const fakePrisma = { confirmedFinding: fakeDelegate(calls) } as unknown as MontrPrismaClient;
    const repo = makeConfirmedRepo(fakePrisma);

    // Minimal valid ConfirmedFinding-shaped input isn't needed here — bulkCreate
    // only touches `id`/`clientId` plus whatever `toCreate` maps, and the fake
    // delegate accepts anything; we only care that skipDuplicates was passed.
    await repo.bulkCreate("client_1", [
      {
        id: "cf_1",
        scanId: "scan_1",
        clientId: "client_1",
        title: "SQL injection in db.ts",
        category: "sql_injection",
        cwe: ["CWE-89"],
        severity: "high",
        exposure: "public",
        location: { file: "src/db.ts", line: 42 },
        impact: "Unauthenticated attacker can read arbitrary rows.",
        proofType: "static",
        proofArtifact: {
          type: "static",
          hops: [],
          sanitizersBypassed: [],
          reason: "reachable from public route with no sanitizer on the path",
        },
        createdAt: "2026-01-01T00:00:00.000Z",
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
    ]);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.skipDuplicates).toBe(true);
  });
});
