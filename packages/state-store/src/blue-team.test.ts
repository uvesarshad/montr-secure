/**
 * DetectionRuleRepositoryImpl / AttackPathRepositoryImpl /
 * DetectionCoverageRepositoryImpl (B1) — offline, no live database. Mirrors
 * `learned-facts.test.ts`'s in-memory fake-Prisma-delegate convention: real
 * repository implementations exercised against a fake that tracks rows in an
 * array, so CRUD + row-scoping behavior is pinned down without Postgres.
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  DetectionRuleRepositoryImpl,
  AttackPathRepositoryImpl,
  DetectionCoverageRepositoryImpl,
} from "./blue-team.js";
import { RepositoryScopeError } from "./repositories.js";
import { Prisma } from "./prisma.js";
import type { MontrPrismaClient } from "./prisma.js";

/** Mirrors real Postgres/Prisma: a written `Prisma.DbNull` sentinel reads back as `null`. */
function normalizeDbNull(value: unknown): unknown {
  return value === Prisma.DbNull ? null : value;
}

interface DetectionRuleFakeRow {
  id: string;
  clientId: string;
  scanId: string;
  findingId: string;
  format: string;
  content: string;
  mitreTechniques: unknown;
  provenance: string;
  createdAt: Date;
}

interface AttackPathFakeRow {
  id: string;
  clientId: string;
  scanId: string;
  steps: unknown;
  feasibilityScore: number;
  severity: string;
  narrative: string;
  createdAt: Date;
}

interface DetectionCoverageFakeRow {
  id: string;
  clientId: string;
  scanId: string;
  findingId: string;
  detected: "detected" | "not_detected" | "unknown";
  reasoning: string;
  detectionRuleId: string | null;
  verification: unknown;
  createdAt: Date;
}

function matches<T extends Record<string, unknown>>(row: T, where: Record<string, unknown>) {
  return Object.entries(where).every(([key, value]) => row[key] === value);
}

/** A minimal in-memory fake covering exactly the Prisma delegate surface the
 * three repositories under test actually call: create/findFirst/findMany on
 * each model's delegate, plus updateMany + $transaction for
 * `DetectionCoverageRepositoryImpl.updateVerification`. */
function makeFakePrisma() {
  const detectionRules: DetectionRuleFakeRow[] = [];
  const attackPaths: AttackPathFakeRow[] = [];
  const detectionCoverage: DetectionCoverageFakeRow[] = [];
  let seq = 0;

  function makeDelegate<T extends { id: string; clientId: string }>(rows: T[], prefix: string) {
    return {
      async create({
        data,
      }: {
        data: Partial<T> & Omit<T, "id" | "createdAt"> & { createdAt?: Date };
      }) {
        const normalized: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
          normalized[key] = normalizeDbNull(value);
        }
        const row = {
          ...normalized,
          id: (data as { id?: string }).id ?? `${prefix}_${++seq}`,
          createdAt: new Date(),
        } as unknown as T;
        rows.push(row);
        return row;
      },
      async findFirst({ where }: { where: Record<string, unknown> }) {
        return rows.find((r) => matches(r as Record<string, unknown>, where)) ?? null;
      },
      async findMany({
        where,
        orderBy,
      }: {
        where: Record<string, unknown>;
        orderBy?: { createdAt?: "asc" | "desc" };
      }) {
        let out = rows.filter((r) => matches(r as Record<string, unknown>, where));
        if (orderBy?.createdAt) {
          out = [...out].sort((a, b) => {
            const at = (a as unknown as { createdAt: Date }).createdAt.getTime();
            const bt = (b as unknown as { createdAt: Date }).createdAt.getTime();
            return orderBy.createdAt === "desc" ? bt - at : at - bt;
          });
        }
        return out;
      },
      async updateMany({
        where,
        data,
      }: {
        where: Record<string, unknown>;
        data: Record<string, unknown>;
      }) {
        let count = 0;
        const normalized: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(data)) {
          normalized[key] = normalizeDbNull(value);
        }
        for (const row of rows) {
          if (matches(row as Record<string, unknown>, where)) {
            Object.assign(row, normalized);
            count += 1;
          }
        }
        return { count };
      },
    };
  }

  const delegates = {
    detectionRule: makeDelegate(detectionRules, "dr"),
    attackPath: makeDelegate(attackPaths, "ap"),
    detectionCoverage: makeDelegate(detectionCoverage, "dc"),
  };

  const prisma = {
    ...delegates,
    // In-memory fake: no real isolation needed, so the "transaction" just
    // hands the callback the same delegates.
    $transaction: async <T>(fn: (tx: typeof delegates) => Promise<T>) => fn(delegates),
  };

  return {
    prisma: prisma as unknown as MontrPrismaClient,
    detectionRules,
    attackPaths,
    detectionCoverage,
  };
}

const NOW = "2026-08-22T00:00:00.000Z";

describe("DetectionRuleRepositoryImpl", () => {
  let ctx: ReturnType<typeof makeFakePrisma>;
  let repo: DetectionRuleRepositoryImpl;

  beforeEach(() => {
    ctx = makeFakePrisma();
    repo = new DetectionRuleRepositoryImpl(ctx.prisma);
  });

  const rule = (overrides: Partial<Parameters<DetectionRuleRepositoryImpl["create"]>[1]> = {}) => ({
    id: "dr_seed",
    clientId: "client_1",
    scanId: "scan_1",
    findingId: "finding_1",
    format: "sigma" as const,
    content: "title: Test\n",
    mitreTechniques: ["T1190"],
    provenance: "static" as const,
    createdAt: NOW,
    ...overrides,
  });

  it("creates and round-trips a detection rule", async () => {
    const created = await repo.create("client_1", rule());
    expect(created.id).toBeTruthy();
    expect(created.format).toBe("sigma");
    expect(created.mitreTechniques).toEqual(["T1190"]);
    expect(created.provenance).toBe("static");

    const fetched = await repo.get("client_1", created.id);
    expect(fetched).toEqual(created);
  });

  it("row-scoping: get returns null for another client's rule", async () => {
    const created = await repo.create("client_1", rule());
    expect(await repo.get("client_2", created.id)).toBeNull();
  });

  it("row-scoping: list never returns another client's rules", async () => {
    await repo.create("client_1", rule({ id: "dr_a" }));
    await repo.create("client_2", rule({ id: "dr_b", findingId: "finding_2" }));

    const client1Rules = await repo.list("client_1");
    const client2Rules = await repo.list("client_2");
    expect(client1Rules).toHaveLength(1);
    expect(client2Rules).toHaveLength(1);
    expect(client1Rules[0]?.clientId).toBe("client_1");
    expect(client2Rules[0]?.clientId).toBe("client_2");
  });

  it("listByFinding: scoped by both clientId and findingId, row-scoping enforced", async () => {
    await repo.create("client_1", rule({ id: "dr_a", findingId: "finding_1", format: "sigma" }));
    await repo.create("client_1", rule({ id: "dr_b", findingId: "finding_1", format: "otel" }));
    await repo.create("client_1", rule({ id: "dr_c", findingId: "finding_2" }));
    await repo.create("client_2", rule({ id: "dr_d", findingId: "finding_1" }));

    const client1Finding1 = await repo.listByFinding("client_1", "finding_1");
    expect(client1Finding1).toHaveLength(2);
    expect(client1Finding1.every((r) => r.clientId === "client_1")).toBe(true);

    const client2Finding1 = await repo.listByFinding("client_2", "finding_1");
    expect(client2Finding1).toHaveLength(1);
    expect(client2Finding1[0]?.clientId).toBe("client_2");
  });
});

describe("AttackPathRepositoryImpl", () => {
  let ctx: ReturnType<typeof makeFakePrisma>;
  let repo: AttackPathRepositoryImpl;

  beforeEach(() => {
    ctx = makeFakePrisma();
    repo = new AttackPathRepositoryImpl(ctx.prisma);
  });

  const path = (overrides: Partial<Parameters<AttackPathRepositoryImpl["create"]>[1]> = {}) => ({
    id: "ap_seed",
    clientId: "client_1",
    scanId: "scan_1",
    steps: [{ findingId: "finding_1" }, { findingId: "finding_2" }],
    feasibilityScore: 0.6,
    severity: "high" as const,
    narrative: "Public route -> SSRF -> credentials.",
    createdAt: NOW,
    ...overrides,
  });

  it("creates and round-trips an attack path", async () => {
    const created = await repo.create("client_1", path());
    expect(created.steps).toHaveLength(2);
    expect(created.severity).toBe("high");

    const fetched = await repo.get("client_1", created.id);
    expect(fetched).toEqual(created);
  });

  it("row-scoping: get returns null for another client's attack path", async () => {
    const created = await repo.create("client_1", path());
    expect(await repo.get("client_2", created.id)).toBeNull();
  });

  it("row-scoping: list never returns another client's attack paths", async () => {
    await repo.create("client_1", path({ id: "ap_a" }));
    await repo.create("client_2", path({ id: "ap_b" }));

    expect(await repo.list("client_1")).toHaveLength(1);
    expect(await repo.list("client_2")).toHaveLength(1);
  });
});

describe("DetectionCoverageRepositoryImpl", () => {
  let ctx: ReturnType<typeof makeFakePrisma>;
  let repo: DetectionCoverageRepositoryImpl;

  beforeEach(() => {
    ctx = makeFakePrisma();
    repo = new DetectionCoverageRepositoryImpl(ctx.prisma);
  });

  const coverage = (
    overrides: Partial<Parameters<DetectionCoverageRepositoryImpl["create"]>[1]> = {},
  ) => ({
    id: "dc_seed",
    clientId: "client_1",
    scanId: "scan_1",
    findingId: "finding_1",
    detected: "unknown" as const,
    reasoning: "No SIEM ingest configured for this route.",
    createdAt: NOW,
    ...overrides,
  });

  it("creates and round-trips a tri-state 'unknown' verdict with no rule/verification", async () => {
    const created = await repo.create("client_1", coverage());
    expect(created.detected).toBe("unknown");
    expect(created.detectionRuleId).toBeUndefined();
    expect(created.verification).toBeUndefined();

    const fetched = await repo.get("client_1", created.id);
    expect(fetched).toEqual(created);
  });

  it("round-trips detected: true with a detectionRuleId", async () => {
    const created = await repo.create(
      "client_1",
      coverage({ detected: true, detectionRuleId: "dr_1" }),
    );
    expect(created.detected).toBe(true);
    expect(created.detectionRuleId).toBe("dr_1");
  });

  it("round-trips detected: false", async () => {
    const created = await repo.create("client_1", coverage({ detected: false }));
    expect(created.detected).toBe(false);
  });

  it("row-scoping: get returns null for another client's coverage row", async () => {
    const created = await repo.create("client_1", coverage());
    expect(await repo.get("client_2", created.id)).toBeNull();
  });

  it("row-scoping: list never returns another client's coverage rows", async () => {
    await repo.create("client_1", coverage({ id: "dc_a" }));
    await repo.create("client_2", coverage({ id: "dc_b" }));

    expect(await repo.list("client_1")).toHaveLength(1);
    expect(await repo.list("client_2")).toHaveLength(1);
  });

  it("listByFinding: scoped by both clientId and findingId", async () => {
    await repo.create("client_1", coverage({ id: "dc_a", findingId: "finding_1" }));
    await repo.create("client_1", coverage({ id: "dc_b", findingId: "finding_2" }));
    await repo.create("client_2", coverage({ id: "dc_c", findingId: "finding_1" }));

    const client1Finding1 = await repo.listByFinding("client_1", "finding_1");
    expect(client1Finding1).toHaveLength(1);
    expect(client1Finding1[0]?.id).toBe("dc_a");
  });

  it("updateVerification attaches a purple-team verification result", async () => {
    const created = await repo.create(
      "client_1",
      coverage({ detected: true, detectionRuleId: "dr_1" }),
    );
    const updated = await repo.updateVerification("client_1", created.id, {
      scenarioId: "scenario_1",
      fired: true,
      verifiedAt: NOW,
      evidence: "siem-alert:12345",
    });
    expect(updated.verification?.fired).toBe(true);
    expect(updated.verification?.scenarioId).toBe("scenario_1");

    const fetched = await repo.get("client_1", created.id);
    expect(fetched?.verification?.fired).toBe(true);
  });

  it("updateVerification is row-scoped: throws RepositoryScopeError for another client's row", async () => {
    const created = await repo.create("client_1", coverage());
    await expect(
      repo.updateVerification("client_2", created.id, { fired: false, verifiedAt: NOW }),
    ).rejects.toThrow(RepositoryScopeError);

    // The row itself is untouched — client_1's own read still shows no verification.
    const fetched = await repo.get("client_1", created.id);
    expect(fetched?.verification).toBeUndefined();
  });

  it("updateVerification throws RepositoryScopeError for a nonexistent id", async () => {
    await expect(
      repo.updateVerification("client_1", "dc_missing", { fired: true, verifiedAt: NOW }),
    ).rejects.toThrow(RepositoryScopeError);
  });
});
