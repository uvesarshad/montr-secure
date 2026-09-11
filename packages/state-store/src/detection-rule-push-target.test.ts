/**
 * DetectionRulePushTargetRepositoryImpl (suggested enhancement, 2026-09-12
 * red/blue agentic-posture audit). Offline, no live database — mirrors
 * `blue-team.test.ts`'s in-memory fake-Prisma-delegate convention. Proves
 * the encrypt-on-write/decrypt-on-read round trip (the same shape
 * `CredentialRepositoryImpl` already relies on), that `getMetadata` never
 * exposes the secret, and that `requireCipher` fails fast without one.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DetectionRulePushTargetRepositoryImpl } from "./detection-rule-push-target.js";
import { createFieldCipher } from "./crypto.js";
import type { MontrPrismaClient } from "./prisma.js";

interface FakeRow {
  id: string;
  clientId: string;
  type: string;
  endpointUrl: string;
  hecToken: string;
  index: string | null;
  sourcetype: string | null;
  createdAt: Date;
  updatedAt: Date;
}

function makeFakePrisma(rows: FakeRow[]): MontrPrismaClient {
  let seq = 0;
  const delegate = {
    async upsert({
      where,
      create,
      update,
    }: {
      where: { clientId: string };
      create: Record<string, unknown>;
      update: Record<string, unknown>;
    }) {
      const existing = rows.find((r) => r.clientId === where.clientId);
      const now = new Date();
      if (existing) {
        Object.assign(existing, update, { updatedAt: now });
        return existing;
      }
      const row: FakeRow = {
        id: `push_${++seq}`,
        clientId: where.clientId,
        type: create.type as string,
        endpointUrl: create.endpointUrl as string,
        hecToken: create.hecToken as string,
        index: (create.index as string | null) ?? null,
        sourcetype: (create.sourcetype as string | null) ?? null,
        createdAt: now,
        updatedAt: now,
      };
      rows.push(row);
      return row;
    },
    async findFirst({ where }: { where: { clientId: string } }) {
      return rows.find((r) => r.clientId === where.clientId) ?? null;
    },
    async deleteMany({ where }: { where: { clientId: string } }) {
      const before = rows.length;
      const remaining = rows.filter((r) => r.clientId !== where.clientId);
      rows.length = 0;
      rows.push(...remaining);
      return { count: before - remaining.length };
    },
  };
  return { detectionRulePushTarget: delegate } as unknown as MontrPrismaClient;
}

describe("DetectionRulePushTargetRepositoryImpl", () => {
  let rows: FakeRow[];
  const cipher = createFieldCipher("a".repeat(32));

  beforeEach(() => {
    rows = [];
  });

  it("encrypts the token at rest — the stored row never carries plaintext", async () => {
    const prisma = makeFakePrisma(rows);
    const repo = new DetectionRulePushTargetRepositoryImpl(prisma, cipher);

    await repo.upsert("client_1", {
      type: "splunk_hec",
      endpointUrl: "https://splunk.example.com:8088/services/collector/event",
      hecToken: "super-secret-hec-token",
      index: "montr_detections",
    });

    expect(rows).toHaveLength(1);
    expect(rows[0]!.hecToken).not.toBe("super-secret-hec-token");
    expect(rows[0]!.hecToken).toMatch(/^montr\.v1\.gcm:/);
  });

  it("round-trips: upsert then get returns the decrypted plaintext token", async () => {
    const prisma = makeFakePrisma(rows);
    const repo = new DetectionRulePushTargetRepositoryImpl(prisma, cipher);

    await repo.upsert("client_1", {
      type: "splunk_hec",
      endpointUrl: "https://splunk.example.com:8088/services/collector/event",
      hecToken: "super-secret-hec-token",
      sourcetype: "montr:detection_rule",
    });

    const got = await repo.get("client_1");
    expect(got).toMatchObject({
      clientId: "client_1",
      type: "splunk_hec",
      endpointUrl: "https://splunk.example.com:8088/services/collector/event",
      hecToken: "super-secret-hec-token",
      sourcetype: "montr:detection_rule",
    });
  });

  it("upsert on the same client replaces the row (one target per client)", async () => {
    const prisma = makeFakePrisma(rows);
    const repo = new DetectionRulePushTargetRepositoryImpl(prisma, cipher);

    await repo.upsert("client_1", {
      type: "splunk_hec",
      endpointUrl: "https://first.example.com/collector",
      hecToken: "token-a",
    });
    await repo.upsert("client_1", {
      type: "splunk_hec",
      endpointUrl: "https://second.example.com/collector",
      hecToken: "token-b",
    });

    expect(rows).toHaveLength(1);
    const got = await repo.get("client_1");
    expect(got?.endpointUrl).toBe("https://second.example.com/collector");
    expect(got?.hecToken).toBe("token-b");
  });

  it("getMetadata never returns the secret token", async () => {
    const prisma = makeFakePrisma(rows);
    const repo = new DetectionRulePushTargetRepositoryImpl(prisma, cipher);
    await repo.upsert("client_1", {
      type: "splunk_hec",
      endpointUrl: "https://splunk.example.com:8088/services/collector/event",
      hecToken: "super-secret-hec-token",
    });

    const meta = await repo.getMetadata("client_1");
    expect(meta).toMatchObject({
      type: "splunk_hec",
      endpointUrl: "https://splunk.example.com:8088/services/collector/event",
    });
    expect(meta).not.toHaveProperty("hecToken");
    expect(JSON.stringify(meta)).not.toContain("super-secret-hec-token");
  });

  it("delete removes the row", async () => {
    const prisma = makeFakePrisma(rows);
    const repo = new DetectionRulePushTargetRepositoryImpl(prisma, cipher);
    await repo.upsert("client_1", {
      type: "splunk_hec",
      endpointUrl: "https://splunk.example.com:8088/services/collector/event",
      hecToken: "t",
    });
    await repo.delete("client_1");
    expect(await repo.get("client_1")).toBeNull();
  });

  it("fails fast without a field-encryption cipher configured", async () => {
    const prisma = makeFakePrisma(rows);
    const repo = new DetectionRulePushTargetRepositoryImpl(prisma, undefined);
    await expect(
      repo.upsert("client_1", {
        type: "splunk_hec",
        endpointUrl: "https://splunk.example.com:8088/services/collector/event",
        hecToken: "t",
      }),
    ).rejects.toThrow(/field-encryption key is required/);
  });
});
