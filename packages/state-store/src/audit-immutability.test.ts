import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createPrismaClient, type MontrPrismaClient } from "./prisma.js";

/**
 * Regression coverage for DB-level audit-log immutability (migration
 * `3_audit_immutability_trigger`): a Postgres trigger that rejects every
 * UPDATE/DELETE on "AuditEvent", closing the gap where a compromised
 * application-layer DB credential could rewrite history and defeat the hash
 * chain's tamper-evidence (retention.ts no longer even attempts a delete).
 *
 * Two layers of coverage:
 *  1. A static assertion on the migration SQL itself — cheap, always runs, and
 *     guards against the migration file being accidentally deleted, renamed,
 *     or having its function/trigger names changed.
 *  2. A REAL integration test against a live Postgres that actually attempts
 *     the tampering and asserts the database rejects it. This only runs when
 *     `AUDIT_IMMUTABILITY_TEST_DATABASE_URL` (or `DATABASE_URL`) points at a
 *     reachable Postgres with this package's migrations applied — it's
 *     skipped (not failed) otherwise, since most CI/dev environments won't
 *     have a live DB wired up for this package's otherwise-fake-Prisma tests.
 */

const migrationSqlPath = fileURLToPath(
  new URL("../prisma/migrations/3_audit_immutability_trigger/migration.sql", import.meta.url),
);

describe("AuditEvent immutability trigger — migration SQL", () => {
  const sql = readFileSync(migrationSqlPath, "utf8");

  it("defines the tamper-prevention function", () => {
    expect(sql).toMatch(/CREATE (OR REPLACE )?FUNCTION prevent_audit_tampering\(\)/);
    expect(sql).toMatch(/RETURNS TRIGGER/);
    expect(sql).toMatch(/RAISE EXCEPTION/);
  });

  it('installs a BEFORE UPDATE OR DELETE trigger on "AuditEvent"', () => {
    expect(sql).toMatch(/CREATE TRIGGER audit_event_prevent_tampering/);
    expect(sql).toMatch(/BEFORE UPDATE OR DELETE ON "AuditEvent"/);
    expect(sql).toMatch(/FOR EACH ROW/);
    expect(sql).toMatch(/EXECUTE FUNCTION prevent_audit_tampering\(\)/);
  });
});

const liveDbUrl = process.env.AUDIT_IMMUTABILITY_TEST_DATABASE_URL ?? process.env.DATABASE_URL;

describe.runIf(Boolean(liveDbUrl))("AuditEvent immutability trigger — live Postgres", () => {
  let prisma: MontrPrismaClient;
  const clientId = `audit_immutability_test_client_${Date.now()}`;
  const eventId = `audit_immutability_test_event_${Date.now()}`;

  beforeAll(async () => {
    prisma = createPrismaClient({ databaseUrl: liveDbUrl! });
    await prisma.client.create({ data: { id: clientId, name: "Audit Immutability Test Client" } });
    await prisma.auditEvent.create({
      data: {
        id: eventId,
        clientId,
        sequence: 1,
        actorType: "system",
        actorId: "audit-immutability-test",
        action: "scan.started",
        summary: "original, untampered event",
        metadata: {},
        prevHash: "GENESIS",
        hash: "test-hash",
      },
    });
  });

  afterAll(async () => {
    // No cleanup DELETE on AuditEvent: the trigger would reject it anyway,
    // by design — that's exactly the behavior under test. Only the Client
    // row would need cleanup, and it's FK-restricted while the (permanent)
    // AuditEvent row exists, so this test's rows are intentionally left in
    // place in whatever scratch DB the caller pointed us at.
    await prisma.$disconnect();
  });

  it("rejects an UPDATE against an existing audit row", async () => {
    await expect(
      prisma.auditEvent.update({
        where: { id: eventId },
        data: { summary: "tampered" },
      }),
    ).rejects.toThrow(/immutable/i);

    const row = await prisma.auditEvent.findUniqueOrThrow({ where: { id: eventId } });
    expect(row.summary).toBe("original, untampered event");
  });

  it("rejects a DELETE against an existing audit row", async () => {
    await expect(prisma.auditEvent.delete({ where: { id: eventId } })).rejects.toThrow(
      /immutable/i,
    );

    const row = await prisma.auditEvent.findUnique({ where: { id: eventId } });
    expect(row).not.toBeNull();
  });
});
