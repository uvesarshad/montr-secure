/**
 * PrismaAuditLogClient.append — the real audit-write chokepoint (audit finding
 * A24). Proves the runtime scrub gate actually runs at the point where an
 * AuditEventInput becomes durable, hash-chained storage — not merely that
 * @montr/security's scrubber functions work in isolation (that's already
 * covered by tests/security.scrubber.test.ts).
 *
 * No live Postgres required: `prisma.ts`'s doc comment says unit tests can pass
 * an in-memory fake with no live database (see repositories.bulk-create.test.ts
 * for the same pattern applied to FindingRepo). Here the fake also implements
 * `$transaction` since `append()` wraps its work in one.
 */
import { describe, expect, it } from "vitest";
import type { AuditEventInput } from "@montr/contracts";
import { findLogViolations } from "@montr/security";
import { PrismaAuditLogClient, scrubAuditInput } from "./audit.js";
import type { MontrPrismaClient } from "./prisma.js";

interface FakeRow {
  id: string;
  clientId: string;
  sequence: number;
  scanId: string | null;
  actorType: string;
  actorId: string;
  actorRole: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  summary: string;
  metadata: unknown;
  prevHash: string;
  hash: string;
  at: Date;
}

function fakePrisma(rows: FakeRow[] = []): MontrPrismaClient {
  const tx = {
    auditEvent: {
      findFirst: async () => (rows.length > 0 ? rows[rows.length - 1] : null),
      create: async ({ data }: { data: FakeRow }) => {
        rows.push(data);
        return data;
      },
    },
  };
  return {
    $transaction: async (fn: (tx: unknown) => unknown) => fn(tx),
  } as unknown as MontrPrismaClient;
}

function input(overrides: Partial<AuditEventInput> = {}): AuditEventInput {
  return {
    clientId: "client_1",
    actor: { type: "system", id: "system" },
    action: "config.changed",
    summary: "config updated",
    metadata: {},
    ...overrides,
  };
}

const SECRET = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX";
const CODE_BODY = [
  "export async function handler(req, res) {",
  "  const id = req.query.id;",
  "  const rows = await db.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);",
  "  return res.json(rows);",
  "}",
].join("\n");

describe("PrismaAuditLogClient.append — runtime scrub gate", () => {
  it("redacts a secret-shaped value hiding in metadata under an innocuous key before persisting", async () => {
    const rows: FakeRow[] = [];
    const client = new PrismaAuditLogClient(fakePrisma(rows));

    const event = await client.append(
      input({ metadata: { note: `client sent ${SECRET}`, scanId: "scan_1" } }),
    );

    // Never reaches the caller's return value…
    expect(JSON.stringify(event.metadata)).not.toContain(SECRET);
    // …nor the persisted row.
    expect(JSON.stringify(rows[0]?.metadata)).not.toContain(SECRET);
    expect(event.metadata["note"] as string).toContain(":secret");
    // benign sibling field survives untouched
    expect(event.metadata["scanId"]).toBe("scan_1");
    // The persisted event is independently certified clean by the verifier.
    expect(findLogViolations(event)).toEqual([]);
  });

  it("redacts a raw code body hiding in metadata under an innocuous key before persisting", async () => {
    const rows: FakeRow[] = [];
    const client = new PrismaAuditLogClient(fakePrisma(rows));

    const event = await client.append(input({ metadata: { note: CODE_BODY } }));

    expect(JSON.stringify(event.metadata)).not.toContain("queryRawUnsafe");
    expect(JSON.stringify(rows[0]?.metadata)).not.toContain("queryRawUnsafe");
    expect(event.metadata["note"] as string).toContain(":code");
    expect(findLogViolations(event)).toEqual([]);
  });

  it("also scrubs the free-form `summary` field, not just metadata", async () => {
    const rows: FakeRow[] = [];
    const client = new PrismaAuditLogClient(fakePrisma(rows));

    const event = await client.append(input({ summary: `deployed key ${SECRET} to production` }));

    expect(event.summary).not.toContain(SECRET);
    expect(rows[0]?.summary).not.toContain(SECRET);
    expect(findLogViolations(event)).toEqual([]);
  });

  it("a code body placed directly in `summary` is redacted too", async () => {
    const rows: FakeRow[] = [];
    const client = new PrismaAuditLogClient(fakePrisma(rows));

    const event = await client.append(input({ summary: CODE_BODY }));

    expect(event.summary).not.toContain("queryRawUnsafe");
    expect(findLogViolations(event)).toEqual([]);
  });

  it("leaves clean, benign metadata and summary untouched", async () => {
    const rows: FakeRow[] = [];
    const client = new PrismaAuditLogClient(fakePrisma(rows));

    const event = await client.append(
      input({ summary: "scan completed", metadata: { scanId: "scan_1", latencyMs: 42, ok: true } }),
    );

    expect(event.summary).toBe("scan completed");
    expect(event.metadata).toEqual({ scanId: "scan_1", latencyMs: 42, ok: true });
  });

  it("every call site funnels through the same gate — a hand-built AuditEventInput with no upstream scrub still comes out clean", async () => {
    // Simulates a future caller that forgets to scrub before calling append(),
    // exactly the gap A24 flags: the type system alone can't stop this, so the
    // chokepoint must.
    const rows: FakeRow[] = [];
    const client = new PrismaAuditLogClient(fakePrisma(rows));
    const rawInput: AuditEventInput = {
      clientId: "client_1",
      actor: { type: "agent", id: "fix-agent" },
      action: "fix.generated",
      summary: "generated fix",
      metadata: { diff: CODE_BODY, apiKey: SECRET },
    };

    await client.append(rawInput);

    expect(JSON.stringify(rows[0])).not.toContain(SECRET);
    expect(JSON.stringify(rows[0])).not.toContain("queryRawUnsafe");
  });
});

describe("scrubAuditInput", () => {
  it("is exported directly so the gate logic is independently testable", () => {
    const result = scrubAuditInput(
      input({ summary: `leak ${SECRET}`, metadata: { code: CODE_BODY } }),
    );
    expect(result.summary).not.toContain(SECRET);
    expect(JSON.stringify(result.metadata)).not.toContain("queryRawUnsafe");
    expect(findLogViolations(result)).toEqual([]);
  });

  it("never throws — always returns a persistable, clean payload (fail-safe, not fail-closed)", () => {
    expect(() =>
      scrubAuditInput(input({ summary: CODE_BODY, metadata: { a: SECRET } })),
    ).not.toThrow();
  });
});
