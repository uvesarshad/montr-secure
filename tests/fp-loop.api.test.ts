import { afterEach, describe, it, expect } from "vitest";
import type { FastifyInstance } from "fastify";
import { getMetrics } from "@montr/telemetry";
import { mockConfirmedFindings, CLIENT_ID } from "@montr/fixtures";
import { buildServer, createInMemoryDeps } from "../apps/api/src/server";
import { createInMemoryApiStore, type ApiStore } from "../apps/api/src/store";
import type { FalsePositiveMarkInput } from "../apps/api/src/fp-corpus";

/**
 * §15 API — an operator/approver MARKS a confirmed finding as a false positive.
 * The mutation is RBAC-guarded, validated, audit-logged, written to the
 * regression corpus, and fed to the FP-feedback metric. Fully offline (app.inject,
 * bearer auth — no CSRF, no network).
 */

const FINDING = mockConfirmedFindings[0]!; // SQLi @ app/api/users/route.ts:9
const CLOCK = { now: () => new Date("2026-07-02T12:00:00.000Z") };

interface Harness {
  app: FastifyInstance;
  store: ApiStore;
  captured: FalsePositiveMarkInput[];
}

let current: FastifyInstance | undefined;

async function setup(): Promise<Harness> {
  const store = createInMemoryApiStore({ clock: CLOCK });
  await store.confirmed.create(CLIENT_ID, FINDING);
  const captured: FalsePositiveMarkInput[] = [];
  const regressionCorpus = { record: (input: FalsePositiveMarkInput) => void captured.push(input) };
  const deps = createInMemoryDeps({ store, clock: CLOCK, regressionCorpus });
  const app = await buildServer(deps);
  current = app;
  return { app, store, captured };
}

function tokenFor(app: FastifyInstance, role: "operator" | "approver" | "viewer"): string {
  // @fastify/jwt decorates `app.jwt`; a bearer token needs no CSRF.
  return (app as unknown as { jwt: { sign(p: unknown): string } }).jwt.sign({
    sub: "user_1",
    clientId: CLIENT_ID,
    email: "u@example.com",
    role,
  });
}

afterEach(async () => {
  await current?.close();
  current = undefined;
});

describe("POST /findings/:id/false-positive", () => {
  it("operator marks FP → audits, writes the corpus, feeds the metric", async () => {
    const { app, store, captured } = await setup();
    const before = getMetrics().snapshot().falsePositiveFeedback;

    const res = await app.inject({
      method: "POST",
      url: `/api/v1/findings/${FINDING.id}/false-positive`,
      headers: { authorization: `Bearer ${tokenFor(app, "operator")}` },
      payload: { reason: "reviewed: query is parameterized upstream" },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true, findingId: FINDING.id });

    // 1. Corpus write — metadata only, no proof/code body (golden rule #1).
    expect(captured).toHaveLength(1);
    const rec = captured[0]!;
    expect(rec.findingId).toBe(FINDING.id);
    expect(rec.category).toBe("sql_injection");
    expect(rec.file).toBe("app/api/users/route.ts");
    expect(rec.line).toBe(9);
    expect(rec.operator).toEqual({ id: "user_1", role: "operator" });
    expect(rec.reason).toContain("parameterized");
    expect(rec.markedAt).toBe("2026-07-02T12:00:00.000Z");
    expect(JSON.stringify(rec)).not.toContain("queryRawUnsafe"); // ⛔ no code body

    // 2. Audit-logged as a tamper-evident mutation, metadata carries the location.
    const events = await store.audit.list(CLIENT_ID);
    const fp = events.find((e) => e.action === "finding.marked_false_positive");
    expect(fp).toBeDefined();
    expect(fp!.actor).toMatchObject({ type: "user", id: "user_1", role: "operator" });
    expect(fp!.metadata).toMatchObject({
      category: "sql_injection",
      file: "app/api/users/route.ts",
      line: 9,
      reason: "reviewed: query is parameterized upstream",
    });
    expect(await store.audit.verifyChain(CLIENT_ID)).toBe(true);

    // 3. FP-feedback metric moved by exactly one.
    expect(getMetrics().snapshot().falsePositiveFeedback - before).toBe(1);
  });

  it("approver may also mark FP", async () => {
    const { app } = await setup();
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/findings/${FINDING.id}/false-positive`,
      headers: { authorization: `Bearer ${tokenFor(app, "approver")}` },
      payload: { reason: "approved as benign" },
    });
    expect(res.statusCode).toBe(200);
  });

  it("⛔ a viewer is forbidden (RBAC)", async () => {
    const { app, captured } = await setup();
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/findings/${FINDING.id}/false-positive`,
      headers: { authorization: `Bearer ${tokenFor(app, "viewer")}` },
      payload: { reason: "should not be allowed" },
    });
    expect(res.statusCode).toBe(403);
    expect(captured).toHaveLength(0); // no corpus write on a rejected request
  });

  it("rejects an unauthenticated request", async () => {
    const { app } = await setup();
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/findings/${FINDING.id}/false-positive`,
      payload: { reason: "no token" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns 404 for an unknown finding and 400 for an empty reason", async () => {
    const { app } = await setup();
    const auth = { authorization: `Bearer ${tokenFor(app, "operator")}` };

    const missing = await app.inject({
      method: "POST",
      url: `/api/v1/findings/does-not-exist/false-positive`,
      headers: auth,
      payload: { reason: "x" },
    });
    expect(missing.statusCode).toBe(404);

    const bad = await app.inject({
      method: "POST",
      url: `/api/v1/findings/${FINDING.id}/false-positive`,
      headers: auth,
      payload: { reason: "" },
    });
    expect(bad.statusCode).toBe(400);
  });
});
