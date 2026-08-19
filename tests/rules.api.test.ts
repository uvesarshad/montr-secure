import { afterEach, describe, it, expect } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, createInMemoryDeps } from "../apps/api/src/server";
import { createInMemoryApiStore, type ApiStore } from "../apps/api/src/store";

/**
 * Phase-4 (§16) — custom rule authoring API. ⛔ Rules are VALIDATED before enable,
 * VERSIONED on update, RBAC-scoped (operator/approver author; viewers read-only),
 * and every mutation is audit-logged (tamper-evident). Fully offline: a secret
 * rule validates by compiling its regex (no subprocess); a structurally-broken
 * rule is rejected before any semgrep spawn, so the suite never needs the binary.
 */

const CLIENT_ID = "client_rules";
const CLOCK = { now: () => new Date("2026-07-03T12:00:00.000Z") };

let current: FastifyInstance | undefined;

async function setup(): Promise<{ app: FastifyInstance; store: ApiStore }> {
  const store = createInMemoryApiStore({ clock: CLOCK });
  const deps = createInMemoryDeps({ store, clock: CLOCK });
  const app = await buildServer(deps);
  current = app;
  return { app, store };
}

function token(
  app: FastifyInstance,
  role: "operator" | "approver" | "viewer",
  clientId = CLIENT_ID,
): string {
  return (app as unknown as { jwt: { sign(p: unknown): string } }).jwt.sign({
    sub: `user_${role}`,
    clientId,
    email: `${role}@example.com`,
    role,
  });
}

afterEach(async () => {
  await current?.close();
  current = undefined;
});

const VALID_SECRET = {
  name: "Custom key",
  engine: "secret",
  language: "typescript",
  body: "cust_[0-9a-f]{20}",
};

describe("POST /rules — validate before enable", () => {
  it("operator authors a valid (enabled) secret rule → 201 + audit rule.created", async () => {
    const { app, store } = await setup();
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "operator")}` },
      payload: { ...VALID_SECRET, enabled: true },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json() as {
      rule: { id: string; version: number; enabled: boolean };
      validation: { valid: boolean };
    };
    expect(body.validation.valid).toBe(true);
    expect(body.rule.version).toBe(1);
    expect(body.rule.enabled).toBe(true);

    const events = await store.audit.list(CLIENT_ID);
    const created = events.find((e) => e.action === "rule.created");
    expect(created).toBeDefined();
    expect(created!.actor).toMatchObject({ type: "user", role: "operator" });
    // ⛔ golden rule #1 — the rule body is never in the audit metadata.
    expect(JSON.stringify(created!.metadata)).not.toContain("cust_[0-9a-f]{20}");
    expect(await store.audit.verifyChain(CLIENT_ID)).toBe(true);
  });

  it("⛔ refuses to ENABLE an invalid rule (400), never persists it", async () => {
    const { app, store } = await setup();
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "operator")}` },
      payload: {
        name: "bad",
        engine: "secret",
        language: "typescript",
        body: "cust_[0-9",
        enabled: true,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(await store.customRules.list(CLIENT_ID)).toHaveLength(0);
  });

  it("stores an invalid DISABLED draft (author can iterate) with validation errors surfaced", async () => {
    const { app } = await setup();
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "operator")}` },
      payload: {
        name: "draft",
        engine: "secret",
        language: "typescript",
        body: "cust_[0-9",
        enabled: false,
      },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json() as { rule: { enabled: boolean }; validation: { valid: boolean } };
    expect(body.rule.enabled).toBe(false);
    expect(body.validation.valid).toBe(false);
  });

  it("⛔ a viewer is forbidden (403); an unauthenticated request is 401", async () => {
    const { app } = await setup();
    const viewer = await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "viewer")}` },
      payload: { ...VALID_SECRET, enabled: true },
    });
    expect(viewer.statusCode).toBe(403);
    const anon = await app.inject({ method: "POST", url: "/api/v1/rules", payload: VALID_SECRET });
    expect(anon.statusCode).toBe(401);
  });
});

describe("PUT /rules/:id — versioning", () => {
  it("bumps the version and audits rule.updated", async () => {
    const { app, store } = await setup();
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
      payload: { ...VALID_SECRET, enabled: true },
    });
    const id = (created.json() as { rule: { id: string } }).rule.id;

    const updated = await app.inject({
      method: "PUT",
      url: `/api/v1/rules/${id}`,
      headers: { authorization: `Bearer ${token(app, "approver")}` },
      payload: { ...VALID_SECRET, name: "Custom key v2", enabled: true },
    });
    expect(updated.statusCode).toBe(200);
    expect((updated.json() as { rule: { version: number } }).rule.version).toBe(2);

    const events = await store.audit.list(CLIENT_ID);
    const upd = events.find((e) => e.action === "rule.updated");
    expect(upd!.metadata).toMatchObject({ fromVersion: 1, toVersion: 2 });
  });
});

describe("DELETE /rules/:id", () => {
  it("deletes the rule and audits rule.deleted", async () => {
    const { app, store } = await setup();
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "operator")}` },
      payload: { ...VALID_SECRET, enabled: false },
    });
    const id = (created.json() as { rule: { id: string } }).rule.id;

    const del = await app.inject({
      method: "DELETE",
      url: `/api/v1/rules/${id}`,
      headers: { authorization: `Bearer ${token(app, "operator")}` },
    });
    expect(del.statusCode).toBe(200);

    const gone = await app.inject({
      method: "GET",
      url: `/api/v1/rules/${id}`,
      headers: { authorization: `Bearer ${token(app, "operator")}` },
    });
    expect(gone.statusCode).toBe(404);
    const events = await store.audit.list(CLIENT_ID);
    expect(events.some((e) => e.action === "rule.deleted")).toBe(true);
  });
});

describe("per-client isolation (§8.3)", () => {
  it("a rule authored by one client is invisible to another", async () => {
    const { app } = await setup();
    await app.inject({
      method: "POST",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "operator", "client_a")}` },
      payload: { ...VALID_SECRET, enabled: false },
    });
    const otherList = await app.inject({
      method: "GET",
      url: "/api/v1/rules",
      headers: { authorization: `Bearer ${token(app, "operator", "client_b")}` },
    });
    expect((otherList.json() as { rules: unknown[] }).rules).toHaveLength(0);
  });
});
