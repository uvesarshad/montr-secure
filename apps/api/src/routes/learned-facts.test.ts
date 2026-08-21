/**
 * POST/GET /learned-facts (E8) — the explicit operator-facing write path for
 * §15 cross-scan memory. See runners.ts's `loadLearnedFactsContext` for the
 * read/injection side (apps/worker), tested there against a fake gateway.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, createInMemoryDeps } from "../server.js";

const PASSWORD = "correct-horse-battery-staple";
const NOW = new Date("2026-08-22T12:00:00.000Z");

interface Session {
  token: string;
  id: string;
}

async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver" | "viewer",
): Promise<Session> {
  await app.inject({
    method: "POST",
    url: "/api/v1/auth/register",
    payload: { email, password: PASSWORD, ...(role ? { role } : {}) },
  });
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email, password: PASSWORD },
  });
  const body = res.json() as { token: string; user: { id: string } };
  return { token: body.token, id: body.user.id };
}

describe("POST /learned-facts", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: Session;
  let viewer: Session;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    operator = await registerAndLogin(app, "lf-operator@example.internal", "operator");
    viewer = await registerAndLogin(app, "lf-viewer@example.internal", "viewer");
  });

  afterAll(async () => app.close());

  it("requires authentication", async () => {
    const res = await app.inject({ method: "POST", url: "/api/v1/learned-facts" });
    expect(res.statusCode).toBe(401);
  });

  it("rejects a viewer (operator/approver only)", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/learned-facts",
      headers: { authorization: `Bearer ${viewer.token}` },
      payload: {
        repo: "github.com/acme/widgets",
        type: "custom_sanitizer",
        content: { sanitizerName: "acmeSanitizeHtml" },
      },
    });
    expect(res.statusCode).toBe(403);
  });

  it("records a fact and audit-logs it as learned_fact.recorded", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/learned-facts",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: {
        repo: "github.com/acme/widgets",
        type: "framework_idiom",
        content: { note: "all mutations go through the repository layer, never raw prisma" },
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { ok: boolean; fact: { id: string; type: string; repo: string } };
    expect(body.ok).toBe(true);
    expect(body.fact.type).toBe("framework_idiom");
    expect(body.fact.repo).toBe("github.com/acme/widgets");

    const auditEvents = await deps.store.audit.list(deps.config.clientId);
    expect(auditEvents.some((e) => e.action === "learned_fact.recorded")).toBe(true);
  });

  it("rejects an oversized content payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/learned-facts",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: {
        repo: "github.com/acme/widgets",
        type: "operator_decision",
        content: { note: "x".repeat(3000) },
      },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe("GET /learned-facts", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: Session;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    operator = await registerAndLogin(app, "lf-list-operator@example.internal", "operator");

    await app.inject({
      method: "POST",
      url: "/api/v1/learned-facts",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: {
        repo: "github.com/acme/widgets",
        type: "custom_sanitizer",
        content: { sanitizerName: "acmeSanitizeHtml" },
      },
    });
  });

  afterAll(async () => app.close());

  it("requires authentication", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/learned-facts?repo=github.com/acme/widgets",
    });
    expect(res.statusCode).toBe(401);
  });

  it("lists facts for the queried repo", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/learned-facts?repo=github.com/acme/widgets",
      headers: { authorization: `Bearer ${operator.token}` },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { facts: Array<{ type: string }> };
    expect(body.facts).toHaveLength(1);
    expect(body.facts[0]?.type).toBe("custom_sanitizer");
  });

  it("client isolation: a different client never sees this client's facts", async () => {
    const otherDeps = createInMemoryDeps({ clock: { now: () => NOW } });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherOperator = await registerAndLogin(
        otherApp,
        "other-lf-op@example.internal",
        "operator",
      );
      const res = await otherApp.inject({
        method: "GET",
        url: "/api/v1/learned-facts?repo=github.com/acme/widgets",
        headers: { authorization: `Bearer ${otherOperator.token}` },
      });
      const body = res.json() as { facts: unknown[] };
      expect(body.facts).toHaveLength(0);
    } finally {
      await otherApp.close();
    }
  });
});
