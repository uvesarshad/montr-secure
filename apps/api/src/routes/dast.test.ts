/**
 * POST /scans/:id/dast/authorize (A5.4) — scan-scoped convenience wrapper
 * around the real target-based flow (`POST /dast/targets`,
 * `POST /dast/targets/:id/authorize`). Covers: approver-only enforcement,
 * allowlist/production-blocked guardrails identical to the target route, that
 * it find-or-registers + authorizes a DastTarget, and — the part that actually
 * matters for pipeline behavior — that it writes `scan.scope.stagingUrl` +
 * `scan.approver` onto the scan, since `computeAllowLive`
 * (packages/orchestrator/src/fsm.ts) reads those two Scan fields directly and
 * knows nothing about DastTarget.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { Scan } from "@montr/contracts";
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import { buildServer, createInMemoryDeps } from "../server.js";

const PASSWORD = "correct-horse-battery-staple";
const NOW = new Date("2026-08-22T12:00:00.000Z");
const STAGING_URL = "https://staging.example.internal";

interface Session {
  token: string;
  id: string;
}

async function register(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver",
): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/register",
    payload: { email, password: PASSWORD, ...(role ? { role } : {}) },
  });
  return (res.json() as { user: { id: string } }).user.id;
}

async function login(app: FastifyInstance, email: string): Promise<Session> {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email, password: PASSWORD },
  });
  const body = res.json() as { token: string; user: { id: string } };
  return { token: body.token, id: body.user.id };
}

async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver",
): Promise<Session> {
  await register(app, email, role);
  return login(app, email);
}

function allowlistedConfig(): MontrConfig {
  return MontrConfigSchema.parse({ dast: { allowlist: [STAGING_URL] } });
}

const auth = (t: string) => ({ authorization: `Bearer ${t}` });

describe("POST /scans/:id/dast/authorize", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let approver: Session;
  let operator: Session;
  let scanId: string;

  beforeAll(async () => {
    deps = createInMemoryDeps({ config: allowlistedConfig(), clock: { now: () => NOW } });
    app = await buildServer(deps);

    approver = await registerAndLogin(app, "dast-approver@example.internal", "approver");
    const operatorId = await register(app, "dast-operator@example.internal"); // forced viewer
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/role",
      headers: auth(approver.token),
      payload: { userId: operatorId, role: "operator" },
    });
    operator = await login(app, "dast-operator@example.internal");

    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: auth(operator.token),
      payload: { repo: "acme/dast-app", branch: "main", mode: "full" },
    });
    scanId = (created.json() as { scan: Scan }).scan.id;
  });

  afterAll(async () => app.close());

  it("404s for a scan that doesn't exist", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scans/does-not-exist/dast/authorize",
      headers: auth(approver.token),
      payload: { stagingUrl: STAGING_URL },
    });
    expect(res.statusCode).toBe(404);
  });

  it("400s for a malformed stagingUrl", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/dast/authorize`,
      headers: auth(approver.token),
      payload: { stagingUrl: "not-a-url" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("403s for a non-approver role (operator) — this is a hard approver-only gate, like the target route", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/dast/authorize`,
      headers: auth(operator.token),
      payload: { stagingUrl: STAGING_URL },
    });
    expect(res.statusCode).toBe(403);
  });

  it("rejects a URL that is not on the allowlist — same guardrail as POST /dast/targets/:id/authorize", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/dast/authorize`,
      headers: auth(approver.token),
      payload: { stagingUrl: "https://not-allowlisted.example.internal" },
    });
    expect(res.statusCode).toBe(403);
  });

  it("authorizes an allowlisted staging URL: writes scan.scope.stagingUrl + scan.approver (what computeAllowLive actually reads), find-or-registers + authorizes a DastTarget, and audits it", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/dast/authorize`,
      headers: auth(approver.token),
      payload: { stagingUrl: STAGING_URL },
    });

    expect(res.statusCode).toBe(200);
    const { scan } = res.json() as { scan: Scan };
    expect(scan.scope.stagingUrl).toBe(STAGING_URL);
    expect(scan.approver).toBe(approver.id);

    const targets = await deps.store.dastTargets.list(deps.config.clientId);
    const target = targets.find((t) => t.url === STAGING_URL);
    expect(target).toBeDefined();
    expect(target?.enabled).toBe(true);
    expect(target?.approvedById).toBe(approver.id);

    const events = await deps.store.audit.list(deps.config.clientId);
    const authorized = events.filter((e) => e.action === "dast.authorized" && e.scanId === scanId);
    expect(authorized).toHaveLength(1);
  });

  it("reuses the existing DastTarget on a second scan authorized against the same URL (no duplicate target rows)", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: auth(operator.token),
      payload: { repo: "acme/dast-app-2", branch: "main", mode: "full" },
    });
    const secondScanId = (created.json() as { scan: Scan }).scan.id;

    await app.inject({
      method: "POST",
      url: `/api/v1/scans/${secondScanId}/dast/authorize`,
      headers: auth(approver.token),
      payload: { stagingUrl: STAGING_URL },
    });

    const targets = await deps.store.dastTargets.list(deps.config.clientId);
    expect(targets.filter((t) => t.url === STAGING_URL)).toHaveLength(1);
  });

  it("never authorizes another client's scan (client isolation)", async () => {
    const otherDeps = createInMemoryDeps({
      config: allowlistedConfig(),
      clock: { now: () => NOW },
    });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherApprover = await registerAndLogin(
        otherApp,
        "other-dast-approver@example.internal",
        "approver",
      );
      const created = await otherApp.inject({
        method: "POST",
        url: "/api/v1/scans",
        headers: auth(otherApprover.token),
        payload: { repo: "other-client/app", branch: "main", mode: "full" },
      });
      const otherScanId = (created.json() as { scan: Scan }).scan.id;

      const res = await app.inject({
        method: "POST",
        url: `/api/v1/scans/${otherScanId}/dast/authorize`,
        headers: auth(approver.token),
        payload: { stagingUrl: STAGING_URL },
      });
      expect(res.statusCode).toBe(404);
    } finally {
      await otherApp.close();
    }
  });
});

describe("POST /scans/:id/dast/authorize — production-blocked policy invariant", () => {
  it("rejects every authorization attempt when dast.productionBlocked has been tampered with (defense in depth)", async () => {
    const config = MontrConfigSchema.parse({ dast: { allowlist: [STAGING_URL] } });
    // `productionBlocked` is `z.literal(true)` in the schema, so this cast
    // simulates a corrupted config object bypassing that type-level guarantee —
    // the route must still refuse, exactly like the target route does.
    (config as { dast: { productionBlocked: boolean } }).dast.productionBlocked = false;

    const deps = createInMemoryDeps({ config, clock: { now: () => NOW } });
    const app = await buildServer(deps);
    try {
      const approver = await registerAndLogin(app, "tamper-approver@example.internal", "approver");
      const created = await app.inject({
        method: "POST",
        url: "/api/v1/scans",
        headers: auth(approver.token),
        payload: { repo: "acme/tamper-app", branch: "main", mode: "full" },
      });
      const scanId = (created.json() as { scan: Scan }).scan.id;

      const res = await app.inject({
        method: "POST",
        url: `/api/v1/scans/${scanId}/dast/authorize`,
        headers: auth(approver.token),
        payload: { stagingUrl: STAGING_URL },
      });
      expect(res.statusCode).toBe(403);
    } finally {
      await app.close();
    }
  });
});
