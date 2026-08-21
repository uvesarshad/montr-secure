/**
 * GET /pull-requests (A5.3) — cross-scan PR aggregate, client-scoped, NOT
 * scan-scoped (unlike the rest of findings.ts).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { PullRequestSchema, type PullRequest, type Scan } from "@montr/contracts";
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
  role?: "operator" | "approver",
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

function pr(
  overrides: Partial<PullRequest> & { id: string; scanId: string; clientId: string },
): PullRequest {
  return PullRequestSchema.parse({
    provider: "github",
    branch: "montr/fix-1",
    baseBranch: "main",
    title: "Fix SQL injection in db.ts",
    bodySummary: "Auto-eligible fix, opened after human gate approval.",
    fixIds: ["fix_1"],
    createdAt: NOW.toISOString(),
    ...overrides,
  });
}

describe("GET /pull-requests (cross-scan aggregate)", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: Session;
  let scanIdA: string;
  let scanIdB: string;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    operator = await registerAndLogin(app, "pr-operator@example.internal", "operator");

    const createdA = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/app-a", branch: "main", mode: "full" },
    });
    scanIdA = (createdA.json() as { scan: Scan }).scan.id;

    const createdB = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/app-b", branch: "main", mode: "full" },
    });
    scanIdB = (createdB.json() as { scan: Scan }).scan.id;

    // Two PRs across TWO different scans — the aggregate must include both.
    await deps.store.pullRequests.create(deps.config.clientId, {
      ...pr({ id: "pr_1", scanId: scanIdA, clientId: deps.config.clientId }),
    });
    await deps.store.pullRequests.create(deps.config.clientId, {
      ...pr({ id: "pr_2", scanId: scanIdB, clientId: deps.config.clientId, title: "Bump lodash" }),
    });
  });

  afterAll(async () => app.close());

  it("requires authentication", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/pull-requests" });
    expect(res.statusCode).toBe(401);
  });

  it("returns the bare PullRequest[] (no wrapper) across every scan for the client", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/pull-requests",
      headers: { authorization: `Bearer ${operator.token}` },
    });

    expect(res.statusCode).toBe(200);
    const prs = res.json() as PullRequest[];
    expect(prs.map((p) => p.id).sort()).toEqual(["pr_1", "pr_2"]);
    expect(new Set(prs.map((p) => p.scanId))).toEqual(new Set([scanIdA, scanIdB]));
  });

  it("never leaks another client's pull requests (client isolation)", async () => {
    const otherDeps = createInMemoryDeps({ clock: { now: () => NOW } });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherOperator = await registerAndLogin(otherApp, "other-pr-op@example.internal");
      const created = await otherApp.inject({
        method: "POST",
        url: "/api/v1/scans",
        headers: { authorization: `Bearer ${otherOperator.token}` },
        payload: { repo: "other-client/app", branch: "main", mode: "full" },
      });
      const otherScanId = (created.json() as { scan: Scan }).scan.id;
      await otherDeps.store.pullRequests.create(otherDeps.config.clientId, {
        ...pr({ id: "pr_other", scanId: otherScanId, clientId: otherDeps.config.clientId }),
      });

      // Query the FIRST app/client — must not see "pr_other".
      const res = await app.inject({
        method: "GET",
        url: "/api/v1/pull-requests",
        headers: { authorization: `Bearer ${operator.token}` },
      });
      const prs = res.json() as PullRequest[];
      expect(prs.some((p) => p.id === "pr_other")).toBe(false);

      // And the reverse: the other client must not see "pr_1"/"pr_2".
      const otherRes = await otherApp.inject({
        method: "GET",
        url: "/api/v1/pull-requests",
        headers: { authorization: `Bearer ${otherOperator.token}` },
      });
      const otherPrs = otherRes.json() as PullRequest[];
      expect(otherPrs.map((p) => p.id)).toEqual(["pr_other"]);
    } finally {
      await otherApp.close();
    }
  });
});
