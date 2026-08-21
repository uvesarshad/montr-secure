/**
 * Phase-4 (Wave 5) — scan-schedule route tests (offline, in-memory).
 *
 * Covers the pure cron evaluator + the CRUD surface: RBAC (viewers are read-only),
 * ⛔ cron validation before enable, `nextRunAt` computation, the hard per-run
 * `budgetCeiling`, and the audit trail (schedule.created / .updated / .deleted).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { ConfirmedFinding, Scan } from "@montr/contracts";
import { buildServer, createInMemoryDeps } from "../server.js";
import { computeFindingsDelta, cronIsValid, nextCronRun, parseCron } from "./schedules.js";

/* ------------------------------- cron unit ------------------------------- */

describe("cron evaluator (UTC, dependency-free)", () => {
  it("accepts standard 5- and 6-field expressions", () => {
    for (const ok of ["0 0 * * *", "*/15 * * * *", "0 9 * * 1-5", "30 2 1 * *", "0 0 0 * * *"]) {
      expect(cronIsValid(ok)).toBe(true);
    }
  });

  it("accepts month/day-of-week names and folds 7 -> Sunday", () => {
    expect(cronIsValid("0 0 * JAN-MAR MON")).toBe(true);
    const sun = parseCron("0 0 * * 7");
    expect(sun.dow.has(0)).toBe(true);
  });

  it("rejects malformed expressions (fail-safe)", () => {
    for (const bad of [
      "",
      "* * *",
      "99 * * * *",
      "0 0 * * 8",
      "0 0 * 13 *",
      "*/0 * * * *",
      "0 0 L * *",
    ]) {
      expect(cronIsValid(bad)).toBe(false);
    }
  });

  it("computes the next UTC occurrence strictly after `from`", () => {
    const from = new Date("2026-07-03T12:07:30.000Z");
    expect(nextCronRun("0 0 * * *", from)?.toISOString()).toBe("2026-07-04T00:00:00.000Z");
    expect(nextCronRun("*/15 * * * *", from)?.toISOString()).toBe("2026-07-03T12:15:00.000Z");
    // Friday 2026-07-03 -> next weekday 09:00 is Monday 2026-07-06.
    expect(nextCronRun("0 9 * * 1-5", from)?.toISOString()).toBe("2026-07-06T09:00:00.000Z");
  });

  it("returns null for a syntactically valid but impossible date", () => {
    expect(cronIsValid("0 0 30 2 *")).toBe(true); // Feb 30 parses…
    expect(nextCronRun("0 0 30 2 *", new Date("2026-01-01T00:00:00.000Z"))).toBeNull(); // …never fires
  });
});

/* ------------------------------- http CRUD ------------------------------- */

const NOW = new Date("2026-07-03T12:00:00.000Z");
const PASSWORD = "correct-horse-battery-staple";

async function token(
  app: FastifyInstance,
  email: string,
  role?: "operator" | "approver",
): Promise<string> {
  await app.inject({
    method: "POST",
    url: "/api/v1/auth/register",
    payload: { email, password: PASSWORD, ...(role ? { role } : {}) },
  });
  const login = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { email, password: PASSWORD },
  });
  return (login.json() as { token: string }).token;
}

describe("scan-schedule routes", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: string;
  let viewer: string;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    operator = await token(app, "operator@example.internal", "operator"); // bootstrap
    viewer = await token(app, "viewer@example.internal"); // forced viewer
  });

  afterAll(async () => {
    await app.close();
  });

  const auth = (t: string) => ({ authorization: `Bearer ${t}` });

  it("creates an enabled schedule: computes nextRunAt, keeps the hard budget ceiling, audits", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/app", cron: "0 0 * * *", budgetCeiling: 7.5, enabled: true },
    });
    expect(res.statusCode).toBe(201);
    const { schedule } = res.json() as { schedule: Record<string, unknown> };
    expect(schedule.repo).toBe("acme/app");
    expect(schedule.enabled).toBe(true);
    expect(schedule.budgetCeiling).toBe(7.5); // ⛔ hard per-run ceiling preserved
    expect(schedule.mode).toBe("full"); // schema default
    expect(schedule.nextRunAt).toBe("2026-07-04T00:00:00.000Z");
    expect(typeof schedule.id).toBe("string");

    const events = await deps.store.audit.list(deps.config.clientId);
    const created = events.filter((e) => e.action === "schedule.created");
    expect(created).toHaveLength(1);
    expect(created[0]!.targetId).toBe(schedule.id);
    expect(created[0]!.metadata.budgetCeiling).toBe(7.5);
  });

  it("⛔ rejects an invalid cron with 400 (validate before enable)", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/app", cron: "99 * * * *", budgetCeiling: 5, enabled: true },
    });
    expect(res.statusCode).toBe(400);
  });

  it("⛔ refuses to enable a cron that never fires", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/app", cron: "0 0 30 2 *", budgetCeiling: 5, enabled: true },
    });
    expect(res.statusCode).toBe(400);
  });

  it("creates a DISABLED schedule with no nextRunAt (even if cron is unusual)", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/api", cron: "0 0 30 2 *", budgetCeiling: 3, enabled: false },
    });
    expect(res.statusCode).toBe(201);
    const { schedule } = res.json() as { schedule: Record<string, unknown> };
    expect(schedule.enabled).toBe(false);
    expect(schedule.nextRunAt).toBeUndefined();
  });

  it("lists, gets, updates (enable->disable) and deletes; each mutation is audited", async () => {
    const create = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/web", cron: "*/30 * * * *", budgetCeiling: 4, enabled: true },
    });
    const id = (create.json() as { schedule: { id: string } }).schedule.id;

    const list = await app.inject({
      method: "GET",
      url: "/api/v1/schedules",
      headers: auth(viewer),
    });
    expect(list.statusCode).toBe(200);
    expect((list.json() as { schedules: unknown[] }).schedules.length).toBeGreaterThan(0);

    const get = await app.inject({
      method: "GET",
      url: `/api/v1/schedules/${id}`,
      headers: auth(viewer),
    });
    expect(get.statusCode).toBe(200);

    // Disable via PUT: nextRunAt clears, enabledChanged recorded.
    const put = await app.inject({
      method: "PUT",
      url: `/api/v1/schedules/${id}`,
      headers: auth(operator),
      payload: { repo: "acme/web", cron: "*/30 * * * *", budgetCeiling: 4, enabled: false },
    });
    expect(put.statusCode).toBe(200);
    const updated = (put.json() as { schedule: Record<string, unknown> }).schedule;
    expect(updated.enabled).toBe(false);
    expect(updated.nextRunAt).toBeUndefined();

    const del = await app.inject({
      method: "DELETE",
      url: `/api/v1/schedules/${id}`,
      headers: auth(operator),
    });
    expect(del.statusCode).toBe(200);
    const after = await app.inject({
      method: "GET",
      url: `/api/v1/schedules/${id}`,
      headers: auth(viewer),
    });
    expect(after.statusCode).toBe(404);

    const actions = (await deps.store.audit.list(deps.config.clientId))
      .filter((e) => e.targetId === id)
      .map((e) => e.action);
    expect(actions).toContain("schedule.created");
    expect(actions).toContain("schedule.updated");
    expect(actions).toContain("schedule.deleted");
  });

  it("⛔ is read-only for viewers (create/update/delete forbidden)", async () => {
    const create = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(viewer),
      payload: { repo: "acme/app", cron: "0 0 * * *", budgetCeiling: 5, enabled: true },
    });
    expect(create.statusCode).toBe(403);

    const put = await app.inject({
      method: "PUT",
      url: "/api/v1/schedules/whatever",
      headers: auth(viewer),
      payload: { repo: "acme/app", cron: "0 0 * * *", budgetCeiling: 5, enabled: false },
    });
    expect(put.statusCode).toBe(403);

    const del = await app.inject({
      method: "DELETE",
      url: "/api/v1/schedules/whatever",
      headers: auth(viewer),
    });
    expect(del.statusCode).toBe(403);
  });

  it("returns 404 for an unknown schedule", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/schedules/does-not-exist",
      headers: auth(operator),
    });
    expect(res.statusCode).toBe(404);
  });
});

/* --------------------------- delta reporting (E12) --------------------------- */

function finding(
  overrides: Partial<ConfirmedFinding> & { id: string; scanId: string },
): ConfirmedFinding {
  return {
    clientId: overrides.clientId ?? "default",
    title: "SQL injection",
    category: "sql_injection",
    cwe: [],
    severity: "high",
    exposure: "public",
    location: { file: "src/db.ts", line: 10 },
    impact: "database read/write",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: "tainted input reaches raw query",
      dataFlow: [],
      sanitizersBypassed: [],
    },
    status: "confirmed",
    createdAt: "2026-07-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("computeFindingsDelta (pure)", () => {
  it("treats a finding as new when its (category, file, line) identity is absent from the previous set", () => {
    const previous = [finding({ id: "f1", scanId: "s1", location: { file: "a.ts", line: 1 } })];
    const current = [
      finding({ id: "f2", scanId: "s2", location: { file: "a.ts", line: 1 } }), // same identity, different id -> not new
      finding({ id: "f3", scanId: "s2", location: { file: "b.ts", line: 5 }, category: "xss" }),
    ];
    const delta = computeFindingsDelta(previous, current);
    expect(delta.newFindings).toHaveLength(1);
    expect(delta.newFindings[0]!.id).toBe("f3");
    expect(delta.resolvedCount).toBe(0);
    expect(delta.currentConfirmedCount).toBe(2);
    expect(delta.previousConfirmedCount).toBe(1);
  });

  it("counts a previous finding with no matching current identity as resolved", () => {
    const previous = [
      finding({ id: "f1", scanId: "s1", location: { file: "a.ts", line: 1 } }),
      finding({ id: "f2", scanId: "s1", location: { file: "b.ts", line: 2 }, category: "xss" }),
    ];
    const current = [finding({ id: "f3", scanId: "s2", location: { file: "a.ts", line: 1 } })];
    const delta = computeFindingsDelta(previous, current);
    expect(delta.newFindings).toHaveLength(0);
    expect(delta.resolvedCount).toBe(1);
  });

  it("is empty-safe on both sides", () => {
    expect(computeFindingsDelta([], [])).toEqual({
      newFindings: [],
      resolvedCount: 0,
      currentConfirmedCount: 0,
      previousConfirmedCount: 0,
    });
  });
});

describe("GET /schedules/:id/delta (E12)", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: string;
  const CLIENT_ID = "default";

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    operator = await token(app, "delta-operator@example.internal", "operator");
  });

  afterAll(async () => {
    await app.close();
  });

  const auth = (t: string) => ({ authorization: `Bearer ${t}` });

  function scanFixture(overrides: Partial<Scan> & { id: string; createdAt: string }): Scan {
    return {
      clientId: CLIENT_ID,
      repo: "acme/delta-repo",
      branch: "main",
      mode: "full",
      scope: {
        mode: "full",
        includePaths: [],
        excludePaths: [],
        changedFiles: [],
        reachableFromChanges: false,
      },
      status: "completed",
      gateState: "not_started",
      operator: "scan-scheduler",
      ...overrides,
    };
  }

  it("reports 'no baseline yet' when no completed scheduled scan exists for the repo", async () => {
    const create = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/delta-repo-none", cron: "0 0 * * *", budgetCeiling: 5, enabled: true },
    });
    const scheduleId = (create.json() as { schedule: { id: string } }).schedule.id;

    const res = await app.inject({
      method: "GET",
      url: `/api/v1/schedules/${scheduleId}/delta`,
      headers: auth(operator),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Record<string, unknown>;
    expect(body.currentScanId).toBeNull();
    expect(body.previousScanId).toBeNull();
    expect(body.newFindings).toEqual([]);
  });

  it("treats a single completed scheduled run as the full baseline (all confirmed = new)", async () => {
    const create = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/delta-repo-one", cron: "0 0 * * *", budgetCeiling: 5, enabled: true },
    });
    const scheduleId = (create.json() as { schedule: { id: string } }).schedule.id;

    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({
        id: "scan_one",
        repo: "acme/delta-repo-one",
        createdAt: "2026-07-01T00:00:00.000Z",
      }),
    );
    await deps.store.confirmed.create(
      CLIENT_ID,
      finding({ id: "f_one", scanId: "scan_one", clientId: CLIENT_ID }),
    );

    const res = await app.inject({
      method: "GET",
      url: `/api/v1/schedules/${scheduleId}/delta`,
      headers: auth(operator),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      currentScanId: string;
      previousScanId: null;
      newFindings: unknown[];
    };
    expect(body.currentScanId).toBe("scan_one");
    expect(body.previousScanId).toBeNull();
    expect(body.newFindings).toHaveLength(1);
  });

  it("diffs confirmed findings between the two most recent completed scheduled runs, ignoring manual scans", async () => {
    const create = await app.inject({
      method: "POST",
      url: "/api/v1/schedules",
      headers: auth(operator),
      payload: { repo: "acme/delta-repo-two", cron: "0 0 * * *", budgetCeiling: 5, enabled: true },
    });
    const scheduleId = (create.json() as { schedule: { id: string } }).schedule.id;

    // A manual (non-scheduler) scan for the same repo must NOT participate.
    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({
        id: "scan_manual",
        repo: "acme/delta-repo-two",
        operator: "some-human-operator",
        createdAt: "2026-06-15T00:00:00.000Z",
      }),
    );

    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({
        id: "scan_prev",
        repo: "acme/delta-repo-two",
        createdAt: "2026-07-01T00:00:00.000Z",
      }),
    );
    await deps.store.confirmed.create(
      CLIENT_ID,
      finding({
        id: "f_prev_persists",
        scanId: "scan_prev",
        clientId: CLIENT_ID,
        location: { file: "a.ts", line: 1 },
      }),
    );
    await deps.store.confirmed.create(
      CLIENT_ID,
      finding({
        id: "f_prev_resolved",
        scanId: "scan_prev",
        clientId: CLIENT_ID,
        category: "xss",
        location: { file: "resolved.ts", line: 9 },
      }),
    );

    await deps.store.scans.create(
      CLIENT_ID,
      scanFixture({
        id: "scan_curr",
        repo: "acme/delta-repo-two",
        createdAt: "2026-07-08T00:00:00.000Z",
      }),
    );
    await deps.store.confirmed.create(
      CLIENT_ID,
      finding({
        id: "f_curr_persists",
        scanId: "scan_curr",
        clientId: CLIENT_ID,
        location: { file: "a.ts", line: 1 }, // same identity as f_prev_persists -> not new
      }),
    );
    await deps.store.confirmed.create(
      CLIENT_ID,
      finding({
        id: "f_curr_new",
        scanId: "scan_curr",
        clientId: CLIENT_ID,
        category: "path_traversal",
        location: { file: "new.ts", line: 42 },
      }),
    );

    const res = await app.inject({
      method: "GET",
      url: `/api/v1/schedules/${scheduleId}/delta`,
      headers: auth(operator),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      currentScanId: string;
      previousScanId: string;
      newFindings: Array<{ id: string }>;
      resolvedCount: number;
      currentConfirmedCount: number;
      previousConfirmedCount: number;
    };
    expect(body.currentScanId).toBe("scan_curr");
    expect(body.previousScanId).toBe("scan_prev");
    expect(body.newFindings.map((f) => f.id)).toEqual(["f_curr_new"]);
    expect(body.resolvedCount).toBe(1); // f_prev_resolved
    expect(body.currentConfirmedCount).toBe(2);
    expect(body.previousConfirmedCount).toBe(2);
  });

  it("returns 404 for an unknown schedule", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/schedules/does-not-exist/delta",
      headers: auth(operator),
    });
    expect(res.statusCode).toBe(404);
  });
});
