/**
 * Phase-4 (Wave 5) — scan-schedule route tests (offline, in-memory).
 *
 * Covers the pure cron evaluator + the CRUD surface: RBAC (viewers are read-only),
 * ⛔ cron validation before enable, `nextRunAt` computation, the hard per-run
 * `budgetCeiling`, and the audit trail (schedule.created / .updated / .deleted).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer, createInMemoryDeps } from "../server.js";
import { cronIsValid, nextCronRun, parseCron } from "./schedules.js";

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
