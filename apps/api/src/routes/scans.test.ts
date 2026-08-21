/**
 * POST /scans/:id/kill — ⛔ kill switch route (A15).
 *
 * Covers: successful kill by an authorized role (operator/approver, mirroring
 * apps/web's `canActivateKillSwitch`), 403 for an unauthorized role (viewer),
 * that the orchestrator's real `kill(signal)` lifecycle method is invoked with
 * the right `KillSwitchSignal`, and that a `dast.kill_switch` audit event is
 * recorded. This route uses `requireRole` (not the hard `requireApprover`
 * guard), so the reject path is an ordinary RBAC 403 and must NOT increment
 * the `gate.bypass_attempt` metric — that metric is reserved for
 * approver-gated actions (fix gate / DAST target authorization).
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  AppMapSchema,
  type AppMap,
  type KillSwitchSignal,
  type PipelineEvent,
  type Scan,
} from "@montr/contracts";
import { getMetrics } from "@montr/telemetry";
import { buildServer, createInMemoryDeps } from "../server.js";

const PASSWORD = "correct-horse-battery-staple"; // >= 12 chars (PasswordSchema)
const NOW = new Date("2026-08-19T12:00:00.000Z");

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

describe("POST /scans/:id/kill", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let killSpy: ReturnType<typeof vi.fn>;
  let approver: Session;
  let operator: Session;
  let viewer: Session;
  let scanId: string;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    // Wrap the stub orchestrator's `kill` so tests can assert the exact
    // KillSwitchSignal it was invoked with, while still exercising the real
    // state-mutation behavior (status -> cancelled, gateState -> blocked).
    const realKill = deps.orchestrator.kill.bind(deps.orchestrator);
    killSpy = vi.fn((signal: KillSwitchSignal) => realKill(signal));
    deps.orchestrator = { ...deps.orchestrator, kill: killSpy };

    app = await buildServer(deps);

    // Bootstrap user claims `approver` so it can elevate the next user via the
    // approver-gated /auth/role route (self-registration otherwise always
    // forces the least-privilege `viewer` role for non-bootstrap users).
    approver = await registerAndLogin(app, "approver@example.internal", "approver");

    const operatorId = await register(app, "operator@example.internal"); // forced viewer initially
    const elevate = await app.inject({
      method: "POST",
      url: "/api/v1/auth/role",
      headers: { authorization: `Bearer ${approver.token}` },
      payload: { userId: operatorId, role: "operator" },
    });
    expect(elevate.statusCode).toBe(200);
    operator = await login(app, "operator@example.internal"); // fresh token carries the new role

    viewer = await registerAndLogin(app, "viewer@example.internal"); // forced viewer, no elevation

    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/app", branch: "main", mode: "full" },
    });
    expect(created.statusCode).toBe(201);
    scanId = (created.json() as { scan: Scan }).scan.id;
  });

  it("POST /scans transitions the created scan to running, not just queued", async () => {
    // Regression guard: createScan() alone only persists a "queued" row —
    // orchestrator.start() is what actually enqueues Layer 0. A caller that
    // stops at createScan() leaves the scan queued forever.
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/other-app", branch: "main", mode: "full" },
    });
    expect(res.statusCode).toBe(201);
    const { scan } = res.json() as { scan: Scan };
    expect(scan.status).toBe("running");
  });

  afterEach(() => {
    killSpy.mockClear();
  });

  afterAll(async () => {
    await app.close();
  });

  const auth = (t: string) => ({ authorization: `Bearer ${t}` });

  it("404s for a scan that doesn't exist", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scans/does-not-exist/kill",
      headers: auth(operator.token),
      payload: { reason: "test" },
    });
    expect(res.statusCode).toBe(404);
    expect(killSpy).not.toHaveBeenCalled();
  });

  it("400s when `reason` is missing", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/kill`,
      headers: auth(operator.token),
      payload: {},
    });
    expect(res.statusCode).toBe(400);
    expect(killSpy).not.toHaveBeenCalled();
  });

  it("403s for an unauthorized role (viewer) WITHOUT firing the gate-bypass-attempt metric", async () => {
    const before = getMetrics().snapshot().gateBypassAttempts;

    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/kill`,
      headers: auth(viewer.token),
      payload: { reason: "unauthorized attempt" },
    });

    expect(res.statusCode).toBe(403);
    expect(killSpy).not.toHaveBeenCalled();
    const body = res.json() as { error: { code: string; message: string } };
    expect(body.error.code).toBe("FORBIDDEN");
    expect(body.error.message).toMatch(/role/i);

    // This route is gated by `requireRole`, not the hard `requireApprover`
    // guard, so it must NOT count as a gate-bypass attempt.
    const after = getMetrics().snapshot().gateBypassAttempts;
    expect(after).toBe(before);
  });

  it("halts the scan for an authorized role (operator), invokes the orchestrator's real kill(), and audits it", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/kill`,
      headers: auth(operator.token),
      payload: { reason: "manual kill switch" },
    });

    expect(res.statusCode).toBe(200);
    const { scan } = res.json() as { scan: Scan };
    expect(scan.id).toBe(scanId);
    expect(scan.status).toBe("cancelled");
    expect(scan.gateState).toBe("blocked");

    // The orchestrator's real lifecycle `kill(signal)` was invoked with the
    // right scope/args — not a bespoke store mutation bypassing it.
    expect(killSpy).toHaveBeenCalledTimes(1);
    expect(killSpy).toHaveBeenCalledWith({
      scope: "scan",
      scanId,
      reason: "manual kill switch",
      requestedBy: operator.id,
      requestedByRole: "operator",
      at: NOW.toISOString(),
    });

    const events = await deps.store.audit.list(deps.config.clientId);
    const kills = events.filter((e) => e.action === "dast.kill_switch" && e.scanId === scanId);
    expect(kills).toHaveLength(1);
    expect(kills[0]!.actor).toEqual({ type: "user", id: operator.id, role: "operator" });
    expect(kills[0]!.targetId).toBe(scanId);
    expect(kills[0]!.metadata.reason).toBe("manual kill switch");
  });

  it("also allows the approver role", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: auth(operator.token),
      payload: { repo: "acme/other", branch: "main", mode: "full" },
    });
    const otherScanId = (created.json() as { scan: Scan }).scan.id;

    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${otherScanId}/kill`,
      headers: auth(approver.token),
      payload: { reason: "approver-initiated halt" },
    });

    expect(res.statusCode).toBe(200);
    expect(killSpy).toHaveBeenCalledWith(
      expect.objectContaining({ requestedBy: approver.id, requestedByRole: "approver" }),
    );
  });
});

/**
 * POST /scans/:id/resume (A3) — same auth/CSRF/role pattern as cancel/kill.
 * Wraps the stub orchestrator's `resume` so tests can assert it was invoked
 * with the right scanId while still exercising its real terminal-state guard
 * (stub-orchestrator.ts, mirroring @montr/orchestrator's controller.ts
 * resume()): completed/cancelled scans are a no-op, everything else resumes.
 */
describe("POST /scans/:id/resume", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let resumeSpy: ReturnType<typeof vi.fn>;
  let operator: Session;
  let viewer: Session;
  let runningScanId: string;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    const realResume = deps.orchestrator.resume.bind(deps.orchestrator);
    resumeSpy = vi.fn((scanId: string) => realResume(scanId));
    deps.orchestrator = { ...deps.orchestrator, resume: resumeSpy };

    app = await buildServer(deps);

    // Bootstrap user claims `approver` (first registrant of a client may claim
    // any role — see auth.ts); it then elevates the operator candidate.
    const approver = await registerAndLogin(app, "resume-approver@example.internal", "approver");
    const operatorId = await register(app, "resume-operator@example.internal"); // forced viewer initially
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/role",
      headers: { authorization: `Bearer ${approver.token}` },
      payload: { userId: operatorId, role: "operator" },
    });
    operator = await login(app, "resume-operator@example.internal");
    viewer = await registerAndLogin(app, "resume-viewer@example.internal"); // forced viewer

    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/resume-app", branch: "main", mode: "full" },
    });
    runningScanId = (created.json() as { scan: Scan }).scan.id;
  });

  afterEach(() => resumeSpy.mockClear());
  afterAll(async () => app.close());

  const auth = (t: string) => ({ authorization: `Bearer ${t}` });

  it("404s for a scan that doesn't exist", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scans/does-not-exist/resume",
      headers: auth(operator.token),
    });
    expect(res.statusCode).toBe(404);
    expect(resumeSpy).not.toHaveBeenCalled();
  });

  it("403s for an unauthorized role (viewer)", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${runningScanId}/resume`,
      headers: auth(viewer.token),
    });
    expect(res.statusCode).toBe(403);
    expect(resumeSpy).not.toHaveBeenCalled();
  });

  it("resumes a running scan, invokes the orchestrator's real resume(), and audits it", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${runningScanId}/resume`,
      headers: auth(operator.token),
    });

    expect(res.statusCode).toBe(200);
    const { scan } = res.json() as { scan: Scan };
    expect(scan.id).toBe(runningScanId);
    expect(scan.status).toBe("running");
    expect(resumeSpy).toHaveBeenCalledWith(runningScanId);

    const events = await deps.store.audit.list(deps.config.clientId);
    const resumed = events.filter((e) => e.action === "scan.resumed" && e.scanId === runningScanId);
    expect(resumed).toHaveLength(1);
    expect(resumed[0]!.actor).toEqual({ type: "user", id: operator.id, role: "operator" });
  });

  it("a completed scan is correctly rejected — resume() is a no-op and status stays completed", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: auth(operator.token),
      payload: { repo: "acme/terminal-app", branch: "main", mode: "full" },
    });
    const scanId = (created.json() as { scan: Scan }).scan.id;

    // Force the scan into a terminal state directly via the store (bypassing
    // the orchestrator, which is the whole point — we want to know resume()
    // itself refuses to revive a terminal scan, not just that nothing called it).
    const scan = await deps.store.scans.get(deps.config.clientId, scanId);
    await deps.store.scans.update(deps.config.clientId, {
      ...(scan as Scan),
      status: "completed",
      finishedAt: NOW.toISOString(),
    });

    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/resume`,
      headers: auth(operator.token),
    });

    expect(res.statusCode).toBe(200);
    const { scan: after } = res.json() as { scan: Scan };
    expect(after.status).toBe("completed"); // NOT flipped back to "running"
    expect(resumeSpy).toHaveBeenCalledWith(scanId);
  });

  it("a cancelled scan is also correctly rejected", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: auth(operator.token),
      payload: { repo: "acme/cancelled-app", branch: "main", mode: "full" },
    });
    const scanId = (created.json() as { scan: Scan }).scan.id;

    await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/cancel`,
      headers: auth(operator.token),
    });

    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scans/${scanId}/resume`,
      headers: auth(operator.token),
    });

    expect(res.statusCode).toBe(200);
    const { scan: after } = res.json() as { scan: Scan };
    expect(after.status).toBe("cancelled");
  });

  it("never resumes another client's scan (client isolation) — 404, not leaked state", async () => {
    const otherDeps = createInMemoryDeps({ clock: { now: () => NOW } });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherOperator = await registerAndLogin(otherApp, "other-client-op@example.internal");
      const created = await otherApp.inject({
        method: "POST",
        url: "/api/v1/scans",
        headers: auth(otherOperator.token),
        payload: { repo: "other-client/app", branch: "main", mode: "full" },
      });
      const otherScanId = (created.json() as { scan: Scan }).scan.id;

      // Same operator token, but hitting the FIRST app's server — different
      // client entirely (each buildServer() call gets its own in-memory store).
      const res = await app.inject({
        method: "POST",
        url: `/api/v1/scans/${otherScanId}/resume`,
        headers: auth(operator.token),
      });
      expect(res.statusCode).toBe(404);
    } finally {
      await otherApp.close();
    }
  });
});

/** GET /scans/:id/progress (A5.1) — drains the orchestrator's event stream
 * without hanging on the live tail, mapping PipelineEvent -> ProgressEvent. */
describe("GET /scans/:id/progress", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: Session;
  let scanId: string;
  // Route handlers destructure `orchestrator` from `deps` once, at registration
  // time (inside `registerScanRoutes`, called by `buildServer` below) — so
  // reassigning `deps.orchestrator` AFTER the server is built would silently no-op.
  // Indirect through a mutable `let` the wired-in `events` override reads at
  // CALL time instead, so individual `it()` blocks can swap the event stream.
  let eventsImpl: (scanId: string) => AsyncIterable<PipelineEvent> = (id) =>
    deps.orchestrator.events(id);

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    const stubEvents = deps.orchestrator.events.bind(deps.orchestrator);
    eventsImpl = stubEvents;
    deps.orchestrator = { ...deps.orchestrator, events: (id: string) => eventsImpl(id) };
    app = await buildServer(deps);
    operator = await registerAndLogin(app, "progress-operator@example.internal", "operator");

    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/progress-app", branch: "main", mode: "full" },
    });
    scanId = (created.json() as { scan: Scan }).scan.id;
  });

  afterAll(async () => app.close());

  const auth = (t: string) => ({ authorization: `Bearer ${t}` });

  it("404s for a scan that doesn't exist", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/scans/does-not-exist/progress",
      headers: auth(operator.token),
    });
    expect(res.statusCode).toBe(404);
  });

  it("maps progress/layer_started/layer_completed events and drops scan-level events, without hanging on a never-ending live stream", async () => {
    const history: PipelineEvent[] = [
      { type: "layer_started", scanId, layer: "layer0", at: "2026-08-22T00:00:00.000Z" },
      {
        type: "progress",
        scanId,
        layer: "layer0",
        pct: 40,
        phase: "parsing",
        at: "2026-08-22T00:00:01.000Z",
      },
      { type: "layer_completed", scanId, layer: "layer0", at: "2026-08-22T00:00:02.000Z" },
      // Scan-level event with no single `layer` in the ProgressEvent sense —
      // must be dropped by the route's mapping, not crash it.
      { type: "gate_required", scanId, gate: "estimate", at: "2026-08-22T00:00:03.000Z" },
    ];
    // A real (never-completed) async iterable, like the live orchestrator's
    // EventBus.subscribe() would return for an in-flight scan: history first,
    // then it would block waiting for the next event forever. The route must
    // NOT hang waiting for that — it must drain history and return.
    eventsImpl = () => ({
      [Symbol.asyncIterator]() {
        let i = 0;
        return {
          next: async (): Promise<IteratorResult<PipelineEvent>> => {
            if (i < history.length) {
              const value = history[i] as PipelineEvent;
              i += 1;
              return { value, done: false };
            }
            // Simulate the live tail: never resolves.
            return new Promise<IteratorResult<PipelineEvent>>(() => {});
          },
        };
      },
    });

    const res = await app.inject({
      method: "GET",
      url: `/api/v1/scans/${scanId}/progress`,
      headers: auth(operator.token),
    });

    expect(res.statusCode).toBe(200);
    const events = res.json() as Array<{ layer: string; phase: string; pct: number }>;
    expect(events).toEqual([
      { scanId, layer: "layer0", phase: "started", pct: 0, at: "2026-08-22T00:00:00.000Z" },
      { scanId, layer: "layer0", phase: "parsing", pct: 40, at: "2026-08-22T00:00:01.000Z" },
      { scanId, layer: "layer0", phase: "completed", pct: 100, at: "2026-08-22T00:00:02.000Z" },
    ]);
  });

  it("never leaks another client's progress (client isolation)", async () => {
    const otherDeps = createInMemoryDeps({ clock: { now: () => NOW } });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherOperator = await registerAndLogin(otherApp, "other-progress-op@example.internal");
      const created = await otherApp.inject({
        method: "POST",
        url: "/api/v1/scans",
        headers: auth(otherOperator.token),
        payload: { repo: "other-client/app", branch: "main", mode: "full" },
      });
      const otherScanId = (created.json() as { scan: Scan }).scan.id;

      const res = await app.inject({
        method: "GET",
        url: `/api/v1/scans/${otherScanId}/progress`,
        headers: auth(operator.token),
      });
      expect(res.statusCode).toBe(404);
    } finally {
      await otherApp.close();
    }
  });
});

/** GET /scans/:id/appmap (A5.2). */
describe("GET /scans/:id/appmap", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let operator: Session;
  let scanId: string;
  let appMap: AppMap;

  beforeAll(async () => {
    deps = createInMemoryDeps({ clock: { now: () => NOW } });
    app = await buildServer(deps);
    operator = await registerAndLogin(app, "appmap-operator@example.internal", "operator");

    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { authorization: `Bearer ${operator.token}` },
      payload: { repo: "acme/appmap-app", branch: "main", mode: "full" },
    });
    scanId = (created.json() as { scan: Scan }).scan.id;

    appMap = AppMapSchema.parse({
      id: "appmap_1",
      clientId: deps.config.clientId,
      scanId,
      repo: "acme/appmap-app",
      branch: "main",
      commitSha: "a".repeat(40),
      createdAt: NOW.toISOString(),
    });
    await deps.store.appMaps.create(deps.config.clientId, appMap);

    const scan = await deps.store.scans.get(deps.config.clientId, scanId);
    await deps.store.scans.update(deps.config.clientId, {
      ...(scan as Scan),
      appMapId: appMap.id,
    });
  });

  afterAll(async () => app.close());

  const auth = (t: string) => ({ authorization: `Bearer ${t}` });

  it("404s for a scan that doesn't exist", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/scans/does-not-exist/appmap",
      headers: auth(operator.token),
    });
    expect(res.statusCode).toBe(404);
  });

  it("404s when the scan has no appMapId yet", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: auth(operator.token),
      payload: { repo: "acme/no-appmap-yet", branch: "main", mode: "full" },
    });
    const otherScanId = (created.json() as { scan: Scan }).scan.id;

    const res = await app.inject({
      method: "GET",
      url: `/api/v1/scans/${otherScanId}/appmap`,
      headers: auth(operator.token),
    });
    expect(res.statusCode).toBe(404);
  });

  it("returns the bare AppMap (no wrapper), matching the client's Promise<AppMap> contract", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/api/v1/scans/${scanId}/appmap`,
      headers: auth(operator.token),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as AppMap;
    expect(body.id).toBe(appMap.id);
    expect(body.repo).toBe("acme/appmap-app");
    // Bare object, not `{ appMap: ... }`.
    expect(body).not.toHaveProperty("appMap");
  });

  it("never leaks another client's App Map (client isolation)", async () => {
    const otherDeps = createInMemoryDeps({ clock: { now: () => NOW } });
    const otherApp = await buildServer(otherDeps);
    try {
      const otherOperator = await registerAndLogin(otherApp, "other-appmap-op@example.internal");
      const created = await otherApp.inject({
        method: "POST",
        url: "/api/v1/scans",
        headers: auth(otherOperator.token),
        payload: { repo: "other-client/appmap-app", branch: "main", mode: "full" },
      });
      const otherScanId = (created.json() as { scan: Scan }).scan.id;

      const res = await app.inject({
        method: "GET",
        url: `/api/v1/scans/${otherScanId}/appmap`,
        headers: auth(operator.token),
      });
      expect(res.statusCode).toBe(404);
    } finally {
      await otherApp.close();
    }
  });
});
