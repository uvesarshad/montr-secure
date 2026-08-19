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
import type { KillSwitchSignal, Scan } from "@montr/contracts";
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
