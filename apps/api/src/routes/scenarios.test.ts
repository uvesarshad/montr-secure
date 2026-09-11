/**
 * A1 (2026-09-12 red/blue agentic-posture audit) — the last major red-team
 * gap: `POST /scenarios/:id/run` used to call `runScenario` with an empty
 * deps object (no transport), so a "run" only ever authorized + gate-checked
 * every step and NOTHING ever left the process, anywhere. This suite covers:
 *
 *   - `POST /scenarios/:id/authorize` (new) — approver-only, requires a
 *     non-empty `authorizationReference`, persists it bound to the scenario's
 *     exact current version, and audits `scenario.authorized`.
 *   - An edit (`PUT /scenarios/:id`) invalidates a prior authorization
 *     outright (version bump + fields cleared) — a stale authorization can
 *     never cover a changed scenario.
 *   - `POST /scenarios/:id/run` REFUSES (403, honest rejection, never a
 *     silent no-op) to enqueue real execution when written authorization is
 *     missing or stale, and audits `scenario.live_run_rejected`.
 *   - `POST /scenarios/:id/run` genuinely enqueues a real worker-side
 *     execution job (via `ScenarioRunProducer`) ONLY once written
 *     authorization is present, and audits `scenario.live_run_enqueued`.
 *   - Neither the RBAC (approver-only) nor the disabled-scenario nor the
 *     config-invariant gates that predate A1 are weakened.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { RedTeamScenario, ScenarioRunJob } from "@montr/contracts";
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import { buildServer, createInMemoryDeps } from "../server.js";
import { createInMemoryScenarioRunProducer } from "../scenario-run-producer.js";

const PASSWORD = "correct-horse-battery-staple";
const NOW = new Date("2026-09-12T12:00:00.000Z");
const TARGET = "https://staging.example.internal";
const AUTH_REF = "SEC-4821 pentest authorization, signed 2026-09-12";

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

/** ⛔ Live-DAST genuinely reachable (mirrors apps/worker/src/runners.test.ts's hardenedConfig). */
function liveDastConfig(): MontrConfig {
  return MontrConfigSchema.parse({
    dast: { enabled: true, allowlist: [TARGET], productionBlocked: true, killSwitchEnabled: true },
  });
}

const auth = (t: string) => ({ authorization: `Bearer ${t}` });

/**
 * `POST /scenarios` always creates DISABLED (server-enforced, §11 — see
 * apps/api/src/routes/scenarios.ts's create handler), regardless of any
 * `enabled` field in the request body. To get an enabled scenario for these
 * tests, create then PUT-enable it (the real console flow) — which also
 * bumps `version` to 2, exactly like an operator's own "Enable" click would.
 */
async function createScenario(
  app: FastifyInstance,
  token: string,
  overrides: { enabled?: boolean } = {},
): Promise<RedTeamScenario> {
  const createRes = await app.inject({
    method: "POST",
    url: "/api/v1/scenarios",
    headers: auth(token),
    payload: {
      name: "Test injection scenario",
      category: "injection",
      targetAllowlistRef: TARGET,
      steps: [{ order: 0, action: "baseline probe", method: "GET", path: "/api/users" }],
    },
  });
  expect(createRes.statusCode).toBe(201);
  let scenario = (createRes.json() as { scenario: RedTeamScenario }).scenario;
  expect(scenario.enabled).toBe(false);

  if (overrides.enabled ?? true) {
    const putRes = await app.inject({
      method: "PUT",
      url: `/api/v1/scenarios/${scenario.id}`,
      headers: auth(token),
      payload: {
        name: scenario.name,
        category: scenario.category,
        targetAllowlistRef: scenario.targetAllowlistRef,
        steps: scenario.steps,
        enabled: true,
      },
    });
    expect(putRes.statusCode).toBe(200);
    scenario = (putRes.json() as { scenario: RedTeamScenario }).scenario;
  }
  return scenario;
}

describe("POST /scenarios/:id/authorize (A1 — written authorization)", () => {
  let app: FastifyInstance;
  let approver: Session;
  let operator: Session;
  let scenario: RedTeamScenario;

  beforeAll(async () => {
    const deps = createInMemoryDeps({ config: liveDastConfig(), clock: { now: () => NOW } });
    app = await buildServer(deps);
    approver = await registerAndLogin(app, "authz-approver@example.internal", "approver");
    const operatorId = await register(app, "authz-operator@example.internal");
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/role",
      headers: auth(approver.token),
      payload: { userId: operatorId, role: "operator" },
    });
    operator = await login(app, "authz-operator@example.internal");
    scenario = await createScenario(app, operator.token);
  });

  afterAll(async () => app.close());

  it("403s for a non-approver role (operator) — hard approver-only gate", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/authorize`,
      headers: auth(operator.token),
      payload: { authorizationReference: AUTH_REF },
    });
    expect(res.statusCode).toBe(403);
  });

  it("400s for an empty authorizationReference — a real free-text record is REQUIRED, not optional", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/authorize`,
      headers: auth(approver.token),
      payload: { authorizationReference: "" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("404s for a scenario that doesn't exist", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/does-not-exist/authorize",
      headers: auth(approver.token),
      payload: { authorizationReference: AUTH_REF },
    });
    expect(res.statusCode).toBe(404);
  });

  it("records the written authorization: approver id, reference, timestamp, bound to the current version — and audits it", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/authorize`,
      headers: auth(approver.token),
      payload: { authorizationReference: AUTH_REF },
    });
    expect(res.statusCode).toBe(200);
    const { scenario: saved } = res.json() as { scenario: RedTeamScenario };
    expect(saved.liveAuthorizedById).toBe(approver.id);
    expect(saved.liveAuthorizationReference).toBe(AUTH_REF);
    expect(saved.liveAuthorizedForVersion).toBe(scenario.version);
    expect(saved.liveAuthorizedAt).toBeTruthy();

    const deps = (
      app as unknown as {
        deps: {
          store: { audit: { list(c: string): Promise<{ action: string }[]> } };
          config: { clientId: string };
        };
      }
    ).deps;
    const events = await deps.store.audit.list(deps.config.clientId);
    expect(events.some((e) => e.action === "scenario.authorized")).toBe(true);
  });

  it("an edit (PUT) afterward invalidates the authorization outright (version bump clears it)", async () => {
    const res = await app.inject({
      method: "PUT",
      url: `/api/v1/scenarios/${scenario.id}`,
      headers: auth(operator.token),
      payload: {
        name: scenario.name,
        category: scenario.category,
        targetAllowlistRef: scenario.targetAllowlistRef,
        steps: scenario.steps,
        enabled: true,
      },
    });
    expect(res.statusCode).toBe(200);
    const { scenario: edited } = res.json() as { scenario: RedTeamScenario };
    expect(edited.version).toBeGreaterThan(scenario.version);
    expect(edited.liveAuthorizedById).toBeUndefined();
    expect(edited.liveAuthorizationReference).toBeUndefined();
    expect(edited.liveAuthorizedForVersion).toBeUndefined();
  });
});

describe("POST /scenarios/:id/run (A1 — written-authorization gate + real worker enqueue)", () => {
  let app: FastifyInstance;
  let deps: ReturnType<typeof createInMemoryDeps>;
  let producer: ReturnType<typeof createInMemoryScenarioRunProducer>;
  let approver: Session;
  let operator: Session;

  beforeAll(async () => {
    producer = createInMemoryScenarioRunProducer();
    deps = createInMemoryDeps({
      config: liveDastConfig(),
      clock: { now: () => NOW },
      scenarioRunProducer: producer,
    });
    app = await buildServer(deps);
    approver = await registerAndLogin(app, "run-approver@example.internal", "approver");
    const operatorId = await register(app, "run-operator@example.internal");
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/role",
      headers: auth(approver.token),
      payload: { userId: operatorId, role: "operator" },
    });
    operator = await login(app, "run-operator@example.internal");
  });

  afterAll(async () => app.close());

  it("403s for a non-approver role (operator) — unchanged from before A1", async () => {
    const scenario = await createScenario(app, operator.token);
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/run`,
      headers: auth(operator.token),
    });
    expect(res.statusCode).toBe(403);
  });

  it("403s for a disabled scenario — unchanged from before A1", async () => {
    const scenario = await createScenario(app, operator.token, { enabled: false });
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/run`,
      headers: auth(approver.token),
    });
    expect(res.statusCode).toBe(403);
  });

  it("A1 — 403s, honestly, with a clear reason (never a silent no-op) when a scenario was NEVER authorized — and enqueues NOTHING", async () => {
    const scenario = await createScenario(app, operator.token);
    const jobsBefore = producer.jobs.length;

    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/run`,
      headers: auth(approver.token),
    });

    expect(res.statusCode).toBe(403);
    const body = res.json() as { error?: { message?: string } };
    expect(body.error?.message).toMatch(/never been authorized/i);
    expect(producer.jobs.length).toBe(jobsBefore); // nothing enqueued

    const events = await deps.store.audit.list(deps.config.clientId);
    const rejected = events.filter(
      (e) => e.action === "scenario.live_run_rejected" && e.targetId === scenario.id,
    );
    expect(rejected).toHaveLength(1);
  });

  it("A1 — 403s with a STALE-specific reason when authorized for a now-superseded version (edited after authorization) — and enqueues NOTHING", async () => {
    const scenario = await createScenario(app, operator.token);
    await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/authorize`,
      headers: auth(approver.token),
      payload: { authorizationReference: AUTH_REF },
    });
    // Edit invalidates it (version bump).
    await app.inject({
      method: "PUT",
      url: `/api/v1/scenarios/${scenario.id}`,
      headers: auth(operator.token),
      payload: {
        name: scenario.name,
        category: scenario.category,
        targetAllowlistRef: scenario.targetAllowlistRef,
        steps: scenario.steps,
        enabled: true,
      },
    });

    const jobsBefore = producer.jobs.length;
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/run`,
      headers: auth(approver.token),
    });
    expect(res.statusCode).toBe(403);
    const body = res.json() as { error?: { message?: string } };
    expect(body.error?.message).toMatch(/never been authorized/i);
    expect(producer.jobs.length).toBe(jobsBefore);
  });

  it("A1 — succeeds and genuinely enqueues a real worker-side execution job ONLY once written authorization is complete and current", async () => {
    const scenario = await createScenario(app, operator.token);
    await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/authorize`,
      headers: auth(approver.token),
      payload: { authorizationReference: AUTH_REF },
    });

    const jobsBefore = producer.jobs.length;
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/scenarios/${scenario.id}/run`,
      headers: auth(approver.token),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as {
      run: { target: string; probed: boolean };
      liveExecution: { enqueued: boolean; jobId?: string };
    };
    expect(body.liveExecution.enqueued).toBe(true);
    expect(body.liveExecution.jobId).toBeTruthy();
    // Gate-only preview never probes from the API process — unchanged (A1
    // added real execution in the WORKER, not in this route).
    expect(body.run.probed).toBe(false);

    expect(producer.jobs.length).toBe(jobsBefore + 1);
    const job = producer.jobs.at(-1) as ScenarioRunJob;
    expect(job.scenarioId).toBe(scenario.id);
    expect(job.requestedById).toBe(approver.id);

    const events = await deps.store.audit.list(deps.config.clientId);
    const enqueued = events.filter(
      (e) => e.action === "scenario.live_run_enqueued" && e.targetId === scenario.id,
    );
    expect(enqueued).toHaveLength(1);
    const ran = events.filter((e) => e.action === "scenario.run" && e.targetId === scenario.id);
    expect(ran).toHaveLength(1);
  });

  it("A1 — production-blocked policy invariant still refuses BEFORE the written-authorization gate is even checked (defense in depth unweakened)", async () => {
    const config = liveDastConfig();
    (config as { dast: { productionBlocked: boolean } }).dast.productionBlocked = false;
    const tamperedDeps = createInMemoryDeps({ config, clock: { now: () => NOW } });
    const tamperedApp = await buildServer(tamperedDeps);
    try {
      const tamperedApprover = await registerAndLogin(
        tamperedApp,
        "tamper-approver@example.internal",
        "approver",
      );
      const scenario = await createScenario(tamperedApp, tamperedApprover.token);
      const res = await tamperedApp.inject({
        method: "POST",
        url: `/api/v1/scenarios/${scenario.id}/run`,
        headers: auth(tamperedApprover.token),
      });
      expect(res.statusCode).toBe(403);
    } finally {
      await tamperedApp.close();
    }
  });
});
