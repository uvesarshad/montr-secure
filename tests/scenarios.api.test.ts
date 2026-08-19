import { afterEach, describe, it, expect } from "vitest";
import type { FastifyInstance } from "fastify";
import { getHardenedDefaults, type MontrConfig } from "@montr/config";
import type { RedTeamScenario } from "@montr/contracts";
import { buildServer, createInMemoryDeps } from "../apps/api/src/server";
import { createInMemoryApiStore, type ApiStore } from "../apps/api/src/store";

/**
 * Phase-4 (§16) — red-team scenario library API. ⛔ RUNNING a scenario is a
 * live-DAST action: approver-only, ALLOWLIST-GATED (production blocked), routed
 * through the Layer-3 guardrails + egress guard, disabled-by-default, and audited.
 * This suite proves a scenario CANNOT be run against a non-allowlisted / production
 * target, and that the API process itself never probes (no transport). Offline.
 */

const CLIENT_ID = "client_scn";
const STAGING = "https://staging.acme.test";
const PROD = "https://www.acme.com";
const CLOCK = { now: () => new Date("2026-07-03T12:00:00.000Z") };

function cfg(dast: Partial<MontrConfig["dast"]>): MontrConfig {
  const base = getHardenedDefaults();
  return { ...base, dast: { ...base.dast, ...dast } };
}

let current: FastifyInstance | undefined;

async function setup(config?: MontrConfig): Promise<{ app: FastifyInstance; store: ApiStore }> {
  const store = createInMemoryApiStore({ clock: CLOCK });
  const deps = createInMemoryDeps({ store, clock: CLOCK, ...(config ? { config } : {}) });
  const app = await buildServer(deps);
  current = app;
  return { app, store };
}

function token(app: FastifyInstance, role: "operator" | "approver" | "viewer"): string {
  return (app as unknown as { jwt: { sign(p: unknown): string } }).jwt.sign({
    sub: `user_${role}`,
    clientId: CLIENT_ID,
    email: `${role}@example.com`,
    role,
  });
}

function scenario(overrides: Partial<RedTeamScenario> = {}): RedTeamScenario {
  return {
    id: overrides.id ?? "scn_seed",
    clientId: CLIENT_ID,
    name: overrides.name ?? "SQLi login probe",
    category: overrides.category ?? "injection",
    steps: overrides.steps ?? [
      { order: 0, action: "GET users", method: "GET", path: "/api/users" },
    ],
    targetAllowlistRef: overrides.targetAllowlistRef ?? STAGING,
    version: 1,
    enabled: overrides.enabled ?? true,
    createdBy: "user_seed",
    createdAt: "2026-07-03T00:00:00.000Z",
  };
}

async function seed(
  store: ApiStore,
  overrides: Partial<RedTeamScenario> = {},
): Promise<RedTeamScenario> {
  const scn = scenario(overrides);
  return store.redTeamScenarios.create(CLIENT_ID, scn);
}

afterEach(async () => {
  await current?.close();
  current = undefined;
});

describe("POST /scenarios — author (disabled-by-default)", () => {
  it("operator authors a scenario, forced disabled, audited", async () => {
    const { app, store } = await setup();
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios",
      headers: { authorization: `Bearer ${token(app, "operator")}` },
      payload: {
        name: "recon",
        category: "recon",
        targetAllowlistRef: STAGING,
        steps: [{ order: 0, action: "probe", method: "GET", path: "/" }],
      },
    });
    expect(res.statusCode).toBe(201);
    expect((res.json() as { scenario: { enabled: boolean } }).scenario.enabled).toBe(false);
    const events = await store.audit.list(CLIENT_ID);
    expect(events.some((e) => e.action === "scenario.created")).toBe(true);
  });

  it("⛔ rejects a step with an absolute-URL path (off-allowlist smuggling) → 400", async () => {
    const { app } = await setup();
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
      payload: {
        name: "bad",
        category: "injection",
        targetAllowlistRef: STAGING,
        steps: [{ order: 0, action: "x", method: "GET", path: "https://evil.test/steal" }],
      },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe("POST /scenarios/:id/run — ⛔ allowlist-gated, approver-only, audited", () => {
  it("runs against an allowlisted staging target (200) and audits scenario.run — API never probes", async () => {
    const { app, store } = await setup(cfg({ enabled: true, allowlist: [STAGING] }));
    await seed(store, { enabled: true, targetAllowlistRef: STAGING });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/scn_seed/run",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
    });
    expect(res.statusCode).toBe(200);
    const run = (res.json() as { run: { authorized: boolean; probed: boolean; target: string } })
      .run;
    expect(run.authorized).toBe(true);
    expect(run.probed).toBe(false); // ⛔ the API process never fires a probe

    const events = await store.audit.list(CLIENT_ID);
    const ran = events.find((e) => e.action === "scenario.run");
    expect(ran).toBeDefined();
    expect(ran!.actor).toMatchObject({ type: "user", role: "approver" });
    expect(ran!.metadata).toMatchObject({ targetHost: "staging.acme.test" });
    expect(await store.audit.verifyChain(CLIENT_ID)).toBe(true);
  });

  it("⛔ refuses a scenario bound to a NON-allowlisted target → 403, no scenario.run audit", async () => {
    const { app, store } = await setup(cfg({ enabled: true, allowlist: [STAGING] }));
    await seed(store, { enabled: true, targetAllowlistRef: "https://evil.attacker.test" });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/scn_seed/run",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
    });
    expect(res.statusCode).toBe(403);
    expect((res.json() as { error: { code: string } }).error.code).toBe(
      "DAST_TARGET_NOT_ALLOWLISTED",
    );
    const events = await store.audit.list(CLIENT_ID);
    expect(events.some((e) => e.action === "scenario.run")).toBe(false);
  });

  it("⛔ refuses an allowlisted-but-PRODUCTION target → 403", async () => {
    const { app, store } = await setup(cfg({ enabled: true, allowlist: [STAGING, PROD] }));
    await seed(store, { enabled: true, targetAllowlistRef: PROD });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/scn_seed/run",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
    });
    expect(res.statusCode).toBe(403);
  });

  it("⛔ refuses to run a DISABLED scenario → 403", async () => {
    const { app, store } = await setup(cfg({ enabled: true, allowlist: [STAGING] }));
    await seed(store, { enabled: false, targetAllowlistRef: STAGING });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/scn_seed/run",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
    });
    expect(res.statusCode).toBe(403);
  });

  it("⛔ default policy: DAST off ⇒ even an enabled allowlisted scenario cannot run → 403", async () => {
    const { app, store } = await setup(); // hardened defaults: dast.enabled=false
    await seed(store, { enabled: true, targetAllowlistRef: STAGING });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/scn_seed/run",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
    });
    expect(res.statusCode).toBe(403);
  });

  it("⛔ operator and viewer cannot run (approver-only) → 403", async () => {
    const { app, store } = await setup(cfg({ enabled: true, allowlist: [STAGING] }));
    await seed(store, { enabled: true, targetAllowlistRef: STAGING });

    for (const role of ["operator", "viewer"] as const) {
      const res = await app.inject({
        method: "POST",
        url: "/api/v1/scenarios/scn_seed/run",
        headers: { authorization: `Bearer ${token(app, role)}` },
      });
      expect(res.statusCode).toBe(403);
    }
  });

  it("enforces the blast-radius cap: a mutating step is blocked (maxMutating=0) but the run is still audited", async () => {
    const { app, store } = await setup(cfg({ enabled: true, allowlist: [STAGING] }));
    await seed(store, {
      enabled: true,
      targetAllowlistRef: STAGING,
      steps: [{ order: 0, action: "delete users", method: "DELETE", path: "/api/users/1" }],
    });

    const res = await app.inject({
      method: "POST",
      url: "/api/v1/scenarios/scn_seed/run",
      headers: { authorization: `Bearer ${token(app, "approver")}` },
    });
    expect(res.statusCode).toBe(200);
    const run = (res.json() as { run: { blocked: boolean; steps: { blocked?: boolean }[] } }).run;
    expect(run.blocked).toBe(true);
    expect(run.steps[0]!.blocked).toBe(true);
    const events = await store.audit.list(CLIENT_ID);
    expect(events.some((e) => e.action === "scenario.run")).toBe(true);
  });
});
