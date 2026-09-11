/**
 * A1 (2026-09-12 red/blue agentic-posture audit) — `processScenarioRunJob` is
 * the ONE place real worker-side scenario execution happens. These tests are
 * the safety-critical core of this change: proving the new written-
 * authorization gate genuinely BLOCKS execution when authorization is
 * missing/stale (never constructing a transport), that every PRE-EXISTING
 * gate (disabled scenario, config invariants) is unweakened, and that a
 * fully-authorized scenario genuinely executes against a REAL local HTTP
 * server (mirrors apps/worker/src/runners.test.ts's A8 end-to-end precedent).
 */
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { RedTeamScenarioSchema, type RedTeamScenario } from "@montr/contracts";
import { processScenarioRunJob, type ScenarioRunStore } from "./service.js";
import { makeInMemoryStore, hardenedConfig } from "../testkit.js";

const CLIENT_ID = "client_test";
const NOW = "2026-09-12T12:00:00.000Z";
const TARGET = "https://staging.example.test";

function baseScenario(overrides: Partial<RedTeamScenario> = {}): RedTeamScenario {
  return RedTeamScenarioSchema.parse({
    id: "scn_run_test_0001",
    clientId: CLIENT_ID,
    name: "Test injection scenario",
    category: "injection",
    steps: [{ order: 0, action: "baseline probe", method: "GET", path: "/api/users" }],
    targetAllowlistRef: TARGET,
    version: 1,
    enabled: true,
    createdBy: "user_test",
    createdAt: NOW,
    ...overrides,
  });
}

const AUTHORIZED_FIELDS = {
  liveAuthorizedById: "user_approver",
  liveAuthorizationReference: "SEC-4821 pentest authorization",
  liveAuthorizedAt: NOW,
} as const;

function job(scenarioId = "scn_run_test_0001") {
  return {
    scenarioId,
    clientId: CLIENT_ID,
    requestedById: "user_approver",
    requestedAt: NOW,
  };
}

interface Fixture {
  store: ScenarioRunStore;
  /** The raw appended audit-event log (testkit's fake `list()` always returns `[]`). */
  audit: readonly { action: string; metadata?: Record<string, unknown> }[];
}

async function storeWith(scenario: RedTeamScenario): Promise<Fixture> {
  const { store, audit } = makeInMemoryStore();
  await store.redTeamScenarios.create(CLIENT_ID, scenario);
  return { store, audit };
}

describe("processScenarioRunJob — safety gating (never constructs a transport when a gate fails)", () => {
  it("rejects when the scenario does not exist", async () => {
    const { store } = makeInMemoryStore();
    const outcome = await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
    });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/not found/i);
  });

  it("rejects a disabled scenario (§11 disabled-by-default, unweakened by A1)", async () => {
    const { store } = await storeWith(
      baseScenario({ enabled: false, ...AUTHORIZED_FIELDS, liveAuthorizedForVersion: 1 }),
    );
    const outcome = await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
    });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/disabled/i);
  });

  it("rejects when config.dast.productionBlocked has been tampered with (defense in depth, unweakened)", async () => {
    const { store } = await storeWith(
      baseScenario({ ...AUTHORIZED_FIELDS, liveAuthorizedForVersion: 1 }),
    );
    const config = hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } });
    (config as unknown as { dast: { productionBlocked: boolean } }).dast.productionBlocked = false;
    const outcome = await processScenarioRunJob(job(), { store, config });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/production/i);
  });

  it("rejects when config.dast.killSwitchEnabled has been tampered with (defense in depth, unweakened)", async () => {
    const { store } = await storeWith(
      baseScenario({ ...AUTHORIZED_FIELDS, liveAuthorizedForVersion: 1 }),
    );
    const config = hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } });
    (config as unknown as { dast: { killSwitchEnabled: boolean } }).dast.killSwitchEnabled = false;
    const outcome = await processScenarioRunJob(job(), { store, config });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/kill switch/i);
  });

  it("A1 — rejects a scenario that was NEVER given written authorization, and never constructs a transport", async () => {
    const { store } = await storeWith(baseScenario()); // no liveAuthorized* fields at all
    let transportBuilt = false;
    const outcome = await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
      transportFactory: async () => {
        transportBuilt = true;
        return { send: async () => ({ status: 200, body: "" }) };
      },
    });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/never been authorized/i);
    expect(transportBuilt).toBe(false);
  });

  it("A1 — rejects a scenario authorized for a STALE version (edited since authorization), and never constructs a transport", async () => {
    const { store } = await storeWith(
      baseScenario({ version: 2, ...AUTHORIZED_FIELDS, liveAuthorizedForVersion: 1 }),
    );
    let transportBuilt = false;
    const outcome = await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
      transportFactory: async () => {
        transportBuilt = true;
        return { send: async () => ({ status: 200, body: "" }) };
      },
    });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/version/i);
    expect(transportBuilt).toBe(false);
  });

  it("A1 — rejects a scenario with an authorization reference missing despite every other field present (fails closed, never trusts a hollow grant)", async () => {
    const { store } = await storeWith(
      baseScenario({
        liveAuthorizedById: "user_approver",
        liveAuthorizedAt: NOW,
        liveAuthorizedForVersion: 1,
        // liveAuthorizationReference intentionally omitted.
      }),
    );
    const outcome = await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
    });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/incomplete/i);
  });

  it("never throws on an unexpected store failure — fails closed and returns a rejected outcome", async () => {
    const store: ScenarioRunStore = {
      redTeamScenarios: {
        get: async () => {
          throw new Error("db exploded");
        },
      },
      audit: { append: async () => ({}) },
    };
    const outcome = await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
    });
    expect(outcome.executed).toBe(false);
    if (!outcome.executed) expect(outcome.rejectedReason).toMatch(/unexpected error/i);
  });

  it("a rejected outcome is audited as scenario.live_run_rejected", async () => {
    const { store, audit } = await storeWith(baseScenario());
    await processScenarioRunJob(job(), {
      store,
      config: hardenedConfig({ dast: { enabled: true, allowlist: [TARGET] } }),
    });
    expect(audit.some((e) => e.action === "scenario.live_run_rejected")).toBe(true);
  });
});

describe("processScenarioRunJob — end to end: real execution against a real local HTTP server", () => {
  it("A1 — a fully, currently authorized scenario genuinely probes a real target and is audited as executed", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const target = `http://127.0.0.1:${port}`;

    try {
      const scenario = baseScenario({
        targetAllowlistRef: target,
        version: 1,
        liveAuthorizedById: "user_approver",
        liveAuthorizationReference: "SEC-4821 pentest authorization",
        liveAuthorizedAt: NOW,
        liveAuthorizedForVersion: 1,
      });
      const { store, audit } = await storeWith(scenario);
      const config = hardenedConfig({ dast: { enabled: true, allowlist: [target] } });

      const outcome = await processScenarioRunJob(job(), { store, config });

      expect(outcome.executed).toBe(true);
      if (outcome.executed) {
        expect(outcome.result.probed).toBe(true);
        expect(outcome.result.requestsSent).toBeGreaterThan(0);
        expect(outcome.result.target).toBe(target);
      }

      const executed = audit.filter((e) => e.action === "scenario.live_run_executed");
      expect(executed).toHaveLength(1);
      expect(executed[0]?.metadata?.["requestsSent"]).toBeGreaterThan(0);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 15_000);

  it("A1 — real execution always runs against the scenario's own authorized targetAllowlistRef (no target-override parameter exists on the job)", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const target = `http://127.0.0.1:${port}`;

    try {
      const scenario = baseScenario({
        targetAllowlistRef: target,
        version: 1,
        liveAuthorizedById: "user_approver",
        liveAuthorizationReference: "SEC-4821 pentest authorization",
        liveAuthorizedAt: NOW,
        liveAuthorizedForVersion: 1,
      });
      const { store } = await storeWith(scenario);
      // Only the REAL target is allowlisted — this would fail closed if
      // execution ever tried to reach anywhere else.
      const config = hardenedConfig({ dast: { enabled: true, allowlist: [target] } });

      const outcome = await processScenarioRunJob(job(), { store, config });
      expect(outcome.executed).toBe(true);
      if (outcome.executed) expect(outcome.result.target).toBe(target);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 15_000);
});
