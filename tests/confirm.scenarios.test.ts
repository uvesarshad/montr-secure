import { describe, it, expect, vi } from "vitest";
import {
  DastTargetNotAllowlistedError,
  HumanApprovalRequiredError,
  KillSwitchActivatedError,
  type RedTeamScenario,
} from "@montr/contracts";
import { getHardenedDefaults, type MontrConfig } from "@montr/config";
import {
  runScenario,
  validateScenario,
  assertScenarioAuthorized,
  type ScenarioRunDeps,
} from "@montr/confirm";
import type { LiveHttpTransport } from "@montr/confirm";

/**
 * ⛔ Red-team scenario library (§16) — a scenario PARAMETERIZES the gated live-DAST
 * engine and adds NO new egress path. These tests prove a scenario CANNOT hit a
 * non-allowlisted or production target: the DAST engine (transport) is mocked and
 * must NEVER be called when the target is off-allowlist / production / DAST off.
 */

const STAGING = "https://staging.acme.test";

function configWith(overrides: Partial<MontrConfig["dast"]> = {}): MontrConfig {
  const base = getHardenedDefaults();
  return { ...base, dast: { ...base.dast, enabled: true, allowlist: [STAGING], ...overrides } };
}

function scenarioOf(overrides: Partial<RedTeamScenario> = {}): RedTeamScenario {
  return {
    id: overrides.id ?? "scn_1",
    clientId: "client_1",
    name: overrides.name ?? "SQLi login probe",
    category: overrides.category ?? "injection",
    steps: overrides.steps ?? [
      { order: 0, action: "GET users with benign query", method: "GET", path: "/api/users" },
      { order: 1, action: "GET users with SQLi payload", method: "GET", path: "/api/users" },
    ],
    targetAllowlistRef: overrides.targetAllowlistRef ?? STAGING,
    version: 1,
    enabled: overrides.enabled ?? true,
    createdBy: "user_1",
    createdAt: "2026-07-03T00:00:00.000Z",
  };
}

/** Allow-everything egress guard so we don't dynamic-import @montr/security here. */
const passEgress = { assert: () => undefined, isAllowed: () => true };

function fakeEngine(): { transport: LiveHttpTransport; send: ReturnType<typeof vi.fn> } {
  const send = vi.fn(async () => ({ status: 200, headers: {}, body: "ok" }));
  return { transport: { send }, send };
}

describe("runScenario — allowlisted staging target (authorized)", () => {
  it("probes through the guard with an injected DAST engine", async () => {
    const { transport, send } = fakeEngine();
    const deps: ScenarioRunDeps = { egressGuard: passEgress, transport };
    const result = await runScenario(
      { scenario: scenarioOf(), config: configWith(), allowLive: true },
      deps,
    );
    expect(result.authorized).toBe(true);
    expect(result.probed).toBe(true);
    expect(result.requestsSent).toBe(2);
    expect(send).toHaveBeenCalledTimes(2);
    expect(result.transcript).toHaveLength(2);
    for (const call of send.mock.calls) {
      expect(String((call[0] as { url: string }).url)).toContain("staging.acme.test");
    }
  });

  it("gate-only mode (no transport) authorizes + checks every step but sends nothing", async () => {
    const result = await runScenario(
      { scenario: scenarioOf(), config: configWith(), allowLive: true },
      { egressGuard: passEgress }, // no transport
    );
    expect(result.authorized).toBe(true);
    expect(result.probed).toBe(false);
    expect(result.requestsSent).toBe(0);
    expect(result.steps).toHaveLength(2);
    expect(result.steps.every((s) => s.probed === false)).toBe(true);
  });
});

describe("⛔ a scenario CANNOT hit a non-allowlisted or production target", () => {
  it("refuses a target that is NOT on the allowlist — the engine is never called", async () => {
    const { transport, send } = fakeEngine();
    await expect(
      runScenario(
        {
          scenario: scenarioOf({ targetAllowlistRef: "https://evil.attacker.test" }),
          config: configWith(),
          allowLive: true,
        },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError);
    expect(send).not.toHaveBeenCalled();
  });

  it("refuses an allowlisted-but-production-looking target — engine never called", async () => {
    const { transport, send } = fakeEngine();
    const prod = "https://www.acme.com";
    await expect(
      runScenario(
        {
          scenario: scenarioOf({ targetAllowlistRef: prod }),
          config: configWith({ allowlist: [STAGING, prod] }), // even if allowlisted…
          allowLive: true,
        },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError); // …production is blocked
    expect(send).not.toHaveBeenCalled();
  });

  it("refuses when DAST is disabled by policy — engine never called", async () => {
    const { transport, send } = fakeEngine();
    await expect(
      runScenario(
        { scenario: scenarioOf(), config: configWith({ enabled: false }), allowLive: true },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(DastTargetNotAllowlistedError);
    expect(send).not.toHaveBeenCalled();
  });

  it("refuses without approver authorization (allowLive=false) — engine never called", async () => {
    const { transport, send } = fakeEngine();
    await expect(
      runScenario(
        { scenario: scenarioOf(), config: configWith(), allowLive: false },
        { egressGuard: passEgress, transport },
      ),
    ).rejects.toBeInstanceOf(HumanApprovalRequiredError);
    expect(send).not.toHaveBeenCalled();
  });
});

describe("⛔ kill switch halts a scenario instantly", () => {
  it("throws KillSwitchActivatedError when the signal is already aborted — nothing is probed", async () => {
    const { transport, send } = fakeEngine();
    const controller = new AbortController();
    controller.abort(new KillSwitchActivatedError("halt"));
    await expect(
      runScenario(
        { scenario: scenarioOf(), config: configWith(), allowLive: true },
        { egressGuard: passEgress, transport, signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(KillSwitchActivatedError);
    expect(send).not.toHaveBeenCalled();
  });
});

describe("validateScenario — a step path must be relative to the allowlisted target", () => {
  it("rejects an absolute-URL step path (off-allowlist smuggling)", () => {
    const res = validateScenario({
      name: "bad",
      targetAllowlistRef: STAGING,
      steps: [{ order: 0, action: "x", method: "GET", path: "https://evil.test/steal" }],
    });
    expect(res.valid).toBe(false);
    expect(res.errors.join(" ")).toMatch(/must be relative/i);
  });

  it("accepts relative paths and warns on mutating steps", () => {
    const res = validateScenario({
      name: "ok",
      targetAllowlistRef: STAGING,
      steps: [
        { order: 0, action: "get", method: "GET", path: "/api/users" },
        { order: 1, action: "post", method: "POST", path: "/api/users" },
      ],
    });
    expect(res.valid).toBe(true);
    expect(res.warnings.join(" ")).toMatch(/mutating/i);
  });

  it("assertScenarioAuthorized returns the validated target for an allowlisted staging URL", () => {
    const target = assertScenarioAuthorized({
      scenario: scenarioOf(),
      config: configWith(),
      allowLive: true,
    });
    expect(target).toBe(STAGING);
  });
});
