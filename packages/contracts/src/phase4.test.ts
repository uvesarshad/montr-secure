import { describe, it, expect } from "vitest";
import { hasLiveRunAuthorization, RedTeamScenarioSchema, type RedTeamScenario } from "./phase4.js";

/**
 * A1 (2026-09-12 red/blue agentic-posture audit) — `hasLiveRunAuthorization`
 * is the shared safety predicate apps/api's run route, apps/worker's
 * scenario-run consumer, AND apps/web's console badge all gate on. It MUST
 * fail closed: any missing/incomplete/stale field means "not authorized."
 */

const BASE: RedTeamScenario = RedTeamScenarioSchema.parse({
  id: "scn_1",
  clientId: "client_1",
  name: "Test scenario",
  category: "injection",
  steps: [],
  targetAllowlistRef: "https://staging.example.test",
  version: 2,
  enabled: true,
  createdBy: "user_1",
  createdAt: "2026-09-12T00:00:00.000Z",
});

const AUTHORIZED: RedTeamScenario = {
  ...BASE,
  liveAuthorizedById: "user_approver",
  liveAuthorizationReference: "SEC-4821",
  liveAuthorizedAt: "2026-09-12T01:00:00.000Z",
  liveAuthorizedForVersion: 2,
};

describe("RedTeamScenarioSchema — A1 written live-run authorization fields", () => {
  it("accepts a scenario with none of the liveAuthorized* fields set (unauthorized default)", () => {
    expect(() => RedTeamScenarioSchema.parse(BASE)).not.toThrow();
    expect(hasLiveRunAuthorization(BASE)).toBe(false);
  });

  it("accepts a fully-authorized scenario", () => {
    expect(() => RedTeamScenarioSchema.parse(AUTHORIZED)).not.toThrow();
    expect(hasLiveRunAuthorization(AUTHORIZED)).toBe(true);
  });

  it("rejects an empty authorization reference (min length 1)", () => {
    expect(() =>
      RedTeamScenarioSchema.parse({ ...AUTHORIZED, liveAuthorizationReference: "" }),
    ).toThrow();
  });
});

describe("hasLiveRunAuthorization — fail-closed on every incomplete state", () => {
  it("is true only when every field is present, non-empty, and version-matched", () => {
    expect(hasLiveRunAuthorization(AUTHORIZED)).toBe(true);
  });

  it("is false when liveAuthorizedById is missing", () => {
    const { liveAuthorizedById: _drop, ...rest } = AUTHORIZED;
    expect(hasLiveRunAuthorization(rest as RedTeamScenario)).toBe(false);
  });

  it("is false when liveAuthorizedAt is missing", () => {
    const { liveAuthorizedAt: _drop, ...rest } = AUTHORIZED;
    expect(hasLiveRunAuthorization(rest as RedTeamScenario)).toBe(false);
  });

  it("is false when liveAuthorizationReference is missing", () => {
    const { liveAuthorizationReference: _drop, ...rest } = AUTHORIZED;
    expect(hasLiveRunAuthorization(rest as RedTeamScenario)).toBe(false);
  });

  it("is false when liveAuthorizationReference is whitespace-only", () => {
    expect(hasLiveRunAuthorization({ ...AUTHORIZED, liveAuthorizationReference: "   " })).toBe(
      false,
    );
  });

  it("is false when liveAuthorizedForVersion does not match the CURRENT version (stale — edited since authorization)", () => {
    expect(hasLiveRunAuthorization({ ...AUTHORIZED, liveAuthorizedForVersion: 1 })).toBe(false);
    // Simulate an edit bumping the scenario's own version past the grant.
    expect(hasLiveRunAuthorization({ ...AUTHORIZED, version: 3 })).toBe(false);
  });

  it("is false when liveAuthorizedForVersion is entirely absent", () => {
    const { liveAuthorizedForVersion: _drop, ...rest } = AUTHORIZED;
    expect(hasLiveRunAuthorization(rest as RedTeamScenario)).toBe(false);
  });
});
