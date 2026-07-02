import { describe, it, expect } from "vitest";
import {
  DastTargetNotAllowlistedError,
  EgressBlockedError,
  HumanApprovalRequiredError,
  KillSwitchActivatedError,
  RateLimitExceededError,
  isMontrError,
} from "@montr/contracts";
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import {
  ScopeGuard,
  assertLiveAuthorized,
  isAllowlisted,
  looksLikeProduction,
  type EgressGuardLike,
} from "@montr/confirm";
// Real egress guard from @montr/security (source), proving end-to-end integration.
import { createEgressGuard } from "../packages/security/src/egress-guard";

/**
 * WS-H Layer-3b GUARDRAILS (build-plan §5.4, §11 — NON-NEGOTIABLE). Every test
 * asserts the guardrails actively BLOCK: production + non-allowlisted targets are
 * refused, the kill switch halts, rate/blast-radius caps trip, and all outbound
 * is gated by @montr/security's egress guard. Fully offline (no network).
 */

const STAGING = "https://staging.client.test";

function dastConfig(dast: Record<string, unknown> = {}): MontrConfig {
  return MontrConfigSchema.parse({
    dast: { enabled: true, allowlist: [STAGING], ...dast },
  });
}

/** A permissive egress guard for isolating the scope-guard logic under test. */
const allowAllEgress: EgressGuardLike = { isAllowed: () => true, assert: () => {} };

describe("assertLiveAuthorized — ⛔ approver + allowlist + production gate", () => {
  it("refuses when DAST is disabled by policy", () => {
    const cfg = MontrConfigSchema.parse({}); // dast OFF (hardened default)
    expect(() =>
      assertLiveAuthorized({ config: cfg, allowLive: true, stagingUrl: STAGING }),
    ).toThrow(DastTargetNotAllowlistedError);
  });

  it("requires approver authorization (allowLive) before any live run", () => {
    expect(() =>
      assertLiveAuthorized({ config: dastConfig(), allowLive: false, stagingUrl: STAGING }),
    ).toThrow(HumanApprovalRequiredError);
  });

  it("⛔ refuses a target that is not on the staging allowlist", () => {
    expect(() =>
      assertLiveAuthorized({
        config: dastConfig(),
        allowLive: true,
        stagingUrl: "https://evil.example.com",
      }),
    ).toThrow(DastTargetNotAllowlistedError);
  });

  it("⛔ refuses a production-looking target even if allowlisted (production blocked by policy)", () => {
    const cfg = dastConfig({ allowlist: ["https://www.acme-prod.com"] });
    try {
      assertLiveAuthorized({
        config: cfg,
        allowLive: true,
        stagingUrl: "https://www.acme-prod.com",
      });
      throw new Error("should have thrown");
    } catch (e) {
      expect(isMontrError(e)).toBe(true);
      expect((e as DastTargetNotAllowlistedError).code).toBe("DAST_TARGET_NOT_ALLOWLISTED");
    }
  });

  it("returns the validated target when every guardrail passes", () => {
    const target = assertLiveAuthorized({
      config: dastConfig(),
      allowLive: true,
      stagingUrl: STAGING,
    });
    expect(target).toBe(STAGING);
  });
});

describe("isAllowlisted — strict host match (no bypass)", () => {
  it("defeats a suffix/substring bypass", () => {
    expect(isAllowlisted("https://staging.client.test.evil.com/x", [STAGING])).toBe(false);
    expect(isAllowlisted("https://staging.client.test.evil.com", [STAGING])).toBe(false);
  });
  it("allows deeper paths on the exact allowlisted host", () => {
    expect(isAllowlisted(`${STAGING}/api/users?q=1`, [STAGING])).toBe(true);
    expect(isAllowlisted(STAGING, [STAGING])).toBe(true);
  });
  it("honors a path-scoped allowlist entry", () => {
    const list = ["https://staging.client.test/app"];
    expect(isAllowlisted("https://staging.client.test/app/login", list)).toBe(true);
    expect(isAllowlisted("https://staging.client.test/admin", list)).toBe(false);
  });
});

describe("looksLikeProduction — markers", () => {
  it("flags production markers, clears staging/test markers", () => {
    expect(looksLikeProduction("https://www.acme-prod.com")).toBe(true);
    expect(looksLikeProduction("https://live.acme.com")).toBe(true);
    expect(looksLikeProduction(STAGING)).toBe(false);
    expect(looksLikeProduction("https://qa.acme.internal")).toBe(false);
    expect(looksLikeProduction("http://localhost:3000")).toBe(false);
  });
});

describe("ScopeGuard.assertProbeAllowed — ⛔ per-probe gate", () => {
  it("blocks a non-allowlisted probe target", () => {
    const guard = new ScopeGuard({ config: dastConfig(), egressGuard: allowAllEgress });
    expect(() => guard.assertProbeAllowed("https://evil.example.com/x", "GET")).toThrow(
      DastTargetNotAllowlistedError,
    );
  });

  it("blocks a production probe target", () => {
    const guard = new ScopeGuard({
      config: dastConfig({ allowlist: ["https://www.acme-prod.com"] }),
      egressGuard: allowAllEgress,
    });
    expect(() => guard.assertProbeAllowed("https://www.acme-prod.com/x", "GET")).toThrow(
      DastTargetNotAllowlistedError,
    );
  });

  it("⛔ routes through the egress guard even when the allowlist passes", () => {
    const seen: string[] = [];
    const egress: EgressGuardLike = {
      isAllowed: () => false,
      assert: (t) => {
        seen.push(t);
        throw new EgressBlockedError(`egress denied: ${t}`);
      },
    };
    const guard = new ScopeGuard({ config: dastConfig(), egressGuard: egress });
    expect(() => guard.assertProbeAllowed(`${STAGING}/api/users?q=1`, "GET")).toThrow(
      EgressBlockedError,
    );
    expect(seen).toContain(`${STAGING}/api/users?q=1`);
  });

  it("integrates with the REAL @montr/security egress guard (allowlisted staging only)", () => {
    const cfg = dastConfig();
    const egress = createEgressGuard(cfg, { includeDastTargets: true });
    // The real guard permits the allowlisted staging host and blocks everything else.
    expect(egress.isAllowed(STAGING)).toBe(true);
    expect(egress.isAllowed("https://evil.example.com/exfil")).toBe(false);

    const guard = new ScopeGuard({ config: cfg, egressGuard: egress });
    expect(() => guard.assertProbeAllowed(`${STAGING}/api/users?q=1`, "GET")).not.toThrow();
  });

  it("⛔ enforces the per-scan blast-radius cap", () => {
    const guard = new ScopeGuard({
      config: dastConfig({ scope: { maxRequestsPerScan: 1 } }),
      egressGuard: allowAllEgress,
    });
    guard.assertProbeAllowed(`${STAGING}/a`, "GET");
    guard.record("GET");
    expect(() => guard.assertProbeAllowed(`${STAGING}/b`, "GET")).toThrow(RateLimitExceededError);
    expect(guard.requestsSent).toBe(1);
  });

  it("⛔ blocks mutating probes by default (maxMutatingRequests = 0)", () => {
    const guard = new ScopeGuard({ config: dastConfig(), egressGuard: allowAllEgress });
    expect(() => guard.assertProbeAllowed(`${STAGING}/x`, "POST")).toThrow(RateLimitExceededError);
    expect(() => guard.assertProbeAllowed(`${STAGING}/x`, "GET")).not.toThrow();
  });

  it("⛔ the kill switch halts probing instantly", () => {
    const controller = new AbortController();
    controller.abort(new KillSwitchActivatedError("operator kill"));
    const guard = new ScopeGuard({
      config: dastConfig(),
      egressGuard: allowAllEgress,
      signal: controller.signal,
    });
    expect(() => guard.assertNotKilled()).toThrow(KillSwitchActivatedError);
    expect(() => guard.assertProbeAllowed(`${STAGING}/x`, "GET")).toThrow(KillSwitchActivatedError);
  });
});

describe("ScopeGuard.throttle — rate limit", () => {
  it("waits when the per-second cap is reached", async () => {
    let clock = 0;
    const sleeps: number[] = [];
    const guard = new ScopeGuard({
      config: dastConfig({ scope: { maxRequestsPerSecond: 2 } }),
      egressGuard: allowAllEgress,
      clockMs: () => clock,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    guard.record("GET");
    guard.record("GET");
    await guard.throttle();
    expect(sleeps).toEqual([1000]);

    // Advancing past the window means no further wait.
    clock = 1001;
    await guard.throttle();
    expect(sleeps).toEqual([1000]);
  });
});
