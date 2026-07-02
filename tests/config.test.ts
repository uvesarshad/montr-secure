import { describe, it, expect } from "vitest";
import { getHardenedDefaults, loadConfig } from "@montr/config";
import { ConfigValidationError } from "@montr/contracts";

describe("@montr/config hardened defaults (§11)", () => {
  const cfg = getHardenedDefaults();

  it("auto-fix is OFF by default", () => {
    expect(cfg.autoFix.enabled).toBe(false);
    expect(cfg.autoFix.prOnly).toBe(true);
  });

  it("DAST is OFF, production blocked, kill switch + approver required", () => {
    expect(cfg.dast.enabled).toBe(false);
    expect(cfg.dast.productionBlocked).toBe(true);
    expect(cfg.dast.killSwitchEnabled).toBe(true);
    expect(cfg.dast.requireApprover).toBe(true);
    expect(cfg.dast.allowlist).toEqual([]);
  });

  it("budget hard-halt is ON by default (DECIDE-4)", () => {
    expect(cfg.budget.enforcement).toBe("hard_halt");
    expect(cfg.budget.requireEstimateApproval).toBe(true);
  });

  it("telemetry is OFF and egress is default-deny", () => {
    expect(cfg.telemetry.enabled).toBe(false);
    expect(cfg.security.egressPolicy).toBe("default-deny");
  });

  it("defaults to the recommended model matrix", () => {
    expect(cfg.llm.modelMatrix.confirmation).toBe("claude-opus-4-8");
    expect(cfg.llm.enforceModelFloor).toBe(true);
  });
});

describe("@montr/config loader", () => {
  it("merges env over defaults", () => {
    const cfg = loadConfig({
      env: { MONTR_AUTOFIX_ENABLED: "true", MONTR_BUDGET_MAX_USD: "12.5" },
    });
    expect(cfg.autoFix.enabled).toBe(true);
    expect(cfg.budget.maxUsdPerScan).toBe(12.5);
    // Untouched safety defaults remain hardened.
    expect(cfg.dast.enabled).toBe(false);
  });

  it("applies explicit overrides at highest precedence", () => {
    const cfg = loadConfig({
      env: { MONTR_AUTOFIX_ENABLED: "true" },
      overrides: { autoFix: { enabled: false } },
    });
    expect(cfg.autoFix.enabled).toBe(false);
  });

  it("throws ConfigValidationError on invalid input", () => {
    expect(() => loadConfig({ overrides: { llm: { provider: "not-a-provider" } } })).toThrow(
      ConfigValidationError,
    );
  });
});
