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
    expect(cfg.llm.modelMatrix.confirmation).toBe("claude-opus-5");
    expect(cfg.llm.enforceModelFloor).toBe(true);
  });

  // A4 (P0): air-gap SAST ruleset dir. Unset by default -> byte-for-byte
  // unchanged (hosted Semgrep Registry packs) behavior for every existing
  // non-air-gapped install.
  it("discovery.rulesetsDir is unset by default", () => {
    expect(cfg.discovery.rulesetsDir).toBeUndefined();
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

  // A4 (P0): MONTR_DISCOVERY_RULESETS_DIR wires the air-gap SAST ruleset dir.
  it("MONTR_DISCOVERY_RULESETS_DIR sets discovery.rulesetsDir", () => {
    const cfg = loadConfig({ env: { MONTR_DISCOVERY_RULESETS_DIR: "/opt/montr/airgap/semgrep" } });
    expect(cfg.discovery.rulesetsDir).toBe("/opt/montr/airgap/semgrep");
  });

  // A11 (P1): MONTR_LLM_FALLBACK_MODEL wires the gateway's model-fallback cascade.
  it("MONTR_LLM_FALLBACK_MODEL sets llm.fallbackModel; unset by default", () => {
    expect(getHardenedDefaults().llm.fallbackModel).toBeUndefined();
    const cfg = loadConfig({ env: { MONTR_LLM_FALLBACK_MODEL: "claude-sonnet-5" } });
    expect(cfg.llm.fallbackModel).toBe("claude-sonnet-5");
  });
});
