import { describe, it, expect } from "vitest";
import { parseConfig, loadConfig } from "./loader.js";
import { getHardenedDefaults, ConfirmationInvestigationConfigSchema } from "./schema.js";

/**
 * A3 (2026-09-12 red/blue agentic-posture audit) — E1/E2/E4 agentic
 * investigation loop + adversarial verifier panel config. See
 * `ConfirmationInvestigationConfigSchema`'s doc comment (packages/config/src/schema.ts)
 * and packages/confirm/src/confirm.ts's severity-scoping gate, wired into
 * `ConfirmDeps.investigation` by apps/worker/src/runners.ts's Layer-3 adapter.
 *
 * ⛔ Unlike every other agentic-loop toggle in this codebase (A5's
 * fixGeneration.agentLoop, A9's semanticIndex — both OFF by default), this
 * one defaults ON — an explicit owner decision, since `idor` and
 * `broken_access_control` have zero static data-flow proof and this loop is
 * the only static-scan path that can ever confirm them.
 */

describe("ConfirmationInvestigationConfigSchema defaults (A3)", () => {
  it("defaults to enabled: true, scoped to high/critical, with the documented caps", () => {
    const parsed = ConfirmationInvestigationConfigSchema.parse({});
    expect(parsed).toEqual({
      enabled: true,
      maxTurns: 6,
      verifierCount: 4,
      severities: ["high", "critical"],
    });
  });

  it("the hardened baseline config carries the same ON-by-default investigation config", () => {
    const defaults = getHardenedDefaults();
    expect(defaults.confirmation).toEqual({
      investigation: {
        enabled: true,
        maxTurns: 6,
        verifierCount: 4,
        severities: ["high", "critical"],
      },
    });
  });

  it("an operator can explicitly disable it (byte-identical pre-A3 behavior)", () => {
    const parsed = ConfirmationInvestigationConfigSchema.parse({ enabled: false });
    expect(parsed.enabled).toBe(false);
  });

  it("rejects a maxTurns above investigate.ts's hard structural ceiling (8) — typo guard", () => {
    expect(() => ConfirmationInvestigationConfigSchema.parse({ maxTurns: 9 })).toThrow();
    expect(() => ConfirmationInvestigationConfigSchema.parse({ maxTurns: 1000 })).toThrow();
  });

  it("rejects a non-positive or non-integer maxTurns", () => {
    expect(() => ConfirmationInvestigationConfigSchema.parse({ maxTurns: 0 })).toThrow();
    expect(() => ConfirmationInvestigationConfigSchema.parse({ maxTurns: -1 })).toThrow();
    expect(() => ConfirmationInvestigationConfigSchema.parse({ maxTurns: 2.5 })).toThrow();
  });

  it("rejects a verifierCount above the 4-lens hard cap in adversarial.ts — typo guard", () => {
    expect(() => ConfirmationInvestigationConfigSchema.parse({ verifierCount: 5 })).toThrow();
  });

  it("rejects an empty severities list (would silently disable investigation for everything)", () => {
    expect(() => ConfirmationInvestigationConfigSchema.parse({ severities: [] })).toThrow();
  });

  it("rejects an invalid severity value", () => {
    expect(() =>
      ConfirmationInvestigationConfigSchema.parse({ severities: ["catastrophic"] }),
    ).toThrow();
  });

  it("accepts an explicit in-bounds config, e.g. scoping to critical only", () => {
    const parsed = ConfirmationInvestigationConfigSchema.parse({
      enabled: true,
      maxTurns: 8,
      verifierCount: 3,
      severities: ["critical"],
    });
    expect(parsed).toEqual({
      enabled: true,
      maxTurns: 8,
      verifierCount: 3,
      severities: ["critical"],
    });
  });
});

describe("loadConfig — MONTR_CONFIRMATION_INVESTIGATION_* env overlay (A3)", () => {
  it("leaves the ON-by-default investigation config at its defaults when unset", () => {
    const config = parseConfig({});
    expect(config.confirmation).toEqual({
      investigation: {
        enabled: true,
        maxTurns: 6,
        verifierCount: 4,
        severities: ["high", "critical"],
      },
    });
  });

  it("MONTR_CONFIRMATION_INVESTIGATION_ENABLED=false flips it off", () => {
    const config = loadConfig({ env: { MONTR_CONFIRMATION_INVESTIGATION_ENABLED: "false" } });
    expect(config.confirmation.investigation.enabled).toBe(false);
  });

  it("MONTR_CONFIRMATION_INVESTIGATION_MAX_TURNS and VERIFIER_COUNT parse as numbers", () => {
    const config = loadConfig({
      env: {
        MONTR_CONFIRMATION_INVESTIGATION_MAX_TURNS: "4",
        MONTR_CONFIRMATION_INVESTIGATION_VERIFIER_COUNT: "2",
      },
    });
    expect(config.confirmation.investigation.maxTurns).toBe(4);
    expect(config.confirmation.investigation.verifierCount).toBe(2);
  });

  it("MONTR_CONFIRMATION_INVESTIGATION_SEVERITIES parses a comma-separated list", () => {
    const config = loadConfig({
      env: { MONTR_CONFIRMATION_INVESTIGATION_SEVERITIES: "critical" },
    });
    expect(config.confirmation.investigation.severities).toEqual(["critical"]);
  });

  it("an out-of-bounds MONTR_CONFIRMATION_INVESTIGATION_MAX_TURNS fails config validation", () => {
    expect(() =>
      loadConfig({ env: { MONTR_CONFIRMATION_INVESTIGATION_MAX_TURNS: "500" } }),
    ).toThrow();
  });

  it("an unset MONTR_CONFIRMATION_INVESTIGATION_* env leaves the rest of the config untouched", () => {
    const config = loadConfig({ env: { MONTR_CLIENT_ID: "acme" } });
    expect(config.clientId).toBe("acme");
    expect(config.confirmation.investigation.enabled).toBe(true);
  });
});
