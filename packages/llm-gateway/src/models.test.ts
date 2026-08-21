import { describe, it, expect, vi } from "vitest";
import { ModelBelowFloorError } from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import type { Logger } from "@montr/telemetry";
import {
  modelRank,
  FLOOR_RANK,
  isBelowFloor,
  checkModelFloor,
  buildDescriptors,
  resolveDescriptor,
  assertModelFloor,
} from "./models.js";

/**
 * Model-floor logic (DECIDE-3): the confirmation tier requires a Sonnet-5-class
 * model or better, so exploit-confirmation accuracy never silently degrades.
 * `assertModelFloor` is the gate the gateway runs at construction — warn by
 * default, hard-throw when `strict`.
 */

function spyLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn(() => logger),
  };
  return logger;
}

function cfg(overrides: { confirmation?: string; enforceModelFloor?: boolean }): MontrConfig {
  return parseConfig({
    llm: {
      apiKey: "sk-test",
      ...(overrides.enforceModelFloor !== undefined
        ? { enforceModelFloor: overrides.enforceModelFloor }
        : {}),
      modelMatrix: {
        triage: "claude-haiku-4-5-20251001",
        default: "claude-sonnet-5",
        confirmation: overrides.confirmation ?? "claude-opus-4-8",
      },
    },
  });
}

/**
 * Refreshed model matrix (A11): the default (unconfigured) model matrix now
 * resolves to `claude-opus-5` as the top/confirmation tier (was
 * `claude-opus-4-8`) and `claude-haiku-4-5` — undated — as the triage tier
 * (was `claude-haiku-4-5-20251001`).
 */
describe("default model matrix resolves the refreshed A11 ids", () => {
  function defaultCfg(): MontrConfig {
    return parseConfig({ llm: { apiKey: "sk-test" } });
  }

  it("resolves the confirmation tier to the current flagship claude-opus-5", () => {
    const d = resolveDescriptor(defaultCfg(), "confirmation");
    expect(d.modelId).toBe("claude-opus-5");
    expect(modelRank(d.modelId)).toBe(4);
    expect(isBelowFloor(d.modelId)).toBe(false);
  });

  it("resolves the triage tier to the undated claude-haiku-4-5", () => {
    const d = resolveDescriptor(defaultCfg(), "triage");
    expect(d.modelId).toBe("claude-haiku-4-5");
    expect(modelRank(d.modelId)).toBe(1);
  });

  it("does not warn at construction with the default (unconfigured) matrix", () => {
    const logger = spyLogger();
    assertModelFloor(defaultCfg(), { logger });
    expect(logger.warn).not.toHaveBeenCalled();
  });
});

describe("modelRank", () => {
  it("ranks opus-class highest (4)", () => {
    expect(modelRank("claude-opus-4-8")).toBe(4);
  });

  it("ranks sonnet-5-class at the floor (3)", () => {
    expect(modelRank("claude-sonnet-5")).toBe(3);
  });

  it("ranks a pre-5 sonnet below the floor (2)", () => {
    expect(modelRank("claude-sonnet-4")).toBe(2);
  });

  it("ranks haiku lowest of the recognized tiers (1)", () => {
    expect(modelRank("claude-haiku-4-5-20251001")).toBe(1);
  });

  it("ranks an unrecognized (e.g. non-Claude BYO) model as 0 — unranked, not flagged", () => {
    expect(modelRank("gpt-4o")).toBe(0);
  });

  it("is case-insensitive", () => {
    expect(modelRank("CLAUDE-SONNET-5")).toBe(3);
  });
});

describe("isBelowFloor", () => {
  it("FLOOR_RANK matches the sonnet-5 rank (3)", () => {
    expect(FLOOR_RANK).toBe(3);
  });

  it("is false for opus (above floor)", () => {
    expect(isBelowFloor("claude-opus-4-8")).toBe(false);
  });

  it("is false for sonnet-5 exactly at the floor", () => {
    expect(isBelowFloor("claude-sonnet-5")).toBe(false);
  });

  it("is true for a sub-floor recognized model (pre-5 sonnet)", () => {
    expect(isBelowFloor("claude-sonnet-4")).toBe(true);
  });

  it("is true for haiku (well below floor)", () => {
    expect(isBelowFloor("claude-haiku-4-5-20251001")).toBe(true);
  });

  it("is false for an unrecognized model — avoids false alarms on BYO models", () => {
    expect(isBelowFloor("gpt-4o")).toBe(false);
  });
});

describe("checkModelFloor", () => {
  it("reports belowFloor + the floor reason for a sub-floor model", () => {
    const check = checkModelFloor("claude-haiku-4-5-20251001");
    expect(check.belowFloor).toBe(true);
    expect(check.reason).toMatch(/Sonnet-5-class/);
  });

  it("reports belowFloor: false for an at-or-above-floor model", () => {
    expect(checkModelFloor("claude-opus-4-8").belowFloor).toBe(false);
  });
});

describe("buildDescriptors / resolveDescriptor", () => {
  it("builds one descriptor per tier from the config's model matrix", () => {
    const descriptors = buildDescriptors(cfg({}));
    expect(descriptors.map((d) => d.tier)).toEqual(["triage", "default", "confirmation"]);
  });

  it("flags the confirmation descriptor belowFloor when its model is sub-floor", () => {
    const descriptors = buildDescriptors(cfg({ confirmation: "claude-haiku-4-5-20251001" }));
    const confirmation = descriptors.find((d) => d.tier === "confirmation")!;
    expect(confirmation.belowFloor).toBe(true);
  });

  it("resolveDescriptor resolves a bare tier name to its configured model", () => {
    const d = resolveDescriptor(cfg({}), "confirmation");
    expect(d.modelId).toBe("claude-opus-4-8");
  });

  it("resolveDescriptor resolves a concrete known model id to its descriptor", () => {
    const d = resolveDescriptor(cfg({}), "claude-sonnet-5");
    expect(d.tier).toBe("default");
  });

  it("resolveDescriptor synthesizes a descriptor for an unknown BYO model id (never throws)", () => {
    const d = resolveDescriptor(cfg({}), "some-custom-model-v3");
    expect(d.modelId).toBe("some-custom-model-v3");
    expect(d.belowFloor).toBe(false);
  });
});

describe("assertModelFloor (construction-time gate)", () => {
  it("is a no-op (returns false, never warns) when enforceModelFloor is disabled", () => {
    const logger = spyLogger();
    const result = assertModelFloor(
      cfg({ confirmation: "claude-haiku-4-5-20251001", enforceModelFloor: false }),
      { logger },
    );
    expect(result).toBe(false);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("returns false and does not warn when the confirmation model is at/above the floor", () => {
    const logger = spyLogger();
    const result = assertModelFloor(cfg({ confirmation: "claude-opus-4-8" }), { logger });
    expect(result).toBe(false);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("WARNS (default, non-strict) on a sub-floor confirmation model — returns true, does not throw", () => {
    const logger = spyLogger();
    const result = assertModelFloor(cfg({ confirmation: "claude-haiku-4-5-20251001" }), {
      logger,
    });
    expect(result).toBe(true);
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.model_below_floor",
      expect.objectContaining({ model: "claude-haiku-4-5-20251001", tier: "confirmation" }),
    );
  });

  it("REJECTS (strict mode) a sub-floor confirmation model by throwing ModelBelowFloorError", () => {
    expect(() =>
      assertModelFloor(cfg({ confirmation: "claude-haiku-4-5-20251001" }), { strict: true }),
    ).toThrow(ModelBelowFloorError);
  });

  it("strict mode does not throw when the confirmation model is at/above the floor", () => {
    expect(() =>
      assertModelFloor(cfg({ confirmation: "claude-sonnet-5" }), { strict: true }),
    ).not.toThrow();
  });
});
