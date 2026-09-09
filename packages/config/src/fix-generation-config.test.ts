import { describe, it, expect } from "vitest";
import { parseConfig, loadConfig } from "./loader.js";
import { getHardenedDefaults, FixAgentLoopConfigSchema } from "./schema.js";

/**
 * A5 — bounded agentic fix loop config (opt-in, OFF by default). See
 * `FixAgentLoopConfigSchema`'s doc comment (packages/config/src/schema.ts) and
 * packages/fix/src/generate.ts's `FixGenerationContext.agentLoop`, which this
 * config is wired into by apps/worker/src/runners.ts's Layer-4 adapter.
 */

describe("FixAgentLoopConfigSchema defaults (A5)", () => {
  it("defaults to disabled with maxIterations 3 and maxToolCalls 0", () => {
    const parsed = FixAgentLoopConfigSchema.parse({});
    expect(parsed).toEqual({ enabled: false, maxIterations: 3, maxToolCalls: 0 });
  });

  it("the hardened baseline config carries the same off-by-default agent-loop config", () => {
    const defaults = getHardenedDefaults();
    expect(defaults.fixGeneration).toEqual({
      agentLoop: { enabled: false, maxIterations: 3, maxToolCalls: 0 },
    });
  });

  it("rejects a negative maxIterations", () => {
    expect(() => FixAgentLoopConfigSchema.parse({ maxIterations: -1 })).toThrow();
  });

  it("rejects a non-integer maxIterations", () => {
    expect(() => FixAgentLoopConfigSchema.parse({ maxIterations: 1.5 })).toThrow();
  });

  it("rejects a maxIterations above the sane upper bound (typo guard)", () => {
    expect(() => FixAgentLoopConfigSchema.parse({ maxIterations: 11 })).toThrow();
    expect(() => FixAgentLoopConfigSchema.parse({ maxIterations: 1000 })).toThrow();
  });

  it("rejects a maxToolCalls above the sane upper bound (typo guard)", () => {
    expect(() => FixAgentLoopConfigSchema.parse({ maxToolCalls: 21 })).toThrow();
  });

  it("rejects a negative maxToolCalls", () => {
    expect(() => FixAgentLoopConfigSchema.parse({ maxToolCalls: -1 })).toThrow();
  });

  it("accepts an explicit enabled config within bounds", () => {
    const parsed = FixAgentLoopConfigSchema.parse({
      enabled: true,
      maxIterations: 5,
      maxToolCalls: 2,
    });
    expect(parsed).toEqual({ enabled: true, maxIterations: 5, maxToolCalls: 2 });
  });
});

describe("loadConfig — MONTR_FIX_AGENT_LOOP_* env overlay (A5)", () => {
  it("leaves the agent-loop config at its off-by-default values when unset (regression safety)", () => {
    const config = parseConfig({});
    expect(config.fixGeneration).toEqual({
      agentLoop: { enabled: false, maxIterations: 3, maxToolCalls: 0 },
    });
  });

  it("MONTR_FIX_AGENT_LOOP_ENABLED=true flips agentLoop.enabled on", () => {
    const config = loadConfig({ env: { MONTR_FIX_AGENT_LOOP_ENABLED: "true" } });
    expect(config.fixGeneration.agentLoop.enabled).toBe(true);
  });

  it("MONTR_FIX_AGENT_LOOP_MAX_ITERATIONS and MAX_TOOL_CALLS parse as numbers", () => {
    const config = loadConfig({
      env: {
        MONTR_FIX_AGENT_LOOP_ENABLED: "true",
        MONTR_FIX_AGENT_LOOP_MAX_ITERATIONS: "5",
        MONTR_FIX_AGENT_LOOP_MAX_TOOL_CALLS: "2",
      },
    });
    expect(config.fixGeneration.agentLoop).toEqual({
      enabled: true,
      maxIterations: 5,
      maxToolCalls: 2,
    });
  });

  it("an out-of-bounds MONTR_FIX_AGENT_LOOP_MAX_ITERATIONS fails config validation", () => {
    expect(() => loadConfig({ env: { MONTR_FIX_AGENT_LOOP_MAX_ITERATIONS: "500" } })).toThrow();
  });

  it("an unset MONTR_FIX_AGENT_LOOP_* env leaves the rest of the config untouched", () => {
    const config = loadConfig({ env: { MONTR_CLIENT_ID: "acme" } });
    expect(config.clientId).toBe("acme");
    expect(config.fixGeneration).toEqual({
      agentLoop: { enabled: false, maxIterations: 3, maxToolCalls: 0 },
    });
  });
});
