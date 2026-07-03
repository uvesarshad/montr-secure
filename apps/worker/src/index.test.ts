import { describe, it, expect } from "vitest";
import { createFakeLlmGateway } from "@montr/fixtures";
import type { Logger } from "@montr/telemetry";
import { startWorker, type WorkerRuntimeDeps } from "./index.js";
import { makeInMemoryStore, hardenedConfig } from "./testkit.js";

function capturingLogger(): { logger: Logger; warns: Array<{ msg: string; fields?: unknown }> } {
  const warns: Array<{ msg: string; fields?: unknown }> = [];
  const logger: Logger = {
    debug() {},
    info() {},
    warn(msg, fields) {
      warns.push({ msg, ...(fields ? { fields } : {}) });
    },
    error() {},
    child() {
      return logger;
    },
  };
  return { logger, warns };
}

function deps(logger?: Logger): WorkerRuntimeDeps {
  return {
    store: makeInMemoryStore().store,
    gateway: createFakeLlmGateway(),
    redis: "redis://localhost:6379", // never connected — start() is not called
    ...(logger ? { logger } : {}),
  };
}

describe("startWorker — egress boot guard (⛔ golden rule #1)", () => {
  it("constructs without connecting to Redis and validates egress for a hardened config", () => {
    const worker = startWorker(hardenedConfig(), deps());
    expect(typeof worker.start).toBe("function");
    expect(typeof worker.stop).toBe("function");
  });

  it("throws before start() when the orchestrator is accessed", () => {
    const worker = startWorker(hardenedConfig(), deps());
    expect(() => worker.orchestrator).toThrow(/not started/);
  });

  it("⛔ refuses to boot when the egress policy is not default-deny", () => {
    const badConfig = {
      ...hardenedConfig(),
      security: { egressPolicy: "open", allowedEgressHosts: [] },
    } as unknown as ReturnType<typeof hardenedConfig>;
    expect(() => startWorker(badConfig, deps())).toThrow(/default-deny/);
  });

  it("surfaces a broad-provider-default egress warning through the logger", () => {
    const { logger, warns } = capturingLogger();
    // Bedrock with no explicit endpoint ⇒ broad '.amazonaws.com' suffix ⇒ warning
    // (still a valid destination, so boot succeeds).
    const worker = startWorker(hardenedConfig({ llm: { provider: "bedrock" } }), deps(logger));
    expect(worker).toBeDefined();
    expect(warns.some((w) => w.msg === "egress.warning")).toBe(true);
  });
});
