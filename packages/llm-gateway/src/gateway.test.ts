import { describe, it, expect, vi } from "vitest";
import {
  KeyTierRejectedError,
  ModelBelowFloorError,
  type LLMRequest,
  type Provider,
} from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import type { Logger } from "@montr/telemetry";
import { MontrLlmGateway, createLlmGateway, type CreateGatewayOptions } from "./gateway.js";
import { makeUsage, type ProviderAdapter, type AdapterCompletion } from "./adapters/index.js";

/**
 * Integration coverage for the gateway's retry/backoff, model-floor, and
 * key-tier guard wiring — the three areas the egress test suite deliberately
 * doesn't touch (see adapters/egress.test.ts). Every test injects a fake
 * `ProviderAdapter` (no real LLM API calls) and a no-op `sleep` so retries
 * run instantly and deterministically.
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

/**
 * A fake adapter whose `complete()` behavior is driven by a per-call-count
 * callback. `provider` is configurable because the gateway derives its
 * key-tier classification from `adapter.provider` (the adapter is the
 * concrete stand-in for "which provider is actually being called"), not
 * from `config.llm.provider` directly.
 */
class FakeAdapter implements ProviderAdapter {
  calls = 0;

  constructor(
    private readonly behavior: (callNumber: number) => AdapterCompletion | Error,
    readonly provider: Provider = "anthropic",
  ) {}

  resolveModelId(modelId: string): string {
    return modelId;
  }

  async complete(_request: LLMRequest, modelId: string): Promise<AdapterCompletion> {
    this.calls++;
    const outcome = this.behavior(this.calls);
    if (outcome instanceof Error) throw outcome;
    return { ...outcome, model: outcome.model ?? modelId };
  }

  // eslint-disable-next-line require-yield -- fake adapter's stream() is never exercised by these tests
  async *stream(): AsyncGenerator<never, void, unknown> {
    throw new Error("not used in these tests");
  }
}

function ok(id = "c1"): AdapterCompletion {
  return {
    id,
    model: "claude-sonnet-5",
    content: "hi",
    stopReason: "end_turn",
    usage: makeUsage(10, 5),
  };
}

function statusError(status: number, message = `status ${status}`): Error {
  return Object.assign(new Error(message), { status });
}

function baseConfig(overrides: Record<string, unknown> = {}): MontrConfig {
  return parseConfig({
    llm: { apiKey: "sk-test", provider: "anthropic", ...overrides },
  });
}

function req(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return {
    messages: [{ role: "user", content: "hi" }],
    maxTokens: 64,
    metadata: { purpose: "triage" },
    ...overrides,
  } as LLMRequest;
}

const noSleep = async () => {};

function makeGateway(
  adapter: ProviderAdapter,
  opts: Partial<CreateGatewayOptions> = {},
): MontrLlmGateway {
  return new MontrLlmGateway({
    config: opts.config ?? baseConfig(),
    adapter,
    sleep: noSleep,
    logger: spyLogger(),
    ...opts,
  }) as MontrLlmGateway;
}

describe("gateway retry/backoff (via complete())", () => {
  it("retries a retryable (429) failure and succeeds on a later attempt", async () => {
    const adapter = new FakeAdapter((n) => (n < 3 ? statusError(429) : ok()));
    const gateway = makeGateway(adapter, { maxRetries: 3 });
    const response = await gateway.complete(req());
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(3);
  });

  it("does NOT retry a non-retryable (401) failure — fails on the first attempt", async () => {
    const adapter = new FakeAdapter(() => statusError(401));
    const gateway = makeGateway(adapter, { maxRetries: 5 });
    await expect(gateway.complete(req())).rejects.toThrow();
    expect(adapter.calls).toBe(1);
  });

  it("exceeds max retries and surfaces the final (typed) error", async () => {
    const adapter = new FakeAdapter((n) => statusError(503, `attempt ${n} unavailable`));
    const gateway = makeGateway(adapter, { maxRetries: 2 });
    let caught: unknown;
    try {
      await gateway.complete(req());
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toContain("attempt 3 unavailable");
    // 1 initial attempt + 2 retries = 3 calls total.
    expect(adapter.calls).toBe(3);
  });

  it("maps a 429 failure that exhausts retries to a retriable RATE_LIMIT_EXCEEDED error", async () => {
    const adapter = new FakeAdapter(() => statusError(429));
    const gateway = makeGateway(adapter, { maxRetries: 1 });
    let caught: unknown;
    try {
      await gateway.complete(req());
    } catch (err) {
      caught = err;
    }
    expect((caught as { code?: string }).code).toBe("RATE_LIMIT_EXCEEDED");
    expect((caught as { retriable?: boolean }).retriable).toBe(true);
    expect(adapter.calls).toBe(2);
  });

  it("succeeds without retrying when the first attempt succeeds", async () => {
    const adapter = new FakeAdapter(() => ok());
    const gateway = makeGateway(adapter, { maxRetries: 3 });
    await gateway.complete(req());
    expect(adapter.calls).toBe(1);
  });
});

describe("gateway model-floor guard (DECIDE-3)", () => {
  function floorConfig(confirmation: string, enforceModelFloor = true): MontrConfig {
    return baseConfig({
      enforceModelFloor,
      modelMatrix: {
        triage: "claude-haiku-4-5-20251001",
        default: "claude-sonnet-5",
        confirmation,
      },
    });
  }

  it("WARNS at construction (default, non-strict) on a sub-floor confirmation model", () => {
    const logger = spyLogger();
    new MontrLlmGateway({
      config: floorConfig("claude-haiku-4-5-20251001"),
      adapter: new FakeAdapter(() => ok()),
      logger,
      sleep: noSleep,
    });
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.model_below_floor",
      expect.objectContaining({ model: "claude-haiku-4-5-20251001", tier: "confirmation" }),
    );
  });

  it("does not warn at construction when the confirmation model is at/above the floor", () => {
    const logger = spyLogger();
    new MontrLlmGateway({
      config: floorConfig("claude-opus-4-8"),
      adapter: new FakeAdapter(() => ok()),
      logger,
      sleep: noSleep,
    });
    expect(logger.warn).not.toHaveBeenCalledWith("llm.model_below_floor", expect.anything());
  });

  it("REJECTS construction (strictModelFloor: true) with ModelBelowFloorError", () => {
    expect(
      () =>
        new MontrLlmGateway({
          config: floorConfig("claude-haiku-4-5-20251001"),
          adapter: new FakeAdapter(() => ok()),
          strictModelFloor: true,
          sleep: noSleep,
        }),
    ).toThrow(ModelBelowFloorError);
  });

  it("also warns at CALL time for a confirmation-tier request on a sub-floor model, once per model", async () => {
    const logger = spyLogger();
    const adapter = new FakeAdapter(() => ok());
    const gateway = makeGateway(adapter, {
      config: floorConfig("claude-haiku-4-5-20251001"),
      logger,
    });
    (logger.warn as ReturnType<typeof vi.fn>).mockClear(); // drop the construction-time warning
    await gateway.complete(req({ tier: "confirmation", metadata: { purpose: "confirmation" } }));
    await gateway.complete(req({ tier: "confirmation", metadata: { purpose: "confirmation" } }));
    const callTimeWarnings = (logger.warn as ReturnType<typeof vi.fn>).mock.calls.filter(
      ([event]) => event === "llm.model_below_floor",
    );
    expect(callTimeWarnings).toHaveLength(1); // deduped: warned once per model, not per call
  });

  it("does not warn at call time when enforceModelFloor is disabled", async () => {
    const logger = spyLogger();
    const adapter = new FakeAdapter(() => ok());
    const gateway = makeGateway(adapter, {
      config: floorConfig("claude-haiku-4-5-20251001", false),
      logger,
    });
    (logger.warn as ReturnType<typeof vi.fn>).mockClear();
    await gateway.complete(req({ tier: "confirmation", metadata: { purpose: "confirmation" } }));
    expect(logger.warn).not.toHaveBeenCalledWith("llm.model_below_floor", expect.anything());
  });
});

describe("gateway key-tier guard (§11)", () => {
  it("'warn' mode (default) on a direct Anthropic key: keyTier is 'unknown' (suspect) and logs a warning", () => {
    const logger = spyLogger();
    const gateway = new MontrLlmGateway({
      config: baseConfig({ keyTierGuard: "warn" }),
      adapter: new FakeAdapter(() => ok()),
      logger,
      sleep: noSleep,
    });
    expect(gateway.keyTier).toBe("unknown");
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.key_tier_suspect",
      expect.objectContaining({ provider: "anthropic", keyTier: "unknown" }),
    );
  });

  it("'block' mode on a direct Anthropic key THROWS KeyTierRejectedError at construction", () => {
    expect(
      () =>
        new MontrLlmGateway({
          config: baseConfig({ keyTierGuard: "block" }),
          adapter: new FakeAdapter(() => ok()),
          sleep: noSleep,
        }),
    ).toThrow(KeyTierRejectedError);
  });

  it("'block' mode does NOT throw when the key tier is enterprise-confirmed (cloud provider)", () => {
    const gateway = new MontrLlmGateway({
      config: parseConfig({
        llm: { apiKey: "sk-test", provider: "bedrock", keyTierGuard: "block" },
      }),
      adapter: new FakeAdapter(() => ok(), "bedrock"),
      sleep: noSleep,
    });
    expect(gateway.keyTier).toBe("enterprise");
  });

  it("'block' mode does NOT throw when an operator declares the key tier enterprise", () => {
    const gateway = new MontrLlmGateway({
      config: baseConfig({ keyTierGuard: "block" }),
      adapter: new FakeAdapter(() => ok()),
      declaredKeyTier: "enterprise",
      sleep: noSleep,
    });
    expect(gateway.keyTier).toBe("enterprise");
  });

  it("'off' mode allows a suspect tier silently (no warning, no throw)", () => {
    const logger = spyLogger();
    const gateway = new MontrLlmGateway({
      config: baseConfig({ keyTierGuard: "off" }),
      adapter: new FakeAdapter(() => ok()),
      logger,
      sleep: noSleep,
    });
    expect(gateway.keyTier).toBe("unknown");
    expect(logger.warn).not.toHaveBeenCalledWith("llm.key_tier_suspect", expect.anything());
  });
});

describe("createLlmGateway factory", () => {
  it("constructs a working LLMGateway instance", async () => {
    const gateway = createLlmGateway({
      config: baseConfig(),
      adapter: new FakeAdapter(() => ok()),
      sleep: noSleep,
    });
    const response = await gateway.complete(req());
    expect(response.content).toBe("hi");
  });
});
