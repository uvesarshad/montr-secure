import { describe, it, expect, vi } from "vitest";
import {
  BudgetExceededError,
  BudgetPolicySchema,
  KeyTierRejectedError,
  ModelBelowFloorError,
  type LLMRequest,
  type LLMStreamEvent,
  type Provider,
} from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import { getMetrics, type Logger } from "@montr/telemetry";
import { createBudgetRegistry, createCostMeter } from "@montr/cost-meter";
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

/**
 * Model-fallback cascade (A11). Previously a failing model was retried on
 * ITSELF and then the call failed outright — no cascade to an alternate model
 * existed. `config.llm.fallbackModel` (packages/config/src/schema.ts) now lets
 * the gateway retry the SAME request against one alternate model, exactly
 * once, after the primary's retry budget is exhausted.
 */
describe("gateway model-fallback cascade (A11)", () => {
  /** Unlike FakeAdapter, routes success/failure — and the returned `model` — by modelId. */
  class ModelRoutedFakeAdapter implements ProviderAdapter {
    calls: string[] = [];

    constructor(
      private readonly behavior: (modelId: string) => AdapterCompletion | Error,
      readonly provider: Provider = "anthropic",
    ) {}

    resolveModelId(modelId: string): string {
      return modelId;
    }

    async complete(_request: LLMRequest, modelId: string): Promise<AdapterCompletion> {
      this.calls.push(modelId);
      const outcome = this.behavior(modelId);
      if (outcome instanceof Error) throw outcome;
      return outcome;
    }

    // eslint-disable-next-line require-yield -- fake adapter's stream() is never exercised by these tests
    async *stream(): AsyncGenerator<never, void, unknown> {
      throw new Error("not used in these tests");
    }
  }

  function okForModel(modelId: string): AdapterCompletion {
    return {
      id: "c1",
      model: modelId,
      content: "hi",
      stopReason: "end_turn",
      usage: makeUsage(10, 5),
    };
  }

  function fallbackConfig(fallbackModel?: string): MontrConfig {
    return baseConfig(fallbackModel ? { fallbackModel } : {});
  }

  it("falls back to the configured model once the primary exhausts retries, and succeeds", async () => {
    const logger = spyLogger();
    const adapter = new ModelRoutedFakeAdapter((modelId) =>
      modelId === "claude-sonnet-5" ? statusError(429) : okForModel(modelId),
    );
    const gateway = makeGateway(adapter, {
      maxRetries: 1,
      logger,
      config: fallbackConfig("claude-haiku-4-5"),
    });
    const response = await gateway.complete(req({ model: "claude-sonnet-5" }));
    expect(response.model).toBe("claude-haiku-4-5");
    // Primary: 1 initial + 1 retry (both fail) = 2 calls. Fallback: exactly 1 call.
    expect(adapter.calls).toEqual(["claude-sonnet-5", "claude-sonnet-5", "claude-haiku-4-5"]);
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.model_fallback",
      expect.objectContaining({ fromModel: "claude-sonnet-5", toModel: "claude-haiku-4-5" }),
    );
  });

  it("still fails (surfacing the fallback's own error) when the fallback model also fails", async () => {
    const adapter = new ModelRoutedFakeAdapter(() => statusError(429));
    const gateway = makeGateway(adapter, {
      maxRetries: 0,
      config: fallbackConfig("claude-haiku-4-5"),
    });
    await expect(gateway.complete(req({ model: "claude-sonnet-5" }))).rejects.toThrow();
    // Primary: exactly 1 attempt (maxRetries: 0 — no retry budget). Fallback: exactly 1 attempt.
    expect(adapter.calls).toEqual(["claude-sonnet-5", "claude-haiku-4-5"]);
  });

  it("never touches the fallback when no fallbackModel is configured (today's behavior unchanged)", async () => {
    const adapter = new ModelRoutedFakeAdapter(() => statusError(429));
    const gateway = makeGateway(adapter, { maxRetries: 1, config: fallbackConfig() });
    await expect(gateway.complete(req({ model: "claude-sonnet-5" }))).rejects.toThrow();
    expect(adapter.calls).toEqual(["claude-sonnet-5", "claude-sonnet-5"]);
  });

  it("never falls back to itself when fallbackModel equals the resolved primary model", async () => {
    const adapter = new ModelRoutedFakeAdapter(() => statusError(429));
    const gateway = makeGateway(adapter, {
      maxRetries: 0,
      config: fallbackConfig("claude-sonnet-5"),
    });
    await expect(gateway.complete(req({ model: "claude-sonnet-5" }))).rejects.toThrow();
    expect(adapter.calls).toEqual(["claude-sonnet-5"]);
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

describe("gateway PRE-call budget guard (A2, DECIDE-4)", () => {
  const SCAN_ID = "scan_budget_1";

  function hardHaltPolicy(overrides: Record<string, unknown> = {}) {
    return BudgetPolicySchema.parse({ enforcement: "hard_halt", ...overrides });
  }

  it("⛔ refuses a call whose estimated cost alone would clear the ceiling — BEFORE the provider is ever dispatched", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    // Effectively zero budget: even a tiny estimated call clears it.
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 0.0001 }));

    const gateway = makeGateway(adapter, { budgetRegistry: registry });
    // Large maxTokens ⇒ a large worst-case output estimate, well past the ceiling.
    const request = req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 100_000 });

    let caught: unknown;
    try {
      await gateway.complete(request);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(BudgetExceededError);
    expect((caught as BudgetExceededError).code).toBe("BUDGET_EXCEEDED");
    expect((caught as BudgetExceededError).details).toMatchObject({ phase: "pre_call" });
    // ⛔ The whole point: the provider adapter was NEVER called.
    expect(adapter.calls).toBe(0);
  });

  it("still refuses mid-LAYER: a scan already under the ceiling on RECORDED spend is refused by a single call whose ESTIMATE alone would exceed it (this is what the between-layers-only enforceBudget check in the orchestrator cannot catch)", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    const policy = hardHaltPolicy({ maxUsd: 1 });
    registry.register(SCAN_ID, meter, policy);

    // Between-layers check would currently pass: nothing recorded yet.
    expect(meter.checkBudget(policy).exceeded).toBe(false);

    const gateway = makeGateway(adapter, { budgetRegistry: registry });
    // At claude-sonnet-5 rates ($15/M output), 100_000 maxTokens alone prices
    // well above the $1 ceiling — refused before ever reaching the adapter.
    const request = req({
      metadata: { purpose: "confirmation", scanId: SCAN_ID },
      maxTokens: 100_000,
    });
    await expect(gateway.complete(request)).rejects.toBeInstanceOf(BudgetExceededError);
    expect(adapter.calls).toBe(0);
  });

  it("adds already-recorded spend to the new estimate before deciding", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    const policy = hardHaltPolicy({ maxUsd: 0.001 });
    registry.register(SCAN_ID, meter, policy);
    // Simulate a prior call in this scan having already spent right up near the ceiling.
    meter.record({
      modelId: "claude-sonnet-5",
      usage: { inputTokens: 60, outputTokens: 10, totalTokens: 70 },
    });
    expect(meter.checkBudget(policy).exceeded).toBe(false); // not yet over on its own

    const gateway = makeGateway(adapter, { budgetRegistry: registry });
    // A small-but-nonzero additional call tips spent+estimate over the ceiling.
    const request = req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 5_000 });
    await expect(gateway.complete(request)).rejects.toBeInstanceOf(BudgetExceededError);
    expect(adapter.calls).toBe(0);
  });

  it("does NOT refuse when no budgetRegistry is configured (today's behavior, unchanged)", async () => {
    const adapter = new FakeAdapter(() => ok());
    const gateway = makeGateway(adapter, {});
    const request = req({
      metadata: { purpose: "triage", scanId: SCAN_ID },
      maxTokens: 100_000,
    });
    const response = await gateway.complete(request);
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(1);
  });

  it("does NOT refuse when the request carries no scanId (nothing to look up)", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 0.0001 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    const request = req({ metadata: { purpose: "triage" }, maxTokens: 100_000 });
    const response = await gateway.complete(request);
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(1);
  });

  it("does NOT refuse when no context is registered for that scanId", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry(); // nothing registered
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    const request = req({
      metadata: { purpose: "triage", scanId: "unregistered_scan" },
      maxTokens: 100_000,
    });
    const response = await gateway.complete(request);
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(1);
  });

  it("does NOT refuse under a 'warn' enforcement policy — only hard_halt refuses pre-call", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(
      SCAN_ID,
      meter,
      BudgetPolicySchema.parse({ enforcement: "warn", maxUsd: 0.0001 }),
    );
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    const request = req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 100_000 });
    const response = await gateway.complete(request);
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(1);
  });

  it("allows a call comfortably within the ceiling", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 100 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    const response = await gateway.complete(
      req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 64 }),
    );
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(1);
  });

  it("also guards stream() the same way, before any adapter dispatch", async () => {
    class StreamingAdapter extends FakeAdapter {
      streamCalls = 0;
      // eslint-disable-next-line require-yield -- refused before the generator is driven
      async *stream(): AsyncGenerator<never, void, unknown> {
        this.streamCalls++;
        throw new Error("should never be reached — refused pre-call");
      }
    }
    const adapter = new StreamingAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 0.0001 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    const iterator = gateway.stream(
      req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 100_000 }),
    );
    await expect(iterator.next()).rejects.toBeInstanceOf(BudgetExceededError);
    expect(adapter.streamCalls).toBe(0);
  });
});

describe("gateway REAL-TIME accounting into the registry-resolved per-scan meter (A32)", () => {
  const SCAN_ID = "scan_accounting_1";

  function hardHaltPolicy(overrides: Record<string, unknown> = {}) {
    return BudgetPolicySchema.parse({ enforcement: "hard_halt", ...overrides });
  }

  it("⛔ closes the loop: a completed call's usage is recorded into the SAME meter instance the registry hands to assertPreCallBudget() — the meter enforceBudget would read — not just checked against it", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    // Room for the call to go through, but tight enough that a second
    // identical call would be refused pre-call IF (and only if) the first
    // call's spend actually got recorded.
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 0.01 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    // Before any call: nothing spent.
    expect(meter.actual().actualUsd).toBe(0);
    expect(meter.checkBudget(hardHaltPolicy({ maxUsd: 0.01 })).spentUsd).toBe(0);

    const response = await gateway.complete(
      req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 64 }),
    );
    expect(response.content).toBe("hi");
    expect(adapter.calls).toBe(1);

    // ⛔ The whole point of A32: the registry's meter — the exact instance
    // `enforceBudget` and a second `assertPreCallBudget()` call would read —
    // now reflects real recorded spend from the completed call, not $0.
    const actual = meter.actual();
    expect(actual.actualUsd).toBeGreaterThan(0);
    expect(actual.usage.totalTokens).toBeGreaterThan(0);
    const spend = meter.checkBudget(hardHaltPolicy({ maxUsd: 0.01 }));
    expect(spend.spentUsd).toBeGreaterThan(0);
    expect(spend.spentUsd).toBe(actual.actualUsd);
  });

  it("attributes recorded spend to metadata.layer, matching what layer packages actually send", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 100 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    await gateway.complete(
      req({
        metadata: { purpose: "confirmation", scanId: SCAN_ID, layer: "layer3" },
        maxTokens: 64,
      }),
    );

    const actual = meter.actual();
    const layer3 = actual.byLayer.find((entry) => entry.key === "layer3");
    expect(layer3).toBeDefined();
    expect(layer3?.usd).toBeGreaterThan(0);
  });

  it("also records a stream() completion's usage into the registry-resolved meter", async () => {
    class StreamingAdapter extends FakeAdapter {
      async *stream(): AsyncGenerator<LLMStreamEvent, void, unknown> {
        yield { type: "message_done", usage: makeUsage(20, 10) };
      }
    }
    const adapter = new StreamingAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 100 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    const events: unknown[] = [];
    for await (const event of gateway.stream(
      req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 64 }),
    )) {
      events.push(event);
    }

    expect(meter.actual().actualUsd).toBeGreaterThan(0);
  });

  it("also records into a standalone constructor-level costMeter when configured (non-worker/test callers, unchanged)", async () => {
    const adapter = new FakeAdapter(() => ok());
    const costMeter = createCostMeter("standalone_scan");
    const gateway = makeGateway(adapter, { costMeter });

    await gateway.complete(req({ metadata: { purpose: "triage" }, maxTokens: 64 }));

    expect(costMeter.actual().actualUsd).toBeGreaterThan(0);
  });

  it("does not double-count when the registry-resolved meter and the standalone costMeter are the exact same instance", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 100 }));
    // Same instance passed both as the standalone costMeter AND reachable via
    // the registry — a caller could plausibly do this; recording must not
    // double-count usage into it.
    const gateway = makeGateway(adapter, { budgetRegistry: registry, costMeter: meter });

    await gateway.complete(
      req({ metadata: { purpose: "triage", scanId: SCAN_ID }, maxTokens: 64 }),
    );

    const singleCallActual = meter.actual();
    // A second call should roughly double the recorded spend if accounting
    // is correct; if double-counted, the FIRST call alone would already show
    // usage inflated by 2x relative to a single non-duplicated recording.
    // We assert directly: totalTokens for one `ok()` response is 15 (10 in + 5 out).
    expect(singleCallActual.usage.totalTokens).toBe(15);
  });

  it("does NOT record into any meter when the request carries no scanId and no standalone costMeter is configured", async () => {
    const adapter = new FakeAdapter(() => ok());
    const registry = createBudgetRegistry();
    const meter = createCostMeter(SCAN_ID);
    registry.register(SCAN_ID, meter, hardHaltPolicy({ maxUsd: 100 }));
    const gateway = makeGateway(adapter, { budgetRegistry: registry });

    await gateway.complete(req({ metadata: { purpose: "triage" }, maxTokens: 64 }));

    // No scanId on the request ⇒ nothing resolvable in the registry; the
    // unrelated scan's meter must stay untouched.
    expect(meter.actual().actualUsd).toBe(0);
  });
});

describe("A13 — LLM response parse-failure metric", () => {
  it("records a parse failure and logs a warning when responseFormat is json but content isn't valid JSON", async () => {
    const adapter = new FakeAdapter(() => ({
      id: "bad",
      model: "claude-sonnet-5",
      content: "not json at all {",
      stopReason: "end_turn",
      usage: makeUsage(10, 5),
    }));
    const logger = spyLogger();
    const gateway = makeGateway(adapter, { logger });

    const before = getMetrics().snapshot().errors;
    await gateway.complete(req({ responseFormat: "json", metadata: { purpose: "correlation" } }));
    const after = getMetrics().snapshot().errors;

    expect(after).toBeGreaterThan(before);
    expect(logger.warn).toHaveBeenCalledWith(
      "llm.response_parse_failure",
      expect.objectContaining({ purpose: "correlation" }),
    );
  });

  it("does NOT record a parse failure when content is valid JSON", async () => {
    const adapter = new FakeAdapter(() => ({
      id: "good",
      model: "claude-sonnet-5",
      content: '{"reachabilityScore":0.5}',
      stopReason: "end_turn",
      usage: makeUsage(10, 5),
    }));
    const logger = spyLogger();
    const gateway = makeGateway(adapter, { logger });

    await gateway.complete(req({ responseFormat: "json", metadata: { purpose: "correlation" } }));

    expect(logger.warn).not.toHaveBeenCalledWith("llm.response_parse_failure", expect.anything());
  });

  it("does NOT check for parse failures when responseFormat is text", async () => {
    const adapter = new FakeAdapter(() => ({
      id: "x",
      model: "claude-sonnet-5",
      content: "plain prose, not json",
      stopReason: "end_turn",
      usage: makeUsage(10, 5),
    }));
    const logger = spyLogger();
    const gateway = makeGateway(adapter, { logger });

    await gateway.complete(req({ responseFormat: "text" }));

    expect(logger.warn).not.toHaveBeenCalledWith("llm.response_parse_failure", expect.anything());
  });

  it("does NOT flag a parse failure on a tool-use turn with no JSON body", async () => {
    const adapter = new FakeAdapter(() => ({
      id: "t",
      model: "claude-sonnet-5",
      content: "",
      stopReason: "tool_use",
      usage: makeUsage(10, 5),
      toolCalls: [{ id: "call_1", name: "grep", input: { pattern: "x" } }],
    }));
    const logger = spyLogger();
    const gateway = makeGateway(adapter, { logger });

    const response = await gateway.complete(
      req({ responseFormat: "json", metadata: { purpose: "confirmation" } }),
    );

    expect(response.toolCalls).toEqual([{ id: "call_1", name: "grep", input: { pattern: "x" } }]);
    expect(logger.warn).not.toHaveBeenCalledWith("llm.response_parse_failure", expect.anything());
  });
});
