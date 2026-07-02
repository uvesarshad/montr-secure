import { describe, it, expect } from "vitest";
import {
  isMontrError,
  LLMRequestSchema,
  LLMResponseSchema,
  type LLMRequest,
  type LLMStreamEvent,
  type Provider,
} from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import { createCostMeter } from "@montr/cost-meter";
import { createNullLogger, type Logger, type LogFields } from "@montr/telemetry";
import {
  createLlmGateway,
  makeUsage,
  type AdapterCompletion,
  type ProviderAdapter,
} from "@montr/llm-gateway";

const CONFIG = getHardenedDefaults();
const NOW = () => new Date("2026-07-02T00:00:00.000Z");

function request(overrides: Partial<Record<string, unknown>> = {}): LLMRequest {
  return LLMRequestSchema.parse({
    messages: [{ role: "user", content: "confirm this finding" }],
    maxTokens: 256,
    metadata: { purpose: "confirmation" },
    ...overrides,
  });
}

interface FakeOpts {
  provider?: Provider;
  complete?: (req: LLMRequest, modelId: string) => Promise<AdapterCompletion>;
  stream?: (req: LLMRequest, modelId: string) => AsyncGenerator<LLMStreamEvent>;
}

function fakeAdapter(opts: FakeOpts = {}): ProviderAdapter {
  const defaultStream = async function* (): AsyncGenerator<LLMStreamEvent> {
    yield { type: "text_delta", text: "hi" };
    yield { type: "message_done", usage: makeUsage(10, 5), stopReason: "end_turn" };
  };
  return {
    provider: opts.provider ?? "anthropic",
    resolveModelId: (m) => m,
    complete:
      opts.complete ??
      (async (_req, modelId) => ({
        id: "cmpl_1",
        model: modelId,
        content: "hi",
        stopReason: "end_turn",
        usage: makeUsage(10, 5),
      })),
    stream: opts.stream ?? defaultStream,
  };
}

function captureLogger(sink: Array<{ level: string; msg: string; fields: LogFields }>): Logger {
  const make = (): Logger => ({
    debug: (msg, fields) => sink.push({ level: "debug", msg, fields: fields ?? {} }),
    info: (msg, fields) => sink.push({ level: "info", msg, fields: fields ?? {} }),
    warn: (msg, fields) => sink.push({ level: "warn", msg, fields: fields ?? {} }),
    error: (msg, fields) => sink.push({ level: "error", msg, fields: fields ?? {} }),
    child: () => make(),
  });
  return make();
}

describe("@montr/llm-gateway complete()/stream()", () => {
  it("returns a contract-valid LLMResponse", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter(),
      logger: createNullLogger(),
      now: NOW,
    });
    const res = await gw.complete(request());
    expect(LLMResponseSchema.safeParse(res).success).toBe(true);
    expect(res.content).toBe("hi");
    expect(res.provider).toBe("anthropic");
    expect(res.usage.totalTokens).toBe(15);
  });

  it("streams text_delta then message_done", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter(),
      logger: createNullLogger(),
      now: NOW,
    });
    const events: LLMStreamEvent[] = [];
    for await (const ev of gw.stream(request())) events.push(ev);
    expect(events[0]?.type).toBe("text_delta");
    expect(events.at(-1)?.type).toBe("message_done");
  });

  it("emits per-call token accounting to the cost meter", async () => {
    const meter = createCostMeter("scan_x", { now: NOW });
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter(),
      costMeter: meter,
      logger: createNullLogger(),
      now: NOW,
    });
    await gw.complete(request());
    for await (const _ev of gw.stream(request())) void _ev;
    expect(meter.actual().usage.totalTokens).toBe(30);
  });

  it("estimateTokens is deterministic; resolveModel/listModels reflect the matrix", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter(),
      logger: createNullLogger(),
      now: NOW,
    });
    expect(await gw.estimateTokens(request())).toBe(await gw.estimateTokens(request()));
    expect(gw.listModels().length).toBe(3);
    expect(gw.resolveModel("confirmation").tier).toBe("confirmation");
  });
});

describe("⛔ metadata-only logging (golden rule #1)", () => {
  it("never logs prompt/system/code bodies", async () => {
    const sink: Array<{ level: string; msg: string; fields: LogFields }> = [];
    const secret = "SUPER_SECRET_CODE_BODY_zzz";
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter(),
      logger: captureLogger(sink),
      now: NOW,
    });
    await gw.complete(
      LLMRequestSchema.parse({
        system: secret,
        messages: [{ role: "user", content: secret }],
        maxTokens: 64,
        metadata: { purpose: "triage", scanId: "scan_1" },
      }),
    );
    const blob = JSON.stringify(sink);
    expect(blob).not.toContain(secret);
    expect(sink.some((e) => e.msg === "llm.call")).toBe(true);
    const call = sink.find((e) => e.msg === "llm.call");
    expect(call?.fields.totalTokens).toBe(15);
    expect(call?.fields.purpose).toBe("triage");
  });
});

describe("retries, timeouts, structured errors", () => {
  it("retries transient (5xx) errors with backoff then succeeds", async () => {
    let calls = 0;
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter({
        complete: async (_req, modelId) => {
          calls++;
          if (calls < 3) throw Object.assign(new Error("overloaded"), { status: 503 });
          return {
            id: "x",
            model: modelId,
            content: "ok",
            stopReason: "end_turn",
            usage: makeUsage(1, 1),
          };
        },
      }),
      sleep: async () => {},
      maxRetries: 3,
      logger: createNullLogger(),
      now: NOW,
    });
    const res = await gw.complete(request());
    expect(calls).toBe(3);
    expect(res.content).toBe("ok");
  });

  it("does not retry non-retriable (400) errors; maps to a typed MontrError", async () => {
    let calls = 0;
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter({
        complete: async () => {
          calls++;
          throw Object.assign(new Error("bad request"), { status: 400 });
        },
      }),
      maxRetries: 3,
      sleep: async () => {},
      logger: createNullLogger(),
      now: NOW,
    });
    let err: unknown;
    try {
      await gw.complete(request());
    } catch (e) {
      err = e;
    }
    expect(calls).toBe(1);
    expect(isMontrError(err) && err.code).toBe("INTERNAL");
  });

  it("maps 429 to RateLimitExceededError", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter({
        complete: async () => {
          throw Object.assign(new Error("rate limited"), { status: 429 });
        },
      }),
      maxRetries: 0,
      logger: createNullLogger(),
      now: NOW,
    });
    let err: unknown;
    try {
      await gw.complete(request());
    } catch (e) {
      err = e;
    }
    expect(isMontrError(err) && err.code).toBe("RATE_LIMIT_EXCEEDED");
  });

  it("times out a hung call with a retriable INTERNAL error", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter({ complete: () => new Promise<never>(() => {}) }),
      timeoutMs: 10,
      maxRetries: 0,
      logger: createNullLogger(),
      now: NOW,
    });
    let err: unknown;
    try {
      await gw.complete(request());
    } catch (e) {
      err = e;
    }
    expect(isMontrError(err) && err.code).toBe("INTERNAL");
    expect(isMontrError(err) && err.details?.timeoutMs).toBe(10);
  });

  it("surfaces a mid-stream failure as a terminal error event", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: fakeAdapter({
        stream: async function* () {
          yield { type: "text_delta", text: "a" };
          throw Object.assign(new Error("stream broke"), { status: 500 });
        },
      }),
      timeoutMs: 1000,
      maxRetries: 0,
      logger: createNullLogger(),
      now: NOW,
    });
    const events: LLMStreamEvent[] = [];
    for await (const ev of gw.stream(request())) events.push(ev);
    expect(events[0]?.type).toBe("text_delta");
    expect(events.at(-1)?.type).toBe("error");
  });
});
