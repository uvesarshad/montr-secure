import { describe, it, expect } from "vitest";
import {
  LLMRequestSchema,
  LLMResponseSchema,
  type LLMRequest,
  type LLMStreamEvent,
  type Provider,
} from "@montr/contracts";
import { parseConfig } from "@montr/config";
import { createCostMeter } from "@montr/cost-meter";
import { createNullLogger } from "@montr/telemetry";
import { createFakeLlmGateway } from "@montr/fixtures";
import {
  AnthropicAdapter,
  AzureAdapter,
  BedrockAdapter,
  VertexAdapter,
  createLlmGateway,
  type AnthropicClientLike,
  type BedrockTransport,
  type OpenAiClientLike,
  type ProviderAdapter,
  type VertexTransport,
} from "@montr/llm-gateway";

/**
 * Gateway conformance: the SAME request contract runs across all four provider
 * adapters (Anthropic / Bedrock / Vertex / Azure) via offline fake clients, plus
 * the @montr/fixtures fake gateway — every one must yield a contract-valid
 * LLMResponse and a text_delta → message_done stream. No network, deterministic.
 */

const NOW = () => new Date("2026-07-02T00:00:00.000Z");
const CONFIG = parseConfig({ llm: { apiKey: "sk-test", endpoint: "https://llm.internal/v1" } });

const REQUEST: LLMRequest = LLMRequestSchema.parse({
  messages: [{ role: "user", content: "confirm this finding" }],
  maxTokens: 128,
  metadata: { purpose: "confirmation", scanId: "scan_1" },
});

const anthropicClient: AnthropicClientLike = {
  messages: {
    create: async (body) => {
      if (body.stream === true) {
        return (async function* () {
          yield { type: "message_start" as const, message: { usage: { input_tokens: 12 } } };
          yield { type: "content_block_delta" as const, delta: { type: "text_delta", text: "hi" } };
          yield {
            type: "message_delta" as const,
            delta: { stop_reason: "end_turn" },
            usage: { output_tokens: 3 },
          };
          yield { type: "message_stop" as const };
        })();
      }
      return {
        id: "m1",
        model: "claude-sonnet-5",
        content: [{ type: "text", text: "hi" }],
        stop_reason: "end_turn",
        usage: { input_tokens: 12, output_tokens: 3 },
      };
    },
  },
};

const bedrockTransport: BedrockTransport = {
  invoke: async () => ({
    id: "b1",
    model: "anthropic.claude-sonnet-5",
    content: [{ type: "text", text: "hi" }],
    stop_reason: "end_turn",
    usage: { input_tokens: 12, output_tokens: 3 },
  }),
  invokeStream: async function* () {
    yield { type: "message_start", message: { usage: { input_tokens: 12 } } };
    yield { type: "content_block_delta", delta: { type: "text_delta", text: "hi" } };
    yield {
      type: "message_delta",
      delta: { stop_reason: "end_turn" },
      usage: { output_tokens: 3 },
    };
  },
};

const vertexTransport: VertexTransport = {
  generate: async () => ({
    candidates: [{ content: { parts: [{ text: "hi" }] }, finishReason: "STOP" }],
    usageMetadata: { promptTokenCount: 12, candidatesTokenCount: 3, totalTokenCount: 15 },
  }),
  generateStream: async function* () {
    yield { candidates: [{ content: { parts: [{ text: "hi" }] } }] };
    yield {
      candidates: [{ content: { parts: [{ text: "" }] }, finishReason: "STOP" }],
      usageMetadata: { promptTokenCount: 12, candidatesTokenCount: 3, totalTokenCount: 15 },
    };
  },
};

const azureClient: OpenAiClientLike = {
  chat: {
    completions: {
      create: async (body) => {
        if (body.stream === true) {
          return (async function* () {
            yield { choices: [{ delta: { content: "hi" }, finish_reason: null }] };
            yield {
              choices: [{ delta: {}, finish_reason: "stop" }],
              usage: { prompt_tokens: 12, completion_tokens: 3, total_tokens: 15 },
            };
          })();
        }
        return {
          id: "a1",
          model: "gpt-4o",
          choices: [{ message: { content: "hi" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 12, completion_tokens: 3, total_tokens: 15 },
        };
      },
    },
  },
};

/** Adapt the @montr/fixtures fake LLMGateway to the internal ProviderAdapter. */
function fakeFixtureAdapter(): ProviderAdapter {
  const fake = createFakeLlmGateway();
  return {
    provider: "anthropic",
    resolveModelId: (m) => m,
    complete: async (req) => {
      const r = await fake.complete(req);
      return {
        id: r.id,
        model: r.model,
        content: r.content,
        stopReason: r.stopReason,
        usage: r.usage,
      };
    },
    stream: (req) => fake.stream(req) as AsyncGenerator<LLMStreamEvent>,
  };
}

interface Case {
  name: string;
  adapter: ProviderAdapter;
  provider: Provider;
  fake?: boolean;
}

const cases: Case[] = [
  {
    name: "anthropic",
    adapter: new AnthropicAdapter({ config: CONFIG, client: anthropicClient }),
    provider: "anthropic",
  },
  {
    name: "bedrock",
    adapter: new BedrockAdapter({ config: CONFIG, transport: bedrockTransport }),
    provider: "bedrock",
  },
  {
    name: "vertex",
    adapter: new VertexAdapter({ config: CONFIG, transport: vertexTransport }),
    provider: "vertex",
  },
  {
    name: "azure",
    adapter: new AzureAdapter({ config: CONFIG, client: azureClient }),
    provider: "azure",
  },
  { name: "fixtures-fake", adapter: fakeFixtureAdapter(), provider: "anthropic", fake: true },
];

describe.each(cases)("gateway conformance: $name", (c) => {
  it("complete() returns a contract-valid LLMResponse with metered usage", async () => {
    const meter = createCostMeter("scan_1", { now: NOW });
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: c.adapter,
      costMeter: meter,
      logger: createNullLogger(),
      now: NOW,
    });
    const res = await gw.complete(REQUEST);
    expect(LLMResponseSchema.safeParse(res).success).toBe(true);
    expect(res.provider).toBe(c.provider);
    expect(res.usage.totalTokens).toBeGreaterThan(0);
    expect(meter.actual().usage.totalTokens).toBe(res.usage.totalTokens);
    if (!c.fake) expect(res.content).toBe("hi");
  });

  it("stream() yields text then a terminal message_done", async () => {
    const gw = createLlmGateway({
      config: CONFIG,
      adapter: c.adapter,
      logger: createNullLogger(),
      now: NOW,
    });
    const events: LLMStreamEvent[] = [];
    for await (const ev of gw.stream(REQUEST)) events.push(ev);
    expect(events.some((e) => e.type === "text_delta")).toBe(true);
    expect(events.at(-1)?.type).toBe("message_done");
  });
});
