import { describe, it, expect } from "vitest";
import { LLMRequestSchema, type LLMRequest } from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import { createEgressGuard } from "@montr/security";
import {
  AnthropicAdapter,
  BedrockAdapter,
  VertexAdapter,
  AzureAdapter,
  type AdapterEgress,
  type AnthropicClientLike,
  type BedrockTransport,
  type VertexTransport,
  type OpenAiClientLike,
  type ProviderAdapter,
} from "./index.js";

/**
 * Carry-over #2 (app-layer egress). Every provider adapter must assert the exact
 * outbound host it is about to contact BEFORE dispatching, so the only reachable
 * destination is the configured client LLM endpoint (golden rule #1, §4.8) —
 * defense-in-depth atop the gateway-level guard and the k8s NetworkPolicy. These
 * tests drive the adapters with offline fakes + a structural spy egress guard.
 */

/** A spy egress guard: records every asserted target; optionally blocks some. */
function spyEgress(block?: (target: string) => boolean): AdapterEgress & { targets: string[] } {
  const targets: string[] = [];
  return {
    targets,
    assert(target: string) {
      targets.push(target);
      if (block?.(target)) throw new Error(`egress blocked: ${target}`);
    },
  };
}

const REQ: LLMRequest = LLMRequestSchema.parse({
  messages: [{ role: "user", content: "x" }],
  maxTokens: 64,
  metadata: { purpose: "triage" },
});

function cfg(endpoint: string | undefined, provider = "anthropic"): MontrConfig {
  return parseConfig({ llm: { apiKey: "sk-test", provider, ...(endpoint ? { endpoint } : {}) } });
}

function anthropicFake(onCall: () => void): AnthropicClientLike {
  return {
    messages: {
      create: async () => {
        onCall();
        return {
          id: "m",
          model: "claude-sonnet-5",
          content: [{ type: "text", text: "hi" }],
          stop_reason: "end_turn",
          usage: { input_tokens: 1, output_tokens: 1 },
        };
      },
    },
  };
}
function bedrockFake(onCall: () => void): BedrockTransport {
  return {
    invoke: async () => {
      onCall();
      return {
        id: "b",
        model: "anthropic.claude-sonnet-5",
        content: [{ type: "text", text: "hi" }],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 1 },
      };
    },
    invokeStream: async function* () {
      onCall();
      yield { type: "content_block_delta", delta: { type: "text_delta", text: "hi" } };
      yield {
        type: "message_delta",
        delta: { stop_reason: "end_turn" },
        usage: { output_tokens: 1 },
      };
    },
  };
}
function vertexFake(onCall: () => void): VertexTransport {
  return {
    generate: async () => {
      onCall();
      return {
        candidates: [{ content: { parts: [{ text: "hi" }] }, finishReason: "STOP" }],
        usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
      };
    },
    generateStream: async function* () {
      onCall();
      yield {
        candidates: [{ content: { parts: [{ text: "hi" }] }, finishReason: "STOP" }],
        usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
      };
    },
  };
}
function azureFake(onCall: () => void): OpenAiClientLike {
  return {
    chat: {
      completions: {
        create: async () => {
          onCall();
          return {
            id: "a",
            model: "gpt-4o",
            choices: [{ message: { content: "hi" }, finish_reason: "stop" }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          };
        },
      },
    },
  };
}

interface Case {
  name: string;
  provider: string;
  /** default outbound host fragment when no endpoint is configured. */
  defaultHost: string;
  hasProviderDefault: boolean;
  make: (
    egress: AdapterEgress,
    endpoint: string | undefined,
    onCall: () => void,
  ) => ProviderAdapter;
}

const cases: Case[] = [
  {
    name: "anthropic",
    provider: "anthropic",
    defaultHost: "api.anthropic.com",
    hasProviderDefault: true,
    make: (egress, endpoint, onCall) =>
      new AnthropicAdapter({
        config: cfg(endpoint, "anthropic"),
        client: anthropicFake(onCall),
        egress,
      }),
  },
  {
    name: "bedrock",
    provider: "bedrock",
    defaultHost: "bedrock-runtime",
    hasProviderDefault: true,
    make: (egress, endpoint, onCall) =>
      new BedrockAdapter({
        config: cfg(endpoint, "bedrock"),
        transport: bedrockFake(onCall),
        egress,
      }),
  },
  {
    name: "vertex",
    provider: "vertex",
    defaultHost: "aiplatform.googleapis.com",
    hasProviderDefault: true,
    make: (egress, endpoint, onCall) =>
      new VertexAdapter({ config: cfg(endpoint, "vertex"), transport: vertexFake(onCall), egress }),
  },
  {
    name: "azure",
    provider: "azure",
    defaultHost: "", // Azure has no generic default host (endpoint is mandatory).
    hasProviderDefault: false,
    make: (egress, endpoint, onCall) =>
      new AzureAdapter({ config: cfg(endpoint, "azure"), client: azureFake(onCall), egress }),
  },
];

describe.each(cases)("⛔ adapter egress: $name", (c) => {
  const ENDPOINT = "https://llm.good.internal/v1";

  it("asserts the configured endpoint before dispatch, then contacts the client", async () => {
    const egress = spyEgress();
    let called = false;
    const adapter = c.make(egress, ENDPOINT, () => (called = true));
    await adapter.complete(REQ, "claude-sonnet-5");
    expect(egress.targets[0]).toContain("llm.good.internal");
    expect(called).toBe(true);
  });

  it("BLOCKS a disallowed outbound host and never contacts the client", async () => {
    const egress = spyEgress((t) => t.includes("evil"));
    let called = false;
    const adapter = c.make(egress, "https://llm.evil.example/v1", () => (called = true));
    await expect(adapter.complete(REQ, "claude-sonnet-5")).rejects.toThrow(/egress blocked/);
    expect(called).toBe(false);
  });

  it("asserts egress on stream() too (before the transport is touched)", async () => {
    const egress = spyEgress((t) => t.includes("evil"));
    let called = false;
    const adapter = c.make(egress, "https://llm.evil.example/v1", () => (called = true));
    await expect(async () => {
      for await (const _ev of adapter.stream(REQ, "claude-sonnet-5")) void _ev;
    }).rejects.toThrow(/egress blocked/);
    expect(called).toBe(false);
  });
});

describe("⛔ adapter egress: provider-default host (no endpoint configured)", () => {
  for (const c of cases.filter((x) => x.hasProviderDefault)) {
    it(`${c.name} asserts its provider-default host`, async () => {
      const egress = spyEgress();
      const adapter = c.make(egress, undefined, () => {});
      await adapter.complete(REQ, "claude-sonnet-5");
      expect(egress.targets[0]).toContain(c.defaultHost);
    });
  }
});

describe("⛔ adapter egress: integration with @montr/security's real guard", () => {
  it("throws EGRESS_BLOCKED when the adapter's endpoint is not the allowed LLM host", async () => {
    // Policy permits only llm.good.internal; the adapter is (mis)pointed at evil.
    const guard = createEgressGuard(cfg("https://llm.good.internal/v1"));
    const adapter = new AnthropicAdapter({
      config: cfg("https://llm.evil.example/v1"),
      client: anthropicFake(() => {}),
      egress: guard,
    });
    let err: unknown;
    try {
      await adapter.complete(REQ, "claude-sonnet-5");
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect((err as { code?: string }).code).toBe("EGRESS_BLOCKED");
  });

  it("allows the request when the adapter's endpoint IS the allowed LLM host", async () => {
    const guard = createEgressGuard(cfg("https://llm.good.internal/v1"));
    let called = false;
    const adapter = new AnthropicAdapter({
      config: cfg("https://llm.good.internal/v1"),
      client: anthropicFake(() => (called = true)),
      egress: guard,
    });
    const res = await adapter.complete(REQ, "claude-sonnet-5");
    expect(called).toBe(true);
    expect(res.content).toBe("hi");
  });
});
