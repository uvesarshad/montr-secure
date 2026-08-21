import { describe, it, expect } from "vitest";
import { LLMRequestSchema, type LLMRequest, type LLMStreamEvent } from "@montr/contracts";
import { parseConfig } from "@montr/config";
import { createCostMeter } from "@montr/cost-meter";
import { MontrLlmGateway } from "./gateway.js";
import {
  AnthropicAdapter,
  type AnthropicClientLike,
  type AnthropicStreamEventLike,
} from "./adapters/index.js";

/**
 * A10 — "built but unwired": `gateway.stream()` is implemented end-to-end in
 * every provider adapter, but no pipeline layer calls it today (every real
 * layer call site — appmap/llm.ts, discovery/triage.ts, correlation/llm.ts,
 * confirm/static.ts, fix/generate.ts — is a small, single-shot metadata
 * request with no streaming UI to feed; see
 * docs/plan/26-08-22-audit-ai-depth.md A10). Rather than force a streaming
 * consumer into a layer that doesn't benefit from one, this proves the
 * gateway's stream() path is REAL, working code end-to-end so it's verified
 * rather than merely present.
 *
 * Unlike gateway.test.ts's retry/budget/key-tier suite (which drives a
 * test-fake `ProviderAdapter` to isolate gateway-level behavior), this test
 * wires a REAL `MontrLlmGateway` to the REAL `AnthropicAdapter` — only the
 * network transport (the Anthropic SDK client) is faked, matching this
 * repo's established adapter-test convention (see adapters/egress.test.ts's
 * `anthropicFake`). So the actual `buildBody()` / `assertEgress()` /
 * `mapAnthropicStream()` SSE-event-mapping logic in adapters/anthropic.ts all
 * runs for real, plus the gateway's own pre-call budget guard, timeout
 * wrapping, and post-stream cost accounting (A32).
 */

function fakeStreamingClient(events: AnthropicStreamEventLike[]): {
  client: AnthropicClientLike;
  calls: Record<string, unknown>[];
} {
  const calls: Record<string, unknown>[] = [];
  return {
    calls,
    client: {
      messages: {
        create: async (body: Record<string, unknown>) => {
          calls.push(body);
          return (async function* (): AsyncGenerator<AnthropicStreamEventLike> {
            for (const ev of events) yield ev;
          })();
        },
      },
    },
  };
}

function req(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return LLMRequestSchema.parse({
    tier: "default",
    system: "You are a test.",
    messages: [{ role: "user", content: "Say hi." }],
    maxTokens: 64,
    responseFormat: "text",
    stream: true,
    metadata: { scanId: "scan_stream_1", clientId: "client_a", purpose: "other" },
    ...overrides,
  });
}

describe("gateway streaming — real end-to-end through a real adapter (A10)", () => {
  it("streams real text deltas and a final usage/stopReason from the REAL Anthropic adapter's SSE mapping", async () => {
    const config = parseConfig({
      clientId: "client_a",
      llm: { apiKey: "sk-test", provider: "anthropic" },
    });
    const { client, calls } = fakeStreamingClient([
      { type: "message_start", message: { id: "msg_1", usage: { input_tokens: 12 } } },
      { type: "content_block_start" },
      { type: "content_block_delta", delta: { type: "text_delta", text: "Hel" } },
      { type: "content_block_delta", delta: { type: "text_delta", text: "lo!" } },
      { type: "content_block_stop" },
      { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 3 } },
      { type: "message_stop" },
    ]);
    const adapter = new AnthropicAdapter({ config, client });
    const costMeter = createCostMeter("scan_stream_1");
    const gateway = new MontrLlmGateway({ config, adapter, costMeter });

    const events: LLMStreamEvent[] = [];
    for await (const event of gateway.stream(req())) events.push(event);

    // Real adapter dispatch happened (not a stub): the actual buildBody()
    // path ran and requested a genuinely STREAMING body against the
    // tier-resolved model id.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.["stream"]).toBe(true);
    expect(calls[0]?.["model"]).toBe("claude-sonnet-5");

    // Real mapAnthropicStream() output (adapters/anthropic.ts), re-yielded
    // verbatim by the gateway's stream() loop.
    const text = events
      .filter((e): e is Extract<LLMStreamEvent, { type: "text_delta" }> => e.type === "text_delta")
      .map((e) => e.text)
      .join("");
    expect(text).toBe("Hello!");

    const done = events.find((e) => e.type === "message_done");
    expect(done).toMatchObject({
      type: "message_done",
      stopReason: "end_turn",
      usage: { inputTokens: 12, outputTokens: 3, totalTokens: 15 },
    });

    // Real end-to-end accounting (A32): the gateway's post-stream account()
    // call recorded this call's usage into the injected CostMeter — proving
    // stream() is wired into the same real accounting path as complete().
    const actual = costMeter.actual();
    expect(actual.usage.inputTokens).toBe(12);
    expect(actual.usage.outputTokens).toBe(3);
  });

  it("surfaces a real adapter stream failure as a terminal error event, never a thrown exception", async () => {
    const config = parseConfig({
      clientId: "client_a",
      llm: { apiKey: "sk-test", provider: "anthropic" },
    });
    const client: AnthropicClientLike = {
      messages: {
        create: async () => {
          throw new Error("network reset");
        },
      },
    };
    const adapter = new AnthropicAdapter({ config, client });
    const gateway = new MontrLlmGateway({ config, adapter });

    const events: LLMStreamEvent[] = [];
    for await (const event of gateway.stream(req())) events.push(event);

    expect(events).toHaveLength(1);
    expect(events[0]?.type).toBe("error");
  });
});
