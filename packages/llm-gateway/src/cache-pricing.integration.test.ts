import { describe, it, expect } from "vitest";
import { LLMRequestSchema, type LLMRequest } from "@montr/contracts";
import { parseConfig } from "@montr/config";
import { createCostMeter } from "@montr/cost-meter";
import { MontrLlmGateway } from "./gateway.js";
import { AnthropicAdapter, type AnthropicClientLike } from "./adapters/index.js";

/**
 * A31 item 1 — confirms prompt-cache usage is priced END TO END through the
 * REAL adapter (`AnthropicAdapter.complete()` → `mapAnthropicMessage`, which
 * extracts `cache_read_input_tokens`/`cache_creation_input_tokens` from the
 * provider response) and the REAL gateway accounting path (`account()` →
 * `CostMeter.record()` → `priceUsageUsd`'s 0.1×/1.25× cache multipliers),
 * not just the request-side `cache_control` marking already covered by
 * `adapters/capabilities.test.ts` or the pricing-formula unit tests in
 * `@montr/cost-meter`. Only the network transport (the Anthropic SDK client)
 * is faked, matching this repo's adapter-test convention (see
 * `streaming.integration.test.ts`).
 */

function req(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return LLMRequestSchema.parse({
    tier: "default",
    system: "You are a test.",
    messages: [{ role: "user", content: "Say hi." }],
    maxTokens: 64,
    responseFormat: "text",
    metadata: { scanId: "scan_cache_1", clientId: "client_a", purpose: "other" },
    ...overrides,
  });
}

describe("prompt-cache usage → real accounting (A31)", () => {
  it("a response reporting cache_read/cache_creation tokens is priced at 0.1x/1.25x and recorded into the CostMeter", async () => {
    const config = parseConfig({
      clientId: "client_a",
      llm: { apiKey: "sk-test", provider: "anthropic" },
    });
    const client: AnthropicClientLike = {
      messages: {
        create: async () => ({
          id: "msg_1",
          model: "claude-sonnet-5",
          content: [{ type: "text", text: "Hi!" }],
          stop_reason: "end_turn",
          usage: {
            input_tokens: 100,
            output_tokens: 20,
            cache_read_input_tokens: 1_000_000,
            cache_creation_input_tokens: 1_000_000,
          },
        }),
      },
    };
    const adapter = new AnthropicAdapter({ config, client });
    const costMeter = createCostMeter("scan_cache_1");
    const gateway = new MontrLlmGateway({ config, adapter, costMeter });

    const response = await gateway.complete(req());

    // Real mapAnthropicMessage() extraction (adapters/anthropic.ts).
    expect(response.usage).toMatchObject({
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 1_000_000,
      cacheWriteTokens: 1_000_000,
    });

    // Real gateway accounting into the CostMeter, real pricing.ts formula:
    // fresh input 100 tok + output 20 tok are negligible; cache read
    // 1,000,000 tok @ 0.1x Sonnet-5's $3/M input rate = $0.30; cache write
    // 1,000,000 tok @ 1.25x = $3.75. Total ≈ $4.05 (+ a few micro-dollars).
    const actual = costMeter.actual();
    expect(actual.usage.cacheReadTokens).toBe(1_000_000);
    expect(actual.usage.cacheWriteTokens).toBe(1_000_000);
    expect(actual.actualUsd).toBeCloseTo(0.3 + 3.75, 2);
  });
});
