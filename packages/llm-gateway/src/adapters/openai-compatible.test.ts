import { describe, it, expect } from "vitest";
import { LLMRequestSchema, type LLMRequest, type LLMToolDefinition } from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import { createEgressGuard } from "@montr/security";
import { OpenAiCompatibleAdapter, type OpenAiClientLike, type AdapterEgress } from "./index.js";

/**
 * A3: the generic OpenAI-compatible adapter (openai/google/xai/moonshot/
 * zhipu/deepseek) shares Azure's wire format, so this mirrors
 * capabilities.test.ts's / tool-conversation.test.ts's / egress.test.ts's
 * AzureAdapter cases — basic completion, a tool call, and the egress guard
 * rejecting a non-allowlisted host — rather than re-deriving new coverage.
 */

function cfg(provider = "openai", endpoint?: string): MontrConfig {
  return parseConfig({ llm: { apiKey: "sk-test", provider, ...(endpoint ? { endpoint } : {}) } });
}

const GREP_TOOL: LLMToolDefinition = {
  name: "grep",
  description: "Search the codebase",
  parameters: {
    type: "object",
    properties: { pattern: { type: "string" } },
    required: ["pattern"],
  },
};

function req(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return LLMRequestSchema.parse({
    system: "You are a security reviewer.",
    messages: [{ role: "user", content: "review this" }],
    maxTokens: 512,
    metadata: { purpose: "correlation" },
    ...overrides,
  });
}

function fakeClient(
  onCall: (body: Record<string, unknown>) => void,
  response: {
    content?: string | null;
    toolCalls?: Array<{
      id: string;
      type: "function";
      function: { name: string; arguments: string };
    }>;
    finishReason?: string;
  } = {},
): OpenAiClientLike {
  return {
    chat: {
      completions: {
        create: async (body) => {
          onCall(body);
          return {
            id: "resp_1",
            model: "gpt-4o-mini",
            choices: [
              {
                message: {
                  content: response.content ?? "hello from the model",
                  tool_calls: response.toolCalls ?? null,
                },
                finish_reason: response.finishReason ?? "stop",
              },
            ],
            usage: { prompt_tokens: 12, completion_tokens: 4, total_tokens: 16 },
          };
        },
      },
    },
  };
}

describe("OpenAiCompatibleAdapter (A3) — basic completion", () => {
  it("builds an OpenAI Chat-Completions body and returns a normalized completion", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client = fakeClient((body) => (capturedBody = body));
    const adapter = new OpenAiCompatibleAdapter({
      provider: "openai",
      defaultBaseUrl: "https://api.openai.com/v1",
      defaultHost: "api.openai.com",
      config: cfg("openai"),
      client,
    });

    const result = await adapter.complete(req(), "gpt-4o-mini");

    expect(capturedBody?.model).toBe("gpt-4o-mini");
    expect(capturedBody?.messages).toEqual([
      { role: "system", content: "You are a security reviewer." },
      { role: "user", content: "review this" },
    ]);
    expect(result).toMatchObject({
      id: "resp_1",
      model: "gpt-4o-mini",
      content: "hello from the model",
      stopReason: "end_turn",
      usage: { inputTokens: 12, outputTokens: 4, totalTokens: 16 },
    });
    expect(result.toolCalls).toBeUndefined();
  });

  it("works identically for the other five OpenAI-compatible providers (google/xai/moonshot/zhipu/deepseek)", async () => {
    for (const provider of ["google", "xai", "moonshot", "zhipu", "deepseek"] as const) {
      const client = fakeClient(() => {});
      const adapter = new OpenAiCompatibleAdapter({
        provider,
        defaultBaseUrl: "https://example.invalid/v1",
        defaultHost: "example.invalid",
        config: cfg(provider),
        client,
      });
      const result = await adapter.complete(req(), "some-model");
      expect(result.content).toBe("hello from the model");
    }
  });
});

describe("OpenAiCompatibleAdapter (A3) — tool calling (A8)", () => {
  it("forwards request.tools as OpenAI function definitions and parses tool_calls", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client = fakeClient((body) => (capturedBody = body), {
      content: null,
      toolCalls: [
        {
          id: "call_1",
          type: "function",
          function: { name: "grep", arguments: '{"pattern":"eval("}' },
        },
      ],
      finishReason: "tool_calls",
    });
    const adapter = new OpenAiCompatibleAdapter({
      provider: "deepseek",
      defaultBaseUrl: "https://api.deepseek.com",
      defaultHost: "api.deepseek.com",
      config: cfg("deepseek"),
      client,
    });

    const result = await adapter.complete(req({ tools: [GREP_TOOL] }), "deepseek-chat");

    expect(capturedBody?.tools).toEqual([
      {
        type: "function",
        function: {
          name: "grep",
          description: "Search the codebase",
          parameters: GREP_TOOL.parameters,
        },
      },
    ]);
    expect(result.stopReason).toBe("tool_use");
    expect(result.toolCalls).toEqual([{ id: "call_1", name: "grep", input: { pattern: "eval(" } }]);
  });

  it("re-encodes a prior tool exchange onto a following turn (A4)", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client = fakeClient((body) => (capturedBody = body));
    const adapter = new OpenAiCompatibleAdapter({
      provider: "xai",
      defaultBaseUrl: "https://api.x.ai/v1",
      defaultHost: "api.x.ai",
      config: cfg("xai"),
      client,
    });

    const request = LLMRequestSchema.parse({
      messages: [
        { role: "user", content: "fix the bug in a.ts" },
        {
          role: "assistant",
          content: "",
          toolCalls: [{ id: "call_1", name: "read_file", input: { path: "a.ts" } }],
        },
        { role: "tool", content: "export const x = 1;", toolCallId: "call_1", name: "read_file" },
      ],
      maxTokens: 256,
      metadata: { purpose: "fix_generation" },
    });
    await adapter.complete(request, "grok-x");

    const msgs = capturedBody?.messages as Array<Record<string, unknown>>;
    const assistant = msgs.find((m) => m.role === "assistant");
    const toolCalls = assistant?.tool_calls as Array<{
      id: string;
      function: { arguments: string };
    }>;
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0]).toMatchObject({
      id: "call_1",
      function: { arguments: '{"path":"a.ts"}' },
    });

    const toolMsg = msgs.find((m) => m.role === "tool");
    expect(toolMsg?.tool_call_id).toBe("call_1");
    expect(toolMsg?.content).toBe("export const x = 1;");
  });

  it("uses response_format json_schema when a schema resolves, else falls back to json_object (A13)", async () => {
    const bodies: Record<string, unknown>[] = [];
    const client = fakeClient((body) => bodies.push(body), { content: "{}" });
    const adapter = new OpenAiCompatibleAdapter({
      provider: "openai",
      defaultBaseUrl: "https://api.openai.com/v1",
      defaultHost: "api.openai.com",
      config: cfg("openai"),
      client,
    });

    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "confirmation" } }),
      "gpt-4o-mini",
    );
    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "other" } }),
      "gpt-4o-mini",
    );

    const withSchema = bodies[0]?.response_format as {
      type: string;
      json_schema?: { schema: unknown };
    };
    expect(withSchema.type).toBe("json_schema");
    expect(withSchema.json_schema?.schema).toMatchObject({ type: "object" });

    const withoutSchema = bodies[1]?.response_format as { type: string };
    expect(withoutSchema.type).toBe("json_object");
  });
});

describe("OpenAiCompatibleAdapter (A3) — egress guard", () => {
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

  it("asserts the provider-default host when no endpoint is configured, then contacts the client", async () => {
    const egress = spyEgress();
    let called = false;
    const client = fakeClient(() => (called = true));
    const adapter = new OpenAiCompatibleAdapter({
      provider: "moonshot",
      defaultBaseUrl: "https://api.moonshot.ai/v1",
      defaultHost: "api.moonshot.ai",
      config: cfg("moonshot"),
      client,
      egress,
    });
    await adapter.complete(req(), "moonshot-v1");
    expect(egress.targets).toEqual(["api.moonshot.ai"]);
    expect(called).toBe(true);
  });

  it("BLOCKS a disallowed outbound host (operator-misconfigured endpoint) and never contacts the client", async () => {
    const egress = spyEgress((t) => t.includes("evil"));
    let called = false;
    const client = fakeClient(() => (called = true));
    const adapter = new OpenAiCompatibleAdapter({
      provider: "openai",
      defaultBaseUrl: "https://api.openai.com/v1",
      defaultHost: "api.openai.com",
      config: cfg("openai", "https://llm.evil.example/v1"),
      client,
      egress,
    });
    await expect(adapter.complete(req(), "gpt-4o-mini")).rejects.toThrow(/egress blocked/);
    expect(called).toBe(false);
  });

  it("integrates with @montr/security's real guard: throws EGRESS_BLOCKED for a non-allowlisted host", async () => {
    // Policy permits only the zhipu provider default; the adapter is pointed at
    // an arbitrary, non-allowlisted host instead (e.g. a compromised/typo'd
    // llm.endpoint) — the real default-deny guard must reject it.
    const guard = createEgressGuard(cfg("zhipu"));
    let called = false;
    const client = fakeClient(() => (called = true));
    const adapter = new OpenAiCompatibleAdapter({
      provider: "zhipu",
      defaultBaseUrl: "https://open.bigmodel.cn/api/paas/v4/",
      defaultHost: "open.bigmodel.cn",
      config: cfg("zhipu", "https://not-allowlisted.example/v1"),
      client,
      egress: guard,
    });

    let err: unknown;
    try {
      await adapter.complete(req(), "glm-4");
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect((err as { code?: string }).code).toBe("EGRESS_BLOCKED");
    expect(called).toBe(false);
  });

  it("integrates with @montr/security's real guard: allows the provider-default host", async () => {
    const guard = createEgressGuard(cfg("zhipu"));
    let called = false;
    const client = fakeClient(() => (called = true));
    const adapter = new OpenAiCompatibleAdapter({
      provider: "zhipu",
      defaultBaseUrl: "https://open.bigmodel.cn/api/paas/v4/",
      defaultHost: "open.bigmodel.cn",
      config: cfg("zhipu"),
      client,
      egress: guard,
    });

    const result = await adapter.complete(req(), "glm-4");
    expect(called).toBe(true);
    expect(result.content).toBe("hello from the model");
  });
});
