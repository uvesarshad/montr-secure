import { describe, it, expect } from "vitest";
import {
  NotImplementedError,
  LLMRequestSchema,
  type LLMRequest,
  type LLMToolDefinition,
} from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import {
  AnthropicAdapter,
  BedrockAdapter,
  VertexAdapter,
  AzureAdapter,
  type AnthropicClientLike,
  type AnthropicBatchLike,
  type AnthropicBatchResultLike,
  type BedrockTransport,
  type VertexTransport,
  type OpenAiClientLike,
} from "./index.js";

/**
 * A8 (tool use, effort/thinking, prompt caching) + A13 (structured outputs)
 * adapter-level round-trip coverage: request -> provider wire payload ->
 * parsed response, for each of the four adapters. Follows the injected-
 * client/transport pattern established by adapters/egress.test.ts — no real
 * network calls.
 */

function cfg(provider = "anthropic"): MontrConfig {
  return parseConfig({ llm: { apiKey: "sk-test", provider } });
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

describe("AnthropicAdapter — A8/A13 capabilities", () => {
  it("forwards request.tools as {name, description, input_schema} and parses a tool_use response", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: AnthropicClientLike = {
      messages: {
        create: async (body) => {
          capturedBody = body;
          return {
            id: "m1",
            model: "claude-sonnet-5",
            content: [
              { type: "tool_use", id: "call_1", name: "grep", input: { pattern: "eval(" } },
            ],
            stop_reason: "tool_use",
            usage: { input_tokens: 10, output_tokens: 5 },
          };
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    const result = await adapter.complete(req({ tools: [GREP_TOOL] }), "claude-sonnet-5");

    expect(capturedBody?.tools).toEqual([
      { name: "grep", description: "Search the codebase", input_schema: GREP_TOOL.parameters },
    ]);
    expect(result.stopReason).toBe("tool_use");
    expect(result.toolCalls).toEqual([{ id: "call_1", name: "grep", input: { pattern: "eval(" } }]);
  });

  it("sets output_config.effort + adaptive thinking for an effort-capable model, and omits both for Haiku", async () => {
    const bodies: Record<string, unknown>[] = [];
    const client: AnthropicClientLike = {
      messages: {
        create: async (body) => {
          bodies.push(body);
          return {
            id: "m",
            model: "claude-sonnet-5",
            content: [{ type: "text", text: "{}" }],
            stop_reason: "end_turn",
            usage: { input_tokens: 1, output_tokens: 1 },
          };
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });

    await adapter.complete(req({ effort: "high" }), "claude-sonnet-5");
    const sonnetBody = bodies[0] as { output_config?: { effort?: string }; thinking?: unknown };
    expect(sonnetBody.output_config?.effort).toBe("high");
    expect(sonnetBody.thinking).toEqual({ type: "adaptive" });

    await adapter.complete(req({ effort: "high" }), "claude-haiku-4-5");
    const haikuBody = bodies[1] as { output_config?: { effort?: string }; thinking?: unknown };
    expect(haikuBody.output_config?.effort).toBeUndefined();
    expect(haikuBody.thinking).toBeUndefined();
  });

  it("marks the system prompt with cache_control: ephemeral", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: AnthropicClientLike = {
      messages: {
        create: async (body) => {
          capturedBody = body;
          return {
            id: "m",
            model: "claude-sonnet-5",
            content: [{ type: "text", text: "{}" }],
            stop_reason: "end_turn",
            usage: { input_tokens: 1, output_tokens: 1 },
          };
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    await adapter.complete(req(), "claude-sonnet-5");

    expect(capturedBody?.system).toEqual([
      { type: "text", text: "You are a security reviewer.", cache_control: { type: "ephemeral" } },
    ]);
  });

  it("sets output_config.format to a real JSON schema for a known purpose when responseFormat is json", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: AnthropicClientLike = {
      messages: {
        create: async (body) => {
          capturedBody = body;
          return {
            id: "m",
            model: "claude-sonnet-5",
            content: [{ type: "text", text: '{"confirmed":true}' }],
            stop_reason: "end_turn",
            usage: { input_tokens: 1, output_tokens: 1 },
          };
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "confirmation" } }),
      "claude-sonnet-5",
    );

    const outputConfig = capturedBody?.output_config as {
      format?: { type: string; schema: unknown };
    };
    expect(outputConfig.format?.type).toBe("json_schema");
    expect(outputConfig.format?.schema).toMatchObject({ type: "object" });
  });
});

describe("BedrockAdapter — A8/A13 capabilities (shares Anthropic's Messages body shape)", () => {
  function bedrockAdapterCapturing(onBody: (body: string) => void): BedrockAdapter {
    const transport: BedrockTransport = {
      invoke: async (_modelId, body) => {
        onBody(body);
        return {
          id: "b1",
          model: "anthropic.claude-sonnet-5",
          content: [{ type: "text", text: '{"confirmed":true}' }],
          stop_reason: "end_turn",
          usage: { input_tokens: 1, output_tokens: 1 },
        };
      },
      invokeStream: async function* () {},
    };
    return new BedrockAdapter({ config: cfg("bedrock"), transport });
  }

  it("forwards tools and effort/thinking in the Bedrock InvokeModel body", async () => {
    let capturedBodyJson: string | undefined;
    const adapter = bedrockAdapterCapturing((b) => (capturedBodyJson = b));
    await adapter.complete(req({ tools: [GREP_TOOL], effort: "high" }), "claude-sonnet-5");

    const body = JSON.parse(capturedBodyJson ?? "{}") as {
      anthropic_version?: string;
      tools?: unknown[];
      output_config?: { effort?: string };
      thinking?: unknown;
    };
    expect(body.anthropic_version).toBe("bedrock-2023-05-31");
    expect(body.tools).toHaveLength(1);
    expect(body.output_config?.effort).toBe("high");
    expect(body.thinking).toEqual({ type: "adaptive" });
  });

  it("sets output_config.format to a real JSON schema when no tools are in play", async () => {
    let capturedBodyJson: string | undefined;
    const adapter = bedrockAdapterCapturing((b) => (capturedBodyJson = b));
    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "confirmation" } }),
      "claude-sonnet-5",
    );

    const body = JSON.parse(capturedBodyJson ?? "{}") as {
      output_config?: { format?: { type: string; schema: unknown } };
    };
    expect(body.output_config?.format?.type).toBe("json_schema");
    expect(body.output_config?.format?.schema).toMatchObject({ type: "object" });
  });
});

describe("VertexAdapter — A8/A13 capabilities", () => {
  it("forwards tools as functionDeclarations and parses a functionCall response into toolCalls", async () => {
    let capturedReq: unknown;
    const transport: VertexTransport = {
      generate: async (_model, r) => {
        capturedReq = r;
        return {
          candidates: [
            {
              content: { parts: [{ functionCall: { name: "grep", args: { pattern: "eval(" } } }] },
              finishReason: "STOP",
            },
          ],
          usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
        };
      },
      generateStream: async function* () {},
    };
    const adapter = new VertexAdapter({ config: cfg("vertex"), transport });
    const result = await adapter.complete(req({ tools: [GREP_TOOL] }), "claude-sonnet-5");

    const sent = capturedReq as { tools?: Array<{ functionDeclarations: unknown[] }> };
    expect(sent.tools?.[0]?.functionDeclarations).toEqual([
      { name: "grep", description: "Search the codebase", parameters: GREP_TOOL.parameters },
    ]);
    expect(result.toolCalls).toEqual([{ id: "grep:0", name: "grep", input: { pattern: "eval(" } }]);
  });

  it("sets responseMimeType/responseSchema when a schema resolves for the purpose", async () => {
    let capturedReq: unknown;
    const transport: VertexTransport = {
      generate: async (_model, r) => {
        capturedReq = r;
        return {
          candidates: [{ content: { parts: [{ text: "{}" }] }, finishReason: "STOP" }],
          usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
        };
      },
      generateStream: async function* () {},
    };
    const adapter = new VertexAdapter({ config: cfg("vertex"), transport });
    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "correlation" } }),
      "claude-sonnet-5",
    );

    const sent = capturedReq as {
      generationConfig: { responseMimeType?: string; responseSchema?: Record<string, unknown> };
    };
    expect(sent.generationConfig.responseMimeType).toBe("application/json");
    expect(sent.generationConfig.responseSchema).toMatchObject({ type: "object" });
  });
});

describe("AzureAdapter — A8/A13 capabilities", () => {
  it("forwards tools as OpenAI function definitions and parses tool_calls (JSON-string arguments)", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: OpenAiClientLike = {
      chat: {
        completions: {
          create: async (body) => {
            capturedBody = body;
            return {
              id: "a1",
              model: "gpt-4o",
              choices: [
                {
                  message: {
                    content: null,
                    tool_calls: [
                      {
                        id: "call_1",
                        type: "function",
                        function: { name: "grep", arguments: '{"pattern":"eval("}' },
                      },
                    ],
                  },
                  finish_reason: "tool_calls",
                },
              ],
              usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
            };
          },
        },
      },
    };
    const adapter = new AzureAdapter({
      config: parseConfig({
        llm: { apiKey: "sk-test", provider: "azure", endpoint: "https://x.openai.azure.com" },
      }),
      client,
    });
    const result = await adapter.complete(req({ tools: [GREP_TOOL] }), "gpt-4o-deployment");

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

  it("uses response_format json_schema when a schema resolves, else falls back to json_object", async () => {
    const bodies: Record<string, unknown>[] = [];
    const client: OpenAiClientLike = {
      chat: {
        completions: {
          create: async (body) => {
            bodies.push(body);
            return {
              id: "a",
              model: "gpt-4o",
              choices: [{ message: { content: "{}" }, finish_reason: "stop" }],
              usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
            };
          },
        },
      },
    };
    const adapter = new AzureAdapter({
      config: parseConfig({
        llm: { apiKey: "sk-test", provider: "azure", endpoint: "https://x.openai.azure.com" },
      }),
      client,
    });

    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "confirmation" } }),
      "gpt-4o-deployment",
    );
    await adapter.complete(
      req({ responseFormat: "json", metadata: { purpose: "other" } }),
      "gpt-4o-deployment",
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

describe("AnthropicAdapter — real token counting (A19)", () => {
  it("calls messages.countTokens with model/messages/system/tools and returns input_tokens", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: AnthropicClientLike = {
      messages: {
        create: async () => {
          throw new Error("complete() should not be called by countTokens()");
        },
        countTokens: async (body) => {
          capturedBody = body;
          return { input_tokens: 42 };
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    const count = await adapter.countTokens(req({ tools: [GREP_TOOL] }), "claude-sonnet-5");

    expect(count).toBe(42);
    expect(capturedBody).toMatchObject({
      model: "claude-sonnet-5",
      messages: [{ role: "user", content: "review this" }],
      system: "You are a security reviewer.",
    });
    expect(capturedBody?.tools).toEqual([
      { name: "grep", description: "Search the codebase", input_schema: GREP_TOOL.parameters },
    ]);
    // count_tokens is billing/cache-irrelevant: no max_tokens/output_config/cache_control leak in.
    expect(capturedBody?.max_tokens).toBeUndefined();
    expect(capturedBody?.output_config).toBeUndefined();
    expect(capturedBody?.thinking).toBeUndefined();
  });

  it("throws NotImplementedError when the injected client has no countTokens (stale SDK)", async () => {
    const client: AnthropicClientLike = {
      messages: { create: async () => ({ id: "m", content: [], usage: {} }) },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    await expect(adapter.countTokens(req(), "claude-sonnet-5")).rejects.toThrow(
      NotImplementedError,
    );
  });
});

describe("AnthropicAdapter — Batch API (A31)", () => {
  function fakeBatchClient(): {
    client: AnthropicClientLike;
    created: { requests: { custom_id: string; params: Record<string, unknown> }[] }[];
  } {
    const created: { requests: { custom_id: string; params: Record<string, unknown> }[] }[] = [];
    const batch: AnthropicBatchLike = {
      id: "batch_1",
      processing_status: "in_progress",
      request_counts: { processing: 2, succeeded: 0, errored: 0, canceled: 0, expired: 0 },
    };
    const results: AnthropicBatchResultLike[] = [
      {
        custom_id: "req-1",
        result: {
          type: "succeeded",
          message: {
            id: "m1",
            model: "claude-sonnet-5",
            content: [{ type: "text", text: '{"ok":true}' }],
            stop_reason: "end_turn",
            usage: { input_tokens: 10, output_tokens: 5 },
          },
        },
      },
      {
        custom_id: "req-2",
        result: { type: "errored", error: { type: "invalid_request", message: "bad request" } },
      },
      { custom_id: "req-3", result: { type: "canceled" } },
      { custom_id: "req-4", result: { type: "expired" } },
    ];
    return {
      created,
      client: {
        messages: {
          create: async () => {
            throw new Error("complete() should not be called by batch methods");
          },
          batches: {
            create: async (body) => {
              created.push(
                body as { requests: { custom_id: string; params: Record<string, unknown> }[] },
              );
              return batch;
            },
            retrieve: async () => ({
              ...batch,
              processing_status: "ended",
              request_counts: { processing: 0, succeeded: 1, errored: 1, canceled: 1, expired: 1 },
            }),
            results: async () =>
              (async function* (): AsyncGenerator<AnthropicBatchResultLike> {
                for (const r of results) yield r;
              })(),
          },
        },
      },
    };
  }

  it("submitBatch() builds one request row per item with the SAME body shape as complete()", async () => {
    const { client, created } = fakeBatchClient();
    const adapter = new AnthropicAdapter({ config: cfg(), client });

    const handle = await adapter.submitBatch([
      { customId: "req-1", request: req(), modelId: "claude-sonnet-5" },
      { customId: "req-2", request: req({ tools: [GREP_TOOL] }), modelId: "claude-sonnet-5" },
    ]);

    expect(handle).toEqual({ batchId: "batch_1", processingStatus: "in_progress" });
    expect(created).toHaveLength(1);
    expect(created[0]?.requests.map((r) => r.custom_id)).toEqual(["req-1", "req-2"]);
    expect(created[0]?.requests[0]?.params).toMatchObject({ model: "claude-sonnet-5" });
    expect(created[0]?.requests[1]?.params?.tools).toEqual([
      { name: "grep", description: "Search the codebase", input_schema: GREP_TOOL.parameters },
    ]);
  });

  it("pollBatch() reports processing status + per-outcome counts", async () => {
    const { client } = fakeBatchClient();
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    const status = await adapter.pollBatch("batch_1");
    expect(status).toEqual({
      batchId: "batch_1",
      processingStatus: "ended",
      counts: { processing: 0, succeeded: 1, errored: 1, canceled: 1, expired: 1 },
    });
  });

  it("getBatchResults() normalizes succeeded/errored/canceled/expired rows, keyed by custom_id", async () => {
    const { client } = fakeBatchClient();
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    const rows = [];
    for await (const row of adapter.getBatchResults("batch_1")) rows.push(row);

    expect(rows).toHaveLength(4);
    expect(rows[0]).toMatchObject({
      customId: "req-1",
      status: "succeeded",
      completion: { content: '{"ok":true}', usage: { inputTokens: 10, outputTokens: 5 } },
    });
    expect(rows[1]).toEqual({
      customId: "req-2",
      status: "errored",
      errorType: "invalid_request",
      message: "bad request",
    });
    expect(rows[2]).toEqual({ customId: "req-3", status: "canceled" });
    expect(rows[3]).toEqual({ customId: "req-4", status: "expired" });
  });

  it("throws NotImplementedError from submitBatch/pollBatch/getBatchResults when the client has no batches API", async () => {
    const client: AnthropicClientLike = {
      messages: { create: async () => ({ id: "m", content: [], usage: {} }) },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    await expect(
      adapter.submitBatch([{ customId: "x", request: req(), modelId: "claude-sonnet-5" }]),
    ).rejects.toThrow(NotImplementedError);
    await expect(adapter.pollBatch("batch_1")).rejects.toThrow(NotImplementedError);
    await expect(async () => {
      for await (const _ of adapter.getBatchResults("batch_1")) {
        // never reached
      }
    }).rejects.toThrow(NotImplementedError);
  });
});
