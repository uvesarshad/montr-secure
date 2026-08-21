import { describe, it, expect } from "vitest";
import { LLMRequestSchema, type LLMRequest, type LLMToolDefinition } from "@montr/contracts";
import { parseConfig, type MontrConfig } from "@montr/config";
import {
  AnthropicAdapter,
  BedrockAdapter,
  VertexAdapter,
  AzureAdapter,
  type AnthropicClientLike,
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
