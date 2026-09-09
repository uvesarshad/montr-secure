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
 * A4: the gateway must be able to re-encode a PRIOR tool exchange (an
 * assistant tool call + the tool's result) onto a FOLLOWING turn, across all
 * three wire families — not just parse a single tool_use response. Ported
 * from the July line's tests/llm-gateway.tools.test.ts, adapted to current's
 * adapter-level injected-client pattern (see capabilities.test.ts) and to
 * `LLMToolCall.input` naming (July used `.arguments` — see mapping.ts's A4
 * doc comment; current's naming is kept everywhere, including this fixture).
 */

function cfg(provider = "anthropic", endpoint?: string): MontrConfig {
  return parseConfig({ llm: { apiKey: "sk-test", provider, ...(endpoint ? { endpoint } : {}) } });
}

const READ_FILE_TOOL: LLMToolDefinition = {
  name: "read_file",
  description: "Read a repo-relative source file.",
  parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
};

/** A multi-turn request: user asks, assistant already called a tool, tool replied. */
function toolConversationRequest(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return LLMRequestSchema.parse({
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
    tools: [READ_FILE_TOOL],
    metadata: { purpose: "fix_generation" },
    ...overrides,
  });
}

describe("tool conversation round-trip — Anthropic wire family", () => {
  it("re-encodes the prior tool_use/tool_result turns and surfaces the next tool_use call", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: AnthropicClientLike = {
      messages: {
        create: async (body) => {
          capturedBody = body;
          return {
            id: "msg_1",
            model: "claude-sonnet-5",
            content: [
              { type: "tool_use", id: "call_9", name: "read_file", input: { path: "c.ts" } },
            ],
            stop_reason: "tool_use",
            usage: { input_tokens: 6, output_tokens: 4 },
          };
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: cfg(), client });
    const result = await adapter.complete(toolConversationRequest(), "claude-sonnet-5");

    expect(result.stopReason).toBe("tool_use");
    expect(result.toolCalls).toEqual([
      { id: "call_9", name: "read_file", input: { path: "c.ts" } },
    ]);

    const tools = capturedBody?.tools as Array<{ name: string; input_schema: unknown }>;
    expect(tools[0]).toMatchObject({ name: "read_file" });

    const msgs = capturedBody?.messages as Array<{ role: string; content: unknown }>;
    const assistant = msgs.find((m) => m.role === "assistant");
    const aBlocks = assistant?.content as Array<{ type: string; id?: string; input?: unknown }>;
    const toolUse = aBlocks.find((b) => b.type === "tool_use");
    expect(toolUse).toMatchObject({ id: "call_1", name: "read_file", input: { path: "a.ts" } });

    const toolResult = msgs
      .flatMap((m) =>
        Array.isArray(m.content)
          ? (m.content as Array<{ type: string; tool_use_id?: string; content?: string }>)
          : [],
      )
      .find((b) => b.type === "tool_result");
    expect(toolResult).toMatchObject({ tool_use_id: "call_1", content: "export const x = 1;" });
  });
});

describe("tool conversation round-trip — Bedrock (shares Anthropic's Messages body shape)", () => {
  it("re-encodes the prior tool_use/tool_result turns in the Bedrock InvokeModel body", async () => {
    let capturedBodyJson: string | undefined;
    const transport: BedrockTransport = {
      invoke: async (_modelId, body) => {
        capturedBodyJson = body;
        return {
          id: "b1",
          model: "anthropic.claude-sonnet-5",
          content: [{ type: "tool_use", id: "call_9", name: "read_file", input: { path: "c.ts" } }],
          stop_reason: "tool_use",
          usage: { input_tokens: 6, output_tokens: 4 },
        };
      },
      invokeStream: async function* () {},
    };
    const adapter = new BedrockAdapter({ config: cfg("bedrock"), transport });
    const result = await adapter.complete(toolConversationRequest(), "claude-sonnet-5");

    expect(result.toolCalls).toEqual([
      { id: "call_9", name: "read_file", input: { path: "c.ts" } },
    ]);

    const body = JSON.parse(capturedBodyJson ?? "{}") as {
      messages: Array<{ role: string; content: unknown }>;
    };
    const assistant = body.messages.find((m) => m.role === "assistant");
    const aBlocks = assistant?.content as Array<{ type: string }>;
    expect(aBlocks.some((b) => b.type === "tool_use")).toBe(true);
    const toolResult = body.messages
      .flatMap((m) => (Array.isArray(m.content) ? (m.content as Array<{ type: string }>) : []))
      .find((b) => b.type === "tool_result");
    expect(toolResult).toBeDefined();
  });
});

describe("tool conversation round-trip — Vertex/Gemini (native)", () => {
  it("re-encodes the prior functionCall/functionResponse turns and surfaces the next call", async () => {
    let capturedReq: unknown;
    const transport: VertexTransport = {
      generate: async (_model, req) => {
        capturedReq = req;
        return {
          candidates: [
            {
              content: { parts: [{ functionCall: { name: "read_file", args: { path: "d.ts" } } }] },
              finishReason: "STOP",
            },
          ],
          usageMetadata: { promptTokenCount: 4, candidatesTokenCount: 2, totalTokenCount: 6 },
        };
      },
      generateStream: async function* () {},
    };
    const adapter = new VertexAdapter({ config: cfg("vertex"), transport });
    const result = await adapter.complete(toolConversationRequest(), "gemini-x");

    expect(result.toolCalls).toEqual([
      { id: "read_file:0", name: "read_file", input: { path: "d.ts" } },
    ]);

    const sent = capturedReq as {
      tools?: Array<{ functionDeclarations: Array<{ name: string }> }>;
      contents: Array<{
        role: string;
        parts: Array<{ functionCall?: unknown; functionResponse?: unknown }>;
      }>;
    };
    expect(sent.tools?.[0]?.functionDeclarations[0]?.name).toBe("read_file");

    const modelFnCall = sent.contents.find(
      (c) => c.role === "model" && c.parts.some((p) => p.functionCall),
    );
    expect(modelFnCall).toBeDefined();
    const fnResp = sent.contents.flatMap((c) => c.parts).find((p) => p.functionResponse);
    expect(fnResp).toBeDefined();
  });
});

describe("tool conversation round-trip — OpenAI/Azure wire family", () => {
  it("re-encodes the prior tool_calls/tool result turns and surfaces the next tool_calls", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    const client: OpenAiClientLike = {
      chat: {
        completions: {
          create: async (body) => {
            capturedBody = body;
            return {
              id: "resp_1",
              model: "gpt-x",
              choices: [
                {
                  message: {
                    content: "",
                    tool_calls: [
                      {
                        id: "call_2",
                        type: "function",
                        function: { name: "read_file", arguments: '{"path":"b.ts"}' },
                      },
                    ],
                  },
                  finish_reason: "tool_calls",
                },
              ],
              usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
            };
          },
        },
      },
    };
    const adapter = new AzureAdapter({
      config: cfg("azure", "https://x.openai.azure.com"),
      client,
    });
    const result = await adapter.complete(toolConversationRequest(), "gpt-x-deployment");

    expect(result.stopReason).toBe("tool_use");
    expect(result.toolCalls).toEqual([
      { id: "call_2", name: "read_file", input: { path: "b.ts" } },
    ]);

    const tools = capturedBody?.tools as Array<{ type: string; function: { name: string } }>;
    expect(tools[0]).toMatchObject({ type: "function", function: { name: "read_file" } });

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
});
