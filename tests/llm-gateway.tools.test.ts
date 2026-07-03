import { describe, it, expect } from "vitest";
import { parseConfig } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import {
  createLlmGateway,
  OpenAiCompatibleAdapter,
  AnthropicAdapter,
  VertexAdapter,
  type OpenAiClientLike,
  type AnthropicClientLike,
  type VertexTransport,
  type VertexGenerateRequest,
} from "@montr/llm-gateway";
import { LLMResponseSchema, type LLMRequest, type LLMToolDefinition } from "@montr/contracts";

/**
 * ⛔ Tool-calling passthrough (Phase 3b): the gateway maps `request.tools` to each
 * wire family, surfaces `tool_use` + parsed tool calls in the response, and carries
 * assistant tool calls + tool results back across turns.
 */

const CONFIG = parseConfig({ llm: { apiKey: "sk-test", endpoint: "https://llm.internal/v1" } });

const READ_FILE_TOOL: LLMToolDefinition = {
  name: "read_file",
  description: "Read a repo-relative source file.",
  parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
};

/** A multi-turn request: user asks, assistant already called a tool, tool replied. */
function toolRequest(): LLMRequest {
  return {
    tier: "default",
    messages: [
      { role: "user", content: "fix the bug in a.ts" },
      {
        role: "assistant",
        content: "",
        toolCalls: [{ id: "call_1", name: "read_file", arguments: { path: "a.ts" } }],
      },
      { role: "tool", content: "export const x = 1;", toolCallId: "call_1", name: "read_file" },
    ],
    maxTokens: 256,
    tools: [READ_FILE_TOOL],
    responseFormat: "text",
    stream: false,
    metadata: { purpose: "fix_generation" },
  };
}

describe("gateway tool-calling — OpenAI wire family", () => {
  it("passes tool definitions + tool-call/result history, and surfaces tool_use calls", async () => {
    let seen: Record<string, unknown> | undefined;
    const client: OpenAiClientLike = {
      chat: {
        completions: {
          create: (body) => {
            seen = body as Record<string, unknown>;
            return Promise.resolve({
              id: "resp_1",
              model: "gpt-x",
              choices: [
                {
                  message: {
                    content: "",
                    tool_calls: [
                      {
                        id: "call_2",
                        function: { name: "read_file", arguments: '{"path":"b.ts"}' },
                      },
                    ],
                  },
                  finish_reason: "tool_calls",
                },
              ],
              usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
            });
          },
        },
      },
    };
    const adapter = new OpenAiCompatibleAdapter({
      provider: "openai",
      defaultBaseUrl: "https://api.openai.com/v1",
      defaultHost: "api.openai.com",
      config: CONFIG,
      client,
    });
    const gw = createLlmGateway({ config: CONFIG, adapter, logger: createNullLogger() });
    const res = await gw.complete(toolRequest());

    expect(LLMResponseSchema.safeParse(res).success).toBe(true);
    expect(res.stopReason).toBe("tool_use");
    expect(res.toolCalls).toEqual([
      { id: "call_2", name: "read_file", arguments: { path: "b.ts" } },
    ]);

    // Request carried the tool definition + the multi-turn tool call/result.
    const tools = seen?.tools as Array<{ type: string; function: { name: string } }>;
    expect(tools[0]).toMatchObject({ type: "function", function: { name: "read_file" } });
    const msgs = seen?.messages as Array<Record<string, unknown>>;
    const assistant = msgs.find((m) => m.role === "assistant");
    expect((assistant?.tool_calls as unknown[])?.length).toBe(1);
    const toolMsg = msgs.find((m) => m.role === "tool");
    expect(toolMsg?.tool_call_id).toBe("call_1");
  });
});

describe("gateway tool-calling — Anthropic wire family", () => {
  it("passes tools + maps tool_use/tool_result blocks, and surfaces tool_use calls", async () => {
    let seen: Record<string, unknown> | undefined;
    const client: AnthropicClientLike = {
      messages: {
        create: (body) => {
          seen = body as Record<string, unknown>;
          return Promise.resolve({
            id: "msg_1",
            model: "claude-x",
            content: [
              { type: "text", text: "" },
              { type: "tool_use", id: "call_9", name: "read_file", input: { path: "c.ts" } },
            ],
            stop_reason: "tool_use",
            usage: { input_tokens: 6, output_tokens: 4 },
          });
        },
      },
    };
    const adapter = new AnthropicAdapter({ config: CONFIG, client });
    const gw = createLlmGateway({ config: CONFIG, adapter, logger: createNullLogger() });
    const res = await gw.complete(toolRequest());

    expect(res.stopReason).toBe("tool_use");
    expect(res.toolCalls).toEqual([
      { id: "call_9", name: "read_file", arguments: { path: "c.ts" } },
    ]);

    // Anthropic tools shape + tool_use/tool_result content blocks in the request.
    const tools = seen?.tools as Array<{ name: string; input_schema: unknown }>;
    expect(tools[0]).toMatchObject({ name: "read_file" });
    expect(tools[0].input_schema).toBeDefined();
    const msgs = seen?.messages as Array<{ role: string; content: unknown }>;
    const assistant = msgs.find((m) => m.role === "assistant");
    const aBlocks = assistant?.content as Array<{ type: string }>;
    expect(aBlocks.some((b) => b.type === "tool_use")).toBe(true);
    const toolResult = msgs
      .flatMap((m) => (Array.isArray(m.content) ? (m.content as Array<{ type: string }>) : []))
      .find((b) => b.type === "tool_result");
    expect(toolResult).toBeDefined();
  });
});

describe("gateway tool-calling — Vertex/Gemini (native)", () => {
  it("passes functionDeclarations + maps functionCall/functionResponse, surfaces tool_use", async () => {
    let seen: VertexGenerateRequest | undefined;
    const transport: VertexTransport = {
      generate: (_model, req) => {
        seen = req;
        return Promise.resolve({
          candidates: [
            {
              content: { parts: [{ functionCall: { name: "read_file", args: { path: "d.ts" } } }] },
              finishReason: "STOP",
            },
          ],
          usageMetadata: { promptTokenCount: 4, candidatesTokenCount: 2, totalTokenCount: 6 },
        });
      },
      // eslint-disable-next-line require-yield
      generateStream: async function* () {
        return;
      },
    };
    const adapter = new VertexAdapter({ config: CONFIG, transport });
    const gw = createLlmGateway({ config: CONFIG, adapter, logger: createNullLogger() });
    const res = await gw.complete(toolRequest());

    expect(res.stopReason).toBe("tool_use");
    expect(res.toolCalls).toEqual([
      { id: "call_0", name: "read_file", arguments: { path: "d.ts" } },
    ]);

    // functionDeclarations passed; functionCall (model) + functionResponse (tool) in contents.
    expect(seen?.tools?.[0].functionDeclarations[0].name).toBe("read_file");
    const modelFnCall = seen?.contents.find(
      (c) => c.role === "model" && c.parts.some((p) => p.functionCall),
    );
    expect(modelFnCall).toBeDefined();
    const fnResp = seen?.contents.flatMap((c) => c.parts).find((p) => p.functionResponse);
    expect(fnResp).toBeDefined();
  });
});
