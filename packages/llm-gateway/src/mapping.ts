import type { LLMMessage, LLMRequest, LLMToolCall, StopReason } from "@montr/contracts";
import { normalizeModelId } from "@montr/cost-meter";

/**
 * Provider-agnostic request/response mapping. Turns the unified @montr/contracts
 * LLMRequest into each provider's message shape, maps tool definitions + tool
 * calls/results across the two wire families (Anthropic Messages, OpenAI Chat
 * Completions), and normalizes stop reasons.
 */

/** Parse a tool-call `arguments` JSON string into an object (never throws). */
function parseToolArgs(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === "object") return raw as Record<string, unknown>;
  if (typeof raw !== "string" || raw.trim() === "") return {};
  try {
    const v: unknown = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Collapse a message content union into a plain string. */
export function contentToString(content: LLMMessage["content"]): string {
  if (typeof content === "string") return content;
  return content.map((block) => block.text).join("");
}

/**
 * The effective system prompt: the request's `system` plus any `system`-role
 * messages (providers that carry system separately need this folded together).
 */
export function collectSystem(request: LLMRequest): string | undefined {
  const parts: string[] = [];
  if (request.system) parts.push(request.system);
  for (const m of request.messages) {
    if (m.role === "system") parts.push(contentToString(m.content));
  }
  return parts.length > 0 ? parts.join("\n\n") : undefined;
}

export type AnthropicContentBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; tool_use_id: string; content: string };

interface RoleContent {
  role: "user" | "assistant";
  content: string | AnthropicContentBlock[];
}

/** Messages for Anthropic/Bedrock: user/assistant turns; tool calls + results as blocks. */
export function toAnthropicMessages(request: LLMRequest): RoleContent[] {
  const out: RoleContent[] = [];
  for (const m of request.messages) {
    if (m.role === "system") continue;
    if (m.role === "tool") {
      out.push({
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: m.toolCallId ?? "",
            content: contentToString(m.content),
          },
        ],
      });
      continue;
    }
    if (m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0) {
      const blocks: AnthropicContentBlock[] = [];
      const text = contentToString(m.content);
      if (text) blocks.push({ type: "text", text });
      for (const tc of m.toolCalls) {
        blocks.push({ type: "tool_use", id: tc.id, name: tc.name, input: tc.arguments });
      }
      out.push({ role: "assistant", content: blocks });
      continue;
    }
    out.push({
      role: m.role === "assistant" ? "assistant" : "user",
      content: contentToString(m.content),
    });
  }
  return out;
}

export interface AnthropicToolDef {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

/** Anthropic tool definitions from the unified request (undefined when none). */
export function toAnthropicTools(request: LLMRequest): AnthropicToolDef[] | undefined {
  if (!request.tools || request.tools.length === 0) return undefined;
  return request.tools.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.parameters,
  }));
}

/** Extract `tool_use` blocks from an Anthropic response's content array. */
export function extractAnthropicToolCalls(
  content: Array<{ type: string; id?: string; name?: string; input?: unknown }> | undefined,
): LLMToolCall[] | undefined {
  if (!content) return undefined;
  const calls = content
    .filter((b) => b.type === "tool_use")
    .map((b, i) => ({
      id: b.id ?? `call_${i}`,
      name: b.name ?? "",
      arguments: parseToolArgs(b.input),
    }));
  return calls.length > 0 ? calls : undefined;
}

export interface VertexContent {
  role: "user" | "model";
  parts: Array<{ text: string }>;
}

/** Contents for Vertex (Gemini): user/model turns; system handled separately. */
export function toVertexContents(request: LLMRequest): VertexContent[] {
  const out: VertexContent[] = [];
  for (const m of request.messages) {
    if (m.role === "system") continue;
    out.push({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: contentToString(m.content) }],
    });
  }
  return out;
}

export interface OpenAiToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

export interface OpenAiMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_calls?: OpenAiToolCall[];
  tool_call_id?: string;
}

/** Messages for OpenAI Chat Completions: system prepended; tool calls + results mapped. */
export function toOpenAiMessages(request: LLMRequest): OpenAiMessage[] {
  const out: OpenAiMessage[] = [];
  const system = collectSystem(request);
  if (system) out.push({ role: "system", content: system });
  for (const m of request.messages) {
    if (m.role === "system") continue;
    if (m.role === "tool") {
      out.push({
        role: "tool",
        content: contentToString(m.content),
        tool_call_id: m.toolCallId ?? "",
      });
      continue;
    }
    if (m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0) {
      out.push({
        role: "assistant",
        content: contentToString(m.content),
        tool_calls: m.toolCalls.map((tc) => ({
          id: tc.id,
          type: "function",
          function: { name: tc.name, arguments: JSON.stringify(tc.arguments) },
        })),
      });
      continue;
    }
    out.push({
      role: m.role === "assistant" ? "assistant" : "user",
      content: contentToString(m.content),
    });
  }
  return out;
}

export interface OpenAiToolDef {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

/** OpenAI function-tool definitions from the unified request (undefined when none). */
export function toOpenAiTools(request: LLMRequest): OpenAiToolDef[] | undefined {
  if (!request.tools || request.tools.length === 0) return undefined;
  return request.tools.map((t) => ({
    type: "function",
    function: { name: t.name, description: t.description, parameters: t.parameters },
  }));
}

/** Normalize an OpenAI response message's `tool_calls` to the contract shape. */
export function extractOpenAiToolCalls(
  toolCalls: Array<{ id?: string; function?: { name?: string; arguments?: string } }> | undefined,
): LLMToolCall[] | undefined {
  if (!toolCalls || toolCalls.length === 0) return undefined;
  const calls = toolCalls.map((tc, i) => ({
    id: tc.id ?? `call_${i}`,
    name: tc.function?.name ?? "",
    arguments: parseToolArgs(tc.function?.arguments),
  }));
  return calls.length > 0 ? calls : undefined;
}

/** Map an Anthropic (native or Bedrock) stop reason to the contract union. */
export function mapAnthropicStopReason(reason: string | null | undefined): StopReason {
  switch (reason) {
    case "end_turn":
    case "max_tokens":
    case "stop_sequence":
    case "tool_use":
    case "refusal":
      return reason;
    case "pause_turn":
      return "end_turn";
    default:
      return "end_turn";
  }
}

/** Map a Vertex (Gemini) finish reason to the contract union. */
export function mapVertexFinishReason(reason: string | null | undefined): StopReason {
  switch ((reason ?? "").toUpperCase()) {
    case "MAX_TOKENS":
      return "max_tokens";
    case "STOP":
      return "end_turn";
    case "SAFETY":
    case "BLOCKLIST":
    case "PROHIBITED_CONTENT":
    case "SPII":
      return "refusal";
    default:
      return "end_turn";
  }
}

/** Map an OpenAI/Azure finish reason to the contract union. */
export function mapOpenAiFinishReason(reason: string | null | undefined): StopReason {
  switch (reason) {
    case "length":
      return "max_tokens";
    case "tool_calls":
    case "function_call":
      return "tool_use";
    case "content_filter":
      return "refusal";
    case "stop":
      return "end_turn";
    default:
      return "end_turn";
  }
}

/**
 * Whether an Anthropic-family model REJECTS sampling params (`temperature` etc.
 * 400 on Fable 5 / Opus 4.8 / 4.7 / Sonnet 5). Older Claude models accept them.
 */
export function anthropicRejectsSampling(modelId: string): boolean {
  const id = normalizeModelId(modelId).toLowerCase();
  if (id.includes("fable") || id.includes("mythos")) return true;
  if (id.includes("sonnet-5") || id.includes("sonnet5")) return true;
  if (id.includes("opus-4-8") || id.includes("opus-4-7")) return true;
  return false;
}
