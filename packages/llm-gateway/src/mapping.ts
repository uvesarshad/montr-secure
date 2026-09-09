import type { LLMMessage, LLMRequest, LLMToolDefinition, StopReason } from "@montr/contracts";
import { normalizeModelId } from "@montr/cost-meter";
import { resolveAnthropicOutputFormat } from "./structured-output.js";

/**
 * Provider-agnostic request/response mapping. Turns the unified @montr/contracts
 * LLMRequest into each provider's message shape and normalizes stop reasons.
 *
 * A8: tool/function-calling IS forwarded — see {@link toAnthropicTools},
 * {@link toVertexTools}, and {@link toOpenAiTools} — each adapter's
 * `buildBody`/`buildRequest` attaches the mapped tool list when
 * `request.tools` is present, and parses a tool-use/function-call response
 * back into a typed {@link LLMToolCall}[] (see each adapter's response mapper).
 *
 * A4: {@link toAnthropicMessages}, {@link toVertexContents} and
 * {@link toOpenAiMessages} also re-encode a PRIOR tool exchange onto a
 * following turn — an assistant message's `toolCalls` (contract's `.input`
 * naming throughout, never July's `.arguments`) becomes `tool_use` /
 * `functionCall` / `tool_calls`, and a `role: "tool"` message becomes
 * `tool_result` / `functionResponse` / a `role: "tool"` turn. This is what
 * turns single-round "the model asked for a tool" into a sustained tool
 * conversation.
 */

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

/**
 * One block of an Anthropic-shaped message's content array (A4: tool
 * round-tripping). `tool_use` re-encodes a prior assistant tool call;
 * `tool_result` re-encodes the tool's reply to it — the pair that lets a tool
 * exchange be carried forward onto a following turn.
 */
export type AnthropicMessageContentBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; tool_use_id: string; content: string };

interface RoleContent {
  role: "user" | "assistant";
  content: string | AnthropicMessageContentBlock[];
}

/**
 * Messages for Anthropic/Bedrock: user/assistant turns. A4: a `role: "tool"`
 * message becomes a user turn carrying a `tool_result` block (keyed by
 * `toolCallId`); an assistant turn that made tool calls carries `tool_use`
 * blocks alongside any text — so a prior tool exchange re-encodes onto a
 * FOLLOWING turn instead of collapsing to plain text.
 */
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
      const blocks: AnthropicMessageContentBlock[] = [];
      const text = contentToString(m.content);
      if (text) blocks.push({ type: "text", text });
      for (const tc of m.toolCalls) {
        blocks.push({ type: "tool_use", id: tc.id, name: tc.name, input: tc.input });
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

/**
 * One part of a Vertex (Gemini) content turn (A4: tool round-tripping).
 * `functionCall` re-encodes a prior assistant tool call; `functionResponse`
 * re-encodes the tool's reply — Gemini's equivalent of Anthropic's
 * `tool_use`/`tool_result` pair.
 */
export interface VertexPart {
  text?: string;
  functionCall?: { name: string; args: Record<string, unknown> };
  functionResponse?: { name: string; response: Record<string, unknown> };
}

export interface VertexContent {
  role: "user" | "model";
  parts: VertexPart[];
}

/**
 * Contents for Vertex (Gemini): user/model turns; system handled separately.
 * A4: a `role: "tool"` message becomes a user turn carrying a
 * `functionResponse` part; a `model` turn that made tool calls carries
 * `functionCall` parts alongside any text.
 */
export function toVertexContents(request: LLMRequest): VertexContent[] {
  const out: VertexContent[] = [];
  for (const m of request.messages) {
    if (m.role === "system") continue;
    if (m.role === "tool") {
      out.push({
        role: "user",
        parts: [
          {
            functionResponse: {
              name: m.name ?? "tool",
              response: { result: contentToString(m.content) },
            },
          },
        ],
      });
      continue;
    }
    if (m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0) {
      const parts: VertexPart[] = [];
      const text = contentToString(m.content);
      if (text) parts.push({ text });
      for (const tc of m.toolCalls) {
        parts.push({ functionCall: { name: tc.name, args: tc.input } });
      }
      out.push({ role: "model", parts });
      continue;
    }
    out.push({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: contentToString(m.content) }],
    });
  }
  return out;
}

/** A tool call re-encoded onto OpenAI/Azure's `assistant.tool_calls` wire shape (A4). */
export interface OpenAiToolCallWire {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

export interface OpenAiMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  /** Present on an assistant turn that made tool calls (A4). */
  tool_calls?: OpenAiToolCallWire[];
  /** Present on a `role: "tool"` turn: the call this result answers (A4). */
  tool_call_id?: string;
}

/**
 * Messages for Azure OpenAI: system prepended, then user/assistant. A4: a
 * `role: "tool"` message becomes a `role: "tool"` turn carrying `tool_call_id`;
 * an assistant turn that made tool calls carries `tool_calls` (arguments
 * re-serialized to JSON strings, OpenAI's wire encoding) alongside any text.
 */
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
          type: "function" as const,
          function: { name: tc.name, arguments: JSON.stringify(tc.input) },
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

export interface AnthropicToolLike {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

/** Map contract tool definitions to Anthropic/Bedrock's `tools` wire shape. */
export function toAnthropicTools(request: LLMRequest): AnthropicToolLike[] | undefined {
  if (!request.tools || request.tools.length === 0) return undefined;
  return request.tools.map((t: LLMToolDefinition) => ({
    name: t.name,
    description: t.description,
    input_schema: t.parameters,
  }));
}

export interface VertexFunctionDeclaration {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}
export interface VertexToolLike {
  functionDeclarations: VertexFunctionDeclaration[];
}

/** Map contract tool definitions to Vertex/Gemini's `tools[].functionDeclarations` shape. */
export function toVertexTools(request: LLMRequest): VertexToolLike[] | undefined {
  if (!request.tools || request.tools.length === 0) return undefined;
  return [
    {
      functionDeclarations: request.tools.map((t: LLMToolDefinition) => ({
        name: t.name,
        description: t.description,
        parameters: t.parameters,
      })),
    },
  ];
}

export interface OpenAiToolLike {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}

/** Map contract tool definitions to Azure/OpenAI's `tools[].function` shape. */
export function toOpenAiTools(request: LLMRequest): OpenAiToolLike[] | undefined {
  if (!request.tools || request.tools.length === 0) return undefined;
  return request.tools.map((t: LLMToolDefinition) => ({
    type: "function" as const,
    function: { name: t.name, description: t.description, parameters: t.parameters },
  }));
}

/**
 * Whether the model accepts `output_config.effort` / adaptive `thinking`
 * (A8). Per the current Claude API, Haiku-tier models reject `effort`
 * (400) — every other model on the recommended matrix (Opus, Sonnet-5,
 * Fable) supports it. This mirrors {@link anthropicRejectsSampling}'s
 * "modern model" gate but is a distinct check: sampling rejection and effort
 * support don't coincide for Haiku (Haiku still accepts `temperature`, just
 * not `effort`/adaptive thinking).
 */
export function anthropicSupportsEffort(modelId: string): boolean {
  const id = normalizeModelId(modelId).toLowerCase();
  return !id.includes("haiku");
}

/**
 * Build the fields common to Anthropic and Bedrock's Anthropic-Messages-shaped
 * request body (A8: tools, effort/thinking, structured-output format; A31:
 * prompt caching on the system prompt). Each adapter merges its own top-level
 * fields (Anthropic: `model`; Bedrock: `anthropic_version`) around this.
 *
 * Prompt caching (A31 partial): the system prompt is the one stable-prefix
 * cache point wired in this pass — marked `cache_control: {type: "ephemeral"}`
 * whenever a system prompt is present. A per-call App Map cache point was
 * evaluated but deferred: no real call site here passes a large stable
 * App-Map-shaped context block without a larger prompt-restructuring refactor
 * across the layer packages, which is out of scope for this change.
 */
export function buildAnthropicStyleFields(
  request: LLMRequest,
  modelId: string,
): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    max_tokens: request.maxTokens,
    messages: toAnthropicMessages(request),
  };
  const system = collectSystem(request);
  if (system) {
    // Array form (rather than a plain string) so a cache_control breakpoint
    // can be attached — the wire shape Anthropic requires for caching.
    fields.system = [{ type: "text", text: system, cache_control: { type: "ephemeral" } }];
  }
  if (request.temperature !== undefined && !anthropicRejectsSampling(modelId)) {
    fields.temperature = request.temperature;
  }
  const tools = toAnthropicTools(request);
  if (tools) fields.tools = tools;

  const outputConfig: Record<string, unknown> = {};
  if (request.effort && anthropicSupportsEffort(modelId)) outputConfig.effort = request.effort;
  const format = resolveAnthropicOutputFormat(request);
  if (format) outputConfig.format = format;
  if (Object.keys(outputConfig).length > 0) fields.output_config = outputConfig;

  if (request.effort && anthropicSupportsEffort(modelId)) {
    fields.thinking = { type: "adaptive" };
  }
  return fields;
}

/**
 * Build the minimal body for Anthropic's real token-counting endpoint
 * (`messages.countTokens` / `POST /v1/messages/count_tokens`, A19). Mirrors
 * {@link buildAnthropicStyleFields}'s message/system/tools mapping (token
 * count depends on all three) but deliberately omits `max_tokens`,
 * `output_config`, `thinking`, and `cache_control` — none of those affect
 * INPUT token count, which is all this endpoint reports, and `cache_control`
 * specifically is meaningless here (count_tokens neither reads nor writes the
 * prompt cache).
 */
export function buildAnthropicCountTokensBody(
  request: LLMRequest,
  modelId: string,
): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    model: modelId,
    messages: toAnthropicMessages(request),
  };
  const system = collectSystem(request);
  if (system) fields.system = system;
  const tools = toAnthropicTools(request);
  if (tools) fields.tools = tools;
  return fields;
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
 * 400 on Fable 5 / Opus 5 / 4.8 / 4.7 / Sonnet 5). Older Claude models accept them.
 *
 * Found-while-working fix (incidental to A8): this previously matched
 * `opus-4-8`/`opus-4-7` but not `opus-5` — a gap that went live when A11's
 * model-matrix refresh made `claude-opus-5` the confirmation-tier default
 * (packages/contracts/src/llm.ts's RECOMMENDED_MODEL_MATRIX), which meant
 * every real confirmation-tier call would have incorrectly sent `temperature`
 * to a model that 400s on it. Added here since {@link buildAnthropicStyleFields}
 * (this same file) is the direct, newly-centralized caller of this check.
 */
export function anthropicRejectsSampling(modelId: string): boolean {
  const id = normalizeModelId(modelId).toLowerCase();
  if (id.includes("fable") || id.includes("mythos")) return true;
  if (id.includes("sonnet-5") || id.includes("sonnet5")) return true;
  if (id.includes("opus-5") || id.includes("opus-4-8") || id.includes("opus-4-7")) return true;
  return false;
}
