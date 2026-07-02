import type { LLMMessage, LLMRequest, StopReason } from "@montr/contracts";
import { normalizeModelId } from "@montr/cost-meter";

/**
 * Provider-agnostic request/response mapping. Turns the unified @montr/contracts
 * LLMRequest into each provider's message shape and normalizes stop reasons.
 * Tool/function-calling passthrough is intentionally out of scope for this pass
 * (the pipeline drives text/JSON prompts); adapters ignore `request.tools`.
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

interface RoleContent {
  role: "user" | "assistant";
  content: string;
}

/** Messages for Anthropic/Bedrock: user/assistant turns only (tool → user). */
export function toAnthropicMessages(request: LLMRequest): RoleContent[] {
  const out: RoleContent[] = [];
  for (const m of request.messages) {
    if (m.role === "system") continue;
    out.push({
      role: m.role === "assistant" ? "assistant" : "user",
      content: contentToString(m.content),
    });
  }
  return out;
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

export interface OpenAiMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

/** Messages for Azure OpenAI: system prepended, then user/assistant (tool → user). */
export function toOpenAiMessages(request: LLMRequest): OpenAiMessage[] {
  const out: OpenAiMessage[] = [];
  const system = collectSystem(request);
  if (system) out.push({ role: "system", content: system });
  for (const m of request.messages) {
    if (m.role === "system") continue;
    out.push({
      role: m.role === "assistant" ? "assistant" : "user",
      content: contentToString(m.content),
    });
  }
  return out;
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
