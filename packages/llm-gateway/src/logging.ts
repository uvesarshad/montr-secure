import type { LLMCallLog, LLMCallMetadata, Provider, TokenUsage } from "@montr/contracts";
import type { Logger, LogFields } from "@montr/telemetry";

/**
 * ⛔ Per-call METADATA-ONLY logging (golden rule #1, §6.5/§11). We build an
 * LLMCallLog from token counts / model / latency / call metadata ONLY. Prompts,
 * system text, message content, code bodies, and API keys are NEVER referenced
 * here — there is no code path in this module that can read a request body.
 */

export interface BuildCallLogInput {
  provider: Provider;
  model: string;
  usage: TokenUsage;
  latencyMs: number;
  metadata: LLMCallMetadata;
  at: string;
}

export function buildCallLog(input: BuildCallLogInput): LLMCallLog {
  return {
    provider: input.provider,
    model: input.model,
    usage: input.usage,
    latencyMs: input.latencyMs,
    metadata: input.metadata,
    at: input.at,
  };
}

/** Flatten a call log into structured log fields (metadata only). */
export function callLogFields(log: LLMCallLog): LogFields {
  return {
    provider: log.provider,
    model: log.model,
    purpose: log.metadata.purpose,
    scanId: log.metadata.scanId,
    clientId: log.metadata.clientId,
    layer: log.metadata.layer,
    inputTokens: log.usage.inputTokens,
    outputTokens: log.usage.outputTokens,
    totalTokens: log.usage.totalTokens,
    latencyMs: log.latencyMs,
    at: log.at,
  };
}

export function logCall(logger: Logger | undefined, log: LLMCallLog): void {
  logger?.info("llm.call", callLogFields(log));
}
