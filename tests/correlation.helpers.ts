/**
 * Shared, OFFLINE test doubles for the @montr/correlation (Layer 2) suites.
 * No network, no DB, no provider SDK — everything is deterministic.
 */
import type {
  AuditEvent,
  AuditEventInput,
  LLMGateway,
  LLMRequest,
  LLMResponse,
  LLMStreamEvent,
  ModelDescriptor,
  ModelTier,
} from "@montr/contracts";
import type { AuditLogClient } from "@montr/telemetry";

/** In-memory audit client that records every appended event input. */
export function makeFakeAudit(): { client: AuditLogClient; events: AuditEventInput[] } {
  const events: AuditEventInput[] = [];
  const client: AuditLogClient = {
    append(input: AuditEventInput): Promise<AuditEvent> {
      events.push(input);
      const sequence = events.length;
      const event: AuditEvent = {
        id: `audit_${sequence}`,
        sequence,
        prevHash: "",
        hash: `h${sequence}`,
        at: "2026-01-15T10:00:00.000Z",
        ...input,
        metadata: input.metadata ?? {},
      };
      return Promise.resolve(event);
    },
    list(): Promise<AuditEvent[]> {
      return Promise.resolve([]);
    },
    verifyChain(): Promise<boolean> {
      return Promise.resolve(true);
    },
  };
  return { client, events };
}

/** Wraps a gateway, capturing every request passed to complete(). */
export class RecordingGateway implements LLMGateway {
  readonly requests: LLMRequest[] = [];
  constructor(private readonly inner: LLMGateway) {}

  complete(request: LLMRequest): Promise<LLMResponse> {
    this.requests.push(request);
    return this.inner.complete(request);
  }
  stream(request: LLMRequest): AsyncIterable<LLMStreamEvent> {
    this.requests.push(request);
    return this.inner.stream(request);
  }
  listModels(): ModelDescriptor[] {
    return this.inner.listModels();
  }
  resolveModel(tierOrId: ModelTier | string): ModelDescriptor {
    return this.inner.resolveModel(tierOrId);
  }
}

/** A minimal gateway whose complete() returns a fixed content string. */
export function fixedContentGateway(content: string, base: LLMGateway): LLMGateway {
  return {
    complete(_request: LLMRequest): Promise<LLMResponse> {
      return Promise.resolve({
        id: "fixed",
        provider: "anthropic",
        model: "claude-sonnet-5",
        content,
        stopReason: "end_turn",
        usage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 },
        latencyMs: 1,
      });
    },
    stream: base.stream.bind(base),
    listModels: base.listModels.bind(base),
    resolveModel: base.resolveModel.bind(base),
  };
}

/** A gateway whose complete() always throws (to exercise fail-safe fallback). */
export function throwingGateway(base: LLMGateway): LLMGateway {
  return {
    complete(): Promise<LLMResponse> {
      return Promise.reject(new Error("simulated gateway outage"));
    },
    stream: base.stream.bind(base),
    listModels: base.listModels.bind(base),
    resolveModel: base.resolveModel.bind(base),
  };
}

/** Concatenated text of every prompt sent to a RecordingGateway. */
export function promptText(gw: RecordingGateway): string {
  return gw.requests
    .map(
      (r) =>
        (r.system ?? "") +
        r.messages
          .map((m) => (typeof m.content === "string" ? m.content : JSON.stringify(m.content)))
          .join(" "),
    )
    .join("\n");
}
