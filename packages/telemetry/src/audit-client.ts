/**
 * Audit-log CLIENT interface + a write-through decorator (§8.5).
 *
 * The append-only, hash-chained audit log itself is implemented against Postgres
 * in `@montr/state-store` (it needs node:crypto + Prisma). This module defines
 * the interface every caller depends on, plus {@link WriteThroughAuditLogClient}
 * — the client apps actually use. It (1) scrubs metadata of any code/secret
 * bodies, (2) emits a metadata-only structured log line, (3) bumps the audit
 * metric, then (4) writes through to the underlying store client.
 *
 * Dependency direction stays acyclic: the store implementation is injected;
 * @montr/telemetry never imports @montr/state-store.
 */
import type { AuditEvent, AuditEventInput } from "@montr/contracts";
import { NotImplementedError } from "@montr/contracts";
import { createNullLogger, type Logger } from "./logger.js";
import { getMetrics, type MontrMetrics } from "./metrics.js";
import { scrubValue } from "./scrubber.js";

export interface AuditListOptions {
  scanId?: string;
  limit?: number;
  fromSequence?: number;
}

/**
 * Append-only, hash-chained audit log (§8.5). Every mutating action binds to an
 * AuditEvent. Implemented by @montr/state-store against Postgres.
 */
export interface AuditLogClient {
  append(input: AuditEventInput): Promise<AuditEvent>;
  list(clientId: string, opts?: AuditListOptions): Promise<AuditEvent[]>;
  /** Verify the hash chain is intact (tamper-evident, §14). */
  verifyChain(clientId: string): Promise<boolean>;
}

/** No-op audit client for early wiring/tests before the Prisma-backed one exists. */
export class NoopAuditLogClient implements AuditLogClient {
  append(_input: AuditEventInput): Promise<AuditEvent> {
    throw new NotImplementedError(
      "AuditLogClient.append — implemented in @montr/state-store (WS-C)",
    );
  }
  list(_clientId: string, _opts?: AuditListOptions): Promise<AuditEvent[]> {
    throw new NotImplementedError("AuditLogClient.list — implemented in @montr/state-store (WS-C)");
  }
  verifyChain(_clientId: string): Promise<boolean> {
    throw new NotImplementedError(
      "AuditLogClient.verifyChain — implemented in @montr/state-store (WS-C)",
    );
  }
}

export interface WriteThroughOptions {
  logger?: Logger;
  metrics?: MontrMetrics;
  /** Skip the structured log line (still scrubs + writes through). */
  silent?: boolean;
}

/**
 * Decorates an {@link AuditLogClient}, scrubbing metadata and recording
 * telemetry on every append. This is the client apps should use — it guarantees
 * (defense-in-depth) that no code/secret body reaches the audit store even if a
 * caller passes an unscrubbed metadata bag.
 */
export class WriteThroughAuditLogClient implements AuditLogClient {
  private readonly logger: Logger;
  private readonly metrics: MontrMetrics;

  constructor(
    private readonly delegate: AuditLogClient,
    opts: WriteThroughOptions = {},
  ) {
    this.logger = opts.silent ? createNullLogger() : (opts.logger ?? createNullLogger());
    this.metrics = opts.metrics ?? getMetrics();
  }

  async append(input: AuditEventInput): Promise<AuditEvent> {
    const scrubbedMetadata = scrubValue(input.metadata ?? {}) as Record<string, unknown>;
    const safeInput: AuditEventInput = { ...input, metadata: scrubbedMetadata };

    const event = await this.delegate.append(safeInput);

    // Metadata only — never the code/secret bodies (golden rule #1).
    this.logger.info("audit.event", {
      action: event.action,
      sequence: event.sequence,
      clientId: event.clientId,
      scanId: event.scanId,
      actorType: event.actor.type,
      actorRole: event.actor.role,
      targetType: event.targetType,
    });
    this.metrics.recordAuditEvent(event.action);
    return event;
  }

  list(clientId: string, opts?: AuditListOptions): Promise<AuditEvent[]> {
    return this.delegate.list(clientId, opts);
  }

  verifyChain(clientId: string): Promise<boolean> {
    return this.delegate.verifyChain(clientId);
  }
}
