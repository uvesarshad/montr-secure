/**
 * @montr/telemetry — structured logging + OpenTelemetry wrappers and the
 * append-only, hash-chained audit-log CLIENT interface.
 *
 * Wave 0: a console-backed logger with a mandatory secret/code SCRUBBER
 * (golden rule #1 — never log code or secret bodies) plus the AuditLogClient
 * interface (Prisma-backed implementation lands in @montr/state-store, WS-C).
 * pino/OTel wiring lands in WS-N/WS-P.
 */
import { NotImplementedError, type AuditEvent, type AuditEventInput } from "@montr/contracts";

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(bindings: LogFields): Logger;
}

/** Keys whose values are redacted before anything is logged (§10, golden rule #1). */
const SENSITIVE_KEY_PATTERN =
  /(code|source|body|patch|snippet|prompt|content|apikey|api_key|token|secret|password|authorization|cookie|key)/i;

const REDACTED = "[REDACTED]";

/** Recursively redact sensitive fields. NEVER logs code or secret bodies. */
export function scrubFields(fields: LogFields | undefined): LogFields {
  if (!fields) return {};
  const out: LogFields = {};
  for (const [k, v] of Object.entries(fields)) {
    if (SENSITIVE_KEY_PATTERN.test(k)) {
      out[k] = REDACTED;
    } else if (v && typeof v === "object" && !Array.isArray(v)) {
      out[k] = scrubFields(v as LogFields);
    } else {
      out[k] = v;
    }
  }
  return out;
}

class ConsoleLogger implements Logger {
  constructor(
    private readonly name: string,
    private readonly bindings: LogFields = {},
  ) {}

  private emit(level: LogLevel, message: string, fields?: LogFields): void {
    const record = {
      level,
      logger: this.name,
      msg: message,
      ...scrubFields({ ...this.bindings, ...fields }),
    };
    // Structured line; pino replaces this in Wave 1.
    const line = JSON.stringify(record);
    if (level === "error") console.error(line);
    else if (level === "warn") console.warn(line);
    else console.log(line);
  }

  debug(message: string, fields?: LogFields): void {
    this.emit("debug", message, fields);
  }
  info(message: string, fields?: LogFields): void {
    this.emit("info", message, fields);
  }
  warn(message: string, fields?: LogFields): void {
    this.emit("warn", message, fields);
  }
  error(message: string, fields?: LogFields): void {
    this.emit("error", message, fields);
  }
  child(bindings: LogFields): Logger {
    return new ConsoleLogger(this.name, { ...this.bindings, ...bindings });
  }
}

export function createLogger(name = "montr", bindings: LogFields = {}): Logger {
  return new ConsoleLogger(name, bindings);
}

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
