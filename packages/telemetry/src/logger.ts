/**
 * Structured logging (§10). A thin, scrubbing wrapper over `pino`. EVERY field
 * passes through the {@link scrubFields} scrubber before it reaches a sink, so
 * code bodies and secrets can never be logged (golden rule #1) — even if a
 * caller forgets. `pino`'s own path-based `redact` is wired as a second line of
 * defense on the well-known keys.
 */
import pino from "pino";
import { scrubFields, type ScrubberOptions } from "./scrubber.js";

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogFields = Record<string, unknown>;

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(bindings: LogFields): Logger;
}

export interface LoggerOptions {
  /** Logger name (added as a binding). */
  name?: string;
  /** Minimum level to emit. Defaults to $LOG_LEVEL or "info". */
  level?: LogLevel;
  /** Scrubber tuning (max string length, extra sensitive keys, …). */
  scrubber?: ScrubberOptions;
  /** Pre-bound fields merged into every record. */
  bindings?: LogFields;
  /** Inject a pino destination (tests capture output here). */
  destination?: pino.DestinationStream;
}

/** pino path redactions — belt-and-suspenders on top of the recursive scrubber. */
const PINO_REDACT_PATHS = [
  "apiKey",
  "api_key",
  "token",
  "refreshToken",
  "password",
  "secret",
  "authorization",
  "cookie",
  "patch",
  "code",
  "prompt",
  "*.apiKey",
  "*.token",
  "*.password",
  "*.secret",
  "*.patch",
];

class PinoLogger implements Logger {
  constructor(
    private readonly pino: pino.Logger,
    private readonly scrubberOpts?: ScrubberOptions,
  ) {}

  private scrub(fields?: LogFields): LogFields {
    return scrubFields(fields, this.scrubberOpts);
  }

  debug(message: string, fields?: LogFields): void {
    this.pino.debug(this.scrub(fields), message);
  }
  info(message: string, fields?: LogFields): void {
    this.pino.info(this.scrub(fields), message);
  }
  warn(message: string, fields?: LogFields): void {
    this.pino.warn(this.scrub(fields), message);
  }
  error(message: string, fields?: LogFields): void {
    this.pino.error(this.scrub(fields), message);
  }
  child(bindings: LogFields): Logger {
    return new PinoLogger(this.pino.child(this.scrub(bindings)), this.scrubberOpts);
  }
}

/**
 * Create a structured, scrubbing logger. `name` may be passed as a string for
 * backwards compatibility, or the full options object.
 */
export function createLogger(nameOrOptions: string | LoggerOptions = "montr"): Logger {
  const opts: LoggerOptions =
    typeof nameOrOptions === "string" ? { name: nameOrOptions } : nameOrOptions;

  const level = opts.level ?? (process.env["LOG_LEVEL"] as LogLevel | undefined) ?? "info";
  const base: LogFields = { ...(opts.bindings ?? {}) };

  const pinoOpts: pino.LoggerOptions = {
    name: opts.name ?? "montr",
    level,
    base: Object.keys(base).length > 0 ? base : undefined,
    redact: { paths: PINO_REDACT_PATHS, censor: "[REDACTED]" },
    // Avoid leaking host/pid unless asked; keep records minimal & deterministic.
  };

  const instance = opts.destination ? pino(pinoOpts, opts.destination) : pino(pinoOpts);

  return new PinoLogger(instance, opts.scrubber);
}

/** A logger that discards everything — for tests and library defaults. */
export function createNullLogger(): Logger {
  const noop: Logger = {
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
    child: () => noop,
  };
  return noop;
}
