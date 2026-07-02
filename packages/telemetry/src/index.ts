/**
 * @montr/telemetry — structured logging + OpenTelemetry/Prometheus metrics and
 * the append-only, hash-chained audit-log CLIENT interface (§10, §15, §8.5).
 *
 * - {@link createLogger}: pino-backed logger with a mandatory SCRUBBER so code
 *   bodies and secrets are never logged (golden rule #1).
 * - {@link MontrMetrics}/{@link getMetrics}: per-layer counters + histograms
 *   (findings in/out, demotion, confirmation, FP-feedback).
 * - {@link startTelemetry}: OTel MeterProvider + Prometheus exporter (opt-in).
 * - {@link AuditLogClient}/{@link WriteThroughAuditLogClient}: the audit client;
 *   the Prisma-backed implementation lives in @montr/state-store (WS-C).
 */
export * from "./scrubber.js";
export * from "./logger.js";
export * from "./metrics.js";
export * from "./otel.js";
export * from "./audit-client.js";
