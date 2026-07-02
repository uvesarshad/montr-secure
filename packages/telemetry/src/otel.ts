/**
 * OpenTelemetry + Prometheus wiring (§10). `startTelemetry` registers a global
 * MeterProvider whose reader is a Prometheus scrape endpoint, so the instruments
 * created in {@link ./metrics} are exported. Telemetry is OFF by default
 * (hardened default, §10): callers must opt in via config, matching
 * `@montr/config` `telemetry.enabled`.
 *
 * NOTE: never wired into unit tests — starting it binds a TCP port. Apps
 * (worker/api) call this once at boot and `shutdown()` on exit.
 */
import { PrometheusExporter } from "@opentelemetry/exporter-prometheus";
import { NodeSDK } from "@opentelemetry/sdk-node";

export interface PrometheusOptions {
  /** Scrape port (Prometheus exporter default 9464). */
  port?: number;
  /** Scrape path (default "/metrics"). */
  endpoint?: string;
  /** Bind host (default all interfaces). */
  host?: string;
}

export interface TelemetryOptions {
  /** Master switch — mirrors config.telemetry.enabled (default OFF). */
  enabled?: boolean;
  serviceName?: string;
  prometheus?: PrometheusOptions;
}

export interface TelemetryHandle {
  readonly enabled: boolean;
  /** e.g. "http://0.0.0.0:9464/metrics" when the Prometheus reader is running. */
  readonly prometheusEndpoint?: string;
  shutdown(): Promise<void>;
}

const NOOP_HANDLE: TelemetryHandle = {
  enabled: false,
  shutdown: async () => {},
};

/**
 * Start the OTel metrics pipeline with a Prometheus exporter. Returns a no-op
 * handle when `enabled` is false so callers can unconditionally start/stop it.
 */
export function startTelemetry(opts: TelemetryOptions = {}): TelemetryHandle {
  if (!opts.enabled) return NOOP_HANDLE;

  const port = opts.prometheus?.port ?? 9464;
  const endpoint = opts.prometheus?.endpoint ?? "/metrics";
  const host = opts.prometheus?.host ?? "0.0.0.0";

  const exporter = new PrometheusExporter({ port, endpoint, host });
  const sdk = new NodeSDK({
    metricReader: exporter,
    // Metrics-only: no auto-instrumentation, no resource detectors, no egress.
    autoDetectResources: false,
    instrumentations: [],
  });
  sdk.start();

  return {
    enabled: true,
    prometheusEndpoint: `http://${host}:${port}${endpoint}`,
    shutdown: () => sdk.shutdown(),
  };
}
