# Observability config (Grafana + Prometheus)

This directory holds **config artifacts only** — this repo does not ship its own
Prometheus/Grafana deployment (there's nothing here for `deploy/helm` or `deploy/docker`
to install). Wire these into whatever Prometheus/Grafana stack you already run.

- `grafana/montr-secure-dashboard.json` — importable Grafana dashboard.
- `prometheus/montr-secure-rules.yaml` — recording + alerting rules.

## What's being scraped

`@montr/telemetry` (`packages/telemetry/src/otel.ts`) registers an OTel `MeterProvider`
with a Prometheus exporter when telemetry is enabled. It is **OFF by default** (hardened
default, §10) — enable it via `config.telemetry.enabled` (Helm: `telemetry.enabled` in
`deploy/helm/montr-secure/values.yaml`). Once enabled, each process (API, worker) serves
Prometheus text format at:

```
http://<pod>:9464/metrics
```

(port/path/host are configurable via `TelemetryOptions.prometheus`; defaults are
`9464` / `/metrics` / all interfaces).

## 1. Scrape config

Point your existing Prometheus at the API and worker pods. A minimal static example:

```yaml
scrape_configs:
  - job_name: montr-secure
    metrics_path: /metrics
    static_configs:
      - targets:
          - montr-secure-api:9464
          - montr-secure-worker:9464
```

In Kubernetes, prefer pod annotations + `kubernetes_sd_configs` (or a `ServiceMonitor` if
you run the Prometheus Operator) over a static target list:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9464"
  prometheus.io/path: "/metrics"
```

## 2. Recording + alerting rules

Add `montr-secure-rules.yaml` to your Prometheus server's `rule_files:`:

```yaml
rule_files:
  - /etc/prometheus/rules/montr-secure-rules.yaml
```

(mount the file into the Prometheus pod/container via ConfigMap, volume, or however your
stack already loads rule files — this repo doesn't manage that mount for you). Reload
Prometheus (`SIGHUP` or the `/-/reload` endpoint) after adding it.

The file defines two groups:

- `montr-secure.recording` — precomputed rates backing the dashboard panels
  (`montr:budget_breach:rate5m`, `montr:kill_switch_activation:rate5m`,
  `montr:gate_bypass_attempt:rate5m`, `montr:errors:rate5m`,
  `montr:layer_duration_ms:p95_5m`).
- `montr-secure.alerts` — fires on the three new safety counters
  (`MontrBudgetBreach`, `MontrKillSwitchActivated`, `MontrGateBypassAttempt`,
  `MontrGateBypassAttemptBurst`) plus two general pipeline-health alerts
  (`MontrErrorRateHigh`, `MontrLayerP95LatencyHigh`).

Route the `critical`/`warning` `severity` labels to your existing Alertmanager receivers
(PagerDuty, Slack, etc.) the same way you already route other services' alerts — no
Montr-specific Alertmanager config is included here.

## 3. Import the dashboard

In Grafana: **Dashboards → New → Import**, upload
`grafana/montr-secure-dashboard.json` (or paste its contents), and select your
Prometheus datasource for the `DS_PROMETHEUS` input prompt. It has two rows:

- **Safety controls (§11 alerting)** — stat tiles + time series for budget breaches,
  kill-switch activations, and gate-bypass attempts (the three new counters), plus an
  overall error-rate tile for context. A dashboard annotation marks kill-switch
  activations on every time series.
- **Pipeline throughput & cost** — findings in/out per layer, layer duration p50/p95,
  LLM call rate (a proxy for spend — see note below), and errors by code.

Re-import (overwrite) to pick up future edits to the JSON file; the dashboard `uid` is
fixed (`montr-secure-overview`) so re-importing updates the same dashboard instead of
creating a duplicate.

### Note on "LLM cost"

There is currently no dollar-denominated OTel metric — `montr_llm_calls_total` (call
count) is the closest proxy and is what the dashboard graphs. Exact per-scan cost is
computed by `@montr/cost-meter` and surfaced in each scan's `CostRollup` (report-side),
not exported to Prometheus. If per-scan USD spend needs to be alertable/graphable in
Grafana, add a dedicated histogram/counter in `packages/telemetry/src/metrics.ts`
(e.g. `montr.cost.usd`) and wire it from `@montr/cost-meter`.

## Metric reference (new counters)

| Prometheus series                             | OTel instrument                | Emitted from                                                                                                 |
| --------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `montr_budget_breach_total{enforcement}`      | `montr.budget.breach`          | `packages/cost-meter/src/variance.ts` (`enforceBudget`), on hard-halt                                        |
| `montr_kill_switch_activation_total{scope}`   | `montr.kill_switch.activation` | `packages/orchestrator/src/controller.ts` (`kill()`), scope `"global"` or `"scan"`                           |
| `montr_gate_bypass_attempt_total{route,role}` | `montr.gate.bypass_attempt`    | `apps/api/src/plugins/auth-plugin.ts` (`requireApprover`), on a non-approver hitting an approver-gated route |
