/**
 * Per-layer metrics collectors (§10, §15). Emits OpenTelemetry instruments AND
 * keeps an internal tally so metrics are introspectable (and unit-testable)
 * without a running exporter or a registered MeterProvider.
 *
 * Headline pipeline metrics:
 *   - findings IN / OUT per layer          (counters)
 *   - demotion count + demotion ratio      (counter + histogram)  — Layer 2
 *   - confirmation count + confirmation rate (counter + histogram) — Layer 3
 *   - false-positive feedback count        (counter)              — §15 FP loop
 *   - per-layer wall-clock duration        (histogram)
 *   - audit events / LLM calls / errors    (counters)
 *   - budget breaches / kill-switch activations / gate-bypass attempts
 *                                           (counters)              — §10, §11 alerting
 */
import { metrics, ValueType, type Counter, type Histogram, type Meter } from "@opentelemetry/api";
import type { AuditAction, LayerId } from "@montr/contracts";

export const METER_NAME = "montr.pipeline";
export const METER_VERSION = "1.0.0";

/** Plain-object view of the internal tallies (for tests / health endpoints). */
export interface MetricsSnapshot {
  findingsIn: Record<string, number>;
  findingsOut: Record<string, number>;
  demoted: number;
  confirmed: number;
  falsePositiveFeedback: number;
  auditEvents: number;
  llmCalls: number;
  errors: number;
  budgetBreaches: number;
  killSwitchActivations: number;
  gateBypassAttempts: number;
}

type Attrs = Record<string, string | number | boolean>;

function inc(map: Map<string, number>, key: string, by: number): void {
  map.set(key, (map.get(key) ?? 0) + by);
}

/**
 * Records the pipeline's per-layer metrics. Construct one per process (see
 * {@link getMetrics}) or per test. Safe to use before {@link startTelemetry}
 * registers a real MeterProvider — the OTel calls no-op and the internal
 * snapshot still updates.
 */
export class MontrMetrics {
  private readonly meter: Meter;

  private readonly findingsInCounter: Counter;
  private readonly findingsOutCounter: Counter;
  private readonly demotedCounter: Counter;
  private readonly confirmedCounter: Counter;
  private readonly fpCounter: Counter;
  private readonly auditCounter: Counter;
  private readonly llmCounter: Counter;
  private readonly errorCounter: Counter;
  private readonly budgetBreachCounter: Counter;
  private readonly killSwitchActivationCounter: Counter;
  private readonly gateBypassAttemptCounter: Counter;

  private readonly layerDuration: Histogram;
  private readonly demotionRatio: Histogram;
  private readonly confirmationRatio: Histogram;

  // Internal tallies (snapshot / test introspection).
  private readonly tFindingsIn = new Map<string, number>();
  private readonly tFindingsOut = new Map<string, number>();
  private tDemoted = 0;
  private tConfirmed = 0;
  private tFp = 0;
  private tAudit = 0;
  private tLlm = 0;
  private tErrors = 0;
  private tBudgetBreaches = 0;
  private tKillSwitchActivations = 0;
  private tGateBypassAttempts = 0;

  constructor(meter: Meter = metrics.getMeter(METER_NAME, METER_VERSION)) {
    this.meter = meter;
    this.findingsInCounter = this.meter.createCounter("montr.findings.in", {
      description: "Findings entering a layer",
      valueType: ValueType.INT,
    });
    this.findingsOutCounter = this.meter.createCounter("montr.findings.out", {
      description: "Findings leaving a layer",
      valueType: ValueType.INT,
    });
    this.demotedCounter = this.meter.createCounter("montr.findings.demoted", {
      description: "Candidates demoted to the appendix (never deleted)",
      valueType: ValueType.INT,
    });
    this.confirmedCounter = this.meter.createCounter("montr.findings.confirmed", {
      description: "Probable findings confirmed exploitable",
      valueType: ValueType.INT,
    });
    this.fpCounter = this.meter.createCounter("montr.findings.false_positive_feedback", {
      description: "Confirmed findings marked false-positive by an operator (§15)",
      valueType: ValueType.INT,
    });
    this.auditCounter = this.meter.createCounter("montr.audit.events", {
      description: "Audit-log events appended",
      valueType: ValueType.INT,
    });
    this.llmCounter = this.meter.createCounter("montr.llm.calls", {
      description: "LLM calls made (metadata only)",
      valueType: ValueType.INT,
    });
    this.errorCounter = this.meter.createCounter("montr.errors", {
      description: "Errors by code",
      valueType: ValueType.INT,
    });
    this.budgetBreachCounter = this.meter.createCounter("montr.budget.breach", {
      description: "Budget ceiling breaches (hard-halt enforcement, DECIDE-4)",
      valueType: ValueType.INT,
    });
    this.killSwitchActivationCounter = this.meter.createCounter("montr.kill_switch.activation", {
      description: "Kill-switch activations, scoped or global (§11, golden rule)",
      valueType: ValueType.INT,
    });
    this.gateBypassAttemptCounter = this.meter.createCounter("montr.gate.bypass_attempt", {
      description:
        "Rejected attempts to act on an approver-gated action without the approver role (§11)",
      valueType: ValueType.INT,
    });
    this.layerDuration = this.meter.createHistogram("montr.layer.duration_ms", {
      description: "Wall-clock duration of a layer",
      unit: "ms",
      valueType: ValueType.DOUBLE,
    });
    this.demotionRatio = this.meter.createHistogram("montr.correlation.demotion_ratio", {
      description: "Fraction of candidates demoted in Layer 2 (0..1)",
      valueType: ValueType.DOUBLE,
    });
    this.confirmationRatio = this.meter.createHistogram("montr.confirmation.rate", {
      description: "Fraction of probable findings confirmed in Layer 3 (0..1)",
      valueType: ValueType.DOUBLE,
    });
  }

  recordFindingsIn(layer: LayerId, count: number, attrs: Attrs = {}): void {
    this.findingsInCounter.add(count, { layer, ...attrs });
    inc(this.tFindingsIn, layer, count);
  }

  recordFindingsOut(layer: LayerId, count: number, attrs: Attrs = {}): void {
    this.findingsOutCounter.add(count, { layer, ...attrs });
    inc(this.tFindingsOut, layer, count);
  }

  recordDemotion(count = 1, attrs: Attrs = {}): void {
    this.demotedCounter.add(count, attrs);
    this.tDemoted += count;
  }

  recordConfirmation(count = 1, attrs: Attrs = {}): void {
    this.confirmedCounter.add(count, attrs);
    this.tConfirmed += count;
  }

  recordFalsePositiveFeedback(count = 1, attrs: Attrs = {}): void {
    this.fpCounter.add(count, attrs);
    this.tFp += count;
  }

  recordAuditEvent(action: AuditAction, count = 1): void {
    this.auditCounter.add(count, { action });
    this.tAudit += count;
  }

  recordLlmCall(attrs: Attrs = {}, count = 1): void {
    this.llmCounter.add(count, attrs);
    this.tLlm += count;
  }

  recordError(code: string, count = 1): void {
    this.errorCounter.add(count, { code });
    this.tErrors += count;
  }

  /** A budget ceiling was breached and hard-halt enforcement fired (DECIDE-4). */
  recordBudgetBreach(count = 1, attrs: Attrs = {}): void {
    this.budgetBreachCounter.add(count, attrs);
    this.tBudgetBreaches += count;
  }

  /** The kill switch was activated for a scan (scoped) or every scan (global). */
  recordKillSwitchActivation(count = 1, attrs: Attrs = {}): void {
    this.killSwitchActivationCounter.add(count, attrs);
    this.tKillSwitchActivations += count;
  }

  /** A caller without the approver role attempted an approver-gated action (§11). */
  recordGateBypassAttempt(count = 1, attrs: Attrs = {}): void {
    this.gateBypassAttemptCounter.add(count, attrs);
    this.tGateBypassAttempts += count;
  }

  observeLayerDuration(layer: LayerId, ms: number, attrs: Attrs = {}): void {
    this.layerDuration.record(ms, { layer, ...attrs });
  }

  /** Record Layer-2 demotion ratio = demoted / candidatesIn (clamped to 0..1). */
  observeDemotionRatio(candidatesIn: number, demoted: number, attrs: Attrs = {}): void {
    if (candidatesIn <= 0) return;
    const ratio = Math.min(1, Math.max(0, demoted / candidatesIn));
    this.demotionRatio.record(ratio, attrs);
  }

  /** Record Layer-3 confirmation rate = confirmed / probableIn (clamped to 0..1). */
  observeConfirmationRate(probableIn: number, confirmed: number, attrs: Attrs = {}): void {
    if (probableIn <= 0) return;
    const ratio = Math.min(1, Math.max(0, confirmed / probableIn));
    this.confirmationRatio.record(ratio, attrs);
  }

  /** Point-in-time snapshot of the internal tallies. */
  snapshot(): MetricsSnapshot {
    return {
      findingsIn: Object.fromEntries(this.tFindingsIn),
      findingsOut: Object.fromEntries(this.tFindingsOut),
      demoted: this.tDemoted,
      confirmed: this.tConfirmed,
      falsePositiveFeedback: this.tFp,
      auditEvents: this.tAudit,
      llmCalls: this.tLlm,
      errors: this.tErrors,
      budgetBreaches: this.tBudgetBreaches,
      killSwitchActivations: this.tKillSwitchActivations,
      gateBypassAttempts: this.tGateBypassAttempts,
    };
  }

  /** Reset internal tallies (tests only — OTel instruments are cumulative). */
  reset(): void {
    this.tFindingsIn.clear();
    this.tFindingsOut.clear();
    this.tDemoted = 0;
    this.tConfirmed = 0;
    this.tFp = 0;
    this.tAudit = 0;
    this.tLlm = 0;
    this.tErrors = 0;
    this.tBudgetBreaches = 0;
    this.tKillSwitchActivations = 0;
    this.tGateBypassAttempts = 0;
  }
}

let shared: MontrMetrics | undefined;

/** Process-wide metrics collector (lazily created against the global meter). */
export function getMetrics(): MontrMetrics {
  shared ??= new MontrMetrics();
  return shared;
}
