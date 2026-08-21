/**
 * @montr/orchestrator controller — the pipeline FSM made concrete.
 *
 * Drives L0→L1→L2→L3→L4→L5 with every state PERSISTED (Scan.status +
 * Scan.gateState + the ResumeToken checkpoint) so runs are idempotent and
 * RESUMABLE: a failed/killed Layer-3 never re-runs Layer 0–2 (§8.1). The gate is
 * an explicit pipeline STATE, not a config flag (golden rule #5). A kill switch
 * halts all active work — especially live DAST — immediately (§11). Every
 * mutation is audit-logged (golden rule #7); audit metadata is ids/counts only,
 * never code or secret bodies (golden rule #1).
 */
import { randomUUID } from "node:crypto";
import {
  buildIdempotencyKey,
  isMontrError,
  KillSwitchActivatedError,
  Layer0JobDataSchema,
  Layer1JobDataSchema,
  Layer2JobDataSchema,
  Layer3JobDataSchema,
  Layer4JobDataSchema,
  Layer5JobDataSchema,
  MontrError,
  ResumeTokenSchema,
  RETRY_POLICIES,
  ScanNotResumableError,
  ScanSchema,
  type AuditActor,
  type AuditEventInput,
  type CostActual,
  type ErrorEnvelope,
  type KillSwitchSignal,
  type LayerId,
  type LayerJobData,
  type LayerJobResultMap,
  type PipelineEvent,
  type Scan,
  type ScanMode,
  type ScanScope,
  type BudgetPolicy,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { StateStore } from "@montr/state-store";
import { getMetrics, type Logger } from "@montr/telemetry";
import type { BudgetRegistry, CostMeter } from "@montr/cost-meter";
import { EventBus, events } from "./events.js";
import { KillRegistry } from "./kill-switch.js";
import { realSleep, runWithRetry, type SleepFn } from "./retry.js";
import { InlineJobScheduler, type JobScheduler } from "./scheduler.js";
import type { LayerContext, LayerRunners, PriorOutputs } from "./runner.js";
import { persistLayerOutput } from "./persist.js";
import {
  computeAllowLive,
  effectiveBudgetPolicy,
  estimateGateRequired,
  evaluateFixGate,
  isTerminalStatus,
  LAYER_ORDER,
  layerAfter,
  nextLayer,
} from "./fsm.js";

/* -------------------------------- public API ------------------------------- */

export interface OrchestratorDeps {
  config: MontrConfig;
  store: StateStore;
  logger: Logger;
  /** Factory so each scan gets its own cost meter instance. */
  createCostMeter: (scanId: string) => CostMeter;
  /** The layer implementations. apps/worker wires real ones; tests inject stubs. */
  layerRunners: LayerRunners;
  /** Job transport. Defaults to an in-process scheduler (no Redis) — see BullMqJobScheduler. */
  scheduler?: JobScheduler;
  /** Shared event bus (e.g. so apps/api can also subscribe). Defaults to a fresh one. */
  eventBus?: EventBus;
  /** Deterministic clock hook (tests). Default: `new Date()`. */
  clock?: () => Date;
  /** Deterministic id hook (tests). Default: `crypto.randomUUID()`. */
  ids?: () => string;
  /** Injectable retry-backoff sleep (tests pass a no-op). Default: real timers. */
  sleep?: SleepFn;
  /**
   * ⛔ PRE-call budget guard (A2, DECIDE-4). When supplied, each running
   * scan's live `CostMeter` + effective `BudgetPolicy` are REGISTERED here the
   * moment a layer starts (and unregistered on cleanup) so `@montr/llm-gateway`
   * can refuse a single over-budget call BEFORE dispatching it — additive to
   * this controller's own `enforceBudget`, which only runs BETWEEN layers.
   * The same `budgetRegistry` instance must be passed to `createLlmGateway`.
   */
  budgetRegistry?: BudgetRegistry;
}

export interface CreateScanInput {
  clientId: string;
  repo: string;
  branch: string;
  mode: ScanMode;
  scope: ScanScope;
  operator: string;
  budgetPolicy?: BudgetPolicy;
}

/** Scan lifecycle API (create/start/pause/resume/cancel) + status/progress stream. */
export interface Orchestrator {
  createScan(input: CreateScanInput): Promise<Scan>;
  start(scanId: string): Promise<void>;
  pause(scanId: string): Promise<void>;
  resume(scanId: string): Promise<void>;
  cancel(scanId: string): Promise<void>;
  /** ⛔ Kill switch — halts all active work immediately (esp. DAST probing). */
  kill(signal: KillSwitchSignal): Promise<void>;
  status(scanId: string): Promise<Scan>;
  /** Approve the cost-estimate or fix gate (approver only; RBAC enforced upstream). */
  approveGate(scanId: string, gate: "estimate" | "fix", approver: string): Promise<void>;
  events(scanId: string): AsyncIterable<PipelineEvent>;
  /** Release scheduler/queue resources. */
  close(): Promise<void>;
}

/* --------------------------------- helpers --------------------------------- */

const SYSTEM_ACTOR: AuditActor = { type: "system", id: "orchestrator" };

function userActor(id: string, role: "operator" | "approver" | "viewer"): AuditActor {
  return { type: "user", id, role };
}

function killActor(signal: KillSwitchSignal): AuditActor {
  return signal.requestedByRole
    ? { type: "user", id: signal.requestedBy, role: signal.requestedByRole }
    : { type: "user", id: signal.requestedBy };
}

function toEnvelope(err: unknown): ErrorEnvelope {
  if (isMontrError(err)) return err.toEnvelope();
  const message = err instanceof Error ? err.message : String(err);
  return { code: "INTERNAL", message, retriable: false };
}

function errorCode(err: unknown): string {
  return isMontrError(err) ? err.code : "INTERNAL";
}

function clampPct(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

function assertNever(x: never): never {
  throw new MontrError("INTERNAL", `unexpected layer: ${String(x)}`);
}

/* ------------------------------- controller -------------------------------- */

class OrchestratorController implements Orchestrator {
  private readonly config: MontrConfig;
  private readonly store: StateStore;
  private readonly logger: Logger;
  private readonly createCostMeter: (scanId: string) => CostMeter;
  private readonly budgetRegistry?: BudgetRegistry;
  private readonly runners: LayerRunners;
  private readonly scheduler: JobScheduler;
  private readonly bus: EventBus;
  private readonly clock: () => Date;
  private readonly ids: () => string;
  private readonly sleep: SleepFn;

  private readonly kills = new KillRegistry();
  private readonly meters = new Map<string, CostMeter>();
  private readonly caches = new Map<string, PriorOutputs>();
  private readonly budgetWarned = new Set<string>();
  private readonly scanClient = new Map<string, string>();
  private schedulerStarted = false;

  constructor(deps: OrchestratorDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.logger = deps.logger.child({ component: "orchestrator" });
    this.createCostMeter = deps.createCostMeter;
    this.budgetRegistry = deps.budgetRegistry;
    this.runners = deps.layerRunners;
    this.scheduler = deps.scheduler ?? new InlineJobScheduler();
    this.bus = deps.eventBus ?? new EventBus();
    this.clock = deps.clock ?? (() => new Date());
    this.ids = deps.ids ?? (() => randomUUID());
    this.sleep = deps.sleep ?? realSleep;

    this.scheduler.setProcessor(this.runLayerJob);
    this.scheduler.onKill((signal) => {
      void this.handleRemoteKill(signal);
    });
  }

  /* ------------------------------ lifecycle ------------------------------- */

  async createScan(input: CreateScanInput): Promise<Scan> {
    const now = this.nowIso();
    const scan = ScanSchema.parse({
      id: this.ids(),
      clientId: input.clientId,
      repo: input.repo,
      branch: input.branch,
      mode: input.mode,
      scope: input.scope,
      status: "queued",
      gateState: "not_started",
      operator: input.operator,
      budgetPolicy: input.budgetPolicy,
      createdAt: now,
    });
    await this.store.scans.create(input.clientId, scan);
    this.scanClient.set(scan.id, input.clientId);
    await this.safeAudit({
      clientId: input.clientId,
      scanId: scan.id,
      action: "scan.created",
      actor: userActor(input.operator, "operator"),
      summary: "Scan created.",
      metadata: { repo: scan.repo, branch: scan.branch, mode: scan.mode },
    });
    return scan;
  }

  async start(scanId: string): Promise<void> {
    const scan = await this.load(scanId);
    if (scan.status !== "queued") {
      this.logger.warn("start ignored: scan not queued", { scanId, status: scan.status });
      return;
    }
    if (this.kills.isGlobalKilled())
      throw new KillSwitchActivatedError("global kill switch active");

    this.kills.register(scanId);
    await this.ensureSchedulerStarted();

    scan.status = "running";
    scan.startedAt = this.nowIso();
    await this.store.scans.update(scan.clientId, scan);
    await this.store.resume.save(
      scan.clientId,
      ResumeTokenSchema.parse({
        scanId,
        completedLayers: [],
        checkpointRef: scanId,
        updatedAt: this.nowIso(),
      }),
    );
    this.emit(events.scanStarted(scanId, this.nowIso()));
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "scan.started",
      actor: userActor(scan.operator, "operator"),
      summary: "Scan started.",
      metadata: { mode: scan.mode },
    });
    await this.scheduleLayer(scan, "layer0");
  }

  async pause(scanId: string): Promise<void> {
    const scan = await this.load(scanId);
    if (isTerminalStatus(scan.status)) return;
    // Cooperative pause: the in-flight layer finishes and persists, then the FSM
    // halts before scheduling the next layer. (Kill is the immediate stop.)
    scan.status = "paused";
    await this.store.scans.update(scan.clientId, scan);
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "scan.paused",
      actor: userActor(scan.operator, "operator"),
      summary: "Scan paused.",
      metadata: {},
    });
  }

  async resume(scanId: string): Promise<void> {
    const scan = await this.load(scanId);
    if (this.kills.isKilled(scanId)) throw new ScanNotResumableError("scan was killed");
    if (scan.status === "completed" || scan.status === "cancelled") {
      this.logger.warn("resume ignored: scan terminal", { scanId, status: scan.status });
      return;
    }

    const token = await this.store.resume.get(scan.clientId, scanId);
    const completed = token?.completedLayers ?? [];

    this.kills.register(scanId);
    await this.ensureSchedulerStarted();

    scan.status = "running";
    await this.store.scans.update(scan.clientId, scan);
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "scan.resumed",
      actor: userActor(scan.operator, "operator"),
      summary: "Scan resumed.",
      metadata: { completedLayers: completed },
    });

    // Never bypass a pending gate on resume.
    if (scan.gateState === "estimate_pending") {
      this.emit(events.gateRequired(scanId, "estimate", this.nowIso()));
      return;
    }
    if (scan.gateState === "fix_gate_pending") {
      this.emit(events.gateRequired(scanId, "fix", this.nowIso()));
      return;
    }

    const next = nextLayer(completed);
    if (!next) {
      await this.finalizeComplete(scan, false);
      return;
    }
    this.emit(events.resumed(scanId, next, this.nowIso()));
    await this.scheduleLayer(scan, next);
  }

  async cancel(scanId: string): Promise<void> {
    const scan = await this.load(scanId);
    if (isTerminalStatus(scan.status)) return;
    // Abort any in-flight work immediately.
    this.kills.abortScan(scanId, "cancelled by operator");
    scan.status = "cancelled";
    if (scan.gateState === "estimate_pending" || scan.gateState === "fix_gate_pending") {
      scan.gateState = "rejected";
    }
    scan.finishedAt = this.nowIso();
    scan.costActual = this.safeActual(scanId);
    await this.store.scans.update(scan.clientId, scan);
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "scan.cancelled",
      actor: userActor(scan.operator, "operator"),
      summary: "Scan cancelled.",
      metadata: {},
    });
    this.cleanup(scanId);
  }

  async kill(signal: KillSwitchSignal): Promise<void> {
    const at = this.nowIso();
    if (signal.scope === "global") {
      const ids = this.kills.activeScanIds();
      this.kills.abortAll(signal.reason);
      await this.scheduler.publishKill(signal);
      for (const scanId of ids) await this.blockKilled(scanId, signal, at);
      // Observability: kill-switch activation counter (§11 alerting).
      getMetrics().recordKillSwitchActivation(1, { scope: "global" });
      await this.safeAudit({
        clientId: this.config.clientId,
        action: "dast.kill_switch",
        actor: killActor(signal),
        summary: `Global kill switch: ${signal.reason}`,
        metadata: { scope: "global", scanCount: ids.length },
      });
      return;
    }
    if (!signal.scanId) throw new MontrError("INTERNAL", "scoped kill requires a scanId");
    this.kills.abortScan(signal.scanId, signal.reason);
    await this.scheduler.publishKill(signal);
    await this.blockKilled(signal.scanId, signal, at);
    // Observability: kill-switch activation counter (§11 alerting).
    getMetrics().recordKillSwitchActivation(1, { scope: "scan" });
  }

  status(scanId: string): Promise<Scan> {
    return this.load(scanId);
  }

  async approveGate(scanId: string, gate: "estimate" | "fix", approver: string): Promise<void> {
    const scan = await this.load(scanId);
    if (isTerminalStatus(scan.status)) {
      this.logger.warn("approveGate ignored: scan terminal", { scanId, gate, status: scan.status });
      return;
    }
    scan.approver = approver;

    if (gate === "estimate") {
      if (scan.gateState !== "estimate_pending") {
        this.logger.warn("approveGate(estimate) ignored: not pending", {
          scanId,
          gateState: scan.gateState,
        });
        return;
      }
      scan.gateState = "estimate_approved";
      scan.status = "running";
      await this.store.scans.update(scan.clientId, scan);
      await this.safeAudit({
        clientId: scan.clientId,
        scanId,
        action: "gate.estimate_approved",
        actor: userActor(approver, "approver"),
        summary: "Cost estimate approved.",
        metadata: this.estimateMeta(scan),
      });
      await this.scheduleLayer(scan, "layer1");
      return;
    }

    // gate === "fix"
    if (scan.gateState !== "fix_gate_pending") {
      this.logger.warn("approveGate(fix) ignored: not pending", {
        scanId,
        gateState: scan.gateState,
      });
      return;
    }
    scan.gateState = "approved";
    await this.store.scans.update(scan.clientId, scan);
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "gate.fix_approved",
      actor: userActor(approver, "approver"),
      summary: "Fix gate approved by approver; PRs will open for auto-eligible fixes only.",
      metadata: {},
    });
    // Human approval authorizes code changes; L5 still opens PRs for auto-eligible only.
    await this.scheduleLayer(scan, "layer5", { autoApply: true });
  }

  events(scanId: string): AsyncIterable<PipelineEvent> {
    return this.bus.subscribe(scanId);
  }

  async close(): Promise<void> {
    await this.scheduler.close();
  }

  /* -------------------------------- engine -------------------------------- */

  /** The processor invoked by the scheduler for each layer job. */
  private readonly runLayerJob = async (job: LayerJobData): Promise<void> => {
    const { scanId, clientId, layer } = job;
    if (this.kills.isKilled(scanId)) return;

    let scan = await this.store.scans.get(clientId, scanId);
    if (!scan) {
      this.logger.error("runLayerJob: scan not found", { scanId, layer });
      return;
    }
    this.scanClient.set(scanId, scan.clientId);
    if (isTerminalStatus(scan.status) || scan.status === "paused") return;

    const signal = this.kills.signalFor(scanId);
    const meter = this.getMeter(scanId);
    // ⛔ PRE-call budget guard (A2): (re-)register BEFORE executing the layer so
    // the gateway can see the ceiling in effect for THIS layer's calls. Cheap
    // and idempotent — a plain Map upsert — so re-registering every job is fine.
    this.budgetRegistry?.register(scanId, meter, effectiveBudgetPolicy(scan, this.config));
    this.emit(events.layerStarted(scanId, layer, this.nowIso()));

    let output: LayerJobResultMap[LayerId];
    try {
      output = await this.executeLayer(scan, job, meter, signal);
    } catch (err) {
      if (signal.aborted || this.kills.isKilled(scanId)) return; // kill path already blocked it
      await this.failScan(scan, layer, err);
      return;
    }

    // Persist the tier and advance the checkpoint BEFORE deciding what runs next.
    try {
      await persistLayerOutput(this.store, clientId, layer, output, scan, this.getCache(scanId));
      await this.advanceResumeToken(clientId, scanId, layer);
    } catch (err) {
      await this.failScan(scan, layer, err);
      return;
    }
    this.emit(events.layerCompleted(scanId, layer, this.nowIso()));
    await this.auditLayer(scan, layer);

    // ⛔ Budget guard (DECIDE-4): hard-halt + partial report on exceed.
    if (await this.enforceBudget(scan, meter)) return;

    // Re-read for fresh status/gate (pause/kill/approve may have landed meanwhile).
    scan = (await this.store.scans.get(clientId, scanId)) ?? scan;
    if (this.kills.isKilled(scanId)) return;
    if (scan.status === "paused" || isTerminalStatus(scan.status)) return;

    await this.advanceAfterLayer(scan, layer);
  };

  private executeLayer(
    scan: Scan,
    job: LayerJobData,
    meter: CostMeter,
    signal: AbortSignal,
  ): Promise<LayerJobResultMap[LayerId]> {
    const runOnce = (attempt: number): Promise<LayerJobResultMap[LayerId]> => {
      const base = {
        scanId: job.scanId,
        clientId: job.clientId,
        scan,
        config: this.config,
        logger: this.logger.child({ scanId: job.scanId, layer: job.layer }),
        costMeter: meter,
        store: this.store,
        signal,
        attempt,
        priorOutputs: this.getCache(job.scanId),
        emitProgress: (phase: string, pct: number, message?: string): void => {
          this.emit(events.progress(job.scanId, job.layer, clampPct(pct), phase, this.nowIso()));
          if (message) {
            this.logger.debug("layer progress", {
              scanId: job.scanId,
              layer: job.layer,
              phase,
              message,
            });
          }
        },
      };
      switch (job.layer) {
        case "layer0":
          return this.runners.layer0({ ...base, job } satisfies LayerContext<"layer0">);
        case "layer1":
          return this.runners.layer1({ ...base, job } satisfies LayerContext<"layer1">);
        case "layer2":
          return this.runners.layer2({ ...base, job } satisfies LayerContext<"layer2">);
        case "layer3":
          return this.runners.layer3({ ...base, job } satisfies LayerContext<"layer3">);
        case "layer4":
          return this.runners.layer4({ ...base, job } satisfies LayerContext<"layer4">);
        case "layer5":
          return this.runners.layer5({ ...base, job } satisfies LayerContext<"layer5">);
        default:
          return assertNever(job);
      }
    };

    return runWithRetry(RETRY_POLICIES[job.layer], signal, runOnce, {
      sleep: this.sleep,
      onRetry: (attempt, err) =>
        this.logger.warn("layer retry", {
          scanId: job.scanId,
          layer: job.layer,
          attempt,
          code: errorCode(err),
        }),
    });
  }

  /** Decide (and persist) the next FSM transition after a layer completes. */
  private async advanceAfterLayer(scan: Scan, layer: LayerId): Promise<void> {
    const { id: scanId, clientId } = scan;

    switch (layer) {
      case "layer0": {
        // ⛔ Pre-scan estimate gate before ANY expensive Layer-1 work.
        if (estimateGateRequired(scan, this.config)) {
          scan.gateState = "estimate_pending";
          await this.store.scans.update(clientId, scan);
          this.emit(events.gateRequired(scanId, "estimate", this.nowIso()));
          await this.safeAudit({
            clientId,
            scanId,
            action: "gate.estimate_presented",
            actor: SYSTEM_ACTOR,
            summary: "Cost estimate presented; awaiting approval before Layer 1.",
            metadata: this.estimateMeta(scan),
          });
          return; // WAIT for approveGate("estimate")
        }
        scan.gateState = "estimate_approved";
        await this.store.scans.update(clientId, scan);
        await this.safeAudit({
          clientId,
          scanId,
          action: "gate.estimate_approved",
          actor: SYSTEM_ACTOR,
          summary: "Estimate approval not required by policy; proceeding to Layer 1.",
          metadata: this.estimateMeta(scan),
        });
        await this.scheduleLayer(scan, "layer1");
        return;
      }

      case "layer1":
      case "layer2":
      case "layer3": {
        const next = layerAfter(layer);
        if (next) await this.scheduleLayer(scan, next);
        return;
      }

      case "layer4": {
        // ⛔ Fix gate — an explicit STATE. Code changes require the auto-eligible
        // bar OR explicit human approval (golden rule #5).
        const fixes = await this.store.fixes.listByScan(clientId, scanId);
        const decision = evaluateFixGate(fixes, this.config);

        if (decision.wouldOpenPrs && this.config.rbac.approverRequiredForGate) {
          scan.gateState = "fix_gate_pending";
          await this.store.scans.update(clientId, scan);
          this.emit(events.gateRequired(scanId, "fix", this.nowIso()));
          this.logger.info("fix gate pending: approver required", {
            scanId,
            autoEligible: decision.autoEligibleFixIds.length,
          });
          return; // WAIT for approveGate("fix")
        }
        if (decision.wouldOpenPrs) {
          scan.gateState = "auto_approved";
          await this.store.scans.update(clientId, scan);
          await this.safeAudit({
            clientId,
            scanId,
            action: "gate.fix_approved",
            actor: SYSTEM_ACTOR,
            summary: "Auto-eligible fixes passed the bar; opening PRs.",
            metadata: { mode: "auto", autoEligibleFixIds: decision.autoEligibleFixIds },
          });
          await this.scheduleLayer(scan, "layer5", { autoApply: true });
          return;
        }
        // Report-first (auto-fix off, or nothing auto-eligible): no code change.
        scan.gateState = "auto_approved";
        await this.store.scans.update(clientId, scan);
        await this.safeAudit({
          clientId,
          scanId,
          action: "gate.fix_approved",
          actor: SYSTEM_ACTOR,
          summary: "Report-first run; fixes are recommendations, no PRs opened.",
          metadata: { mode: "report_only" },
        });
        await this.scheduleLayer(scan, "layer5", { autoApply: false });
        return;
      }

      case "layer5":
        await this.finalizeComplete(scan, false);
        return;

      default:
        assertNever(layer);
    }
  }

  private async scheduleLayer(
    scan: Scan,
    layer: LayerId,
    extra?: { autoApply?: boolean },
  ): Promise<void> {
    // Entering the working phase (post estimate gate): reflect it in gate state.
    if (layer === "layer1" && scan.gateState !== "running") {
      scan.gateState = "running";
      await this.store.scans.update(scan.clientId, scan);
    }
    const job = this.buildJob(scan, layer, extra);
    await this.scheduler.enqueue(job, RETRY_POLICIES[layer]);
  }

  private buildJob(scan: Scan, layer: LayerId, extra?: { autoApply?: boolean }): LayerJobData {
    const base = {
      scanId: scan.id,
      clientId: scan.clientId,
      layer,
      idempotencyKey: buildIdempotencyKey(scan.id, layer),
      attempt: 0,
      resumeTokenRef: scan.id,
    };
    switch (layer) {
      case "layer0":
        return Layer0JobDataSchema.parse({
          ...base,
          repo: scan.repo,
          branch: scan.branch,
          mode: scan.mode,
          scope: scan.scope,
        });
      case "layer1":
        return Layer1JobDataSchema.parse({ ...base, appMapId: scan.appMapId });
      case "layer2":
        return Layer2JobDataSchema.parse(base);
      case "layer3":
        return Layer3JobDataSchema.parse({
          ...base,
          allowLive: computeAllowLive(scan, this.config),
          stagingUrl: scan.scope.stagingUrl,
        });
      case "layer4":
        return Layer4JobDataSchema.parse(base);
      case "layer5":
        return Layer5JobDataSchema.parse({ ...base, autoApply: extra?.autoApply ?? false });
      default:
        return assertNever(layer);
    }
  }

  /* ------------------------------- outcomes ------------------------------- */

  private async finalizeComplete(scan: Scan, partial: boolean): Promise<void> {
    scan.status = partial ? "partial" : "completed";
    scan.finishedAt = this.nowIso();
    scan.costActual = this.safeActual(scan.id);
    await this.store.scans.update(scan.clientId, scan);
    this.emit(events.scanCompleted(scan.id, partial, this.nowIso()));
    await this.safeAudit({
      clientId: scan.clientId,
      scanId: scan.id,
      action: "scan.completed",
      actor: SYSTEM_ACTOR,
      summary: partial ? "Scan completed (partial report)." : "Scan completed.",
      metadata: { partial, gateState: scan.gateState },
    });
    this.cleanup(scan.id);
  }

  /** Returns true when the scan was hard-halted by the budget ceiling. */
  private async enforceBudget(scan: Scan, meter: CostMeter): Promise<boolean> {
    const policy = effectiveBudgetPolicy(scan, this.config);
    let check;
    try {
      check = meter.checkBudget(policy);
    } catch (err) {
      this.logger.error("budget check failed", { scanId: scan.id, code: errorCode(err) });
      return false;
    }
    const ceiling = policy.maxUsd;

    if (check.warn && !this.budgetWarned.has(scan.id)) {
      this.budgetWarned.add(scan.id);
      this.emit(events.budgetWarning(scan.id, check.spentUsd, ceiling, this.nowIso()));
      await this.safeAudit({
        clientId: scan.clientId,
        scanId: scan.id,
        action: "budget.warning",
        actor: SYSTEM_ACTOR,
        summary: "Budget warning threshold reached.",
        metadata: { spentUsd: check.spentUsd, ceilingUsd: ceiling },
      });
    }

    if (check.exceeded) {
      this.emit(events.budgetExceeded(scan.id, check.spentUsd, ceiling, this.nowIso()));
      await this.safeAudit({
        clientId: scan.clientId,
        scanId: scan.id,
        action: "budget.exceeded",
        actor: SYSTEM_ACTOR,
        summary: "Budget ceiling exceeded.",
        metadata: { spentUsd: check.spentUsd, ceilingUsd: ceiling },
      });
      if (policy.enforcement === "hard_halt") {
        // ⛔ Never silently burn tokens: stop now, mark blocked, emit partial report.
        scan.gateState = "blocked";
        await this.finalizeComplete(scan, true);
        return true;
      }
    }
    return false;
  }

  private async failScan(scan: Scan, layer: LayerId, err: unknown): Promise<void> {
    const envelope = toEnvelope(err);
    scan.status = "failed";
    scan.finishedAt = this.nowIso();
    scan.costActual = this.safeActual(scan.id);
    // Keep the resume checkpoint intact so resume() picks up AT the failed layer
    // and does not re-run earlier layers (§8.1).
    await this.store.scans.update(scan.clientId, scan);
    this.logger.error("layer failed", {
      scanId: scan.id,
      layer,
      code: envelope.code,
      retriable: envelope.retriable,
    });
    this.emit(events.failed(scan.id, layer, envelope, this.nowIso()));
    await this.safeAudit({
      clientId: scan.clientId,
      scanId: scan.id,
      action: "scan.failed",
      actor: SYSTEM_ACTOR,
      summary: `Layer ${layer} failed: ${envelope.code}`,
      metadata: { layer, code: envelope.code },
    });
    // The stream stays OPEN — a failed scan is resumable.
  }

  private async blockKilled(scanId: string, signal: KillSwitchSignal, at: string): Promise<void> {
    const clientId = this.resolveClientId(scanId);
    const scan = await this.store.scans.get(clientId, scanId);
    if (!scan) return;
    this.scanClient.set(scanId, scan.clientId);
    if (!isTerminalStatus(scan.status)) {
      scan.status = "cancelled";
      scan.gateState = "blocked";
      scan.finishedAt = at;
      scan.costActual = this.safeActual(scanId);
      await this.store.scans.update(scan.clientId, scan);
    }
    this.emit(events.killed(scanId, signal.reason, at));
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "dast.kill_switch",
      actor: killActor(signal),
      summary: `Kill switch halted scan: ${signal.reason}`,
      metadata: { scope: signal.scope },
    });
    await this.safeAudit({
      clientId: scan.clientId,
      scanId,
      action: "scan.cancelled",
      actor: killActor(signal),
      summary: "Scan halted by kill switch.",
      metadata: {},
    });
    this.cleanup(scanId);
  }

  private async handleRemoteKill(signal: KillSwitchSignal): Promise<void> {
    const at = this.nowIso();
    if (signal.scope === "global") {
      const ids = this.kills.activeScanIds();
      this.kills.abortAll(signal.reason);
      for (const scanId of ids) await this.blockKilled(scanId, signal, at);
      return;
    }
    if (signal.scanId) {
      this.kills.abortScan(signal.scanId, signal.reason);
      await this.blockKilled(signal.scanId, signal, at);
    }
  }

  /* -------------------------------- support ------------------------------- */

  private async advanceResumeToken(
    clientId: string,
    scanId: string,
    layer: LayerId,
  ): Promise<void> {
    const existing = await this.store.resume.get(clientId, scanId);
    const completed = new Set(existing?.completedLayers ?? []);
    completed.add(layer);
    const token = ResumeTokenSchema.parse({
      id: existing?.id,
      scanId,
      completedLayers: LAYER_ORDER.filter((l) => completed.has(l)),
      lastCompletedLayer: layer,
      checkpointRef: scanId,
      updatedAt: this.nowIso(),
    });
    await this.store.resume.save(clientId, token);
  }

  private async auditLayer(scan: Scan, layer: LayerId): Promise<void> {
    if (layer === "layer0") {
      await this.safeAudit({
        clientId: scan.clientId,
        scanId: scan.id,
        action: "appmap.built",
        actor: SYSTEM_ACTOR,
        targetType: "AppMap",
        targetId: scan.appMapId,
        summary: "App Map built and persisted.",
        metadata: {
          routeCount: scan.scope.routeCount,
          fileCount: scan.scope.fileCount,
        },
      });
    }
  }

  private emit(event: PipelineEvent): void {
    this.bus.emit(event);
  }

  private async safeAudit(input: AuditEventInput): Promise<void> {
    try {
      await this.store.audit.append(input);
    } catch (err) {
      // Audit backend hiccups must not crash a scan, but they ARE logged loudly.
      this.logger.error("audit append failed", {
        action: input.action,
        scanId: input.scanId,
        code: errorCode(err),
      });
    }
  }

  private estimateMeta(scan: Scan): Record<string, unknown> {
    return {
      projectedUsd: scan.costEstimate?.projectedUsd,
      projectedTotalTokens: scan.costEstimate?.projectedTotalTokens,
    };
  }

  private getMeter(scanId: string): CostMeter {
    let meter = this.meters.get(scanId);
    if (!meter) {
      meter = this.createCostMeter(scanId);
      this.meters.set(scanId, meter);
    }
    return meter;
  }

  private getCache(scanId: string): PriorOutputs {
    let cache = this.caches.get(scanId);
    if (!cache) {
      cache = {};
      this.caches.set(scanId, cache);
    }
    return cache;
  }

  private safeActual(scanId: string): CostActual | undefined {
    const meter = this.meters.get(scanId);
    if (!meter) return undefined;
    try {
      return meter.actual();
    } catch (err) {
      this.logger.warn("cost actual unavailable", { scanId, code: errorCode(err) });
      return undefined;
    }
  }

  private cleanup(scanId: string): void {
    this.meters.delete(scanId);
    this.caches.delete(scanId);
    this.budgetWarned.delete(scanId);
    this.budgetRegistry?.unregister(scanId);
    this.kills.clear(scanId);
    this.bus.end(scanId);
  }

  private resolveClientId(scanId: string): string {
    return this.scanClient.get(scanId) ?? this.config.clientId;
  }

  private async load(scanId: string): Promise<Scan> {
    const clientId = this.resolveClientId(scanId);
    const scan = await this.store.scans.get(clientId, scanId);
    if (!scan) throw new MontrError("INTERNAL", `scan not found: ${scanId}`);
    this.scanClient.set(scanId, scan.clientId);
    return scan;
  }

  private async ensureSchedulerStarted(): Promise<void> {
    if (this.schedulerStarted) return;
    this.schedulerStarted = true;
    await this.scheduler.start();
  }

  private nowIso(): string {
    return this.clock().toISOString();
  }
}

/** Construct the orchestrator (defaults to the in-process inline scheduler). */
export function createOrchestrator(deps: OrchestratorDeps): Orchestrator {
  return new OrchestratorController(deps);
}
