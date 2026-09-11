/**
 * apps/worker — BullMQ worker host that runs the orchestrator + layer agents
 * (build-plan §8.1, Wave-2 carry-over 6–8).
 *
 * The worker is the process that actually reaches the LLM (via
 * @montr/llm-gateway), so the ⛔ egress boot guard (golden rule #1) is asserted
 * FIRST, before any work is scheduled. It then brings up the durable BullMQ
 * scheduler (one queue+worker per layer over ioredis) and an orchestrator that
 * consumes per-layer jobs, runs the REAL layer runners, reports progress /
 * lifecycle events, and honors the kill-switch + resume-token + retry contracts
 * from @montr/contracts (all implemented inside @montr/orchestrator; this app
 * wires the runners and the transport).
 *
 * For offline CI/E2E without Redis, use the in-process driver (`runScanInProcess`
 * / `createInProcessOrchestrator`) exported below.
 */
import { MontrError } from "@montr/contracts";
import type { LLMGateway } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { assertStartupEgress } from "@montr/security";
import { createLogger, type Logger } from "@montr/telemetry";
import {
  createBullMqScheduler,
  createOrchestrator,
  deriveTenantSchedulerOptions,
  EventBus,
  type BullMqJobScheduler,
  type LayerRunners,
  type Orchestrator,
  type RedisConnection,
} from "@montr/orchestrator";
import { createCostMeter, type BudgetRegistry, type CostMeter } from "@montr/cost-meter";
import type { StateStore } from "@montr/state-store";

import { createLayerRunners, type LayerRunnerOptions } from "./runners.js";
// A1 (2026-09-12) — real worker-side red-team scenario execution, gated
// behind written authorization (see ./scenario-runs/service.ts's header).
import { startScenarioRunWorker, type ScenarioRunWorker } from "./scenario-runs/index.js";
export {
  processScenarioRunJob,
  createScenarioRunWorker,
  startScenarioRunWorker,
  type ScenarioRunOutcome,
  type ScenarioRunStore,
  type ScenarioRunServiceDeps,
  type ScenarioRunConsumerTransport,
  type ScenarioRunWorker,
  type StartScenarioRunWorkerDeps,
} from "./scenario-runs/index.js";

export { createLayerRunners, type LayerRunnerOptions } from "./runners.js";
// A3 (§8.1) — boot-time reconciliation for scans a crashed worker parked as
// `running` forever. Exported so apps/worker/src/main.ts can wire it in and so
// it's independently unit-testable without a real Postgres/Redis boot.
export {
  reconcileStuckScans,
  DEFAULT_STUCK_SCAN_THRESHOLD_MS,
  type ReconcileDeps,
  type ReconcileResult,
} from "./reconcile.js";
export {
  createInProcessOrchestrator,
  runScanInProcess,
  type InProcessPipelineDeps,
  type RunScanOptions,
} from "./pipeline.js";
// Phase-4 (Wave 5) — cron-scheduled scans (BullMQ repeatable jobs). Additive; the
// core scheduler runs the SAME pipeline + gate + hard budget ceiling as a manual
// scan (see ./scheduling/scan-scheduler.ts for the ⛔ safety invariants).
export {
  startScanScheduler,
  createScanScheduleService,
  createBullMqScanTransport,
  scheduledBudgetPolicy,
  SCHEDULER_ACTOR,
  type ScanScheduleService,
  type StartScanSchedulerDeps,
  type RepeatableScanTransport,
  type ScanScheduleJob,
  type ScheduledJobInfo,
} from "./scheduling/index.js";

/** Runtime collaborators the durable worker needs (the composition root wires these). */
export interface WorkerRuntimeDeps {
  /** Per-client persistence (Prisma/Postgres in prod; an in-memory store in tests). */
  store: StateStore;
  /** ⛔ BYO-key LLM gateway — the single egress path (golden rule #2). */
  gateway: LLMGateway;
  /** ioredis connection (URL string or options) for the BullMQ queues + kill channel. */
  redis: RedisConnection;
  logger?: Logger;
  /** Per-scan cost meter factory. Default: `@montr/cost-meter`'s live meter. */
  createCostMeter?: (scanId: string) => CostMeter;
  /**
   * ⛔ PRE-call budget guard (A2, DECIDE-4). Pass the SAME instance given to
   * `createLlmGateway({ budgetRegistry })` when constructing `gateway` — the
   * orchestrator registers each running scan's meter + policy here, and the
   * gateway reads it back to refuse a single over-budget call before dispatch.
   * Omit to leave today's between-layers-only enforcement unchanged.
   */
  budgetRegistry?: BudgetRegistry;
  /** Layer-runner seams (opener, source reader, semgrep/gitleaks, workspaceRoot…). */
  runnerOptions?: Partial<Omit<LayerRunnerOptions, "gateway">>;
  /** Fully override the layer runners (tests). */
  layerRunners?: LayerRunners;
  /** Shared event bus (e.g. so apps/api subscribes to the same stream). */
  eventBus?: EventBus;
}

export interface Worker {
  /** Bring the BullMQ queues + per-layer workers online and start consuming. */
  start(): Promise<void>;
  /** Drain and release all queues/connections. */
  stop(): Promise<void>;
  /** The orchestrator this worker drives (also exposed so a co-located API can create scans). Throws before {@link start}. */
  readonly orchestrator: Orchestrator;
}

/**
 * Construct the durable worker. Validates the egress policy at boot (throws on a
 * non-default-deny policy or an unreachable LLM endpoint), then returns a handle
 * whose {@link Worker.start} wires the BullMQ scheduler + orchestrator and begins
 * consuming jobs. Constructing the worker does NOT connect to Redis — `start`
 * does — so the boot guard runs even in environments where Redis is absent.
 */
export function startWorker(config: MontrConfig, deps: WorkerRuntimeDeps): Worker {
  const logger =
    deps.logger ?? createLogger({ name: "montr-worker", bindings: { clientId: config.clientId } });

  // ⛔ Golden rule #1: compile + validate the default-deny egress policy at boot.
  // Throws on a non-default-deny policy or an unreachable LLM endpoint. DAST
  // staging targets are included so live-probe egress (when enabled) is scoped
  // to the same allowlist. The gateway re-asserts per outbound call.
  assertStartupEgress(config, {
    includeDastTargets: true,
    onWarning: (message) => logger.warn("egress.warning", { message }),
  });

  let scheduler: BullMqJobScheduler | undefined;
  let orchestrator: Orchestrator | undefined;
  let scenarioRunWorker: ScenarioRunWorker | undefined;
  let started = false;

  return {
    get orchestrator(): Orchestrator {
      if (!orchestrator) {
        throw new MontrError(
          "INTERNAL",
          "worker not started — call start() before using the orchestrator",
        );
      }
      return orchestrator;
    },

    async start(): Promise<void> {
      if (started) return;
      const layerRunners =
        deps.layerRunners ??
        createLayerRunners({ gateway: deps.gateway, ...(deps.runnerOptions ?? {}) });

      // Durable BullMQ scheduler (one queue+worker per layer + a Redis kill
      // channel; A27 tenant options are OFF by default — see
      // deriveTenantSchedulerOptions's doc comment — so this is unchanged
      // unless config.queue.perTenantIsolation is explicitly set).
      const tenantOptions = deriveTenantSchedulerOptions(config);
      scheduler = await createBullMqScheduler(deps.redis, tenantOptions);
      // The orchestrator binds its processor onto the scheduler in its constructor,
      // so it MUST be created before we start the scheduler's workers.
      orchestrator = createOrchestrator({
        config,
        store: deps.store,
        logger,
        createCostMeter: deps.createCostMeter ?? ((scanId) => createCostMeter(scanId)),
        layerRunners,
        scheduler,
        ...(deps.eventBus ? { eventBus: deps.eventBus } : {}),
        ...(deps.budgetRegistry ? { budgetRegistry: deps.budgetRegistry } : {}),
      });
      // Bring the per-layer BullMQ workers online — the processing loop begins here.
      await scheduler.start();
      // A1 — the dedicated, non-pipeline scenario-run consumer (separate
      // queue from the per-layer scheduler above; see packages/contracts/src/
      // queue.ts's SCENARIO_RUN_QUEUE_NAME doc comment for why). Real
      // execution stays gated behind written authorization regardless of
      // whether this consumer is running — starting it does not, by itself,
      // loosen any safety gate.
      scenarioRunWorker = await startScenarioRunWorker({
        store: deps.store,
        config,
        redis: deps.redis,
        logger,
      });
      started = true;
      const queues = tenantOptions.tenantIsolation ? 6 * (tenantOptions.tenantIds?.length ?? 0) : 6;
      logger.info("worker.started", { queues, tenantIsolation: tenantOptions.tenantIsolation });
    },

    async stop(): Promise<void> {
      if (!started) return;
      // Orchestrator.close() tears down the scheduler (workers + queues + kill channel).
      await orchestrator?.close();
      await scenarioRunWorker?.stop();
      started = false;
      logger.info("worker.stopped");
    },
  };
}
