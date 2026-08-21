/**
 * @montr/orchestrator — pipeline FSM, BullMQ workers, explicit gate STATE, kill
 * switch, and resumability (§8.1, build-plan §4.3).
 *
 * The pipeline runs L0→L1→L2→L3→L4→L5 as a state machine whose states are
 * PERSISTED (Scan.status + Scan.gateState + the ResumeToken checkpoint), so runs
 * are idempotent and RESUMABLE — kill after L2, resume, and L0–L2 are not
 * re-run. Layers are invoked ONLY through the orchestrator, via the
 * @montr/contracts layer I/O types (golden rule #10). The gate is a real
 * pipeline STATE, never a config flag (golden rule #5). A kill switch halts all
 * active work immediately, especially live DAST probing (§11).
 *
 * Two schedulers share the same FSM: an in-process `InlineJobScheduler` (default,
 * no Redis — powers offline tests) and a durable `BullMqJobScheduler`
 * (BullMQ + ioredis) for apps/worker.
 */
export {
  createOrchestrator,
  type Orchestrator,
  type OrchestratorDeps,
  type CreateScanInput,
} from "./controller.js";

export { EventBus, events, type EventSink, type Now } from "./events.js";

export { KillRegistry } from "./kill-switch.js";

export { runWithRetry, realSleep, type SleepFn, type RunWithRetryOptions } from "./retry.js";

export type { LayerContext, LayerRunner, LayerRunners, PriorOutputs } from "./runner.js";

export { persistLayerOutput } from "./persist.js";

export { InlineJobScheduler, type JobScheduler, type JobProcessor } from "./scheduler.js";

export {
  BullMqJobScheduler,
  createBullMqScheduler,
  createRealBullMqTransport,
  deriveTenantSchedulerOptions,
  type BullMqTransport,
  type BullMqSchedulerOptions,
  type QueueHandle,
  type WorkerHandle,
  type KillChannel,
  type JobEnqueueOptions,
  type RedisConnection,
} from "./bullmq-scheduler.js";

export {
  LAYER_ORDER,
  nextLayer,
  layerAfter,
  isTerminalStatus,
  effectiveBudgetPolicy,
  estimateGateRequired,
  evaluateFixGate,
  computeAllowLive,
  type FixGateDecision,
} from "./fsm.js";
