/**
 * apps/worker — scheduled scans (cron) public surface. Wires the BullMQ transport
 * to the core scheduler. See scan-scheduler.ts for the ⛔ safety invariants
 * (hard budget ceiling + human gate preserved on every scheduled run).
 */
import type { RedisConnection } from "@montr/orchestrator";
import type { Logger } from "@montr/telemetry";
import {
  createScanScheduleService,
  type ScanScheduleService,
  type SchedulerOrchestrator,
  type SchedulerStore,
} from "./scan-scheduler.js";
import { createBullMqScanTransport } from "./bullmq-transport.js";

export {
  createScanScheduleService,
  scheduledBudgetPolicy,
  SCHEDULER_ACTOR,
  type RepeatableScanTransport,
  type ScanScheduleJob,
  type ScanScheduleService,
  type ScanScheduleServiceDeps,
  type SchedulerOrchestrator,
  type SchedulerStore,
  type ScheduledJobInfo,
} from "./scan-scheduler.js";
export { createBullMqScanTransport } from "./bullmq-transport.js";

export interface StartScanSchedulerDeps {
  /** This deployment's client (per-client isolation). */
  clientId: string;
  store: SchedulerStore;
  orchestrator: SchedulerOrchestrator;
  /** ioredis connection shared with the durable worker (URL string or options). */
  redis: RedisConnection;
  logger?: Logger;
}

/**
 * Production wiring: build the BullMQ transport + core scheduler, then start
 * consuming fired jobs + reconciling the store's enabled schedules. Call from the
 * worker composition root after the orchestrator is online. The returned handle's
 * `stop()` releases the transport.
 */
export async function startScanScheduler(
  deps: StartScanSchedulerDeps,
): Promise<ScanScheduleService> {
  const transport = await createBullMqScanTransport(deps.redis);
  const service = createScanScheduleService({
    clientId: deps.clientId,
    store: deps.store,
    orchestrator: deps.orchestrator,
    transport,
    ...(deps.logger ? { logger: deps.logger } : {}),
  });
  await service.start();
  return service;
}
