/**
 * apps/worker — real red-team scenario execution (A1, 2026-09-12 red/blue
 * agentic-posture audit) public surface. See service.ts's header for the full
 * gate order and safety invariants.
 */
import type { RedisConnection } from "@montr/orchestrator";
import type { MontrConfig } from "@montr/config";
import type { Logger } from "@montr/telemetry";
import {
  createScenarioRunWorker,
  type ScenarioRunStore,
  type ScenarioRunWorker,
} from "./service.js";
import { createBullMqScenarioRunConsumerTransport } from "./bullmq-transport.js";

export {
  processScenarioRunJob,
  createScenarioRunWorker,
  type ScenarioRunOutcome,
  type ScenarioRunStore,
  type ScenarioRunServiceDeps,
  type ScenarioRunConsumerTransport,
  type ScenarioRunWorker,
} from "./service.js";
export { createBullMqScenarioRunConsumerTransport } from "./bullmq-transport.js";

export interface StartScenarioRunWorkerDeps {
  store: ScenarioRunStore;
  config: MontrConfig;
  /** ioredis connection shared with the durable worker. */
  redis: RedisConnection;
  logger?: Logger;
}

/**
 * Production wiring: build the real BullMQ consumer transport + core worker,
 * then start consuming enqueued scenario-run jobs. Call from
 * apps/worker/src/index.ts's `startWorker` alongside the per-layer scheduler.
 */
export async function startScenarioRunWorker(
  deps: StartScenarioRunWorkerDeps,
): Promise<ScenarioRunWorker> {
  const transport = await createBullMqScenarioRunConsumerTransport(deps.redis);
  const worker = createScenarioRunWorker({
    store: deps.store,
    config: deps.config,
    ...(deps.logger ? { logger: deps.logger } : {}),
    transport,
  });
  await worker.start();
  return worker;
}
