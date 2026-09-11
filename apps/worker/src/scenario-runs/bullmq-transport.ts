/**
 * apps/worker — production {@link ScenarioRunConsumerTransport} backed by
 * BullMQ over ioredis, consuming `SCENARIO_RUN_QUEUE_NAME`
 * (packages/contracts/src/queue.ts) — a dedicated, non-pipeline queue
 * apps/api's produce-only `apps/api/src/scenario-run-producer.ts` enqueues
 * into (see that file's header for why this is NOT the per-layer FSM queue).
 *
 * bullmq/ioredis are loaded LAZILY (mirrors apps/worker/src/scheduling/
 * bullmq-transport.ts's identical convention) so they stay OUT of this
 * package's offline/typecheck module graph — runtime-only production deps.
 */
import type { RedisConnection } from "@montr/orchestrator";
import {
  SCENARIO_RUN_QUEUE_NAME,
  ScenarioRunJobSchema,
  type ScenarioRunJob,
} from "@montr/contracts";
import type { ScenarioRunConsumerTransport } from "./service.js";

/* -------- minimal structural view of the bits of bullmq/ioredis we use -------- */

interface BullJob {
  data: unknown;
}
interface BullWorker {
  close(): Promise<void>;
}
type BullWorkerCtor = new (
  name: string,
  processor: (job: BullJob) => Promise<void>,
  opts: Record<string, unknown>,
) => BullWorker;
interface BullMqModule {
  Worker: BullWorkerCtor;
}
interface RedisConn {
  quit(): Promise<unknown>;
}
type RedisCtor = new (arg1: RedisConnection, arg2?: Record<string, unknown>) => RedisConn;

async function loadDeps(): Promise<{ bullmq: BullMqModule; Redis: RedisCtor }> {
  const bullmqSpec = ["bull", "mq"].join("");
  const ioredisSpec = ["io", "redis"].join("");
  const bullmq = (await import(bullmqSpec)) as unknown as BullMqModule;
  const ioredis = (await import(ioredisSpec)) as unknown as { default: RedisCtor };
  return { bullmq, Redis: ioredis.default };
}

/**
 * Build the real BullMQ consumer transport for scenario-run jobs. Call from
 * the worker composition root (apps/worker/src/index.ts's `startWorker`).
 */
export async function createBullMqScenarioRunConsumerTransport(
  connection: RedisConnection,
): Promise<ScenarioRunConsumerTransport> {
  const { bullmq, Redis } = await loadDeps();
  const openConnections: RedisConn[] = [];
  let worker: BullWorker | undefined;

  return {
    async consume(handler: (job: ScenarioRunJob) => Promise<void>): Promise<void> {
      if (worker) return; // idempotent — one worker per transport.
      const workerConnection: RedisConn =
        typeof connection === "string"
          ? new Redis(connection, { maxRetriesPerRequest: null })
          : new Redis({ ...connection, maxRetriesPerRequest: null });
      openConnections.push(workerConnection);
      worker = new bullmq.Worker(
        SCENARIO_RUN_QUEUE_NAME,
        async (job: BullJob) => {
          // Re-validate the payload shape defensively — never trust a raw
          // Redis-sourced object as-is, even though the producer only ever
          // enqueues a validated ScenarioRunJob.
          const data = ScenarioRunJobSchema.parse(job.data);
          await handler(data);
        },
        { connection: workerConnection },
      );
    },

    async close(): Promise<void> {
      await worker?.close();
      for (const conn of openConnections) {
        try {
          await conn.quit();
        } catch {
          // best-effort teardown
        }
      }
    },
  };
}
