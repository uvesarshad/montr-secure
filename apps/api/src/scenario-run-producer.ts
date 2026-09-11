/**
 * A1 (2026-09-12 red/blue agentic-posture audit) — produce-only BullMQ
 * enqueue for real worker-side red-team scenario execution.
 *
 * Mirrors `apps/api/src/enqueue-scheduler.ts`'s produce-only role (apps/api
 * pushes real jobs to Redis for apps/worker to execute; it never becomes a
 * consumer) but targets the dedicated `SCENARIO_RUN_QUEUE_NAME` queue
 * (packages/contracts/src/queue.ts) rather than the per-layer FSM queues — a
 * scenario run is a standalone, on-demand action, not a pipeline layer.
 *
 * bullmq/ioredis are imported LAZILY so they stay out of this package's
 * offline/typecheck module graph (mirrors
 * apps/worker/src/scheduling/bullmq-transport.ts's identical lazy-load
 * convention) — they are runtime-only dependencies of the production process.
 */
import type { RedisConnection } from "@montr/orchestrator";
import {
  SCENARIO_RUN_JOB_NAME,
  SCENARIO_RUN_QUEUE_NAME,
  type ScenarioRunJob,
} from "@montr/contracts";

/** Produce-only seam: enqueue a scenario-run job for apps/worker to consume. */
export interface ScenarioRunProducer {
  /** Enqueue one run. Returns the BullMQ job id (audit trail only). */
  enqueue(job: ScenarioRunJob): Promise<string>;
  close(): Promise<void>;
}

/* -------- minimal structural view of the bits of bullmq/ioredis we use -------- */

interface BullQueue {
  add(name: string, data: unknown, opts: Record<string, unknown>): Promise<{ id?: string }>;
  close(): Promise<void>;
}
type BullQueueCtor = new (name: string, opts: Record<string, unknown>) => BullQueue;
interface BullMqModule {
  Queue: BullQueueCtor;
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

/** Build the real BullMQ-backed producer. Call once from production-deps.ts. */
export async function createBullMqScenarioRunProducer(
  connection: RedisConnection,
): Promise<ScenarioRunProducer> {
  const { bullmq, Redis } = await loadDeps();
  const conn =
    typeof connection === "string"
      ? new Redis(connection, { maxRetriesPerRequest: null })
      : new Redis({ ...connection, maxRetriesPerRequest: null });
  const queue = new bullmq.Queue(SCENARIO_RUN_QUEUE_NAME, { connection: conn });

  return {
    async enqueue(job: ScenarioRunJob): Promise<string> {
      // Idempotency key: one authorized run request per (scenario, requestedAt)
      // — a genuine double-submit (same approver double-clicking) dedupes;
      // distinct requests always carry a distinct timestamp.
      const jobId = `${job.scenarioId}:${job.requestedAt}`;
      const added = await queue.add(SCENARIO_RUN_JOB_NAME, job, {
        jobId,
        attempts: 1,
        removeOnComplete: 100,
        removeOnFail: 100,
      });
      return added.id ?? jobId;
    },
    async close(): Promise<void> {
      await queue.close();
      try {
        await conn.quit();
      } catch {
        // best-effort teardown
      }
    },
  };
}

/**
 * In-memory fake — the default for dev/tests (mirrors `noopRegressionCorpus`'s
 * fail-safe-default precedent, `apps/api/src/fp-corpus.ts`). Enqueued jobs are
 * recorded on `.jobs` for test assertions; nothing consumes them without a
 * real worker wired to the same Redis queue, so this is inert (not a security
 * concern) — production always injects `createBullMqScenarioRunProducer`.
 */
export function createInMemoryScenarioRunProducer(): ScenarioRunProducer & {
  readonly jobs: ScenarioRunJob[];
} {
  const jobs: ScenarioRunJob[] = [];
  let counter = 0;
  return {
    jobs,
    async enqueue(job: ScenarioRunJob): Promise<string> {
      jobs.push(job);
      counter += 1;
      return `inmemory_${counter}`;
    },
    async close(): Promise<void> {
      // nothing to release
    },
  };
}
