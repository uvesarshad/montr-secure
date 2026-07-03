/**
 * apps/worker — production {@link RepeatableScanTransport} backed by BullMQ
 * repeatable/cron jobs over ioredis (build-plan §8, "scheduled scans (cron)").
 *
 * bullmq/ioredis are loaded LAZILY via a runtime-computed specifier so they stay
 * OUT of this package's typecheck + offline-test module graph: they are NOT a
 * build-time dependency of apps/worker (the core scheduler is exercised with a
 * fake transport), but they ARE runtime dependencies in production. This mirrors
 * @montr/orchestrator's lazy BullMQ transport (queue infra, not an LLM provider
 * SDK — golden rule #2 is not implicated).
 */
import type { RedisConnection } from "@montr/orchestrator";
import type {
  RepeatableScanTransport,
  ScanScheduleJob,
  ScheduledJobInfo,
} from "./scan-scheduler.js";

/** Dedicated queue for cron-scheduled scans (separate from the per-layer queues). */
const QUEUE_NAME = "montr:scan-schedules";
/** Job name every schedule occurrence carries. */
const JOB_NAME = "scheduled-scan";

/* -------- minimal structural views of the bits of bullmq/ioredis we use -------- */

interface JobSchedulerJson {
  key?: string;
  id?: string;
  name?: string;
  next?: number | null;
}
interface BullQueue {
  upsertJobScheduler(
    schedulerId: string,
    repeat: Record<string, unknown>,
    template?: Record<string, unknown>,
  ): Promise<unknown>;
  removeJobScheduler(schedulerId: string): Promise<unknown>;
  getJobSchedulers(): Promise<JobSchedulerJson[]>;
  close(): Promise<void>;
}
type BullQueueCtor = new (name: string, opts: Record<string, unknown>) => BullQueue;
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
  Queue: BullQueueCtor;
  Worker: BullWorkerCtor;
}
interface RedisConn {
  quit(): Promise<unknown>;
}
type RedisCtor = new (arg1: RedisConnection, arg2?: Record<string, unknown>) => RedisConn;

/**
 * Load bullmq/ioredis at RUNTIME only. The specifiers are computed so `tsc` does
 * not resolve them at build time (they are production-only deps of apps/worker).
 */
async function loadDeps(): Promise<{ bullmq: BullMqModule; Redis: RedisCtor }> {
  const bullmqSpec = ["bull", "mq"].join("");
  const ioredisSpec = ["io", "redis"].join("");
  const bullmq = (await import(bullmqSpec)) as unknown as BullMqModule;
  const ioredis = (await import(ioredisSpec)) as unknown as { default: RedisCtor };
  return { bullmq, Redis: ioredis.default };
}

/**
 * Build the real BullMQ transport for scheduled scans. Call from the worker
 * composition root (see `startScanScheduler`).
 */
export async function createBullMqScanTransport(
  connection: RedisConnection,
): Promise<RepeatableScanTransport> {
  const { bullmq, Redis } = await loadDeps();
  const connect = (): RedisConn =>
    typeof connection === "string"
      ? new Redis(connection, { maxRetriesPerRequest: null })
      : new Redis({ ...connection, maxRetriesPerRequest: null });

  const queueConnection = connect();
  const queue = new bullmq.Queue(QUEUE_NAME, { connection: queueConnection });
  const openConnections: RedisConn[] = [queueConnection];
  let worker: BullWorker | undefined;

  return {
    async schedule(job: ScanScheduleJob, cron: string): Promise<void> {
      // Keyed by scheduleId so re-registering a changed cron replaces cleanly.
      await queue.upsertJobScheduler(
        job.scheduleId,
        { pattern: cron },
        { name: JOB_NAME, data: job },
      );
    },

    async unschedule(scheduleId: string): Promise<void> {
      await queue.removeJobScheduler(scheduleId);
    },

    async listScheduled(): Promise<ScheduledJobInfo[]> {
      const rows = await queue.getJobSchedulers();
      return rows.map((r) => ({ scheduleId: r.key ?? r.id ?? "", nextMs: r.next ?? null }));
    },

    async consume(handler: (job: ScanScheduleJob) => Promise<void>): Promise<void> {
      if (worker) return; // idempotent — one worker per transport.
      const workerConnection = connect();
      openConnections.push(workerConnection);
      worker = new bullmq.Worker(
        QUEUE_NAME,
        async (job: BullJob) => {
          await handler(job.data as ScanScheduleJob);
        },
        { connection: workerConnection },
      );
    },

    async close(): Promise<void> {
      await worker?.close();
      await queue.close();
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
