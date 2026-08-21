/**
 * Durable scheduler backed by BullMQ (one queue+worker per layer) over ioredis,
 * plus a Redis pub/sub channel for the ⛔ kill switch so a kill in one process
 * halts workers everywhere.
 *
 * bullmq/ioredis are imported LAZILY (dynamic import) behind a `BullMqTransport`
 * seam. That keeps them out of the module graph for offline inline tests, and
 * lets tests inject a fake transport to exercise this scheduler without Redis.
 * (bullmq/ioredis are queue infra, NOT LLM provider SDKs — golden rule #2 is
 * about provider SDKs and is not implicated here.)
 */
import {
  KILL_SWITCH_CHANNEL,
  KillSwitchSignalSchema,
  LayerJobDataSchema,
  QUEUE_NAMES,
  type KillSwitchSignal,
  type LayerJobData,
  type QueueName,
  type RetryPolicy,
} from "@montr/contracts";
import { LAYER_ORDER } from "./fsm.js";
import type { JobProcessor, JobScheduler } from "./scheduler.js";

/* --------------------------------- seam --------------------------------- */

export interface QueueHandle {
  add(name: string, data: LayerJobData, opts: JobEnqueueOptions): Promise<void>;
  close(): Promise<void>;
}

export interface WorkerHandle {
  close(): Promise<void>;
}

export interface KillChannel {
  subscribe(handler: (signal: KillSwitchSignal) => void): void;
  publish(signal: KillSwitchSignal): Promise<void>;
  close(): Promise<void>;
}

export interface JobEnqueueOptions {
  jobId: string;
  attempts: number;
  backoff: RetryPolicy["backoff"];
  removeOnComplete?: boolean | number;
  removeOnFail?: boolean | number;
}

/** Everything the scheduler needs from BullMQ/Redis, so it can be faked in tests. */
export interface BullMqTransport {
  createQueue(name: QueueName): QueueHandle;
  createWorker(name: QueueName, processor: JobProcessor): WorkerHandle;
  killChannel(): KillChannel;
  close(): Promise<void>;
}

/* ------------------------------- scheduler ------------------------------- */

export class BullMqJobScheduler implements JobScheduler {
  private processor?: JobProcessor;
  private readonly queues = new Map<QueueName, QueueHandle>();
  private readonly workers: WorkerHandle[] = [];
  private channel?: KillChannel;
  private killHandler?: (signal: KillSwitchSignal) => void;

  constructor(private readonly transport: BullMqTransport) {}

  setProcessor(processor: JobProcessor): void {
    this.processor = processor;
  }

  async start(): Promise<void> {
    if (!this.processor) throw new Error("BullMqJobScheduler.start(): processor not set");
    for (const layer of LAYER_ORDER) {
      const name = QUEUE_NAMES[layer];
      this.queues.set(name, this.transport.createQueue(name));
    }
    for (const layer of LAYER_ORDER) {
      this.workers.push(this.transport.createWorker(QUEUE_NAMES[layer], this.processor));
    }
    this.channel = this.transport.killChannel();
    this.channel.subscribe((signal) => this.killHandler?.(signal));
    await Promise.resolve();
  }

  async enqueue(job: LayerJobData, policy: RetryPolicy): Promise<void> {
    const queue = this.queues.get(QUEUE_NAMES[job.layer]);
    if (!queue) throw new Error(`BullMqJobScheduler: no queue for layer ${job.layer}`);
    // Retry is centralized in the controller, so BullMQ delivers each job once
    // (attempts: 1); the idempotencyKey is the jobId so replays dedupe.
    await queue.add(job.layer, job, {
      jobId: job.idempotencyKey,
      attempts: 1,
      backoff: policy.backoff,
      removeOnComplete: policy.removeOnComplete,
      removeOnFail: policy.removeOnFail,
    });
  }

  onKill(handler: (signal: KillSwitchSignal) => void): void {
    this.killHandler = handler;
  }

  async publishKill(signal: KillSwitchSignal): Promise<void> {
    await this.channel?.publish(signal);
  }

  async close(): Promise<void> {
    for (const worker of this.workers) await worker.close();
    for (const queue of this.queues.values()) await queue.close();
    await this.channel?.close();
    await this.transport.close();
  }
}

/* --------------------------- real transport ----------------------------- */

/** ioredis connection: a URL string or an options object. */
export type RedisConnection = string | Record<string, unknown>;

interface RedisConn {
  publish(channel: string, message: string): Promise<number>;
  subscribe(channel: string): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  duplicate(): RedisConn;
  quit(): Promise<unknown>;
}
type RedisCtor = new (arg1: RedisConnection, arg2?: Record<string, unknown>) => RedisConn;

interface BullJob {
  data: unknown;
}
interface BullQueue {
  add(name: string, data: unknown, opts?: Record<string, unknown>): Promise<unknown>;
  close(): Promise<void>;
}
type BullQueueCtor = new (name: string, opts: Record<string, unknown>) => BullQueue;
interface BullWorker {
  close(): Promise<void>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
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

/**
 * Build the real BullMQ/ioredis transport. Lazily imports the packages so they
 * never load during offline inline tests. Call from apps/worker.
 */
export async function createRealBullMqTransport(
  connection: RedisConnection,
): Promise<BullMqTransport> {
  const bullmq = (await import("bullmq")) as unknown as BullMqModule;
  const ioredis = (await import("ioredis")) as unknown as { default: RedisCtor };
  const Redis = ioredis.default;

  const connect = (): RedisConn =>
    typeof connection === "string"
      ? new Redis(connection, { maxRetriesPerRequest: null })
      : new Redis({ ...connection, maxRetriesPerRequest: null });

  const sharedConnection = connect();
  const openConnections: RedisConn[] = [sharedConnection];

  return {
    createQueue(name: QueueName): QueueHandle {
      const queue = new bullmq.Queue(name, { connection: sharedConnection });
      return {
        async add(jobName, data, opts): Promise<void> {
          await queue.add(jobName, data, {
            jobId: opts.jobId,
            attempts: opts.attempts,
            backoff: opts.backoff,
            removeOnComplete: opts.removeOnComplete,
            removeOnFail: opts.removeOnFail,
          });
        },
        close: () => queue.close(),
      };
    },

    createWorker(name: QueueName, processor: JobProcessor): WorkerHandle {
      // Each worker gets its own blocking connection (BullMQ requirement).
      const workerConnection = connect();
      openConnections.push(workerConnection);
      const worker = new bullmq.Worker(
        name,
        async (job: BullJob) => {
          const data = LayerJobDataSchema.parse(job.data);
          await processor(data);
        },
        {
          connection: workerConnection,
          // A3 (§8.1): BullMQ's defaults (lockDuration 30s, stalledInterval 30s,
          // maxStalledCount 1) are tuned for short jobs. A layer job can run for
          // minutes — Layer 1 shells out to Semgrep/gitleaks across a whole repo,
          // Layer 0/1's AST/tree-sitter parsing is synchronous CPU work that can
          // block the event loop for tens of seconds on a large repo, and every
          // layer makes a network LLM call with its own retry/backoff. BullMQ
          // auto-renews the lock at lockDuration/2 as long as the event loop gets
          // a turn, so the real risk with the 30s default is a legitimately-busy
          // layer missing a renewal window and being marked stalled + redelivered
          // mid-flight (duplicate work; only saved from data loss by
          // idempotencyKey dedup + FindingRepo.bulkCreate's skipDuplicates).
          // lockDuration=10m gives a long CPU-bound layer plenty of headroom;
          // stalledInterval stays at the BullMQ default (check every 30s) so a
          // TRULY crashed worker (lock never renewed at all) is still detected
          // reasonably quickly; maxStalledCount=1 (also the default, set
          // explicitly for intent) allows exactly one stall-triggered redelivery
          // before BullMQ gives up and marks the job failed — at which point
          // apps/worker's boot-time reconciliation (main.ts) is the backstop that
          // resumes the scan from its last persisted checkpoint.
          lockDuration: 10 * 60 * 1000,
          stalledInterval: 30 * 1000,
          maxStalledCount: 1,
        },
      );
      return { close: () => worker.close() };
    },

    killChannel(): KillChannel {
      const subscriber = sharedConnection.duplicate();
      const publisher = sharedConnection.duplicate();
      openConnections.push(subscriber, publisher);
      return {
        subscribe(handler): void {
          void subscriber.subscribe(KILL_SWITCH_CHANNEL);
          subscriber.on("message", (...args: unknown[]) => {
            const [channel, message] = args as [string, string];
            if (channel !== KILL_SWITCH_CHANNEL) return;
            const parsed = KillSwitchSignalSchema.safeParse(JSON.parse(message));
            if (parsed.success) handler(parsed.data);
          });
        },
        async publish(signal): Promise<void> {
          await publisher.publish(KILL_SWITCH_CHANNEL, JSON.stringify(signal));
        },
        async close(): Promise<void> {
          await subscriber.quit();
          await publisher.quit();
        },
      };
    },

    async close(): Promise<void> {
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

/** Convenience: a BullMQ scheduler wired to the real transport (apps/worker). */
export async function createBullMqScheduler(
  connection: RedisConnection,
): Promise<BullMqJobScheduler> {
  const transport = await createRealBullMqTransport(connection);
  return new BullMqJobScheduler(transport);
}
