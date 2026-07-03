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

  /**
   * @param consume when false, {@link start} sets up the queues + kill channel for
   *   ENQUEUEING and kill propagation but does NOT bring up per-layer workers. This
   *   is the producer role used by apps/api: it creates + starts + kills scans and
   *   enqueues Layer-0, while apps/worker (the sole consumer, with the scanners +
   *   git) processes every layer. Keeps the split deployment safe (the distroless
   *   api image never tries to run a scanner-bearing layer job).
   */
  constructor(
    private readonly transport: BullMqTransport,
    private readonly consume = true,
  ) {}

  setProcessor(processor: JobProcessor): void {
    this.processor = processor;
  }

  async start(): Promise<void> {
    if (this.consume && !this.processor)
      throw new Error("BullMqJobScheduler.start(): processor not set");
    for (const layer of LAYER_ORDER) {
      const name = QUEUE_NAMES[layer];
      this.queues.set(name, this.transport.createQueue(name));
    }
    if (this.consume) {
      for (const layer of LAYER_ORDER) {
        this.workers.push(this.transport.createWorker(QUEUE_NAMES[layer], this.processor!));
      }
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
        { connection: workerConnection },
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
  opts: { consume?: boolean } = {},
): Promise<BullMqJobScheduler> {
  const transport = await createRealBullMqTransport(connection);
  return new BullMqJobScheduler(transport, opts.consume ?? true);
}
