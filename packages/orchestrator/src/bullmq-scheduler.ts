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
  resolveQueueName,
  type KillSwitchSignal,
  type LayerId,
  type LayerJobData,
  type RetryPolicy,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
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

/**
 * Everything the scheduler needs from BullMQ/Redis, so it can be faked in
 * tests. `createQueue`/`createWorker` take a plain `string` (not `QueueName`)
 * because per-tenant queue isolation (A27) derives names dynamically via
 * `resolveQueueName` — they are no longer limited to the fixed
 * `QUEUE_NAMES` literal set.
 */
export interface BullMqTransport {
  createQueue(name: string): QueueHandle;
  createWorker(name: string, processor: JobProcessor): WorkerHandle;
  killChannel(): KillChannel;
  close(): Promise<void>;
}

/**
 * Per-tenant queue isolation (A27, opt-in). `tenantIsolation: false`
 * (default) is byte-for-byte identical to pre-A27 behavior: one shared queue
 * per layer, keyed by `QUEUE_NAMES[layer]`. `tenantIsolation: true` fans out
 * one queue + one BullMQ Worker per (layer, tenantId) pair instead — each
 * Worker independently polls Redis, so a large backlog on one tenant's queue
 * cannot block a newly-queued job on another tenant's queue for the same
 * layer (no shared head-of-line). `tenantIds` must be non-empty when
 * `tenantIsolation` is true.
 */
export interface BullMqSchedulerOptions {
  tenantIsolation?: boolean;
  tenantIds?: string[];
}

/**
 * Derive {@link BullMqSchedulerOptions} from a loaded `MontrConfig`. Shared by
 * apps/worker (consumer: queues + workers) and apps/api's produce-only
 * scheduler, so both processes agree on exactly the same queue names — a
 * mismatch here would mean apps/api enqueues into a queue apps/worker never
 * listens on. See `QueueConfigSchema`'s doc comment (packages/config/src/
 * schema.ts) for the off-by-default rationale and the tenantIds default.
 */
export function deriveTenantSchedulerOptions(
  config: Pick<MontrConfig, "clientId" | "queue">,
): BullMqSchedulerOptions {
  if (!config.queue.perTenantIsolation) return { tenantIsolation: false };
  const tenantIds = config.queue.tenantIds.length > 0 ? config.queue.tenantIds : [config.clientId];
  return { tenantIsolation: true, tenantIds };
}

/* ------------------------------- scheduler ------------------------------- */

export class BullMqJobScheduler implements JobScheduler {
  private processor?: JobProcessor;
  /** Keyed by layer (shared mode) or `${layer}:${clientId}` (tenant-isolated mode). */
  private readonly queues = new Map<string, QueueHandle>();
  private readonly workers: WorkerHandle[] = [];
  private channel?: KillChannel;
  private killHandler?: (signal: KillSwitchSignal) => void;
  private readonly tenantIsolation: boolean;
  private readonly tenantIds: string[];

  constructor(
    private readonly transport: BullMqTransport,
    options: BullMqSchedulerOptions = {},
  ) {
    this.tenantIsolation = options.tenantIsolation ?? false;
    this.tenantIds = options.tenantIds ?? [];
    if (this.tenantIsolation && this.tenantIds.length === 0) {
      throw new Error(
        "BullMqJobScheduler: tenantIsolation is enabled but no tenantIds were provided",
      );
    }
  }

  setProcessor(processor: JobProcessor): void {
    this.processor = processor;
  }

  async start(): Promise<void> {
    if (!this.processor) throw new Error("BullMqJobScheduler.start(): processor not set");
    // Shared mode: one [undefined] "tenant" per layer, i.e. today's behavior
    // unchanged. Tenant-isolated mode: one real tenantId per layer.
    const tenants: (string | undefined)[] = this.tenantIsolation ? this.tenantIds : [undefined];
    for (const layer of LAYER_ORDER) {
      for (const tenantId of tenants) {
        const name = this.queueName(layer, tenantId);
        this.queues.set(this.queueKey(layer, tenantId), this.transport.createQueue(name));
      }
    }
    // A separate loop (queues first, then workers) preserves the pre-A27
    // ordering and, in tenant-isolated mode, gives every tenant's queue a
    // dedicated Worker that polls Redis concurrently and independently of
    // every other tenant's Worker — no queue is fully drained before another
    // tenant's jobs are picked up.
    for (const layer of LAYER_ORDER) {
      for (const tenantId of tenants) {
        const name = this.queueName(layer, tenantId);
        this.workers.push(this.transport.createWorker(name, this.processor));
      }
    }
    this.channel = this.transport.killChannel();
    this.channel.subscribe((signal) => this.killHandler?.(signal));
    await Promise.resolve();
  }

  async enqueue(job: LayerJobData, policy: RetryPolicy): Promise<void> {
    const key = this.queueKey(job.layer, this.tenantIsolation ? job.clientId : undefined);
    const queue = this.queues.get(key);
    if (!queue) {
      throw new Error(
        this.tenantIsolation
          ? `BullMqJobScheduler: no queue for layer ${job.layer} clientId ${job.clientId} ` +
              "(clientId is not in the configured tenantIds)"
          : `BullMqJobScheduler: no queue for layer ${job.layer}`,
      );
    }
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

  private queueName(layer: LayerId, tenantId: string | undefined): string {
    return tenantId ? resolveQueueName(layer, tenantId, true) : QUEUE_NAMES[layer];
  }

  private queueKey(layer: LayerId, tenantId: string | undefined): string {
    return tenantId ? `${layer}:${tenantId}` : layer;
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
    createQueue(name: string): QueueHandle {
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

    createWorker(name: string, processor: JobProcessor): WorkerHandle {
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
  options?: BullMqSchedulerOptions,
): Promise<BullMqJobScheduler> {
  const transport = await createRealBullMqTransport(connection);
  return new BullMqJobScheduler(transport, options);
}
