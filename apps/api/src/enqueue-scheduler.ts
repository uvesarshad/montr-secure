/**
 * Produce-only BullMQ job scheduler for apps/api.
 *
 * `@montr/orchestrator`'s `BullMqJobScheduler.start()` creates BOTH the per-layer
 * Redis queues (producer side) AND a BullMQ `Worker` consumer for every layer
 * queue in the SAME process (see `packages/orchestrator/src/bullmq-scheduler.ts`).
 * `OrchestratorController.start()`/`resume()` call that unconditionally
 * (`ensureSchedulerStarted`), so any process — including apps/api — that builds
 * a real `Orchestrator` with a `BullMqJobScheduler` and calls
 * `orchestrator.start(scanId)` would ALSO start consuming L0–L5 jobs itself.
 *
 * That's wrong for apps/api: its distroless image ships no Python/semgrep/
 * gitleaks toolchain (only apps/worker's image does — see Dockerfile.worker),
 * and layer execution is meant to happen in apps/worker exclusively. Two
 * competing consumer pools (api's + worker's) on the same queues would also
 * mean roughly half of every scan's jobs land on whichever one happens to be
 * idle, not necessarily the capable one.
 *
 * This scheduler implements the same `JobScheduler` seam but `start()` only
 * opens the producer-side BullMQ `Queue` handles (via the already-exported
 * `createRealBullMqTransport`) plus the kill-switch pub/sub channel — it never
 * calls `transport.createWorker(...)`, so apps/api can enqueue durably without
 * ever becoming a job consumer. `setProcessor` is accepted (to satisfy the
 * interface) but the processor is intentionally never invoked.
 */
import {
  LAYER_ORDER,
  createRealBullMqTransport,
  type BullMqTransport,
  type JobProcessor,
  type JobScheduler,
  type KillChannel,
  type QueueHandle,
  type RedisConnection,
} from "@montr/orchestrator";
import {
  QUEUE_NAMES,
  type KillSwitchSignal,
  type LayerJobData,
  type QueueName,
  type RetryPolicy,
} from "@montr/contracts";

export class EnqueueOnlyScheduler implements JobScheduler {
  private readonly queues = new Map<QueueName, QueueHandle>();
  private killHandler?: (signal: KillSwitchSignal) => void;
  private channel?: KillChannel;
  private started = false;

  constructor(private readonly transport: BullMqTransport) {}

  /** Never invoked: this scheduler never creates a consumer for any queue. */
  setProcessor(_processor: JobProcessor): void {
    // intentionally a no-op — apps/api must never execute pipeline layers.
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    for (const layer of LAYER_ORDER) {
      const name = QUEUE_NAMES[layer];
      this.queues.set(name, this.transport.createQueue(name));
    }
    this.channel = this.transport.killChannel();
    this.channel.subscribe((signal) => this.killHandler?.(signal));
  }

  async enqueue(job: LayerJobData, policy: RetryPolicy): Promise<void> {
    const queue = this.queues.get(QUEUE_NAMES[job.layer]);
    if (!queue) throw new Error(`EnqueueOnlyScheduler: no queue for layer ${job.layer}`);
    // Mirrors BullMqJobScheduler.enqueue: retry is centralized in the
    // controller, so BullMQ delivers each job once (attempts: 1); the
    // idempotencyKey is the jobId so replays dedupe.
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
    for (const queue of this.queues.values()) await queue.close();
    await this.channel?.close();
    await this.transport.close();
  }
}

/** Build the produce-only scheduler over the real BullMQ/ioredis transport. */
export async function createEnqueueOnlyScheduler(
  connection: RedisConnection,
): Promise<EnqueueOnlyScheduler> {
  const transport = await createRealBullMqTransport(connection);
  return new EnqueueOnlyScheduler(transport);
}
