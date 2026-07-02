/**
 * Job scheduling seam. The FSM decides WHAT layer runs next; the scheduler
 * decides HOW it is delivered to the processor. Two implementations share the
 * exact same processor (the controller's layer runner):
 *   - InlineJobScheduler  — in-process, no Redis; drives the whole pipeline and
 *                           powers offline unit tests.
 *   - BullMqJobScheduler  — durable BullMQ queues per layer (see bullmq-scheduler).
 */
import type { KillSwitchSignal, LayerJobData, RetryPolicy } from "@montr/contracts";

/** A processor consumes one layer job (the controller wires this in). */
export type JobProcessor = (job: LayerJobData) => Promise<void>;

export interface JobScheduler {
  /** Bind the processor that runs a delivered job. */
  setProcessor(processor: JobProcessor): void;
  /** Bring the scheduler online (create queues/workers, subscribe to kill). */
  start(): Promise<void>;
  /** Enqueue the next layer job with its retry policy. */
  enqueue(job: LayerJobData, policy: RetryPolicy): Promise<void>;
  /** Register a handler invoked when a kill signal arrives out-of-band (Redis). */
  onKill(handler: (signal: KillSwitchSignal) => void): void;
  /** ⛔ Broadcast a kill so other worker processes stop too. */
  publishKill(signal: KillSwitchSignal): Promise<void>;
  /** Tear everything down. */
  close(): Promise<void>;
}

/**
 * Single-process scheduler: runs jobs on the microtask queue, strictly in FIFO
 * order, one at a time. Layers within a scan are sequential by construction;
 * scheduling the next layer just pushes onto the same drain loop. Kill is
 * handled in-process by the KillRegistry, so publish/subscribe are no-ops here.
 */
export class InlineJobScheduler implements JobScheduler {
  private processor?: JobProcessor;
  private readonly queue: LayerJobData[] = [];
  private draining = false;
  private closed = false;

  setProcessor(processor: JobProcessor): void {
    this.processor = processor;
  }

  start(): Promise<void> {
    this.closed = false;
    return Promise.resolve();
  }

  enqueue(job: LayerJobData, _policy: RetryPolicy): Promise<void> {
    if (this.closed) return Promise.resolve();
    this.queue.push(job);
    this.pump();
    return Promise.resolve();
  }

  onKill(_handler: (signal: KillSwitchSignal) => void): void {
    // No cross-process channel inline; the KillRegistry aborts running work directly.
  }

  publishKill(_signal: KillSwitchSignal): Promise<void> {
    return Promise.resolve();
  }

  close(): Promise<void> {
    this.closed = true;
    this.queue.length = 0;
    return Promise.resolve();
  }

  private pump(): void {
    if (this.draining) return;
    this.draining = true;
    queueMicrotask(async () => {
      try {
        while (this.queue.length > 0 && !this.closed) {
          const job = this.queue.shift();
          if (!job) continue;
          if (this.processor) await this.processor(job);
        }
      } finally {
        this.draining = false;
        // A job may have enqueued the next layer after we set draining=false.
        if (this.queue.length > 0 && !this.closed) this.pump();
      }
    });
  }
}
