/**
 * In-process pub/sub for the pipeline event stream (§8.1 progress stream). Each
 * scan gets a replayable channel: subscribers receive the full history so far,
 * then live events, and the iterator ends when the scan reaches a terminal
 * state. This backs `Orchestrator.events(scanId)`.
 *
 * Multi-process deployments can back the same interface with Redis pub/sub; the
 * orchestrator only depends on the `EventSink` shape below.
 */
import type { LayerId, PipelineEvent } from "@montr/contracts";

/** Anything the controller can push pipeline events into. */
export interface EventSink {
  emit(event: PipelineEvent): void;
  /** Mark a scan's stream complete so open iterators finish gracefully. */
  end(scanId: string): void;
}

export class EventBus implements EventSink {
  private readonly history = new Map<string, PipelineEvent[]>();
  private readonly waiters = new Map<string, Array<() => void>>();
  private readonly ended = new Set<string>();

  emit(event: PipelineEvent): void {
    const arr = this.history.get(event.scanId);
    if (arr) arr.push(event);
    else this.history.set(event.scanId, [event]);
    this.wake(event.scanId);
  }

  end(scanId: string): void {
    this.ended.add(scanId);
    this.wake(scanId);
  }

  /** Drop retained history for a scan (call once no consumers remain). */
  clear(scanId: string): void {
    this.history.delete(scanId);
    this.waiters.delete(scanId);
    this.ended.delete(scanId);
  }

  private wake(scanId: string): void {
    const ws = this.waiters.get(scanId);
    if (!ws || ws.length === 0) return;
    this.waiters.set(scanId, []);
    for (const resolve of ws) resolve();
  }

  /** Replay-then-live async iterator for one scan's events. */
  subscribe(scanId: string): AsyncIterableIterator<PipelineEvent> {
    let index = 0;
    // Destructure the shared Map/Set references (avoids aliasing `this`, which the
    // returned iterator object rebinds); behavior is identical to `this.<field>`.
    const { history, ended, waiters } = this;
    return {
      [Symbol.asyncIterator]() {
        return this;
      },
      next(): Promise<IteratorResult<PipelineEvent>> {
        return (async () => {
          for (;;) {
            const arr = history.get(scanId) ?? [];
            if (index < arr.length) {
              const value = arr[index] as PipelineEvent;
              index += 1;
              return { value, done: false };
            }
            if (ended.has(scanId)) {
              return { value: undefined, done: true } as IteratorResult<PipelineEvent>;
            }
            await new Promise<void>((resolve) => {
              const ws = waiters.get(scanId);
              if (ws) ws.push(resolve);
              else waiters.set(scanId, [resolve]);
            });
          }
        })();
      },
      return(): Promise<IteratorResult<PipelineEvent>> {
        return Promise.resolve({ value: undefined, done: true } as IteratorResult<PipelineEvent>);
      },
    };
  }
}

/* --------------------------------------------------------------------------- *
 * Typed event factories — construct exact @montr/contracts PipelineEvent shapes.
 * A single `now` source keeps timestamps deterministic in tests.
 * --------------------------------------------------------------------------- */

export type Now = () => string;

export const events = {
  scanStarted: (scanId: string, at: string): PipelineEvent => ({
    type: "scan_started",
    scanId,
    at,
  }),
  layerStarted: (scanId: string, layer: LayerId, at: string): PipelineEvent => ({
    type: "layer_started",
    scanId,
    layer,
    at,
  }),
  progress: (
    scanId: string,
    layer: LayerId,
    pct: number,
    phase: string,
    at: string,
  ): PipelineEvent => ({ type: "progress", scanId, layer, pct, phase, at }),
  layerCompleted: (scanId: string, layer: LayerId, at: string): PipelineEvent => ({
    type: "layer_completed",
    scanId,
    layer,
    at,
  }),
  gateRequired: (scanId: string, gate: "estimate" | "fix", at: string): PipelineEvent => ({
    type: "gate_required",
    scanId,
    gate,
    at,
  }),
  budgetWarning: (
    scanId: string,
    spentUsd: number,
    ceilingUsd: number | undefined,
    at: string,
  ): PipelineEvent => ({ type: "budget_warning", scanId, spentUsd, ceilingUsd, at }),
  budgetExceeded: (
    scanId: string,
    spentUsd: number,
    ceilingUsd: number | undefined,
    at: string,
  ): PipelineEvent => ({ type: "budget_exceeded", scanId, spentUsd, ceilingUsd, at }),
  killed: (scanId: string, reason: string, at: string): PipelineEvent => ({
    type: "killed",
    scanId,
    reason,
    at,
  }),
  failed: (
    scanId: string,
    layer: LayerId | undefined,
    error: Extract<PipelineEvent, { type: "failed" }>["error"],
    at: string,
  ): PipelineEvent => ({ type: "failed", scanId, layer, error, at }),
  resumed: (scanId: string, fromLayer: LayerId, at: string): PipelineEvent => ({
    type: "resumed",
    scanId,
    fromLayer,
    at,
  }),
  scanCompleted: (scanId: string, partial: boolean, at: string): PipelineEvent => ({
    type: "scan_completed",
    scanId,
    partial,
    at,
  }),
};
