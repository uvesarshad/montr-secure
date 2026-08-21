/**
 * A3.4 — BullMQ Worker lock/stall tuning (bullmq-scheduler.ts `createWorker`).
 *
 * `bullmq`/`ioredis` are mocked so this never touches a real Redis connection —
 * consistent with the file's own doc comment ("bullmq/ioredis are queue infra
 * ... imported LAZILY behind a `BullMqTransport` seam" specifically so tests
 * can avoid a live Redis). This intercepts the `new bullmq.Worker(...)` call
 * and asserts the options object carries the tuned lock/stall settings, so a
 * layer job that runs for minutes (Semgrep subprocess, synchronous AST
 * parsing, an LLM call with retries) isn't marked stalled and redelivered
 * while it's still legitimately in flight.
 */
import { describe, it, expect, vi, afterEach } from "vitest";

interface CtorCall {
  args: unknown[];
}

const workerCtorCalls: CtorCall[] = [];
const queueCtorCalls: CtorCall[] = [];

class FakeRedis {
  constructor(..._args: unknown[]) {}
  on(): this {
    return this;
  }
  duplicate(): FakeRedis {
    return new FakeRedis();
  }
  async quit(): Promise<void> {}
  async publish(): Promise<number> {
    return 0;
  }
  async subscribe(): Promise<number> {
    return 0;
  }
}

class FakeQueue {
  constructor(...args: unknown[]) {
    queueCtorCalls.push({ args });
  }
  async add(): Promise<void> {}
  async close(): Promise<void> {}
}

class FakeWorker {
  constructor(...args: unknown[]) {
    workerCtorCalls.push({ args });
  }
  async close(): Promise<void> {}
  on(): this {
    return this;
  }
}

vi.mock("ioredis", () => ({ default: FakeRedis }));
vi.mock("bullmq", () => ({ Queue: FakeQueue, Worker: FakeWorker }));

const { createRealBullMqTransport } = await import("./bullmq-scheduler.js");

describe("createRealBullMqTransport — createWorker lock/stall tuning", () => {
  afterEach(() => {
    workerCtorCalls.length = 0;
    queueCtorCalls.length = 0;
  });

  it("sets lockDuration/stalledInterval/maxStalledCount on every per-layer BullMQ Worker", async () => {
    const transport = await createRealBullMqTransport("redis://fake:6379");
    try {
      transport.createWorker("montr.layer1", async () => {});
      transport.createWorker("montr.layer3", async () => {});

      expect(workerCtorCalls).toHaveLength(2);
      for (const call of workerCtorCalls) {
        const [name, , opts] = call.args as [string, unknown, Record<string, unknown>];
        expect(typeof name).toBe("string");
        // A truly crashed worker's lock is never renewed, so it's still caught —
        // just not prematurely, while a legitimately long-running layer keeps
        // its lock alive via BullMQ's automatic lockDuration/2 renewal.
        expect(opts["lockDuration"]).toBe(10 * 60 * 1000);
        expect(opts["stalledInterval"]).toBe(30 * 1000);
        expect(opts["maxStalledCount"]).toBe(1);
      }
    } finally {
      await transport.close();
    }
  });

  it("does not apply the lock/stall tuning to Queue construction (producer side only)", async () => {
    const transport = await createRealBullMqTransport("redis://fake:6379");
    try {
      transport.createQueue("montr.layer0");
      expect(queueCtorCalls).toHaveLength(1);
      const [, opts] = queueCtorCalls[0]?.args as [string, Record<string, unknown>];
      expect(opts["lockDuration"]).toBeUndefined();
    } finally {
      await transport.close();
    }
  });
});
