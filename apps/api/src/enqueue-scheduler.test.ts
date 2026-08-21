/**
 * A27 — per-tenant BullMQ queue isolation (opt-in, OFF by default) for
 * apps/api's produce-only scheduler. Mirrors
 * packages/orchestrator/src/bullmq-scheduler.tenant-isolation.test.ts:
 * `EnqueueOnlyScheduler` must derive EXACTLY the same queue names as
 * `BullMqJobScheduler` (via the shared `resolveQueueName`/
 * `deriveTenantSchedulerOptions`), or a job apps/api enqueues here would land
 * in a queue apps/worker's consumer never listens on.
 *
 * Uses a hand-written fake `BullMqTransport` (no bullmq/ioredis mocking
 * needed — `EnqueueOnlyScheduler` only ever talks to the transport seam).
 */
import { describe, it, expect } from "vitest";
import type { LayerJobData, KillSwitchSignal } from "@montr/contracts";
import { QUEUE_NAMES, RETRY_POLICIES } from "@montr/contracts";
import type {
  BullMqTransport,
  JobProcessor,
  KillChannel,
  QueueHandle,
  WorkerHandle,
} from "@montr/orchestrator";
import { EnqueueOnlyScheduler } from "./enqueue-scheduler.js";

class FakeQueue implements QueueHandle {
  readonly added: LayerJobData[] = [];
  constructor(public readonly name: string) {}
  async add(_name: string, data: LayerJobData): Promise<void> {
    this.added.push(data);
  }
  async close(): Promise<void> {}
}

class FakeTransport implements BullMqTransport {
  readonly queueNames: string[] = [];
  readonly workerNames: string[] = [];
  readonly queuesByName = new Map<string, FakeQueue>();

  createQueue(name: string): QueueHandle {
    this.queueNames.push(name);
    const q = new FakeQueue(name);
    this.queuesByName.set(name, q);
    return q;
  }

  // apps/api must NEVER become a job consumer — assert that below.
  createWorker(name: string, _processor: JobProcessor): WorkerHandle {
    this.workerNames.push(name);
    return { close: async () => {} };
  }

  killChannel(): KillChannel {
    return {
      subscribe(_handler: (signal: KillSwitchSignal) => void): void {},
      async publish(): Promise<void> {},
      async close(): Promise<void> {},
    };
  }

  async close(): Promise<void> {}
}

function job(clientId: string, idempotencyKey: string): LayerJobData {
  return { scanId: `scan_${clientId}`, clientId, layer: "layer1", idempotencyKey, attempt: 0 };
}

describe("EnqueueOnlyScheduler — tenant isolation OFF (default, regression safety)", () => {
  it("creates one queue per layer named QUEUE_NAMES[layer] and never a Worker", async () => {
    const transport = new FakeTransport();
    const scheduler = new EnqueueOnlyScheduler(transport); // no options passed at all
    await scheduler.start();

    expect(transport.queueNames.sort()).toEqual(Object.values(QUEUE_NAMES).slice(0, 6).sort());
    expect(transport.workerNames).toHaveLength(0); // produce-only — never a consumer
  });

  it("routes jobs from different clientIds into the same shared queue (today's behavior)", async () => {
    const transport = new FakeTransport();
    const scheduler = new EnqueueOnlyScheduler(transport);
    await scheduler.start();

    await scheduler.enqueue(job("client_a", "k1"), RETRY_POLICIES.layer1);
    await scheduler.enqueue(job("client_b", "k2"), RETRY_POLICIES.layer1);

    const sharedQueue = transport.queuesByName.get(QUEUE_NAMES.layer1);
    expect(sharedQueue?.added).toHaveLength(2);
  });
});

describe("EnqueueOnlyScheduler — tenant isolation ON (A27, opt-in)", () => {
  it("derives the SAME per-tenant queue names as BullMqJobScheduler's consumer side", async () => {
    const transport = new FakeTransport();
    const scheduler = new EnqueueOnlyScheduler(transport, {
      tenantIsolation: true,
      tenantIds: ["client_a", "client_b"],
    });
    await scheduler.start();

    expect(transport.queueNames).toHaveLength(12); // 6 layers x 2 tenants
    expect(transport.queueNames).toContain("montr.layer1.client_a");
    expect(transport.queueNames).toContain("montr.layer1.client_b");
    expect(transport.workerNames).toHaveLength(0); // still produce-only
  });

  it("a job enqueued for one client only ever lands in that client's queue", async () => {
    const transport = new FakeTransport();
    const scheduler = new EnqueueOnlyScheduler(transport, {
      tenantIsolation: true,
      tenantIds: ["client_a", "client_b"],
    });
    await scheduler.start();

    await scheduler.enqueue(job("client_a", "k1"), RETRY_POLICIES.layer1);
    await scheduler.enqueue(job("client_b", "k2"), RETRY_POLICIES.layer1);

    expect(transport.queuesByName.get("montr.layer1.client_a")?.added).toHaveLength(1);
    expect(transport.queuesByName.get("montr.layer1.client_b")?.added).toHaveLength(1);
  });

  it("throws when enqueuing a job for a clientId outside the configured tenantIds", async () => {
    const transport = new FakeTransport();
    const scheduler = new EnqueueOnlyScheduler(transport, {
      tenantIsolation: true,
      tenantIds: ["client_a"],
    });
    await scheduler.start();

    await expect(
      scheduler.enqueue(job("client_unknown", "k1"), RETRY_POLICIES.layer1),
    ).rejects.toThrow(/no queue for layer layer1 clientId client_unknown/);
  });

  it("constructor throws immediately when tenantIsolation is on but tenantIds is empty", () => {
    const transport = new FakeTransport();
    expect(() => new EnqueueOnlyScheduler(transport, { tenantIsolation: true })).toThrow(
      /no tenantIds were provided/,
    );
  });
});
