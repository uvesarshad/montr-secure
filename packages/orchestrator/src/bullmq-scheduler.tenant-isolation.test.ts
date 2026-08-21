/**
 * A27 — per-tenant BullMQ queue isolation (opt-in, OFF by default).
 *
 * Exercises `BullMqJobScheduler` against a hand-written fake `BullMqTransport`
 * (no bullmq/ioredis mocking needed — the scheduler only ever talks to the
 * transport seam). Two properties matter:
 *
 *   (a) REGRESSION SAFETY — with the feature off (the default, and every
 *       existing caller that doesn't pass `options`), queue names and worker
 *       registration are byte-for-byte identical to pre-A27 behavior: one
 *       queue + one worker per layer, keyed by QUEUE_NAMES[layer].
 *
 *   (b) ISOLATION — with the feature on, each (layer, tenant) pair gets its
 *       OWN queue and its OWN BullMQ Worker instance. This is a structural
 *       proof of fair scheduling rather than a timing-based load test: a
 *       large backlog on one tenant's queue cannot starve another tenant's
 *       job because they are different Worker objects each independently
 *       polling Redis — not one Worker draining one shared queue before the
 *       next tenant's jobs are even visible. We assert this by checking (1)
 *       distinct queue names per tenant, (2) one Worker constructed per
 *       (layer, tenant) pair — never a single Worker shared across tenants —
 *       and (3) that enqueuing a job for one tenant only ever touches that
 *       tenant's queue.
 */
import { describe, it, expect } from "vitest";
import type { LayerJobData, KillSwitchSignal } from "@montr/contracts";
import { QUEUE_NAMES, RETRY_POLICIES } from "@montr/contracts";
import {
  BullMqJobScheduler,
  deriveTenantSchedulerOptions,
  type BullMqTransport,
  type KillChannel,
  type QueueHandle,
  type WorkerHandle,
} from "./bullmq-scheduler.js";
import type { JobProcessor } from "./scheduler.js";

class FakeQueue implements QueueHandle {
  readonly added: LayerJobData[] = [];
  closed = false;
  constructor(public readonly name: string) {}
  async add(_name: string, data: LayerJobData): Promise<void> {
    this.added.push(data);
  }
  async close(): Promise<void> {
    this.closed = true;
  }
}

class FakeWorker implements WorkerHandle {
  closed = false;
  constructor(public readonly name: string) {}
  async close(): Promise<void> {
    this.closed = true;
  }
}

class FakeTransport implements BullMqTransport {
  readonly queueNames: string[] = [];
  readonly workerNames: string[] = [];
  readonly queuesByName = new Map<string, FakeQueue>();
  readonly workersByName = new Map<string, FakeWorker>();
  closed = false;

  createQueue(name: string): QueueHandle {
    this.queueNames.push(name);
    const q = new FakeQueue(name);
    this.queuesByName.set(name, q);
    return q;
  }

  createWorker(name: string, _processor: JobProcessor): WorkerHandle {
    this.workerNames.push(name);
    const w = new FakeWorker(name);
    this.workersByName.set(name, w);
    return w;
  }

  killChannel(): KillChannel {
    return {
      subscribe(_handler: (signal: KillSwitchSignal) => void): void {},
      async publish(): Promise<void> {},
      async close(): Promise<void> {},
    };
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

const LAYERS = ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"] as const;

function job(layer: (typeof LAYERS)[number], clientId: string): LayerJobData {
  const base = {
    scanId: `scan_${clientId}`,
    clientId,
    idempotencyKey: `scan_${clientId}:${layer}:0`,
  };
  switch (layer) {
    case "layer0":
      return {
        ...base,
        layer: "layer0",
        repo: "org/repo",
        branch: "main",
        mode: "full",
        scope: {
          mode: "full",
          includePaths: [],
          excludePaths: [],
          changedFiles: [],
          reachableFromChanges: false,
        },
        attempt: 0,
      };
    default:
      return { ...base, layer, attempt: 0 } as LayerJobData;
  }
}

const NOOP_PROCESSOR: JobProcessor = async () => {};

describe("BullMqJobScheduler — tenant isolation OFF (default, regression safety)", () => {
  it("creates exactly one queue + one worker per layer, named QUEUE_NAMES[layer]", async () => {
    const transport = new FakeTransport();
    const scheduler = new BullMqJobScheduler(transport); // no options passed at all
    scheduler.setProcessor(NOOP_PROCESSOR);
    await scheduler.start();

    expect(transport.queueNames.sort()).toEqual(Object.values(QUEUE_NAMES).slice(0, 6).sort());
    expect(transport.workerNames.sort()).toEqual(Object.values(QUEUE_NAMES).slice(0, 6).sort());
    expect(transport.queueNames).toHaveLength(6);
    expect(transport.workerNames).toHaveLength(6);
  });

  it("routes jobs from different clientIds into the SAME shared queue (today's behavior)", async () => {
    const transport = new FakeTransport();
    const scheduler = new BullMqJobScheduler(transport, { tenantIsolation: false });
    scheduler.setProcessor(NOOP_PROCESSOR);
    await scheduler.start();

    await scheduler.enqueue(job("layer1", "client_a"), RETRY_POLICIES.layer1);
    await scheduler.enqueue(job("layer1", "client_b"), RETRY_POLICIES.layer1);

    const sharedQueue = transport.queuesByName.get(QUEUE_NAMES.layer1);
    expect(sharedQueue?.added).toHaveLength(2);
    expect(sharedQueue?.added.map((d) => d.clientId).sort()).toEqual(["client_a", "client_b"]);
  });
});

describe("BullMqJobScheduler — tenant isolation ON (A27, opt-in)", () => {
  it("creates one queue + one Worker per (layer, tenant) pair, named montr.<layer>.<clientId>", async () => {
    const transport = new FakeTransport();
    const scheduler = new BullMqJobScheduler(transport, {
      tenantIsolation: true,
      tenantIds: ["client_a", "client_b"],
    });
    scheduler.setProcessor(NOOP_PROCESSOR);
    await scheduler.start();

    expect(transport.queueNames).toHaveLength(12); // 6 layers x 2 tenants
    expect(transport.workerNames).toHaveLength(12);
    for (const layer of LAYERS) {
      expect(transport.queueNames).toContain(`${QUEUE_NAMES[layer]}.client_a`);
      expect(transport.queueNames).toContain(`${QUEUE_NAMES[layer]}.client_b`);
    }
    // Structural fair-scheduling proof: no worker name is shared across
    // tenants — each tenant's queue is polled by its OWN Worker instance,
    // never a single Worker draining one tenant's backlog before the other
    // tenant's jobs become visible.
    expect(new Set(transport.workerNames).size).toBe(transport.workerNames.length);
  });

  it("a job for one client only ever touches that client's queue (no shared head-of-line)", async () => {
    const transport = new FakeTransport();
    const scheduler = new BullMqJobScheduler(transport, {
      tenantIsolation: true,
      tenantIds: ["client_a", "client_b"],
    });
    scheduler.setProcessor(NOOP_PROCESSOR);
    await scheduler.start();

    // Simulate client_a having a large backlog already queued.
    for (let i = 0; i < 50; i++) {
      await scheduler.enqueue(
        { ...job("layer1", "client_a"), idempotencyKey: `scan_a_${i}:layer1:0` },
        RETRY_POLICIES.layer1,
      );
    }
    // client_b's newly-queued job lands in ITS OWN queue, untouched by A's backlog.
    await scheduler.enqueue(job("layer1", "client_b"), RETRY_POLICIES.layer1);

    const queueA = transport.queuesByName.get("montr.layer1.client_a");
    const queueB = transport.queuesByName.get("montr.layer1.client_b");
    expect(queueA?.added).toHaveLength(50);
    expect(queueB?.added).toHaveLength(1);
    // client_b's single job was never appended to client_a's queue, and vice
    // versa — proving the two clients don't share a queue on this layer.
    expect(queueB?.added.every((d) => d.clientId === "client_b")).toBe(true);
    expect(queueA?.added.every((d) => d.clientId === "client_a")).toBe(true);
  });

  it("throws when enqueuing a job for a clientId outside the configured tenantIds", async () => {
    const transport = new FakeTransport();
    const scheduler = new BullMqJobScheduler(transport, {
      tenantIsolation: true,
      tenantIds: ["client_a"],
    });
    scheduler.setProcessor(NOOP_PROCESSOR);
    await scheduler.start();

    await expect(
      scheduler.enqueue(job("layer1", "client_unknown"), RETRY_POLICIES.layer1),
    ).rejects.toThrow(/no queue for layer layer1 clientId client_unknown/);
  });

  it("constructor throws immediately when tenantIsolation is on but tenantIds is empty", () => {
    const transport = new FakeTransport();
    expect(() => new BullMqJobScheduler(transport, { tenantIsolation: true })).toThrow(
      /no tenantIds were provided/,
    );
  });
});

describe("deriveTenantSchedulerOptions — shared by apps/worker (consumer) and apps/api (producer)", () => {
  it("off by default: perTenantIsolation:false yields {tenantIsolation:false}", () => {
    const opts = deriveTenantSchedulerOptions({
      clientId: "acme",
      queue: { perTenantIsolation: false, tenantIds: [] },
    });
    expect(opts).toEqual({ tenantIsolation: false });
  });

  it("on with no explicit tenantIds: defaults to just this deployment's own clientId", () => {
    const opts = deriveTenantSchedulerOptions({
      clientId: "acme",
      queue: { perTenantIsolation: true, tenantIds: [] },
    });
    expect(opts).toEqual({ tenantIsolation: true, tenantIds: ["acme"] });
  });

  it("on with explicit tenantIds: passes them through unchanged", () => {
    const opts = deriveTenantSchedulerOptions({
      clientId: "acme",
      queue: { perTenantIsolation: true, tenantIds: ["client_a", "client_b"] },
    });
    expect(opts).toEqual({ tenantIsolation: true, tenantIds: ["client_a", "client_b"] });
  });
});
