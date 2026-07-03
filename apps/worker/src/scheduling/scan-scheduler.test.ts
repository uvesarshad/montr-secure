/**
 * apps/worker — scheduled-scan dispatch tests (offline; fake BullMQ transport +
 * stub orchestrator, no Redis).
 *
 * ⛔ Asserts the safety invariants a scheduled run must NEVER weaken:
 *   - the schedule's hard `budgetCeiling` is passed through as a `hard_halt`
 *     BudgetPolicy (budget hard-halt, §8.4);
 *   - the HUMAN GATE is honored — `requireEstimateApproval` stays true and the
 *     scheduler never approves a gate;
 *   - disabled/removed schedules never run;
 *   - the trigger is audited (schedule.triggered).
 */
import { describe, expect, it } from "vitest";
import {
  ScanSchema,
  ScanScheduleSchema,
  type AuditEventInput,
  type Scan,
  type ScanSchedule,
} from "@montr/contracts";
import type { CreateScanInput } from "@montr/orchestrator";
import {
  createScanScheduleService,
  scheduledBudgetPolicy,
  type RepeatableScanTransport,
  type ScheduledJobInfo,
} from "./scan-scheduler.js";

const CLIENT = "client_acme";

function schedule(overrides: Partial<ScanSchedule> = {}): ScanSchedule {
  return ScanScheduleSchema.parse({
    id: "sched_1",
    clientId: CLIENT,
    repo: "acme/app",
    mode: "full",
    cron: "0 0 * * *",
    budgetCeiling: 12.5,
    enabled: true,
    createdBy: "user_op",
    createdAt: "2026-07-03T00:00:00.000Z",
    ...overrides,
  });
}

/** Structural fake of the store surface the scheduler uses. */
function makeStore(initial: ScanSchedule[] = []) {
  const rows = new Map(initial.map((s) => [s.id, structuredClone(s)]));
  const audit: AuditEventInput[] = [];
  const store = {
    scanSchedules: {
      listEnabled: async (c: string) =>
        [...rows.values()]
          .filter((s) => s.clientId === c && s.enabled)
          .map((s) => structuredClone(s)),
      get: async (c: string, id: string) => {
        const s = rows.get(id);
        return s && s.clientId === c ? structuredClone(s) : null;
      },
      update: async (_c: string, s: ScanSchedule) => {
        rows.set(s.id, structuredClone(s));
        return structuredClone(s);
      },
    },
    audit: {
      append: async (input: AuditEventInput) => {
        audit.push(structuredClone(input));
        return input;
      },
    },
  };
  return { store, audit, rows };
}

/** Stub orchestrator that records every call (and would flag a gate approval). */
function makeOrchestrator() {
  const created: CreateScanInput[] = [];
  const started: string[] = [];
  let approveGateCalls = 0;
  const orchestrator = {
    createScan: async (input: CreateScanInput): Promise<Scan> => {
      created.push(structuredClone(input));
      return ScanSchema.parse({
        id: `scan_${created.length}`,
        clientId: input.clientId,
        repo: input.repo,
        branch: input.branch,
        mode: input.mode,
        scope: input.scope,
        operator: input.operator,
        budgetPolicy: input.budgetPolicy,
        createdAt: "2026-07-03T12:00:00.000Z",
      });
    },
    start: async (id: string): Promise<void> => {
      started.push(id);
    },
    // Present so a stray approval would be observable; the scheduler must never call it.
    approveGate: async (): Promise<void> => {
      approveGateCalls += 1;
    },
  };
  return { orchestrator, created, started, gateApprovals: () => approveGateCalls };
}

function makeTransport(infos: ScheduledJobInfo[] = []) {
  const scheduled = new Map<string, string>();
  const unscheduled: string[] = [];
  let consumer: ((job: { scheduleId: string; clientId: string }) => Promise<void>) | undefined;
  const transport: RepeatableScanTransport = {
    schedule: async (job, cron) => {
      scheduled.set(job.scheduleId, cron);
    },
    unschedule: async (id) => {
      unscheduled.push(id);
    },
    listScheduled: async () => infos.map((i) => ({ ...i })),
    consume: async (handler) => {
      consumer = handler;
    },
    close: async () => {},
  };
  return {
    transport,
    scheduled,
    unscheduled,
    fire: (id: string) => consumer?.({ scheduleId: id, clientId: CLIENT }),
  };
}

describe("scheduledBudgetPolicy", () => {
  it("⛔ maps budgetCeiling to a hard_halt ceiling and keeps the estimate gate on", () => {
    const p = scheduledBudgetPolicy(schedule({ budgetCeiling: 9 }));
    expect(p.maxUsd).toBe(9);
    expect(p.enforcement).toBe("hard_halt");
    expect(p.requireEstimateApproval).toBe(true);
  });
});

describe("ScanScheduleService.trigger", () => {
  it("⛔ runs the same pipeline with the hard budget ceiling + human gate, and audits", async () => {
    const { store, audit } = makeStore([schedule({ budgetCeiling: 12.5 })]);
    const orch = makeOrchestrator();
    const { transport } = makeTransport();
    const svc = createScanScheduleService({
      clientId: CLIENT,
      store,
      orchestrator: orch.orchestrator,
      transport,
    });

    const scan = await svc.trigger({ scheduleId: "sched_1", clientId: CLIENT });

    expect(scan).not.toBeNull();
    // Created with the schedule's repo/mode and the HARD budget ceiling.
    expect(orch.created).toHaveLength(1);
    const input = orch.created[0]!;
    expect(input.repo).toBe("acme/app");
    expect(input.mode).toBe("full");
    expect(input.budgetPolicy?.maxUsd).toBe(12.5); // ⛔ hard per-run ceiling
    expect(input.budgetPolicy?.enforcement).toBe("hard_halt");
    // ⛔ Human gate preserved: estimate approval still required…
    expect(input.budgetPolicy?.requireEstimateApproval).toBe(true);
    // …the pipeline is started…
    expect(orch.started).toEqual([scan!.id]);
    // …and NO gate is auto-approved by the scheduler.
    expect(orch.gateApprovals()).toBe(0);

    const triggered = audit.filter((e) => e.action === "schedule.triggered");
    expect(triggered).toHaveLength(1);
    expect(triggered[0]!.scanId).toBe(scan!.id);
    expect(triggered[0]!.targetId).toBe("sched_1");
    expect(triggered[0]!.metadata?.budgetCeiling).toBe(12.5);
  });

  it("⛔ never runs a disabled schedule (fail-safe re-check)", async () => {
    const { store, audit } = makeStore([schedule({ enabled: false })]);
    const orch = makeOrchestrator();
    const { transport } = makeTransport();
    const svc = createScanScheduleService({
      clientId: CLIENT,
      store,
      orchestrator: orch.orchestrator,
      transport,
    });

    const scan = await svc.trigger({ scheduleId: "sched_1", clientId: CLIENT });
    expect(scan).toBeNull();
    expect(orch.created).toHaveLength(0);
    expect(audit).toHaveLength(0);
  });

  it("does nothing for a schedule removed since the job was registered", async () => {
    const { store } = makeStore([]);
    const orch = makeOrchestrator();
    const { transport } = makeTransport();
    const svc = createScanScheduleService({
      clientId: CLIENT,
      store,
      orchestrator: orch.orchestrator,
      transport,
    });
    expect(await svc.trigger({ scheduleId: "ghost", clientId: CLIENT })).toBeNull();
    expect(orch.created).toHaveLength(0);
  });

  it("a fired BullMQ job flows through consume() to a real scheduled run", async () => {
    const { store, audit } = makeStore([schedule()]);
    const orch = makeOrchestrator();
    const { transport, scheduled, fire } = makeTransport([{ scheduleId: "sched_1", nextMs: null }]);
    const svc = createScanScheduleService({
      clientId: CLIENT,
      store,
      orchestrator: orch.orchestrator,
      transport,
    });

    await svc.start(); // wires consume() + initial sync()
    expect(scheduled.get("sched_1")).toBe("0 0 * * *"); // registered on the queue

    await fire("sched_1"); // simulate BullMQ delivering the repeatable job
    expect(orch.created).toHaveLength(1);
    expect(audit.some((e) => e.action === "schedule.triggered")).toBe(true);
  });
});

describe("ScanScheduleService.sync", () => {
  it("registers enabled schedules, drops stale jobs, and refreshes nextRunAt", async () => {
    const a = schedule({ id: "sched_a", repo: "acme/a", cron: "0 1 * * *" });
    const b = schedule({ id: "sched_b", repo: "acme/b", cron: "0 2 * * *" });
    const { store, rows } = makeStore([a, b]);
    const orch = makeOrchestrator();
    // The queue currently holds A (still wanted) and C (stale — must be removed).
    const nextMs = Date.parse("2026-07-04T01:00:00.000Z");
    const { transport, scheduled, unscheduled } = makeTransport([
      { scheduleId: "sched_a", nextMs },
      { scheduleId: "sched_c", nextMs: Date.parse("2026-07-04T09:00:00.000Z") },
    ]);
    const svc = createScanScheduleService({
      clientId: CLIENT,
      store,
      orchestrator: orch.orchestrator,
      transport,
    });

    await svc.sync();

    // Both enabled schedules are (re)registered…
    expect(scheduled.get("sched_a")).toBe("0 1 * * *");
    expect(scheduled.get("sched_b")).toBe("0 2 * * *");
    // …the stale job is removed…
    expect(unscheduled).toContain("sched_c");
    // …and nextRunAt for A is refreshed from the authoritative queue.
    expect(rows.get("sched_a")!.nextRunAt).toBe("2026-07-04T01:00:00.000Z");
  });
});
