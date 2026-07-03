/**
 * apps/worker — scheduled scans (build-plan §8, PRD §16 Phase-4).
 *
 * A ScanSchedule (authored + cron-validated in apps/api) fires on a cron cadence
 * and runs the SAME orchestrator pipeline as a manual scan. This module owns the
 * dispatch: reconciling BullMQ repeatable jobs with the store (`sync`) and, when
 * a job fires, creating + starting a scan (`trigger`).
 *
 * ⛔ SAFETY (§11, golden rules — never weakened by automation):
 *   - Every scheduled run carries the schedule's HARD per-run `budgetCeiling`
 *     (USD) as a `hard_halt` BudgetPolicy — a runaway scan halts + emits a partial
 *     report; it never silently burns tokens (§8.4, DECIDE-4).
 *   - The run STILL honors the HUMAN GATE: `requireEstimateApproval` stays TRUE,
 *     so the scan parks at the estimate gate for a human, and the scheduler NEVER
 *     approves a gate (there is no `approveGate` call in this module). Auto-fix
 *     stays PR-only + approver-gated exactly as for a manual scan (rules #3, #5).
 *   - Disabled/removed schedules never run (fail-safe re-check at trigger time).
 *   - Each trigger is bound to a `schedule.triggered` audit event.
 *
 * BullMQ/ioredis stay behind the {@link RepeatableScanTransport} seam so this core
 * is unit-tested offline with a fake transport + a stub orchestrator.
 */
import {
  ScanScopeSchema,
  type AuditActor,
  type AuditEventInput,
  type BudgetPolicy,
  type Scan,
  type ScanSchedule,
} from "@montr/contracts";
import type { CreateScanInput, Orchestrator } from "@montr/orchestrator";
import { createNullLogger, type Logger } from "@montr/telemetry";

/** ⛔ System actor recorded for scheduler-initiated actions (audit trail). */
export const SCHEDULER_ACTOR: AuditActor = { type: "system", id: "scan-scheduler" };

/** Operator id stamped on scheduler-created scans (a system principal). */
const SCHEDULER_OPERATOR = "scan-scheduler";

/**
 * ScanSchedule carries no branch (frozen contract); scheduled runs target the
 * repo's default branch. Revisit if the contract later grows a branch field.
 */
const SCHEDULED_BRANCH = "main";

/** BullMQ-facing payload: which schedule fired, for which client. */
export interface ScanScheduleJob {
  scheduleId: string;
  clientId: string;
}

/** One registered repeatable job + its next fire time (ms epoch), if known. */
export interface ScheduledJobInfo {
  scheduleId: string;
  nextMs: number | null;
}

/**
 * Seam over BullMQ's repeatable/cron jobs. The production implementation
 * (`createBullMqScanTransport`) lazily loads bullmq/ioredis; tests inject a fake
 * so no Redis is required.
 */
export interface RepeatableScanTransport {
  /** Register or replace the repeatable job for a schedule (cron cadence). */
  schedule(job: ScanScheduleJob, cron: string): Promise<void>;
  /** Remove the repeatable job for a schedule id. */
  unschedule(scheduleId: string): Promise<void>;
  /** Currently-registered repeatable jobs (for reconciliation + nextRunAt). */
  listScheduled(): Promise<ScheduledJobInfo[]>;
  /** Start consuming fired jobs; `handler` runs one scheduled scan. Idempotent. */
  consume(handler: (job: ScanScheduleJob) => Promise<void>): Promise<void>;
  /** Drain + release resources. */
  close(): Promise<void>;
}

/** Minimal store surface the scheduler needs (the real StateStore satisfies it). */
export interface SchedulerStore {
  scanSchedules: {
    listEnabled(clientId: string): Promise<ScanSchedule[]>;
    get(clientId: string, id: string): Promise<ScanSchedule | null>;
    update(clientId: string, schedule: ScanSchedule): Promise<ScanSchedule>;
  };
  audit: { append(input: AuditEventInput): Promise<unknown> };
}

/** Minimal orchestrator surface: create a scan + start its pipeline. */
export type SchedulerOrchestrator = Pick<Orchestrator, "createScan" | "start">;

export interface ScanScheduleServiceDeps {
  /** This deployment's client (per-client isolation — one deployment per client). */
  clientId: string;
  store: SchedulerStore;
  orchestrator: SchedulerOrchestrator;
  transport: RepeatableScanTransport;
  logger?: Logger;
}

/**
 * ⛔ The HARD budget policy for a scheduled run: the schedule's `budgetCeiling`
 * as a `hard_halt` USD ceiling, with the estimate gate LEFT ON so a human still
 * acknowledges cost. Never relax these for automation (golden rules #3, DECIDE-4).
 */
export function scheduledBudgetPolicy(schedule: ScanSchedule): BudgetPolicy {
  return {
    maxUsd: schedule.budgetCeiling,
    enforcement: "hard_halt",
    requireEstimateApproval: true,
    warnThresholdPct: 0.8,
  };
}

function scheduledScanInput(schedule: ScanSchedule): CreateScanInput {
  return {
    clientId: schedule.clientId,
    repo: schedule.repo,
    branch: SCHEDULED_BRANCH,
    mode: schedule.mode,
    scope: ScanScopeSchema.parse({ mode: schedule.mode }),
    operator: SCHEDULER_OPERATOR,
    budgetPolicy: scheduledBudgetPolicy(schedule),
  };
}

export interface ScanScheduleService {
  /** Reconcile BullMQ repeatable jobs with the store's enabled schedules. */
  sync(): Promise<void>;
  /** Run one scheduled scan (create + start; NEVER approves a gate). */
  trigger(job: ScanScheduleJob): Promise<Scan | null>;
  /** Wire the consumer + do an initial reconcile. */
  start(): Promise<void>;
  /** Release the transport. */
  stop(): Promise<void>;
}

export function createScanScheduleService(deps: ScanScheduleServiceDeps): ScanScheduleService {
  const logger = (deps.logger ?? createNullLogger()).child({ component: "scan-scheduler" });
  const { clientId, store, orchestrator, transport } = deps;

  async function trigger(job: ScanScheduleJob): Promise<Scan | null> {
    const schedule = await store.scanSchedules.get(job.clientId, job.scheduleId);
    // Fail-safe: a schedule deleted/disabled since the job was registered never runs.
    if (!schedule) {
      logger.warn("schedule.trigger.missing", { scheduleId: job.scheduleId });
      return null;
    }
    if (!schedule.enabled) {
      logger.info("schedule.trigger.skipped_disabled", { scheduleId: schedule.id });
      return null;
    }

    // ⛔ Same pipeline as a manual scan: create + start, carrying the hard budget
    //    ceiling. We DO NOT approve any gate — the scan parks at the estimate gate
    //    for a human, and the fix gate stays approver-only (golden rules #3, #5).
    const scan = await orchestrator.createScan(scheduledScanInput(schedule));
    await orchestrator.start(scan.id);

    await store.audit.append({
      clientId: schedule.clientId,
      scanId: scan.id,
      actor: SCHEDULER_ACTOR,
      action: "schedule.triggered",
      targetType: "scan_schedule",
      targetId: schedule.id,
      summary:
        `Scheduled scan started for ${schedule.repo} (${schedule.mode}); ` +
        `budget ceiling $${schedule.budgetCeiling}/run, human gate enforced.`,
      metadata: {
        repo: schedule.repo,
        mode: schedule.mode,
        cron: schedule.cron,
        budgetCeiling: schedule.budgetCeiling,
      },
    });
    logger.info("schedule.triggered", { scheduleId: schedule.id, scanId: scan.id });
    return scan;
  }

  async function sync(): Promise<void> {
    const enabled = await store.scanSchedules.listEnabled(clientId);
    const wanted = new Map(enabled.map((s) => [s.id, s]));

    for (const s of enabled) {
      await transport.schedule({ scheduleId: s.id, clientId }, s.cron);
    }
    // Drop repeatable jobs for schedules that were disabled/removed.
    for (const info of await transport.listScheduled()) {
      if (!wanted.has(info.scheduleId)) await transport.unschedule(info.scheduleId);
    }
    // Refresh nextRunAt from the authoritative (BullMQ) schedule so the console
    // shows the true next fire time. Bookkeeping only — NOT an audited mutation.
    for (const info of await transport.listScheduled()) {
      const s = wanted.get(info.scheduleId);
      if (!s || info.nextMs == null) continue;
      const nextRunAt = new Date(info.nextMs).toISOString();
      if (s.nextRunAt !== nextRunAt) {
        await store.scanSchedules.update(clientId, { ...s, nextRunAt });
      }
    }
    logger.info("schedule.sync", { enabled: enabled.length });
  }

  async function start(): Promise<void> {
    await transport.consume(async (job) => {
      await trigger(job);
    });
    await sync();
  }

  async function stop(): Promise<void> {
    await transport.close();
  }

  return { sync, trigger, start, stop };
}
