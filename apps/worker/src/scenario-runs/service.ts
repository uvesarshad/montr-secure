/**
 * A1 (2026-09-12 red/blue agentic-posture audit) — REAL worker-side red-team
 * scenario execution. Closes the last major red-team gap: previously
 * `POST /scenarios/:id/run` (apps/api/src/routes/scenarios.ts) always called
 * `runScenario` with an empty deps object — no transport — so a "run" only
 * ever authorized + gate-checked every step and NOTHING ever left the
 * process, anywhere. There was no worker-side scenario-execution path at all.
 *
 * This module is that path. `processScenarioRunJob` is the sole entry point:
 * it re-loads the scenario record (never trusts the job payload's mere
 * existence as authorization), re-checks EVERY existing safety gate, and adds
 * ONE new gate on top — never a replacement for any existing one:
 *
 *   ⛔ WRITTEN AUTHORIZATION (A1): `hasLiveRunAuthorization` (packages/
 *   contracts/src/phase4.ts) must be true — an approver must have recorded a
 *   free-text authorization reference for THIS EXACT scenario version via
 *   `POST /scenarios/:id/authorize`. Checked BEFORE any transport is ever
 *   constructed. Missing/stale (edited-since-authorized) ⇒ reject, fail
 *   closed, audit `scenario.live_run_rejected`, never probe.
 *
 * Every gate this module reuses is untouched and unweakened:
 *   - `scenario.enabled` (disabled-by-default, §11)
 *   - `config.dast.productionBlocked` / `config.dast.killSwitchEnabled`
 *     invariants (defense in depth, mirrors the API route)
 *   - `assertScenarioAuthorized` + `ScopeGuard` inside `runScenario` itself
 *     (packages/confirm/src/scenarios.ts / guard.ts) — allowlist, production
 *     block, kill switch, rate/blast-radius caps, egress guard
 *
 * The transport is `@montr/confirm`'s exported `defaultTransport` — the SAME
 * real HTTP transport Layer 3's own live-DAST confirmation and the A8
 * purple-team loop (apps/worker/src/runners.ts) already use. No new egress
 * path. Real execution NEVER honors a target override — it always runs
 * against the scenario's own authorized `targetAllowlistRef`.
 *
 * Every outcome (rejected or executed) is bound to an audit event
 * (`scenario.live_run_rejected` / `scenario.live_run_executed`), and this
 * function NEVER throws — a store/transport/guardrail failure is caught,
 * logged, and reported as a rejected outcome, so a bad job can never crash
 * the BullMQ consumer loop (mirrors apps/worker/src/scheduling/scan-
 * scheduler.ts's `trigger`'s fail-safe shape).
 */
import {
  hasLiveRunAuthorization,
  type RedTeamScenario,
  type ScenarioRunJob,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { createNullLogger, type Logger } from "@montr/telemetry";
import {
  defaultTransport,
  hostOf,
  runScenario,
  type LiveHttpTransport,
  type ScenarioRunResult,
} from "@montr/confirm";

/** ⛔ System actor recorded for worker-initiated scenario-run outcomes. */
const SCENARIO_RUN_ACTOR = { type: "system" as const, id: "scenario-run-worker" };

/** Minimal store surface this module needs (the real StateStore satisfies it). */
export interface ScenarioRunStore {
  redTeamScenarios: {
    get(clientId: string, id: string): Promise<RedTeamScenario | null>;
  };
  audit: {
    append(input: {
      clientId: string;
      actor: { type: "system"; id: string };
      action: "scenario.live_run_rejected" | "scenario.live_run_executed";
      targetType: string;
      targetId: string;
      summary: string;
      metadata: Record<string, unknown>;
    }): Promise<unknown>;
  };
}

export interface ScenarioRunServiceDeps {
  store: ScenarioRunStore;
  config: MontrConfig;
  logger?: Logger;
  signal?: AbortSignal;
  now?: () => string;
  /** Seam for tests — default: `@montr/confirm`'s real `defaultTransport`. */
  transportFactory?: () => Promise<LiveHttpTransport>;
}

export type ScenarioRunOutcome =
  | {
      executed: true;
      scenarioId: string;
      clientId: string;
      result: ScenarioRunResult;
    }
  | {
      executed: false;
      scenarioId: string;
      clientId: string;
      rejectedReason: string;
    };

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * ⛔ A1 — why real execution refused (mirrors apps/api/src/routes/
 * scenarios.ts's `writtenAuthorizationGapReason` for the pre-flight case;
 * this one narrates a scenario the worker actually loaded).
 */
function writtenAuthorizationGapReason(scenario: RedTeamScenario): string {
  if (!scenario.liveAuthorizedById || !scenario.liveAuthorizedAt) {
    return "scenario has never been authorized for live execution (no written authorizationReference on record)";
  }
  if (scenario.liveAuthorizedForVersion !== scenario.version) {
    return (
      `scenario was authorized for version ${scenario.liveAuthorizedForVersion ?? "?"} but is ` +
      `now version ${scenario.version} (edited since authorization) — re-authorization required`
    );
  }
  return "scenario's written authorization is incomplete (missing an authorization reference)";
}

/**
 * Process one {@link ScenarioRunJob}: re-load + re-gate + (if authorized)
 * actually execute the scenario with a real transport. See module header for
 * the full gate order and the fail-safe/never-throws contract.
 */
export async function processScenarioRunJob(
  job: ScenarioRunJob,
  deps: ScenarioRunServiceDeps,
): Promise<ScenarioRunOutcome> {
  const logger = deps.logger ?? createNullLogger();

  async function reject(reason: string, scenario?: RedTeamScenario): Promise<ScenarioRunOutcome> {
    logger.warn("worker.scenario_run.rejected", {
      scenarioId: job.scenarioId,
      clientId: job.clientId,
      reason,
    });
    try {
      await deps.store.audit.append({
        clientId: job.clientId,
        actor: SCENARIO_RUN_ACTOR,
        action: "scenario.live_run_rejected",
        targetType: "red_team_scenario",
        targetId: job.scenarioId,
        summary: `Real worker-side scenario execution refused: ${reason}`,
        metadata: {
          reason,
          requestedById: job.requestedById,
          requestedAt: job.requestedAt,
          ...(scenario ? { version: scenario.version } : {}),
        },
      });
    } catch (auditErr) {
      // Audit-write failure must never mask the rejection itself — log and
      // still return the rejected outcome (fail closed either way).
      logger.warn("worker.scenario_run.audit_failed", { error: msg(auditErr) });
    }
    return {
      executed: false,
      scenarioId: job.scenarioId,
      clientId: job.clientId,
      rejectedReason: reason,
    };
  }

  try {
    const scenario = await deps.store.redTeamScenarios.get(job.clientId, job.scenarioId);
    if (!scenario) return await reject("scenario not found");
    // ⛔ Disabled scenarios can never run (disabled-by-default, §11) — reused
    // unchanged from the API route's own check.
    if (!scenario.enabled) return await reject("scenario is disabled", scenario);
    // ⛔ Config invariants (defense in depth; both are literal-true in config,
    // mirrors the API route's identical checks).
    if (deps.config.dast.productionBlocked !== true) {
      return await reject(
        "production DAST is blocked by policy (config invariant violated)",
        scenario,
      );
    }
    if (deps.config.dast.killSwitchEnabled !== true) {
      return await reject(
        "DAST kill switch must be enabled by policy (config invariant violated)",
        scenario,
      );
    }

    // ⛔ A1 — THE WRITTEN-AUTHORIZATION GATE. Checked BEFORE any transport is
    // ever constructed. Additive on top of every gate above and below —
    // never a replacement for any of them.
    if (!hasLiveRunAuthorization(scenario)) {
      return await reject(writtenAuthorizationGapReason(scenario), scenario);
    }

    let transport: LiveHttpTransport;
    try {
      transport = deps.transportFactory ? await deps.transportFactory() : await defaultTransport();
    } catch (err) {
      return await reject(`failed to construct live transport: ${msg(err)}`, scenario);
    }

    let result: ScenarioRunResult;
    try {
      // No target override — real execution always runs against the
      // scenario's OWN authorized targetAllowlistRef. `runScenario` still
      // independently re-asserts allowlist + production + kill switch +
      // rate/blast-radius caps + egress guard (guard.ts) — this call adds no
      // new egress path and removes none of those checks.
      result = await runScenario(
        { scenario, config: deps.config, allowLive: true },
        {
          transport,
          ...(deps.signal ? { signal: deps.signal } : {}),
          logger,
        },
      );
    } catch (err) {
      return await reject(`execution guardrail refused: ${msg(err)}`, scenario);
    }

    logger.info("worker.scenario_run.executed", {
      scenarioId: scenario.id,
      clientId: job.clientId,
      target: hostOf(result.target),
      probed: result.probed,
      requestsSent: result.requestsSent,
    });
    try {
      await deps.store.audit.append({
        clientId: job.clientId,
        actor: SCENARIO_RUN_ACTOR,
        action: "scenario.live_run_executed",
        targetType: "red_team_scenario",
        targetId: scenario.id,
        summary: `Real worker-side execution completed for scenario "${scenario.name}" against ${hostOf(result.target)}`,
        metadata: {
          requestedById: job.requestedById,
          requestedAt: job.requestedAt,
          authorizedById: scenario.liveAuthorizedById,
          authorizationReference: scenario.liveAuthorizationReference,
          targetHost: hostOf(result.target),
          probed: result.probed,
          blocked: result.blocked,
          requestsSent: result.requestsSent,
          mutatingSent: result.mutatingSent,
        },
      });
    } catch (auditErr) {
      logger.warn("worker.scenario_run.audit_failed", { error: msg(auditErr) });
    }

    return { executed: true, scenarioId: scenario.id, clientId: job.clientId, result };
  } catch (err) {
    // Fail-safe backstop: an unexpected error anywhere above (e.g. a store
    // read failure before we even have a `scenario` to attach) must still
    // never throw out of this function — a malformed/failing job must never
    // crash the BullMQ consumer loop.
    return await reject(`unexpected error: ${msg(err)}`);
  }
}

/** Seam over the real BullMQ consumer (production) vs. a fake (tests). */
export interface ScenarioRunConsumerTransport {
  /** Start consuming jobs; `handler` processes one job. Idempotent. */
  consume(handler: (job: ScenarioRunJob) => Promise<void>): Promise<void>;
  /** Drain + release resources. */
  close(): Promise<void>;
}

export interface ScenarioRunWorkerDeps extends ScenarioRunServiceDeps {
  transport: ScenarioRunConsumerTransport;
}

export interface ScenarioRunWorker {
  start(): Promise<void>;
  stop(): Promise<void>;
}

/** Wire {@link processScenarioRunJob} to a {@link ScenarioRunConsumerTransport}. */
export function createScenarioRunWorker(deps: ScenarioRunWorkerDeps): ScenarioRunWorker {
  const { transport, ...serviceDeps } = deps;
  return {
    async start(): Promise<void> {
      await transport.consume(async (job) => {
        // processScenarioRunJob never throws (see its own doc comment) — no
        // extra try/catch needed here to protect the consumer loop.
        await processScenarioRunJob(job, serviceDeps);
      });
    },
    async stop(): Promise<void> {
      await transport.close();
    },
  };
}
