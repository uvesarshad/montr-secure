/**
 * apps/worker — IN-PROCESS pipeline driver (build-plan §8.1, §9.2 E2E).
 *
 * Drives the orchestrator FSM through L0→L5 WITHOUT a live Redis/BullMQ, using
 * the orchestrator's in-process `InlineJobScheduler` and the SAME real layer
 * runners the durable worker uses. This is the seam the CI E2E / golden-corpus
 * scan runs on: one process, an in-memory or test state store, the fake LLM
 * adapter — no infra required. The durable multi-process path is `startWorker`.
 */
import {
  createOrchestrator,
  EventBus,
  InlineJobScheduler,
  type CreateScanInput,
  type LayerRunners,
  type Orchestrator,
} from "@montr/orchestrator";
import { createCostMeter, type CostMeter } from "@montr/cost-meter";
import { createNullLogger, type Logger } from "@montr/telemetry";
import type { MontrConfig } from "@montr/config";
import type { StateStore } from "@montr/state-store";
import type { LLMGateway, Scan } from "@montr/contracts";

import { createLayerRunners, type LayerRunnerOptions } from "./runners.js";

/** Everything the in-process driver needs. Mirrors the durable worker's deps. */
export interface InProcessPipelineDeps {
  config: MontrConfig;
  store: StateStore;
  /** ⛔ The one LLM egress path (BYO-key). Injected into every LLM-using layer. */
  gateway: LLMGateway;
  logger?: Logger;
  /** Per-scan cost meter factory. Default: `@montr/cost-meter`'s live meter. */
  createCostMeter?: (scanId: string) => CostMeter;
  /** Layer-runner seams (opener, source reader, semgrep/gitleaks, workspaceRoot…). */
  runnerOptions?: Partial<Omit<LayerRunnerOptions, "gateway">>;
  /** Fully override the layer runners (tests inject stubs for individual layers). */
  layerRunners?: LayerRunners;
  /** Shared event bus (e.g. so a UI can subscribe). Defaults to a fresh one. */
  eventBus?: EventBus;
  /** Deterministic clock hook (tests). */
  clock?: () => Date;
  /** Deterministic id hook (tests). */
  ids?: () => string;
  /** Injectable retry-backoff sleep (tests pass a no-op). */
  sleep?: () => Promise<void>;
}

/**
 * Construct an orchestrator wired to the real layer runners over the in-process
 * inline scheduler (no Redis). Use this to drive the lifecycle manually
 * (createScan / start / pause / resume / cancel / kill / events).
 */
export function createInProcessOrchestrator(deps: InProcessPipelineDeps): Orchestrator {
  const logger = deps.logger ?? createNullLogger();
  const layerRunners =
    deps.layerRunners ??
    createLayerRunners({ gateway: deps.gateway, ...(deps.runnerOptions ?? {}) });

  return createOrchestrator({
    config: deps.config,
    store: deps.store,
    logger,
    createCostMeter: deps.createCostMeter ?? ((scanId) => createCostMeter(scanId)),
    layerRunners,
    // In-process, no Redis: the inline scheduler drives the whole pipeline.
    scheduler: new InlineJobScheduler(),
    ...(deps.eventBus ? { eventBus: deps.eventBus } : {}),
    ...(deps.clock ? { clock: deps.clock } : {}),
    ...(deps.ids ? { ids: deps.ids } : {}),
    ...(deps.sleep ? { sleep: deps.sleep } : {}),
  });
}

const TERMINAL_STATUSES = new Set<Scan["status"]>(["completed", "failed", "cancelled", "partial"]);

/** Options controlling how the driver treats the two human gates. */
export interface RunScanOptions {
  /**
   * ⛔ Cost-estimate gate: when the scan parks at `estimate_pending`, auto-approve
   * it (pass `true` or an approver id). A cost decision — recorded in the audit
   * log. Omit to leave the estimate gate to a human (the driver resolves parked).
   */
  approveEstimate?: boolean | string;
  /**
   * ⛔ Fix gate (code-change authorization): auto-approve `fix_gate_pending`. This
   * authorizes PRs for auto-eligible fixes only (golden rule #5) and is recorded
   * in the audit log. Omit to leave the gate to a human (the safe default).
   */
  approveFix?: boolean | string;
  /** Approver identity recorded when `approveEstimate`/`approveFix` is `true`. */
  approver?: string;
  /** Overall wall-clock budget for the drive loop (default 15_000ms). */
  timeoutMs?: number;
  /** Leave the orchestrator open on resolve (caller closes). Default: close it. */
  keepOpen?: boolean;
}

const DEFAULT_APPROVER = "worker-inproc-driver";

function approverId(flag: boolean | string | undefined, fallback: string): string {
  return typeof flag === "string" ? flag : fallback;
}

/**
 * Create a scan, start it, and drive the FSM to a terminal state (or to a human
 * gate the options did not authorize — the returned scan's `gateState` tells you
 * which). Resolves with the final scan snapshot. Fully offline: no Redis, no
 * network beyond whatever the injected gateway does.
 */
export async function runScanInProcess(
  deps: InProcessPipelineDeps,
  input: CreateScanInput,
  options: RunScanOptions = {},
): Promise<Scan> {
  const orchestrator = createInProcessOrchestrator(deps);
  try {
    const created = await orchestrator.createScan(input);
    await orchestrator.start(created.id);
    return await driveToSettled(orchestrator, deps.store, input.clientId, created.id, options);
  } finally {
    if (!options.keepOpen) await orchestrator.close();
  }
}

/**
 * Poll the store until the scan reaches a terminal state or an unauthorized gate,
 * auto-approving gates per {@link RunScanOptions}. Yields to the microtask/timer
 * queue each tick so the inline scheduler makes progress.
 */
async function driveToSettled(
  orchestrator: Orchestrator,
  store: StateStore,
  clientId: string,
  scanId: string,
  options: RunScanOptions,
): Promise<Scan> {
  const deadline = Date.now() + (options.timeoutMs ?? 15_000);
  const approver = options.approver ?? DEFAULT_APPROVER;
  const approvedGates = new Set<"estimate" | "fix">();

  for (;;) {
    const scan = await store.scans.get(clientId, scanId);
    if (!scan) throw new Error(`runScanInProcess: scan ${scanId} vanished from the store`);
    if (TERMINAL_STATUSES.has(scan.status)) return scan;

    if (scan.gateState === "estimate_pending") {
      if (options.approveEstimate && !approvedGates.has("estimate")) {
        approvedGates.add("estimate");
        await orchestrator.approveGate(
          scanId,
          "estimate",
          approverId(options.approveEstimate, approver),
        );
      } else if (!options.approveEstimate) {
        return scan; // parked at the cost gate — left to a human by choice.
      }
    } else if (scan.gateState === "fix_gate_pending") {
      if (options.approveFix && !approvedGates.has("fix")) {
        approvedGates.add("fix");
        await orchestrator.approveGate(scanId, "fix", approverId(options.approveFix, approver));
      } else if (!options.approveFix) {
        return scan; // parked at the code-change gate — the safe default.
      }
    }

    if (Date.now() > deadline) {
      throw new Error(
        `runScanInProcess: scan ${scanId} did not settle within the timeout (status=${scan.status}, gate=${scan.gateState})`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
