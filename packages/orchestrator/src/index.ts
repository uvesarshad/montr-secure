/**
 * @montr/orchestrator — pipeline FSM, BullMQ workers, explicit gate STATE, kill
 * switch, and resumability (§8.1). Layer handoff is contract-typed; no layer
 * reaches around the orchestrator.
 *
 * Wave 0: interface + FSM shape only (WS-D wires BullMQ). Gate is a pipeline
 * state, never a config flag (golden rule #5). Kill switch halts everything,
 * especially DAST.
 */
import {
  NotImplementedError,
  type KillSwitchSignal,
  type PipelineEvent,
  type Scan,
  type ScanMode,
  type ScanScope,
  type BudgetPolicy,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { StateStore } from "@montr/state-store";
import type { Logger } from "@montr/telemetry";
import type { CostMeter } from "@montr/cost-meter";

export interface OrchestratorDeps {
  config: MontrConfig;
  store: StateStore;
  logger: Logger;
  /** Factory so each scan gets its own meter instance. */
  createCostMeter: (scanId: string) => CostMeter;
}

export interface CreateScanInput {
  clientId: string;
  repo: string;
  branch: string;
  mode: ScanMode;
  scope: ScanScope;
  operator: string;
  budgetPolicy?: BudgetPolicy;
}

/** Scan lifecycle API (create/start/pause/resume/cancel) + status/progress stream. */
export interface Orchestrator {
  createScan(input: CreateScanInput): Promise<Scan>;
  start(scanId: string): Promise<void>;
  pause(scanId: string): Promise<void>;
  resume(scanId: string): Promise<void>;
  cancel(scanId: string): Promise<void>;
  /** ⛔ Kill switch — halts all active work immediately (esp. DAST probing). */
  kill(signal: KillSwitchSignal): Promise<void>;
  status(scanId: string): Promise<Scan>;
  /** Approve the cost-estimate or fix gate (approver only). */
  approveGate(scanId: string, gate: "estimate" | "fix", approver: string): Promise<void>;
  events(scanId: string): AsyncIterable<PipelineEvent>;
}

export function createOrchestrator(_deps: OrchestratorDeps): Orchestrator {
  throw new NotImplementedError("createOrchestrator — WS-D");
}
