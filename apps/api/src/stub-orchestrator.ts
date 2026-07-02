/**
 * A deterministic in-memory Orchestrator implementing the real @montr/orchestrator
 * lifecycle interface. Used for local dev and unit tests until WS-D's BullMQ
 * orchestrator is wired at integration. It persists scans to the ApiStore so the
 * read routes observe the same state, and drives the gate STATE transitions the
 * API depends on (estimate → fix). It performs NO pipeline work.
 */
import { ScanSchema, type KillSwitchSignal, type PipelineEvent, type Scan } from "@montr/contracts";
import type { CreateScanInput, Orchestrator } from "@montr/orchestrator";
import type { ApiStore, Clock, IdGen } from "./store.js";

export interface StubOrchestratorDeps {
  store: ApiStore;
  clock: Clock;
  idgen: IdGen;
}

export function createStubOrchestrator(deps: StubOrchestratorDeps): Orchestrator {
  const { store, clock, idgen } = deps;
  const clientOf = new Map<string, string>();

  async function loadScan(scanId: string): Promise<Scan | null> {
    const clientId = clientOf.get(scanId);
    if (!clientId) return null;
    return store.scans.get(clientId, scanId);
  }

  async function mutate(scanId: string, changes: Partial<Scan>): Promise<Scan> {
    const scan = await loadScan(scanId);
    if (!scan) throw new Error(`scan not found: ${scanId}`);
    const updated: Scan = { ...scan, ...changes };
    return store.scans.update(scan.clientId, updated);
  }

  return {
    async createScan(input: CreateScanInput): Promise<Scan> {
      const requireEstimate = input.budgetPolicy?.requireEstimateApproval ?? true;
      const scan = ScanSchema.parse({
        id: idgen("scan"),
        clientId: input.clientId,
        repo: input.repo,
        branch: input.branch,
        mode: input.mode,
        scope: input.scope,
        status: "queued",
        gateState: requireEstimate ? "estimate_pending" : "estimate_approved",
        operator: input.operator,
        ...(input.budgetPolicy ? { budgetPolicy: input.budgetPolicy } : {}),
        createdAt: clock.now().toISOString(),
      });
      await store.scans.create(input.clientId, scan);
      clientOf.set(scan.id, input.clientId);
      return scan;
    },

    async start(scanId: string): Promise<void> {
      await mutate(scanId, {
        status: "running",
        gateState: "running",
        startedAt: clock.now().toISOString(),
      });
    },
    async pause(scanId: string): Promise<void> {
      await mutate(scanId, { status: "paused" });
    },
    async resume(scanId: string): Promise<void> {
      await mutate(scanId, { status: "running" });
    },
    async cancel(scanId: string): Promise<void> {
      await mutate(scanId, { status: "cancelled", finishedAt: clock.now().toISOString() });
    },

    async kill(signal: KillSwitchSignal): Promise<void> {
      const ids =
        signal.scope === "global" ? [...clientOf.keys()] : signal.scanId ? [signal.scanId] : [];
      for (const id of ids) {
        const scan = await loadScan(id);
        if (scan) {
          await store.scans.update(scan.clientId, {
            ...scan,
            status: "cancelled",
            gateState: "blocked",
          });
        }
      }
    },

    async status(scanId: string): Promise<Scan> {
      const scan = await loadScan(scanId);
      if (!scan) throw new Error(`scan not found: ${scanId}`);
      return scan;
    },

    async approveGate(scanId: string, gate: "estimate" | "fix", approver: string): Promise<void> {
      if (gate === "estimate") {
        await mutate(scanId, { gateState: "estimate_approved", approver });
      } else {
        await mutate(scanId, { gateState: "approved", approver });
      }
    },

    events(_scanId: string): AsyncIterable<PipelineEvent> {
      return {
        async *[Symbol.asyncIterator](): AsyncIterator<PipelineEvent> {
          // The stub emits no pipeline events.
        },
      };
    },

    async close(): Promise<void> {
      // The stub is fully in-memory; there are no scheduler/queue resources to release.
    },
  };
}
