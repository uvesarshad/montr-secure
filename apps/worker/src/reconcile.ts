/**
 * Boot-time stuck-scan reconciliation (A3, §8.1).
 *
 * The FSM resume mechanism is real: `OrchestratorController.resume(scanId)`
 * correctly skips finished layers via the persisted ResumeToken checkpoint and
 * re-checks gate state before scheduling the next layer. But nothing calls it
 * automatically — a worker process crash mid-layer leaves the scan parked at
 * `status: "running"` forever, with no operator-visible way to unstick it short
 * of a manual `POST /scans/:id/resume`.
 *
 * This module is the automatic half: on worker boot, find every `running` scan
 * for this client whose resume checkpoint has gone stale (hasn't advanced in
 * `thresholdMs`) and resume it. Checkpoint staleness — not scan age — is the
 * signal: `OrchestratorController.advanceResumeToken` bumps the ResumeToken's
 * `updatedAt` every time a layer completes, so a scan that is still
 * legitimately mid-layer keeps advancing that timestamp and is correctly left
 * alone. Only a scan whose checkpoint hasn't moved in `thresholdMs` is presumed
 * abandoned by a crashed process.
 */
import type { Scan, ScanStatus } from "@montr/contracts";
import type { Orchestrator } from "@montr/orchestrator";
import type { StateStore } from "@montr/state-store";
import type { Logger } from "@montr/telemetry";

/** Only these statuses represent a scan a crashed worker could have abandoned
 * mid-layer. `paused`/terminal statuses are left alone — resuming those is an
 * explicit operator action (POST /scans/:id/resume), not automatic. */
const RECONCILE_STATUS: ScanStatus = "running";

/** Default: a scan whose checkpoint hasn't advanced in 10 minutes is presumed stuck. */
export const DEFAULT_STUCK_SCAN_THRESHOLD_MS = 10 * 60 * 1000;

export interface ReconcileDeps {
  store: StateStore;
  orchestrator: Orchestrator;
  /** This deployment's tenant (single-tenant on-prem — see apps/worker/src/main.ts). */
  clientId: string;
  logger: Logger;
  /** How long a `running` scan's checkpoint may go unchanged before it's presumed
   * abandoned. Default {@link DEFAULT_STUCK_SCAN_THRESHOLD_MS}. */
  thresholdMs?: number;
  /** Injectable clock (tests). Default: `Date.now`. */
  now?: () => number;
}

export interface ReconcileResult {
  /** Scans found `running`, regardless of staleness. */
  candidateCount: number;
  /** Scan ids actually resumed (checkpoint was stale). */
  resumed: string[];
  /** Scan ids where `resume()` itself threw (best-effort — logged, not thrown). */
  failed: string[];
}

/**
 * Find and resume scans stuck `running` from a prior worker crash. Best-effort
 * end to end: a single scan's lookup/resume failure is logged and skipped, it
 * never blocks the others or worker boot.
 */
export async function reconcileStuckScans(deps: ReconcileDeps): Promise<ReconcileResult> {
  const { store, orchestrator, clientId, logger } = deps;
  const thresholdMs = deps.thresholdMs ?? DEFAULT_STUCK_SCAN_THRESHOLD_MS;
  const now = deps.now ?? Date.now;

  let running: Scan[];
  try {
    running = await store.scans.listByStatus(clientId, RECONCILE_STATUS);
  } catch (err) {
    logger.error("worker.reconcile.list_failed", { error: errMessage(err) });
    return { candidateCount: 0, resumed: [], failed: [] };
  }

  const resumed: string[] = [];
  const failed: string[] = [];

  for (const scan of running) {
    const lastProgressIso = await lastProgressAt(store, clientId, scan);
    const lastProgressMs = lastProgressIso ? Date.parse(lastProgressIso) : NaN;
    const stale = Number.isNaN(lastProgressMs) || now() - lastProgressMs >= thresholdMs;
    if (!stale) continue;

    try {
      await orchestrator.resume(scan.id);
      resumed.push(scan.id);
      logger.info("worker.reconcile.resumed", {
        scanId: scan.id,
        lastProgressAt: lastProgressIso,
      });
    } catch (err) {
      failed.push(scan.id);
      logger.error("worker.reconcile.resume_failed", { scanId: scan.id, error: errMessage(err) });
    }
  }

  if (running.length > 0) {
    logger.info("worker.reconcile.scan_complete", {
      candidateCount: running.length,
      resumedCount: resumed.length,
      failedCount: failed.length,
    });
  }

  return { candidateCount: running.length, resumed, failed };
}

/** Last time this scan's pipeline demonstrably moved forward. Falls back to
 * `startedAt`/`createdAt` when there is no resume checkpoint yet (e.g. the
 * process crashed before Layer 0 ever completed). */
async function lastProgressAt(
  store: StateStore,
  clientId: string,
  scan: Scan,
): Promise<string | undefined> {
  try {
    const token = await store.resume.get(clientId, scan.id);
    return token?.updatedAt ?? scan.startedAt ?? scan.createdAt;
  } catch {
    return scan.startedAt ?? scan.createdAt;
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
