/**
 * ⛔ Kill switch (§11, golden rule, build-plan §4.3). Halts all active work
 * immediately — ESPECIALLY live DAST probing. Every running layer receives an
 * `AbortSignal` from here; `kill()` aborts it synchronously so in-flight probes
 * stop at once, and the killed flag prevents any queued layer from starting.
 */
import { KillSwitchActivatedError } from "@montr/contracts";

export class KillRegistry {
  private readonly controllers = new Map<string, AbortController>();
  private readonly killed = new Set<string>();
  private globalKilled = false;

  /** Ensure (and return) the AbortController for a scan. */
  register(scanId: string): AbortController {
    let controller = this.controllers.get(scanId);
    if (!controller) {
      controller = new AbortController();
      this.controllers.set(scanId, controller);
    }
    return controller;
  }

  /** The signal a running layer must honor. Already-aborted for killed scans. */
  signalFor(scanId: string): AbortSignal {
    if (this.isKilled(scanId)) {
      const aborted = new AbortController();
      aborted.abort(new KillSwitchActivatedError("scan already killed"));
      return aborted.signal;
    }
    return this.register(scanId).signal;
  }

  /** Halt one scan immediately. */
  abortScan(scanId: string, reason: string): void {
    this.killed.add(scanId);
    const controller = this.controllers.get(scanId);
    if (controller && !controller.signal.aborted) {
      controller.abort(new KillSwitchActivatedError(reason));
    }
  }

  /** Halt EVERY active scan immediately (global kill switch). */
  abortAll(reason: string): void {
    this.globalKilled = true;
    for (const [scanId, controller] of this.controllers) {
      this.killed.add(scanId);
      if (!controller.signal.aborted) controller.abort(new KillSwitchActivatedError(reason));
    }
  }

  isKilled(scanId: string): boolean {
    return this.globalKilled || this.killed.has(scanId);
  }

  isGlobalKilled(): boolean {
    return this.globalKilled;
  }

  /** Scans that currently have a controller (candidates to block on global kill). */
  activeScanIds(): string[] {
    return [...this.controllers.keys()];
  }

  /** Forget a scan's controller once it has terminated. */
  clear(scanId: string): void {
    this.controllers.delete(scanId);
  }
}
