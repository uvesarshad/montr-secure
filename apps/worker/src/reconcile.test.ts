/**
 * Boot-time stuck-scan reconciliation (A3, §8.1) — offline, no Redis/Postgres.
 */
import { describe, it, expect, vi } from "vitest";
import type { Orchestrator } from "@montr/orchestrator";
import type { Scan } from "@montr/contracts";
import { reconcileStuckScans, DEFAULT_STUCK_SCAN_THRESHOLD_MS } from "./reconcile.js";
import { makeInMemoryStore, silentLogger } from "./testkit.js";

const CLIENT_ID = "client_1";

function scan(id: string, overrides: Partial<Scan> = {}): Scan {
  return {
    id,
    clientId: CLIENT_ID,
    repo: "acme/app",
    branch: "main",
    mode: "full",
    scope: { mode: "full" },
    status: "running",
    gateState: "running",
    operator: "user_1",
    createdAt: "2026-01-01T00:00:00.000Z",
    startedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  } as Scan;
}

function fakeOrchestrator(resume: (scanId: string) => Promise<void>): Orchestrator {
  return {
    createScan: vi.fn(),
    start: vi.fn(),
    pause: vi.fn(),
    resume,
    cancel: vi.fn(),
    kill: vi.fn(),
    status: vi.fn(),
    approveGate: vi.fn(),
    events: vi.fn(),
    close: vi.fn(),
  } as unknown as Orchestrator;
}

describe("reconcileStuckScans", () => {
  it("resumes a running scan whose checkpoint has gone stale", async () => {
    const { store } = makeInMemoryStore();
    await store.scans.create(CLIENT_ID, scan("scan_stale"));
    await store.resume.save(CLIENT_ID, {
      scanId: "scan_stale",
      completedLayers: ["layer0"],
      updatedAt: "2026-01-01T00:00:00.000Z", // 20 minutes before `now` below
    });

    const resume = vi.fn(async () => {});
    const now = Date.parse("2026-01-01T00:20:00.000Z"); // 20 min later

    const result = await reconcileStuckScans({
      store,
      orchestrator: fakeOrchestrator(resume),
      clientId: CLIENT_ID,
      logger: silentLogger,
      thresholdMs: DEFAULT_STUCK_SCAN_THRESHOLD_MS, // 10 min
      now: () => now,
    });

    expect(resume).toHaveBeenCalledWith("scan_stale");
    expect(result.resumed).toEqual(["scan_stale"]);
    expect(result.candidateCount).toBe(1);
    expect(result.failed).toEqual([]);
  });

  it("leaves a running scan alone when its checkpoint is still fresh (legitimately mid-layer)", async () => {
    const { store } = makeInMemoryStore();
    await store.scans.create(CLIENT_ID, scan("scan_healthy"));
    await store.resume.save(CLIENT_ID, {
      scanId: "scan_healthy",
      completedLayers: ["layer0"],
      updatedAt: "2026-01-01T00:19:00.000Z", // 1 minute before `now`
    });

    const resume = vi.fn(async () => {});
    const now = Date.parse("2026-01-01T00:20:00.000Z");

    const result = await reconcileStuckScans({
      store,
      orchestrator: fakeOrchestrator(resume),
      clientId: CLIENT_ID,
      logger: silentLogger,
      thresholdMs: DEFAULT_STUCK_SCAN_THRESHOLD_MS,
      now: () => now,
    });

    expect(resume).not.toHaveBeenCalled();
    expect(result.resumed).toEqual([]);
    expect(result.candidateCount).toBe(1);
  });

  it("falls back to scan.startedAt when there is no resume checkpoint yet (crashed before Layer 0 finished)", async () => {
    const { store } = makeInMemoryStore();
    await store.scans.create(
      CLIENT_ID,
      scan("scan_no_checkpoint", { startedAt: "2026-01-01T00:00:00.000Z" }),
    );
    // No store.resume.save() call at all for this scan.

    const resume = vi.fn(async () => {});
    const now = Date.parse("2026-01-01T00:20:00.000Z");

    const result = await reconcileStuckScans({
      store,
      orchestrator: fakeOrchestrator(resume),
      clientId: CLIENT_ID,
      logger: silentLogger,
      thresholdMs: DEFAULT_STUCK_SCAN_THRESHOLD_MS,
      now: () => now,
    });

    expect(resume).toHaveBeenCalledWith("scan_no_checkpoint");
    expect(result.resumed).toEqual(["scan_no_checkpoint"]);
  });

  it("ignores scans in other statuses (paused/completed/failed) — only `running` is a candidate", async () => {
    const { store } = makeInMemoryStore();
    await store.scans.create(CLIENT_ID, scan("scan_paused", { status: "paused" }));
    await store.scans.create(CLIENT_ID, scan("scan_completed", { status: "completed" }));
    await store.scans.create(CLIENT_ID, scan("scan_failed", { status: "failed" }));

    const resume = vi.fn(async () => {});
    const result = await reconcileStuckScans({
      store,
      orchestrator: fakeOrchestrator(resume),
      clientId: CLIENT_ID,
      logger: silentLogger,
      now: () => Date.parse("2027-01-01T00:00:00.000Z"), // far enough that any of these WOULD be stale
    });

    expect(resume).not.toHaveBeenCalled();
    expect(result.candidateCount).toBe(0);
  });

  it("is best-effort: one scan's resume() failure is logged and does not block the others", async () => {
    const { store } = makeInMemoryStore();
    await store.scans.create(CLIENT_ID, scan("scan_a"));
    await store.scans.create(CLIENT_ID, scan("scan_b"));
    // Both stale (no checkpoint, startedAt far in the past relative to `now`).

    const resume = vi.fn(async (scanId: string) => {
      if (scanId === "scan_a") throw new Error("boom");
    });

    const result = await reconcileStuckScans({
      store,
      orchestrator: fakeOrchestrator(resume),
      clientId: CLIENT_ID,
      logger: silentLogger,
      now: () => Date.parse("2027-01-01T00:00:00.000Z"),
    });

    expect(resume).toHaveBeenCalledTimes(2);
    expect(result.failed).toEqual(["scan_a"]);
    expect(result.resumed).toEqual(["scan_b"]);
  });

  it("scopes reconciliation to the given clientId — never touches another client's scans", async () => {
    const { store } = makeInMemoryStore();
    await store.scans.create("other_client", scan("scan_other"));

    const resume = vi.fn(async () => {});
    const result = await reconcileStuckScans({
      store,
      orchestrator: fakeOrchestrator(resume),
      clientId: CLIENT_ID,
      logger: silentLogger,
      now: () => Date.parse("2027-01-01T00:00:00.000Z"),
    });

    expect(resume).not.toHaveBeenCalled();
    expect(result.candidateCount).toBe(0);
  });
});
