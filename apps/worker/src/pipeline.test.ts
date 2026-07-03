import { describe, it, expect } from "vitest";
import {
  CLIENT_ID,
  SCAN_ID,
  createFakeLlmGateway,
  mockLayer0Output,
  mockLayer1Output,
} from "@montr/fixtures";
import type {
  Layer2Output,
  Layer3Output,
  Layer4Output,
  Layer5Output,
  LayerContext,
  Scan,
} from "@montr/contracts";
import type { LayerRunners } from "@montr/orchestrator";
import { createInProcessOrchestrator, runScanInProcess } from "./pipeline.js";
import { createLayerRunners } from "./runners.js";
import { makeInMemoryStore, hardenedConfig, instrument, silentLogger } from "./testkit.js";

const gateway = createFakeLlmGateway();

const SCOPE = { mode: "full" as const, includePaths: ["app/", "lib/", "prisma/"] };

function scanInput(overrides: Record<string, unknown> = {}) {
  return {
    clientId: CLIENT_ID,
    repo: "https://example.internal/montr/vulnerable-nextjs",
    branch: "main",
    mode: "full" as const,
    scope: SCOPE,
    operator: "user_operator_0001",
    ...overrides,
  };
}

/** Real L2–L5 adapters; L0/L1 seeded from fixtures so the E2E is offline + fast. */
function seededRunners(): LayerRunners {
  const real = createLayerRunners({ gateway });
  return {
    ...real,
    layer0: () => Promise.resolve(mockLayer0Output),
    layer1: () => Promise.resolve(mockLayer1Output),
  };
}

async function waitForStatus(
  store: ReturnType<typeof makeInMemoryStore>["store"],
  scanId: string,
  predicate: (s: Scan) => boolean,
  tries = 2000,
): Promise<Scan> {
  for (let i = 0; i < tries; i++) {
    const s = await store.scans.get(CLIENT_ID, scanId);
    if (s && predicate(s)) return s;
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error(`scan ${scanId} did not reach the expected state`);
}

describe("in-process pipeline driver — full L0→L5 (offline, no Redis)", () => {
  it("drives the FSM through every layer and completes report-first, persisting each tier", async () => {
    const { store } = makeInMemoryStore();
    const { runners, calls, outputs } = instrument(seededRunners());

    const scan = await runScanInProcess(
      {
        config: hardenedConfig({ budget: { requireEstimateApproval: false } }),
        store,
        gateway,
        logger: silentLogger,
        layerRunners: runners,
        ids: () => SCAN_ID,
        sleep: () => Promise.resolve(),
      },
      scanInput(),
    );

    // FSM walked L0→L5 exactly once each.
    for (const layer of ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"]) {
      expect(calls[layer as keyof typeof calls]).toBe(1);
    }
    expect(scan.status).toBe("completed");
    expect(scan.gateState).toBe("auto_approved"); // report-first (auto-fix off)
    expect(scan.appMapId).toBe(mockLayer0Output.appMap.id);
    expect(scan.costActual).toBeDefined();

    // Persisted tiers match what the REAL adapters emitted (persist division intact).
    const l2 = outputs.layer2 as Layer2Output;
    const l3 = outputs.layer3 as Layer3Output;
    const l4 = outputs.layer4 as Layer4Output;
    const l5 = outputs.layer5 as Layer5Output;

    expect((await store.probable.listByScan(CLIENT_ID, SCAN_ID)).length).toBe(l2.probable.length);
    expect((await store.confirmed.listByScan(CLIENT_ID, SCAN_ID)).length).toBe(l3.confirmed.length);
    expect((await store.fixes.listByScan(CLIENT_ID, SCAN_ID)).length).toBe(l4.fixes.length);

    // The moat + confirmation produced the SQLi finding (matches ground truth).
    expect(l2.probable.length).toBe(4);
    expect(l3.confirmed.some((c) => c.category === "sql_injection")).toBe(true);
    expect(l4.fixes.length).toBe(l3.confirmed.length);

    // ⛔ Report headline = confirmed only; breadth stays in the appendix.
    expect(l5.report.executiveSummary.totalConfirmed).toBe(l3.confirmed.length);
    expect(l5.report.confirmedFindings.length).toBe(l3.confirmed.length);
    expect(l5.report.unconfirmedAppendix.length).toBe(l3.unconfirmed.length);
    expect(l5.pullRequests).toHaveLength(0); // no opener ⇒ no PRs
  });
});

describe("in-process pipeline driver — pre-scan cost gate (§8.1)", () => {
  it("⛔ parks at estimate_pending and runs NO Layer-1 work until approved", async () => {
    const { store } = makeInMemoryStore();
    const { runners, calls } = instrument(seededRunners());

    // Default hardened config ⇒ requireEstimateApproval = true. No auto-approval.
    const parked = await runScanInProcess(
      {
        config: hardenedConfig(),
        store,
        gateway,
        logger: silentLogger,
        layerRunners: runners,
        ids: () => SCAN_ID,
        sleep: () => Promise.resolve(),
      },
      scanInput(),
    );

    expect(parked.gateState).toBe("estimate_pending");
    expect(calls.layer0).toBe(1);
    expect(calls.layer1).toBe(0); // ⛔ no expensive work before approval
  });

  it("completes when the driver is authorized to approve the estimate gate", async () => {
    const { store } = makeInMemoryStore();
    const { runners, calls } = instrument(seededRunners());

    const done = await runScanInProcess(
      {
        config: hardenedConfig(),
        store,
        gateway,
        logger: silentLogger,
        layerRunners: runners,
        ids: () => SCAN_ID,
        sleep: () => Promise.resolve(),
      },
      scanInput(),
      { approveEstimate: "user_approver_0001" },
    );

    expect(done.status).toBe("completed");
    expect(calls.layer1).toBe(1);
    expect(calls.layer5).toBe(1);
  });
});

describe("in-process pipeline driver — kill switch (§11)", () => {
  it("⛔ halts in-flight Layer-3 work immediately and never runs L4/L5", async () => {
    const { store, audit } = makeInMemoryStore();
    let enterLayer3!: () => void;
    const layer3Entered = new Promise<void>((resolve) => {
      enterLayer3 = resolve;
    });

    const real = createLayerRunners({ gateway });
    const custom: LayerRunners = {
      ...real,
      layer0: () => Promise.resolve(mockLayer0Output),
      layer1: () => Promise.resolve(mockLayer1Output),
      // Block Layer 3 until the kill switch aborts it.
      layer3: (ctx: LayerContext<"layer3">) => {
        enterLayer3();
        return new Promise((_resolve, reject) => {
          if (ctx.signal.aborted) return reject(ctx.signal.reason);
          ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason), { once: true });
        });
      },
    };
    const { runners, calls } = instrument(custom);

    const orchestrator = createInProcessOrchestrator({
      config: hardenedConfig({ budget: { requireEstimateApproval: false } }),
      store,
      gateway,
      logger: silentLogger,
      layerRunners: runners,
      ids: () => SCAN_ID,
      sleep: () => Promise.resolve(),
    });

    try {
      const scan = await orchestrator.createScan(scanInput());
      await orchestrator.start(scan.id);
      await layer3Entered; // Layer 3 is now blocking on its abort signal.

      await orchestrator.kill({
        scope: "scan",
        scanId: scan.id,
        reason: "operator hit the kill switch",
        requestedBy: "user_approver_0001",
        requestedByRole: "approver",
        at: "2026-02-01T00:05:00.000Z",
      });

      const killed = await waitForStatus(store, scan.id, (s) => s.status === "cancelled");
      expect(killed.status).toBe("cancelled");
      expect(killed.gateState).toBe("blocked");
      expect(calls.layer3).toBe(1);
      expect(calls.layer4).toBe(0); // ⛔ nothing ran after the kill
      expect(calls.layer5).toBe(0);
      expect(audit.map((a) => a.action)).toContain("dast.kill_switch");
    } finally {
      await orchestrator.close();
    }
  });
});
