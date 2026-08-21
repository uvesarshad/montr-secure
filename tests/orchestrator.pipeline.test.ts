import { describe, it, expect } from "vitest";
import {
  createOrchestrator,
  LAYER_ORDER,
  nextLayer,
  evaluateFixGate,
  computeAllowLive,
  estimateGateRequired,
  type LayerRunners,
  type Orchestrator,
} from "@montr/orchestrator";
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import {
  ScanSchema,
  type AuditEventInput,
  type AuditEvent,
  type CostActual,
  type Fix,
  type LayerContext,
  type PipelineEvent,
  type Provider,
  type Scan,
} from "@montr/contracts";
import type { StateStore } from "@montr/state-store";
import type { Logger } from "@montr/telemetry";
import {
  createBudgetRegistry,
  createCostMeter,
  type CostMeter,
  type BudgetCheck,
} from "@montr/cost-meter";
import {
  createLlmGateway,
  makeUsage,
  type AdapterCompletion,
  type ProviderAdapter,
} from "@montr/llm-gateway";
import {
  mockLayer0Output,
  mockLayer1Output,
  mockLayer2Output,
  mockLayer3Output,
  mockLayer4Output,
  mockLayer5Output,
  mockCostEstimate,
  mockFixes,
  CLIENT_ID,
} from "@montr/fixtures";

/* ------------------------------- test doubles ------------------------------ */

const clone = <T>(v: T): T => (v === null || v === undefined ? v : structuredClone(v));

const silent: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return silent;
  },
};

interface HasIdScan {
  id: string;
  clientId: string;
  scanId: string;
}

function findingRepo<T extends HasIdScan>() {
  const byClient = new Map<string, T[]>();
  const arr = (c: string): T[] => {
    let a = byClient.get(c);
    if (!a) {
      a = [];
      byClient.set(c, a);
    }
    return a;
  };
  return {
    create: (c: string, e: T) => {
      arr(c).push(clone(e));
      return Promise.resolve(clone(e));
    },
    get: (c: string, id: string) => Promise.resolve(clone(arr(c).find((x) => x.id === id) ?? null)),
    list: (c: string) => Promise.resolve(arr(c).map(clone)),
    bulkCreate: (c: string, es: T[]) => {
      for (const e of es) arr(c).push(clone(e));
      return Promise.resolve(es.map(clone));
    },
    listByScan: (c: string, sid: string) =>
      Promise.resolve(
        arr(c)
          .filter((x) => x.scanId === sid)
          .map(clone),
      ),
  };
}

function makeStore(): { store: StateStore; audit: AuditEventInput[] } {
  const scans = new Map<string, Scan>();
  const appMaps = new Map<string, unknown>();
  const fixesByClient = new Map<string, Fix[]>();
  const resume = new Map<string, unknown>();
  const auditLog: AuditEventInput[] = [];
  const fixArr = (c: string): Fix[] => {
    let a = fixesByClient.get(c);
    if (!a) {
      a = [];
      fixesByClient.set(c, a);
    }
    return a;
  };

  const store = {
    scans: {
      create: (c: string, s: Scan) => {
        scans.set(`${c}:${s.id}`, clone(s));
        return Promise.resolve(clone(s));
      },
      get: (c: string, id: string) => Promise.resolve(clone(scans.get(`${c}:${id}`) ?? null)),
      list: (c: string) =>
        Promise.resolve(
          [...scans.entries()].filter(([k]) => k.startsWith(`${c}:`)).map(([, v]) => clone(v)),
        ),
      update: (c: string, s: Scan) => {
        scans.set(`${c}:${s.id}`, clone(s));
        return Promise.resolve(clone(s));
      },
    },
    appMaps: {
      create: (c: string, m: { id: string }) => {
        appMaps.set(`${c}:${m.id}`, clone(m));
        return Promise.resolve(clone(m));
      },
      get: (c: string, id: string) => Promise.resolve(clone(appMaps.get(`${c}:${id}`) ?? null)),
      list: () => Promise.resolve([]),
      latestForCommit: () => Promise.resolve(null),
      markStale: () => Promise.resolve(),
    },
    candidates: findingRepo(),
    probable: findingRepo(),
    confirmed: findingRepo(),
    unconfirmed: findingRepo(),
    fixes: {
      create: (c: string, f: Fix) => {
        fixArr(c).push(clone(f));
        return Promise.resolve(clone(f));
      },
      get: (c: string, id: string) =>
        Promise.resolve(clone(fixArr(c).find((x) => x.id === id) ?? null)),
      list: (c: string) => Promise.resolve(fixArr(c).map(clone)),
      update: (c: string, f: Fix) => {
        const a = fixArr(c);
        const i = a.findIndex((x) => x.id === f.id);
        if (i >= 0) a[i] = clone(f);
        return Promise.resolve(clone(f));
      },
      listByScan: (c: string, sid: string) =>
        Promise.resolve(
          fixArr(c)
            .filter((x) => x.scanId === sid)
            .map(clone),
        ),
    },
    resume: {
      save: (c: string, t: { scanId: string }) => {
        resume.set(`${c}:${t.scanId}`, clone(t));
        return Promise.resolve(clone(t));
      },
      get: (c: string, sid: string) => Promise.resolve(clone(resume.get(`${c}:${sid}`) ?? null)),
    },
    audit: {
      append: (input: AuditEventInput) => {
        auditLog.push(clone(input));
        const seq = auditLog.length;
        const event: AuditEvent = {
          id: `audit_${seq}`,
          sequence: seq,
          prevHash: "",
          hash: `h${seq}`,
          at: "2026-02-01T00:00:00.000Z",
          ...input,
          metadata: input.metadata ?? {},
        };
        return Promise.resolve(event);
      },
      list: () => Promise.resolve([]),
      verifyChain: () => Promise.resolve(true),
    },
    disconnect: () => Promise.resolve(),
  } as unknown as StateStore;

  return { store, audit: auditLog };
}

function makeActual(scanId: string): CostActual {
  return {
    scanId,
    usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    actualUsd: 0,
    wallClockSeconds: 0,
    byLayer: [],
    byModel: [],
    updatedAt: "2026-02-01T00:00:00.000Z",
  };
}

function makeMeter(budget: BudgetCheck[] = []): CostMeter {
  return {
    estimate: () => mockCostEstimate,
    record: () => {},
    actual: () => makeActual("scan"),
    checkBudget: () =>
      budget.shift() ?? {
        withinBudget: true,
        exceeded: false,
        warn: false,
        spentUsd: 0,
        spentTokens: 0,
      },
  };
}

type RunnerMap = Partial<{
  [L in (typeof LAYER_ORDER)[number]]: (ctx: LayerContext<L>) => unknown;
}>;

function makeRunners(overrides: RunnerMap = {}): {
  runners: LayerRunners;
  calls: Record<string, number>;
} {
  const calls: Record<string, number> = {
    layer0: 0,
    layer1: 0,
    layer2: 0,
    layer3: 0,
    layer4: 0,
    layer5: 0,
  };
  const defaults: Record<string, (ctx: LayerContext) => unknown> = {
    layer0: () => mockLayer0Output,
    layer1: () => mockLayer1Output,
    layer2: () => mockLayer2Output,
    layer3: () => mockLayer3Output,
    layer4: () => mockLayer4Output,
    layer5: () => mockLayer5Output,
  };
  const runners: Record<string, (ctx: LayerContext) => Promise<unknown>> = {};
  for (const layer of LAYER_ORDER) {
    const impl =
      (overrides as Record<string, ((ctx: LayerContext) => unknown) | undefined>)[layer] ??
      defaults[layer]!;
    runners[layer] = async (ctx: LayerContext) => {
      calls[layer] = (calls[layer] ?? 0) + 1;
      return impl(ctx);
    };
  }
  return { runners: runners as unknown as LayerRunners, calls };
}

interface Harness {
  orch: Orchestrator;
  store: StateStore;
  audit: AuditEventInput[];
  calls: Record<string, number>;
}

function setup(
  opts: {
    config?: Record<string, unknown>;
    runners?: RunnerMap;
    budget?: BudgetCheck[];
  } = {},
): Harness {
  const { store, audit } = makeStore();
  const config: MontrConfig = MontrConfigSchema.parse({ clientId: CLIENT_ID, ...opts.config });
  const meter = makeMeter(opts.budget);
  const { runners, calls } = makeRunners(opts.runners);
  let tick = 0;
  let idc = 0;
  const base = Date.parse("2026-02-01T00:00:00.000Z");
  const orch = createOrchestrator({
    config,
    store,
    logger: silent,
    createCostMeter: () => meter,
    layerRunners: runners,
    clock: () => new Date(base + tick++ * 1000),
    ids: () => `scan_${idc++}`,
    sleep: () => Promise.resolve(),
  });
  return { orch, store, audit, calls };
}

const SCOPE = { mode: "full" as const, includePaths: ["app/"] };

function createInput(overrides: Record<string, unknown> = {}) {
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

/* -------------------------------- utilities -------------------------------- */

async function settle(
  store: StateStore,
  scanId: string,
  predicate: (s: Scan) => boolean,
  tries = 2000,
): Promise<Scan> {
  for (let i = 0; i < tries; i++) {
    const s = await store.scans.get(CLIENT_ID, scanId);
    if (s && predicate(s)) return s;
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error(`scan ${scanId} did not reach expected state`);
}

const TERMINAL = new Set(["completed", "failed", "cancelled", "partial"]);
const isTerminal = (s: Scan) => TERMINAL.has(s.status);

/** Drain currently-buffered events, stopping when the stream ends or goes quiet. */
async function peekEvents(orch: Orchestrator, scanId: string, ms = 30): Promise<PipelineEvent[]> {
  const it = orch.events(scanId)[Symbol.asyncIterator]();
  const out: PipelineEvent[] = [];
  for (;;) {
    const timeout = new Promise<"timeout">((r) => setTimeout(() => r("timeout"), ms));
    const res = await Promise.race([it.next(), timeout]);
    if (res === "timeout") break;
    if (res.done) break;
    out.push(res.value);
  }
  await it.return?.();
  return out;
}

const types = (evs: PipelineEvent[]) => evs.map((e) => e.type);
const actions = (audit: AuditEventInput[]) => audit.map((a) => a.action);

/* ---------------------------------- tests ---------------------------------- */

describe("orchestrator FSM — full pipeline (inline, offline)", () => {
  it("runs L0→L5 report-first and completes, persisting every state", async () => {
    const { orch, store, audit, calls } = setup({
      config: { budget: { requireEstimateApproval: false } },
    });
    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);

    const done = await settle(store, scan.id, isTerminal);
    expect(done.status).toBe("completed");
    // report-first (auto-fix off) auto-resolves the fix gate without a human.
    expect(done.gateState).toBe("auto_approved");
    expect(done.appMapId).toBe(mockLayer0Output.appMap.id);
    expect(done.costActual).toBeDefined();

    for (const layer of LAYER_ORDER) expect(calls[layer]).toBe(1);

    const token = await store.resume.get(CLIENT_ID, scan.id);
    expect((token as { completedLayers: string[] }).completedLayers).toEqual([...LAYER_ORDER]);

    const evs = await peekEvents(orch, scan.id);
    expect(types(evs)).toContain("scan_started");
    expect(types(evs)).toContain("scan_completed");
    expect(evs.filter((e) => e.type === "layer_completed")).toHaveLength(6);

    expect(actions(audit)).toEqual(
      expect.arrayContaining(["scan.created", "scan.started", "appmap.built", "scan.completed"]),
    );
  });

  it("⛔ estimate gate blocks before Layer 1 until approved (pre-scan cost gate)", async () => {
    // Default hardened config: requireEstimateApproval = true.
    const { orch, store, audit, calls } = setup();
    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);

    const gated = await settle(store, scan.id, (s) => s.gateState === "estimate_pending");
    expect(gated.gateState).toBe("estimate_pending");
    expect(calls.layer0).toBe(1);
    expect(calls.layer1).toBe(0); // NO expensive work before approval
    expect(actions(audit)).toContain("gate.estimate_presented");

    const gateEvents = await peekEvents(orch, scan.id);
    expect(gateEvents.some((e) => e.type === "gate_required" && e.gate === "estimate")).toBe(true);

    await orch.approveGate(scan.id, "estimate", "user_approver_0001");
    const done = await settle(store, scan.id, isTerminal);
    expect(done.status).toBe("completed");
    expect(calls.layer1).toBe(1);
    expect(actions(audit)).toContain("gate.estimate_approved");
  });
});

describe("orchestrator FSM — fix gate (code-change authorization)", () => {
  it("auto-approves auto-eligible PRs when auto-fix ON and no approver required", async () => {
    let layer5Job: { autoApply?: boolean } | undefined;
    const { orch, store, calls } = setup({
      config: {
        budget: { requireEstimateApproval: false },
        autoFix: { enabled: true },
        rbac: { approverRequiredForGate: false },
      },
      runners: {
        layer4: (ctx) => ({
          fixes: mockFixes.map((f) => ({ ...f, scanId: ctx.scanId, clientId: ctx.clientId })),
        }),
        layer5: (ctx) => {
          layer5Job = { autoApply: ctx.job.autoApply };
          return mockLayer5Output;
        },
      },
    });
    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);

    const done = await settle(store, scan.id, isTerminal);
    expect(done.status).toBe("completed");
    expect(done.gateState).toBe("auto_approved");
    expect(layer5Job?.autoApply).toBe(true); // PRs opened for auto-eligible fixes
    expect(calls.layer5).toBe(1);
  });

  it("⛔ blocks at fix_gate_pending for human approval when approver required, then proceeds", async () => {
    let layer5Job: { autoApply?: boolean } | undefined;
    const { orch, store, audit, calls } = setup({
      config: {
        budget: { requireEstimateApproval: false },
        autoFix: { enabled: true },
        rbac: { approverRequiredForGate: true },
      },
      runners: {
        layer4: (ctx) => ({
          fixes: mockFixes.map((f) => ({ ...f, scanId: ctx.scanId, clientId: ctx.clientId })),
        }),
        layer5: (ctx) => {
          layer5Job = { autoApply: ctx.job.autoApply };
          return mockLayer5Output;
        },
      },
    });
    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);

    const gated = await settle(store, scan.id, (s) => s.gateState === "fix_gate_pending");
    expect(gated.gateState).toBe("fix_gate_pending");
    expect(calls.layer5).toBe(0); // NO code change without approval

    await orch.approveGate(scan.id, "fix", "user_approver_0001");
    const done = await settle(store, scan.id, isTerminal);
    expect(done.status).toBe("completed");
    expect(done.gateState).toBe("approved");
    expect(layer5Job?.autoApply).toBe(true);
    expect(actions(audit)).toContain("gate.fix_approved");
  });
});

describe("orchestrator FSM — resumability (§8.1)", () => {
  it("resumes after a Layer-3 crash WITHOUT re-running L0–L2", async () => {
    const { store, audit } = makeStore();
    const config = MontrConfigSchema.parse({
      clientId: CLIENT_ID,
      budget: { requireEstimateApproval: false },
    });
    const meter = makeMeter();
    let tick = 0;
    let idc = 0;
    const base = Date.parse("2026-02-01T00:00:00.000Z");
    const deps = {
      config,
      store,
      logger: silent,
      createCostMeter: () => meter,
      clock: () => new Date(base + tick++ * 1000),
      ids: () => `scan_${idc++}`,
      sleep: () => Promise.resolve(),
    };

    // Controller A: L0,L1,L2 succeed, L3 throws (simulating a crash at L3).
    const a = makeRunners({
      layer3: () => {
        throw new Error("layer 3 crashed");
      },
    });
    const orchA = createOrchestrator({ ...deps, layerRunners: a.runners });
    const scan = await orchA.createScan(createInput());
    await orchA.start(scan.id);
    const failed = await settle(store, scan.id, (s) => s.status === "failed");
    expect(failed.status).toBe("failed");
    expect(a.calls.layer0).toBe(1);
    expect(a.calls.layer1).toBe(1);
    expect(a.calls.layer2).toBe(1);
    expect(a.calls.layer3).toBe(2); // layer3 policy = 2 attempts
    expect(a.calls.layer4).toBe(0);

    // Checkpoint persisted L0–L2 only.
    const token = await store.resume.get(CLIENT_ID, scan.id);
    expect((token as { completedLayers: string[] }).completedLayers).toEqual([
      "layer0",
      "layer1",
      "layer2",
    ]);

    // Controller B (fresh process): L3 now succeeds. Resume.
    const b = makeRunners();
    const orchB = createOrchestrator({ ...deps, layerRunners: b.runners });
    await orchB.resume(scan.id);
    const done = await settle(store, scan.id, isTerminal);

    expect(done.status).toBe("completed");
    // ⛔ L0–L2 were NOT re-run by the resuming controller.
    expect(b.calls.layer0).toBe(0);
    expect(b.calls.layer1).toBe(0);
    expect(b.calls.layer2).toBe(0);
    expect(b.calls.layer3).toBe(1);
    expect(b.calls.layer4).toBe(1);
    expect(b.calls.layer5).toBe(1);
    expect(actions(audit)).toContain("scan.resumed");
  });
});

describe("orchestrator FSM — kill switch (§11)", () => {
  it("⛔ halts in-flight Layer-3 (DAST) work immediately and never runs L4/L5", async () => {
    let l3Entered!: () => void;
    const started = new Promise<void>((r) => {
      l3Entered = r;
    });
    const { orch, store, audit, calls } = setup({
      config: { budget: { requireEstimateApproval: false } },
      runners: {
        layer3: (ctx) => {
          l3Entered();
          return new Promise((_resolve, reject) => {
            if (ctx.signal.aborted) return reject(ctx.signal.reason);
            ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason), { once: true });
          });
        },
      },
    });
    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);
    await started; // Layer 3 is now blocking on the abort signal.

    await orch.kill({
      scope: "scan",
      scanId: scan.id,
      reason: "operator hit the kill switch",
      requestedBy: "user_approver_0001",
      requestedByRole: "approver",
      at: "2026-02-01T00:05:00.000Z",
    });

    const killed = await settle(store, scan.id, (s) => s.status === "cancelled");
    expect(killed.status).toBe("cancelled");
    expect(killed.gateState).toBe("blocked");
    expect(calls.layer3).toBe(1);
    expect(calls.layer4).toBe(0); // ⛔ nothing ran after the kill
    expect(calls.layer5).toBe(0);
    expect(actions(audit)).toContain("dast.kill_switch");

    const evs = await peekEvents(orch, scan.id);
    expect(evs.some((e) => e.type === "killed")).toBe(true);
  });
});

describe("orchestrator FSM — budget hard-halt (DECIDE-4)", () => {
  it("⛔ stops the pipeline and emits a partial report when the ceiling is exceeded", async () => {
    const { orch, store, audit, calls } = setup({
      config: { budget: { requireEstimateApproval: false, maxUsdPerScan: 1 } },
      // checkBudget: ok after L0, exceeded after L1.
      budget: [
        { withinBudget: true, exceeded: false, warn: false, spentUsd: 0.2, spentTokens: 10 },
        { withinBudget: false, exceeded: true, warn: true, spentUsd: 5, spentTokens: 999 },
      ],
    });
    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);

    const halted = await settle(store, scan.id, isTerminal);
    expect(halted.status).toBe("partial");
    expect(halted.gateState).toBe("blocked");
    expect(calls.layer1).toBe(1);
    expect(calls.layer2).toBe(0); // ⛔ never silently burns more tokens

    expect(actions(audit)).toEqual(expect.arrayContaining(["budget.exceeded", "scan.completed"]));
    const evs = await peekEvents(orch, scan.id);
    expect(evs.some((e) => e.type === "budget_exceeded")).toBe(true);
    expect(evs.some((e) => e.type === "scan_completed" && e.partial === true)).toBe(true);
  });
});

describe("orchestrator FSM — PRE-call budget guard (A2, DECIDE-4)", () => {
  /** Minimal fake provider adapter — never actually reached when the guard fires. */
  class FakeAdapter implements ProviderAdapter {
    calls = 0;
    readonly provider: Provider = "anthropic";
    resolveModelId(modelId: string): string {
      return modelId;
    }
    async complete(): Promise<AdapterCompletion> {
      this.calls++;
      return {
        id: "c1",
        model: "claude-sonnet-5",
        content: "hi",
        stopReason: "end_turn",
        usage: makeUsage(10, 5),
      };
    }
    // eslint-disable-next-line require-yield -- never driven when the guard fires first
    async *stream(): AsyncGenerator<never, void, unknown> {
      throw new Error("not used in this test");
    }
  }

  it("⛔ refuses a single over-budget call DURING a layer — the between-layers enforceBudget check alone would have let it through (nothing had been recorded yet)", async () => {
    const { store, audit } = makeStore();
    // A near-zero ceiling: the FIRST call's own estimated cost already clears it,
    // while RECORDED spend (what the post-layer enforceBudget reads) is still $0.
    const config = MontrConfigSchema.parse({
      clientId: CLIENT_ID,
      budget: { requireEstimateApproval: false, maxUsdPerScan: 0.0001, enforcement: "hard_halt" },
    });

    const adapter = new FakeAdapter();
    // The SAME registry instance is threaded into both the gateway (reader) and
    // the orchestrator (writer) — exactly the production wiring in
    // apps/worker/src/main.ts.
    const budgetRegistry = createBudgetRegistry();
    const gateway = createLlmGateway({ config, adapter, sleep: async () => {}, budgetRegistry });

    const { runners, calls } = makeRunners({
      layer2: async (ctx) => {
        // What a real correlation call looks like today (packages/correlation
        // calls gateway.complete() once per candidate batch) — sized so its
        // OWN estimated cost alone blows the ceiling above.
        await gateway.complete({
          messages: [{ role: "user", content: "correlate these findings against the app map" }],
          maxTokens: 100_000,
          metadata: { purpose: "correlation", scanId: ctx.scanId },
        });
        return mockLayer2Output;
      },
    });

    let tick = 0;
    let idc = 0;
    const base = Date.parse("2026-02-01T00:00:00.000Z");
    const orch = createOrchestrator({
      config,
      store,
      logger: silent,
      createCostMeter: (scanId) => createCostMeter(scanId),
      layerRunners: runners,
      clock: () => new Date(base + tick++ * 1000),
      ids: () => `scan_${idc++}`,
      sleep: () => Promise.resolve(),
      budgetRegistry,
    });

    const scan = await orch.createScan(createInput());
    await orch.start(scan.id);

    const done = await settle(store, scan.id, isTerminal);
    // ⛔ The layer FAILED — the call was refused, not silently sent and only
    // discovered afterwards. A pure between-layers check would have measured
    // $0 recorded spend here and let this call through.
    expect(done.status).toBe("failed");
    expect(calls.layer0).toBe(1);
    expect(calls.layer1).toBe(1);
    expect(calls.layer2).toBe(1); // entered layer 2 — refused DURING it
    expect(calls.layer3).toBe(0); // never advanced past the refused layer
    expect(adapter.calls).toBe(0); // ⛔ the provider adapter was never dispatched
    expect(actions(audit)).toContain("scan.failed");
  });
});

describe("orchestrator FSM — pure decision helpers", () => {
  it("nextLayer walks the pipeline order and stops when complete", () => {
    expect(nextLayer([])).toBe("layer0");
    expect(nextLayer(["layer0", "layer1"])).toBe("layer2");
    expect(nextLayer([...LAYER_ORDER])).toBeNull();
  });

  it("evaluateFixGate: auto-fix OFF never opens PRs even for auto-eligible fixes", () => {
    const off = MontrConfigSchema.parse({ autoFix: { enabled: false } });
    expect(evaluateFixGate(mockFixes, off).wouldOpenPrs).toBe(false);
  });

  it("evaluateFixGate: auto-fix ON opens PRs only for auto-eligible fixes", () => {
    const on = MontrConfigSchema.parse({ autoFix: { enabled: true } });
    expect(evaluateFixGate(mockFixes, on).wouldOpenPrs).toBe(true);

    const humanOnly: Fix[] = mockFixes.map((f) => ({ ...f, riskClass: "human-required" as const }));
    const decision = evaluateFixGate(humanOnly, on);
    expect(decision.wouldOpenPrs).toBe(false); // ⛔ human-required never auto-opens
    expect(decision.autoEligibleFixIds).toHaveLength(0);
  });

  it("estimateGateRequired honors the per-scan budget policy override", () => {
    const config = MontrConfigSchema.parse({});
    const base = ScanSchema.parse({
      id: "s1",
      clientId: CLIENT_ID,
      repo: "r",
      branch: "main",
      mode: "full",
      scope: SCOPE,
      operator: "op",
      createdAt: "2026-02-01T00:00:00.000Z",
    });
    const noApproval = ScanSchema.parse({
      ...base,
      budgetPolicy: { requireEstimateApproval: false },
    });
    expect(estimateGateRequired(base, config)).toBe(true); // config default
    expect(estimateGateRequired(noApproval, config)).toBe(false);
  });

  it("⛔ computeAllowLive defaults to static-only unless every DAST guardrail passes", () => {
    const scope = { mode: "full" as const, stagingUrl: "https://staging.internal/app" };
    const base = ScanSchema.parse({
      id: "s2",
      clientId: CLIENT_ID,
      repo: "r",
      branch: "main",
      mode: "full",
      scope,
      operator: "op",
      approver: "user_approver_0001",
      createdAt: "2026-02-01T00:00:00.000Z",
    });

    const dastOff = MontrConfigSchema.parse({});
    expect(computeAllowLive(base, dastOff)).toBe(false);

    const dastOn = MontrConfigSchema.parse({
      dast: { enabled: true, allowlist: ["https://staging.internal"], requireApprover: true },
    });
    expect(computeAllowLive(base, dastOn)).toBe(true);

    const noApprover = ScanSchema.parse({ ...base, approver: undefined });
    expect(computeAllowLive(noApprover, dastOn)).toBe(false); // approver required

    const notAllowlisted = MontrConfigSchema.parse({
      dast: { enabled: true, allowlist: ["https://other.internal"], requireApprover: false },
    });
    expect(computeAllowLive(base, notAllowlisted)).toBe(false); // production/other blocked
  });
});
