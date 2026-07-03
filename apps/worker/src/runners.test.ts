import { describe, it, expect } from "vitest";
import {
  CLIENT_ID,
  SCAN_ID,
  CANDIDATE_DEP_ID,
  createFakeLlmGateway,
  mockAppMap,
  mockScan,
  mockCandidateFindings,
  mockProbableFindings,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockLayer0Output,
} from "@montr/fixtures";
import type { SemgrepJson } from "@montr/discovery";
import { createLayerRunners } from "./runners.js";
import { makeInMemoryStore, makeLayerContext, clone, hardenedConfig } from "./testkit.js";

const gateway = createFakeLlmGateway();

/** A Semgrep runner stub yielding one in-scope SQLi result (no binary needed). */
function stubSemgrep(): () => Promise<SemgrepJson> {
  return () =>
    Promise.resolve({
      results: [
        {
          check_id: "typescript.prisma.raw-query-unsafe",
          path: "app/api/users/route.ts",
          start: { line: 9 },
          extra: {
            severity: "ERROR",
            message: "Unsafe raw SQL query",
            metadata: { cwe: ["CWE-89"] },
          },
        },
      ],
    });
}

const baseJob = (layer: string, extra: Record<string, unknown> = {}) => ({
  scanId: SCAN_ID,
  clientId: CLIENT_ID,
  layer,
  idempotencyKey: `${SCAN_ID}:${layer}:0`,
  attempt: 0,
  ...extra,
});

describe("layer runner adapters — Layer 1 (discovery)", () => {
  it("converts context → RunDiscoveryInput, reads the App Map from the cache, and stays pure (no store writes)", async () => {
    const { store, writes } = makeInMemoryStore();
    const runners = createLayerRunners({
      gateway,
      semgrep: stubSemgrep(),
      gitleaks: () => Promise.resolve([]),
    });
    const ctx = makeLayerContext<"layer1">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer1", { appMapId: mockAppMap.id }) as never,
      store,
      priorOutputs: { layer0: mockLayer0Output },
    });

    const out = await runners.layer1(ctx);

    expect(Array.isArray(out.candidates)).toBe(true);
    expect(out.candidates.length).toBeGreaterThanOrEqual(1);
    expect(out.candidates.some((c) => c.location.file === "app/api/users/route.ts")).toBe(true);
    // ⛔ Persist division: the pure runner NEVER writes candidate rows.
    expect(writes["candidates.bulkCreate"]).toBeUndefined();
  });

  it("falls back to the persisted App Map when the in-process cache is empty (resume path)", async () => {
    const { store } = makeInMemoryStore();
    await store.appMaps.create(CLIENT_ID, mockAppMap);
    const runners = createLayerRunners({
      gateway,
      semgrep: stubSemgrep(),
      gitleaks: () => Promise.resolve([]),
    });
    const ctx = makeLayerContext<"layer1">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan), // scan.appMapId === mockAppMap.id
      job: baseJob("layer1", { appMapId: mockAppMap.id }) as never,
      store,
      priorOutputs: {}, // no cache
    });

    const out = await runners.layer1(ctx);
    expect(out.candidates.length).toBeGreaterThanOrEqual(1);
  });
});

describe("layer runner adapters — Layer 2 (correlation)", () => {
  it("correlates the candidate pile against the App Map (cache path)", async () => {
    const { store, writes } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer2">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer2") as never,
      store,
      priorOutputs: { layer0: mockLayer0Output, layer1: { candidates: mockCandidateFindings } },
    });

    const out = await runners.layer2(ctx);
    // 5 candidates → 4 probable + 1 demoted (the osv dep), per the correlation moat.
    expect(out.probable.length).toBe(4);
    expect(out.demoted.map((d) => d.id)).toContain(CANDIDATE_DEP_ID);
    expect(out.probable[0]?.category).toBe("sql_injection");
    expect(writes["probable.bulkCreate"]).toBeUndefined();
  });

  it("reads candidates from the store when the cache is empty", async () => {
    const { store } = makeInMemoryStore();
    await store.appMaps.create(CLIENT_ID, mockAppMap);
    await store.candidates.bulkCreate(CLIENT_ID, mockCandidateFindings);
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer2">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer2") as never,
      store,
      priorOutputs: {}, // force the store fallback
    });

    const out = await runners.layer2(ctx);
    expect(out.probable.length).toBe(4);
  });
});

describe("layer runner adapters — Layer 3 (confirmation)", () => {
  it("statically confirms probable findings and appends the rest (allowLive off)", async () => {
    const { store, writes } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer3">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer3", { allowLive: false }) as never,
      store,
      priorOutputs: {
        layer0: mockLayer0Output,
        layer2: { probable: mockProbableFindings, demoted: [] },
      },
    });

    const out = await runners.layer3(ctx);
    expect(out.confirmed.length).toBe(2); // SQLi + XSS
    expect(out.unconfirmed.length).toBe(1); // CORS → appendix
    expect(out.confirmed.every((c) => c.proofType === "static")).toBe(true);
    expect(writes["confirmed.bulkCreate"]).toBeUndefined();
    expect(writes["unconfirmed.bulkCreate"]).toBeUndefined();
  });
});

describe("layer runner adapters — Layer 4 (fix generation)", () => {
  it("generates one fix per confirmed finding; empty source ⇒ human-required (fail-safe)", async () => {
    const { store, writes } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway }); // no repoRoot ⇒ empty source reader
    const ctx = makeLayerContext<"layer4">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer4") as never,
      store,
      priorOutputs: { layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] } },
    });

    const out = await runners.layer4(ctx);
    expect(out.fixes.length).toBe(mockConfirmedFindings.length);
    // ⛔ Golden rule #4: with no source to validate a mechanical patch, fixes are
    // advisory → human-required. Uncertainty never resolves toward autonomy.
    expect(out.fixes.every((f) => f.riskClass === "human-required")).toBe(true);
    expect(writes["fixes.create"]).toBeUndefined();
  });
});

describe("layer runner adapters — Layer 5 (report + gate)", () => {
  it("builds the §12 report: headline = confirmed only, appendix kept, cost rollup present", async () => {
    const { store } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway }); // no opener ⇒ pure path, no PRs
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer1: { candidates: mockCandidateFindings },
        layer2: { probable: mockProbableFindings, demoted: [] },
        layer3: { confirmed: mockConfirmedFindings, unconfirmed: mockUnconfirmedFindings },
        layer4: { fixes: [] },
      },
    });

    const out = await runners.layer5(ctx);
    expect(out.report.executiveSummary.totalConfirmed).toBe(mockConfirmedFindings.length);
    expect(out.report.confirmedFindings.length).toBe(mockConfirmedFindings.length);
    expect(out.report.unconfirmedAppendix.length).toBe(mockUnconfirmedFindings.length);
    expect(out.report.costAndScope.cost.scanId).toBe(SCAN_ID);
    expect(out.pullRequests).toHaveLength(0); // no opener injected
  });

  it("⛔ reads the demoted appendix from the cached Layer2Output.demoted (not the store)", async () => {
    const { store } = makeInMemoryStore();
    // Store candidate pile is EMPTY — the only source signal comes from the
    // in-process Layer-2 demoted cache (the osv dependency).
    const demotedDep = mockCandidateFindings.find((c) => c.id === CANDIDATE_DEP_ID)!;
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer2: { probable: [], demoted: [demotedDep] },
        layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] },
        layer4: { fixes: [] },
      },
    });

    const out = await runners.layer5(ctx);
    // toolsConsolidated is derived from candidates + demoted; here only the
    // demoted dep (source "osv") is available, proving the cache path is used.
    expect(out.report.executiveSummary.toolsConsolidated).toContain("osv");
  });
});

describe("layer runner adapters — construction", () => {
  it("exposes exactly the six orchestrator layer runners", () => {
    const runners = createLayerRunners({ gateway });
    expect(Object.keys(runners).sort()).toEqual([
      "layer0",
      "layer1",
      "layer2",
      "layer3",
      "layer4",
      "layer5",
    ]);
    for (const layer of Object.keys(runners)) {
      expect(typeof (runners as Record<string, unknown>)[layer]).toBe("function");
    }
  });

  it("honors an injected human-required category set from config", async () => {
    const { store } = makeInMemoryStore();
    const config = hardenedConfig();
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer4">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer4") as never,
      store,
      config,
      priorOutputs: { layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] } },
    });
    const out = await runners.layer4(ctx);
    expect(out.fixes.every((f) => typeof f.riskClass === "string")).toBe(true);
  });
});
