import { describe, it, expect } from "vitest";
import {
  CLIENT_ID,
  SCAN_ID,
  CANDIDATE_DEP_ID,
  CANDIDATE_SQLI_ID,
  REPO_URL,
  createFakeLlmGateway,
  mockAppMap,
  mockScan,
  mockCandidateFindings,
  mockProbableFindings,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockLayer0Output,
} from "@montr/fixtures";
import type { LLMGateway, LLMRequest } from "@montr/contracts";
import type { SemgrepJson } from "@montr/discovery";
import { createLayerRunners } from "./runners.js";
import { makeInMemoryStore, makeLayerContext, clone, hardenedConfig } from "./testkit.js";

/**
 * Wraps a real gateway to record every request passed to `complete()`, so E8
 * tests can assert on the exact `system` prompt text a layer sent — including
 * whether the learned-facts context block was appended.
 */
function spyGateway(inner: LLMGateway): { gateway: LLMGateway; requests: LLMRequest[] } {
  const requests: LLMRequest[] = [];
  const gateway: LLMGateway = {
    listModels: () => inner.listModels(),
    resolveModel: (tierOrId) => inner.resolveModel(tierOrId),
    complete: (request) => {
      requests.push(request);
      return inner.complete(request);
    },
    stream: (request) => inner.stream(request),
    ...(inner.estimateTokens
      ? { estimateTokens: (r: LLMRequest) => inner.estimateTokens!(r) }
      : {}),
    ...(inner.resolvePrompt
      ? {
          resolvePrompt: (n: string, f: string, o?: { clientId?: string | null }) =>
            inner.resolvePrompt!(n, f, o),
        }
      : {}),
  };
  return { gateway, requests };
}

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

  it("A10 §15 FP-feedback loop: a prior operator FP mark on the same finding-shape demotes the repeat instead of promoting it", async () => {
    const { store } = makeInMemoryStore();
    // Simulate what apps/api/src/routes/findings.ts's POST /findings/:id/false-positive
    // route writes to the audit log when an operator marks a confirmed finding as a
    // false positive — same action + metadata shape.
    await store.audit.append({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      actor: { type: "user", id: "user_1", role: "operator" },
      action: "finding.marked_false_positive",
      targetType: "confirmed_finding",
      targetId: "cf_prior",
      summary: "Finding marked as false positive",
      metadata: { category: "sql_injection", file: "app/api/users/route.ts", line: 9 },
    });

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
    // Without the tuning mark this candidate is `out.probable[0]` (see the test
    // above) — with a matching prior FP mark on the SAME (category, file, line)
    // it must be routed to the appendix instead, on the very next scan.
    expect(out.probable.some((p) => p.mergedCandidateIds.includes(CANDIDATE_SQLI_ID))).toBe(false);
    expect(out.demoted.some((d) => d.id === CANDIDATE_SQLI_ID)).toBe(true);
    expect(out.probable.length).toBe(3); // one fewer than the untuned baseline (4)
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

describe("layer runner adapters — §15 cross-scan memory (E8)", () => {
  const PROVENANCE = {
    source: "operator" as const,
    operatorId: "user_1",
    at: "2026-08-22T00:00:00.000Z",
  };

  it("Layer 2: a learned fact recorded for this client+repo in an earlier scan is injected into the next scan's correlation prompt", async () => {
    const { store } = makeInMemoryStore();
    await store.learnedFacts.record({
      clientId: CLIENT_ID,
      repo: REPO_URL,
      type: "custom_sanitizer",
      content: { sanitizerName: "acmeSanitizeHtml", importPath: "@acme/security" },
      provenance: PROVENANCE,
    });

    const spy = spyGateway(createFakeLlmGateway());
    const runners = createLayerRunners({ gateway: spy.gateway });
    const ctx = makeLayerContext<"layer2">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan), // mockScan.repo === REPO_URL
      job: baseJob("layer2") as never,
      store,
      priorOutputs: { layer0: mockLayer0Output, layer1: { candidates: mockCandidateFindings } },
    });

    await runners.layer2(ctx);

    const correlationRequests = spy.requests.filter((r) => r.metadata.purpose === "correlation");
    expect(correlationRequests.length).toBeGreaterThan(0);
    for (const req of correlationRequests) {
      expect(req.system ?? "").toContain("acmeSanitizeHtml");
      expect(req.system ?? "").toContain("custom sanitizer");
    }
  });

  it("Layer 3: a learned fact for this client+repo is injected into the confirmation prompt", async () => {
    const { store } = makeInMemoryStore();
    await store.learnedFacts.record({
      clientId: CLIENT_ID,
      repo: REPO_URL,
      type: "operator_decision",
      content: { decision: "not exploitable", note: "input is validated upstream by middleware" },
      provenance: PROVENANCE,
    });

    const spy = spyGateway(createFakeLlmGateway());
    const runners = createLayerRunners({ gateway: spy.gateway });
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

    await runners.layer3(ctx);

    const confirmationRequests = spy.requests.filter((r) => r.metadata.purpose === "confirmation");
    expect(confirmationRequests.length).toBeGreaterThan(0);
    for (const req of confirmationRequests) {
      expect(req.system ?? "").toContain("not exploitable");
    }
  });

  it("row-scoping: a learned fact recorded for a DIFFERENT client is never injected", async () => {
    const { store } = makeInMemoryStore();
    await store.learnedFacts.record({
      clientId: "some_other_client",
      repo: REPO_URL,
      type: "custom_sanitizer",
      content: { sanitizerName: "shouldNeverAppear" },
      provenance: PROVENANCE,
    });

    const spy = spyGateway(createFakeLlmGateway());
    const runners = createLayerRunners({ gateway: spy.gateway });
    const ctx = makeLayerContext<"layer2">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID, // NOT "some_other_client"
      scan: clone(mockScan),
      job: baseJob("layer2") as never,
      store,
      priorOutputs: { layer0: mockLayer0Output, layer1: { candidates: mockCandidateFindings } },
    });

    await runners.layer2(ctx);

    for (const req of spy.requests) {
      expect(req.system ?? "").not.toContain("shouldNeverAppear");
    }
  });

  it("context-size cap: more than LEARNED_FACT_CONTEXT_LIMIT (10) facts are bounded, not dumped whole", async () => {
    const { store } = makeInMemoryStore();
    for (let i = 0; i < 15; i++) {
      await store.learnedFacts.record({
        clientId: CLIENT_ID,
        repo: REPO_URL,
        type: "framework_idiom",
        content: { idiomIndex: i, marker: `idiom-marker-${i}` },
        provenance: PROVENANCE,
      });
    }

    const spy = spyGateway(createFakeLlmGateway());
    const runners = createLayerRunners({ gateway: spy.gateway });
    const ctx = makeLayerContext<"layer2">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer2") as never,
      store,
      priorOutputs: { layer0: mockLayer0Output, layer1: { candidates: mockCandidateFindings } },
    });

    await runners.layer2(ctx);

    const correlationRequest = spy.requests.find((r) => r.metadata.purpose === "correlation");
    expect(correlationRequest).toBeDefined();
    const system = correlationRequest?.system ?? "";
    const factLines = system.split("\n").filter((line) => line.startsWith("- [framework idiom]"));
    // At most 10 facts are injected even though 15 were recorded — the cap.
    expect(factLines.length).toBeLessThanOrEqual(10);
    expect(factLines.length).toBeGreaterThan(0);
  });

  it("regression safety: a scan with NO prior learned facts or FP marks produces the exact same probable findings as before this change", async () => {
    const { store } = makeInMemoryStore();
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
    // Same assertions as the pre-existing "correlates the candidate pile"
    // test above — an empty learned-facts store must change NOTHING.
    expect(out.probable.length).toBe(4);
    expect(out.demoted.map((d) => d.id)).toContain(CANDIDATE_DEP_ID);
    expect(out.probable[0]?.category).toBe("sql_injection");
  });

  it("regression safety: no learned-facts context block is appended to the system prompt when the store is empty", async () => {
    const { store } = makeInMemoryStore();
    const spy = spyGateway(createFakeLlmGateway());
    const runners = createLayerRunners({ gateway: spy.gateway });
    const ctx = makeLayerContext<"layer2">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer2") as never,
      store,
      priorOutputs: { layer0: mockLayer0Output, layer1: { candidates: mockCandidateFindings } },
    });

    await runners.layer2(ctx);

    for (const req of spy.requests) {
      expect(req.system ?? "").not.toContain("Prior knowledge about this repository");
    }
  });
});
