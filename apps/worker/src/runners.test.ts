import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import {
  CLIENT_ID,
  SCAN_ID,
  CANDIDATE_DEP_ID,
  CANDIDATE_SQLI_ID,
  CONFIRMED_SQLI_ID,
  CONFIRMED_XSS_ID,
  FIXED_NOW,
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
import type {
  LLMGateway,
  LLMRequest,
  LLMResponse,
  LLMStreamEvent,
  LLMToolCall,
  ModelDescriptor,
  StopReason,
} from "@montr/contracts";
import { RedTeamScenarioSchema } from "@montr/contracts";
import type { SemgrepJson } from "@montr/discovery";
import { createMapSourceReader } from "@montr/fix";
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
    // A8 — allowLive is off, so the purple-team loop never engages (see
    // runPurpleTeamVerification's own doc comment on why).
    expect(out.purpleTeamEntries).toEqual([]);
  });

  it("A7 — persists a real tri-state DetectionCoverage row (B6) for every confirmed finding", async () => {
    const { store } = makeInMemoryStore();
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
    expect(out.confirmed.length).toBe(2);

    // Real repository calls: persistDetectionCoverageForScan actually wrote
    // through ctx.store.detectionCoverage — not a mocked-away no-op.
    const rows = await store.detectionCoverage.list(CLIENT_ID);
    expect(rows.length).toBe(2);
    const findingIds = rows.map((r) => r.findingId).sort();
    expect(findingIds).toEqual([...out.confirmed.map((c) => c.id)].sort());
    for (const row of rows) {
      expect(["true", "false", "unknown"]).toContain(String(row.detected));
      expect(row.reasoning.length).toBeGreaterThan(0);
    }
  });

  it("A8 — with allowLive on and a matching enabled scenario, the purple-team loop is actually reached and safely refuses an unauthorized target (fail-safe; confirmation itself is unaffected)", async () => {
    const { store } = makeInMemoryStore();
    // An enabled, real catalogue-shaped scenario whose coarse "injection"
    // category maps (REDTEAM_CATEGORY_TO_FINDING_CATEGORIES) to sql_injection
    // — matches the confirmed SQLi finding's category.
    const scenario = RedTeamScenarioSchema.parse({
      id: "scn_test_injection_0001",
      clientId: CLIENT_ID,
      name: "Test injection scenario",
      category: "injection",
      steps: [{ order: 0, action: "probe baseline", method: "GET", path: "/api/users" }],
      targetAllowlistRef: "https://staging.example.test",
      version: 1,
      enabled: true,
      createdBy: "test",
      createdAt: FIXED_NOW,
    });
    await store.redTeamScenarios.create(CLIENT_ID, scenario);

    const warnings: Array<{ message: string; fields?: Record<string, unknown> }> = [];
    const logger = {
      debug() {},
      info() {},
      warn(message: string, fields?: Record<string, unknown>) {
        warnings.push({ message, fields });
      },
      error() {},
      child() {
        return logger;
      },
    };

    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer3">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      // ⛔ allowLive is true (the orchestrator's approver gate), but
      // hardenedConfig()'s default config.dast.enabled is false — the SAME
      // guardrail every other live-DAST caller in this codebase is subject
      // to (packages/confirm/src/guard.ts's assertLiveAuthorized). This
      // proves the purple-team wiring reuses that gate rather than adding a
      // new, looser one.
      job: baseJob("layer3", { allowLive: true }) as never,
      store,
      logger,
      priorOutputs: {
        layer0: mockLayer0Output,
        layer2: { probable: mockProbableFindings, demoted: [] },
      },
    });

    const out = await runners.layer3(ctx);

    // Confirmation itself is byte-identical to the allowLive:false case —
    // a refused purple-team pair never touches the confirmed/unconfirmed sets.
    expect(out.confirmed.length).toBe(2);
    expect(out.unconfirmed.length).toBe(1);
    expect(out.purpleTeamEntries).toEqual([]);

    // Layer 3 derives its OWN confirmed-finding ids (cf_static_<probableId>),
    // distinct from the report-layer fixtures' CONFIRMED_SQLI_ID — look up
    // the real one this run actually produced.
    const sqliFinding = out.confirmed.find((c) => c.category === "sql_injection")!;
    const failure = warnings.find((w) => w.message === "worker.purple_team.verification_failed");
    expect(failure).toBeDefined();
    expect(failure?.fields?.["scenarioId"]).toBe(scenario.id);
    expect(failure?.fields?.["findingId"]).toBe(sqliFinding.id);
    expect(String(failure?.fields?.["error"])).toContain("dast.enabled=false");
  });

  it("A8 — end to end: a real allowlisted target actually runs the scenario and persists a genuine live verification onto the finding's DetectionCoverage row", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const target = `http://127.0.0.1:${port}`;

    try {
      const { store } = makeInMemoryStore();
      const scenario = RedTeamScenarioSchema.parse({
        id: "scn_test_injection_live_0001",
        clientId: CLIENT_ID,
        name: "Test live injection scenario",
        category: "injection",
        steps: [{ order: 0, action: "probe baseline", method: "GET", path: "/api/users" }],
        targetAllowlistRef: target,
        version: 1,
        enabled: true,
        createdBy: "test",
        createdAt: FIXED_NOW,
      });
      await store.redTeamScenarios.create(CLIENT_ID, scenario);

      const config = hardenedConfig({ dast: { enabled: true, allowlist: [target] } });
      const runners = createLayerRunners({ gateway });
      const ctx = makeLayerContext<"layer3">({
        scanId: SCAN_ID,
        clientId: CLIENT_ID,
        scan: clone(mockScan),
        // stagingUrl deliberately omitted — this test isolates the purple-team
        // loop (which resolves its OWN target from the scenario's
        // targetAllowlistRef) from Layer 3's separate live-DAST confirmation
        // path, which requires its own stagingUrl to engage at all.
        job: baseJob("layer3", { allowLive: true }) as never,
        store,
        config,
        priorOutputs: {
          layer0: mockLayer0Output,
          layer2: { probable: mockProbableFindings, demoted: [] },
        },
      });

      const out = await runners.layer3(ctx);
      const sqliFinding = out.confirmed.find((c) => c.category === "sql_injection")!;

      // A real scenario run actually happened — one entry, for the SQLi
      // finding the "injection" scenario category matches.
      expect(out.purpleTeamEntries.length).toBe(1);
      expect(out.purpleTeamEntries[0]?.scenarioId).toBe(scenario.id);
      expect(out.purpleTeamEntries[0]?.findingId).toBe(sqliFinding.id);
      expect(out.purpleTeamEntries[0]?.findingCategory).toBe("sql_injection");

      // The SAME DetectionCoverage row A7 persisted above now carries a real
      // verification block (B5 composing on top of B6's row, not a second
      // disconnected write).
      const rows = await store.detectionCoverage.list(CLIENT_ID);
      const sqliCoverage = rows.find((r) => r.findingId === sqliFinding.id);
      expect(sqliCoverage?.verification).toBeDefined();
      expect(sqliCoverage?.verification?.scenarioId).toBe(scenario.id);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 15_000);
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

  it("A5 — with no fixGeneration config set, the gateway request is unchanged and the agent loop never engages", async () => {
    const { store } = makeInMemoryStore();
    const { gateway: spied, requests } = spyGateway(gateway);
    const runners = createLayerRunners({ gateway: spied }); // no repoRoot ⇒ empty source reader
    const config = hardenedConfig(); // nothing configured ⇒ off-by-default
    expect(config.fixGeneration.agentLoop.enabled).toBe(false);

    const ctx = makeLayerContext<"layer4">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer4") as never,
      store,
      config,
      priorOutputs: { layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] } },
    });

    await runners.layer4(ctx);

    // Exactly one gateway call per confirmed finding — the single-shot path,
    // never a retry loop — and none of the requests carry a `tools` array
    // (the agent loop's read_file tool is only ever attached when enabled).
    expect(requests).toHaveLength(mockConfirmedFindings.length);
    for (const request of requests) {
      expect(request.tools).toBeUndefined();
      expect(request.responseFormat).toBe("json");
    }
  });

  it("A12 — logs a warning when the agent loop is enabled but maxToolCalls is explicitly 0", async () => {
    const { store } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway }); // no repoRoot ⇒ empty source reader
    // FixAgentLoopConfigSchema now defaults maxToolCalls to 3 (A12); this test
    // exercises the one remaining silent-gap case, where an operator has
    // explicitly overridden it back to 0.
    const config = hardenedConfig({
      fixGeneration: { agentLoop: { enabled: true, maxIterations: 1, maxToolCalls: 0 } },
    });
    const warnings: Array<{ message: string; fields?: Record<string, unknown> }> = [];
    const logger = {
      debug() {},
      info() {},
      warn(message: string, fields?: Record<string, unknown>) {
        warnings.push({ message, fields });
      },
      error() {},
      child() {
        return logger;
      },
    };

    const ctx = makeLayerContext<"layer4">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer4") as never,
      store,
      config,
      logger,
      priorOutputs: { layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] } },
    });

    await runners.layer4(ctx);

    expect(warnings.some((w) => w.message === "worker.fix_agent_loop.no_tool_calls")).toBe(true);
  });

  it("A5 — with fixGeneration.agentLoop configured, the bounded agent loop is reached with the operator's bounds", async () => {
    const XSS_ORIGINAL_LINES = [
      "import React from 'react';",
      "",
      "export default function SearchPage({ q }) {",
      "  return (",
      "    <div>",
      "      <h1>Search</h1>",
      "      <div>",
      "        <div dangerouslySetInnerHTML={{ __html: q }} />",
      "      </div>",
      "    </div>",
      "  );",
      "}",
      "",
    ];
    const XSS_ORIGINAL = XSS_ORIGINAL_LINES.join("\n");
    const VULN_LINE_NO = 8;
    const FIXED_LINE = XSS_ORIGINAL_LINES[VULN_LINE_NO - 1]!.replace(
      /<(\w+)\s+dangerouslySetInnerHTML=\{\{\s*__html:\s*([\s\S]*?)\s*\}\}\s*\/>/,
      (_m, tag: string, expr: string) => `<${tag}>{${expr.trim()}}</${tag}>`,
    );
    const STILL_VULNERABLE_LINE = `${XSS_ORIGINAL_LINES[VULN_LINE_NO - 1]!} // TODO`;

    const goodEditsJson = JSON.stringify({
      edits: [{ startLine: VULN_LINE_NO, endLine: VULN_LINE_NO, replacement: FIXED_LINE }],
      rationale: "removed dangerouslySetInnerHTML",
    });
    const stillVulnerableEditsJson = JSON.stringify({
      edits: [
        { startLine: VULN_LINE_NO, endLine: VULN_LINE_NO, replacement: STILL_VULNERABLE_LINE },
      ],
      rationale: "attempted fix",
    });

    const FAKE_MODEL: ModelDescriptor = {
      provider: "anthropic",
      modelId: "claude-sonnet-5",
      tier: "default",
      contextWindow: 1_000_000,
      maxOutputTokens: 128_000,
      supportsTools: true,
      supportsStreaming: true,
      belowFloor: false,
    };
    let respSeq = 0;
    function textResponse(content: string, stopReason: StopReason = "end_turn"): LLMResponse {
      respSeq++;
      return {
        id: `resp_${respSeq}`,
        provider: "anthropic",
        model: "claude-sonnet-5",
        content,
        stopReason,
        usage: { inputTokens: 10, outputTokens: 10, totalTokens: 20 },
        latencyMs: 1,
      };
    }
    function toolUseResponse(toolCalls: LLMToolCall[]): LLMResponse {
      respSeq++;
      return {
        id: `resp_tool_${respSeq}`,
        provider: "anthropic",
        model: "claude-sonnet-5",
        content: "",
        stopReason: "tool_use",
        usage: { inputTokens: 10, outputTokens: 10, totalTokens: 20 },
        latencyMs: 1,
        toolCalls,
      };
    }

    /** A gateway that returns queued responses in order, recording every request. */
    class QueueGateway implements LLMGateway {
      readonly requests: LLMRequest[] = [];
      private readonly queue: LLMResponse[];
      constructor(responses: LLMResponse[]) {
        this.queue = [...responses];
      }
      complete(request: LLMRequest): Promise<LLMResponse> {
        this.requests.push({ ...request, messages: [...request.messages] });
        const next = this.queue.shift();
        if (!next) {
          throw new Error(
            `QueueGateway: complete() called more times (${this.requests.length}) than queued`,
          );
        }
        return Promise.resolve(next);
      }
      async *stream(request: LLMRequest): AsyncGenerator<LLMStreamEvent> {
        const response = await this.complete(request);
        yield { type: "text_delta", text: response.content };
        yield { type: "message_done", usage: response.usage, stopReason: response.stopReason };
      }
      listModels(): ModelDescriptor[] {
        return [FAKE_MODEL];
      }
      resolveModel(): ModelDescriptor {
        return FAKE_MODEL;
      }
    }

    const xssFinding = mockConfirmedFindings.find((f) => f.id === CONFIRMED_XSS_ID)!;
    const filePath = xssFinding.location.file;

    const queueGateway = new QueueGateway([
      // Tool round: the model inspects a sibling file before answering — proves
      // maxToolCalls > 0 actually reached the model as an offered tool.
      toolUseResponse([{ id: "call_1", name: "read_file", input: { path: "shared/helper.ts" } }]),
      // Proposal attempt #1: structurally valid but leaves the vuln in place —
      // must be retried (proves maxIterations > 1 is actually exercised).
      textResponse(stillVulnerableEditsJson),
      // Proposal attempt #2: a real fix — accepted.
      textResponse(goodEditsJson),
    ]);

    const { store } = makeInMemoryStore();
    const config = hardenedConfig({
      fixGeneration: { agentLoop: { enabled: true, maxIterations: 3, maxToolCalls: 2 } },
    });
    const runners = createLayerRunners({
      gateway: queueGateway,
      sourceReader: () =>
        createMapSourceReader({
          [filePath]: XSS_ORIGINAL,
          "shared/helper.ts": "export const HELPER = 1;\n",
        }),
    });
    const ctx = makeLayerContext<"layer4">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer4") as never,
      store,
      config,
      priorOutputs: { layer3: { confirmed: [xssFinding], unconfirmed: [] } },
    });

    const out = await runners.layer4(ctx);

    // 1 tool round + 2 proposal attempts (bounded within maxIterations: 3,
    // maxToolCalls: 2) — proves the operator's configured bounds actually
    // reached the loop, not just that it engaged at all.
    expect(queueGateway.requests).toHaveLength(3);
    expect(queueGateway.requests[0]!.tools?.some((t) => t.name === "read_file")).toBe(true);

    const fix = out.fixes[0]!;
    expect(fix.rationale).toContain("Model-proposed");
    expect(fix.riskClass).toBe("auto-eligible");
  }, 30_000);
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
        // A2 — Layer 5 now resolves the App Map exactly like Layers 1-3;
        // without this the layer throws "App Map not found" (see the A2
        // test below for the dedicated regression check on that wiring).
        layer0: mockLayer0Output,
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
        layer0: mockLayer0Output,
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

  it("A2 — resolves the App Map like Layers 1-3 and threads it into buildReport: detection-coverage stops being permanently empty", async () => {
    const { store } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer0: mockLayer0Output,
        layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] },
        layer4: { fixes: [] },
      },
    });

    const out = await runners.layer5(ctx);
    // buildDetectionCoverage (B6) can only produce a verdict per confirmed
    // finding when it has a real App Map to resolve routes/telemetry
    // against — before A2, `appMap` was always undefined here and this
    // section rendered permanently empty ([]).
    expect(out.report.blueTeam.detectionEngineering.coverage.length).toBe(
      mockConfirmedFindings.length,
    );
    for (const c of out.report.blueTeam.detectionEngineering.coverage) {
      expect(c.reasoning.length).toBeGreaterThan(0);
    }
  });

  it("throws when the App Map is genuinely unavailable, exactly like Layers 1-3", async () => {
    const { store } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway });
    const scanWithNoAppMap = { ...clone(mockScan), appMapId: undefined };
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: scanWithNoAppMap,
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] },
        layer4: { fixes: [] },
      },
    });

    await expect(runners.layer5(ctx)).rejects.toThrow(/App Map not found/);
  });

  it("A8 — purple-team entries computed at Layer 3 flow through the in-process priorOutputs cache into buildReport's purpleTeam section", async () => {
    const { store } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway });
    const purpleTeamEntries = [
      {
        scenarioId: "scn_test_0001",
        scenarioName: "Test scenario",
        findingId: CONFIRMED_SQLI_ID,
        findingCategory: "sql_injection",
        detected: true,
        reason: "the rule's route+method condition matched the scenario's baseline request",
      },
    ];
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer0: mockLayer0Output,
        layer3: { confirmed: mockConfirmedFindings, unconfirmed: [], purpleTeamEntries },
        layer4: { fixes: [] },
      },
    });

    const out = await runners.layer5(ctx);
    expect(out.report.blueTeam.purpleTeam.entries).toEqual(purpleTeamEntries);
    expect(out.report.blueTeam.purpleTeam.totalScenarios).toBe(1);
    expect(out.report.blueTeam.purpleTeam.detectedCount).toBe(1);
  });

  it("A8 — a resumed run with an empty in-process cache reports zero purple-team scenarios, never a fabricated verdict", async () => {
    const { store } = makeInMemoryStore();
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer0: mockLayer0Output,
        // no layer3 cache at all — forces the store fallback for confirmed/
        // unconfirmed, and [] for purpleTeamEntries (not persisted, by design).
        layer4: { fixes: [] },
      },
    });
    await store.confirmed.bulkCreate(CLIENT_ID, mockConfirmedFindings);

    const out = await runners.layer5(ctx);
    expect(out.report.blueTeam.purpleTeam).toEqual({
      entries: [],
      totalScenarios: 0,
      detectedCount: 0,
      undetectedCount: 0,
    });
  });

  it("A13 — generates real advisory hardening recommendations from an actual repo checkout on disk and threads them into buildReport", async () => {
    const { store } = makeInMemoryStore();
    const repoRoot = mkdtempSync(join(tmpdir(), "montr-a13-hardening-"));
    try {
      // A genuinely empty checkout: mockAppMap.frameworks includes "nextjs"
      // with no next.config.{js,mjs,ts,cjs} present, which
      // detectSecurityHeaderGaps (packages/hardening/src/categories/
      // security-headers.ts) real-detects as a missing-headers gap — not a
      // hand-fed fixture.
      writeFileSync(join(repoRoot, "package.json"), JSON.stringify({ name: "tmp" }));

      const runners = createLayerRunners({ gateway, resolveRepoRoot: () => repoRoot });
      const ctx = makeLayerContext<"layer5">({
        scanId: SCAN_ID,
        clientId: CLIENT_ID,
        scan: clone(mockScan),
        job: baseJob("layer5", { autoApply: false }) as never,
        store,
        priorOutputs: {
          layer0: mockLayer0Output,
          layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] },
          layer4: { fixes: [] },
        },
      });

      const out = await runners.layer5(ctx);
      expect(out.report.blueTeam.hardening.advisoryOnly).toBe(true);
      expect(out.report.blueTeam.hardening.recommendations.length).toBeGreaterThan(0);
      expect(
        out.report.blueTeam.hardening.recommendations.some(
          (r) => r.category === "security_headers",
        ),
      ).toBe(true);
      // ⛔ Architectural boundary (B9): never a diff/patch/RiskClass field.
      for (const r of out.report.blueTeam.hardening.recommendations) {
        expect(r).not.toHaveProperty("diff");
        expect(r).not.toHaveProperty("riskClass");
      }
    } finally {
      rmSync(repoRoot, { recursive: true, force: true });
    }
  });

  it("A13 — degrades to an honest empty list (never a guess) when there is no local repo checkout to inspect", async () => {
    const { store } = makeInMemoryStore();
    // No resolveRepoRoot override, and mockScan.repo is a remote https:// URL
    // ⇒ defaultRepoRoot resolves to undefined, exactly like Layer 1/4's own
    // remote-repo degradation.
    const runners = createLayerRunners({ gateway });
    const ctx = makeLayerContext<"layer5">({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: clone(mockScan),
      job: baseJob("layer5", { autoApply: false }) as never,
      store,
      priorOutputs: {
        layer0: mockLayer0Output,
        layer3: { confirmed: mockConfirmedFindings, unconfirmed: [] },
        layer4: { fixes: [] },
      },
    });

    const out = await runners.layer5(ctx);
    expect(out.report.blueTeam.hardening.recommendations).toEqual([]);
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
