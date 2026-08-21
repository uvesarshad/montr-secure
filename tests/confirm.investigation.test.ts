import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AppMapSchema,
  ProbableFindingSchema,
  type AppMap,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type ModelDescriptor,
  type ModelTier,
  type ProbableFinding,
} from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import { CLIENT_ID, SCAN_ID, FIXED_NOW } from "@montr/fixtures";
import {
  confirmFindings,
  runInvestigation,
  attemptInvestigationConfirmation,
  runAdversarialVerification,
  gatherExecutableEvidence,
  SUBMIT_CONCLUSION_TOOL,
  type ConfirmInput,
  type ConfirmDeps,
  type TestRunner,
} from "@montr/confirm";

/**
 * E1 + E2 + E4 — the agentic investigation loop, the executable-evidence
 * gate, and the adversarial-majority panel. Every existing confirm test file
 * (confirm.static/live/guards/scenarios/callgraph) keeps passing unmodified —
 * this suite proves the NEW path is additive, opt-in, and fail-safe.
 */

const NOW = (): string => FIXED_NOW;
const ROUTE_ID = "route_orders_0001";
const HANDLER_PATH = "app/api/orders/[id]/route.ts";

/** A repo checkout containing a genuine IDOR: no ownership check on the queried order. */
async function writeVulnerableRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "montr-investigate-fixture-"));
  await mkdir(join(dir, "app/api/orders/[id]"), { recursive: true });
  await writeFile(
    join(dir, HANDLER_PATH),
    [
      "import { prisma } from '../../../../lib/db';",
      "",
      "export async function GET(req, { params }) {",
      "  const order = await prisma.order.findUnique({ where: { id: params.id } });",
      "  // NOTE: no check that order.userId === session.user.id — any authenticated",
      "  // user can read any other user's order by guessing/incrementing the id.",
      "  return Response.json(order);",
      "}",
    ].join("\n"),
    "utf8",
  );
  await writeFile(
    join(dir, "app/api/orders/ownership.existing.test.ts"),
    [
      "import { describe, it, expect } from 'vitest';",
      "// A REAL pre-existing test asserting orders are ownership-scoped.",
      "// It fails today because the handler above has no such check.",
      "describe('order ownership', () => {",
      "  it('does not return another user\\'s order', () => {",
      "    expect(false).toBe(true); // placeholder — the fake TestRunner supplies the real verdict in tests",
      "  });",
      "});",
    ].join("\n"),
    "utf8",
  );
  return dir;
}

function idorAppMap(): AppMap {
  return AppMapSchema.parse({
    id: "appmap_investigate_0001",
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: "https://example.internal/montr/orders-app",
    branch: "main",
    commitSha: "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
    createdAt: FIXED_NOW,
    languages: ["typescript"],
    frameworks: ["nextjs", "prisma"],
    routes: [
      {
        id: ROUTE_ID,
        path: "/api/orders/:id",
        method: "GET",
        authState: "authenticated",
        isApiRoute: true,
        handler: { file: HANDLER_PATH, line: 3 },
        referencedModels: [{ modelName: "Order", operations: ["read"] }],
      },
    ],
    ormModels: [
      {
        name: "Order",
        dataStore: "app_db",
        fields: [
          { name: "id", type: "Int", isId: true },
          { name: "userId", type: "Int" },
        ],
      },
    ],
    taintSources: [],
    taintSinks: [],
    taintFlows: [],
    stale: false,
    rebuildPolicy: "rebuild_on_stale_commit",
  });
}

function idorProbableFinding(): ProbableFinding {
  return ProbableFindingSchema.parse({
    id: "prob_idor_0001",
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    rootCauseId: "rc_idor_0001",
    category: "idor",
    mergedCandidateIds: [],
    reachabilityHypothesis:
      "any authenticated user can reach GET /api/orders/:id with an arbitrary id",
    exploitHypothesis: "incrementing the id parameter discloses other users' orders",
    exposure: "authed",
    routeId: ROUTE_ID,
    location: { file: HANDLER_PATH, line: 4 },
    reachabilityScore: 0.7,
    exposureScore: 0.6,
    impactScore: 0.6,
    rank: 1,
    createdAt: FIXED_NOW,
  });
}

function baseInput(overrides: Partial<ConfirmInput> = {}): ConfirmInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    appMap: idorAppMap(),
    probable: [idorProbableFinding()],
    allowLive: false,
    config: getHardenedDefaults(),
    ...overrides,
  };
}

const DESCRIPTOR: ModelDescriptor = {
  provider: "anthropic",
  modelId: "claude-opus-5",
  tier: "confirmation",
  contextWindow: 1_000_000,
  maxOutputTokens: 128_000,
  supportsTools: true,
  supportsStreaming: true,
  belowFloor: false,
};

function toolResponse(
  id: string,
  calls: Array<{ id: string; name: string; input: Record<string, unknown> }>,
): LLMResponse {
  return {
    id,
    provider: "anthropic",
    model: "claude-opus-5",
    content: "",
    stopReason: "tool_use",
    usage: { inputTokens: 50, outputTokens: 20, totalTokens: 70 },
    latencyMs: 1,
    toolCalls: calls,
  };
}

/**
 * Scripted fake gateway distinguishing investigation-loop calls (carry
 * `request.tools`) from E4 verifier calls (JSON, no tools). Investigation
 * responses are consumed IN ORDER; once exhausted the LAST one repeats
 * (used by the runaway-loop test to prove the hard structural cap, not this
 * fake's script length, is what halts the loop).
 */
class ScriptedGateway implements LLMGateway {
  readonly calls: LLMRequest[] = [];
  private investigationTurn = 0;

  constructor(
    private readonly investigationResponses: LLMResponse[],
    private readonly verifierContent: (request: LLMRequest, index: number) => string,
  ) {}

  complete(request: LLMRequest): Promise<LLMResponse> {
    this.calls.push(request);
    if (request.tools && request.tools.length > 0) {
      const idx = Math.min(this.investigationTurn, this.investigationResponses.length - 1);
      const template = this.investigationResponses[idx] as LLMResponse;
      this.investigationTurn++;
      return Promise.resolve({ ...template, id: `${template.id}_${this.investigationTurn}` });
    }
    const verifierIdx = this.calls.filter((c) => !c.tools || c.tools.length === 0).length - 1;
    const content = this.verifierContent(request, verifierIdx);
    return Promise.resolve({
      id: `ver_${verifierIdx}`,
      provider: "anthropic",
      model: "claude-opus-5",
      content,
      stopReason: "end_turn",
      usage: { inputTokens: 20, outputTokens: 10, totalTokens: 30 },
      latencyMs: 1,
    });
  }

  stream(): AsyncIterable<LLMStreamEvent> {
    throw new Error("stream() is not used by these tests");
  }
  listModels(): ModelDescriptor[] {
    return [DESCRIPTOR];
  }
  resolveModel(_t: ModelTier | string): ModelDescriptor {
    return DESCRIPTOR;
  }
}

/** All four E4 lenses vote confirm. */
function allConfirmVerifier(): (request: LLMRequest) => string {
  return () =>
    JSON.stringify({ confirm: true, rationale: "no ownership check guards this resource" });
}

const cleanupDirs: string[] = [];
afterEach(async () => {
  while (cleanupDirs.length > 0) {
    const dir = cleanupDirs.pop();
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
});

describe("E1 — agentic investigation loop actually reads files and calls tools", () => {
  it("read_file returns REAL content from the repo checkout, not a canned string", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);

    const gateway = new ScriptedGateway(
      [
        toolResponse("t1", [{ id: "c1", name: "list_routes", input: {} }]),
        toolResponse("t2", [{ id: "c2", name: "read_file", input: { path: HANDLER_PATH } }]),
        toolResponse("t3", [
          {
            id: "c3",
            name: SUBMIT_CONCLUSION_TOOL,
            input: {
              verdict: "confirmed_candidate",
              rationale: "prisma.order.findUnique has no ownership check against the session user.",
              ownershipCheckFound: false,
              existingTestFile: "app/api/orders/ownership.existing.test.ts",
              targetRouteId: ROUTE_ID,
            },
          },
        ]),
      ],
      allConfirmVerifier(),
    );

    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = { now: NOW, llm: gateway, investigation: { enabled: true } };
    const outcome = await runInvestigation(idorProbableFinding(), input, deps);

    expect(outcome.verdict).toBe("confirmed_candidate");
    expect(outcome.existingTestFile).toBe("app/api/orders/ownership.existing.test.ts");
    expect(outcome.toolCallCount).toBe(2); // list_routes + read_file (submit_conclusion is terminal, not counted)

    const readTurn = outcome.turns.find((t) => t.toolCalls.some((c) => c.name === "read_file"));
    const readResult = readTurn?.toolCalls.find((c) => c.name === "read_file")?.result ?? "";
    // Proves the tool executed a REAL filesystem read of the fixture we wrote to disk.
    expect(readResult).toContain("prisma.order.findUnique");
    expect(readResult).toContain("no check that order.userId");
  });

  it("without a repo checkout, read_file/grep degrade gracefully instead of throwing", async () => {
    const gateway = new ScriptedGateway(
      [
        toolResponse("t1", [{ id: "c1", name: "read_file", input: { path: HANDLER_PATH } }]),
        toolResponse("t2", [
          {
            id: "c2",
            name: SUBMIT_CONCLUSION_TOOL,
            input: { verdict: "inconclusive", rationale: "no repo access" },
          },
        ]),
      ],
      allConfirmVerifier(),
    );
    const input = baseInput(); // no repoRoot
    const deps: ConfirmDeps = { now: NOW, llm: gateway, investigation: { enabled: true } };
    const outcome = await runInvestigation(idorProbableFinding(), input, deps);
    expect(outcome.verdict).toBe("inconclusive");
    const readResult = outcome.turns[0]?.toolCalls[0]?.result ?? "";
    expect(readResult).toContain("no repo checkout available");
  });
});

describe("E1 — hard structural turn-budget cap halts a runaway loop", () => {
  it("never exceeds 8 investigation turns even when the model never submits a conclusion", async () => {
    // Only ONE scripted response, repeated forever by ScriptedGateway — proves
    // the LOOP's own hard ceiling stops it, not the length of this script.
    const gateway = new ScriptedGateway(
      [toolResponse("loop", [{ id: "cX", name: "list_routes", input: {} }])],
      allConfirmVerifier(),
    );
    const input = baseInput();
    // maxTurns deliberately set ABOVE the hard ceiling to prove it is clamped.
    const deps: ConfirmDeps = {
      now: NOW,
      llm: gateway,
      investigation: { enabled: true, maxTurns: 1000 },
    };
    const outcome = await runInvestigation(idorProbableFinding(), input, deps);

    expect(outcome.haltedByBudget).toBe(true);
    expect(outcome.verdict).toBe("inconclusive"); // budget exhaustion is NEVER confirmed
    expect(outcome.turnsUsed).toBe(8);
    expect(gateway.calls.length).toBe(8);
  });
});

describe("E10 — emitProgress narrates the investigation loop, additively", () => {
  /** The same 3-turn scripted scenario used by the "actually reads files" test above. */
  function scriptedScenario(): ScriptedGateway {
    return new ScriptedGateway(
      [
        toolResponse("t1", [{ id: "c1", name: "list_routes", input: {} }]),
        toolResponse("t2", [{ id: "c2", name: "read_file", input: { path: HANDLER_PATH } }]),
        toolResponse("t3", [
          {
            id: "c3",
            name: SUBMIT_CONCLUSION_TOOL,
            input: {
              verdict: "confirmed_candidate",
              rationale: "prisma.order.findUnique has no ownership check against the session user.",
              ownershipCheckFound: false,
              existingTestFile: "app/api/orders/ownership.existing.test.ts",
              targetRouteId: ROUTE_ID,
            },
          },
        ]),
      ],
      allConfirmVerifier(),
    );
  }

  it("is called exactly once per investigation turn, with a sensible phase/pct/message derived from the actual tool call", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);

    const progressCalls: Array<{ phase: string; pct: number; message?: string }> = [];
    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = {
      now: NOW,
      llm: scriptedScenario(),
      investigation: { enabled: true },
      emitProgress: (phase, pct, message) => {
        progressCalls.push({ phase, pct, message });
      },
    };

    const outcome = await runInvestigation(idorProbableFinding(), input, deps);

    expect(outcome.verdict).toBe("confirmed_candidate");
    expect(outcome.turnsUsed).toBe(3);
    // Exactly one emitProgress call per investigation turn (3 turns used).
    expect(progressCalls.length).toBe(3);

    for (const call of progressCalls) {
      expect(call.phase).toBe("investigating");
      expect(call.pct).toBeGreaterThan(0);
      expect(call.pct).toBeLessThanOrEqual(100);
    }
    // pct climbs monotonically toward completion as turns advance.
    expect(progressCalls[0]?.pct).toBeLessThanOrEqual(progressCalls[1]?.pct ?? 0);
    expect(progressCalls[1]?.pct).toBeLessThanOrEqual(progressCalls[2]?.pct ?? 0);

    // Messages are derived from the REAL tool call each turn made, not a generic placeholder.
    expect(progressCalls[0]?.message).toBe("Listing App Map routes...");
    expect(progressCalls[1]?.message).toBe(`Reading ${HANDLER_PATH}...`);
    expect(progressCalls[2]?.message).toBe(
      "Submitting investigation verdict (confirmed_candidate)...",
    );
    // The final call reflects the loop's completion.
    expect(progressCalls[2]?.pct).toBe(100);
  });

  it("a throwing emitProgress callback never breaks the investigation loop (best-effort telemetry)", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);

    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = {
      now: NOW,
      llm: scriptedScenario(),
      investigation: { enabled: true },
      emitProgress: () => {
        throw new Error("boom — a broken progress consumer");
      },
    };

    const outcome = await runInvestigation(idorProbableFinding(), input, deps);
    expect(outcome.verdict).toBe("confirmed_candidate");
    expect(outcome.existingTestFile).toBe("app/api/orders/ownership.existing.test.ts");
  });

  it("REGRESSION: omitting emitProgress leaves the investigation loop's outcome byte-identical to before this change", async () => {
    const repoRootWith = await writeVulnerableRepo();
    const repoRootWithout = await writeVulnerableRepo();
    cleanupDirs.push(repoRootWith, repoRootWithout);

    const outcomeWithoutCallback = await runInvestigation(
      idorProbableFinding(),
      baseInput({ repoRoot: repoRootWithout }),
      { now: NOW, llm: scriptedScenario(), investigation: { enabled: true } }, // no emitProgress
    );

    const outcomeWithCallback = await runInvestigation(
      idorProbableFinding(),
      baseInput({ repoRoot: repoRootWith }),
      {
        now: NOW,
        llm: scriptedScenario(),
        investigation: { enabled: true },
        emitProgress: () => undefined,
      },
    );

    expect(outcomeWithoutCallback.verdict).toBe(outcomeWithCallback.verdict);
    expect(outcomeWithoutCallback.rationale).toBe(outcomeWithCallback.rationale);
    expect(outcomeWithoutCallback.existingTestFile).toBe(outcomeWithCallback.existingTestFile);
    expect(outcomeWithoutCallback.turnsUsed).toBe(outcomeWithCallback.turnsUsed);
    expect(outcomeWithoutCallback.toolCallCount).toBe(outcomeWithCallback.toolCallCount);
    expect(outcomeWithoutCallback.haltedByBudget).toBe(outcomeWithCallback.haltedByBudget);
    expect(outcomeWithoutCallback.turns).toEqual(outcomeWithCallback.turns);
  });
});

describe("E1/E2/E4 wired into confirmFindings — additive, opt-in, and only confirms with full proof", () => {
  it("metadata-only confirmation (investigation disabled, the default) leaves an IDOR finding unconfirmed", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);
    // A gateway that WOULD happily confirm anything if ever asked — proves the
    // miss below is because investigation never ran, not because it refused.
    const gateway = new ScriptedGateway(
      [
        toolResponse("unused", [
          {
            id: "c1",
            name: SUBMIT_CONCLUSION_TOOL,
            input: { verdict: "confirmed_candidate", rationale: "x" },
          },
        ]),
      ],
      allConfirmVerifier(),
    );
    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = { now: NOW, llm: gateway }; // investigation NOT set — off by default
    const out = await confirmFindings(input, deps);

    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
    expect(out.unconfirmed[0]?.category).toBe("idor");
    expect(gateway.calls).toHaveLength(0); // idor has no static data-flow path, so nothing calls the LLM at all
  });

  it("full E1+E2+E4 pipeline confirms the SAME IDOR finding when explicitly enabled with real evidence and adversarial majority", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);
    const gateway = new ScriptedGateway(
      [
        toolResponse("t1", [{ id: "c1", name: "list_routes", input: {} }]),
        toolResponse("t2", [{ id: "c2", name: "read_file", input: { path: HANDLER_PATH } }]),
        toolResponse("t3", [
          {
            id: "c3",
            name: SUBMIT_CONCLUSION_TOOL,
            input: {
              verdict: "confirmed_candidate",
              rationale:
                "no ownership check on the Order lookup — any authenticated user can read any order.",
              ownershipCheckFound: false,
              existingTestFile: "app/api/orders/ownership.existing.test.ts",
              targetRouteId: ROUTE_ID,
            },
          },
        ]),
      ],
      allConfirmVerifier(),
    );
    const testRunner: TestRunner = {
      run: (_repoRoot, testFile) =>
        Promise.resolve({
          ran: true,
          passed: false,
          summary: `existing test ${testFile} FAILED — order returned without an ownership check`,
        }),
    };
    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = {
      now: NOW,
      llm: gateway,
      testRunner,
      investigation: { enabled: true, maxTurns: 6, verifierCount: 4 },
    };
    const out = await confirmFindings(input, deps);

    expect(out.unconfirmed).toHaveLength(0);
    expect(out.confirmed).toHaveLength(1);
    const confirmed = out.confirmed[0];
    expect(confirmed?.category).toBe("idor");
    expect(confirmed?.proofType).toBe("static");
    if (confirmed?.proofArtifact.kind !== "static") throw new Error("expected static proof");
    expect(confirmed.proofArtifact.argument).toMatch(/Agentic investigation proof/);
    expect(confirmed.proofArtifact.argument).toMatch(/4\/4 confirmed/);
    // 3 investigation turns + 4 verifier calls.
    expect(gateway.calls).toHaveLength(7);
  });
});

describe("E2 — unproven proposals never reach confirmed (executable-evidence gate)", () => {
  it("a confirmed_candidate verdict with NO existing test file stays unconfirmed", async () => {
    // No `existingTestFile` supplied — mirrors an investigation outcome that
    // never named a test (the pipeline never even attempts to run anything).
    const evidence = await gatherExecutableEvidence({ repoRoot: "/tmp/does-not-matter" });
    expect(evidence).toBeUndefined();
  });

  it("a named existing test that PASSES is not evidence (it doesn't demonstrate the flaw)", async () => {
    const testRunner: TestRunner = {
      run: () => Promise.resolve({ ran: true, passed: true, summary: "passed" }),
    };
    const evidence = await gatherExecutableEvidence({
      repoRoot: "/tmp/does-not-matter",
      existingTestFile: "some.test.ts",
      testRunner,
    });
    expect(evidence).toBeUndefined();
  });

  it("attemptInvestigationConfirmation returns undefined end-to-end when no evidence is found, even though the model concluded confirmed_candidate", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);
    const gateway = new ScriptedGateway(
      [
        toolResponse("t1", [
          {
            id: "c1",
            name: SUBMIT_CONCLUSION_TOOL,
            // No existingTestFile named — the model's opinion alone.
            input: { verdict: "confirmed_candidate", rationale: "looks unguarded to me" },
          },
        ]),
      ],
      allConfirmVerifier(),
    );
    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = { now: NOW, llm: gateway, investigation: { enabled: true } };
    const result = await attemptInvestigationConfirmation(
      idorProbableFinding(),
      input,
      deps,
      undefined,
    );
    expect(result).toBeUndefined();
    // Only the one investigation call happened — E4 verifiers never ran because E2's gate rejected first.
    expect(gateway.calls).toHaveLength(1);
  });
});

describe("E4 — adversarial majority (disagreement correctly does NOT confirm)", () => {
  it("requires a strict majority (3/4); a 2/4 split does not confirm", async () => {
    let call = 0;
    const gateway = new ScriptedGateway([], (_req) => {
      // exploitability, reachability confirm; business_impact, refutation reject.
      const confirm = call < 2;
      call++;
      return JSON.stringify({ confirm, rationale: confirm ? "supports it" : "not convinced" });
    });
    const input = baseInput();
    const deps: ConfirmDeps = { now: NOW, llm: gateway };
    const outcome = await runAdversarialVerification(
      deps,
      input,
      {
        id: "prob_idor_0001",
        category: "idor",
        exposure: "authed",
        location: { file: HANDLER_PATH, line: 4 },
      },
      "investigator rationale",
      "evidence summary",
    );
    expect(outcome).toBeDefined();
    expect(outcome?.confirmVotes).toBe(2);
    expect(outcome?.totalVerifiers).toBe(4);
    expect(outcome?.requiredVotes).toBe(3);
    expect(outcome?.confirmed).toBe(false);
  });

  it("a 3/4 majority DOES confirm", async () => {
    let call = 0;
    const gateway = new ScriptedGateway([], () => {
      const confirm = call < 3;
      call++;
      return JSON.stringify({ confirm, rationale: "x" });
    });
    const input = baseInput();
    const deps: ConfirmDeps = { now: NOW, llm: gateway };
    const outcome = await runAdversarialVerification(
      deps,
      input,
      {
        id: "prob_idor_0001",
        category: "idor",
        exposure: "authed",
        location: { file: HANDLER_PATH, line: 4 },
      },
      "investigator rationale",
      "evidence summary",
    );
    expect(outcome?.confirmed).toBe(true);
    expect(outcome?.confirmVotes).toBe(3);
  });

  it("a verifier call that errors counts as a reject vote, never a silent confirm", async () => {
    const gateway: LLMGateway = {
      complete: () => Promise.reject(new Error("provider timeout")),
      stream: () => {
        throw new Error("unused");
      },
      listModels: () => [DESCRIPTOR],
      resolveModel: () => DESCRIPTOR,
    };
    const input = baseInput();
    const deps: ConfirmDeps = { now: NOW, llm: gateway };
    const outcome = await runAdversarialVerification(
      deps,
      input,
      {
        id: "prob_idor_0001",
        category: "idor",
        exposure: "authed",
        location: { file: HANDLER_PATH, line: 4 },
      },
      "investigator rationale",
      "evidence summary",
    );
    expect(outcome?.confirmVotes).toBe(0);
    expect(outcome?.confirmed).toBe(false);
    expect(outcome?.verdicts.every((v) => v.errored)).toBe(true);
  });

  it("returns undefined (never confirms) when no LLM gateway is configured", async () => {
    const input = baseInput();
    const outcome = await runAdversarialVerification(
      {},
      input,
      {
        id: "prob_idor_0001",
        category: "idor",
        exposure: "authed",
        location: { file: HANDLER_PATH, line: 4 },
      },
      "r",
      "e",
    );
    expect(outcome).toBeUndefined();
  });

  it("end-to-end: investigation + evidence succeed but a 2/4 verifier split still leaves the finding unconfirmed", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);
    let verifierCall = 0;
    const gateway = new ScriptedGateway(
      [
        toolResponse("t1", [
          {
            id: "c1",
            name: SUBMIT_CONCLUSION_TOOL,
            input: {
              verdict: "confirmed_candidate",
              rationale: "no ownership check",
              existingTestFile: "app/api/orders/ownership.existing.test.ts",
            },
          },
        ]),
      ],
      () => {
        const confirm = verifierCall < 1; // only 1/4 confirm — well below majority
        verifierCall++;
        return JSON.stringify({ confirm, rationale: "split panel" });
      },
    );
    const testRunner: TestRunner = {
      run: () => Promise.resolve({ ran: true, passed: false, summary: "failed as expected" }),
    };
    const input = baseInput({ repoRoot });
    const deps: ConfirmDeps = {
      now: NOW,
      llm: gateway,
      testRunner,
      investigation: { enabled: true },
    };
    const out = await confirmFindings(input, deps);

    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
  });
});
