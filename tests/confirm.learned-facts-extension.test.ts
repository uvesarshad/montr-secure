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
  SUBMIT_CONCLUSION_TOOL,
  type ConfirmInput,
  type ConfirmDeps,
  type TestRunner,
  type PriorConfirmedShapes,
} from "@montr/confirm";

/**
 * E8 extension (2026-09-12 red/blue agentic-posture audit's "extend
 * cross-scan learning beyond false positives" suggested enhancement):
 *
 *   1. `ConfirmDeps.learnedSanitizers` — a repo-scoped, operator-confirmed
 *      custom sanitizer name is merged into `static.ts`'s heuristics, so a
 *      sink it neutralizes reads as sanitized WITHOUT ever calling the
 *      confirmation-tier LLM (real spend avoidance, not just a claim).
 *   2. `ConfirmDeps.priorConfirmedShapes` — a repo-scoped confirmed-exploit-
 *      shape prior can WIDEN which findings get a shot at the E1/E2/E4
 *      investigation loop when their category falls outside the configured
 *      severity scope, demonstrating a concrete SCAN-OVER-SCAN recall
 *      improvement while every existing proof gate (E1 verdict, E2 real
 *      executable evidence, E4 adversarial majority) still applies in full.
 *
 * Both seams are additive/opt-in: every existing confirm.* suite (static,
 * live, investigation, guards, scenarios) keeps passing unmodified.
 */

const NOW = (): string => FIXED_NOW;

/** Counting LLM spy — proves whether/how many times the LLM was actually called. */
class SpyGateway implements LLMGateway {
  readonly calls: LLMRequest[] = [];
  constructor(private readonly inner: LLMGateway) {}
  complete(req: LLMRequest): Promise<LLMResponse> {
    this.calls.push(req);
    return this.inner.complete(req);
  }
  stream(req: LLMRequest): AsyncIterable<LLMStreamEvent> {
    return this.inner.stream(req);
  }
  listModels(): ModelDescriptor[] {
    return this.inner.listModels();
  }
  resolveModel(t: ModelTier | string): ModelDescriptor {
    return this.inner.resolveModel(t);
  }
}

/** Always vetoes (confirmed: false) — irrelevant to these tests, since what's
 * measured is whether the LLM was called AT ALL, not its verdict. */
const vetoingGateway: LLMGateway = {
  complete: () =>
    Promise.resolve({
      id: "veto_1",
      provider: "anthropic",
      model: "claude-opus-5",
      content: JSON.stringify({ confirmed: false, argument: "insufficient evidence" }),
      stopReason: "end_turn",
      usage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 },
      latencyMs: 1,
    }),
  stream: () => {
    throw new Error("not used");
  },
  listModels: () => [],
  resolveModel: (t) => ({
    provider: "anthropic",
    modelId: String(t),
    tier: "confirmation",
    contextWindow: 200_000,
    maxOutputTokens: 8192,
    supportsTools: false,
    supportsStreaming: false,
    belowFloor: false,
  }),
};

const CMD_ROUTE_ID = "route_admin_0001";
const CMD_HANDLER_PATH = "app/api/admin/run/route.ts";

/**
 * A command_injection sink whose description names a REPO-SPECIFIC wrapper
 * ("acmeclean") that is not, and should not be, part of the base/per-language
 * SAFE_MARKERS vocabulary (taxonomy.ts) — deliberately phrased to avoid every
 * existing UNSAFE_MARKERS/SAFE_MARKERS substring, so the base assessment
 * falls through to the raw-sink-kind fallback (dangerous: true) absent a
 * learned marker.
 */
function sanitizerAppMap(): AppMap {
  return AppMapSchema.parse({
    id: "appmap_sanitizer_0001",
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: "https://example.internal/montr/admin-app",
    branch: "main",
    commitSha: "c1c2c3c4c5c6c7c8c9c0d1d2d3d4d5d6d7d8d9d0",
    createdAt: FIXED_NOW,
    languages: ["typescript"],
    frameworks: ["nextjs"],
    routes: [
      {
        id: CMD_ROUTE_ID,
        path: "/api/admin/run",
        method: "POST",
        authState: "role_gated",
        isApiRoute: true,
        handler: { file: CMD_HANDLER_PATH, line: 3 },
      },
    ],
    taintSources: [
      {
        kind: "request_body",
        location: { file: CMD_HANDLER_PATH, line: 4 },
        description: "req.body.cmd",
        routeId: CMD_ROUTE_ID,
      },
    ],
    taintSinks: [
      {
        kind: "command_exec",
        location: { file: CMD_HANDLER_PATH, line: 6 },
        description: "argument is passed through the acmeclean utility before shelling out",
      },
    ],
    stale: false,
    rebuildPolicy: "rebuild_on_stale_commit",
  });
}

function sanitizerFinding(): ProbableFinding {
  return ProbableFindingSchema.parse({
    id: "prob_cmdi_0001",
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    rootCauseId: "rc_cmdi_0001",
    category: "command_injection",
    mergedCandidateIds: [],
    reachabilityHypothesis: "req.body.cmd flows into a shell invocation.",
    exploitHypothesis: "an arbitrary OS command could be injected via cmd.",
    exposure: "authed",
    routeId: CMD_ROUTE_ID,
    location: { file: CMD_HANDLER_PATH, line: 6 },
    reachabilityScore: 0.7,
    exposureScore: 0.5,
    impactScore: 0.8,
    rank: 1,
    createdAt: FIXED_NOW,
  });
}

function sanitizerInput(overrides: Partial<ConfirmInput> = {}): ConfirmInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    appMap: sanitizerAppMap(),
    probable: [sanitizerFinding()],
    allowLive: false,
    config: getHardenedDefaults(),
    ...overrides,
  };
}

describe("E8 extension — custom_sanitizer learned facts reduce false positives AND LLM spend", () => {
  it("without a learned sanitizer marker: the sink reads as dangerous and the confirmation LLM IS called", async () => {
    const spy = new SpyGateway(vetoingGateway);
    const out = await confirmFindings(sanitizerInput(), { now: NOW, llm: spy });

    // No learned marker recognizes "acmeclean" — falls through to the
    // raw-sink-kind fallback (command_exec, no sanitizer on path).
    expect(spy.calls).toHaveLength(1);
    // The LLM vetoed (fail-safe) — demoted, matching today's unchanged behavior.
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed[0]?.unconfirmedReason).toMatch(/NOT exploitable on review/i);
  });

  it("with the SAME repo's learned 'acmeclean' sanitizer marker: the sink resolves sanitized BEFORE the LLM is ever called", async () => {
    const spy = new SpyGateway(vetoingGateway);
    const out = await confirmFindings(sanitizerInput(), {
      now: NOW,
      llm: spy,
      learnedSanitizers: ["acmeclean"],
    });

    // Zero LLM calls — real spend avoidance, not merely a faster veto.
    expect(spy.calls).toHaveLength(0);
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
    expect(out.unconfirmed[0]?.unconfirmedReason).toMatch(/sanitiz/i);
    expect(out.unconfirmed[0]?.unconfirmedReason).toMatch(/acmeclean/);
  });

  it("a short/near-empty learned marker is ignored (guards against an over-broad match)", async () => {
    const spy = new SpyGateway(vetoingGateway);
    const out = await confirmFindings(sanitizerInput(), {
      now: NOW,
      llm: spy,
      learnedSanitizers: ["", "  ", "ab"], // all below the 3-char floor
    });
    expect(spy.calls).toHaveLength(1); // unchanged — no marker was honored
    expect(out.confirmed).toHaveLength(0);
  });
});

/* --------------------------------------------------------------------------- *
 * confirmed_exploit_shape — two-scan recall-improvement demonstration.
 * --------------------------------------------------------------------------- */

const ROUTE_ID = "route_orders_0001";
const HANDLER_PATH = "app/api/orders/[id]/route.ts";

async function writeVulnerableRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "montr-prior-shape-fixture-"));
  await mkdir(join(dir, "app/api/orders/[id]"), { recursive: true });
  await writeFile(
    join(dir, HANDLER_PATH),
    [
      "import { prisma } from '../../../../lib/db';",
      "",
      "export async function GET(req, { params }) {",
      "  const order = await prisma.order.findUnique({ where: { id: params.id } });",
      "  // NOTE: no check that order.userId === session.user.id.",
      "  return Response.json(order);",
      "}",
    ].join("\n"),
    "utf8",
  );
  await writeFile(
    join(dir, "app/api/orders/ownership.existing.test.ts"),
    [
      "import { describe, it, expect } from 'vitest';",
      "describe('order ownership', () => {",
      "  it('does not return another user\\'s order', () => {",
      "    expect(false).toBe(true); // the fake TestRunner supplies the real verdict in tests",
      "  });",
      "});",
    ].join("\n"),
    "utf8",
  );
  return dir;
}

function idorAppMap(): AppMap {
  return AppMapSchema.parse({
    id: "appmap_prior_shape_0001",
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: "https://example.internal/montr/orders-app",
    branch: "main",
    commitSha: "d1d2d3d4d5d6d7d8d9d0e1e2e3e4e5e6e7e8e9e0",
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
    id: "prob_idor_prior_0001",
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    rootCauseId: "rc_idor_prior_0001",
    category: "idor",
    mergedCandidateIds: [],
    reachabilityHypothesis:
      "any authenticated user can reach GET /api/orders/:id with an arbitrary id",
    exploitHypothesis: "incrementing the id parameter discloses other users' orders",
    exposure: "public", // base category severity ("high") is what the eligibility gate reads
    routeId: ROUTE_ID,
    location: { file: HANDLER_PATH, line: 4 },
    reachabilityScore: 0.7,
    exposureScore: 0.6,
    impactScore: 0.6,
    rank: 1,
    createdAt: FIXED_NOW,
  });
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
  resolveModel(): ModelDescriptor {
    return DESCRIPTOR;
  }
}

function allConfirmVerifier(): (request: LLMRequest) => string {
  return () =>
    JSON.stringify({ confirm: true, rationale: "no ownership check guards this resource" });
}

/** Exactly what `apps/worker/src/runners.ts`'s `loadPriorConfirmedShapes` builds
 * from a persisted `confirmed_exploit_shape` learned fact — reproduced here to
 * test the packages/confirm consumption seam directly, without a live store. */
function priorShapesMatcher(category: string, filePattern: string): PriorConfirmedShapes {
  return {
    matches: (signal) => signal.category === category && signal.file.startsWith(`${filePattern}/`),
  };
}

const cleanupDirs: string[] = [];
afterEach(async () => {
  while (cleanupDirs.length > 0) {
    const dir = cleanupDirs.pop();
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
});

describe("E8 extension — confirmed_exploit_shape priors demonstrate a real scan-over-scan recall improvement", () => {
  it("SCAN 1 (nothing learned yet): an idor finding outside the configured severity scope stays unconfirmed, zero LLM spend — byte-identical to today", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);
    // A gateway that WOULD happily confirm anything if ever asked — proves the
    // miss is because the eligibility gate never let the loop run, not
    // because the loop failed.
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
    const input: ConfirmInput = {
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: idorAppMap(),
      probable: [idorProbableFinding()],
      allowLive: false,
      config: getHardenedDefaults(),
      repoRoot,
    };
    const deps: ConfirmDeps = {
      now: NOW,
      llm: gateway,
      // idor's base severity is "high" — deliberately narrowed to "critical"
      // only, so idor is OUT of scope (mirrors this repo's own A3 precedent
      // test). No priorConfirmedShapes yet — this repo has never been
      // scanned before.
      investigation: { enabled: true, severities: ["critical"] },
    };
    const out = await confirmFindings(input, deps);

    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
    expect(gateway.calls).toHaveLength(0); // eligibility gate never let the loop run
  });

  it("SCAN 2 (this repo's earlier scan recorded a confirmed_exploit_shape for a structurally similar idor): the SAME out-of-scope category now gets a real shot — and, with full E1+E2+E4 proof, is genuinely confirmed", async () => {
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
              rationale: "no ownership check on the Order lookup.",
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
    const input: ConfirmInput = {
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: idorAppMap(),
      probable: [idorProbableFinding()],
      allowLive: false,
      config: getHardenedDefaults(),
      repoRoot,
    };
    const deps: ConfirmDeps = {
      now: NOW,
      llm: gateway,
      testRunner,
      // SAME narrow severities scope as scan 1 — nothing about the operator's
      // configuration changed between scans.
      investigation: { enabled: true, severities: ["critical"] },
      // The only thing that changed: this repo's OWN confirmed history now
      // includes a genuinely-confirmed idor in the same route directory.
      priorConfirmedShapes: priorShapesMatcher("idor", "app/api/orders/[id]"),
    };
    const out = await confirmFindings(input, deps);

    // Recall improved: the exact same out-of-scope category that was
    // unconditionally unconfirmed in scan 1 is now genuinely confirmed —
    // through the SAME full E1 verdict + E2 executable evidence + E4
    // adversarial-majority gate every other investigation-confirmed finding
    // goes through. Nothing was bypassed.
    expect(out.unconfirmed).toHaveLength(0);
    expect(out.confirmed).toHaveLength(1);
    const confirmed = out.confirmed[0];
    expect(confirmed?.category).toBe("idor");
    if (confirmed?.proofArtifact.kind !== "static") throw new Error("expected static proof");
    expect(confirmed.proofArtifact.argument).toMatch(/Agentic investigation proof/);
    expect(confirmed.proofArtifact.argument).toMatch(/4\/4 confirmed/);
  });

  it("a NON-matching prior (different category) does not widen eligibility — still no LLM spend", async () => {
    const repoRoot = await writeVulnerableRepo();
    cleanupDirs.push(repoRoot);
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
    const input: ConfirmInput = {
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: idorAppMap(),
      probable: [idorProbableFinding()],
      allowLive: false,
      config: getHardenedDefaults(),
      repoRoot,
    };
    const deps: ConfirmDeps = {
      now: NOW,
      llm: gateway,
      investigation: { enabled: true, severities: ["critical"] },
      // Confirmed shape is for a DIFFERENT category in the same directory —
      // must not match.
      priorConfirmedShapes: priorShapesMatcher("sql_injection", "app/api/orders/[id]"),
    };
    const out = await confirmFindings(input, deps);

    expect(out.confirmed).toHaveLength(0);
    expect(gateway.calls).toHaveLength(0);
  });
});
