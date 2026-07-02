import { describe, it, expect } from "vitest";
import {
  Layer3OutputSchema,
  ProbableFindingSchema,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type ModelDescriptor,
  type ModelTier,
} from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import {
  mockAppMap,
  mockCleanAppMap,
  mockProbableFindings,
  createFakeLlmGateway,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  PROBABLE_CORS_ID,
} from "@montr/fixtures";
import { confirmFindings, type ConfirmInput, type ConfirmDeps } from "@montr/confirm";

/**
 * WS-H Layer-3a STATIC confirmation (build-plan §5.4). Deterministic data-flow
 * proof (source → sink, auth state per hop). NO requests fired, fully offline.
 * Golden path: probables [SQLi, XSS, CORS] → confirmed [SQLi, XSS] (static) +
 * unconfirmed [CORS], matching the ground-truth manifest.
 */

const NOW = (): string => FIXED_NOW;

function baseInput(overrides: Partial<ConfirmInput> = {}): ConfirmInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    appMap: mockAppMap,
    probable: mockProbableFindings,
    allowLive: false,
    config: getHardenedDefaults(),
    ...overrides,
  };
}

/** Counting LLM spy wrapping a real fake gateway, to prove call gating. */
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

describe("confirmFindings — static golden path", () => {
  it("confirms SQLi + XSS statically and demotes CORS to the appendix", async () => {
    const out = await confirmFindings(baseInput(), { now: NOW });

    expect(() => Layer3OutputSchema.parse(out)).not.toThrow();
    expect(out.confirmed).toHaveLength(2);
    expect(out.unconfirmed).toHaveLength(1);

    const cats = out.confirmed.map((c) => c.category).sort();
    expect(cats).toEqual(["sql_injection", "xss"]);
    expect(out.confirmed.every((c) => c.proofType === "static")).toBe(true);
    expect(out.confirmed.every((c) => c.status === "confirmed")).toBe(true);

    expect(out.unconfirmed[0]?.category).toBe("permissive_cors");
    expect(out.unconfirmed[0]?.id).toBe(PROBABLE_CORS_ID);
    expect(out.unconfirmed[0]?.status).toBe("unconfirmed");
    expect(out.unconfirmed[0]?.unconfirmedReason).toMatch(/configuration|component-class/i);
  });

  it("sets severity, CWE/OWASP mapping, exposure and probableId per finding", async () => {
    const out = await confirmFindings(baseInput(), { now: NOW });
    const sqli = out.confirmed.find((c) => c.category === "sql_injection");
    const xss = out.confirmed.find((c) => c.category === "xss");

    expect(sqli?.severity).toBe("critical");
    expect(sqli?.exposure).toBe("public");
    expect(sqli?.cwe).toContain("CWE-89");
    expect(sqli?.owasp).toBe("A03:2021");
    expect(sqli?.probableId).toBe("prob_sqli_0001");
    expect(sqli?.id).toBe("cf_static_prob_sqli_0001");

    expect(xss?.severity).toBe("high");
    expect(xss?.cwe).toContain("CWE-79");
  });

  it("emits a data-flow proof carrying auth state at every hop (no requests fired)", async () => {
    const out = await confirmFindings(baseInput(), { now: NOW });
    const sqli = out.confirmed.find((c) => c.category === "sql_injection");
    expect(sqli).toBeDefined();
    if (sqli?.proofArtifact.kind !== "static") throw new Error("expected static proof");

    const proof = sqli.proofArtifact;
    expect(proof.dataFlow.length).toBeGreaterThanOrEqual(2);
    // source hop then sink hop, both public (route /api/users is public).
    expect(proof.dataFlow[0]?.authState).toBe("public");
    expect(proof.dataFlow.at(-1)?.authState).toBe("public");
    expect(proof.dataFlow[0]?.location.line).toBe(6); // taint source
    expect(proof.dataFlow.at(-1)?.location.line).toBe(9); // sink
    expect(proof.argument).toMatch(/no requests fired/i);
    expect(proof.argument).toMatch(/public/i);
  });

  it("is deterministic — identical inputs produce identical output", async () => {
    const a = await confirmFindings(baseInput(), { now: NOW });
    const b = await confirmFindings(baseInput(), { now: NOW });
    expect(a).toEqual(b);
  });
});

describe("confirmFindings — LLM assist (enrich + fail-safe veto)", () => {
  it("enriches the static argument but only calls the LLM for data-flow findings", async () => {
    const spy = new SpyGateway(createFakeLlmGateway());
    const out = await confirmFindings(baseInput(), { now: NOW, llm: spy });

    // SQLi + XSS trigger a confirmation-tier call; CORS short-circuits (config-class).
    expect(spy.calls).toHaveLength(2);
    expect(spy.calls.every((c) => c.metadata.purpose === "confirmation")).toBe(true);
    expect(spy.calls.every((c) => c.metadata.layer === "layer3")).toBe(true);
    expect(spy.calls.every((c) => c.tier === "confirmation")).toBe(true);

    expect(out.confirmed).toHaveLength(2);
    const sqli = out.confirmed.find((c) => c.category === "sql_injection");
    if (sqli?.proofArtifact.kind !== "static") throw new Error("expected static proof");
    expect(sqli.proofArtifact.argument).toMatch(/Model review:/);
  });

  it("⛔ the LLM can only DEMOTE: a 'not exploitable' verdict moves a finding to the appendix", async () => {
    const vetoing = createFakeLlmGateway({
      cannedByPurpose: { confirmation: '{"confirmed":false}' },
    });
    const out = await confirmFindings(baseInput(), { now: NOW, llm: vetoing });

    // Deterministically-reachable SQLi + XSS are demoted by the veto (fail-safe, golden rule #4).
    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(3);
    const sqli = out.unconfirmed.find((u) => u.category === "sql_injection");
    expect(sqli?.unconfirmedReason).toMatch(/not exploitable|fail-safe/i);
  });

  it("a broken/garbage LLM response never demotes a solid deterministic proof", async () => {
    const garbage = createFakeLlmGateway({ cannedByPurpose: { confirmation: "not json at all" } });
    const out = await confirmFindings(baseInput(), { now: NOW, llm: garbage });
    expect(out.confirmed).toHaveLength(2); // deterministic proof stands
  });
});

describe("confirmFindings — no false positives on sanitized paths", () => {
  it("does NOT confirm a parameterized sink on the clean repo (sanitizer interrupts)", async () => {
    const cleanProbable = ProbableFindingSchema.parse({
      id: "prob_clean_sqli_0001",
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      rootCauseId: "rc_clean",
      category: "sql_injection",
      mergedCandidateIds: [],
      reachabilityHypothesis: "q may reach the query",
      exploitHypothesis: "attempt boolean injection",
      exposure: "authed",
      location: { file: "app/api/users/route.ts", line: 9 },
      reachabilityScore: 0.5,
      exposureScore: 0.5,
      impactScore: 0.5,
      rank: 1,
      createdAt: FIXED_NOW,
    });

    const out = await confirmFindings(
      baseInput({ appMap: mockCleanAppMap, probable: [cleanProbable] }),
      { now: NOW },
    );

    expect(out.confirmed).toHaveLength(0);
    expect(out.unconfirmed).toHaveLength(1);
    expect(out.unconfirmed[0]?.unconfirmedReason).toMatch(/sanitiz|parameteriz/i);
  });
});

describe("confirmFindings — degenerate inputs", () => {
  it("returns an empty, contract-valid Layer3Output for no probables", async () => {
    const out = await confirmFindings(baseInput({ probable: [] }), { now: NOW });
    expect(out.confirmed).toEqual([]);
    expect(out.unconfirmed).toEqual([]);
    expect(() => Layer3OutputSchema.parse(out)).not.toThrow();
  });

  it("works with zero deps (pure static, no LLM, no target)", async () => {
    const deps: ConfirmDeps = {};
    const out = await confirmFindings(baseInput(), deps);
    expect(out.confirmed).toHaveLength(2);
  });
});
