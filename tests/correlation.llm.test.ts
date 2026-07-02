import { describe, it, expect } from "vitest";
import {
  mockAppMap,
  mockCandidateFindings,
  createFakeLlmGateway,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  CANDIDATE_DEP_ID,
} from "@montr/fixtures";
import { correlate, parseCorrelationResponse, blendScore } from "@montr/correlation";
import {
  RecordingGateway,
  fixedContentGateway,
  throwingGateway,
  promptText,
} from "./correlation.helpers.js";

const base = { clientId: CLIENT_ID, scanId: SCAN_ID, now: FIXED_NOW } as const;
const run = (extra: Record<string, unknown>) =>
  correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings, ...extra });

describe("@montr/correlation — LLM correlation reasoning (via the gateway)", () => {
  it("calls the gateway once per promoted finding with correlation/layer2 metadata", async () => {
    const gw = new RecordingGateway(createFakeLlmGateway());
    const out = await run({ gateway: gw });

    expect(gw.requests).toHaveLength(out.probable.length);
    for (const req of gw.requests) {
      expect(req.metadata.purpose).toBe("correlation");
      expect(req.metadata.layer).toBe("layer2");
      expect(req.metadata.scanId).toBe(SCAN_ID);
      expect(req.metadata.clientId).toBe(CLIENT_ID);
      expect(req.tier).toBe("default");
      expect(req.responseFormat).toBe("json");
      expect(req.messages[0]!.role).toBe("user");
    }
  });

  it("⛔ sends NO client code bodies in the prompt (golden rule #1)", async () => {
    const gw = new RecordingGateway(createFakeLlmGateway());
    await run({ gateway: gw });
    const text = promptText(gw);
    // Structured facts only — the raw evidence-snippet CODE bodies never egress.
    // (Markers chosen to appear only in evidence snippets / secret values, never
    // in a scanner rule-id or an App Map enum.)
    for (const codeBody of ["$queryRawUnsafe", "__html", "sk_live", "PAYMENTS_API_KEY"]) {
      expect(text).not.toContain(codeBody);
    }
    // ...but the structural facts the LLM reasons over ARE present.
    expect(text).toContain("orm_raw_query");
    expect(text).toContain("/api/users");
  });

  it("uses the LLM's reachability hypothesis while preserving deterministic ranking", async () => {
    const out = await run({ gateway: createFakeLlmGateway() });
    // The fake returns a canned correlation hypothesis for every call.
    expect(
      out.probable.every((p) => p.reachabilityHypothesis === "tainted q reaches raw query"),
    ).toBe(true);
    // Ranking is still deterministic and App-Map-grounded: SQLi stays #1.
    expect(out.probable[0]!.category).toBe("sql_injection");
    expect(out.probable[0]!.rank).toBe(1);
    expect(out.probable.map((p) => p.rank)).toEqual([1, 2, 3, 4]);
  });

  it("the App Map stays authoritative: the LLM cannot un-demote or change exposure", async () => {
    const out = await run({ gateway: createFakeLlmGateway() });
    // Dependency is still demoted despite the LLM's optimistic canned scores.
    expect(out.probable.some((p) => p.category === "vulnerable_dependency")).toBe(false);
    expect(out.demoted.map((d) => d.id)).toContain(CANDIDATE_DEP_ID);
    // Secret exposure stays "authed" (structural, not LLM-decided).
    expect(out.probable.find((p) => p.category === "hardcoded_secret")!.exposure).toBe("authed");
  });

  it("fail-safe: a malformed LLM response falls back to the deterministic result", async () => {
    const deterministic = await run({});
    const withBadLlm = await run({
      gateway: fixedContentGateway("this is not json {{{", createFakeLlmGateway()),
    });
    // Identical scores + hypotheses — the garbage response changed nothing.
    expect(withBadLlm.probable).toEqual(deterministic.probable);
    expect(withBadLlm.demoted).toEqual(deterministic.demoted);
  });

  it("fail-safe: a gateway outage does not crash correlation", async () => {
    const deterministic = await run({});
    const withOutage = await run({ gateway: throwingGateway(createFakeLlmGateway()) });
    expect(withOutage.probable).toEqual(deterministic.probable);
    expect(withOutage.demoted).toEqual(deterministic.demoted);
  });

  it("useLlm:false runs deterministic-only even when a gateway is supplied", async () => {
    const gw = new RecordingGateway(createFakeLlmGateway());
    const out = await run({ gateway: gw, useLlm: false });
    const deterministic = await run({});
    expect(gw.requests).toHaveLength(0);
    expect(out.probable).toEqual(deterministic.probable);
  });

  describe("parseCorrelationResponse", () => {
    it("reads scores + the fixture's generic 'hypothesis' field", () => {
      const parsed = parseCorrelationResponse(
        '{"rank":1,"reachabilityScore":0.95,"exposureScore":1,"impactScore":0.9,"hypothesis":"tainted q reaches raw query"}',
      );
      expect(parsed).toEqual({
        reachabilityScore: 0.95,
        impactScore: 0.9,
        reachabilityHypothesis: "tainted q reaches raw query",
        exploitHypothesis: undefined,
      });
    });

    it("reads dedicated hypothesis fields", () => {
      const parsed = parseCorrelationResponse(
        '{"reachabilityHypothesis":"reach","exploitHypothesis":"exploit"}',
      );
      expect(parsed?.reachabilityHypothesis).toBe("reach");
      expect(parsed?.exploitHypothesis).toBe("exploit");
    });

    it("returns null for malformed / signal-free responses", () => {
      expect(parseCorrelationResponse("not json")).toBeNull();
      expect(parseCorrelationResponse("42")).toBeNull();
      expect(parseCorrelationResponse("{}")).toBeNull();
      expect(parseCorrelationResponse('{"unrelated":1}')).toBeNull();
    });
  });

  describe("blendScore (bounded nudge)", () => {
    it("returns the base when the LLM offers no score", () => {
      expect(blendScore(0.5, undefined, 0.5, 0.2)).toBe(0.5);
    });
    it("nudges toward the LLM value within ±maxDelta at trust", () => {
      expect(blendScore(0.5, 1, 0.5, 0.2)).toBeCloseTo(0.6, 6);
      expect(blendScore(0.5, 0, 0.5, 0.2)).toBeCloseTo(0.4, 6);
    });
    it("clamps into [0,1]", () => {
      expect(blendScore(0.95, 2, 1, 0.2)).toBe(1);
      expect(blendScore(0.05, -2, 1, 0.2)).toBe(0);
    });
  });
});
