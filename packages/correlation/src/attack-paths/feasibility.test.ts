/**
 * B8 — feasibility scoring. Product-of-factors: every hop's confirmation
 * confidence (proofType) and every connecting condition's structural
 * strength multiply together, so a chain is only as feasible as its weakest
 * link, and a live-DAST-proven chain must score strictly higher than an
 * otherwise-identical static-proof-only chain.
 */
import { describe, it, expect } from "vitest";
import type { ConfirmedFinding } from "@montr/contracts";
import { computeFeasibility, findingConfidence } from "./feasibility.js";
import type { ChainCondition } from "./conditions.js";

function mkFinding(proofType: ConfirmedFinding["proofType"]): ConfirmedFinding {
  return {
    id: "f1",
    scanId: "scan_1",
    clientId: "client_1",
    title: "t",
    category: "ssrf",
    cwe: [],
    severity: "high",
    exposure: "public",
    location: { file: "a.ts", line: 1 },
    impact: "impact",
    proofType,
    proofArtifact:
      proofType === "live"
        ? { kind: "live", target: "https://x", transcript: [] }
        : { kind: "static", argument: "arg", dataFlow: [], sanitizersBypassed: [] },
    status: "confirmed",
    createdAt: "2026-08-22T00:00:00.000Z",
  };
}

const cond = (strength: number): ChainCondition => ({
  kind: "ssrf-internal-pivot",
  strength,
  note: "n",
});

describe("findingConfidence", () => {
  it("live proof is strictly more confident than static proof", () => {
    expect(findingConfidence(mkFinding("live"))).toBeGreaterThan(
      findingConfidence(mkFinding("static")),
    );
    expect(findingConfidence(mkFinding("live"))).toBe(1);
  });
});

describe("computeFeasibility", () => {
  it("multiplies finding confidence and condition strength (product, not average)", () => {
    const score = computeFeasibility([mkFinding("static"), mkFinding("static")], [cond(0.5)]);
    // 0.7 * 0.7 * 0.5 = 0.245
    expect(score).toBeCloseTo(0.245, 3);
  });

  it("ranks an all-live chain above an otherwise-identical all-static chain", () => {
    const liveScore = computeFeasibility([mkFinding("live"), mkFinding("live")], [cond(0.6)]);
    const staticScore = computeFeasibility([mkFinding("static"), mkFinding("static")], [cond(0.6)]);
    expect(liveScore).toBeGreaterThan(staticScore);
  });

  it("one weak/speculative link drags the whole chain down even with strong hops elsewhere", () => {
    const strongChain = computeFeasibility(
      [mkFinding("live"), mkFinding("live"), mkFinding("live")],
      [cond(0.95), cond(0.95)],
    );
    const oneWeakLink = computeFeasibility(
      [mkFinding("live"), mkFinding("live"), mkFinding("live")],
      [cond(0.95), cond(0.2)],
    );
    expect(oneWeakLink).toBeLessThan(strongChain);
  });

  it("stays within [0, 1]", () => {
    const score = computeFeasibility([mkFinding("live")], [cond(1)]);
    expect(score).toBeLessThanOrEqual(1);
    expect(score).toBeGreaterThanOrEqual(0);
  });
});
