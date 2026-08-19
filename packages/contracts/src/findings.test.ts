import { describe, it, expect } from "vitest";
import {
  CandidateFindingSchema,
  ProbableFindingSchema,
  ConfirmedFindingSchema,
  UnconfirmedFindingSchema,
  StaticProofSchema,
  LiveProofSchema,
  ProofArtifactSchema,
} from "./findings.js";

/**
 * The three finding tiers (PRD §9) gate what gets headlined vs. appendixed.
 * ConfirmedFindingSchema carries a `.superRefine` cross-field check tying
 * `proofType` to `proofArtifact.kind` — real, non-trivial validation logic
 * worth pinning down directly (a mismatch here would let a "live" claim ride
 * on a static-only proof, or vice versa).
 */

const NOW = "2026-08-19T00:00:00.000Z";
const LOCATION = { file: "src/a.ts", line: 10 };

describe("CandidateFindingSchema (Layer 1 — over-inclusive, tool-tagged)", () => {
  const base = {
    id: "c1",
    scanId: "scan_1",
    clientId: "client_1",
    source: "semgrep",
    ruleId: "sql-injection-1",
    category: "sql_injection",
    location: LOCATION,
    rawSeverity: "high",
    createdAt: NOW,
  };

  it("accepts a minimal candidate, defaulting cwe/evidenceSnippet/status", () => {
    const parsed = CandidateFindingSchema.parse(base);
    expect(parsed.cwe).toEqual([]);
    expect(parsed.evidenceSnippet).toBe("");
    expect(parsed.status).toBe("candidate");
  });

  it("rejects an invalid tool source", () => {
    expect(() => CandidateFindingSchema.parse({ ...base, source: "sonarqube" })).toThrow();
  });

  it("rejects an empty ruleId", () => {
    expect(() => CandidateFindingSchema.parse({ ...base, ruleId: "" })).toThrow();
  });

  it("rejects a malformed CWE id (must match CWE-<number>)", () => {
    expect(() => CandidateFindingSchema.parse({ ...base, cwe: ["89"] })).toThrow();
  });
});

describe("ProbableFindingSchema (Layer 2 — reachability × exposure × impact)", () => {
  const base = {
    id: "p1",
    scanId: "scan_1",
    clientId: "client_1",
    rootCauseId: "rc1",
    category: "sql_injection",
    reachabilityHypothesis: "reachable from POST /users",
    exploitHypothesis: "unsanitized id in raw query",
    exposure: "public",
    location: LOCATION,
    reachabilityScore: 0.9,
    exposureScore: 0.8,
    impactScore: 0.95,
    rank: 1,
    createdAt: NOW,
  };

  it("accepts a well-formed probable finding", () => {
    const parsed = ProbableFindingSchema.parse(base);
    expect(parsed.status).toBe("probable");
  });

  it("rejects a reachabilityScore outside [0, 1]", () => {
    expect(() => ProbableFindingSchema.parse({ ...base, reachabilityScore: 1.5 })).toThrow();
  });

  it("rejects a non-positive rank", () => {
    expect(() => ProbableFindingSchema.parse({ ...base, rank: 0 })).toThrow();
  });

  it("rejects an invalid exposure value", () => {
    expect(() => ProbableFindingSchema.parse({ ...base, exposure: "internal" })).toThrow();
  });
});

describe("ProofArtifactSchema (discriminated union static | live)", () => {
  it("accepts a static proof", () => {
    const proof = { kind: "static", argument: "tainted param reaches raw query" };
    const parsed = ProofArtifactSchema.parse(proof);
    expect(parsed.kind).toBe("static");
  });

  it("accepts a live proof with a transcript", () => {
    const proof = {
      kind: "live",
      target: "https://staging.example.com",
      transcript: [
        {
          request: { method: "GET", url: "/x" },
          response: { status: 200 },
        },
      ],
    };
    expect(ProofArtifactSchema.parse(proof).kind).toBe("live");
  });

  it("rejects a proof with neither 'static' nor 'live' kind", () => {
    expect(() => ProofArtifactSchema.parse({ kind: "dynamic", argument: "x" })).toThrow();
  });

  it("StaticProofSchema rejects a missing 'argument'", () => {
    expect(() => StaticProofSchema.parse({ kind: "static" })).toThrow();
  });

  it("LiveProofSchema rejects a missing 'target'", () => {
    expect(() => LiveProofSchema.parse({ kind: "live" })).toThrow();
  });
});

describe("ConfirmedFindingSchema (Layer 3 — proofType must match proofArtifact.kind)", () => {
  const base = {
    id: "cf1",
    scanId: "scan_1",
    clientId: "client_1",
    title: "SQL Injection in /users",
    category: "sql_injection",
    severity: "critical",
    exposure: "public",
    location: LOCATION,
    impact: "full DB read/write",
    createdAt: NOW,
  };

  it("accepts a confirmed finding where proofType matches proofArtifact.kind (static)", () => {
    const finding = {
      ...base,
      proofType: "static",
      proofArtifact: { kind: "static", argument: "tainted param reaches raw query" },
    };
    const parsed = ConfirmedFindingSchema.parse(finding);
    expect(parsed.status).toBe("confirmed");
  });

  it("accepts a confirmed finding where proofType matches proofArtifact.kind (live)", () => {
    const finding = {
      ...base,
      proofType: "live",
      proofArtifact: { kind: "live", target: "https://staging.example.com" },
    };
    expect(ConfirmedFindingSchema.parse(finding).proofType).toBe("live");
  });

  it("REJECTS a mismatched proofType vs proofArtifact.kind (static claimed, live artifact)", () => {
    const finding = {
      ...base,
      proofType: "static",
      proofArtifact: { kind: "live", target: "https://staging.example.com" },
    };
    expect(() => ConfirmedFindingSchema.parse(finding)).toThrow(/must match/);
  });

  it("REJECTS a mismatched proofType vs proofArtifact.kind (live claimed, static artifact)", () => {
    const finding = {
      ...base,
      proofType: "live",
      proofArtifact: { kind: "static", argument: "x" },
    };
    expect(() => ConfirmedFindingSchema.parse(finding)).toThrow(/must match/);
  });

  it("rejects a missing severity", () => {
    const { severity: _severity, ...rest } = base;
    expect(() =>
      ConfirmedFindingSchema.parse({
        ...rest,
        proofType: "static",
        proofArtifact: { kind: "static", argument: "x" },
      }),
    ).toThrow();
  });

  it("rejects an empty title", () => {
    expect(() =>
      ConfirmedFindingSchema.parse({
        ...base,
        title: "",
        proofType: "static",
        proofArtifact: { kind: "static", argument: "x" },
      }),
    ).toThrow();
  });
});

describe("UnconfirmedFindingSchema (§7 L3 appendix — never deleted)", () => {
  it("accepts an unconfirmed finding derived from a probable one, requiring a reason", () => {
    const finding = {
      id: "p1",
      scanId: "scan_1",
      clientId: "client_1",
      rootCauseId: "rc1",
      category: "xss",
      reachabilityHypothesis: "h",
      exploitHypothesis: "e",
      exposure: "authed",
      location: LOCATION,
      reachabilityScore: 0.2,
      exposureScore: 0.2,
      impactScore: 0.2,
      rank: 5,
      createdAt: NOW,
      unconfirmedReason: "sanitizer confirmed present on manual review",
    };
    const parsed = UnconfirmedFindingSchema.parse(finding);
    expect(parsed.status).toBe("unconfirmed");
  });

  it("rejects an unconfirmed finding missing the required unconfirmedReason", () => {
    const finding = {
      id: "p1",
      scanId: "scan_1",
      clientId: "client_1",
      rootCauseId: "rc1",
      category: "xss",
      reachabilityHypothesis: "h",
      exploitHypothesis: "e",
      exposure: "authed",
      location: LOCATION,
      reachabilityScore: 0.2,
      exposureScore: 0.2,
      impactScore: 0.2,
      rank: 5,
      createdAt: NOW,
    };
    expect(() => UnconfirmedFindingSchema.parse(finding)).toThrow();
  });
});
