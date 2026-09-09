import { describe, it, expect } from "vitest";
import {
  DetectionRuleFormatSchema,
  DetectionRuleSchema,
  AttackPathStepSchema,
  AttackPathSchema,
  DetectionStatusSchema,
  DetectionVerificationResultSchema,
  DetectionCoverageSchema,
} from "./blue-team.js";

const NOW = "2026-08-22T00:00:00.000Z";

describe("DetectionRuleFormatSchema", () => {
  it("accepts sigma/otel/siem_query", () => {
    expect(DetectionRuleFormatSchema.parse("sigma")).toBe("sigma");
    expect(DetectionRuleFormatSchema.parse("otel")).toBe("otel");
    expect(DetectionRuleFormatSchema.parse("siem_query")).toBe("siem_query");
  });

  it("rejects an unknown format", () => {
    expect(() => DetectionRuleFormatSchema.parse("yara")).toThrow();
  });
});

describe("DetectionRuleSchema", () => {
  const base = {
    id: "dr_1",
    clientId: "client_1",
    scanId: "scan_1",
    findingId: "finding_1",
    format: "sigma" as const,
    content: "title: Test Rule\nlogsource:\n  category: process_creation\n",
    mitreTechniques: ["T1190"],
    provenance: "static" as const,
    createdAt: NOW,
  };

  it("accepts a well-formed static-provenance rule", () => {
    const parsed = DetectionRuleSchema.parse(base);
    expect(parsed.format).toBe("sigma");
    expect(parsed.mitreTechniques).toEqual(["T1190"]);
    expect(parsed.provenance).toBe("static");
  });

  it("accepts a live-provenance rule", () => {
    const parsed = DetectionRuleSchema.parse({ ...base, provenance: "live" });
    expect(parsed.provenance).toBe("live");
  });

  it("defaults mitreTechniques to an empty array when omitted", () => {
    const { mitreTechniques: _mitreTechniques, ...rest } = base;
    const parsed = DetectionRuleSchema.parse(rest);
    expect(parsed.mitreTechniques).toEqual([]);
  });

  it("rejects empty rule content", () => {
    expect(() => DetectionRuleSchema.parse({ ...base, content: "" })).toThrow();
  });

  it("rejects an invalid format", () => {
    expect(() => DetectionRuleSchema.parse({ ...base, format: "yara" })).toThrow();
  });

  it("rejects an invalid provenance", () => {
    expect(() => DetectionRuleSchema.parse({ ...base, provenance: "dynamic" })).toThrow();
  });

  it("rejects a missing findingId", () => {
    const { findingId: _findingId, ...rest } = base;
    expect(() => DetectionRuleSchema.parse(rest)).toThrow();
  });
});

describe("AttackPathStepSchema / AttackPathSchema", () => {
  const step1 = { findingId: "finding_1", note: "public route accepts attacker-controlled URL" };
  const step2 = { findingId: "finding_2" };

  it("AttackPathStepSchema accepts an optional note", () => {
    expect(AttackPathStepSchema.parse(step1).note).toBeTruthy();
    expect(AttackPathStepSchema.parse(step2).note).toBeUndefined();
  });

  const base = {
    id: "ap_1",
    clientId: "client_1",
    scanId: "scan_1",
    steps: [step1, step2],
    feasibilityScore: 0.75,
    severity: "high" as const,
    narrative: "Public route -> SSRF -> metadata endpoint -> credentials.",
    createdAt: NOW,
  };

  it("accepts a well-formed 2-hop chain", () => {
    const parsed = AttackPathSchema.parse(base);
    expect(parsed.steps).toHaveLength(2);
    expect(parsed.severity).toBe("high");
  });

  it("accepts a longer chain (3+ hops)", () => {
    const parsed = AttackPathSchema.parse({
      ...base,
      steps: [step1, { findingId: "finding_2" }, { findingId: "finding_3" }],
    });
    expect(parsed.steps).toHaveLength(3);
  });

  it("rejects a chain with fewer than 2 steps", () => {
    expect(() => AttackPathSchema.parse({ ...base, steps: [step1] })).toThrow();
  });

  it("rejects an empty chain", () => {
    expect(() => AttackPathSchema.parse({ ...base, steps: [] })).toThrow();
  });

  it("rejects a feasibilityScore outside [0, 1]", () => {
    expect(() => AttackPathSchema.parse({ ...base, feasibilityScore: 1.5 })).toThrow();
  });

  it("rejects an empty narrative", () => {
    expect(() => AttackPathSchema.parse({ ...base, narrative: "" })).toThrow();
  });

  it("rejects an invalid severity", () => {
    expect(() => AttackPathSchema.parse({ ...base, severity: "catastrophic" })).toThrow();
  });
});

describe("DetectionStatusSchema (tri-state)", () => {
  it("accepts true, false, and 'unknown'", () => {
    expect(DetectionStatusSchema.parse(true)).toBe(true);
    expect(DetectionStatusSchema.parse(false)).toBe(false);
    expect(DetectionStatusSchema.parse("unknown")).toBe("unknown");
  });

  it("rejects any other string", () => {
    expect(() => DetectionStatusSchema.parse("maybe")).toThrow();
  });
});

describe("DetectionVerificationResultSchema", () => {
  it("accepts a fired result with evidence", () => {
    const parsed = DetectionVerificationResultSchema.parse({
      scenarioId: "scenario_1",
      fired: true,
      verifiedAt: NOW,
      evidence: "siem-alert:12345",
    });
    expect(parsed.fired).toBe(true);
  });

  it("accepts a minimal not-fired result", () => {
    const parsed = DetectionVerificationResultSchema.parse({ fired: false, verifiedAt: NOW });
    expect(parsed.fired).toBe(false);
    expect(parsed.scenarioId).toBeUndefined();
  });

  it("rejects a missing verifiedAt", () => {
    expect(() => DetectionVerificationResultSchema.parse({ fired: true })).toThrow();
  });
});

describe("DetectionCoverageSchema", () => {
  const base = {
    id: "dc_1",
    clientId: "client_1",
    scanId: "scan_1",
    findingId: "finding_1",
    detected: "unknown" as const,
    reasoning: "No SIEM ingest configured for this route's process telemetry.",
    createdAt: NOW,
  };

  it("accepts a well-formed unknown-verdict record with no rule/verification yet", () => {
    const parsed = DetectionCoverageSchema.parse(base);
    expect(parsed.detected).toBe("unknown");
    expect(parsed.detectionRuleId).toBeUndefined();
    expect(parsed.verification).toBeUndefined();
  });

  it("accepts detected: true with a detectionRuleId and a verification result", () => {
    const parsed = DetectionCoverageSchema.parse({
      ...base,
      detected: true,
      detectionRuleId: "dr_1",
      verification: { fired: true, verifiedAt: NOW },
    });
    expect(parsed.detected).toBe(true);
    expect(parsed.verification?.fired).toBe(true);
  });

  it("accepts detected: false", () => {
    expect(DetectionCoverageSchema.parse({ ...base, detected: false }).detected).toBe(false);
  });

  it("rejects an empty reasoning", () => {
    expect(() => DetectionCoverageSchema.parse({ ...base, reasoning: "" })).toThrow();
  });

  it("rejects an invalid detected value", () => {
    expect(() => DetectionCoverageSchema.parse({ ...base, detected: "maybe" })).toThrow();
  });

  it("rejects a missing findingId", () => {
    const { findingId: _findingId, ...rest } = base;
    expect(() => DetectionCoverageSchema.parse(rest)).toThrow();
  });
});
