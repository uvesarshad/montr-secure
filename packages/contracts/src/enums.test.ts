import { describe, it, expect } from "vitest";
import {
  RiskClassSchema,
  GateStateSchema,
  ScanStatusSchema,
  RoleSchema,
  SeveritySchema,
  ExposureSchema,
  ProofTypeSchema,
  FindingStatusSchema,
  FixStatusSchema,
  LayerIdSchema,
  ScanModeSchema,
} from "./enums.js";

/**
 * Enum schemas gate real safety/authorization decisions downstream (auto-fix
 * eligibility, RBAC, pipeline gate state). A typo'd or accidentally-widened
 * enum value here would silently break those checks, so we pin the exact
 * accepted value sets and prove close-but-wrong values are rejected.
 */

describe("RiskClassSchema (auto-fix vs human-required gating)", () => {
  it("accepts 'auto-eligible'", () => {
    expect(RiskClassSchema.parse("auto-eligible")).toBe("auto-eligible");
  });

  it("accepts 'human-required'", () => {
    expect(RiskClassSchema.parse("human-required")).toBe("human-required");
  });

  it("rejects a value not in the enum", () => {
    expect(() => RiskClassSchema.parse("auto-approved")).toThrow();
  });

  it("rejects a case-mismatched value", () => {
    expect(() => RiskClassSchema.parse("Human-Required")).toThrow();
  });

  it("rejects a non-string value", () => {
    expect(() => RiskClassSchema.parse(1)).toThrow();
  });
});

describe("GateStateSchema (pipeline gate — golden rule #5 explicit state)", () => {
  const valid = [
    "not_started",
    "estimate_pending",
    "estimate_approved",
    "running",
    "fix_gate_pending",
    "auto_approved",
    "approved",
    "rejected",
    "blocked",
  ];

  it.each(valid)("accepts '%s'", (value) => {
    expect(GateStateSchema.parse(value)).toBe(value);
  });

  it("rejects an unrecognized gate state", () => {
    expect(() => GateStateSchema.parse("in_progress")).toThrow();
  });

  it("rejects an empty string", () => {
    expect(() => GateStateSchema.parse("")).toThrow();
  });
});

describe("ScanStatusSchema", () => {
  it("accepts every documented status", () => {
    for (const s of [
      "queued",
      "running",
      "paused",
      "completed",
      "failed",
      "cancelled",
      "partial",
    ]) {
      expect(ScanStatusSchema.parse(s)).toBe(s);
    }
  });

  it("rejects an unknown status", () => {
    expect(() => ScanStatusSchema.parse("done")).toThrow();
  });
});

describe("RoleSchema (RBAC — approver gates the human gate + DAST auth)", () => {
  it("accepts operator, approver, viewer", () => {
    expect(RoleSchema.parse("operator")).toBe("operator");
    expect(RoleSchema.parse("approver")).toBe("approver");
    expect(RoleSchema.parse("viewer")).toBe("viewer");
  });

  it("rejects an unrecognized role (e.g. 'admin')", () => {
    expect(() => RoleSchema.parse("admin")).toThrow();
  });
});

describe("SeveritySchema", () => {
  it("accepts the full severity scale in order", () => {
    for (const s of ["info", "low", "medium", "high", "critical"]) {
      expect(SeveritySchema.parse(s)).toBe(s);
    }
  });

  it("rejects a non-scale value", () => {
    expect(() => SeveritySchema.parse("severe")).toThrow();
  });
});

describe("ExposureSchema / ProofTypeSchema", () => {
  it("Exposure accepts public/authed and rejects other values", () => {
    expect(ExposureSchema.parse("public")).toBe("public");
    expect(ExposureSchema.parse("authed")).toBe("authed");
    expect(() => ExposureSchema.parse("internal")).toThrow();
  });

  it("ProofType accepts static/live and rejects other values", () => {
    expect(ProofTypeSchema.parse("static")).toBe("static");
    expect(ProofTypeSchema.parse("live")).toBe("live");
    expect(() => ProofTypeSchema.parse("dynamic")).toThrow();
  });
});

describe("FindingStatusSchema / FixStatusSchema", () => {
  it("FindingStatus accepts the four finding tiers", () => {
    for (const s of ["candidate", "probable", "confirmed", "unconfirmed"]) {
      expect(FindingStatusSchema.parse(s)).toBe(s);
    }
    expect(() => FindingStatusSchema.parse("resolved")).toThrow();
  });

  it("FixStatus accepts the fix lifecycle values", () => {
    for (const s of ["proposed", "pr-open", "merged", "rejected"]) {
      expect(FixStatusSchema.parse(s)).toBe(s);
    }
    expect(() => FixStatusSchema.parse("draft")).toThrow();
  });
});

describe("LayerIdSchema / ScanModeSchema", () => {
  it("LayerId accepts layer0..layer5 and rejects an out-of-range layer", () => {
    for (const l of ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"]) {
      expect(LayerIdSchema.parse(l)).toBe(l);
    }
    expect(() => LayerIdSchema.parse("layer6")).toThrow();
  });

  it("ScanMode accepts full/diff and rejects other values", () => {
    expect(ScanModeSchema.parse("full")).toBe("full");
    expect(ScanModeSchema.parse("diff")).toBe("diff");
    expect(() => ScanModeSchema.parse("incremental")).toThrow();
  });
});
