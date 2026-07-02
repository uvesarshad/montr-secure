import { describe, it, expect } from "vitest";
import { canonicalJson, computeAuditHash } from "@montr/state-store";

describe("@montr/state-store audit hashing", () => {
  it("canonicalJson is key-order stable", () => {
    expect(canonicalJson({ b: 1, a: 2, c: { z: 1, a: 2 } })).toBe(
      '{"a":2,"b":1,"c":{"a":2,"z":1}}',
    );
    expect(canonicalJson({ a: 2, b: 1 })).toBe(canonicalJson({ b: 1, a: 2 }));
  });

  it("computeAuditHash is deterministic and chains", () => {
    const e1 = { action: "scan.created", summary: "created", sequence: 1 };
    const e2 = { action: "scan.started", summary: "started", sequence: 2 };
    const h1 = computeAuditHash("", e1);
    const h1again = computeAuditHash("", e1);
    expect(h1).toBe(h1again);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);

    const h2 = computeAuditHash(h1, e2);
    // Tampering with a prior link changes downstream hashes (tamper-evident).
    const tampered = computeAuditHash(h1, { ...e2, summary: "tampered" });
    expect(h2).not.toBe(tampered);
  });
});
