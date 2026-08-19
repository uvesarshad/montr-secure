import { describe, it, expect } from "vitest";
import {
  ActorTypeSchema,
  AuditActorSchema,
  AuditActionSchema,
  AuditEventSchema,
  AuditEventInputSchema,
} from "./audit.js";

/**
 * The audit log is append-only and hash-chained (tamper-evident) — every
 * agent action, LLM call, code modification, and human approval is recorded
 * here (§8.5). AuditEventSchema is squarely in the "safety-critical" bucket
 * called out for this task: a malformed audit event must be rejected, not
 * silently accepted with missing hash-chain fields.
 */

const NOW = "2026-08-19T00:00:00.000Z";

describe("ActorTypeSchema", () => {
  it("accepts user, agent, system", () => {
    for (const t of ["user", "agent", "system"]) {
      expect(ActorTypeSchema.parse(t)).toBe(t);
    }
  });

  it("rejects an unrecognized actor type", () => {
    expect(() => ActorTypeSchema.parse("service")).toThrow();
  });
});

describe("AuditActorSchema", () => {
  it("accepts an agent actor without a role", () => {
    const actor = { type: "agent", id: "agent_1" };
    expect(AuditActorSchema.parse(actor)).toEqual(actor);
  });

  it("accepts a user actor with a role", () => {
    const actor = { type: "user", id: "user_1", role: "approver" };
    expect(AuditActorSchema.parse(actor)).toEqual(actor);
  });

  it("rejects an invalid role value", () => {
    expect(() =>
      AuditActorSchema.parse({ type: "user", id: "user_1", role: "superadmin" }),
    ).toThrow();
  });

  it("rejects a missing actor id", () => {
    expect(() => AuditActorSchema.parse({ type: "user" })).toThrow();
  });
});

describe("AuditActionSchema", () => {
  it("accepts a representative sample of every audited action category", () => {
    const sample = [
      "scan.created",
      "gate.estimate_approved",
      "llm.call",
      "finding.confirmed",
      "fix.pr_opened",
      "dast.kill_switch",
      "budget.exceeded",
      "auth.role_changed",
      "scenario.run",
      "posture.snapshot",
    ];
    for (const action of sample) {
      expect(AuditActionSchema.parse(action)).toBe(action);
    }
  });

  it("rejects an action string not in the closed set (no free-form actions)", () => {
    expect(() => AuditActionSchema.parse("scan.deleted")).toThrow();
  });
});

describe("AuditEventSchema (hash-chained, append-only record)", () => {
  const base = {
    id: "evt_1",
    clientId: "client_1",
    sequence: 1,
    actor: { type: "system", id: "system" },
    action: "scan.created",
    summary: "Scan created",
    prevHash: "",
    hash: "deadbeef",
    at: NOW,
  };

  it("accepts a well-formed event, defaulting metadata to {}", () => {
    const parsed = AuditEventSchema.parse(base);
    expect(parsed.metadata).toEqual({});
  });

  it("accepts the first-record sentinel: empty prevHash", () => {
    expect(AuditEventSchema.parse(base).prevHash).toBe("");
  });

  it("rejects a non-positive sequence number (must be 1-based monotonic)", () => {
    expect(() => AuditEventSchema.parse({ ...base, sequence: 0 })).toThrow();
    expect(() => AuditEventSchema.parse({ ...base, sequence: -1 })).toThrow();
  });

  it("rejects a non-integer sequence number", () => {
    expect(() => AuditEventSchema.parse({ ...base, sequence: 1.5 })).toThrow();
  });

  it("rejects an invalid action", () => {
    expect(() => AuditEventSchema.parse({ ...base, action: "not.a.real.action" })).toThrow();
  });

  it("rejects a missing hash field (breaks the hash chain)", () => {
    const { hash: _hash, ...rest } = base;
    expect(() => AuditEventSchema.parse(rest)).toThrow();
  });

  it("rejects a missing prevHash field", () => {
    const { prevHash: _prevHash, ...rest } = base;
    expect(() => AuditEventSchema.parse(rest)).toThrow();
  });

  it("rejects a malformed actor nested object", () => {
    expect(() => AuditEventSchema.parse({ ...base, actor: { type: "bogus", id: "x" } })).toThrow();
  });
});

describe("AuditEventInputSchema (append input — server computes hash/sequence/at)", () => {
  it("accepts an input omitting id/sequence/prevHash/hash/at", () => {
    const input = {
      clientId: "client_1",
      actor: { type: "agent", id: "agent_1" },
      action: "llm.call",
      summary: "LLM call metadata logged",
    };
    expect(AuditEventInputSchema.parse(input)).toMatchObject(input);
  });

  it("rejects an input that supplies a server-computed 'hash' field (not in the input shape)", () => {
    // AuditEventInputSchema strips hash/sequence/prevHash/id/at via .omit(); passing them
    // through .parse() should not resurrect them into the parsed result.
    const input = {
      clientId: "client_1",
      actor: { type: "agent", id: "agent_1" },
      action: "llm.call",
      summary: "x",
      hash: "should-be-stripped",
    };
    const parsed = AuditEventInputSchema.parse(input) as Record<string, unknown>;
    expect(parsed.hash).toBeUndefined();
  });

  it("rejects a missing required 'action'", () => {
    expect(() =>
      AuditEventInputSchema.parse({
        clientId: "client_1",
        actor: { type: "agent", id: "agent_1" },
        summary: "x",
      }),
    ).toThrow();
  });
});
