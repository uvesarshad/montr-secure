import { describe, it, expect } from "vitest";
import {
  ProofOfFixTestSchema,
  FixSchema,
  VcsProviderSchema,
  PullRequestStatusSchema,
  PullRequestSchema,
} from "./fix.js";

/**
 * Fix contracts (§7 L4/L5) directly feed the human-required / auto-eligible
 * gate: `riskClass` + a mandatory `riskClassRationale` are the auditable
 * record of why a fix was (or wasn't) allowed to auto-merge (§11, golden
 * rule #3). PullRequestSchema encodes "PRs only, never direct commits"
 * (golden rule #5) via a required, non-empty fixIds array.
 */

const NOW = "2026-08-19T00:00:00.000Z";

describe("ProofOfFixTestSchema (must fail pre-patch, pass post-patch — §7 L4)", () => {
  it("accepts a well-formed proof-of-fix test", () => {
    const test = { code: "expect(x).toBe(1)", failsPrePatch: true, passesPostPatch: true };
    expect(ProofOfFixTestSchema.parse(test)).toMatchObject(test);
  });

  it("rejects a missing 'code' field", () => {
    expect(() =>
      ProofOfFixTestSchema.parse({ failsPrePatch: true, passesPostPatch: true }),
    ).toThrow();
  });

  it("rejects a missing 'failsPrePatch' flag", () => {
    expect(() => ProofOfFixTestSchema.parse({ code: "x", passesPostPatch: true })).toThrow();
  });
});

describe("FixSchema (riskClass gates human-required vs auto-eligible)", () => {
  const base = {
    id: "fix_1",
    scanId: "scan_1",
    clientId: "client_1",
    confirmedFindingId: "cf_1",
    patch: "--- a/x\n+++ b/x\n",
    rationale: "Parameterize the query.",
    proofOfFixTest: { code: "x", failsPrePatch: true, passesPostPatch: true },
    riskClass: "auto-eligible",
    riskClassRationale: "Pure input-validation change, no auth/session/crypto surface touched.",
    createdAt: NOW,
  };

  it("accepts a well-formed auto-eligible fix, defaulting status to 'proposed'", () => {
    const parsed = FixSchema.parse(base);
    expect(parsed.status).toBe("proposed");
  });

  it("accepts a human-required fix with its rationale", () => {
    const fix = {
      ...base,
      riskClass: "human-required",
      riskClassRationale: "Touches session cookie handling — hard rule (§11, golden rule #3).",
    };
    expect(FixSchema.parse(fix).riskClass).toBe("human-required");
  });

  it("rejects a fix missing the required riskClassRationale (auditability requirement)", () => {
    const { riskClassRationale: _r, ...rest } = base;
    expect(() => FixSchema.parse(rest)).toThrow();
  });

  it("rejects an invalid riskClass value", () => {
    expect(() => FixSchema.parse({ ...base, riskClass: "maybe-eligible" })).toThrow();
  });

  it("rejects an invalid fix status", () => {
    expect(() => FixSchema.parse({ ...base, status: "in-review" })).toThrow();
  });

  it("rejects a missing patch", () => {
    const { patch: _patch, ...rest } = base;
    expect(() => FixSchema.parse(rest)).toThrow();
  });
});

describe("VcsProviderSchema / PullRequestStatusSchema", () => {
  it("VcsProvider accepts github/gitlab and rejects others", () => {
    expect(VcsProviderSchema.parse("github")).toBe("github");
    expect(VcsProviderSchema.parse("gitlab")).toBe("gitlab");
    expect(() => VcsProviderSchema.parse("bitbucket")).toThrow();
  });

  it("PullRequestStatus accepts the lifecycle values and rejects others", () => {
    for (const s of ["draft", "open", "merged", "closed"]) {
      expect(PullRequestStatusSchema.parse(s)).toBe(s);
    }
    expect(() => PullRequestStatusSchema.parse("archived")).toThrow();
  });
});

describe("PullRequestSchema (auto-eligible fixes → PR only, never a direct commit)", () => {
  const base = {
    id: "pr_1",
    scanId: "scan_1",
    clientId: "client_1",
    provider: "github",
    branch: "montr/fix-sqli-1",
    title: "Fix SQL injection in /users",
    bodySummary: "Parameterizes the raw query.",
    fixIds: ["fix_1"],
    createdAt: NOW,
  };

  it("accepts a well-formed PR, defaulting status to 'open' and baseBranch to 'main'", () => {
    const parsed = PullRequestSchema.parse(base);
    expect(parsed.status).toBe("open");
    expect(parsed.baseBranch).toBe("main");
  });

  it("rejects a PR with an empty fixIds array (must reference at least one fix)", () => {
    expect(() => PullRequestSchema.parse({ ...base, fixIds: [] })).toThrow();
  });

  it("rejects an empty branch name", () => {
    expect(() => PullRequestSchema.parse({ ...base, branch: "" })).toThrow();
  });

  it("rejects an invalid VCS provider", () => {
    expect(() => PullRequestSchema.parse({ ...base, provider: "svn" })).toThrow();
  });
});
