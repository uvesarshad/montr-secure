import { describe, it, expect } from "vitest";
import {
  PullRequestSchema,
  FixSchema,
  ScanSchema,
  AuditEventSchema,
  GateNotPassedError,
  type AuditEvent,
  type AuditEventInput,
  type Fix,
  type GateState,
  type PullRequest,
  type Scan,
} from "@montr/contracts";
import type { AuditLogClient } from "@montr/telemetry";
import {
  buildReport,
  planAutoFixPullRequests,
  openAutoFixPullRequests,
  prGateDecision,
  assertPrGate,
  isGatePassed,
  type AutoFixPrPlan,
  type PullRequestOpener,
} from "@montr/report";
import {
  mockScan,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockFixes,
  mockCostRollup,
  FIXED_NOW,
  FIXED_LATER,
  FIX_SQLI_ID,
  FIX_XSS_ID,
} from "@montr/fixtures";

/** Offline VCS opener — records plans, never touches a network or a git binary. */
class FakeOpener implements PullRequestOpener {
  readonly provider = "github" as const;
  readonly opened: AutoFixPrPlan[] = [];
  async open(plan: AutoFixPrPlan): Promise<PullRequest> {
    this.opened.push(plan);
    return PullRequestSchema.parse({
      id: plan.prId,
      scanId: plan.scanId,
      clientId: plan.clientId,
      provider: plan.provider,
      url: `https://vcs.internal/montr/pr/${plan.prId}`,
      number: this.opened.length,
      branch: plan.branch,
      baseBranch: plan.baseBranch,
      title: plan.title,
      bodySummary: plan.bodySummary,
      fixIds: plan.fixIds,
      status: "open",
      createdAt: FIXED_NOW,
    });
  }
}

/** Capturing audit client (implements the frozen AuditLogClient contract). */
class FakeAudit implements AuditLogClient {
  readonly events: AuditEventInput[] = [];
  async append(input: AuditEventInput): Promise<AuditEvent> {
    this.events.push(input);
    return AuditEventSchema.parse({
      id: `audit_${this.events.length}`,
      clientId: input.clientId,
      sequence: this.events.length,
      ...(input.scanId ? { scanId: input.scanId } : {}),
      actor: input.actor,
      action: input.action,
      ...(input.targetType ? { targetType: input.targetType } : {}),
      ...(input.targetId ? { targetId: input.targetId } : {}),
      summary: input.summary,
      metadata: input.metadata ?? {},
      prevHash: "",
      hash: `h${this.events.length}`,
      at: FIXED_NOW,
    });
  }
  async list(): Promise<AuditEvent[]> {
    return [];
  }
  async verifyChain(): Promise<boolean> {
    return true;
  }
}

function scanWithGate(gateState: GateState): Scan {
  return ScanSchema.parse({ ...mockScan, gateState });
}

const humanRequiredFix: Fix = FixSchema.parse({
  ...mockFixes[1],
  id: FIX_XSS_ID,
  riskClass: "human-required",
  riskClassRationale: "Touches access-control — always human-required (§11).",
});

const baseInput = () => ({
  scan: mockScan, // gateState "approved"
  confirmed: mockConfirmedFindings,
  unconfirmed: mockUnconfirmedFindings,
  fixes: mockFixes, // both auto-eligible
  costRollup: mockCostRollup,
  generatedAt: FIXED_LATER,
});

describe("@montr/report PR gate — ⛔ no PR without the auto-eligible bar OR approver (§7 L5)", () => {
  it("permits an auto-eligible fix only when auto-apply is on AND the gate passed", () => {
    const fix = mockFixes[0]!;
    expect(prGateDecision({ autoApply: true, gateState: "approved" }, fix).eligible).toBe(true);
    expect(prGateDecision({ autoApply: true, gateState: "auto_approved" }, fix).eligible).toBe(
      true,
    );
    expect(prGateDecision({ autoApply: false, gateState: "approved" }, fix)).toEqual({
      eligible: false,
      reason: "auto-apply-disabled",
    });
    expect(prGateDecision({ autoApply: true, gateState: "fix_gate_pending" }, fix)).toEqual({
      eligible: false,
      reason: "gate-not-passed",
    });
  });

  it("NEVER permits a human-required fix — even with explicit approver approval", () => {
    expect(prGateDecision({ autoApply: true, gateState: "approved" }, humanRequiredFix)).toEqual({
      eligible: false,
      reason: "not-auto-eligible",
    });
    expect(() =>
      assertPrGate({ autoApply: true, gateState: "approved" }, humanRequiredFix),
    ).toThrow(GateNotPassedError);
  });

  it("only auto_approved / approved states count as gate-passed", () => {
    expect(isGatePassed("auto_approved")).toBe(true);
    expect(isGatePassed("approved")).toBe(true);
    for (const s of [
      "not_started",
      "fix_gate_pending",
      "rejected",
      "blocked",
      "running",
    ] as const) {
      expect(isGatePassed(s)).toBe(false);
    }
  });
});

describe("@montr/report auto-fix flow — PRs only, never direct commits", () => {
  it("opens one PR per auto-eligible fix; each targets a NON-base branch", async () => {
    const opener = new FakeOpener();
    const prs = await openAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: true,
      opener,
    });
    expect(prs).toHaveLength(2); // per-fix default
    for (const plan of opener.opened) {
      expect(plan.branch).not.toBe(plan.baseBranch); // ⛔ never a direct commit
      expect(plan.branch.startsWith("montr/")).toBe(true);
      expect(plan.fixIds).toHaveLength(1);
    }
    expect(prs.every((pr) => pr.status === "open" && pr.url?.startsWith("https://"))).toBe(true);
  });

  it("PR body carries the rationale and the proof-of-fix test", async () => {
    const plans = planAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: true,
    });
    const sqliPlan = plans.find((p) => p.fixIds.includes(FIX_SQLI_ID))!;
    expect(sqliPlan.bodySummary).toContain(mockFixes[0]!.rationale);
    expect(sqliPlan.bodySummary).toContain(mockFixes[0]!.proofOfFixTest.code);
    expect(sqliPlan.bodySummary).toContain("Proof-of-fix test");
  });

  it("human-required fixes NEVER reach the opener (recommendations only)", async () => {
    const opener = new FakeOpener();
    const prs = await openAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: [mockFixes[0]!, humanRequiredFix],
      autoApply: true,
      opener,
    });
    expect(prs).toHaveLength(1);
    const openedFixIds = opener.opened.flatMap((p) => p.fixIds);
    expect(openedFixIds).toContain(FIX_SQLI_ID);
    expect(openedFixIds).not.toContain(FIX_XSS_ID);
  });

  it("opens NOTHING when the gate has not passed (even with auto-apply + opener)", async () => {
    const opener = new FakeOpener();
    const prs = await openAutoFixPullRequests({
      scan: scanWithGate("fix_gate_pending"),
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: true,
      opener,
    });
    expect(prs).toHaveLength(0);
    expect(opener.opened).toHaveLength(0);
  });

  it("opens NOTHING when auto-apply is off", async () => {
    const opener = new FakeOpener();
    const prs = await openAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: false,
      opener,
    });
    expect(prs).toHaveLength(0);
  });

  it("opens NOTHING (but still classifies) when no opener is wired", async () => {
    const prs = await openAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: true,
    });
    expect(prs).toHaveLength(0);
  });

  it("grouped strategy bundles auto-eligible fixes into a single reviewable PR", async () => {
    const opener = new FakeOpener();
    const prs = await openAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: true,
      opener,
      prStrategy: "grouped",
    });
    expect(prs).toHaveLength(1);
    expect(prs[0]!.fixIds).toEqual([FIX_SQLI_ID, FIX_XSS_ID]);
    expect(prs[0]!.branch).not.toBe(prs[0]!.baseBranch);
  });

  it("audit-logs every opened PR as fix.pr_opened with NO code/patch body in metadata", async () => {
    const audit = new FakeAudit();
    await openAutoFixPullRequests({
      scan: mockScan,
      confirmed: mockConfirmedFindings,
      fixes: mockFixes,
      autoApply: true,
      opener: new FakeOpener(),
      audit,
    });
    expect(audit.events).toHaveLength(2);
    expect(audit.events.every((e) => e.action === "fix.pr_opened")).toBe(true);
    for (const e of audit.events) {
      const serialized = JSON.stringify(e.metadata);
      // The patch body must never land in an audit record (golden rule #1).
      expect(serialized).not.toContain("queryRawUnsafe");
      expect(serialized).not.toContain("dangerouslySetInnerHTML");
      expect(e.metadata).not.toHaveProperty("patch");
    }
  });
});

describe("@montr/report buildReport ⇄ PR integration", () => {
  it("embeds opened PRs and marks their fixes pr-open", async () => {
    const opener = new FakeOpener();
    const out = await buildReport({ ...baseInput(), autoApply: true, opener });
    expect(out.pullRequests).toHaveLength(2);
    // Layer5Output.pullRequests and the report's fixStatus reference the same PRs.
    expect(out.report.fixStatus.pullRequests).toEqual(out.pullRequests);
    const sqli = out.report.confirmedFindings.find((rf) => rf.finding.category === "sql_injection");
    expect(sqli?.fix?.status).toBe("pr-open");
    expect(sqli?.fix?.pullRequestId).toBeDefined();
  });

  it("with auto-apply on but gate not passed, opens nothing yet still lists auto-eligible fixes", async () => {
    const opener = new FakeOpener();
    const out = await buildReport({
      ...baseInput(),
      scan: scanWithGate("fix_gate_pending"),
      autoApply: true,
      opener,
    });
    expect(out.pullRequests).toHaveLength(0);
    expect(out.report.fixStatus.autoEligibleFixIds).toEqual([FIX_SQLI_ID, FIX_XSS_ID]);
    const sqli = out.report.confirmedFindings.find((rf) => rf.finding.category === "sql_injection");
    expect(sqli?.fix?.status).toBe("proposed"); // not opened → unchanged
  });
});
