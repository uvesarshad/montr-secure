import { describe, it, expect } from "vitest";
import {
  AppMapSchema,
  CandidateFindingSchema,
  ProbableFindingSchema,
  ConfirmedFindingSchema,
  UnconfirmedFindingSchema,
  FixSchema,
  PullRequestSchema,
  ScanSchema,
  ReportSchema,
  Layer5OutputSchema,
  LLMRequestSchema,
} from "@montr/contracts";
import {
  mockAppMap,
  mockCleanAppMap,
  mockCandidateFindings,
  mockProbableFindings,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockFixes,
  mockPullRequest,
  mockScan,
  mockReport,
  mockLayer5Output,
  createFakeLlmGateway,
  groundTruthManifest,
} from "@montr/fixtures";

describe("@montr/fixtures validate against contracts", () => {
  it("app maps are valid", () => {
    expect(AppMapSchema.safeParse(mockAppMap).success).toBe(true);
    expect(AppMapSchema.safeParse(mockCleanAppMap).success).toBe(true);
  });

  it("all finding tiers are valid", () => {
    for (const c of mockCandidateFindings)
      expect(CandidateFindingSchema.safeParse(c).success).toBe(true);
    for (const p of mockProbableFindings)
      expect(ProbableFindingSchema.safeParse(p).success).toBe(true);
    for (const c of mockConfirmedFindings)
      expect(ConfirmedFindingSchema.safeParse(c).success).toBe(true);
    for (const u of mockUnconfirmedFindings)
      expect(UnconfirmedFindingSchema.safeParse(u).success).toBe(true);
  });

  it("fixes, PR, scan, report, layer output are valid", () => {
    for (const f of mockFixes) expect(FixSchema.safeParse(f).success).toBe(true);
    expect(PullRequestSchema.safeParse(mockPullRequest).success).toBe(true);
    expect(ScanSchema.safeParse(mockScan).success).toBe(true);
    expect(ReportSchema.safeParse(mockReport).success).toBe(true);
    expect(Layer5OutputSchema.safeParse(mockLayer5Output).success).toBe(true);
  });

  it("report headlines confirmed findings only, PRs are auto-eligible-only", () => {
    expect(mockReport.executiveSummary.totalConfirmed).toBe(mockConfirmedFindings.length);
    expect(mockReport.fixStatus.humanRequiredFixIds).toEqual([]);
    expect(mockReport.fixStatus.pullRequests.length).toBeGreaterThan(0);
  });
});

describe("ground-truth manifest", () => {
  it("has a vulnerable repo with 5 findings and a clean repo with 0", () => {
    const vuln = groundTruthManifest.repos.find((r) => r.kind === "vulnerable");
    const clean = groundTruthManifest.repos.find((r) => r.kind === "clean");
    expect(vuln?.expectedFindings.length).toBe(5);
    expect(clean?.expectedFindings.length).toBe(0);
    // 3 exploitable (confirmed), 2 present-but-demoted.
    expect(vuln?.expectedFindings.filter((f) => f.exploitable).length).toBe(3);
  });
});

describe("fake LLM adapter is deterministic and offline", () => {
  const gateway = createFakeLlmGateway();
  const request = LLMRequestSchema.parse({
    messages: [{ role: "user", content: "confirm this" }],
    maxTokens: 256,
    metadata: { purpose: "confirmation" },
  });

  it("returns identical responses for identical requests", async () => {
    const a = await gateway.complete(request);
    const b = await gateway.complete(request);
    expect(a).toEqual(b);
    expect(a.usage.totalTokens).toBe(a.usage.inputTokens + a.usage.outputTokens);
    expect(a.latencyMs).toBe(42);
  });

  it("streams text_delta then message_done", async () => {
    const events = [];
    for await (const ev of gateway.stream(request)) events.push(ev);
    expect(events[0]?.type).toBe("text_delta");
    expect(events.at(-1)?.type).toBe("message_done");
  });
});
