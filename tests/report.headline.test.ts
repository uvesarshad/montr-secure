import { describe, it, expect } from "vitest";
import type { CandidateFinding } from "@montr/contracts";
import {
  buildReport,
  renderHeadline,
  buildHeadline,
  assertConfirmedOnlyHeadline,
} from "@montr/report";
import {
  mockScan,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
  mockFixes,
  mockCandidateFindings,
  mockCostRollup,
  FIXED_LATER,
} from "@montr/fixtures";

/** Simulate the deliberately over-inclusive Layer-1 pile ("500 issues"). */
const RAW_PILE = 500;
function hugeCandidatePile(): CandidateFinding[] {
  const seed = mockCandidateFindings[0]!;
  return Array.from({ length: RAW_PILE }, (_, i) => ({ ...seed, id: `cand_pile_${i}` }));
}

const input = () => ({
  scan: mockScan,
  confirmed: mockConfirmedFindings, // exactly 2 confirmed
  unconfirmed: mockUnconfirmedFindings,
  fixes: mockFixes,
  costRollup: mockCostRollup,
  autoApply: false,
  generatedAt: FIXED_LATER,
  candidates: hugeCandidatePile(),
});

describe("@montr/report headline safety — ⛔ NEVER headline raw counts (§12)", () => {
  it("headline reflects CONFIRMED count, never the raw candidate pile", async () => {
    const { report } = await buildReport(input());
    const headline = renderHeadline(report);
    expect(headline).toContain("2 confirmed");
    // The 500-issue pile must not appear anywhere in the headline.
    expect(headline).not.toContain(String(RAW_PILE));
  });

  it("executive summary never encodes the raw pile size", async () => {
    const { report } = await buildReport(input());
    const serialized = JSON.stringify(report.executiveSummary);
    expect(serialized).not.toContain(String(RAW_PILE));
    expect(report.executiveSummary.totalConfirmed).toBe(2);
  });

  it("assertConfirmedOnlyHeadline passes for a confirmed-only summary, even beside a huge pile", async () => {
    const { report } = await buildReport(input());
    expect(() => assertConfirmedOnlyHeadline(report, RAW_PILE)).not.toThrow();
  });

  it("assertConfirmedOnlyHeadline throws if totalConfirmed is tampered to the raw count", async () => {
    const { report } = await buildReport(input());
    const tampered = {
      ...report,
      executiveSummary: {
        ...report.executiveSummary,
        totalConfirmed: RAW_PILE,
        confirmedBySeverity: { ...report.executiveSummary.confirmedBySeverity, info: RAW_PILE - 2 },
      },
    };
    expect(() => assertConfirmedOnlyHeadline(tampered, RAW_PILE)).toThrow();
  });

  it("buildHeadline severity breakdown omits empty buckets, highest-first", async () => {
    const { report } = await buildReport(input());
    const h = buildHeadline(report);
    expect(h.bySeverity).toEqual([
      { severity: "critical", count: 1 },
      { severity: "high", count: 1 },
    ]);
    expect(h.totalConfirmed).toBe(2);
  });

  it("headline surfaces posture delta when a previous scan is present (still no raw count)", async () => {
    const { report } = await buildReport({
      ...input(),
      previous: { scanId: "scan_prev", confirmed: [mockConfirmedFindings[0]!] },
    });
    const headline = renderHeadline(report);
    expect(headline).toContain("Posture");
    expect(headline).not.toContain(String(RAW_PILE));
  });
});
