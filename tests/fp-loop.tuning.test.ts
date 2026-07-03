import { describe, it, expect } from "vitest";
import {
  Layer2OutputSchema,
  Layer3OutputSchema,
  type AuditEventInput,
  type ConfirmedFinding,
} from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import {
  mockAppMap,
  mockCandidateFindings,
  mockProbableFindings,
  mockConfirmedFindings,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  CANDIDATE_SQLI_ID,
} from "@montr/fixtures";
import { correlate } from "@montr/correlation";
import { confirmFindings, type ConfirmInput } from "@montr/confirm";
import {
  buildFalsePositiveTuning,
  deriveFalsePositiveRecord,
} from "../packages/qa/src/regression-corpus";
import { makeFakeAudit } from "./correlation.helpers";

/**
 * §15 tuning hook — the regression corpus deterministically down-ranks/skips a
 * known false positive in BOTH Layer 2 (correlation) and Layer 3 (confirmation).
 * Additive + fail-safe: it only demotes/suppresses, never promotes or confirms.
 */

const sqliConfirmed: ConfirmedFinding = mockConfirmedFindings[0]!; // SQLi @ app/api/users/route.ts:9

// Build the tuning matcher from a real corpus record (exact-line match).
const tuning = buildFalsePositiveTuning([
  deriveFalsePositiveRecord({
    finding: sqliConfirmed,
    operator: { id: "user_op_1", role: "operator" },
    reason: "reviewed: query is parameterized upstream",
    markedAt: FIXED_NOW,
  }),
]);

describe("Layer 2 correlation — FP tuning demotes a known false positive", () => {
  const base = { clientId: CLIENT_ID, scanId: SCAN_ID, appMap: mockAppMap, now: FIXED_NOW };

  it("promotes SQLi to probable without tuning", async () => {
    const out = await correlate({ ...base, candidates: mockCandidateFindings });
    expect(out.probable.map((p) => p.category)).toContain("sql_injection");
  });

  it("demotes the known-FP SQLi to the appendix (kept, never deleted) + audits it", async () => {
    const { client: audit, events } = makeFakeAudit();
    const out = await correlate({
      ...base,
      candidates: mockCandidateFindings,
      audit,
      fpTuning: tuning,
    });

    expect(() => Layer2OutputSchema.parse(out)).not.toThrow();
    // Suppressed from the probable set...
    expect(out.probable.map((p) => p.category)).not.toContain("sql_injection");
    // ...but KEPT in the demoted appendix (never deleted).
    expect(out.demoted.some((c) => c.id === CANDIDATE_SQLI_ID)).toBe(true);

    const demoteEvent = events.find(
      (e: AuditEventInput) =>
        e.action === "finding.demoted" && e.metadata?.knownFalsePositive === true,
    );
    expect(demoteEvent).toBeDefined();
    expect(demoteEvent!.metadata?.category).toBe("sql_injection");
    expect(String(demoteEvent!.metadata?.reason)).toContain("regression corpus");
  });

  it("is deterministic across runs", async () => {
    const a = await correlate({ ...base, candidates: mockCandidateFindings, fpTuning: tuning });
    const b = await correlate({ ...base, candidates: mockCandidateFindings, fpTuning: tuning });
    expect(a.probable.map((p) => p.id)).toEqual(b.probable.map((p) => p.id));
    expect(a.demoted.map((c) => c.id)).toEqual(b.demoted.map((c) => c.id));
  });

  it("is inert when the corpus has no matching signature (no guardrail change)", async () => {
    const emptyTuning = buildFalsePositiveTuning([]);
    const withHook = await correlate({
      ...base,
      candidates: mockCandidateFindings,
      fpTuning: emptyTuning,
    });
    const without = await correlate({ ...base, candidates: mockCandidateFindings });
    expect(withHook.probable.map((p) => p.id)).toEqual(without.probable.map((p) => p.id));
  });
});

describe("Layer 3 confirmation — FP tuning suppresses a known false positive", () => {
  function baseInput(): ConfirmInput {
    return {
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: mockAppMap,
      probable: mockProbableFindings,
      allowLive: false,
      config: getHardenedDefaults(),
    };
  }
  const NOW = (): string => FIXED_NOW;

  it("confirms SQLi + XSS without tuning", async () => {
    const out = await confirmFindings(baseInput(), { now: NOW });
    expect(out.confirmed.map((c) => c.category).sort()).toEqual(["sql_injection", "xss"]);
  });

  it("routes the known-FP SQLi to the Unconfirmed appendix + audits it", async () => {
    const events: AuditEventInput[] = [];
    const audit = { append: (ev: AuditEventInput) => void events.push(ev) };
    const out = await confirmFindings(baseInput(), { now: NOW, audit, fpTuning: tuning });

    expect(() => Layer3OutputSchema.parse(out)).not.toThrow();
    // SQLi is NO LONGER confirmed...
    expect(out.confirmed.map((c) => c.category)).not.toContain("sql_injection");
    expect(out.confirmed.map((c) => c.category)).toContain("xss");
    // ...it is kept in the appendix with a clear reason (never deleted).
    const suppressed = out.unconfirmed.find((u) => u.category === "sql_injection");
    expect(suppressed).toBeDefined();
    expect(suppressed!.unconfirmedReason).toContain("regression corpus");

    const demoteEvent = events.find(
      (e) => e.action === "finding.demoted" && e.metadata?.reason === "known_false_positive",
    );
    expect(demoteEvent).toBeDefined();
    expect(demoteEvent!.metadata?.category).toBe("sql_injection");
  });

  it("never confirms via the hook — a suppressed finding is only withheld (fail-safe)", async () => {
    const withHook = await confirmFindings(baseInput(), { now: NOW, fpTuning: tuning });
    const without = await confirmFindings(baseInput(), { now: NOW });
    // The hook can only REDUCE confirmations, never add one.
    expect(withHook.confirmed.length).toBeLessThan(without.confirmed.length);
    expect(withHook.confirmed.length + withHook.unconfirmed.length).toBe(
      without.confirmed.length + without.unconfirmed.length,
    );
  });
});
