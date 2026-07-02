import { describe, it, expect } from "vitest";
import {
  mockAppMap,
  mockCleanAppMap,
  mockCandidateFindings,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  CANDIDATE_SQLI_ID,
  CANDIDATE_DEP_ID,
} from "@montr/fixtures";
import {
  AppMapSchema,
  Layer2OutputSchema,
  ProbableFindingSchema,
  type CandidateFinding,
} from "@montr/contracts";
import { correlate } from "@montr/correlation";

const base = { clientId: CLIENT_ID, scanId: SCAN_ID, now: FIXED_NOW } as const;

describe("@montr/correlation — Layer 2 correlate (the moat)", () => {
  it("emits a contract-valid Layer2Output", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });
    expect(() => Layer2OutputSchema.parse(out)).not.toThrow();
    for (const p of out.probable) expect(() => ProbableFindingSchema.parse(p)).not.toThrow();
  });

  it("ranks by reachability × exposure × impact, not raw CVSS", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });

    // SQLi and CORS both have raw severity high/medium, but ranking is driven by
    // reachability × exposure × impact — SQLi first, CORS last.
    expect(out.probable.map((p) => p.category)).toEqual([
      "sql_injection",
      "xss",
      "hardcoded_secret",
      "permissive_cors",
    ]);
    expect(out.probable.map((p) => p.rank)).toEqual([1, 2, 3, 4]);

    const top = out.probable[0]!;
    expect(top.category).toBe("sql_injection");
    expect(top.exposure).toBe("public");
    expect(top.exposureScore).toBe(1);
    expect(top.reachabilityScore).toBeGreaterThanOrEqual(0.9);
    expect(top.routeId).toBe("route_users_0001");

    // Every score stays in [0,1].
    for (const p of out.probable) {
      for (const s of [p.reachabilityScore, p.exposureScore, p.impactScore]) {
        expect(s).toBeGreaterThanOrEqual(0);
        expect(s).toBeLessThanOrEqual(1);
      }
    }
  });

  it("grounds exposure in the App Map: public sink outranks a hard-coded secret off-route", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });
    const secret = out.probable.find((p) => p.category === "hardcoded_secret")!;
    const cors = out.probable.find((p) => p.category === "permissive_cors")!;

    // The secret is not on an HTTP route — reported conservatively as authed.
    expect(secret.exposure).toBe("authed");
    expect(secret.exposureScore).toBeLessThan(1);
    expect(secret.routeId).toBeUndefined();

    // Wildcard CORS on a public, non-credentialed read endpoint = low impact.
    expect(cors.exposure).toBe("public");
    expect(cors.impactScore).toBeLessThanOrEqual(0.3);
    const sqli = out.probable.find((p) => p.category === "sql_injection")!;
    expect(cors.impactScore).toBeLessThan(sqli.impactScore);
  });

  it("attaches a reachability AND an exploit hypothesis to every probable", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });
    for (const p of out.probable) {
      expect(p.reachabilityHypothesis.length).toBeGreaterThan(0);
      expect(p.exploitHypothesis.length).toBeGreaterThan(0);
    }
    const sqli = out.probable.find((p) => p.category === "sql_injection")!;
    expect(sqli.reachabilityHypothesis).toContain("orm raw query");
    expect(sqli.reachabilityHypothesis).toContain("/api/users");
    expect(sqli.exploitHypothesis.toLowerCase()).toContain("union");
  });

  it("deduplicates the same root cause reported by multiple tools into one issue", async () => {
    const sqli = mockCandidateFindings[0]!;
    // A second tool flags the SAME flow at the SOURCE line (6), not the sink (9).
    const dup: CandidateFinding = {
      ...sqli,
      id: "cand_sqli_dup_0002",
      source: "custom",
      ruleId: "custom.sqli.raw",
      location: { file: "app/api/users/route.ts", line: 6 },
    };

    const out = await correlate({ ...base, appMap: mockAppMap, candidates: [sqli, dup] });
    const sqliProbable = out.probable.filter((p) => p.category === "sql_injection");
    expect(sqliProbable).toHaveLength(1);
    expect(sqliProbable[0]!.mergedCandidateIds).toEqual(
      expect.arrayContaining([CANDIDATE_SQLI_ID, "cand_sqli_dup_0002"]),
    );
    expect(out.demoted).toHaveLength(0);
  });

  it("DEMOTES an uncorroborated candidate to the appendix — never deletes it", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });

    // The vulnerable dependency has no import-graph reachability in the App Map.
    expect(out.probable.some((p) => p.category === "vulnerable_dependency")).toBe(false);
    const demoted = out.demoted.find((d) => d.id === CANDIDATE_DEP_ID);
    expect(demoted).toBeDefined();
    // Kept verbatim, still a candidate (demoted, not mutated, not deleted).
    expect(demoted!.status).toBe("candidate");
    expect(demoted!.category).toBe("vulnerable_dependency");
  });

  it("never loses a candidate: every input is either merged into a probable or demoted", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });
    const merged = new Set(out.probable.flatMap((p) => p.mergedCandidateIds));
    const demoted = new Set(out.demoted.map((d) => d.id));
    const accounted = new Set<string>([...merged, ...demoted]);
    expect(accounted).toEqual(new Set(mockCandidateFindings.map((c) => c.id)));
  });

  it("demotes a finding whose location is not on any registered surface", async () => {
    const orphan: CandidateFinding = {
      ...mockCandidateFindings[0]!,
      id: "cand_orphan_0001",
      location: { file: "app/dead/unused.ts", line: 3 },
    };
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: [orphan] });
    expect(out.probable).toHaveLength(0);
    expect(out.demoted.map((d) => d.id)).toContain("cand_orphan_0001");
  });

  it("recognizes a validator/sanitizer that interrupts the taint path (clean repo)", async () => {
    // The clean App Map's sink is a parameterized query and its source is validated.
    const cand: CandidateFinding = {
      ...mockCandidateFindings[0]!,
      id: "cand_clean_sqli",
      location: { file: "app/api/users/route.ts", line: 9 },
    };
    const out = await correlate({ ...base, appMap: mockCleanAppMap, candidates: [cand] });
    expect(out.probable.some((p) => p.category === "sql_injection")).toBe(false);
    expect(out.demoted.map((d) => d.id)).toContain("cand_clean_sqli");
  });

  it("gates exposure by auth state: an authed route yields exposure=authed + authGate", async () => {
    const authedMap = AppMapSchema.parse({
      id: "appmap_authed",
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      repo: "https://example.internal/authed",
      branch: "main",
      commitSha: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
      createdAt: FIXED_NOW,
      languages: ["typescript"],
      frameworks: ["nextjs", "prisma"],
      routes: [
        {
          id: "route_admin_0001",
          path: "/api/admin/report",
          method: "POST",
          authState: "authenticated",
          isApiRoute: true,
          authGate: "requireSession",
          handler: { file: "app/api/admin/report/route.ts", line: 5 },
        },
      ],
      taintSources: [
        {
          kind: "request_body",
          location: { file: "app/api/admin/report/route.ts", line: 7 },
          description: "await req.json() name",
          routeId: "route_admin_0001",
        },
      ],
      taintSinks: [
        {
          kind: "orm_raw_query",
          location: { file: "app/api/admin/report/route.ts", line: 11 },
          description: "prisma.$queryRawUnsafe(`... ${name} ...`)",
        },
      ],
    });
    const cand: CandidateFinding = {
      ...mockCandidateFindings[0]!,
      id: "cand_authed_sqli",
      location: { file: "app/api/admin/report/route.ts", line: 11 },
    };
    const out = await correlate({ ...base, appMap: authedMap, candidates: [cand] });
    const p = out.probable.find((x) => x.category === "sql_injection")!;
    expect(p).toBeDefined();
    expect(p.exposure).toBe("authed");
    expect(p.exposureScore).toBeLessThan(1);
    expect(p.authGate).toBe("requireSession");
    expect(p.routeId).toBe("route_admin_0001");
  });

  it("handles an empty candidate set", async () => {
    const out = await correlate({ ...base, appMap: mockAppMap, candidates: [] });
    expect(out.probable).toEqual([]);
    expect(out.demoted).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const a = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });
    const b = await correlate({ ...base, appMap: mockAppMap, candidates: mockCandidateFindings });
    expect(a).toEqual(b);
  });
});
