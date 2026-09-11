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
  type AppMap,
  type CandidateFinding,
} from "@montr/contracts";
import { correlate, AppMapIndex, groundCandidate } from "@montr/correlation";

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

  it("cites the ORM model actually implicated by the finding, not just appMap.ormModels[0]", async () => {
    // Two models registered ("Order" sorts before "User"), two SQLi sinks on
    // two different routes — the exploit hypothesis must name the model that
    // matches THIS finding's route/sink, not always the first model in the map.
    const multiModelMap = AppMapSchema.parse({
      id: "appmap_multi_model",
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      repo: "https://example.internal/montr/multi-model",
      branch: "main",
      commitSha: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
      createdAt: FIXED_NOW,
      languages: ["typescript"],
      frameworks: ["nextjs", "prisma"],
      routes: [
        {
          id: "route_orders_0001",
          path: "/api/orders",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/orders/route.ts", line: 5 },
        },
        {
          id: "route_users_multi_0001",
          path: "/api/users",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/users/route.ts", line: 5 },
        },
      ],
      dataStores: [{ kind: "postgres", name: "app_db", accessedVia: "prisma" }],
      ormModels: [
        { name: "Order", dataStore: "app_db", file: "prisma/schema.prisma", fields: [] },
        { name: "User", dataStore: "app_db", file: "prisma/schema.prisma", fields: [] },
      ],
      taintSources: [
        {
          kind: "query_param",
          location: { file: "app/api/orders/route.ts", line: 6 },
          description: "req.nextUrl.searchParams.get('q')",
          routeId: "route_orders_0001",
        },
        {
          kind: "query_param",
          location: { file: "app/api/users/route.ts", line: 6 },
          description: "req.nextUrl.searchParams.get('q')",
          routeId: "route_users_multi_0001",
        },
      ],
      taintSinks: [
        {
          kind: "orm_raw_query",
          location: { file: "app/api/orders/route.ts", line: 9 },
          description: "prisma.order.$queryRawUnsafe(`... ${q} ...`)",
        },
        {
          kind: "orm_raw_query",
          location: { file: "app/api/users/route.ts", line: 9 },
          description: "prisma.user.$queryRawUnsafe(`... ${q} ...`)",
        },
      ],
      stale: false,
      rebuildPolicy: "rebuild_on_stale_commit",
    });

    const ordersCand: CandidateFinding = {
      ...mockCandidateFindings[0]!,
      id: "cand_orders_sqli",
      location: { file: "app/api/orders/route.ts", line: 9 },
    };
    const usersCand: CandidateFinding = {
      ...mockCandidateFindings[0]!,
      id: "cand_users_sqli",
      location: { file: "app/api/users/route.ts", line: 9 },
    };

    const out = await correlate({
      ...base,
      appMap: multiModelMap,
      candidates: [ordersCand, usersCand],
    });
    const orders = out.probable.find((p) => p.routeId === "route_orders_0001")!;
    const users = out.probable.find((p) => p.routeId === "route_users_multi_0001")!;
    expect(orders).toBeDefined();
    expect(users).toBeDefined();
    expect(orders.exploitHypothesis).toContain("the Order model");
    expect(orders.exploitHypothesis).not.toContain("the User model");
    expect(users.exploitHypothesis).toContain("the User model");
    expect(users.exploitHypothesis).not.toContain("the Order model");
  });

  it("A24: resolves a cross-file taint flow (source in file A, sink in file B) via taintFlows — the same-file heuristic alone cannot see this", async () => {
    // The tainted source lives in the route handler; the sink lives in an
    // entirely separate db-helper file with NO taint source/sink registered
    // in it at all — the old same-file proximity heuristic would find nothing
    // in the sink's own file and demote this candidate. `taintFlows` supplies
    // the structural proof a real call-graph resolver would have produced.
    const crossFileMap: AppMap = AppMapSchema.parse({
      id: "appmap_crossfile_0001",
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      repo: "https://example.internal/montr/crossfile",
      branch: "main",
      commitSha: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
      createdAt: FIXED_NOW,
      languages: ["typescript"],
      frameworks: ["nextjs", "prisma"],
      routes: [
        {
          id: "route_report_0001",
          path: "/api/report",
          method: "GET",
          authState: "public",
          isApiRoute: true,
          handler: { file: "app/api/report/route.ts", line: 5 },
        },
      ],
      // Deliberately NO taintSources/taintSinks entries — proving the verdict
      // below comes from `taintFlows`, not the nearest-line heuristic.
      taintFlows: [
        {
          sourceLocation: { file: "app/api/report/route.ts", line: 6 },
          sourceKind: "query_param",
          throughFunction: "runReportQuery",
          throughLocation: { file: "lib/db.ts", line: 3 },
          sinkLocation: { file: "lib/db.ts", line: 5 },
          sinkKind: "sql_query",
          resolution: "direct-call",
          hops: 1,
          crossFile: true,
        },
      ],
      stale: false,
      rebuildPolicy: "rebuild_on_stale_commit",
    });

    const cand: CandidateFinding = {
      ...mockCandidateFindings[0]!,
      id: "cand_crossfile_sqli",
      category: "sql_injection",
      // The candidate's own location is the SINK side (file B), per the flow's
      // sinkLocation — this is the file a real scanner would flag.
      location: { file: "lib/db.ts", line: 5 },
    };

    // Unit-level: groundCandidate must report the resolved-flow verdict.
    const index = new AppMapIndex(crossFileMap);
    const g = groundCandidate(cand, index);
    expect(g.taintFlowKind).toBe("cross-file-resolved");
    expect(g.matchedFlow).toEqual(crossFileMap.taintFlows[0]);
    expect(g.taintReaches).toBe(true);
    expect(g.sanitizerInterrupts).toBe(false);
    expect(g.corroborated).toBe(true);
    expect(g.demote).toBe(false);

    // End-to-end: the finding survives correlation as a probable, not demoted.
    const out = await correlate({ ...base, appMap: crossFileMap, candidates: [cand] });
    expect(out.demoted).toHaveLength(0);
    const probable = out.probable.find((p) => p.category === "sql_injection");
    expect(probable).toBeDefined();
    expect(probable!.reachabilityScore).toBeGreaterThanOrEqual(0.9);
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

describe("A9 — semantic grounding (informational only, never a scoring input)", () => {
  it("appends a semantic-search note to the reachability hypothesis without touching scores", async () => {
    const calls: Array<{ queryText: string; topK?: number }> = [];
    const withoutSemantic = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
    });
    const withSemantic = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      semanticSearch: async (queryText, topK) => {
        calls.push({ queryText, topK });
        return [
          {
            id: "chunk_similar",
            file: "app/api/admin/route.ts",
            startLine: 20,
            endLine: 28,
            language: "typescript",
            kind: "function",
            symbolName: "GET",
            content: "prisma.$queryRawUnsafe(...)",
            similarity: 0.91,
          },
          // A low-similarity match must be filtered out.
          {
            id: "chunk_weak",
            file: "app/api/other/route.ts",
            startLine: 1,
            endLine: 5,
            language: "typescript",
            kind: "function",
            symbolName: "POST",
            content: "unrelated",
            similarity: 0.2,
          },
          // A match in the candidate's OWN file must be filtered out (it
          // trivially "matches itself").
          {
            id: "chunk_self",
            file: "app/api/users/route.ts",
            startLine: 9,
            endLine: 9,
            language: "typescript",
            kind: "function",
            symbolName: "GET",
            content: "self",
            similarity: 0.99,
          },
        ];
      },
    });

    expect(calls.length).toBeGreaterThan(0);
    expect(calls[0]?.queryText).toContain("prisma.$queryRawUnsafe");

    const before = withoutSemantic.probable.find((p) => p.category === "sql_injection")!;
    const after = withSemantic.probable.find((p) => p.category === "sql_injection")!;

    // Scores are byte-identical — semantic search never feeds scoring.
    expect(after.reachabilityScore).toBe(before.reachabilityScore);
    expect(after.exposureScore).toBe(before.exposureScore);
    expect(after.impactScore).toBe(before.impactScore);
    expect(after.rank).toBe(before.rank);
    expect(after.exploitHypothesis).toBe(before.exploitHypothesis);

    // Only the reachability hypothesis gains the additive, factual note —
    // citing the strong cross-file match but not the weak or self match.
    expect(after.reachabilityHypothesis).toContain(before.reachabilityHypothesis);
    expect(after.reachabilityHypothesis).toContain("app/api/admin/route.ts:20");
    expect(after.reachabilityHypothesis).not.toContain("app/api/other/route.ts");
    expect(after.reachabilityHypothesis).not.toContain("app/api/users/route.ts:9 (");
  });

  it("degrades silently when semanticSearch throws (never fails correlation)", async () => {
    const out = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      semanticSearch: async () => {
        throw new Error("pgvector extension not installed");
      },
    });
    expect(() => Layer2OutputSchema.parse(out)).not.toThrow();
    expect(out.probable.length).toBeGreaterThan(0);
  });

  it("is a no-op when omitted (default byte-identical behavior)", async () => {
    const withDefault = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
    });
    const withUndefinedResults = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      semanticSearch: async () => [],
    });
    const sqli1 = withDefault.probable.find((p) => p.category === "sql_injection")!;
    const sqli2 = withUndefinedResults.probable.find((p) => p.category === "sql_injection")!;
    expect(sqli2.reachabilityHypothesis).toBe(sqli1.reachabilityHypothesis);
  });
});
