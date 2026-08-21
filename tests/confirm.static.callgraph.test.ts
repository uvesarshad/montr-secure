/**
 * A21 — Layer 3 static confirmation's cross-function fallback.
 *
 * `packages/confirm/src/static.ts`'s `findSink`/`findSource` previously only
 * ever looked at SAME-FILE `appMap.taintSinks`/`taintSources`, even for
 * TypeScript, whose `typescript/callgraph.ts` has resolved interprocedural
 * `taintFlows` edges since before this change — those edges were only ever
 * consumed by `correlation/src/grounding.ts` (Layer 2 scoring), never by
 * Layer 3's actual proof engine. This suite proves the new fallback (added
 * alongside A21's Python/Java call graphs, so their new `taintFlows` output
 * is actually WIRED into confirmation rather than another "built but
 * unwired" seam — see audit finding A10): when nothing same-file matches,
 * `confirmStatic` now resolves a sink/source pair across a `taintFlows` edge,
 * language-agnostically. A single stack-agnostic fixture proves it; the
 * behavior is identical regardless of which analyzer produced the edge.
 */
import { describe, it, expect } from "vitest";
import { AppMapSchema, ProbableFindingSchema, type AppMap } from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import { confirmStatic, type ConfirmInput } from "@montr/confirm";

const NOW = "2026-01-01T00:00:00.000Z";

/** A minimal, self-contained App Map: the candidate's flagged line (the
 * SOURCE, `service.py:3`) has no sink in its own file — the sink only exists
 * two hops away at `db.py:9`, connected exclusively via a `taintFlows` edge
 * (exactly the shape `python/callgraph.ts` / `java/callgraph.ts` / the
 * pre-existing `typescript/callgraph.ts` all emit). Same-file lookup alone
 * cannot confirm this finding; only the new fallback can. */
const appMap: AppMap = AppMapSchema.parse({
  id: "appmap_crossfn",
  clientId: "client_test",
  scanId: "scan_test",
  repo: "https://example.internal/montr/crossfn",
  branch: "main",
  commitSha: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
  createdAt: NOW,
  languages: ["python"],
  frameworks: [],
  entrypoints: [],
  routes: [],
  dataStores: [],
  ormModels: [],
  thirdPartyCalls: [],
  envSecretSurfaces: [],
  taintSources: [
    {
      kind: "query_param",
      location: { file: "service.py", line: 3 },
      description: "request.args.get('id')",
    },
  ],
  taintSinks: [
    {
      kind: "sql_query",
      location: { file: "db.py", line: 9 },
      description: "cursor.execute(...) — raw sql via string interpolation",
    },
  ],
  taintFlows: [
    {
      sourceLocation: { file: "service.py", line: 3 },
      sourceKind: "query_param",
      throughFunction: "run_query",
      throughLocation: { file: "db.py", line: 5 },
      sinkLocation: { file: "db.py", line: 9 },
      sinkKind: "sql_query",
      resolution: "direct-call",
      hops: 1,
      crossFile: true,
    },
  ],
  stale: false,
  rebuildPolicy: "rebuild_on_stale_commit",
});

function baseInput(): ConfirmInput {
  return {
    clientId: "client_test",
    scanId: "scan_test",
    appMap,
    probable: [],
    allowLive: false,
    config: getHardenedDefaults(),
  };
}

describe("confirmStatic — cross-function fallback via taintFlows (A21)", () => {
  it("confirms a candidate whose flagged line has NO same-file sink, via a taintFlows edge", async () => {
    const finding = ProbableFindingSchema.parse({
      id: "prob_crossfn_0001",
      scanId: "scan_test",
      clientId: "client_test",
      rootCauseId: "rc_crossfn",
      category: "sql_injection",
      mergedCandidateIds: [],
      reachabilityHypothesis: "id flows into run_query then into a raw cursor.execute",
      exploitHypothesis: "boolean-based SQL injection via the id query param",
      exposure: "public",
      // The candidate is flagged at the SOURCE file/line — a real detector
      // typically flags where tainted input enters, not the downstream sink.
      location: { file: "service.py", line: 3 },
      reachabilityScore: 0.5,
      exposureScore: 0.5,
      impactScore: 0.5,
      rank: 1,
      createdAt: NOW,
    });

    const outcome = await confirmStatic(finding, baseInput(), { now: () => NOW });

    expect(outcome.kind).toBe("confirmed");
    if (outcome.kind !== "confirmed") throw new Error("expected confirmed");
    expect(outcome.finding.category).toBe("sql_injection");
    expect(outcome.finding.proofType).toBe("static");
    if (outcome.finding.proofArtifact.kind !== "static") throw new Error("expected static proof");
    // The full real TaintSink record (with its description) was resolved via
    // the edge, not a bare kind+location stub — proven by the sanitizer
    // marker text actually driving the dangerous/sanitized decision.
    expect(outcome.finding.proofArtifact.argument).toMatch(/sql_query sink/);
  });

  it("still returns unconfirmed when no taintFlows edge matches (fallback is additive, not a bypass)", async () => {
    const finding = ProbableFindingSchema.parse({
      id: "prob_crossfn_0002",
      scanId: "scan_test",
      clientId: "client_test",
      rootCauseId: "rc_crossfn_2",
      category: "sql_injection",
      mergedCandidateIds: [],
      reachabilityHypothesis: "unrelated file",
      exploitHypothesis: "n/a",
      exposure: "public",
      location: { file: "unrelated.py", line: 1 },
      reachabilityScore: 0.5,
      exposureScore: 0.5,
      impactScore: 0.5,
      rank: 1,
      createdAt: NOW,
    });

    const outcome = await confirmStatic(finding, baseInput(), { now: () => NOW });
    expect(outcome.kind).toBe("unconfirmed");
  });
});
