import { describe, it, expect } from "vitest";
import type { ModelDescriptor } from "@montr/contracts";
import { groundTruthManifest, type GroundTruthManifest } from "@montr/fixtures";
import { runModelVariance } from "./model-variance.js";
import {
  gatewayForModel,
  realConfirmedForRepo,
  realVarianceModelMatrix,
} from "./real-confirmation-scanner.js";
import type { LoadedCorpus, LoadedRepo } from "./corpus.js";

/**
 * A23 — the regression test that would have caught the original bug: the
 * model-variance harness's ONLY wired caller (`perfectConfirmedForRepo`)
 * ignored the `model` parameter entirely, so every model scored an identical,
 * tautological 100% no matter what was passed. These tests prove the REAL
 * replacement (`realConfirmedForRepo`) is NOT model-invariant — different
 * models produce genuinely DIFFERENT `ConfirmedFinding[]` and, downstream,
 * genuinely different numeric recall in the model matrix. Fully offline
 * (fake gateway, no provider credentials/spend) but exercises the REAL
 * `@montr/confirm` static-confirmation engine, not a mock of it.
 */

const VULN_REPO_GT = groundTruthManifest.repos.find((r) => r.name === "vulnerable-nextjs");
if (!VULN_REPO_GT)
  throw new Error("fixtures manifest missing vulnerable-nextjs — test setup broken");

const vulnerableRepo: LoadedRepo = {
  name: VULN_REPO_GT.name,
  kind: VULN_REPO_GT.kind,
  source: "fixtures",
  path: VULN_REPO_GT.path,
  expectedFindings: VULN_REPO_GT.expectedFindings,
};

function modelDescriptor(overrides: Partial<ModelDescriptor>): ModelDescriptor {
  return {
    provider: "anthropic",
    modelId: "test-model",
    tier: "confirmation",
    contextWindow: 200_000,
    maxOutputTokens: 8_192,
    supportsTools: true,
    supportsStreaming: true,
    belowFloor: false,
    ...overrides,
  };
}

describe("A23 — realConfirmedForRepo genuinely differentiates by model", () => {
  it("a below-floor model and a floor-or-better model produce DIFFERENT confirmed sets for the SAME repo", async () => {
    const weak = modelDescriptor({ modelId: "weak-model", tier: "triage", belowFloor: true });
    const strong = modelDescriptor({
      modelId: "strong-model",
      tier: "confirmation",
      belowFloor: false,
    });

    const weakConfirmed = await realConfirmedForRepo(vulnerableRepo, weak, gatewayForModel(weak));
    const strongConfirmed = await realConfirmedForRepo(
      vulnerableRepo,
      strong,
      gatewayForModel(strong),
    );

    // Deterministically reachable SQLi + XSS: the below-floor model's veto
    // demotes both (golden rule #4 fail-safe); the floor-or-better model
    // confirms both. This is a REAL difference produced by the REAL
    // packages/confirm engine, not two hand-typed arrays.
    expect(weakConfirmed).toHaveLength(0);
    expect(strongConfirmed).toHaveLength(2);
    expect(strongConfirmed.map((c) => c.category).sort()).toEqual(["sql_injection", "xss"]);
  });

  it("is otherwise deterministic — same model, same repo, same result twice", async () => {
    const strong = modelDescriptor({ modelId: "strong-model", belowFloor: false });
    const a = await realConfirmedForRepo(vulnerableRepo, strong, gatewayForModel(strong));
    const b = await realConfirmedForRepo(vulnerableRepo, strong, gatewayForModel(strong));
    expect(a).toEqual(b);
  });

  it("returns [] (not a crash) for a corpus repo with no hand-built fixture", async () => {
    const someModel = modelDescriptor({});
    const unknownRepo: LoadedRepo = { ...vulnerableRepo, name: "not-a-real-fixture-repo" };
    const out = await realConfirmedForRepo(unknownRepo, someModel, gatewayForModel(someModel));
    expect(out).toEqual([]);
  });
});

describe("A23 — the model matrix produces genuinely different NUMERIC scores per model", () => {
  function inlineCorpus(): LoadedCorpus {
    const manifest: GroundTruthManifest = {
      version: groundTruthManifest.version,
      repos: [vulnerableRepo].map((r) => ({
        name: r.name,
        kind: r.kind,
        path: r.path,
        expectedFindings: r.expectedFindings,
      })),
    };
    return {
      version: "test",
      fixturesVersion: groundTruthManifest.version,
      repos: [vulnerableRepo],
      manifest,
      warnings: [],
      root: "/tmp/inline",
    };
  }

  it("a below-floor row scores LOWER recall than a floor-or-better row — not an identical 100% across the board", async () => {
    const models = realVarianceModelMatrix();
    // Sanity: the fixture matrix actually contains both a below-floor and an
    // at/above-floor model (otherwise this test would prove nothing).
    expect(models.some((m) => m.belowFloor)).toBe(true);
    expect(models.some((m) => !m.belowFloor)).toBe(true);

    const matrix = await runModelVariance({
      corpus: inlineCorpus(),
      gateway: gatewayForModel(models[0] as ModelDescriptor), // unused by realConfirmedForRepo itself
      scan: realConfirmedForRepo,
      models,
    });

    const recalls = new Set(matrix.rows.map((r) => r.score.recall));
    // THE core regression assertion: today's bug made every row identical
    // (all 100%). A real, model-differentiated scanner must NOT do that.
    expect(recalls.size).toBeGreaterThan(1);

    const belowFloorRow = matrix.rows.find((r) => r.belowFloor);
    const floorRow = matrix.rows.find((r) => !r.belowFloor);
    expect(belowFloorRow?.score.recall).toBe(0);
    // 2/3, not 1: the ground-truth manifest's third exploitable case for this
    // repo (gt_secret, hardcoded_secret) has no data-flow sink at all
    // (DATAFLOW_SINK_KINDS.hardcoded_secret === []) — real static confirmation
    // can never reach it regardless of model (that's Layer 1/secret-detection's
    // job), and it is correctly absent from mockProbableFindings. A false
    // negative there is honest pipeline behavior, not a test bug.
    expect(floorRow?.score.recall).toBeCloseTo(2 / 3, 10);
    expect(belowFloorRow?.score.recall).toBeLessThan(floorRow?.score.recall as number);

    // The below-floor model's real degradation is flagged as an accuracy
    // cliff — this is precisely what PRD §15/§17 asks the harness to catch.
    expect(belowFloorRow?.accuracyCliff).toBe(true);
  });
});
