import { describe, it, expect } from "vitest";
import {
  createFakeLlmGateway,
  mockCandidateFindings,
  mockProbableFindings,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
} from "@montr/fixtures";
import { computePipelineMetrics } from "../packages/qa/src/layer-metrics";
import { runModelVariance, type ModelScanner } from "../packages/qa/src/model-variance";
import { loadCorpus } from "../packages/qa/src/corpus";
import { perfectConfirmedForRepo } from "../packages/qa/src/synthetic";
import { runQaSuite } from "../packages/qa/src/index";

describe("computePipelineMetrics — per-layer helpers", () => {
  it("derives dedup/confirmation/demotion rates and layer flows", () => {
    const m = computePipelineMetrics({
      candidates: mockCandidateFindings, // 5
      probable: mockProbableFindings, // 3
      confirmed: mockConfirmedFindings, // 2
      unconfirmed: mockUnconfirmedFindings, // 1
    });
    expect(m.candidates).toBe(5);
    expect(m.probable).toBe(3);
    expect(m.confirmed).toBe(2);
    expect(m.unconfirmed).toBe(1);
    expect(m.dedupRate).toBeCloseTo(0.4, 10); // 1 - 3/5
    expect(m.confirmationRate).toBeCloseTo(2 / 3, 10);
    expect(m.demotionRate).toBeCloseTo(1 / 3, 10);
    const l3 = m.flows.find((f) => f.layer === "layer3")!;
    expect(l3).toMatchObject({ in: 3, out: 2, demoted: 1 });
  });

  it("is divide-by-zero safe on empty input", () => {
    const m = computePipelineMetrics({});
    expect(m).toMatchObject({ candidates: 0, dedupRate: 0, confirmationRate: 0, demotionRate: 0 });
  });
});

describe("runModelVariance — harness scaffold over the gateway (fake adapter)", () => {
  it("emits a model matrix and flags accuracy cliffs on below-floor models", async () => {
    const corpus = await loadCorpus();
    const gateway = createFakeLlmGateway();
    // Simulate an accuracy cliff: below-floor models miss everything; floor models are perfect.
    const scan: ModelScanner = (repo, model) =>
      model.belowFloor ? [] : perfectConfirmedForRepo(repo);

    const matrix = await runModelVariance({
      corpus,
      gateway,
      scan,
      now: () => "2026-01-15T10:00:00.000Z",
    });

    expect(matrix.generatedAt).toBe("2026-01-15T10:00:00.000Z");
    expect(matrix.rows.length).toBe(gateway.listModels().length);

    const below = matrix.rows.filter((r) => r.belowFloor);
    const floor = matrix.rows.filter((r) => !r.belowFloor);
    expect(below.length).toBeGreaterThan(0);
    expect(floor.length).toBeGreaterThan(0);
    // Below-floor model degraded => cliff + failed gate.
    for (const r of below) {
      expect(r.accuracyCliff).toBe(true);
      expect(r.regression.passed).toBe(false);
    }
    // Floor-or-better models are perfect => no cliff, gate passes.
    for (const r of floor) {
      expect(r.accuracyCliff).toBe(false);
      expect(r.regression.passed).toBe(true);
    }
    expect(matrix.floorModelIds).toEqual(floor.map((r) => r.modelId));
  });

  it("no cliff when every model performs at the floor", async () => {
    const corpus = await loadCorpus();
    const gateway = createFakeLlmGateway();
    const scan: ModelScanner = (repo) => perfectConfirmedForRepo(repo);
    const matrix = await runModelVariance({ corpus, gateway, scan, now: () => "t" });
    expect(matrix.rows.every((r) => !r.accuracyCliff)).toBe(true);
    expect(matrix.rows.every((r) => r.regression.passed)).toBe(true);
  });
});

describe("runQaSuite — end-to-end self-check", () => {
  it("perfect scanner passes the committed gate with zero false positives", async () => {
    const { corpus, run, regression } = await runQaSuite();
    expect(corpus.repos.length).toBe(4);
    expect(run.score.fpRate).toBe(0);
    expect(run.score.falsePositives).toBe(0);
    expect(run.score.falseNegatives).toBe(0);
    expect(regression.passed).toBe(true);
  });
});
