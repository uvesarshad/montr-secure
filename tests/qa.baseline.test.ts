import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { isMontrError } from "@montr/contracts";
import {
  DEFAULT_BASELINE,
  evaluateBaseline,
  loadBaselineFile,
  parseBaseline,
} from "../packages/qa/src/baseline";
import { findRepoRoot } from "../packages/qa/src/corpus";
import type { CorpusScore } from "../packages/qa/src/types";

/** WS-P baseline / regression-gate tests. */

function mkScore(over: Partial<CorpusScore> = {}): CorpusScore {
  return {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    precision: 1,
    recall: 1,
    f1: 1,
    fpRate: 0,
    perCategory: [],
    overConfirmed: 0,
    reposScored: 4,
    reposWithResults: 4,
    unknownRepoResults: 0,
    perRepo: [],
    ...over,
  };
}

describe("parseBaseline", () => {
  it("accepts a valid baseline with per-category thresholds", () => {
    const b = parseBaseline({
      fpRateMax: 0.05,
      precisionMin: 0.9,
      recallMin: 0.9,
      minReposScored: 4,
      perCategory: { xss: { recallMin: 1, fpRateMax: 0 } },
    });
    expect(b.fpRateMax).toBe(0.05);
    expect(b.perCategory?.xss?.recallMin).toBe(1);
  });

  it("rejects out-of-range rates and bad shapes", () => {
    expect(() => parseBaseline({ fpRateMax: 1.5, precisionMin: 0.9, recallMin: 0.9 })).toThrow();
    expect(() => parseBaseline({ precisionMin: 0.9, recallMin: 0.9 })).toThrow(); // missing fpRateMax
    expect(() =>
      parseBaseline({ fpRateMax: 0.05, precisionMin: 0.9, recallMin: 0.9, minReposScored: -1 }),
    ).toThrow();
    expect(() => parseBaseline("nope")).toThrow();
    const err = (() => {
      try {
        parseBaseline({ fpRateMax: "x", precisionMin: 0.9, recallMin: 0.9 });
      } catch (e) {
        return e;
      }
    })();
    expect(isMontrError(err) && err.code).toBe("CONFIG_VALIDATION");
  });
});

describe("evaluateBaseline", () => {
  it("passes when every metric meets the baseline", () => {
    const r = evaluateBaseline(mkScore({ precision: 1, recall: 1, fpRate: 0 }), DEFAULT_BASELINE);
    expect(r.passed).toBe(true);
    expect(r.violations).toEqual([]);
  });

  it("fails and reports EVERY breached threshold at once", () => {
    const r = evaluateBaseline(
      mkScore({
        precision: 0.5,
        recall: 0.5,
        fpRate: 0.5,
        truePositives: 1,
        falsePositives: 1,
        falseNegatives: 1,
      }),
      DEFAULT_BASELINE,
    );
    expect(r.passed).toBe(false);
    const metrics = r.violations.map((v) => v.metric).sort();
    expect(metrics).toEqual(["fpRate", "precision", "recall"]);
  });

  it("headline fpRate breach is flagged as a `max` violation", () => {
    const r = evaluateBaseline(mkScore({ fpRate: 0.2, precision: 0.8 }), DEFAULT_BASELINE);
    const fp = r.violations.find((v) => v.metric === "fpRate");
    expect(fp?.direction).toBe("max");
    expect(fp?.threshold).toBe(0.05);
  });

  it("treats a metric exactly at the threshold as passing (epsilon)", () => {
    const r = evaluateBaseline(mkScore({ fpRate: 0.05, precision: 0.95 }), DEFAULT_BASELINE);
    expect(r.passed).toBe(true);
  });

  it("enforces minReposScored (catches an empty corpus run)", () => {
    const r = evaluateBaseline(mkScore({ reposScored: 1 }), {
      ...DEFAULT_BASELINE,
      minReposScored: 4,
    });
    expect(r.violations.some((v) => v.metric === "reposScored")).toBe(true);
  });

  it("enforces per-category thresholds", () => {
    const score = mkScore({
      perCategory: [
        {
          category: "xss",
          truePositives: 0,
          falsePositives: 1,
          falseNegatives: 1,
          precision: 0,
          recall: 0,
          f1: 0,
          fpRate: 1,
        },
      ],
    });
    const r = evaluateBaseline(score, {
      ...DEFAULT_BASELINE,
      perCategory: { xss: { recallMin: 1, fpRateMax: 0 } },
    });
    expect(r.passed).toBe(false);
    expect(r.violations.filter((v) => v.scope === "xss").length).toBe(2);
  });
});

describe("loadBaselineFile — the committed corpus baseline", () => {
  it("loads corpus/baseline.json with the DoD headline threshold (<5% FP)", async () => {
    const root = findRepoRoot(fileURLToPath(import.meta.url));
    const baseline = await loadBaselineFile(join(root, "corpus", "baseline.json"));
    expect(baseline.fpRateMax).toBeLessThanOrEqual(0.05);
    expect(baseline.precisionMin).toBeGreaterThanOrEqual(0.9);
    expect(baseline.minReposScored).toBeGreaterThanOrEqual(1);
  });

  it("throws ConfigValidationError for a missing file", async () => {
    await expect(loadBaselineFile("/no/such/baseline.json")).rejects.toThrow();
  });
});
