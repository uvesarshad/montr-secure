import { describe, it, expect } from "vitest";
import { evaluateBaseline, DEFAULT_BASELINE } from "../packages/qa/src/baseline";
import {
  formatCorpusScore,
  formatRegression,
  toJsonReport,
  sampleSizeCaveat,
  LOW_SAMPLE_CONFIRMED_FLOOR,
} from "../packages/qa/src/report";
import type { CorpusScore } from "../packages/qa/src/types";

/**
 * A6: precision/FP-rate must never be reported without recall alongside it, and
 * a small confirmed-finding sample (today: TP+FP=11 on the real golden corpus,
 * corpus/baseline.json $measurement) must carry an explicit "not yet
 * statistically meaningful" caveat everywhere the headline metric is surfaced.
 */

function mkScore(over: Partial<CorpusScore> = {}): CorpusScore {
  return {
    truePositives: 11,
    falsePositives: 0,
    falseNegatives: 33,
    precision: 1,
    recall: 0.25,
    f1: 0.4,
    fpRate: 0,
    perCategory: [],
    overConfirmed: 0,
    reposScored: 16,
    reposWithResults: 16,
    unknownRepoResults: 0,
    perRepo: [],
    ...over,
  };
}

describe("sampleSizeCaveat", () => {
  it("warns below the low-sample floor (today's real n=11 case)", () => {
    const msg = sampleSizeCaveat(11);
    expect(msg).toBeDefined();
    expect(msg).toContain("11 confirmed");
    expect(msg).toMatch(/not yet statistically meaningful/);
  });

  it("is silent once the sample clears the floor", () => {
    expect(sampleSizeCaveat(LOW_SAMPLE_CONFIRMED_FLOOR)).toBeUndefined();
    expect(sampleSizeCaveat(LOW_SAMPLE_CONFIRMED_FLOOR + 1)).toBeUndefined();
  });

  it("singular/plural noun agreement at n=1", () => {
    expect(sampleSizeCaveat(1)).toContain("1 confirmed finding ");
    expect(sampleSizeCaveat(1)).not.toContain("1 confirmed findings");
  });
});

describe("formatCorpusScore — precision AND recall reported together, never alone", () => {
  it("always renders both fpRate/precision AND recall", () => {
    const text = formatCorpusScore(mkScore());
    expect(text).toMatch(/FP-rate:\s+0\.0%/);
    expect(text).toMatch(/precision:\s+100\.0%/);
    expect(text).toMatch(/recall:\s+25\.0%/);
  });

  it("surfaces the low-sample-size caveat when TP+FP is small (today's real n=11)", () => {
    const text = formatCorpusScore(mkScore({ truePositives: 11, falsePositives: 0 }));
    expect(text).toMatch(/not yet statistically meaningful/);
    expect(text).toContain("11 confirmed");
  });

  it("omits the caveat once the confirmed sample is large enough", () => {
    const text = formatCorpusScore(
      mkScore({ truePositives: 40, falsePositives: 0, falseNegatives: 4 }),
    );
    expect(text).not.toMatch(/not yet statistically meaningful/);
  });
});

describe("toJsonReport — machine-readable headline carries recall + the sample-size caveat", () => {
  it("includes recall alongside fpRate/precision in the JSON headline", () => {
    const score = mkScore();
    const regression = evaluateBaseline(score, DEFAULT_BASELINE);
    const json = toJsonReport(score, regression) as { headline: Record<string, unknown> };
    expect(json.headline.fpRate).toBe(0);
    expect(json.headline.precision).toBe(1);
    expect(json.headline.recall).toBe(0.25);
    expect(json.headline.confirmedSampleSize).toBe(11);
    expect(typeof json.headline.sampleSizeCaveat).toBe("string");
    expect(json.headline.sampleSizeCaveat as string).toMatch(/not yet statistically meaningful/);
  });

  it("sampleSizeCaveat is undefined once the sample is large enough", () => {
    const score = mkScore({ truePositives: 40, falsePositives: 0, falseNegatives: 4 });
    const regression = evaluateBaseline(score, DEFAULT_BASELINE);
    const json = toJsonReport(score, regression) as { headline: Record<string, unknown> };
    expect(json.headline.sampleSizeCaveat).toBeUndefined();
  });
});

describe("formatRegression — recallMin is part of the published PASS threshold summary", () => {
  it("PASS message names recallMin alongside fpRateMax/precisionMin", () => {
    const score = mkScore();
    // A baseline the n=11 real measurement actually clears (DEFAULT_BASELINE's
    // aspirational recallMin=0.9 would fail it — this test is about the PASS
    // message shape, not re-proving the gate logic covered above).
    const permissiveBaseline = { ...DEFAULT_BASELINE, recallMin: 0.2 };
    const regression = evaluateBaseline(score, permissiveBaseline);
    const text = formatRegression(regression);
    expect(text).toContain("PASS");
    expect(text).toMatch(/fpRateMax=/);
    expect(text).toMatch(/precisionMin=/);
    expect(text).toMatch(/recallMin=/);
  });
});
