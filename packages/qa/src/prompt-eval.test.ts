import { describe, it, expect } from "vitest";
import { groundTruthManifest, type GroundTruthManifest } from "@montr/fixtures";
import { InMemoryPromptVersionRegistry } from "@montr/llm-gateway";
import {
  DEFAULT_PROMPT_RUBRIC,
  PromptEvalGateway,
  evaluatePromptCandidate,
  promptMeetsRubric,
  scorePromptQuality,
} from "./prompt-eval.js";
import type { LoadedCorpus, LoadedRepo } from "./corpus.js";

/**
 * E15 — proves the CORE claim: the eval harness correctly identifies a BETTER
 * vs a WORSE prompt version on the golden corpus (using the real
 * @montr/confirm engine, via confirmedForRepoWithGateway), and the regression
 * gate promotes/rejects accordingly. Fully offline.
 */

const VULN_REPO_GT = groundTruthManifest.repos.find((r) => r.name === "vulnerable-nextjs");
if (!VULN_REPO_GT) throw new Error("fixtures manifest missing vulnerable-nextjs");

const vulnerableRepo: LoadedRepo = {
  name: VULN_REPO_GT.name,
  kind: VULN_REPO_GT.kind,
  source: "fixtures",
  path: VULN_REPO_GT.path,
  expectedFindings: VULN_REPO_GT.expectedFindings,
};

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

const PROMPT_NAME = "confirm.static_review.system";
const SYSTEM_FALLBACK =
  "You are a security exploit-confirmation reviewer. Judge exploitability conservatively from the static data-flow. When uncertain, set confirmed=false.";

describe("scorePromptQuality / promptMeetsRubric", () => {
  it("scores the REAL production fallback prompt as passing the default rubric", () => {
    expect(scorePromptQuality(SYSTEM_FALLBACK)).toBe(1);
    expect(promptMeetsRubric(SYSTEM_FALLBACK)).toBe(true);
  });

  it("scores a vague prompt missing all markers as failing", () => {
    const vague = "Approve or reject this finding.";
    expect(scorePromptQuality(vague)).toBe(0);
    expect(promptMeetsRubric(vague)).toBe(false);
  });

  it("is case-insensitive and a partial match still yields a fractional score", () => {
    const partial = "Be CONSERVATIVE. Nothing else specified.";
    const score = scorePromptQuality(partial);
    expect(score).toBeCloseTo(1 / 3, 10);
    expect(promptMeetsRubric(partial)).toBe(false); // default rubric requires ALL markers
  });

  it("respects a custom minMarkerFraction", () => {
    const partial = "Be CONSERVATIVE. Nothing else specified.";
    expect(promptMeetsRubric(partial, { ...DEFAULT_PROMPT_RUBRIC, minMarkerFraction: 0.3 })).toBe(
      true,
    );
  });
});

describe("PromptEvalGateway", () => {
  it("resolvePrompt round-trips through the registry exactly like production's gateway.resolvePrompt", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    const v1 = registry.createVersion({ name: PROMPT_NAME, template: "V1 TEXT" });
    registry.markActive(v1.id);
    const gateway = new PromptEvalGateway(registry, PROMPT_NAME, SYSTEM_FALLBACK);
    await expect(gateway.resolvePrompt(PROMPT_NAME, SYSTEM_FALLBACK)).resolves.toBe("V1 TEXT");
  });

  it("falls back to the hardcoded default when nothing is active in the registry", async () => {
    const registry = new InMemoryPromptVersionRegistry();
    const gateway = new PromptEvalGateway(registry, PROMPT_NAME, SYSTEM_FALLBACK);
    await expect(gateway.resolvePrompt(PROMPT_NAME, SYSTEM_FALLBACK)).resolves.toBe(
      SYSTEM_FALLBACK,
    );
  });
});

describe("evaluatePromptCandidate — the core E15 claim", () => {
  it("an identical candidate scores the same as active and is promoted (no regression)", async () => {
    const result = await evaluatePromptCandidate({
      promptName: PROMPT_NAME,
      systemFallback: SYSTEM_FALLBACK,
      activeTemplate: SYSTEM_FALLBACK,
      candidateTemplate: SYSTEM_FALLBACK,
      corpus: inlineCorpus(),
    });
    expect(result.active.corpusScore.recall).toBe(result.candidate.corpusScore.recall);
    expect(result.verdict).toBe("promote");
    expect(result.regression.passed).toBe(true);
    expect(result.reasons).toEqual([]);
  });

  it("a genuinely WORSE candidate (fails the rigor rubric) scores lower recall and is REJECTED", async () => {
    const result = await evaluatePromptCandidate({
      promptName: PROMPT_NAME,
      systemFallback: SYSTEM_FALLBACK,
      activeTemplate: SYSTEM_FALLBACK, // passes the rubric -> confirms real findings
      candidateTemplate: "Approve or reject this finding.", // fails the rubric -> vetoes everything
      corpus: inlineCorpus(),
    });
    expect(result.active.corpusScore.recall).toBeGreaterThan(0);
    expect(result.candidate.corpusScore.recall).toBe(0);
    expect(result.candidate.corpusScore.recall).toBeLessThan(result.active.corpusScore.recall);
    expect(result.verdict).toBe("reject");
    expect(result.regression.passed).toBe(false);
    expect(result.reasons.some((r) => r.includes("recall"))).toBe(true);
  });

  it("a candidate that is at least as rigorous (superset wording) is PROMOTED", async () => {
    const richer =
      SYSTEM_FALLBACK +
      " Additionally cross-check the sanitizer chain against known bypass techniques.";
    const result = await evaluatePromptCandidate({
      promptName: PROMPT_NAME,
      systemFallback: SYSTEM_FALLBACK,
      activeTemplate: SYSTEM_FALLBACK,
      candidateTemplate: richer,
      corpus: inlineCorpus(),
    });
    expect(result.candidate.corpusScore.recall).toBeGreaterThanOrEqual(
      result.active.corpusScore.recall,
    );
    expect(result.verdict).toBe("promote");
  });

  it("is deterministic — running the same evaluation twice yields identical scores", async () => {
    const opts = {
      promptName: PROMPT_NAME,
      systemFallback: SYSTEM_FALLBACK,
      activeTemplate: SYSTEM_FALLBACK,
      candidateTemplate: "Approve or reject this finding.",
      corpus: inlineCorpus(),
    };
    const a = await evaluatePromptCandidate(opts);
    const b = await evaluatePromptCandidate(opts);
    expect(a.active.corpusScore).toEqual(b.active.corpusScore);
    expect(a.candidate.corpusScore).toEqual(b.candidate.corpusScore);
    expect(a.verdict).toBe(b.verdict);
  });

  it("honors an explicit external baseline instead of the active-relative default", async () => {
    // A worse candidate still gets REJECTED against a strict fixed floor even
    // if we didn't compute the active score's own numbers as the gate.
    const result = await evaluatePromptCandidate({
      promptName: PROMPT_NAME,
      systemFallback: SYSTEM_FALLBACK,
      activeTemplate: SYSTEM_FALLBACK,
      candidateTemplate: "Approve or reject this finding.",
      corpus: inlineCorpus(),
      baseline: { fpRateMax: 0.05, precisionMin: 0.9, recallMin: 0.5 },
    });
    expect(result.verdict).toBe("reject");
  });
});
