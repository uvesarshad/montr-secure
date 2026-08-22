/**
 * ⛔ Blue-team detection-corpus REAL-MODE run driver (B12 — the blue-team
 * mirror of `scripts/corpus-scan.run.test.ts`).
 *
 * Runs the REAL B5 purple-team verification loop
 * (`packages/confirm/src/purple-loop.ts`'s `runPurpleTeamScenario`, which
 * itself calls the real, identically-gated `runScenario`) against every
 * labelled case in `packages/qa/src/blue-team-corpus.ts`'s
 * `BLUE_TEAM_GROUND_TRUTH`, using the REAL B3 detection-rule generator
 * (`packages/report/src/detection-rules/generate.ts`'s
 * `generateDetectionRules`) and the REAL red-team scenario catalogue
 * (`packages/state-store/src/redteam-catalogue.ts`'s
 * `REDTEAM_SCENARIO_CATALOGUE`, via `instantiateScenario`) — nothing here is
 * hand-computed or a synthetic echo. A fake, in-process `LiveHttpTransport`
 * stands in for the network (never touches a real socket — `runBlueTeamCorpus`
 * in blue-team-corpus.ts wires this in, mirroring
 * `tests/confirm.purple-loop.test.ts`'s own `fakeEngine`).
 *
 * Writes an aggregated results file to `BLUE_TEAM_CORPUS_SCAN_OUT` (default:
 * `blue-team-scan.json` at the repo root) in the shape
 * `packages/qa/src/blue-team-findings-io.ts#parseBlueTeamScanFindings` expects.
 *
 * Run via `node scripts/blue-team-corpus-scan.mjs` (mirrors
 * `scripts/corpus-scan.mjs`), not directly by `pnpm test` — see
 * `scripts/blue-team-corpus-scan.vitest.config.ts` for why this file is
 * excluded from the ordinary vitest sweep.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  BLUE_TEAM_GROUND_TRUTH,
  runBlueTeamCorpus,
  scoreBlueTeamResults,
  type BlueTeamScenarioResult,
} from "@montr/qa";
import { REDTEAM_SCENARIO_CATALOGUE } from "@montr/state-store";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const OUT_PATH = process.env.BLUE_TEAM_CORPUS_SCAN_OUT
  ? fileURLToPath(new URL(process.env.BLUE_TEAM_CORPUS_SCAN_OUT, `file://${REPO_ROOT}`))
  : fileURLToPath(new URL("blue-team-scan.json", `file://${REPO_ROOT}`));

let results: BlueTeamScenarioResult[] = [];

beforeAll(async () => {
  // ⛔ THE real invocation — every case runs through the real B3 rule
  // generator and the real B5 gated evaluator (see runBlueTeamCorpus's own
  // header in blue-team-corpus.ts).
  results = await runBlueTeamCorpus();

  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(
    OUT_PATH,
    `${JSON.stringify(
      {
        results: results.map((r) => ({
          templateKey: r.templateKey,
          scenarioName: r.scenarioName,
          actualFired: r.actualFired,
          evidence: r.evidence,
          sigmaRulesEvaluated: r.sigmaRulesEvaluated,
        })),
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
}, 60_000);

afterAll(() => {
  if (process.env.BLUE_TEAM_CORPUS_SCAN_PRINT) {
    const score = scoreBlueTeamResults(results);
    const lines = [
      "",
      "════════════════════════════════════════════════════════════════════",
      "  MONTR SECURE — BLUE-TEAM DETECTION-CORPUS REAL-MODE RUN (B12)",
      "════════════════════════════════════════════════════════════════════",
      `  labelled scenarios: ${results.length} of ${REDTEAM_SCENARIO_CATALOGUE.length} in REDTEAM_SCENARIO_CATALOGUE`,
      `  detection precision: ${(score.detectionPrecision * 100).toFixed(1)}%`,
      `  detection recall:    ${(score.detectionRecall * 100).toFixed(1)}%`,
      ...results.map(
        (r) =>
          `  • ${r.templateKey.padEnd(38)} expected=${String(r.expectedFired).padEnd(5)} actual=${String(
            r.actualFired,
          ).padEnd(5)} ${r.expectedFired === r.actualFired ? "OK" : "MISMATCH"}`,
      ),
      `  wrote: ${OUT_PATH}`,
      "════════════════════════════════════════════════════════════════════",
      "",
    ];
    console.log(lines.join("\n"));
  }
});

describe("blue-team-corpus-scan — real B3+B5 run over the labelled blue-team corpus (B12)", () => {
  it("ran every labelled ground-truth case exactly once with a real evaluator verdict", () => {
    expect(results.length).toBe(BLUE_TEAM_GROUND_TRUTH.length);
    for (const r of results) {
      expect(typeof r.actualFired).toBe("boolean");
      expect(r.sigmaRulesEvaluated).toBeGreaterThan(0);
    }
  });

  it("wrote an aggregated results file consumable by qa:blue-team-corpus --findings", async () => {
    const { readFile } = await import("node:fs/promises");
    const raw = JSON.parse(await readFile(OUT_PATH, "utf8")) as { results: unknown[] };
    expect(raw.results.length).toBe(results.length);
  });

  it("this is a REAL run, not a tautological echo — both fired:true and fired:false verdicts occur", () => {
    expect(results.some((r) => r.actualFired === true)).toBe(true);
    expect(results.some((r) => r.actualFired === false)).toBe(true);
  });

  it("every hand-traced ground-truth label matches the real measured verdict", () => {
    const mismatches = results.filter((r) => r.expectedFired !== r.actualFired);
    expect(
      mismatches,
      `ground-truth trace mismatch(es): ${JSON.stringify(mismatches, null, 2)}`,
    ).toEqual([]);
  });
});
