/**
 * ⛔ Detection-coverage REAL-MODE scan driver (suggested enhancement,
 * docs/plan/26-09-12-tasks-red-blue-agentic-posture.md — mirrors
 * `scripts/corpus-scan.run.test.ts`'s exact pattern).
 *
 * Runs the REAL apps/worker pipeline — map (L0) → discovery (L1, real
 * semgrep/gitleaks subprocesses when the binaries are on PATH, else the
 * pipeline's own graceful degrade to empty + a warning) → correlation (L2) →
 * static confirmation (L3) — against EVERY repo in the golden corpus
 * (`@montr/qa`'s `loadCorpus()`), using the offline in-process driver + FAKE
 * in-process LLM gateway (same convention as `corpus-scan.run.test.ts` and
 * `apps/worker/src/e2e-scan.test.ts`).
 *
 * Unlike `corpus-scan.run.test.ts` (which grades Layer 3's `confirmed`
 * output against ground truth), this driver grades the REAL, PERSISTED
 * `DetectionCoverage` rows A7 already writes for every confirmed finding
 * (`persistDetectionCoverageForScan`, called from `apps/worker/src/runners.ts`'s
 * Layer 3 runner right after `confirmFindings` resolves — see that file's own
 * comment). Nothing here is hand-computed: `evaluateCoverageForFinding`
 * (`packages/appmap/src/coverage-analysis.ts`) is invoked by the REAL
 * production call site, against the REAL App Map each repo's real Layer 0 run
 * produced, and this driver only reads the result back out of the same
 * in-memory `StateStore.detectionCoverage` repository the real worker uses in
 * production (Prisma-backed there; in-memory here, same interface — see
 * `apps/worker/src/testkit.ts`).
 *
 * Writes an aggregated results file to `DETECTION_COVERAGE_SCAN_OUT`
 * (default: `detection-coverage-scan.json` at the repo root) in the shape
 * `packages/qa/src/detection-coverage-findings-io.ts#parseDetectionCoverageFindings`
 * expects:
 *
 *     { "results": [{ "repo", "findingId", "category", "detected", "reasoning" }, ...] }
 *
 * so `pnpm --filter @montr/qa qa:detection-coverage -- --findings detection-coverage-scan.json`
 * scores this REAL run against the committed baseline (never the tautological
 * self-check `qa:detection-coverage:selfcheck` runs with no `--findings`).
 *
 * Run via `node scripts/detection-coverage-scan.mjs` (mirrors
 * `scripts/corpus-scan.mjs`), not directly by `pnpm test` — see
 * `scripts/detection-coverage-scan.vitest.config.ts` for why this file is
 * excluded from the ordinary vitest sweep.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFakeLlmGateway } from "@montr/fixtures";
import type { ConfirmedFinding, DetectionCoverage, LayerId } from "@montr/contracts";
import { loadCorpus, type LoadedRepo } from "@montr/qa";
import { runScanInProcess } from "../apps/worker/src/pipeline.js";
import { createLayerRunners } from "../apps/worker/src/runners.js";
import {
  hardenedConfig,
  instrument,
  makeInMemoryStore,
  silentLogger,
} from "../apps/worker/src/testkit.js";

/** Where to write the aggregated results file (repo-root-relative by default). */
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const OUT_PATH = process.env.DETECTION_COVERAGE_SCAN_OUT
  ? fileURLToPath(new URL(process.env.DETECTION_COVERAGE_SCAN_OUT, `file://${REPO_ROOT}`))
  : fileURLToPath(new URL("detection-coverage-scan.json", `file://${REPO_ROOT}`));

const CLIENT_ID = "client_detection_coverage_scan";
const APPROVER = "qa_detection_coverage_scan_driver";

interface DetectionCoverageResultEntry {
  repo: string;
  findingId: string;
  category: string;
  detected: boolean | "unknown";
  reasoning: string;
}

interface RepoRun {
  repo: LoadedRepo;
  confirmed: ConfirmedFinding[];
  coverage: DetectionCoverage[];
  scanStatus: string;
  layerCalls: Record<LayerId, number>;
  error?: string;
}

const runs: RepoRun[] = [];
let corpusVersion = "";
let corpusWarnings: string[] = [];
/** Any persisted coverage row whose findingId did not resolve to a confirmed finding from the SAME run — should always stay empty. */
const missingFindingLookups: string[] = [];

/** Run the real L0-L3 pipeline (fake LLM gateway) against a single corpus repo. */
async function scanRepo(
  repo: LoadedRepo,
  gateway: ReturnType<typeof createFakeLlmGateway>,
): Promise<RepoRun> {
  const { store } = makeInMemoryStore();
  const { runners, calls, outputs } = instrument(createLayerRunners({ gateway }));

  const scan = await runScanInProcess(
    {
      config: hardenedConfig(),
      store,
      gateway,
      logger: silentLogger,
      layerRunners: runners,
      ids: () => `scan_detcov_${repo.name}`,
      sleep: () => Promise.resolve(),
    },
    {
      clientId: CLIENT_ID,
      repo: repo.path, // LOCAL path ⇒ Layer 0 builds a REAL map (never a remote clone).
      branch: "main",
      mode: "full",
      scope: { mode: "full", includePaths: [] },
      operator: APPROVER,
    },
    { approveEstimate: APPROVER, timeoutMs: 10 * 60_000 },
  );

  const layer3 = outputs.layer3 as { confirmed: ConfirmedFinding[] } | undefined;
  const confirmed = layer3?.confirmed ?? [];
  // ⛔ THE real signal: A7 already persists a real DetectionCoverage row per
  // confirmed finding inside the Layer 3 runner (persistDetectionCoverageForScan,
  // apps/worker/src/runners.ts) — read it back from the store's real
  // repository. Nothing is hand-computed here.
  const coverage = await store.detectionCoverage.list(CLIENT_ID);

  return {
    repo,
    confirmed,
    coverage,
    scanStatus: scan.status,
    layerCalls: calls,
  };
}

beforeAll(async () => {
  const corpus = await loadCorpus({ verifyPaths: true });
  corpusVersion = corpus.version;
  corpusWarnings = corpus.warnings;
  const gateway = createFakeLlmGateway();

  for (const repo of corpus.repos) {
    try {
      runs.push(await scanRepo(repo, gateway));
    } catch (err) {
      // ⛔ Fail loudly, don't silently drop a repo from the gate — mirrors
      // corpus-scan.run.test.ts's own discipline.
      runs.push({
        repo,
        confirmed: [],
        coverage: [],
        scanStatus: "failed",
        layerCalls: { layer0: 0, layer1: 0, layer2: 0, layer3: 0, layer4: 0, layer5: 0 },
        error: err instanceof Error ? (err.stack ?? err.message) : String(err),
      });
    }
  }

  const results: DetectionCoverageResultEntry[] = [];
  for (const r of runs) {
    const findingById = new Map(r.confirmed.map((f) => [f.id, f]));
    for (const c of r.coverage) {
      const finding = findingById.get(c.findingId);
      if (!finding) {
        missingFindingLookups.push(`${r.repo.name}:${c.findingId}`);
        continue;
      }
      results.push({
        repo: r.repo.name,
        findingId: c.findingId,
        category: finding.category,
        detected: c.detected,
        reasoning: c.reasoning,
      });
    }
  }

  // Write the aggregated results file BEFORE any `it()` runs (not in
  // afterAll) so the assertions below can read back what was written.
  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, `${JSON.stringify({ results }, null, 2)}\n`, "utf8");
}, 30 * 60_000);

afterAll(() => {
  if (process.env.DETECTION_COVERAGE_SCAN_PRINT) {
    const totalConfirmed = runs.reduce((n, r) => n + r.confirmed.length, 0);
    const totalCoverage = runs.reduce((n, r) => n + r.coverage.length, 0);
    const detectedTrue = runs.reduce(
      (n, r) => n + r.coverage.filter((c) => c.detected === true).length,
      0,
    );
    const detectedFalse = runs.reduce(
      (n, r) => n + r.coverage.filter((c) => c.detected === false).length,
      0,
    );
    const detectedUnknown = runs.reduce(
      (n, r) => n + r.coverage.filter((c) => c.detected === "unknown").length,
      0,
    );
    const lines = [
      "",
      "════════════════════════════════════════════════════════════════════",
      "  MONTR SECURE — DETECTION-COVERAGE REAL-MODE SCAN",
      "════════════════════════════════════════════════════════════════════",
      `  corpus version:  ${corpusVersion}`,
      ...corpusWarnings.map((w) => `  warning: ${w}`),
      ...runs.map(
        (r) =>
          `  • ${r.repo.name.padEnd(28)} [${r.repo.kind}] status=${r.scanStatus} confirmed=${r.confirmed.length} coverage=${r.coverage.length}` +
          (r.error ? ` ERROR=${r.error.split("\n")[0]}` : ""),
      ),
      `  total confirmed:  ${totalConfirmed}`,
      `  total coverage:   ${totalCoverage} (true=${detectedTrue} false=${detectedFalse} unknown=${detectedUnknown})`,
      `  wrote: ${OUT_PATH}`,
      "════════════════════════════════════════════════════════════════════",
      "",
    ];
    console.log(lines.join("\n"));
  }
});

describe("detection-coverage-scan — real pipeline (L0-L3) run over the golden corpus", () => {
  it("scanned every corpus repo exactly once with no crashes", () => {
    expect(runs.length).toBeGreaterThan(0);
    for (const r of runs) {
      expect(r.error, `${r.repo.name}: ${r.error ?? ""}`).toBeUndefined();
      expect(r.layerCalls.layer3).toBe(1);
    }
  });

  it("wrote an aggregated results file consumable by `qa:detection-coverage --findings`", async () => {
    const { readFile } = await import("node:fs/promises");
    const raw = JSON.parse(await readFile(OUT_PATH, "utf8")) as {
      results: DetectionCoverageResultEntry[];
    };
    const totalCoverage = runs.reduce((n, r) => n + r.coverage.length, 0);
    expect(raw.results.length).toBe(totalCoverage);
  });

  it("this is a REAL persisted-row readout, not a hand-computed mock — every coverage row traces back to a real confirmed finding from the same run", () => {
    expect(missingFindingLookups).toEqual([]);
  });

  it("at least one confirmed finding produced a real DetectionCoverage verdict", () => {
    const totalCoverage = runs.reduce((n, r) => n + r.coverage.length, 0);
    expect(totalCoverage).toBeGreaterThan(0);
  });
});
