/**
 * ⛔ Golden-corpus REAL-MODE scan driver (fixes A2 — the CI gate scoring
 * ground truth against itself).
 *
 * Runs the REAL apps/worker pipeline — map (L0) → discovery (L1, real
 * semgrep/gitleaks subprocesses when the binaries are on PATH, else the
 * pipeline's own graceful degrade to empty + a warning — never a synthetic
 * candidate pile) → correlation (L2) → static confirmation (L3) — against
 * EVERY repo in the golden corpus (`@montr/qa`'s `loadCorpus()`: the
 * `@montr/fixtures` seed repos + `corpus/repos` + the standalone per-stack
 * corpora under `corpus/<stack>-vuln|clean`), using the offline in-process
 * driver + FAKE in-process LLM gateway — the SAME pattern
 * `apps/worker/src/e2e-scan.test.ts` uses so this needs no live LLM
 * credentials in CI (golden rule #2's egress path is exercised, just with the
 * fake adapter). L4/L5 are not needed to grade precision/recall/FP-rate, so
 * this driver stops at L3's `confirmed` output per repo.
 *
 * Writes an aggregated findings file to `CORPUS_SCAN_OUT` (default: `scan.json`
 * at the repo root) in exactly the shape
 * `packages/qa/src/findings-io.ts#parseScanFindings` expects:
 *
 *     { "results": [{ "repo": "<name>", "confirmed": ConfirmedFinding[] }, ...] }
 *
 * so `pnpm --filter @montr/qa qa:corpus -- --findings scan.json` scores this
 * REAL run against ground truth (never the tautological `perfectScanner`
 * self-check `qa:corpus` runs with no `--findings`).
 *
 * Run via `node scripts/corpus-scan.mjs` (mirrors `scripts/e2e-scan.mjs`), not
 * directly by `pnpm test` — see `scripts/corpus-scan.vitest.config.ts` for why
 * this file is excluded from the ordinary vitest sweep.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFakeLlmGateway } from "@montr/fixtures";
import type { ConfirmedFinding, LayerId } from "@montr/contracts";
import { loadCorpus, type LoadedRepo, type RepoScanResult } from "@montr/qa";
import { runScanInProcess } from "../apps/worker/src/pipeline.js";
import { createLayerRunners } from "../apps/worker/src/runners.js";
import {
  hardenedConfig,
  instrument,
  makeInMemoryStore,
  silentLogger,
} from "../apps/worker/src/testkit.js";

/** Where to write the aggregated scan-results file (repo-root-relative by default). */
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const OUT_PATH = process.env.CORPUS_SCAN_OUT
  ? fileURLToPath(new URL(process.env.CORPUS_SCAN_OUT, `file://${REPO_ROOT}`))
  : fileURLToPath(new URL("scan.json", `file://${REPO_ROOT}`));

const CLIENT_ID = "client_corpus_scan";
const APPROVER = "qa_corpus_scan_driver";

interface RepoRun {
  repo: LoadedRepo;
  confirmed: ConfirmedFinding[];
  scanStatus: string;
  layerCalls: Record<LayerId, number>;
  error?: string;
}

const runs: RepoRun[] = [];
let corpusVersion = "";
let corpusWarnings: string[] = [];

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
      ids: () => `scan_corpus_${repo.name}`,
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
  return {
    repo,
    confirmed: layer3?.confirmed ?? [],
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
      // ⛔ Fail loudly, don't silently drop a repo from the gate — a repo that
      // can't be scanned is exactly the kind of real regression this driver
      // exists to catch (a crash is not the same as "zero findings").
      runs.push({
        repo,
        confirmed: [],
        scanStatus: "failed",
        layerCalls: { layer0: 0, layer1: 0, layer2: 0, layer3: 0, layer4: 0, layer5: 0 },
        error: err instanceof Error ? (err.stack ?? err.message) : String(err),
      });
    }
  }

  // Write the aggregated findings file BEFORE any `it()` runs (not in
  // afterAll) so the assertions below can read back what was written.
  const results: RepoScanResult[] = runs.map((r) => ({
    repo: r.repo.name,
    confirmed: r.confirmed,
  }));
  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, `${JSON.stringify({ results }, null, 2)}\n`, "utf8");
}, 30 * 60_000);

afterAll(() => {
  if (process.env.CORPUS_SCAN_PRINT) {
    const totalConfirmed = runs.reduce((n, r) => n + r.confirmed.length, 0);
    const lines = [
      "",
      "════════════════════════════════════════════════════════════════════",
      "  MONTR SECURE — GOLDEN-CORPUS REAL-MODE SCAN",
      "════════════════════════════════════════════════════════════════════",
      `  corpus version:  ${corpusVersion}`,
      ...corpusWarnings.map((w) => `  warning: ${w}`),
      ...runs.map(
        (r) =>
          `  • ${r.repo.name.padEnd(28)} [${r.repo.kind}] status=${r.scanStatus} confirmed=${r.confirmed.length}` +
          (r.error ? ` ERROR=${r.error.split("\n")[0]}` : ""),
      ),
      `  total confirmed: ${totalConfirmed}`,
      `  wrote: ${OUT_PATH}`,
      "════════════════════════════════════════════════════════════════════",
      "",
    ];
    console.log(lines.join("\n"));
  }
});

describe("corpus-scan — real pipeline (L0-L3) run over the golden corpus", () => {
  it("scanned every corpus repo exactly once with no crashes", () => {
    expect(runs.length).toBeGreaterThan(0);
    for (const r of runs) {
      expect(r.error, `${r.repo.name}: ${r.error ?? ""}`).toBeUndefined();
      expect(r.layerCalls.layer3).toBe(1);
    }
  });

  it("wrote an aggregated scan-results file consumable by `qa:corpus --findings`", async () => {
    const { readFile } = await import("node:fs/promises");
    const raw = JSON.parse(await readFile(OUT_PATH, "utf8")) as { results: RepoScanResult[] };
    expect(raw.results.length).toBe(runs.length);
  });

  it("this is a REAL scan, not the ground-truth echo (perfectScanner) — at least one real confirmed finding", () => {
    const total = runs.reduce((n, r) => n + r.confirmed.length, 0);
    expect(total).toBeGreaterThan(0);
  });
});
