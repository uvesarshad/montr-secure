/**
 * ⛔ OWASP Benchmark REAL-MODE scan driver (E14, closes A29).
 *
 * Mirrors `scripts/corpus-scan.run.test.ts` exactly (same real
 * `apps/worker` pipeline — L0 map, L1 discovery with a real Semgrep
 * subprocess when it's on PATH, L2 correlation, L3 static confirmation — the
 * offline in-process driver + FAKE in-process LLM gateway), but points it at
 * the vendored `corpus/owasp-benchmark/` subset instead of the internal
 * golden corpus. Deliberately a SEPARATE driver, not a `loadCorpus()` entry:
 * `corpus/owasp-benchmark`'s ground truth is OWASP Benchmark's OWN
 * `expectedresults-subset.csv`, scored by `@montr/qa`'s
 * `owasp-benchmark.ts`/`owasp-benchmark-cli.ts` — never merged into
 * `corpus/baseline.json`'s internal gate (see
 * `corpus/owasp-benchmark/README.md`).
 *
 * SAST is a REQUIRED detector (A4): this run needs a real `semgrep` binary
 * reachable on PATH or the whole scan fails loudly (by design — an empty
 * scan must never look clean). Run via `node scripts/benchmark-owasp.mjs`
 * (mirrors `scripts/corpus-scan.mjs`), not directly by `pnpm test` — see
 * `scripts/benchmark-owasp.vitest.config.ts` for why this file is excluded
 * from the ordinary vitest sweep.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFakeLlmGateway } from "@montr/fixtures";
import type { ConfirmedFinding, LayerId } from "@montr/contracts";
import { OWASP_BENCHMARK_DIR, type RepoScanResult } from "@montr/qa";
import { runScanInProcess } from "../apps/worker/src/pipeline.js";
import { createLayerRunners } from "../apps/worker/src/runners.js";
import {
  hardenedConfig,
  instrument,
  makeInMemoryStore,
  silentLogger,
} from "../apps/worker/src/testkit.js";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const REPO_PATH = join(REPO_ROOT, OWASP_BENCHMARK_DIR);
const OUT_PATH = process.env.BENCHMARK_SCAN_OUT
  ? fileURLToPath(new URL(process.env.BENCHMARK_SCAN_OUT, `file://${REPO_ROOT}`))
  : fileURLToPath(new URL("owasp-benchmark-scan.json", `file://${REPO_ROOT}`));

const CLIENT_ID = "client_owasp_benchmark";
const APPROVER = "qa_owasp_benchmark_driver";

let confirmed: ConfirmedFinding[] = [];
let scanStatus = "unknown";
let layerCalls: Record<LayerId, number> = {
  layer0: 0,
  layer1: 0,
  layer2: 0,
  layer3: 0,
  layer4: 0,
  layer5: 0,
};
let runError: string | undefined;

beforeAll(async () => {
  const gateway = createFakeLlmGateway();
  const { store } = makeInMemoryStore();
  const { runners, calls, outputs } = instrument(createLayerRunners({ gateway }));

  try {
    const scan = await runScanInProcess(
      {
        config: hardenedConfig(),
        store,
        gateway,
        logger: silentLogger,
        layerRunners: runners,
        ids: () => "scan_owasp_benchmark",
        sleep: () => Promise.resolve(),
      },
      {
        clientId: CLIENT_ID,
        repo: REPO_PATH, // LOCAL path ⇒ Layer 0 builds a REAL map.
        branch: "main",
        mode: "full",
        scope: { mode: "full", includePaths: [] },
        operator: APPROVER,
      },
      { approveEstimate: APPROVER, timeoutMs: 10 * 60_000 },
    );
    const layer3 = outputs.layer3 as { confirmed: ConfirmedFinding[] } | undefined;
    confirmed = layer3?.confirmed ?? [];
    scanStatus = scan.status;
    layerCalls = calls;
  } catch (err) {
    // Fail loudly, don't silently report zero findings — a crash (e.g. Semgrep
    // genuinely unavailable, since SAST is a required detector per A4) is a
    // real harness failure, never scored as "0 findings" / a clean run.
    runError = err instanceof Error ? (err.stack ?? err.message) : String(err);
  }

  const results: RepoScanResult[] = [{ repo: "owasp-benchmark", confirmed }];
  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(OUT_PATH, `${JSON.stringify({ results }, null, 2)}\n`, "utf8");
}, 10 * 60_000);

afterAll(() => {
  if (process.env.BENCHMARK_SCAN_PRINT) {
    const lines = [
      "",
      "════════════════════════════════════════════════════════════════════",
      "  MONTR SECURE — OWASP BENCHMARK REAL-MODE SCAN (E14 / A29)",
      "════════════════════════════════════════════════════════════════════",
      `  repo:      ${REPO_PATH}`,
      `  status:    ${scanStatus}`,
      `  confirmed: ${confirmed.length}`,
      ...(runError ? [`  ERROR: ${runError.split("\n")[0]}`] : []),
      `  wrote:     ${OUT_PATH}`,
      "════════════════════════════════════════════════════════════════════",
      "",
    ];
    console.log(lines.join("\n"));
  }
});

describe("benchmark-owasp — real pipeline (L0-L3) run over the vendored OWASP Benchmark subset", () => {
  it("scanned the subset with no crash (requires real semgrep on PATH — SAST is a required detector, A4)", () => {
    expect(runError, runError ?? "").toBeUndefined();
    expect(layerCalls.layer3).toBe(1);
  });

  it("wrote a scan-results file consumable by `qa:owasp-benchmark --our-findings`", async () => {
    const { readFile } = await import("node:fs/promises");
    const raw = JSON.parse(await readFile(OUT_PATH, "utf8")) as { results: RepoScanResult[] };
    expect(raw.results.length).toBe(1);
    expect(raw.results[0]?.repo).toBe("owasp-benchmark");
  });
});
