/**
 * ⛔ THE self-scan / dogfood driver (build-plan §4.8, §14, §19 DoD "scans itself
 * clean" — fixes A7, the CI self-scan job that was a no-op `grep -qw selfscan`
 * check with nothing to find).
 *
 * Runs the REAL apps/worker pipeline — map (L0) → discovery (L1, real
 * semgrep/gitleaks subprocesses when the binaries are on PATH, else the
 * pipeline's own graceful degrade to empty + a warning, same as everywhere
 * else — never a synthetic candidate pile) → correlation (L2) → static
 * confirmation (L3) — against THIS repo's OWN source tree (`repo: REPO_ROOT`,
 * a LOCAL path ⇒ Layer 0 builds a REAL map), using the FAKE in-process LLM
 * gateway (same offline pattern as `apps/worker/src/e2e-scan.test.ts` and
 * `scripts/corpus-scan.run.test.ts` — no live LLM credentials needed).
 *
 * Intentionally-vulnerable/clean fixture corpora (`corpus/`,
 * `packages/fixtures/sample-repos/`) plant vulnerabilities ON PURPOSE — they
 * must never count as real self-scan findings. They are excluded via
 * `scope.excludePaths`, which `packages/discovery/src/index.ts`'s
 * `inScope()` filter applies to EVERY candidate regardless of which detector
 * (semgrep, gitleaks, or the custom regex detectors) produced it — the one
 * filter point common to all three, so this is authoritative for what can
 * ever reach a `ConfirmedFinding`. (Layer 0's App Map walk does not itself
 * respect `scope.excludePaths` — `packages/appmap/src/sources.ts`'s ignore
 * list is hardcoded to build/VCS noise only — so the map may still index
 * fixture routes/entrypoints; this is a pre-existing Layer-0 property shared
 * by every caller of the real pipeline, not something this driver can fix
 * without touching `packages/appmap`, which is out of scope here. It does not
 * affect correctness of the confirmed-findings output because no candidate
 * whose location falls under an excluded path can ever be promoted past L1.)
 *
 * PASS condition (the CI blocking gate, mirrored in `.github/workflows/ci.yml`):
 * zero HIGH/CRITICAL confirmed findings against this repo's own source that
 * are not explicitly, individually documented in `scripts/selfscan.allowlist.json`
 * (a reviewed exceptions file — never a blanket suppression; see that file's
 * `$comment`). Lower-severity confirmed findings are reported but never gate.
 *
 * Run via `node scripts/selfscan.mjs` (`pnpm selfscan`), not directly by
 * `pnpm test` — see `scripts/selfscan.vitest.config.ts` for why this file is
 * excluded from the ordinary vitest sweep.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFakeLlmGateway } from "@montr/fixtures";
import type { ConfirmedFinding, LayerId, Severity } from "@montr/contracts";
import { runScanInProcess } from "../apps/worker/src/pipeline.js";
import { createLayerRunners } from "../apps/worker/src/runners.js";
import {
  hardenedConfig,
  instrument,
  makeInMemoryStore,
  silentLogger,
} from "../apps/worker/src/testkit.js";

/** THIS repo's own root — the self-scan target. */
const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** Where to write the aggregated self-scan-results file (repo-root-relative by default). */
const OUT_PATH = process.env.SELFSCAN_OUT
  ? fileURLToPath(new URL(process.env.SELFSCAN_OUT, `file://${REPO_ROOT}`))
  : fileURLToPath(new URL("selfscan.json", `file://${REPO_ROOT}`));

/** The reviewed, documented exceptions file (see its own `$comment`). */
const ALLOWLIST_PATH = fileURLToPath(new URL("./selfscan.allowlist.json", import.meta.url));

const CLIENT_ID = "client_selfscan";
const APPROVER = "montr_selfscan_driver";

/**
 * Excluded from the scan scope. `corpus` and `packages/fixtures/sample-repos`
 * plant vulns on purpose (mirrors `.github/gitleaks.toml`'s allowlist and the
 * CI self-scan Semgrep step's `--exclude` flags). The build/dependency-output
 * dirs are ALSO already hardcoded-ignored by Layer 0 (`packages/appmap`) and
 * Layer 1's file walker (`packages/discovery/src/util/files.ts`'s
 * `IGNORE_DIRS`, matched at any depth) — repeated here anyway as
 * belt-and-suspenders since `excludePaths` is the one filter guaranteed to
 * apply to every candidate source (see the file header).
 */
const EXCLUDE_PATHS: readonly string[] = [
  "corpus",
  "packages/fixtures/sample-repos",
  "node_modules",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".turbo",
  ".git",
];

/** Severities that gate CI (PRD/build-plan: "scans itself clean"). */
const GATING_SEVERITIES: ReadonlySet<Severity> = new Set(["high", "critical"]);

interface AllowlistEntry {
  category: string;
  file: string;
  line: number;
  reason: string;
}

/** Stable content-based identity for allowlist matching (ids are not guaranteed stable across runs). */
function findingKey(f: Pick<ConfirmedFinding, "category" | "location">): string {
  return `${f.category}::${f.location.file}::${f.location.line}`;
}

interface SelfScanRun {
  confirmed: ConfirmedFinding[];
  scanStatus: string;
  layerCalls: Record<LayerId, number>;
  error?: string;
}

let run: SelfScanRun;
let allowlist: AllowlistEntry[] = [];
const gatingFindings: ConfirmedFinding[] = [];
const allowlistedHits: ConfirmedFinding[] = [];

beforeAll(async () => {
  const allowlistRaw = JSON.parse(await readFile(ALLOWLIST_PATH, "utf8")) as {
    entries: AllowlistEntry[];
  };
  allowlist = allowlistRaw.entries ?? [];
  const allowedKeys = new Set(allowlist.map((e) => `${e.category}::${e.file}::${e.line}`));

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
        ids: () => "scan_selfscan",
        sleep: () => Promise.resolve(),
      },
      {
        clientId: CLIENT_ID,
        repo: REPO_ROOT, // LOCAL path ⇒ Layer 0 builds a REAL map of THIS repo.
        branch: "main",
        mode: "full",
        scope: { mode: "full", includePaths: [], excludePaths: [...EXCLUDE_PATHS] },
        operator: APPROVER,
      },
      { approveEstimate: APPROVER, timeoutMs: 10 * 60_000 },
    );
    const layer3 = outputs.layer3 as { confirmed: ConfirmedFinding[] } | undefined;
    run = { confirmed: layer3?.confirmed ?? [], scanStatus: scan.status, layerCalls: calls };
  } catch (err) {
    // ⛔ Fail loudly, don't silently report "clean" — a crashed pipeline is not
    // the same as "zero findings".
    run = {
      confirmed: [],
      scanStatus: "failed",
      layerCalls: { layer0: 0, layer1: 0, layer2: 0, layer3: 0, layer4: 0, layer5: 0 },
      error: err instanceof Error ? (err.stack ?? err.message) : String(err),
    };
  }

  for (const f of run.confirmed) {
    if (!GATING_SEVERITIES.has(f.severity)) continue;
    if (allowedKeys.has(findingKey(f))) allowlistedHits.push(f);
    else gatingFindings.push(f);
  }

  // Write the aggregated findings file BEFORE any `it()` runs (not in
  // afterAll) so the assertions below can read back what was written.
  await mkdir(dirname(OUT_PATH), { recursive: true });
  await writeFile(
    OUT_PATH,
    `${JSON.stringify(
      { results: [{ repo: "montr-secure", confirmed: run.confirmed }] },
      null,
      2,
    )}\n`,
    "utf8",
  );
}, 15 * 60_000);

function describeFinding(f: ConfirmedFinding): string {
  return `[${f.severity}] ${f.category} @ ${f.location.file}:${f.location.line} — ${f.title}`;
}

afterAll(() => {
  if (!process.env.SELFSCAN_PRINT) return;
  const bySeverity: Record<string, number> = {};
  for (const f of run.confirmed) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  const lines = [
    "",
    "════════════════════════════════════════════════════════════════════",
    "  MONTR SECURE — SELF-SCAN (dogfood — real pipeline vs. own source)",
    "════════════════════════════════════════════════════════════════════",
    `  repo:            ${REPO_ROOT}`,
    `  status:          ${run.scanStatus}` +
      (run.error ? ` ERROR=${run.error.split("\n")[0]}` : ""),
    `  confirmed total: ${run.confirmed.length}  (${
      Object.entries(bySeverity)
        .map(([s, n]) => `${s}=${n}`)
        .join(", ") || "none"
    })`,
    `  allowlist:       ${allowlist.length} documented entr${allowlist.length === 1 ? "y" : "ies"}`,
    ...(allowlistedHits.length
      ? [
          "  ── ALLOWLISTED (accepted, documented) ──",
          ...allowlistedHits.map((f) => `   • ${describeFinding(f)}`),
        ]
      : []),
    ...(gatingFindings.length
      ? [
          "  ── ⛔ GATING (HIGH/CRITICAL, un-allowlisted — FAILS CI) ──",
          ...gatingFindings.map((f) => `   • ${describeFinding(f)}`),
        ]
      : ["  ── no un-allowlisted HIGH/CRITICAL findings — clean ──"]),
    `  wrote: ${OUT_PATH}`,
    "════════════════════════════════════════════════════════════════════",
    "",
  ];
  console.log(lines.join("\n"));
});

describe("self-scan — real pipeline (L0-L3) run over Montr Secure's own source", () => {
  it("ran the real pipeline against this repo without crashing", () => {
    expect(run.error, run.error ?? "").toBeUndefined();
    expect(run.layerCalls.layer3).toBe(1);
  });

  it("wrote an aggregated self-scan-results file", async () => {
    const raw = JSON.parse(await readFile(OUT_PATH, "utf8")) as {
      results: { repo: string; confirmed: ConfirmedFinding[] }[];
    };
    expect(raw.results.length).toBe(1);
    expect(raw.results[0]?.confirmed.length).toBe(run.confirmed.length);
  });

  // ⛔ THE BLOCKING GATE (PRD §19 DoD: "scans itself clean").
  it("⛔ self-scan is clean: zero un-allowlisted HIGH/CRITICAL confirmed findings", () => {
    const message =
      gatingFindings.length === 0
        ? ""
        : [
            `${gatingFindings.length} un-allowlisted HIGH/CRITICAL finding(s) in Montr Secure's own source:`,
            ...gatingFindings.map((f) => `  - ${describeFinding(f)}`),
            "",
            "Either fix the underlying code, or — ONLY if this is a confirmed false",
            "positive or a reviewed, accepted low-risk case — add a narrowly-scoped,",
            "documented entry to scripts/selfscan.allowlist.json (never a blanket rule).",
          ].join("\n");
    expect(gatingFindings, message).toEqual([]);
  });
});
