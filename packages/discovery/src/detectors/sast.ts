/**
 * SAST agent (§5.2). Runs Semgrep as a subprocess (`--json`) over curated
 * rulesets and maps every result to a {@link CandidateFinding}. The LLM does NOT
 * run here — Semgrep (deterministic) detects; any LLM triage/explain happens
 * afterward, separately (golden rule #6).
 *
 * ⛔ SAST is a REQUIRED detector (A4): unlike the graceful "degrade to []"
 * posture Layer 1's other detectors use for genuinely optional tooling, an
 * unavailable Semgrep means the scan has NO static analysis coverage at all —
 * so `detectSast` THROWS ({@link RequiredDetectorUnavailableError}) rather than
 * warn-and-return `[]`. A scan can never complete successfully and look clean
 * while its SAST pass silently didn't run. This propagates out of the Layer 1
 * runner and fails the scan via the orchestrator's `failScan` path (see
 * `packages/orchestrator/src/controller.ts`).
 *
 * ⛔ Air-gap support (A4): when `config.discovery.rulesetsDir` is set, Semgrep
 * is invoked against that LOCAL directory of rule YAML instead of the hosted
 * `p/...` Semgrep Registry pack IDs, which require network egress the
 * air-gap NetworkPolicy forbids. This is the runtime consumer of
 * `deploy/airgap/build-bundle.sh --semgrep-rules-dir` /
 * `import-bundle.sh` (which installs artifacts flat under
 * `<dest-dir>/semgrep/`). Unset (default): behavior is byte-for-byte
 * unchanged — hosted registry packs, exactly as before.
 */
import nodePath from "node:path";
import { readdir } from "node:fs/promises";
import type { CandidateFinding } from "@montr/contracts";
import { RequiredDetectorUnavailableError } from "@montr/contracts";
import type { DetectorContext, SemgrepJson, SemgrepResult, SemgrepRunner } from "../types.js";
import { buildCandidate } from "../util/candidate.js";
import {
  categoryForCwe,
  categoryFromRuleId,
  normalizeCwe,
  severityFromTool,
} from "../util/severity.js";
import { errMessage, isBinaryMissing } from "../util/text.js";

/** Curated rulesets (build-plan §5.2). `custom` client rules append via options. */
export const DEFAULT_SEMGREP_RULESETS: readonly string[] = [
  "p/owasp-top-ten",
  "p/typescript",
  "p/nextjs",
  "p/react",
  "p/secrets",
];

export interface DetectSastOptions {
  rulesets?: string[];
  runner?: SemgrepRunner;
}

/** Default runner: shells out to `semgrep` via execa (dynamically imported). */
export const defaultSemgrepRunner: SemgrepRunner = async ({ repoRoot, rulesets, signal }) => {
  const { execa } = await import("execa");
  const args = ["--json", "--quiet", "--disable-version-check", "--metrics=off"];
  for (const r of rulesets) args.push("--config", r);
  args.push(".");
  try {
    const res = await execa("semgrep", args, {
      cwd: repoRoot,
      reject: false,
      // execa v9 renamed `signal` → `cancelSignal` (the old `signal` key is
      // silently rejected, which previously made every live-scanner run
      // throw and degrade to empty — see the golden-corpus REAL-MODE fix,
      // build-plan §4.7 / A2).
      cancelSignal: signal,
      timeout: 300_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    const stdout = typeof res.stdout === "string" ? res.stdout : "";
    if (stdout.trim()) return JSON.parse(stdout) as SemgrepJson;
    // No output: a failed spawn (binary absent / crashed) → signal unavailable so
    // the detector degrades with a warning; a clean no-findings run stays empty.
    if (res.failed) return null;
    return { results: [] };
  } catch (err) {
    if (isBinaryMissing(err)) return null; // binary absent → degrade
    throw err;
  }
};

function extractCwes(metadata: Record<string, unknown> | undefined): string[] {
  const raw = metadata?.["cwe"];
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === "string" || typeof raw === "number") return [String(raw)];
  return [];
}

/**
 * Recursively check a local ruleset directory contains at least one Semgrep
 * rule file (`*.yml`/`*.yaml`) — matches how `build-bundle.sh --semgrep-rules-dir`
 * discovers source files (`find ... -name '*.yml' -o -name '*.yaml'`) and
 * tolerates both `import-bundle.sh`'s flat `<dest-dir>/semgrep/` install
 * layout and an operator pointing `rulesetsDir` straight at a nested source
 * tree. Missing directory, non-directory path, or zero rule files -> false.
 */
async function localRulesetDirHasRules(dir: string): Promise<boolean> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true, recursive: true });
  } catch {
    return false; // missing, not a directory, or unreadable
  }
  return entries.some((e) => e.isFile() && (e.name.endsWith(".yml") || e.name.endsWith(".yaml")));
}

/** Relativize an absolute semgrep path against the scanned repo root. */
function relPath(p: string, repoRoot: string | undefined): string {
  if (!repoRoot) return p.replace(/^\.\//, "");
  const root = nodePath.resolve(repoRoot);
  const abs = nodePath.resolve(repoRoot, p);
  const rel = nodePath.relative(root, abs);
  return rel.split(nodePath.sep).join("/").replace(/^\.\//, "");
}

/** Map one Semgrep result to a CandidateFinding (or null if unusable). */
export function candidateFromSemgrep(
  ctx: DetectorContext,
  r: SemgrepResult,
): CandidateFinding | null {
  if (!r.check_id || !r.path || !r.start) return null;
  const metadata = r.extra?.metadata;
  const cweStrings = extractCwes(metadata);
  const cwe = cweStrings.map(normalizeCwe).filter((c): c is NonNullable<typeof c> => Boolean(c));

  // Category precedence: CWE metadata → rule-id heuristic → "other".
  const category =
    cweStrings.map(categoryForCwe).find(Boolean) ?? categoryFromRuleId(r.check_id) ?? "other";

  return buildCandidate(ctx, {
    source: "semgrep",
    ruleId: r.check_id,
    category,
    cwe: cwe.length > 0 ? cwe : undefined,
    file: relPath(r.path, ctx.repoRoot),
    line: r.start.line,
    endLine: r.end?.line,
    column: r.start.col,
    rawSeverity: severityFromTool(r.extra?.severity),
    snippet: r.extra?.lines,
    title: r.extra?.message,
    metadata: {
      engine: "semgrep",
      ...(metadata?.["owasp"] !== undefined ? { owasp: metadata["owasp"] } : {}),
    },
  });
}

/** Parse a full Semgrep JSON document into candidates. */
export function parseSemgrepJson(json: SemgrepJson, ctx: DetectorContext): CandidateFinding[] {
  const results = json.results ?? [];
  const out: CandidateFinding[] = [];
  for (const r of results) {
    const c = candidateFromSemgrep(ctx, r);
    if (c) out.push(c);
  }
  return out;
}

/**
 * Run the SAST agent. SAST is a REQUIRED detector (A4): once we know a real
 * Semgrep invocation was attempted, an unavailable/erroring/misconfigured
 * scanner THROWS {@link RequiredDetectorUnavailableError} instead of degrading
 * to `[]` + a warning — an empty scan must never complete and look clean.
 *
 * The one case left as a graceful skip (unchanged from before A4) is having
 * neither an injected runner nor a `repoRoot`: that is the in-memory-only
 * scan shape (`RunDiscoveryInput.files` with no repo checkout), which is
 * never used by the production Layer 1 runner
 * (`apps/worker/src/runners.ts` always resolves a `repoRoot`) — a
 * structurally different, pre-existing situation than A4's "Semgrep was
 * reachable but network/config broke it" failure mode.
 */
export async function detectSast(
  ctx: DetectorContext,
  opts: DetectSastOptions = {},
): Promise<CandidateFinding[]> {
  if (ctx.signal?.aborted) return [];
  const runner = opts.runner;

  if (!runner && !ctx.repoRoot) {
    ctx.warn("sast", "Semgrep skipped: no repoRoot and no runner injected.");
    return [];
  }

  // Air-gap (A4): a configured local ruleset dir REPLACES the hosted
  // `p/...` Semgrep Registry pack IDs, which need network egress the air-gap
  // NetworkPolicy forbids. Non-registry entries the caller already resolved
  // (materialized client custom-rule temp files — local paths, never
  // `p/...` ids) still run alongside it. Missing/empty dir -> the required
  // detector is unavailable; throw before even attempting to run Semgrep.
  const rulesetsDir = ctx.config.discovery?.rulesetsDir;
  let rulesets: string[];
  if (rulesetsDir) {
    if (!(await localRulesetDirHasRules(rulesetsDir))) {
      throw new RequiredDetectorUnavailableError(
        `SAST is a required detector but the configured rulesetsDir '${rulesetsDir}' does not exist or contains no rule files.`,
        { detector: "sast", rulesetsDir },
      );
    }
    const extra = (opts.rulesets ?? []).filter((r) => !r.startsWith("p/"));
    rulesets = [rulesetsDir, ...extra];
  } else {
    rulesets = opts.rulesets ?? [...DEFAULT_SEMGREP_RULESETS];
  }

  let json: SemgrepJson | null;
  try {
    json = await (runner ?? defaultSemgrepRunner)({
      repoRoot: ctx.repoRoot ?? ".",
      rulesets,
      signal: ctx.signal,
    });
  } catch (err) {
    throw new RequiredDetectorUnavailableError(
      `SAST is a required detector but the Semgrep run failed: ${errMessage(err)}`,
      { detector: "sast" },
    );
  }
  if (!json) {
    throw new RequiredDetectorUnavailableError(
      "SAST is a required detector but the Semgrep binary is unavailable.",
      { detector: "sast" },
    );
  }
  return parseSemgrepJson(json, ctx);
}
