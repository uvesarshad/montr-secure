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
 *
 * ⛔ Per-pack degradation (A33): real Semgrep aborts its ENTIRE `--json`
 * invocation when even ONE `--config` target fails to resolve — not just the
 * failing pack (verified: `packages/discovery/src/rulesets/java/index.ts`
 * used to ship `["p/java", "p/spring"]`; the `p/spring` Registry pack 404s,
 * which silently zeroed EVERY JVM SAST finding, `p/java`'s included). So in
 * the NON-air-gapped (hosted registry pack ID) path, `detectSast` resolves
 * every `--config` entry — a `p/...` pack ID OR a materialized custom-rule
 * file path — in its OWN Semgrep subprocess (`runRegistryRulesets`) rather
 * than one shared invocation. A pack that fails to resolve is skipped with a
 * warning + a `sast.ruleset_pack_unresolved` metric; every OTHER pack's real
 * findings still ship. Only when EVERY pack fails does the existing A4
 * hard-failure path fire — that guarantee now specifically means "we got
 * literally zero rulesets to work with," not "one of several had a stale
 * reference." The air-gapped `rulesetsDir` path is untouched: it is a single
 * local directory (plus any local custom-rule paths), not a list of
 * independently-resolved registry pack IDs, so this per-pack splitting does
 * not apply there.
 */
import nodePath from "node:path";
import { readdir } from "node:fs/promises";
import type { CandidateFinding } from "@montr/contracts";
import { RequiredDetectorUnavailableError } from "@montr/contracts";
import { getMetrics } from "@montr/telemetry";
import type { DetectorContext, SemgrepJson, SemgrepResult, SemgrepRunner } from "../types.js";
import { buildCandidate, dedupeById } from "../util/candidate.js";
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

/** Outcome of resolving ONE `--config` entry (registry pack ID or a local
 * rule file path) in its own Semgrep invocation (A33). */
interface RulesetOutcome {
  ruleset: string;
  candidates: CandidateFinding[];
  /** True when this specific entry failed to produce a usable result — a
   * dead registry pack, a runner throw, or the runner reporting the
   * binary/config unavailable. DISTINCT from a genuinely clean 0-finding
   * run of a pack that resolved fine. */
  failed: boolean;
  errorMessage?: string;
}

/**
 * Best-effort signal that a JSON result represents "this pack's `--config`
 * failed to resolve" rather than "this pack genuinely found nothing". The
 * real runner already surfaces total resolution failure by returning `null`
 * (see `defaultSemgrepRunner`'s `res.failed && !stdout.trim()` branch); this
 * covers an injected/future runner that instead returns a well-formed but
 * empty JSON body with a populated `errors` array for that one pack.
 */
function looksLikeResolutionFailure(json: SemgrepJson): boolean {
  return (json.results?.length ?? 0) === 0 && Array.isArray(json.errors) && json.errors.length > 0;
}

/** Resolve ONE `--config` entry in its own Semgrep subprocess (A33). */
async function resolveOneRuleset(
  ctx: DetectorContext,
  runner: SemgrepRunner,
  repoRoot: string,
  ruleset: string,
): Promise<RulesetOutcome> {
  try {
    const json = await runner({ repoRoot, rulesets: [ruleset], signal: ctx.signal });
    if (!json) {
      return {
        ruleset,
        candidates: [],
        failed: true,
        errorMessage: "Semgrep binary/config unavailable",
      };
    }
    const candidates = parseSemgrepJson(json, ctx);
    if (looksLikeResolutionFailure(json)) {
      return {
        ruleset,
        candidates,
        failed: true,
        errorMessage: "ruleset produced no results and reported errors",
      };
    }
    return { ruleset, candidates, failed: false };
  } catch (err) {
    return { ruleset, candidates: [], failed: true, errorMessage: errMessage(err) };
  }
}

/**
 * Resolve every `--config` entry (hosted Registry pack ID or a materialized
 * local rule file path) in its OWN Semgrep invocation, concurrently, then
 * merge (A33). This is the fix for real Semgrep aborting its ENTIRE `--json`
 * run when even ONE `--config` target fails to resolve (see this file's
 * module doc) — splitting one process per entry means a dead pack can only
 * take out ITS OWN findings, never any other pack's.
 *
 * - Every entry failing -> the existing A4 hard-failure path fires (we got
 *   literally zero rulesets to work with) — `RequiredDetectorUnavailableError`.
 * - Some (not all) entries failing -> each failure is a `ctx.warn` +
 *   `getMetrics().recordError("sast.ruleset_pack_unresolved")`, distinct from
 *   the A4 hard-failure case; every succeeding pack's real findings still ship.
 * - Duplicate candidates across packs (e.g. two packs matching the same
 *   rule/file/line) are deduped by the deterministic candidate id.
 */
async function runRegistryRulesets(
  ctx: DetectorContext,
  runner: SemgrepRunner,
  repoRoot: string,
  rulesets: readonly string[],
): Promise<CandidateFinding[]> {
  const outcomes = await Promise.all(
    rulesets.map((ruleset) => resolveOneRuleset(ctx, runner, repoRoot, ruleset)),
  );
  const succeeded = outcomes.filter((o) => !o.failed);
  const failed = outcomes.filter((o) => o.failed);

  if (succeeded.length === 0) {
    const detail = failed
      .map((o) => `${o.ruleset}${o.errorMessage ? ` (${o.errorMessage})` : ""}`)
      .join(", ");
    throw new RequiredDetectorUnavailableError(
      `SAST is a required detector but every configured Semgrep ruleset failed to resolve: ${detail}`,
      { detector: "sast", failedRulesets: failed.map((o) => o.ruleset) },
    );
  }

  for (const o of failed) {
    getMetrics().recordError("sast.ruleset_pack_unresolved");
    ctx.warn(
      "sast",
      `Semgrep ruleset '${o.ruleset}' failed to resolve and was skipped; ${succeeded.length} other ruleset(s) still ran.${o.errorMessage ? ` (${o.errorMessage})` : ""}`,
    );
  }

  return dedupeById(succeeded.flatMap((o) => o.candidates));
}

/**
 * Run the SAST agent. SAST is a REQUIRED detector (A4): once we know a real
 * Semgrep invocation was attempted, an unavailable/erroring/misconfigured
 * scanner THROWS {@link RequiredDetectorUnavailableError} instead of degrading
 * to `[]` + a warning — an empty scan must never complete and look clean. A33
 * refines what "unavailable" means in the registry-pack path: it now takes
 * EVERY configured pack failing to trigger the hard failure, not just one
 * (see {@link runRegistryRulesets}).
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

  const repoRoot = ctx.repoRoot ?? ".";
  const resolvedRunner = runner ?? defaultSemgrepRunner;

  // Air-gap (A4): a configured local ruleset dir REPLACES the hosted
  // `p/...` Semgrep Registry pack IDs, which need network egress the air-gap
  // NetworkPolicy forbids. Non-registry entries the caller already resolved
  // (materialized client custom-rule temp files — local paths, never
  // `p/...` ids) still run alongside it, in the SAME invocation — a local
  // directory + local file paths are not independently-resolved registry
  // pack IDs, so A33's per-pack splitting below does not apply here. Missing/
  // empty dir -> the required detector is unavailable; throw before even
  // attempting to run Semgrep.
  const rulesetsDir = ctx.config.discovery?.rulesetsDir;
  if (rulesetsDir) {
    if (!(await localRulesetDirHasRules(rulesetsDir))) {
      throw new RequiredDetectorUnavailableError(
        `SAST is a required detector but the configured rulesetsDir '${rulesetsDir}' does not exist or contains no rule files.`,
        { detector: "sast", rulesetsDir },
      );
    }
    const extra = (opts.rulesets ?? []).filter((r) => !r.startsWith("p/"));
    const rulesets = [rulesetsDir, ...extra];

    let json: SemgrepJson | null;
    try {
      json = await resolvedRunner({ repoRoot, rulesets, signal: ctx.signal });
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

  // Registry-pack path (A33): resolve each `p/...` pack ID / materialized
  // custom-rule file path in its own Semgrep invocation so one dead pack
  // can never zero out every other pack's real findings.
  const rulesets = opts.rulesets ?? [...DEFAULT_SEMGREP_RULESETS];
  return runRegistryRulesets(ctx, resolvedRunner, repoRoot, rulesets);
}
