/**
 * SAST agent (§5.2). Runs Semgrep as a subprocess (`--json`) over curated
 * rulesets and maps every result to a {@link CandidateFinding}. The LLM does NOT
 * run here — Semgrep (deterministic) detects; any LLM triage/explain happens
 * afterward, separately (golden rule #6).
 *
 * ⛔ Graceful degradation: if the Semgrep binary is absent or fails, this returns
 * an empty list plus a warning — the pipeline never hard-fails on a missing
 * scanner. Tests inject a canned {@link SemgrepRunner}; production shells out.
 */
import nodePath from "node:path";
import type { CandidateFinding } from "@montr/contracts";
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
      signal,
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

/** Run the SAST agent. Deterministic tools detect; never throws on a missing binary. */
export async function detectSast(
  ctx: DetectorContext,
  opts: DetectSastOptions = {},
): Promise<CandidateFinding[]> {
  if (ctx.signal?.aborted) return [];
  const rulesets = opts.rulesets ?? [...DEFAULT_SEMGREP_RULESETS];
  const runner = opts.runner;

  if (!runner && !ctx.repoRoot) {
    ctx.warn("sast", "Semgrep skipped: no repoRoot and no runner injected.");
    return [];
  }

  let json: SemgrepJson | null;
  try {
    json = await (runner ?? defaultSemgrepRunner)({
      repoRoot: ctx.repoRoot ?? ".",
      rulesets,
      signal: ctx.signal,
    });
  } catch (err) {
    ctx.warn("sast", `Semgrep run failed; SAST degraded to empty. ${errMessage(err)}`);
    return [];
  }
  if (!json) {
    ctx.warn("sast", "Semgrep binary unavailable; SAST degraded to empty.");
    return [];
  }
  return parseSemgrepJson(json, ctx);
}
