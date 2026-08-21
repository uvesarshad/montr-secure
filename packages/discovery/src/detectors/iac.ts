/**
 * E16 — IaC agent (Dockerfile / Kubernetes / Terraform). A structurally
 * DIFFERENT Layer-1 detector than `sast.ts`: it targets infrastructure
 * definitions, not application source, so it is its own module rather than an
 * extra ruleset bolted onto `detectSast` — but it follows the exact same
 * Semgrep-subprocess pattern (`SemgrepRunner`, `parseSemgrepJson`,
 * `candidateFromSemgrep`, all reused unmodified from `sast.ts`) for the
 * optional registry-pack pass.
 *
 * Two independent, additive layers of coverage:
 *   1. Real, offline, structural pattern-based detectors — `iac/dockerfile.ts`,
 *      `iac/kubernetes.ts` (real YAML parsing), `iac/terraform.ts` (block-aware
 *      HCL-ish structural scan) — always run, no scanner binary required.
 *   2. An OPTIONAL Semgrep pass against Semgrep's own real Dockerfile/
 *      Kubernetes/Terraform registry packs, when the `semgrep` binary is
 *      available (or a runner is injected). Unlike `detectSast`, this is
 *      NOT a required detector — IaC scanning is new, additive breadth, so an
 *      unavailable Semgrep degrades gracefully with a warning (mirrors
 *      `detectDependencies`/`detectSecretsAndConfig`'s posture, not
 *      `detectSast`'s hard-fail one).
 */
import type { CandidateFinding } from "@montr/contracts";
import type { DetectorContext, SemgrepJson, SemgrepRunner } from "../types.js";
import { buildCandidate } from "../util/candidate.js";
import { readAll, isDockerfileName, isTerraformFile, isYamlFile } from "../util/files.js";
import { errMessage, isBinaryMissing } from "../util/text.js";
import { defaultSemgrepRunner, parseSemgrepJson } from "./sast.js";
import { detectDockerfileIssues, detectMissingDockerignore } from "./iac/dockerfile.js";
import { detectTerraformIssues } from "./iac/terraform.js";
import {
  detectKubernetesIssues,
  detectMissingNetworkPolicy,
  summarizeManifests,
} from "./iac/kubernetes.js";
import nodePath from "node:path";

/** Semgrep's own real Dockerfile/Kubernetes/Terraform registry packs (E16). */
export const DEFAULT_IAC_SEMGREP_RULESETS: readonly string[] = [
  "p/dockerfile",
  "p/kubernetes",
  "p/terraform",
];

export interface DetectIacOptions {
  runner?: SemgrepRunner;
  rulesets?: string[];
}

/**
 * Structural detectors — always run, fully offline. Returns raw candidates
 * already tagged `source: "custom"` (mirrors the convention `detectors/
 * secrets.ts` custom detectors use, since these are not Semgrep results).
 */
async function runStructuralDetectors(ctx: DetectorContext): Promise<CandidateFinding[]> {
  const out: CandidateFinding[] = [];

  // Read every text file ONCE — `detectMissingDockerignore` needs the full
  // listing (to check for a `.dockerignore` and enumerate sensitive files),
  // not just the Dockerfile(s) themselves.
  const allFiles = await readAll(ctx.files);
  const dockerFiles = allFiles.filter((f) => isDockerfileName(nodePath.posix.basename(f.path)));
  for (const file of dockerFiles) {
    for (const raw of detectDockerfileIssues(file)) {
      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: raw.rule,
          category: raw.category,
          file: file.path,
          line: raw.line,
          rawSeverity: raw.severity,
          snippet: raw.snippet,
          title: raw.title,
          metadata: raw.metadata,
        }),
      );
    }
  }
  for (const { file, finding } of detectMissingDockerignore(allFiles)) {
    out.push(
      buildCandidate(ctx, {
        source: "custom",
        ruleId: finding.rule,
        category: finding.category,
        file,
        line: finding.line,
        rawSeverity: finding.severity,
        snippet: finding.snippet,
        title: finding.title,
        metadata: finding.metadata,
      }),
    );
  }

  const terraformFiles = allFiles.filter((f) => isTerraformFile(f.path));
  for (const file of terraformFiles) {
    for (const raw of detectTerraformIssues(file)) {
      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: raw.rule,
          category: raw.category,
          file: file.path,
          line: raw.line,
          rawSeverity: raw.severity,
          snippet: raw.snippet,
          title: raw.title,
          metadata: raw.metadata,
        }),
      );
    }
  }

  const yamlFiles = allFiles.filter((f) => isYamlFile(f.path));
  for (const file of yamlFiles) {
    for (const raw of detectKubernetesIssues(file)) {
      out.push(
        buildCandidate(ctx, {
          source: "custom",
          ruleId: raw.rule,
          category: raw.category,
          file: file.path,
          line: raw.line,
          rawSeverity: raw.severity,
          snippet: raw.snippet,
          title: raw.title,
          metadata: raw.metadata,
        }),
      );
    }
  }
  const manifests = yamlFiles.flatMap((f) => summarizeManifests(f));
  for (const { file, finding } of detectMissingNetworkPolicy(manifests)) {
    out.push(
      buildCandidate(ctx, {
        source: "custom",
        ruleId: finding.rule,
        category: finding.category,
        file,
        line: finding.line,
        rawSeverity: finding.severity,
        snippet: finding.snippet,
        title: finding.title,
        metadata: finding.metadata,
      }),
    );
  }

  return out;
}

/**
 * Optional Semgrep pass against the real IaC registry packs. Gracefully
 * degrades (warning, empty result) when the binary/runner is unavailable —
 * this is NOT a required detector (unlike `detectSast`'s app-source SAST),
 * since it is additive breadth layered on top of the structural detectors
 * above, which already provide real, always-on coverage.
 */
async function runSemgrepPass(
  ctx: DetectorContext,
  opts: DetectIacOptions,
): Promise<CandidateFinding[]> {
  if (!opts.runner && !ctx.repoRoot) return []; // in-memory-only scan shape — nothing to shell out against
  const rulesets = opts.rulesets ?? [...DEFAULT_IAC_SEMGREP_RULESETS];
  let json: SemgrepJson | null;
  try {
    json = await (opts.runner ?? defaultSemgrepRunner)({
      repoRoot: ctx.repoRoot ?? ".",
      rulesets,
      signal: ctx.signal,
    });
  } catch (err) {
    if (isBinaryMissing(err)) {
      ctx.warn(
        "iac",
        "Semgrep binary unavailable for IaC scanning; structural detectors still ran.",
      );
      return [];
    }
    ctx.warn(
      "iac",
      `Semgrep IaC pass failed; continuing with structural-only IaC detection. ${errMessage(err)}`,
    );
    return [];
  }
  if (!json) {
    ctx.warn("iac", "Semgrep binary unavailable for IaC scanning; structural detectors still ran.");
    return [];
  }
  return parseSemgrepJson(json, ctx).map((c) => ({
    ...c,
    // Tag distinctly from app-source SAST results in metadata, without
    // touching the frozen ToolSource enum (still "semgrep").
    metadata: { ...c.metadata, engine: "semgrep", pass: "iac" },
  }));
}

/** Run the IaC agent (structural detectors + optional Semgrep IaC packs). */
export async function detectIac(
  ctx: DetectorContext,
  opts: DetectIacOptions = {},
): Promise<CandidateFinding[]> {
  if (ctx.signal?.aborted) return [];
  const [structural, semgrep] = await Promise.all([
    runStructuralDetectors(ctx),
    runSemgrepPass(ctx, opts),
  ]);
  return [...structural, ...semgrep];
}
