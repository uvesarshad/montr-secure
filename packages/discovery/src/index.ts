/**
 * @montr/discovery — Layer 1: parallel SAST (Semgrep) + secrets/config
 * (gitleaks + custom detectors) + dependency/SCA (offline OSV/GHSA + import-graph
 * reachability) agents.
 *
 * ⛔ Deliberately over-inclusive; Layer-1 output is NEVER surfaced to the user
 * (§7 L2 — the "500 issues" pile is for Layer 2 to correlate/rank/demote).
 * Deterministic tools DETECT; the LLM only TRIAGES/EXPLAINS, and only after the
 * App Map exists (golden rules #6). Implementation: WS-F.
 */
import { Layer1OutputSchema, type CandidateFinding, type Layer1Output } from "@montr/contracts";
import { createNullLogger, type Logger } from "@montr/telemetry";

import type { DetectorContext, DiscoveryDeps, RunDiscoveryInput } from "./types.js";
import { detectSast } from "./detectors/sast.js";
import { detectSecretsAndConfig } from "./detectors/secrets.js";
import { detectDependencies, resolveInstalledPackages } from "./detectors/sca.js";
import { detectAiSecurity } from "./detectors/ai-security.js";
import { detectIac } from "./detectors/iac.js";
import { detectSupplyChainRisks } from "./detectors/supply-chain.js";
import { selectCustomDetectors, selectSemgrepRulesets } from "./rulesets/registry.js";
import { loadCustomRules, type LoadedSemgrepRule } from "./custom-rules.js";
import { triageCandidates } from "./triage.js";
import { applyThreatModelScopeHints } from "./threat-model-scope.js";
import { persistCandidates, type AuditAppender, type CandidatePersister } from "./persist.js";
import { dedupeById } from "./util/candidate.js";
import { countBy } from "./util/text.js";
import {
  emptyFileProvider,
  fsFileProvider,
  inScope,
  memoryFileProvider,
  type FileProvider,
} from "./util/files.js";

/** Detailed discovery result: the contract output plus diagnostics. */
export interface DiscoveryResult {
  output: Layer1Output;
  /** Graceful-degradation warnings (missing scanner binaries, etc.). */
  warnings: string[];
  /** Candidate counts by producing tool/source. */
  bySource: Record<string, number>;
}

function resolveFileProvider(input: RunDiscoveryInput): FileProvider {
  const deps = input.deps ?? {};
  if (deps.fileProvider) return deps.fileProvider;
  if (input.files !== undefined) return memoryFileProvider(input.files);
  if (input.repoRoot) return fsFileProvider(input.repoRoot);
  return emptyFileProvider();
}

function makeContext(
  input: RunDiscoveryInput,
  deps: DiscoveryDeps,
  logger: Logger,
): DetectorContext {
  const warnings: string[] = [];
  return {
    clientId: input.clientId,
    scanId: input.scanId,
    appMap: input.appMap,
    scope: input.scope,
    config: input.config,
    repoRoot: input.repoRoot,
    files: resolveFileProvider(input),
    now: deps.now ?? (() => new Date().toISOString()),
    logger,
    signal: deps.signal,
    warnings,
    warn(detector: string, message: string): void {
      warnings.push(`[${detector}] ${message}`);
      logger.warn("discovery.degraded", { detector, message });
    },
  };
}

/**
 * Materialize enabled custom SEMGREP rule bodies to temporary `--config` files.
 * Returns their paths plus a `cleanup` that removes the temp dir. When there are
 * no semgrep custom rules this does ZERO filesystem work (fast no-op path), so a
 * scan without custom rules is unaffected.
 */
async function writeSemgrepRuleFiles(
  rules: readonly LoadedSemgrepRule[],
): Promise<{ paths: string[]; cleanup: () => Promise<void> }> {
  if (rules.length === 0) return { paths: [], cleanup: async () => undefined };
  const os = await import("node:os");
  const fs = await import("node:fs/promises");
  const nodePath = await import("node:path");
  const { randomUUID } = await import("node:crypto");
  const dir = await fs.mkdtemp(nodePath.join(os.tmpdir(), "montr-custom-rules-"));
  const paths: string[] = [];
  for (const rule of rules) {
    const file = nodePath.join(dir, `${rule.id}-${randomUUID()}.yaml`);
    await fs.writeFile(file, rule.body, "utf8");
    paths.push(file);
  }
  return {
    paths,
    cleanup: async () => {
      await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
    },
  };
}

/**
 * Run Layer-1 discovery and return the contract output plus diagnostics.
 *
 * The three sub-detectors run CONCURRENTLY (the "three agents writing
 * CandidateFinding[]" harness, §5.2); each degrades to empty + a warning if its
 * scanner binary is absent, so discovery never hard-fails on tooling.
 */
export async function runDiscoveryDetailed(input: RunDiscoveryInput): Promise<DiscoveryResult> {
  const deps = input.deps ?? {};
  const logger = deps.logger ?? createNullLogger();
  const ctx = makeContext(input, deps, logger);

  if (ctx.signal?.aborted) {
    return {
      output: Layer1OutputSchema.parse({ candidates: [] }),
      warnings: ["aborted"],
      bySource: {},
    };
  }

  // ⛔ Phase-4 (§16): load ENABLED client custom rules to run ALONGSIDE the curated
  // rulesets. Disabled drafts are skipped (fail-safe — they never feed a scan);
  // enabled secret rules become extra detectors, enabled semgrep bodies are
  // materialized to temp `--config` files (cleaned up as soon as SAST returns).
  const loaded = loadCustomRules(input.customRules ?? []);
  for (const s of loaded.skipped) {
    if (s.reason !== "disabled")
      ctx.warn("custom-rules", `skipped custom rule ${s.id}: ${s.reason}`);
  }
  const customSemgrep = await writeSemgrepRuleFiles(loaded.semgrepRules);

  // Fan out the three deterministic detectors concurrently. Semgrep rulesets +
  // extra secrets detectors are selected per stack from the ruleset registry
  // (keyed on the App Map's detected languages); Phase-1 TS/JS apps get exactly
  // the curated default set + base detectors. Enabled client custom rules append
  // to both (their configs + detectors), never replacing the curated set.
  const [sast, secrets, sca, aiSecurity, iac, supplyChain] = await Promise.all([
    detectSast(ctx, {
      runner: deps.semgrep,
      rulesets: [
        ...(deps.semgrepRulesets ?? selectSemgrepRulesets(input.appMap)),
        ...customSemgrep.paths,
      ],
    }),
    detectSecretsAndConfig(ctx, {
      runner: deps.gitleaks,
      extraDetectors: [...selectCustomDetectors(input.appMap), ...loaded.secretDetectors],
    }),
    detectDependencies(ctx, {}),
    // E11: AI-application security agent (prompt injection surface, unsafe
    // tool exposure, unescaped LLM output, secrets-into-prompt, missing
    // output validation) — fully offline, no scanner binary, degrades to []
    // for a repo with no recognized LLM SDK call sites (see ai-security.ts).
    detectAiSecurity(ctx),
    // E16: IaC agent (Dockerfile/Kubernetes/Terraform). Real structural
    // detectors always run offline; an optional Semgrep pass against the
    // real p/dockerfile, p/kubernetes, p/terraform registry packs layers on
    // top when the binary is available — NOT a required detector (see
    // iac.ts's module doc for why this differs from detectSast's posture).
    detectIac(ctx, { runner: deps.iacSemgrep }),
    // E16: supply-chain risk (typosquatting, install-script risk, basic
    // malicious-package heuristics) — built on the same resolved dependency
    // set SCA already computes; see supply-chain.ts's module doc for exactly
    // what is and isn't checkable fully offline.
    (async () => detectSupplyChainRisks(ctx, await resolveInstalledPackages(ctx.files)))(),
  ]).finally(() => customSemgrep.cleanup());

  // Merge, dedupe (deterministic ids make cross-tool dupes collapse), scope-filter.
  let candidates: CandidateFinding[] = dedupeById([
    ...sast,
    ...secrets,
    ...sca,
    ...aiSecurity,
    ...iac,
    ...supplyChain,
  ]).filter((c) => inScope(c.location.file, input.scope));

  // OPTIONAL LLM triage/explain — enriches only, never detects (golden rule #6).
  const triageEnabled = Boolean(deps.gateway) && deps.enableTriage !== false;
  if (triageEnabled && deps.gateway && input.appMap?.id) {
    candidates = await triageCandidates(candidates, {
      gateway: deps.gateway,
      scanId: input.scanId,
      clientId: input.clientId,
      logger,
    });
  } else if (deps.enableTriage === true && !deps.gateway) {
    ctx.warn("triage", "Triage requested but no gateway provided; skipped.");
  }

  // E6: additive-only prioritization from Layer 0's threat model, when one is
  // attached to the App Map (see threat-model-scope.ts's module doc — this
  // NEVER drops a candidate or changes the count, only annotates + reorders).
  candidates = applyThreatModelScopeHints(candidates, input.appMap);

  const bySource = countBy(candidates, (c) => c.source);
  logger.info("discovery.complete", {
    scanId: input.scanId,
    total: candidates.length,
    bySource,
    warnings: ctx.warnings.length,
  });

  return {
    output: Layer1OutputSchema.parse({ candidates }),
    warnings: ctx.warnings,
    bySource,
  };
}

/**
 * Layer-1 entry point (orchestrator LayerRunner shape). Emits the frozen
 * {@link Layer1Output} contract. PURE — persistence is the orchestrator's job
 * (`persistLayerOutput` → `store.candidates.bulkCreate`). For the standalone
 * concurrency-harness path that persists + audits itself, use
 * {@link runDiscoveryToStore}.
 */
export async function runDiscovery(input: RunDiscoveryInput): Promise<Layer1Output> {
  const { output } = await runDiscoveryDetailed(input);
  return output;
}

export interface DiscoverySinks {
  store: CandidatePersister;
  audit?: AuditAppender;
}

/**
 * Run discovery AND persist the candidates via @montr/state-store, audit-logging
 * the write (golden rule #7). Use this for the standalone Layer-1 path; when the
 * orchestrator drives the layer it persists via its own contract-validated step,
 * so call the pure {@link runDiscovery} there to avoid double-writing.
 */
export async function runDiscoveryToStore(
  input: RunDiscoveryInput,
  sinks: DiscoverySinks,
): Promise<DiscoveryResult> {
  const result = await runDiscoveryDetailed(input);
  await persistCandidates({
    clientId: input.clientId,
    scanId: input.scanId,
    candidates: result.output.candidates,
    store: sinks.store,
    audit: sinks.audit,
    logger: input.deps?.logger,
  });
  return result;
}

// --- public API re-exports --------------------------------------------------
export type {
  RunDiscoveryInput,
  DiscoveryDeps,
  DetectorContext,
  SemgrepRunner,
  SemgrepJson,
  SemgrepResult,
  GitleaksRunner,
  GitleaksFinding,
} from "./types.js";

export {
  detectSast,
  defaultSemgrepRunner,
  parseSemgrepJson,
  candidateFromSemgrep,
  DEFAULT_SEMGREP_RULESETS,
  type DetectSastOptions,
} from "./detectors/sast.js";
export {
  detectSecretsAndConfig,
  defaultGitleaksRunner,
  candidatesFromGitleaks,
  runCustomDetectors,
  looksLikePlaceholder,
  type DetectSecretsOptions,
  type FileDetector,
  type RawFinding,
} from "./detectors/secrets.js";

// ⛔ Per-language ruleset registry (Layer 1 stack breadth — build-plan §7 Wave 4).
// A new stack adds a ruleset under rulesets/<lang>/ and is appended to
// LANGUAGE_RULESETS — the detectors + runDiscovery stay stack-agnostic.
export {
  LANGUAGE_RULESETS,
  selectSemgrepRulesets,
  selectCustomDetectors,
  selectScaEcosystems,
} from "./rulesets/registry.js";
export type { LanguageRuleset } from "./rulesets/types.js";
export {
  detectDependencies,
  resolveInstalledPackages,
  collectImportedPackages,
  collectCalledPackages,
  barePackageName,
  parsePnpmLock,
  parsePackageLock,
  parsePackageJson,
  parsePkgKey,
  type DetectScaOptions,
  type InstalledPackage,
  type ResolvedDeps,
  type CallSiteReachability,
} from "./detectors/sca.js";

// ⛔ AI-application security agent (E11). Scans TARGET apps for prompt
// injection surface, unsafe tool/function exposure, unescaped LLM output,
// secrets-into-prompt, and missing output validation — see ai-security.ts's
// module doc for the full design writeup and the Semgrep-vs-AST judgment call.
export { detectAiSecurity } from "./detectors/ai-security.js";

// ⛔ IaC agent (E16). Dockerfile/Kubernetes/Terraform structural detectors
// (always-on, offline) plus an optional Semgrep p/dockerfile+p/kubernetes+
// p/terraform pass — see iac.ts's module doc for why it is its own detector
// rather than extra SAST rulesets.
export { detectIac, DEFAULT_IAC_SEMGREP_RULESETS, type DetectIacOptions } from "./detectors/iac.js";
export { detectDockerfileIssues, detectMissingDockerignore } from "./detectors/iac/dockerfile.js";
export { detectTerraformIssues, extractResourceBlocks } from "./detectors/iac/terraform.js";
export {
  detectKubernetesIssues,
  detectMissingNetworkPolicy,
  summarizeManifests,
} from "./detectors/iac/kubernetes.js";

// ⛔ Supply-chain risk (E16): typosquatting, install-script risk, basic
// malicious-package heuristics — see supply-chain.ts's module doc for the
// honest scope line on what is/isn't checkable fully offline.
export {
  detectSupplyChainRisks,
  detectTyposquats,
  detectOwnInstallScriptRisk,
  detectDependencyInstallScriptRisk,
  detectSuspiciousPackageNames,
  detectSuspiciousRegistryResolution,
  levenshtein,
  POPULAR_NPM_PACKAGES,
  type TyposquatMatch,
  type InstallScriptFinding,
  type SuspiciousResolution,
  type DetectSupplyChainOptions,
} from "./detectors/supply-chain.js";

// ⛔ Custom rule authoring (Phase-4 / Wave 5, §16). VALIDATE a client rule before
// it may be enabled, then LOAD enabled rules alongside the curated rulesets
// (semgrep bodies as extra `--config`, secret rules as `extraDetectors`).
export {
  validateCustomRule,
  validateSemgrepStructure,
  validateSecretStructure,
  defaultSemgrepValidateRunner,
  customRuleToDetector,
  loadCustomRules,
  type SemgrepValidateRunner,
  type SemgrepValidateInput,
  type SemgrepValidateOutcome,
  type ValidateCustomRuleOptions,
  type LoadedCustomRules,
  type LoadedSemgrepRule,
} from "./custom-rules.js";

export { triageCandidates, parseTriage, type TriageOptions } from "./triage.js";
export { applyThreatModelScopeHints } from "./threat-model-scope.js";
export {
  persistCandidates,
  type PersistCandidatesInput,
  type CandidatePersister,
  type AuditAppender,
} from "./persist.js";

export { ADVISORY_DB, matchAdvisories, type Advisory } from "./advisories.js";

// ⛔ SBOM dependency inventory (E16). The full resolved dependency tree +
// advisory matches, independent of Layer 1's CandidateFinding shape — see
// sbom.ts's module doc for why this is a standalone entry point rather than
// derived from detectDependencies's output, and packages/report/src/exports/
// cyclonedx.ts for the CycloneDX renderer that consumes it.
export {
  buildDependencyInventory,
  type DependencyInventory,
  type SbomComponent,
  type SbomVulnerability,
  type BuildDependencyInventoryOptions,
} from "./sbom.js";
export { satisfies as semverSatisfies, coerce as coerceSemver } from "./semver.js";
export { buildCandidate, dedupeById } from "./util/candidate.js";
export { candidateId, fnv1a, toSnippet } from "./util/ids.js";
export {
  memoryFileProvider,
  fsFileProvider,
  emptyFileProvider,
  readAll,
  isSourceFile,
  isTextFile,
  isDockerfileName,
  isTerraformFile,
  isYamlFile,
  inScope,
  type FileProvider,
  type RepoFile,
} from "./util/files.js";
