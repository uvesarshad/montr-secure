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
import { detectDependencies } from "./detectors/sca.js";
import { selectCustomDetectors, selectSemgrepRulesets } from "./rulesets/registry.js";
import { triageCandidates } from "./triage.js";
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

  // Fan out the three deterministic detectors concurrently. Semgrep rulesets +
  // extra secrets detectors are selected per stack from the ruleset registry
  // (keyed on the App Map's detected languages); Phase-1 TS/JS apps get exactly
  // the curated default set + base detectors.
  const [sast, secrets, sca] = await Promise.all([
    detectSast(ctx, {
      runner: deps.semgrep,
      rulesets: deps.semgrepRulesets ?? selectSemgrepRulesets(input.appMap),
    }),
    detectSecretsAndConfig(ctx, {
      runner: deps.gitleaks,
      extraDetectors: selectCustomDetectors(input.appMap),
    }),
    detectDependencies(ctx, {}),
  ]);

  // Merge, dedupe (deterministic ids make cross-tool dupes collapse), scope-filter.
  let candidates: CandidateFinding[] = dedupeById([...sast, ...secrets, ...sca]).filter((c) =>
    inScope(c.location.file, input.scope),
  );

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
  runCustomDetectors,
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
  barePackageName,
  parsePnpmLock,
  parsePackageLock,
  parsePackageJson,
  parsePkgKey,
  type DetectScaOptions,
  type InstalledPackage,
  type ResolvedDeps,
} from "./detectors/sca.js";

export { triageCandidates, parseTriage, type TriageOptions } from "./triage.js";
export {
  persistCandidates,
  type PersistCandidatesInput,
  type CandidatePersister,
  type AuditAppender,
} from "./persist.js";

export { ADVISORY_DB, matchAdvisories, type Advisory } from "./advisories.js";
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
  inScope,
  type FileProvider,
  type RepoFile,
} from "./util/files.js";
