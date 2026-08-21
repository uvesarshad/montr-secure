/**
 * E16 — dependency inventory for SBOM export. Layer 1's SCA detector
 * (`detectors/sca.ts`) already resolves the full installed-package list, the
 * offline OSV/GHSA advisory match per package, and — for TypeScript/
 * JavaScript — real call-site reachability (A12). `detectDependencies` only
 * ever turns that into `vulnerable_dependency` CandidateFindings (one per
 * matched advisory) though, which drops every NON-vulnerable package before
 * it ever reaches Layer 2/3/5 — an SBOM must list the WHOLE dependency tree,
 * not just the vulnerable subset.
 *
 * `buildDependencyInventory` is the standalone entry point that runs the same
 * resolution SCA does and returns EVERY resolved package (reachability
 * annotated when known) plus every matched advisory, as plain data with zero
 * dependency on @montr/report or the Report/CandidateFinding contract shapes.
 * `packages/report/src/exports/cyclonedx.ts` structurally consumes exactly
 * this shape (duck-typed, not imported) to stay a one-way dependency: report
 * does not need to depend on @montr/discovery, and discovery does not need to
 * depend on @montr/report — the caller (apps/worker's Layer 5 assembly, or a
 * standalone SBOM CLI/route) wires the two together.
 */
import type { Severity } from "@montr/contracts";
import type { FileProvider } from "./util/files.js";
import { ADVISORY_DB, matchAdvisories, type Advisory } from "./advisories.js";
import {
  collectCalledPackages,
  collectImportedPackages,
  resolveInstalledPackages,
} from "./detectors/sca.js";

/** One resolved dependency, independent of whether it has any known advisory. */
export interface SbomComponent {
  name: string;
  version: string;
  /** Package ecosystem, PURL "type" segment (currently always "npm" — see sca.ts's own ecosystem note). */
  ecosystem: string;
  /**
   * Real call-site reachability (A12) when it was resolvable (TS/JS with at
   * least one parseable source file); `undefined` when the repo's stack
   * could not be analyzed at all (a non-TS/JS-only repo) rather than falsely
   * claiming "not reachable".
   */
  reachable?: boolean;
}

/** One advisory matched against a resolved component. */
export interface SbomVulnerability {
  id: string;
  source: "osv" | "ghsa";
  packageName: string;
  packageVersion: string;
  severity: Severity;
  cwe?: readonly string[];
  summary?: string;
  fixedVersion?: string;
  aliases?: readonly string[];
  /** Real call-site reachability for this specific package, when known. */
  reachable?: boolean;
}

export interface DependencyInventory {
  components: SbomComponent[];
  vulnerabilities: SbomVulnerability[];
  /** Which manifest/lockfile drove resolution — surfaced for the SBOM's own provenance metadata. */
  source?: string;
}

export interface BuildDependencyInventoryOptions {
  advisories?: readonly Advisory[];
}

/**
 * Resolve the full dependency tree + advisory matches — the SBOM's input.
 * Mirrors `detectDependencies`'s resolution exactly (same lockfile parsing,
 * same call-site-reachability-preferred-over-import-presence rule, A12) but
 * returns every package, not just the ones with a matched advisory.
 */
export async function buildDependencyInventory(
  files: FileProvider,
  opts: BuildDependencyInventoryOptions = {},
): Promise<DependencyInventory> {
  const db = opts.advisories ?? ADVISORY_DB;
  const resolved = await resolveInstalledPackages(files);
  if (resolved.packages.length === 0) {
    return { components: [], vulnerabilities: [] };
  }

  const imported = await collectImportedPackages(files);
  const callSites = await collectCalledPackages(files);
  const reachableOf = (name: string): boolean | undefined => {
    if (callSites.analyzed) return callSites.called.has(name);
    // Fall back to import-presence only when nothing parsed as TS/JS at all
    // (same posture as sca.ts) — for a genuinely non-analyzable stack this
    // still can't distinguish "never checked" from "checked, not reachable",
    // so surface it as unknown rather than guessing.
    return imported.size > 0 ? imported.has(name) : undefined;
  };

  const components: SbomComponent[] = resolved.packages.map((pkg) => ({
    name: pkg.name,
    version: pkg.version,
    ecosystem: "npm",
    reachable: reachableOf(pkg.name),
  }));

  const vulnerabilities: SbomVulnerability[] = [];
  for (const pkg of resolved.packages) {
    for (const adv of matchAdvisories(pkg.name, pkg.version, db)) {
      vulnerabilities.push({
        id: adv.id,
        source: adv.source === "ghsa" ? "ghsa" : "osv",
        packageName: pkg.name,
        packageVersion: pkg.version,
        severity: adv.severity,
        cwe: adv.cwe,
        summary: adv.summary,
        fixedVersion: adv.fixedVersion,
        aliases: adv.aliases,
        reachable: reachableOf(pkg.name),
      });
    }
  }

  return {
    components,
    vulnerabilities,
    source: resolved.lockfile ?? resolved.packageJsonPath,
  };
}
