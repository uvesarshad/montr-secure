/**
 * OFFLINE advisory mirror (OSV + GHSA) for the SCA agent (§5.2, §9.3).
 *
 * The mirror is a set of static JSON files under `./advisories-data/` — one
 * per ecosystem (`npm.json`, `pypi.json`, `maven.json`) — generated from the
 * real OSV.dev bulk export by `../scripts/refresh-advisories.mjs` (filtered to
 * a curated allow-list of popular/high-impact packages; see that script and
 * `README.md` for how to regenerate). GHSA advisories are already merged into
 * OSV's per-ecosystem data, so this single source covers both. They are
 * loaded ONCE at module init via a synchronous `fs.readFileSync` — no network
 * call is ever made at scan time, matching this package's offline contract.
 *
 * `matchAdvisories` below (unchanged interface) is the stable seam the mirror
 * plugs into — swapping the data source never requires touching the matcher
 * or its callers (`detectors/sca.ts`).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import type { CweId, Severity } from "@montr/contracts";
import { satisfies } from "./semver.js";

/** OSV ecosystem tags this mirror ships data for. */
export type AdvisoryEcosystem = "npm" | "PyPI" | "Maven";

export interface Advisory {
  /** Primary id — GHSA-… or CVE-… (also decides the tool source tag). */
  id: string;
  aliases?: string[];
  /** Package name in its native ecosystem form (npm name, PyPI project, or Maven `groupId:artifactId`). */
  package: string;
  ecosystem: AdvisoryEcosystem;
  /** Semver-ish range of AFFECTED versions (comparator groups, `||`-joined — see `semver.ts`). */
  vulnerableRange: string;
  /** First fixed version, if known (used by the fix layer / report). */
  fixedVersion?: string;
  cwe: CweId[];
  severity: Severity;
  summary: string;
  /** Which feed this record models — drives the CandidateFinding.source tag. */
  source: "osv" | "ghsa";
}

const DATA_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "advisories-data");

/** Load + loosely validate one ecosystem's mirror file. Never throws: a
 * missing/corrupt file degrades to an empty list (fail-safe, same posture as
 * every other detector in this package) rather than crashing discovery. */
function loadEcosystemFile(filename: string): Advisory[] {
  try {
    const raw = readFileSync(path.join(DATA_DIR, filename), "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r): r is Advisory =>
        !!r &&
        typeof r === "object" &&
        typeof (r as Advisory).id === "string" &&
        typeof (r as Advisory).package === "string" &&
        typeof (r as Advisory).vulnerableRange === "string",
    );
  } catch {
    return [];
  }
}

/**
 * The full offline mirror across every shipped ecosystem. Built once at
 * import time from `advisories-data/*.json` (see module doc above). The
 * Phase-1 SCA detector only resolves npm packages today (`detectDependencies`
 * in `detectors/sca.ts`), so `matchAdvisories` defaults its ecosystem filter
 * to `"npm"` — the PyPI/Maven rows ship ready for the Python/JVM lockfile
 * resolvers declared in `rulesets/{python,java}` (build-plan §7 Wave 4) to
 * consume via the same `matchAdvisories(pkg, version, db, ecosystem)` seam.
 */
export const ADVISORY_DB: readonly Advisory[] = [
  ...loadEcosystemFile("npm.json"),
  ...loadEcosystemFile("pypi.json"),
  ...loadEcosystemFile("maven.json"),
];

/** All advisories affecting `pkg@version` in the given DB + ecosystem (default: the full mirror, npm). */
export function matchAdvisories(
  pkg: string,
  version: string,
  db: readonly Advisory[] = ADVISORY_DB,
  ecosystem: AdvisoryEcosystem = "npm",
): Advisory[] {
  return db.filter(
    (a) => a.package === pkg && a.ecosystem === ecosystem && satisfies(version, a.vulnerableRange),
  );
}
