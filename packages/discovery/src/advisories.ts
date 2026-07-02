/**
 * OFFLINE advisory mirror (OSV + GHSA) for the SCA agent (§5.2, §9.3).
 *
 * This seed set is intentionally small and deterministic. In a real deployment
 * it is REPLACED by the full signed OSV/GHSA offline bundle imported via the
 * air-gap tooling (build-plan §9.3) — the matcher below (`matchAdvisories`) is
 * the stable interface that bundle plugs into. No network is ever required.
 */
import type { CweId, Severity } from "@montr/contracts";
import { satisfies } from "./semver.js";

export interface Advisory {
  /** Primary id — GHSA-… or CVE-… (also decides the tool source tag). */
  id: string;
  aliases?: string[];
  /** npm package name (scoped names allowed). */
  package: string;
  ecosystem: "npm";
  /** Semver range of AFFECTED versions. */
  vulnerableRange: string;
  /** First fixed version, if known (used by the fix layer / report). */
  fixedVersion?: string;
  cwe: CweId[];
  severity: Severity;
  summary: string;
  /** Which feed this record models — drives the CandidateFinding.source tag. */
  source: "osv" | "ghsa";
}

/**
 * Seed advisories. `lodash <4.17.12` is the one exercised by the vulnerable
 * sample repo (prototype pollution, CWE-1321 / GHSA-jf85-cpcp-j695). The rest
 * exercise the range matcher without touching the sample corpus.
 */
export const ADVISORY_DB: readonly Advisory[] = [
  {
    id: "GHSA-jf85-cpcp-j695",
    aliases: ["CVE-2019-10744"],
    package: "lodash",
    ecosystem: "npm",
    vulnerableRange: "<4.17.12",
    fixedVersion: "4.17.12",
    cwe: ["CWE-1321"],
    // Kept at medium to match the sample ground-truth's finding-level severity;
    // reachability (below) is what actually decides promotion vs demotion.
    severity: "medium",
    summary: "Prototype pollution in lodash (defaultsDeep).",
    source: "ghsa",
  },
  {
    id: "GHSA-vh95-rmgr-6w4m",
    aliases: ["CVE-2021-44906"],
    package: "minimist",
    ecosystem: "npm",
    vulnerableRange: "<1.2.6",
    fixedVersion: "1.2.6",
    cwe: ["CWE-1321"],
    severity: "high",
    summary: "Prototype pollution in minimist.",
    source: "ghsa",
  },
  {
    id: "GHSA-cph5-m8f7-6c5x",
    aliases: ["CVE-2021-3749"],
    package: "axios",
    ecosystem: "npm",
    vulnerableRange: ">=0.8.1 <0.21.2",
    fixedVersion: "0.21.2",
    cwe: ["CWE-918"],
    severity: "high",
    summary: "Inefficient regular expression / SSRF in axios.",
    source: "osv",
  },
];

/** All advisories affecting `pkg@version` in the given DB (default: the seed DB). */
export function matchAdvisories(
  pkg: string,
  version: string,
  db: readonly Advisory[] = ADVISORY_DB,
): Advisory[] {
  return db.filter(
    (a) => a.package === pkg && a.ecosystem === "npm" && satisfies(version, a.vulnerableRange),
  );
}
