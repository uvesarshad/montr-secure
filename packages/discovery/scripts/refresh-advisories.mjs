#!/usr/bin/env node
/**
 * Regenerates the offline OSV advisory mirror shipped in
 * `packages/discovery/src/advisories-data/{npm,pypi,maven}.json`.
 *
 * WHAT THIS DOES
 * 1. Downloads the OSV.dev bulk ecosystem exports (`all.zip`) for npm, PyPI,
 *    and Maven from `https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip`.
 *    GHSA advisories are already merged into OSV's npm/PyPI/Maven data, so this
 *    single source covers both OSV- and GHSA-authored records — no separate
 *    GHSA API call is needed.
 * 2. Extracts each zip (one JSON file per advisory) with the system `unzip`.
 * 3. Filters down to advisories affecting a curated allow-list of popular /
 *    historically-significant packages (`popular-packages.json`, edit that
 *    file to widen or narrow coverage) — the full bulk export is 200k+ files
 *    and not something we want to ship verbatim in this repo.
 * 4. Transforms each matching `(advisory, affected-package)` pair into this
 *    package's `Advisory` shape (see `../src/advisories.ts`) and writes the
 *    result to `../src/advisories-data/<ecosystem>.json`, sorted by id for a
 *    stable diff.
 *
 * USAGE
 *   node packages/discovery/scripts/refresh-advisories.mjs
 *   node packages/discovery/scripts/refresh-advisories.mjs --zip-dir /path/to/cached/zips
 *
 * `--zip-dir` points at a directory already containing `npm.zip` / `PyPI.zip`
 * / `Maven.zip` (as downloaded from the URLs above) to skip re-downloading —
 * useful for iterating on the filter/transform logic offline.
 *
 * REQUIRES: network access to *.storage.googleapis.com (unless --zip-dir is
 * given) and the `unzip` binary on PATH (present on macOS/Linux CI images).
 * Nothing here runs at scan time — this is an operator/CI-triggered refresh
 * of the static mirror the SCA detector loads offline (see README.md).
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_DIR = __dirname;
const DISCOVERY_ROOT = path.resolve(SCRIPT_DIR, "..");
const OUT_DIR = path.join(DISCOVERY_ROOT, "src", "advisories-data");

/** OSV ecosystem name -> our internal ecosystem tag + output filename. */
const ECOSYSTEMS = [
  { osv: "npm", tag: "npm", file: "npm.json" },
  { osv: "PyPI", tag: "PyPI", file: "pypi.json" },
  { osv: "Maven", tag: "Maven", file: "maven.json" },
];

function parseArgs(argv) {
  const out = { zipDir: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--zip-dir") out.zipDir = argv[++i];
  }
  return out;
}

async function downloadZip(osvEcosystem, destPath) {
  const url = `https://osv-vulnerabilities.storage.googleapis.com/${osvEcosystem}/all.zip`;
  console.log(`  downloading ${url} ...`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed for ${osvEcosystem}: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(destPath, buf);
}

async function extractZip(zipPath, destDir) {
  await mkdir(destDir, { recursive: true });
  await execFileAsync("unzip", ["-q", "-o", zipPath, "-d", destDir]);
}

// --- CVSS v3.x base score (FIRST.org spec) --> our 5-point severity scale ---

const CVSS3_AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const CVSS3_AC = { L: 0.77, H: 0.44 };
const CVSS3_PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const CVSS3_PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const CVSS3_UI = { N: 0.85, R: 0.62 };
const CVSS3_IMPACT = { N: 0, L: 0.22, H: 0.56 };

function roundUp1(n) {
  // CVSS spec's roundup: round to nearest 0.1, biased up, avoiding fp error.
  const int = Math.round(n * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

/** Parse a `CVSS:3.x/AV:.../...` vector into its metric map. */
function parseCvssVector(vector) {
  const parts = vector.split("/").filter((p) => p.includes(":"));
  const map = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    map[k] = v;
  }
  return map;
}

function cvss3BaseScore(vector) {
  const m = parseCvssVector(vector);
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const iscBase = 1 - (1 - CVSS3_IMPACT[m.C]) * (1 - CVSS3_IMPACT[m.I]) * (1 - CVSS3_IMPACT[m.A]);
  const scopeChanged = m.S === "C";
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  const pr = scopeChanged ? CVSS3_PR_CHANGED[m.PR] : CVSS3_PR_UNCHANGED[m.PR];
  const exploitability = 8.22 * CVSS3_AV[m.AV] * CVSS3_AC[m.AC] * pr * CVSS3_UI[m.UI];
  if (impact <= 0) return 0;
  const raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundUp1(Math.min(raw, 10));
}

/** Coarse CVSS v4 severity estimate: not the full MacroVector algorithm — we
 * only need a 5-bucket severity, so we bucket on how many of the vulnerable-
 * system impact metrics (VC/VI/VA) plus attack requirements are "High"/none. */
function cvss4Severity(vector) {
  const m = parseCvssVector(vector);
  const highCount = ["VC", "VI", "VA", "SC", "SI", "SA"].filter((k) => m[k] === "H").length;
  const easy = m.AV === "N" && (m.AC === "L" || m.AT === "N");
  if (highCount >= 2 && easy) return "critical";
  if (highCount >= 2) return "high";
  if (highCount === 1) return easy ? "high" : "medium";
  const lowCount = ["VC", "VI", "VA"].filter((k) => m[k] === "L").length;
  return lowCount > 0 ? "medium" : "low";
}

function bucketScore(score) {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

/** Best-effort severity for an OSV record: GHSA's own bucket first (most
 * reliable), then a CVSS-vector-derived estimate, then a conservative
 * "medium" default (mirrors this mirror's original hand-seeded convention). */
function deriveSeverity(record) {
  const dbSev = record.database_specific?.severity;
  const known = { LOW: "low", MODERATE: "medium", HIGH: "high", CRITICAL: "critical" };
  if (dbSev && known[dbSev]) return known[dbSev];

  for (const s of record.severity ?? []) {
    if (typeof s.score !== "string" || !s.score.startsWith("CVSS:")) continue;
    if (s.type === "CVSS_V3") {
      const score = cvss3BaseScore(s.score);
      if (score !== null) return bucketScore(score);
    }
    if (s.type === "CVSS_V4") {
      return cvss4Severity(s.score);
    }
  }
  return "medium";
}

// --- version-range transform: OSV events -> our comparator-string ranges ---

/** One OSV `ranges[].events` array (already sorted) -> our range string
 * (comparator groups joined by " || ", matching `src/semver.ts`'s `satisfies`). */
function eventsToRange(events) {
  const segments = [];
  let introduced = null;
  for (const ev of events) {
    if ("introduced" in ev) {
      introduced = ev.introduced;
    } else if ("fixed" in ev) {
      segments.push(
        introduced === "0" || introduced === null ? `<${ev.fixed}` : `>=${introduced} <${ev.fixed}`,
      );
      introduced = null;
    } else if ("last_affected" in ev) {
      segments.push(
        introduced === "0" || introduced === null
          ? `<=${ev.last_affected}`
          : `>=${introduced} <=${ev.last_affected}`,
      );
      introduced = null;
    }
    // "limit" events (rare) are ignored — not expressible in our comparator grammar.
  }
  if (introduced !== null) {
    // Still-open interval: vulnerable from `introduced` onward, no fix published yet.
    segments.push(introduced === "0" ? "*" : `>=${introduced}`);
  }
  return segments;
}

function lastFixedVersion(events) {
  let fixed;
  for (const ev of events) if ("fixed" in ev) fixed = ev.fixed;
  return fixed;
}

/** Transform one OSV record into zero or more of our `Advisory` rows — one
 * per affected package block that matches the allow-list for this ecosystem.
 * Each row carries a transient `_published` (used only for cross-advisory
 * de-duplication below; stripped before the file is written). */
function transformRecord(record, osvEcosystem, allowSet) {
  if (record.id?.startsWith("MAL-")) return []; // malicious-package reports, not version-range CVEs
  const out = [];
  const cweIds = (record.database_specific?.cwe_ids ?? []).filter((c) => /^CWE-\d+$/.test(c));
  const severity = deriveSeverity(record);
  const source = record.id?.startsWith("GHSA-") ? "ghsa" : "osv";
  const summary = (record.summary || record.details || "").split("\n")[0].slice(0, 300).trim();

  // A single OSV record can list the SAME package more than once in `affected`
  // (e.g. one range for an abandoned 0.x line, another for the current 1.x
  // line). Group by package name first so each ends up as ONE Advisory row
  // with an OR'd range (our `satisfies()` already supports `||` groups) rather
  // than several rows duplicating the same id/package pair.
  const byPackage = new Map();
  for (const affected of record.affected ?? []) {
    const pkg = affected.package;
    if (!pkg || pkg.ecosystem !== osvEcosystem) continue;
    if (!allowSet.has(pkg.name)) continue;
    if (!byPackage.has(pkg.name)) byPackage.set(pkg.name, []);
    byPackage.get(pkg.name).push(affected);
  }

  for (const [pkgName, blocks] of byPackage) {
    const ranges = blocks.flatMap((b) =>
      (b.ranges ?? []).filter((r) => r.type === "SEMVER" || r.type === "ECOSYSTEM"),
    );
    let rangeSegments = ranges.flatMap((r) => eventsToRange(r.events ?? []));
    const fixedVersion = ranges.map((r) => lastFixedVersion(r.events ?? [])).find(Boolean);

    // Some records only carry an explicit `versions` list (no range events).
    if (rangeSegments.length === 0) {
      const versions = blocks.flatMap((b) => (Array.isArray(b.versions) ? b.versions : []));
      if (versions.length > 0) rangeSegments = versions.map((v) => `=${v}`);
    }
    if (rangeSegments.length === 0) continue; // nothing we can express as a version range

    out.push({
      id: record.id,
      aliases: record.aliases ?? [],
      package: pkgName,
      ecosystem: osvEcosystem,
      vulnerableRange: rangeSegments.join(" || "),
      ...(fixedVersion ? { fixedVersion } : {}),
      cwe: cweIds,
      severity,
      summary: summary || `${pkgName} vulnerability (${record.id}).`,
      source,
      _published: record.published ?? "",
    });
  }
  return out;
}

/**
 * GHSA advisories occasionally get re-published under a NEW GHSA id that
 * cross-references the original as a mutual alias (same underlying CVE, often
 * with a refreshed/broadened affected-version assessment). Left alone this
 * emits two near-duplicate candidates for one real vulnerability. Collapse
 * same-package groups that share a CVE alias down to the most-recently
 * published record (the up-to-date range assessment wins).
 */
function dedupeReissuedAdvisories(rows) {
  const byKey = new Map();
  const passthrough = [];
  for (const r of rows) {
    const cveAliases = (r.aliases ?? []).filter((a) => a.startsWith("CVE-")).sort();
    if (cveAliases.length === 0) {
      passthrough.push(r);
      continue;
    }
    const key = `${r.package}::${cveAliases.join(",")}`;
    const existing = byKey.get(key);
    if (!existing || (r._published ?? "") > (existing._published ?? "")) byKey.set(key, r);
  }
  return [...byKey.values(), ...passthrough];
}

async function loadAllowSet(popularPackages, ecoTag) {
  return new Set(popularPackages[ecoTag] ?? []);
}

async function processEcosystem({ osv, tag, file }, extractedRoot, popularPackages) {
  const dir = path.join(extractedRoot, osv);
  const files = (await readdir(dir)).filter((f) => f.endsWith(".json"));
  const allowSet = await loadAllowSet(popularPackages, tag);

  const rows = [];
  for (const f of files) {
    let record;
    try {
      record = JSON.parse(await readFile(path.join(dir, f), "utf8"));
    } catch {
      continue;
    }
    rows.push(...transformRecord(record, osv, allowSet));
  }

  // Dedupe (same advisory can list the same package twice across ranges arrays
  // in malformed/edge-case records), collapse re-issued GHSA advisories that
  // share a CVE alias, strip the transient `_published` field, and sort for a
  // stable, reviewable diff.
  const seen = new Set();
  let deduped = [];
  for (const r of rows) {
    const key = `${r.id}::${r.package}::${r.vulnerableRange}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(r);
  }
  deduped = dedupeReissuedAdvisories(deduped).map(({ _published, ...r }) => r);
  deduped.sort((a, b) =>
    a.package === b.package ? a.id.localeCompare(b.id) : a.package.localeCompare(b.package),
  );

  await mkdir(OUT_DIR, { recursive: true });
  await writeFile(path.join(OUT_DIR, file), `${JSON.stringify(deduped, null, 2)}\n`);
  return deduped.length;
}

async function main() {
  const { zipDir } = parseArgs(process.argv.slice(2));
  const popularPackages = JSON.parse(
    await readFile(path.join(SCRIPT_DIR, "popular-packages.json"), "utf8"),
  );

  const work = zipDir ?? (await mkdtemp(path.join(tmpdir(), "osv-refresh-")));
  const extractedRoot = await mkdtemp(path.join(tmpdir(), "osv-extracted-"));

  console.log(`Working dir: ${work}`);
  try {
    for (const eco of ECOSYSTEMS) {
      const zipPath = path.join(work, `${eco.osv}.zip`);
      if (!zipDir) {
        console.log(`[${eco.osv}] downloading bulk export...`);
        await downloadZip(eco.osv, zipPath);
      } else {
        console.log(`[${eco.osv}] using cached zip at ${zipPath}`);
      }
      console.log(`[${eco.osv}] extracting...`);
      await extractZip(zipPath, path.join(extractedRoot, eco.osv));
    }

    let total = 0;
    for (const eco of ECOSYSTEMS) {
      console.log(`[${eco.osv}] filtering + transforming...`);
      const count = await processEcosystem(eco, extractedRoot, popularPackages);
      console.log(
        `[${eco.osv}] wrote ${count} advisory records -> src/advisories-data/${eco.file}`,
      );
      total += count;
    }
    console.log(`\nDone. ${total} total advisory records across ${ECOSYSTEMS.length} ecosystems.`);
  } finally {
    await rm(extractedRoot, { recursive: true, force: true });
    if (!zipDir) await rm(work, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
