/**
 * Dependency / SCA agent (§5.2). Resolves the installed dependency set from the
 * lockfile (pnpm-lock.yaml / package-lock.json) or, failing that, package.json,
 * matches each package against the OFFLINE advisory mirror, and — critically —
 * runs a REACHABILITY check: is the vulnerable package actually imported through
 * the code's import graph? Reachability is tagged on every candidate so Layer 2
 * can promote reachable vulns and demote merely-present ones (§7 L2). No network.
 */
import nodePath from "node:path";
import type { CandidateFinding } from "@montr/contracts";
import type { DetectorContext } from "../types.js";
import { ADVISORY_DB, matchAdvisories, type Advisory } from "../advisories.js";
import { coerce } from "../semver.js";
import { buildCandidate } from "../util/candidate.js";
import { isSourceFile, readAll, type FileProvider } from "../util/files.js";
import { lineOfFirst } from "../util/text.js";

export interface DetectScaOptions {
  advisories?: readonly Advisory[];
}

export interface InstalledPackage {
  name: string;
  version: string;
}

export interface ResolvedDeps {
  packages: InstalledPackage[];
  /** File that drove version resolution. */
  lockfile?: string;
  packageJsonPath?: string;
  packageJsonContent?: string;
}

// --- safe JSON access helpers (no `any`) ----------------------------------

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}
function getString(rec: Record<string, unknown> | undefined, key: string): string | undefined {
  const v = rec?.[key];
  return typeof v === "string" ? v : undefined;
}
function safeJson(text: string): Record<string, unknown> | undefined {
  try {
    return asRecord(JSON.parse(text));
  } catch {
    return undefined;
  }
}

// --- lockfile / manifest parsers ------------------------------------------

/** Parse a `name@version` (pnpm) or `name/version` (v5) lock key. */
export function parsePkgKey(key: string): InstalledPackage | null {
  const k = key.replace(/^\//, "").replace(/\(.*\)$/, "");
  const at = k.lastIndexOf("@");
  if (at > 0) {
    const name = k.slice(0, at);
    const version = k.slice(at + 1);
    if (/^\d/.test(version)) return { name, version };
  }
  const segs = k.split("/");
  const last = segs[segs.length - 1] ?? "";
  if (/^\d/.test(last) && segs.length >= 2) {
    return { name: segs.slice(0, -1).join("/"), version: last };
  }
  return null;
}

/** Parse a pnpm-lock.yaml (v9/v6/v5 tolerant). Lazily imports the yaml parser. */
export async function parsePnpmLock(text: string): Promise<InstalledPackage[]> {
  let doc: unknown;
  try {
    const { parse } = await import("yaml");
    doc = parse(text);
  } catch {
    return [];
  }
  const out = new Map<string, InstalledPackage>();
  const collect = (section: unknown): void => {
    const rec = asRecord(section);
    if (!rec) return;
    for (const key of Object.keys(rec)) {
      const parsed = parsePkgKey(key);
      if (parsed) out.set(`${parsed.name}@${parsed.version}`, parsed);
    }
  };
  const d = asRecord(doc);
  collect(d?.["packages"]);
  collect(d?.["snapshots"]);
  return [...out.values()];
}

/** Parse a package-lock.json (v2/v3 `packages`, v1 `dependencies`). */
export function parsePackageLock(text: string): InstalledPackage[] {
  const doc = safeJson(text);
  if (!doc) return [];
  const out = new Map<string, InstalledPackage>();
  const packages = asRecord(doc["packages"]);
  if (packages) {
    for (const [key, val] of Object.entries(packages)) {
      if (!key) continue; // "" is the project root
      const marker = "node_modules/";
      const idx = key.lastIndexOf(marker);
      if (idx < 0) continue;
      const name = key.slice(idx + marker.length);
      const version = getString(asRecord(val), "version");
      if (name && version) out.set(`${name}@${version}`, { name, version });
    }
  }
  const walk = (deps: unknown): void => {
    const rec = asRecord(deps);
    if (!rec) return;
    for (const [name, val] of Object.entries(rec)) {
      const node = asRecord(val);
      const version = getString(node, "version");
      if (version) out.set(`${name}@${version}`, { name, version });
      walk(node?.["dependencies"]);
    }
  };
  walk(doc["dependencies"]);
  return [...out.values()];
}

/** Parse package.json dependency ranges → coerced concrete versions (fallback). */
export function parsePackageJson(text: string): InstalledPackage[] {
  const rec = safeJson(text);
  if (!rec) return [];
  const out = new Map<string, InstalledPackage>();
  for (const field of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const deps = asRecord(rec[field]);
    if (!deps) continue;
    for (const [name, range] of Object.entries(deps)) {
      if (typeof range !== "string") continue;
      const v = coerce(range);
      if (v) out.set(name, { name, version: `${v.major}.${v.minor}.${v.patch}` });
    }
  }
  return [...out.values()];
}

function pickShallowest(paths: string[], base: string): string | undefined {
  return paths
    .filter((p) => nodePath.posix.basename(p) === base)
    .sort((a, b) => a.split("/").length - b.split("/").length || a.length - b.length)[0];
}

/** Resolve the installed dependency set (lockfile-preferred, package.json fallback). */
export async function resolveInstalledPackages(files: FileProvider): Promise<ResolvedDeps> {
  const list = await files.list();
  const packageJsonPath = pickShallowest(list, "package.json");
  const packageJsonContent = packageJsonPath
    ? ((await files.read(packageJsonPath)) ?? undefined)
    : undefined;

  const pnpmPath = pickShallowest(list, "pnpm-lock.yaml");
  const npmLockPath = pickShallowest(list, "package-lock.json");

  let packages: InstalledPackage[] = [];
  let lockfile: string | undefined;

  if (pnpmPath) {
    const c = await files.read(pnpmPath);
    if (c) {
      packages = await parsePnpmLock(c);
      lockfile = pnpmPath;
    }
  }
  if (packages.length === 0 && npmLockPath) {
    const c = await files.read(npmLockPath);
    if (c) {
      packages = parsePackageLock(c);
      lockfile = npmLockPath;
    }
  }
  if (packages.length === 0 && packageJsonContent) {
    packages = parsePackageJson(packageJsonContent);
    lockfile = packageJsonPath;
  }
  return { packages, lockfile, packageJsonPath, packageJsonContent };
}

// --- reachability (import graph) ------------------------------------------

const IMPORT_RES: readonly RegExp[] = [
  /import\s+(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/g,
  /export\s+(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/g,
  /require\(\s*["']([^"']+)["']\s*\)/g,
  /import\(\s*["']([^"']+)["']\s*\)/g,
];

/** Bare package name for an import specifier, or null for relative/builtin. */
export function barePackageName(spec: string): string | null {
  if (spec.startsWith(".") || spec.startsWith("/") || spec.startsWith("node:")) return null;
  const parts = spec.split("/");
  if (spec.startsWith("@")) {
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  return parts[0] || null;
}

/** The set of npm packages actually imported anywhere in the source. */
export async function collectImportedPackages(files: FileProvider): Promise<Set<string>> {
  const sources = await readAll(files, isSourceFile);
  const imported = new Set<string>();
  for (const file of sources) {
    for (const base of IMPORT_RES) {
      const re = new RegExp(base.source, base.flags);
      let m: RegExpExecArray | null;
      while ((m = re.exec(file.content)) !== null) {
        const spec = m[1];
        if (!spec) continue;
        const name = barePackageName(spec);
        if (name) imported.add(name);
      }
    }
  }
  return imported;
}

// --- entry point -----------------------------------------------------------

export async function detectDependencies(
  ctx: DetectorContext,
  opts: DetectScaOptions = {},
): Promise<CandidateFinding[]> {
  if (ctx.signal?.aborted) return [];
  const db = opts.advisories ?? ADVISORY_DB;
  const resolved = await resolveInstalledPackages(ctx.files);
  if (resolved.packages.length === 0) {
    ctx.warn("sca", "No lockfile or package.json found; SCA degraded to empty.");
    return [];
  }
  const imported = await collectImportedPackages(ctx.files);
  const locFile = resolved.packageJsonPath ?? resolved.lockfile ?? "package.json";

  const out: CandidateFinding[] = [];
  for (const pkg of resolved.packages) {
    for (const adv of matchAdvisories(pkg.name, pkg.version, db)) {
      const reachable = imported.has(pkg.name);
      const line = resolved.packageJsonContent
        ? lineOfFirst(resolved.packageJsonContent, `"${pkg.name}"`)
        : 0;
      out.push(
        buildCandidate(ctx, {
          source: adv.source === "ghsa" ? "ghsa" : "osv",
          ruleId: adv.id,
          category: "vulnerable_dependency",
          cwe: adv.cwe,
          file: locFile,
          line,
          rawSeverity: adv.severity,
          snippet: `${pkg.name}@${pkg.version} — ${adv.summary}`,
          title: `Vulnerable dependency: ${pkg.name}@${pkg.version} (${adv.id})`,
          idExtra: adv.id,
          metadata: {
            detector: "sca",
            package: pkg.name,
            version: pkg.version,
            advisoryId: adv.id,
            aliases: adv.aliases ?? [],
            fixedVersion: adv.fixedVersion,
            vulnerableRange: adv.vulnerableRange,
            ecosystem: "npm",
            // ⛔ Reachability drives Layer-2 promote/demote — a present-but-unimported
            // vuln is demoted, not headlined.
            reachable,
          },
        }),
      );
    }
  }
  return out;
}
