/**
 * E16 — supply-chain risk heuristics, built on top of Layer 1's existing SCA
 * dependency resolution (`detectors/sca.ts`'s `resolveInstalledPackages`):
 *
 *   1. Typosquatting — Levenshtein edit-distance against a curated list of
 *      popular npm packages; flags a resolved name that is suspiciously close
 *      to (but not exactly) a well-known package.
 *   2. Install-script risk — a `preinstall`/`postinstall`/`install` script,
 *      in the project's OWN `package.json` and (when present) in a resolved
 *      dependency's `node_modules/<pkg>/package.json`, is a well-known
 *      supply-chain attack vector (arbitrary code execution on `npm install`,
 *      no user interaction required). Content is pattern-scanned for
 *      known-suspicious shapes (remote-fetch-and-execute, base64/eval
 *      obfuscation) to separate a legitimate build-tooling hook (e.g.
 *      `husky install`, `prisma generate`) from a genuinely risky one.
 *   3. Basic malicious-package heuristics, SCOPED TO WHAT IS REALISTICALLY
 *      CHECKABLE OFFLINE (this product does not fetch live npm registry
 *      metadata — see the module's Constraints doc below for the honest
 *      scope line): non-ASCII/homoglyph package names, and a lockfile entry
 *      resolving from a non-standard registry host (dependency-confusion /
 *      registry-substitution signal).
 *
 * ⛔ Constraints / documented gaps (be honest about exactly what this can't
 * do rather than fake it):
 *   - "Very recently published + very few downloads + requests unusual
 *     permissions" (the audit's own suggested malicious-package signal)
 *     requires LIVE npm registry API metadata (publish date, download
 *     counts) — this product is explicitly on-prem/BYO-key with source never
 *     leaving client infrastructure except to the LLM endpoint (golden rule
 *     #1); adding a live npm-registry network call is a deliberate, separate
 *     product decision this change does not make. Documented as explicit
 *     future work, not silently skipped.
 *   - `node_modules` is excluded from `fsFileProvider`'s directory WALK
 *     (`IGNORE_DIRS`, see `util/files.ts`) — the install-script check below
 *     works around this by READING a specific `node_modules/<pkg>/
 *     package.json` PATH directly (`FileProvider.read` has no ignore-list;
 *     only `list()`'s walk does), which works whenever `node_modules` is
 *     actually present on disk (e.g. a CI/post-`npm install` scan) and
 *     degrades to "nothing found" — not a false negative claim, a true
 *     absence — for the far more common git-checkout-only scan.
 */
import nodePath from "node:path";
import type { CandidateFinding, Category, Severity } from "@montr/contracts";
import type { DetectorContext } from "../types.js";
import { buildCandidate } from "../util/candidate.js";
import { lineOfFirst } from "../util/text.js";
import type { InstalledPackage, ResolvedDeps } from "./sca.js";

export interface RawFinding {
  rule: string;
  category: Category;
  severity: Severity;
  packageName: string;
  snippet: string;
  title: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 1. Typosquatting
// ---------------------------------------------------------------------------

/**
 * Curated top-of-distribution npm packages (by rough real-world popularity).
 * Necessarily non-exhaustive — a hand-maintained list, same honest posture as
 * `advisories.ts`'s offline mirror being a snapshot rather than a live feed.
 */
export const POPULAR_NPM_PACKAGES: readonly string[] = [
  "react",
  "react-dom",
  "vue",
  "angular",
  "next",
  "express",
  "fastify",
  "koa",
  "lodash",
  "underscore",
  "axios",
  "node-fetch",
  "request",
  "chalk",
  "commander",
  "yargs",
  "inquirer",
  "webpack",
  "vite",
  "rollup",
  "esbuild",
  "parcel",
  "babel-core",
  "@babel/core",
  "typescript",
  "eslint",
  "prettier",
  "jest",
  "mocha",
  "chai",
  "vitest",
  "moment",
  "dayjs",
  "date-fns",
  "uuid",
  "dotenv",
  "cors",
  "body-parser",
  "cookie-parser",
  "jsonwebtoken",
  "bcrypt",
  "bcryptjs",
  "mongoose",
  "sequelize",
  "prisma",
  "@prisma/client",
  "typeorm",
  "graphql",
  "apollo-server",
  "socket.io",
  "ws",
  "passport",
  "nodemailer",
  "multer",
  "sharp",
  "puppeteer",
  "playwright",
  "cheerio",
  "jsdom",
  "colors",
  "figlet",
  "ora",
  "table",
  "csv-parser",
  "xml2js",
  "js-yaml",
  "yaml",
  "glob",
  "rimraf",
  "mkdirp",
  "fs-extra",
  "chokidar",
  "nodemon",
  "pm2",
  "winston",
  "pino",
  "morgan",
  "helmet",
  "joi",
  "zod",
  "yup",
  "ajv",
  "validator",
  "sanitize-html",
  "dompurify",
  "marked",
  "highlight.js",
  "three",
  "d3",
  "chart.js",
  "classnames",
  "clsx",
  "styled-components",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "sass",
  "less",
  "gulp",
  "grunt",
  "browserify",
  "core-js",
  "tslib",
  "reflect-metadata",
  "rxjs",
  "immer",
  "zustand",
  "redux",
  "react-redux",
  "react-router",
  "react-router-dom",
  "next-auth",
  "firebase",
  "aws-sdk",
  "stripe",
  "twilio",
  "openai",
  "semver",
  "minimist",
  "async",
  "bluebird",
  "lru-cache",
  "debug",
  "ms",
  "qs",
  "form-data",
  "content-type",
  "mime",
  "mime-types",
  "ejs",
  "handlebars",
  "pug",
  "compression",
  "serve-static",
  "http-proxy",
  "http-proxy-middleware",
  "ioredis",
  "redis",
  "pg",
  "pg-promise",
  "mysql",
  "mysql2",
  "sqlite3",
  "knex",
];

const NORMALIZED_POPULAR = POPULAR_NPM_PACKAGES.map((p) => ({ raw: p, base: basePackageName(p) }));

function basePackageName(name: string): string {
  const at = name.indexOf("/");
  return (name.startsWith("@") && at > 0 ? name.slice(at + 1) : name).toLowerCase();
}

/** Standard Levenshtein edit distance (DP), bounded — callers only compare short names. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur.push(Math.min((prev[j] ?? 0) + 1, (cur[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost));
    }
    prev = cur;
  }
  return prev[n] ?? Math.max(m, n);
}

/** Small-package names need a tighter distance threshold than long ones (edit-distance-1 on "axios" is very suspicious; the same distance on a 20-char name is unremarkable). */
function distanceThreshold(len: number): number {
  if (len <= 5) return 1;
  if (len <= 12) return 2;
  return 3;
}

export interface TyposquatMatch {
  pkg: InstalledPackage;
  matchedPopular: string;
  distance: number;
}

/** Real, offline Levenshtein-distance typosquat check against the curated popular-package list. */
export function detectTyposquats(packages: readonly InstalledPackage[]): TyposquatMatch[] {
  const out: TyposquatMatch[] = [];
  const popularBaseSet = new Set(NORMALIZED_POPULAR.map((p) => p.base));
  for (const pkg of packages) {
    const base = basePackageName(pkg.name);
    if (popularBaseSet.has(base)) continue; // exact match to a known-good name -> not a typosquat
    if (base.length < 3 || base.length > 40) continue; // too short/long for a meaningful distance signal
    let best: TyposquatMatch | undefined;
    for (const popular of NORMALIZED_POPULAR) {
      if (Math.abs(popular.base.length - base.length) > 3) continue; // cheap pre-filter
      const d = levenshtein(base, popular.base);
      if (d === 0) continue; // handled by the exact-match check above
      if (d <= distanceThreshold(base.length) && (!best || d < best.distance)) {
        best = { pkg, matchedPopular: popular.raw, distance: d };
      }
    }
    if (best) out.push(best);
  }
  return out;
}

// ---------------------------------------------------------------------------
// 2. Install-script risk
// ---------------------------------------------------------------------------

const INSTALL_HOOK_KEYS = ["preinstall", "install", "postinstall"] as const;

const SUSPICIOUS_SCRIPT_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [
    /curl\s+[^|]*\|\s*(?:sudo\s+)?(?:sh|bash)/i,
    "pipes a remote curl download directly into a shell",
  ],
  [
    /wget\s+[^|]*\|\s*(?:sudo\s+)?(?:sh|bash)/i,
    "pipes a remote wget download directly into a shell",
  ],
  [/base64\s+(?:-d|--decode)/i, "decodes a base64-obfuscated payload"],
  [/Buffer\.from\([^)]*['"]base64['"]\)/i, "decodes a base64-obfuscated payload"],
  [/\batob\s*\(/i, "decodes a base64-obfuscated payload"],
  [/\beval\s*\(/i, "evaluates a dynamically constructed string as code"],
  [/require\(['"]child_process['"]\)/i, "spawns a subprocess from the install hook"],
  [
    /(?:raw\.githubusercontent\.com|pastebin\.com|ngrok\.io)/i,
    "fetches from a known anonymous-hosting/paste endpoint",
  ],
  [/process\.env/i, "reads process.env during install (possible credential exfiltration)"],
];

function scriptRisk(script: string): { severity: Severity; reasons: string[] } {
  const reasons: string[] = [];
  for (const [re, reason] of SUSPICIOUS_SCRIPT_PATTERNS) {
    if (re.test(script)) reasons.push(reason);
  }
  return { severity: reasons.length > 0 ? "high" : "low", reasons };
}

export interface InstallScriptFinding {
  packageName: string;
  hook: (typeof INSTALL_HOOK_KEYS)[number];
  script: string;
  severity: Severity;
  reasons: string[];
}

/** Parse `scripts.{preinstall,install,postinstall}` out of a raw package.json string. */
function extractInstallHooks(
  pkgJsonText: string,
): Array<{ hook: (typeof INSTALL_HOOK_KEYS)[number]; script: string }> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(pkgJsonText);
  } catch {
    return [];
  }
  const scripts =
    parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)["scripts"]
      : undefined;
  if (!scripts || typeof scripts !== "object" || Array.isArray(scripts)) return [];
  const out: Array<{ hook: (typeof INSTALL_HOOK_KEYS)[number]; script: string }> = [];
  for (const hook of INSTALL_HOOK_KEYS) {
    const script = (scripts as Record<string, unknown>)[hook];
    if (typeof script === "string" && script.trim()) out.push({ hook, script });
  }
  return out;
}

/** The project's OWN install hooks (always checkable — its package.json is always in scope). */
export function detectOwnInstallScriptRisk(
  packageName: string,
  packageJsonContent: string,
): InstallScriptFinding[] {
  return extractInstallHooks(packageJsonContent).map(({ hook, script }) => {
    const { severity, reasons } = scriptRisk(script);
    return { packageName, hook, script, severity, reasons };
  });
}

/**
 * Dependencies' install hooks, ONLY resolvable when `node_modules` is
 * actually present on disk — see module doc for why this can't see through a
 * plain git checkout, and why that's a true absence, not a swallowed error.
 * Reads are targeted (`read(path)` for a SPECIFIC computed path), never a
 * walk — `node_modules` stays excluded from every general directory listing.
 */
export async function detectDependencyInstallScriptRisk(
  ctx: DetectorContext,
  packages: readonly InstalledPackage[],
  limit = 300,
): Promise<InstallScriptFinding[]> {
  const out: InstallScriptFinding[] = [];
  for (const pkg of packages.slice(0, limit)) {
    if (ctx.signal?.aborted) break;
    const rel = `node_modules/${pkg.name}/package.json`;
    const content = await ctx.files.read(rel);
    if (!content) continue;
    out.push(...detectOwnInstallScriptRisk(pkg.name, content));
  }
  return out;
}

// ---------------------------------------------------------------------------
// 3. Basic malicious-package heuristics (offline-checkable subset — see module doc)
// ---------------------------------------------------------------------------

/**
 * A non-ASCII / zero-width / bidi-control character in a package name — a
 * known obfuscation technique (visually-identical homoglyph names, or an
 * invisible character that makes a malicious name render identically to a
 * trusted one). Explicit \uXXXX escapes only — no literal invisible
 * characters in source, for reviewability.
 */
// eslint-disable-next-line no-control-regex -- \x00-\x7F is the intended ASCII-range bound, not a stray control character.
const SUSPICIOUS_NAME_CHAR_RE = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]|[^\x00-\x7F]/;

export function detectSuspiciousPackageNames(
  packages: readonly InstalledPackage[],
): InstalledPackage[] {
  return packages.filter((p) => SUSPICIOUS_NAME_CHAR_RE.test(p.name));
}

const KNOWN_REGISTRY_HOSTS = new Set(["registry.npmjs.org"]);

export interface SuspiciousResolution {
  packageName: string;
  resolvedUrl: string;
  host: string;
}

/**
 * `package-lock.json`'s `packages[key].resolved` field is a real per-package
 * tarball URL — a dependency resolving from anything other than the standard
 * npm registry host is a dependency-confusion / registry-substitution
 * signal. `pnpm-lock.yaml` does not carry an explicit URL for standard
 * registry-resolved packages (only for git/tarball deps), so this check is
 * npm-lockfile-specific — documented, not silently generalized.
 */
export function detectSuspiciousRegistryResolution(
  packageLockJsonContent: string,
): SuspiciousResolution[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(packageLockJsonContent);
  } catch {
    return [];
  }
  const doc =
    parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : undefined;
  const packages = doc?.["packages"];
  if (!packages || typeof packages !== "object" || Array.isArray(packages)) return [];
  const out: SuspiciousResolution[] = [];
  for (const [key, val] of Object.entries(packages as Record<string, unknown>)) {
    if (!key) continue; // "" is the project root
    const node = val && typeof val === "object" ? (val as Record<string, unknown>) : undefined;
    const resolved = node?.["resolved"];
    if (typeof resolved !== "string" || !/^https?:\/\//i.test(resolved)) continue;
    let host: string;
    try {
      host = new URL(resolved).host;
    } catch {
      continue;
    }
    if (KNOWN_REGISTRY_HOSTS.has(host)) continue;
    const marker = "node_modules/";
    const idx = key.lastIndexOf(marker);
    const name = idx >= 0 ? key.slice(idx + marker.length) : key;
    out.push({ packageName: name, resolvedUrl: resolved, host });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export interface DetectSupplyChainOptions {
  /** Cap on how many resolved packages get their own node_modules/<pkg>/package.json probed (perf bound). */
  installScriptProbeLimit?: number;
}

/**
 * Run every supply-chain check over the already-resolved dependency set.
 * Deliberately takes `resolved`/`packageLockJsonContent` rather than
 * re-resolving — the caller (`iac.ts`'s sibling `sca.ts`, or a future shared
 * Layer 1 orchestration point) already did that resolution once.
 */
export async function detectSupplyChainRisks(
  ctx: DetectorContext,
  resolved: ResolvedDeps,
  opts: DetectSupplyChainOptions = {},
): Promise<CandidateFinding[]> {
  const out: CandidateFinding[] = [];
  const anchorFile = resolved.packageJsonPath ?? resolved.lockfile ?? "package.json";

  const push = (raw: RawFinding, line: number): void => {
    out.push(
      buildCandidate(ctx, {
        source: "custom",
        ruleId: raw.rule,
        category: raw.category,
        file: anchorFile,
        line,
        rawSeverity: raw.severity,
        snippet: raw.snippet,
        title: raw.title,
        metadata: raw.metadata,
      }),
    );
  };
  const lineFor = (name: string): number =>
    resolved.packageJsonContent ? lineOfFirst(resolved.packageJsonContent, `"${name}"`) : 0;

  // 1. Typosquatting.
  for (const match of detectTyposquats(resolved.packages)) {
    push(
      {
        rule: "supply-chain.typosquat",
        category: "vulnerable_dependency",
        severity: match.distance === 1 ? "high" : "medium",
        packageName: match.pkg.name,
        snippet: `"${match.pkg.name}" is edit-distance ${match.distance} from popular package "${match.matchedPopular}"`,
        title: `Possible typosquat: "${match.pkg.name}" closely resembles "${match.matchedPopular}"`,
        metadata: {
          detector: "supply-chain",
          check: "typosquat",
          package: match.pkg.name,
          matchedPopular: match.matchedPopular,
          distance: match.distance,
        },
      },
      lineFor(match.pkg.name),
    );
  }

  // 2a. The project's own install hooks (always checkable).
  if (resolved.packageJsonContent) {
    const projectName = nodePath.posix.basename(resolved.packageJsonPath ?? "package.json");
    for (const f of detectOwnInstallScriptRisk(projectName, resolved.packageJsonContent)) {
      push(
        {
          rule: `supply-chain.install-script.${f.hook}`,
          category: "vulnerable_dependency",
          severity: f.severity,
          packageName: f.packageName,
          snippet: f.reasons.length > 0 ? f.reasons.join("; ") : `${f.hook} script present`,
          title:
            f.reasons.length > 0
              ? `Suspicious ${f.hook} script: ${f.reasons[0]}`
              : `Project defines a ${f.hook} script (review before trusting CI installs)`,
          metadata: {
            detector: "supply-chain",
            check: "install-script",
            hook: f.hook,
            reasons: f.reasons,
          },
        },
        lineOfFirst(resolved.packageJsonContent, `"${f.hook}"`),
      );
    }
  }

  // 2b. Dependencies' install hooks — only when node_modules is present (see module doc).
  const depHooks = await detectDependencyInstallScriptRisk(
    ctx,
    resolved.packages,
    opts.installScriptProbeLimit,
  );
  for (const f of depHooks) {
    if (f.reasons.length === 0) continue; // only surface DEPENDENCIES' hooks when actually suspicious — a benign postinstall in every transitive dep would be pure noise at scale
    push(
      {
        rule: `supply-chain.dependency-install-script.${f.hook}`,
        category: "vulnerable_dependency",
        severity: f.severity,
        packageName: f.packageName,
        snippet: f.reasons.join("; "),
        title: `Dependency "${f.packageName}" has a suspicious ${f.hook} script: ${f.reasons[0]}`,
        metadata: {
          detector: "supply-chain",
          check: "dependency-install-script",
          hook: f.hook,
          reasons: f.reasons,
        },
      },
      lineFor(f.packageName),
    );
  }

  // 3a. Homoglyph/non-ASCII package names.
  for (const pkg of detectSuspiciousPackageNames(resolved.packages)) {
    push(
      {
        rule: "supply-chain.suspicious-package-name",
        category: "vulnerable_dependency",
        severity: "high",
        packageName: pkg.name,
        snippet: `package name contains non-ASCII/zero-width/bidi-control characters`,
        title: `Suspicious package name (non-ASCII/homoglyph characters): "${pkg.name}"`,
        metadata: { detector: "supply-chain", check: "suspicious-name", package: pkg.name },
      },
      lineFor(pkg.name),
    );
  }

  // 3b. Non-standard registry resolution (package-lock.json only — see doc comment).
  if (resolved.lockfile?.endsWith("package-lock.json")) {
    const content = await ctx.files.read(resolved.lockfile);
    if (content) {
      for (const r of detectSuspiciousRegistryResolution(content)) {
        push(
          {
            rule: "supply-chain.non-standard-registry",
            category: "vulnerable_dependency",
            severity: "high",
            packageName: r.packageName,
            snippet: `resolved from "${r.host}" instead of the standard npm registry`,
            title: `Dependency "${r.packageName}" resolves from a non-standard registry host: ${r.host}`,
            metadata: {
              detector: "supply-chain",
              check: "non-standard-registry",
              package: r.packageName,
              host: r.host,
            },
          },
          lineFor(r.packageName),
        );
      }
    }
  }

  return out;
}
