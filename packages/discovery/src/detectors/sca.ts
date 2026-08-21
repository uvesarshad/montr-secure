/**
 * Dependency / SCA agent (§5.2). Resolves the installed dependency set from the
 * lockfile (pnpm-lock.yaml / package-lock.json) or, failing that, package.json,
 * matches each package against the OFFLINE advisory mirror, and — critically —
 * runs a REACHABILITY check. Reachability is tagged on every candidate so
 * Layer 2 can promote reachable vulns and demote merely-present ones (§7 L2).
 * No network.
 *
 * A12: on TypeScript/JavaScript (the only ecosystem this detector currently
 * resolves — see the ecosystem note below), reachability is CALL-granularity,
 * not package-granularity: a real ts-morph AST scan (`collectCalledPackages`)
 * checks whether a binding imported from the vulnerable package is actually
 * INVOKED anywhere, not merely present in an `import`/`require` statement.
 * `collectImportedPackages`'s plain import-presence regex scan is kept as a
 * fallback for the (rare) case nothing could be parsed as TS/JS at all — see
 * that function's doc comment for exactly what the call-site check does and
 * does not resolve, and why it is not full interprocedural call-graph
 * reachability.
 */
import nodePath from "node:path";
import { Node, Project, SyntaxKind, ts, type SourceFile } from "ts-morph";
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

// --- call-site reachability (A12, TypeScript/JavaScript only) --------------
//
// `collectImportedPackages` above answers "was this package's name mentioned
// in an import/require specifier anywhere?" — PACKAGE-granularity presence. A
// package imported once and never actually used still counts as reachable
// there. PRD §7 Layer 1 promises "is the vulnerable path actually
// imported/called?", which needs a stronger, CALL-granularity signal: was a
// binding that import introduced actually INVOKED (called, constructed with
// `new`, or rendered as a JSX component) anywhere — as opposed to imported
// and left unused, imported only for its type, or merely re-exported.
//
// This is a real ts-morph AST call-site scan (not a regex), and it is a
// meaningfully stronger signal than plain import presence. It is deliberately
// NOT full interprocedural call-graph reachability from an HTTP entry point:
// it does not trace through intermediate helper functions, so
// `helper(lib.get)` (passing the bound export on without calling it) or
// `lib.get` reaching a sink two functions later would both read as "not
// called" here even though a deeper analysis might find a real path.
//
// Why not reuse the project's real call graph? Because there isn't one that
// can answer this. `packages/appmap/src/languages/typescript/callgraph.ts`
// (`scanTaintFlows`) is the one real interprocedural resolver in this
// codebase, but it is a narrow 1-2 hop taint SOURCE→SINK chain over
// *relative* (`./`, `../`) imports only — its own module doc states plainly
// that bare/package specifiers (npm imports, i.e. exactly what SCA
// reachability needs) are "out of scope, by design". `AppMap.thirdPartyCalls`
// (`packages/appmap/src/languages/typescript/surfaces.ts`) is also no
// stronger than the regex scan above: it records the same
// import-declaration-present signal, not call-site usage. So while Layer 1
// DOES receive the App Map before it runs (see `apps/worker/src/runners.ts`
// — `layer1` resolves `ctx.priorOutputs.layer0.appMap` the same way `layer2`
// does), there is no existing App-Map artifact this function can borrow;
// building genuine entry-point-to-package-export call-graph reachability
// would mean building new call-graph infrastructure for npm packages, which
// is out of this task's scope (tracked separately — see A21/E1 in
// docs/plan/26-08-22-audit-ai-depth.md). This function is the best
// improvement achievable within Layer 1's own existing scope.
//
// Scope: TypeScript/JavaScript only — the only stack with a syntactic AST
// this cheaply available, and (today) the only ecosystem this detector
// actually resolves dependencies for in the first place (lockfile/package.json
// parsing above is npm-specific; `matchAdvisories` below defaults to the
// "npm" ecosystem). If this detector is ever extended to PyPI/Maven
// manifests, THEIR reachability must not silently inherit this call-level
// claim until they get their own analysis.

/** Local-identifier -> bare-package-name bindings introduced by imports/`require` in one file. */
function collectImportBindings(sf: SourceFile): Map<string, string> {
  const bindings = new Map<string, string>();
  const add = (local: string | undefined, pkg: string | null): void => {
    if (local && pkg) bindings.set(local, pkg);
  };

  for (const imp of sf.getImportDeclarations()) {
    if (imp.isTypeOnly()) continue; // `import type { X } from "pkg"` can never be a call site.
    const pkg = barePackageName(imp.getModuleSpecifierValue());
    if (!pkg) continue;
    const def = imp.getDefaultImport();
    if (def) add(def.getText(), pkg);
    const ns = imp.getNamespaceImport();
    if (ns) add(ns.getText(), pkg);
    for (const named of imp.getNamedImports()) {
      if (named.isTypeOnly()) continue;
      add(named.getAliasNode()?.getText() ?? named.getNameNode().getText(), pkg);
    }
  }

  // CommonJS: `const x = require("pkg")` / `const { a } = require("pkg")`.
  for (const vs of sf.getVariableStatements()) {
    for (const decl of vs.getDeclarations()) {
      const init = decl.getInitializer();
      if (!init || !Node.isCallExpression(init)) continue;
      if (init.getExpression().getText() !== "require") continue;
      const arg = init.getArguments()[0];
      if (!arg || !Node.isStringLiteral(arg)) continue;
      const pkg = barePackageName(arg.getLiteralText());
      if (!pkg) continue;
      const nameNode = decl.getNameNode();
      if (Node.isIdentifier(nameNode)) {
        add(nameNode.getText(), pkg);
      } else if (Node.isObjectBindingPattern(nameNode)) {
        for (const el of nameNode.getElements()) {
          const elName = el.getNameNode();
          if (Node.isIdentifier(elName)) add(elName.getText(), pkg);
        }
      }
    }
  }

  return bindings;
}

/** The base identifier of a (possibly chained) member-access expression: `a.b.c` -> `a`. */
function leftmostIdentifier(expr: Node): string | undefined {
  let cur: Node = expr;
  while (Node.isPropertyAccessExpression(cur) || Node.isElementAccessExpression(cur)) {
    cur = cur.getExpression();
  }
  return Node.isIdentifier(cur) ? cur.getText() : undefined;
}

/** Which of `bindings`' packages are actually invoked (call/`new`/JSX) in `sf`. */
function scanCalledPackages(sf: SourceFile, bindings: ReadonlyMap<string, string>): Set<string> {
  const called = new Set<string>();
  const mark = (name: string | undefined): void => {
    if (!name) return;
    const pkg = bindings.get(name);
    if (pkg) called.add(pkg);
  };
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    mark(leftmostIdentifier(call.getExpression()));
  }
  for (const ctor of sf.getDescendantsOfKind(SyntaxKind.NewExpression)) {
    mark(leftmostIdentifier(ctor.getExpression()));
  }
  for (const jsx of sf.getDescendantsOfKind(SyntaxKind.JsxSelfClosingElement)) {
    mark(leftmostIdentifier(jsx.getTagNameNode()));
  }
  for (const jsx of sf.getDescendantsOfKind(SyntaxKind.JsxOpeningElement)) {
    mark(leftmostIdentifier(jsx.getTagNameNode()));
  }
  return called;
}

export interface CallSiteReachability {
  /** True when at least one TS/JS source file was found and parsed — i.e. this
   * signal is trustworthy and `imported`-only fallback should NOT be used. */
  analyzed: boolean;
  /** Bare package names with a real call/`new`/JSX-render site somewhere in the repo. */
  called: Set<string>;
}

/**
 * Real (ts-morph AST, not regex) call-site scan: which imported/`require`d
 * npm packages are actually INVOKED anywhere in the TS/JS source, as opposed
 * to merely imported. See the module doc comment above for exactly what this
 * does and does not resolve.
 */
export async function collectCalledPackages(files: FileProvider): Promise<CallSiteReachability> {
  const sources = await readAll(files, isSourceFile);
  if (sources.length === 0) return { analyzed: false, called: new Set() };

  const project = new Project({
    useInMemoryFileSystem: true,
    skipFileDependencyResolution: true,
    skipLoadingLibFiles: true,
    compilerOptions: {
      allowJs: true,
      jsx: ts.JsxEmit.Preserve,
      noLib: true,
      target: ts.ScriptTarget.Latest,
    },
  });
  let added = 0;
  for (const file of sources) {
    try {
      project.createSourceFile(file.path, file.content, { overwrite: true });
      added++;
    } catch {
      /* unparsable/oversized file -> skip; other files still contribute */
    }
  }
  if (added === 0) return { analyzed: false, called: new Set() };

  const called = new Set<string>();
  for (const sf of project.getSourceFiles()) {
    const bindings = collectImportBindings(sf);
    if (bindings.size === 0) continue;
    for (const pkg of scanCalledPackages(sf, bindings)) called.add(pkg);
  }
  return { analyzed: true, called };
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
  // A12: prefer real call-site reachability over plain import presence. Falls
  // back to `imported` only when nothing could be parsed as TS/JS at all (a
  // non-analyzable stack), so this detector never regresses to a WEAKER
  // signal than it had before — see the doc comment on
  // `collectCalledPackages` for exactly what this does and does not resolve.
  const callSites = await collectCalledPackages(ctx.files);
  const locFile = resolved.packageJsonPath ?? resolved.lockfile ?? "package.json";

  const out: CandidateFinding[] = [];
  for (const pkg of resolved.packages) {
    for (const adv of matchAdvisories(pkg.name, pkg.version, db)) {
      const reachable = callSites.analyzed
        ? callSites.called.has(pkg.name)
        : imported.has(pkg.name);
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
            // (or imported-but-never-called; see `collectCalledPackages`, A12)
            // vuln is demoted, not headlined.
            reachable,
          },
        }),
      );
    }
  }
  return out;
}
