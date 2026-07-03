/**
 * JVM (Spring / JPA) App-Map analyzer — Layer 0 stack breadth.
 *
 * Registered in `../registry.ts`; this directory is the ONLY place JVM stack
 * knowledge lives. It mirrors the TypeScript/Python reference analyzers: detect
 * the stack, parse deterministically with `web-tree-sitter` + the prebuilt
 * `tree-sitter-java` grammar (see {@link parser}), extract the language-agnostic
 * App-Map pieces per file (see {@link extract}), fold in Spring config
 * (datasources + secret surfaces, see {@link config}), and emit one merged
 * {@link AppMapContribution} of frozen `@montr/contracts` shapes.
 *
 * The shared file inventory only globs TS/JS, so this analyzer OWNS its `.java`
 * discovery under `input.dir` (by design — keeps the shared inventory + TS path
 * untouched). NO LLM runs here (golden rule #6); correlation/confirm/fix/report
 * consume the output unchanged (the stack-agnostic invariant).
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import fg from "fast-glob";
import type {
  DataStore,
  Entrypoint,
  EnvSecretSurface,
  Framework,
  OrmModel,
  Route,
  TaintSink,
  TaintSource,
  ThirdPartyCall,
} from "@montr/contracts";
import type { AnalyzerInput, AppMapContribution, LanguageAnalyzer } from "../types.js";
import { parseJava } from "./parser.js";
import { extractFile } from "./extract.js";
import { scanJavaConfig } from "./config.js";

/** Build dirs + VCS noise never worth parsing. */
const JAVA_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/target/**",
  "**/build/**",
  "**/out/**",
  "**/bin/**",
  "**/dist/**",
  "**/.gradle/**",
  "**/.idea/**",
  "**/generated/**",
  "**/generated-sources/**",
];

/** Build manifests that mark a repo as JVM even before any `.java` is found. */
const JAVA_MANIFESTS = [
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "settings.gradle.kts",
];

/** Spring config files feeding the deterministic datasource/secret scan. */
const CONFIG_GLOBS = [
  "**/application*.properties",
  "**/application*.yml",
  "**/application*.yaml",
  "**/bootstrap*.properties",
  "**/bootstrap*.yml",
  "**/bootstrap*.yaml",
];

/** Skip absurdly large generated files. */
const MAX_FILE_BYTES = 1_000_000;

function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}

/** Detected frameworks (stable enum order) from source annotations + manifests. */
function detectFrameworks(usesSpring: boolean, manifestBlob: string): Framework[] {
  const spring =
    usesSpring || /org\.springframework|spring-boot|spring-web|springframework/i.test(manifestBlob);
  return spring ? ["spring"] : [];
}

// --- deterministic dedupe + sort (single-contribution output is returned ------
//     verbatim by the registry merge, so the analyzer sorts its own arrays) ----

function byName<T extends { name: string }>(a: T, b: T): number {
  return a.name.localeCompare(b.name);
}
function byLocation<T extends { location: { file: string; line: number } }>(a: T, b: T): number {
  return a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line;
}

function dedupeByLoc<T extends { kind: string; location: { file: string; line: number } }>(
  arr: T[],
): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of arr) {
    const key = `${x.kind}:${x.location.file}:${x.location.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(x);
  }
  return out;
}

export const javaAnalyzer: LanguageAnalyzer = {
  id: "java",

  detect(input: AnalyzerInput): boolean {
    const opts = { cwd: input.dir, ignore: JAVA_IGNORE, followSymbolicLinks: false, dot: false };
    if (fg.sync(["**/*.java"], opts).length > 0) return true;
    return fg.sync(JAVA_MANIFESTS, { ...opts, deep: 2 }).length > 0;
  },

  async analyze(input: AnalyzerInput): Promise<AppMapContribution> {
    const { dir, signal } = input;

    const files = (
      await fg(["**/*.java"], { cwd: dir, ignore: JAVA_IGNORE, followSymbolicLinks: false })
    ).sort();

    const routes: Route[] = [];
    const entrypoints: Entrypoint[] = [];
    const ormModels: OrmModel[] = [];
    const taintSources: TaintSource[] = [];
    const taintSinks: TaintSink[] = [];
    const envSecretSurfaces: EnvSecretSurface[] = [];
    const thirdPartyCalls: ThirdPartyCall[] = [];
    let usesSpring = false;

    for (const rel of files) {
      if (signal?.aborted) break;
      let source: string;
      try {
        source = await readFile(join(dir, rel), "utf8");
      } catch {
        continue; // unreadable file → map degrades gracefully
      }
      if (source.length > MAX_FILE_BYTES) continue;
      const root = await parseJava(source);
      if (!root) continue;

      const ex = extractFile(root, posix(rel));
      routes.push(...ex.routes);
      entrypoints.push(...ex.entrypoints);
      ormModels.push(...ex.ormModels);
      taintSources.push(...ex.taintSources);
      taintSinks.push(...ex.taintSinks);
      envSecretSurfaces.push(...ex.envSecretSurfaces);
      thirdPartyCalls.push(...ex.thirdPartyCalls);
      usesSpring = usesSpring || ex.usesSpring;
    }

    // Spring config: datasources + secret-looking config surfaces (offline).
    const configFiles = (
      await fg(CONFIG_GLOBS, { cwd: dir, ignore: JAVA_IGNORE, followSymbolicLinks: false })
    ).sort();
    const cfg = await scanJavaConfig(dir, configFiles);
    const dataStores: DataStore[] = cfg.dataStores;
    envSecretSurfaces.push(...cfg.envSecretSurfaces);

    // Link JPA entities to the primary datastore when one was declared.
    const linkedModels: OrmModel[] = cfg.primaryStore
      ? ormModels.map((m) => ({ ...m, dataStore: m.dataStore ?? cfg.primaryStore }))
      : ormModels;

    // Framework detection reads manifests once (deps often name Spring).
    let manifestBlob = "";
    try {
      const manifests = await fg(JAVA_MANIFESTS, {
        cwd: dir,
        ignore: JAVA_IGNORE,
        followSymbolicLinks: false,
        deep: 3,
      });
      const contents = await Promise.all(
        manifests.map((m) => readFile(join(dir, m), "utf8").catch(() => "")),
      );
      manifestBlob = contents.join("\n");
    } catch {
      /* manifests optional */
    }

    // Dedupe + stably sort (registry returns a single contribution verbatim).
    const dedupeRoutes = dedupeByKey(routes, (r) => `${r.method} ${r.path}`).sort((a, b) =>
      a.isApiRoute === b.isApiRoute
        ? a.path.localeCompare(b.path) || a.method.localeCompare(b.method)
        : a.isApiRoute
          ? -1
          : 1,
    );

    return {
      languages: ["java"],
      frameworks: detectFrameworks(usesSpring, manifestBlob),
      entrypoints: dedupeByKey(entrypoints, entrypointKey).sort(byName),
      routes: dedupeRoutes,
      dataStores: [...dataStores].sort(byName),
      ormModels: dedupeByKey(linkedModels, (m) => `${m.name}:${m.file ?? ""}`).sort(byName),
      thirdPartyCalls: dedupeByKey(
        thirdPartyCalls,
        (t) => `${t.kind}:${t.name}:${t.location?.file ?? ""}:${t.location?.line ?? 0}`,
      ).sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name)),
      envSecretSurfaces: dedupeByKey(
        envSecretSurfaces,
        (e) => `${e.name}:${e.location?.file ?? ""}:${e.location?.line ?? 0}`,
      ).sort(byName),
      taintSources: dedupeByLoc(taintSources).sort(byLocation),
      taintSinks: dedupeByLoc(taintSinks).sort(byLocation),
    };
  },
};

/** Stable dedupe preserving first occurrence, keyed by `key`. */
function dedupeByKey<T>(arr: T[], key: (x: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of arr) {
    const k = key(x);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(x);
  }
  return out;
}

function entrypointKey(e: Entrypoint): string {
  return `${e.kind}:${e.name}:${e.location?.file ?? ""}:${e.location?.line ?? 0}`;
}

// Re-export the deterministic builders so `@montr/appmap` keeps exposing them
// (focused reuse + testing) even though they live behind the plugin.
export { parseJava, getJavaParser } from "./parser.js";
export { extractFile, type FileExtraction } from "./extract.js";
export { scanJavaConfig, type ConfigScan } from "./config.js";
