/**
 * File inventory + language/framework detection (build-plan §5.1, deterministic).
 *
 * Collects the source surface once (fast-glob), parses package.json, locates
 * Prisma schemas / env files, and builds a shared ts-morph Project the route and
 * taint builders reuse. Dependency resolution is skipped — the builders use
 * SYNTACTIC patterns, so node_modules type-loading is neither needed nor wanted.
 */
import { join } from "node:path";
import fg from "fast-glob";
import { Project, ts } from "ts-morph";
import type { Framework, Language } from "@montr/contracts";
import { readRepoFile } from "./workspace.js";

const SOURCE_GLOBS = ["**/*.{ts,tsx,js,jsx,mjs,cjs}"];
const IGNORE = [
  "**/node_modules/**",
  "**/dist/**",
  "**/.next/**",
  "**/build/**",
  "**/coverage/**",
  "**/.git/**",
  "**/.turbo/**",
  "**/out/**",
];

export interface FileInventory {
  dir: string;
  /** Repo-relative source files (ts/tsx/js/jsx/mjs/cjs). */
  sourceFiles: string[];
  /** Repo-relative Prisma schema files. */
  prismaSchemas: string[];
  /** Repo-relative env files (.env, .env.*). */
  envFiles: string[];
  /** Parsed root package.json dependencies (name → version), merged dev+prod. */
  dependencies: Record<string, string>;
  hasNextConfig: boolean;
  hasPackageJson: boolean;
}

const EXT_LANGUAGE: Array<[RegExp, Language]> = [
  [/\.tsx?$/i, "typescript"],
  [/\.(jsx?|mjs|cjs)$/i, "javascript"],
  [/\.py$/i, "python"],
  [/\.java$/i, "java"],
  [/\.go$/i, "go"],
  [/\.rb$/i, "ruby"],
  [/\.php$/i, "php"],
  [/\.cs$/i, "csharp"],
];

/** Collect the file surface deterministically (sorted for stable output). */
export async function collectFiles(dir: string): Promise<FileInventory> {
  const sourceFiles = (
    await fg(SOURCE_GLOBS, { cwd: dir, ignore: IGNORE, dot: false, followSymbolicLinks: false })
  ).sort();
  const prismaSchemas = (
    await fg(["**/*.prisma"], { cwd: dir, ignore: IGNORE, followSymbolicLinks: false })
  ).sort();
  const envFiles = (
    await fg([".env", ".env.*"], {
      cwd: dir,
      ignore: IGNORE,
      dot: true,
      followSymbolicLinks: false,
    })
  ).sort();

  const pkgRaw = await readRepoFile(dir, "package.json");
  let dependencies: Record<string, string> = {};
  let hasPackageJson = false;
  if (pkgRaw) {
    hasPackageJson = true;
    try {
      const pkg = JSON.parse(pkgRaw) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      dependencies = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    } catch {
      /* malformed package.json → treat as no declared deps */
    }
  }

  const nextConfig = await fg(["next.config.{js,mjs,ts,cjs}"], {
    cwd: dir,
    ignore: IGNORE,
    followSymbolicLinks: false,
  });

  return {
    dir,
    sourceFiles,
    prismaSchemas,
    envFiles,
    dependencies,
    hasNextConfig: nextConfig.length > 0,
    hasPackageJson,
  };
}

/** Languages present in the source surface (stable order, deduped). */
export function detectLanguages(sourceFiles: string[]): Language[] {
  const found = new Set<Language>();
  for (const f of sourceFiles) {
    for (const [re, lang] of EXT_LANGUAGE) {
      if (re.test(f)) {
        found.add(lang);
        break;
      }
    }
  }
  const order: Language[] = [
    "typescript",
    "javascript",
    "python",
    "java",
    "go",
    "ruby",
    "php",
    "csharp",
  ];
  return order.filter((l) => found.has(l));
}

/** Frameworks inferred from declared deps + config/schema presence. */
export function detectFrameworks(inv: FileInventory): Framework[] {
  const found = new Set<Framework>();
  const dep = (name: string): boolean =>
    Object.prototype.hasOwnProperty.call(inv.dependencies, name);

  if (dep("next") || inv.hasNextConfig) found.add("nextjs");
  if (dep("react") || dep("react-dom")) found.add("react");
  if (dep("express")) found.add("express");
  if (dep("fastify")) found.add("fastify");
  if (dep("@prisma/client") || dep("prisma") || inv.prismaSchemas.length > 0) found.add("prisma");
  if (dep("django")) found.add("django");
  if (dep("fastapi")) found.add("fastapi");
  if (dep("flask")) found.add("flask");
  if (dep("@nestjs/core") || dep("spring")) found.add("spring");

  // Stable order matching the enum.
  const order: Framework[] = [
    "nextjs",
    "react",
    "express",
    "fastify",
    "node",
    "prisma",
    "django",
    "fastapi",
    "flask",
    "spring",
    "other",
  ];
  return order.filter((f) => found.has(f));
}

/**
 * Build a shared ts-morph Project over the source files. Dependency resolution
 * is disabled (syntactic analysis only) for speed and offline determinism.
 */
export function createProject(dir: string, sourceFiles: string[]): Project {
  const project = new Project({
    useInMemoryFileSystem: false,
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
    skipLoadingLibFiles: true,
    compilerOptions: {
      allowJs: true,
      jsx: ts.JsxEmit.Preserve,
      noLib: true,
      target: ts.ScriptTarget.Latest,
    },
  });
  for (const rel of sourceFiles) {
    // Only TS/JS files carry an AST worth walking.
    if (!/\.(tsx?|jsx?|mjs|cjs)$/i.test(rel)) continue;
    try {
      project.addSourceFileAtPath(join(dir, rel));
    } catch {
      /* unreadable/oversized file → skip, map degrades gracefully */
    }
  }
  return project;
}
