/**
 * Language-analyzer registry + dispatcher (Layer 0).
 *
 * `buildAppMap` calls {@link buildDeterministicPieces}: it detects which stacks
 * a repo contains, runs every matching {@link LanguageAnalyzer} concurrently,
 * and MERGES their language-agnostic contributions into one set of App-Map
 * pieces. Adding a stack = append its analyzer to {@link LANGUAGE_ANALYZERS};
 * the dispatcher, `buildAppMap`, and every downstream layer stay untouched.
 *
 * ⛔ Fail-safe: an analyzer that throws is logged and contributes nothing rather
 * than failing the whole scan (a partial map still feeds correlation).
 */
import type { Framework, Language } from "@montr/contracts";
import { typescriptAnalyzer } from "./typescript/index.js";
import { pythonAnalyzer } from "./python/index.js";
import { javaAnalyzer } from "./java/index.js";
import { emptyContribution } from "./types.js";
import type { AnalyzerInput, AppMapContribution, LanguageAnalyzer } from "./types.js";

/**
 * Registered stack analyzers, in a stable, deterministic order. TypeScript,
 * Python, and JVM are all fully implemented (build-plan §7 Wave 4) — each
 * uses real `web-tree-sitter` WASM parsing (not regex) under `languages/<lang>/`.
 * A future stack is added by appending its analyzer here.
 */
export const LANGUAGE_ANALYZERS: readonly LanguageAnalyzer[] = [
  typescriptAnalyzer,
  pythonAnalyzer,
  javaAnalyzer,
];

/** Canonical language order for deterministic merged output (mirrors the enum). */
const LANGUAGE_ORDER: readonly Language[] = [
  "typescript",
  "javascript",
  "python",
  "java",
  "go",
  "ruby",
  "php",
  "csharp",
  "other",
];

/** Canonical framework order for deterministic merged output (mirrors the enum). */
const FRAMEWORK_ORDER: readonly Framework[] = [
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

function uniqueInOrder<T>(values: T[], order: readonly T[]): T[] {
  const present = new Set(values);
  return order.filter((v) => present.has(v));
}

const byName = (a: { name: string }, b: { name: string }): number => a.name.localeCompare(b.name);
const byLocation = (
  a: { location: { file: string; line: number } },
  b: { location: { file: string; line: number } },
): number => a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line;

/**
 * Merge several language contributions into one. A SINGLE contribution (the
 * common single-stack case, incl. every Phase-1 repo) is returned verbatim, so
 * the merged output is byte-identical to the analyzer's own stably-sorted
 * output. When several stacks run, arrays are concatenated and re-sorted with
 * the same comparators the builders use, and languages/frameworks are unioned in
 * canonical order.
 */
export function mergeContributions(contributions: AppMapContribution[]): AppMapContribution {
  if (contributions.length === 0) return emptyContribution();
  if (contributions.length === 1) return contributions[0]!;

  const merged = emptyContribution();
  for (const c of contributions) {
    merged.entrypoints.push(...c.entrypoints);
    merged.routes.push(...c.routes);
    merged.dataStores.push(...c.dataStores);
    merged.ormModels.push(...c.ormModels);
    merged.thirdPartyCalls.push(...c.thirdPartyCalls);
    merged.envSecretSurfaces.push(...c.envSecretSurfaces);
    merged.taintSources.push(...c.taintSources);
    merged.taintSinks.push(...c.taintSinks);
    merged.languages.push(...c.languages);
    merged.frameworks.push(...c.frameworks);
  }

  merged.routes.sort((a, b) =>
    a.isApiRoute === b.isApiRoute
      ? a.path.localeCompare(b.path) || a.method.localeCompare(b.method)
      : a.isApiRoute
        ? -1
        : 1,
  );
  merged.entrypoints.sort(byName);
  merged.dataStores.sort(byName);
  merged.ormModels.sort(byName);
  merged.thirdPartyCalls.sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name),
  );
  merged.envSecretSurfaces.sort(byName);
  merged.taintSources.sort(byLocation);
  merged.taintSinks.sort(byLocation);

  return {
    ...merged,
    languages: uniqueInOrder(merged.languages, LANGUAGE_ORDER),
    frameworks: uniqueInOrder(merged.frameworks, FRAMEWORK_ORDER),
  };
}

/**
 * Detect the stacks present, run their analyzers concurrently, and merge the
 * results. `analyzers` is injectable for focused tests; production uses
 * {@link LANGUAGE_ANALYZERS}.
 */
export async function buildDeterministicPieces(
  input: AnalyzerInput,
  analyzers: readonly LanguageAnalyzer[] = LANGUAGE_ANALYZERS,
): Promise<AppMapContribution> {
  const active = analyzers.filter((a) => {
    try {
      return a.detect(input);
    } catch (err) {
      input.logger.warn("appmap.analyzer.detect_failed", {
        analyzer: a.id,
        message: err instanceof Error ? err.message : "unknown",
      });
      return false;
    }
  });

  const contributions = await Promise.all(
    active.map(async (a): Promise<AppMapContribution> => {
      try {
        return await a.analyze(input);
      } catch (err) {
        input.logger.warn("appmap.analyzer.failed", {
          analyzer: a.id,
          message: err instanceof Error ? err.message : "unknown",
        });
        return emptyContribution();
      }
    }),
  );

  return mergeContributions(contributions);
}
