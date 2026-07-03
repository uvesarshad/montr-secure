/**
 * Python (Django / FastAPI / Flask) App-Map analyzer — Layer 0 stack breadth.
 *
 * ⛔ SEAM FOR THE PYTHON STACK AGENT (build-plan §7 Wave 4, PRD §16 Phase 3).
 * Registered in `../registry.ts`; this directory is the ONLY place Python stack
 * knowledge lives. It mirrors the TypeScript reference analyzer: detect the
 * stack, parse deterministically with `web-tree-sitter` + the prebuilt
 * `tree-sitter-python` grammar, and emit the language-agnostic
 * {@link AppMapContribution} (routes, orm_models, third_party, env_surface,
 * taint sources/sinks) — all frozen `@montr/contracts` shapes.
 *
 * The shared file inventory only globs TS/JS, so this analyzer OWNS its `.py`
 * discovery under `input.dir` (by design — keeps the shared inventory + TS path
 * untouched). NO LLM runs here (golden rule #6); correlation/confirm/fix/report
 * consume the output unchanged (the stack-agnostic invariant).
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import fg from "fast-glob";
import type { Framework } from "@montr/contracts";
import type { AnalyzerInput, AppMapContribution, LanguageAnalyzer } from "../types.js";
import { getPythonParser, parseModule, type ParsedModule } from "./parser.js";
import { scanPythonRoutes } from "./routes.js";
import { scanPythonModels } from "./models.js";
import { scanPythonSurfaces } from "./surfaces.js";
import { scanPythonTaint } from "./taint.js";

const PY_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/.venv/**",
  "**/venv/**",
  "**/env/**",
  "**/__pycache__/**",
  "**/site-packages/**",
  "**/.tox/**",
  "**/.mypy_cache/**",
  "**/.pytest_cache/**",
  "**/dist/**",
  "**/build/**",
  "**/.eggs/**",
  "**/migrations/**",
];

const PY_MANIFESTS = [
  "requirements*.txt",
  "pyproject.toml",
  "Pipfile",
  "manage.py",
  "setup.py",
  "setup.cfg",
];

/** Skip absurdly large generated files. */
const MAX_FILE_BYTES = 1_000_000;

function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}

/** Detected frameworks (stable enum order) from source imports + manifests. */
function detectFrameworks(mods: ParsedModule[], manifestBlob: string): Framework[] {
  const found = new Set<Framework>();
  const test = (re: RegExp): boolean =>
    mods.some((m) => re.test(m.source)) || re.test(manifestBlob);

  if (
    test(/\b(?:from|import)\s+django\b/) ||
    test(/\bmodels\.Model\b/) ||
    test(/\burlpatterns\b/) ||
    /(^|\n)\s*django\b/i.test(manifestBlob)
  ) {
    found.add("django");
  }
  if (test(/\b(?:from|import)\s+fastapi\b/) || test(/\bFastAPI\s*\(/) || test(/\bAPIRouter\s*\(/)) {
    found.add("fastapi");
  }
  if (test(/\b(?:from|import)\s+flask\b/) || test(/\bFlask\s*\(/)) {
    found.add("flask");
  }

  const order: Framework[] = ["django", "fastapi", "flask"];
  return order.filter((f) => found.has(f));
}

export const pythonAnalyzer: LanguageAnalyzer = {
  id: "python",

  detect(input: AnalyzerInput): boolean {
    const opts = { cwd: input.dir, ignore: PY_IGNORE, followSymbolicLinks: false, dot: false };
    if (fg.sync(["**/*.py"], opts).length > 0) return true;
    return fg.sync(PY_MANIFESTS, { ...opts, deep: 2 }).length > 0;
  },

  async analyze(input: AnalyzerInput): Promise<AppMapContribution> {
    const { dir, signal } = input;
    const files = (
      await fg(["**/*.py"], { cwd: dir, ignore: PY_IGNORE, followSymbolicLinks: false })
    ).sort();

    const parser = await getPythonParser();
    const mods: ParsedModule[] = [];
    for (const rel of files) {
      if (signal?.aborted) break;
      let source: string;
      try {
        source = await readFile(join(dir, rel), "utf8");
      } catch {
        continue; // unreadable file → map degrades gracefully
      }
      if (source.length > MAX_FILE_BYTES) continue;
      const root = parseModule(parser, source);
      if (!root) continue;
      mods.push({ rel: posix(rel), source, root });
    }

    // Read manifests once for framework detection (deps often name the framework).
    let manifestBlob = "";
    try {
      const manifests = await fg(PY_MANIFESTS, {
        cwd: dir,
        ignore: PY_IGNORE,
        followSymbolicLinks: false,
        deep: 2,
      });
      const contents = await Promise.all(
        manifests.map((m) => readFile(join(dir, m), "utf8").catch(() => "")),
      );
      manifestBlob = contents.join("\n");
    } catch {
      /* manifests optional */
    }

    const routes = scanPythonRoutes(mods);
    const models = scanPythonModels(mods);
    const surfaces = scanPythonSurfaces(mods);
    const taint = scanPythonTaint(mods, routes.routeIdsByFile);

    return {
      languages: ["python"],
      frameworks: detectFrameworks(mods, manifestBlob),
      entrypoints: routes.entrypoints,
      routes: routes.routes,
      dataStores: models.dataStores,
      ormModels: models.ormModels,
      thirdPartyCalls: surfaces.thirdPartyCalls,
      envSecretSurfaces: surfaces.envSecretSurfaces,
      taintSources: taint.taintSources,
      taintSinks: taint.taintSinks,
    };
  },
};
