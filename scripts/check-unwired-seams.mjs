#!/usr/bin/env node
/**
 * CI check: catch "built, tested, but structurally unreachable in production"
 * code — the dominant defect class identified by docs/plan/26-08-22-audit-ai-depth.md
 * (A10) and re-confirmed by docs/plan/26-09-12-tasks-red-blue-agentic-posture.md's
 * "unwired seams" enhancement. Two complementary mechanisms:
 *
 * PART 1 — hand-declared seams (SEAMS / KNOWN_UNWIRED below). A short, curated
 * list of specific exported symbols with a written reason they matter, checked
 * by a simple fixed-string grep. Good for giving a human-readable "why this
 * symbol is load-bearing" next to the enforcement, but only as strong as
 * whoever remembered to add an entry — it went years without ever catching a
 * regression to "unwired" because nobody had to add a NEW export here for the
 * check to notice it.
 *
 * PART 2 — structural reachability check (checkStructuralReachability below).
 * Doesn't rely on anyone remembering to declare anything. It builds a
 * file-level import graph across the whole workspace (every `import`,
 * re-export, and dynamic `import()`, resolved through the same `@montr/*` ->
 * `packages/*\/src/index.ts` mapping vitest.config.ts's own aliases use), takes
 * every real production entrypoint as a root (every file under `apps/*\/src`,
 * every package's published `bin` CLI entry, every root `scripts/*.mjs`), and
 * walks forward from those roots. Any file under `packages/*\/src` the walk
 * never reaches is, by construction, a module with NO path to anything that
 * actually runs in production — not "nobody grepped for its name today" but
 * "there is no import chain into it from anywhere real." For each such file
 * it lists the exported functions/classes it defines, since those are the
 * concrete "seams" this whole audit cycle is about.
 *
 * Granularity is deliberately at the FILE level, not the individual-export
 * level: if file A is reached, every export A defines is treated as reached,
 * even if only one of several exports is actually used. This trades some
 * recall (a genuinely-dead sibling export in an otherwise-live file won't be
 * flagged) for much higher precision (a helper that's legitimately used by a
 * neighboring function in the same live file is never a false positive). Per
 * this task's own framing, a false-positive-prone checker gets disabled and
 * is worse than no checker — so PART 2 is deliberately conservative:
 *   - type-only imports/exports never count as a reachability edge (a module
 *     imported only for its types has zero runtime call path, so a function
 *     it also happens to export is correctly still flagged);
 *   - test files (`*.test.ts(x)`, `*.spec.ts(x)`) and known test-only helper
 *     modules (`testkit.ts`, `test-helpers.ts`) are excluded from both the
 *     root set and the findings set;
 *   - packages that are deliberately test-only infrastructure (never a
 *     runtime `dependencies` entry of any app — see STRUCTURAL_EXCLUDED_PACKAGES)
 *     are excluded wholesale, with the reason written down;
 *   - specific files that are a deliberate, judgment-call exception are
 *     listed in STRUCTURAL_ALLOWLIST (excluded, reason required) or
 *     STRUCTURAL_KNOWN_UNWIRED (still printed, but informational — mirrors
 *     the PART 1 KNOWN_UNWIRED convention) rather than silently dropped.
 *
 * Usage: node scripts/check-unwired-seams.mjs
 * Exit code: 0 = every hand-declared seam has a qualifying caller AND every
 * packages/*\/src file is reachable from a real production entrypoint (or is
 * an explicitly documented exception); 1 = otherwise (or the tooling itself
 * failed).
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

const root = fileURLToPath(new URL("..", import.meta.url));

/* ============================================================================
 * PART 1 — hand-declared seams (legacy mechanism, kept for the human-readable
 * "why". Reconciled against PART 2 below: any pattern PART 2 also catches
 * structurally is noted as redundant-by-design rather than being the only
 * thing catching it. Entries that were unwired but have SINCE been wired up
 * by this session's work were removed rather than left stale (A15's point).
 * ============================================================================
 */

/**
 * `pattern` is matched as a FIXED STRING (grep -F) across every non-test
 * `.ts`/`.tsx` file under apps/ and packages/, excluding node_modules, dist,
 * and .turbo output.
 *
 * `definedIn` is the package whose OWN internal usage doesn't count as
 * "wired" (a seam only called by its own plumbing isn't reaching production)
 * — UNLESS `allowSelfPackage` is set, for helpers that are legitimately only
 * ever called by another exported function in the same file/package (e.g.
 * `resolveFieldEncryptionKey` calling `createKeySource` internally).
 *
 * Every pattern below also has a same-named export reachable structurally
 * via PART 2 (they all live in a package's public `src/index.ts` surface),
 * so PART 2 would independently catch a regression to "unwired" for all of
 * them too. They stay declared here anyway because the one-line `name` field
 * carries WHY each symbol matters (the specific audit finding, the specific
 * production risk) — context PART 2's generic file-reachability walk has no
 * way to express.
 */
const SEAMS = [
  {
    name: "packages/config: resolveFieldEncryptionKey() — pluggable env/file/Vault key source (A10)",
    pattern: "resolveFieldEncryptionKey(",
    definedIn: "packages/config",
  },
  {
    name: "packages/config: createKeySource() — pluggable env/file/Vault key source (A10)",
    pattern: "createKeySource(",
    definedIn: "packages/config",
    allowSelfPackage: true,
  },
  {
    name: "packages/llm-gateway: gateway.resolvePrompt(...) — DB-versioned prompt registry (A10)",
    pattern: ".resolvePrompt?.(",
    definedIn: "packages/llm-gateway",
  },
  {
    name: "packages/llm-gateway: createLlmGateway() — the one BYO-key LLM egress factory",
    pattern: "createLlmGateway(",
    definedIn: "packages/llm-gateway",
  },
  {
    name: "packages/cost-meter: createBudgetRegistry() — pre-call + real-time budget guard (A2/A32)",
    pattern: "createBudgetRegistry(",
    definedIn: "packages/cost-meter",
  },
  {
    name: "packages/state-store: store.falsePositiveMarks — §15 FP-feedback tuning loop (A10)",
    pattern: "falsePositiveMarks",
    definedIn: "packages/state-store",
  },
  {
    name: "packages/llm-gateway: createEmbeddingAdapter() — embeddings capability for the semantic codebase index (A9)",
    pattern: "createEmbeddingAdapter(",
    definedIn: "packages/llm-gateway",
  },
  {
    name: "packages/semantic-index: buildSemanticIndex() — AST-chunked pgvector code index, built alongside Layer 0's App Map (A9)",
    pattern: "buildSemanticIndex(",
    definedIn: "packages/semantic-index",
  },
  {
    name: "packages/semantic-index: querySemanticIndex() — semantic retrieval consumed by Layer 2 correlation + Layer 3 confirmation (A9)",
    pattern: "querySemanticIndex(",
    definedIn: "packages/semantic-index",
  },
  {
    name: "packages/llm-gateway: gateway.stream() — Layer 3's agentic investigation loop drives its tool-calling turns off it, streaming a live narrative into emitProgress (A14)",
    pattern: "llm.stream(request)",
    definedIn: "packages/llm-gateway",
  },
];

/**
 * Seams that are REAL, TESTED, working code but are a deliberate judgment
 * call to leave unconsumed by any pipeline layer for now (documented, not
 * silently dropped). Printed as informational only — never fails the build.
 * Revisit if a layer gains a genuine streaming consumer (a console/UI
 * surface, or a multi-turn agent loop per the audit's enhancement E10).
 *
 * NOTE: this specific case is a METHOD on an already-reached file/interface
 * (packages/llm-gateway/src/gateway.ts, `LLMGateway.stream`), not a whole
 * unreached FILE — PART 2's file-level structural check cannot see this kind
 * of finding by construction (see the granularity trade-off documented
 * above), so it has to stay a hand-maintained entry.
 */
// A14 (2026-09-12): gateway.stream() gained a real production consumer —
// packages/confirm/src/investigate.ts's agentic investigation loop — and
// moved from here into the enforced SEAMS list above, mirroring A9's
// createEmbeddingAdapter()/buildSemanticIndex()/querySemanticIndex()
// precedent for a seam that goes from "known, judgment-call unwired" to
// "real and enforced" once a genuine caller lands.
const KNOWN_UNWIRED = [];

function grepFiles(pattern) {
  try {
    const out = execFileSync(
      "grep",
      [
        "-rl",
        "-F",
        "--include=*.ts",
        "--include=*.tsx",
        "--exclude=*.test.ts",
        "--exclude-dir=node_modules",
        "--exclude-dir=dist",
        "--exclude-dir=.turbo",
        pattern,
        "apps",
        "packages",
      ],
      { cwd: root, encoding: "utf8" },
    );
    return out.split("\n").filter(Boolean);
  } catch (err) {
    // grep exits 1 (not an error) when there are simply no matches.
    if (err.status === 1) return [];
    throw err;
  }
}

function checkSeam(seam) {
  const matches = grepFiles(seam.pattern);
  const qualifying = seam.allowSelfPackage
    ? matches
    : matches.filter((f) => !f.startsWith(`${seam.definedIn}/`));
  return { seam, matches, qualifying, ok: qualifying.length > 0 };
}

/* ============================================================================
 * PART 2 — structural file-reachability check
 * ============================================================================
 */

// Packages that are deliberately test-only infrastructure: never listed as a
// runtime `dependencies` entry of any app (workspace devDependency only, or
// unreferenced outside test files), so having zero production caller is
// correct BY DESIGN, not a gap. Verified by hand at the time each was added:
const STRUCTURAL_EXCLUDED_PACKAGES = {
  fixtures:
    "Sample scan/finding/report objects for tests only. @montr/fixtures is a " +
    "devDependency (never `dependencies`) everywhere it appears, and its only " +
    "non-test-file reference is apps/worker/src/testkit.ts, itself a test-only " +
    "helper module — confirmed by hand 2026-09-12.",
};

// Specific FILES that are a deliberate, judgment-call exception to the
// structural check: real, working code with no current production caller,
// but excluded (not just informationally listed) for the stated reason.
// Empty today — populate with {file, reason} if a genuine, justified case
// shows up in a future run.
const STRUCTURAL_ALLOWLIST = [];

// Files the structural check finds genuinely unreached from any production
// entrypoint, but that are a deliberate, documented judgment call rather
// than a bug to fix right now — printed, never fails the build. Mirrors the
// PART 1 KNOWN_UNWIRED convention. Populate as {file, reason}.
//
// The five entries below were discovered by this structural check's FIRST
// real run (2026-09-12, the same day it was built) — all five are genuinely
// pre-existing gaps, NOT introduced by the red/blue agentic-posture audit's
// 32-item task list this session closed out. Declared here honestly rather
// than silently reproducing the exact "built, tested, no production caller"
// failure mode this whole audit was about — each needs a real follow-up
// task, not a shrug.
const STRUCTURAL_KNOWN_UNWIRED = [
  {
    file: "packages/qa/src/index.ts",
    reason:
      "runQaSuite() is a small orphaned convenience wrapper around the qa suite; " +
      "packages/qa/src/cli.ts's real handler does the equivalent work via its own, " +
      "not-quite-identical code path rather than calling this. Follow-up: either " +
      "rewire cli.ts to call runQaSuite() directly, or delete it if the duplication " +
      "is intentional and this is genuinely dead.",
  },
  {
    file: "packages/qa/src/layer-metrics.ts",
    reason:
      "computePipelineMetrics() has zero test coverage and zero caller — the most " +
      "clear-cut unwired case found. Follow-up: determine whether this was meant to " +
      "feed a per-layer cost/latency report and wire it in, or remove it.",
  },
  {
    file: "packages/qa/src/prompt-eval.ts",
    reason:
      "scorePromptQuality/promptMeetsRubric/PromptEvalGateway/evaluatePromptCandidate " +
      "are fully unit-tested but have no production caller — a self-contained prompt- " +
      "quality evaluation harness never wired into any CI gate or CLI command. Follow-up: " +
      "wire into a real prompt-regression CI step (mirroring the golden-corpus/blue-team- " +
      "corpus/detection-coverage gate pattern) or into qa's CLI as a standalone command.",
  },
  {
    file: "packages/qa/src/real-mode.ts",
    reason:
      "gradeScanResults/gradeCorpus are fully unit-tested but have no production caller. " +
      "Follow-up: determine the intended real-mode grading entrypoint (likely a CLI " +
      "command or CI step parallel to corpus-scan.mjs) and wire it in.",
  },
  {
    file: "packages/qa/src/regression-corpus.ts",
    reason:
      "The §15 false-positive regression-corpus sink (InMemoryRegressionCorpus/" +
      "FileRegressionCorpus/corpusRecorder/buildFalsePositiveTuning and friends) has no " +
      "production caller — apps/api/src/fp-corpus.ts's own header comment claims " +
      "'production wires this' but no file in apps/*/src actually imports from " +
      "regression-corpus.ts. This is a real, potentially higher-priority gap (the FP- " +
      "tuning loop's corpus persistence layer may be silently inert in production) that " +
      "deserves its own dedicated investigation, not a quick fix bundled into an unrelated " +
      "checker-improvement task.",
  },
];

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx"]);
const TEST_FILE_RE = /\.(test|spec)\.[cm]?[jt]sx?$/;
const TEST_HELPER_NAME_RE = /(^|\/)(testkit|test-helpers?)\.[cm]?[jt]sx?$/;

function isTestFile(relPath) {
  return TEST_FILE_RE.test(relPath) || TEST_HELPER_NAME_RE.test(relPath);
}

function walkDir(absDir, out) {
  let entries;
  try {
    entries = readdirSync(absDir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".turbo") continue;
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) {
      walkDir(abs, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (SOURCE_EXTENSIONS.has(ext) || ext === ".mjs") out.push(abs);
    }
  }
  return out;
}

/** name -> { dir, indexFile } for every packages/* workspace package. */
function loadPackageIndexMap() {
  const map = new Map();
  const pkgsDir = path.join(root, "packages");
  for (const entry of readdirSync(pkgsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(pkgsDir, entry.name);
    const pkgJsonPath = path.join(dir, "package.json");
    let name;
    try {
      name = JSON.parse(readFileSync(pkgJsonPath, "utf8")).name;
    } catch {
      continue;
    }
    if (!name) continue;
    const indexFile = path.join(dir, "src", "index.ts");
    map.set(name, { dir, indexFile });
  }
  return map;
}

function scriptKindFor(absPath) {
  if (absPath.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (absPath.endsWith(".mjs") || absPath.endsWith(".js")) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/**
 * Whether an import/export clause pulls in a runtime VALUE (creates a real
 * reachability edge) as opposed to being entirely type-only (creates none —
 * see the granularity note in the header comment for why this matters).
 */
function isValueBearingClause(node) {
  // `import type X from "./y"` / `export type { X } from "./y"`
  if (node.isTypeOnly) return false;
  const namedBindings = node.namedBindings ?? node.exportClause;
  if (namedBindings && ts.isNamedImports(namedBindings)) {
    const hasDefaultOrNamespace = !!node.name; // `import Foo, {...} from ...`
    const allSpecifiersTypeOnly = namedBindings.elements.every((el) => el.isTypeOnly);
    if (!hasDefaultOrNamespace && allSpecifiersTypeOnly && namedBindings.elements.length > 0) {
      return false;
    }
  }
  if (namedBindings && ts.isNamedExports(namedBindings)) {
    const allSpecifiersTypeOnly = namedBindings.elements.every((el) => el.isTypeOnly);
    if (allSpecifiersTypeOnly && namedBindings.elements.length > 0) return false;
  }
  return true;
}

/** Parses one file for {imports: string[], exports: {name, kind}[]}. */
function parseFile(absPath) {
  let text;
  try {
    text = readFileSync(absPath, "utf8");
  } catch {
    return { imports: [], exports: [] };
  }
  const sf = ts.createSourceFile(
    absPath,
    text,
    ts.ScriptTarget.Latest,
    true,
    scriptKindFor(absPath),
  );

  const imports = [];
  const exports = [];

  function visit(node) {
    if (
      ts.isImportDeclaration(node) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const clause = node.importClause;
      const valueBearing = !clause || isValueBearingClause(clause);
      if (valueBearing) imports.push(node.moduleSpecifier.text);
    } else if (
      ts.isExportDeclaration(node) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const valueBearing = isValueBearingClause(node);
      if (valueBearing) imports.push(node.moduleSpecifier.text);
    } else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments[0] &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      imports.push(node.arguments[0].text);
    }

    // Top-level export inventory (function/class/const-arrow-or-function).
    if (node.parent === sf) {
      const hasExportModifier = (n) =>
        ts.canHaveModifiers(n) &&
        ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

      if (ts.isFunctionDeclaration(node) && node.name && hasExportModifier(node)) {
        exports.push({ name: node.name.text, kind: "function" });
      } else if (ts.isClassDeclaration(node) && node.name && hasExportModifier(node)) {
        exports.push({ name: node.name.text, kind: "class" });
      } else if (ts.isVariableStatement(node) && hasExportModifier(node)) {
        for (const decl of node.declarationList.declarations) {
          if (
            ts.isIdentifier(decl.name) &&
            decl.initializer &&
            (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))
          ) {
            exports.push({ name: decl.name.text, kind: "function (const)" });
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  }
  visit(sf);
  return { imports, exports };
}

function resolveRelative(fromFile, spec) {
  let target = path.resolve(path.dirname(fromFile), spec);
  const candidates = [];
  if (target.endsWith(".js"))
    candidates.push(target.slice(0, -3) + ".ts", target.slice(0, -3) + ".tsx");
  else if (target.endsWith(".jsx")) candidates.push(target.slice(0, -4) + ".tsx");
  else {
    candidates.push(
      target,
      `${target}.ts`,
      `${target}.tsx`,
      path.join(target, "index.ts"),
      path.join(target, "index.tsx"),
    );
  }
  for (const c of candidates) {
    try {
      if (statSync(c).isFile()) return c;
    } catch {
      /* try next candidate */
    }
  }
  return undefined;
}

function resolveSpecifier(fromFile, spec, pkgIndexMap) {
  if (spec.startsWith(".")) return resolveRelative(fromFile, spec);
  if (spec.startsWith("@montr/")) {
    const exact = pkgIndexMap.get(spec);
    if (exact) return exact.indexFile;
    // Subpath import, e.g. "@montr/foo/bar" -> packages/foo/src/bar.ts
    for (const [name, info] of pkgIndexMap) {
      if (spec.startsWith(`${name}/`)) {
        const subpath = spec.slice(name.length + 1);
        return resolveRelative(path.join(info.dir, "src", "PLACEHOLDER.ts"), `./${subpath}`);
      }
    }
  }
  return undefined; // external package / node builtin — not a workspace edge
}

function relFromRoot(absPath) {
  return path.relative(root, absPath).split(path.sep).join("/");
}

function collectRoots() {
  const roots = [];
  for (const app of ["api", "cli", "web", "worker"]) {
    const appSrc = path.join(root, "apps", app, "src");
    for (const f of walkDir(appSrc, [])) {
      if (SOURCE_EXTENSIONS.has(path.extname(f)) && !isTestFile(relFromRoot(f))) roots.push(f);
    }
  }
  // Published CLI bin entrypoints — real, directly-executed production
  // entrypoints, not reached via any `import`, so they must be explicit
  // graph roots too (see each package.json's "bin" field).
  const binSources = [
    "packages/qa/src/cli.ts",
    "packages/qa/src/owasp-benchmark-cli.ts",
    "packages/qa/src/blue-team-cli.ts",
    "packages/qa/src/detection-coverage-cli.ts",
    "packages/security/src/audit-verify-cli.ts",
  ];
  for (const rel of binSources) {
    const abs = path.join(root, rel);
    try {
      if (statSync(abs).isFile()) roots.push(abs);
    } catch {
      /* bin entry renamed/removed — ignore, nothing to root */
    }
  }
  // Root-level automation scripts: real, executable entrypoints invoked by
  // `pnpm run <script>` and wired into CI (corpus/blue-team/benchmark gates),
  // not test files. Deliberately treated as production-adjacent roots — see
  // header comment: excluding these would false-flag real, running,
  // CI-gating tooling (e.g. packages/qa/src/corpus.ts) as "unwired".
  const scriptsDir = path.join(root, "scripts");
  for (const f of readdirSync(scriptsDir)) {
    if (f.endsWith(".mjs") && !f.includes(".vitest.config") && !f.includes(".run.test")) {
      roots.push(path.join(scriptsDir, f));
    }
  }
  return roots;
}

function collectAllWorkspaceFiles() {
  const files = [];
  for (const app of ["api", "cli", "web", "worker"]) {
    walkDir(path.join(root, "apps", app, "src"), files);
  }
  for (const f of walkDir(path.join(root, "packages"), [])) files.push(f);
  const scriptsDir = path.join(root, "scripts");
  for (const f of readdirSync(scriptsDir)) {
    if (f.endsWith(".mjs")) files.push(path.join(scriptsDir, f));
  }
  return files;
}

function checkStructuralReachability() {
  const pkgIndexMap = loadPackageIndexMap();
  const allFiles = collectAllWorkspaceFiles();
  const parsed = new Map(); // absPath -> {imports, exports}
  for (const f of allFiles) parsed.set(f, parseFile(f));

  const edges = new Map(); // absPath -> Set<absPath>
  for (const [file, info] of parsed) {
    const targets = new Set();
    for (const spec of info.imports) {
      const resolved = resolveSpecifier(file, spec, pkgIndexMap);
      if (resolved && parsed.has(resolved)) targets.add(resolved);
    }
    edges.set(file, targets);
  }

  const roots = collectRoots().filter((f) => parsed.has(f));
  const visited = new Set(roots);
  const queue = [...roots];
  while (queue.length > 0) {
    const cur = queue.pop();
    for (const next of edges.get(cur) ?? []) {
      if (!visited.has(next)) {
        visited.add(next);
        queue.push(next);
      }
    }
  }

  const allowlistSet = new Set(STRUCTURAL_ALLOWLIST.map((e) => e.file));
  const knownUnwiredSet = new Set(STRUCTURAL_KNOWN_UNWIRED.map((e) => e.file));

  const findings = [];
  const known = [];
  for (const [file, info] of parsed) {
    const rel = relFromRoot(file);
    if (!rel.startsWith("packages/")) continue;
    if (isTestFile(rel)) continue;
    if (rel.endsWith(".d.ts")) continue;
    const pkgName = rel.split("/")[1];
    if (STRUCTURAL_EXCLUDED_PACKAGES[pkgName]) continue;
    if (visited.has(file)) continue;
    if (info.exports.length === 0) continue; // nothing concrete to report
    if (allowlistSet.has(rel)) continue;
    const entry = { file: rel, exports: info.exports };
    if (knownUnwiredSet.has(rel)) {
      known.push({ ...entry, reason: STRUCTURAL_KNOWN_UNWIRED.find((e) => e.file === rel).reason });
    } else {
      findings.push(entry);
    }
  }

  return { findings, known, filesScanned: parsed.size, rootsUsed: roots.length };
}

/* ============================================================================
 * main
 * ============================================================================
 */

function main() {
  console.log(
    "Unwired-seam check — every declared production seam must have a real caller,\n" +
      "and every packages/*/src module must be reachable from a real production entrypoint\n",
  );

  const results = SEAMS.map(checkSeam);
  const failures = results.filter((r) => !r.ok);

  console.log("PART 1 — hand-declared seams:");
  for (const r of results) {
    const status = r.ok ? "OK  " : "FAIL";
    console.log(`[${status}] ${r.seam.name}`);
    if (r.qualifying.length > 0) {
      for (const f of r.qualifying) console.log(`         called from ${f}`);
    }
  }
  if (KNOWN_UNWIRED.length > 0) {
    console.log("\nKnown, documented exceptions (informational — do not fail the build):");
    for (const k of KNOWN_UNWIRED) {
      console.log(`  - ${k.name}`);
      console.log(`    ${k.reason}`);
    }
  }

  console.log("\nPART 2 — structural reachability (every packages/*/src module):");
  const structural = checkStructuralReachability();
  console.log(
    `  Scanned ${structural.filesScanned} files, walked from ${structural.rootsUsed} production ` +
      "entrypoints (apps/*/src, published bin CLIs, scripts/*.mjs).",
  );

  if (structural.known.length > 0) {
    console.log("\n  Documented unreached modules (informational — do not fail the build):");
    for (const k of structural.known) {
      console.log(`  - ${k.file}`);
      console.log(`    ${k.reason}`);
      for (const e of k.exports) console.log(`      exports ${e.kind} ${e.name}()`);
    }
  }

  if (structural.findings.length > 0) {
    console.log("\n  FAIL — modules with NO import path from any production entrypoint:");
    for (const f of structural.findings) {
      console.log(`  - ${f.file}`);
      for (const e of f.exports) console.log(`      exports ${e.kind} ${e.name}()`);
    }
  } else {
    console.log("\n  OK — every packages/*/src module is reachable from a real entrypoint.");
  }

  const totalFailures = failures.length + structural.findings.length;
  if (totalFailures > 0) {
    console.error(`\n${totalFailures} seam(s)/module(s) regressed to "built but unwired":\n`);
    for (const f of failures) {
      console.error(`  - [hand-declared] ${f.seam.name}`);
      console.error(
        `    No non-test caller found outside ${f.seam.definedIn} (searched for "${f.seam.pattern}").`,
      );
    }
    for (const f of structural.findings) {
      console.error(`  - [structural] ${f.file}`);
      console.error(
        "    No import path from any apps/*/src file, published bin CLI, or scripts/*.mjs entrypoint.",
      );
      console.error(
        "    Fix it by wiring a real caller, or — if this is a deliberate exception — add it to " +
          "STRUCTURAL_ALLOWLIST/STRUCTURAL_KNOWN_UNWIRED in scripts/check-unwired-seams.mjs with a reason.",
      );
    }
    process.exit(1);
  }

  console.log("\nAll declared seams have a real production caller, and every module is reachable.");
  process.exit(0);
}

main();
