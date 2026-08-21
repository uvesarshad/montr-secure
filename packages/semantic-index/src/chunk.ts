/**
 * AST chunker (E5) — cuts source into semantically coherent units for
 * embedding, reusing @montr/appmap's own parser loaders so this package
 * parses the SAME grammars through the SAME code path as Layer 0 (ts-morph
 * for TypeScript/JavaScript, web-tree-sitter for Python and Java) rather than
 * duplicating WASM-loading/project-setup logic.
 *
 * GRANULARITY (documented judgment call): one chunk per FUNCTION-LIKE UNIT —
 * a top-level function declaration, a top-level `const x = (...) => {}` /
 * `function() {}` assignment, or a class method. A whole class becomes one
 * chunk only when it has no methods at all (e.g. a plain DTO/data class),
 * so nothing is silently dropped.
 *
 * Why function-level, not file-level or class-level:
 *   - It keeps individual chunks small enough that a batch of them fits
 *     comfortably in one embedding-provider request and stays cheap to
 *     re-embed (file-level chunking on a large route/controller file would
 *     blow both the embedding request size and the eventual "show this to
 *     an LLM as context" token budget the audit calls out — E5 exists
 *     specifically to avoid that).
 *   - It matches the natural unit correlation/confirmation already reason
 *     about: a route handler, a query helper, a sanitizer — each is a
 *     function. "Find every other place this pattern occurs" (E5's stated
 *     goal) is most useful phrased as "find other functions that do a
 *     similar thing," which is exactly this granularity.
 *   - Route handlers specifically are NOT special-cased here: a route
 *     handler is a function (or a class method for some frameworks), and is
 *     therefore captured by the same rule — no separate "route_handler"
 *     kind was introduced. A consumer that wants "is this chunk a route
 *     handler" can cross-reference AppMap's own `Route.handler` source
 *     location (file + line) against a chunk's file/startLine/endLine range.
 *
 * KNOWN GAPS (documented, not silently swallowed):
 *   - TypeScript: only top-level function declarations/expressions and class
 *     methods are chunked — not object-literal method shorthand, not
 *     get/set accessors, not IIFEs, not overload signatures (no body to
 *     chunk), not default-exported anonymous functions.
 *   - Python: only `function_definition` nodes (module-level functions and
 *     methods alike — the grammar doesn't distinguish) and a class-level
 *     fallback for a class with zero methods; decorators/async are captured
 *     as part of the node's own text.
 *   - Java: only `method_declaration` + `constructor_declaration` and a
 *     class-level fallback for a class/interface with neither; nested/inner
 *     classes are walked (descendantsOfType finds them), but are not
 *     separately labeled as "nested."
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import fg from "fast-glob";
import { Node, type Project, type SourceFile } from "ts-morph";
import type { Node as TSNode } from "web-tree-sitter";
import {
  createProject,
  getJavaParser,
  javaDescendantsOfType,
  javaLineOf,
  parseJava,
  getPythonParser,
  parsePythonModule,
  pythonDescendants,
  pythonLineOf,
} from "@montr/appmap";
import type { CodeChunkDraft } from "./types.js";

/** Chunks over this size are truncated (with a marker) — see the module doc comment. */
export const MAX_CHUNK_CHARS = 8_000;
/** Chunks with fewer than this many lines are skipped (boilerplate, not worth indexing). */
const MIN_CHUNK_LINES = 2;

function contentHash(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function toPosix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}

function makeChunk(
  file: string,
  startLine: number,
  endLine: number,
  language: CodeChunkDraft["language"],
  kind: CodeChunkDraft["kind"],
  symbolName: string | undefined,
  rawContent: string,
): CodeChunkDraft | undefined {
  if (endLine - startLine + 1 < MIN_CHUNK_LINES) return undefined;
  const truncated = rawContent.length > MAX_CHUNK_CHARS;
  const content = truncated
    ? `${rawContent.slice(0, MAX_CHUNK_CHARS)}\n/* …truncated (${rawContent.length} chars total)… */`
    : rawContent;
  return {
    file,
    startLine,
    endLine,
    language,
    kind,
    ...(symbolName ? { symbolName } : {}),
    content,
    contentHash: contentHash(content),
  };
}

// --------------------------------------------------------------------------- //
// TypeScript / JavaScript — ts-morph
// --------------------------------------------------------------------------- //

/** Chunk one already-parsed ts-morph `SourceFile`. Exported for direct/unit-test use. */
export function chunkTypeScriptFile(file: string, sourceFile: SourceFile): CodeChunkDraft[] {
  const rel = toPosix(file);
  const chunks: CodeChunkDraft[] = [];

  for (const fn of sourceFile.getFunctions()) {
    if (!fn.getBody()) continue; // overload signature — nothing to embed
    const c = makeChunk(
      rel,
      fn.getStartLineNumber(),
      fn.getEndLineNumber(),
      "typescript",
      "function",
      fn.getName(),
      fn.getText(),
    );
    if (c) chunks.push(c);
  }

  for (const stmt of sourceFile.getVariableStatements()) {
    for (const decl of stmt.getDeclarations()) {
      const init = decl.getInitializer();
      if (!init || (!Node.isArrowFunction(init) && !Node.isFunctionExpression(init))) continue;
      const nameNode = decl.getNameNode();
      const name = Node.isIdentifier(nameNode) ? nameNode.getText() : undefined;
      const c = makeChunk(
        rel,
        decl.getStartLineNumber(),
        decl.getEndLineNumber(),
        "typescript",
        "function",
        name,
        decl.getText(),
      );
      if (c) chunks.push(c);
    }
  }

  for (const cls of sourceFile.getClasses()) {
    const methods = cls.getMethods().filter((m) => m.getBody());
    for (const m of methods) {
      const c = makeChunk(
        rel,
        m.getStartLineNumber(),
        m.getEndLineNumber(),
        "typescript",
        "method",
        m.getName(),
        m.getText(),
      );
      if (c) chunks.push(c);
    }
    if (methods.length === 0) {
      const c = makeChunk(
        rel,
        cls.getStartLineNumber(),
        cls.getEndLineNumber(),
        "typescript",
        "class",
        cls.getName(),
        cls.getText(),
      );
      if (c) chunks.push(c);
    }
  }

  return chunks;
}

/** Chunk every TS/JS file already added to `project` — call `chunkTypeScriptFile` per file if you built the project yourself. */
export function chunkTypeScriptProject(project: Project, files: string[]): CodeChunkDraft[] {
  const chunks: CodeChunkDraft[] = [];
  for (const rel of files) {
    if (!/\.(tsx?|jsx?|mjs|cjs)$/i.test(rel)) continue;
    const sourceFile = project.getSourceFile((f) =>
      toPosix(f.getFilePath()).endsWith(toPosix(rel)),
    );
    if (!sourceFile) continue;
    chunks.push(...chunkTypeScriptFile(rel, sourceFile));
  }
  return chunks;
}

// --------------------------------------------------------------------------- //
// Python — web-tree-sitter (via @montr/appmap's loader)
// --------------------------------------------------------------------------- //

export async function chunkPythonSource(file: string, source: string): Promise<CodeChunkDraft[]> {
  const parser = await getPythonParser();
  const root = parsePythonModule(parser, source);
  if (!root) return [];
  const rel = toPosix(file);
  const chunks: CodeChunkDraft[] = [];
  const lines = source.split("\n");
  const endLineOf = (n: { endPosition: { row: number } }): number => n.endPosition.row + 1;

  const functionNodes = pythonDescendants(root, "function_definition");
  const functionRanges = new Set<string>();
  for (const fn of functionNodes) {
    const nameNode = fn.childForFieldName("name");
    const startLine = pythonLineOf(fn);
    const endLine = endLineOf(fn);
    functionRanges.add(`${startLine}:${endLine}`);
    const text = lines.slice(startLine - 1, endLine).join("\n");
    const c = makeChunk(rel, startLine, endLine, "python", "function", nameNode?.text, text);
    if (c) chunks.push(c);
  }

  for (const cls of pythonDescendants(root, "class_definition")) {
    const hasOwnMethod = functionNodes.some(
      (fn) => pythonLineOf(fn) >= pythonLineOf(cls) && endLineOf(fn) <= endLineOf(cls),
    );
    if (hasOwnMethod) continue; // its methods were already chunked individually
    const nameNode = cls.childForFieldName("name");
    const startLine = pythonLineOf(cls);
    const endLine = endLineOf(cls);
    const text = lines.slice(startLine - 1, endLine).join("\n");
    const c = makeChunk(rel, startLine, endLine, "python", "class", nameNode?.text, text);
    if (c) chunks.push(c);
  }

  return chunks;
}

// --------------------------------------------------------------------------- //
// Java — web-tree-sitter (via @montr/appmap's loader)
// --------------------------------------------------------------------------- //

const JAVA_METHOD_TYPES = ["method_declaration", "constructor_declaration"];
const JAVA_CLASS_TYPES = ["class_declaration", "interface_declaration"];

export async function chunkJavaSource(file: string, source: string): Promise<CodeChunkDraft[]> {
  const root = await parseJava(source);
  if (!root) return [];
  const rel = toPosix(file);
  const chunks: CodeChunkDraft[] = [];
  const lines = source.split("\n");
  const endLineOf = (n: TSNode): number => n.endPosition.row + 1;

  const methodNodes = javaDescendantsOfType(root, JAVA_METHOD_TYPES);
  for (const m of methodNodes) {
    if (!m.childForFieldName("body")) continue; // abstract/interface signature — no body to embed
    const nameNode = m.childForFieldName("name");
    const startLine = javaLineOf(m);
    const endLine = endLineOf(m);
    const text = lines.slice(startLine - 1, endLine).join("\n");
    const c = makeChunk(rel, startLine, endLine, "java", "method", nameNode?.text, text);
    if (c) chunks.push(c);
  }

  for (const cls of javaDescendantsOfType(root, JAVA_CLASS_TYPES)) {
    const startLine = javaLineOf(cls);
    const endLine = endLineOf(cls);
    const hasOwnMethod = methodNodes.some(
      (m) => javaLineOf(m) >= startLine && endLineOf(m) <= endLine,
    );
    if (hasOwnMethod) continue;
    const nameNode = cls.childForFieldName("name");
    const text = lines.slice(startLine - 1, endLine).join("\n");
    const c = makeChunk(rel, startLine, endLine, "java", "class", nameNode?.text, text);
    if (c) chunks.push(c);
  }

  return chunks;
}

// --------------------------------------------------------------------------- //
// Whole-repo entry point
// --------------------------------------------------------------------------- //

const IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/target/**",
  "**/out/**",
  "**/.venv/**",
  "**/venv/**",
  "**/__pycache__/**",
  "**/.gradle/**",
];

export interface ChunkRepoResult {
  chunks: CodeChunkDraft[];
  filesScanned: number;
}

/**
 * Chunk every TS/JS, Python, and Java source file under `dir`. This is the
 * function `build.ts`'s `buildSemanticIndex` calls; also usable standalone.
 */
export async function chunkRepo(dir: string): Promise<ChunkRepoResult> {
  const [tsFiles, pyFiles, javaFiles] = await Promise.all([
    fg("**/*.{ts,tsx,js,jsx,mjs,cjs}", { cwd: dir, ignore: IGNORE, dot: false }),
    fg("**/*.py", { cwd: dir, ignore: IGNORE, dot: false }),
    fg("**/*.java", { cwd: dir, ignore: IGNORE, dot: false }),
  ]);

  const chunks: CodeChunkDraft[] = [];

  if (tsFiles.length > 0) {
    const project = createProject(dir, tsFiles);
    chunks.push(...chunkTypeScriptProject(project, tsFiles));
  }

  for (const rel of pyFiles) {
    try {
      const source = await readFile(join(dir, rel), "utf8");
      chunks.push(...(await chunkPythonSource(rel, source)));
    } catch {
      /* unreadable/oversized file — skip, index degrades gracefully */
    }
  }

  for (const rel of javaFiles) {
    try {
      const source = await readFile(join(dir, rel), "utf8");
      chunks.push(...(await chunkJavaSource(rel, source)));
    } catch {
      /* unreadable/oversized file — skip, index degrades gracefully */
    }
  }

  return { chunks, filesScanned: tsFiles.length + pyFiles.length + javaFiles.length };
}

// Re-export so callers needing to warm the parser cache (e.g. before timing a
// benchmark) don't need a direct @montr/appmap import just for this.
export { getPythonParser, getJavaParser };
