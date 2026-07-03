/**
 * web-tree-sitter loader + AST helpers for the Python analyzer (Layer 0).
 *
 * Loads the prebuilt `tree-sitter-python` grammar from `tree-sitter-wasms`
 * (no native build) via the web-tree-sitter 0.25 API and memoizes a single
 * configured `Parser`. All parsing is SYNCHRONOUS and OFFLINE — the grammar wasm
 * ships in `node_modules`, so no network or filesystem beyond the repo is touched
 * (golden rules #1, #6: deterministic, no LLM here).
 *
 * The rest of the Python builders (routes/models/surfaces/taint) depend only on
 * the small, null-safe helpers exported here — never on the raw grammar shape —
 * so a grammar-version bump stays contained to this file.
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { Language, Parser } from "web-tree-sitter";
import type { Node } from "web-tree-sitter";

const require = createRequire(import.meta.url);

let parserPromise: Promise<Parser> | null = null;

/** Resolve the runtime + grammar wasm out of the installed packages (offline). */
function grammarWasmPath(): string {
  const pkg = require.resolve("tree-sitter-wasms/package.json");
  return join(dirname(pkg), "out", "tree-sitter-python.wasm");
}

async function loadPythonParser(): Promise<Parser> {
  // web-tree-sitter locates its own runtime wasm under Node; pass a `locateFile`
  // hint pointing at the installed copy so it works regardless of cwd.
  let init: unknown = undefined;
  try {
    const runtime = require.resolve("web-tree-sitter/tree-sitter.wasm");
    init = { locateFile: (): string => runtime };
  } catch {
    init = undefined;
  }
  await Parser.init(init as Parameters<typeof Parser.init>[0]);
  const bytes = await readFile(grammarWasmPath());
  const language = await Language.load(new Uint8Array(bytes));
  const parser = new Parser();
  parser.setLanguage(language);
  return parser;
}

/** The memoized, python-configured parser (loaded once per process). */
export function getPythonParser(): Promise<Parser> {
  if (!parserPromise) parserPromise = loadPythonParser();
  return parserPromise;
}

/** Parse one source file; returns the root {@link Node} or null on failure. */
export function parseModule(parser: Parser, source: string): Node | null {
  const tree = parser.parse(source);
  return tree ? tree.rootNode : null;
}

/** One parsed Python module — the shared input to every builder. */
export interface ParsedModule {
  /** Repo-relative POSIX path. */
  rel: string;
  /** Full source text (used for cheap lexical framework hints). */
  source: string;
  /** The module's syntax-tree root. */
  root: Node;
}

// ---------------------------------------------------------------------------
// Null-safe AST helpers (the builders use ONLY these).
// ---------------------------------------------------------------------------

/** 1-based start line (tree-sitter rows are 0-based). */
export function lineOf(node: Node): number {
  return node.startPosition.row + 1;
}

/** All descendants of the given type(s), nulls filtered out. */
export function descendants(root: Node, types: string | string[]): Node[] {
  return root.descendantsOfType(types).filter((n): n is Node => n !== null);
}

/** A named field child, or undefined. */
export function field(node: Node, name: string): Node | undefined {
  return node.childForFieldName(name) ?? undefined;
}

/** Named children with nulls filtered out. */
export function namedChildren(node: Node): Node[] {
  return node.namedChildren.filter((n): n is Node => n !== null);
}

/** The dotted callee text of a `call` node, e.g. `cursor.execute`. */
export function calleeText(call: Node): string {
  return field(call, "function")?.text ?? "";
}

/** Positional (non-keyword) argument nodes of a `call`, in order. */
export function positionalArgs(call: Node): Node[] {
  const args = field(call, "arguments");
  if (!args) return [];
  return namedChildren(args).filter((a) => a.type !== "keyword_argument" && a.type !== "comment");
}

/** Value node of a keyword argument `name=...` on a `call`, or undefined. */
export function keywordArg(call: Node, name: string): Node | undefined {
  const args = field(call, "arguments");
  if (!args) return undefined;
  for (const child of namedChildren(args)) {
    if (child.type !== "keyword_argument") continue;
    if (field(child, "name")?.text === name) return field(child, "value");
  }
  return undefined;
}

/** Strip Python string prefixes + surrounding quotes; undefined if not a string. */
export function stringValue(node: Node | undefined): string | undefined {
  if (!node || node.type !== "string") return undefined;
  const raw = node.text;
  const noPrefix = raw.replace(/^[rbfuRBFU]{0,3}/, "");
  const m = /^("""|'''|"|')([\s\S]*)\1$/.exec(noPrefix);
  return m ? m[2] : undefined;
}

/** True when a `string` node is an f-string (has interpolation / an f prefix). */
export function isFString(node: Node): boolean {
  if (node.type !== "string") return false;
  if (/^[rbuRBU]{0,2}[fF]/.test(node.text)) return true;
  return node.descendantsOfType("interpolation").some((n) => n !== null);
}

/**
 * Does this expression node mix untrusted data into a string (interpolation /
 * `%` / `.format` / `+` concat)? Used to tell a dangerous sink argument from a
 * constant one, so a plain `open("const.txt")` is not flagged.
 */
export function isDynamicString(node: Node | undefined): boolean {
  if (!node) return false;
  switch (node.type) {
    case "string":
      return isFString(node);
    case "binary_operator": {
      // `"..." % x`, `"a" + b`
      const op = node.text;
      return op.includes("%") || op.includes("+");
    }
    case "call":
      // `"...{}".format(x)`
      return /\.format$/.test(calleeText(node));
    case "identifier":
    case "attribute":
    case "subscript":
      return true; // a bare variable/attr flowing into the sink
    default:
      return false;
  }
}
