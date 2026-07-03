/**
 * tree-sitter-java loader + small, null-safe AST helpers (JVM App-Map analyzer).
 *
 * Loads the prebuilt `tree-sitter-java.wasm` grammar via `web-tree-sitter`
 * (0.25 API: `Parser.init()` → `Language.load(wasm)` → `parser.setLanguage`).
 * Everything here is SYNTACTIC + OFFLINE — no native build, no dependency
 * resolution, no network. The grammar is loaded once and the parser reused
 * sequentially (the dispatcher runs one Java analyzer per scan).
 */
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { Language, Parser } from "web-tree-sitter";
import type { Node as TSNode } from "web-tree-sitter";

export type { TSNode };

let parserPromise: Promise<Parser> | undefined;

/** Locate `tree-sitter-java.wasm` inside the `tree-sitter-wasms` package `out/` dir. */
function javaWasmPath(): string {
  const require = createRequire(import.meta.url);
  const pkg = require.resolve("tree-sitter-wasms/package.json");
  return join(dirname(pkg), "out", "tree-sitter-java.wasm");
}

/** Lazily init the WASM runtime + Java grammar once; reuse the parser thereafter. */
export async function getJavaParser(): Promise<Parser> {
  if (!parserPromise) {
    parserPromise = (async (): Promise<Parser> => {
      await Parser.init();
      const language = await Language.load(javaWasmPath());
      const parser = new Parser();
      parser.setLanguage(language);
      return parser;
    })().catch((err: unknown) => {
      // Allow a later retry if the one-time init transiently failed.
      parserPromise = undefined;
      throw err;
    });
  }
  return parserPromise;
}

/** Parse Java source → the `program` root node (or null if the grammar bailed). */
export async function parseJava(source: string): Promise<TSNode | null> {
  const parser = await getJavaParser();
  const tree = parser.parse(source);
  return tree ? tree.rootNode : null;
}

// ---------------------------------------------------------------------------
// Null-safe traversal helpers
// ---------------------------------------------------------------------------

/** 1-based start line of a node (tree-sitter rows are 0-based). */
export function lineOf(node: TSNode): number {
  return node.startPosition.row + 1;
}

/** Named children with the grammar's nulls filtered out. */
export function namedKids(node: TSNode): TSNode[] {
  return node.namedChildren.filter((c): c is TSNode => c !== null);
}

/** First named child of a given type, if any. */
export function firstOfType(node: TSNode, type: string): TSNode | undefined {
  for (const c of node.namedChildren) if (c && c.type === type) return c;
  return undefined;
}

/** A field child (`childForFieldName`), normalized to `undefined`. */
export function field(node: TSNode, name: string): TSNode | undefined {
  return node.childForFieldName(name) ?? undefined;
}

/** All descendants of the given type(s) (delegates to the wasm traversal). */
export function descendantsOfType(node: TSNode, types: string | string[]): TSNode[] {
  return node.descendantsOfType(types).filter((c): c is TSNode => c !== null);
}

/** Trailing identifier of a possibly-scoped name (`a.b.C` → `C`). */
export function lastIdentText(node: TSNode | undefined): string {
  if (!node) return "";
  if (node.type === "identifier" || node.type === "type_identifier") return node.text;
  const idents = descendantsOfType(node, ["identifier", "type_identifier"]);
  const last = idents[idents.length - 1];
  return last ? last.text : node.text;
}

/** Content of a `string_literal`, without the surrounding quotes/escapes. */
export function unquote(node: TSNode | undefined): string {
  if (!node) return "";
  const frag = firstOfType(node, "string_fragment");
  if (frag) return frag.text;
  const t = node.text;
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) return t.slice(1, -1);
  return t;
}

// ---------------------------------------------------------------------------
// Annotation helpers (@RestController, @GetMapping("/x"), @RequestParam("q") …)
// ---------------------------------------------------------------------------

export interface AnnotationInfo {
  /** Simple annotation name, package-stripped (e.g. `GetMapping`). */
  name: string;
  /** The annotation node itself. */
  node: TSNode;
  /** The `annotation_argument_list` node, if the annotation had arguments. */
  args: TSNode | undefined;
}

/** The `modifiers` node attached to a declaration, if present. */
export function modifiersOf(decl: TSNode): TSNode | undefined {
  return firstOfType(decl, "modifiers");
}

/** Annotations declared on `decl` (reads its `modifiers` child). */
export function annotationsOf(decl: TSNode): AnnotationInfo[] {
  const mods = modifiersOf(decl);
  if (!mods) return [];
  const out: AnnotationInfo[] = [];
  for (const c of namedKids(mods)) {
    if (c.type !== "annotation" && c.type !== "marker_annotation") continue;
    const nameNode = field(c, "name");
    out.push({
      name: lastIdentText(nameNode ?? c),
      node: c,
      args: firstOfType(c, "annotation_argument_list"),
    });
  }
  return out;
}

/** First annotation on `decl` whose (package-stripped) name is in `names`. */
export function findAnnotation(
  decl: TSNode,
  names: ReadonlySet<string>,
): AnnotationInfo | undefined {
  return annotationsOf(decl).find((a) => names.has(a.name));
}

/**
 * The string value of an annotation argument: a positional string
 * (`@GetMapping("/x")`), the first element of an array (`@GetMapping({"/a"})`),
 * or a named attribute (`@RequestMapping(value = "/x")`, keys default to
 * value/path). Returns undefined when the annotation carries no string.
 */
export function annotationStringValue(
  ann: AnnotationInfo,
  keys: readonly string[] = ["value", "path"],
): string | undefined {
  const args = ann.args;
  if (!args) return undefined;
  for (const c of namedKids(args)) {
    if (c.type === "string_literal") return unquote(c);
    if (c.type === "element_value_array_initializer") {
      const s = firstOfType(c, "string_literal");
      if (s) return unquote(s);
    }
    if (c.type === "element_value_pair") {
      const key = field(c, "key");
      if (key && keys.includes(key.text)) {
        const value = field(c, "value");
        if (value?.type === "string_literal") return unquote(value);
        if (value?.type === "element_value_array_initializer") {
          const s = firstOfType(value, "string_literal");
          if (s) return unquote(s);
        }
      }
    }
  }
  return undefined;
}

/** Raw (unparsed) text of a named annotation attribute, e.g. `method` → `RequestMethod.POST`. */
export function annotationAttrText(ann: AnnotationInfo, key: string): string | undefined {
  const args = ann.args;
  if (!args) return undefined;
  for (const c of namedKids(args)) {
    if (c.type !== "element_value_pair") continue;
    if (field(c, "key")?.text === key) return field(c, "value")?.text;
  }
  return undefined;
}
