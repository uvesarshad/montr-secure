/**
 * Bounded interprocedural taint-flow resolution for Python (A21).
 *
 * Mirrors `typescript/callgraph.ts`'s exact bounded-scope philosophy and output
 * shape (`TaintFlowEdge[]`) — same 1-2 hop convention, same "resolve nothing
 * ambiguous" fail-safe posture. Prior to this module Python had NO call graph
 * at all (`languages/python/index.ts` always emitted `taintFlows: []`), so
 * `confirm/src/static.ts` and `correlation/src/grounding.ts` could only ever
 * see same-file taint sources/sinks for Python.
 *
 * ============================================================================
 * TIERS REACHED (see audit A21 / task list — reported explicitly per language):
 * ============================================================================
 *   (a) real function/call-site extraction  — YES (module-level `def`s only;
 *       see scope note below).
 *   (b) same-file call resolution           — YES.
 *   (c) one-hop relative-import resolution  — YES, for `from .mod import name`
 *       / `from ..pkg.mod import name` (dot-prefixed specifiers only, exactly
 *       mirroring the TS module's own restriction to relative `./`/`../`
 *       specifiers — a bare/absolute `from myapp.utils import x` is NOT
 *       resolved, since Python has no first-class notion distinguishing an
 *       internal absolute import from a third-party one without a package-root
 *       config this module does not have access to).
 *
 * ============================================================================
 * WHAT THIS RESOLVES:
 * ============================================================================
 *   1. DIRECT PASS-THROUGH (1 hop, may cross a file boundary via a relative
 *      import): call site `helper(<tainted-looking arg>)` where `helper` is a
 *      MODULE-LEVEL `def` (same file, or resolved via a relative import) whose
 *      body passes that parameter, untouched, as the first positional argument
 *      of a recognized sink call.
 *   2. RETURN-PROPAGATED (2 hops): `helper` returns the tainted parameter
 *      untouched (`return x`), and the call site's own use of the result
 *      reaches a sink one step later — either wrapped (`sink(helper(arg))`) or
 *      assigned then used by a later statement in the same block.
 *
 * A "tainted-looking arg" is a `request.<attr>[.get(...)|[...]]`-shaped
 * expression (Django/Flask/DRF — the same source vocabulary as `taint.ts`), or
 * a bare identifier whose nearest preceding assignment in the same block reads
 * one. No deeper alias chains are attempted.
 *
 * ============================================================================
 * WHAT THIS explicitly DOES NOT RESOLVE (out of scope, by design):
 * ============================================================================
 *   - Class methods / `self.foo()` / any attribute-call chain (`a.b.c(x)`) —
 *     only bare-identifier calls to a MODULE-LEVEL function are resolved,
 *     exactly mirroring the TS module's own "no dynamic dispatch / method
 *     chains" exclusion. A Django/DRF class-based view's `self.`-prefixed
 *     helper calls are therefore invisible to this pass.
 *   - Absolute/bare imports (`from myapp.utils import x`, `import utils`) —
 *     only dot-prefixed relative specifiers are resolved.
 *   - Decorated top-level functions ARE catalogued (the decorator doesn't
 *     change the function's callable identity), but a function reassigned
 *     through `functools.wraps`-style indirection is not specially unwrapped.
 *   - FastAPI `Depends(...)`-injected parameters are not tracked as taint
 *     sources here (they are not source-SHAPED expressions at a call site —
 *     `routes.ts`'s own auth/param handling covers them separately).
 *   - Chains longer than 2 hops, closures over an outer-scope variable,
 *     `*args`/`**kwargs`/default-valued parameters (only a plain or
 *     type-annotated identifier parameter is tracked).
 *
 * When any of the above is hit, resolution simply yields no edge for that call
 * site — NOT a claim that no flow exists. `grounding.ts` (Layer 2) and the
 * cross-function fallback in `confirm/src/static.ts` (Layer 3, A21) both keep
 * their existing same-file heuristics for everything this module misses.
 */
import { posix as posixPath } from "node:path";
import type { TaintFlowEdge, TaintSinkKind, TaintSourceKind } from "@montr/contracts";
import {
  calleeText,
  descendants,
  field,
  lineOf,
  namedChildren,
  positionalArgs,
  type ParsedModule,
} from "./parser.js";
import type { Node } from "web-tree-sitter";

/**
 * web-tree-sitter re-wraps AST nodes on every traversal call — the SAME
 * underlying syntax node fetched via two different paths (e.g. a descendant
 * search vs. a `.parent` walk) is NOT `===` the same JS object, only `.id`
 * equal. Every node-identity check in this module compares `.id`, never `===`.
 */
function sameNode(a: Node | undefined, b: Node | undefined): boolean {
  return !!a && !!b && a.id === b.id;
}

// --- Source/sink pattern matching -------------------------------------------
// Deliberately duplicated (not imported) from `taint.ts`'s tables — this module
// analyzes ARGUMENT expressions inside arbitrary function bodies (a different
// traversal shape than taint.ts's flat per-module scan). Keep in sync by hand.

const REQUEST_ATTR_KIND: Record<string, TaintSourceKind> = {
  GET: "query_param",
  args: "query_param",
  query_params: "query_param",
  values: "query_param",
  POST: "request_body",
  form: "request_body",
  data: "request_body",
  json: "request_body",
  body: "request_body",
  files: "request_body",
  COOKIES: "cookie",
  cookies: "cookie",
  headers: "request_header",
  META: "request_header",
};

/** Is `node` itself a source-shaped expression (same shapes `taint.ts` finds)? */
function sourceKindOfExpr(node: Node): TaintSourceKind | undefined {
  if (node.type === "call") {
    const callee = calleeText(node);
    const m = /^request\.([A-Za-z_]+)\.get$/.exec(callee);
    if (m?.[1] && REQUEST_ATTR_KIND[m[1]]) return REQUEST_ATTR_KIND[m[1]];
    if (/^request\.get_json$/.test(callee)) return "request_body";
    return undefined;
  }
  if (node.type === "subscript") {
    const value = field(node, "value")?.text ?? "";
    const m = /^request\.([A-Za-z_]+)$/.exec(value);
    return m?.[1] ? REQUEST_ATTR_KIND[m[1]] : undefined;
  }
  if (node.type === "attribute") {
    const m = /^request\.([A-Za-z_]+)$/.exec(node.text);
    return m?.[1] ? REQUEST_ATTR_KIND[m[1]] : undefined;
  }
  return undefined;
}

/** Sink kind for a call whose FIRST positional argument is the tainted-relevant one. */
function sinkKindOfCallee(callee: string): TaintSinkKind | undefined {
  const leaf = callee.split(".").pop() ?? callee;
  if (leaf === "raw" || leaf === "extra") return "orm_raw_query";
  if (leaf === "execute" || leaf === "executemany") return "sql_query";
  if (callee === "os.system" || callee === "os.popen") return "command_exec";
  if (
    /^subprocess\.(call|run|Popen|check_output|check_call|getoutput|getstatusoutput)$/.test(callee)
  )
    return "command_exec";
  if (callee === "eval" || callee === "exec") return "eval";
  if (/^(pickle|marshal|dill|cpickle|_pickle)\.(loads?|load)$/.test(callee)) return "deserialize";
  if (callee === "yaml.load") return "deserialize";
  if (leaf === "redirect" || leaf === "HttpResponseRedirect" || leaf === "RedirectResponse")
    return "redirect";
  if (leaf === "open") return "fs_read";
  if (/^(requests|httpx)\.(get|post|put|patch|delete|head|options|request)$/.test(callee))
    return "http_client";
  if (/(^|\.)urlopen$/.test(callee)) return "http_client";
  return undefined;
}

function isTemplateOrConcat(node: Node): boolean {
  return node.type === "string" || node.type === "binary_operator";
}

/** No nested call inside a template/concat expression (nothing sanitizer-shaped skipped). */
function hasNestedCall(node: Node): boolean {
  return descendants(node, "call").length > 0;
}

/**
 * True when `argExpr` is exactly the identifier `paramName`, or an f-string /
 * `%`-`+` concat expression that references `paramName` and contains no
 * nested call.
 */
function isCleanParamUse(argExpr: Node, paramName: string): boolean {
  if (argExpr.type === "identifier") return argExpr.text === paramName;
  if (isTemplateOrConcat(argExpr)) {
    if (hasNestedCall(argExpr)) return false;
    return descendants(argExpr, "identifier").some((id) => id.text === paramName);
  }
  return false;
}

// --- Function cataloguing ----------------------------------------------------

interface SinkHit {
  kind: TaintSinkKind;
  line: number;
  description: string;
}

interface FunctionProfile {
  name: string;
  file: string;
  line: number;
  paramNames: Array<string | undefined>;
  sinksByParam: Map<number, SinkHit>;
  returnsParam: Set<number>;
}

/** Extract a trackable bare/type-annotated parameter's name, else undefined
 * (default-valued and `*args`/`**kwargs` params are intentionally skipped —
 * a default's presence doesn't change runtime taintedness, but matching TS's
 * own conservative "bare identifier only" convention keeps both modules'
 * scope directly comparable). */
function paramName(p: Node): string | undefined {
  if (p.type === "identifier") return p.text;
  if (p.type === "typed_parameter") {
    const first = p.namedChildren[0];
    return first && first.type === "identifier" ? first.text : undefined;
  }
  return undefined;
}

function paramNamesOf(fn: Node): Array<string | undefined> {
  const params = field(fn, "parameters");
  if (!params) return [];
  return namedChildren(params).map(paramName);
}

/** Nearest enclosing function-DEFINITION ancestor (keeps analysis from
 * bleeding into a nested closure's body — closures are out of scope). */
function enclosingFunctionDef(node: Node): Node | undefined {
  let cur = node.parent;
  while (cur) {
    if (cur.type === "function_definition") return cur;
    cur = cur.parent;
  }
  return undefined;
}

/** Scan one function's body for (a) params landing directly in a sink call's
 * first argument, and (b) params returned untouched. */
function analyzeFunction(
  fn: Node,
  paramNames: Array<string | undefined>,
): { sinksByParam: Map<number, SinkHit>; returnsParam: Set<number> } {
  const sinksByParam = new Map<number, SinkHit>();
  const returnsParam = new Set<number>();
  const body = field(fn, "body");
  if (!body) return { sinksByParam, returnsParam };

  for (const call of descendants(body, "call")) {
    if (!sameNode(enclosingFunctionDef(call), fn)) continue; // skip nested defs/lambdas
    const callee = calleeText(call);
    const sinkKind = sinkKindOfCallee(callee);
    if (!sinkKind) continue;
    const arg0 = positionalArgs(call)[0];
    if (!arg0) continue;
    paramNames.forEach((pname, idx) => {
      if (pname && !sinksByParam.has(idx) && isCleanParamUse(arg0, pname)) {
        const line = isTemplateOrConcat(arg0) ? lineOf(arg0) : lineOf(call);
        sinksByParam.set(idx, { kind: sinkKind, line, description: `${callee}(...)` });
      }
    });
  }

  for (const ret of descendants(body, "return_statement")) {
    if (!sameNode(enclosingFunctionDef(ret), fn)) continue;
    const expr = namedChildren(ret)[0];
    if (!expr) continue;
    paramNames.forEach((pname, idx) => {
      if (pname && isCleanParamUse(expr, pname)) returnsParam.add(idx);
    });
  }

  return { sinksByParam, returnsParam };
}

/** Module-level `def`s only (direct children, or wrapped in a top-level
 * `decorated_definition`) — class methods are intentionally not catalogued. */
function moduleLevelFunctions(root: Node): Node[] {
  const out: Node[] = [];
  for (const child of namedChildren(root)) {
    if (child.type === "function_definition") {
      out.push(child);
    } else if (child.type === "decorated_definition") {
      const def =
        field(child, "definition") ??
        namedChildren(child)
          .slice()
          .reverse()
          .find((c) => c.type === "function_definition");
      if (def && def.type === "function_definition") out.push(def);
    }
  }
  return out;
}

function catalogFunctions(mod: ParsedModule): Map<string, FunctionProfile> {
  const out = new Map<string, FunctionProfile>();
  for (const fn of moduleLevelFunctions(mod.root)) {
    const nameNode = field(fn, "name");
    if (!nameNode) continue;
    const name = nameNode.text;
    const paramNames = paramNamesOf(fn);
    const { sinksByParam, returnsParam } = analyzeFunction(fn, paramNames);
    out.set(name, {
      name,
      file: mod.rel,
      line: lineOf(fn),
      paramNames,
      sinksByParam,
      returnsParam,
    });
  }
  return out;
}

// --- Relative-import resolution (tier c) -------------------------------------

interface ImportEntry {
  importedName: string;
  fromFile: string;
}

/** Resolve `from .mod import name` / `from ..pkg.mod import name` to a
 * repo-relative file already in `allFiles`. Only dot-prefixed (relative)
 * specifiers are handled — bare/absolute module paths are out of scope. */
function resolveRelativeImport(
  fromFile: string,
  dots: number,
  remainder: string,
  allFiles: ReadonlySet<string>,
): string | undefined {
  let dir = fromFile.includes("/") ? fromFile.slice(0, fromFile.lastIndexOf("/")) : "";
  // 1 dot = current package dir (no ascent); each extra dot ascends one level.
  for (let i = 1; i < dots; i++) {
    dir = dir.includes("/") ? dir.slice(0, dir.lastIndexOf("/")) : "";
  }
  const segments = remainder ? remainder.split(".") : [];
  const joined = posixPath.normalize(segments.length > 0 ? posixPath.join(dir, ...segments) : dir);
  const candidates = [`${joined}.py`, `${joined}/__init__.py`];
  return candidates.find((c) => allFiles.has(c));
}

function buildImportMap(
  mod: ParsedModule,
  allFiles: ReadonlySet<string>,
): Map<string, ImportEntry> {
  const map = new Map<string, ImportEntry>();
  for (const stmt of descendants(mod.root, "import_from_statement")) {
    const moduleNameNode = field(stmt, "module_name");
    if (!moduleNameNode || moduleNameNode.type !== "relative_import") continue;
    const prefix = moduleNameNode.namedChildren.find((c) => c && c.type === "import_prefix");
    const dots = prefix?.text.length ?? 0;
    if (dots < 1) continue;
    const dottedName = moduleNameNode.namedChildren.find((c) => c && c.type === "dotted_name");
    const remainder = dottedName?.text ?? "";
    const resolved = resolveRelativeImport(mod.rel, dots, remainder, allFiles);
    if (!resolved) continue;

    // Imported clauses follow the module_name child: bare `dotted_name` or
    // `aliased_import` (dotted_name `as` identifier).
    for (const child of namedChildren(stmt)) {
      if (sameNode(child, moduleNameNode)) continue;
      if (child.type === "dotted_name" && !child.text.includes(".")) {
        map.set(child.text, { importedName: child.text, fromFile: resolved });
      } else if (child.type === "aliased_import") {
        const orig = field(child, "name") ?? namedChildren(child)[0];
        const alias = field(child, "alias") ?? namedChildren(child)[1];
        if (orig && alias && !orig.text.includes(".")) {
          map.set(alias.text, { importedName: orig.text, fromFile: resolved });
        }
      }
    }
  }
  return map;
}

// --- Tainted-argument detection at a call site --------------------------------

interface TaintedArg {
  location: { file: string; line: number };
  kind: TaintSourceKind | undefined;
}

/** The direct-child-of-block/module statement that (transitively) contains `node`. */
function enclosingStatement(node: Node): Node | undefined {
  let cur: Node = node;
  for (;;) {
    const parent = cur.parent;
    if (!parent) return undefined;
    if (parent.type === "block" || parent.type === "module") return cur;
    cur = parent;
  }
}

function taintOfArg(argExpr: Node, rel: string): TaintedArg | undefined {
  const direct = sourceKindOfExpr(argExpr);
  if (direct) return { location: { file: rel, line: lineOf(argExpr) }, kind: direct };
  if (argExpr.type !== "identifier") return undefined;

  const name = argExpr.text;
  const stmt = enclosingStatement(argExpr);
  if (!stmt) return undefined;
  const block = stmt.parent;
  if (!block || (block.type !== "block" && block.type !== "module")) return undefined;
  const statements = namedChildren(block);
  const idx = statements.findIndex((s) => sameNode(s, stmt));
  if (idx < 0) return undefined;

  for (let i = idx - 1; i >= 0; i--) {
    const s = statements[i];
    if (!s || s.type !== "expression_statement") continue;
    const assignment = namedChildren(s)[0];
    if (!assignment || assignment.type !== "assignment") continue;
    const left = field(assignment, "left");
    const right = field(assignment, "right");
    if (!left || left.type !== "identifier" || left.text !== name || !right) continue;
    const kind = sourceKindOfExpr(right);
    if (kind) return { location: { file: rel, line: lineOf(right) }, kind };
  }
  return undefined;
}

function findLaterSinkUse(
  statements: Node[],
  fromIdx: number,
  varName: string,
): SinkHit | undefined {
  for (let i = fromIdx; i < statements.length; i++) {
    const stmt = statements[i];
    if (!stmt) continue;
    for (const call of descendants(stmt, "call")) {
      const callee = calleeText(call);
      const kind = sinkKindOfCallee(callee);
      if (!kind) continue;
      const arg0 = positionalArgs(call)[0];
      if (arg0 && isCleanParamUse(arg0, varName)) {
        const line = isTemplateOrConcat(arg0) ? lineOf(arg0) : lineOf(call);
        return { kind, line, description: `${callee}(...)` };
      }
    }
  }
  return undefined;
}

function outerSinkWrapping(call: Node): SinkHit | undefined {
  // `call`'s own parent is its argument_list container (`(y)`), not the outer
  // call directly — the outer call is the argument_list's OWN parent.
  const argList = call.parent;
  if (!argList || argList.type !== "argument_list") return undefined;
  const parent = argList.parent;
  if (!parent || parent.type !== "call") return undefined;
  const arg0 = positionalArgs(parent)[0];
  if (!arg0 || arg0.id !== call.id) return undefined;
  const callee = calleeText(parent);
  const kind = sinkKindOfCallee(callee);
  if (!kind) return undefined;
  return { kind, line: lineOf(parent), description: `${callee}(...)` };
}

// --- Entry point ---------------------------------------------------------------

/**
 * Resolve bounded 1-2 hop interprocedural taint flows across a Python project.
 * See the module doc comment for the exact patterns handled — and, just as
 * importantly, those explicitly NOT handled.
 */
export function scanPythonTaintFlows(mods: ParsedModule[]): TaintFlowEdge[] {
  const allFiles = new Set(mods.map((m) => m.rel));
  const functionsByFile = new Map<string, Map<string, FunctionProfile>>();
  const importsByFile = new Map<string, Map<string, ImportEntry>>();
  for (const mod of mods) {
    functionsByFile.set(mod.rel, catalogFunctions(mod));
    importsByFile.set(mod.rel, buildImportMap(mod, allFiles));
  }

  const edges: TaintFlowEdge[] = [];

  for (const mod of mods) {
    const localFns = functionsByFile.get(mod.rel);
    const imports = importsByFile.get(mod.rel);

    for (const call of descendants(mod.root, "call")) {
      const calleeNode = field(call, "function");
      if (!calleeNode || calleeNode.type !== "identifier") continue; // no attribute/method calls
      const name = calleeNode.text;

      let target = localFns?.get(name);
      if (!target) {
        const entry = imports?.get(name);
        if (entry) target = functionsByFile.get(entry.fromFile)?.get(entry.importedName);
      }
      if (!target) continue;

      const args = positionalArgs(call);
      for (let i = 0; i < args.length; i++) {
        const argExpr = args[i];
        if (!argExpr) continue;
        const tainted = taintOfArg(argExpr, mod.rel);
        if (!tainted) continue;

        const direct = target.sinksByParam.get(i);
        if (direct) {
          edges.push({
            sourceLocation: tainted.location,
            ...(tainted.kind ? { sourceKind: tainted.kind } : {}),
            throughFunction: target.name,
            throughLocation: { file: target.file, line: target.line },
            sinkLocation: { file: target.file, line: direct.line },
            sinkKind: direct.kind,
            resolution: "direct-call",
            hops: 1,
            crossFile: tainted.location.file !== target.file,
          });
        }

        if (target.returnsParam.has(i)) {
          const wrapped = outerSinkWrapping(call);
          if (wrapped) {
            edges.push({
              sourceLocation: tainted.location,
              ...(tainted.kind ? { sourceKind: tainted.kind } : {}),
              throughFunction: target.name,
              throughLocation: { file: target.file, line: target.line },
              sinkLocation: { file: mod.rel, line: wrapped.line },
              sinkKind: wrapped.kind,
              resolution: "return-propagated",
              hops: 2,
              crossFile: tainted.location.file !== mod.rel,
            });
            continue;
          }

          const assignStmt = enclosingStatement(call);
          const assignment =
            assignStmt?.type === "expression_statement" ? namedChildren(assignStmt)[0] : undefined;
          if (assignStmt && assignment?.type === "assignment") {
            const leftNode = field(assignment, "left");
            if (leftNode && leftNode.type === "identifier") {
              const block = assignStmt.parent;
              const statements =
                block && (block.type === "block" || block.type === "module")
                  ? namedChildren(block)
                  : [];
              const idx = statements.findIndex((s) => sameNode(s, assignStmt));
              if (idx >= 0) {
                const later = findLaterSinkUse(statements, idx + 1, leftNode.text);
                if (later) {
                  edges.push({
                    sourceLocation: tainted.location,
                    ...(tainted.kind ? { sourceKind: tainted.kind } : {}),
                    throughFunction: target.name,
                    throughLocation: { file: target.file, line: target.line },
                    sinkLocation: { file: mod.rel, line: later.line },
                    sinkKind: later.kind,
                    resolution: "return-propagated",
                    hops: 2,
                    crossFile: tainted.location.file !== mod.rel,
                  });
                }
              }
            }
          }
        }
      }
    }
  }

  const seen = new Set<string>();
  const deduped = edges.filter((e) => {
    const key = `${e.sourceLocation.file}:${e.sourceLocation.line}>${e.sinkLocation.file}:${e.sinkLocation.line}:${e.resolution}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return deduped.sort(
    (a, b) =>
      a.sinkLocation.file.localeCompare(b.sinkLocation.file) ||
      a.sinkLocation.line - b.sinkLocation.line ||
      a.sourceLocation.file.localeCompare(b.sourceLocation.file) ||
      a.sourceLocation.line - b.sourceLocation.line,
  );
}
