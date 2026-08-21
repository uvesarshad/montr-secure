/**
 * Bounded interprocedural taint-flow resolution for Java (A21).
 *
 * Mirrors `typescript/callgraph.ts`'s bounded-scope philosophy and output shape
 * (`TaintFlowEdge[]`). Prior to this module Java had NO call graph at all
 * (`languages/java/index.ts` always emitted `taintFlows: []`), so
 * `confirm/src/static.ts` and `correlation/src/grounding.ts` could only ever
 * see same-file taint sources/sinks for Java.
 *
 * ============================================================================
 * TIERS REACHED (see audit A21 / task list — reported explicitly per language):
 * ============================================================================
 *   (a) real function/call-site extraction — YES (method_declarations + their
 *       call sites, per class).
 *   (b) same-file call resolution          — YES: same-class unqualified/
 *       `this.`-qualified calls, AND same-FILE cross-class static-style calls
 *       (`OtherClassInSameFile.method(x)`, matching a class also declared in
 *       this file — common in test fixtures and small controllers/services
 *       kept in one file).
 *   (c) one-hop cross-file resolution      — NOT attempted. Unlike TS's
 *       explicit `import {x} from "./y"` or Python's explicit
 *       `from .y import x`, Java source files require NO import statement at
 *       all to call another class in the SAME package — same-package
 *       resolution can only be approximated (e.g. "another .java file in the
 *       same directory"), which is a materially weaker signal than an
 *       explicit specifier and risks a wrong edge in any multi-module
 *       Maven/Gradle layout with same-named classes in sibling package roots.
 *       Given this module's fail-safe philosophy (an edge is a POSITIVE claim
 *       consumed downstream — see the module-level caveat below), that
 *       weaker signal was deliberately not used. A real cross-file resolver
 *       would need actual `package`/`import` declaration parsing (not yet
 *       done anywhere in this analyzer) to do safely; tracked as a follow-up.
 *
 * ============================================================================
 * WHAT THIS RESOLVES:
 * ============================================================================
 *   1. DIRECT PASS-THROUGH (1 hop): call site `target.method(<tainted arg>)`
 *      (same class, `this.`-qualified, or same-file static-style) whose callee
 *      method passes that parameter, untouched or via a `+`-concatenation, as
 *      the first argument of a recognized sink call.
 *   2. RETURN-PROPAGATED (2 hops): the callee method `return`s the tainted
 *      parameter untouched, and the call site's own use of the result reaches
 *      a sink one step later — wrapped (`sink(helper(arg))`) or assigned to a
 *      local then used by a later statement in the same block.
 *
 * A "tainted-looking arg" is EITHER (a) an inline `HttpServletRequest` getter
 * call used directly as the argument (`service.find(request.getParameter(
 * "id"))`), matching `extract.ts`'s own source vocabulary, OR (b) a bare
 * identifier that is itself a parameter of the ENCLOSING (calling) method
 * carrying a Spring source annotation (`@RequestParam`/`@PathVariable`/…) —
 * this second form is what actually resolves the realistic
 * controller-calls-service pattern (`@GetMapping("/x") X get(@RequestParam
 * String id) { return service.find(id); }`), since Java taint sources are
 * established at annotated PARAMETERS, not source-shaped inline expressions
 * the way TS/Python's `req.query`-style access is.
 *
 * ============================================================================
 * WHAT THIS explicitly DOES NOT RESOLVE (out of scope, by design):
 * ============================================================================
 *   - Instance method calls through a locally-typed variable
 *     (`Bar b = new Bar(); b.util(x)`) — only unqualified/`this.` (same
 *     class) and a literal `ClassName.method(...)` text match against a
 *     same-file class are resolved. No variable-type tracking is attempted.
 *   - Interfaces / abstract dispatch / Spring `@Autowired` field injection —
 *     a call through an injected dependency's declared interface type cannot
 *     be resolved to a concrete implementation without a much larger type
 *     system than this pass has.
 *   - Method overloading is conflated: a class with multiple methods sharing
 *     a name resolves to the FIRST one catalogued (documented limitation,
 *     the same class of simplification TS's own name-only function map has
 *     for JS function redeclaration).
 *   - Constructors, static initializer blocks, lambda bodies, and anonymous
 *     inner classes are not catalogued as callable targets.
 *   - Chains longer than 2 hops.
 *
 * When any of the above is hit, resolution simply yields no edge — NOT a
 * claim that no flow exists. `grounding.ts` (Layer 2) and the cross-function
 * fallback in `confirm/src/static.ts` (Layer 3, A21) both keep their existing
 * same-file heuristics for everything this module misses.
 */
import type { TaintFlowEdge, TaintSinkKind, TaintSourceKind } from "@montr/contracts";
import {
  annotationsOf,
  descendantsOfType,
  field,
  lineOf,
  namedKids,
  type TSNode,
} from "./parser.js";

/** See `python/callgraph.ts`'s identical caveat: web-tree-sitter re-wraps AST
 * nodes per traversal call, so node identity must compare `.id`, never `===`. */
function sameNode(a: TSNode | undefined, b: TSNode | undefined): boolean {
  return !!a && !!b && a.id === b.id;
}

// --- Source/sink vocabularies -------------------------------------------------
// Deliberately duplicated (not imported) from `extract.ts` — same convention
// as `express.ts`/`fastify.ts` duplicating `routes.ts`'s auth-guard list. Keep
// in sync by hand.

const SOURCE_ANNOTATION_KIND: Record<string, TaintSourceKind> = {
  RequestParam: "query_param",
  PathVariable: "path_param",
  RequestBody: "request_body",
  RequestHeader: "request_header",
  CookieValue: "cookie",
  ModelAttribute: "request_body",
};

const REQUEST_GETTER_KIND: Record<string, TaintSourceKind> = {
  getParameter: "query_param",
  getParameterValues: "query_param",
  getParameterMap: "query_param",
  getQueryString: "query_param",
  getHeader: "request_header",
  getHeaders: "request_header",
  getCookies: "cookie",
};

const SQL_EXEC_METHODS = new Set([
  "executeQuery",
  "executeUpdate",
  "executeLargeUpdate",
  "execute",
  "query",
  "queryForObject",
  "queryForList",
  "queryForMap",
  "update",
]);
const JPQL_METHODS = new Set(["createQuery", "createNativeQuery", "createNamedQuery"]);

function own<T>(map: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(map, key) ? map[key] : undefined;
}

/** Sink kind for a `method_invocation` whose FIRST argument is the tainted one. */
function sinkKindOfMethodCall(name: string, objectText: string): TaintSinkKind | undefined {
  if (SQL_EXEC_METHODS.has(name)) return "sql_query";
  if (JPQL_METHODS.has(name)) return "orm_raw_query";
  if (name === "exec" && /getRuntime\(\)$|Runtime$/.test(objectText)) return "command_exec";
  if (name === "readObject") return "deserialize";
  if (name === "sendRedirect") return "redirect";
  if (name === "parseExpression") return "eval";
  return undefined;
}

function isConcat(node: TSNode): boolean {
  return node.type === "binary_expression" && node.text.includes("+");
}

function hasNestedInvocation(node: TSNode): boolean {
  return descendantsOfType(node, "method_invocation").length > 0;
}

/** Bare identifier === paramName, or a `+`-concatenation referencing it with
 * no nested method call in between. */
function isCleanParamUse(argExpr: TSNode, paramName: string): boolean {
  if (argExpr.type === "identifier") return argExpr.text === paramName;
  if (isConcat(argExpr)) {
    if (hasNestedInvocation(argExpr)) return false;
    return descendantsOfType(argExpr, "identifier").some((id) => id.text === paramName);
  }
  return false;
}

function firstArg(call: TSNode): TSNode | undefined {
  const args = field(call, "arguments");
  return args ? namedKids(args)[0] : undefined;
}

// --- Method cataloguing --------------------------------------------------------

interface SinkHit {
  kind: TaintSinkKind;
  line: number;
  description: string;
}

interface MethodProfile {
  name: string;
  className: string;
  file: string;
  line: number;
  node: TSNode;
  paramNames: Array<string | undefined>;
  sinksByParam: Map<number, SinkHit>;
  returnsParam: Set<number>;
}

/** Trackable formal-parameter name (varargs/spread params are skipped). */
function formalParamName(p: TSNode): string | undefined {
  if (p.type !== "formal_parameter") return undefined;
  return field(p, "name")?.text;
}

function paramNamesOf(method: TSNode): Array<string | undefined> {
  const params = field(method, "parameters");
  if (!params) return [];
  return namedKids(params).map(formalParamName);
}

function enclosingMethod(node: TSNode): TSNode | undefined {
  let cur = node.parent;
  while (cur) {
    if (cur.type === "method_declaration") return cur;
    cur = cur.parent;
  }
  return undefined;
}

/** Which of a method's OWN parameters carry a Spring source annotation. */
function sourceParamsOf(method: TSNode): Map<string, TaintSourceKind> {
  const out = new Map<string, TaintSourceKind>();
  const params = field(method, "parameters");
  if (!params) return out;
  for (const p of namedKids(params)) {
    if (p.type !== "formal_parameter") continue;
    const name = field(p, "name")?.text;
    if (!name) continue;
    for (const ann of annotationsOf(p)) {
      const kind = own(SOURCE_ANNOTATION_KIND, ann.name);
      if (kind) {
        out.set(name, kind);
        break;
      }
    }
  }
  return out;
}

/** Is `argExpr` itself a source-shaped expression (an inline request getter call)? */
function inlineSourceKind(argExpr: TSNode): TaintSourceKind | undefined {
  if (argExpr.type !== "method_invocation") return undefined;
  const name = field(argExpr, "name")?.text ?? "";
  const objectText = field(argExpr, "object")?.text ?? "";
  const kind = own(REQUEST_GETTER_KIND, name);
  if (!kind) return undefined;
  const lower = objectText.toLowerCase();
  return lower.includes("request") || lower === "req" ? kind : undefined;
}

/** Scan one method's body for (a) params landing directly in a sink call's
 * first argument, and (b) params returned untouched. */
function analyzeMethod(
  method: TSNode,
  paramNames: Array<string | undefined>,
): { sinksByParam: Map<number, SinkHit>; returnsParam: Set<number> } {
  const sinksByParam = new Map<number, SinkHit>();
  const returnsParam = new Set<number>();
  const body = field(method, "body");
  if (!body) return { sinksByParam, returnsParam };

  for (const call of descendantsOfType(body, "method_invocation")) {
    if (!sameNode(enclosingMethod(call), method)) continue; // skip nested lambdas
    const name = field(call, "name")?.text ?? "";
    const objectText = field(call, "object")?.text ?? "";
    const sinkKind = sinkKindOfMethodCall(name, objectText);
    if (!sinkKind) continue;
    const arg0 = firstArg(call);
    if (!arg0) continue;
    paramNames.forEach((pname, idx) => {
      if (pname && !sinksByParam.has(idx) && isCleanParamUse(arg0, pname)) {
        const line = isConcat(arg0) ? lineOf(arg0) : lineOf(call);
        sinksByParam.set(idx, { kind: sinkKind, line, description: `${objectText}.${name}(...)` });
      }
    });
  }

  for (const ret of descendantsOfType(body, "return_statement")) {
    if (!sameNode(enclosingMethod(ret), method)) continue;
    const expr = namedKids(ret)[0];
    if (!expr) continue;
    paramNames.forEach((pname, idx) => {
      if (pname && isCleanParamUse(expr, pname)) returnsParam.add(idx);
    });
  }

  return { sinksByParam, returnsParam };
}

interface ClassCatalog {
  className: string;
  methods: Map<string, MethodProfile>;
}

function catalogClass(cls: TSNode, rel: string): ClassCatalog {
  const className = field(cls, "name")?.text ?? "";
  const methods = new Map<string, MethodProfile>();
  const body = field(cls, "body");
  if (body) {
    for (const method of namedKids(body).filter((c) => c.type === "method_declaration")) {
      const name = field(method, "name")?.text;
      if (!name || methods.has(name)) continue; // first-wins on overloads
      const paramNames = paramNamesOf(method);
      const { sinksByParam, returnsParam } = analyzeMethod(method, paramNames);
      methods.set(name, {
        name,
        className,
        file: rel,
        line: lineOf(method),
        node: method,
        paramNames,
        sinksByParam,
        returnsParam,
      });
    }
  }
  return { className, methods };
}

// --- Tainted-argument detection at a call site --------------------------------

interface TaintedArg {
  location: { file: string; line: number };
  kind: TaintSourceKind | undefined;
}

function taintOfArg(
  argExpr: TSNode,
  rel: string,
  enclosingSources: Map<string, TaintSourceKind>,
): TaintedArg | undefined {
  const inline = inlineSourceKind(argExpr);
  if (inline) return { location: { file: rel, line: lineOf(argExpr) }, kind: inline };
  if (argExpr.type !== "identifier") return undefined;
  const kind = enclosingSources.get(argExpr.text);
  if (!kind) return undefined;
  return { location: { file: rel, line: lineOf(argExpr) }, kind };
}

/** The direct child-of-block statement that (transitively) contains `node`. */
function enclosingBlockStatement(node: TSNode): TSNode | undefined {
  let cur: TSNode = node;
  for (;;) {
    const parent = cur.parent;
    if (!parent) return undefined;
    if (parent.type === "block") return cur;
    cur = parent;
  }
}

function findLaterSinkUse(
  statements: TSNode[],
  fromIdx: number,
  varName: string,
): SinkHit | undefined {
  for (let i = fromIdx; i < statements.length; i++) {
    const stmt = statements[i];
    if (!stmt) continue;
    for (const call of descendantsOfType(stmt, "method_invocation")) {
      const name = field(call, "name")?.text ?? "";
      const objectText = field(call, "object")?.text ?? "";
      const kind = sinkKindOfMethodCall(name, objectText);
      if (!kind) continue;
      const arg0 = firstArg(call);
      if (arg0 && isCleanParamUse(arg0, varName)) {
        const line = isConcat(arg0) ? lineOf(arg0) : lineOf(call);
        return { kind, line, description: `${objectText}.${name}(...)` };
      }
    }
  }
  return undefined;
}

/** Is `call` itself the exact first argument of an outer sink call (`sink(call(...))`)? */
function outerSinkWrapping(call: TSNode): SinkHit | undefined {
  const argList = call.parent;
  if (!argList || argList.type !== "argument_list") return undefined;
  const outer = argList.parent;
  if (!outer || outer.type !== "method_invocation") return undefined;
  const arg0 = firstArg(outer);
  if (!sameNode(arg0, call)) return undefined;
  const name = field(outer, "name")?.text ?? "";
  const objectText = field(outer, "object")?.text ?? "";
  const kind = sinkKindOfMethodCall(name, objectText);
  if (!kind) return undefined;
  return { kind, line: lineOf(outer), description: `${objectText}.${name}(...)` };
}

// --- Entry point ---------------------------------------------------------------

export interface JavaFileForCallgraph {
  rel: string;
  root: TSNode;
}

/**
 * Resolve bounded 1-2 hop interprocedural taint flows across a Java project.
 * See the module doc comment for the exact patterns handled — and, just as
 * importantly, those explicitly NOT handled (tier (c) cross-file is NOT
 * attempted for Java — see the doc comment for why).
 */
export function scanJavaTaintFlows(files: JavaFileForCallgraph[]): TaintFlowEdge[] {
  // Per-file class catalogues, and a same-file class-name -> catalogue index
  // (for the tier-(b) same-file cross-class static-style resolution).
  const classesByFile = new Map<string, ClassCatalog[]>();
  for (const f of files) {
    const classes = descendantsOfType(f.root, "class_declaration").map((cls) =>
      catalogClass(cls, f.rel),
    );
    classesByFile.set(f.rel, classes);
  }

  const edges: TaintFlowEdge[] = [];

  for (const f of files) {
    const classes = classesByFile.get(f.rel) ?? [];

    for (const cls of descendantsOfType(f.root, "class_declaration")) {
      const ownCatalog = classes.find((c) => c.className === (field(cls, "name")?.text ?? ""));
      if (!ownCatalog) continue;

      for (const call of descendantsOfType(cls, "method_invocation")) {
        const callerMethod = enclosingMethod(call);
        if (!callerMethod) continue; // only calls made from inside a method are tracked
        // Restrict traversal to calls textually inside THIS class's own
        // methods (nested classes get their own top-level loop iteration).
        if (!sameNode(enclosingClass(call), cls)) continue;

        const objectNode = field(call, "object");
        const objectText = objectNode?.text ?? "";
        let target: MethodProfile | undefined;
        if (!objectNode || objectText === "this") {
          target = ownCatalog.methods.get(field(call, "name")?.text ?? "");
        } else {
          // Same-file, cross-class, STATIC-STYLE resolution only (see doc
          // comment): the object text must literally equal another class
          // declared in this same file.
          const other = classes.find((c) => c.className === objectText && c !== ownCatalog);
          if (other) target = other.methods.get(field(call, "name")?.text ?? "");
        }
        if (!target) continue;

        const enclosingSources = sourceParamsOf(callerMethod);
        const argsNode = field(call, "arguments");
        const args = argsNode ? namedKids(argsNode) : [];
        for (let i = 0; i < args.length; i++) {
          const argExpr = args[i];
          if (!argExpr) continue;
          const tainted = taintOfArg(argExpr, f.rel, enclosingSources);
          if (!tainted) continue;

          const direct = target.sinksByParam.get(i);
          if (direct) {
            edges.push({
              sourceLocation: tainted.location,
              ...(tainted.kind ? { sourceKind: tainted.kind } : {}),
              throughFunction: `${target.className}.${target.name}`,
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
                throughFunction: `${target.className}.${target.name}`,
                throughLocation: { file: target.file, line: target.line },
                sinkLocation: { file: f.rel, line: wrapped.line },
                sinkKind: wrapped.kind,
                resolution: "return-propagated",
                hops: 2,
                crossFile: tainted.location.file !== f.rel,
              });
              continue;
            }

            const declStmt = enclosingBlockStatement(call);
            if (declStmt?.type === "local_variable_declaration") {
              const declarator = namedKids(declStmt).find((c) => c.type === "variable_declarator");
              const nameNode = declarator ? field(declarator, "name") : undefined;
              if (nameNode) {
                const block = declStmt.parent;
                const statements = block && block.type === "block" ? namedKids(block) : [];
                const idx = statements.findIndex((s) => sameNode(s, declStmt));
                if (idx >= 0) {
                  const later = findLaterSinkUse(statements, idx + 1, nameNode.text);
                  if (later) {
                    edges.push({
                      sourceLocation: tainted.location,
                      ...(tainted.kind ? { sourceKind: tainted.kind } : {}),
                      throughFunction: `${target.className}.${target.name}`,
                      throughLocation: { file: target.file, line: target.line },
                      sinkLocation: { file: f.rel, line: later.line },
                      sinkKind: later.kind,
                      resolution: "return-propagated",
                      hops: 2,
                      crossFile: tainted.location.file !== f.rel,
                    });
                  }
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

function enclosingClass(node: TSNode): TSNode | undefined {
  let cur = node.parent;
  while (cur) {
    if (cur.type === "class_declaration") return cur;
    cur = cur.parent;
  }
  return undefined;
}
