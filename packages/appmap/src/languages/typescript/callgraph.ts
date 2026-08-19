/**
 * Bounded interprocedural taint-flow resolution (TS/JS only).
 *
 * `taint.ts` finds taint SOURCES and SINKS syntactically, one file at a time —
 * it has no notion of a call graph, so a source in file A that only reaches a
 * sink after passing through a helper function declared in file B is invisible
 * to it, and to `packages/correlation/src/grounding.ts`'s same-file nearest-
 * line heuristic that consumes it. This module is a narrow, EXPLICIT extension
 * that resolves a bounded set of interprocedural patterns using the same
 * ts-morph AST `taint.ts` already parses, by following actual `import`
 * specifiers to the file that declares the imported identifier (the Project
 * has every source file added, so this is real file-to-file resolution — see
 * `sources.ts` for why full TS module/type resolution is deliberately
 * disabled: this module does its OWN lightweight specifier resolution instead
 * of relying on the type checker).
 *
 * ============================================================================
 * WHAT THIS RESOLVES (honestly, this is the full list — nothing broader):
 * ============================================================================
 *
 *   1. DIRECT PASS-THROUGH (1 hop, may cross a file boundary):
 *        call site  `helper(<tainted-looking arg>)`
 *        callee     `function helper(x) { ...sink(x)... }`   // same or another file
 *      `helper` must resolve to a top-level `function` declaration or a
 *      top-level `const helper = (x) => ...` / `function (x) {...}` — via
 *      either a same-file lookup or a local (`./`, `../`) `import { helper }`
 *      specifier. The parameter must reach the sink's first argument either
 *      as a bare reference or interpolated into a template/concatenation with
 *      NOTHING else called on it in between (so nothing sanitizer-shaped can
 *      be silently skipped).
 *
 *   2. RETURN-PROPAGATED (2 hops, may cross a file boundary):
 *        callee returns the tainted parameter untouched:
 *          `function helper(x) { return x; }`
 *        and the CALL SITE's use of the result reaches a sink one step later:
 *          either  `sink(helper(taintedArg))`                      (wrapped)
 *          or      `const y = helper(taintedArg); ...; sink(y);`   (assigned,
 *                  sink call must be a LATER statement in the SAME enclosing
 *                  block)
 *
 * A "tainted-looking arg" is either a source-shaped expression directly at the
 * call site (`req.query.id`, `searchParams.get(...)`, ...), or a bare
 * identifier whose nearest preceding `const`/`let` in the same block assigns
 * it a source-shaped expression. No deeper alias chains are attempted.
 *
 * ============================================================================
 * WHAT THIS explicitly DOES NOT RESOLVE (out of scope, by design):
 * ============================================================================
 *   - Dynamic dispatch / higher-order functions: `obj[key](x)`, a function
 *     passed as a callback and invoked indirectly, `.call`/`.apply`/`.bind`.
 *   - Class methods / `this.foo()` / any method-call chain (`a.b.c(x)`).
 *   - Re-exports through barrel files (`export * from "./x"` or
 *     `export { helper } from "./x"` without a local declaration) — only a
 *     DIRECT import of a locally declared top-level function/const is
 *     resolved.
 *   - Bare-specifier imports (npm packages) — only relative (`./`, `../`)
 *     specifiers are resolved.
 *   - Closures capturing a tainted variable from an OUTER scope — only
 *     explicit parameters are tracked.
 *   - Chains longer than 2 hops (helper calling a second helper calling a
 *     third).
 *   - Destructured / rest / default-valued parameters (only a plain
 *     identifier parameter is tracked; others are silently skipped for that
 *     position).
 *   - Default exports (`export default function ...`) — only named
 *     declarations are catalogued, to avoid guessing at anonymous-export
 *     identity.
 *   - Sinks that aren't a bare call expression's first argument (so
 *     `dangerouslySetInnerHTML={...}` / `el.innerHTML = ...` are not chased
 *     interprocedurally — only the call-expression sink kinds are).
 *
 * When any of the above is hit, resolution simply yields no edge for that call
 * site. It is NOT a claim that no flow exists — `grounding.ts` keeps its
 * existing same-file proximity heuristic as the fallback for everything this
 * module does not resolve.
 */
import { posix as posixPath } from "node:path";
import { Node, SyntaxKind } from "ts-morph";
import type {
  ArrowFunction,
  CallExpression,
  FunctionDeclaration,
  FunctionExpression,
  Project,
  SourceFile,
} from "ts-morph";
import type { TaintFlowEdge, TaintSinkKind, TaintSourceKind } from "@montr/contracts";

function posix(p: string): string {
  return p.replace(/\\/g, "/");
}
function relPath(abs: string, dir: string): string {
  return posix(abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs);
}

// --- Source/sink pattern matching -------------------------------------------
// Deliberately duplicated (not imported) from taint.ts's small regex tables:
// this module analyzes ARGUMENT expressions inside arbitrary function bodies
// (a different traversal shape than taint.ts's flat per-file scan), and
// keeping the two independent avoids a risky refactor of the existing,
// already-relied-upon same-file scanner. Keep the patterns in sync by hand.

const REQ_PROP_KIND: Record<string, TaintSourceKind> = {
  query: "query_param",
  body: "request_body",
  params: "path_param",
  headers: "request_header",
  cookies: "cookie",
};

/** Is `node` itself a source-shaped expression (same shapes taint.ts's scanSources finds)? */
function sourceKindOfExpr(node: Node): TaintSourceKind | undefined {
  if (Node.isCallExpression(node)) {
    const callee = node.getExpression().getText();
    if (/\.searchParams\.get$/.test(callee) || /(^|\.)searchParams\.getAll$/.test(callee)) {
      return "query_param";
    }
    if (/^(req|request)\.(json|formData|text)$/.test(callee)) return "request_body";
    if (/\bcookies\(\)\.get$/.test(callee)) return "cookie";
    if (/\bheaders\(\)\.get$/.test(callee)) return "request_header";
    return undefined;
  }
  if (Node.isPropertyAccessExpression(node)) {
    const exprText = node.getExpression().getText();
    const name = node.getName();
    if (exprText === "searchParams" && name !== "get" && name !== "getAll") return "query_param";
    if (/^(req|request|ctx\.req)$/.test(exprText)) return REQ_PROP_KIND[name];
  }
  return undefined;
}

/** Sink kind for a call-expression whose FIRST argument is the tainted-relevant one. */
function sinkKindOfCallee(callee: string): TaintSinkKind | undefined {
  if (/\.\$(queryRawUnsafe|executeRawUnsafe|queryRaw|executeRaw)$/.test(callee)) {
    return "orm_raw_query";
  }
  if (/(^|\.)query$/.test(callee)) return "sql_query";
  if (/(^|\.)(exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(callee)) {
    return "command_exec";
  }
  if (/(^|\.)(writeFile|writeFileSync|appendFile|appendFileSync)$/.test(callee)) return "fs_write";
  if (/(^|\.)(readFile|readFileSync|createReadStream)$/.test(callee)) return "fs_read";
  if (callee === "eval") return "eval";
  if (/(^|\.)redirect$/.test(callee)) return "redirect";
  if (/(^|\.)(unserialize|deserialize)$/.test(callee)) return "deserialize";
  if (/(^|\.)render$/.test(callee) && /^(res|response|ctx)\./.test(callee))
    return "template_render";
  return undefined;
}

function isTemplateOrConcat(node: Node): boolean {
  const k = node.getKind();
  return (
    k === SyntaxKind.TemplateExpression ||
    k === SyntaxKind.NoSubstitutionTemplateLiteral ||
    k === SyntaxKind.BinaryExpression
  );
}

/**
 * True when `argExpr` is exactly the identifier `paramName`, or a
 * template/concat expression that references `paramName` and contains no
 * nested call (so nothing sanitizer-shaped — or anything else — sits between
 * the parameter and the sink).
 */
function isCleanParamUse(argExpr: Node, paramName: string): boolean {
  if (Node.isIdentifier(argExpr)) return argExpr.getText() === paramName;
  if (isTemplateOrConcat(argExpr)) {
    const hasCall = argExpr.getDescendantsOfKind(SyntaxKind.CallExpression).length > 0;
    if (hasCall) return false;
    return argExpr
      .getDescendantsOfKind(SyntaxKind.Identifier)
      .some((id) => id.getText() === paramName);
  }
  return false;
}

// --- Function cataloguing ----------------------------------------------------

type FnLike = FunctionDeclaration | ArrowFunction | FunctionExpression;

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

function paramNamesOf(fn: FnLike): Array<string | undefined> {
  return fn.getParameters().map((p) => {
    const nameNode = p.getNameNode();
    return Node.isIdentifier(nameNode) ? nameNode.getText() : undefined;
  });
}

/** Nearest enclosing function-like ancestor (used to keep analysis from
 * bleeding into a NESTED closure's body — closures are explicitly out of scope). */
function enclosingFnLike(node: Node): Node | undefined {
  return node.getFirstAncestor(
    (a) => Node.isFunctionDeclaration(a) || Node.isArrowFunction(a) || Node.isFunctionExpression(a),
  );
}

/** Scan one function's body for (a) params landing directly in a sink call's
 * first argument, and (b) params returned untouched. */
function analyzeFunction(
  fn: FnLike,
  paramNames: Array<string | undefined>,
): {
  sinksByParam: Map<number, SinkHit>;
  returnsParam: Set<number>;
} {
  const sinksByParam = new Map<number, SinkHit>();
  const returnsParam = new Set<number>();
  const body = fn.getBody();
  if (!body) return { sinksByParam, returnsParam };

  const checkReturnExpr = (expr: Node | undefined): void => {
    if (!expr) return;
    paramNames.forEach((pname, idx) => {
      if (pname && isCleanParamUse(expr, pname)) returnsParam.add(idx);
    });
  };

  const checkSinkCall = (call: CallExpression): void => {
    const callee = call.getExpression().getText();
    const sinkKind = sinkKindOfCallee(callee);
    if (!sinkKind) return;
    const arg0 = call.getArguments()[0];
    if (!arg0) return;
    paramNames.forEach((pname, idx) => {
      if (pname && !sinksByParam.has(idx) && isCleanParamUse(arg0, pname)) {
        const line = isTemplateOrConcat(arg0)
          ? arg0.getStartLineNumber()
          : call.getStartLineNumber();
        sinksByParam.set(idx, { kind: sinkKind, line, description: `${callee}(...)` });
      }
    });
  };

  if (Node.isBlock(body)) {
    for (const call of body.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (enclosingFnLike(call) !== fn) continue; // skip nested closures
      checkSinkCall(call);
    }
    for (const ret of body.getDescendantsOfKind(SyntaxKind.ReturnStatement)) {
      if (enclosingFnLike(ret) !== fn) continue;
      checkReturnExpr(ret.getExpression());
    }
  } else {
    // Expression-bodied arrow: the expression IS an implicit return, and may
    // itself be a direct sink call.
    if (Node.isCallExpression(body)) checkSinkCall(body);
    checkReturnExpr(body);
  }

  return { sinksByParam, returnsParam };
}

/** Catalogue every top-level named function/const-arrow in a file. Nested and
 * anonymous/default-exported functions are intentionally not catalogued. */
function catalogFunctions(sf: SourceFile, rel: string): Map<string, FunctionProfile> {
  const out = new Map<string, FunctionProfile>();

  for (const fn of sf.getFunctions()) {
    const name = fn.getName();
    if (!name) continue;
    const paramNames = paramNamesOf(fn);
    const { sinksByParam, returnsParam } = analyzeFunction(fn, paramNames);
    out.set(name, {
      name,
      file: rel,
      line: fn.getStartLineNumber(),
      paramNames,
      sinksByParam,
      returnsParam,
    });
  }

  for (const stmt of sf.getVariableStatements()) {
    for (const decl of stmt.getDeclarations()) {
      const init = decl.getInitializer();
      if (!init || (!Node.isArrowFunction(init) && !Node.isFunctionExpression(init))) continue;
      const nameNode = decl.getNameNode();
      if (!Node.isIdentifier(nameNode)) continue;
      const name = nameNode.getText();
      const paramNames = paramNamesOf(init);
      const { sinksByParam, returnsParam } = analyzeFunction(init, paramNames);
      out.set(name, {
        name,
        file: rel,
        line: decl.getStartLineNumber(),
        paramNames,
        sinksByParam,
        returnsParam,
      });
    }
  }

  return out;
}

// --- Local import resolution -------------------------------------------------

interface ImportEntry {
  importedName: string;
  fromFile: string;
}

/** Resolve a relative import specifier to a repo-relative file already in `allFiles`. */
function resolveRelativeImport(
  fromFile: string,
  spec: string,
  allFiles: ReadonlySet<string>,
): string | undefined {
  const fromDir = fromFile.includes("/") ? fromFile.slice(0, fromFile.lastIndexOf("/")) : "";
  const joined = posix(posixPath.normalize(posixPath.join(fromDir, spec)));
  const candidates = [
    joined,
    `${joined}.ts`,
    `${joined}.tsx`,
    `${joined}.js`,
    `${joined}.jsx`,
    `${joined}.mjs`,
    `${joined}.cjs`,
    `${joined}/index.ts`,
    `${joined}/index.tsx`,
    `${joined}/index.js`,
    `${joined}/index.jsx`,
  ];
  return candidates.find((c) => allFiles.has(c));
}

/** Named-import map for one file: local identifier -> where it's really declared. */
function buildImportMap(
  sf: SourceFile,
  rel: string,
  allFiles: ReadonlySet<string>,
): Map<string, ImportEntry> {
  const map = new Map<string, ImportEntry>();
  for (const imp of sf.getImportDeclarations()) {
    const spec = imp.getModuleSpecifierValue();
    if (!spec.startsWith(".")) continue; // bare/package imports are out of scope
    const resolved = resolveRelativeImport(rel, spec, allFiles);
    if (!resolved) continue;
    for (const named of imp.getNamedImports()) {
      const local = named.getAliasNode()?.getText() ?? named.getNameNode().getText();
      const importedName = named.getNameNode().getText();
      map.set(local, { importedName, fromFile: resolved });
    }
  }
  return map;
}

// --- Tainted-argument detection at a call site --------------------------------

interface TaintedArg {
  location: { file: string; line: number };
  kind: TaintSourceKind | undefined;
}

/** The direct-child-of-block statement that (transitively) contains `node`. */
function enclosingStatement(node: Node): Node | undefined {
  let cur: Node = node;
  for (;;) {
    const parent = cur.getParent();
    if (!parent) return undefined;
    if (Node.isBlock(parent) || Node.isSourceFile(parent)) return cur;
    cur = parent;
  }
}

/** Is this call-site argument tainted, and if so where does the taint originate? */
function taintOfArg(argExpr: Node, rel: string): TaintedArg | undefined {
  const direct = sourceKindOfExpr(argExpr);
  if (direct) {
    return { location: { file: rel, line: argExpr.getStartLineNumber() }, kind: direct };
  }
  if (!Node.isIdentifier(argExpr)) return undefined;

  // One-level backward alias: `const name = <source-expr>` earlier in the same block.
  const name = argExpr.getText();
  const stmt = enclosingStatement(argExpr);
  if (!stmt) return undefined;
  const block = stmt.getParent();
  if (!block || !(Node.isBlock(block) || Node.isSourceFile(block))) return undefined;
  const statements = block.getStatements();
  const idx = statements.findIndex((s) => s === stmt);
  if (idx < 0) return undefined;

  for (let i = idx - 1; i >= 0; i--) {
    const s = statements[i];
    if (!s || !Node.isVariableStatement(s)) continue;
    for (const decl of s.getDeclarations()) {
      const declName = decl.getNameNode();
      if (!Node.isIdentifier(declName) || declName.getText() !== name) continue;
      const init = decl.getInitializer();
      if (!init) continue;
      const kind = sourceKindOfExpr(init);
      if (kind) return { location: { file: rel, line: init.getStartLineNumber() }, kind };
    }
  }
  return undefined;
}

/** Find a sink call in `statements` (index >= `fromIdx`) whose first argument
 * is a clean reference to `varName`. Used for the return-propagated 2nd hop. */
function findLaterSinkUse(
  statements: Node[],
  fromIdx: number,
  varName: string,
): SinkHit | undefined {
  for (let i = fromIdx; i < statements.length; i++) {
    const stmt = statements[i];
    if (!stmt) continue;
    for (const call of stmt.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression().getText();
      const kind = sinkKindOfCallee(callee);
      if (!kind) continue;
      const arg0 = call.getArguments()[0];
      if (arg0 && isCleanParamUse(arg0, varName)) {
        const line = isTemplateOrConcat(arg0)
          ? arg0.getStartLineNumber()
          : call.getStartLineNumber();
        return { kind, line, description: `${callee}(...)` };
      }
    }
  }
  return undefined;
}

/** Is `call` itself the exact first argument of an outer sink call (`sink(call(...))`)? */
function outerSinkWrapping(call: CallExpression): SinkHit | undefined {
  const parent = call.getParent();
  if (!parent || !Node.isCallExpression(parent)) return undefined;
  const arg0 = parent.getArguments()[0];
  if (arg0 !== call) return undefined;
  const callee = parent.getExpression().getText();
  const kind = sinkKindOfCallee(callee);
  if (!kind) return undefined;
  return { kind, line: parent.getStartLineNumber(), description: `${callee}(...)` };
}

// --- Entry point ---------------------------------------------------------------

/**
 * Resolve bounded 1-2 hop interprocedural taint flows across the project. See
 * the module doc comment for the exact patterns handled and, just as
 * importantly, the patterns explicitly NOT handled.
 */
export function scanTaintFlows(project: Project, dir: string): TaintFlowEdge[] {
  const sourceFiles = project.getSourceFiles();
  const relByFile = new Map<SourceFile, string>();
  const allFiles = new Set<string>();
  for (const sf of sourceFiles) {
    const rel = relPath(sf.getFilePath(), dir);
    relByFile.set(sf, rel);
    allFiles.add(rel);
  }

  const functionsByFile = new Map<string, Map<string, FunctionProfile>>();
  const importsByFile = new Map<string, Map<string, ImportEntry>>();
  for (const sf of sourceFiles) {
    const rel = relByFile.get(sf);
    if (!rel) continue;
    functionsByFile.set(rel, catalogFunctions(sf, rel));
    importsByFile.set(rel, buildImportMap(sf, rel, allFiles));
  }

  const edges: TaintFlowEdge[] = [];

  for (const sf of sourceFiles) {
    const rel = relByFile.get(sf);
    if (!rel) continue;
    const localFns = functionsByFile.get(rel);
    const imports = importsByFile.get(rel);

    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression();
      if (!Node.isIdentifier(callee)) continue; // no dynamic dispatch / method chains
      const name = callee.getText();

      let target = localFns?.get(name);
      if (!target) {
        const entry = imports?.get(name);
        if (entry) target = functionsByFile.get(entry.fromFile)?.get(entry.importedName);
      }
      if (!target) continue;

      const args = call.getArguments();
      for (let i = 0; i < args.length; i++) {
        const argExpr = args[i];
        if (!argExpr) continue;
        const tainted = taintOfArg(argExpr, rel);
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
              sinkLocation: { file: rel, line: wrapped.line },
              sinkKind: wrapped.kind,
              resolution: "return-propagated",
              hops: 2,
              crossFile: tainted.location.file !== rel,
            });
            continue;
          }

          // `const y = helper(taintedArg); ...; sink(y);` — later statement, same block.
          const declStmt = call.getFirstAncestorByKind(SyntaxKind.VariableStatement);
          const varDecl = call.getFirstAncestorByKind(SyntaxKind.VariableDeclaration);
          if (declStmt && varDecl) {
            const nameNode = varDecl.getNameNode();
            if (Node.isIdentifier(nameNode)) {
              const block = declStmt.getParent();
              const statements =
                block && (Node.isBlock(block) || Node.isSourceFile(block))
                  ? block.getStatements()
                  : [];
              const idx = statements.findIndex((s) => s === declStmt);
              if (idx >= 0) {
                const later = findLaterSinkUse(statements, idx + 1, nameNode.getText());
                if (later) {
                  edges.push({
                    sourceLocation: tainted.location,
                    ...(tainted.kind ? { sourceKind: tainted.kind } : {}),
                    throughFunction: target.name,
                    throughLocation: { file: target.file, line: target.line },
                    sinkLocation: { file: rel, line: later.line },
                    sinkKind: later.kind,
                    resolution: "return-propagated",
                    hops: 2,
                    crossFile: tainted.location.file !== rel,
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
