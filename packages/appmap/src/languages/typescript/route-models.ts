/**
 * Route → ORM-model cross-reference (A18 — prerequisite for IDOR / broken-
 * access-control reasoning: you can't reason about "which records does this
 * route touch, and whose are they" without first knowing which model(s) a
 * route handler actually queries).
 *
 * Operates generically on the FINAL merged `Route[]` + each route's handler
 * function node (collected by `routes.ts`/`express.ts`/`fastify.ts` into
 * `handlersByRouteId`, regardless of which of those three produced the
 * route) — so this one pass covers every TS/JS framework this analyzer
 * supports without each route scanner reimplementing it.
 *
 * RESOLUTION DEPTH (mirrors `callgraph.ts`'s own bounded-hop convention):
 *   - Direct: a `prisma.<model>.<crudMethod>(...)` (or `this.prisma...`) call
 *     literally inside the handler body.
 *   - One hop: the handler calls a LOCAL function by a bare identifier — a
 *     top-level `function`/const-arrow declared in the SAME file, or reached
 *     via a RELATIVE (`./`, `../`) import — and THAT function's body contains
 *     a direct `prisma.<model>.<crudMethod>(...)` call.
 *
 * NOT resolved (by design, same boundary `callgraph.ts` documents):
 *   - Method-call chains (`a.b.c(x)`) — so a repository-pattern indirection
 *     like `store.scans.get(...)` calling into a `ScanRepo` CLASS METHOD that
 *     itself does `this.prisma.scan.findFirst(...)` is NOT traced: that is a
 *     property-access-then-method-call, not a plain identifier call to a
 *     top-level function, and this package's ts-morph `Project` has type
 *     checking deliberately disabled (`sources.ts`), so there's no static way
 *     to know what type `store.scans` is without it.
 *   - Bare/workspace package specifiers (`@montr/state-store`, `express`, …)
 *     — only relative imports are followed, same as `callgraph.ts`.
 *   - Raw queries (`$queryRaw`/`$executeRaw`/`Unsafe` variants) — these are
 *     called on the client directly (not scoped to a model), so there is no
 *     static model name to attribute without parsing the SQL string, which is
 *     out of scope.
 */
import { posix as posixPath } from "node:path";
import { Node, SyntaxKind } from "ts-morph";
import type { Project, SourceFile } from "ts-morph";
import type { OrmModel, Route, RouteModelOperation, RouteModelRef } from "@montr/contracts";
import type { FnLike } from "./routes.js";

/** Prisma CRUD method name → coarse read/write/delete bucket (model-scoped
 * methods only — `$queryRaw`/`$executeRaw` are client-scoped, not handled here). */
const PRISMA_OPERATIONS: Record<string, RouteModelOperation> = {
  findMany: "read",
  findFirst: "read",
  findFirstOrThrow: "read",
  findUnique: "read",
  findUniqueOrThrow: "read",
  count: "read",
  aggregate: "read",
  groupBy: "read",
  create: "write",
  createMany: "write",
  createManyAndReturn: "write",
  update: "write",
  updateMany: "write",
  updateManyAndReturn: "write",
  upsert: "write",
  delete: "delete",
  deleteMany: "delete",
};

const MODEL_CALL_RE = /(?:^|\.)prisma\.(\w+)\.(\w+)$/;

function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}
function relPath(abs: string, dir: string): string {
  return posix(abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs);
}

/** `Model` (PascalCase, as Prisma DMMF names it) → `model` (the client property name). */
function toClientProperty(modelName: string): string {
  return modelName.length > 0 ? modelName[0]!.toLowerCase() + modelName.slice(1) : modelName;
}

function matchModelCall(
  calleeText: string,
  camelToModel: ReadonlyMap<string, string>,
): { modelName: string; operation: RouteModelOperation } | undefined {
  const m = MODEL_CALL_RE.exec(calleeText);
  if (!m) return undefined;
  const camel = m[1]!;
  const method = m[2]!;
  const modelName = camelToModel.get(camel);
  if (!modelName) return undefined;
  const operation = PRISMA_OPERATIONS[method];
  if (!operation) return undefined;
  return { modelName, operation };
}

/** Top-level named function/const-arrow declarations in one file (name → node). */
function catalogTopLevelFns(sf: SourceFile): Map<string, FnLike> {
  const out = new Map<string, FnLike>();
  for (const fn of sf.getFunctions()) {
    const name = fn.getName();
    if (name) out.set(name, fn);
  }
  for (const vs of sf.getVariableStatements()) {
    for (const decl of vs.getDeclarations()) {
      const init = decl.getInitializer();
      if (!init || (!Node.isArrowFunction(init) && !Node.isFunctionExpression(init))) continue;
      const nameNode = decl.getNameNode();
      if (!Node.isIdentifier(nameNode)) continue;
      out.set(nameNode.getText(), init);
    }
  }
  return out;
}

interface ImportEntry {
  importedName: string;
  fromFile: string;
}

/** Deliberately duplicated from `callgraph.ts` (same convention: independent
 * copies per module rather than a shared risky refactor — see its doc comment),
 * with one fix: the specifier's own extension (if any — this codebase's own
 * NodeNext/ESM convention writes `./routes.js` for a `routes.ts` source file)
 * is stripped BEFORE the extension candidates below are appended, so a `.js`-
 * suffixed specifier resolves to its `.ts` source instead of only ever
 * matching a literal `.js` file. */
function resolveRelativeImport(
  fromFile: string,
  spec: string,
  allFiles: ReadonlySet<string>,
): string | undefined {
  const fromDir = fromFile.includes("/") ? fromFile.slice(0, fromFile.lastIndexOf("/")) : "";
  const specNoExt = spec.replace(/\.(m|c)?jsx?$/i, "");
  const joined = posix(posixPath.normalize(posixPath.join(fromDir, specNoExt)));
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

function resolveLocalFn(
  name: string,
  fromFile: string,
  fnsByFile: ReadonlyMap<string, Map<string, FnLike>>,
  importsByFile: ReadonlyMap<string, Map<string, ImportEntry>>,
): FnLike | undefined {
  const local = fnsByFile.get(fromFile)?.get(name);
  if (local) return local;
  const entry = importsByFile.get(fromFile)?.get(name);
  if (!entry) return undefined;
  return fnsByFile.get(entry.fromFile)?.get(entry.importedName);
}

/** Every direct `prisma.<model>.<crudMethod>(...)` call inside `node`. */
function collectDirectModelCalls(
  node: Node,
  camelToModel: ReadonlyMap<string, string>,
): Array<{ modelName: string; operation: RouteModelOperation }> {
  const out: Array<{ modelName: string; operation: RouteModelOperation }> = [];
  for (const call of node.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const match = matchModelCall(call.getExpression().getText(), camelToModel);
    if (match) out.push(match);
  }
  return out;
}

/**
 * Link each route to the ORM model(s) its handler statically queries. Returns
 * a NEW `Route[]` — routes with no resolved model are returned unchanged
 * (`referencedModels` stays absent, not an empty array).
 */
export function linkRouteModels(
  project: Project,
  dir: string,
  routes: Route[],
  ormModels: OrmModel[],
  handlersByRouteId: ReadonlyMap<string, FnLike>,
): Route[] {
  if (routes.length === 0 || ormModels.length === 0 || handlersByRouteId.size === 0) return routes;

  const camelToModel = new Map<string, string>();
  for (const m of ormModels) {
    const camel = toClientProperty(m.name);
    if (!camelToModel.has(camel)) camelToModel.set(camel, m.name);
  }

  const sourceFiles = project.getSourceFiles();
  const allFiles = new Set<string>();
  for (const sf of sourceFiles) allFiles.add(relPath(sf.getFilePath(), dir));

  const fnsByFile = new Map<string, Map<string, FnLike>>();
  const importsByFile = new Map<string, Map<string, ImportEntry>>();
  for (const sf of sourceFiles) {
    const rel = relPath(sf.getFilePath(), dir);
    fnsByFile.set(rel, catalogTopLevelFns(sf));
    importsByFile.set(rel, buildImportMap(sf, rel, allFiles));
  }

  return routes.map((route) => {
    if (!route.id) return route;
    const fn = handlersByRouteId.get(route.id);
    if (!fn) return route;

    const opsByModel = new Map<string, Set<RouteModelOperation>>();
    const record = (m: { modelName: string; operation: RouteModelOperation }): void => {
      const set = opsByModel.get(m.modelName) ?? new Set<RouteModelOperation>();
      set.add(m.operation);
      opsByModel.set(m.modelName, set);
    };

    for (const m of collectDirectModelCalls(fn, camelToModel)) record(m);

    // One hop: bare-identifier calls to a local (same-file or relative-import) function.
    const handlerFile = relPath(fn.getSourceFile().getFilePath(), dir);
    for (const call of fn.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression();
      if (!Node.isIdentifier(callee)) continue;
      const target = resolveLocalFn(callee.getText(), handlerFile, fnsByFile, importsByFile);
      if (!target || target === fn) continue;
      for (const m of collectDirectModelCalls(target, camelToModel)) record(m);
    }

    if (opsByModel.size === 0) return route;
    const referencedModels: RouteModelRef[] = [...opsByModel.entries()]
      .map(([modelName, ops]) => ({ modelName, operations: [...ops].sort() }))
      .sort((a, b) => a.modelName.localeCompare(b.modelName));
    return { ...route, referencedModels };
  });
}
