/**
 * Express registered-route introspection (A17 gap-fix — companion to
 * `routes.ts`'s Next.js introspection).
 *
 * Express has no fixed instance-variable convention (`app`, `router`, `api`, a
 * destructured function parameter, ...), so matching is RECEIVER-AGNOSTIC: any
 * call shaped like `<expr>.<verb>(<path-string-literal>, ...handlers)` where
 * `<verb>` is an HTTP method name and there are >= 2 arguments (the >= 2 filter
 * rejects unrelated single-arg `.get(key)` calls — `Map#get`, a cache client,
 * config lookups — which are not route registrations). Only runs when
 * `express` is a detected framework dependency (see `sources.ts` →
 * `languages/typescript/index.ts`), which keeps the receiver-agnostic match
 * from firing on non-Express repos.
 *
 * `app.use(mountPath, router)` mounting is resolved for the common, high-
 * signal SAME-FILE case: a local `const router = express.Router()` (or a bare
 * `Router()` call, however imported) mounted in the same file has its own
 * registrations prefixed with the mount path — resolved recursively, so a
 * router mounted into another mounted router still resolves. Cross-file router
 * composition (an imported router module passed to `.use`, or `require(...)`)
 * is NOT resolved — out of scope for this pass, consistent with
 * `callgraph.ts`'s own bounded-hop philosophy (only relative-import
 * resolution is attempted elsewhere in this package, never bare specifiers);
 * those registrations still surface as their own (unprefixed) routes rather
 * than being silently dropped.
 *
 * Auth is detected the same syntactic way as `routes.ts` (guard-identifier
 * presence, same identifier list) but scoped to the CALL's own argument text
 * (options/middleware args, not the path), not the whole file — a single
 * Express router file commonly registers many routes with different guards,
 * unlike a Next.js `route.ts` file which is one route per export.
 */
import { Node, SyntaxKind } from "ts-morph";
import type { NoSubstitutionTemplateLiteral, Project, SourceFile, StringLiteral } from "ts-morph";
import type { AuthState, Entrypoint, HttpMethod, Route, SourceLocation } from "@montr/contracts";
import type { FnLike } from "./routes.js";

export interface ExpressScanResult {
  routes: Route[];
  entrypoints: Entrypoint[];
  /** file (repo-relative) → route ids whose handler lives there (source↔route link). */
  routeIdsByFile: Map<string, string[]>;
  /** route id → its handler function node, when the last call argument is function-like (A18). */
  handlersByRouteId: Map<string, FnLike>;
}

const VERB_METHODS: Record<string, HttpMethod> = {
  get: "GET",
  post: "POST",
  put: "PUT",
  patch: "PATCH",
  delete: "DELETE",
  head: "HEAD",
  options: "OPTIONS",
  all: "ALL",
};

/** Same identifier list as `routes.ts` — kept in sync by hand (duplicated,
 * not imported, so each analyzer's auth heuristic stays independently safe
 * to change — see `taint.ts`'s doc comment for the same convention). */
const AUTH_GUARD_RE =
  /\b(requireSession|requireAuth|requireUser|ensureAuthenticated|isAuthenticated|getServerSession|getSession|getToken|withAuth|currentUser|auth|protect|assertRole|checkPermission)\b/;

function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}
function relPath(abs: string, dir: string): string {
  // `dir` is a native-separator (node:path) path; ts-morph's getFilePath() is
  // always forward-slash, even on Windows. Normalize dir before comparing —
  // otherwise startsWith silently fails on Windows and every path here falls
  // through to the untouched absolute path instead of a repo-relative one.
  const posixDir = posix(dir);
  return posix(abs.startsWith(posixDir) ? abs.slice(posixDir.length).replace(/^\//, "") : abs);
}

/** Deterministic, stable route id from method + path (same slug shape as `routes.ts`). */
function routeId(method: HttpMethod, path: string): string {
  const slug = path
    .replace(/[[\]().]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `route_${method}_${slug || "root"}`;
}

function normalizePath(p: string): string {
  return p.startsWith("/") ? p : `/${p}`;
}

/** Join an accumulated mount PREFIX ("" = no mount yet) with the next path SEGMENT. */
function joinSeg(prefix: string, seg: string): string {
  const a = prefix.replace(/\/+$/, "");
  const b = seg === "/" ? "" : seg;
  const joined = `${a}${b}`;
  return joined === "" ? "/" : joined;
}

/** `express.Router(...)` or a bare `Router(...)` call (however the callee got there). */
function isRouterInit(expr: Node | undefined): boolean {
  if (!expr || !Node.isCallExpression(expr)) return false;
  return /(^|\.)Router$/.test(expr.getExpression().getText());
}

function isFnLike(n: Node | undefined): n is FnLike {
  return (
    !!n &&
    (Node.isArrowFunction(n) || Node.isFunctionExpression(n) || Node.isFunctionDeclaration(n))
  );
}

function isStringy(n: Node | undefined): n is StringLiteral | NoSubstitutionTemplateLiteral {
  return !!n && (Node.isStringLiteral(n) || Node.isNoSubstitutionTemplateLiteral(n));
}

function literalText(n: StringLiteral | NoSubstitutionTemplateLiteral): string {
  return n.getLiteralText();
}

function detectAuthFromArgs(args: Node[]): { authState: AuthState; authGate?: string } {
  const text = args.map((a) => a.getText()).join(" ");
  const m = AUTH_GUARD_RE.exec(text);
  if (m && m[1]) return { authState: "authenticated", authGate: m[1] };
  return { authState: "unknown" };
}

interface RawReg {
  receiver: string;
  method: HttpMethod;
  path: string;
  handlerLoc: SourceLocation;
  handlerFn: FnLike | undefined;
  authState: AuthState;
  authGate?: string;
}
interface RawMount {
  /** The receiver `.use` was called on (the "parent" doing the mounting). */
  container: string;
  /** The identifier text of the router being mounted. */
  mountedName: string;
  mountPath: string;
}

/** One file's raw registrations + router-variable/mount bookkeeping. */
function scanFile(
  sf: SourceFile,
  rel: string,
): { regs: RawReg[]; routerVars: Set<string>; mounts: RawMount[] } {
  const regs: RawReg[] = [];
  const routerVars = new Set<string>();
  const mounts: RawMount[] = [];

  for (const vs of sf.getVariableStatements()) {
    for (const decl of vs.getDeclarations()) {
      const nameNode = decl.getNameNode();
      if (Node.isIdentifier(nameNode) && isRouterInit(decl.getInitializer())) {
        routerVars.add(nameNode.getText());
      }
    }
  }

  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    if (!Node.isPropertyAccessExpression(callee)) continue;
    const receiver = callee.getExpression().getText();
    const name = callee.getName();
    const args = call.getArguments();

    if (name === "use") {
      const a0 = args[0];
      const a1 = args[1];
      if (args.length === 1 && a0 && Node.isIdentifier(a0)) {
        mounts.push({ container: receiver, mountedName: a0.getText(), mountPath: "/" });
      } else if (args.length >= 2 && a0 && isStringy(a0) && a1 && Node.isIdentifier(a1)) {
        mounts.push({
          container: receiver,
          mountedName: a1.getText(),
          mountPath: normalizePath(literalText(a0)),
        });
      }
      continue;
    }

    const method = VERB_METHODS[name];
    if (!method) continue;
    if (args.length < 2) continue; // reject `.get(key)`-shaped non-route calls
    const pathArg = args[0];
    if (!pathArg || !isStringy(pathArg)) continue;
    const path = normalizePath(literalText(pathArg));
    const lastArg = args[args.length - 1];
    const handlerFn = isFnLike(lastArg) ? lastArg : undefined;
    const handlerLoc: SourceLocation = {
      file: rel,
      line: handlerFn ? handlerFn.getStartLineNumber() : call.getStartLineNumber(),
    };
    const auth = detectAuthFromArgs(args.slice(1));
    regs.push({ receiver, method, path, handlerLoc, handlerFn, ...auth });
  }

  return { regs, routerVars, mounts };
}

/** Scan Express `app`/`router` route registrations across the project. */
export function scanExpressRoutes(project: Project, dir: string): ExpressScanResult {
  const routes: Route[] = [];
  const entrypoints: Entrypoint[] = [];
  const routeIdsByFile = new Map<string, string[]>();
  const handlersByRouteId = new Map<string, FnLike>();
  const seen = new Set<string>();

  for (const sf of project.getSourceFiles()) {
    const rel = relPath(sf.getFilePath(), dir);
    const { regs, routerVars, mounts } = scanFile(sf, rel);
    if (regs.length === 0) continue;

    // Same-file mount-prefix resolution (see module doc comment for scope).
    const mountEdgesByChild = new Map<string, Array<{ container: string; mountPath: string }>>();
    for (const m of mounts) {
      if (!routerVars.has(m.mountedName)) continue;
      const arr = mountEdgesByChild.get(m.mountedName) ?? [];
      arr.push({ container: m.container, mountPath: m.mountPath });
      mountEdgesByChild.set(m.mountedName, arr);
    }
    const memo = new Map<string, string[]>();
    const prefixesOf = (varName: string, visiting: Set<string>): string[] => {
      const cached = memo.get(varName);
      if (cached) return cached;
      if (visiting.has(varName)) return [""]; // cycle guard — treat as root
      visiting.add(varName);
      const incoming = mountEdgesByChild.get(varName) ?? [];
      let result: string[];
      if (incoming.length === 0) {
        result = [""];
      } else {
        const set = new Set<string>();
        for (const e of incoming) {
          for (const pp of prefixesOf(e.container, visiting)) set.add(joinSeg(pp, e.mountPath));
        }
        result = [...set];
      }
      visiting.delete(varName);
      memo.set(varName, result);
      return result;
    };

    for (const reg of regs) {
      const prefixes = prefixesOf(reg.receiver, new Set());
      for (const prefix of prefixes) {
        const finalPath = joinSeg(prefix, reg.path);
        const key = `${reg.method} ${finalPath}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const id = routeId(reg.method, finalPath);
        routes.push({
          id,
          path: finalPath,
          method: reg.method,
          authState: reg.authState,
          isApiRoute: true,
          handler: reg.handlerLoc,
          ...(reg.authGate ? { authGate: reg.authGate } : {}),
        });
        entrypoints.push({
          kind: "http_route",
          name: `${reg.method} ${finalPath}`,
          location: reg.handlerLoc,
        });
        const list = routeIdsByFile.get(rel) ?? [];
        list.push(id);
        routeIdsByFile.set(rel, list);
        if (reg.handlerFn) handlersByRouteId.set(id, reg.handlerFn);
      }
    }
  }

  routes.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  entrypoints.sort((a, b) => a.name.localeCompare(b.name));
  return { routes, entrypoints, routeIdsByFile, handlersByRouteId };
}
