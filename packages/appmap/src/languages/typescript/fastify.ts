/**
 * Fastify registered-route introspection (A17 gap-fix — companion to
 * `routes.ts`'s Next.js and `express.ts`'s Express introspection).
 *
 * Covers the two real registration shapes Fastify apps use (verified against
 * this repo's OWN `apps/api/src/routes/*.ts` — a large, real Fastify app):
 *
 *   1. `app.get/post/put/patch/delete/head/options(path, opts, handler)` and
 *      the 2-arg form `app.get(path, handler)` (no `opts`). The receiver is
 *      matched receiver-agnostically (`app`, `router`, a destructured/typed
 *      `FastifyInstance` parameter, ...) the same way `express.ts` matches —
 *      only runs when `fastify` is a detected framework dependency, so the
 *      receiver-agnostic match doesn't fire on non-Fastify repos.
 *   2. `app.route({ method, url, handler, preHandler?, ... })` — `method` may
 *      be a single string or an array of strings (Fastify supports both);
 *      `url` and the legacy `path` property alias are both accepted.
 *
 * No mount-path composition: Fastify's own nesting primitive is
 * `app.register(plugin, { prefix })`, a materially different (and more
 * dynamic — `plugin` is usually a whole function/module) shape than Express's
 * `.use(path, router)`, and is explicitly OUT of scope for this pass — prefix
 * resolution would require resolving an arbitrary plugin function's body
 * across a file boundary, which is a bigger investment than this gap-fix
 * warrants. Routes registered inside a `register()`'d plugin still surface
 * with whatever path string literal they were written with (unprefixed).
 *
 * Auth is detected the same syntactic way as `express.ts` (guard-identifier
 * presence, same identifier list) scoped to the call's own `opts`/`preHandler`
 * argument text — real Fastify auth here is a `preHandler` array
 * (`preHandler: [app.authenticate, app.requireRole(...)]`), which this
 * regex-based heuristic only catches when an identifier from the known guard
 * list is used (see `routes.ts`'s own doc comment + audit finding A20 — this
 * is an intentionally-inherited limitation, not something this pass fixes).
 */
import { Node, SyntaxKind } from "ts-morph";
import type { NoSubstitutionTemplateLiteral, Project, SourceFile, StringLiteral } from "ts-morph";
import type { AuthState, Entrypoint, HttpMethod, Route, SourceLocation } from "@montr/contracts";
import type { FnLike } from "./routes.js";

export interface FastifyScanResult {
  routes: Route[];
  entrypoints: Entrypoint[];
  /** file (repo-relative) → route ids whose handler lives there (source↔route link). */
  routeIdsByFile: Map<string, string[]>;
  /** route id → its handler function node, when statically resolvable (A18). */
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
};

/** Same identifier list as `routes.ts`/`express.ts` — kept in sync by hand. */
const AUTH_GUARD_RE =
  /\b(requireSession|requireAuth|requireUser|ensureAuthenticated|isAuthenticated|getServerSession|getSession|getToken|withAuth|currentUser|auth|protect|assertRole|checkPermission)\b/;

function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}
function relPath(abs: string, dir: string): string {
  return posix(abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs);
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
  method: HttpMethod;
  path: string;
  handlerLoc: SourceLocation;
  handlerFn: FnLike | undefined;
  authState: AuthState;
  authGate?: string;
}

/** `app.get/post/.../route(path, [opts], handler)` — the verb-method call shapes. */
function scanVerbCalls(sf: SourceFile, rel: string, out: RawReg[]): void {
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    if (!Node.isPropertyAccessExpression(callee)) continue;
    const name = callee.getName();
    const method = VERB_METHODS[name];
    if (!method) continue;
    const args = call.getArguments();
    if (args.length < 2) continue; // reject `.get(key)`-shaped non-route calls
    const pathArg = args[0];
    if (!pathArg || !isStringy(pathArg)) continue;
    const lastArg = args[args.length - 1];
    if (!isFnLike(lastArg)) continue; // Fastify's handler is always the last arg
    const path = normalizePath(literalText(pathArg));
    const handlerLoc: SourceLocation = { file: rel, line: lastArg.getStartLineNumber() };
    // `opts` (when present) sits between path and handler — that's where
    // `preHandler`/auth guards live. The 2-arg form (no `opts`) has nothing to
    // scan and stays `unknown` (fail-safe) rather than false-positive-matching
    // against the handler BODY's own text.
    const auth = detectAuthFromArgs(args.slice(1, -1));
    out.push({ method, path, handlerLoc, handlerFn: lastArg, ...auth });
  }
}

/** `app.route({ method, url|path, handler, preHandler?, ... })` object-config shape. */
function scanRouteObjectCalls(sf: SourceFile, rel: string, out: RawReg[]): void {
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    if (!Node.isPropertyAccessExpression(callee) || callee.getName() !== "route") continue;
    const arg0 = call.getArguments()[0];
    if (!arg0 || !Node.isObjectLiteralExpression(arg0)) continue;

    let methods: HttpMethod[] = [];
    let path: string | undefined;
    let handlerFn: FnLike | undefined;
    let handlerLine: number | undefined;

    for (const prop of arg0.getProperties()) {
      if (!Node.isPropertyAssignment(prop)) continue;
      const key = prop.getName();
      const init = prop.getInitializer();
      if (!init) continue;

      if (key === "method") {
        if (isStringy(init)) {
          const m = VERB_METHODS[literalText(init).toLowerCase()];
          if (m) methods = [m];
        } else if (Node.isArrayLiteralExpression(init)) {
          methods = init
            .getElements()
            .filter(isStringy)
            .map((el) => VERB_METHODS[literalText(el).toLowerCase()])
            .filter((m): m is HttpMethod => !!m);
        }
      } else if (key === "url" || key === "path") {
        if (isStringy(init)) path = normalizePath(literalText(init));
      } else if (key === "handler") {
        if (isFnLike(init)) {
          handlerFn = init;
          handlerLine = init.getStartLineNumber();
        }
      }
    }

    if (!path || methods.length === 0) continue;
    const handlerLoc: SourceLocation = {
      file: rel,
      line: handlerLine ?? call.getStartLineNumber(),
    };
    // Auth guards on this shape usually live in a sibling `preHandler` property
    // of the SAME object literal — scan the whole object literal's text.
    const auth = detectAuthFromArgs(arg0.getProperties());
    for (const method of methods) {
      out.push({ method, path, handlerLoc, handlerFn, ...auth });
    }
  }
}

/** Scan Fastify `app`/`router` route registrations across the project. */
export function scanFastifyRoutes(project: Project, dir: string): FastifyScanResult {
  const routes: Route[] = [];
  const entrypoints: Entrypoint[] = [];
  const routeIdsByFile = new Map<string, string[]>();
  const handlersByRouteId = new Map<string, FnLike>();
  const seen = new Set<string>();

  for (const sf of project.getSourceFiles()) {
    const rel = relPath(sf.getFilePath(), dir);
    const regs: RawReg[] = [];
    scanVerbCalls(sf, rel, regs);
    scanRouteObjectCalls(sf, rel, regs);

    for (const reg of regs) {
      const key = `${reg.method} ${reg.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const id = routeId(reg.method, reg.path);
      routes.push({
        id,
        path: reg.path,
        method: reg.method,
        authState: reg.authState,
        isApiRoute: true,
        handler: reg.handlerLoc,
        ...(reg.authGate ? { authGate: reg.authGate } : {}),
      });
      entrypoints.push({
        kind: "http_route",
        name: `${reg.method} ${reg.path}`,
        location: reg.handlerLoc,
      });
      const list = routeIdsByFile.get(rel) ?? [];
      list.push(id);
      routeIdsByFile.set(rel, list);
      if (reg.handlerFn) handlersByRouteId.set(id, reg.handlerFn);
    }
  }

  routes.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  entrypoints.sort((a, b) => a.name.localeCompare(b.name));
  return { routes, entrypoints, routeIdsByFile, handlersByRouteId };
}
