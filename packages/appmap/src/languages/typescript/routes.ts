/**
 * Next.js registered-route introspection (build-plan §5.1, deterministic).
 *
 * Covers the App Router (route.ts API handlers + page.tsx pages under `app/`),
 * the Pages Router (files under `pages/`, incl. `pages/api`), a `src/` prefix,
 * route groups `(group)`, and dynamic segments `[id]` / `[...slug]`. Methods for
 * App-Router API routes are the exported HTTP-verb functions, read via ts-morph.
 *
 * Auth detection (A20 — real control-flow analysis, not identifier-text regex,
 * at two levels, tried in order, both additive over the pre-A20 behavior):
 *   1. HOC-wrap verification: `export const GET = withAuth(handler)` or the
 *      factory form `export const GET = requireRole("admin")(handler)` — the
 *      export's initializer is inspected as an AST `CallExpression` (its own
 *      callee, or — for the factory form — the callee's OWN callee, must be an
 *      identifier matching a known guard name) via {@link detectHocWrap}. This
 *      is a real call-shape check, not a substring match: `const notAGuard =
 *      "withAuth-adjacent text"` never matches, and `withAuth` must actually be
 *      CALLED wrapping this specific export, not merely present anywhere.
 *   2. Next.js `middleware.ts` global auth: a root (or `src/`) `middleware.ts`
 *      whose body references a known guard identifier is treated as gating
 *      every route matched by its exported `config.matcher` (or every route,
 *      Next's own default when no `matcher` is declared) — see
 *      {@link applyNextMiddlewareAuth}. Mirrors Express `app.use(authMiddleware)`
 *      / Fastify global `preHandler` semantics for the framework that actually
 *      has this file (Next has no `app.use`-style registration to trace).
 * Only when NEITHER of the above resolves anything does detection fall back to
 * the original whole-file guard-identifier-text scan ({@link detectAuth}) as
 * the last-resort, already-fail-safe default (`unknown` otherwise).
 */
import { Node } from "ts-morph";
import type {
  ArrowFunction,
  CallExpression,
  FunctionDeclaration,
  FunctionExpression,
  Project,
  SourceFile,
} from "ts-morph";
import type { Entrypoint, HttpMethod, Route, AuthState, SourceLocation } from "@montr/contracts";

const HTTP_METHODS: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
const HTTP_METHOD_SET = new Set<string>(HTTP_METHODS);

/** Known auth-guard identifiers → route is behind auth (fail-safe otherwise "unknown"). */
const AUTH_GUARD_RE =
  /\b(requireSession|requireAuth|requireUser|ensureAuthenticated|isAuthenticated|getServerSession|getSession|getToken|withAuth|currentUser|auth|protect|assertRole|checkPermission)\b/;

/** A function-like declaration a route handler can resolve to. */
export type FnLike = FunctionDeclaration | ArrowFunction | FunctionExpression;

export interface RouteScanResult {
  routes: Route[];
  entrypoints: Entrypoint[];
  /** file (repo-relative) → route ids whose handler lives there (source↔route link). */
  routeIdsByFile: Map<string, string[]>;
  /**
   * route id → its handler function node, when statically resolvable (A18 —
   * consumed by `route-models.ts` to link routes to the ORM models their
   * handlers query). Absent for routes whose export shape isn't a
   * function/arrow (e.g. an anonymous default export ts-morph can't name).
   */
  handlersByRouteId: Map<string, FnLike>;
}

/** Normalize a repo-relative path to POSIX + strip a leading `./`. */
function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}

/** Strip the framework root (`app`/`pages`, optionally under `src/`). */
function stripRoot(rel: string): { kind: "app" | "pages"; rest: string } | null {
  const p = posix(rel);
  const m = /^(?:src\/)?(app|pages)\/(.*)$/.exec(p);
  if (!m) return null;
  return { kind: m[1] as "app" | "pages", rest: m[2] ?? "" };
}

/** Derive the URL path for an App-Router file (drops route/page filename + groups). */
function appRouterPath(rest: string): string {
  const parts = rest.split("/");
  parts.pop(); // drop route.ts / page.tsx
  const segs = parts
    .filter((s) => s.length > 0)
    .filter((s) => !(s.startsWith("(") && s.endsWith(")"))); // route groups are not URL segments
  return "/" + segs.join("/");
}

/** Derive the URL path for a Pages-Router file. */
function pagesRouterPath(rest: string): string {
  let p = rest.replace(/\.(tsx|ts|jsx|js|mjs|cjs)$/i, "");
  p = p.replace(/\/index$/i, "");
  if (p === "index") p = "";
  return "/" + p;
}

/** Deterministic, stable route id from method + path. */
function routeId(method: HttpMethod, path: string): string {
  const slug = path
    .replace(/[[\]().]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `route_${method}_${slug || "root"}`;
}

const PAGES_SPECIAL = new Set([
  "_app",
  "_document",
  "_error",
  "404",
  "500",
  "middleware",
  "_middleware",
]);

/** Exported top-level declaration names → their 1-based start line. */
function exportedDeclLines(sf: SourceFile): Map<string, number> {
  const out = new Map<string, number>();
  for (const fn of sf.getFunctions()) {
    const name = fn.getName();
    if (name && fn.isExported()) out.set(name, fn.getStartLineNumber());
  }
  for (const vs of sf.getVariableStatements()) {
    if (!vs.isExported()) continue;
    for (const d of vs.getDeclarations()) {
      out.set(d.getName(), d.getStartLineNumber());
    }
  }
  return out;
}

/**
 * Exported top-level declaration names → their function node, when the export
 * IS a function-like declaration (a named `export function` or an exported
 * `const x = (...) => ...` / `function (...) {}`). Additive companion to
 * {@link exportedDeclLines} (A18) — kept separate rather than folded in so the
 * existing line-resolution logic above is untouched.
 */
function exportedDeclFns(sf: SourceFile): Map<string, FnLike> {
  const out = new Map<string, FnLike>();
  for (const fn of sf.getFunctions()) {
    const name = fn.getName();
    if (name && fn.isExported()) out.set(name, fn);
  }
  for (const vs of sf.getVariableStatements()) {
    if (!vs.isExported()) continue;
    for (const d of vs.getDeclarations()) {
      const init = d.getInitializer();
      if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) {
        out.set(d.getName(), init);
      }
    }
  }
  return out;
}

function detectAuth(text: string): { authState: AuthState; authGate?: string } {
  const m = AUTH_GUARD_RE.exec(text);
  if (m && m[1]) return { authState: "authenticated", authGate: m[1] };
  return { authState: "unknown" };
}

/**
 * Verify an export's initializer is ACTUALLY a call wrapping the handler in a
 * known guard — `withAuth(handler)` (direct) or `requireRole("admin")(handler)`
 * (factory: the callee is itself a call). Real AST call-shape verification, not
 * a text-substring match — `AUTH_GUARD_RE` is only tested against the CALLEE
 * identifier text, never the whole expression or file.
 */
function authFromWrapCall(
  call: CallExpression,
): { authState: AuthState; authGate: string } | undefined {
  const callee = call.getExpression();
  if (Node.isIdentifier(callee)) {
    const name = callee.getText();
    if (AUTH_GUARD_RE.test(name)) return { authState: "authenticated", authGate: name };
    return undefined;
  }
  // Factory form: `requireRole(...)(handler)` — the callee of the OUTER call
  // is itself a CallExpression; check ITS callee identifier.
  if (Node.isCallExpression(callee)) {
    const inner = callee.getExpression();
    if (Node.isIdentifier(inner)) {
      const name = inner.getText();
      if (AUTH_GUARD_RE.test(name)) return { authState: "authenticated", authGate: name };
    }
  }
  return undefined;
}

/**
 * Does `sf` export `exportName` as a variable whose initializer is a
 * guard-wrapping call (see {@link authFromWrapCall})? Handles both the
 * App-Router HTTP-verb export shape (`export const GET = withAuth(...)`) and
 * the Pages-Router/App-Router-page default-export shape
 * (`export default withAuth(Page)`).
 */
function detectHocWrap(
  sf: SourceFile,
  exportName: string,
): { authState: AuthState; authGate: string } | undefined {
  if (exportName === "default") {
    const def = sf.getExportAssignments().find((ea) => !ea.isExportEquals());
    const init = def?.getExpression();
    if (init && Node.isCallExpression(init)) return authFromWrapCall(init);
    return undefined;
  }
  for (const vs of sf.getVariableStatements()) {
    if (!vs.isExported()) continue;
    for (const d of vs.getDeclarations()) {
      if (d.getName() !== exportName) continue;
      const init = d.getInitializer();
      if (init && Node.isCallExpression(init)) return authFromWrapCall(init);
    }
  }
  return undefined;
}

/** Try the precise per-export HOC-wrap check first; fall back to the
 * whole-file text scan (already-fail-safe) only when it resolves nothing. */
function resolveRouteAuth(
  sf: SourceFile,
  exportName: string,
  fallback: { authState: AuthState; authGate?: string },
): { authState: AuthState; authGate?: string } {
  return detectHocWrap(sf, exportName) ?? fallback;
}

/**
 * Best-effort `path-to-regexp`-ish matcher-pattern → RegExp, covering the
 * shapes Next.js's own middleware `config.matcher` docs show: a literal path,
 * `:name`/`:name*`/`:name+` dynamic segments, and a bare `*` wildcard. This is
 * intentionally NOT a full path-to-regexp implementation (no regex-group
 * matcher objects, no negative lookaheads) — anything more exotic falls
 * through to "no match" for that pattern (fail-safe: under-propagating auth
 * is safe, over-propagating it is not).
 */
function matcherToRegex(pattern: string): RegExp | undefined {
  if (typeof pattern !== "string" || pattern.length === 0) return undefined;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/:[A-Za-z0-9_]+\*/g, ".*")
    .replace(/:[A-Za-z0-9_]+\+/g, ".+")
    .replace(/:[A-Za-z0-9_]+/g, "[^/]+")
    .replace(/\*/g, ".*");
  try {
    return new RegExp(`^${escaped}$`);
  } catch {
    return undefined;
  }
}

function literalTextOf(n: Node): string | undefined {
  if (Node.isStringLiteral(n) || Node.isNoSubstitutionTemplateLiteral(n)) return n.getLiteralText();
  return undefined;
}

/** String literals inside an array/single-string expression (matcher can be
 * `"/x"` or `["/x", "/y"]`). */
function stringLiteralsOf(expr: Node): string[] {
  const direct = literalTextOf(expr);
  if (direct !== undefined) return [direct];
  if (Node.isArrayLiteralExpression(expr)) {
    const out: string[] = [];
    for (const el of expr.getElements()) {
      const t = literalTextOf(el);
      if (t !== undefined) out.push(t);
    }
    return out;
  }
  return [];
}

/**
 * Next.js middleware global auth (A20 (a) — the real Next analog of Express
 * `app.use(authMiddleware)` / Fastify's global `preHandler`: Next has no
 * `app.use`-style per-route registration to trace, since routing itself is
 * file-based, but a root/`src/` `middleware.ts` runs ahead of every matched
 * request exactly the way registered middleware does elsewhere). Finds such a
 * file; if its body looks like an auth check (a known guard identifier), every
 * route matching its exported `config.matcher` (or EVERY route, when no
 * `matcher` is declared — Next's own documented default) with a still-`unknown`
 * authState is upgraded to `authenticated`. A route with an already-resolved,
 * more specific auth signal (HOC-wrap or the per-file regex) is never
 * overridden — global middleware only fills the gap, it never contradicts a
 * signal the route's own file already gave.
 */
function applyNextMiddlewareAuth(project: Project, dir: string, routes: Route[]): void {
  const mw = project.getSourceFiles().find((sf) => {
    const abs = sf.getFilePath();
    const rel = posix(abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs);
    return /^(?:src\/)?middleware\.(ts|js|tsx|jsx)$/i.test(rel);
  });
  if (!mw) return;

  const bodyText = mw.getFullText();
  const guardMatch = AUTH_GUARD_RE.exec(bodyText);
  if (!guardMatch || !guardMatch[1]) return; // no guard-shaped reference → not an auth middleware
  const authGate = `middleware.ts (global: ${guardMatch[1]})`;

  let matchers: string[] = [];
  for (const vs of mw.getVariableStatements()) {
    if (!vs.isExported()) continue;
    for (const d of vs.getDeclarations()) {
      if (d.getName() !== "config") continue;
      const init = d.getInitializer();
      if (init && Node.isObjectLiteralExpression(init)) {
        for (const prop of init.getProperties()) {
          if (!Node.isPropertyAssignment(prop) || prop.getName() !== "matcher") continue;
          const val = prop.getInitializer();
          if (val) matchers = stringLiteralsOf(val);
        }
      }
    }
  }

  const patterns = matchers.map(matcherToRegex).filter((r): r is RegExp => r !== undefined);
  const matches = (path: string): boolean =>
    patterns.length === 0 || patterns.some((re) => re.test(path));

  for (const route of routes) {
    if (route.authState !== "unknown") continue; // never override a known signal
    if (matches(route.path)) {
      route.authState = "authenticated";
      route.authGate = authGate;
    }
  }
}

/** Introspect all Next.js routes across the project's source files. */
export function scanRoutes(project: Project, dir: string): RouteScanResult {
  const routes: Route[] = [];
  const entrypoints: Entrypoint[] = [];
  const routeIdsByFile = new Map<string, string[]>();
  const handlersByRouteId = new Map<string, FnLike>();
  const seen = new Set<string>();

  const addRoute = (route: Route, file: string, handlerFn?: FnLike): void => {
    const key = `${route.method} ${route.path}`;
    if (seen.has(key)) return;
    seen.add(key);
    routes.push(route);
    entrypoints.push({
      kind: "http_route",
      name: `${route.method} ${route.path}`,
      location: route.handler,
    });
    const list = routeIdsByFile.get(file) ?? [];
    if (route.id) list.push(route.id);
    routeIdsByFile.set(file, list);
    if (route.id && handlerFn) handlersByRouteId.set(route.id, handlerFn);
  };

  for (const sf of project.getSourceFiles()) {
    const abs = sf.getFilePath();
    const rel = posix(abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs);
    const root = stripRoot(rel);
    if (!root) continue;
    const filename = rel.split("/").pop() ?? "";
    const text = sf.getFullText();
    const auth = detectAuth(text);
    const exported = exportedDeclLines(sf);
    const exportedFns = exportedDeclFns(sf);

    if (root.kind === "app" && /^route\.(tsx?|jsx?|mjs|cjs)$/i.test(filename)) {
      // App-Router API route: one Route per exported HTTP-verb handler.
      const path = appRouterPath(root.rest);
      const methods = [...exported.keys()].filter((n) => HTTP_METHOD_SET.has(n)) as HttpMethod[];
      const list = methods.length > 0 ? methods : (["GET"] as HttpMethod[]);
      for (const method of list) {
        const line = exported.get(method) ?? 1;
        const handler: SourceLocation = { file: rel, line };
        const routeAuth = resolveRouteAuth(sf, method, auth);
        addRoute(
          {
            id: routeId(method, path),
            path,
            method,
            authState: routeAuth.authState,
            isApiRoute: true,
            handler,
            ...(routeAuth.authGate ? { authGate: routeAuth.authGate } : {}),
          },
          rel,
          exportedFns.get(method),
        );
      }
      continue;
    }

    if (root.kind === "app" && /^page\.(tsx?|jsx?)$/i.test(filename)) {
      // App-Router page → a GET route rendering the page.
      const path = appRouterPath(root.rest);
      const def = exported.get("default") ?? 1;
      const routeAuth = resolveRouteAuth(sf, "default", auth);
      addRoute(
        {
          id: routeId("GET", path),
          path,
          method: "GET",
          authState: routeAuth.authState,
          isApiRoute: false,
          handler: { file: rel, line: def },
          ...(routeAuth.authGate ? { authGate: routeAuth.authGate } : {}),
        },
        rel,
        exportedFns.get("default"),
      );
      continue;
    }

    if (root.kind === "pages") {
      const baseNoExt = (rel.split("/").pop() ?? "").replace(/\.(tsx|ts|jsx|js|mjs|cjs)$/i, "");
      if (PAGES_SPECIAL.has(baseNoExt)) continue;
      const isApi = /^(?:src\/)?pages\/api\//.test(rel);
      const path = pagesRouterPath(root.rest);
      const def = exported.get("default") ?? 1;
      const routeAuth = resolveRouteAuth(sf, "default", auth);
      if (isApi) {
        addRoute(
          {
            id: routeId("ALL", path),
            path,
            method: "ALL",
            authState: routeAuth.authState,
            isApiRoute: true,
            handler: { file: rel, line: def },
            ...(routeAuth.authGate ? { authGate: routeAuth.authGate } : {}),
          },
          rel,
          exportedFns.get("default"),
        );
      } else {
        addRoute(
          {
            id: routeId("GET", path),
            path,
            method: "GET",
            authState: routeAuth.authState,
            isApiRoute: false,
            handler: { file: rel, line: def },
            ...(routeAuth.authGate ? { authGate: routeAuth.authGate } : {}),
          },
          rel,
          exportedFns.get("default"),
        );
      }
    }
  }

  applyNextMiddlewareAuth(project, dir, routes);

  // Stable ordering: API routes first, then by path.
  routes.sort((a, b) =>
    a.isApiRoute === b.isApiRoute
      ? a.path.localeCompare(b.path) || a.method.localeCompare(b.method)
      : a.isApiRoute
        ? -1
        : 1,
  );
  entrypoints.sort((a, b) => a.name.localeCompare(b.name));
  return { routes, entrypoints, routeIdsByFile, handlersByRouteId };
}
