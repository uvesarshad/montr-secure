/**
 * Next.js registered-route introspection (build-plan §5.1, deterministic).
 *
 * Covers the App Router (route.ts API handlers + page.tsx pages under `app/`),
 * the Pages Router (files under `pages/`, incl. `pages/api`), a `src/` prefix,
 * route groups `(group)`, and dynamic segments `[id]` / `[...slug]`. Methods for
 * App-Router API routes are the exported HTTP-verb functions, read via ts-morph.
 * Auth gates are detected syntactically (guard-identifier presence); the exact
 * public/authed boundary is refined later by the LLM semantic pass.
 */
import { Node } from "ts-morph";
import type {
  ArrowFunction,
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
        addRoute(
          {
            id: routeId(method, path),
            path,
            method,
            authState: auth.authState,
            isApiRoute: true,
            handler,
            ...(auth.authGate ? { authGate: auth.authGate } : {}),
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
      addRoute(
        {
          id: routeId("GET", path),
          path,
          method: "GET",
          authState: auth.authState,
          isApiRoute: false,
          handler: { file: rel, line: def },
          ...(auth.authGate ? { authGate: auth.authGate } : {}),
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
      if (isApi) {
        addRoute(
          {
            id: routeId("ALL", path),
            path,
            method: "ALL",
            authState: auth.authState,
            isApiRoute: true,
            handler: { file: rel, line: def },
            ...(auth.authGate ? { authGate: auth.authGate } : {}),
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
            authState: auth.authState,
            isApiRoute: false,
            handler: { file: rel, line: def },
            ...(auth.authGate ? { authGate: auth.authGate } : {}),
          },
          rel,
          exportedFns.get("default"),
        );
      }
    }
  }

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
