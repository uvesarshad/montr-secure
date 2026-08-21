/**
 * Python registered-route introspection (Layer 0, deterministic).
 *
 * Two route conventions, both parsed from the tree-sitter-python AST:
 *   • Django  — `urlpatterns` entries via `path()` / `re_path()` / `url()` in a
 *     URLConf module; the view target + optional `name=` are captured, dynamic
 *     segments (`<int:id>` / `(?P<id>…)`) are normalised to `{id}`.
 *   • FastAPI / Flask — decorator routes `@app.get("/x")`, `@router.post(...)`,
 *     `@app.route("/x", methods=[...])`, honouring an `APIRouter(prefix=…)`.
 *
 * Auth is detected syntactically at two levels (A20 — the second is real
 * control-flow analysis of a declarative global-auth switch, not per-route
 * identifier-text matching):
 *   1. Per-route: a guard decorator like `@login_required`, a class-based-view
 *      auth mixin, or a `Depends(get_current_user)` parameter → `authenticated`.
 *   2. Global (Django only): `MIDDLEWARE` in a settings module containing
 *      `django.contrib.auth.middleware.LoginRequiredMiddleware` (Django 5.1+)
 *      makes EVERY view require login by default — this is Django's real
 *      declarative analog of Express `app.use(authMiddleware)` / Fastify's
 *      global `preHandler` (see {@link detectDjangoGlobalLoginRequired}); it
 *      upgrades every URLConf route still at `unknown` to `authenticated`. The
 *      per-view `@login_not_required` opt-out is NOT resolved (the view is
 *      typically declared in a different file than the URLConf entry this
 *      module reads, and cross-file view resolution is out of scope here —
 *      the same bounded-hop philosophy `typescript/callgraph.ts` documents).
 * Otherwise `unknown` (fail-safe — the LLM semantic pass refines it later,
 * never this file). Entrypoints mirror routes, plus management commands
 * (`cli`) and Celery tasks (`job`). Every emitted shape is a frozen
 * `@montr/contracts` type.
 */
import type { Node } from "web-tree-sitter";
import type { AuthState, Entrypoint, HttpMethod, Route } from "@montr/contracts";
import {
  calleeText,
  descendants,
  field,
  keywordArg,
  lineOf,
  namedChildren,
  positionalArgs,
  stringValue,
  type ParsedModule,
} from "./parser.js";

export interface PythonRouteResult {
  routes: Route[];
  entrypoints: Entrypoint[];
  /** file (repo-relative) → route ids whose handler lives there (source↔route link). */
  routeIdsByFile: Map<string, string[]>;
}

const HTTP_VERB_METHODS: Record<string, HttpMethod> = {
  get: "GET",
  post: "POST",
  put: "PUT",
  patch: "PATCH",
  delete: "DELETE",
  options: "OPTIONS",
  head: "HEAD",
};

/** Decorator/parameter markers that put a route behind auth. */
const AUTH_DECORATOR_RE =
  /\b(login_required|permission_required|user_passes_test|staff_member_required|requires?_auth|require_http_methods|jwt_required|token_required|authenticated|permission_classes)\b/;
const AUTH_DEPENDS_RE =
  /\b(?:Depends|Security)\(\s*(get_current_user|get_current_active_user|current_user|require_[a-z_]+|auth[a-z_]*|verify_[a-z_]+|valid[a-z_]*_token|oauth2?_scheme)/i;

/** Deterministic, stable route id from method + path (mirrors the TS builder). */
function routeId(method: string, path: string): string {
  const slug = path
    .replace(/[[\](){}.<>?:]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `route_${method}_${slug || "root"}`;
}

/** `users/<int:id>/` or `^users/(?P<id>\d+)/$` → `/users/{id}`. */
function normalisePath(pattern: string, isRegex: boolean): string {
  let p = pattern;
  if (isRegex) {
    p = p.replace(/^\^/, "").replace(/\$$/, "");
    p = p.replace(/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>[^)]*\)/g, "{$1}");
    p = p.replace(/\\\//g, "/");
  } else {
    // Django path() converters: <int:id> / <id>
    p = p.replace(/<(?:[a-zA-Z_]+:)?([A-Za-z_][A-Za-z0-9_]*)>/g, "{$1}");
  }
  if (!p.startsWith("/")) p = "/" + p;
  return p.replace(/\/{2,}/g, "/");
}

function isApi(path: string): boolean {
  return /(^|\/)(api|v\d+|graphql)(\/|$)/i.test(path);
}

/**
 * Django 5.1+ global auth switch (A20): `MIDDLEWARE = [..., "django.contrib.
 * auth.middleware.LoginRequiredMiddleware", ...]` in a settings module makes
 * every view require a logged-in user by default. Real AST inspection of the
 * `MIDDLEWARE` list assignment's right-hand side, not a whole-file text scan —
 * a module containing the string "LoginRequiredMiddleware" somewhere unrelated
 * (a comment, an unrelated variable) does not trigger this.
 */
function detectDjangoGlobalLoginRequired(mods: ParsedModule[]): boolean {
  for (const mod of mods) {
    if (!/MIDDLEWARE/.test(mod.source)) continue; // cheap pre-filter
    for (const assign of descendants(mod.root, "assignment")) {
      const left = field(assign, "left");
      if (!left || left.type !== "identifier" || left.text !== "MIDDLEWARE") continue;
      const right = field(assign, "right");
      if (right && /LoginRequiredMiddleware/.test(right.text)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Django URLConf
// ---------------------------------------------------------------------------

function scanDjangoUrls(mod: ParsedModule, res: PythonRouteResult, seen: Set<string>): void {
  // Only treat a module as a URLConf when it actually defines urlpatterns (or is
  // named urls.py) — avoids mistaking an unrelated `path(...)` call for a route.
  const base = mod.rel.split("/").pop() ?? "";
  if (!/urlpatterns/.test(mod.source) && base !== "urls.py") return;

  for (const call of descendants(mod.root, "call")) {
    const fn = calleeText(call);
    const leaf = fn.split(".").pop() ?? fn;
    if (leaf !== "path" && leaf !== "re_path" && leaf !== "url") continue;
    const args = positionalArgs(call);
    const patternNode = args[0];
    const pattern = stringValue(patternNode);
    if (pattern === undefined) continue;
    // `path("admin/", include("admin.urls"))` is a mount, not a leaf route.
    const target = args[1];
    if (target && target.type === "call" && /(^|\.)include$/.test(calleeText(target))) continue;

    const isRegex = leaf !== "path";
    const path = normalisePath(pattern, isRegex);
    const nameKw = keywordArg(call, "name");
    const viewText = target?.text ?? "view";
    const line = lineOf(call);
    // Django dispatches every HTTP method to the view → method-agnostic.
    addRoute(res, seen, {
      method: "ALL",
      path,
      isApiRoute: isApi(path) || /as_view|ViewSet|api/i.test(viewText),
      handler: { file: mod.rel, line },
      auth: routeAuthFromView(viewText),
      name: stringValue(nameKw),
    });
  }
}

/**
 * Cheap auth hint for a Django view referenced from a URLConf. Cross-file view
 * resolution is correlation's job; here we only lift an unambiguous class-based
 * auth mixin off the reference text. Everything else stays `unknown` (fail-safe).
 */
function routeAuthFromView(viewText: string): AuthGate {
  if (/LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin/.test(viewText)) {
    return { authState: "authenticated", authGate: "LoginRequiredMixin" };
  }
  return { authState: "unknown" };
}

// ---------------------------------------------------------------------------
// FastAPI / Flask decorators
// ---------------------------------------------------------------------------

/** var name → URL prefix declared via `X = APIRouter(prefix="/x")`. */
function collectRouterPrefixes(mod: ParsedModule): Map<string, string> {
  const prefixes = new Map<string, string>();
  for (const assign of descendants(mod.root, "assignment")) {
    const left = field(assign, "left");
    const right = field(assign, "right");
    if (!left || !right || left.type !== "identifier" || right.type !== "call") continue;
    const callee = calleeText(right);
    if (!/(^|\.)APIRouter$/.test(callee)) continue;
    const prefix = stringValue(keywordArg(right, "prefix"));
    if (prefix) prefixes.set(left.text, prefix.replace(/\/$/, ""));
  }
  return prefixes;
}

function scanDecoratorRoutes(mod: ParsedModule, res: PythonRouteResult, seen: Set<string>): void {
  const prefixes = collectRouterPrefixes(mod);

  for (const dec of descendants(mod.root, "decorated_definition")) {
    const def = field(dec, "definition") ?? lastDefinition(dec);
    if (!def) continue;
    const isFunction = def.type === "function_definition";
    const isClass = def.type === "class_definition";
    if (!isFunction && !isClass) continue;
    const handlerName = field(def, "name")?.text ?? "handler";

    const decorators = namedChildren(dec).filter((c) => c.type === "decorator");
    const decoratorText = decorators.map((d) => d.text).join("\n");
    const authed = routeAuthFromDecorators(decoratorText, def);

    for (const decorator of decorators) {
      const call = firstCall(decorator);
      if (!call) continue;
      const callee = calleeText(call);
      const m = /(?:^|\.)([A-Za-z_]+)$/.exec(callee);
      const verb = m?.[1]?.toLowerCase();
      if (!verb) continue;
      const objName = callee.includes(".") ? (callee.split(".").slice(0, -1).pop() ?? "") : "";
      const prefix = prefixes.get(objName) ?? "";
      const sub = stringValue(positionalArgs(call)[0]);
      if (sub === undefined) continue;
      const path = normalisePath(prefix + (sub.startsWith("/") ? sub : "/" + sub), false);
      const line = lineOf(def);

      const methods = methodsForVerb(verb, call);
      for (const method of methods) {
        addRoute(res, seen, {
          method,
          path,
          isApiRoute: true, // FastAPI/Flask decorator routes are API handlers
          handler: { file: mod.rel, line },
          auth: authed,
          name: handlerName,
        });
      }
    }
  }
}

/** Resolve the HTTP method(s) a decorator verb maps to (route() reads methods=[…]). */
function methodsForVerb(verb: string, call: Node): HttpMethod[] {
  const direct = HTTP_VERB_METHODS[verb];
  if (direct) return [direct];
  if (verb === "route" || verb === "add_url_rule" || verb === "websocket") {
    const methodsKw = keywordArg(call, "methods");
    if (methodsKw && methodsKw.type === "list") {
      const found: HttpMethod[] = [];
      for (const el of namedChildren(methodsKw)) {
        const v = stringValue(el)?.toUpperCase();
        if (v && v in METHOD_SET) found.push(v as HttpMethod);
      }
      if (found.length > 0) return found;
    }
    return ["GET"]; // Flask @route default
  }
  return [];
}

const METHOD_SET: Record<string, true> = {
  GET: true,
  POST: true,
  PUT: true,
  PATCH: true,
  DELETE: true,
  OPTIONS: true,
  HEAD: true,
  ALL: true,
};

function routeAuthFromDecorators(decoratorText: string, def: Node): AuthGate {
  const dm = AUTH_DECORATOR_RE.exec(decoratorText);
  if (dm?.[1]) return { authState: "authenticated", authGate: dm[1] };
  // FastAPI dependency-injected auth: `def h(user = Depends(get_current_user))`.
  const params = field(def, "parameters");
  if (params) {
    const pm = AUTH_DEPENDS_RE.exec(params.text);
    if (pm) return { authState: "authenticated", authGate: `Depends(${pm[1]})` };
  }
  return { authState: "unknown" };
}

// ---------------------------------------------------------------------------
// Entrypoints beyond HTTP routes: management commands + tasks
// ---------------------------------------------------------------------------

function scanNonHttpEntrypoints(mod: ParsedModule, res: PythonRouteResult): void {
  // Django management command: `class Command(BaseCommand): def handle(...)`.
  for (const cls of descendants(mod.root, "class_definition")) {
    const supers = field(cls, "superclasses")?.text ?? "";
    if (/BaseCommand/.test(supers) && field(cls, "name")?.text === "Command") {
      res.entrypoints.push({
        kind: "cli",
        name: `manage: ${mod.rel.split("/").pop() ?? "command"}`,
        location: { file: mod.rel, line: lineOf(cls) },
      });
    }
  }
  // Celery / task workers: `@shared_task` / `@app.task` / `@celery.task`.
  for (const dec of descendants(mod.root, "decorated_definition")) {
    const decText = namedChildren(dec)
      .filter((c) => c.type === "decorator")
      .map((d) => d.text)
      .join("\n");
    if (!/@\s*(shared_task|[A-Za-z_]+\.task)\b/.test(decText)) continue;
    const def = field(dec, "definition") ?? lastDefinition(dec);
    if (!def) continue;
    res.entrypoints.push({
      kind: "job",
      name: `task: ${field(def, "name")?.text ?? "task"}`,
      location: { file: mod.rel, line: lineOf(def) },
    });
  }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

interface AuthGate {
  authState: AuthState;
  authGate?: string;
}

function firstCall(node: Node): Node | undefined {
  if (node.type === "call") return node;
  for (const child of namedChildren(node)) {
    if (child.type === "call") return child;
    if (child.type === "attribute" || child.type === "identifier") continue;
  }
  // decorator wraps its expression as the first named child
  const first = namedChildren(node)[0];
  return first && first.type === "call" ? first : undefined;
}

function lastDefinition(dec: Node): Node | undefined {
  const kids = namedChildren(dec);
  for (let i = kids.length - 1; i >= 0; i--) {
    const k = kids[i];
    if (k && (k.type === "function_definition" || k.type === "class_definition")) return k;
  }
  return undefined;
}

interface RouteDraft {
  method: HttpMethod;
  path: string;
  isApiRoute: boolean;
  handler: { file: string; line: number };
  auth: AuthGate;
  name?: string;
}

function addRoute(res: PythonRouteResult, seen: Set<string>, draft: RouteDraft): void {
  const key = `${draft.method} ${draft.path}`;
  if (seen.has(key)) return;
  seen.add(key);
  const id = routeId(draft.method, draft.path);
  res.routes.push({
    id,
    path: draft.path,
    method: draft.method,
    authState: draft.auth.authState,
    isApiRoute: draft.isApiRoute,
    handler: draft.handler,
    ...(draft.auth.authGate ? { authGate: draft.auth.authGate } : {}),
  });
  res.entrypoints.push({
    kind: "http_route",
    name: `${draft.method} ${draft.path}`,
    location: draft.handler,
  });
  const list = res.routeIdsByFile.get(draft.handler.file) ?? [];
  list.push(id);
  res.routeIdsByFile.set(draft.handler.file, list);
}

/** Introspect every Python route (Django URLConf + FastAPI/Flask decorators). */
export function scanPythonRoutes(mods: ParsedModule[]): PythonRouteResult {
  const res: PythonRouteResult = {
    routes: [],
    entrypoints: [],
    routeIdsByFile: new Map(),
  };
  const seen = new Set<string>();
  for (const mod of mods) {
    scanDjangoUrls(mod, res, seen);
    scanDecoratorRoutes(mod, res, seen);
    scanNonHttpEntrypoints(mod, res);
  }

  if (detectDjangoGlobalLoginRequired(mods)) {
    for (const route of res.routes) {
      // Django dispatches ALL methods to the view for a URLConf entry
      // (`scanDjangoUrls`'s own `method: "ALL"`) — a reliable proxy for
      // "this route came from the URLConf" vs. a FastAPI/Flask decorator
      // route (always a specific verb), without needing a separate per-route
      // provenance flag.
      if (route.method === "ALL" && route.authState === "unknown") {
        route.authState = "authenticated";
        route.authGate = "LoginRequiredMiddleware (global)";
      }
    }
  }

  res.routes.sort((a, b) =>
    a.isApiRoute === b.isApiRoute
      ? a.path.localeCompare(b.path) || a.method.localeCompare(b.method)
      : a.isApiRoute
        ? -1
        : 1,
  );
  res.entrypoints.sort((a, b) => a.name.localeCompare(b.name));
  return res;
}
