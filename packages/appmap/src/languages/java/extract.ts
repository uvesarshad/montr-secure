/**
 * Per-file JVM App-Map extraction (deterministic, syntactic, offline).
 *
 * Walks one parsed Java file and emits the language-agnostic App-Map pieces:
 *   • routes / entrypoints — Spring `@GetMapping`/`@PostMapping`/`@RequestMapping`
 *     (+ class `@RequestMapping` base + `@PreAuthorize`/`@Secured` auth) and
 *     JAX-RS `@Path` + `@GET`/`@POST`; `@Scheduled` + listener beans as entrypoints.
 *   • ormModels — JPA `@Entity` classes + their fields (`@Id` marks the key).
 *   • taintSources — `@RequestParam`/`@PathVariable`/`@RequestBody`/`@RequestHeader`/
 *     `@CookieValue` params + `HttpServletRequest` getters, linked to their route.
 *   • taintSinks — string-concatenated JDBC/JPQL, `Runtime.exec`/`ProcessBuilder`,
 *     `ObjectInputStream.readObject`, reflection, SpEL, `sendRedirect`.
 *   • envSecretSurfaces — `@Value("${...}")` + `System.getenv`.
 *   • thirdPartyCalls — `RestTemplate`/`WebClient`/`HttpClient` + known SDK imports.
 *
 * All output is frozen @montr/contracts shapes; nothing here is stack-specific on
 * the way out (correlation/confirm/fix/report consume it unchanged).
 */
import type {
  Entrypoint,
  EntrypointKind,
  EnvSecretSurface,
  HttpMethod,
  OrmModel,
  Route,
  TaintSink,
  TaintSinkKind,
  TaintSource,
  TaintSourceKind,
  ThirdPartyCall,
} from "@montr/contracts";
import {
  annotationAttrText,
  annotationsOf,
  annotationStringValue,
  descendantsOfType,
  field,
  findAnnotation,
  lineOf,
  namedKids,
  type AnnotationInfo,
  type TSNode,
} from "./parser.js";

export interface FileExtraction {
  routes: Route[];
  entrypoints: Entrypoint[];
  ormModels: OrmModel[];
  taintSources: TaintSource[];
  taintSinks: TaintSink[];
  envSecretSurfaces: EnvSecretSurface[];
  thirdPartyCalls: ThirdPartyCall[];
  /** Import specifiers (dotted) — for framework/SDK detection by the analyzer. */
  imports: string[];
  /** True when a Spring web/stereotype annotation or import was seen in this file. */
  usesSpring: boolean;
}

// --- annotation vocabularies ------------------------------------------------

const SPRING_METHOD_MAPPING: Record<string, HttpMethod> = {
  GetMapping: "GET",
  PostMapping: "POST",
  PutMapping: "PUT",
  DeleteMapping: "DELETE",
  PatchMapping: "PATCH",
};
const JAXRS_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);
const CONTROLLER_ANNOTATIONS = new Set(["RestController", "Controller"]);
const ENTITY_ANNOTATIONS = new Set(["Entity", "MappedSuperclass"]);
const AUTH_ANNOTATIONS = new Set([
  "PreAuthorize",
  "PostAuthorize",
  "Secured",
  "RolesAllowed",
  "PermitAll",
  "DenyAll",
]);
const REQUEST_METHOD_RE = /RequestMethod\.([A-Z]+)/;

const SOURCE_ANNOTATION_KIND: Record<string, TaintSourceKind> = {
  RequestParam: "query_param",
  PathVariable: "path_param",
  RequestBody: "request_body",
  RequestHeader: "request_header",
  CookieValue: "cookie",
  ModelAttribute: "request_body",
};

/** `HttpServletRequest` getter → the taint kind it introduces. */
const REQUEST_GETTER_KIND: Record<string, TaintSourceKind> = {
  getParameter: "query_param",
  getParameterValues: "query_param",
  getParameterMap: "query_param",
  getQueryString: "query_param",
  getHeader: "request_header",
  getHeaders: "request_header",
  getCookies: "cookie",
  getInputStream: "request_body",
  getReader: "request_body",
  getPart: "request_body",
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
  "queryForRowSet",
  "update",
  "prepareStatement",
  "prepareCall",
]);
const JPQL_METHODS = new Set(["createQuery", "createNativeQuery", "createNamedQuery"]);
const HTTP_CLIENT_TYPES = new Set(["RestTemplate", "WebClient", "HttpClient", "OkHttpClient"]);
const HTTP_CLIENT_METHODS = new Set([
  "getForObject",
  "getForEntity",
  "postForObject",
  "postForEntity",
  "exchange",
  "getForm",
]);
/** Import prefixes that are third-party SDKs (vendor integrations), not the JDK/Spring. */
const SDK_IMPORT_PREFIXES: ReadonlyArray<[RegExp, string]> = [
  [/^com\.stripe\./, "com.stripe"],
  [/^com\.amazonaws\./, "com.amazonaws"],
  [/^software\.amazon\.awssdk\./, "software.amazon.awssdk"],
  [/^com\.google\.cloud\./, "com.google.cloud"],
  [/^com\.twilio\./, "com.twilio"],
  [/^com\.sendgrid\./, "com.sendgrid"],
  [/^io\.jsonwebtoken\./, "io.jsonwebtoken"],
];

// --- small local utils ------------------------------------------------------

function posixPath(rel: string): string {
  return rel.replace(/\\/g, "/").replace(/^\.\//, "");
}

/**
 * Prototype-safe lookup into a string-keyed record. Java method/annotation names
 * pulled from the AST (e.g. `valueOf`, `toString`, `constructor`, `hasOwnProperty`)
 * collide with `Object.prototype` members, so a bare `record[name]` would return
 * an inherited FUNCTION instead of `undefined`. That poisoned value would then be
 * emitted as a `TaintSource.kind` / `Route.method`, failing `Layer0OutputSchema`
 * and crashing the whole Layer-0 build for any Java repo that calls `.toString()`.
 */
function own<T>(map: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(map, key) ? map[key] : undefined;
}

/** Deterministic, stable route id from method + path (mirrors the TS builder). */
function routeId(method: HttpMethod, path: string): string {
  const slug = path
    .replace(/[[\]{}().]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `route_${method}_${slug || "root"}`;
}

/** Join a controller base path and a method path into one normalized URL path. */
function combinePath(base: string, sub: string): string {
  const parts = `${base}/${sub}`.split("/").filter((s) => s.length > 0);
  return "/" + parts.join("/");
}

interface ResolvedAuth {
  authState: Route["authState"];
  authGate?: string;
}

/** Resolve the auth state a set of annotations implies (fail-safe: undefined). */
function resolveAuth(anns: AnnotationInfo[]): ResolvedAuth | undefined {
  const ann = anns.find((a) => AUTH_ANNOTATIONS.has(a.name));
  if (!ann) return undefined;
  if (ann.name === "PermitAll") return { authState: "public", authGate: "PermitAll" };
  if (ann.name === "Secured" || ann.name === "RolesAllowed") {
    return { authState: "role_gated", authGate: ann.name };
  }
  if (ann.name === "DenyAll") return { authState: "authenticated", authGate: "DenyAll" };
  const expr = annotationStringValue(ann) ?? "";
  const roleGated = /hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|ROLE_/.test(expr);
  return { authState: roleGated ? "role_gated" : "authenticated", authGate: ann.name };
}

/** Direct method_declaration children of a class body. */
function methodsOf(cls: TSNode): TSNode[] {
  const body = field(cls, "body");
  if (!body) return [];
  return namedKids(body).filter((c) => c.type === "method_declaration");
}

/** Direct field_declaration children of a class body. */
function fieldsOf(cls: TSNode): TSNode[] {
  const body = field(cls, "body");
  if (!body) return [];
  return namedKids(body).filter((c) => c.type === "field_declaration");
}

// --- concatenation analysis (SQL/JPQL string building) ----------------------

/** Does this node subtree build a string by `+` concatenation with a literal? */
function isConcatSubtree(node: TSNode): boolean {
  if (node.type !== "binary_expression") return false;
  const hasString = descendantsOfType(node, "string_literal").length > 0;
  const hasDynamic =
    descendantsOfType(node, ["identifier", "method_invocation", "field_access"]).length > 0;
  return hasString && hasDynamic;
}

/** Local variable names assigned from a string concatenation (built-then-used SQL). */
function collectConcatLocals(root: TSNode): Set<string> {
  const names = new Set<string>();
  for (const decl of descendantsOfType(root, "variable_declarator")) {
    const value = field(decl, "value");
    const name = field(decl, "name");
    if (name && value && isConcatSubtree(value)) names.add(name.text);
  }
  for (const asg of descendantsOfType(root, "assignment_expression")) {
    const left = field(asg, "left");
    const right = field(asg, "right");
    if (left?.type === "identifier" && right && isConcatSubtree(right)) names.add(left.text);
  }
  return names;
}

/** Is the first argument of a call a concatenated / format-built string? */
function firstArgConcatenated(call: TSNode, concatLocals: ReadonlySet<string>): boolean {
  const args = field(call, "arguments");
  if (!args) return false;
  const first = namedKids(args)[0];
  if (!first) return false;
  if (isConcatSubtree(first)) return true;
  if (first.type === "identifier" && concatLocals.has(first.text)) return true;
  if (first.type === "method_invocation" && field(first, "name")?.text === "format") return true;
  return false;
}

// --- extraction -------------------------------------------------------------

interface RouteRange {
  start: number;
  end: number;
  routeId: string;
  authState: Route["authState"];
}

function enclosingRoute(line: number, ranges: RouteRange[]): RouteRange | undefined {
  // Innermost containing range wins (handlers don't nest, but be safe).
  let best: RouteRange | undefined;
  for (const r of ranges) {
    if (line >= r.start && line <= r.end) {
      if (!best || r.start >= best.start) best = r;
    }
  }
  return best;
}

/** Extract every App-Map piece from one parsed Java file. */
export function extractFile(root: TSNode, relPath: string): FileExtraction {
  const rel = posixPath(relPath);
  const out: FileExtraction = {
    routes: [],
    entrypoints: [],
    ormModels: [],
    taintSources: [],
    taintSinks: [],
    envSecretSurfaces: [],
    thirdPartyCalls: [],
    imports: [],
    usesSpring: false,
  };

  // Imports (framework + SDK signal).
  for (const imp of descendantsOfType(root, "import_declaration")) {
    const scoped = namedKids(imp).find(
      (c) => c.type === "scoped_identifier" || c.type === "identifier",
    );
    if (!scoped) continue;
    const spec = scoped.text;
    out.imports.push(spec);
    if (spec.startsWith("org.springframework")) out.usesSpring = true;
    for (const [re, name] of SDK_IMPORT_PREFIXES) {
      if (re.test(spec)) {
        out.thirdPartyCalls.push({
          kind: "sdk",
          name,
          target: spec,
          location: { file: rel, line: lineOf(imp) },
        });
      }
    }
  }

  const concatLocals = collectConcatLocals(root);
  const routeRanges: RouteRange[] = [];
  const seenRoutes = new Set<string>();

  // --- classes: routes, entrypoints, entities, param sources ---------------
  for (const cls of descendantsOfType(root, "class_declaration")) {
    const classAnns = annotationsOf(cls);
    const classAnnNames = new Set(classAnns.map((a) => a.name));
    const isController = [...classAnnNames].some((n) => CONTROLLER_ANNOTATIONS.has(n));
    const isJaxrs = classAnnNames.has("Path");
    const isEntity = [...classAnnNames].some((n) => ENTITY_ANNOTATIONS.has(n));
    if (
      classAnns.some(
        (a) =>
          a.name === "RestController" || a.name === "Controller" || a.name === "RequestMapping",
      )
    ) {
      out.usesSpring = true;
    }

    if (isEntity) out.ormModels.push(extractEntity(cls, rel));

    const classPathAnn =
      findAnnotation(cls, new Set(["RequestMapping"])) ??
      (isJaxrs ? findAnnotation(cls, new Set(["Path"])) : undefined);
    const basePath = classPathAnn ? (annotationStringValue(classPathAnn) ?? "") : "";
    const classAuth = resolveAuth(classAnns);

    for (const method of methodsOf(cls)) {
      const methodAnns = annotationsOf(method);
      const mappings = resolveMappings(methodAnns, isJaxrs);
      // Non-route entrypoints (scheduled jobs / message listeners).
      const special = specialEntrypoint(methodAnns);
      if (special) {
        const mname = field(method, "name")?.text ?? "handler";
        out.entrypoints.push({
          kind: special,
          name: `${special}:${mname}`,
          location: { file: rel, line: lineOf(method) },
        });
      }
      if (mappings.length === 0) continue;
      if (!isController && !isJaxrs && !classAnnNames.has("RequestMapping")) {
        // A mapping annotation on a method in a non-controller class still routes.
      }

      const methodAuth = resolveAuth(methodAnns);
      const auth = methodAuth ?? classAuth ?? { authState: "unknown" as const };
      const mStart = lineOf(method);
      const mEnd = method.endPosition.row + 1;

      for (const { method: httpMethod, sub } of mappings) {
        const path = combinePath(basePath, sub);
        const key = `${httpMethod} ${path}`;
        if (seenRoutes.has(key)) continue;
        seenRoutes.add(key);
        const id = routeId(httpMethod, path);
        const route: Route = {
          id,
          path,
          method: httpMethod,
          authState: auth.authState,
          isApiRoute: true,
          handler: { file: rel, line: mStart },
          ...(auth.authGate ? { authGate: auth.authGate } : {}),
        };
        out.routes.push(route);
        out.entrypoints.push({
          kind: "http_route",
          name: `${httpMethod} ${path}`,
          location: route.handler,
        });
        routeRanges.push({ start: mStart, end: mEnd, routeId: id, authState: auth.authState });

        // Parameter-annotation taint sources, linked to this route.
        for (const src of paramSources(method, rel, id)) out.taintSources.push(src);
      }
    }
  }

  // --- file-wide: request getters, sinks, @Value, System.getenv, http clients
  for (const call of descendantsOfType(root, "method_invocation")) {
    const name = field(call, "name")?.text ?? "";
    const objectNode = field(call, "object");
    const objectText = objectNode?.text ?? "";
    const argsText = field(call, "arguments")?.text ?? "";

    // Request-object getters → taint sources. `own` guards the lookup against
    // inherited Object.prototype members (valueOf/toString are common in Java).
    const getterKind = own(REQUEST_GETTER_KIND, name);
    // Stream getters (getInputStream/getReader/getPart) also exist on Process/
    // Socket/URLConnection; only treat them as request input when the receiver is
    // request-like, so e.g. `proc.getInputStream()` is not a false taint source.
    const streamGetter = name === "getInputStream" || name === "getReader" || name === "getPart";
    const lowerObject = objectText.toLowerCase();
    const receiverLooksRequest = lowerObject.includes("request") || lowerObject === "req";
    if (getterKind && (objectText || argsText) && (!streamGetter || receiverLooksRequest)) {
      const rr = enclosingRoute(lineOf(call), routeRanges);
      const argString = descendantsOfType(field(call, "arguments") ?? call, "string_literal")[0];
      const paramName = argString ? argString.text : "";
      out.taintSources.push({
        kind: getterKind,
        location: { file: rel, line: lineOf(call) },
        description: `${name}(${paramName})`,
        ...(rr ? { routeId: rr.routeId } : {}),
      });
    }

    // Sinks.
    const sink = callSink(call, name, objectText, concatLocals, rel);
    if (sink) out.taintSinks.push(sink);

    // System.getenv / getProperty → process_env surface.
    if ((name === "getenv" || name === "getProperty") && objectText === "System") {
      const s = descendantsOfType(field(call, "arguments") ?? call, "string_literal")[0];
      out.envSecretSurfaces.push({
        kind: "process_env",
        name: s ? unquoteText(s.text) : "getenv",
        location: { file: rel, line: lineOf(call) },
      });
    }

    // Outbound HTTP clients.
    if (HTTP_CLIENT_METHODS.has(name) || /rest_?template|webclient|httpclient/i.test(objectText)) {
      const clientName = /webclient/i.test(objectText)
        ? "WebClient"
        : /httpclient/i.test(objectText)
          ? "HttpClient"
          : "RestTemplate";
      out.thirdPartyCalls.push({
        kind: "http",
        name: clientName,
        location: { file: rel, line: lineOf(call) },
      });
    }
  }

  for (const create of descendantsOfType(root, "object_creation_expression")) {
    const typeName = field(create, "type")?.text ?? "";
    if (typeName === "ProcessBuilder") {
      out.taintSinks.push({
        kind: "command_exec",
        location: { file: rel, line: lineOf(create) },
        description: "new ProcessBuilder(...) executes an external process",
      });
    }
    if (HTTP_CLIENT_TYPES.has(typeName)) {
      out.thirdPartyCalls.push({
        kind: "http",
        name: typeName,
        location: { file: rel, line: lineOf(create) },
      });
    }
  }

  // @Value("${...}") env/secret surfaces (fields + constructor params).
  for (const ann of descendantsOfType(root, ["annotation", "marker_annotation"])) {
    const nameNode = field(ann, "name");
    if (!nameNode || nameNode.text.replace(/^.*\./, "") !== "Value") continue;
    const info: AnnotationInfo = { name: "Value", node: ann, args: undefined };
    const raw = annotationStringValue({
      ...info,
      args: descendantsOfType(ann, "annotation_argument_list")[0],
    });
    const key = extractValueKey(raw);
    if (key) {
      out.envSecretSurfaces.push({
        kind: "config_file",
        name: key,
        location: { file: rel, line: lineOf(ann) },
      });
    }
  }

  return out;
}

interface MethodMapping {
  method: HttpMethod;
  sub: string;
}

/** Resolve the HTTP method(s) + sub-path a handler's annotations declare. */
function resolveMappings(anns: AnnotationInfo[], isJaxrs: boolean): MethodMapping[] {
  const out: MethodMapping[] = [];
  let jaxrsPath = "";
  for (const ann of anns) {
    if (isJaxrs && ann.name === "Path") jaxrsPath = annotationStringValue(ann) ?? "";
  }
  for (const ann of anns) {
    const springMethod = own(SPRING_METHOD_MAPPING, ann.name);
    if (springMethod) {
      out.push({ method: springMethod, sub: annotationStringValue(ann) ?? "" });
    } else if (ann.name === "RequestMapping") {
      const methodAttr = annotationAttrText(ann, "method");
      const m = methodAttr ? REQUEST_METHOD_RE.exec(methodAttr) : null;
      const httpMethod = (m?.[1] as HttpMethod | undefined) ?? "ALL";
      out.push({ method: httpMethod, sub: annotationStringValue(ann) ?? "" });
    } else if (isJaxrs && JAXRS_METHODS.has(ann.name)) {
      out.push({ method: ann.name as HttpMethod, sub: jaxrsPath });
    }
  }
  return out;
}

/** A non-route entrypoint kind implied by scheduling/listener annotations. */
function specialEntrypoint(anns: AnnotationInfo[]): EntrypointKind | undefined {
  const names = new Set(anns.map((a) => a.name));
  if (names.has("Scheduled")) return "cron";
  if (
    names.has("EventListener") ||
    names.has("KafkaListener") ||
    names.has("RabbitListener") ||
    names.has("JmsListener")
  ) {
    return "event_handler";
  }
  return undefined;
}

/** Taint sources declared as annotated handler parameters, linked to `routeId`. */
function paramSources(method: TSNode, rel: string, routeId: string): TaintSource[] {
  const out: TaintSource[] = [];
  const params = field(method, "parameters");
  if (!params) return out;
  for (const p of namedKids(params)) {
    if (p.type !== "formal_parameter") continue;
    const anns = annotationsOf(p);
    const varName = field(p, "name")?.text ?? "";
    const typeName = field(p, "type")?.text ?? "";
    let matched = false;
    for (const ann of anns) {
      const kind = own(SOURCE_ANNOTATION_KIND, ann.name);
      if (!kind) continue;
      matched = true;
      const resolvedName = annotationStringValue(ann) ?? varName;
      out.push({
        kind,
        location: { file: rel, line: lineOf(p) },
        description: `@${ann.name} ${resolvedName}`,
        routeId,
      });
    }
    if (!matched && /HttpServletRequest$/.test(typeName)) {
      out.push({
        kind: "http_request",
        location: { file: rel, line: lineOf(p) },
        description: `HttpServletRequest ${varName}`,
        routeId,
      });
    }
  }
  return out;
}

/** Map one JPA `@Entity` class to an OrmModel with its persistent fields. */
function extractEntity(cls: TSNode, rel: string): OrmModel {
  const name = field(cls, "name")?.text ?? "Entity";
  const fields = fieldsOf(cls).flatMap((fd) => {
    const anns = annotationsOf(fd);
    const isId = anns.some((a) => a.name === "Id" || a.name === "EmbeddedId");
    if (anns.some((a) => a.name === "Transient")) return [];
    const type = field(fd, "type")?.text ?? "";
    const declarator = namedKids(fd).find((c) => c.type === "variable_declarator");
    const fieldName = declarator ? (field(declarator, "name")?.text ?? "") : "";
    if (!fieldName) return [];
    return [{ name: fieldName, type, isId }];
  });
  return { name, file: rel, fields };
}

/** Classify a method-invocation sink (SQL/JPQL/exec/deserialize/reflection/redirect/SpEL). */
function callSink(
  call: TSNode,
  name: string,
  objectText: string,
  concatLocals: ReadonlySet<string>,
  rel: string,
): TaintSink | undefined {
  const at = (kind: TaintSinkKind, description: string): TaintSink => ({
    kind,
    location: { file: rel, line: lineOf(call) },
    description,
  });

  if (SQL_EXEC_METHODS.has(name) && firstArgConcatenated(call, concatLocals)) {
    return at(
      "sql_query",
      `${objectText}.${name}(<string concatenation>) — raw SQL built by concatenation`,
    );
  }
  if (JPQL_METHODS.has(name) && firstArgConcatenated(call, concatLocals)) {
    return at(
      "orm_raw_query",
      `${name}(<string concatenation>) — JPQL/native query built by concatenation`,
    );
  }
  if (name === "exec" && /getRuntime\(\)$|Runtime$/.test(objectText)) {
    return at("command_exec", "Runtime.getRuntime().exec(...) runs an OS command");
  }
  if (name === "readObject") {
    return at("deserialize", "ObjectInputStream.readObject() deserializes untrusted data");
  }
  if (name === "forName" && objectText === "Class") {
    return at("eval", "Class.forName(...) reflective class loading from a name");
  }
  if (name === "parseExpression") {
    return at("eval", "ExpressionParser.parseExpression(...) evaluates a SpEL expression");
  }
  if (name === "sendRedirect") {
    return at("redirect", "response.sendRedirect(...) redirect to a caller-influenced URL");
  }
  return undefined;
}

/** Extract the property key from a `@Value("${key:default}")` expression. */
function extractValueKey(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const m = /\$\{\s*([A-Za-z0-9_.-]+)\s*(?::[^}]*)?\}/.exec(raw);
  return m?.[1];
}

function unquoteText(text: string): string {
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) return text.slice(1, -1);
  return text;
}
