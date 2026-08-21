/**
 * Telemetry-surfaces detection (B6) — Layer 0 sub-step, same convention as
 * `threat-model.ts` (E6): an ADDITIONAL step inside `build.ts`'s existing
 * Layer 0 execution, deterministic (no LLM required), additive, and never
 * fails the scan (an analyzer error degrades to "nothing detected" rather
 * than throwing).
 *
 * ⛔ NOT the same thing as B5's purple-team loop: B5 runs an ACTUAL red-team
 * scenario and checks whether a GENERATED `DetectionRule` fires against the
 * resulting LIVE telemetry (packages/confirm/src/scenarios.ts, a later,
 * separate wave item depending on B3's rules existing). This module answers
 * a narrower, STATIC question, entirely from the App Map's own structural
 * evidence: does the target even HAVE observability a rule could ever match
 * against — a structured-logging library dependency, a detected APM/
 * observability tool, and (TypeScript/JavaScript only today) does THIS
 * SPECIFIC route's handler actually call a logging function, or is it
 * silent?
 *
 * Two independent signals, both real evidence — never a guess:
 *   1. Repo-level: {@link detectRepoTelemetry} matches KNOWN structured-
 *      logging and APM/observability package names against the repo's real
 *      dependency manifests (package.json for Node; requirements.txt /
 *      pyproject.toml for Python; pom.xml / build.gradle[.kts] for JVM) —
 *      the exact "check what's actually detectable via this codebase's
 *      existing import/dependency-scanning infrastructure" the task calls
 *      for, mirroring `packages/discovery/src/detectors/sca.ts`'s manifest-
 *      driven approach and `sources.ts`'s own `inv.dependencies` parse for
 *      Node. Python's stdlib `logging` module has no manifest entry (it
 *      ships with the interpreter), so it is additionally detected via a
 *      real source-level `import logging` / `import structlog` scan.
 *   2. Per-route: {@link detectRouteTelemetry} is a real ts-morph AST scan
 *      (TypeScript/JavaScript only — the only stack with a syntactic AST
 *      this cheaply available here, same scope boundary A12's
 *      `collectCalledPackages` and A18's `route-models.ts` already draw) of
 *      each route handler's own body for an actual logging call: a bound
 *      structured-logger instance (`winston.createLogger(...)`,
 *      `pino()`, `bunyan.createLogger(...)`, `log4js.getLogger(...)`, or a
 *      directly-imported structured-logging binding) invoked with a real
 *      logger-shaped method name, or a bare `console.*` call (real evidence
 *      of SOME logging, but with no structured fields — see the module doc
 *      on `RouteLoggerKindSchema`). A route whose handler node cannot be
 *      statically resolved is OMITTED from the result, never recorded as
 *      "silent" — the same absent-vs-empty discipline `Route.referencedModels`
 *      (A18) already established.
 */
import { join } from "node:path";
import fg from "fast-glob";
import { Node, Project, SyntaxKind } from "ts-morph";
import type { SourceFile } from "ts-morph";
import type {
  AppMap,
  ObservabilityTool,
  ObservabilityToolKind,
  Route,
  RouteLoggerKind,
  RouteTelemetry,
  StructuredLoggingLibrary,
  TelemetrySurfaces,
} from "@montr/contracts";
import { TelemetrySurfacesSchema } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";
import { readRepoFile } from "./workspace.js";
import { createProject, type FileInventory } from "./sources.js";

const IGNORE = ["**/node_modules/**", "**/dist/**", "**/.git/**", "**/build/**", "**/target/**"];

// ---------------------------------------------------------------------------
// 1. Repo-level structured-logging + APM/observability detection.
// ---------------------------------------------------------------------------

/** Node.js dependency name -> structured-logging library id. */
const NODE_LOGGING_PACKAGES: Record<string, StructuredLoggingLibrary> = {
  winston: "winston",
  pino: "pino",
  bunyan: "bunyan",
  log4js: "log4js",
  loglevel: "loglevel",
  tslog: "tslog",
};

/** Substring found in requirements.txt/pyproject.toml/Pipfile -> library id. */
const PYTHON_LOGGING_MANIFEST_MATCHERS: ReadonlyArray<[string, StructuredLoggingLibrary]> = [
  ["structlog", "structlog"],
];

/** Substring found in pom.xml/build.gradle[.kts] -> library id. */
const JAVA_LOGGING_MANIFEST_MATCHERS: ReadonlyArray<[string, StructuredLoggingLibrary]> = [
  ["slf4j", "slf4j"],
  ["logback", "logback"],
];

interface ApmMatcher {
  kind: ObservabilityToolKind;
  /** Real dependency/manifest substrings for this ecosystem. */
  matchers: readonly string[];
}

const NODE_APM_MATCHERS: readonly ApmMatcher[] = [
  { kind: "datadog", matchers: ["dd-trace", "hot-shots", "datadog-metrics"] },
  { kind: "new_relic", matchers: ["newrelic"] },
  {
    kind: "opentelemetry",
    matchers: ["@opentelemetry/api", "@opentelemetry/sdk-node", "@opentelemetry/sdk-trace-node"],
  },
  {
    kind: "sentry",
    matchers: ["@sentry/node", "@sentry/nextjs", "@sentry/react", "@sentry/browser"],
  },
  {
    kind: "cloudwatch",
    matchers: [
      "winston-cloudwatch",
      "@aws-sdk/client-cloudwatch-logs",
      "@aws-sdk/client-cloudwatch",
    ],
  },
];

const PYTHON_APM_MATCHERS: readonly ApmMatcher[] = [
  { kind: "datadog", matchers: ["ddtrace"] },
  { kind: "new_relic", matchers: ["newrelic"] },
  { kind: "opentelemetry", matchers: ["opentelemetry-sdk", "opentelemetry-api"] },
  { kind: "sentry", matchers: ["sentry-sdk"] },
  { kind: "cloudwatch", matchers: ["watchtower"] },
];

const JAVA_APM_MATCHERS: readonly ApmMatcher[] = [
  { kind: "datadog", matchers: ["dd-trace-java", "dd-trace-api"] },
  { kind: "new_relic", matchers: ["newrelic-agent", "newrelic-api"] },
  { kind: "opentelemetry", matchers: ["io.opentelemetry"] },
  { kind: "sentry", matchers: ["io.sentry"] },
  { kind: "cloudwatch", matchers: ["aws-java-sdk-cloudwatch", "cloudwatchlogs"] },
];

function matchApm(haystack: string, matchers: readonly ApmMatcher[]): ObservabilityTool[] {
  const found: ObservabilityTool[] = [];
  for (const { kind, matchers: names } of matchers) {
    for (const name of names) {
      if (haystack.includes(name)) {
        found.push({ kind, packageName: name });
        break; // one hit per tool kind is enough evidence
      }
    }
  }
  return found;
}

interface RepoTelemetrySignals {
  loggingLibraries: StructuredLoggingLibrary[];
  observabilityTools: ObservabilityTool[];
}

/** Node.js: real `package.json` dependency-name matching (mirrors `sources.ts`'s own parse). */
function detectNodeSignals(inventory: FileInventory): RepoTelemetrySignals {
  const loggingLibraries: StructuredLoggingLibrary[] = [];
  for (const [pkg, lib] of Object.entries(NODE_LOGGING_PACKAGES)) {
    if (Object.prototype.hasOwnProperty.call(inventory.dependencies, pkg))
      loggingLibraries.push(lib);
  }
  const depNames = Object.keys(inventory.dependencies).join(" ");
  const observabilityTools = matchApm(depNames, NODE_APM_MATCHERS);
  return { loggingLibraries, observabilityTools };
}

/** Python: real manifest-content + real `import` source-scan (stdlib `logging` has no manifest entry). */
async function detectPythonSignals(dir: string): Promise<RepoTelemetrySignals> {
  const loggingLibraries = new Set<StructuredLoggingLibrary>();
  const observabilityTools: ObservabilityTool[] = [];

  const manifestFiles = await fg(["requirements*.txt", "pyproject.toml", "Pipfile", "setup.py"], {
    cwd: dir,
    ignore: IGNORE,
    followSymbolicLinks: false,
    dot: false,
  });
  let manifestText = "";
  for (const rel of manifestFiles) {
    const content = await readRepoFile(dir, rel);
    if (content) manifestText += `\n${content}`;
  }
  for (const [needle, lib] of PYTHON_LOGGING_MANIFEST_MATCHERS) {
    if (manifestText.includes(needle)) loggingLibraries.add(lib);
  }
  observabilityTools.push(...matchApm(manifestText, PYTHON_APM_MATCHERS));

  // Stdlib `logging`/`structlog` usage: a real source-level import scan, since
  // the stdlib module never appears in a dependency manifest.
  const pyFiles = await fg(["**/*.py"], { cwd: dir, ignore: IGNORE, followSymbolicLinks: false });
  const IMPORT_LOGGING_RE =
    /^\s*(?:import\s+logging\b|from\s+logging\b|import\s+structlog\b|from\s+structlog\b)/m;
  for (const rel of pyFiles.slice(0, 500)) {
    // Bounded scan — a repo-wide import presence check, not a full parse; 500
    // files is generous headroom for a real project without unbounded cost.
    const content = await readRepoFile(dir, rel);
    if (!content) continue;
    if (/structlog/.test(content) && IMPORT_LOGGING_RE.test(content))
      loggingLibraries.add("structlog");
    else if (IMPORT_LOGGING_RE.test(content)) loggingLibraries.add("logging");
    if (loggingLibraries.has("structlog") && loggingLibraries.has("logging")) break;
  }

  return { loggingLibraries: [...loggingLibraries], observabilityTools };
}

/** JVM: real `pom.xml` / `build.gradle[.kts]` content matching. */
async function detectJavaSignals(dir: string): Promise<RepoTelemetrySignals> {
  const loggingLibraries = new Set<StructuredLoggingLibrary>();
  const manifestFiles = await fg(["pom.xml", "**/build.gradle", "**/build.gradle.kts"], {
    cwd: dir,
    ignore: IGNORE,
    followSymbolicLinks: false,
  });
  let manifestText = "";
  for (const rel of manifestFiles) {
    const content = await readRepoFile(dir, rel);
    if (content) manifestText += `\n${content}`;
  }
  for (const [needle, lib] of JAVA_LOGGING_MANIFEST_MATCHERS) {
    if (manifestText.includes(needle)) loggingLibraries.add(lib);
  }
  const observabilityTools = matchApm(manifestText, JAVA_APM_MATCHERS);
  return { loggingLibraries: [...loggingLibraries], observabilityTools };
}

/**
 * Detect repo-level structured-logging + APM signals across every stack
 * present. Always returns a result (empty arrays, never a throw) — an
 * unreadable/missing manifest degrades to "nothing detected", the same
 * fail-safe posture `threat-model.ts` and `sources.ts` already use.
 */
export async function detectRepoTelemetry(
  dir: string,
  inventory: FileInventory,
  logger?: Logger,
): Promise<RepoTelemetrySignals> {
  try {
    const node = detectNodeSignals(inventory);
    const [python, java] = await Promise.all([detectPythonSignals(dir), detectJavaSignals(dir)]);
    const loggingLibraries = [
      ...new Set([...node.loggingLibraries, ...python.loggingLibraries, ...java.loggingLibraries]),
    ];
    const observabilityTools = [
      ...node.observabilityTools,
      ...python.observabilityTools,
      ...java.observabilityTools,
    ];
    return { loggingLibraries, observabilityTools };
  } catch (err) {
    logger?.warn("appmap.telemetry_surfaces.repo_detect_failed", {
      message: err instanceof Error ? err.message : "unknown",
    });
    return { loggingLibraries: [], observabilityTools: [] };
  }
}

// ---------------------------------------------------------------------------
// 2. Per-route logging-call detection (TypeScript/JavaScript only).
// ---------------------------------------------------------------------------

const CONSOLE_METHODS = new Set(["log", "info", "warn", "error", "debug"]);
const LOGGER_METHOD_NAMES = new Set([
  "info",
  "warn",
  "error",
  "debug",
  "trace",
  "log",
  "fatal",
  "child",
]);
const KNOWN_LOGGING_PACKAGE_NAMES = new Set(Object.keys(NODE_LOGGING_PACKAGES));

/** The base identifier of a (possibly chained) member-access expression: `a.b.c` -> `a`. */
function leftmostIdentifier(expr: Node): string | undefined {
  let cur: Node = expr;
  while (Node.isPropertyAccessExpression(cur) || Node.isElementAccessExpression(cur)) {
    cur = cur.getExpression();
  }
  return Node.isIdentifier(cur) ? cur.getText() : undefined;
}

/** The property-access method name of a call's callee, if any (`logger.info(...)` -> `"info"`). */
function calleeMethodName(callee: Node): string | undefined {
  return Node.isPropertyAccessExpression(callee) ? callee.getName() : undefined;
}

/** Local-identifier -> known logging package name, from THIS file's direct imports/`require`. */
function collectLoggingPackageBindings(sf: SourceFile): Map<string, StructuredLoggingLibrary> {
  const bindings = new Map<string, StructuredLoggingLibrary>();
  const add = (local: string | undefined, pkg: string): void => {
    if (!local || !KNOWN_LOGGING_PACKAGE_NAMES.has(pkg)) return;
    bindings.set(local, NODE_LOGGING_PACKAGES[pkg]!);
  };
  for (const imp of sf.getImportDeclarations()) {
    if (imp.isTypeOnly()) continue;
    const spec = imp.getModuleSpecifierValue();
    const def = imp.getDefaultImport();
    if (def) add(def.getText(), spec);
    const ns = imp.getNamespaceImport();
    if (ns) add(ns.getText(), spec);
    for (const named of imp.getNamedImports()) {
      if (named.isTypeOnly()) continue;
      add(named.getAliasNode()?.getText() ?? named.getNameNode().getText(), spec);
    }
  }
  for (const vs of sf.getVariableStatements()) {
    for (const decl of vs.getDeclarations()) {
      const init = decl.getInitializer();
      if (!init || !Node.isCallExpression(init)) continue;
      if (init.getExpression().getText() !== "require") continue;
      const arg = init.getArguments()[0];
      if (!arg || !Node.isStringLiteral(arg)) continue;
      const nameNode = decl.getNameNode();
      if (Node.isIdentifier(nameNode)) add(nameNode.getText(), arg.getLiteralText());
    }
  }
  return bindings;
}

/**
 * Local identifiers imported from a RELATIVE specifier in this file (e.g. a
 * local `./logger.js` wrapper module) — no target resolution, just "this
 * name came from a relative import", used only as a weaker composite signal
 * below (never sufficient on its own).
 */
function collectRelativeImportBindings(sf: SourceFile): Set<string> {
  const names = new Set<string>();
  for (const imp of sf.getImportDeclarations()) {
    if (imp.isTypeOnly() || !imp.getModuleSpecifierValue().startsWith(".")) continue;
    const def = imp.getDefaultImport();
    if (def) names.add(def.getText());
    const ns = imp.getNamespaceImport();
    if (ns) names.add(ns.getText());
    for (const named of imp.getNamedImports()) {
      if (!named.isTypeOnly())
        names.add(named.getAliasNode()?.getText() ?? named.getNameNode().getText());
    }
  }
  return names;
}

/**
 * Local variable names bound to a constructed structured logger, e.g.
 * `const logger = winston.createLogger(...)`, `const log = pino()`,
 * `const logger = bunyan.createLogger(...)`, `const log = log4js.getLogger(...)`.
 */
function collectConstructedLoggerVars(
  sf: SourceFile,
  packageBindings: ReadonlyMap<string, StructuredLoggingLibrary>,
): Map<string, StructuredLoggingLibrary> {
  const vars = new Map<string, StructuredLoggingLibrary>();
  for (const vs of sf.getVariableStatements()) {
    for (const decl of vs.getDeclarations()) {
      const init = decl.getInitializer();
      const nameNode = decl.getNameNode();
      if (!init || !Node.isCallExpression(init) || !Node.isIdentifier(nameNode)) continue;
      const base = leftmostIdentifier(init.getExpression());
      const lib = base ? packageBindings.get(base) : undefined;
      if (lib) vars.set(nameNode.getText(), lib);
    }
  }
  return vars;
}

/** Every function-like node in a file, for matching a route handler by its start line. */
function findHandlerNode(sf: SourceFile, line: number): Node | undefined {
  const candidates = [
    ...sf.getDescendantsOfKind(SyntaxKind.FunctionDeclaration),
    ...sf.getDescendantsOfKind(SyntaxKind.ArrowFunction),
    ...sf.getDescendantsOfKind(SyntaxKind.FunctionExpression),
  ];
  return candidates.find((fn) => fn.getStartLineNumber() === line);
}

interface LoggingScanResult {
  hasLoggingCall: boolean;
  loggerKind?: RouteLoggerKind;
  sample?: string;
}

function truncate(text: string, max = 120): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > max ? `${oneLine.slice(0, max)}…` : oneLine;
}

/** Scan one handler function body for a real logging call. Structured beats console. */
function scanForLoggingCalls(
  sf: SourceFile,
  fn: Node,
  repoHasStructuredLogging: boolean,
): LoggingScanResult {
  const packageBindings = collectLoggingPackageBindings(sf);
  const loggerVars = collectConstructedLoggerVars(sf, packageBindings);
  const relativeBindings = collectRelativeImportBindings(sf);

  let consoleHit: string | undefined;
  let structuredHit: string | undefined;

  for (const call of fn.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression();
    const base = leftmostIdentifier(callee);
    const method = calleeMethodName(callee);
    if (!base) continue;

    if (base === "console" && method && CONSOLE_METHODS.has(method)) {
      consoleHit ??= truncate(call.getText());
      continue;
    }
    if (structuredHit) continue;

    // Direct call on a package-imported binding itself, e.g. `pino().info(...)`
    // is rare; the common real-world shapes are covered below.
    if (loggerVars.has(base) && method && LOGGER_METHOD_NAMES.has(method)) {
      structuredHit = truncate(call.getText());
      continue;
    }
    // A directly package-imported binding used as the logger itself
    // (e.g. `import pino from "pino"; const log = pino; ... log.info(...)`
    // is unusual, but a bare package-bound identifier called with a real
    // logger method name is still real evidence.
    if (packageBindings.has(base) && method && LOGGER_METHOD_NAMES.has(method)) {
      structuredHit = truncate(call.getText());
      continue;
    }
    // Weaker composite signal: a local `./logger`-style wrapper, called with
    // a real logger method name, AND the repo is independently known (via
    // real dependency-manifest evidence) to have a structured-logging
    // library installed somewhere. Never sufficient alone.
    if (
      repoHasStructuredLogging &&
      relativeBindings.has(base) &&
      method &&
      LOGGER_METHOD_NAMES.has(method) &&
      method !== "log"
    ) {
      structuredHit = truncate(call.getText());
    }
  }

  if (structuredHit)
    return { hasLoggingCall: true, loggerKind: "structured", sample: structuredHit };
  if (consoleHit) return { hasLoggingCall: true, loggerKind: "console", sample: consoleHit };
  return { hasLoggingCall: false };
}

/**
 * Real ts-morph AST scan of each TS/JS route's handler for a logging call.
 * Routes with no resolvable handler node are OMITTED from the result (never
 * recorded as silent — see the module doc). `project` should already have
 * every TS/JS source file loaded (mirrors `createProject`'s own convention).
 */
export function detectRouteTelemetry(
  project: Project,
  dir: string,
  routes: readonly Route[],
  repoHasStructuredLogging: boolean,
): RouteTelemetry[] {
  const out: RouteTelemetry[] = [];
  for (const route of routes) {
    const file = route.handler?.file;
    const line = route.handler?.line;
    if (!file || line === undefined) continue;
    const sf = project.getSourceFile(join(dir, file));
    if (!sf) continue;
    const fn = findHandlerNode(sf, line);
    if (!fn) continue;
    const scan = scanForLoggingCalls(sf, fn, repoHasStructuredLogging);
    out.push({
      path: route.path,
      method: route.method,
      hasLoggingCall: scan.hasLoggingCall,
      ...(scan.loggerKind ? { loggerKind: scan.loggerKind } : {}),
      ...(scan.sample ? { sample: scan.sample } : {}),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 3. Entry point — combine both signals into `TelemetrySurfaces`.
// ---------------------------------------------------------------------------

export interface BuildTelemetrySurfacesOptions {
  dir: string;
  inventory: FileInventory;
  /** A pre-built project covering the same source files, reused when available
   * (mirrors `build.ts`'s diff-project reuse) — built fresh otherwise. */
  project?: Project;
  logger?: Logger;
}

/**
 * Build the full `TelemetrySurfaces` for an App Map already assembled with
 * its final `routes`. Never throws — any analyzer failure degrades to "no
 * signal detected" for that piece, the same fail-safe posture as
 * `deriveThreatModel`.
 */
export async function buildTelemetrySurfaces(
  appMap: AppMap,
  opts: BuildTelemetrySurfacesOptions,
): Promise<TelemetrySurfaces> {
  const { loggingLibraries, observabilityTools } = await detectRepoTelemetry(
    opts.dir,
    opts.inventory,
    opts.logger,
  );
  const hasStructuredLogging = loggingLibraries.length > 0;

  let routeTelemetry: RouteTelemetry[] = [];
  const tsRoutes = appMap.routes.filter((r) =>
    /\.(tsx?|jsx?|mjs|cjs)$/i.test(r.handler?.file ?? ""),
  );
  if (tsRoutes.length > 0) {
    try {
      const project = opts.project ?? createProject(opts.dir, opts.inventory.sourceFiles);
      routeTelemetry = detectRouteTelemetry(project, opts.dir, tsRoutes, hasStructuredLogging);
    } catch (err) {
      opts.logger?.warn("appmap.telemetry_surfaces.route_detect_failed", {
        message: err instanceof Error ? err.message : "unknown",
      });
    }
  }

  return TelemetrySurfacesSchema.parse({
    hasStructuredLogging,
    loggingLibraries,
    observabilityTools,
    routes: routeTelemetry,
  } satisfies TelemetrySurfaces);
}
