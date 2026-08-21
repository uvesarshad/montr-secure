import { z } from "zod";
import {
  IdSchema,
  IsoDateTimeSchema,
  CommitShaSchema,
  FilePathSchema,
  SourceLocationSchema,
} from "./primitives.js";
import {
  HttpMethodSchema,
  AuthStateSchema,
  LanguageSchema,
  FrameworkSchema,
  TaintSourceKindSchema,
  TaintSinkKindSchema,
} from "./enums.js";
import { ThreatModelSchema } from "./threat-model.js";

/**
 * PRD §9 — the App Map data model. The App Map is the substrate for correlation
 * (Layer 2) and is persisted per-client (DECIDE-2).
 */

/**
 * A CRUD-shaped operation a route handler performs against an ORM model,
 * coarsened from the underlying Prisma method (e.g. `findMany` → `read`,
 * `upsert` → `write`, `deleteMany` → `delete`). Used for IDOR / broken-access-
 * control reasoning (A18) — knowing a route *reads* vs *writes* / *deletes* a
 * model matters more than the exact Prisma method name.
 */
export const RouteModelOperationSchema = z.enum(["read", "write", "delete"]);
export type RouteModelOperation = z.infer<typeof RouteModelOperationSchema>;

/** One ORM model a route handler statically references, + which operations. */
export const RouteModelRefSchema = z.object({
  modelName: z.string().min(1),
  operations: z.array(RouteModelOperationSchema).default([]),
});
export type RouteModelRef = z.infer<typeof RouteModelRefSchema>;

/** A registered route / entry point (path + method + auth state). */
export const RouteSchema = z.object({
  id: IdSchema.optional(),
  path: z.string().min(1),
  method: HttpMethodSchema,
  authState: AuthStateSchema.default("unknown"),
  isApiRoute: z.boolean().default(false),
  handler: SourceLocationSchema.optional(),
  /** Which auth middleware/guard gates this route, if known. */
  authGate: z.string().optional(),
  /**
   * ORM model(s) this route's handler statically queries (A18 route→model
   * cross-reference — see `packages/appmap/src/languages/typescript/route-models.ts`).
   * Absent (not an empty array) when nothing was resolved, to keep routes that
   * were never analyzed for this indistinguishable from routes proven to touch
   * no model.
   */
  referencedModels: z.array(RouteModelRefSchema).optional(),
});
export type Route = z.infer<typeof RouteSchema>;

export const EntrypointKindSchema = z.enum([
  "http_route",
  "cli",
  "job",
  "cron",
  "webhook",
  "event_handler",
  "graphql_resolver",
]);
export type EntrypointKind = z.infer<typeof EntrypointKindSchema>;

export const EntrypointSchema = z.object({
  id: IdSchema.optional(),
  kind: EntrypointKindSchema,
  name: z.string().min(1),
  location: SourceLocationSchema.optional(),
});
export type Entrypoint = z.infer<typeof EntrypointSchema>;

export const DataStoreKindSchema = z.enum([
  "postgres",
  "mysql",
  "sqlite",
  "mongodb",
  "redis",
  "elasticsearch",
  "other",
]);
export type DataStoreKind = z.infer<typeof DataStoreKindSchema>;

export const DataStoreSchema = z.object({
  id: IdSchema.optional(),
  kind: DataStoreKindSchema,
  name: z.string().min(1),
  /** e.g. accessed "via" prisma. */
  accessedVia: FrameworkSchema.optional(),
});
export type DataStore = z.infer<typeof DataStoreSchema>;

/** An ORM model — for Prisma this is derived deterministically from the DMMF. */
export const OrmModelSchema = z.object({
  id: IdSchema.optional(),
  name: z.string().min(1),
  dataStore: z.string().optional(),
  file: FilePathSchema.optional(),
  fields: z
    .array(z.object({ name: z.string(), type: z.string(), isId: z.boolean().default(false) }))
    .default([]),
});
export type OrmModel = z.infer<typeof OrmModelSchema>;

export const ThirdPartyCallKindSchema = z.enum(["http", "sdk", "grpc", "queue", "other"]);
export type ThirdPartyCallKind = z.infer<typeof ThirdPartyCallKindSchema>;

export const ThirdPartyCallSchema = z.object({
  id: IdSchema.optional(),
  kind: ThirdPartyCallKindSchema,
  name: z.string().min(1),
  target: z.string().optional(),
  location: SourceLocationSchema.optional(),
});
export type ThirdPartyCall = z.infer<typeof ThirdPartyCallSchema>;

export const EnvSecretSurfaceKindSchema = z.enum([
  "process_env",
  "config_file",
  "dotenv",
  "k8s_secret",
]);
export type EnvSecretSurfaceKind = z.infer<typeof EnvSecretSurfaceKindSchema>;

/** Where secrets/config enter the app (`process.env`, config files, ...). */
export const EnvSecretSurfaceSchema = z.object({
  id: IdSchema.optional(),
  kind: EnvSecretSurfaceKindSchema,
  name: z.string().min(1),
  location: SourceLocationSchema.optional(),
});
export type EnvSecretSurface = z.infer<typeof EnvSecretSurfaceSchema>;

/** A point where untrusted input enters (req input → ...). */
export const TaintSourceSchema = z.object({
  id: IdSchema.optional(),
  kind: TaintSourceKindSchema,
  location: SourceLocationSchema,
  description: z.string().optional(),
  /** Route/entrypoint this source is reachable from, if known. */
  routeId: IdSchema.optional(),
});
export type TaintSource = z.infer<typeof TaintSourceSchema>;

/** A dangerous operation tainted input may reach (db/exec/fs/response). */
export const TaintSinkSchema = z.object({
  id: IdSchema.optional(),
  kind: TaintSinkKindSchema,
  location: SourceLocationSchema,
  description: z.string().optional(),
});
export type TaintSink = z.infer<typeof TaintSinkSchema>;

/**
 * How a {@link TaintFlowEdge} determined the source reaches the sink through an
 * intermediate function, rather than same-file line proximity.
 */
export const TaintFlowResolutionSchema = z.enum([
  /** The tainted argument is used directly as the sink's argument inside the callee. */
  "direct-call",
  /** The tainted argument is returned by the callee; the caller's use of the
   * return value (passed straight to a sink, or assigned then used by a sink)
   * is the second hop. */
  "return-propagated",
]);
export type TaintFlowResolution = z.infer<typeof TaintFlowResolutionSchema>;

/**
 * A source -> sink taint flow RESOLVED across an explicit, bounded call chain —
 * i.e. a language analyzer actually named the function that carries the tainted
 * value from its origin to the sink (optionally crossing a file boundary), as
 * opposed to `grounding.ts`'s same-file nearest-line proximity guess. Emitted
 * only by analyzers that implement this (TS/JS today — see
 * `packages/appmap/src/languages/typescript/callgraph.ts` for exactly which
 * patterns are, and are not, resolved). Absence of an edge for a given
 * source/sink pair is NOT a claim that no flow exists — Layer 2 falls back to
 * the proximity heuristic whenever no edge is present.
 */
export const TaintFlowEdgeSchema = z.object({
  id: IdSchema.optional(),
  /** Where the tainted value originates (the argument expression at the outermost call). */
  sourceLocation: SourceLocationSchema,
  sourceKind: TaintSourceKindSchema.optional(),
  /** The intermediate function/method name that carried the taint, if resolvable. */
  throughFunction: z.string().optional(),
  throughLocation: SourceLocationSchema.optional(),
  /** Where the sink call itself sits (this is what a candidate finding's location should match). */
  sinkLocation: SourceLocationSchema,
  sinkKind: TaintSinkKindSchema,
  resolution: TaintFlowResolutionSchema,
  /** 1 = tainted arg flows straight into the sink inside the callee; 2 = via one intermediate return hop. */
  hops: z.number().int().min(1).max(2),
  /** True when source and sink are not in the same file (the case the old heuristic missed). */
  crossFile: z.boolean(),
});
export type TaintFlowEdge = z.infer<typeof TaintFlowEdgeSchema>;

/**
 * Telemetry / observability surfaces (B6) — the target application's
 * PRE-EXISTING logging/monitoring posture, ingested during Layer 0 (see
 * `packages/appmap/src/telemetry-surfaces.ts`). Distinct from B5's
 * purple-team loop, which runs an actual scenario and checks whether a
 * GENERATED rule fires against LIVE telemetry; this is a static assessment
 * of whether the target even HAS telemetry a rule could ever match against,
 * derived the same way A12's SCA reachability and E6's threat model are —
 * real dependency-manifest presence and real per-route AST call detection,
 * never a guess.
 */
export const StructuredLoggingLibrarySchema = z.enum([
  // Node.js
  "winston",
  "pino",
  "bunyan",
  "log4js",
  "loglevel",
  "tslog",
  // Python
  "structlog",
  "logging",
  // JVM
  "slf4j",
  "logback",
]);
export type StructuredLoggingLibrary = z.infer<typeof StructuredLoggingLibrarySchema>;

export const ObservabilityToolKindSchema = z.enum([
  "datadog",
  "new_relic",
  "opentelemetry",
  "sentry",
  "cloudwatch",
]);
export type ObservabilityToolKind = z.infer<typeof ObservabilityToolKindSchema>;

/** One detected APM/observability integration, with the real matched dependency. */
export const ObservabilityToolSchema = z.object({
  kind: ObservabilityToolKindSchema,
  /** The actual package/dependency name that matched (e.g. "@sentry/node"), not a guess. */
  packageName: z.string().min(1),
});
export type ObservabilityTool = z.infer<typeof ObservabilityToolSchema>;

/**
 * `"structured"` — the call resolves to a real structured-logging library
 * binding (a known package import, or a factory call like
 * `winston.createLogger(...)`). `"console"` — the only logging signal found
 * is a bare `console.*` call: real evidence of SOME logging, but with no
 * structured fields a detection rule could reliably match on.
 */
export const RouteLoggerKindSchema = z.enum(["structured", "console"]);
export type RouteLoggerKind = z.infer<typeof RouteLoggerKindSchema>;

/**
 * Per-route logging presence. One entry per route that was actually
 * ANALYZED (TypeScript/JavaScript route handlers only today — see
 * `telemetry-surfaces.ts`'s module doc); a route absent from
 * `TelemetrySurfaces.routes` was never analyzed, which is NOT the same
 * claim as "proven silent" (mirrors `Route.referencedModels`'s
 * absent-vs-empty discipline, A18).
 */
export const RouteTelemetrySchema = z.object({
  path: z.string().min(1),
  method: HttpMethodSchema,
  /** True when a real logging call (structured or console) was found in the handler. */
  hasLoggingCall: z.boolean(),
  loggerKind: RouteLoggerKindSchema.optional(),
  /** A truncated real source snippet of the matched call — evidence, not a claim. */
  sample: z.string().optional(),
});
export type RouteTelemetry = z.infer<typeof RouteTelemetrySchema>;

/** The target application's structural telemetry/observability posture (B6). */
export const TelemetrySurfacesSchema = z.object({
  /** True when at least one known structured-logging library is a real dependency. */
  hasStructuredLogging: z.boolean(),
  loggingLibraries: z.array(StructuredLoggingLibrarySchema).default([]),
  observabilityTools: z.array(ObservabilityToolSchema).default([]),
  routes: z.array(RouteTelemetrySchema).default([]),
});
export type TelemetrySurfaces = z.infer<typeof TelemetrySurfacesSchema>;

/**
 * DECIDE-2: AppMap is persisted per client, encrypted, and rebuilt on a stale
 * commit by default.
 */
export const AppMapRebuildPolicySchema = z.enum([
  "rebuild_on_stale_commit",
  "always_rebuild",
  "never_rebuild",
]);
export type AppMapRebuildPolicy = z.infer<typeof AppMapRebuildPolicySchema>;

/** The full structural model of the target app (PRD §9). */
export const AppMapSchema = z.object({
  id: IdSchema,
  clientId: IdSchema,
  scanId: IdSchema.optional(),
  repo: z.string().min(1),
  branch: z.string().min(1),
  commitSha: CommitShaSchema,
  createdAt: IsoDateTimeSchema,
  languages: z.array(LanguageSchema).default([]),
  frameworks: z.array(FrameworkSchema).default([]),
  entrypoints: z.array(EntrypointSchema).default([]),
  routes: z.array(RouteSchema).default([]),
  dataStores: z.array(DataStoreSchema).default([]),
  ormModels: z.array(OrmModelSchema).default([]),
  thirdPartyCalls: z.array(ThirdPartyCallSchema).default([]),
  envSecretSurfaces: z.array(EnvSecretSurfaceSchema).default([]),
  taintSources: z.array(TaintSourceSchema).default([]),
  taintSinks: z.array(TaintSinkSchema).default([]),
  /** Resolved cross-function/cross-file taint flows (see {@link TaintFlowEdgeSchema}). */
  taintFlows: z.array(TaintFlowEdgeSchema).default([]),
  /**
   * Threat model derived from this map at the end of Layer 0 (E6/B7 — see
   * `packages/appmap/src/threat-model.ts`): trust boundaries, attack-surface
   * plausibility per category, abuse cases, and the scope hints that drive
   * Layer 1/Layer 3 prioritization. `deriveThreatModel` always attaches a
   * result (a deterministic baseline runs even with no LLM gateway wired), so
   * absence here means Layer 0 itself never ran against this object (e.g. a
   * hand-built test fixture), not that derivation was skipped. Populated on the
   * in-memory AppMap object the same way A18's `Route.referencedModels` is: NOT
   * yet persisted through `packages/state-store` (no Prisma column), so a map
   * reloaded from Postgres after a fresh `appMaps.get()` will not carry it — a
   * follow-up migration, out of scope here.
   */
  threatModel: ThreatModelSchema.optional(),
  /**
   * The target's pre-existing telemetry/observability posture (B6 — see
   * `packages/appmap/src/telemetry-surfaces.ts`): structured-logging library
   * presence, detected APM/observability tool integrations, and per-route
   * logging-call presence. Populated deterministically as an additional
   * Layer 0 step, no LLM required. Same in-memory-only persistence
   * limitation as `threatModel`/`Route.referencedModels` above — not yet a
   * Prisma column, so a map reloaded from Postgres will not carry it.
   */
  telemetrySurfaces: TelemetrySurfacesSchema.optional(),
  /** True when the persisted map is older than the current commit (DECIDE-2). */
  stale: z.boolean().default(false),
  rebuildPolicy: AppMapRebuildPolicySchema.default("rebuild_on_stale_commit"),
});
export type AppMap = z.infer<typeof AppMapSchema>;
