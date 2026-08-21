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
  /** True when the persisted map is older than the current commit (DECIDE-2). */
  stale: z.boolean().default(false),
  rebuildPolicy: AppMapRebuildPolicySchema.default("rebuild_on_stale_commit"),
});
export type AppMap = z.infer<typeof AppMapSchema>;
