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
  /** True when the persisted map is older than the current commit (DECIDE-2). */
  stale: z.boolean().default(false),
  rebuildPolicy: AppMapRebuildPolicySchema.default("rebuild_on_stale_commit"),
});
export type AppMap = z.infer<typeof AppMapSchema>;
