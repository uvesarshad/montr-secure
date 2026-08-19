/**
 * Language-plugin contract for Layer 0 App-Map construction.
 *
 * The App Map (PRD §9) is STACK-AGNOSTIC — its shapes (routes, orm_models,
 * third_party, env_surface, taint sources/sinks) live in @montr/contracts and
 * carry no language-specific fields. A {@link LanguageAnalyzer} is the ONLY place
 * stack knowledge lives: it detects whether it applies to a repo and parses the
 * language-agnostic App-Map pieces. `buildAppMap` detects the languages present,
 * runs every matching analyzer, and merges their contributions.
 *
 * ⛔ Layers 2 (correlation), 4 (fix) and 5 (report) NEVER add stack-specific
 * logic — a new stack (Python/JVM/…) is added by dropping a new analyzer under
 * `languages/<lang>/` and NOTHING ELSE in this package's core.
 */
import type {
  DataStore,
  Entrypoint,
  EnvSecretSurface,
  Framework,
  Language,
  OrmModel,
  Route,
  TaintFlowEdge,
  TaintSink,
  TaintSource,
  ThirdPartyCall,
} from "@montr/contracts";
import type { Logger } from "@montr/telemetry";
import type { FileInventory } from "../sources.js";

/**
 * The language-agnostic App-Map pieces one analyzer contributes. Every field is
 * a slice of {@link import("@montr/contracts").AppMap}; the dispatcher merges the
 * per-language contributions into the final map. Analyzers should return their
 * arrays already deduped + stably sorted (the merge preserves a single
 * contribution verbatim and only re-sorts when several analyzers run).
 */
export interface AppMapContribution {
  languages: Language[];
  frameworks: Framework[];
  entrypoints: Entrypoint[];
  routes: Route[];
  dataStores: DataStore[];
  ormModels: OrmModel[];
  thirdPartyCalls: ThirdPartyCall[];
  envSecretSurfaces: EnvSecretSurface[];
  taintSources: TaintSource[];
  taintSinks: TaintSink[];
  /** Resolved cross-function/cross-file taint flows (optional — empty for
   * analyzers that don't implement interprocedural resolution). */
  taintFlows: TaintFlowEdge[];
}

/** Everything an analyzer needs, assembled once by the dispatcher (offline). */
export interface AnalyzerInput {
  /** Absolute path to the checked-out / in-place repo root. */
  dir: string;
  /**
   * The shared, already-collected file inventory (source files, Prisma schemas,
   * env files, declared deps). Analyzers may also do their OWN language-specific
   * globbing under `dir` (e.g. `.py` sources) when the shared inventory does not
   * surface their files.
   */
  inventory: FileInventory;
  logger: Logger;
  /** ⛔ Kill switch — a long parse should bail when this aborts (fail-safe). */
  signal?: AbortSignal;
}

/**
 * A stack plugin. `detect` is a cheap check (does this repo contain code I
 * handle?); `analyze` performs the deterministic parse. Registration lives in
 * {@link import("./registry.js")} — a new stack adds an analyzer module and is
 * appended there; it does not touch the dispatcher or `buildAppMap`.
 */
export interface LanguageAnalyzer {
  /** Primary language this analyzer owns (also its stable registry key). */
  readonly id: Language;
  /** True when this analyzer should run against the given repo. */
  detect(input: AnalyzerInput): boolean;
  /** Parse the language-agnostic App-Map pieces. Runs only when `detect` is true. */
  analyze(input: AnalyzerInput): Promise<AppMapContribution>;
}

/** An empty contribution — the identity element for the merge + stub default. */
export function emptyContribution(): AppMapContribution {
  return {
    languages: [],
    frameworks: [],
    entrypoints: [],
    routes: [],
    dataStores: [],
    ormModels: [],
    thirdPartyCalls: [],
    envSecretSurfaces: [],
    taintSources: [],
    taintSinks: [],
    taintFlows: [],
  };
}
