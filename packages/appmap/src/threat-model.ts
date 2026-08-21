/**
 * Threat-model derivation (E6) — Layer 0's threat-model SUB-STEP, not a new
 * pipeline layer.
 *
 * ⛔ IMPLEMENTATION CHOICE (documented per the task): `LayerId` is a closed
 * six-member union threaded through `packages/contracts/src/queue.ts`'s
 * `QUEUE_NAMES` / job-data discriminated union / `RETRY_POLICIES`, and
 * `packages/orchestrator/src/{fsm,controller,persist,runner}.ts`'s
 * `LAYER_ORDER`/every layer-keyed `Record<LayerId, ...>`. Inserting a real
 * "layer0.5" id would touch all of those, plus persistence + resume-token
 * shapes — for a step with no gate, no independent retry policy, and no
 * reason to be resumable on its own. So this runs as an ADDITIONAL step
 * inside `packages/appmap/src/build.ts`'s existing Layer 0 execution, strictly
 * AFTER `labelAuthBoundaries` (golden rule #6 — no LLM call before the
 * deterministic map exists) and BEFORE persistence. `controller.ts` and
 * `queue.ts` are UNCHANGED by this feature.
 *
 * Two-tier derivation, mirroring `llm.ts`'s `labelAuthBoundaries` fail-safe
 * shape:
 *   1. {@link buildDeterministicThreatModel} — ALWAYS runs, no LLM required.
 *      Trust boundaries, attack-surface plausibility per category, and a
 *      first pass of abuse cases + scope hints, all derived by inspecting the
 *      App Map's own routes/models/taint sinks/data stores. This is what
 *      makes the mechanism testable and useful even with no gateway wired.
 *   2. {@link deriveThreatModel} — when a gateway is available, asks the model
 *      to ADD abuse-case scenarios and ADDITIONAL priority-category hints on
 *      top of the deterministic baseline. The model may only APPEND; it can
 *      never remove or downgrade a deterministic entry (same "never override
 *      a fail-safe deterministic signal" discipline as auth-boundary
 *      labeling), and every route path / category it proposes is validated
 *      against the real App Map before being accepted (no hallucinated
 *      routes/categories can leak through). ⛔ NO CODE EGRESS: the prompt
 *      carries only structural metadata — never source bodies.
 *
 * ⛔ SCOPE-HINT SAFETY (E6's whole point): the `ScopeHints` this module
 * produces are a PRIORITIZATION signal for `packages/discovery` (and,
 * documented but not wired here, `packages/confirm`) — never a hard filter.
 * See `ScopeHintsSchema`'s doc comment in `@montr/contracts` for the one
 * narrow, advisory-only exception (`zeroSurfaceCategories`).
 */
import {
  CategorySchema,
  ThreatModelSchema,
  type AbuseCase,
  type AppMap,
  type AttackSurfaceEntry,
  type AuthState,
  type Category,
  type LLMGateway,
  type ModelTier,
  type PriorityCategoryHint,
  type ScopeHints,
  type SurfacePlausibility,
  type TaintSink,
  type TaintSinkKind,
  type ThreatModel,
  type TokenUsage,
  type TrustBoundary,
} from "@montr/contracts";
import type { Logger } from "@montr/telemetry";

const VALID_CATEGORIES = new Set<string>(CategorySchema.options);

/** Strip ```json fences a model may wrap JSON in (mirrors llm.ts's helper). */
function unfence(text: string): string {
  const m = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  return (m?.[1] ?? text).trim();
}

// ---------------------------------------------------------------------------
// 1. Deterministic baseline — no LLM required, always computed.
// ---------------------------------------------------------------------------

function sinksOfKind(appMap: AppMap, kinds: readonly TaintSinkKind[]): TaintSink[] {
  return appMap.taintSinks.filter((s) => kinds.includes(s.kind));
}

function describeSink(sink: TaintSink): string {
  const loc = `${sink.location.file}:${sink.location.line}`;
  return sink.description ? `${loc} (${sink.description})` : loc;
}

function routePathForFile(appMap: AppMap, file: string): string | undefined {
  return appMap.routes.find((r) => r.handler?.file === file)?.path;
}

const AUTH_BOUNDARY_LABELS: Record<AuthState, string> = {
  public: "Public unauthenticated routes",
  authenticated: "Authenticated user-scoped routes",
  role_gated: "Role-gated / admin routes",
  unknown: "Routes with unresolved auth boundary",
};

/** Trust boundaries: group routes by auth state, plus an external-calls boundary. */
export function buildTrustBoundaries(appMap: AppMap): TrustBoundary[] {
  const boundaries: TrustBoundary[] = [];
  const byState = new Map<AuthState, string[]>();
  for (const route of appMap.routes) {
    const list = byState.get(route.authState) ?? [];
    list.push(route.path);
    byState.set(route.authState, list);
  }
  for (const state of ["public", "authenticated", "role_gated", "unknown"] as const) {
    const paths = byState.get(state);
    if (!paths || paths.length === 0) continue;
    const unique = [...new Set(paths)];
    boundaries.push({
      name: AUTH_BOUNDARY_LABELS[state],
      description: `${unique.length} route(s) classified "${state}": ${unique.join(", ")}.`,
      routePaths: unique,
    });
  }
  if (appMap.thirdPartyCalls.length > 0) {
    const names = [...new Set(appMap.thirdPartyCalls.map((c) => c.name))];
    boundaries.push({
      name: "External API integrations",
      description: `${appMap.thirdPartyCalls.length} outbound third-party call(s): ${names.slice(0, 5).join(", ")}.`,
      routePaths: [],
    });
  }
  return boundaries;
}

interface WeakAuthFanOut {
  flaggedRoutePaths: string[];
  flaggedModels: string[];
  /** True when this came from real A18 route→model links, not a coarse fallback. */
  resolved: boolean;
}

/**
 * The specific structural signal A18's audit finding named as the IDOR /
 * broken-access-control blocker: routes with weak (public/unresolved) auth
 * that write or delete an ORM model. Falls back to a coarser "weak-auth route
 * + any ORM model exists" signal when no route→model link resolved for this
 * stack (Python/Java, or unlinked indirection) — still grounded in real route
 * paths and real model names, just lower-confidence (see the caller).
 */
function weakAuthModelFanOut(appMap: AppMap): WeakAuthFanOut {
  const weakAuth = (state: AuthState): boolean => state === "public" || state === "unknown";
  const resolvedRoutes = appMap.routes.filter(
    (r) =>
      weakAuth(r.authState) &&
      (r.referencedModels ?? []).some(
        (m) => m.operations.includes("write") || m.operations.includes("delete"),
      ),
  );
  if (resolvedRoutes.length > 0) {
    const models = new Set<string>();
    for (const r of resolvedRoutes) {
      for (const m of r.referencedModels ?? []) {
        if (m.operations.includes("write") || m.operations.includes("delete")) {
          models.add(m.modelName);
        }
      }
    }
    return {
      flaggedRoutePaths: resolvedRoutes.map((r) => r.path),
      flaggedModels: [...models],
      resolved: true,
    };
  }
  if (appMap.ormModels.length === 0) {
    return { flaggedRoutePaths: [], flaggedModels: [], resolved: false };
  }
  const weakRoutes = appMap.routes.filter((r) => weakAuth(r.authState));
  if (weakRoutes.length === 0) return { flaggedRoutePaths: [], flaggedModels: [], resolved: false };
  return {
    flaggedRoutePaths: weakRoutes.map((r) => r.path),
    flaggedModels: appMap.ormModels.map((m) => m.name),
    resolved: false,
  };
}

/**
 * Per-category plausibility, grounded in concrete App Map evidence (taint
 * sink kinds present, data-store kinds, route→model fan-out) — a category is
 * only emitted when the App Map's structural shape actually says something
 * about it, so this is never a mechanical 24-row OWASP dump (P2 concern from
 * the audit: "not generic boilerplate").
 */
export function buildAttackSurfaceBaseline(appMap: AppMap): AttackSurfaceEntry[] {
  const entries: AttackSurfaceEntry[] = [];
  const push = (category: Category, plausibility: SurfacePlausibility, rationale: string): void => {
    entries.push({ category, plausibility, rationale });
  };

  const sqlSinks = sinksOfKind(appMap, ["sql_query", "orm_raw_query"]);
  if (sqlSinks.length > 0) {
    push(
      "sql_injection",
      "high",
      `${sqlSinks.length} raw/SQL query sink(s) detected: ${sqlSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
  }

  const hasNonRelationalStore = appMap.dataStores.some((d) => d.kind === "mongodb");
  if (!hasNonRelationalStore) {
    push(
      "nosql_injection",
      "none",
      "No MongoDB (or other non-relational) data store detected in the App Map; " +
        "NoSQL-operator injection has no reachable target.",
    );
  } else if (sqlSinks.length > 0) {
    push(
      "nosql_injection",
      "medium",
      `A MongoDB data store is present alongside ${sqlSinks.length} raw-query sink(s); ` +
        "confirm whether any of them build Mongo operator queries from tainted input.",
    );
  }

  const execSinks = sinksOfKind(appMap, ["command_exec", "eval"]);
  if (execSinks.length > 0) {
    push(
      "command_injection",
      "high",
      `${execSinks.length} shell-exec/eval sink(s) detected: ${execSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
  }

  const renderSinks = sinksOfKind(appMap, ["html_render", "template_render"]);
  if (renderSinks.length > 0) {
    push(
      "xss",
      "high",
      `${renderSinks.length} HTML/template render sink(s) detected: ${renderSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
  }

  const httpClientSinks = sinksOfKind(appMap, ["http_client"]);
  if (httpClientSinks.length > 0 || appMap.thirdPartyCalls.length > 0) {
    push(
      "ssrf",
      httpClientSinks.length > 0 ? "medium" : "low",
      `${httpClientSinks.length} outbound HTTP client sink(s) and ${appMap.thirdPartyCalls.length} ` +
        "third-party call(s) detected; confirm none accept a tainted URL/host.",
    );
  } else {
    push(
      "ssrf",
      "none",
      "No outbound HTTP client sink and no third-party call detected in the App Map.",
    );
  }

  const fsSinks = sinksOfKind(appMap, ["fs_read", "fs_write"]);
  if (fsSinks.length > 0) {
    push(
      "path_traversal",
      "high",
      `${fsSinks.length} filesystem sink(s) detected: ${fsSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
  }

  const deserializeSinks = sinksOfKind(appMap, ["deserialize"]);
  if (deserializeSinks.length > 0) {
    push(
      "insecure_deserialization",
      "high",
      `${deserializeSinks.length} deserialize sink(s) detected: ${deserializeSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
    push(
      "xxe",
      "medium",
      "Deserialization sink(s) present; if any of them parses XML this app has real XXE " +
        "surface — confirm the parser.",
    );
  } else {
    push(
      "insecure_deserialization",
      "none",
      "No deserialize-kind taint sink detected anywhere in the App Map.",
    );
    push(
      "xxe",
      "none",
      "No deserialize/XML-parsing sink detected; XXE requires a reachable XML parser, which " +
        "the structural map shows no evidence of.",
    );
  }

  const redirectSinks = sinksOfKind(appMap, ["redirect"]);
  if (redirectSinks.length > 0) {
    push(
      "open_redirect",
      "medium",
      `${redirectSinks.length} redirect sink(s) detected: ${redirectSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
  }

  const cryptoSinks = sinksOfKind(appMap, ["crypto"]);
  if (cryptoSinks.length > 0) {
    push(
      "weak_crypto",
      "medium",
      `${cryptoSinks.length} crypto-related call site(s) detected: ${cryptoSinks
        .slice(0, 3)
        .map(describeSink)
        .join("; ")}.`,
    );
  }

  if (appMap.envSecretSurfaces.length > 0) {
    push(
      "hardcoded_secret",
      "medium",
      `${appMap.envSecretSurfaces.length} secret/config surface(s) detected (e.g. ` +
        `${appMap.envSecretSurfaces[0]?.name}); confirm none are hardcoded rather than injected.`,
    );
  }

  const cookieSources = appMap.taintSources.filter((s) => s.kind === "cookie");
  if (cookieSources.length > 0) {
    push(
      "csrf",
      "medium",
      `${cookieSources.length} cookie-derived taint source(s) detected; confirm state-changing ` +
        "routes carry CSRF protection.",
    );
  }

  // idor / broken_access_control — the two 0%-recall categories (A6/A18).
  const fanOut = weakAuthModelFanOut(appMap);
  if (fanOut.flaggedRoutePaths.length > 0) {
    const plausibility: SurfacePlausibility = fanOut.resolved ? "high" : "medium";
    const rationale = fanOut.resolved
      ? `Route(s) ${fanOut.flaggedRoutePaths.join(", ")} write/delete ORM model(s) ` +
        `${fanOut.flaggedModels.join(", ")} behind public/unresolved auth (A18 route→model links).`
      : `${fanOut.flaggedRoutePaths.length} public/unresolved-auth route(s) ` +
        `(${fanOut.flaggedRoutePaths.join(", ")}) share the app with ${fanOut.flaggedModels.length} ` +
        `ORM model(s) (${fanOut.flaggedModels.join(", ")}), but route→model ownership links are not ` +
        "resolved for this stack — cannot rule out unauthorized cross-tenant access.";
    push("idor", plausibility, rationale);
    push("broken_access_control", plausibility, rationale);
  }

  const unknownAuthRoutes = appMap.routes.filter((r) => r.authState === "unknown");
  if (unknownAuthRoutes.length > 0) {
    push(
      "broken_authentication",
      "medium",
      `${unknownAuthRoutes.length} route(s) have an unresolved auth boundary: ` +
        `${unknownAuthRoutes
          .slice(0, 5)
          .map((r) => r.path)
          .join(", ")}.`,
    );
  }

  const writeRoutes = appMap.routes.filter((r) =>
    (r.referencedModels ?? []).some((m) => m.operations.includes("write")),
  );
  if (writeRoutes.length > 0) {
    push(
      "mass_assignment",
      "medium",
      `${writeRoutes.length} route(s) write an ORM model directly ` +
        `(${writeRoutes
          .slice(0, 5)
          .map((r) => r.path)
          .join(", ")}); confirm field-level allowlisting.`,
    );
  }

  return entries;
}

/** Deterministic first pass at abuse cases, grounded in real sinks/routes. */
function buildDeterministicAbuseCases(appMap: AppMap): AbuseCase[] {
  const cases: AbuseCase[] = [];

  for (const sink of sinksOfKind(appMap, ["sql_query", "orm_raw_query"]).slice(0, 3)) {
    const route = routePathForFile(appMap, sink.location.file);
    cases.push({
      title: `Raw-query SQL injection${route ? ` via ${route}` : ""}`,
      description:
        "An attacker submits crafted input that reaches the raw/SQL sink at " +
        `${describeSink(sink)}${route ? `, exposed by route ${route}` : ""}.`,
      routePaths: route ? [route] : [],
      categories: ["sql_injection"],
    });
  }

  for (const sink of sinksOfKind(appMap, ["html_render", "template_render"]).slice(0, 3)) {
    const route = routePathForFile(appMap, sink.location.file);
    cases.push({
      title: `Reflected/stored script execution${route ? ` via ${route}` : ""}`,
      description:
        `Untrusted input reaches the render sink at ${describeSink(sink)}` +
        `${route ? `, exposed by route ${route}` : ""}, letting an attacker run script in another ` +
        "user's session.",
      routePaths: route ? [route] : [],
      categories: ["xss"],
    });
  }

  const fanOut = weakAuthModelFanOut(appMap);
  if (fanOut.flaggedRoutePaths.length > 0) {
    cases.push({
      title: "Cross-tenant object access via weakly-authenticated route",
      description:
        `A caller on route(s) ${fanOut.flaggedRoutePaths.join(", ")} may reach another tenant's ` +
        `${fanOut.flaggedModels.join(", ")} record(s) by supplying a foreign identifier: ${
          fanOut.resolved ? "the route writes/deletes the model behind" : "auth for these routes is"
        } public/unresolved.`,
      routePaths: fanOut.flaggedRoutePaths,
      categories: ["idor", "broken_access_control"],
    });
  }

  return cases;
}

const PLAUSIBILITY_ORDER: Record<SurfacePlausibility, number> = {
  high: 0,
  medium: 1,
  low: 2,
  none: 3,
};

function buildScopeHints(appMap: AppMap, attackSurface: AttackSurfaceEntry[]): ScopeHints {
  const priorityCategories: PriorityCategoryHint[] = attackSurface
    .filter((e) => e.plausibility === "high" || e.plausibility === "medium")
    .slice()
    .sort((a, b) => PLAUSIBILITY_ORDER[a.plausibility] - PLAUSIBILITY_ORDER[b.plausibility])
    .map((e) => ({ category: e.category, rationale: e.rationale }));

  const fanOut = weakAuthModelFanOut(appMap);
  const priorityRoutePaths = [...new Set(fanOut.flaggedRoutePaths)];

  const zeroSurfaceCategories = attackSurface
    .filter((e) => e.plausibility === "none")
    .map((e) => e.category);

  return { priorityCategories, priorityRoutePaths, zeroSurfaceCategories };
}

/**
 * Build the deterministic threat-model baseline. No LLM required — this is
 * always computed and attached, so the mechanism is useful (and fully
 * testable) even for a client with no gateway wired.
 */
export function buildDeterministicThreatModel(appMap: AppMap): ThreatModel {
  const attackSurface = buildAttackSurfaceBaseline(appMap);
  const trustBoundaries = buildTrustBoundaries(appMap);
  const abuseCases = buildDeterministicAbuseCases(appMap);
  const scopeHints = buildScopeHints(appMap, attackSurface);
  return ThreatModelSchema.parse({
    trustBoundaries,
    attackSurface,
    abuseCases,
    scopeHints,
    generatedByLlm: false,
  });
}

// ---------------------------------------------------------------------------
// 2. LLM enrichment — additive only, on top of the deterministic baseline.
// ---------------------------------------------------------------------------

export interface ThreatModelOptions {
  scanId: string;
  clientId: string;
  signal?: AbortSignal;
  logger?: Logger;
  /** Model tier for the derivation call (default: "default"). */
  tier?: ModelTier;
  maxTokens?: number;
}

export interface ThreatModelResult {
  threatModel: ThreatModel;
  /** True if the gateway was actually invoked (mirrors AuthLabelResult's `called`). */
  called: boolean;
  usage?: TokenUsage;
}

interface LlmAbuseCaseSuggestion {
  title?: unknown;
  description?: unknown;
  routePaths?: unknown;
  categories?: unknown;
}

interface LlmPrioritySuggestion {
  category?: unknown;
  rationale?: unknown;
}

interface LlmThreatModelSuggestion {
  abuseCases?: LlmAbuseCaseSuggestion[];
  additionalPriorityCategories?: LlmPrioritySuggestion[];
}

function parseSuggestion(content: string): LlmThreatModelSuggestion {
  try {
    const parsed = JSON.parse(unfence(content)) as unknown;
    if (parsed && typeof parsed === "object") return parsed as LlmThreatModelSuggestion;
  } catch {
    /* fall through to empty suggestion */
  }
  return {};
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function stringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/**
 * Derive the full threat model: the deterministic baseline, optionally
 * enriched by an LLM pass that may ONLY append abuse cases and additional
 * priority-category hints — never remove or downgrade a deterministic entry.
 * Every LLM-proposed route path / category is validated against the REAL App
 * Map / taxonomy before acceptance, so a hallucinated route or category can
 * never reach the result (fail-safe: on any doubt, drop the suggestion, keep
 * the baseline).
 */
export async function deriveThreatModel(
  appMap: AppMap,
  gateway: LLMGateway | undefined,
  opts: ThreatModelOptions,
): Promise<ThreatModelResult> {
  const baseline = buildDeterministicThreatModel(appMap);

  // ⛔ Preconditions — every one of these keeps us on the deterministic baseline.
  if (!gateway) return { threatModel: baseline, called: false };
  if (opts.signal?.aborted) {
    opts.logger?.warn("appmap.threat_model.skipped", { reason: "kill_switch" });
    return { threatModel: baseline, called: false };
  }
  if (appMap.routes.length === 0) {
    // Nothing to reason about — never spend a token needlessly.
    return { threatModel: baseline, called: false };
  }

  const validRoutePaths = new Set(appMap.routes.map((r) => r.path));

  const payload = {
    routes: appMap.routes.map((r) => ({ path: r.path, method: r.method, authState: r.authState })),
    ormModels: appMap.ormModels.map((m) => ({ name: m.name, fieldCount: m.fields.length })),
    frameworks: appMap.frameworks,
    trustBoundaries: baseline.trustBoundaries.map((b) => ({
      name: b.name,
      routePaths: b.routePaths,
    })),
    attackSurfaceBaseline: baseline.attackSurface.map((e) => ({
      category: e.category,
      plausibility: e.plausibility,
    })),
  };

  const fallbackSystem =
    "You extend an ALREADY-DERIVED, deterministic threat-model baseline for an application. " +
    "You receive only structural metadata (route paths/methods/auth states, ORM model names, " +
    "frameworks) — never source code. You may ONLY (1) propose additional concrete abuse-case " +
    "scenarios grounded in the given routes/models, and (2) suggest additional finding categories " +
    "worth prioritizing, each with a one-line rationale. Reference ONLY route paths given to you; " +
    "never invent a route. Reply ONLY as minified JSON of the form " +
    '{"abuseCases":[{"title","description","routePaths","categories"}],' +
    '"additionalPriorityCategories":[{"category","rationale"}]}.';

  // Prompt registry (§8.2, §15): same convention as labelAuthBoundaries/triage.
  const system =
    (await gateway.resolvePrompt?.("appmap.threat_model.system", fallbackSystem, {
      clientId: opts.clientId,
    })) ?? fallbackSystem;

  let content: string;
  let usage: TokenUsage | undefined;
  try {
    const response = await gateway.complete({
      tier: opts.tier ?? "default",
      system,
      messages: [{ role: "user", content: JSON.stringify(payload) }],
      maxTokens: opts.maxTokens ?? 1024,
      temperature: 0,
      responseFormat: "json",
      stream: false,
      metadata: {
        scanId: opts.scanId,
        clientId: opts.clientId,
        layer: "layer0",
        purpose: "threat_model",
      },
    });
    content = response.content;
    usage = response.usage;
  } catch (err) {
    // Fail-safe: threat-model enrichment is best-effort; the deterministic
    // baseline still ships (same posture as labelAuthBoundaries).
    opts.logger?.warn("appmap.threat_model.error", {
      message: err instanceof Error ? err.message : "unknown",
    });
    return { threatModel: baseline, called: false };
  }

  const suggestion = parseSuggestion(content);

  const extraAbuseCases: AbuseCase[] = (suggestion.abuseCases ?? [])
    .filter(
      (c): c is LlmAbuseCaseSuggestion & { title: string; description: string } =>
        isNonEmptyString(c?.title) && isNonEmptyString(c?.description),
    )
    .slice(0, 8)
    .map((c) => ({
      title: c.title,
      description: c.description,
      routePaths: stringArray(c.routePaths).filter((p) => validRoutePaths.has(p)),
      categories: stringArray(c.categories).filter((cat) =>
        VALID_CATEGORIES.has(cat),
      ) as Category[],
    }));

  const existingPriority = new Set(baseline.scopeHints.priorityCategories.map((h) => h.category));
  const extraPriority: PriorityCategoryHint[] = (suggestion.additionalPriorityCategories ?? [])
    .filter(
      (h): h is LlmPrioritySuggestion & { category: string; rationale: string } =>
        isNonEmptyString(h?.category) && isNonEmptyString(h?.rationale),
    )
    .filter(
      (h) => VALID_CATEGORIES.has(h.category) && !existingPriority.has(h.category as Category),
    )
    .slice(0, 5)
    .map((h) => ({ category: h.category as Category, rationale: h.rationale }));

  if (extraAbuseCases.length === 0 && extraPriority.length === 0) {
    return { threatModel: baseline, called: true, ...(usage ? { usage } : {}) };
  }

  const enriched = ThreatModelSchema.parse({
    ...baseline,
    abuseCases: [...baseline.abuseCases, ...extraAbuseCases],
    scopeHints: {
      ...baseline.scopeHints,
      priorityCategories: [...baseline.scopeHints.priorityCategories, ...extraPriority],
    },
    generatedByLlm: true,
  } satisfies ThreatModel);

  opts.logger?.info("appmap.threat_model.enriched", {
    abuseCases: enriched.abuseCases.length,
    priorityCategories: enriched.scopeHints.priorityCategories.length,
  });

  return { threatModel: enriched, called: true, ...(usage ? { usage } : {}) };
}
