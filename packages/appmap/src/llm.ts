/**
 * LLM semantic pass (build-plan §5.1) — labels AUTH BOUNDARIES and fills only the
 * gaps the deterministic pass left.
 *
 * ⛔ GOLDEN RULE #6: this runs strictly AFTER the deterministic App Map exists.
 * The caller passes the already-built map; this function additionally refuses to
 * call the gateway when there is nothing to label, when no gateway is wired, or
 * when the kill switch is set (fail-safe → deterministic map unchanged).
 *
 * ⛔ NO CODE EGRESS: the prompt carries only STRUCTURAL metadata (route paths,
 * methods, detected guard names) — never source bodies. The gateway logs
 * metadata only (golden rule #1). The model may only NARROW `unknown` auth
 * states; a deterministically-known boundary is never overridden (fail-safe).
 */
import type { AppMap, AuthState, LLMGateway, Route, TokenUsage } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";

export interface AuthLabelOptions {
  scanId: string;
  clientId: string;
  signal?: AbortSignal;
  logger?: Logger;
  /** Model tier for the labeling call (default: "default"). */
  tier?: "triage" | "default" | "confirmation";
  maxTokens?: number;
}

export interface AuthLabelResult {
  appMap: AppMap;
  /** True if the gateway was actually invoked. */
  called: boolean;
  usage?: TokenUsage;
}

const VALID_AUTH_STATES = new Set<AuthState>(["public", "authenticated", "role_gated", "unknown"]);

/** Strip ```json fences a model may wrap JSON in. */
function unfence(text: string): string {
  const m = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  return (m?.[1] ?? text).trim();
}

interface AuthBoundary {
  route?: string;
  method?: string;
  authState?: string;
  authGate?: string;
}

function parseBoundaries(content: string): AuthBoundary[] {
  try {
    const parsed = JSON.parse(unfence(content)) as unknown;
    const arr = (parsed as { authBoundaries?: unknown })?.authBoundaries;
    if (Array.isArray(arr)) return arr as AuthBoundary[];
    if (Array.isArray(parsed)) return parsed as AuthBoundary[];
    return [];
  } catch {
    return [];
  }
}

/** Build the structural (code-free) labeling prompt from the deterministic map. */
function buildPrompt(routes: Route[]): { system: string; user: string } {
  const summary = routes.map((r) => ({
    route: r.path,
    method: r.method,
    isApiRoute: r.isApiRoute,
    authState: r.authState,
    ...(r.authGate ? { authGate: r.authGate } : {}),
  }));
  const system =
    "You annotate an ALREADY-BUILT application route map with auth boundaries. " +
    "You receive only structural metadata (paths, methods, detected guard names) — never source code. " +
    'Return ONLY minified JSON of the form {"authBoundaries":[{"route","method","authState","authGate"}]}. ' +
    "authState must be one of: public, authenticated, role_gated. " +
    "Only classify routes whose authState is currently 'unknown'; omit the rest.";
  const user = JSON.stringify({ routes: summary });
  return { system, user };
}

/**
 * Label auth boundaries via the LLM, filling only `unknown` gaps. Returns the
 * (possibly) enriched map; on any uncertainty returns the deterministic map.
 */
export async function labelAuthBoundaries(
  appMap: AppMap,
  gateway: LLMGateway | undefined,
  opts: AuthLabelOptions,
): Promise<AuthLabelResult> {
  const logger = opts.logger;

  // ⛔ Preconditions — every one of these keeps us on the deterministic map.
  if (!gateway) return { appMap, called: false };
  if (opts.signal?.aborted) {
    logger?.warn("appmap.llm.skipped", { reason: "kill_switch" });
    return { appMap, called: false };
  }
  const gaps = appMap.routes.filter((r) => r.authState === "unknown");
  if (appMap.routes.length === 0 || gaps.length === 0) {
    // Nothing to label — never spend a token needlessly.
    return { appMap, called: false };
  }

  const { system, user } = buildPrompt(appMap.routes);
  let content: string;
  let usage: TokenUsage | undefined;
  try {
    const response = await gateway.complete({
      tier: opts.tier ?? "default",
      system,
      messages: [{ role: "user", content: user }],
      maxTokens: opts.maxTokens ?? 1024,
      temperature: 0,
      responseFormat: "json",
      stream: false,
      metadata: {
        scanId: opts.scanId,
        clientId: opts.clientId,
        layer: "layer0",
        purpose: "appmap_labeling",
      },
    });
    content = response.content;
    usage = response.usage;
  } catch (err) {
    // Fail-safe: labeling is best-effort; the deterministic map still ships.
    logger?.warn("appmap.llm.error", { message: err instanceof Error ? err.message : "unknown" });
    return { appMap, called: false };
  }

  const boundaries = parseBoundaries(content);
  if (boundaries.length === 0) return { appMap, called: true, ...(usage ? { usage } : {}) };

  // Index gaps by path (and path+method) for precise, gap-only application.
  const byPath = new Map<string, Route[]>();
  for (const r of gaps) {
    const list = byPath.get(r.path) ?? [];
    list.push(r);
    byPath.set(r.path, list);
  }

  let applied = 0;
  const routes: Route[] = appMap.routes.map((r) => ({ ...r }));
  const routeByIdentity = new Map<Route, Route>();
  for (let i = 0; i < appMap.routes.length; i++) {
    routeByIdentity.set(appMap.routes[i] as Route, routes[i] as Route);
  }

  for (const b of boundaries) {
    if (!b.route) continue;
    const candidates = byPath.get(b.route);
    if (!candidates) continue;
    const state = b.authState as AuthState | undefined;
    if (!state || !VALID_AUTH_STATES.has(state) || state === "unknown") continue;
    for (const original of candidates) {
      if (b.method && b.method !== original.method) continue;
      const target = routeByIdentity.get(original);
      if (!target || target.authState !== "unknown") continue; // never override deterministic
      target.authState = state;
      if (b.authGate && !target.authGate) target.authGate = b.authGate;
      applied++;
    }
  }

  logger?.info("appmap.llm.labeled", { routes: appMap.routes.length, gaps: gaps.length, applied });
  return { appMap: { ...appMap, routes }, called: true, ...(usage ? { usage } : {}) };
}
