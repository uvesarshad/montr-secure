/**
 * Rate limits (B9). Grounded in the App Map's public (unauthenticated)
 * routes plus a real dependency-presence check for a rate-limiting
 * middleware. A repo where a rate limiter is already installed produces NO
 * recommendation at all (precision) — this module does not attempt to prove
 * per-route coverage of an already-present limiter, only that ONE exists;
 * see the module-level caveat below for why that is a deliberate, documented
 * simplification rather than a silent gap.
 */
import type { AppMap, Category, ConfirmedFinding, Route } from "@montr/contracts";
import type { FileProvider } from "@montr/discovery";
import { detectAnyDependency } from "../detect.js";
import type { RecommendationDraft } from "../types.js";

const RATE_LIMIT_PACKAGES = ["express-rate-limit", "@fastify/rate-limit", "rate-limiter-flexible"];

/** Bound how many per-route recommendations one repo can produce (avoid report spam). */
const MAX_ROUTE_RECOMMENDATIONS = 5;

function expressSnippet(route: Route): string {
  return [
    'import rateLimit from "express-rate-limit";',
    "",
    `const ${varName(route)} = rateLimit({`,
    "  windowMs: 15 * 60 * 1000, // 15 minutes",
    "  max: 100, // requests per window per IP",
    "  standardHeaders: true,",
    "  legacyHeaders: false,",
    "});",
    "",
    `app.${route.method.toLowerCase()}("${route.path}", ${varName(route)}, handler);`,
  ].join("\n");
}

function fastifySnippet(route: Route): string {
  return [
    'import rateLimit from "@fastify/rate-limit";',
    "",
    `app.register(rateLimit, { max: 100, timeWindow: "15 minutes" });`,
    "",
    `// Applies globally once registered, or scope it per-route with config on the`,
    `// route options for "${route.method} ${route.path}":`,
    `app.route({ method: "${route.method}", url: "${route.path}", config: { rateLimit: { max: 100, timeWindow: "15 minutes" } }, handler });`,
  ].join("\n");
}

function nextjsSnippet(route: Route): string {
  return [
    "// Edge-compatible option (e.g. @upstash/ratelimit backed by Redis), enforced",
    `// in middleware.ts scoped to matcher: ["${route.path}"]:`,
    'import { Ratelimit } from "@upstash/ratelimit";',
    "",
    'const ratelimit = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(100, "15 m") });',
    "",
    "export async function middleware(request: NextRequest) {",
    '  const { success } = await ratelimit.limit(request.ip ?? "anonymous");',
    '  if (!success) return new NextResponse("Too Many Requests", { status: 429 });',
    "}",
  ].join("\n");
}

function varName(route: Route): string {
  const slug = route.path.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "route";
  return `${slug}Limiter`;
}

export async function detectRateLimitGaps(
  appMap: AppMap,
  files: FileProvider,
  confirmedFindings: readonly ConfirmedFinding[] = [],
): Promise<RecommendationDraft[]> {
  const dep = await detectAnyDependency(files, RATE_LIMIT_PACKAGES);
  if (dep.present) return []; // a rate limiter exists somewhere — precision over redundant noise.

  const publicRoutes = appMap.routes
    .filter((r) => r.authState === "public")
    .slice(0, MAX_ROUTE_RECOMMENDATIONS);
  if (publicRoutes.length === 0) return [];

  const rateLimitFindingIds = confirmedFindings
    .filter((f: ConfirmedFinding) => (f.category as Category) === "rate_limit_missing")
    .map((f) => f.id);

  const frameworks = new Set(appMap.frameworks);
  const framework = frameworks.has("fastify")
    ? "fastify"
    : frameworks.has("express")
      ? "express"
      : frameworks.has("nextjs")
        ? "nextjs"
        : undefined;
  if (!framework) return []; // no idiomatic snippet for an unrecognized/unlisted framework.

  return publicRoutes.map((route) => ({
    category: "rate_limits" as const,
    severity: "medium" as const,
    title: `Add rate limiting to public route ${route.method} ${route.path}`,
    gap: `${route.method} ${route.path} is a public (unauthenticated) route with no rate-limiting dependency detected anywhere in the repo (checked ${RATE_LIMIT_PACKAGES.join(", ")}).`,
    recommendation:
      framework === "fastify"
        ? fastifySnippet(route)
        : framework === "nextjs"
          ? nextjsSnippet(route)
          : expressSnippet(route),
    rationale:
      "An unauthenticated route with no rate limit is exposed to credential stuffing, scraping, and resource-exhaustion abuse with no cost to the attacker.",
    evidence: [
      `App Map route: ${route.method} ${route.path} (authState: public)`,
      `No ${RATE_LIMIT_PACKAGES.join("/")} dependency detected`,
    ],
    framework: framework as RecommendationDraft["framework"],
    relatedFindingIds: rateLimitFindingIds,
  }));
}
