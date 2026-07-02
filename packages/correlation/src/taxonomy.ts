/**
 * Category taxonomy for correlation: how each finding category is CLASSIFIED
 * (injection / config / secret / dependency / access / other) and its intrinsic
 * impact + severity weighting. These are the deterministic priors the ranking is
 * built on (the App Map grounding then adjusts them per finding).
 */
import type { Category, Severity } from "@montr/contracts";

export type FindingClass = "injection" | "config" | "secret" | "dependency" | "access" | "other";

/** Categories where a tainted source must reach a dangerous sink to matter. */
export const INJECTION_CATEGORIES: ReadonlySet<Category> = new Set<Category>([
  "sql_injection",
  "nosql_injection",
  "command_injection",
  "xss",
  "ssrf",
  "path_traversal",
  "insecure_deserialization",
  "xxe",
  "open_redirect",
]);

/** Security-misconfiguration categories tied to a route/handler surface. */
export const CONFIG_CATEGORIES: ReadonlySet<Category> = new Set<Category>([
  "permissive_cors",
  "missing_security_headers",
  "insecure_cookie",
  "weak_crypto",
  "csrf",
  "rate_limit_missing",
  "insufficient_logging",
]);

/** Secret-exposure categories corroborated by the env/secret surface. */
export const SECRET_CATEGORIES: ReadonlySet<Category> = new Set<Category>([
  "hardcoded_secret",
  "sensitive_data_exposure",
]);

/** Dependency/SCA categories — corroborated by the import / third-party graph. */
export const DEPENDENCY_CATEGORIES: ReadonlySet<Category> = new Set<Category>([
  "vulnerable_dependency",
]);

/** Access-control categories (missing/broken checks on a handler). */
export const ACCESS_CATEGORIES: ReadonlySet<Category> = new Set<Category>([
  "broken_access_control",
  "broken_authentication",
  "idor",
  "mass_assignment",
]);

export function classifyCategory(category: Category): FindingClass {
  if (INJECTION_CATEGORIES.has(category)) return "injection";
  if (SECRET_CATEGORIES.has(category)) return "secret";
  if (DEPENDENCY_CATEGORIES.has(category)) return "dependency";
  if (ACCESS_CATEGORIES.has(category)) return "access";
  if (CONFIG_CATEGORIES.has(category)) return "config";
  return "other";
}

/** Normalized weight of a raw tool severity, [0,1]. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0.1,
  low: 0.3,
  medium: 0.5,
  high: 0.75,
  critical: 1,
};

/**
 * Intrinsic impact prior per category, [0,1] — the damage if exploited, before
 * reachability/exposure. Ranking is reachability × exposure × impact, never raw
 * CVSS, so this is only one of the three factors.
 */
export const CATEGORY_IMPACT_BASE: Record<Category, number> = {
  sql_injection: 0.9,
  nosql_injection: 0.85,
  command_injection: 0.95,
  xss: 0.7,
  ssrf: 0.8,
  path_traversal: 0.75,
  insecure_deserialization: 0.9,
  hardcoded_secret: 0.85,
  vulnerable_dependency: 0.5,
  permissive_cors: 0.35,
  missing_security_headers: 0.25,
  insecure_cookie: 0.35,
  weak_crypto: 0.6,
  broken_access_control: 0.85,
  broken_authentication: 0.9,
  open_redirect: 0.4,
  xxe: 0.7,
  csrf: 0.5,
  sensitive_data_exposure: 0.7,
  insufficient_logging: 0.2,
  idor: 0.7,
  mass_assignment: 0.6,
  rate_limit_missing: 0.3,
  other: 0.4,
};

/** Humanize an enum token ("orm_raw_query" -> "orm raw query"). */
export function humanize(token: string): string {
  return token.replace(/_/g, " ");
}
