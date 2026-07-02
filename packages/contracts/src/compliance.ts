import { z } from "zod";

/**
 * Compliance & taxonomy types (§13). Every finding maps to a CWE and an
 * OWASP Top 10 (2021) category.
 */

/** CWE identifier, e.g. "CWE-89". Format-validated (catalog below is non-exhaustive). */
export const CweIdSchema = z.string().regex(/^CWE-\d+$/, "expected CWE-<number>");
export type CweId = z.infer<typeof CweIdSchema>;

/** OWASP Top 10 (2021) category codes. */
export const OwaspIdSchema = z.enum([
  "A01:2021",
  "A02:2021",
  "A03:2021",
  "A04:2021",
  "A05:2021",
  "A06:2021",
  "A07:2021",
  "A08:2021",
  "A09:2021",
  "A10:2021",
]);
export type OwaspId = z.infer<typeof OwaspIdSchema>;

export const OWASP_TITLES: Record<OwaspId, string> = {
  "A01:2021": "Broken Access Control",
  "A02:2021": "Cryptographic Failures",
  "A03:2021": "Injection",
  "A04:2021": "Insecure Design",
  "A05:2021": "Security Misconfiguration",
  "A06:2021": "Vulnerable and Outdated Components",
  "A07:2021": "Identification and Authentication Failures",
  "A08:2021": "Software and Data Integrity Failures",
  "A09:2021": "Security Logging and Monitoring Failures",
  "A10:2021": "Server-Side Request Forgery (SSRF)",
};

/**
 * Normalized finding category. Correlation dedups tool-specific rule IDs into
 * one of these root causes; the taxonomy below maps each to CWE + OWASP.
 */
export const CategorySchema = z.enum([
  "sql_injection",
  "nosql_injection",
  "command_injection",
  "xss",
  "ssrf",
  "path_traversal",
  "insecure_deserialization",
  "hardcoded_secret",
  "vulnerable_dependency",
  "permissive_cors",
  "missing_security_headers",
  "insecure_cookie",
  "weak_crypto",
  "broken_access_control",
  "broken_authentication",
  "open_redirect",
  "xxe",
  "csrf",
  "sensitive_data_exposure",
  "insufficient_logging",
  "idor",
  "mass_assignment",
  "rate_limit_missing",
  "other",
]);
export type Category = z.infer<typeof CategorySchema>;

export interface CategoryTaxonomyEntry {
  readonly title: string;
  readonly cwe: readonly CweId[];
  readonly owasp: OwaspId;
}

/** Static category -> {CWE, OWASP} mapping (§13). Consumed by the report + compliance export. */
export const CATEGORY_TAXONOMY: Record<Category, CategoryTaxonomyEntry> = {
  sql_injection: { title: "SQL Injection", cwe: ["CWE-89"], owasp: "A03:2021" },
  nosql_injection: { title: "NoSQL Injection", cwe: ["CWE-943"], owasp: "A03:2021" },
  command_injection: { title: "OS Command Injection", cwe: ["CWE-78"], owasp: "A03:2021" },
  xss: { title: "Cross-Site Scripting", cwe: ["CWE-79"], owasp: "A03:2021" },
  ssrf: { title: "Server-Side Request Forgery", cwe: ["CWE-918"], owasp: "A10:2021" },
  path_traversal: { title: "Path Traversal", cwe: ["CWE-22"], owasp: "A01:2021" },
  insecure_deserialization: {
    title: "Insecure Deserialization",
    cwe: ["CWE-502"],
    owasp: "A08:2021",
  },
  hardcoded_secret: {
    title: "Use of Hard-coded Credentials",
    cwe: ["CWE-798"],
    owasp: "A07:2021",
  },
  vulnerable_dependency: {
    title: "Vulnerable / Outdated Component",
    cwe: ["CWE-1104", "CWE-937"],
    owasp: "A06:2021",
  },
  permissive_cors: { title: "Permissive CORS", cwe: ["CWE-942"], owasp: "A05:2021" },
  missing_security_headers: {
    title: "Missing Security Headers",
    cwe: ["CWE-693"],
    owasp: "A05:2021",
  },
  insecure_cookie: {
    title: "Insecure Cookie Configuration",
    cwe: ["CWE-614", "CWE-1004"],
    owasp: "A05:2021",
  },
  weak_crypto: { title: "Weak Cryptography", cwe: ["CWE-327"], owasp: "A02:2021" },
  broken_access_control: {
    title: "Broken Access Control",
    cwe: ["CWE-284"],
    owasp: "A01:2021",
  },
  broken_authentication: {
    title: "Broken Authentication",
    cwe: ["CWE-287"],
    owasp: "A07:2021",
  },
  open_redirect: { title: "Open Redirect", cwe: ["CWE-601"], owasp: "A01:2021" },
  xxe: { title: "XML External Entities", cwe: ["CWE-611"], owasp: "A05:2021" },
  csrf: { title: "Cross-Site Request Forgery", cwe: ["CWE-352"], owasp: "A01:2021" },
  sensitive_data_exposure: {
    title: "Sensitive Data Exposure",
    cwe: ["CWE-200"],
    owasp: "A02:2021",
  },
  insufficient_logging: {
    title: "Insufficient Logging & Monitoring",
    cwe: ["CWE-778"],
    owasp: "A09:2021",
  },
  idor: { title: "Insecure Direct Object Reference", cwe: ["CWE-639"], owasp: "A01:2021" },
  mass_assignment: { title: "Mass Assignment", cwe: ["CWE-915"], owasp: "A08:2021" },
  rate_limit_missing: {
    title: "Missing Rate Limiting",
    cwe: ["CWE-770"],
    owasp: "A04:2021",
  },
  other: { title: "Other", cwe: [], owasp: "A04:2021" },
};

/** A single finding's compliance mapping, as surfaced in the report. */
export const ComplianceMappingSchema = z.object({
  category: CategorySchema,
  cwe: z.array(CweIdSchema),
  owasp: OwaspIdSchema,
  owaspTitle: z.string(),
});
export type ComplianceMapping = z.infer<typeof ComplianceMappingSchema>;

/** Convenience: build a ComplianceMapping from a Category via the taxonomy. */
export function complianceForCategory(category: Category): ComplianceMapping {
  const entry = CATEGORY_TAXONOMY[category];
  return {
    category,
    cwe: [...entry.cwe],
    owasp: entry.owasp,
    owaspTitle: OWASP_TITLES[entry.owasp],
  };
}
