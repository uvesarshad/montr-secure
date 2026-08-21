import type { Category } from "./compliance.js";

/**
 * MITRE ATT&CK mapping (B2), alongside the existing OWASP/CWE taxonomy in
 * ./compliance.ts. Reuses that file's exhaustive `Record<Category, ...>`
 * pattern (also mirrored by `packages/report/src/exports/controls.ts`'s SOC 2 /
 * ISO 27001 control maps) so the compiler enforces full coverage over
 * {@link Category} — adding a category without a MITRE entry is a compile
 * error, not a silent gap.
 *
 * This lives in @montr/contracts (not @montr/report, where the SOC 2/ISO 27001
 * catalogs live) because `DetectionRule.mitreTechniques` (./blue-team.ts, B1)
 * is a CONTRACTS-layer field: B3 (or a later wave) populates it by calling
 * {@link mitreTechniqueIdsForCategory} directly against a `ConfirmedFinding`,
 * with no dependency on @montr/report. @montr/report's SARIF/evidence exports
 * import this module the same way they already import `CATEGORY_TAXONOMY` from
 * ./compliance.ts.
 *
 * Every id below is a REAL technique from MITRE's own knowledge bases — never a
 * fabricated-but-plausible-looking id — because this is presented as
 * authoritative security metadata (SARIF tags, compliance reports) an auditor
 * or buyer may check against attack.mitre.org. Enterprise ATT&CK is
 * adversary-behavior-focused, not weakness-focused, so several categories
 * (permissive_cors, missing_security_headers, csrf, other) have no precise
 * dedicated technique; those honestly fall back to T1190 (Exploit
 * Public-Facing Application), the umbrella technique for "attacker abuses a
 * web-facing app weakness to gain a foothold" — the same fallback pattern
 * real-world OWASP-to-ATT&CK mapping efforts use. One category
 * (prompt_injection) has no Enterprise ATT&CK technique at all; it uses the
 * real id from MITRE ATLAS, the sibling MITRE knowledge base for AI/ML
 * attacks, rather than forcing an inaccurate Enterprise mapping.
 */

/** Which MITRE knowledge base a technique id belongs to. */
export type MitreFramework = "attack-enterprise" | "atlas";

/** A single MITRE technique/sub-technique, independent of which categories reference it. */
export interface MitreTechniqueDescriptor {
  readonly id: string;
  readonly name: string;
  /** Tactic(s) this technique belongs to, per MITRE's own listing (comma-joined when more than one). */
  readonly tactic: string;
  readonly framework: MitreFramework;
  readonly url: string;
}

/**
 * Catalog of every MITRE technique id referenced by {@link CATEGORY_MITRE_TECHNIQUES}
 * below, keyed by id (mirrors controls.ts's SOC2_CATALOG/ISO27001_CATALOG shape).
 */
export const MITRE_TECHNIQUE_CATALOG: Record<string, Omit<MitreTechniqueDescriptor, "id">> = {
  T1190: {
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1190/",
  },
  T1213: {
    name: "Data from Information Repositories",
    tactic: "Collection",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1213/",
  },
  T1059: {
    name: "Command and Scripting Interpreter",
    tactic: "Execution",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1059/",
  },
  "T1059.007": {
    name: "Command and Scripting Interpreter: JavaScript",
    tactic: "Execution",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1059/007/",
  },
  T1539: {
    name: "Steal Web Session Cookie",
    tactic: "Credential Access",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1539/",
  },
  "T1552.001": {
    name: "Unsecured Credentials: Credentials In Files",
    tactic: "Credential Access",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1552/001/",
  },
  "T1552.005": {
    name: "Unsecured Credentials: Cloud Instance Metadata API",
    tactic: "Credential Access",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1552/005/",
  },
  T1005: {
    name: "Data from Local System",
    tactic: "Collection",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1005/",
  },
  T1600: {
    name: "Weaken Encryption",
    tactic: "Defense Evasion",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1600/",
  },
  T1548: {
    name: "Abuse Elevation Control Mechanism",
    tactic: "Privilege Escalation, Defense Evasion",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1548/",
  },
  T1078: {
    name: "Valid Accounts",
    tactic: "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1078/",
  },
  T1110: {
    name: "Brute Force",
    tactic: "Credential Access",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1110/",
  },
  "T1566.002": {
    name: "Phishing: Spearphishing Link",
    tactic: "Initial Access",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1566/002/",
  },
  "T1562.008": {
    name: "Impair Defenses: Disable or Modify Cloud Logs",
    tactic: "Defense Evasion",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1562/008/",
  },
  "T1499.003": {
    name: "Endpoint Denial of Service: Application Exhaustion Flood",
    tactic: "Impact",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1499/003/",
  },
  T1611: {
    name: "Escape to Host",
    tactic: "Privilege Escalation",
    framework: "attack-enterprise",
    url: "https://attack.mitre.org/techniques/T1611/",
  },
  // MITRE ATLAS (not Enterprise ATT&CK) — the dedicated MITRE knowledge base for
  // AI/ML attack techniques. Enterprise ATT&CK has no prompt-injection technique;
  // using the real ATLAS id is more accurate than forcing an Enterprise id.
  "AML.T0051": {
    name: "LLM Prompt Injection",
    tactic: "Initial Access",
    framework: "atlas",
    url: "https://atlas.mitre.org/techniques/AML.T0051",
  },
};

/**
 * Category -> MITRE ATT&CK/ATLAS technique ids (exhaustive over {@link Category},
 * mirrors controls.ts's SOC2_CATEGORY_CONTROLS/ISO27001_CATEGORY_CONTROLS
 * pattern). Every id here MUST have a {@link MITRE_TECHNIQUE_CATALOG} entry —
 * asserted by a unit test, not just documented.
 */
export const CATEGORY_MITRE_TECHNIQUES: Record<Category, readonly string[]> = {
  // Classic injection: exploiting the public-facing app (T1190) to reach and
  // collect data from the backing data store (T1213).
  sql_injection: ["T1190", "T1213"],
  nosql_injection: ["T1190", "T1213"],
  // Injection reaching a shell/interpreter rather than a data store.
  command_injection: ["T1190", "T1059"],
  // XSS is attacker JavaScript executing in the victim's browser (T1059.007),
  // most commonly to steal the victim's session cookie (T1539).
  xss: ["T1059.007", "T1539"],
  // SSRF's most common high-value target is a cloud metadata endpoint.
  ssrf: ["T1190", "T1552.005"],
  // Path traversal / arbitrary file read.
  path_traversal: ["T1190", "T1005"],
  // Deserialization gadget chains typically achieve code execution.
  insecure_deserialization: ["T1190", "T1059"],
  hardcoded_secret: ["T1552.001"],
  // No dedicated "outdated component" technique; T1190 is the exploitation vector.
  vulnerable_dependency: ["T1190"],
  // No dedicated CORS technique in Enterprise ATT&CK; falls back to the
  // umbrella web-app-exploitation technique.
  permissive_cors: ["T1190"],
  missing_security_headers: ["T1190"],
  insecure_cookie: ["T1539"],
  weak_crypto: ["T1600"],
  broken_access_control: ["T1548", "T1078"],
  broken_authentication: ["T1110", "T1078"],
  // Open redirects are most commonly weaponized to make phishing links look trustworthy.
  open_redirect: ["T1566.002"],
  xxe: ["T1190", "T1005"],
  // No dedicated CSRF technique in Enterprise ATT&CK.
  csrf: ["T1190"],
  sensitive_data_exposure: ["T1213", "T1005"],
  // Nearest ATT&CK analog for "insufficient logging/monitoring" is the defense-
  // evasion family of impairing/disabling the very logs that would have caught it.
  insufficient_logging: ["T1562.008"],
  idor: ["T1078"],
  mass_assignment: ["T1548"],
  rate_limit_missing: ["T1499.003"],
  // See MITRE_TECHNIQUE_CATALOG's AML.T0051 comment: MITRE ATLAS, not Enterprise ATT&CK.
  prompt_injection: ["AML.T0051"],
  // E16: IaC/container misconfiguration — T1611 (Escape to Host) is the precise
  // technique for privileged/hostNetwork/hostPID container escapes.
  insecure_configuration: ["T1190", "T1611"],
  other: ["T1190"],
};

/** Full MITRE technique descriptor for a category (id + name + tactic + url). */
export function mitreTechniquesForCategory(category: Category): MitreTechniqueDescriptor[] {
  return CATEGORY_MITRE_TECHNIQUES[category].map((id) => {
    const entry = MITRE_TECHNIQUE_CATALOG[id];
    // Fail-safe (mirrors controls.ts's resolve()): degrade rather than crash if an
    // id is ever added to the category map without a catalog entry — a unit test
    // asserts this never actually happens.
    if (!entry) {
      return { id, name: id, tactic: "", framework: "attack-enterprise" as const, url: "" };
    }
    return { id, ...entry };
  });
}

/**
 * Raw technique ids for a category — the shape `DetectionRule.mitreTechniques`
 * (packages/contracts/src/blue-team.ts) expects. This is the function B3 (or a
 * later wave) calls when constructing a `DetectionRule` from a `ConfirmedFinding`.
 */
export function mitreTechniqueIdsForCategory(category: Category): string[] {
  return [...CATEGORY_MITRE_TECHNIQUES[category]];
}

/** Every technique id referenced by any category mapping (for completeness checks). */
export function referencedMitreTechniqueIds(): string[] {
  return [...new Set(Object.values(CATEGORY_MITRE_TECHNIQUES).flat())].sort();
}
