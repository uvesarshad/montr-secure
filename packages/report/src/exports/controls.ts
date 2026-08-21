/**
 * Compliance CONTROL catalogs + per-category mappings (§13, WS-M).
 *
 * Every {@link Category} in the frozen @montr/contracts taxonomy is mapped to the
 * relevant SOC 2 Trust Services Criteria (Common Criteria, "CC-series") and
 * ISO/IEC 27001:2022 Annex A controls, so a confirmed finding drops straight into
 * an auditor's evidence collection under the right control. The mapping is static
 * and deterministic (no LLM, no network) and is exhaustive over `Category` — the
 * `Record<Category, ...>` types make the compiler enforce full coverage.
 */
import type { Category } from "@montr/contracts";

/** Which evidence framework a control belongs to. */
export type ComplianceFramework = "soc2" | "iso27001";

/** Human-readable framework label (used in export headers). */
export const FRAMEWORK_LABEL: Record<ComplianceFramework, string> = {
  soc2: "SOC 2 (AICPA Trust Services Criteria)",
  iso27001: "ISO/IEC 27001:2022 (Annex A)",
};

/** A single control an auditor recognizes. */
export interface ControlDescriptor {
  readonly framework: ComplianceFramework;
  readonly id: string;
  readonly title: string;
  /** Control grouping ("Common Criteria" for SOC 2, "Annex A" for ISO 27001). */
  readonly family: string;
  readonly description: string;
}

/* ------------------------------------------------------------------ *
 * SOC 2 — Common Criteria control catalog (subset relevant to app-sec)
 * ------------------------------------------------------------------ */
const SOC2_CATALOG: Record<string, Omit<ControlDescriptor, "framework" | "id">> = {
  "CC6.1": {
    title: "Logical access security",
    family: "Common Criteria",
    description:
      "Logical access security software, infrastructure, and architectures protect information assets from security events.",
  },
  "CC6.2": {
    title: "User registration & authorization",
    family: "Common Criteria",
    description:
      "Prior to issuing credentials, users are registered and authorized; credentials are removed when access is no longer required.",
  },
  "CC6.3": {
    title: "Role-based access & least privilege",
    family: "Common Criteria",
    description:
      "Access to data and functions is authorized based on roles and least privilege / segregation of duties.",
  },
  "CC6.6": {
    title: "Boundary protection",
    family: "Common Criteria",
    description:
      "Security measures protect against threats from sources outside the system boundary.",
  },
  "CC6.7": {
    title: "Restriction of data in transit",
    family: "Common Criteria",
    description:
      "Transmission, movement, and removal of information is restricted to authorized users and protected in transit.",
  },
  "CC6.8": {
    title: "Prevention of malicious software",
    family: "Common Criteria",
    description:
      "Controls prevent or detect and act upon the introduction of unauthorized or malicious software.",
  },
  "CC7.1": {
    title: "Vulnerability detection & configuration monitoring",
    family: "Common Criteria",
    description:
      "Detection and monitoring procedures identify changes to configurations and new vulnerabilities.",
  },
  "CC7.2": {
    title: "Security event monitoring",
    family: "Common Criteria",
    description:
      "The system is monitored to detect anomalies and security events indicative of malicious acts or errors.",
  },
  "CC7.3": {
    title: "Security event evaluation",
    family: "Common Criteria",
    description: "Detected security events are evaluated to determine whether they are incidents.",
  },
  "CC8.1": {
    title: "Change management",
    family: "Common Criteria",
    description:
      "Changes to infrastructure, data, software, and procedures are authorized, designed, developed, tested, and approved.",
  },
};

/* ------------------------------------------------------------------ *
 * ISO/IEC 27001:2022 — Annex A control catalog (subset relevant to app-sec)
 * ------------------------------------------------------------------ */
const ISO27001_CATALOG: Record<string, Omit<ControlDescriptor, "framework" | "id">> = {
  "A.5.7": {
    title: "Threat intelligence",
    family: "Annex A",
    description: "Information relating to information security threats is collected and analyzed.",
  },
  "A.5.15": {
    title: "Access control",
    family: "Annex A",
    description:
      "Rules to control physical and logical access to information are established and implemented.",
  },
  "A.5.17": {
    title: "Authentication information",
    family: "Annex A",
    description:
      "Allocation and management of authentication information is controlled by a management process.",
  },
  "A.8.2": {
    title: "Privileged access rights",
    family: "Annex A",
    description: "The allocation and use of privileged access rights is restricted and managed.",
  },
  "A.8.3": {
    title: "Information access restriction",
    family: "Annex A",
    description:
      "Access to information and application functions is restricted per the access-control policy.",
  },
  "A.8.5": {
    title: "Secure authentication",
    family: "Annex A",
    description:
      "Secure authentication technologies and procedures are implemented based on access restrictions.",
  },
  "A.8.8": {
    title: "Management of technical vulnerabilities",
    family: "Annex A",
    description:
      "Information about technical vulnerabilities is obtained and appropriate measures are taken.",
  },
  "A.8.9": {
    title: "Configuration management",
    family: "Annex A",
    description:
      "Configurations, including security configurations, of hardware, software, and services are established and monitored.",
  },
  "A.8.12": {
    title: "Data leakage prevention",
    family: "Annex A",
    description:
      "Data leakage prevention measures are applied to systems that process sensitive information.",
  },
  "A.8.15": {
    title: "Logging",
    family: "Annex A",
    description:
      "Logs recording activities, exceptions, faults, and other relevant events are produced and protected.",
  },
  "A.8.16": {
    title: "Monitoring activities",
    family: "Annex A",
    description: "Networks, systems, and applications are monitored for anomalous behavior.",
  },
  "A.8.24": {
    title: "Use of cryptography",
    family: "Annex A",
    description:
      "Rules for the effective use of cryptography, including key management, are defined and implemented.",
  },
  "A.8.25": {
    title: "Secure development life cycle",
    family: "Annex A",
    description:
      "Rules for the secure development of software and systems are established and applied.",
  },
  "A.8.26": {
    title: "Application security requirements",
    family: "Annex A",
    description:
      "Information security requirements are identified, specified, and approved when developing applications.",
  },
  "A.8.28": {
    title: "Secure coding",
    family: "Annex A",
    description: "Secure coding principles are applied to software development.",
  },
  "A.8.29": {
    title: "Security testing in development and acceptance",
    family: "Annex A",
    description:
      "Security testing processes are defined and implemented in the development life cycle.",
  },
};

/** Category → SOC 2 Common Criteria control ids (exhaustive over Category). */
const SOC2_CATEGORY_CONTROLS: Record<Category, readonly string[]> = {
  sql_injection: ["CC6.1", "CC7.1", "CC8.1"],
  nosql_injection: ["CC6.1", "CC7.1", "CC8.1"],
  command_injection: ["CC6.1", "CC6.8", "CC8.1"],
  xss: ["CC6.1", "CC7.1", "CC8.1"],
  ssrf: ["CC6.1", "CC6.6", "CC8.1"],
  path_traversal: ["CC6.1", "CC6.3", "CC8.1"],
  insecure_deserialization: ["CC6.1", "CC7.1", "CC8.1"],
  hardcoded_secret: ["CC6.1", "CC6.3", "CC8.1"],
  vulnerable_dependency: ["CC7.1", "CC8.1"],
  permissive_cors: ["CC6.6", "CC7.1", "CC8.1"],
  missing_security_headers: ["CC6.6", "CC6.7", "CC7.1"],
  insecure_cookie: ["CC6.7", "CC6.1", "CC8.1"],
  weak_crypto: ["CC6.1", "CC6.7"],
  broken_access_control: ["CC6.1", "CC6.3"],
  broken_authentication: ["CC6.1", "CC6.2"],
  open_redirect: ["CC6.1", "CC6.6", "CC8.1"],
  xxe: ["CC6.1", "CC7.1", "CC8.1"],
  csrf: ["CC6.1", "CC6.6"],
  sensitive_data_exposure: ["CC6.1", "CC6.7", "CC6.3"],
  insufficient_logging: ["CC7.2", "CC7.3"],
  idor: ["CC6.1", "CC6.3"],
  mass_assignment: ["CC6.1", "CC6.3", "CC8.1"],
  rate_limit_missing: ["CC6.6", "CC7.2"],
  // Same control set as the other injection-family categories (sql_injection,
  // xxe): input validation (CC6.1), operational detection (CC7.1), and secure
  // development lifecycle (CC8.1) apply identically when the injection target
  // is an LLM prompt instead of a query/template (E11).
  prompt_injection: ["CC6.1", "CC7.1", "CC8.1"],
  // Configuration monitoring (CC7.1) is the direct hit for an IaC/container/
  // cloud misconfiguration; change management (CC8.1) covers the
  // infrastructure-as-code review process itself (E16).
  insecure_configuration: ["CC7.1", "CC8.1"],
  other: ["CC6.1", "CC7.1"],
};

/** Category → ISO/IEC 27001:2022 Annex A control ids (exhaustive over Category). */
const ISO27001_CATEGORY_CONTROLS: Record<Category, readonly string[]> = {
  sql_injection: ["A.8.28", "A.8.26", "A.8.29"],
  nosql_injection: ["A.8.28", "A.8.26", "A.8.29"],
  command_injection: ["A.8.28", "A.8.26", "A.8.29"],
  xss: ["A.8.28", "A.8.26", "A.8.29"],
  ssrf: ["A.8.28", "A.8.26", "A.8.9"],
  path_traversal: ["A.8.28", "A.8.3", "A.8.26"],
  insecure_deserialization: ["A.8.28", "A.8.26", "A.8.25"],
  hardcoded_secret: ["A.8.24", "A.5.17", "A.8.28"],
  vulnerable_dependency: ["A.8.8", "A.8.25"],
  permissive_cors: ["A.8.9", "A.8.26"],
  missing_security_headers: ["A.8.9", "A.8.26"],
  insecure_cookie: ["A.8.9", "A.8.24"],
  weak_crypto: ["A.8.24", "A.8.28"],
  broken_access_control: ["A.5.15", "A.8.3", "A.8.2"],
  broken_authentication: ["A.8.5", "A.5.17"],
  open_redirect: ["A.8.28", "A.8.26"],
  xxe: ["A.8.28", "A.8.26", "A.8.29"],
  csrf: ["A.8.28", "A.8.26"],
  sensitive_data_exposure: ["A.8.12", "A.8.24"],
  insufficient_logging: ["A.8.15", "A.8.16"],
  idor: ["A.5.15", "A.8.3"],
  mass_assignment: ["A.8.28", "A.8.3"],
  rate_limit_missing: ["A.8.16", "A.8.26"],
  // Same Annex A set as sql_injection/xss: secure coding (A.8.28), application
  // security requirements (A.8.26), and security testing in development
  // (A.8.29) (E11).
  prompt_injection: ["A.8.28", "A.8.26", "A.8.29"],
  // Configuration management (A.8.9) is the exact Annex A control for an
  // IaC/container misconfiguration finding (E16).
  insecure_configuration: ["A.8.9", "A.8.25"],
  other: ["A.8.28", "A.8.25"],
};

function resolve(
  framework: ComplianceFramework,
  catalog: Record<string, Omit<ControlDescriptor, "framework" | "id">>,
  ids: readonly string[],
): ControlDescriptor[] {
  return ids.map((id) => {
    const entry = catalog[id];
    // Fail-safe: an unmapped id degrades to a bare descriptor rather than crashing
    // report generation (should never happen — a unit test asserts completeness).
    if (!entry) {
      return { framework, id, title: id, family: "Unmapped", description: "" };
    }
    return { framework, id, ...entry };
  });
}

/** The controls a single finding category maps to, for the given framework. */
export function controlsForCategory(
  framework: ComplianceFramework,
  category: Category,
): ControlDescriptor[] {
  if (framework === "soc2") {
    return resolve("soc2", SOC2_CATALOG, SOC2_CATEGORY_CONTROLS[category]);
  }
  return resolve("iso27001", ISO27001_CATALOG, ISO27001_CATEGORY_CONTROLS[category]);
}

/** Full control catalog for a framework (for coverage summaries / tests). */
export function controlCatalog(framework: ComplianceFramework): ControlDescriptor[] {
  const catalog = framework === "soc2" ? SOC2_CATALOG : ISO27001_CATALOG;
  return Object.entries(catalog).map(([id, entry]) => ({ framework, id, ...entry }));
}

/** Every control id referenced by any category mapping (for completeness checks). */
export function referencedControlIds(framework: ComplianceFramework): string[] {
  const map = framework === "soc2" ? SOC2_CATEGORY_CONTROLS : ISO27001_CATEGORY_CONTROLS;
  return [...new Set(Object.values(map).flat())].sort();
}
