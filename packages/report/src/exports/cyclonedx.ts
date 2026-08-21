/**
 * CycloneDX 1.5 SBOM exporter (E16). Serializes the FULL resolved dependency
 * tree — not just confirmed/vulnerable findings — into a schema-valid
 * CycloneDX JSON document, annotated with real call-site reachability (A12)
 * and matched OSV/GHSA advisories where they exist.
 *
 * Structurally DIFFERENT input than every other exporter in this directory:
 * SARIF/OWASP/SOC2/ISO27001 all render from a `Report`'s `confirmedFindings`
 * (a filtered, pipeline-processed subset). An SBOM's entire point is to list
 * EVERY dependency, vulnerable or not — data a `Report` never carries (Layer
 * 1's `detectDependencies` only ever emits a `CandidateFinding` per MATCHED
 * advisory, dropping every clean package before Layer 2/3 even run; see
 * `packages/discovery/src/sbom.ts`'s module doc for the full reasoning).
 * `buildCycloneDxSbom`/`renderCycloneDxSbom` therefore take a plain
 * `DependencyInventory`-shaped input directly (duck-typed structurally, not
 * imported — this package does not depend on `@montr/discovery`, keeping the
 * dependency graph one-way; the caller wires
 * `@montr/discovery`'s `buildDependencyInventory()` output into
 * `GenerateExportOptions.dependencyInventory` to reach the `EXPORTERS`
 * registry entry below).
 *
 * The `Report`-shaped `renderReportCyclonedx` convenience wrapper folds in
 * the report's OWN confirmed `vulnerable_dependency` findings as an
 * ADDITIONAL vulnerability cross-check when no inventory is supplied, so the
 * export never silently produces an empty/near-empty SBOM for a caller that
 * only has a `Report` on hand — but a real inventory (with the full package
 * list) always produces the richer, spec-accurate document and should be
 * preferred whenever the caller has one.
 */
import { randomUUID } from "node:crypto";
import type { Report, Severity } from "@montr/contracts";

const SBOM_TOOL_NAME = "Montr Secure";
const SBOM_TOOL_VENDOR = "Montr";
export const CYCLONEDX_SPEC_VERSION = "1.5";

/** Structural (duck-typed) mirror of `@montr/discovery`'s `SbomComponent` — see module doc. */
export interface CycloneDxComponentInput {
  name: string;
  version: string;
  ecosystem?: string;
  reachable?: boolean;
}

/** Structural mirror of `@montr/discovery`'s `SbomVulnerability`. */
export interface CycloneDxVulnerabilityInput {
  id: string;
  source: "osv" | "ghsa";
  packageName: string;
  packageVersion: string;
  severity: Severity;
  cwe?: readonly string[];
  summary?: string;
  fixedVersion?: string;
  aliases?: readonly string[];
  reachable?: boolean;
}

export interface DependencyInventoryInput {
  components: readonly CycloneDxComponentInput[];
  vulnerabilities?: readonly CycloneDxVulnerabilityInput[];
  source?: string;
}

export interface BuildCycloneDxSbomOptions {
  /** Deterministic generation time (tests). Defaults to now. */
  now?: string;
  /** Deterministic serial number (tests). Defaults to a fresh UUID. */
  serialNumber?: string;
  scanId?: string;
}

interface CycloneDxProperty {
  name: string;
  value: string;
}

interface CycloneDxComponent {
  type: "library";
  "bom-ref": string;
  name: string;
  version: string;
  purl: string;
  properties: CycloneDxProperty[];
}

interface CycloneDxRating {
  severity: "critical" | "high" | "medium" | "low" | "info" | "unknown";
  method: "other";
}

interface CycloneDxVulnerability {
  id: string;
  source: { name: string };
  ratings: CycloneDxRating[];
  cwes: number[];
  description?: string;
  recommendation?: string;
  affects: Array<{ ref: string }>;
  properties: CycloneDxProperty[];
}

export interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: string;
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: { components: Array<{ type: "application"; name: string; vendor: string }> };
    component?: { type: "application"; "bom-ref": string; name: string };
  };
  components: CycloneDxComponent[];
  vulnerabilities: CycloneDxVulnerability[];
}

/** `pkg:npm/name@version` — the npm PURL form (only ecosystem this product resolves today, A12/sca.ts). */
function purlFor(name: string, version: string, ecosystem: string | undefined): string {
  const type = ecosystem ?? "npm";
  // Scoped packages (`@scope/name`) must have the `@` percent-encoded per the
  // PURL spec's npm type rules.
  const encodedName = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:${type}/${encodedName}@${version}`;
}

const RATING_SEVERITY: Record<Severity, CycloneDxRating["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

function cweNumber(cwe: string): number | undefined {
  const m = /^CWE-(\d+)$/i.exec(cwe);
  return m?.[1] ? Number(m[1]) : undefined;
}

/** Build a schema-shaped CycloneDX 1.5 BOM from a plain dependency inventory. */
export function buildCycloneDxSbom(
  inventory: DependencyInventoryInput,
  opts: BuildCycloneDxSbomOptions = {},
): CycloneDxBom {
  const componentRef = new Map<string, string>();
  const components: CycloneDxComponent[] = inventory.components.map((c) => {
    const ref = purlFor(c.name, c.version, c.ecosystem);
    componentRef.set(`${c.name}@${c.version}`, ref);
    const properties: CycloneDxProperty[] = [];
    if (c.reachable !== undefined) {
      properties.push({ name: "montr:reachable", value: String(c.reachable) });
    }
    return {
      type: "library",
      "bom-ref": ref,
      name: c.name,
      version: c.version,
      purl: ref,
      properties,
    };
  });

  const vulnerabilities: CycloneDxVulnerability[] = (inventory.vulnerabilities ?? []).map((v) => {
    const key = `${v.packageName}@${v.packageVersion}`;
    // A vulnerability whose package isn't in `components` (shouldn't happen
    // for real callers, but defensive) still gets a synthesized PURL ref
    // rather than silently dropping the finding from the SBOM.
    const ref = componentRef.get(key) ?? purlFor(v.packageName, v.packageVersion, undefined);
    const properties: CycloneDxProperty[] = [];
    if (v.reachable !== undefined) {
      properties.push({ name: "montr:reachable", value: String(v.reachable) });
    }
    if (v.aliases && v.aliases.length > 0) {
      properties.push({ name: "montr:aliases", value: v.aliases.join(",") });
    }
    return {
      id: v.id,
      source: { name: v.source === "ghsa" ? "GHSA" : "OSV" },
      ratings: [{ severity: RATING_SEVERITY[v.severity], method: "other" }],
      cwes: (v.cwe ?? []).map(cweNumber).filter((n): n is number => n !== undefined),
      ...(v.summary ? { description: v.summary } : {}),
      ...(v.fixedVersion ? { recommendation: `Upgrade to ${v.fixedVersion} or later.` } : {}),
      affects: [{ ref }],
      properties,
    };
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: opts.serialNumber ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: opts.now ?? new Date().toISOString(),
      tools: {
        components: [{ type: "application", name: SBOM_TOOL_NAME, vendor: SBOM_TOOL_VENDOR }],
      },
      ...(opts.scanId
        ? { component: { type: "application", "bom-ref": opts.scanId, name: opts.scanId } }
        : {}),
    },
    components,
    vulnerabilities,
  };
}

/** CycloneDX JSON string (pretty-printed) from a plain dependency inventory. */
export function renderCycloneDxSbom(
  inventory: DependencyInventoryInput,
  opts: BuildCycloneDxSbomOptions = {},
): string {
  return JSON.stringify(buildCycloneDxSbom(inventory, opts), null, 2);
}

/**
 * `Report`-shaped convenience path: when the caller has no real
 * `DependencyInventory` on hand, derive a (necessarily partial — see module
 * doc) inventory from the report's own confirmed `vulnerable_dependency`
 * findings, so `generateExport(report, "cyclonedx")` never throws or
 * produces a schema-invalid document even with the leaner input.
 */
export function inventoryFromReport(report: Report): DependencyInventoryInput {
  const vulnFindings = report.confirmedFindings
    .map((rf) => rf.finding)
    .filter((f) => f.category === "vulnerable_dependency");

  const seen = new Map<string, CycloneDxComponentInput>();
  const vulnerabilities: CycloneDxVulnerabilityInput[] = [];
  for (const f of vulnFindings) {
    // Best-effort package/version split from the finding title
    // ("Vulnerable dependency: name@version (ADV-ID)", `sca.ts`'s exact
    // format) — the confirmed-finding contract has no structured
    // name/version fields (see this file's module doc on why the real
    // inventory path should be preferred whenever available).
    const m = /^Vulnerable dependency: (.+)@([^@\s]+) \(([^)]+)\)$/.exec(f.title);
    const name = m?.[1] ?? f.location.file;
    const version = m?.[2] ?? "0.0.0";
    const advisoryId = m?.[3] ?? f.id;
    if (!seen.has(`${name}@${version}`)) {
      seen.set(`${name}@${version}`, { name, version, ecosystem: "npm" });
    }
    vulnerabilities.push({
      id: advisoryId,
      source: advisoryId.toUpperCase().startsWith("GHSA") ? "ghsa" : "osv",
      packageName: name,
      packageVersion: version,
      severity: f.severity,
      cwe: f.cwe,
      summary: f.impact,
    });
  }

  return { components: [...seen.values()], vulnerabilities };
}
