/**
 * MITRE ATT&CK report surfacing (B2).
 *
 * @montr/contracts's `packages/contracts/src/mitre.ts` owns the actual
 * `Category -> technique id[]` mapping (the exhaustive, compiler-enforced
 * `Record<Category, readonly string[]>`, mirroring this file's SOC 2/ISO 27001
 * sibling `./controls.ts`). This module is purely the REPORT-SURFACING layer on
 * top of it — the ATT&CK analog of `./evidence.ts`'s per-finding control
 * mapping, but standalone: it does not import from or mutate `./evidence.ts`,
 * `./controls.ts`, `./index.ts`'s export registry, or `../report-builder.ts`
 * (the main report-assembly file), so it carries zero merge risk against the
 * other blue-team work landing in this same wave. A later wave (B10, per the
 * wave plan) is responsible for wiring this into the final report shape /
 * export registry alongside the other standalone blue-team capabilities.
 *
 * Two views over the same underlying per-finding mapping, same shape as
 * `./evidence.ts`'s `EvidenceRecord` + `ControlCoverage` pair:
 *   - {@link MitreFindingMapping} — one row per CONFIRMED finding, the
 *     technique descriptors (id + name + tactic + url) its category maps to.
 *   - {@link MitreTechniqueCoverage} — the inverse index: one row per
 *     referenced technique, which/how-many findings map to it.
 */
import {
  mitreTechniquesForCategory,
  type ConfirmedFinding,
  type MitreTechniqueDescriptor,
  type Report,
} from "@montr/contracts";

/** One confirmed finding's MITRE ATT&CK/ATLAS technique mapping. */
export interface MitreFindingMapping {
  findingId: string;
  title: string;
  category: string;
  severity: string;
  techniques: MitreTechniqueDescriptor[];
}

/** Per-technique coverage: how many (and which) findings map to this technique. */
export interface MitreTechniqueCoverage {
  technique: MitreTechniqueDescriptor;
  findingCount: number;
  findingIds: string[];
}

/** The full MITRE ATT&CK section for a report: per-finding mappings + the coverage index. */
export interface MitreAttackSection {
  scanId: string;
  clientId: string;
  generatedAt: string;
  findings: MitreFindingMapping[];
  coverage: MitreTechniqueCoverage[];
}

function mappingFor(finding: ConfirmedFinding): MitreFindingMapping {
  return {
    findingId: finding.id,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    techniques: mitreTechniquesForCategory(finding.category),
  };
}

function coverageOf(mappings: readonly MitreFindingMapping[]): MitreTechniqueCoverage[] {
  const byId = new Map<string, MitreTechniqueCoverage>();
  for (const mapping of mappings) {
    for (const technique of mapping.techniques) {
      let cov = byId.get(technique.id);
      if (!cov) {
        cov = { technique, findingCount: 0, findingIds: [] };
        byId.set(technique.id, cov);
      }
      cov.findingCount += 1;
      cov.findingIds.push(mapping.findingId);
    }
  }
  return [...byId.values()].sort((a, b) => a.technique.id.localeCompare(b.technique.id));
}

/** Build the MITRE ATT&CK mapping for every CONFIRMED finding in a report. */
export function buildMitreFindingMappings(report: Report): MitreFindingMapping[] {
  return report.confirmedFindings.map((rf) => mappingFor(rf.finding));
}

/** Build the full MITRE ATT&CK report section (per-finding mappings + coverage index). */
export function buildMitreAttackSection(report: Report, now?: string): MitreAttackSection {
  const findings = buildMitreFindingMappings(report);
  return {
    scanId: report.scanId,
    clientId: report.clientId,
    generatedAt: now ?? report.generatedAt,
    findings,
    coverage: coverageOf(findings),
  };
}

/** JSON rendering of the MITRE ATT&CK report section (drop-in alongside evidence JSON exports). */
export function renderMitreAttackJson(report: Report, now?: string): string {
  return JSON.stringify(buildMitreAttackSection(report, now), null, 2);
}
