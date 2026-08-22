/**
 * Report model assembly (PRD §12) — the hero product.
 *
 * ⛔ HEADLINE = confirmed + prioritized. The executive summary is derived ONLY
 * from confirmed findings; the raw candidate pile is NEVER counted here (that
 * breadth lives in the unconfirmed appendix). See {@link renderHeadline} /
 * {@link assertConfirmedOnlyHeadline} for the enforced invariant.
 *
 * `buildReport` is PURE and offline unless a `PullRequestOpener` is injected —
 * only then does it open PRs (auto-eligible + gate-passed only).
 */
import {
  complianceForCategory,
  ExecutiveSummarySchema,
  Layer5OutputSchema,
  PostureDeltaSchema,
  ReportSchema,
  type BlueTeamReport,
  type ComplianceMapping,
  type ConfirmedFinding,
  type ExecutiveSummary,
  type Fix,
  type Layer5Output,
  type PostureDelta,
  type PullRequest,
  type Report,
  type ReportFinding,
  type Severity,
} from "@montr/contracts";
import { buildDetectionCoverage } from "@montr/appmap";
import { buildAttackPaths } from "@montr/correlation";
import { openAutoFixPullRequests, prIdByFixId } from "./auto-fix.js";
import { generateDetectionRules } from "./detection-rules/generate.js";
import { buildMitreAttackSection } from "./exports/mitre-attack.js";
import { buildThreatModelReport, renderThreatModelReportMarkdown } from "./exports/threat-model.js";
import type { BuildReportInput, PreviousScanContext } from "./types.js";

/** Priority ordering for the headline (most severe first). */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const ALL_SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

/** Public exposure sorts before authed within the same severity. */
function exposureRank(exposure: ConfirmedFinding["exposure"]): number {
  return exposure === "public" ? 0 : 1;
}

/**
 * A stable, cross-scan fingerprint for a confirmed finding (category + file +
 * symbol/line). Used for the posture delta so line drift alone does not read as
 * "resolved + new".
 */
export function findingFingerprint(finding: ConfirmedFinding): string {
  const loc = finding.location;
  return `${finding.category}|${loc.file}|${loc.symbol ?? loc.line}`;
}

/** Prioritized order: severity desc, public-before-authed, then title. */
export function prioritize(confirmed: readonly ConfirmedFinding[]): ConfirmedFinding[] {
  return [...confirmed].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      exposureRank(a.exposure) - exposureRank(b.exposure) ||
      a.title.localeCompare(b.title),
  );
}

/** Count confirmed findings per severity (all five keys always present). */
export function countBySeverity(confirmed: readonly ConfirmedFinding[]): Record<Severity, number> {
  const counts = Object.fromEntries(ALL_SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of confirmed) counts[f.severity] += 1;
  return counts;
}

/**
 * Posture delta vs the previous scan (§12.1). `netDelta = newIssues -
 * resolvedIssues` (positive = regression). Compares by {@link findingFingerprint}.
 */
export function computePostureDelta(
  current: readonly ConfirmedFinding[],
  previous: PreviousScanContext,
): PostureDelta {
  const cur = new Set(current.map(findingFingerprint));
  const prev = new Set(previous.confirmed.map(findingFingerprint));
  let newIssues = 0;
  for (const fp of cur) if (!prev.has(fp)) newIssues += 1;
  let resolvedIssues = 0;
  for (const fp of prev) if (!cur.has(fp)) resolvedIssues += 1;
  return PostureDeltaSchema.parse({
    ...(previous.scanId ? { previousScanId: previous.scanId } : {}),
    newIssues,
    resolvedIssues,
    netDelta: newIssues - resolvedIssues,
  });
}

/** Distinct point tools consolidated into this scan (from the candidate pile). */
export function deriveToolsConsolidated(input: BuildReportInput): string[] {
  if (input.toolsConsolidated) return [...new Set(input.toolsConsolidated)].sort();
  if (!input.candidates) return [];
  const tools = new Set<string>();
  for (const c of input.candidates) if (c.source !== "llm-triage") tools.add(c.source);
  return [...tools].sort();
}

/**
 * Executive summary (§12.1). ⛔ Counts CONFIRMED findings only — never the raw
 * candidate/probable pile. That is the headline safety property (golden rule).
 */
export function buildExecutiveSummary(input: BuildReportInput): ExecutiveSummary {
  const confirmed = input.confirmed;
  const summary: ExecutiveSummary = {
    totalConfirmed: confirmed.length,
    confirmedBySeverity: countBySeverity(confirmed),
    toolsConsolidated: deriveToolsConsolidated(input),
    ...(input.previous ? { postureDelta: computePostureDelta(confirmed, input.previous) } : {}),
  };
  return ExecutiveSummarySchema.parse(summary);
}

/** Distinct compliance mappings across the confirmed findings (§12.5), deduped. */
export function buildComplianceMapping(
  confirmed: readonly ConfirmedFinding[],
): ComplianceMapping[] {
  const seen = new Set<string>();
  const out: ComplianceMapping[] = [];
  for (const f of confirmed) {
    if (seen.has(f.category)) continue;
    seen.add(f.category);
    out.push(complianceForCategory(f.category));
  }
  return out;
}

/** Reflect PR state onto the fixes that landed in a PR (status → "pr-open"). */
function applyPrStatus(
  fixes: readonly Fix[],
  prs: readonly PullRequest[],
  updatedAt: string,
): Fix[] {
  const prByFix = prIdByFixId([...prs]);
  return fixes.map((fix) => {
    const prId = prByFix.get(fix.id);
    if (!prId) return fix;
    return { ...fix, status: "pr-open", pullRequestId: prId, updatedAt };
  });
}

/**
 * Assemble the full Layer-5 output: the §12 report + the opened PRs.
 *
 * Ordering matters: the report EMBEDS the PR state (fix status "pr-open"), so PRs
 * are opened first, then the report is built to reflect them. When no opener is
 * injected (the pure path), no PRs open and every auto-eligible fix is surfaced
 * as "ready" via `fixStatus.autoEligibleFixIds`.
 */
export async function buildReport(input: BuildReportInput): Promise<Layer5Output> {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const reportId = input.reportId ?? `report_${input.scan.id}`;

  // 1. Gated auto-fix PRs (auto-eligible + gate-passed only; [] on the pure path).
  const pullRequests = await openAutoFixPullRequests({
    scan: input.scan,
    confirmed: input.confirmed,
    fixes: input.fixes,
    autoApply: input.autoApply,
    ...(input.opener ? { opener: input.opener } : {}),
    ...(input.prStrategy ? { prStrategy: input.prStrategy } : {}),
    ...(input.baseBranch ? { baseBranch: input.baseBranch } : {}),
    ...(input.audit ? { audit: input.audit } : {}),
    ...(input.logger ? { logger: input.logger } : {}),
  });

  // 2. Reflect PR state onto fixes and index them by confirmed-finding id.
  const fixes = applyPrStatus(input.fixes, pullRequests, generatedAt);
  const fixByFinding = new Map<string, Fix>();
  for (const fix of fixes) {
    if (!fixByFinding.has(fix.confirmedFindingId)) {
      fixByFinding.set(fix.confirmedFindingId, fix);
    }
  }

  // 3. Confirmed findings, prioritized, each with its merge-ready fix + compliance.
  const confirmedFindings: ReportFinding[] = prioritize(input.confirmed).map((finding) => {
    const fix = fixByFinding.get(finding.id);
    return {
      finding,
      ...(fix ? { fix } : {}),
      compliance: complianceForCategory(finding.category),
    };
  });

  // 4. Fix status: which are auto-eligible (PRs) vs human-required (recommendations).
  const autoEligibleFixIds = input.fixes
    .filter((f) => f.riskClass === "auto-eligible")
    .map((f) => f.id);
  const humanRequiredFixIds = input.fixes
    .filter((f) => f.riskClass === "human-required")
    .map((f) => f.id);

  const reportCore = ReportSchema.parse({
    id: reportId,
    scanId: input.scan.id,
    clientId: input.scan.clientId,
    generatedAt,
    executiveSummary: buildExecutiveSummary(input),
    confirmedFindings,
    fixStatus: { autoEligibleFixIds, humanRequiredFixIds, pullRequests },
    unconfirmedAppendix: input.unconfirmed,
    complianceMapping: buildComplianceMapping(input.confirmed),
    costAndScope: { scope: input.scan.scope, cost: input.costRollup },
  });

  // 5. Blue-team sections (B10) — computed against the just-built core report
  // (already carries prioritized confirmedFindings/scanId/clientId/generatedAt,
  // exactly what buildMitreAttackSection etc. need), then folded back in with
  // a second parse.
  const blueTeam = buildBlueTeamReport(
    reportCore,
    reportCore.confirmedFindings.map((rf) => rf.finding),
    input,
  );
  const report = ReportSchema.parse({ ...reportCore, blueTeam });

  return Layer5OutputSchema.parse({ report, pullRequests });
}

/**
 * Assemble the six blue-team sections (B10, see this file's header) on top
 * of an already-built, schema-valid core `Report`. Every section is computed
 * independently and degrades to an honest empty/absent state when its
 * optional input (`appMap`, `hardeningRecommendations`, `purpleTeamEntries`)
 * is not supplied — never a guess (mirrors `DetectionCoverage`'s own
 * tri-state discipline).
 */
export function buildBlueTeamReport(
  report: Report,
  confirmed: readonly ConfirmedFinding[],
  input: BuildReportInput,
): BlueTeamReport {
  const generatedAt = report.generatedAt;
  const appMap = input.appMap;

  // B2 — MITRE ATT&CK per-finding mapping + technique coverage index.
  const mitre = buildMitreAttackSection(report, generatedAt);

  // B3/B4 — generated Sigma/OTel/SIEM rules + log-signature narrative, one
  // triple per confirmed finding. Pure; `appMap` only resolves a route for
  // static-proof findings (optional — degrades to a file-scoped rule).
  const rules = confirmed.flatMap((finding) =>
    generateDetectionRules(finding, { ...(appMap ? { appMap } : {}), now: () => generatedAt }),
  );

  // B6 — tri-state coverage verdict per finding, grounded in the SAME
  // generated rules above (so a rule a coverage verdict cites is always one
  // this same report's detectionEngineering.rules also lists).
  const coverage = appMap
    ? buildDetectionCoverage(appMap, confirmed, rules, { now: () => new Date(generatedAt) })
    : [];

  // B8 — chained kill-chains across >= 2 confirmed findings, ranked by
  // feasibility then severity (buildAttackPaths's own ranking).
  const attackPaths = appMap
    ? buildAttackPaths({
        clientId: report.clientId,
        scanId: report.scanId,
        appMap,
        findings: confirmed,
        now: generatedAt,
      })
    : [];

  // B7 — the reviewable threat-model artifact, when the App Map carried one.
  const threatModel = appMap?.threatModel;
  const threatModelSection = threatModel
    ? {
        present: true as const,
        summary: buildThreatModelReport(threatModel, { scanId: report.scanId, now: generatedAt })
          .summary,
        markdown: renderThreatModelReportMarkdown(threatModel, {
          scanId: report.scanId,
          now: generatedAt,
        }),
        raw: threatModel,
      }
    : { present: false as const };

  // B9 — advisory-only hardening recommendations, precomputed by the caller
  // (see BuildReportInput.hardeningRecommendations's doc comment: generation
  // needs a FileProvider over the real repo checkout, genuine I/O buildReport
  // stays free of, mirroring how `fixes`/`costRollup` are precomputed too).
  const hardening = {
    advisoryOnly: true as const,
    recommendations: input.hardeningRecommendations ?? [],
  };

  // B5 — purple-team detected-vs-undetected summary, precomputed by the
  // caller (see BuildReportInput.purpleTeamEntries's doc comment). Empty
  // entries -> zero counts, never a fabricated verdict.
  const purpleEntries = input.purpleTeamEntries ?? [];
  const detectedCount = purpleEntries.filter((e) => e.detected).length;
  const purpleTeam = {
    entries: purpleEntries,
    totalScenarios: purpleEntries.length,
    detectedCount,
    undetectedCount: purpleEntries.length - detectedCount,
  };

  return {
    mitreAttack: { findings: mitre.findings, coverage: mitre.coverage },
    detectionEngineering: { rules, coverage },
    attackPaths,
    threatModel: threatModelSection,
    hardening,
    purpleTeam,
  };
}
