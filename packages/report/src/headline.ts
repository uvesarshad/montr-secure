/**
 * ⛔ HEADLINE SAFETY (golden rule, PRD §12).
 *
 * "Never headline raw counts. Headline = confirmed + prioritized. The appendix
 * is where breadth lives." This module is the single place that renders the
 * headline, and it renders it EXCLUSIVELY from confirmed findings + fix status.
 * It never has access to the candidate/probable pile, so a raw count physically
 * cannot leak into the headline. {@link assertConfirmedOnlyHeadline} makes the
 * invariant testable.
 */
import type { Report, Severity } from "@montr/contracts";

const HEADLINE_SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Structured headline — confirmed-only, prioritized. Safe to surface anywhere. */
export interface Headline {
  totalConfirmed: number;
  /** Severity breakdown, highest first, zero buckets omitted. */
  bySeverity: Array<{ severity: Severity; count: number }>;
  prsOpened: number;
  autoEligibleFixes: number;
  humanRequiredFixes: number;
  postureText?: string;
}

/** Build the structured, confirmed-only headline from a finished report. */
export function buildHeadline(report: Report): Headline {
  const es = report.executiveSummary;
  const bySeverity = HEADLINE_SEVERITY_ORDER.map((severity) => ({
    severity,
    count: es.confirmedBySeverity[severity] ?? 0,
  })).filter((b) => b.count > 0);

  const headline: Headline = {
    totalConfirmed: es.totalConfirmed,
    bySeverity,
    prsOpened: report.fixStatus.pullRequests.length,
    autoEligibleFixes: report.fixStatus.autoEligibleFixIds.length,
    humanRequiredFixes: report.fixStatus.humanRequiredFixIds.length,
  };

  const delta = es.postureDelta;
  if (delta) {
    headline.postureText = `${delta.newIssues} new, ${delta.resolvedIssues} resolved vs last scan (net ${delta.netDelta >= 0 ? "+" : ""}${delta.netDelta})`;
  }
  return headline;
}

/** One-line human headline. Confirmed + prioritized only — never a raw count. */
export function renderHeadline(report: Report): string {
  const h = buildHeadline(report);
  const noun = h.totalConfirmed === 1 ? "confirmed vulnerability" : "confirmed vulnerabilities";
  const breakdown =
    h.bySeverity.length > 0
      ? ` (${h.bySeverity.map((b) => `${b.count} ${b.severity}`).join(", ")})`
      : "";
  const parts = [`${h.totalConfirmed} ${noun}${breakdown}.`];
  if (h.prsOpened > 0) {
    parts.push(`${h.prsOpened} auto-fix PR${h.prsOpened === 1 ? "" : "s"} opened.`);
  } else if (h.autoEligibleFixes > 0) {
    parts.push(
      `${h.autoEligibleFixes} auto-fix${h.autoEligibleFixes === 1 ? "" : "es"} ready; ${h.humanRequiredFixes} require human review.`,
    );
  }
  if (h.postureText) parts.push(`Posture: ${h.postureText}.`);
  return parts.join(" ");
}

/**
 * ⛔ Invariant: the executive summary counts CONFIRMED findings only. Throws if
 * `totalConfirmed` disagrees with the per-severity breakdown, or (when the raw
 * candidate count is known) if the summary ever echoes it. Used by tests and can
 * gate report emission.
 */
export function assertConfirmedOnlyHeadline(report: Report, rawCandidateCount?: number): void {
  const es = report.executiveSummary;
  const sum = Object.values(es.confirmedBySeverity).reduce((a, b) => a + (b ?? 0), 0);
  if (sum !== es.totalConfirmed) {
    throw new Error(
      `headline invariant: totalConfirmed (${es.totalConfirmed}) != sum(confirmedBySeverity) (${sum})`,
    );
  }
  if (es.totalConfirmed !== report.confirmedFindings.length) {
    throw new Error(
      `headline invariant: totalConfirmed (${es.totalConfirmed}) != confirmedFindings.length (${report.confirmedFindings.length})`,
    );
  }
  if (
    rawCandidateCount !== undefined &&
    rawCandidateCount !== es.totalConfirmed &&
    (es.totalConfirmed === rawCandidateCount || sum === rawCandidateCount)
  ) {
    throw new Error("headline invariant: raw candidate count must never headline the report");
  }
}
