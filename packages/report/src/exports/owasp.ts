/**
 * Generic OWASP Top 10 (2021) + CWE report (§13, DECIDE-5: OWASP ships first).
 *
 * Every confirmed finding is mapped to its OWASP Top 10 category and CWE(s) via
 * the frozen @montr/contracts taxonomy (`complianceForCategory` / `OWASP_TITLES`).
 * The report is a full COVERAGE view: all ten categories are listed (even the
 * ones with zero findings) so a reader sees the whole standard, not just what hit.
 *
 * Three renderings, all driven from the same {@link buildOwaspCoverage} model:
 *   - `renderReportOwaspJson` — machine-readable (JSON).
 *   - `renderOwaspHtml`       — human-readable, self-contained, XSS-safe HTML.
 *   - `renderOwaspPdf`        — the HTML above via the existing puppeteer-core path.
 */
import {
  complianceForCategory,
  OWASP_TITLES,
  OwaspIdSchema,
  type OwaspId,
  type Report,
  type ReportFinding,
} from "@montr/contracts";
import { escapeHtml } from "./html.js";
import { htmlToPdf, type PdfOptions } from "./pdf.js";

/** The ten OWASP Top 10 (2021) category codes, in order. */
export const OWASP_TOP_10: readonly OwaspId[] = OwaspIdSchema.options;

/** One finding as it appears under an OWASP category. */
export interface OwaspFindingRow {
  id: string;
  title: string;
  severity: string;
  exposure: string;
  cwe: string[];
  location: { file: string; line: number };
  proofType: string;
  fixAvailable: boolean;
}

/** One OWASP category with the confirmed findings mapped to it. */
export interface OwaspCategoryGroup {
  owasp: OwaspId;
  owaspTitle: string;
  count: number;
  present: boolean;
  findings: OwaspFindingRow[];
}

function findingRow(rf: ReportFinding): OwaspFindingRow {
  const f = rf.finding;
  const cwe = f.cwe.length > 0 ? f.cwe : rf.compliance.cwe;
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    exposure: f.exposure,
    cwe: [...cwe],
    location: { file: f.location.file, line: f.location.line },
    proofType: f.proofType,
    fixAvailable: rf.fix !== undefined,
  };
}

/**
 * Build the full OWASP Top 10 coverage model: all ten categories, each with the
 * confirmed findings mapped to it (via the finding's category → OWASP taxonomy).
 */
export function buildOwaspCoverage(report: Report): OwaspCategoryGroup[] {
  const byOwasp = new Map<OwaspId, OwaspFindingRow[]>();
  for (const code of OWASP_TOP_10) byOwasp.set(code, []);
  for (const rf of report.confirmedFindings) {
    const owasp = rf.finding.owasp ?? complianceForCategory(rf.finding.category).owasp;
    byOwasp.get(owasp)?.push(findingRow(rf));
  }
  return OWASP_TOP_10.map((owasp) => {
    const findings = byOwasp.get(owasp) ?? [];
    return {
      owasp,
      owaspTitle: OWASP_TITLES[owasp],
      count: findings.length,
      present: findings.length > 0,
      findings,
    };
  });
}

/**
 * Generic OWASP-oriented JSON. Full coverage (all ten categories in `coverage`)
 * plus the covered groups in `owaspTop10` (each finding carries its CWE mapping).
 */
export function renderReportOwaspJson(report: Report): string {
  const coverage = buildOwaspCoverage(report);
  const covered = coverage.filter((g) => g.present);
  return JSON.stringify(
    {
      tool: "Montr Secure",
      standard: "OWASP Top 10 (2021)",
      scanId: report.scanId,
      clientId: report.clientId,
      generatedAt: report.generatedAt,
      totalConfirmed: report.executiveSummary.totalConfirmed,
      // Full standard coverage: every category, with its confirmed count.
      coverage: coverage.map((g) => ({
        owasp: g.owasp,
        title: g.owaspTitle,
        count: g.count,
        present: g.present,
      })),
      // Categories that actually have confirmed findings (each mapped to CWE).
      owaspTop10: covered.map((g) => ({
        owasp: g.owasp,
        title: g.owaspTitle,
        count: g.count,
        findings: g.findings,
      })),
    },
    null,
    2,
  );
}

const OWASP_STYLE = `
  :root { color-scheme: light dark; }
  body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; max-width: 960px; margin-inline: auto; color: #1a1a2e; }
  h1 { font-size: 1.7rem; margin-bottom: .2rem; }
  h2 { font-size: 1.2rem; margin-top: 1.6rem; }
  table { border-collapse: collapse; width: 100%; margin: .6rem 0; }
  th, td { text-align: left; padding: .4rem .6rem; border: 1px solid #e2e2ee; vertical-align: top; }
  th { background: #f7f7fc; }
  .cat { border: 1px solid #e2e2ee; border-radius: 10px; padding: .8rem 1.1rem; margin: .9rem 0; }
  .cat.empty { opacity: .6; }
  .count { font-weight: 700; }
  .badge { font-size: .72rem; font-weight: 700; padding: .12rem .5rem; border-radius: 999px; text-transform: uppercase; }
  .sev-critical { background: #7a0b28; color: #fff; } .sev-high { background: #c62828; color: #fff; }
  .sev-medium { background: #ef6c00; color: #fff; } .sev-low { background: #f9a825; color: #222; } .sev-info { background: #90a4ae; color: #fff; }
  footer { margin-top: 2.5rem; color: #888; font-size: .8rem; border-top: 1px solid #e2e2ee; padding-top: 1rem; }
`;

function owaspCategoryHtml(g: OwaspCategoryGroup): string {
  const header = `<h2>${escapeHtml(g.owasp)} — ${escapeHtml(g.owaspTitle)} <span class="count">(${escapeHtml(g.count)})</span></h2>`;
  if (!g.present) {
    return `<section class="cat empty">${header}<p>No confirmed findings in this category.</p></section>`;
  }
  const rows = g.findings
    .map(
      (f) =>
        `<tr><td>${escapeHtml(f.title)} <span class="badge sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td><td>${escapeHtml(f.cwe.join(", "))}</td><td><code>${escapeHtml(f.location.file)}:${escapeHtml(f.location.line)}</code></td><td>${escapeHtml(f.exposure)}</td><td>${escapeHtml(f.proofType)}</td><td>${f.fixAvailable ? "yes" : "no"}</td></tr>`,
    )
    .join("");
  return `<section class="cat">${header}<table><thead><tr><th>Finding</th><th>CWE</th><th>Location</th><th>Exposure</th><th>Proof</th><th>Fix</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

/** Human-readable, self-contained, XSS-safe OWASP Top 10 report HTML. */
export function renderOwaspHtml(report: Report): string {
  const coverage = buildOwaspCoverage(report);
  const coveredCount = coverage.filter((g) => g.present).length;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Montr Secure — OWASP Top 10 (2021) Report — ${escapeHtml(report.scanId)}</title>
  <style>${OWASP_STYLE}</style>
</head>
<body>
  <h1>OWASP Top 10 (2021) — Coverage Report</h1>
  <p>Scan <code>${escapeHtml(report.scanId)}</code> · generated ${escapeHtml(report.generatedAt)}</p>
  <p><strong>${escapeHtml(report.executiveSummary.totalConfirmed)}</strong> confirmed findings across <strong>${escapeHtml(coveredCount)}</strong> of 10 OWASP categories. Every confirmed finding is mapped to its OWASP category and CWE(s).</p>
  ${coverage.map(owaspCategoryHtml).join("\n")}
  <footer>Generated by Montr Secure. Mapping driven by the CWE / OWASP Top 10 (2021) taxonomy. Confirmed findings only — breadth lives in the main report appendix.</footer>
</body>
</html>`;
}

/** Render the OWASP Top 10 report to PDF via the existing puppeteer-core path. */
export async function renderOwaspPdf(report: Report, opts: PdfOptions = {}): Promise<Uint8Array> {
  return htmlToPdf(renderOwaspHtml(report), opts);
}
