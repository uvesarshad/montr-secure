/**
 * Self-contained HTML report (§12). Renders the confirmed-first report: headline,
 * executive summary, confirmed findings with PROOF (static argument or live
 * transcript) and merge-ready fix + test, fix status, the clearly-separated
 * unconfirmed appendix, compliance mapping, and cost & scope.
 *
 * The report tool must be exemplary: EVERY interpolated value is HTML-escaped so
 * the report can never introduce XSS from finding text or a captured transcript.
 * No external assets (CSP-safe, printable → the PDF exporter renders this same HTML).
 */
import type {
  ComplianceMapping,
  ConfirmedFinding,
  Fix,
  ProofArtifact,
  Report,
  ReportFinding,
  UnconfirmedFinding,
} from "@montr/contracts";
import { renderHeadline } from "../headline.js";

/** HTML-escape a value (defends the report against XSS from finding/transcript text). */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function codeBlock(code: string): string {
  return `<pre class="code"><code>${escapeHtml(code)}</code></pre>`;
}

function sevBadge(severity: string): string {
  return `<span class="badge sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>`;
}

function renderProof(proof: ProofArtifact): string {
  if (proof.kind === "static") {
    const hops = proof.dataFlow
      .map(
        (h) =>
          `<li><code>${escapeHtml(h.location.file)}:${escapeHtml(h.location.line)}</code> — auth: ${escapeHtml(h.authState)}${h.transform ? ` — ${escapeHtml(h.transform)}` : ""}${h.note ? ` <em>(${escapeHtml(h.note)})</em>` : ""}</li>`,
      )
      .join("");
    const bypass =
      proof.sanitizersBypassed.length > 0
        ? `<p><strong>Sanitizers bypassed:</strong> ${escapeHtml(proof.sanitizersBypassed.join(", "))}</p>`
        : "";
    return `<div class="proof"><p class="proof-kind">Static proof-of-reachability</p><p>${escapeHtml(proof.argument)}</p>${hops ? `<ol class="dataflow">${hops}</ol>` : ""}${bypass}</div>`;
  }
  const exchanges = proof.transcript
    .map(
      (x) =>
        `<li><code>${escapeHtml(x.request.method)} ${escapeHtml(x.request.url)}</code> → <strong>${escapeHtml(x.response.status)}</strong>${x.note ? ` <em>(${escapeHtml(x.note)})</em>` : ""}${x.response.bodySnippet ? `<br/>${codeBlock(x.response.bodySnippet)}` : ""}</li>`,
    )
    .join("");
  return `<div class="proof"><p class="proof-kind">Live transcript — <code>${escapeHtml(proof.target)}</code></p><ol class="transcript">${exchanges}</ol></div>`;
}

function renderFix(fix: Fix): string {
  const test = fix.proofOfFixTest;
  return `<div class="fix">
      <p><strong>Merge-ready fix</strong> — risk: ${escapeHtml(fix.riskClass)} — status: ${escapeHtml(fix.status)}</p>
      <p>${escapeHtml(fix.rationale)}</p>
      ${codeBlock(fix.patch)}
      <p class="test-label">Proof-of-fix test (${escapeHtml(test.framework ?? "test")}) — fails pre-patch: ${escapeHtml(test.failsPrePatch)}, passes post-patch: ${escapeHtml(test.passesPostPatch)}</p>
      ${codeBlock(test.code)}
    </div>`;
}

function renderFinding(rf: ReportFinding, index: number): string {
  const f: ConfirmedFinding = rf.finding;
  const c: ComplianceMapping = rf.compliance;
  const cwe = f.cwe.length > 0 ? f.cwe.join(", ") : c.cwe.join(", ");
  return `<section class="finding">
      <h3>${index + 1}. ${escapeHtml(f.title)} ${sevBadge(f.severity)}</h3>
      <table class="meta">
        <tr><th>Category</th><td>${escapeHtml(c.owaspTitle)} (${escapeHtml(c.owasp)})</td></tr>
        <tr><th>CWE</th><td>${escapeHtml(cwe)}</td></tr>
        <tr><th>Location</th><td><code>${escapeHtml(f.location.file)}:${escapeHtml(f.location.line)}</code></td></tr>
        <tr><th>Exposure</th><td>${escapeHtml(f.exposure)}</td></tr>
        <tr><th>Impact</th><td>${escapeHtml(f.impact)}</td></tr>
      </table>
      ${renderProof(f.proofArtifact)}
      ${rf.fix ? renderFix(rf.fix) : '<p class="no-fix">No automated fix generated — manual remediation required.</p>'}
    </section>`;
}

function renderAppendix(items: readonly UnconfirmedFinding[]): string {
  if (items.length === 0) return "<p>None. Every probable finding was confirmed or resolved.</p>";
  const rows = items
    .map(
      (u) =>
        `<tr><td>${escapeHtml(u.category)}</td><td><code>${escapeHtml(u.location.file)}:${escapeHtml(u.location.line)}</code></td><td>${escapeHtml(u.exposure)}</td><td>${escapeHtml(u.unconfirmedReason)}</td></tr>`,
    )
    .join("");
  return `<table class="appendix"><thead><tr><th>Category</th><th>Location</th><th>Exposure</th><th>Why not confirmed</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderCompliance(mappings: readonly ComplianceMapping[]): string {
  if (mappings.length === 0) return "<p>No confirmed findings to map.</p>";
  const rows = mappings
    .map(
      (m) =>
        `<tr><td>${escapeHtml(m.category)}</td><td>${escapeHtml(m.owasp)} — ${escapeHtml(m.owaspTitle)}</td><td>${escapeHtml(m.cwe.join(", "))}</td></tr>`,
    )
    .join("");
  return `<table class="compliance"><thead><tr><th>Category</th><th>OWASP Top 10</th><th>CWE</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderExecSummary(report: Report): string {
  const es = report.executiveSummary;
  const sev = (["critical", "high", "medium", "low", "info"] as const)
    .map((s) => `${es.confirmedBySeverity[s] ?? 0} ${s}`)
    .join(" · ");
  const tools =
    es.toolsConsolidated.length > 0
      ? `<p><strong>Tools consolidated:</strong> ${escapeHtml(es.toolsConsolidated.join(", "))}</p>`
      : "";
  const posture = es.postureDelta
    ? `<p><strong>Posture vs last scan:</strong> ${escapeHtml(es.postureDelta.newIssues)} new, ${escapeHtml(es.postureDelta.resolvedIssues)} resolved (net ${es.postureDelta.netDelta >= 0 ? "+" : ""}${escapeHtml(es.postureDelta.netDelta)})</p>`
    : "";
  return `<p class="headline">${escapeHtml(renderHeadline(report))}</p>
      <p><strong>Confirmed by severity:</strong> ${escapeHtml(sev)}</p>
      ${posture}${tools}`;
}

function renderFixStatus(report: Report): string {
  const fs = report.fixStatus;
  const prs =
    fs.pullRequests.length > 0
      ? `<ul>${fs.pullRequests
          .map(
            (pr) =>
              `<li>${escapeHtml(pr.provider)} — <code>${escapeHtml(pr.branch)}</code>${pr.url ? ` — <a href="${escapeHtml(pr.url)}">${escapeHtml(pr.url)}</a>` : ""} (${escapeHtml(pr.fixIds.length)} fix${pr.fixIds.length === 1 ? "" : "es"}, ${escapeHtml(pr.status)})</li>`,
          )
          .join("")}</ul>`
      : "<p>No PRs opened.</p>";
  return `<p><strong>Auto-eligible fixes:</strong> ${escapeHtml(fs.autoEligibleFixIds.length)} — opened as PRs (never direct commits).</p>
      <p><strong>Human-required fixes:</strong> ${escapeHtml(fs.humanRequiredFixIds.length)} — recommendations only (auth/session/crypto/access-control are never auto-opened).</p>
      ${prs}`;
}

function renderCostScope(report: Report): string {
  const { scope, cost } = report.costAndScope;
  const variance =
    cost.variancePct !== undefined ? ` (variance ${(cost.variancePct * 100).toFixed(1)}%)` : "";
  const actual = cost.actual ? `$${cost.actual.actualUsd.toFixed(2)}` : "n/a";
  return `<table class="cost">
      <tr><th>Mode</th><td>${escapeHtml(scope.mode)}</td></tr>
      <tr><th>Files scanned</th><td>${escapeHtml(scope.fileCount ?? "n/a")}</td></tr>
      <tr><th>Routes</th><td>${escapeHtml(scope.routeCount ?? "n/a")}</td></tr>
      <tr><th>Estimated cost</th><td>$${escapeHtml(cost.estimate.projectedUsd.toFixed(2))}</td></tr>
      <tr><th>Actual cost</th><td>${escapeHtml(actual)}${escapeHtml(variance)}</td></tr>
    </table>`;
}

const STYLE = `
  :root { color-scheme: light dark; }
  body { font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; max-width: 960px; margin-inline: auto; color: #1a1a2e; }
  h1 { font-size: 1.7rem; margin-bottom: .2rem; }
  h2 { font-size: 1.25rem; margin-top: 2.2rem; border-bottom: 2px solid #e2e2ee; padding-bottom: .3rem; }
  h3 { font-size: 1.05rem; margin-top: 1.6rem; }
  .headline { font-size: 1.15rem; font-weight: 600; background: #f4f4fb; padding: .8rem 1rem; border-radius: 8px; border-left: 4px solid #5b5be0; }
  .badge { font-size: .72rem; font-weight: 700; padding: .12rem .5rem; border-radius: 999px; text-transform: uppercase; vertical-align: middle; }
  .sev-critical { background: #7a0b28; color: #fff; } .sev-high { background: #c62828; color: #fff; }
  .sev-medium { background: #ef6c00; color: #fff; } .sev-low { background: #f9a825; color: #222; } .sev-info { background: #90a4ae; color: #fff; }
  table { border-collapse: collapse; width: 100%; margin: .6rem 0; }
  th, td { text-align: left; padding: .4rem .6rem; border: 1px solid #e2e2ee; vertical-align: top; }
  table.meta th { width: 8rem; background: #f7f7fc; }
  pre.code { background: #1a1a2e; color: #eaeaf5; padding: .8rem 1rem; border-radius: 6px; overflow-x: auto; font-size: .82rem; }
  .proof { background: #eef6ff; border-left: 3px solid #2f6feb; padding: .6rem 1rem; margin: .8rem 0; border-radius: 4px; }
  .proof-kind { font-weight: 700; margin: 0 0 .4rem; }
  .fix { background: #eefaf0; border-left: 3px solid #2e9e5b; padding: .6rem 1rem; margin: .8rem 0; border-radius: 4px; }
  .no-fix { color: #b0473e; font-style: italic; }
  .finding { border: 1px solid #e2e2ee; border-radius: 10px; padding: 1rem 1.2rem; margin: 1rem 0; }
  .appendix caption { text-align: left; font-style: italic; color: #666; }
  footer { margin-top: 3rem; color: #888; font-size: .8rem; border-top: 1px solid #e2e2ee; padding-top: 1rem; }
  a { color: #2f6feb; }
`;

/** Render the full HTML report as a self-contained string. */
export function renderReportHtml(report: Report): string {
  const findings =
    report.confirmedFindings.length > 0
      ? report.confirmedFindings.map((rf, i) => renderFinding(rf, i)).join("\n")
      : "<p>No confirmed findings. See the appendix for demoted candidates.</p>";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Montr Secure Report — ${escapeHtml(report.scanId)}</title>
  <style>${STYLE}</style>
</head>
<body>
  <h1>Montr Secure — Security Report</h1>
  <p>Scan <code>${escapeHtml(report.scanId)}</code> · generated ${escapeHtml(report.generatedAt)}</p>

  <h2>Executive Summary</h2>
  ${renderExecSummary(report)}

  <h2>Confirmed Findings</h2>
  ${findings}

  <h2>Fix Status</h2>
  ${renderFixStatus(report)}

  <h2>Appendix — Unconfirmed Candidates</h2>
  <p><em>Demoted for completeness; not part of the headline.</em></p>
  ${renderAppendix(report.unconfirmedAppendix)}

  <h2>Compliance Mapping</h2>
  ${renderCompliance(report.complianceMapping)}

  <h2>Cost &amp; Scope</h2>
  ${renderCostScope(report)}

  <footer>Generated by Montr Secure. Confirmed findings are headlined; breadth lives in the appendix. Auth/session/crypto/access-control fixes are always human-required.</footer>
</body>
</html>`;
}
