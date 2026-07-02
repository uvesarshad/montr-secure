/**
 * SARIF 2.1.0 exporter (§13, DECIDE-5: SARIF ships first, broadest). Maps each
 * CONFIRMED finding to a SARIF result so the report drops into any SARIF-aware
 * code-scanning UI / evidence pipeline. Output is validated against the frozen
 * {@link SarifLogSchema} before it leaves this module.
 */
import {
  SarifLogSchema,
  type ConfirmedFinding,
  type Report,
  type SarifLog,
  type SarifResult,
  type Severity,
} from "@montr/contracts";

export const SARIF_TOOL_NAME = "Montr Secure";
export const SARIF_INFO_URI = "https://montr.security/secure";

/** SARIF severity levels, per confirmed-finding severity. */
const SARIF_LEVEL: Record<Severity, SarifResult["level"]> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

function toResult(finding: ConfirmedFinding): SarifResult {
  const line = finding.location.line;
  return {
    ruleId: finding.category,
    level: SARIF_LEVEL[finding.severity],
    message: { text: `${finding.title} — ${finding.impact}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: finding.location.file },
          // Contract requires a positive startLine; omit the region for line 0.
          ...(line > 0 ? { region: { startLine: line } } : {}),
        },
      },
    ],
  };
}

/** Build a validated SARIF log from a report (one run, one Montr driver). */
export function toSarif(report: Report): SarifLog {
  const confirmed = report.confirmedFindings.map((rf) => rf.finding);
  const ruleIds = [...new Set(confirmed.map((f) => f.category))];
  return SarifLogSchema.parse({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: SARIF_TOOL_NAME,
            informationUri: SARIF_INFO_URI,
            rules: ruleIds.map((id) => ({ id })),
          },
        },
        results: confirmed.map(toResult),
      },
    ],
  });
}

/** SARIF JSON string (pretty-printed). */
export function renderReportSarif(report: Report): string {
  return JSON.stringify(toSarif(report), null, 2);
}
