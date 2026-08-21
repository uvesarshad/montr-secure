/**
 * SARIF 2.1.0 exporter (§13, DECIDE-5: SARIF ships first, broadest). Maps each
 * CONFIRMED finding to a SARIF result so the report drops into any SARIF-aware
 * code-scanning UI (GitHub code scanning, Azure DevOps, DefectDojo, …).
 *
 * Rich metadata for downstream tools:
 *   - `driver.rules[]` — one reporting descriptor per finding category, with a
 *     name, short/full description, `helpUri`, CWE + OWASP + MITRE ATT&CK
 *     (B2, via @montr/contracts's `mitreTechniqueIdsForCategory`) `tags`, and a
 *     `security-severity` (GitHub reads this to set the alert severity).
 *   - `results[]` — `ruleId` + `ruleIndex`, level, message, location, and
 *     `partialFingerprints` (a stable, line-drift-resistant identity so the same
 *     finding is not re-alerted after unrelated edits), plus CWE/OWASP/MITRE properties.
 *
 * The rich object is a SUPERSET of the frozen {@link SarifLogSchema}. We
 * `SarifLogSchema.parse(...)` it purely to ASSERT the core 2.1.0 shape is valid
 * (Zod strips the extra rich keys from its result — so we assert on the parse but
 * SERIALIZE the rich object, keeping both contract-conformance and rich output).
 */
import { createHash } from "node:crypto";
import {
  CATEGORY_TAXONOMY,
  OWASP_TITLES,
  SarifLogSchema,
  complianceForCategory,
  mitreTechniqueIdsForCategory,
  type Category,
  type ConfirmedFinding,
  type Report,
  type Severity,
} from "@montr/contracts";

export const SARIF_TOOL_NAME = "Montr Secure";
export const SARIF_INFO_URI = "https://montr.security/secure";
export const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";
/** Namespace for partial fingerprints emitted by this exporter. */
export const SARIF_FINGERPRINT_KEY = "montr/v1";

type SarifLevel = "none" | "note" | "warning" | "error";

/** SARIF severity levels, per confirmed-finding severity. */
const SARIF_LEVEL: Record<Severity, SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

/** GitHub code-scanning `security-severity` (decimal string) per severity. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.1",
  medium: "5.5",
  low: "3.1",
  info: "0.0",
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

interface RichSarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: {
    tags: string[];
    "security-severity": string;
    cwe: string[];
    owasp: string;
    /** MITRE ATT&CK/ATLAS technique ids this category maps to (B2). Also carried in `tags`. */
    mitre: string[];
  };
}

interface RichSarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  partialFingerprints: Record<string, string>;
  properties: {
    category: string;
    cwe: string[];
    owasp: string;
    owaspTitle: string;
    severity: string;
    exposure: string;
    proofType: string;
    /** MITRE ATT&CK/ATLAS technique ids for this finding's category (B2). */
    mitre: string[];
  };
}

/** A superset of {@link SarifLog} carrying the rich rule/result metadata. */
export interface RichSarifLog {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        rules: RichSarifRule[];
      };
    };
    results: RichSarifResult[];
  }>;
}

/** Stable, line-drift-resistant fingerprint (category + file + symbol/title). */
function fingerprint(finding: ConfirmedFinding): string {
  const anchor = finding.location.symbol ?? finding.title;
  return createHash("sha256")
    .update(`${finding.category}|${finding.location.file}|${anchor}`, "utf8")
    .digest("hex");
}

function helpUri(category: Category): string {
  const cwe = CATEGORY_TAXONOMY[category].cwe[0];
  if (cwe) {
    const num = cwe.replace("CWE-", "");
    return `https://cwe.mitre.org/data/definitions/${num}.html`;
  }
  return "https://owasp.org/www-project-top-ten/";
}

/** `external/attack/<lowercased-id>` — mirrors the existing `external/cwe/<lowercased-id>` tag shape. */
function mitreTag(id: string): string {
  return `external/attack/${id.toLowerCase()}`;
}

function ruleTags(category: Category): string[] {
  const entry = CATEGORY_TAXONOMY[category];
  const cweTags = entry.cwe.map((c) => `external/cwe/${c.toLowerCase()}`);
  const mitreTags = mitreTechniqueIdsForCategory(category).map(mitreTag);
  return ["security", category, `OWASP-${entry.owasp}`, ...cweTags, ...mitreTags];
}

function buildRule(category: Category, maxSeverity: Severity): RichSarifRule {
  const entry = CATEGORY_TAXONOMY[category];
  return {
    id: category,
    name: entry.title,
    shortDescription: { text: entry.title },
    fullDescription: {
      text: `${entry.title} — maps to ${entry.owasp} (${OWASP_TITLES[entry.owasp]})${entry.cwe.length > 0 ? ` and ${entry.cwe.join(", ")}` : ""}.`,
    },
    helpUri: helpUri(category),
    properties: {
      tags: ruleTags(category),
      "security-severity": SECURITY_SEVERITY[maxSeverity],
      cwe: [...entry.cwe],
      owasp: entry.owasp,
      mitre: mitreTechniqueIdsForCategory(category),
    },
  };
}

function buildResult(finding: ConfirmedFinding, ruleIndex: number): RichSarifResult {
  const line = finding.location.line;
  const compliance = complianceForCategory(finding.category);
  const cwe = finding.cwe.length > 0 ? finding.cwe : compliance.cwe;
  return {
    ruleId: finding.category,
    ruleIndex,
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
    partialFingerprints: { [SARIF_FINGERPRINT_KEY]: fingerprint(finding) },
    properties: {
      category: finding.category,
      cwe: [...cwe],
      owasp: finding.owasp ?? compliance.owasp,
      owaspTitle: compliance.owaspTitle,
      severity: finding.severity,
      exposure: finding.exposure,
      proofType: finding.proofType,
      mitre: mitreTechniqueIdsForCategory(finding.category),
    },
  };
}

/** Build a rich, schema-conformant SARIF log from a report (one run, one driver). */
export function toSarif(report: Report): RichSarifLog {
  const confirmed = report.confirmedFindings.map((rf) => rf.finding);

  // Distinct categories in first-appearance order, each with its max severity.
  const order: Category[] = [];
  const maxSeverity = new Map<Category, Severity>();
  for (const f of confirmed) {
    if (!maxSeverity.has(f.category)) order.push(f.category);
    const cur = maxSeverity.get(f.category);
    if (!cur || SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur]) {
      maxSeverity.set(f.category, f.severity);
    }
  }
  const ruleIndex = new Map<Category, number>(order.map((c, i) => [c, i]));
  const rules = order.map((c) => buildRule(c, maxSeverity.get(c)!));
  const results = confirmed.map((f) => buildResult(f, ruleIndex.get(f.category)!));

  const log: RichSarifLog = {
    version: "2.1.0",
    $schema: SARIF_SCHEMA_URI,
    runs: [
      {
        tool: {
          driver: {
            name: SARIF_TOOL_NAME,
            informationUri: SARIF_INFO_URI,
            rules,
          },
        },
        results,
      },
    ],
  };

  // Assert the core SARIF 2.1.0 shape (rich keys are stripped by parse, not
  // rejected). Throws if a required field is missing/mistyped — then serialize
  // the RICH object, not the stripped parse result.
  SarifLogSchema.parse(log);
  return log;
}

/** SARIF JSON string (pretty-printed), including the rich rule/result metadata. */
export function renderReportSarif(report: Report): string {
  return JSON.stringify(toSarif(report), null, 2);
}
