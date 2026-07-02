import {
  ReportSchema,
  Layer0OutputSchema,
  Layer1OutputSchema,
  Layer2OutputSchema,
  Layer3OutputSchema,
  Layer4OutputSchema,
  Layer5OutputSchema,
  complianceForCategory,
  type Report,
  type Layer0Output,
  type Layer1Output,
  type Layer2Output,
  type Layer3Output,
  type Layer4Output,
  type Layer5Output,
} from "@montr/contracts";
import { REPORT_ID, SCAN_ID, CLIENT_ID, FIXED_LATER } from "./ids.js";
import { mockAppMap } from "./appmap.js";
import {
  mockCandidateFindings,
  mockProbableFindings,
  mockConfirmedFindings,
  mockUnconfirmedFindings,
} from "./findings.js";
import { mockFixes, mockPullRequest } from "./fixes.js";
import { mockCostEstimate, mockCostRollup } from "./cost.js";
import { mockScan } from "./scan.js";

export const mockLayer0Output: Layer0Output = Layer0OutputSchema.parse({
  appMap: mockAppMap,
  scope: mockScan.scope,
  costEstimate: mockCostEstimate,
});

export const mockLayer1Output: Layer1Output = Layer1OutputSchema.parse({
  candidates: mockCandidateFindings,
});

export const mockLayer2Output: Layer2Output = Layer2OutputSchema.parse({
  probable: mockProbableFindings,
  demoted: [],
});

export const mockLayer3Output: Layer3Output = Layer3OutputSchema.parse({
  confirmed: mockConfirmedFindings,
  unconfirmed: mockUnconfirmedFindings,
});

export const mockLayer4Output: Layer4Output = Layer4OutputSchema.parse({
  fixes: mockFixes,
});

/** The full report model (§12) — headline is confirmed + prioritized. */
export const mockReport: Report = ReportSchema.parse({
  id: REPORT_ID,
  scanId: SCAN_ID,
  clientId: CLIENT_ID,
  generatedAt: FIXED_LATER,
  executiveSummary: {
    totalConfirmed: mockConfirmedFindings.length,
    confirmedBySeverity: { info: 0, low: 0, medium: 0, high: 1, critical: 1 },
    toolsConsolidated: ["semgrep", "gitleaks", "osv"],
  },
  confirmedFindings: mockConfirmedFindings.map((finding, i) => ({
    finding,
    fix: mockFixes[i],
    compliance: complianceForCategory(finding.category),
  })),
  fixStatus: {
    autoEligibleFixIds: mockFixes.map((f) => f.id),
    humanRequiredFixIds: [],
    pullRequests: [mockPullRequest],
  },
  unconfirmedAppendix: mockUnconfirmedFindings,
  complianceMapping: [complianceForCategory("sql_injection"), complianceForCategory("xss")],
  costAndScope: {
    scope: mockScan.scope,
    cost: mockCostRollup,
  },
});

export const mockLayer5Output: Layer5Output = Layer5OutputSchema.parse({
  report: mockReport,
  pullRequests: [mockPullRequest],
});
