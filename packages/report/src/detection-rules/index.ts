/**
 * @montr/report/detection-rules — B3 (Sigma/OTel/SIEM detection-rule
 * generation) + B4 (the "what this looks like in your logs" narrative) for
 * confirmed findings. See generate.ts's header for the full picture: pure
 * generation vs. the `StateStore`-backed persistence wrapper, and how
 * `generateDetectionRules` is wired into report-builder.ts's
 * buildBlueTeamReport.
 */
export {
  generateDetectionRules,
  persistDetectionRules,
  type GenerateDetectionRulesDeps,
} from "./generate.js";
export {
  buildRuleContext,
  CATEGORY_MARKERS,
  type RuleContext,
  type RuleContextKind,
} from "./context.js";
export { buildSigmaRule } from "./sigma.js";
export { buildOtelQuery } from "./otel.js";
export { buildSiemQuery } from "./siem.js";
export { buildLogSignature } from "./narrative.js";
export { resolveRoute } from "./route.js";
export { deterministicUuid } from "./id.js";

// Suggested-enhancement follow-up (2026-09-12 red/blue agentic-posture
// audit): pushing generated rules to a real SOC tool, not just downloading
// them. See push/types.ts for the full design rationale (one real adapter —
// Splunk HEC — plus honest NotImplementedError stubs for Elastic/Sentinel).
export * from "./push/index.js";
