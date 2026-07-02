/**
 * @montr/fix — Layer 4: for each CONFIRMED finding, a diff-ready patch, a
 * plain-English rationale, and a proof-of-fix test that fails pre-patch and
 * passes post-patch. Then RISK-CLASSIFY the fix.
 *
 * ⛔ The risk classifier is a SAFETY control (§11, golden rules #3/#4):
 * auth/session/crypto/access-control OR wide blast radius ⇒ human-required, and
 * uncertainty always resolves to human-required. The class decision is
 * deterministic/rule-first and is NEVER delegated to the LLM — the model only
 * proposes a patch, which is accepted only if it passes deterministic validation.
 */
export {
  classifyFixRisk,
  classifyConfirmedFindingRisk,
  deriveRiskSignals,
  ALWAYS_HUMAN_REQUIRED_CATEGORIES,
  AUTO_ELIGIBLE_CATEGORIES,
  MAX_AUTO_CHANGED_LINES,
  type ClassifyRiskInput,
  type ClassifyOptions,
  type RiskEvidence,
  type RiskSignals,
  type RiskDecision,
} from "./risk.js";

export {
  FIX_STRATEGIES,
  pickStrategy,
  advisoryProofTestCode,
  proofTestPath,
  type FixStrategy,
} from "./strategies.js";

export {
  buildUnifiedDiff,
  validatePatch,
  countChangedLines,
  type PatchValidation,
} from "./patch.js";

export { createFsSourceReader, createMapSourceReader, type SourceReader } from "./source.js";

export { generateFixes, type GenerateFixesInput, type FixGenerationContext } from "./generate.js";
