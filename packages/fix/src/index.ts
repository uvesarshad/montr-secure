/**
 * @montr/fix — Layer 4: for each CONFIRMED finding, a diff-ready patch, a
 * plain-English rationale, and a proof-of-fix test. Then RISK-CLASSIFY the fix.
 *
 * ⛔ The risk classifier is a SAFETY control (§11, golden rules #3/#4):
 * auth/session/crypto/access-control OR wide blast radius ⇒ human-required, and
 * uncertainty always resolves to human-required. Implementation: WS-I.
 */
import {
  NotImplementedError,
  type Category,
  type ConfirmedFinding,
  type Layer4Output,
  type RiskClass,
} from "@montr/contracts";

/** Categories that are ALWAYS human-required regardless of the auto-fix toggle. */
export const ALWAYS_HUMAN_REQUIRED_CATEGORIES: readonly Category[] = [
  "broken_access_control",
  "broken_authentication",
  "weak_crypto",
  "idor",
  "csrf",
  "sensitive_data_exposure",
  "insecure_deserialization",
];

/** Mechanical, low-blast-radius categories eligible for auto-fix PRs. */
export const AUTO_ELIGIBLE_CATEGORIES: readonly Category[] = [
  "sql_injection",
  "nosql_injection",
  "xss",
  "permissive_cors",
  "insecure_cookie",
  "missing_security_headers",
  "vulnerable_dependency",
  "open_redirect",
];

export interface ClassifyRiskInput {
  category: Category;
  /** Set true if the patch touches auth/session/crypto/access-control code. */
  touchesAuthOrCrypto?: boolean;
  /** Set true for wide blast radius (many files / shared module). */
  wideBlastRadius?: boolean;
  /** Set true if the classifier is uncertain (fail-safe → human-required). */
  uncertain?: boolean;
}

/**
 * Deterministic risk classification. Fail-safe: anything not clearly
 * auto-eligible resolves to `human-required` (golden rule #4).
 */
export function classifyFixRisk(input: ClassifyRiskInput): RiskClass {
  if (input.touchesAuthOrCrypto) return "human-required";
  if (input.wideBlastRadius) return "human-required";
  if (input.uncertain) return "human-required";
  if (ALWAYS_HUMAN_REQUIRED_CATEGORIES.includes(input.category)) return "human-required";
  if (AUTO_ELIGIBLE_CATEGORIES.includes(input.category)) return "auto-eligible";
  return "human-required";
}

export interface GenerateFixesInput {
  clientId: string;
  scanId: string;
  confirmed: ConfirmedFinding[];
  /** Categories the deployment forces to human review (from @montr/config). */
  humanRequiredCategoriesAlways?: Category[];
}

export async function generateFixes(_input: GenerateFixesInput): Promise<Layer4Output> {
  throw new NotImplementedError("generateFixes — WS-I");
}
