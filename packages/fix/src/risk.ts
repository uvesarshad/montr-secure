/**
 * ⛔ DETERMINISTIC risk classification — a SAFETY control, not a convenience
 * (PRD §7 L4, §11; golden rules #3/#4). The class decision is RULE-FIRST and
 * never delegated to the LLM: the model may propose a patch, but whether that
 * patch may be auto-applied is decided here, by rules.
 *
 * Hard rules:
 *   - auth / session / crypto / access-control  ⇒ `human-required` (always).
 *   - wide blast radius                          ⇒ `human-required`.
 *   - ANY uncertainty                            ⇒ `human-required` (fail-safe).
 * Only mechanical, low-blast-radius categories with no auth/crypto touch and a
 * cleanly-validated patch are ever `auto-eligible`.
 */
import type { Category, ConfirmedFinding, RiskClass } from "@montr/contracts";

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

/**
 * Path segments/filenames that indicate auth/session/crypto/access-control code.
 * Deliberately broad — over-escalation to human review is the fail-safe direction.
 */
const AUTH_PATH_RE =
  /(^|[/._-])(auth|authn|authz|session|login|logout|signin|signup|oauth|oidc|saml|jwt|password|passwd|credential|rbac|acl|permission|middleware|guard)([/._-]|$)/i;

/**
 * APIs in a patch body that indicate the change touches auth/session/crypto.
 * Note: generic cookie-setting is intentionally EXCLUDED so that mechanical
 * cookie-flag fixes on non-session cookies can stay auto-eligible.
 */
const AUTH_CRYPTO_API_RE =
  /\b(crypto|createcipher(?:iv)?|createdecipher(?:iv)?|createhash|createhmac|randombytes|pbkdf2|scrypt|bcrypt|argon2|jsonwebtoken|passport|next-auth|getserversession|usesession|hashpassword|comparepassword|setpassword|signtoken|verifytoken)\b|\bjwt\.|\.sign\(|\.verify\(|\bsession\.|\breq\.session\b/i;

/** Shared/broadly-imported modules → a change here has wide blast radius. */
const SHARED_MODULE_RE = /(^|\/)(shared|common|core|middleware)(\/|\.)/i;

/** A patch changing more than this many lines is treated as wide blast radius. */
export const MAX_AUTO_CHANGED_LINES = 40;

export interface RiskEvidence {
  /** The unified-diff patch (empty string for an advisory / no-patch fix). */
  patch: string;
  /** Repo-relative files the patch changes (at least the finding's file). */
  changedFiles: string[];
  /** Count of +/- lines in the patch. */
  changedLines: number;
  /** True when no cleanly-validated mechanical fix was produced (advisory). */
  uncertain: boolean;
}

export interface RiskSignals {
  touchesAuthOrCrypto: boolean;
  wideBlastRadius: boolean;
  uncertain: boolean;
}

export interface RiskDecision {
  riskClass: RiskClass;
  /** Human-readable, audit-ready explanation of the deciding rule. */
  rationale: string;
  signals: RiskSignals;
}

export interface ClassifyOptions {
  /** Extra categories a deployment forces to human review (from @montr/config). */
  alwaysHumanCategories?: readonly Category[];
}

/** Derive the deterministic risk signals for a confirmed finding + its patch. */
export function deriveRiskSignals(finding: ConfirmedFinding, evidence: RiskEvidence): RiskSignals {
  const files = evidence.changedFiles.length > 0 ? evidence.changedFiles : [finding.location.file];

  const pathTouchesAuth = files.some((f) => AUTH_PATH_RE.test(f));
  const patchTouchesAuth = evidence.patch.length > 0 && AUTH_CRYPTO_API_RE.test(evidence.patch);
  const touchesAuthOrCrypto = pathTouchesAuth || patchTouchesAuth;

  const wideBlastRadius =
    files.length > 1 ||
    evidence.changedLines > MAX_AUTO_CHANGED_LINES ||
    files.some((f) => SHARED_MODULE_RE.test(f));

  return { touchesAuthOrCrypto, wideBlastRadius, uncertain: evidence.uncertain };
}

/**
 * Classify a confirmed finding's fix. Deterministic + rule-first, with an
 * audit-ready rationale. Mirrors {@link classifyFixRisk}'s precedence so the
 * rationale always names the rule that actually decided the class.
 */
export function classifyConfirmedFindingRisk(
  finding: ConfirmedFinding,
  evidence: RiskEvidence,
  options: ClassifyOptions = {},
): RiskDecision {
  const category = finding.category;

  // Deployment policy override (config-driven) — force human review.
  if (options.alwaysHumanCategories?.includes(category)) {
    const signals = deriveRiskSignals(finding, evidence);
    return {
      riskClass: "human-required",
      rationale: `Deployment policy forces category "${category}" to human review.`,
      signals: { ...signals, uncertain: true },
    };
  }

  const signals = deriveRiskSignals(finding, evidence);
  const riskClass = classifyFixRisk({ category, ...signals });

  let rationale: string;
  if (signals.touchesAuthOrCrypto) {
    rationale =
      "Patch touches auth/session/crypto/access-control code — human-required (hard rule §11).";
  } else if (signals.wideBlastRadius) {
    const files =
      evidence.changedFiles.length > 0 ? evidence.changedFiles : [finding.location.file];
    rationale = `Wide blast radius (${files.length} file(s), ${evidence.changedLines} changed line(s)) — human-required.`;
  } else if (signals.uncertain) {
    rationale =
      "Classifier uncertain (no cleanly-validated mechanical fix) — fail-safe to human review.";
  } else if (ALWAYS_HUMAN_REQUIRED_CATEGORIES.includes(category)) {
    rationale = `Category "${category}" always requires human review (auth/crypto/access-control hard rule §11).`;
  } else if (AUTO_ELIGIBLE_CATEGORIES.includes(category)) {
    rationale = `Mechanical, low-blast-radius "${category}" fix with a cleanly-validated patch — auto-eligible.`;
  } else {
    rationale = `Category "${category}" is not on the auto-eligible allowlist — fail-safe to human review.`;
  }

  return { riskClass, rationale, signals };
}
