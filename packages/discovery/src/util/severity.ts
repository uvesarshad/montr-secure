/**
 * Mapping helpers: tool-native severity strings and CWE ids → the frozen
 * @montr/contracts enums, plus a rule-id → Category heuristic used when a
 * scanner does not tag CWE metadata. Deterministic; no I/O.
 */
import { CATEGORY_TAXONOMY, type Category, type CweId, type Severity } from "@montr/contracts";

/** Reverse index: CWE id → the first normalized Category that lists it. */
const CWE_TO_CATEGORY: Record<string, Category> = (() => {
  const m: Record<string, Category> = {};
  for (const key of Object.keys(CATEGORY_TAXONOMY) as Category[]) {
    for (const cwe of CATEGORY_TAXONOMY[key].cwe) {
      if (!(cwe in m)) m[cwe] = key;
    }
  }
  return m;
})();

/** Normalize a CWE reference ("CWE-89", "cwe-89: ...", 89) to canonical "CWE-89". */
export function normalizeCwe(raw: string | number | undefined | null): CweId | undefined {
  if (raw === undefined || raw === null) return undefined;
  const m = String(raw).match(/(\d{1,7})/);
  if (!m || !m[1]) return undefined;
  return `CWE-${m[1]}` as CweId;
}

/** Map a CWE reference to a normalized Category, if known. */
export function categoryForCwe(raw: string | number | undefined | null): Category | undefined {
  const cwe = normalizeCwe(raw);
  if (!cwe) return undefined;
  return CWE_TO_CATEGORY[cwe];
}

/** The taxonomy CWE list for a Category (used when the tool omits CWE metadata). */
export function cweForCategory(category: Category): CweId[] {
  return [...CATEGORY_TAXONOMY[category].cwe];
}

/** Map a Semgrep/tool severity token to the contract Severity scale. */
export function severityFromTool(sev: string | undefined | null): Severity {
  switch (String(sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "ERROR":
    case "HIGH":
      return "high";
    case "WARNING":
    case "MEDIUM":
    case "MODERATE":
      return "medium";
    case "INFO":
    case "LOW":
      return "low";
    case "NONE":
      return "info";
    default:
      return "medium";
  }
}

/** Ordered rule-id substring hints → Category (first match wins). */
const RULE_HINTS: ReadonlyArray<readonly [RegExp, Category]> = [
  [/sqli|sql-inject|sql_inject|queryraw|raw-query|raw_query/i, "sql_injection"],
  [/nosql|mongo-inject/i, "nosql_injection"],
  [/command-inject|command_inject|child_process|os-command|shell-inject/i, "command_injection"],
  [/dangerouslysetinnerhtml|reflected-xss|stored-xss|\bxss\b|cross-site-scripting/i, "xss"],
  [/\bssrf\b|server-side-request/i, "ssrf"],
  [/path-traversal|path_traversal|directory-traversal|zip-slip/i, "path_traversal"],
  [/deserial|insecure-deserial/i, "insecure_deserialization"],
  [/hardcoded|hard-coded|secret|api-key|api_key|credential/i, "hardcoded_secret"],
  [/permissive-cors|cors-misconfig|\bcors\b/i, "permissive_cors"],
  [/security-header|missing-header|helmet/i, "missing_security_headers"],
  [/insecure-cookie|cookie-.*(httponly|secure|samesite)|missing-cookie/i, "insecure_cookie"],
  [/weak-crypto|weak-hash|\bmd5\b|\bsha1\b|insecure-cipher|weak-cipher|\becb\b/i, "weak_crypto"],
  [/open-redirect|open_redirect|unvalidated-redirect/i, "open_redirect"],
  [/\bxxe\b|xml-external/i, "xxe"],
  [/\bcsrf\b|cross-site-request/i, "csrf"],
  [/broken-access|missing-authz|authorization/i, "broken_access_control"],
  [/broken-auth|auth-bypass|missing-authn/i, "broken_authentication"],
  [/\bidor\b|insecure-direct-object/i, "idor"],
  [/mass-assign|mass_assign/i, "mass_assignment"],
  [/rate-limit|rate_limit/i, "rate_limit_missing"],
  [/sensitive-data|data-exposure|pii-leak/i, "sensitive_data_exposure"],
  [/logging|log-inject/i, "insufficient_logging"],
  // E11: a scanner/tool that tags its own rule id with AI/LLM-prompt vocabulary.
  [/prompt-inject|prompt_inject|llm-inject|jailbreak/i, "prompt_injection"],
  // E16: Semgrep's Dockerfile/Kubernetes/Terraform registry packs use their
  // own rule-id vocabulary; map the common ones onto the closest existing
  // category before falling back to "other". Order matters — more specific
  // patterns (secret/crypto/access) are checked ahead of the generic
  // "insecure_configuration" catch-alls in this same list.
  [/unencrypted|missing-encryption|no-encryption/i, "weak_crypto"],
  [
    /security-group|iam-.*(wildcard|permissive|policy)|allow-all|0\.0\.0\.0/i,
    "broken_access_control",
  ],
  [
    /missing-user|run(s|ning)?-as-root|privileged|host-network|host-pid|hostnetwork|hostpid|missing-resource|unpinned|latest-tag|no-tag|add-instead-of-copy/i,
    "insecure_configuration",
  ],
];

/** Best-effort Category inference from a scanner rule id. */
export function categoryFromRuleId(ruleId: string): Category | undefined {
  for (const [re, category] of RULE_HINTS) {
    if (re.test(ruleId)) return category;
  }
  return undefined;
}
