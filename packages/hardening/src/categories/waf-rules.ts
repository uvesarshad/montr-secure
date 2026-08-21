/**
 * WAF rules (B9). Maps a confirmed finding's category to a real,
 * well-formed defense-in-depth WAF rule: an AWS WAF managed rule GROUP name,
 * a Cloudflare WAF managed ruleset name, and/or an OWASP ModSecurity CRS
 * rule-file reference. Every name below is a genuine, currently-shipping
 * rule identifier from that vendor/project's own docs — never a fabricated
 * placeholder. Categories with no clean WAF-layer analog (e.g.
 * `broken_access_control`, `idor` — application-logic bugs a network WAF
 * cannot meaningfully detect) are deliberately absent from the map, so this
 * generator stays silent for them rather than inventing a rule that would
 * not actually help.
 *
 * One recommendation per CATEGORY present in `confirmedFindings` (not one
 * per finding) — grouping avoids spamming the report with N duplicate WAF
 * recommendations for N findings of the same category, while
 * `relatedFindingIds` still names every finding it defends.
 */
import type { Category, ConfirmedFinding } from "@montr/contracts";
import type { RecommendationDraft } from "../types.js";

interface WafMapEntry {
  title: string;
  recommendation: string;
  rationale: string;
}

/**
 * Honest hedging: categories marked with a trailing "(closest applicable)"
 * note do not have a CRS rule FILE dedicated to them one-to-one — the CRS
 * group named is the nearest real coverage, not an exact match, and the
 * recommendation text says so rather than implying precision that isn't there.
 */
const WAF_MAP: Partial<Record<Category, WafMapEntry>> = {
  sql_injection: {
    title: "Add SQL-injection WAF coverage",
    recommendation:
      'AWS WAF: attach the AWSManagedRulesSQLiRuleSet managed rule group. Cloudflare: enable the OWASP Core Ruleset with the "SQLi" tag active. ModSecurity: enable REQUEST-942-APPLICATION-ATTACK-SQLI from the OWASP Core Rule Set.',
    rationale:
      "A confirmed SQL injection is a code-level bug; a WAF rule is defense-in-depth that blocks exploitation attempts while the fix ships/rolls out.",
  },
  nosql_injection: {
    title: "Add NoSQL-injection WAF coverage",
    recommendation:
      "AWS WAF: attach AWSManagedRulesSQLiRuleSet (covers common NoSQL operator-injection payloads) plus AWSManagedRulesKnownBadInputsRuleSet. Cloudflare: enable the OWASP Core Ruleset. ModSecurity: enable REQUEST-942-APPLICATION-ATTACK-SQLI (covers $ne/$gt-style operator injection patterns as SQLi-adjacent).",
    rationale:
      "NoSQL operator injection shares payload shape with SQLi enough that the SQLi-focused managed rule groups catch a meaningful share of attempts.",
  },
  xss: {
    title: "Add XSS WAF coverage",
    recommendation:
      'AWS WAF: attach the AWSManagedRulesCommonRuleSet managed rule group (includes its CrossSiteScripting_* rules). Cloudflare: enable the OWASP Core Ruleset with the "XSS" tag active. ModSecurity: enable REQUEST-941-APPLICATION-ATTACK-XSS from the OWASP Core Rule Set.',
    rationale:
      "A WAF-level XSS filter blocks common reflected-payload shapes at the edge, ahead of app-level output encoding fixes.",
  },
  ssrf: {
    title: "Add SSRF WAF coverage (pair with network egress restriction)",
    recommendation:
      "AWS WAF: attach AWSManagedRulesKnownBadInputsRuleSet (flags internal/metadata-IP request patterns). Cloudflare: enable the OWASP Core Ruleset plus a custom WAF rule blocking outbound-referencing request bodies containing `169.254.169.254` or `metadata.google.internal`. ModSecurity: enable REQUEST-931-APPLICATION-ATTACK-RFI (closest applicable — SSRF is not a dedicated CRS category, RFI/external-resource-inclusion rules are the nearest real coverage). A WAF alone cannot fully mitigate SSRF — see the network_policy recommendation for real egress restriction.",
    rationale:
      "SSRF is fundamentally a network-reachability problem; the WAF rule above is a partial, request-pattern-based mitigation, not a substitute for egress restriction.",
  },
  command_injection: {
    title: "Add command-injection WAF coverage",
    recommendation:
      "AWS WAF: attach AWSManagedRulesUnixRuleSet (or AWSManagedRulesKnownBadInputsRuleSet on non-Unix targets). Cloudflare: enable the OWASP Core Ruleset. ModSecurity: enable REQUEST-932-APPLICATION-ATTACK-RCE from the OWASP Core Rule Set.",
    rationale:
      "Blocks common shell-metacharacter and known-payload command-injection patterns at the edge.",
  },
  path_traversal: {
    title: "Add path-traversal WAF coverage",
    recommendation:
      "AWS WAF: attach AWSManagedRulesKnownBadInputsRuleSet (flags `../`/encoded-traversal patterns). Cloudflare: enable the OWASP Core Ruleset. ModSecurity: enable REQUEST-930-APPLICATION-ATTACK-LFI from the OWASP Core Rule Set.",
    rationale:
      "Blocks encoded and raw directory-traversal payload shapes ahead of an app-level path-normalization fix.",
  },
  xxe: {
    title: "Add XXE-adjacent WAF coverage (app-layer fix is primary)",
    recommendation:
      "ModSecurity: enable REQUEST-921-PROTOCOL-ATTACK (closest applicable — CRS has no XXE-dedicated rule file; this group's XML/protocol-anomaly rules are the nearest real coverage). AWS WAF: attach AWSManagedRulesKnownBadInputsRuleSet. The primary control is disabling external-entity resolution in the XML parser itself — the WAF rule here is defense-in-depth only.",
    rationale:
      "XXE is best mitigated at the parser-configuration level; WAF coverage for it is inherently partial.",
  },
  insecure_deserialization: {
    title: "Add insecure-deserialization WAF coverage",
    recommendation:
      "AWS WAF: attach AWSManagedRulesKnownBadInputsRuleSet. ModSecurity: enable REQUEST-934-APPLICATION-ATTACK-NODEJS (Node.js targets) or REQUEST-944-APPLICATION-ATTACK-JAVA (Java targets) from the OWASP Core Rule Set — pick the group matching the target's stack.",
    rationale:
      "These rule groups flag known gadget-chain and prototype-pollution payload signatures at the edge.",
  },
  open_redirect: {
    title: "Add open-redirect WAF coverage",
    recommendation:
      "ModSecurity: enable REQUEST-931-APPLICATION-ATTACK-RFI (closest applicable — open redirect is not a dedicated CRS category; its external-URL-reference rules are the nearest real coverage). AWS WAF: attach AWSManagedRulesKnownBadInputsRuleSet.",
    rationale:
      "Partial mitigation only — the durable fix is an app-level allowlist of redirect targets.",
  },
  broken_authentication: {
    title: "Add credential-stuffing / account-takeover WAF coverage",
    recommendation:
      "AWS WAF: attach AWSManagedRulesATPRuleSet (Account Takeover Prevention) plus AWSManagedRulesAnonymousIpList. Cloudflare: enable Bot Management / the Cloudflare Managed Ruleset with the authentication-endpoint rate-limiting rules active.",
    rationale:
      "Broken-authentication findings are frequently paired with credential-stuffing exposure; these managed groups target that abuse pattern specifically.",
  },
};

export function detectWafRuleRecommendations(
  confirmedFindings: readonly ConfirmedFinding[],
): RecommendationDraft[] {
  const byCategory = new Map<Category, ConfirmedFinding[]>();
  for (const f of confirmedFindings) {
    const entry = WAF_MAP[f.category];
    if (!entry) continue;
    const list = byCategory.get(f.category) ?? [];
    list.push(f);
    byCategory.set(f.category, list);
  }

  const drafts: RecommendationDraft[] = [];
  for (const [category, findings] of byCategory) {
    const entry = WAF_MAP[category];
    if (!entry) continue;
    drafts.push({
      category: "waf_rules",
      severity: findings.some((f) => f.severity === "critical") ? "high" : "medium",
      title: entry.title,
      gap: `${findings.length} confirmed "${category}" finding(s) with no corresponding WAF rule detected in scope.`,
      recommendation: entry.recommendation,
      rationale: entry.rationale,
      evidence: findings.map((f) => `${f.title} (${f.location.file}:${f.location.line})`),
      relatedFindingIds: findings.map((f) => f.id),
    });
  }
  return drafts;
}
