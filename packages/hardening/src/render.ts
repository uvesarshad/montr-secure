/**
 * Render a `HardeningRecommendation[]` list to Markdown. Standalone —
 * NOT wired into `packages/report/src/report-builder.ts` yet (B10's job,
 * per this task's brief). Grouped by category, in a fixed severity order
 * within each group so the highest-impact recommendation in a category
 * reads first.
 */
import type { HardeningCategory, HardeningRecommendation, Severity } from "@montr/contracts";

const CATEGORY_TITLES: Record<HardeningCategory, string> = {
  security_headers: "Security Headers",
  csp: "Content-Security-Policy",
  cookie_policy: "Cookie Policy",
  rate_limits: "Rate Limits",
  waf_rules: "WAF Rules",
  network_policy: "Network Policy",
  framework_configuration: "Framework Configuration",
};

const CATEGORY_ORDER: HardeningCategory[] = [
  "security_headers",
  "csp",
  "cookie_policy",
  "rate_limits",
  "waf_rules",
  "network_policy",
  "framework_configuration",
];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Render the full recommendation set to Markdown. Returns an explicit
 * "no gaps detected" note (never an empty/blank section) when `recommendations`
 * is empty, so a clean report distinguishes "we checked and found nothing" from
 * "this section was never generated".
 */
export function renderHardeningRecommendationsMarkdown(
  recommendations: readonly HardeningRecommendation[],
): string {
  const lines: string[] = [
    "## Hardening Recommendations",
    "",
    "_Advisory-only blue-team configuration guidance — security headers, CSP, cookie policy, " +
      "rate limits, WAF rules, network policy, and framework configuration. These are config/infra " +
      "recommendations, not code patches, and are never auto-applied._",
    "",
  ];

  if (recommendations.length === 0) {
    lines.push("No hardening gaps were detected against the categories checked.");
    return lines.join("\n");
  }

  for (const category of CATEGORY_ORDER) {
    const items = recommendations
      .filter((r) => r.category === category)
      .slice()
      .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    if (items.length === 0) continue;

    lines.push(`### ${CATEGORY_TITLES[category]}`, "");
    for (const r of items) {
      lines.push(`#### ${r.title} (${r.severity})`, "");
      lines.push(`**Gap:** ${r.gap}`, "");
      lines.push(`**Recommendation:**`, "", "```", r.recommendation, "```", "");
      lines.push(`**Rationale:** ${r.rationale}`, "");
      lines.push(`**Evidence:**`);
      for (const e of r.evidence) lines.push(`- ${e}`);
      if (r.relatedFindingIds.length > 0) {
        lines.push("", `**Related findings:** ${r.relatedFindingIds.join(", ")}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
