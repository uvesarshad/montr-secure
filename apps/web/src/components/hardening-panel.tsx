"use client";

import * as React from "react";
import type { BlueTeamReport, HardeningCategory } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Badge } from "./ui/badge.js";
import { EmptyState } from "./ui/empty-state.js";
import { SeverityBadge, StatusChip } from "./chips.js";
import { AlertTriangleIcon, WrenchIcon } from "./icons.js";

const CATEGORY_LABEL: Record<HardeningCategory, string> = {
  security_headers: "Security headers",
  csp: "Content-Security-Policy",
  cookie_policy: "Cookie policy",
  rate_limits: "Rate limits",
  waf_rules: "WAF rules",
  network_policy: "Network policy",
  framework_configuration: "Framework configuration",
};

/**
 * B11 — renders B9's advisory hardening recommendations. `advisoryOnly` is a
 * structural, always-`true` field on the section — these are config/infra
 * suggestions, NEVER auto-applied diffs (unlike Layer 4 fixes), so the
 * banner below is load-bearing, not decorative.
 */
export function HardeningPanel({ hardening }: { hardening: BlueTeamReport["hardening"] }) {
  if (hardening.recommendations.length === 0) {
    return (
      <EmptyState
        icon={<WrenchIcon className="h-6 w-6" />}
        title="No hardening recommendations"
        description="Config/infra hardening guidance (security headers, CSP, cookie policy, rate limits, WAF rules, network policy) appears here when generated for this scan's repo checkout."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
        <AlertTriangleIcon className="mt-0.5 h-4 w-4 text-amber-300" />
        <div>
          <p className="font-medium text-amber-200">Advisory only</p>
          <p className="text-muted-foreground">
            These are config/infra recommendations, not code patches. They carry no diff and are
            never auto-applied — an operator or approver must implement them manually, distinct from
            Layer 4's auto-eligible/human-required fixes.
          </p>
        </div>
      </div>

      {hardening.recommendations.map((rec) => (
        <Card key={rec.id}>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={rec.severity} />
              <StatusChip tone="neutral">{CATEGORY_LABEL[rec.category]}</StatusChip>
              {rec.framework ? <StatusChip tone="info">{rec.framework}</StatusChip> : null}
            </div>
            <CardTitle className="text-sm font-semibold">{rec.title}</CardTitle>
            <p className="text-sm text-muted-foreground">{rec.gap}</p>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Recommendation
              </p>
              <pre className="max-h-56 overflow-auto rounded-md border border-border bg-background/70 p-3 font-mono text-xs leading-relaxed">
                {rec.recommendation}
              </pre>
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Rationale
              </p>
              <p className="text-sm text-muted-foreground">{rec.rationale}</p>
            </div>
            <div>
              <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Evidence
              </p>
              <div className="flex flex-wrap gap-1">
                {rec.evidence.map((e, i) => (
                  <Badge key={i} className="border-border bg-secondary font-mono text-[11px]">
                    {e}
                  </Badge>
                ))}
              </div>
            </div>
            {rec.relatedFindingIds.length > 0 ? (
              <div>
                <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Related findings
                </p>
                <div className="flex flex-wrap gap-1">
                  {rec.relatedFindingIds.map((id) => (
                    <code key={id} className="font-mono text-xs text-muted-foreground">
                      {id}
                    </code>
                  ))}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
