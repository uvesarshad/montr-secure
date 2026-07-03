import * as React from "react";
import type { ExecutiveSummary, Severity } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Badge } from "./ui/badge.js";
import { SeverityBadge, StatusChip } from "./chips.js";
import { SEVERITY_ORDER } from "../lib/format.js";

/**
 * Executive summary (§12.1). ⛔ The headline is CONFIRMED + prioritized findings,
 * broken down by severity — NEVER a raw candidate count. Breadth lives in the
 * unconfirmed appendix. Also surfaces the posture delta vs the last scan and the
 * prior point tools consolidated into this one report.
 */
export function ExecSummary({
  summary,
  unconfirmedCount,
}: {
  summary: ExecutiveSummary;
  unconfirmedCount: number;
}) {
  const severities = (Object.keys(SEVERITY_ORDER) as Severity[])
    .sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a])
    .map((sev) => ({ sev, count: summary.confirmedBySeverity[sev] ?? 0 }))
    .filter((s) => s.count > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Executive summary</CardTitle>
        <p className="text-sm text-muted-foreground">
          Headline is confirmed, exploit-validated findings — not raw scanner counts. The{" "}
          {unconfirmedCount} demoted candidate{unconfirmedCount === 1 ? "" : "s"} are kept in the
          appendix for completeness.
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
          <div>
            <p className="text-4xl font-semibold tabular-nums">{summary.totalConfirmed}</p>
            <p className="text-xs uppercase tracking-wide text-muted-foreground">
              Confirmed finding{summary.totalConfirmed === 1 ? "" : "s"}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {severities.length > 0 ? (
              severities.map(({ sev, count }) => (
                <span key={sev} className="inline-flex items-center gap-1.5">
                  <SeverityBadge severity={sev} />
                  <span className="text-sm font-medium tabular-nums">{count}</span>
                </span>
              ))
            ) : (
              <StatusChip tone="success">No confirmed findings</StatusChip>
            )}
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <PostureDelta summary={summary} />
          <div>
            <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Tools consolidated
            </p>
            {summary.toolsConsolidated.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {summary.toolsConsolidated.map((tool) => (
                  <Badge key={tool} className="border-border bg-secondary text-[11px]">
                    {tool}
                  </Badge>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">—</p>
            )}
            <p className="mt-1.5 text-xs text-muted-foreground">
              {summary.toolsConsolidated.length} prior point tool
              {summary.toolsConsolidated.length === 1 ? "" : "s"} correlated into one report.
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function PostureDelta({ summary }: { summary: ExecutiveSummary }) {
  const delta = summary.postureDelta;
  return (
    <div>
      <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Posture delta vs last scan
      </p>
      {delta ? (
        <div className="flex flex-wrap items-center gap-2">
          <StatusChip tone={delta.netDelta <= 0 ? "success" : "danger"}>
            {delta.netDelta > 0 ? "+" : ""}
            {delta.netDelta} net
          </StatusChip>
          <span className="text-sm text-muted-foreground">
            {delta.newIssues} new · {delta.resolvedIssues} resolved
          </span>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          No previous scan to compare — this is the baseline.
        </p>
      )}
    </div>
  );
}
