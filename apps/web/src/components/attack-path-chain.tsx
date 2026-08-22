"use client";

import * as React from "react";
import type { AttackPath, Report } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { EmptyState } from "./ui/empty-state.js";
import { SeverityBadge } from "./chips.js";
import { TargetIcon } from "./icons.js";

function feasibilityTone(score: number): string {
  if (score >= 0.75) return "text-sev-critical";
  if (score >= 0.5) return "text-sev-high";
  if (score >= 0.25) return "text-sev-medium";
  return "text-sev-low";
}

/**
 * B11 — attack-path graph view. `blueTeam.attackPaths` (B8) are kill chains
 * across >= 2 confirmed findings; rendered here as an ordered step-by-step
 * chain (dot + connecting line, mirroring proof-viewer.tsx's static
 * data-flow rendering convention) rather than a full graph library, since a
 * chain is inherently linear — the visual complexity of a force-directed
 * graph would add nothing a reader couldn't already get from an ordered list.
 */
export function AttackPathsPanel({
  attackPaths,
  report,
}: {
  attackPaths: readonly AttackPath[];
  report: Report;
}) {
  const findingFor = React.useMemo(() => {
    const map = new Map(report.confirmedFindings.map((rf) => [rf.finding.id, rf.finding]));
    return (findingId: string) => map.get(findingId);
  }, [report]);

  if (attackPaths.length === 0) {
    return (
      <EmptyState
        icon={<TargetIcon className="h-6 w-6" />}
        title="No attack-path chains identified"
        description="A chain requires >= 2 confirmed findings whose structural relationship (RCE-enables-everything, credential-leaking IDOR, or an SSRF pivot) was detected in this scan's App Map."
      />
    );
  }

  return (
    <div className="space-y-4">
      {[...attackPaths]
        .sort((a, b) => b.feasibilityScore - a.feasibilityScore)
        .map((path) => (
          <Card key={path.id}>
            <CardHeader className="gap-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={path.severity} />
                  <CardTitle className="text-sm font-semibold">
                    {path.steps.length}-hop kill chain
                  </CardTitle>
                </div>
                <div className="text-right">
                  <p
                    className={`text-2xl font-bold leading-none ${feasibilityTone(path.feasibilityScore)}`}
                  >
                    {Math.round(path.feasibilityScore * 100)}%
                  </p>
                  <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
                    Feasibility
                  </p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">{path.narrative}</p>
            </CardHeader>
            <CardContent>
              <ol className="space-y-0">
                {path.steps.map((step, i) => {
                  const finding = findingFor(step.findingId);
                  const isLast = i === path.steps.length - 1;
                  return (
                    <li key={`${step.findingId}-${i}`} className="relative pl-7">
                      <span className="absolute left-1.5 top-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-[10px] font-bold text-primary-foreground">
                        {i + 1}
                      </span>
                      {!isLast ? (
                        <span className="absolute left-[0.9rem] top-6 h-[calc(100%-0.6rem)] w-px bg-border" />
                      ) : null}
                      <div className="pb-6">
                        <div className="flex flex-wrap items-center gap-2">
                          {finding ? <SeverityBadge severity={finding.severity} /> : null}
                          <span className="text-sm font-medium">
                            {finding ? finding.title : step.findingId}
                          </span>
                        </div>
                        {finding ? (
                          <code className="mt-0.5 block font-mono text-xs text-muted-foreground">
                            {finding.location.file}:{finding.location.line}
                          </code>
                        ) : null}
                        {step.note ? (
                          <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                            <span aria-hidden className="text-primary">
                              &rarr;
                            </span>
                            {step.note}
                          </p>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ol>
            </CardContent>
          </Card>
        ))}
    </div>
  );
}
