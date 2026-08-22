"use client";

import * as React from "react";
import type { DetectionRule, Report } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Button } from "./ui/button.js";
import { Badge } from "./ui/badge.js";
import { EmptyState } from "./ui/empty-state.js";
import { StatusChip } from "./chips.js";
import { DownloadIcon, ShieldAlertIcon } from "./icons.js";
import {
  downloadDetectionRule,
  downloadDetectionRuleBundle,
  detectionRuleFilename,
} from "../lib/exports.js";

const FORMAT_LABEL: Record<DetectionRule["format"], string> = {
  sigma: "Sigma",
  otel: "OpenTelemetry (OTTL)",
  siem_query: "SIEM query (SPL)",
};

/**
 * B11 — Detection Rules page. Lists every generated Sigma/OTel/SIEM rule
 * (`blueTeam.detectionEngineering.rules`, B3/B4) alongside the confirmed
 * finding it detects, its MITRE ATT&CK technique tags (B2), and the
 * human-readable log-signature narrative (B4) — concrete log fields, the
 * exact pattern to alert on, and finding-specific false-alarm guidance.
 * Export follows the exact client-side-generation pattern already used by
 * the compliance tab's SARIF/SOC2/ISO/CSV/JSON exports (see lib/exports.ts).
 */
export function DetectionRulesPanel({ report }: { report: Report }) {
  const rules = report.blueTeam.detectionEngineering.rules;

  const findingTitleFor = React.useMemo(() => {
    const map = new Map<string, string>();
    for (const rf of report.confirmedFindings) map.set(rf.finding.id, rf.finding.title);
    return (findingId: string) => map.get(findingId) ?? findingId;
  }, [report]);

  const findingFor = React.useMemo(() => {
    const map = new Map(report.confirmedFindings.map((rf) => [rf.finding.id, rf.finding]));
    return (findingId: string) => map.get(findingId);
  }, [report]);

  if (rules.length === 0) {
    return (
      <EmptyState
        icon={<ShieldAlertIcon className="h-6 w-6" />}
        title="No detection rules generated"
        description="Sigma/OTel/SIEM rules are generated per confirmed finding once Layer 3 confirms exploitability."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {rules.length} generated rule{rules.length === 1 ? "" : "s"} across{" "}
          {new Set(rules.map((r) => r.findingId)).size} confirmed finding
          {new Set(rules.map((r) => r.findingId)).size === 1 ? "" : "s"}.
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => downloadDetectionRuleBundle(report.scanId, rules, findingTitleFor)}
        >
          <DownloadIcon className="h-4 w-4" /> Export all rules
        </Button>
      </div>

      {rules.map((rule) => {
        const finding = findingFor(rule.findingId);
        return (
          <Card key={rule.id}>
            <CardHeader className="gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <StatusChip tone="info">{FORMAT_LABEL[rule.format]}</StatusChip>
                <StatusChip tone={rule.provenance === "live" ? "warning" : "neutral"}>
                  {rule.provenance === "live" ? "Live DAST proof" : "Static proof"}
                </StatusChip>
                {rule.mitreTechniques.map((t) => (
                  <Badge key={t} className="border-border bg-secondary font-mono text-[11px]">
                    {t}
                  </Badge>
                ))}
              </div>
              <div>
                <CardTitle className="text-sm font-semibold">
                  {finding ? finding.title : findingTitleFor(rule.findingId)}
                </CardTitle>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Finding <code className="font-mono">{rule.findingId}</code>
                  {finding ? (
                    <>
                      {" "}
                      ·{" "}
                      <code className="font-mono">
                        {finding.location.file}:{finding.location.line}
                      </code>
                    </>
                  ) : null}
                </p>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Rule content
                  </p>
                  <Button variant="ghost" size="sm" onClick={() => downloadDetectionRule(rule)}>
                    <DownloadIcon className="h-3.5 w-3.5" /> {detectionRuleFilename(rule)}
                  </Button>
                </div>
                <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background/70 p-3 font-mono text-xs leading-relaxed">
                  {rule.content}
                </pre>
              </div>

              {rule.logSignature ? (
                <div className="rounded-md border border-border bg-secondary/30 p-3">
                  <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Log signature
                  </p>
                  <div className="space-y-2 text-sm">
                    <div className="flex flex-wrap gap-1">
                      {rule.logSignature.fields.map((f) => (
                        <Badge
                          key={f}
                          className="border-border bg-background font-mono text-[11px]"
                        >
                          {f}
                        </Badge>
                      ))}
                    </div>
                    <p className="font-mono text-xs text-foreground/90">
                      {rule.logSignature.pattern}
                    </p>
                    {rule.logSignature.falseAlarmSources.length > 0 ? (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground">
                          Known false-alarm sources
                        </p>
                        <ul className="mt-1 list-inside list-disc text-xs text-muted-foreground">
                          {rule.logSignature.falseAlarmSources.map((s, i) => (
                            <li key={i}>{s}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : null}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
