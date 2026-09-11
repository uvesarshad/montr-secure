"use client";

import * as React from "react";
import type { BlueTeamOrgSummary, DetectionRule } from "@montr/contracts";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Stat } from "../../components/stat.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card.js";
import { Button } from "../../components/ui/button.js";
import { Badge } from "../../components/ui/badge.js";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "../../components/ui/table.js";
import { EmptyState } from "../../components/ui/empty-state.js";
import { LoadingCards, ErrorState } from "../../components/states.js";
import { StatusChip } from "../../components/chips.js";
import { AttackHeatMap } from "../../components/attack-heatmap.js";
import { ShieldAlertIcon, ClockIcon, DownloadIcon } from "../../components/icons.js";
import { ROLE_LABEL } from "../../lib/rbac.js";
import {
  downloadDetectionRule,
  downloadDetectionRuleBundle,
  detectionRuleFilename,
} from "../../lib/exports.js";
import { useBlueTeamOrgSummary } from "./hooks.js";

/**
 * A5 (red/blue agentic-posture audit) — the org-wide blue-team console. The
 * per-scan Blue Team tab (apps/web/src/app/scans/[scanId]/blue-team, B11) is
 * reachable only by opening one specific scan; this is the cross-scan
 * aggregate every role that can see reports could already reach two clicks
 * deep, now surfaced as its own top-level nav item — same
 * `view_reports_and_audit` viewer-visible permission, read-only.
 *
 * Three real, data-backed sections, all sourced from `GET /analytics/blue-team`
 * (apps/api/src/routes/analytics.ts), which itself reads only real per-scan
 * data — each scan's already-built `Report.blueTeam.mitreAttack` (B2/B10) and
 * the real, persisted (A7) `DetectionRule`/`DetectionCoverage` repositories.
 * No new persistence, no mock data:
 *
 *   1. Org-wide ATT&CK coverage over time — the SAME `AttackHeatMap` the
 *      per-scan tab renders (reused as-is, same severity-scale heat tokens),
 *      plus a chronological per-scan coverage-growth table.
 *   2. Detection-rule inventory — every distinct rule generated across scans,
 *      deduped by (format, content), with the SAME per-rule/export-all
 *      download pattern (lib/exports.ts, B11) the per-scan
 *      DetectionRulesPanel uses — no new export mechanism.
 *   3. Detection-coverage trend — real detected/undetected/unknown tri-state
 *      counts per scan over time (A7), never mock data.
 */
export default function BlueTeamPage() {
  const user = useCurrentUser();
  const { data: summary, isLoading, isError, error } = useBlueTeamOrgSummary();

  const isEmpty =
    !!summary &&
    summary.scansConsidered === 0 &&
    summary.detectionRules.totalGenerated === 0 &&
    summary.detectionCoverageTrend.points.length === 0;

  return (
    <div>
      <PageHeader
        title="Blue Team"
        description={`Org-wide detection engineering, ATT&CK coverage, and detection-coverage trend across every scan — aggregated from the same confirmed-finding-derived data the per-scan Blue Team tab renders. Signed in as ${ROLE_LABEL[user.role]}.`}
      />

      {isLoading ? (
        <LoadingCards count={3} />
      ) : isError ? (
        <Card>
          <CardContent className="pt-5">
            <ErrorState error={error} />
          </CardContent>
        </Card>
      ) : !summary || isEmpty ? (
        <Card>
          <CardContent className="pt-5">
            <EmptyState
              icon={<ShieldAlertIcon className="h-6 w-6" />}
              title="No blue-team data yet"
              description="ATT&CK coverage, detection rules, and detection-coverage verdicts are generated per scan once Layer 3 confirms exploitable findings. Run a scan to completion to see the org-wide rollup here."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Scans aggregated" value={summary.scansConsidered} />
            <Stat
              label="Techniques covered"
              value={summary.attackCoverage.coverage.length}
              hint="distinct ATT&CK techniques"
            />
            <Stat
              label="Detection rules"
              value={summary.detectionRules.rules.length}
              hint={`${summary.detectionRules.totalGenerated} generated across scans`}
            />
            <Stat
              label="Coverage verdicts"
              value={
                summary.detectionCoverageTrend.totals.detected +
                summary.detectionCoverageTrend.totals.undetected +
                summary.detectionCoverageTrend.totals.unknown
              }
              hint={`${summary.detectionCoverageTrend.totals.detected} detected`}
            />
          </div>

          <AttackCoverageSection summary={summary} />
          <DetectionRuleInventorySection summary={summary} />
          <DetectionCoverageTrendSection summary={summary} />
        </div>
      )}
    </div>
  );
}

/* ------------------------------- ATT&CK coverage ------------------------------- */

function AttackCoverageSection({ summary }: { summary: BlueTeamOrgSummary }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Org-wide ATT&amp;CK coverage</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <AttackHeatMap coverage={summary.attackCoverage.coverage} />

        {summary.attackCoverage.overTime.length > 0 ? (
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Coverage growth over time
            </p>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scan completed</TableHead>
                    <TableHead>Repository</TableHead>
                    <TableHead>Techniques this scan</TableHead>
                    <TableHead className="text-right">Cumulative techniques</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.attackCoverage.overTime.map((pt) => (
                    <TableRow key={pt.scanId}>
                      <TableCell className="text-muted-foreground">
                        <span className="inline-flex items-center gap-1">
                          <ClockIcon className="h-3 w-3" />
                          {new Date(pt.at).toLocaleString()}
                        </span>
                      </TableCell>
                      <TableCell className="font-medium">{pt.repo}</TableCell>
                      <TableCell className="tabular-nums">{pt.techniqueCount}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {pt.cumulativeTechniqueCount}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

/* --------------------------- detection-rule inventory --------------------------- */

// Mirrors detection-rules-panel.tsx's FORMAT_LABEL (kept local to each panel,
// same precedent as SEVERITY_CHIP/SEVERITY_LABEL living beside their callers).
const FORMAT_LABEL: Record<DetectionRule["format"], string> = {
  sigma: "Sigma",
  otel: "OpenTelemetry (OTTL)",
  siem_query: "SIEM query (SPL)",
};

function DetectionRuleInventorySection({ summary }: { summary: BlueTeamOrgSummary }) {
  const rules = summary.detectionRules.rules;

  // `downloadDetectionRuleBundle` wants a finding-title lookup (B11's per-scan
  // panel resolves this from the loaded Report); this aggregate view has no
  // single Report to resolve titles from, so it falls back to the raw finding
  // id — still a real, useful label, never fabricated.
  const findingTitleFor = React.useCallback((findingId: string) => findingId, []);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Detection-rule inventory</CardTitle>
        {rules.length > 0 ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              downloadDetectionRuleBundle(
                "org-wide",
                rules.map((r) => r.rule),
                findingTitleFor,
              )
            }
          >
            <DownloadIcon className="h-4 w-4" /> Export all rules
          </Button>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-4">
        {rules.length === 0 ? (
          <EmptyState
            icon={<ShieldAlertIcon className="h-6 w-6" />}
            title="No detection rules generated yet"
            description="Sigma/OTel/SIEM rules are generated per confirmed finding once Layer 3 confirms exploitability."
          />
        ) : (
          <>
            <p className="text-sm text-muted-foreground">
              {rules.length} distinct rule{rules.length === 1 ? "" : "s"} across{" "}
              {summary.detectionRules.totalGenerated} generated occurrence
              {summary.detectionRules.totalGenerated === 1 ? "" : "s"} — deduped by format and rule
              content.
            </p>
            {rules.map(({ rule, occurrences, scanIds }) => (
              <Card key={rule.id}>
                <CardHeader className="gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusChip tone="info">{FORMAT_LABEL[rule.format]}</StatusChip>
                    <StatusChip tone={rule.provenance === "live" ? "warning" : "neutral"}>
                      {rule.provenance === "live" ? "Live DAST proof" : "Static proof"}
                    </StatusChip>
                    {occurrences > 1 ? (
                      <StatusChip tone="success">Seen in {occurrences} scans</StatusChip>
                    ) : null}
                    {rule.mitreTechniques.map((t) => (
                      <Badge key={t} className="border-border bg-secondary font-mono text-[11px]">
                        {t}
                      </Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Repeated for scan{scanIds.length === 1 ? "" : "s"}{" "}
                    <code className="font-mono">{scanIds.join(", ")}</code>
                  </p>
                </CardHeader>
                <CardContent>
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
                </CardContent>
              </Card>
            ))}
          </>
        )}
      </CardContent>
    </Card>
  );
}

/* -------------------------- detection-coverage trend -------------------------- */

function DetectionCoverageTrendSection({ summary }: { summary: BlueTeamOrgSummary }) {
  const points = summary.detectionCoverageTrend.points;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Detection-coverage trend</CardTitle>
      </CardHeader>
      <CardContent>
        {points.length === 0 ? (
          <EmptyState
            icon={<ShieldAlertIcon className="h-6 w-6" />}
            title="No detection-coverage verdicts yet"
            description="A tri-state detected/not-detected/unknown verdict is recorded per confirmed finding once Layer 3 completes."
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan completed</TableHead>
                  <TableHead>Repository</TableHead>
                  <TableHead>Detected</TableHead>
                  <TableHead>Not detected</TableHead>
                  <TableHead className="text-right">Unknown</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {points.map((pt) => (
                  <TableRow key={pt.scanId}>
                    <TableCell className="text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        <ClockIcon className="h-3 w-3" />
                        {new Date(pt.at).toLocaleString()}
                      </span>
                    </TableCell>
                    <TableCell className="font-medium">{pt.repo}</TableCell>
                    <TableCell>
                      <StatusChip tone="success">{pt.detected}</StatusChip>
                    </TableCell>
                    <TableCell>
                      <StatusChip tone="danger">{pt.undetected}</StatusChip>
                    </TableCell>
                    <TableCell className="text-right">
                      <StatusChip tone="neutral">{pt.unknown}</StatusChip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
