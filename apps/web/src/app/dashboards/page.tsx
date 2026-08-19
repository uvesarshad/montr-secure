"use client";

import * as React from "react";
import type { RepoPosture, Severity } from "@montr/contracts";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Stat } from "../../components/stat.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card.js";
import { Button } from "../../components/ui/button.js";
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
import { SeverityBadge, StatusChip } from "../../components/chips.js";
import { BarChartIcon, ClockIcon } from "../../components/icons.js";
import { SEVERITY_ORDER } from "../../lib/format.js";
import { ROLE_LABEL } from "../../lib/rbac.js";
import { useOrgPosture, useRepoTrend } from "./hooks.js";

/**
 * Phase-4 (Wave 5) — org-wide posture dashboards + cross-scan trend
 * intelligence (PRD §16). RBAC-scoped: read-only for every role, per-client
 * isolated. Consumes GET /analytics/posture (org aggregate) and
 * GET /analytics/trends (per-repo time series), both backed by
 * `PostureRepositoryImpl` (packages/state-store).
 *
 * ⛔ Headlines CONFIRMED findings by severity + posture delta over time —
 *    never raw candidate counts (golden rule, §12).
 */
export default function DashboardsPage() {
  const user = useCurrentUser();
  const { data: summary, isLoading, isError, error } = useOrgPosture();
  const [selectedRepo, setSelectedRepo] = React.useState<string | undefined>(undefined);

  const severities = (Object.keys(SEVERITY_ORDER) as Severity[])
    .sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a])
    .map((sev) => ({ sev, count: summary?.totals.confirmedBySeverity[sev] ?? 0 }))
    .filter((s) => s.count > 0);

  return (
    <div>
      <PageHeader
        title="Posture Dashboards"
        description={`Org-wide security posture and per-repo trends over time. Confirmed, prioritized findings — never raw counts. Signed in as ${ROLE_LABEL[user.role]}.`}
      />

      {isLoading ? (
        <LoadingCards count={3} />
      ) : isError ? (
        <Card>
          <CardContent className="pt-5">
            <ErrorState error={error} />
          </CardContent>
        </Card>
      ) : !summary || summary.repos.length === 0 ? (
        <Card>
          <CardContent className="pt-5">
            <EmptyState
              icon={<BarChartIcon className="h-6 w-6" />}
              title="No posture snapshots yet"
              description="Posture snapshots are recorded as scans complete. Run a scan to completion to see confirmed-by-severity totals and regression deltas per repo here."
            />
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Repos tracked" value={summary.totals.repoCount} />
            <Stat label="Confirmed findings" value={summary.totals.total} />
            <Stat
              label="By severity"
              value={
                severities.length > 0 ? (
                  <span className="flex flex-wrap items-center gap-1.5 text-sm">
                    {severities.map(({ sev, count }) => (
                      <span key={sev} className="inline-flex items-center gap-1">
                        <SeverityBadge severity={sev} />
                        <span className="tabular-nums">{count}</span>
                      </span>
                    ))}
                  </span>
                ) : (
                  "—"
                )
              }
              className="col-span-2 lg:col-span-2"
            />
            <Stat
              label="As of"
              value={new Date(summary.at).toLocaleString()}
              hint="last aggregated"
            />
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Repository posture</CardTitle>
            </CardHeader>
            <CardContent>
              <RepoTable
                repos={summary.repos}
                selectedRepo={selectedRepo}
                onSelect={setSelectedRepo}
              />
            </CardContent>
          </Card>

          {selectedRepo ? (
            <RepoTrendCard repo={selectedRepo} onClose={() => setSelectedRepo(undefined)} />
          ) : null}
        </>
      )}
    </div>
  );
}

function RepoTable({
  repos,
  selectedRepo,
  onSelect,
}: {
  repos: RepoPosture[];
  selectedRepo: string | undefined;
  onSelect: (repo: string) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Repository</TableHead>
            <TableHead>Confirmed</TableHead>
            <TableHead>By severity</TableHead>
            <TableHead>Latest scan</TableHead>
            <TableHead className="text-right">Trend</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {repos.map((r) => (
            <TableRow
              key={r.repo}
              className={r.repo === selectedRepo ? "bg-secondary/50" : undefined}
            >
              <TableCell className="font-medium">{r.repo}</TableCell>
              <TableCell className="tabular-nums">{r.total}</TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1">
                  {(Object.keys(SEVERITY_ORDER) as Severity[])
                    .sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a])
                    .filter((sev) => (r.confirmedBySeverity[sev] ?? 0) > 0)
                    .map((sev) => (
                      <span key={sev} className="inline-flex items-center gap-1 text-xs">
                        <SeverityBadge severity={sev} />
                        <span className="tabular-nums">{r.confirmedBySeverity[sev]}</span>
                      </span>
                    ))}
                  {(Object.keys(SEVERITY_ORDER) as Severity[]).every(
                    (sev) => (r.confirmedBySeverity[sev] ?? 0) === 0,
                  ) ? (
                    <StatusChip tone="success">Clean</StatusChip>
                  ) : null}
                </div>
              </TableCell>
              <TableCell className="text-muted-foreground">
                {r.latestAt ? (
                  <span className="inline-flex items-center gap-1">
                    <ClockIcon className="h-3 w-3" />
                    {new Date(r.latestAt).toLocaleString()}
                  </span>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="text-right">
                <Button size="sm" variant="outline" onClick={() => onSelect(r.repo)}>
                  View trend
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function RepoTrendCard({ repo, onClose }: { repo: string; onClose: () => void }) {
  const { data: trend, isLoading, isError, error } = useRepoTrend(repo);

  return (
    <Card className="mt-4">
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <BarChartIcon className="h-4 w-4" /> Posture trend — {repo}
        </CardTitle>
        <Button size="sm" variant="outline" onClick={onClose}>
          Close
        </Button>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingCards count={2} />
        ) : isError ? (
          <ErrorState error={error} />
        ) : !trend || trend.snapshots.length === 0 ? (
          <EmptyState
            icon={<BarChartIcon className="h-6 w-6" />}
            title="No snapshots for this repo yet"
            description="A posture snapshot is recorded each time a scan completes for this repo."
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan completed</TableHead>
                  <TableHead>Confirmed</TableHead>
                  <TableHead>By severity</TableHead>
                  <TableHead>Delta vs previous</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...trend.snapshots].reverse().map((snap) => (
                  <TableRow key={snap.id}>
                    <TableCell className="text-muted-foreground">
                      {new Date(snap.at).toLocaleString()}
                    </TableCell>
                    <TableCell className="tabular-nums">{snap.total}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {(Object.keys(SEVERITY_ORDER) as Severity[])
                          .sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a])
                          .filter((sev) => (snap.confirmedBySeverity[sev] ?? 0) > 0)
                          .map((sev) => (
                            <span key={sev} className="inline-flex items-center gap-1 text-xs">
                              <SeverityBadge severity={sev} />
                              <span className="tabular-nums">{snap.confirmedBySeverity[sev]}</span>
                            </span>
                          ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      {snap.delta ? (
                        <span className="flex items-center gap-2">
                          <StatusChip tone={snap.delta.netDelta <= 0 ? "success" : "danger"}>
                            {snap.delta.netDelta > 0 ? "+" : ""}
                            {snap.delta.netDelta} net
                          </StatusChip>
                          <span className="text-xs text-muted-foreground">
                            {snap.delta.newIssues} new · {snap.delta.resolvedIssues} resolved
                          </span>
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">baseline</span>
                      )}
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
