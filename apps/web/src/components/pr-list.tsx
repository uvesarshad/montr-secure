import * as React from "react";
import Link from "next/link";
import type { PullRequest } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Badge } from "./ui/badge.js";
import { PrStatusBadge } from "./chips.js";
import { EmptyState } from "./ui/empty-state.js";
import { GitPullRequestIcon, ExternalLinkIcon } from "./icons.js";
import { formatDateTime } from "../lib/format.js";

/**
 * Pull-request status list (§12.3). PRs are opened for auto-eligible fixes ONLY —
 * never direct commits (§7 L5, golden rule #5) — each independently reviewable.
 * Used both on the global Pull Requests page and inside a scan's Fixes tab.
 */
export function PrList({
  pullRequests,
  showScan = false,
}: {
  pullRequests: PullRequest[];
  showScan?: boolean;
}) {
  if (pullRequests.length === 0) {
    return (
      <EmptyState
        icon={<GitPullRequestIcon className="h-6 w-6" />}
        title="No pull requests"
        description="Auto-eligible fixes open reviewable PRs here once the fix gate is cleared."
      />
    );
  }
  return (
    <div className="space-y-3">
      {pullRequests.map((pr) => (
        <PrCard key={pr.id} pr={pr} showScan={showScan} />
      ))}
    </div>
  );
}

function PrCard({ pr, showScan }: { pr: PullRequest; showScan: boolean }) {
  return (
    <Card>
      <CardHeader className="gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <PrStatusBadge status={pr.status} />
          <Badge className="border-border bg-secondary text-[11px]">{pr.provider}</Badge>
          {pr.number ? (
            <span className="font-mono text-xs text-muted-foreground">#{pr.number}</span>
          ) : null}
          <Badge className="border-emerald-500/30 bg-emerald-500/10 text-[11px] text-emerald-300">
            {pr.fixIds.length} auto-eligible fix{pr.fixIds.length === 1 ? "" : "es"}
          </Badge>
        </div>
        <CardTitle className="text-sm">{pr.title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">{pr.bodySummary}</p>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>
            <code className="font-mono">{pr.branch}</code> →{" "}
            <code className="font-mono">{pr.baseBranch}</code>
          </span>
          <span>Opened {formatDateTime(pr.createdAt)}</span>
          {showScan ? (
            <Link href={`/scans/${pr.scanId}/fixes`} className="text-primary hover:underline">
              View scan
            </Link>
          ) : null}
          {pr.url ? (
            <a
              href={pr.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              Open PR <ExternalLinkIcon className="h-3 w-3" />
            </a>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
