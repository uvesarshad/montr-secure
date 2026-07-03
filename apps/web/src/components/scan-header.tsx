"use client";

import * as React from "react";
import type { Scan } from "@montr/contracts";
import { ScanStatusBadge, GateBadge } from "./chips.js";
import { KillSwitchButton } from "./kill-switch-button.js";
import { PageHeader } from "./page-header.js";
import { formatUsd, formatDateTime } from "../lib/format.js";

function repoName(repo: string): string {
  const match = repo.match(/([^/:]+\/[^/]+?)(?:\.git)?$/);
  return match?.[1] ?? repo;
}

/** Persistent scan context header shown across every scan sub-tab. */
export function ScanHeader({ scan }: { scan: Scan }) {
  const active = scan.status === "running" || scan.status === "queued" || scan.status === "paused";
  return (
    <PageHeader
      breadcrumbs={[{ label: "Scans", href: "/scans" }, { label: repoName(scan.repo) }]}
      title={
        <span className="flex flex-wrap items-center gap-2">
          {repoName(scan.repo)}
          <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
            {scan.branch}
          </span>
        </span>
      }
      description={
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="uppercase">{scan.mode} scan</span>
          {scan.commitSha ? (
            <span className="font-mono text-xs">{scan.commitSha.slice(0, 10)}</span>
          ) : null}
          <span>Created {formatDateTime(scan.createdAt)}</span>
          {scan.costEstimate ? <span>Est. {formatUsd(scan.costEstimate.projectedUsd)}</span> : null}
        </span>
      }
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <ScanStatusBadge status={scan.status} />
          <GateBadge gate={scan.gateState} />
          {active ? <KillSwitchButton scanId={scan.id} /> : null}
        </div>
      }
    />
  );
}
