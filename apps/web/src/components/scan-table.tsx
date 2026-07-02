"use client";

import * as React from "react";
import Link from "next/link";
import type { Scan } from "@montr/contracts";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import { ScanStatusBadge, GateBadge } from "./chips.js";
import { ChevronRightIcon } from "./icons.js";
import { formatUsd, formatDateTime } from "../lib/format.js";

function repoName(repo: string): string {
  const match = repo.match(/([^/:]+\/[^/]+?)(?:\.git)?$/);
  return match?.[1] ?? repo;
}

export function ScanTable({ scans }: { scans: Scan[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Repository</TableHead>
          <TableHead>Mode</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Gate</TableHead>
          <TableHead className="text-right">Est. cost</TableHead>
          <TableHead>Created</TableHead>
          <TableHead className="w-8" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => (
          <TableRow key={scan.id}>
            <TableCell>
              <Link href={`/scans/${scan.id}`} className="font-medium hover:text-primary">
                {repoName(scan.repo)}
              </Link>
              <p className="text-xs text-muted-foreground">{scan.branch}</p>
            </TableCell>
            <TableCell className="uppercase text-xs text-muted-foreground">{scan.mode}</TableCell>
            <TableCell>
              <ScanStatusBadge status={scan.status} />
            </TableCell>
            <TableCell>
              <GateBadge gate={scan.gateState} />
            </TableCell>
            <TableCell className="text-right tabular-nums">
              {scan.costEstimate ? formatUsd(scan.costEstimate.projectedUsd) : "—"}
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {formatDateTime(scan.createdAt)}
            </TableCell>
            <TableCell>
              <Link
                href={`/scans/${scan.id}`}
                aria-label="Open scan"
                className="text-muted-foreground hover:text-foreground"
              >
                <ChevronRightIcon className="h-4 w-4" />
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
