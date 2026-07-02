import * as React from "react";
import type { CostRollup, ScanScope, CostLineItem } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import { StatusChip } from "./chips.js";
import { formatUsd, formatTokens, formatPercent, formatDuration } from "../lib/format.js";

/** Estimate-vs-actual cost rollup (§8.4, §12.6). Variance target is ±15%. */
export function CostPanel({ cost }: { cost: CostRollup }) {
  const { estimate, actual, variancePct, costPerFindingUsd } = cost;
  const withinTarget = variancePct === undefined ? undefined : Math.abs(variancePct) <= 0.15;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Token cost</CardTitle>
        {variancePct !== undefined ? (
          <StatusChip tone={withinTarget ? "success" : "warning"}>
            Variance {formatPercent(variancePct)} {withinTarget ? "· within ±15%" : "· over target"}
          </StatusChip>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Metric label="Estimated" value={formatUsd(estimate.projectedUsd)} />
          <Metric label="Actual" value={actual ? formatUsd(actual.actualUsd) : "—"} />
          <Metric
            label="Tokens (actual)"
            value={
              actual
                ? formatTokens(actual.usage.totalTokens)
                : formatTokens(estimate.projectedTotalTokens)
            }
          />
          <Metric
            label="Cost / finding"
            value={costPerFindingUsd !== undefined ? formatUsd(costPerFindingUsd) : "—"}
          />
        </div>

        <p className="text-xs text-muted-foreground">
          Basis: {estimate.basis}. Wall-clock:{" "}
          {actual
            ? formatDuration(actual.wallClockSeconds)
            : formatDuration(estimate.projectedWallClockSeconds)}
          .
        </p>

        {actual && actual.byModel.length > 0 ? (
          <LineItemsTable title="By model" items={actual.byModel} />
        ) : null}
        {actual && actual.byLayer.length > 0 ? (
          <LineItemsTable title="By layer" items={actual.byLayer} />
        ) : (
          <LineItemsTable title="Estimated by layer" items={estimate.byLayer} />
        )}
      </CardContent>
    </Card>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-lg font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function LineItemsTable({ title, items }: { title: string; items: CostLineItem[] }) {
  return (
    <div>
      <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {title}
      </p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Key</TableHead>
            <TableHead className="text-right">Input</TableHead>
            <TableHead className="text-right">Output</TableHead>
            <TableHead className="text-right">USD</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((item) => (
            <TableRow key={item.key}>
              <TableCell className="font-mono text-xs">{item.key}</TableCell>
              <TableCell className="text-right tabular-nums">
                {formatTokens(item.usage.inputTokens)}
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {formatTokens(item.usage.outputTokens)}
              </TableCell>
              <TableCell className="text-right tabular-nums">{formatUsd(item.usd)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function ScopePanel({ scope }: { scope: ScanScope }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Scope</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <Row label="Mode" value={<span className="uppercase">{scope.mode}</span>} />
        {scope.routeCount !== undefined ? <Row label="Routes" value={scope.routeCount} /> : null}
        {scope.fileCount !== undefined ? <Row label="Files" value={scope.fileCount} /> : null}
        {scope.includePaths.length > 0 ? (
          <Row label="Included" value={<PathList paths={scope.includePaths} />} />
        ) : null}
        {scope.excludePaths.length > 0 ? (
          <Row label="Excluded" value={<PathList paths={scope.excludePaths} />} />
        ) : null}
        {scope.mode === "diff" ? (
          <>
            <Row label="Changed files" value={<PathList paths={scope.changedFiles} />} />
            <Row label="Reachable from changes" value={scope.reachableFromChanges ? "Yes" : "No"} />
          </>
        ) : null}
        {scope.stagingUrl ? (
          <Row
            label="Staging target (DAST)"
            value={<code className="font-mono text-xs">{scope.stagingUrl}</code>}
          />
        ) : null}
      </CardContent>
    </Card>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right">{value}</span>
    </div>
  );
}

function PathList({ paths }: { paths: string[] }) {
  if (paths.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex flex-wrap justify-end gap-1">
      {paths.map((p) => (
        <code key={p} className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">
          {p}
        </code>
      ))}
    </span>
  );
}
