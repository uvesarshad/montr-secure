"use client";

import * as React from "react";
import type { CostEstimate, Scan, BudgetPolicy } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Button } from "./ui/button.js";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import { StatusChip } from "./chips.js";
import { CheckIcon, DollarIcon } from "./icons.js";
import { formatUsd, formatTokens, formatDuration } from "../lib/format.js";
import { useApproveEstimate } from "../lib/api/hooks.js";
import { useCurrentUser } from "./role-context.js";
import { canApproveEstimate } from "../lib/rbac.js";

/**
 * Pre-scan cost-estimate approval (§6.6, §8.4). Cost is a first-class output:
 * the estimate is surfaced and (per BudgetPolicy) must be acknowledged before
 * Layer 1 runs — so clients never silently burn tokens. Operator OR approver may
 * approve; viewers are read-only.
 */
export function EstimatePanel({ scan, estimate }: { scan: Scan; estimate: CostEstimate }) {
  const user = useCurrentUser();
  const mutation = useApproveEstimate(scan.id);

  const pending = scan.gateState === "estimate_pending";
  const approved =
    scan.gateState === "estimate_approved" ||
    scan.gateState === "running" ||
    scan.gateState === "approved" ||
    scan.gateState === "auto_approved" ||
    Boolean(scan.startedAt);
  const canApprove = canApproveEstimate(user.role);

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <DollarIcon className="h-4 w-4" /> Pre-scan cost estimate
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Projected from map size × scan mode. Approve before the pipeline spends any tokens.
          </p>
        </div>
        {approved ? (
          <StatusChip tone="success">Approved</StatusChip>
        ) : pending ? (
          <StatusChip tone="warning">Awaiting approval</StatusChip>
        ) : (
          <StatusChip tone="neutral">Not started</StatusChip>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Metric label="Projected cost" value={formatUsd(estimate.projectedUsd)} />
          <Metric label="Total tokens" value={formatTokens(estimate.projectedTotalTokens)} />
          <Metric label="Wall-clock" value={formatDuration(estimate.projectedWallClockSeconds)} />
          <Metric label="Mode" value={<span className="uppercase">{estimate.mode}</span>} />
        </div>

        <p className="text-xs text-muted-foreground">Basis: {estimate.basis}.</p>

        <BudgetNote policy={scan.budgetPolicy} projectedUsd={estimate.projectedUsd} />

        {estimate.byLayer.length > 0 ? (
          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Projected by layer
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Layer</TableHead>
                  <TableHead className="text-right">Input</TableHead>
                  <TableHead className="text-right">Output</TableHead>
                  <TableHead className="text-right">USD</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {estimate.byLayer.map((item) => (
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
        ) : null}

        {approved ? (
          <div className="flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-100">
            <CheckIcon className="h-4 w-4 text-emerald-300" />
            Estimate approved — the pipeline is authorized to spend up to the budget ceiling.
          </div>
        ) : canApprove ? (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
            <span className="text-xs text-muted-foreground">
              Approving records an audit event and releases the pipeline past Layer 0.
            </span>
            <Button
              size="sm"
              disabled={mutation.isPending || !pending}
              onClick={() => mutation.mutate()}
            >
              {mutation.isPending ? "Approving…" : "Approve estimate"}
            </Button>
          </div>
        ) : (
          <p className="border-t border-border pt-3 text-xs text-muted-foreground">
            Operator or approver role required to approve the estimate. Your role is read-only here.
          </p>
        )}
        {mutation.isError ? (
          <p className="text-xs text-red-300">Approval failed. Please retry.</p>
        ) : null}
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

function BudgetNote({ policy, projectedUsd }: { policy?: BudgetPolicy; projectedUsd: number }) {
  if (!policy?.maxUsd) return null;
  const overCeiling = projectedUsd > policy.maxUsd;
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <StatusChip tone={overCeiling ? "danger" : "neutral"}>
        Budget ceiling {formatUsd(policy.maxUsd)}
      </StatusChip>
      <span className="text-muted-foreground">
        Enforcement: {policy.enforcement === "hard_halt" ? "hard halt + partial report" : "warn"}.
        {overCeiling ? " Estimate exceeds the ceiling." : ""}
      </span>
    </div>
  );
}
