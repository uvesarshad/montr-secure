"use client";

import * as React from "react";
import { useParams } from "next/navigation";
import type { Fix, Id } from "@montr/contracts";
import {
  useScan,
  useFixes,
  useReport,
  useScanPullRequests,
  useApproveFixGate,
} from "../../../../lib/api/hooks.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../../../components/ui/card.js";
import { Button } from "../../../../components/ui/button.js";
import { StatusChip } from "../../../../components/chips.js";
import { FixDetails } from "../../../../components/fix-details.js";
import { PrList } from "../../../../components/pr-list.js";
import { LoadingCards } from "../../../../components/states.js";
import { EmptyState } from "../../../../components/ui/empty-state.js";
import { WrenchIcon, AlertTriangleIcon } from "../../../../components/icons.js";
import { useCurrentUser } from "../../../../components/role-context.js";
import { canApproveFixGate } from "../../../../lib/rbac.js";

export default function ScanFixesPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: scan } = useScan(scanId);
  const { data: fixes, isLoading } = useFixes(scanId);
  const { data: report } = useReport(scanId);
  const { data: pullRequests } = useScanPullRequests(scanId);

  const titleFor = React.useMemo(() => {
    const map = new Map<Id, string>();
    for (const rf of report?.confirmedFindings ?? []) map.set(rf.finding.id, rf.finding.title);
    return (fix: Fix) => map.get(fix.confirmedFindingId) ?? fix.confirmedFindingId;
  }, [report]);

  if (isLoading) return <LoadingCards />;

  const all = fixes ?? [];
  const autoEligible = all.filter((f) => f.riskClass === "auto-eligible");
  const humanRequired = all.filter((f) => f.riskClass === "human-required");

  return (
    <div className="space-y-6">
      {scan ? <FixGateCard scanId={scanId} gateState={scan.gateState} /> : null}

      <FixGroup
        title="Auto-eligible fixes"
        subtitle="Mechanical, low blast radius. Eligible for gated pull requests — never direct commits."
        fixes={autoEligible}
        titleFor={titleFor}
      />

      <FixGroup
        title="Human-required fixes"
        subtitle="Touch auth/session/crypto/access-control or wide blast radius. Recommendations only — never auto-applied (§11)."
        fixes={humanRequired}
        titleFor={titleFor}
      />

      <Card>
        <CardHeader>
          <CardTitle>Pull requests</CardTitle>
        </CardHeader>
        <CardContent>
          <PrList pullRequests={pullRequests ?? []} />
        </CardContent>
      </Card>
    </div>
  );
}

function FixGroup({
  title,
  subtitle,
  fixes,
  titleFor,
}: {
  title: string;
  subtitle: string;
  fixes: Fix[];
  titleFor: (fix: Fix) => string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <WrenchIcon className="h-4 w-4" /> {title}
          <StatusChip tone="neutral">{fixes.length}</StatusChip>
        </CardTitle>
        <p className="text-sm text-muted-foreground">{subtitle}</p>
      </CardHeader>
      <CardContent>
        {fixes.length === 0 ? (
          <EmptyState title="None in this class" />
        ) : (
          <div className="space-y-5">
            {fixes.map((fix) => (
              <div key={fix.id} className="rounded-lg border border-border p-4">
                <p className="mb-3 text-sm font-semibold">{titleFor(fix)}</p>
                <FixDetails fix={fix} />
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function FixGateCard({ scanId, gateState }: { scanId: string; gateState: string }) {
  const user = useCurrentUser();
  const mutation = useApproveFixGate(scanId);
  const pending = gateState === "fix_gate_pending";
  const cleared =
    gateState === "approved" || gateState === "auto_approved" || gateState === "estimate_approved";

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="space-y-1">
          <CardTitle>Fix gate</CardTitle>
          <p className="text-sm text-muted-foreground">
            ⛔ No PR opens without passing the auto-eligible bar OR explicit approver approval (§7
            L5, golden rule #5).
          </p>
        </div>
        <StatusChip tone={cleared ? "success" : pending ? "warning" : "neutral"}>
          {cleared ? "Cleared" : pending ? "Awaiting approver" : gateState}
        </StatusChip>
      </CardHeader>
      <CardContent>
        {cleared ? (
          <p className="text-sm text-muted-foreground">
            The gate is cleared. Auto-eligible fixes may open reviewable PRs; human-required fixes
            remain recommendations.
          </p>
        ) : canApproveFixGate(user.role) ? (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">
              Approving clears the gate for auto-eligible fixes and is recorded in the audit log.
            </span>
            <Button size="sm" disabled={mutation.isPending} onClick={() => mutation.mutate()}>
              {mutation.isPending ? "Approving…" : "Approve fix gate"}
            </Button>
          </div>
        ) : (
          <div className="flex items-start gap-2 rounded-md border border-border bg-secondary/40 p-3 text-xs text-muted-foreground">
            <AlertTriangleIcon className="mt-0.5 h-4 w-4 shrink-0" />
            <span>Approver role required to clear the fix gate (§10, §11).</span>
          </div>
        )}
        {mutation.isError ? (
          <p className="mt-2 text-xs text-red-300">Approval failed. Approver role is required.</p>
        ) : null}
      </CardContent>
    </Card>
  );
}
