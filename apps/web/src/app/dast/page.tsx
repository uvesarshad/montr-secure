"use client";

import * as React from "react";
import Link from "next/link";
import { useScans } from "../../lib/api/hooks.js";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent } from "../../components/ui/card.js";
import { DastPanel } from "../../components/dast-panel.js";
import { LoadingCards, ErrorState } from "../../components/states.js";
import { EmptyState } from "../../components/ui/empty-state.js";
import { RadarIcon, ShieldAlertIcon } from "../../components/icons.js";
import { canAuthorizeDast } from "../../lib/rbac.js";

export default function DastAuthorizationPage() {
  const { data: scans, isLoading, isError, error } = useScans();
  const user = useCurrentUser();
  const isApprover = canAuthorizeDast(user.role);

  // Scans eligible for live DAST: already authorized, or still active.
  const eligible = (scans ?? []).filter(
    (s) => Boolean(s.scope.stagingUrl) || s.status === "running" || s.status === "queued",
  );

  return (
    <div>
      <PageHeader
        title="DAST Authorization"
        description="Authorize live confirmation against allowlisted staging targets. Production is blocked by policy; a kill switch halts probing instantly (§11)."
      />

      {!isApprover ? (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">
          <ShieldAlertIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <span>
            Live DAST authorization is approver-only. You can view authorization status but cannot
            authorize probing (§10, §11).
          </span>
        </div>
      ) : null}

      {isLoading ? (
        <LoadingCards />
      ) : isError ? (
        <ErrorState error={error} />
      ) : eligible.length === 0 ? (
        <Card>
          <CardContent className="pt-5">
            <EmptyState
              icon={<RadarIcon className="h-6 w-6" />}
              title="No scans eligible for live DAST"
              description="Static confirmation runs on every scan by default; live DAST needs an authorized staging target."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {eligible.map((scan) => (
            <div key={scan.id} className="space-y-2">
              <Link
                href={`/scans/${scan.id}/dast`}
                className="text-sm font-medium hover:text-primary"
              >
                {scan.repo} · <span className="text-muted-foreground">{scan.branch}</span>
              </Link>
              <DastPanel scan={scan} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
