"use client";

import * as React from "react";
import Link from "next/link";
import { useScans } from "../lib/api/hooks.js";
import { PageHeader } from "../components/page-header.js";
import { Stat } from "../components/stat.js";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card.js";
import { ScanTable } from "../components/scan-table.js";
import { LoadingCards, ErrorState } from "../components/states.js";
import { EmptyState } from "../components/ui/empty-state.js";
import { ShieldIcon } from "../components/icons.js";

export default function DashboardPage() {
  const { data: scans, isLoading, isError, error } = useScans();

  const running = scans?.filter((s) => s.status === "running").length ?? 0;
  const awaiting =
    scans?.filter((s) => s.gateState === "estimate_pending" || s.gateState === "fix_gate_pending")
      .length ?? 0;
  const completed = scans?.filter((s) => s.status === "completed").length ?? 0;

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Consolidated SAST · SCA · secrets · DAST. The report headlines confirmed, prioritized findings — never raw counts."
      />

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Scans" value={scans?.length ?? "—"} />
        <Stat label="Running" value={running} />
        <Stat label="Awaiting gate" value={awaiting} hint="estimate or fix approval" />
        <Stat label="Completed" value={completed} />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Recent scans</CardTitle>
          <Link href="/scans" className="text-sm text-primary hover:underline">
            View all
          </Link>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingCards />
          ) : isError ? (
            <ErrorState error={error} />
          ) : !scans || scans.length === 0 ? (
            <EmptyState icon={<ShieldIcon className="h-6 w-6" />} title="No scans yet" />
          ) : (
            <ScanTable scans={scans.slice(0, 5)} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
