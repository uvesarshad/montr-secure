"use client";

import * as React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useScan, useProgress, useAppMap } from "../../../lib/api/hooks.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../../components/ui/card.js";
import { LayerProgress } from "../../../components/layer-progress.js";
import { AppMapSummary } from "../../../components/app-map-summary.js";
import { LoadingCards, ErrorState } from "../../../components/states.js";
import { EmptyState } from "../../../components/ui/empty-state.js";
import { ShieldIcon, FileTextIcon } from "../../../components/icons.js";

export default function ScanOverviewPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: scan } = useScan(scanId);
  const isRunning = scan?.status === "running" || scan?.status === "queued";
  const { data: progress, isLoading, isError, error } = useProgress(scanId, isRunning);
  const { data: appMap } = useAppMap(scanId);
  const hasReport = scan?.status === "completed";

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2 space-y-4">
        {appMap ? (
          <AppMapSummary appMap={appMap} />
        ) : (
          <Card>
            <CardContent className="pt-5">
              <EmptyState
                icon={<ShieldIcon className="h-6 w-6" />}
                title="App Map not available yet"
                description="Layer 0 builds the structural model before any expensive work runs."
              />
            </CardContent>
          </Card>
        )}
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Pipeline</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <LoadingCards count={2} />
            ) : isError ? (
              <ErrorState error={error} />
            ) : (
              <LayerProgress events={progress ?? []} scan={scan} />
            )}
          </CardContent>
        </Card>

        {hasReport ? (
          <Card>
            <CardContent className="pt-5">
              <Link
                href={`/scans/${scanId}/report`}
                className="flex items-center gap-2 text-sm font-medium text-primary hover:underline"
              >
                <FileTextIcon className="h-4 w-4" /> View the confirmed-findings report
              </Link>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}
