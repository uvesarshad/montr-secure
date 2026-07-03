"use client";

import * as React from "react";
import { useParams } from "next/navigation";
import { useScan, useReport } from "../../../../lib/api/hooks.js";
import { DastPanel } from "../../../../components/dast-panel.js";
import { ProofViewer } from "../../../../components/proof-viewer.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../../../components/ui/card.js";
import { LoadingCards } from "../../../../components/states.js";

export default function ScanDastPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: scan, isLoading } = useScan(scanId);
  const { data: report } = useReport(scanId);

  if (isLoading || !scan) return <LoadingCards count={2} />;

  const liveFindings = (report?.confirmedFindings ?? []).filter(
    (rf) => rf.finding.proofType === "live",
  );

  return (
    <div className="max-w-3xl space-y-4">
      <DastPanel scan={scan} />

      {liveFindings.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Live-confirmed findings ({liveFindings.length})</CardTitle>
            <p className="text-sm text-muted-foreground">
              Captured request/response transcripts against the allowlisted staging target.
            </p>
          </CardHeader>
          <CardContent className="space-y-5">
            {liveFindings.map((rf) => (
              <div key={rf.finding.id}>
                <p className="mb-2 text-sm font-semibold">{rf.finding.title}</p>
                <ProofViewer proof={rf.finding.proofArtifact} />
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
