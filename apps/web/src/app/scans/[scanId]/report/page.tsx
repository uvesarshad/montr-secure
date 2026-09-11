"use client";

import * as React from "react";
import { useParams } from "next/navigation";
import type { Id } from "@montr/contracts";
import { useReport, useAudit } from "../../../../lib/api/hooks.js";
import { ApiError } from "../../../../lib/api/client.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../../../components/ui/card.js";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../../../../components/ui/tabs.js";
import { ExecSummary } from "../../../../components/exec-summary.js";
import { GeneratedExecutiveSummaryPanel } from "../../../../components/generated-executive-summary.js";
import { FindingCard } from "../../../../components/finding-card.js";
import { UnconfirmedAppendix } from "../../../../components/unconfirmed-appendix.js";
import { ComplianceTable } from "../../../../components/compliance-table.js";
import { ExportButtons, QuickExportButton } from "../../../../components/export-buttons.js";
import { CostPanel, ScopePanel } from "../../../../components/cost-panel.js";
import { LoadingCards } from "../../../../components/states.js";
import { EmptyState } from "../../../../components/ui/empty-state.js";
import { FileTextIcon } from "../../../../components/icons.js";
import { compareSeverity } from "../../../../lib/format.js";

export default function ScanReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: report, isLoading, isError, error } = useReport(scanId);
  const { data: audit } = useAudit(scanId);

  // FP status round-trips through the audit log: marking a finding FP appends a
  // `finding.marked_false_positive` event (§15), which we reflect back here.
  const fpIds = React.useMemo<Set<Id>>(() => {
    const ids = (audit ?? [])
      .filter((e) => e.action === "finding.marked_false_positive")
      .map((e) => e.targetId)
      .filter((id): id is Id => Boolean(id));
    return new Set(ids);
  }, [audit]);

  if (isLoading) return <LoadingCards />;

  if (isError || !report) {
    const gated = error instanceof ApiError && error.code === "GATE_NOT_PASSED";
    return (
      <Card>
        <CardContent className="pt-5">
          <EmptyState
            icon={<FileTextIcon className="h-6 w-6" />}
            title={gated ? "Report not available yet" : "Unable to load the report"}
            description={
              gated
                ? "The report headlines confirmed findings once the scan completes. Track progress on the Overview tab."
                : error instanceof Error
                  ? error.message
                  : "Something went wrong."
            }
          />
        </CardContent>
      </Card>
    );
  }

  const confirmed = [...report.confirmedFindings].sort((a, b) =>
    compareSeverity(a.finding.severity, b.finding.severity),
  );

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <QuickExportButton report={report} />
      </div>

      <ExecSummary
        summary={report.executiveSummary}
        unconfirmedCount={report.unconfirmedAppendix.length}
      />

      {report.generatedExecutiveSummary ? (
        <GeneratedExecutiveSummaryPanel summary={report.generatedExecutiveSummary} />
      ) : null}

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Confirmed ({confirmed.length})</TabsTrigger>
          <TabsTrigger value="appendix">Appendix ({report.unconfirmedAppendix.length})</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="cost">Cost &amp; scope</TabsTrigger>
        </TabsList>

        <TabsContent value="findings">
          {confirmed.length === 0 ? (
            <EmptyState
              title="No confirmed findings"
              description="Nothing reached the confirmed tier."
            />
          ) : (
            <div className="space-y-4">
              {confirmed.map((rf) => (
                <FindingCard
                  key={rf.finding.id}
                  reportFinding={rf}
                  scanId={scanId}
                  falsePositive={fpIds.has(rf.finding.id)}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="appendix">
          <UnconfirmedAppendix findings={report.unconfirmedAppendix} />
        </TabsContent>

        <TabsContent value="compliance">
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>OWASP Top 10 / CWE mapping</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Every finding is mapped to a CWE and an OWASP Top 10 (2021) category (§13).
                </p>
              </CardHeader>
              <CardContent>
                <ComplianceTable mappings={report.complianceMapping} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Downloadable exports</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Drops into SOC 2 / ISO 27001 evidence collection and SARIF-aware pipelines
                  (DECIDE-5 order).
                </p>
              </CardHeader>
              <CardContent>
                <ExportButtons report={report} />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="cost">
          <div className="grid gap-4 lg:grid-cols-2">
            <CostPanel cost={report.costAndScope.cost} />
            <ScopePanel scope={report.costAndScope.scope} />
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
