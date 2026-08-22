"use client";

import * as React from "react";
import { useParams } from "next/navigation";
import { useReport } from "../../../../lib/api/hooks.js";
import { ApiError } from "../../../../lib/api/client.js";
import { Card, CardContent } from "../../../../components/ui/card.js";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../../../../components/ui/tabs.js";
import { DetectionRulesPanel } from "../../../../components/detection-rules-panel.js";
import { AttackHeatMap } from "../../../../components/attack-heatmap.js";
import { AttackPathsPanel } from "../../../../components/attack-path-chain.js";
import { PurpleTeamPanel } from "../../../../components/purple-team-panel.js";
import { ThreatModelPanel } from "../../../../components/threat-model-panel.js";
import { HardeningPanel } from "../../../../components/hardening-panel.js";
import { LoadingCards } from "../../../../components/states.js";
import { EmptyState } from "../../../../components/ui/empty-state.js";
import { ShieldAlertIcon } from "../../../../components/icons.js";

/**
 * B11 — the blue-team console: detection-rule generation (Sigma/OTel/SIEM),
 * the ATT&CK coverage heat map, the attack-path kill-chain view, and
 * purple-loop verification results, plus B7's threat model and B9's
 * advisory hardening recommendations. All of it is consumed straight off
 * the already-loaded `Report.blueTeam` field (B10) — no new API route, same
 * `useReport` hook the Report/Fixes tabs already use.
 */
export default function ScanBlueTeamPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: report, isLoading, isError, error } = useReport(scanId);

  if (isLoading) return <LoadingCards />;

  if (isError || !report) {
    const gated = error instanceof ApiError && error.code === "GATE_NOT_PASSED";
    return (
      <Card>
        <CardContent className="pt-5">
          <EmptyState
            icon={<ShieldAlertIcon className="h-6 w-6" />}
            title={gated ? "Blue-team data not available yet" : "Unable to load blue-team data"}
            description={
              gated
                ? "Detection rules, ATT&CK coverage, attack paths, and purple-team results are derived from the report once the scan completes."
                : error instanceof Error
                  ? error.message
                  : "Something went wrong."
            }
          />
        </CardContent>
      </Card>
    );
  }

  const { blueTeam } = report;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Blue team</h2>
        <p className="text-sm text-muted-foreground">
          Detection engineering, ATT&CK coverage, attack-path kill chains, and purple-team
          verification derived from this scan's confirmed findings (§16, blue-team build).
        </p>
      </div>

      <Tabs defaultValue="detection-rules">
        <TabsList>
          <TabsTrigger value="detection-rules">
            Detection Rules ({blueTeam.detectionEngineering.rules.length})
          </TabsTrigger>
          <TabsTrigger value="attack-matrix">
            ATT&amp;CK Matrix ({blueTeam.mitreAttack.coverage.length})
          </TabsTrigger>
          <TabsTrigger value="attack-paths">
            Attack Paths ({blueTeam.attackPaths.length})
          </TabsTrigger>
          <TabsTrigger value="purple-team">
            Purple Team ({blueTeam.purpleTeam.totalScenarios})
          </TabsTrigger>
          <TabsTrigger value="threat-model">Threat Model</TabsTrigger>
          <TabsTrigger value="hardening">
            Hardening ({blueTeam.hardening.recommendations.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="detection-rules">
          <DetectionRulesPanel report={report} />
        </TabsContent>

        <TabsContent value="attack-matrix">
          <AttackHeatMap coverage={blueTeam.mitreAttack.coverage} />
        </TabsContent>

        <TabsContent value="attack-paths">
          <AttackPathsPanel attackPaths={blueTeam.attackPaths} report={report} />
        </TabsContent>

        <TabsContent value="purple-team">
          <PurpleTeamPanel purpleTeam={blueTeam.purpleTeam} />
        </TabsContent>

        <TabsContent value="threat-model">
          <ThreatModelPanel threatModel={blueTeam.threatModel} />
        </TabsContent>

        <TabsContent value="hardening">
          <HardeningPanel hardening={blueTeam.hardening} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
