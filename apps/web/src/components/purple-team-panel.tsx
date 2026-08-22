"use client";

import * as React from "react";
import type { BlueTeamReport } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import { EmptyState } from "./ui/empty-state.js";
import { StatusChip } from "./chips.js";
import { FlaskIcon, CheckIcon, XIcon } from "./icons.js";

/**
 * B11 — purple-loop results view. `blueTeam.purpleTeam` (B5) is the result of
 * actually running a red-team scenario through the gated Layer-3 engine and
 * structurally checking whether the generated detection rule for that
 * finding would have fired against the resulting transcript — a genuine
 * verification, not a static "coverage exists" guess.
 */
export function PurpleTeamPanel({ purpleTeam }: { purpleTeam: BlueTeamReport["purpleTeam"] }) {
  if (purpleTeam.totalScenarios === 0) {
    return (
      <EmptyState
        icon={<FlaskIcon className="h-6 w-6" />}
        title="No purple-team runs yet"
        description="Run a red-team scenario against an allowlisted staging target to verify whether its detection rule actually fires (approver-only, mirrors DAST authorization)."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard label="Scenarios run" value={purpleTeam.totalScenarios} tone="neutral" />
        <StatCard label="Detected" value={purpleTeam.detectedCount} tone="success" />
        <StatCard label="Undetected" value={purpleTeam.undetectedCount} tone="danger" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Scenario verification results</CardTitle>
          <p className="text-sm text-muted-foreground">
            Whether the finding's generated detection rule actually fired when the corresponding
            red-team scenario ran (B5). "Why not" reasoning is always concrete — never a generic
            placeholder.
          </p>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Scenario</TableHead>
                <TableHead>Finding category</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Result</TableHead>
                <TableHead>Reason</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {purpleTeam.entries.map((entry) => (
                <TableRow key={entry.scenarioId}>
                  <TableCell className="font-medium">{entry.scenarioName}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {entry.findingCategory}
                  </TableCell>
                  <TableCell>
                    {entry.detectionRuleId ? (
                      <code className="font-mono text-xs text-muted-foreground">
                        {entry.detectionRuleId}
                      </code>
                    ) : (
                      <span className="text-xs text-muted-foreground">no rule</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {entry.detected ? (
                      <StatusChip tone="success">
                        <CheckIcon className="h-3 w-3" /> Detected
                      </StatusChip>
                    ) : (
                      <StatusChip tone="danger">
                        <XIcon className="h-3 w-3" /> Undetected
                      </StatusChip>
                    )}
                  </TableCell>
                  <TableCell className="max-w-xs text-xs text-muted-foreground">
                    {entry.reason}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "neutral" | "success" | "danger";
}) {
  const toneClass =
    tone === "success"
      ? "text-emerald-300"
      : tone === "danger"
        ? "text-red-300"
        : "text-foreground";
  return (
    <Card>
      <CardContent className="pt-5">
        <p className={`text-3xl font-bold ${toneClass}`}>{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </CardContent>
    </Card>
  );
}
