"use client";

import * as React from "react";
import { CATEGORY_TAXONOMY, type ReportFinding } from "@montr/contracts";
import { Card, CardContent, CardHeader } from "./ui/card.js";
import { Button } from "./ui/button.js";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs.js";
import { Badge } from "./ui/badge.js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog.js";
import {
  SeverityBadge,
  ExposureBadge,
  ProofBadge,
  RiskBadge,
  FixStatusBadge,
  StatusChip,
} from "./chips.js";
import { ProofViewer } from "./proof-viewer.js";
import { DiffViewer } from "./diff-viewer.js";
import { ShieldAlertIcon, AlertTriangleIcon, FlaskIcon } from "./icons.js";
import { useMarkFalsePositive } from "../lib/api/hooks.js";
import { useCurrentUser } from "./role-context.js";
import { canMarkFalsePositive } from "../lib/rbac.js";
import { cn } from "../lib/utils.js";

export function FindingCard({
  reportFinding,
  scanId,
  falsePositive,
}: {
  reportFinding: ReportFinding;
  scanId: string;
  falsePositive: boolean;
}) {
  const { finding, fix, compliance } = reportFinding;
  const taxonomy = CATEGORY_TAXONOMY[finding.category];

  return (
    <Card className={cn(falsePositive && "opacity-70")} id={finding.id}>
      <CardHeader className="gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <ExposureBadge exposure={finding.exposure} />
          <ProofBadge proofType={finding.proofType} />
          {fix ? <RiskBadge riskClass={fix.riskClass} /> : null}
          {falsePositive ? <StatusChip tone="neutral">Marked false positive</StatusChip> : null}
        </div>
        <div>
          <h3 className="text-base font-semibold">{finding.title}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {taxonomy.title} ·{" "}
            <code className="font-mono">
              {finding.location.file}:{finding.location.line}
            </code>{" "}
            · {finding.cwe.join(", ") || compliance.cwe.join(", ")} · {compliance.owasp}
          </p>
        </div>
        <p className="text-sm text-muted-foreground">{finding.impact}</p>
      </CardHeader>

      <CardContent className="space-y-4">
        {falsePositive ? (
          <div className="flex items-start gap-2 rounded-md border border-border bg-secondary/40 p-3 text-xs text-muted-foreground">
            <AlertTriangleIcon className="mt-0.5 h-4 w-4" />
            <span>
              This confirmed finding was marked a false positive. It is retained (never deleted) and
              fed to the FP regression corpus to tune correlation/confirmation thresholds (§15).
            </span>
          </div>
        ) : null}

        <Tabs defaultValue="proof">
          <TabsList>
            <TabsTrigger value="proof">
              <ShieldAlertIcon className="h-3.5 w-3.5" /> Proof
            </TabsTrigger>
            <TabsTrigger value="fix">Merge-ready fix</TabsTrigger>
            <TabsTrigger value="compliance">Compliance</TabsTrigger>
          </TabsList>

          <TabsContent value="proof">
            <ProofViewer proof={finding.proofArtifact} />
          </TabsContent>

          <TabsContent value="fix">
            {fix ? (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <RiskBadge riskClass={fix.riskClass} />
                  <FixStatusBadge status={fix.status} />
                </div>
                <p className="text-sm">{fix.rationale}</p>

                {fix.riskClass === "human-required" ? (
                  <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
                    <AlertTriangleIcon className="mt-0.5 h-4 w-4 text-amber-300" />
                    <span className="text-amber-100">
                      Human-required: {fix.riskClassRationale} This fix is a recommendation only and
                      is never auto-applied (§11, golden rule #3).
                    </span>
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">{fix.riskClassRationale}</p>
                )}

                <div>
                  <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Patch (diff)
                  </p>
                  <DiffViewer patch={fix.patch} />
                </div>

                <div>
                  <div className="mb-1 flex flex-wrap items-center gap-2">
                    <FlaskIcon className="h-4 w-4 text-muted-foreground" />
                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Proof-of-fix test
                    </p>
                    {fix.proofOfFixTest.framework ? (
                      <Badge className="border-border bg-secondary text-[11px]">
                        {fix.proofOfFixTest.framework}
                      </Badge>
                    ) : null}
                    {fix.proofOfFixTest.failsPrePatch ? (
                      <StatusChip tone="info">Fails before fix</StatusChip>
                    ) : null}
                    {fix.proofOfFixTest.passesPostPatch ? (
                      <StatusChip tone="success">Passes after fix</StatusChip>
                    ) : null}
                  </div>
                  {fix.proofOfFixTest.filePath ? (
                    <p className="mb-1 font-mono text-xs text-muted-foreground">
                      {fix.proofOfFixTest.filePath}
                    </p>
                  ) : null}
                  <pre className="overflow-x-auto rounded-md border border-border bg-background/70 p-3 font-mono text-xs">
                    {fix.proofOfFixTest.code}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                No fix generated for this finding yet.
              </p>
            )}
          </TabsContent>

          <TabsContent value="compliance">
            <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
              <div>
                <dt className="text-xs text-muted-foreground">Category</dt>
                <dd className="font-medium">{CATEGORY_TAXONOMY[compliance.category].title}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">CWE</dt>
                <dd className="flex flex-wrap gap-1">
                  {compliance.cwe.map((c) => (
                    <Badge key={c} className="border-border bg-secondary font-mono text-[11px]">
                      {c}
                    </Badge>
                  ))}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">OWASP Top 10</dt>
                <dd>
                  <span className="font-mono text-xs">{compliance.owasp}</span>{" "}
                  {compliance.owaspTitle}
                </dd>
              </div>
            </dl>
          </TabsContent>
        </Tabs>
      </CardContent>

      {!falsePositive ? (
        <div className="flex justify-end px-5 pb-5">
          <FalsePositiveButton scanId={scanId} findingId={finding.id} title={finding.title} />
        </div>
      ) : null}
    </Card>
  );
}

function FalsePositiveButton({
  scanId,
  findingId,
  title,
}: {
  scanId: string;
  findingId: string;
  title: string;
}) {
  const user = useCurrentUser();
  const [open, setOpen] = React.useState(false);
  const [reason, setReason] = React.useState("");
  const mutation = useMarkFalsePositive(scanId);

  if (!canMarkFalsePositive(user.role)) {
    return (
      <span className="text-xs text-muted-foreground">Viewer role cannot triage findings.</span>
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          Mark false positive
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Mark as false positive</DialogTitle>
          <DialogDescription>
            {title}. This is recorded in the audit log and fed to the FP regression corpus (§15).
            The finding is retained in the report, not deleted.
          </DialogDescription>
        </DialogHeader>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={3}
          placeholder="Why is this a false positive? (e.g. input is validated upstream)"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        {mutation.isError ? (
          <p className="text-xs text-red-300">Failed to record. Please retry.</p>
        ) : null}
        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={mutation.isPending || reason.trim().length === 0}
            onClick={() =>
              mutation.mutate(
                { findingId, reason: reason.trim() },
                { onSuccess: () => setOpen(false) },
              )
            }
          >
            {mutation.isPending ? "Recording…" : "Confirm false positive"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
