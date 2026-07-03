import * as React from "react";
import type { Fix } from "@montr/contracts";
import { Badge } from "./ui/badge.js";
import { RiskBadge, FixStatusBadge, StatusChip } from "./chips.js";
import { DiffViewer } from "./diff-viewer.js";
import { AlertTriangleIcon, FlaskIcon } from "./icons.js";

/**
 * Renders a single merge-ready fix: risk classification, rationale, the
 * unified-diff patch, and the proof-of-fix test (fails pre-patch, passes
 * post-patch). Shared by the report finding cards and the Fixes & PRs tab so the
 * auto-eligible vs human-required framing is identical everywhere (§12.2/§12.3).
 *
 * ⛔ human-required fixes (auth/session/crypto/access-control or wide blast
 * radius) are shown as recommendations only — never auto-applied (§11, rule #3).
 */
export function FixDetails({ fix }: { fix: Fix }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <RiskBadge riskClass={fix.riskClass} />
        <FixStatusBadge status={fix.status} />
      </div>

      <p className="text-sm">{fix.rationale}</p>

      {fix.riskClass === "human-required" ? (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
          <AlertTriangleIcon className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <span className="text-amber-100">
            <span className="font-medium">Human-required.</span> {fix.riskClassRationale} This fix
            is a recommendation only and is never auto-applied (§11, golden rule #3).
          </span>
        </div>
      ) : (
        <div className="flex items-start gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs">
          <span className="text-emerald-100">
            <span className="font-medium">Auto-eligible.</span> {fix.riskClassRationale} Eligible
            for a gated pull request — never a direct commit (§7 L5).
          </span>
        </div>
      )}

      <div>
        <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Patch (unified diff)
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
  );
}
