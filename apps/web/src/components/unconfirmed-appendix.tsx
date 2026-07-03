import * as React from "react";
import {
  CATEGORY_TAXONOMY,
  complianceForCategory,
  type UnconfirmedFinding,
} from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { Badge } from "./ui/badge.js";
import { ExposureBadge, StatusChip } from "./chips.js";
import { EmptyState } from "./ui/empty-state.js";
import { AlertTriangleIcon } from "./icons.js";

/**
 * Appendix: unconfirmed candidates (§12.4). Demoted, never deleted, and CLEARLY
 * separated from the confirmed headline — this is where breadth lives so the
 * headline stays confirmed + prioritized (golden rule / §12).
 */
export function UnconfirmedAppendix({ findings }: { findings: UnconfirmedFinding[] }) {
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-md border border-border bg-secondary/40 p-3 text-xs text-muted-foreground">
        <AlertTriangleIcon className="mt-0.5 h-4 w-4 shrink-0" />
        <span>
          These candidates could not be corroborated against the App Map or failed exploit
          confirmation. They are retained for completeness and to feed the regression corpus — they
          are deliberately NOT part of the confirmed headline.
        </span>
      </div>

      {findings.length === 0 ? (
        <EmptyState
          title="No demoted candidates"
          description="Everything surfaced was confirmed."
        />
      ) : (
        findings.map((f) => <UnconfirmedCard key={f.id} finding={f} />)
      )}
    </div>
  );
}

function UnconfirmedCard({ finding }: { finding: UnconfirmedFinding }) {
  const taxonomy = CATEGORY_TAXONOMY[finding.category];
  const compliance = complianceForCategory(finding.category);
  return (
    <Card className="opacity-90">
      <CardHeader className="gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatusChip tone="neutral">Unconfirmed</StatusChip>
          <ExposureBadge exposure={finding.exposure} />
          <span className="text-xs text-muted-foreground">Rank #{finding.rank}</span>
        </div>
        <CardTitle className="text-sm">{taxonomy.title}</CardTitle>
        <p className="text-xs text-muted-foreground">
          <code className="font-mono">
            {finding.location.file}:{finding.location.line}
          </code>{" "}
          · {compliance.cwe.join(", ")} · {compliance.owasp}
        </p>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-2.5 text-xs">
          <span className="font-medium text-amber-200">Why demoted: </span>
          <span className="text-muted-foreground">{finding.unconfirmedReason}</span>
        </div>
        <p className="text-xs text-muted-foreground">{finding.reachabilityHypothesis}</p>
        <div className="flex flex-wrap gap-1.5">
          <ScoreBadge label="Reachability" score={finding.reachabilityScore} />
          <ScoreBadge label="Exposure" score={finding.exposureScore} />
          <ScoreBadge label="Impact" score={finding.impactScore} />
        </div>
      </CardContent>
    </Card>
  );
}

function ScoreBadge({ label, score }: { label: string; score: number }) {
  return (
    <Badge className="border-border bg-secondary text-[11px]">
      {label} {(score * 100).toFixed(0)}%
    </Badge>
  );
}
