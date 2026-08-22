"use client";

import * as React from "react";
import type { MitreTechniqueCoverageShape } from "@montr/contracts";
import { EmptyState } from "./ui/empty-state.js";
import { ShieldAlertIcon, ExternalLinkIcon } from "./icons.js";
import { cn } from "../lib/utils.js";

/**
 * B11 — ATT&CK coverage matrix/heat map. Enterprise ATT&CK's own tactic
 * ordering (kill-chain order), used to sort matrix columns; any tactic this
 * report references that isn't in this list (should not happen — every
 * catalog tactic in `packages/contracts/src/mitre.ts` is a real ATT&CK/ATLAS
 * tactic) sorts alphabetically after the known ones rather than being
 * dropped.
 */
const TACTIC_ORDER: readonly string[] = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

interface MatrixCell {
  id: string;
  name: string;
  url: string;
  findingCount: number;
  findingIds: readonly string[];
}

interface MatrixColumn {
  tactic: string;
  cells: MatrixCell[];
}

function buildMatrix(coverage: readonly MitreTechniqueCoverageShape[]): MatrixColumn[] {
  const byTactic = new Map<string, MatrixCell[]>();
  for (const row of coverage) {
    // `technique.tactic` is comma-joined when a technique spans multiple
    // tactics (e.g. T1078 "Valid Accounts" -> Initial Access, Persistence,
    // Privilege Escalation, Defense Evasion) — it appears as its own cell in
    // EVERY tactic column it belongs to, mirroring the real MITRE Navigator.
    const tactics = row.technique.tactic.split(",").map((t) => t.trim());
    for (const tactic of tactics) {
      const cell: MatrixCell = {
        id: row.technique.id,
        name: row.technique.name,
        url: row.technique.url,
        findingCount: row.findingCount,
        findingIds: row.findingIds,
      };
      const existing = byTactic.get(tactic);
      if (existing) existing.push(cell);
      else byTactic.set(tactic, [cell]);
    }
  }
  return [...byTactic.entries()]
    .map(([tactic, cells]) => ({
      tactic,
      cells: cells.sort((a, b) => b.findingCount - a.findingCount || a.id.localeCompare(b.id)),
    }))
    .sort((a, b) => {
      const ai = TACTIC_ORDER.indexOf(a.tactic);
      const bi = TACTIC_ORDER.indexOf(b.tactic);
      if (ai === -1 && bi === -1) return a.tactic.localeCompare(b.tactic);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });
}

/**
 * Heat intensity reuses the SAME severity color language docs/ui/theming.md
 * defines (sev-critical/high/medium/low), scaled by each technique's finding
 * count relative to the busiest technique in this report — never a new,
 * invented color system.
 */
function heatClass(count: number, max: number): string {
  if (max <= 1) return "bg-sev-low/25 border-sev-low/40 text-sev-low";
  const ratio = count / max;
  if (ratio >= 0.75) return "bg-sev-critical/30 border-sev-critical/50 text-sev-critical";
  if (ratio >= 0.5) return "bg-sev-high/25 border-sev-high/45 text-sev-high";
  if (ratio >= 0.25) return "bg-sev-medium/20 border-sev-medium/40 text-sev-medium";
  return "bg-sev-low/15 border-sev-low/30 text-sev-low";
}

export function AttackHeatMap({ coverage }: { coverage: readonly MitreTechniqueCoverageShape[] }) {
  if (coverage.length === 0) {
    return (
      <EmptyState
        icon={<ShieldAlertIcon className="h-6 w-6" />}
        title="No ATT&CK techniques mapped"
        description="Technique mappings appear once confirmed findings exist for this scan."
      />
    );
  }

  const columns = buildMatrix(coverage);
  const max = Math.max(...coverage.map((c) => c.findingCount));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span className="font-medium text-foreground">Heat legend:</span>
        <LegendSwatch className="bg-sev-low/15 border-sev-low/30" label="1 finding" />
        <LegendSwatch className="bg-sev-medium/20 border-sev-medium/40" label="low-mid" />
        <LegendSwatch className="bg-sev-high/25 border-sev-high/45" label="mid-high" />
        <LegendSwatch
          className="bg-sev-critical/30 border-sev-critical/50"
          label={`${max} (max)`}
        />
      </div>

      <div className="overflow-x-auto rounded-lg border border-border">
        <div className="flex min-w-max gap-px bg-border">
          {columns.map((col) => (
            <div key={col.tactic} className="flex w-44 shrink-0 flex-col gap-px bg-border">
              <div className="bg-card px-2 py-2 text-center text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {col.tactic}
              </div>
              {col.cells.map((cell) => (
                <a
                  key={cell.id}
                  href={cell.url}
                  target="_blank"
                  rel="noreferrer"
                  title={`${cell.id} ${cell.name} — ${cell.findingCount} confirmed finding${cell.findingCount === 1 ? "" : "s"}`}
                  className={cn(
                    "group flex flex-col gap-0.5 border px-2 py-2 text-left transition-opacity hover:opacity-90",
                    heatClass(cell.findingCount, max),
                  )}
                >
                  <span className="flex items-center justify-between gap-1 font-mono text-[11px] font-semibold">
                    {cell.id}
                    <ExternalLinkIcon className="h-3 w-3 opacity-0 group-hover:opacity-70" />
                  </span>
                  <span className="line-clamp-2 text-[11px] leading-tight">{cell.name}</span>
                  <span className="text-[10px] font-semibold">
                    {cell.findingCount} finding{cell.findingCount === 1 ? "" : "s"}
                  </span>
                </a>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function LegendSwatch({ className, label }: { className: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className={cn("h-3 w-3 rounded-sm border", className)} />
      {label}
    </span>
  );
}
