import * as React from "react";
import type { AuditEvent, AuditAction, AuditActor } from "@montr/contracts";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import { Badge } from "./ui/badge.js";
import { StatusChip } from "./chips.js";
import { EmptyState } from "./ui/empty-state.js";
import { ScrollIcon } from "./icons.js";
import { formatDateTime, type Tone } from "../lib/format.js";

/** Coarse tone per audited action family (safety-relevant actions stand out). */
function actionTone(action: AuditAction): Tone {
  if (action.startsWith("budget.") || action === "dast.kill_switch" || action === "gate.rejected")
    return "danger";
  if (action.startsWith("dast.")) return "warning";
  if (action.startsWith("gate.") || action.startsWith("fix.") || action === "finding.confirmed")
    return "info";
  if (action === "scan.completed") return "success";
  return "neutral";
}

function actorLabel(actor: AuditActor): string {
  if (actor.type === "user") return `${actor.role ?? "user"} · ${actor.id}`;
  return `${actor.type} · ${actor.id}`;
}

/**
 * Audit-log viewer (§8.5, §13). Append-only + hash-chained (tamper-evident):
 * every agent action, LLM call (metadata only — never code bodies), code
 * modification and human approval is recorded and exportable for auditors.
 */
export function AuditTable({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return <EmptyState icon={<ScrollIcon className="h-6 w-6" />} title="No audit events" />;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-10">#</TableHead>
          <TableHead>Time</TableHead>
          <TableHead>Actor</TableHead>
          <TableHead>Action</TableHead>
          <TableHead>Summary</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((ev) => (
          <TableRow key={ev.id}>
            <TableCell className="font-mono text-xs text-muted-foreground tabular-nums">
              {ev.sequence}
            </TableCell>
            <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
              {formatDateTime(ev.at)}
            </TableCell>
            <TableCell className="whitespace-nowrap text-xs">
              <Badge className="border-border bg-secondary text-[11px] capitalize">
                {actorLabel(ev.actor)}
              </Badge>
            </TableCell>
            <TableCell>
              <StatusChip tone={actionTone(ev.action)} className="font-mono text-[11px]">
                {ev.action}
              </StatusChip>
            </TableCell>
            <TableCell className="text-sm">
              {ev.summary}
              {ev.metadata && Object.keys(ev.metadata).length > 0 ? (
                <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {renderMetadata(ev.metadata)}
                </p>
              ) : null}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/** Metadata is already scrubbed to primitives upstream; render compactly. */
function renderMetadata(metadata: Record<string, unknown>): string {
  return Object.entries(metadata)
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}
