"use client";

import * as React from "react";
import type { Report } from "@montr/contracts";
import { Button } from "./ui/button.js";
import { DownloadIcon } from "./icons.js";
import {
  REPORT_EXPORTS,
  downloadReportExport,
  type ReportExportDescriptor,
  type ReportExportGroup,
} from "../lib/exports.js";

const GROUP_LABEL: Record<ReportExportGroup, string> = {
  scanner: "Scanner formats",
  compliance: "Compliance evidence",
  raw: "Raw data",
};

const GROUP_ORDER: ReportExportGroup[] = ["scanner", "compliance", "raw"];

/**
 * Downloadable exports for the compliance tab (§12.5, §13, DECIDE-5 order):
 * SARIF + OWASP first, then SOC 2 evidence, then ISO 27001, then raw CSV/JSON.
 * Generation is client-side from the loaded report (see lib/exports.ts), so the
 * download works offline with no server round-trip.
 */
export function ExportButtons({ report }: { report: Report }) {
  const [busy, setBusy] = React.useState<string | null>(null);

  const run = (descriptor: ReportExportDescriptor) => {
    setBusy(descriptor.format);
    try {
      downloadReportExport(report, descriptor);
    } finally {
      // Give the click a tick before clearing the pressed state.
      window.setTimeout(() => setBusy(null), 300);
    }
  };

  const grouped = GROUP_ORDER.map((group) => ({
    group,
    items: REPORT_EXPORTS.filter((e) => e.group === group),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="space-y-4">
      {grouped.map(({ group, items }) => (
        <div key={group}>
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {GROUP_LABEL[group]}
          </p>
          <div className="grid gap-2 sm:grid-cols-2">
            {items.map((descriptor) => (
              <button
                key={descriptor.format}
                type="button"
                onClick={() => run(descriptor)}
                aria-label={`Download ${descriptor.label} export`}
                className="flex items-start gap-3 rounded-md border border-border bg-background/60 p-3 text-left transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <DownloadIcon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                <span className="min-w-0">
                  <span className="flex items-center gap-2 text-sm font-medium">
                    {descriptor.label}
                    {busy === descriptor.format ? (
                      <span className="text-xs text-muted-foreground">downloading…</span>
                    ) : null}
                  </span>
                  <span className="mt-0.5 block text-xs text-muted-foreground">
                    {descriptor.description}
                  </span>
                </span>
              </button>
            ))}
          </div>
        </div>
      ))}
      <p className="text-xs text-muted-foreground">
        Compliance evidence (SARIF / OWASP / SOC 2 / ISO) carries metadata only — locations,
        categories and remediation status, never source bodies or secrets. The raw JSON export is
        the full on-prem report model (including fixes) and never leaves your perimeter (§11).
      </p>
    </div>
  );
}

/** Single primary export button (used in report headers for a quick SARIF grab). */
export function QuickExportButton({ report }: { report: Report }) {
  const sarif = REPORT_EXPORTS.find((e) => e.format === "sarif")!;
  return (
    <Button variant="outline" size="sm" onClick={() => downloadReportExport(report, sarif)}>
      <DownloadIcon className="h-4 w-4" /> SARIF
    </Button>
  );
}
