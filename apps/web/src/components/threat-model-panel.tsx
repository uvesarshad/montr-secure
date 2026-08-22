"use client";

import * as React from "react";
import type { BlueTeamReport } from "@montr/contracts";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.js";
import { EmptyState } from "./ui/empty-state.js";
import { ShieldIcon } from "./icons.js";

/**
 * Minimal, dependency-free line-based Markdown renderer — this console has no
 * markdown library in apps/web/package.json (see B10's `renderThreatModelReportMarkdown`,
 * which produces plain `#`/`##`/`-` Markdown, not HTML). Handles exactly the
 * shapes that renderer emits: `#`/`##`/`###` headings, `-`/`*` bullet lines,
 * blank-line paragraph breaks, and plain prose — not a general CommonMark
 * parser, so it never mis-renders unsupported syntax as literal characters
 * for the subset actually produced server-side.
 */
/** Inline `**bold**` spans only (the one inline construct `renderThreatModelReportMarkdown`
 * actually emits, e.g. `**Public API boundary**`) — everything else renders as plain text. */
function renderInline(text: string, keyPrefix: string): React.ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
      return <strong key={`${keyPrefix}-${i}`}>{part.slice(2, -2)}</strong>;
    }
    return <React.Fragment key={`${keyPrefix}-${i}`}>{part}</React.Fragment>;
  });
}

function renderMarkdownLines(markdown: string): React.ReactNode[] {
  const lines = markdown.split("\n");
  const nodes: React.ReactNode[] = [];
  let listBuffer: string[] = [];

  const flushList = () => {
    if (listBuffer.length === 0) return;
    nodes.push(
      <ul key={`ul-${nodes.length}`} className="ml-4 list-outside list-disc space-y-1">
        {listBuffer.map((item, i) => (
          <li key={i} className="text-sm">
            {renderInline(item, `li-${nodes.length}-${i}`)}
          </li>
        ))}
      </ul>,
    );
    listBuffer = [];
  };

  lines.forEach((raw, i) => {
    const line = raw.trimEnd();
    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    const bullet = /^[-*]\s+(.*)$/.exec(line);

    if (heading) {
      flushList();
      const level = (heading[1] ?? "#").length;
      const text = heading[2] ?? "";
      const cls =
        level === 1
          ? "text-lg font-semibold"
          : level === 2
            ? "text-base font-semibold"
            : "text-sm font-semibold";
      nodes.push(
        <p key={i} className={`${cls} mt-4 first:mt-0`}>
          {text}
        </p>,
      );
    } else if (bullet) {
      listBuffer.push(bullet[1] ?? "");
    } else if (line.trim().length === 0) {
      flushList();
    } else {
      flushList();
      nodes.push(
        <p key={i} className="text-sm leading-relaxed text-foreground/90">
          {renderInline(line, `p-${i}`)}
        </p>,
      );
    }
  });
  flushList();
  return nodes;
}

/**
 * B11 — renders B7's reviewable threat-model artifact. `present: false` means
 * the scan's App Map carried no threat model (honestly absent, never a
 * fabricated placeholder).
 */
export function ThreatModelPanel({ threatModel }: { threatModel: BlueTeamReport["threatModel"] }) {
  if (!threatModel.present) {
    return (
      <EmptyState
        icon={<ShieldIcon className="h-6 w-6" />}
        title="No threat model available"
        description="This scan's App Map did not produce a threat model (E6). Trust boundaries and STRIDE classification appear here once one is derived."
      />
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Threat model</CardTitle>
        {threatModel.summary ? (
          <p className="text-sm text-muted-foreground">{threatModel.summary}</p>
        ) : null}
      </CardHeader>
      <CardContent>
        {threatModel.markdown ? (
          <div className="space-y-1">{renderMarkdownLines(threatModel.markdown)}</div>
        ) : (
          <p className="text-sm text-muted-foreground">No rendered artifact available.</p>
        )}
      </CardContent>
    </Card>
  );
}
