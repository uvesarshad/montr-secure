import * as React from "react";
import type { LayerId, ProgressEvent, Scan } from "@montr/contracts";
import {
  deriveLayerProgress,
  layerNarrativeTrace,
  overallPct,
  type LayerStatus,
} from "../lib/progress.js";
import { CheckIcon, ClockIcon, DotIcon, BanIcon } from "./icons.js";
import { cn } from "../lib/utils.js";

function StatusDot({ status }: { status: LayerStatus }) {
  switch (status) {
    case "done":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-300">
          <CheckIcon className="h-3.5 w-3.5" />
        </span>
      );
    case "active":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-sky-500/20 text-sky-300">
          <ClockIcon className="h-3.5 w-3.5 animate-pulse" />
        </span>
      );
    case "blocked":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-red-500/20 text-red-300">
          <BanIcon className="h-3.5 w-3.5" />
        </span>
      );
    default:
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <DotIcon className="h-2.5 w-2.5" />
        </span>
      );
  }
}

/**
 * A14 — a simple, honest live "agent trace": the ordered narrative messages
 * for one layer, e.g. Layer 3's agentic investigation loop (E1) narrating its
 * reasoning turn by turn as `gateway.stream()` tokens arrive (see
 * docs/modules/confirmation.md's Live Progress Narration entry). Reuses the
 * SAME polled `ProgressEvent[]` the pipeline overview already fetches —
 * no new transport. Renders nothing when there's no more history than the
 * single "phase · pct%" line already shown above it.
 */
function AgentTrace({ events, layer }: { events: ProgressEvent[]; layer: LayerId }) {
  const trace = layerNarrativeTrace(events, layer);
  if (trace.length < 2) return null;
  return (
    <ul className="mt-1 max-h-32 space-y-0.5 overflow-y-auto rounded border border-border/60 bg-muted/30 p-1.5 font-mono text-[10px] leading-snug text-muted-foreground">
      {trace.map((ev, i) => (
        <li key={`${ev.at}_${i}`} className="truncate" title={ev.message}>
          {ev.message}
        </li>
      ))}
    </ul>
  );
}

export function LayerProgress({ events, scan }: { events: ProgressEvent[]; scan?: Scan }) {
  const layers = deriveLayerProgress(events, scan);
  const overall = overallPct(layers);

  return (
    <div className="space-y-4">
      <div>
        <div className="mb-1 flex items-center justify-between text-sm">
          <span className="font-medium">Pipeline progress</span>
          <span className="text-muted-foreground">{overall}%</span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-primary transition-all"
            style={{ width: `${overall}%` }}
          />
        </div>
      </div>

      <ol className="space-y-0">
        {layers.map((layer, i) => (
          <li key={layer.layer} className="relative flex gap-3 pb-5 last:pb-0">
            {i < layers.length - 1 ? (
              <span className="absolute left-3 top-6 h-full w-px bg-border" />
            ) : null}
            <StatusDot status={layer.status} />
            <div className="flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p
                  className={cn(
                    "text-sm font-medium",
                    layer.status === "pending" && "text-muted-foreground",
                  )}
                >
                  {layer.title}
                </p>
                <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
                  {layer.layer}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">{layer.description}</p>
              {layer.status === "active" ? (
                <div className="mt-2 space-y-1">
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full bg-sky-400"
                      style={{ width: `${layer.pct}%` }}
                    />
                  </div>
                  {layer.phase ? (
                    <p className="text-[11px] text-muted-foreground">
                      {layer.phase} · {layer.pct}%
                    </p>
                  ) : null}
                  <AgentTrace events={events} layer={layer.layer} />
                </div>
              ) : null}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
