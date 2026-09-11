import type { LayerId, ProgressEvent, Scan } from "@montr/contracts";

/** Ordered pipeline layers with human-facing copy (PRD §7). */
export const LAYER_ORDER: readonly LayerId[] = [
  "layer0",
  "layer1",
  "layer2",
  "layer3",
  "layer4",
  "layer5",
];

export const LAYER_META: Record<LayerId, { title: string; description: string }> = {
  layer0: { title: "Intake & Scoping", description: "App Map, scope, and pre-scan cost estimate." },
  layer1: {
    title: "Parallel Discovery",
    description: "SAST · secrets · SCA. Deliberately over-inclusive; never surfaced to the user.",
  },
  layer2: {
    title: "Correlation (the moat)",
    description: "Rank by reachability × exposure × impact; demote uncorroborated candidates.",
  },
  layer3: {
    title: "Exploit Confirmation",
    description: "Static proof by default; live DAST is approver-gated and off by default.",
  },
  layer4: {
    title: "Fix Generation",
    description: "Diff-ready patch + proof-of-fix test + risk classification.",
  },
  layer5: {
    title: "Human Gate & Output",
    description: "Report headlines confirmed findings; PRs only for auto-eligible fixes.",
  },
};

export type LayerStatus = "pending" | "active" | "done" | "blocked";

export interface LayerProgress {
  layer: LayerId;
  title: string;
  description: string;
  status: LayerStatus;
  pct: number;
  phase?: string;
  /** A14 — the most recent progress message for this layer (e.g. Layer 3's live investigation narrative). */
  message?: string;
}

/**
 * Derive a per-layer progress view from the raw ProgressEvent stream + scan
 * lifecycle. Deterministic and pure so it can be unit-tested without a backend.
 */
export function deriveLayerProgress(events: ProgressEvent[], scan?: Scan): LayerProgress[] {
  const latest = new Map<LayerId, ProgressEvent>();
  for (const ev of events) {
    const prev = latest.get(ev.layer);
    if (!prev || ev.pct >= prev.pct) latest.set(ev.layer, ev);
  }

  const terminalDone = scan?.status === "completed";
  const blocked = scan?.gateState === "blocked";

  // Index of the layer currently in progress (first non-complete with any signal).
  return LAYER_ORDER.map((layer) => {
    const ev = latest.get(layer);
    const pct = terminalDone ? 100 : (ev?.pct ?? 0);
    let status: LayerStatus;
    if (blocked && ev && ev.pct < 100) {
      status = "blocked";
    } else if (pct >= 100) {
      status = "done";
    } else if (pct > 0) {
      status = "active";
    } else {
      status = "pending";
    }
    return {
      layer,
      title: LAYER_META[layer].title,
      description: LAYER_META[layer].description,
      status,
      pct,
      phase: ev?.phase,
      message: ev?.message,
    };
  });
}

/** Overall completion percentage across all six layers (0..100). */
export function overallPct(layers: LayerProgress[]): number {
  if (layers.length === 0) return 0;
  const sum = layers.reduce((acc, l) => acc + l.pct, 0);
  return Math.round(sum / layers.length);
}

/**
 * A14 — the ordered narrative trace of progress messages for one layer (e.g.
 * Layer 3's live agentic-investigation narrative, streamed via
 * `gateway.stream()` — see docs/modules/confirmation.md's Live Progress
 * Narration entry), most recent last, trimmed to `limit` entries. Unlike
 * `deriveLayerProgress` above (which collapses a layer down to its single
 * LATEST event for the pipeline-overview rows), this keeps the full ordered
 * history so a console view can render an honest, scrollable "agent trace"
 * rather than only ever showing the newest line.
 */
export function layerNarrativeTrace(
  events: ProgressEvent[],
  layer: LayerId,
  limit = 30,
): ProgressEvent[] {
  const withMessage = events.filter((e) => e.layer === layer && e.message);
  return withMessage.length > limit ? withMessage.slice(withMessage.length - limit) : withMessage;
}
