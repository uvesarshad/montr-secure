/**
 * Layer invocation contract. Layers are invoked ONLY through the orchestrator,
 * via the @montr/contracts layer I/O types — no layer reaches around it (§8.1,
 * golden rule #10). apps/worker wires the REAL layer functions (which close over
 * the @montr/llm-gateway); unit tests inject deterministic stubs built from
 * @montr/fixtures. Either way the orchestrator only sees these typed runners.
 */
import type {
  Layer0Output,
  Layer1Output,
  Layer2Output,
  Layer3Output,
  Layer4Output,
  Layer5Output,
  LayerId,
  LayerJobDataMap,
  LayerJobResultMap,
  Scan,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { StateStore } from "@montr/state-store";
import type { Logger } from "@montr/telemetry";
import type { CostMeter } from "@montr/cost-meter";

/**
 * Outputs of already-completed layers, available in-process as a convenience.
 * The DURABLE source of truth is the state store (so resumed runs in a fresh
 * process read persisted tiers) — this cache is only populated within one run.
 */
export interface PriorOutputs {
  layer0?: Layer0Output;
  layer1?: Layer1Output;
  layer2?: Layer2Output;
  layer3?: Layer3Output;
  layer4?: Layer4Output;
  layer5?: Layer5Output;
}

/** Everything a layer needs to do its work, handed in by the orchestrator. */
export interface LayerContext<L extends LayerId = LayerId> {
  readonly scanId: string;
  readonly clientId: string;
  readonly scan: Scan;
  /** The typed, validated job for this exact layer. */
  readonly job: LayerJobDataMap[L];
  readonly config: MontrConfig;
  readonly logger: Logger;
  /** Per-scan cost meter — layers record LLM usage here for the budget guard. */
  readonly costMeter: CostMeter;
  readonly store: StateStore;
  /** ⛔ Kill switch. Layers (esp. Layer 3 DAST) MUST honor this and stop on abort. */
  readonly signal: AbortSignal;
  /** 0-based retry attempt index. */
  readonly attempt: number;
  readonly priorOutputs: PriorOutputs;
  /** Emit an intra-layer progress event (0..100). */
  emitProgress(phase: string, pct: number, message?: string): void;
}

/** A single layer's implementation: consume its context, emit its typed output. */
export type LayerRunner<L extends LayerId> = (
  ctx: LayerContext<L>,
) => Promise<LayerJobResultMap[L]>;

/** The full set of layer implementations the orchestrator drives. */
export type LayerRunners = {
  readonly [L in LayerId]: LayerRunner<L>;
};
