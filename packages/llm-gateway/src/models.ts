import {
  MODEL_FLOOR,
  ModelBelowFloorError,
  type ModelDescriptor,
  type ModelTier,
  type Provider,
} from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { normalizeModelId } from "@montr/cost-meter";
import type { Logger } from "@montr/telemetry";

/**
 * Model matrix + model-floor logic (DECIDE-3). The floor for the confirmation
 * tier is Sonnet-5-class; the gateway WARNS when a client points a sub-floor
 * model at confirmation, which materially degrades exploit-confirmation accuracy.
 */

/** Coarse capability rank on the Anthropic scale. 0 = unrecognized (not ranked). */
export function modelRank(modelId: string): number {
  const id = normalizeModelId(modelId).toLowerCase();
  if (id.includes("opus") || id.includes("fable") || id.includes("mythos")) return 4;
  if (id.includes("sonnet-5") || id.includes("sonnet5")) return 3;
  if (id.includes("sonnet")) return 2;
  if (id.includes("haiku")) return 1;
  return 0;
}

/** The confirmation-tier floor rank (Sonnet-5-class). */
export const FLOOR_RANK = modelRank(MODEL_FLOOR.confirmationTier.minModelId);

/**
 * Whether a model sits below the confirmation floor. Unrecognized models
 * (rank 0 — e.g. non-Claude BYO models) are NOT flagged, to avoid false alarms;
 * their floor simply can't be evaluated on the Anthropic scale.
 */
export function isBelowFloor(modelId: string): boolean {
  const rank = modelRank(modelId);
  return rank > 0 && rank < FLOOR_RANK;
}

export interface ModelFloorCheck {
  belowFloor: boolean;
  reason: string;
}

export function checkModelFloor(modelId: string): ModelFloorCheck {
  return { belowFloor: isBelowFloor(modelId), reason: MODEL_FLOOR.confirmationTier.reason };
}

interface Caps {
  contextWindow: number;
  maxOutputTokens: number;
}

function capsForModel(modelId: string): Caps {
  switch (modelRank(modelId)) {
    case 4:
    case 3:
    case 2:
      return { contextWindow: 1_000_000, maxOutputTokens: 64_000 };
    case 1:
      return { contextWindow: 200_000, maxOutputTokens: 64_000 };
    default:
      return { contextWindow: 200_000, maxOutputTokens: 8_192 };
  }
}

function inferTier(modelId: string): ModelTier {
  const rank = modelRank(modelId);
  if (rank >= 4) return "confirmation";
  if (rank <= 1 && rank > 0) return "triage";
  return "default";
}

function descriptor(provider: Provider, modelId: string, tier: ModelTier): ModelDescriptor {
  const caps = capsForModel(modelId);
  return {
    provider,
    modelId,
    tier,
    contextWindow: caps.contextWindow,
    maxOutputTokens: caps.maxOutputTokens,
    supportsTools: true,
    supportsStreaming: true,
    belowFloor: tier === "confirmation" ? isBelowFloor(modelId) : false,
  };
}

/** The three tier descriptors derived from the client's configured model matrix. */
export function buildDescriptors(config: MontrConfig): ModelDescriptor[] {
  const { provider, modelMatrix } = config.llm;
  return [
    descriptor(provider, modelMatrix.triage, "triage"),
    descriptor(provider, modelMatrix.default, "default"),
    descriptor(provider, modelMatrix.confirmation, "confirmation"),
  ];
}

const TIERS: readonly ModelTier[] = ["triage", "default", "confirmation"];

/** The configured tier ladder, cheapest first (E9 escalation walks this in order). */
export const TIER_ORDER: readonly ModelTier[] = TIERS;

function isTier(value: string): value is ModelTier {
  return (TIERS as readonly string[]).includes(value);
}

/**
 * The tier immediately above `tier` in {@link TIER_ORDER} (E9 dynamic
 * model-tier escalation — packages/llm-gateway/src/escalation.ts). Returns
 * `undefined` when `tier` is already the top configured tier
 * (`"confirmation"`), so a caller walking this never escalates past it.
 */
export function nextTier(tier: ModelTier): ModelTier | undefined {
  const idx = TIER_ORDER.indexOf(tier);
  if (idx === -1 || idx === TIER_ORDER.length - 1) return undefined;
  return TIER_ORDER[idx + 1];
}

/**
 * Resolve a tier or concrete model id to a descriptor. Unknown ids get a
 * synthesized descriptor (provider from config, tier inferred from rank) rather
 * than throwing — the gateway never hard-fails on a BYO model choice here.
 */
export function resolveDescriptor(
  config: MontrConfig,
  tierOrId: ModelTier | string,
): ModelDescriptor {
  const descriptors = buildDescriptors(config);
  if (isTier(tierOrId)) {
    return descriptors.find((d) => d.tier === tierOrId) ?? descriptors[1]!;
  }
  const byId = descriptors.find((d) => d.modelId === tierOrId);
  if (byId) return byId;
  return descriptor(config.llm.provider, tierOrId, inferTier(tierOrId));
}

export interface AssertModelFloorOptions {
  /** Throw `ModelBelowFloorError` instead of warning (default false → warn). */
  strict?: boolean;
  logger?: Logger;
}

/**
 * Check the configured confirmation-tier model against the floor. Returns whether
 * it is below floor. Warns (default) or throws when `strict`. A no-op when
 * `config.llm.enforceModelFloor` is false.
 */
export function assertModelFloor(config: MontrConfig, opts: AssertModelFloorOptions = {}): boolean {
  if (!config.llm.enforceModelFloor) return false;
  const modelId = config.llm.modelMatrix.confirmation;
  if (!isBelowFloor(modelId)) return false;
  const details = {
    model: modelId,
    floor: MODEL_FLOOR.confirmationTier.minModelId,
    tier: "confirmation",
  };
  if (opts.strict) {
    throw new ModelBelowFloorError(MODEL_FLOOR.confirmationTier.reason, details);
  }
  opts.logger?.warn("llm.model_below_floor", {
    ...details,
    reason: MODEL_FLOOR.confirmationTier.reason,
  });
  return true;
}
