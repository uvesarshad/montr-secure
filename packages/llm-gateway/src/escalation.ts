import type { LLMRequest, ModelTier, ResponseFormat } from "@montr/contracts";
import { nextTier } from "./models.js";

/**
 * Dynamic model-tier escalation (E9, audit finding E9 / PRD §17's cost/accuracy
 * frontier). The `triage`/`default`/`confirmation` tier machinery
 * (models.ts, `RECOMMENDED_MODEL_MATRIX`) has existed since the product's
 * first commit but nothing used it ADAPTIVELY — a layer's tier was fixed at
 * call time. This module runs cheap-model-first and escalates to the next
 * tier up when the cheap tier's response looks unreliable, bounded so cost
 * stays predictable. OFF by default (gateway.ts's `CreateGatewayOptions.escalation`
 * is `undefined` unless a caller opts in) — this module changes nothing for a
 * caller that doesn't construct the gateway with it.
 *
 * This is deliberately a DIFFERENT mechanism from retry.ts's `withRetryAndFallback`
 * (A11): fallback triggers on FAILURE/exhausted-retries and swaps to a
 * client-configured alternate MODEL; escalation triggers on a SUCCESSFUL
 * response judged low-confidence and walks up the configured TIER ladder.
 * The two compose (an escalated call still gets the full retry+fallback
 * treatment — see gateway.ts's `completeOnce`) but are never conflated.
 */

/** Which signal produced a low/high-confidence verdict, for logging. */
export type ConfidenceSource = "self_reported" | "refusal" | "unparseable_json" | "none";

export interface ConfidenceSignal {
  /** In [0,1] when a numeric confidence was derived (self-reported or mapped from a qualitative label). */
  confidence?: number;
  /** True when this response should trigger escalation. */
  low: boolean;
  source: ConfidenceSource;
}

/**
 * Escalation policy — the opt-in gateway capability (E9). Mirrors the
 * established pattern of `CreateGatewayOptions.budgetRegistry`/`fallbackModel`:
 * a constructor-level option, universal across every tier-routed call once
 * enabled, not a per-request flag (matching how `fallbackModel` applies to
 * every call, not one call at a time).
 */
export interface EscalationPolicy {
  /** Opt-in switch. Default OFF — omit this whole object to leave today's fixed-tier-per-call behavior unchanged. */
  enabled: boolean;
  /**
   * Confidence threshold below which a response is treated as low-confidence
   * and triggers escalation. Default {@link DEFAULT_CONFIDENCE_THRESHOLD}.
   */
  confidenceThreshold?: number;
  /**
   * Hard cap on escalation attempts PER `complete()` call, so cost stays
   * predictable regardless of chain length. Default
   * {@link DEFAULT_MAX_ESCALATIONS} (2 — the full triage→default→confirmation
   * ladder in today's 3-tier matrix). Escalation additionally never proceeds
   * past the top configured tier even if the cap isn't reached — see
   * `models.ts`'s `nextTier`.
   */
  maxEscalations?: number;
  /** Invoked once per escalation attempt, before it runs (logging/metrics; mirrors `ModelFallbackOptions.onFallback`). */
  onEscalate?: (fromTier: ModelTier, toTier: ModelTier, signal: ConfidenceSignal) => void;
}

export const DEFAULT_CONFIDENCE_THRESHOLD = 0.5;
export const DEFAULT_MAX_ESCALATIONS = 2;

function coerceReportedConfidence(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1) {
    return value;
  }
  if (typeof value === "string") {
    const norm = value.trim().toLowerCase();
    if (norm === "low") return 0.2;
    if (norm === "medium" || norm === "med") return 0.5;
    if (norm === "high") return 0.9;
  }
  return undefined;
}

/**
 * Look for a top-level `confidence` field in a JSON-mode response body.
 * Nothing today asks a prompt to emit this (no call site's prompt was
 * changed by this task — see docs/modules/llm-gateway.md's E9 section for
 * why), so in practice this is forward-compatible dead code until a future
 * prompt (or E4's verifier vote spread) starts emitting it — the proxy
 * signals below are what make escalation actually fire today.
 */
function extractSelfReportedConfidence(content: string): number | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return undefined;
  return coerceReportedConfidence((parsed as Record<string, unknown>)["confidence"]);
}

/**
 * Confidence-signal extraction (E9). Cheapest/most-reliable signal first:
 *
 * 1. Self-reported confidence — a top-level `confidence` field (number
 *    [0,1], or "low"/"medium"/"high") in a JSON-mode response body.
 * 2. Proxy signals (no prompt cooperation required, work today with zero
 *    changes to any call site's prompt):
 *    - `stopReason === "refusal"` — the model explicitly declined to answer
 *      definitively (already a first-class `StopReasonSchema` value).
 *    - a JSON-mode response whose body fails `JSON.parse` — an "uncertain"/
 *      malformed response from the (typically cheaper) tier. Related to but
 *      logged separately from `gateway.ts`'s existing
 *      `llm_gateway.response_parse_failure` metric (A13).
 *
 * Deliberately NOT a new REQUIRED schema field every prompt must emit: that
 * would mean editing packages/discovery, packages/correlation, and
 * packages/confirm's prompts, all out of scope for this change (and, per
 * A10's "built but unwired" lesson, editing a prompt is not enough on its
 * own — the model has to reliably comply). Self-reported confidence is read
 * opportunistically for forward-compatibility; the proxy signals need no
 * prompt cooperation at all, so escalation is exercisable today against
 * triage's existing hand-written prompt (`packages/discovery/src/triage.ts`,
 * unmodified by this change) purely from `stopReason` and JSON-parseability.
 */
export function evaluateConfidence(
  responseFormat: ResponseFormat,
  content: string,
  stopReason: string,
  threshold: number,
): ConfidenceSignal {
  if (responseFormat === "json") {
    const reported = extractSelfReportedConfidence(content);
    if (reported !== undefined) {
      return { confidence: reported, low: reported < threshold, source: "self_reported" };
    }
  }
  if (stopReason === "refusal") {
    return { low: true, source: "refusal" };
  }
  if (responseFormat === "json") {
    try {
      JSON.parse(content);
    } catch {
      return { low: true, source: "unparseable_json" };
    }
  }
  return { low: false, source: "none" };
}

/**
 * Whether `request` is eligible for tier escalation: it must have resolved
 * via an explicit `tier` (the caller opted into tier-based routing, e.g.
 * `triage.ts`'s `{ tier: "triage" }`), and NOT a pinned `model` — escalating
 * a caller's explicit model choice would silently override it, which is not
 * what "escalate the cheap tier" means.
 */
export function isEligibleForEscalation(request: Pick<LLMRequest, "tier" | "model">): boolean {
  return request.tier !== undefined && request.model === undefined;
}

/** Build the escalated request: identical payload, tier bumped, model left unset. */
export function withEscalatedTier(request: LLMRequest, tier: ModelTier): LLMRequest {
  return { ...request, tier, model: undefined };
}

export { nextTier };
