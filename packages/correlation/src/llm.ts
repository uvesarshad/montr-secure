/**
 * The semantic reachability/exposure reasoning step — the ONE place Layer 2
 * calls the LLM (via @montr/llm-gateway). It is grounded strictly in the
 * deterministic App Map facts: the prompt carries STRUCTURED metadata only
 * (categories, route auth state, source/sink KINDS, scores) — never code bodies
 * (golden rule #1). The LLM may refine the hypotheses and NUDGE reachability /
 * impact within a bounded delta; it can never change route existence, exposure,
 * or whether a finding is demoted — those stay owned by the App Map.
 */
import type { CandidateFinding, LLMRequest } from "@montr/contracts";
import type { Grounding } from "./grounding.js";
import type { ScoreTriple } from "./scoring.js";
import { clamp01 } from "./scoring.js";

/** Structured, code-free facts handed to the LLM for correlation reasoning. */
export interface CorrelationFacts {
  category: string;
  tools: { source: string; ruleId: string }[];
  route: { path: string; method: string; authState: string; authGate?: string } | null;
  exposure: string;
  taintSourceKind: string | null;
  taintSinkKind: string | null;
  sanitizerInterrupts: boolean;
  taintReaches: boolean;
  location: { file: string; line: number };
  deterministic: ScoreTriple & {
    reachabilityHypothesis: string;
    exploitHypothesis: string;
  };
}

const SYSTEM_PROMPT =
  "You are the correlation-reasoning step of a security scanner. You receive STRUCTURED App Map facts (never source code). " +
  "Ground every judgment ONLY in those facts; never invent routes, sinks, or auth states. " +
  "Return STRICT JSON with keys: reachabilityScore (0-1), impactScore (0-1), reachabilityHypothesis (string), exploitHypothesis (string). " +
  "Do not include any source code in your response.";

export function buildCorrelationFacts(
  representative: CandidateFinding,
  members: CandidateFinding[],
  g: Grounding,
  base: ScoreTriple & { reachabilityHypothesis: string; exploitHypothesis: string },
): CorrelationFacts {
  return {
    category: representative.category,
    tools: members.map((m) => ({ source: m.source, ruleId: m.ruleId })),
    route: g.route
      ? {
          path: g.route.path,
          method: g.route.method,
          authState: g.route.authState,
          ...(g.authGate ? { authGate: g.authGate } : {}),
        }
      : null,
    exposure: g.exposure,
    taintSourceKind: g.matchedSource?.kind ?? null,
    taintSinkKind: g.matchedSink?.kind ?? null,
    sanitizerInterrupts: g.sanitizerInterrupts,
    taintReaches: g.taintReaches,
    location: { file: representative.location.file, line: representative.location.line },
    deterministic: base,
  };
}

export function buildCorrelationRequest(
  facts: CorrelationFacts,
  meta: { scanId: string; clientId: string },
): LLMRequest {
  return {
    tier: "default",
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: JSON.stringify(facts) }],
    maxTokens: 512,
    temperature: 0,
    responseFormat: "json",
    stream: false,
    metadata: {
      scanId: meta.scanId,
      clientId: meta.clientId,
      layer: "layer2",
      purpose: "correlation",
    },
  };
}

export interface ParsedCorrelation {
  reachabilityScore?: number;
  impactScore?: number;
  reachabilityHypothesis?: string;
  exploitHypothesis?: string;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim().length > 0 ? v : undefined;
}

/**
 * Parse the model's JSON safely. Any malformed/unexpected shape yields `null`
 * and the caller falls back to the deterministic result (fail-safe).
 */
export function parseCorrelationResponse(content: string): ParsedCorrelation | null {
  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  const parsed: ParsedCorrelation = {
    reachabilityScore: num(obj["reachabilityScore"]),
    impactScore: num(obj["impactScore"]),
    // Accept both a dedicated field and the fixture's generic "hypothesis".
    reachabilityHypothesis: str(obj["reachabilityHypothesis"]) ?? str(obj["hypothesis"]),
    exploitHypothesis: str(obj["exploitHypothesis"]),
  };
  const hasSignal =
    parsed.reachabilityScore !== undefined ||
    parsed.impactScore !== undefined ||
    parsed.reachabilityHypothesis !== undefined ||
    parsed.exploitHypothesis !== undefined;
  return hasSignal ? parsed : null;
}

/**
 * Blend an LLM score into the deterministic base within ±maxDelta at `trust`.
 * The deterministic value dominates; the model can only nudge, never override.
 */
export function blendScore(
  base: number,
  llm: number | undefined,
  trust: number,
  maxDelta: number,
): number {
  if (llm === undefined) return base;
  const bounded = Math.min(maxDelta, Math.max(-maxDelta, llm - base));
  return clamp01(base + bounded * trust);
}
