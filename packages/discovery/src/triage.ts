/**
 * OPTIONAL LLM triage/explain pass (§5.2). ⛔ The LLM does NOT detect — Semgrep,
 * gitleaks, the custom detectors, and the SCA matcher already produced every
 * candidate. Triage only ANNOTATES them (keep/reason), and only through
 * @montr/llm-gateway — the single sanctioned egress path, which logs call
 * METADATA ONLY (golden rule #1). Precondition: the App Map exists (it is a
 * required input to discovery, so "no LLM before the map" holds, golden rule #6).
 *
 * Degrades to the untouched candidates on any gateway/parse failure — the
 * deterministic pile is never lost because the LLM was unavailable.
 */
import type { CandidateFinding, LLMGateway, LLMRequest } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";
import { errMessage } from "./util/text.js";

export interface TriageOptions {
  gateway: LLMGateway;
  scanId: string;
  clientId: string;
  logger?: Logger;
  maxTokens?: number;
}

interface TriageVerdict {
  keep?: boolean;
  reason?: string;
}

const TRIAGE_SYSTEM =
  "You are a security triage assistant. You DO NOT find new issues; deterministic scanners already produced the candidates. " +
  "For each candidate, judge whether it looks like a true positive and give a one-line reason. " +
  'Reply ONLY as JSON: {"items":[{"i":<index>,"keep":<boolean>,"reason":"<short>"}]}.';

function coerceVerdict(v: unknown): TriageVerdict | null {
  if (!v || typeof v !== "object") return null;
  const rec = v as Record<string, unknown>;
  const keep = typeof rec["keep"] === "boolean" ? (rec["keep"] as boolean) : undefined;
  const reason = typeof rec["reason"] === "string" ? (rec["reason"] as string) : undefined;
  if (keep === undefined && reason === undefined) return null;
  return { keep, reason };
}

/**
 * Parse a triage response into a per-index map plus an optional single verdict
 * applied to all candidates (the shape the fake adapter returns).
 */
export function parseTriage(content: string): {
  byIndex: Map<number, TriageVerdict>;
  shared: TriageVerdict | null;
} {
  const byIndex = new Map<number, TriageVerdict>();
  let shared: TriageVerdict | null = null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { byIndex, shared };
  }
  const items = Array.isArray(parsed)
    ? parsed
    : Array.isArray((parsed as Record<string, unknown>)?.["items"])
      ? ((parsed as Record<string, unknown>)["items"] as unknown[])
      : null;
  if (items) {
    for (const raw of items) {
      const rec = raw as Record<string, unknown>;
      const verdict = coerceVerdict(rec);
      const i = typeof rec?.["i"] === "number" ? (rec["i"] as number) : undefined;
      if (verdict && i !== undefined) byIndex.set(i, verdict);
    }
  } else {
    shared = coerceVerdict(parsed);
  }
  return { byIndex, shared };
}

/** Annotate candidates with LLM triage verdicts. Never adds/removes candidates. */
export async function triageCandidates(
  candidates: CandidateFinding[],
  opts: TriageOptions,
): Promise<CandidateFinding[]> {
  if (candidates.length === 0) return candidates;

  // Metadata-grade payload only — rule/category/location + the already-short,
  // already-redacted snippet. Whole file bodies are NEVER sent.
  const items = candidates.map((c, i) => ({
    i,
    ruleId: c.ruleId,
    category: c.category,
    severity: c.rawSeverity,
    file: c.location.file,
    line: c.location.line,
    snippet: c.evidenceSnippet,
  }));

  const request: LLMRequest = {
    tier: "triage",
    system: TRIAGE_SYSTEM,
    messages: [{ role: "user", content: JSON.stringify({ candidates: items }) }],
    maxTokens: opts.maxTokens ?? 1024,
    responseFormat: "json",
    stream: false,
    metadata: {
      scanId: opts.scanId,
      clientId: opts.clientId,
      layer: "layer1",
      purpose: "triage",
    },
  };

  let content: string;
  try {
    const res = await opts.gateway.complete(request);
    content = res.content;
  } catch (err) {
    opts.logger?.warn("discovery.triage.failed", { reason: errMessage(err) });
    return candidates;
  }

  const { byIndex, shared } = parseTriage(content);
  if (byIndex.size === 0 && !shared) return candidates;

  return candidates.map((c, i) => {
    const verdict = byIndex.get(i) ?? shared;
    if (!verdict) return c;
    return {
      ...c,
      metadata: {
        ...(c.metadata ?? {}),
        triage: {
          keep: verdict.keep ?? true,
          ...(verdict.reason ? { reason: verdict.reason } : {}),
        },
      },
    };
  });
}
