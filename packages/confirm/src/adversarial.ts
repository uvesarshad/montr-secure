/**
 * E4 — multi-agent adversarial confirmation.
 *
 * Wraps a "candidate for confirmed" finding — one that has ALREADY cleared
 * either the deterministic static proof, a live-DAST transcript, or E1's
 * investigation loop plus E2's executable-evidence gate — in N independent
 * verifier calls, each reasoning from a DISTINCT lens, one of which is
 * explicitly instructed to try to REFUTE the finding. A strict majority is
 * required before the wrapped candidate is allowed to become genuinely
 * `confirmed: true`.
 *
 * This is deliberately a SEPARATE gate from E2's executable-evidence
 * requirement, not a substitute for it — `confirm.ts` requires BOTH for the
 * investigation-originated path (see that file's header comment for the full
 * three-path invariant). Cost is bounded exactly like every other gateway
 * call: each verifier issues exactly one `gateway.complete()` call, which
 * inherits the existing A2 pre-call budget guard; N is capped at the number
 * of defined lenses (4) so this can never silently balloon.
 */
import type { LLMRequest, LLMResponse } from "@montr/contracts";
import type { ConfirmDeps, ConfirmInput } from "./types.js";

export type VerifierLens = "exploitability" | "reachability" | "business_impact" | "refutation";

/**
 * Fixed lens order — verifiers always run in this order so a `verifierCount`
 * override picks a stable, deterministic PREFIX of lenses, never a random
 * subset. `refutation` runs LAST deliberately: it is given the other three
 * lenses' rationale as read-only context, so its "try to tear this down" pass
 * is genuinely adversarial against the strongest case already built, not
 * against a blank slate.
 */
const LENS_ORDER: readonly VerifierLens[] = [
  "exploitability",
  "reachability",
  "business_impact",
  "refutation",
];

const LENS_SYSTEM_PROMPT: Record<VerifierLens, string> = {
  exploitability:
    "You are an independent EXPLOITABILITY verifier. Judge ONLY whether the described flow, if reached by an " +
    'attacker, is genuinely exploitable (not just theoretically reachable). Respond ONLY as JSON {"confirm": boolean, "rationale": string}. When uncertain, confirm=false (fail-safe).',
  reachability:
    "You are an independent REACHABILITY verifier. Judge ONLY whether an attacker (authenticated or not, per the " +
    'stated exposure) can actually reach this code path given the route/auth information provided. Respond ONLY as JSON {"confirm": boolean, "rationale": string}. When uncertain, confirm=false (fail-safe).',
  business_impact:
    "You are an independent BUSINESS-IMPACT verifier. Judge ONLY whether a successful exploit would have a " +
    'material security impact (data exposure, integrity loss, availability loss, or privilege escalation) — not whether it is merely a code-quality issue. Respond ONLY as JSON {"confirm": boolean, "rationale": string}. When uncertain, confirm=false (fail-safe).',
  refutation:
    "You are an independent, ADVERSARIAL verifier whose ONLY job is to try to REFUTE this finding — actively look " +
    "for a sanitizer, an ownership/authorization check, a framework default, or any other reason this is a false " +
    'positive, using the evidence and the other verifiers’ rationale below. Respond ONLY as JSON {"confirm": boolean, "rationale": string} — confirm=true ONLY if you tried and genuinely could not refute it; otherwise confirm=false.',
};

export interface VerifierVerdict {
  lens: VerifierLens;
  /** True when this verifier's call could not be completed/parsed — always counted as a reject vote. */
  errored?: boolean;
  confirm: boolean;
  rationale: string;
}

export interface AdversarialOutcome {
  confirmed: boolean;
  verdicts: VerifierVerdict[];
  confirmVotes: number;
  totalVerifiers: number;
  /** Strict majority: floor(totalVerifiers / 2) + 1. */
  requiredVotes: number;
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(Math.max(n, min), max);
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * A17: explicit schema for this verifier's own `{confirm, rationale}` reply
 * shape. Without this, `metadata.purpose: "confirmation"` would resolve
 * `packages/llm-gateway/src/structured-output.ts`'s PURPOSE_JSON_SCHEMAS
 * default for that purpose instead — `confirm/src/static.ts`'s DIFFERENT
 * `{confirmed, argument}` contract, which this file's own lenses never ask
 * for. Under real provider-side schema-constrained decoding that mismatched
 * default's `additionalProperties: false` would silently strip `confirm`/
 * `rationale` from every real response, so `rec.confirm`/`rec.rationale`
 * below would always read `undefined` and every verifier would vote reject
 * — a live bug the fake-gateway-backed tests can't see, since a hand-mocked
 * `complete()` returns canned content directly and never passes through the
 * gateway's schema-constrained wire path. `request.responseSchema` (checked
 * before the purpose-keyed default — see `resolveStructuredOutputSchema`)
 * overrides it with this call site's own real shape.
 */
const VERIFIER_RESPONSE_SCHEMA: Record<string, unknown> = {
  type: "object",
  properties: {
    confirm: { type: "boolean" },
    rationale: { type: "string" },
  },
  required: [],
  additionalProperties: false,
};

interface VerificationPayload {
  category: string;
  exposure: string;
  location: { file: string; line: number };
  candidateRationale: string;
  evidenceSummary: string;
  priorVerdicts: Array<{ lens: VerifierLens; confirm: boolean; rationale: string }>;
}

async function runOneVerifier(
  llm: NonNullable<ConfirmDeps["llm"]>,
  input: ConfirmInput,
  lens: VerifierLens,
  payload: VerificationPayload,
  findingId: string,
): Promise<VerifierVerdict> {
  const request: LLMRequest = {
    tier: "confirmation",
    system: LENS_SYSTEM_PROMPT[lens],
    messages: [{ role: "user", content: JSON.stringify(payload) }],
    maxTokens: 1024,
    temperature: 0,
    responseFormat: "json",
    responseSchema: VERIFIER_RESPONSE_SCHEMA,
    stream: false,
    metadata: {
      scanId: input.scanId,
      clientId: input.clientId,
      layer: "layer3",
      purpose: "confirmation",
    },
  };
  let resp: LLMResponse;
  try {
    resp = await llm.complete(request);
  } catch (err) {
    return {
      lens,
      errored: true,
      confirm: false, // a verifier that can't run is a reject vote — never a silent confirm.
      rationale: `verifier call failed for finding ${findingId}: ${errMessage(err)} (fail-safe reject).`,
    };
  }
  const parsed = safeJson(resp.content);
  if (!parsed || typeof parsed !== "object") {
    return {
      lens,
      errored: true,
      confirm: false,
      rationale: "verifier response was not valid JSON (fail-safe reject).",
    };
  }
  const rec = parsed as Record<string, unknown>;
  const confirm = rec.confirm === true;
  const rationale =
    typeof rec.rationale === "string" && rec.rationale.trim().length > 0
      ? rec.rationale.trim()
      : "(no rationale provided)";
  return { lens, confirm, rationale };
}

/**
 * Run the adversarial verifier panel. Returns `undefined` when no `deps.llm`
 * is configured (this gate structurally cannot run without one — the caller
 * treats that exactly like "not confirmed"). Verifiers run SEQUENTIALLY
 * (never in parallel) so `refutation`'s prompt can see the other three
 * lenses' actual rationale, and so N gateway calls stay easy to reason about
 * against the per-scan budget one at a time.
 */
export async function runAdversarialVerification(
  deps: ConfirmDeps,
  input: ConfirmInput,
  finding: {
    id: string;
    category: string;
    exposure: string;
    location: { file: string; line: number };
  },
  candidateRationale: string,
  evidenceSummary: string,
): Promise<AdversarialOutcome | undefined> {
  const llm = deps.llm;
  if (!llm) return undefined;

  const count = clamp(deps.investigation?.verifierCount ?? LENS_ORDER.length, 1, LENS_ORDER.length);
  const lenses = LENS_ORDER.slice(0, count);
  const verdicts: VerifierVerdict[] = [];

  for (const lens of lenses) {
    const payload: VerificationPayload = {
      category: finding.category,
      exposure: finding.exposure,
      location: finding.location,
      candidateRationale,
      evidenceSummary,
      priorVerdicts: verdicts.map((v) => ({
        lens: v.lens,
        confirm: v.confirm,
        rationale: v.rationale,
      })),
    };
    // Deliberately sequential (not Promise.all) — see the doc comment above.
    const verdict = await runOneVerifier(llm, input, lens, payload, finding.id);
    verdicts.push(verdict);
  }

  const confirmVotes = verdicts.filter((v) => v.confirm).length;
  const requiredVotes = Math.floor(lenses.length / 2) + 1;
  return {
    confirmed: lenses.length > 0 && confirmVotes >= requiredVotes,
    verdicts,
    confirmVotes,
    totalVerifiers: lenses.length,
    requiredVotes,
  };
}
