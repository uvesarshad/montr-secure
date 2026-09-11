/**
 * A18 (2026-09-12 red/blue agentic-posture audit) — the optional, injected
 * executive-narrative generator. This is `@montr/report`'s FIRST real
 * `@montr/llm-gateway` consumer: every other Layer 5 output
 * (`report-builder.ts`, `headline.ts`, the compliance/detection-rule/
 * attack-path/threat-model/hardening sections) is template-assembled from
 * already-structured data, deliberately deterministic and free.
 *
 * ⛔ This module is NEVER imported by `report-builder.ts` — `buildReport`
 * stays pure/offline, exactly as its own header comment promises. The
 * `LLMGateway` is an OPTIONAL, INJECTED capability the CALLER supplies,
 * mirroring `packages/confirm/src/types.ts`'s `ConfirmDeps.llm?: LLMGateway`
 * and `packages/discovery/src/triage.ts`'s "skip when no gateway is
 * provided" precedent — never a concrete `@montr/llm-gateway` import here
 * (this package does not, and must not, depend on that package; only the
 * `LLMGateway` TYPE from `@montr/contracts`, same as every other real call
 * site). `apps/worker/src/runners.ts`'s Layer 5 runner is the sole real
 * caller: it runs `buildReport` first, then — only when
 * `reporting.executiveSummary.enabled` is true AND a gateway is configured —
 * calls {@link generateExecutiveSummary} against the just-built `Report` and
 * attaches the result at `Report.generatedExecutiveSummary` before
 * persisting/returning. Disabled or no gateway ⇒ the field is simply absent,
 * zero behavior change.
 *
 * Budget: this issues exactly one `gateway.complete()` call using the SAME
 * `LLMGateway` instance the rest of the scan uses (`opts.gateway` in
 * `runners.ts`, never a separately constructed one), so it automatically
 * flows through the existing pre-call budget hard-halt guard
 * (`packages/llm-gateway/src/gateway.ts`'s `assertPreCallBudget`) with no
 * additional wiring.
 *
 * ⛔ NO CODE EGRESS: the prompt payload is built ONLY from fields already
 * present on the deterministic `Report` (counts, categories, severities,
 * blue-team section sizes, cost/budget rollup) — never source snippets,
 * proof artifacts, or raw evidence (golden rule #1, mirrors
 * `packages/discovery/src/triage.ts`'s "metadata-grade payload only").
 *
 * Fail-safe: any gateway error or an unusable/malformed reply returns
 * `undefined` — the deterministic report ships unchanged, exactly like
 * `packages/appmap/src/llm.ts`'s `labelAuthBoundaries` and
 * `packages/discovery/src/triage.ts`'s `triageCandidates`.
 */
import type { LLMGateway, LLMRequest, Report } from "@montr/contracts";
import { GeneratedExecutiveSummarySchema, type GeneratedExecutiveSummary } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";

export interface GenerateExecutiveSummaryOptions {
  /** The scan's real, shared gateway instance — see this file's header. */
  gateway: LLMGateway;
  scanId: string;
  clientId: string;
  logger?: Logger;
  maxTokens?: number;
  /** Deterministic ISO clock (tests). Default: wall-clock. */
  now?: () => string;
}

const SYSTEM_PROMPT =
  "You write a short executive narrative summarizing a completed security scan for a " +
  "non-technical stakeholder, from structured rollup data you are given (counts, " +
  "categories, severities, cost). You DO NOT have access to source code, raw findings, " +
  "or exploit evidence, and must NEVER invent counts, finding ids, or categories not " +
  "present in the data. Never contradict or restate raw candidate counts — this is a " +
  "narrative gloss on ALREADY-CONFIRMED findings only. Reply ONLY as JSON: " +
  '{"narrative": "<2-4 sentence prose summary>", "topPriorities": ["<short advisory ' +
  'bullet>", ...]} — topPriorities is at most 5 short, actionable sentences, or an ' +
  "empty array when there is nothing confirmed to prioritize.";

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Top categories among confirmed findings, most frequent first (metadata only). */
function topCategories(report: Report): Array<{ category: string; count: number }> {
  const counts = new Map<string, number>();
  for (const rf of report.confirmedFindings) {
    counts.set(rf.finding.category, (counts.get(rf.finding.category) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([category, count]) => ({ category, count }));
}

/**
 * Structural rollup payload — every field already exists somewhere on the
 * deterministic `Report`; nothing here is re-derived or guessed.
 */
function buildPayload(report: Report) {
  const cost = report.costAndScope.cost;
  return {
    totalConfirmed: report.executiveSummary.totalConfirmed,
    confirmedBySeverity: report.executiveSummary.confirmedBySeverity,
    topCategories: topCategories(report),
    postureDelta: report.executiveSummary.postureDelta ?? null,
    toolsConsolidated: report.executiveSummary.toolsConsolidated,
    unconfirmedAppendixCount: report.unconfirmedAppendix.length,
    fixStatus: {
      autoEligible: report.fixStatus.autoEligibleFixIds.length,
      humanRequired: report.fixStatus.humanRequiredFixIds.length,
      pullRequestsOpened: report.fixStatus.pullRequests.length,
    },
    blueTeam: {
      attackPathCount: report.blueTeam.attackPaths.length,
      mitreTechniquesCovered: report.blueTeam.mitreAttack.coverage.length,
      detectionRuleCount: report.blueTeam.detectionEngineering.rules.length,
      threatModelPresent: report.blueTeam.threatModel.present,
      purpleTeam: {
        totalScenarios: report.blueTeam.purpleTeam.totalScenarios,
        detected: report.blueTeam.purpleTeam.detectedCount,
        undetected: report.blueTeam.purpleTeam.undetectedCount,
      },
    },
    cost: {
      estimatedUsd: cost.estimate.projectedUsd,
      actualUsd: cost.actual?.actualUsd ?? null,
    },
  };
}

interface ParsedContent {
  narrative: string;
  topPriorities: string[];
}

/**
 * Decode the schema-constrained reply. Since `metadata.purpose:
 * "executive_summary"` resolves a real JSON schema (see
 * `packages/llm-gateway/src/structured-output.ts`'s `PURPOSE_JSON_SCHEMAS`)
 * on every provider with real structured-output support, this is a plain
 * parse-and-shape-check — no defensive multi-shape coercion needed (A17's
 * lesson: the schema already rules out every other shape).
 */
function parseContent(content: string): ParsedContent | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const rec = parsed as Record<string, unknown>;
  if (typeof rec["narrative"] !== "string" || rec["narrative"].trim().length === 0) return null;
  const topPriorities = Array.isArray(rec["topPriorities"])
    ? rec["topPriorities"].filter((p): p is string => typeof p === "string" && p.trim().length > 0)
    : [];
  return { narrative: rec["narrative"], topPriorities };
}

/**
 * Generate the optional AI narrative on top of an already-built,
 * schema-valid `Report`. Returns `undefined` on any gateway error or
 * unusable reply (fail-safe — never throws, never blocks Layer 5).
 */
export async function generateExecutiveSummary(
  report: Report,
  opts: GenerateExecutiveSummaryOptions,
): Promise<GeneratedExecutiveSummary | undefined> {
  const payload = buildPayload(report);

  // Prompt registry (§8.2, §15): resolve the DB-versioned template for this
  // prompt name when one is active; otherwise SYSTEM_PROMPT above is used
  // unchanged (resolvePrompt's own fallback contract).
  const system =
    (await opts.gateway.resolvePrompt?.("report.executive_summary.system", SYSTEM_PROMPT, {
      clientId: opts.clientId,
    })) ?? SYSTEM_PROMPT;

  const request: LLMRequest = {
    tier: "default",
    system,
    messages: [{ role: "user", content: JSON.stringify(payload) }],
    maxTokens: opts.maxTokens ?? 1024,
    temperature: 0.3,
    responseFormat: "json",
    stream: false,
    metadata: {
      scanId: opts.scanId,
      clientId: opts.clientId,
      layer: "layer5",
      purpose: "executive_summary",
    },
  };

  let content: string;
  let model: string;
  let provider: string;
  try {
    const response = await opts.gateway.complete(request);
    content = response.content;
    model = response.model;
    provider = response.provider;
  } catch (err) {
    opts.logger?.warn("report.executive_summary.failed", {
      scanId: opts.scanId,
      reason: errMessage(err),
    });
    return undefined;
  }

  const parsed = parseContent(content);
  if (!parsed) {
    opts.logger?.warn("report.executive_summary.unusable", { scanId: opts.scanId });
    return undefined;
  }

  return GeneratedExecutiveSummarySchema.parse({
    narrative: parsed.narrative,
    topPriorities: parsed.topPriorities,
    generatedAt: (opts.now ?? (() => new Date().toISOString()))(),
    model,
    provider,
  });
}
