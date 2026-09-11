/**
 * E1 — Agentic investigation loop for Layer 3.
 *
 * Where `static.ts`'s `runLlmReview` hands the model pre-chewed metadata and
 * gets back a yes/no veto, this loop hands the model READ-ONLY repo tools
 * (`investigate-tools.ts`) and lets it actually trace a probable finding
 * across files — read the handler, follow the query, look for the
 * ownership/role check (or its absence) — before it concludes anything. This
 * is what a single 2-4k-token metadata call structurally cannot do, and is
 * the mechanism the audit identifies as the one that can lift IDOR and broken
 * access control off 0% recall (neither category has a static data-flow
 * proof at all — see `taxonomy.ts`'s `DATAFLOW_SINK_KINDS`).
 *
 * ⛔ Golden invariant (unchanged from golden rule #4, extended here): reaching
 * `verdict: "confirmed_candidate"` here NEVER by itself confirms a finding.
 * It only produces a CANDIDATE that `confirm.ts` then requires to clear TWO
 * more independent gates before it is ever marked `confirmed: true`:
 *   1. E2 — executable evidence (`evidence.ts`): a real failing test found in
 *      the target repo, or a successful live-DAST probe.
 *   2. E4 — adversarial majority (`adversarial.ts`): N independent verifier
 *      calls with distinct lenses, including one instructed to actively try
 *      to REFUTE the finding.
 * Budget exhaustion (the turn cap below) is treated as `inconclusive`, never
 * as a confirmation — fail-safe, matching this codebase's demote-only-by-
 * default discipline (A7).
 */
import {
  KillSwitchActivatedError,
  type LLMMessage,
  type LLMRequest,
  type LLMResponse,
  type ProbableFinding,
} from "@montr/contracts";
import {
  INVESTIGATION_TOOL_DEFINITIONS,
  SUBMIT_CONCLUSION_TOOL,
  executeInvestigationTool,
  type InvestigationToolContext,
} from "./investigate-tools.js";
import type { ConfirmDeps, ConfirmInput } from "./types.js";

/**
 * Soft default — overridable per call via `ConfirmDeps.investigation.maxTurns`.
 * Exported so `investigation-pipeline.ts`'s A11 per-finding effort scaling has
 * a single source of truth for "the configured budget" instead of duplicating
 * the constant.
 */
export const DEFAULT_MAX_TURNS = 6;
/**
 * Hard structural ceiling on tool-call turns, enforced UNCONDITIONALLY
 * regardless of any override. This is independent of, and additive to, the
 * A2 per-call budget guard already wired into `gateway.complete()` — that
 * guard bounds a single call's cost; this bounds the LOOP ITSELF from ever
 * issuing more than 8 confirmation-tier calls for one finding, so a
 * misbehaving model (or a bug that keeps returning tool calls) cannot turn
 * one finding into an unbounded, budget-draining loop.
 */
const ABSOLUTE_MAX_INVESTIGATION_TURNS = 8;
/** Bounded fan-out: at most this many tool calls executed per model turn. */
const MAX_TOOL_CALLS_PER_TURN = 4;

export type InvestigationVerdict = "confirmed_candidate" | "refuted" | "inconclusive";

export interface InvestigationToolCallRecord {
  id: string;
  name: string;
  input: Record<string, unknown>;
  result: string;
}

export interface InvestigationTurn {
  turn: number;
  responseText?: string;
  toolCalls: InvestigationToolCallRecord[];
}

export interface InvestigationOutcome {
  verdict: InvestigationVerdict;
  rationale: string;
  ownershipCheckFound?: boolean;
  /** A repo-relative path to a REAL existing test the model claims exercises this path (E2 evidence candidate). */
  existingTestFile?: string;
  targetRouteId?: string;
  turns: InvestigationTurn[];
  turnsUsed: number;
  toolCallCount: number;
  /** True when the loop ended because the turn budget was exhausted (⇒ verdict is always "inconclusive"). */
  haltedByBudget: boolean;
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function summarizeRoute(input: ConfirmInput, finding: ProbableFinding): string {
  const route =
    (finding.routeId ? input.appMap.routes.find((r) => r.id === finding.routeId) : undefined) ??
    input.appMap.routes.find((r) => r.handler?.file === finding.location.file);
  if (!route) return "no route matched in the App Map for this finding's file.";
  const models = route.referencedModels?.length
    ? route.referencedModels
        .map((m) => `${m.modelName}(${m.operations.join("/") || "?"})`)
        .join(", ")
    : "none resolved by the App Map";
  return (
    `Route ${route.method} ${route.path} (id: ${route.id ?? "unknown"}); authState=${route.authState}` +
    `${route.authGate ? `; authGate=${route.authGate}` : ""}; handler=${
      route.handler ? `${route.handler.file}:${route.handler.line}` : "unknown"
    }; referencedModels=[${models}].`
  );
}

const INVESTIGATION_SYSTEM_PROMPT = [
  "You are a security exploit-confirmation INVESTIGATOR for Montr Secure's Layer 3.",
  "You have READ-ONLY tools to inspect the target repository and its already-built App Map:",
  "read_file, grep, find_definition, query_call_graph, list_routes, get_orm_model, semantic_search.",
  "semantic_search retrieves code by MEANING (a description or a snippet) rather than literal text — use it",
  "alongside grep to find other places the same vulnerable pattern occurs, or when you don't know the exact",
  "symbol/string to grep for; it may be unavailable in this run, in which case fall back to grep.",
  "Use them to trace the actual data flow and check for an ownership/role/authorization check — do not guess.",
  "You can NEVER write, execute, or modify anything; your job is investigation only.",
  'Be conservative: only conclude "confirmed_candidate" when you found a concrete exploit path AND actively',
  "looked for (and did not find) an ownership/authorization check that would prevent it. If you found such a",
  'check, conclude "refuted". If you cannot determine either way within your tool budget, conclude',
  '"inconclusive" — never guess "confirmed_candidate" out of uncertainty (fail-safe).',
  "When you are done, call submit_conclusion EXACTLY ONCE with your verdict, rationale, and — if applicable —",
  "whether you found an ownership check, a real existing test file (found via grep/read_file, never invented)",
  "that already exercises this exact path, and the route id.",
  'Note: "confirmed_candidate" here is NOT sufficient to confirm this finding by itself — it becomes a',
  "candidate that must still pass an executable-evidence check and independent adversarial verification.",
].join(" ");

function buildInvestigationUserPrompt(
  input: ConfirmInput,
  finding: ProbableFinding,
  priorStaticReason: string | undefined,
): string {
  return JSON.stringify({
    task: "Investigate whether this probable finding is a genuine, exploitable vulnerability. Use your tools to read the actual code before concluding anything.",
    category: finding.category,
    exposure: finding.exposure,
    location: finding.location,
    reachabilityHypothesis: finding.reachabilityHypothesis,
    exploitHypothesis: finding.exploitHypothesis,
    route: summarizeRoute(input, finding),
    priorStaticAssessment:
      priorStaticReason ??
      "no static source→sink data-flow proof exists for this category — this is exactly the class of finding that needs real investigation, not pattern-matching.",
  });
}

type PartialOutcome = Pick<
  InvestigationOutcome,
  "verdict" | "rationale" | "ownershipCheckFound" | "existingTestFile" | "targetRouteId"
>;

function asVerdict(v: unknown): InvestigationVerdict {
  return v === "confirmed_candidate" || v === "refuted" ? v : "inconclusive";
}

function parseConclusion(rawInput: Record<string, unknown>): PartialOutcome {
  const verdict = asVerdict(rawInput.verdict);
  const rationale =
    typeof rawInput.rationale === "string" && rawInput.rationale.trim().length > 0
      ? rawInput.rationale.trim()
      : "model submitted a conclusion with no rationale text.";
  const out: PartialOutcome = { verdict, rationale };
  if (typeof rawInput.ownershipCheckFound === "boolean")
    out.ownershipCheckFound = rawInput.ownershipCheckFound;
  if (
    typeof rawInput.existingTestFile === "string" &&
    rawInput.existingTestFile.trim().length > 0
  ) {
    out.existingTestFile = rawInput.existingTestFile.trim();
  }
  if (typeof rawInput.targetRouteId === "string" && rawInput.targetRouteId.trim().length > 0) {
    out.targetRouteId = rawInput.targetRouteId.trim();
  }
  return out;
}

/** Fallback for a model that answered in prose/JSON instead of calling `submit_conclusion`. */
function tryParseFreeformConclusion(content: string): PartialOutcome | undefined {
  try {
    const parsed: unknown = JSON.parse(content);
    if (parsed && typeof parsed === "object" && "verdict" in parsed) {
      return parseConclusion(parsed as Record<string, unknown>);
    }
  } catch {
    /* not JSON — no freeform conclusion available */
  }
  return undefined;
}

/**
 * E10 — human-readable, per-turn progress narrative for `ConfirmDeps.emitProgress`.
 * Derived from the actual tool call(s) about to run/being submitted this turn,
 * never a generic placeholder (e.g. "Reading packages/api/routes/scans.ts...").
 */
function describeToolCall(call: { name: string; input: Record<string, unknown> }): string {
  const input = call.input ?? {};
  switch (call.name) {
    case "read_file": {
      const path = typeof input.path === "string" ? input.path : "a file";
      return `Reading ${path}...`;
    }
    case "grep": {
      const pattern = typeof input.pattern === "string" ? input.pattern : "a pattern";
      return `Searching the repo for "${pattern}"...`;
    }
    case "find_definition": {
      const symbol = typeof input.symbol === "string" ? input.symbol : "a symbol";
      return `Finding the definition of ${symbol}...`;
    }
    case "query_call_graph": {
      const file = typeof input.file === "string" ? input.file : "the code";
      return `Checking the call graph for ${file}...`;
    }
    case "semantic_search": {
      const query = typeof input.query === "string" ? input.query : "similar code";
      return `Searching the semantic code index for "${query}"...`;
    }
    case "list_routes":
      return "Listing App Map routes...";
    case "get_orm_model": {
      const name = typeof input.name === "string" ? input.name : "a model";
      return `Inspecting ORM model ${name}...`;
    }
    case SUBMIT_CONCLUSION_TOOL: {
      const verdict = typeof input.verdict === "string" ? input.verdict : "a verdict";
      return `Submitting investigation verdict (${verdict})...`;
    }
    default:
      return `Calling ${call.name}...`;
  }
}

function describeToolCalls(calls: { name: string; input: Record<string, unknown> }[]): string {
  return calls.map(describeToolCall).join("; ");
}

/** Turn-based progress estimate against the (already-clamped) turn cap. */
function progressPct(turn: number, turnsCap: number): number {
  return Math.max(1, Math.min(100, Math.round((turn / turnsCap) * 100)));
}

/** Best-effort — a broken/throwing progress consumer must never break the investigation. */
function safeEmitProgress(deps: ConfirmDeps, phase: string, pct: number, message: string): void {
  if (!deps.emitProgress) return;
  try {
    deps.emitProgress(phase, pct, message);
  } catch {
    /* progress reporting is best-effort telemetry — never propagate its failures */
  }
}

function throwIfKilled(deps: ConfirmDeps): void {
  const sig = deps.signal;
  if (sig?.aborted) {
    const reason = sig.reason;
    throw reason instanceof KillSwitchActivatedError
      ? reason
      : new KillSwitchActivatedError("kill switch activated — halting Layer 3 investigation");
  }
}

/**
 * Run the multi-turn tool-using investigation for one probable finding.
 * Requires `deps.llm` — callers gate this behind `deps.investigation?.enabled`
 * (OFF by default, see `types.ts`) since it is materially more expensive than
 * the single-call static veto. Returns `inconclusive` (never throws for a
 * budget/parse issue) whenever the model doesn't reach a clean verdict.
 */
export async function runInvestigation(
  finding: ProbableFinding,
  input: ConfirmInput,
  deps: ConfirmDeps,
  priorStaticReason?: string,
): Promise<InvestigationOutcome> {
  const turns: InvestigationTurn[] = [];
  const llm = deps.llm;
  if (!llm) {
    return {
      verdict: "inconclusive",
      rationale: "no LLM gateway configured; the investigation loop requires one.",
      turns,
      turnsUsed: 0,
      toolCallCount: 0,
      haltedByBudget: false,
    };
  }

  const turnsCap = Math.min(
    Math.max(1, deps.investigation?.maxTurns ?? DEFAULT_MAX_TURNS),
    ABSOLUTE_MAX_INVESTIGATION_TURNS,
  );
  const toolCtx: InvestigationToolContext = {
    appMap: input.appMap,
    ...(input.repoRoot ? { repoRoot: input.repoRoot } : {}),
    // A9 — real semantic-code-search capability, when the caller (apps/worker)
    // wired one. Absent ⇒ the `semantic_search` tool degrades to an honest
    // "not available" result (see investigate-tools.ts), never a crash.
    ...(deps.semanticSearch ? { semanticSearch: deps.semanticSearch } : {}),
  };

  const messages: LLMMessage[] = [
    { role: "user", content: buildInvestigationUserPrompt(input, finding, priorStaticReason) },
  ];
  let toolCallCount = 0;

  for (let turn = 1; turn <= turnsCap; turn++) {
    throwIfKilled(deps); // ⛔ kill switch halts between investigation turns too

    const request: LLMRequest = {
      tier: "confirmation",
      system: INVESTIGATION_SYSTEM_PROMPT,
      messages,
      maxTokens: 2048,
      temperature: 0,
      tools: INVESTIGATION_TOOL_DEFINITIONS,
      effort: deps.investigation?.effort ?? "high",
      responseFormat: "text",
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
      turns.push({ turn, toolCalls: [] });
      return {
        verdict: "inconclusive",
        rationale: `investigation call failed on turn ${turn}: ${errMessage(err)} (fail-safe — treated as inconclusive).`,
        turns,
        turnsUsed: turn,
        toolCallCount,
        haltedByBudget: false,
      };
    }

    const toolCalls = resp.toolCalls ?? [];
    const submission = toolCalls.find((c) => c.name === SUBMIT_CONCLUSION_TOOL);
    if (submission) {
      turns.push({
        turn,
        ...(resp.content ? { responseText: resp.content } : {}),
        toolCalls: [
          {
            id: submission.id,
            name: submission.name,
            input: submission.input,
            result: "(terminal)",
          },
        ],
      });
      const parsed = parseConclusion(submission.input);
      safeEmitProgress(
        deps,
        "investigating",
        100,
        describeToolCall({ name: submission.name, input: submission.input }),
      );
      return { ...parsed, turns, turnsUsed: turn, toolCallCount, haltedByBudget: false };
    }

    if (toolCalls.length === 0) {
      const parsed = tryParseFreeformConclusion(resp.content);
      turns.push({ turn, ...(resp.content ? { responseText: resp.content } : {}), toolCalls: [] });
      safeEmitProgress(
        deps,
        "investigating",
        progressPct(turn, turnsCap),
        parsed
          ? `Concluding investigation (${parsed.verdict}) without a further tool call...`
          : "Reviewing findings without a further tool call...",
      );
      if (parsed) {
        return { ...parsed, turns, turnsUsed: turn, toolCallCount, haltedByBudget: false };
      }
      return {
        verdict: "inconclusive",
        rationale: `model returned no tool call and no parseable conclusion on turn ${turn}; investigation ended (fail-safe).`,
        turns,
        turnsUsed: turn,
        toolCallCount,
        haltedByBudget: false,
      };
    }

    const bounded = toolCalls.slice(0, MAX_TOOL_CALLS_PER_TURN);
    safeEmitProgress(
      deps,
      "investigating",
      progressPct(turn, turnsCap),
      describeToolCalls(bounded),
    );
    // The gateway's LLMMessage contract has no structured tool_use content
    // block (packages/contracts is read-only for this change), so the
    // assistant's tool-call turn is echoed as a compact text summary — enough
    // context for the model to stay coherent turn-to-turn without inventing a
    // new wire shape outside this task's scope.
    messages.push({
      role: "assistant",
      content:
        resp.content && resp.content.trim().length > 0
          ? resp.content
          : `[requested ${bounded.length} tool call(s): ${bounded.map((c) => c.name).join(", ")}]`,
    });
    const record: InvestigationToolCallRecord[] = [];
    for (const call of bounded) {
      toolCallCount++;
      const result = await executeInvestigationTool(call.name, call.input, toolCtx);
      record.push({ id: call.id, name: call.name, input: call.input, result });
      messages.push({ role: "tool", content: result, toolCallId: call.id, name: call.name });
    }
    turns.push({
      turn,
      ...(resp.content ? { responseText: resp.content } : {}),
      toolCalls: record,
    });
  }

  // Structural turn-budget exhaustion — ALWAYS inconclusive, never confirmed.
  return {
    verdict: "inconclusive",
    rationale: `investigation exhausted its ${turnsCap}-turn budget without a submitted conclusion; treated as inconclusive (fail-safe — budget exhaustion never confirms).`,
    turns,
    turnsUsed: turnsCap,
    toolCallCount,
    haltedByBudget: true,
  };
}
