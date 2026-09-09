/**
 * Layer 4 — Fix Generation (PRD §7 L4, build-plan §5.5).
 *
 * For each CONFIRMED finding, produce a `Fix{ patch, test, rationale, risk_class,
 * status:'proposed' }`:
 *   1. Ask the LLM (via the gateway — the ONLY egress path) to PROPOSE a fix.
 *      OFF BY DEFAULT, `ctx.agentLoop.enabled` swaps the single-shot ask for a
 *      BOUNDED retry loop with an optional sandboxed `read_file` tool — see
 *      `proposeFixWithAgent`'s doc comment for the loop/oracle design (A5).
 *   2. Fall back to a deterministic transform; prefer whichever proposal
 *      VALIDATES — patch applies cleanly, proof-of-fix predicate fails pre-patch
 *      and passes post-patch.
 *   3. Classify risk DETERMINISTICALLY (never from the LLM). Auth/session/crypto/
 *      access-control or wide blast radius or any uncertainty ⇒ human-required.
 *   4. Audit-log every generated fix (metadata only — never code bodies).
 *
 * If no cleanly-validated mechanical fix is possible, emit an advisory fix that
 * is always human-required (fail-safe).
 */
import { applyPatch } from "diff";
import {
  FixSchema,
  Layer4OutputSchema,
  type Category,
  type ConfirmedFinding,
  type Fix,
  type Layer4Output,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
} from "@montr/contracts";
import {
  createNullLogger,
  getMetrics,
  type AuditLogClient,
  type Logger,
  type MontrMetrics,
} from "@montr/telemetry";
import { classifyConfirmedFindingRisk, type RiskDecision } from "./risk.js";
import { buildUnifiedDiff, validatePatch } from "./patch.js";
import {
  validatePatchWithContainerReplay,
  type ContainerReplayEvidence,
} from "./container-validate.js";
import {
  advisoryProofTestCode,
  pickStrategy,
  proofTestPath,
  type FixStrategy,
} from "./strategies.js";
import type { SourceReader } from "./source.js";
import { applyLineEdits, numberLines, parseLlmEdits } from "./edits.js";

export interface FixGenerationContext {
  clientId: string;
  scanId: string;
  /** ⛔ ALL LLM calls go through the gateway (golden rule #2). */
  gateway: LLMGateway;
  /** Reads repo-relative source (sandbox FS in prod; injected in tests). */
  source: SourceReader;
  /** Optional audit sink — every generated fix is recorded (golden rule #7). */
  audit?: AuditLogClient;
  /** Categories the deployment forces to human review (from @montr/config). */
  humanRequiredCategoriesAlways?: Category[];
  /** Deterministic clock (defaults to wall-clock). */
  now?: () => string;
  /** Deterministic id factory (defaults to `fix_<confirmedFindingId>`). */
  makeId?: (finding: ConfirmedFinding, index: number) => string;
  /** Metrics collector for LLM parse/apply-failure visibility (A14; defaults to the process-wide one). */
  metrics?: MontrMetrics;
  /** Structured logger for LLM parse/apply-failure visibility (A14; defaults to a no-op logger). */
  logger?: Logger;
  /**
   * E13 — OFF by default. When enabled AND a confirmed finding carries a real
   * live-DAST proof artifact (an HTTP exploit transcript), proof-of-fix
   * validation attempts a genuine ephemeral-container replay of that SAME
   * probe against the target app instead of (falling back to, on missing
   * evidence or container-infra failure) the vitest-subprocess regex-assertion
   * mechanism. See container-validate.ts. Mirrors the existing OFF-by-default,
   * constructor-opt-in convention used by `ConfirmDeps.investigation.enabled`
   * (E1), `escalation` (E9), etc.
   */
  containerProof?: {
    enabled: boolean;
    /**
     * Filesystem checkout of the FULL target application (not just the
     * vulnerable file) — required to build a real container image. Not yet
     * populated by apps/worker/src/runners.ts in production, the same
     * documented not-yet-wired pattern as `ConfirmInput.repoRoot` for E1's
     * investigation loop — enabling this without a directory just yields the
     * vitest fallback (never a hang or a crash).
     */
    targetRepoDir?: string;
    /** Per-container-lifecycle timeout budget (ms). Default 120_000. */
    timeoutMs?: number;
    dockerBin?: string;
  };
  /**
   * A5 — OFF by default (mirrors `containerProof`'s constructor-opt-in
   * convention). When enabled, the proposal step iterates against a CHEAP,
   * in-process oracle instead of a single shot — propose, check, feed back a
   * specific failure reason, retry — up to `maxIterations`; and with
   * `maxToolCalls > 0` gives the model a sandboxed `read_file` tool (backed by
   * `ctx.source`, so it is bound by the SAME sandbox as everything else in
   * this module) to inspect imported/sibling files before answering. See
   * `proposeFixWithAgent`'s doc comment for why the oracle inside this loop
   * must stay cheap (no real `vitest`, no Docker) and how that differs from
   * the expensive validation `generateOne` still runs exactly once at the end.
   */
  agentLoop?: {
    enabled: boolean;
    /** Bounds real proposal attempts (NOT tool round-trips — see `maxToolCalls`). */
    maxIterations: number;
    /** Bounds `read_file` tool round-trips. 0 (default) exposes no tool at all. */
    maxToolCalls?: number;
  };
}

export interface GenerateFixesInput extends FixGenerationContext {
  confirmed: ConfirmedFinding[];
}

// A14: the model returns a targeted, line-anchored EDIT LIST (see edits.ts)
// instead of the entire fixed file. The old `{"fixedSource": "<the full fixed
// file>"}` contract truncated on any file over ~1,500 lines — the response
// couldn't fit — and JSON.parse failed with no error, no metric, no retry.
// Scoping the response to only the changed lines removes that ceiling: a
// 50-line vulnerable snippet inside a 3,000-line file only costs ~50 lines of
// output, not 3,000.
const FIX_SYSTEM_PROMPT =
  "You are a secure-code fix generator. The user message's `source` field is the vulnerable " +
  'file with each line prefixed "<lineNumber>: " (1-based, e.g. "12: const x = 1;"). Propose ' +
  "the SMALLEST possible set of line-range edits that fixes ONLY the vulnerability — never " +
  "re-emit the whole file. Return ONLY minified JSON of the form " +
  '{"edits":[{"startLine":<n>,"endLine":<n>,"replacement":"<replacement lines, WITHOUT ' +
  'line-number prefixes>"}],"rationale":"<plain English>"}. `startLine`/`endLine` are 1-based ' +
  "and inclusive, refer to the ORIGINAL line numbers, and edits must not overlap. Change as " +
  "little as possible. NEVER modify authentication, session, cryptography, or access-control " +
  "logic. If you cannot fix it safely, return {}.";

/**
 * Output budget for a fix-generation call — defense in depth alongside the
 * edit-list format above (A14). A response now only has to hold a handful of
 * changed-line hunks plus a short rationale, not an entire file body, so this
 * doesn't need to be huge; raised 4x over the old whole-file-rewrite cap
 * (2048) to comfortably fit several hunks of real code for a multi-hunk fix
 * (the other per-layer annotation-only calls sit at 512–1024, but THIS call
 * must also emit verbatim replacement code, not just short JSON fields), while
 * staying a small fraction of the model's actual output ceiling (128k tokens
 * for the default tier per RECOMMENDED_MODEL_MATRIX).
 */
const FIX_GENERATION_MAX_TOKENS = 8192;

interface LlmProposal {
  fixedSource?: string;
  rationale?: string;
  model: string;
}

function safeJsonObject(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

type FixMessage = LLMRequest["messages"][number];
type FixTool = NonNullable<LLMRequest["tools"]>[number];

/** The user payload for a fix request: finding metadata + the line-numbered source. */
function fixUserPayload(finding: ConfirmedFinding, source: string | null): string {
  return JSON.stringify({
    category: finding.category,
    filePath: finding.location.file,
    title: finding.title,
    impact: finding.impact,
    // Source is context inside a call to the CLIENT's own key — permitted (§11).
    // Line-numbered (A14) so the model can address exact ranges in `edits`.
    source: source !== null ? numberLines(source) : "",
  });
}

/**
 * A sandboxed read tool the agent loop (A5) may expose to the model so it can
 * inspect imported/sibling files BEFORE answering — genuine multi-file
 * context, not just the one vulnerable file. Only ever reachable through
 * `ctx.source` (see `executeToolCalls`), so it is bound by the exact same
 * sandbox as every other read in this module (the sandboxed workspace reader
 * in production, an in-memory map in tests) — never raw `fs`.
 */
const READ_FILE_TOOL: FixTool = {
  name: "read_file",
  description:
    "Read a repo-relative source file (e.g. an imported module, a shared helper, or a " +
    "config) to understand context BEFORE proposing the fix. Returns the file text.",
  parameters: {
    type: "object",
    properties: { path: { type: "string", description: "repo-relative file path" } },
    required: ["path"],
  },
};

/** Appended to the resolved system prompt only when the read_file tool is offered (A5). */
const AGENT_TOOL_SUFFIX =
  " If a read_file tool is available, you MAY call it to inspect imported or sibling files for " +
  "context before answering; when ready, stop calling tools and return ONLY the JSON edit list.";

/** Resolve the (possibly DB-versioned, §8.2/§15) fix-generation system prompt. */
async function resolveFixSystemPrompt(ctx: FixGenerationContext): Promise<string> {
  return (
    (await ctx.gateway.resolvePrompt?.("fix.system", FIX_SYSTEM_PROMPT, {
      clientId: ctx.clientId,
    })) ?? FIX_SYSTEM_PROMPT
  );
}

/** Build the fix-generation request from a message history (the single egress path). */
function buildFixRequest(
  messages: FixMessage[],
  ctx: FixGenerationContext,
  system: string,
  tools?: FixTool[],
): LLMRequest {
  const withTools = tools !== undefined && tools.length > 0;
  return {
    tier: "default",
    system,
    messages,
    maxTokens: FIX_GENERATION_MAX_TOKENS,
    temperature: 0,
    // With tools available the model alternates tool_use / final text, so JSON
    // is not forced; the final answer is still parsed leniently below. The
    // non-agent-loop path never sets `tools`, so its request is byte-for-byte
    // unchanged from before this change (`responseFormat: "json"` always).
    responseFormat: withTools ? "text" : "json",
    stream: false,
    ...(withTools ? { tools } : {}),
    metadata: {
      purpose: "fix_generation",
      scanId: ctx.scanId,
      clientId: ctx.clientId,
      layer: "layer4",
    },
  };
}

/** Execute the agent's tool calls (only `read_file`, via the sandboxed reader). */
async function executeToolCalls(
  toolCalls: NonNullable<LLMResponse["toolCalls"]>,
  ctx: FixGenerationContext,
): Promise<FixMessage[]> {
  const out: FixMessage[] = [];
  for (const tc of toolCalls) {
    let content: string;
    if (tc.name === "read_file") {
      const path = typeof tc.input.path === "string" ? tc.input.path : "";
      // ⛔ Reads go through the sandboxed SourceReader (repo-root scoped) — no raw fs.
      const src = path ? await ctx.source.read(path) : null;
      content = src ?? `(file not found or unreadable: ${path})`;
    } else {
      content = `(unsupported tool: ${tc.name})`;
    }
    out.push({ role: "tool", content, toolCallId: tc.id, name: tc.name });
  }
  return out;
}

interface InterpretedFixResponse {
  fixedSource?: string;
  rationale?: string;
  /** Set when the response could not be turned into a usable edit list — drives
   * both the A14 metrics/logging below AND the agent loop's retry feedback (A5). */
  issue?: "unparseable" | "invalid_edits";
}

/**
 * Parse one gateway response body into a candidate fix, applying the SAME A14
 * failure-visibility bookkeeping (metrics + structured logging) regardless of
 * whether this is the single-shot path or one turn of the agent loop — a
 * malformed/invalid proposal is exactly as observable either way.
 */
function interpretFixResponse(
  content: string,
  source: string | null,
  finding: ConfirmedFinding,
  response: { model: string; stopReason: string },
  ctx: FixGenerationContext,
): InterpretedFixResponse {
  const metrics = ctx.metrics ?? getMetrics();
  const logger = ctx.logger ?? createNullLogger();
  const parsed = safeJsonObject(content);
  const logFields = {
    scanId: ctx.scanId,
    clientId: ctx.clientId,
    category: finding.category,
    filePath: finding.location.file,
    model: response.model,
    stopReason: response.stopReason,
    // A truncated response (the model hit its output ceiling mid-JSON) is
    // the exact failure mode A14 exists to make visible instead of silent.
    likelyTruncated: response.stopReason === "max_tokens",
  };

  if (parsed === null) {
    metrics.recordError("fix_generation.llm_response_unparseable");
    logger.warn("fix_generation.llm_response_unparseable", logFields);
    return { issue: "unparseable" };
  }

  const rationale = typeof parsed.rationale === "string" ? parsed.rationale : undefined;

  if (source !== null && parsed.edits !== undefined) {
    const totalLines = source.split("\n").length;
    const edits = parseLlmEdits(parsed.edits, totalLines);
    if (edits === null) {
      // The model returned an `edits` field, but it was malformed, out of
      // range, or overlapping — this is exactly the "diff can't be parsed
      // or doesn't apply cleanly" case A14 requires be counted and logged,
      // never a silent null-and-degrade.
      metrics.recordError("fix_generation.llm_edits_invalid");
      logger.warn("fix_generation.llm_edits_invalid", logFields);
      return { rationale, issue: "invalid_edits" };
    }
    return { fixedSource: applyLineEdits(source, edits), rationale };
  }

  return { rationale };
}

/** Ask the gateway to propose a fix (single shot, unchanged default path). Degrades to `null` on any error. */
async function proposeFixWithLlm(
  finding: ConfirmedFinding,
  source: string | null,
  ctx: FixGenerationContext,
): Promise<LlmProposal | null> {
  const system = await resolveFixSystemPrompt(ctx);
  const request = buildFixRequest(
    [{ role: "user", content: fixUserPayload(finding, source) }],
    ctx,
    system,
  );
  try {
    const response = await ctx.gateway.complete(request);
    const interpreted = interpretFixResponse(response.content, source, finding, response, ctx);
    return {
      fixedSource: interpreted.fixedSource,
      rationale: interpreted.rationale,
      model: response.model,
    };
  } catch {
    return null;
  }
}

interface CheapOracleResult {
  /** The patch applies cleanly to the original source (pure `diff`-library apply, no subprocess). */
  applies: boolean;
  /** The vulnerable pattern is present in the ORIGINAL (⇒ the fix targets a real vulnerability). */
  failsPrePatch: boolean;
  /** The vulnerable pattern is gone AFTER the patch. */
  passesPostPatch: boolean;
}

/**
 * CHEAP, IN-PROCESS oracle for the agent loop's retry/feedback cycle: a pure
 * `diff`-library patch-apply plus the strategy's own vulnerability REGEX
 * predicate — no subprocess, no `vitest`, no Docker.
 *
 * This is the whole design answer to A5's central constraint: `patch.ts`'s
 * `validatePatch` actually spawns a real `vitest` subprocess (twice, seconds
 * each), and `container-validate.ts`'s `validatePatchWithContainerReplay` can
 * spin up a real Docker container on top of that. Looping either of those
 * per retry would turn a bounded few-iteration loop into a multi-second-per-
 * iteration one — a serious performance regression, not a feature. So this
 * loop drives retries against this cheap predicate ONLY; the real, expensive
 * validation still runs in `generateOne` below, exactly as before this
 * change — ONCE per candidate, after the loop has already returned.
 */
function cheapPatchOracle(
  original: string,
  patch: string,
  vulnerable: (source: string) => boolean,
): CheapOracleResult {
  const applied = applyPatch(original, patch);
  const applies = applied !== false;
  const appliedSource = applies ? applied : null;
  return {
    applies,
    failsPrePatch: vulnerable(original),
    passesPostPatch: appliedSource !== null && !vulnerable(appliedSource),
  };
}

/** Feedback describing which check the last proposal failed, reconciled with edits.ts's own
 * validation vocabulary (A5) — always a SPECIFIC, actionable reason, never a generic retry nudge. */
function agentFeedback(
  issue: "unparseable" | "invalid_edits" | undefined,
  oracle?: CheapOracleResult,
): string {
  if (issue === "unparseable") {
    return (
      "Your reply was not valid JSON. Return ONLY minified JSON of the form " +
      '{"edits":[{"startLine":<n>,"endLine":<n>,"replacement":"<...>"}],"rationale":"..."}.'
    );
  }
  if (issue === "invalid_edits") {
    return (
      "Your edits were structurally invalid — an out-of-range startLine/endLine, a malformed " +
      "entry, or two overlapping ranges. Re-read the numbered source and return a corrected " +
      "edits list: each entry's startLine/endLine must be a 1-based, in-range, inclusive pair " +
      "referring to the ORIGINAL line numbers, and ranges must not overlap."
    );
  }
  if (!oracle) {
    return (
      'Your reply had no usable "edits". Return ONLY minified JSON ' +
      '{"edits":[{"startLine":<n>,"endLine":<n>,"replacement":"..."}],"rationale":"..."} that ' +
      "removes the vulnerability."
    );
  }
  if (!oracle.applies) {
    return (
      "Your edits did not produce a patch that applies cleanly to the original file. Re-check " +
      "your line ranges against the ORIGINAL numbered source (they must match exactly) and " +
      "try again."
    );
  }
  if (!oracle.failsPrePatch) {
    return (
      "The vulnerability check did not detect the vulnerable pattern in the ORIGINAL file — " +
      "re-read the finding and target the exact vulnerable lines."
    );
  }
  return (
    "Your fix did NOT remove the vulnerability (the vulnerable pattern is still present after " +
    "your edit). Return a new edits list that changes the necessary lines so the pattern is gone, " +
    "changing as little else as possible."
  );
}

/**
 * A5 — bounded agentic fix loop: propose → check against the CHEAP oracle
 * above → feed back a specific failure reason → retry, up to `maxIterations`
 * real proposal attempts (tool round-trips are bounded separately by
 * `maxToolCalls` and never consume a proposal attempt). Returns the first
 * accepted proposal, or the LAST attempt if none was accepted, plus the
 * number of proposal attempts actually made (for audit visibility).
 *
 * Every turn is still ONE gateway call (golden rule #2), and the risk
 * classifier + real `validatePatch`/`validatePatchWithContainerReplay` +
 * PR gate downstream in `generateOne` are completely unchanged — this
 * function only changes HOW a fix is proposed, never how it is finally
 * validated or gated. OFF by default: `generateOne` only calls this when
 * `ctx.agentLoop.enabled` is true.
 */
async function proposeFixWithAgent(
  finding: ConfirmedFinding,
  original: string | null,
  strategy: FixStrategy | undefined,
  ctx: FixGenerationContext,
  maxIterations: number,
  maxToolCalls: number,
): Promise<{ proposal: LlmProposal | null; iterations: number }> {
  const filePath = finding.location.file;
  const resolvedSystem = await resolveFixSystemPrompt(ctx);
  const tools = maxToolCalls > 0 ? [READ_FILE_TOOL] : undefined;
  const system = tools ? resolvedSystem + AGENT_TOOL_SUFFIX : resolvedSystem;
  const messages: FixMessage[] = [{ role: "user", content: fixUserPayload(finding, original) }];

  const maxIters = Math.max(1, maxIterations);
  let last: LlmProposal | null = null;
  let fixIters = 0;
  let toolRounds = 0;

  while (fixIters < maxIters) {
    let response: LLMResponse;
    try {
      response = await ctx.gateway.complete(buildFixRequest(messages, ctx, system, tools));
    } catch {
      return { proposal: last, iterations: Math.max(1, fixIters) };
    }

    // Tool round: the model wants to inspect other files first. Execute + continue
    // WITHOUT consuming a proposal attempt (bounded separately by maxToolCalls).
    if (
      response.stopReason === "tool_use" &&
      response.toolCalls &&
      response.toolCalls.length > 0 &&
      toolRounds < maxToolCalls
    ) {
      toolRounds++;
      messages.push({
        role: "assistant",
        content: response.content,
        toolCalls: response.toolCalls,
      });
      messages.push(...(await executeToolCalls(response.toolCalls, ctx)));
      continue;
    }

    // Proposal attempt.
    fixIters++;
    const interpreted = interpretFixResponse(response.content, original, finding, response, ctx);
    last = {
      fixedSource: interpreted.fixedSource,
      rationale: interpreted.rationale,
      model: response.model,
    };
    messages.push({ role: "assistant", content: response.content });

    if (interpreted.issue) {
      messages.push({ role: "user", content: agentFeedback(interpreted.issue) });
      continue;
    }

    if (!interpreted.fixedSource || interpreted.fixedSource === original) {
      // A deliberate decline (`{}`) or a no-op edit: nothing to check against
      // the oracle. Without a strategy/source to validate against anyway,
      // there is nothing further a retry could usefully change — stop here.
      if (!strategy || original === null) {
        return { proposal: last, iterations: fixIters };
      }
      messages.push({ role: "user", content: agentFeedback(undefined) });
      continue;
    }

    if (!strategy || original === null) {
      // No deterministic strategy for this (category, language) pair — there
      // is no cheap oracle to iterate against. Accept the first structurally
      // valid proposal; `generateOne` will fall through to the advisory path
      // exactly as the single-shot path already does in this case.
      return { proposal: last, iterations: fixIters };
    }

    const patch = buildUnifiedDiff(filePath, original, interpreted.fixedSource);
    const oracle = cheapPatchOracle(original, patch, strategy.vulnerable);
    if (oracle.applies && oracle.failsPrePatch && oracle.passesPostPatch) {
      return { proposal: last, iterations: fixIters };
    }
    messages.push({ role: "user", content: agentFeedback(undefined, oracle) });
  }
  return { proposal: last, iterations: Math.max(1, fixIters) };
}

function composeRationale(
  strategy: FixStrategy,
  via: "llm" | "deterministic",
  llmRationale: string | undefined,
): string {
  const base =
    via === "llm"
      ? `${strategy.rationale} (Model-proposed patch, deterministically validated.)`
      : `${strategy.rationale} (Deterministic patch.)`;
  return via !== "llm" && llmRationale ? `${base} Model note: ${llmRationale}` : base;
}

function defaultNow(): string {
  return new Date().toISOString();
}

function defaultMakeId(finding: ConfirmedFinding): string {
  return `fix_${finding.id}`;
}

interface FixParts {
  patch: string;
  rationale: string;
  proofOfFixTest: {
    filePath: string;
    framework: string;
    code: string;
    failsPrePatch: boolean;
    passesPostPatch: boolean;
    /** E13: the full ephemeral-container exploit-replay evidence (request/
     * response transcript for both runs) — persisted on the Fix row itself,
     * NOT the audit log (golden rule #1: audit metadata stays metadata-only,
     * never raw request/response bodies; see `auditFixGenerated` below). */
    containerReplay?: ContainerReplayEvidence;
  };
  risk: RiskDecision;
}

/** A LEAN summary of `ContainerReplayEvidence` safe for audit metadata — every
 * transcript/body field is stripped (golden rule #1). The full evidence lives
 * on `Fix.proofOfFixTest.containerReplay` instead. */
function leanContainerReplaySummary(ev: ContainerReplayEvidence): Record<string, unknown> {
  return {
    attempted: ev.attempted,
    replayed: ev.replayed,
    harness: ev.harness ?? null,
    prePatchExploitSucceeded: ev.prePatch?.exploitSucceeded ?? null,
    postPatchExploitSucceeded: ev.postPatch?.exploitSucceeded ?? null,
    reason: ev.reason ?? null,
    error: ev.error ?? null,
  };
}

function assembleFix(
  finding: ConfirmedFinding,
  index: number,
  ctx: FixGenerationContext,
  parts: FixParts,
): Fix {
  const id = (ctx.makeId ?? defaultMakeId)(finding, index);
  const createdAt = (ctx.now ?? defaultNow)();
  return FixSchema.parse({
    id,
    scanId: finding.scanId,
    clientId: finding.clientId,
    confirmedFindingId: finding.id,
    patch: parts.patch,
    rationale: parts.rationale,
    proofOfFixTest: parts.proofOfFixTest,
    riskClass: parts.risk.riskClass,
    riskClassRationale: parts.risk.rationale,
    status: "proposed",
    createdAt,
  });
}

interface AuditMeta {
  validated: boolean;
  via: "llm" | "deterministic" | "advisory";
  changedLines: number;
  model?: string;
  /** E13: present whenever `ctx.containerProof.enabled` — a LEAN summary (no
   * transcript bodies; see `leanContainerReplaySummary`) of the container
   * replay attempt. The FULL evidence (with the request/response transcript)
   * is persisted on `Fix.proofOfFixTest.containerReplay` instead, never here. */
  containerReplay?: Record<string, unknown>;
  /** A5: proposal attempts taken to reach this result — 1 for the (default,
   * unchanged) single-shot path, up to `ctx.agentLoop.maxIterations` when the
   * bounded agent loop is enabled. Metadata only (a round-trip count), never
   * a code body — safe for the audit log under golden rule #1. */
  iterations?: number;
}

interface GeneratedOne {
  fix: Fix;
  auditMeta: AuditMeta;
}

function generateAdvisory(
  finding: ConfirmedFinding,
  index: number,
  ctx: FixGenerationContext,
  llm: LlmProposal | null,
  sourceAvailable: boolean,
): GeneratedOne {
  const filePath = finding.location.file;
  const risk = classifyConfirmedFindingRisk(
    finding,
    { patch: "", changedFiles: [filePath], changedLines: 0, uncertain: true },
    { alwaysHumanCategories: ctx.humanRequiredCategoriesAlways },
  );
  const rationale = [
    `No auto-validated mechanical fix was produced for ${finding.category} at ${filePath}` +
      (sourceAvailable ? "" : " (source unavailable)") +
      ".",
    "This finding requires manual remediation by an engineer and is recorded as human-required.",
    llm?.rationale ? `Model guidance: ${llm.rationale}` : "",
  ]
    .filter(Boolean)
    .join(" ");

  const fix = assembleFix(finding, index, ctx, {
    patch: "",
    rationale,
    proofOfFixTest: {
      filePath: proofTestPath(filePath),
      framework: "vitest",
      code: advisoryProofTestCode(filePath, finding),
      failsPrePatch: false,
      passesPostPatch: false,
    },
    risk,
  });
  return {
    fix,
    auditMeta: { validated: false, via: "advisory", changedLines: 0, model: llm?.model },
  };
}

async function generateOne(
  finding: ConfirmedFinding,
  index: number,
  ctx: FixGenerationContext,
): Promise<GeneratedOne> {
  const filePath = finding.location.file;
  const original = await ctx.source.read(filePath);
  // Language-aware: only a strategy whose syntax actually matches this
  // finding's file (by extension) is ever picked — see strategies.ts's
  // pickStrategy docstring. No match ⇒ falls through to generateAdvisory.
  const strategy = pickStrategy(finding.category, filePath);

  // Always exercise the gateway (architecture + token accounting + audit path).
  // A5 — OFF by default: only when ctx.agentLoop.enabled does this become a
  // bounded retry loop; otherwise this is the exact single-shot call as before.
  const { proposal: llm, iterations } = ctx.agentLoop?.enabled
    ? await proposeFixWithAgent(
        finding,
        original,
        strategy,
        ctx,
        ctx.agentLoop.maxIterations,
        ctx.agentLoop.maxToolCalls ?? 0,
      )
    : { proposal: await proposeFixWithLlm(finding, original, ctx), iterations: 1 };

  if (original !== null && strategy) {
    // Candidate fixed sources: prefer a VALIDATED model proposal, else the
    // deterministic transform. Both must pass the same validation gate.
    const candidates: { fixedSource: string; via: "llm" | "deterministic" }[] = [];
    if (llm?.fixedSource && llm.fixedSource !== original) {
      candidates.push({ fixedSource: llm.fixedSource, via: "llm" });
    }
    const deterministic = strategy.apply(original);
    if (deterministic !== null) {
      candidates.push({ fixedSource: deterministic, via: "deterministic" });
    }

    // Generated once — every candidate is validated against the SAME proof
    // test, and the winning candidate's Fix ships EXACTLY the code that was
    // actually executed (never a re-derived copy).
    const proofTestCode = strategy.proofTestCode(filePath, finding);

    for (const candidate of candidates) {
      const patch = buildUnifiedDiff(filePath, original, candidate.fixedSource);
      const containerProof = ctx.containerProof;
      let validation: Awaited<ReturnType<typeof validatePatch>>;
      let containerReplay: ContainerReplayEvidence | undefined;
      if (containerProof?.enabled) {
        const result = await validatePatchWithContainerReplay(original, patch, {
          filePath,
          proofTestCode,
          confirmedFinding: finding,
          ...(containerProof.targetRepoDir ? { targetRepoDir: containerProof.targetRepoDir } : {}),
          ...(containerProof.timeoutMs !== undefined
            ? { containerTimeoutMs: containerProof.timeoutMs }
            : {}),
          ...(containerProof.dockerBin ? { dockerBin: containerProof.dockerBin } : {}),
        });
        validation = result;
        containerReplay = result.containerReplay;
      } else {
        validation = await validatePatch(original, patch, { filePath, proofTestCode });
      }
      if (validation.applies && validation.failsPrePatch && validation.passesPostPatch) {
        const risk = classifyConfirmedFindingRisk(
          finding,
          {
            patch,
            changedFiles: [filePath],
            changedLines: validation.changedLines,
            uncertain: false,
          },
          { alwaysHumanCategories: ctx.humanRequiredCategoriesAlways },
        );
        const fix = assembleFix(finding, index, ctx, {
          patch,
          rationale: composeRationale(strategy, candidate.via, llm?.rationale),
          proofOfFixTest: {
            filePath: proofTestPath(filePath),
            framework: strategy.testFramework,
            code: proofTestCode,
            failsPrePatch: validation.failsPrePatch,
            passesPostPatch: validation.passesPostPatch,
            // E13: the FULL evidence (with transcript) rides on the Fix row
            // itself — audit metadata gets only the lean summary below.
            ...(containerReplay ? { containerReplay } : {}),
          },
          risk,
        });
        return {
          fix,
          auditMeta: {
            validated: true,
            via: candidate.via,
            changedLines: validation.changedLines,
            model: llm?.model,
            iterations,
            ...(containerReplay
              ? { containerReplay: leanContainerReplaySummary(containerReplay) }
              : {}),
          },
        };
      }
    }
  }

  const advisory = generateAdvisory(finding, index, ctx, llm, original !== null);
  advisory.auditMeta.iterations = iterations;
  return advisory;
}

async function auditFixGenerated(
  audit: AuditLogClient,
  finding: ConfirmedFinding,
  fix: Fix,
  meta: AuditMeta,
): Promise<void> {
  // ⛔ Metadata only — never the patch/source/test bodies (golden rule #1).
  await audit.append({
    clientId: fix.clientId,
    scanId: fix.scanId,
    actor: { type: "agent", id: "montr-fix" },
    action: "fix.generated",
    targetType: "fix",
    targetId: fix.id,
    summary: `Generated ${fix.riskClass} fix for ${finding.category} at ${finding.location.file}`,
    metadata: {
      category: finding.category,
      riskClass: fix.riskClass,
      filePath: finding.location.file,
      validated: meta.validated,
      via: meta.via,
      changedLines: meta.changedLines,
      framework: fix.proofOfFixTest.framework ?? null,
      model: meta.model ?? null,
      // A5: proposal-attempt round-trip count — 1 for the default single-shot
      // path, >1 only when ctx.agentLoop.enabled retried. A round-trip count
      // is metadata, never a code body (golden rule #1).
      iterations: meta.iterations ?? null,
      // E13: a LEAN summary (harness kind, per-phase pass/fail — no request/
      // response bodies) of the ephemeral-container exploit-replay attempt,
      // when one was made for this fix. Golden rule #1: audit metadata never
      // carries transcript/body content — the FULL evidence artifact (the
      // real request/response transcript for both runs) is persisted on
      // `Fix.proofOfFixTest.containerReplay` instead. `null` when container
      // proof was never enabled/attempted (the common case, OFF by default).
      containerReplay: meta.containerReplay ?? null,
    },
  });
}

/**
 * Generate `Fix[]` for a set of confirmed findings. Emits the exact
 * `Layer4Output` contract. Runs sequentially so audit ordering is deterministic.
 */
export async function generateFixes(input: GenerateFixesInput): Promise<Layer4Output> {
  const fixes: Fix[] = [];
  let index = 0;
  for (const finding of input.confirmed) {
    const { fix, auditMeta } = await generateOne(finding, index, input);
    fixes.push(fix);
    if (input.audit) {
      await auditFixGenerated(input.audit, finding, fix, auditMeta);
    }
    index++;
  }
  return Layer4OutputSchema.parse({ fixes });
}
