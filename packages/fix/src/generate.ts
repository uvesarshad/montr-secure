/**
 * Layer 4 — Fix Generation (PRD §7 L4, build-plan §5.5).
 *
 * For each CONFIRMED finding, produce a `Fix{ patch, test, rationale, risk_class,
 * status:'proposed' }`:
 *   1. Ask the LLM (via the gateway — the ONLY egress path) to PROPOSE a fix.
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
import type { AuditLogClient } from "@montr/telemetry";
import { classifyConfirmedFindingRisk, type RiskDecision } from "./risk.js";
import { buildUnifiedDiff, validatePatch } from "./patch.js";
import {
  advisoryProofTestCode,
  pickStrategy,
  proofTestPath,
  type FixStrategy,
} from "./strategies.js";
import type { SourceReader } from "./source.js";
import type { ProofTestRunner } from "./proof-runner.js";

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
  /**
   * ⛔ Bounded coding-agent loop (OFF by default). When enabled, the proposal step
   * iterates against the deterministic patch oracle instead of a single shot, and
   * (when maxToolCalls > 0) gives the model a sandboxed read_file tool so it can
   * inspect imported/sibling files — a multi-file agent. The validation gate + risk
   * classifier + PR gate are unchanged.
   */
  agentLoop?: { enabled: boolean; maxIterations: number; maxToolCalls?: number };
  /**
   * ⛔ Optional proof-of-fix EXECUTOR. When present, the synthesized proof test is
   * actually run against the original + patched source; a candidate is accepted
   * only if the test FAILS pre-patch and PASSES post-patch by real execution.
   */
  proofRunner?: ProofTestRunner;
}

export interface GenerateFixesInput extends FixGenerationContext {
  confirmed: ConfirmedFinding[];
}

const FIX_SYSTEM_PROMPT =
  "You are a secure-code fix generator. Given a confirmed vulnerability and the source file, return " +
  'ONLY minified JSON of the form {"fixedSource": "<the full fixed file>", "rationale": "<plain English>"}. ' +
  "Change as little as possible and remove ONLY the vulnerability. NEVER modify authentication, session, " +
  "cryptography, or access-control logic. If you cannot fix it safely, return {}. " +
  "If a read_file tool is available, you MAY call it to inspect imported or related files before answering; " +
  "when ready, stop calling tools and return the JSON fix.";

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

/** The user payload for a fix request: finding metadata + the source file. */
function fixUserPayload(finding: ConfirmedFinding, source: string | null): string {
  return JSON.stringify({
    category: finding.category,
    filePath: finding.location.file,
    title: finding.title,
    impact: finding.impact,
    // Source is context inside a call to the CLIENT's own key — permitted (§11).
    source: source ?? "",
  });
}

type FixTool = NonNullable<LLMRequest["tools"]>[number];

/** A sandboxed read tool the agent may call to inspect imported/sibling files. */
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

/** Build the fix-generation request from a message history (the single egress path). */
function buildFixRequest(
  messages: FixMessage[],
  ctx: FixGenerationContext,
  tools?: FixTool[],
): LLMRequest {
  const withTools = tools !== undefined && tools.length > 0;
  return {
    tier: "default",
    system: FIX_SYSTEM_PROMPT,
    messages,
    maxTokens: 2048,
    temperature: 0,
    // With tools available the model alternates tool_use / final text, so JSON is
    // not forced; the final answer is still parsed leniently by safeJsonObject.
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
      const path = typeof tc.arguments.path === "string" ? tc.arguments.path : "";
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

/** Extract a proposal from a gateway response body. */
function parseProposal(content: string, model: string): LlmProposal {
  const parsed = safeJsonObject(content);
  const fixedSource =
    parsed && typeof parsed.fixedSource === "string" ? parsed.fixedSource : undefined;
  const rationale = parsed && typeof parsed.rationale === "string" ? parsed.rationale : undefined;
  return { fixedSource, rationale, model };
}

/** Ask the gateway to propose a fix (single shot). Degrades to `null` on any error. */
async function proposeFixWithLlm(
  finding: ConfirmedFinding,
  source: string | null,
  ctx: FixGenerationContext,
): Promise<LlmProposal | null> {
  try {
    const response = await ctx.gateway.complete(
      buildFixRequest([{ role: "user", content: fixUserPayload(finding, source) }], ctx),
    );
    return parseProposal(response.content, response.model);
  } catch {
    return null;
  }
}

/** Feedback describing which validation check the last proposal failed. */
function agentFeedback(v: { applies: boolean; failsPrePatch: boolean }): string {
  if (!v.applies) {
    return "Your fix could not be applied to the file. Return the FULL corrected file (not a diff).";
  }
  if (!v.failsPrePatch) {
    return "The proof-of-fix check did not detect the vulnerability in the ORIGINAL file — re-read the finding and target the exact vulnerable code.";
  }
  return "Your fix did NOT remove the vulnerability (the vulnerable pattern is still present). Rewrite so the pattern is gone, changing as little else as possible.";
}

/**
 * ⛔ Bounded coding-agent loop: propose a fix → validate against the deterministic
 * patch oracle → feed the failure back → retry, up to `maxIterations`. Returns the
 * first VALIDATED proposal (or the last attempt) plus the round-trip count. Every
 * turn is ONE gateway call (golden rule #2); the oracle + downstream risk
 * classification + PR gate are unchanged, so this only changes HOW a fix is
 * proposed, never how it is validated or gated.
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
  const messages: FixMessage[] = [{ role: "user", content: fixUserPayload(finding, original) }];
  const tools = maxToolCalls > 0 ? [READ_FILE_TOOL] : undefined;
  let last: LlmProposal | null = null;
  let fixIters = 0;
  let toolRounds = 0;

  // Bound total round-trips: proposal attempts + tool rounds.
  while (fixIters < maxIterations) {
    let response: LLMResponse;
    try {
      response = await ctx.gateway.complete(buildFixRequest(messages, ctx, tools));
    } catch {
      return { proposal: last, iterations: Math.max(1, fixIters) };
    }

    // Tool round: the model wants to inspect other files first. Execute + continue
    // WITHOUT consuming a fix attempt (bounded separately by maxToolCalls).
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
    const proposal = parseProposal(response.content, response.model);
    last = proposal;
    messages.push({ role: "assistant", content: response.content });

    // Oracle: the SAME deterministic patch check the accept-gate uses below.
    if (
      original !== null &&
      strategy &&
      proposal.fixedSource &&
      proposal.fixedSource !== original
    ) {
      const patch = buildUnifiedDiff(filePath, original, proposal.fixedSource);
      const v = validatePatch(original, patch, strategy.vulnerable);
      if (v.applies && v.failsPrePatch && v.passesPostPatch) {
        return { proposal, iterations: fixIters };
      }
      messages.push({ role: "user", content: agentFeedback(v) });
    } else {
      messages.push({
        role: "user",
        content:
          'Your reply had no usable "fixedSource". Return ONLY minified JSON ' +
          '{"fixedSource":"<full fixed file>","rationale":"..."} that removes the vulnerability.',
      });
    }
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
  };
  risk: RiskDecision;
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
  /** Coding-agent loop round-trips taken to reach this proposal (1 = single-shot). */
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
  const strategy = pickStrategy(finding.category);

  // Always exercise the gateway (architecture + token accounting + audit path).
  // With the coding-agent loop enabled, iterate against the patch oracle; else
  // a single shot. Either way the proposal flows through the SAME accept-gate below.
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

    const proofCode = strategy.proofTestCode(filePath, finding);
    for (const candidate of candidates) {
      const patch = buildUnifiedDiff(filePath, original, candidate.fixedSource);
      const validation = validatePatch(original, patch, strategy.vulnerable);
      if (validation.applies && validation.failsPrePatch && validation.passesPostPatch) {
        // Execution-backed proof-of-fix: actually run the synthesized test against
        // the original (must FAIL) + patched (must PASS). Reject on contradiction.
        if (ctx.proofRunner) {
          const failsPre = !(await ctx.proofRunner.run({
            testCode: proofCode,
            targetPath: filePath,
            source: original,
          }));
          const passesPost = await ctx.proofRunner.run({
            testCode: proofCode,
            targetPath: filePath,
            source: candidate.fixedSource,
          });
          if (!failsPre || !passesPost) continue;
        }
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
            code: strategy.proofTestCode(filePath, finding),
            failsPrePatch: validation.failsPrePatch,
            passesPostPatch: validation.passesPostPatch,
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
      iterations: meta.iterations ?? null,
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
