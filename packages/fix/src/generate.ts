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

/** Ask the gateway to propose a fix. Degrades to `null` on any error. */
async function proposeFixWithLlm(
  finding: ConfirmedFinding,
  source: string | null,
  ctx: FixGenerationContext,
): Promise<LlmProposal | null> {
  // Prompt registry (§8.2, §15): resolve the DB-versioned template for this
  // prompt name when one is active; otherwise FIX_SYSTEM_PROMPT above is used
  // unchanged (resolvePrompt's own fallback contract).
  const system =
    (await ctx.gateway.resolvePrompt?.("fix.system", FIX_SYSTEM_PROMPT, {
      clientId: ctx.clientId,
    })) ?? FIX_SYSTEM_PROMPT;

  const request: LLMRequest = {
    tier: "default",
    system,
    messages: [
      {
        role: "user",
        content: JSON.stringify({
          category: finding.category,
          filePath: finding.location.file,
          title: finding.title,
          impact: finding.impact,
          // Source is context inside a call to the CLIENT's own key — permitted (§11).
          // Line-numbered (A14) so the model can address exact ranges in `edits`.
          source: source !== null ? numberLines(source) : "",
        }),
      },
    ],
    maxTokens: FIX_GENERATION_MAX_TOKENS,
    temperature: 0,
    responseFormat: "json",
    stream: false,
    metadata: {
      purpose: "fix_generation",
      scanId: ctx.scanId,
      clientId: ctx.clientId,
      layer: "layer4",
    },
  };

  const metrics = ctx.metrics ?? getMetrics();
  const logger = ctx.logger ?? createNullLogger();

  try {
    const response = await ctx.gateway.complete(request);
    const parsed = safeJsonObject(response.content);
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
      return { model: response.model };
    }

    const rationale = typeof parsed.rationale === "string" ? parsed.rationale : undefined;

    let fixedSource: string | undefined;
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
      } else {
        fixedSource = applyLineEdits(source, edits);
      }
    }

    return { fixedSource, rationale, model: response.model };
  } catch {
    return null;
  }
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
  const llm = await proposeFixWithLlm(finding, original, ctx);

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
      const validation = await validatePatch(original, patch, { filePath, proofTestCode });
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
          },
        };
      }
    }
  }

  return generateAdvisory(finding, index, ctx, llm, original !== null);
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
