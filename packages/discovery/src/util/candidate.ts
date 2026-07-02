/**
 * The one place a {@link CandidateFinding} is constructed. Every candidate is
 * validated against the frozen @montr/contracts schema on creation
 * (defense-in-depth: no detector can emit an off-contract shape), tagged with a
 * deterministic id, and defaulted to the taxonomy CWEs when a tool omits them.
 */
import {
  CandidateFindingSchema,
  type CandidateFinding,
  type Category,
  type CweId,
  type Severity,
  type ToolSource,
} from "@montr/contracts";
import { candidateId, toSnippet } from "./ids.js";
import { cweForCategory } from "./severity.js";

export interface CandidateSpec {
  source: ToolSource;
  ruleId: string;
  category: Category;
  cwe?: CweId[];
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  rawSeverity: Severity;
  /** Short, in-perimeter excerpt — SECRET VALUES MUST already be redacted. */
  snippet?: string;
  title?: string;
  metadata?: Record<string, unknown>;
  /** Extra discriminator folded into the id (e.g. advisory id) to avoid collisions. */
  idExtra?: string;
}

export interface CandidateCtx {
  clientId: string;
  scanId: string;
  now: () => string;
}

/** Build + validate a CandidateFinding from a detector's spec. */
export function buildCandidate(ctx: CandidateCtx, spec: CandidateSpec): CandidateFinding {
  const cwe = spec.cwe && spec.cwe.length > 0 ? spec.cwe : cweForCategory(spec.category);
  return CandidateFindingSchema.parse({
    id: candidateId({
      source: spec.source,
      ruleId: spec.ruleId,
      file: spec.file,
      line: spec.line,
      extra: spec.idExtra,
    }),
    scanId: ctx.scanId,
    clientId: ctx.clientId,
    source: spec.source,
    ruleId: spec.ruleId,
    category: spec.category,
    cwe,
    location: {
      file: spec.file,
      line: spec.line,
      ...(spec.endLine !== undefined ? { endLine: spec.endLine } : {}),
      ...(spec.column !== undefined ? { column: spec.column } : {}),
    },
    rawSeverity: spec.rawSeverity,
    evidenceSnippet: toSnippet(spec.snippet),
    ...(spec.title ? { title: toSnippet(spec.title, 160) } : {}),
    createdAt: ctx.now(),
    ...(spec.metadata ? { metadata: spec.metadata } : {}),
  });
}

/** De-duplicate candidates by their (deterministic) id, keeping the first seen. */
export function dedupeById(candidates: readonly CandidateFinding[]): CandidateFinding[] {
  const seen = new Map<string, CandidateFinding>();
  for (const c of candidates) if (!seen.has(c.id)) seen.set(c.id, c);
  return [...seen.values()];
}
