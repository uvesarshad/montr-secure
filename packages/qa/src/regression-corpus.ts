/**
 * §15 Regression corpus — the durable, structured record of operator-marked
 * FALSE POSITIVES that closes the feedback loop (PRD §15, build-plan §6).
 *
 * When an operator/approver overturns a confirmed finding, that decision is
 * recorded here as a **metadata-only** record (category, location, compliance
 * ids, who + why + when). The corpus is what:
 *   - the golden-corpus scorer consumes to count marked FPs against precision
 *     and feed the headline FP-rate metric (see `scoreFalsePositiveFeedback`),
 *   - the correlation/confirmation tuning hook consumes to DOWN-RANK / SKIP a
 *     re-detected known false positive (see `buildFalsePositiveTuning`).
 *
 * ⛔ Metadata only — NEVER a code body, proof artifact, or secret (golden rule
 * #1). The zod schema is `.strict()` so a proof/transcript can never leak in.
 * The corpus is durable-by-construction: it can be reconstructed from the
 * append-only, hash-chained audit log (`regressionCorpusFromAuditEvents`).
 */
import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  CategorySchema,
  CweIdSchema,
  ExposureSchema,
  OwaspIdSchema,
  ProofTypeSchema,
  RoleSchema,
  SeveritySchema,
  type AuditEvent,
  type Category,
  type ConfirmedFinding,
  type CweId,
  type Exposure,
  type OwaspId,
  type ProofType,
  type Role,
  type Severity,
} from "@montr/contracts";
import type { FalsePositiveMarker } from "./types.js";

/* --------------------------------------------------------------------------- *
 * Record shape (metadata only).
 * --------------------------------------------------------------------------- *
 * Validated by assembling ONLY the listed fields (see `parseFalsePositiveRecord`)
 * — a proof artifact / code body can never enter regardless of input (golden
 * rule #1). Enum fields are validated with the frozen @montr/contracts schemas.
 * Kept dependency-free (no direct `zod` import) so the QA package builds in
 * isolation.
 */

/** One durable false-positive record — metadata only, never a code body. */
export interface FalsePositiveRecord {
  /** Stable content signature = sha256(category|file|line). Dedup + identity key. */
  signature: string;
  clientId: string;
  scanId: string;
  /** The confirmed finding the operator overturned. */
  findingId: string;
  category: Category;
  cwe: CweId[];
  owasp?: OwaspId;
  /** Repo-relative file + line — metadata only, never a code body. */
  file: string;
  line: number;
  severity?: Severity;
  exposure?: Exposure;
  proofType?: ProofType;
  /** Who overturned it. */
  operatorId: string;
  operatorRole?: Role;
  /** The operator's free-text justification (their words — not code). */
  reason: string;
  /** ISO-8601 timestamp the FP was marked. */
  markedAt: string;
  /** Originating tool rule id, when known from the source candidate. */
  ruleId?: string;
}

function nonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`false-positive record: "${field}" must be a non-empty string`);
  }
  return value;
}

function nonNegInt(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new TypeError(`false-positive record: "${field}" must be a non-negative integer`);
  }
  return value;
}

/**
 * Validate an untrusted object into a {@link FalsePositiveRecord}, assembling
 * ONLY known metadata fields (extras are dropped, so a code body can never
 * persist). Throws on a malformed required field.
 */
export function parseFalsePositiveRecord(input: unknown): FalsePositiveRecord {
  if (typeof input !== "object" || input === null) {
    throw new TypeError("false-positive record must be an object");
  }
  const r = input as Record<string, unknown>;
  const cwe = Array.isArray(r.cwe) ? r.cwe.map((c) => CweIdSchema.parse(c)) : [];
  const record: FalsePositiveRecord = {
    signature: nonEmptyString(r.signature, "signature"),
    clientId: nonEmptyString(r.clientId, "clientId"),
    scanId: nonEmptyString(r.scanId, "scanId"),
    findingId: nonEmptyString(r.findingId, "findingId"),
    category: CategorySchema.parse(r.category),
    cwe,
    file: nonEmptyString(r.file, "file"),
    line: nonNegInt(r.line, "line"),
    operatorId: nonEmptyString(r.operatorId, "operatorId"),
    reason: nonEmptyString(r.reason, "reason"),
    markedAt: nonEmptyString(r.markedAt, "markedAt"),
  };
  if (r.owasp !== undefined) record.owasp = OwaspIdSchema.parse(r.owasp);
  if (r.severity !== undefined) record.severity = SeveritySchema.parse(r.severity);
  if (r.exposure !== undefined) record.exposure = ExposureSchema.parse(r.exposure);
  if (r.proofType !== undefined) record.proofType = ProofTypeSchema.parse(r.proofType);
  if (r.operatorRole !== undefined) record.operatorRole = RoleSchema.parse(r.operatorRole);
  if (r.ruleId !== undefined) record.ruleId = nonEmptyString(r.ruleId, "ruleId");
  return record;
}

/** Non-throwing {@link parseFalsePositiveRecord}. */
export function safeParseFalsePositiveRecord(input: unknown): FalsePositiveRecord | undefined {
  try {
    return parseFalsePositiveRecord(input);
  } catch {
    return undefined;
  }
}

/**
 * The metadata an API/operator supplies to record a false positive. Structurally
 * mirrored by `apps/api`'s `FalsePositiveMarkInput` (the API stays decoupled from
 * the QA harness at build time, per the state-store mirroring pattern).
 */
export interface FalsePositiveMarkInput {
  clientId: string;
  scanId: string;
  findingId: string;
  category: Category;
  cwe?: string[];
  owasp?: string;
  file: string;
  line: number;
  severity?: string;
  exposure?: string;
  proofType?: string;
  operator: { id: string; role?: string };
  reason: string;
  markedAt: string;
  ruleId?: string;
}

/* --------------------------------------------------------------------------- *
 * Signature + derivation.
 * --------------------------------------------------------------------------- */

/** A finding location signal used to compute a false-positive signature. */
export interface FalsePositiveSignal {
  category: Category;
  file: string;
  line: number;
}

/**
 * Stable, metadata-only content signature for a finding location. Matching for
 * tuning uses the raw category/file/line with a tolerance (see
 * `buildFalsePositiveTuning`); this hash is the dedup/identity key.
 */
export function falsePositiveSignature(signal: FalsePositiveSignal): string {
  const basis = `${signal.category}|${signal.file}|${signal.line}`;
  return createHash("sha256").update(basis).digest("hex").slice(0, 32);
}

/** Build a corpus record from a confirmed finding + the operator's decision. */
export function deriveFalsePositiveRecord(input: {
  finding: ConfirmedFinding;
  operator: { id: string; role?: string };
  reason: string;
  markedAt: string;
  ruleId?: string;
}): FalsePositiveRecord {
  const f = input.finding;
  return markInputToRecord({
    clientId: f.clientId,
    scanId: f.scanId,
    findingId: f.id,
    category: f.category,
    cwe: f.cwe,
    ...(f.owasp ? { owasp: f.owasp } : {}),
    file: f.location.file,
    line: f.location.line,
    severity: f.severity,
    exposure: f.exposure,
    proofType: f.proofType,
    operator: input.operator,
    reason: input.reason,
    markedAt: input.markedAt,
    ...(input.ruleId ? { ruleId: input.ruleId } : {}),
  });
}

/** Validate + normalize a mark-input into a durable record (computes signature). */
export function markInputToRecord(input: FalsePositiveMarkInput): FalsePositiveRecord {
  return parseFalsePositiveRecord({
    signature: falsePositiveSignature({
      category: input.category,
      file: input.file,
      line: input.line,
    }),
    clientId: input.clientId,
    scanId: input.scanId,
    findingId: input.findingId,
    category: input.category,
    cwe: input.cwe ?? [],
    ...(input.owasp ? { owasp: input.owasp } : {}),
    file: input.file,
    line: input.line,
    ...(input.severity ? { severity: input.severity } : {}),
    ...(input.exposure ? { exposure: input.exposure } : {}),
    ...(input.proofType ? { proofType: input.proofType } : {}),
    operatorId: input.operator.id,
    ...(input.operator.role ? { operatorRole: input.operator.role } : {}),
    reason: input.reason,
    markedAt: input.markedAt,
    ...(input.ruleId ? { ruleId: input.ruleId } : {}),
  });
}

/* --------------------------------------------------------------------------- *
 * Durable stores.
 * --------------------------------------------------------------------------- */

export interface CorpusListFilter {
  clientId?: string;
}

/** Append-only store of false-positive records. */
export interface RegressionCorpusStore {
  append(record: FalsePositiveRecord): Promise<FalsePositiveRecord>;
  list(filter?: CorpusListFilter): Promise<FalsePositiveRecord[]>;
}

/** In-memory corpus for dev + offline tests. Never for production durability. */
export class InMemoryRegressionCorpus implements RegressionCorpusStore {
  private readonly records: FalsePositiveRecord[] = [];

  async append(record: FalsePositiveRecord): Promise<FalsePositiveRecord> {
    const parsed = parseFalsePositiveRecord(record);
    this.records.push(parsed);
    return { ...parsed };
  }

  async list(filter?: CorpusListFilter): Promise<FalsePositiveRecord[]> {
    return this.records
      .filter((r) => !filter?.clientId || r.clientId === filter.clientId)
      .map((r) => ({ ...r }));
  }
}

/**
 * Durable JSONL corpus the golden-corpus harness can consume. Append-only: one
 * validated record per line. A malformed line is skipped on read (fail-safe —
 * one corrupt entry never blocks tuning or scoring).
 */
export class FileRegressionCorpus implements RegressionCorpusStore {
  constructor(private readonly path: string) {}

  async append(record: FalsePositiveRecord): Promise<FalsePositiveRecord> {
    const parsed = parseFalsePositiveRecord(record);
    await mkdir(dirname(this.path), { recursive: true });
    await appendFile(this.path, `${JSON.stringify(parsed)}\n`, "utf8");
    return { ...parsed };
  }

  async list(filter?: CorpusListFilter): Promise<FalsePositiveRecord[]> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch {
      return [];
    }
    const out: FalsePositiveRecord[] = [];
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      let json: unknown;
      try {
        json = JSON.parse(t);
      } catch {
        continue;
      }
      const parsed = safeParseFalsePositiveRecord(json);
      if (parsed && (!filter?.clientId || parsed.clientId === filter.clientId)) {
        out.push(parsed);
      }
    }
    return out;
  }
}

/**
 * The metadata-only sink the API/operator writes through. Mirrors the API's
 * `RegressionCorpusRecorder`. Wrap any {@link RegressionCorpusStore} with
 * {@link corpusRecorder} to obtain one.
 */
export interface RegressionCorpusRecorder {
  record(input: FalsePositiveMarkInput): Promise<FalsePositiveRecord>;
}

/** Adapt a store into a mark-input recorder (validates + computes the signature). */
export function corpusRecorder(store: RegressionCorpusStore): RegressionCorpusRecorder {
  return {
    record: (input) => store.append(markInputToRecord(input)),
  };
}

/* --------------------------------------------------------------------------- *
 * Audit-log projection (durable-by-construction).
 * --------------------------------------------------------------------------- */

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/**
 * Reconstruct the regression corpus from the append-only audit log. Every
 * `finding.marked_false_positive` event carries the metadata needed to rebuild a
 * record, so the tamper-evident audit trail IS a durable corpus (golden rule
 * #7). Events lacking the required metadata are skipped (fail-safe).
 */
export function regressionCorpusFromAuditEvents(
  events: readonly AuditEvent[],
): FalsePositiveRecord[] {
  const out: FalsePositiveRecord[] = [];
  for (const e of events) {
    if (e.action !== "finding.marked_false_positive") continue;
    const m = e.metadata ?? {};
    const category = str(m.category);
    const file = str(m.file);
    const line = typeof m.line === "number" ? m.line : undefined;
    const findingId = e.targetId ?? str(m.findingId);
    const reason = str(m.reason);
    if (!category || !file || line === undefined || !findingId || !reason) continue;

    const candidate = {
      signature: falsePositiveSignature({ category: category as Category, file, line }),
      clientId: e.clientId,
      scanId: e.scanId ?? str(m.scanId) ?? "",
      findingId,
      category,
      cwe: Array.isArray(m.cwe) ? m.cwe : [],
      ...(str(m.owasp) ? { owasp: str(m.owasp) } : {}),
      file,
      line,
      ...(str(m.severity) ? { severity: str(m.severity) } : {}),
      ...(str(m.exposure) ? { exposure: str(m.exposure) } : {}),
      ...(str(m.proofType) ? { proofType: str(m.proofType) } : {}),
      operatorId: e.actor.id,
      ...(e.actor.role ? { operatorRole: e.actor.role } : {}),
      reason,
      markedAt: e.at,
      ...(str(m.ruleId) ? { ruleId: str(m.ruleId) } : {}),
    };
    const parsed = safeParseFalsePositiveRecord(candidate);
    if (parsed) out.push(parsed);
  }
  return out;
}

/* --------------------------------------------------------------------------- *
 * Scorer + tuning adapters.
 * --------------------------------------------------------------------------- */

/** Project corpus records to (category, file, line) markers for the scorer. */
export function toFalsePositiveMarkers(
  records: readonly FalsePositiveRecord[],
): FalsePositiveMarker[] {
  return records.map((r) => ({ category: r.category, file: r.file, line: r.line }));
}

/** A finding "signal" the tuning hook matches against — metadata only. */
export interface FalsePositiveTuningSignal {
  category: Category;
  file: string;
  line: number;
  ruleId?: string;
}

/**
 * Injected regression-corpus tuning for the correlation + confirmation layers.
 * Additive + fail-safe by contract: consumers may only DOWN-RANK / SKIP a
 * matched finding (never promote), so a stale corpus can never weaken a
 * guardrail — only make the pipeline more conservative.
 */
export interface FalsePositiveTuning {
  isKnownFalsePositive(signal: FalsePositiveTuningSignal): boolean;
  /** Number of distinct locations in the tuning set (introspection/tests). */
  readonly size: number;
}

export interface BuildTuningOptions {
  /**
   * Max |signal.line - recorded.line| to still match. Default 0 (exact): only
   * the operator's exact marked location is suppressed, so unrelated code that
   * later shifts onto that line is re-evaluated rather than silently skipped.
   */
  lineTolerance?: number;
}

/**
 * Build a deterministic tuning matcher from corpus records (or bare markers).
 * Matches on category + file with a line tolerance. Pure and stateless.
 */
export function buildFalsePositiveTuning(
  entries: readonly FalsePositiveRecord[] | readonly FalsePositiveMarker[],
  opts: BuildTuningOptions = {},
): FalsePositiveTuning {
  const tol = Math.max(0, opts.lineTolerance ?? 0);
  // category|file -> sorted unique lines.
  const byLocation = new Map<string, number[]>();
  for (const e of entries) {
    const key = `${e.category} ${e.file}`;
    const lines = byLocation.get(key) ?? [];
    if (!lines.includes(e.line)) lines.push(e.line);
    byLocation.set(key, lines);
  }
  for (const lines of byLocation.values()) lines.sort((a, b) => a - b);

  return {
    size: byLocation.size,
    isKnownFalsePositive(signal: FalsePositiveTuningSignal): boolean {
      const lines = byLocation.get(`${signal.category} ${signal.file}`);
      if (!lines) return false;
      return lines.some((l) => Math.abs(l - signal.line) <= tol);
    },
  };
}
