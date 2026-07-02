/**
 * LOG-SCRUBBER VERIFIER (build-plan §4.8, golden rule #1 & #7).
 *
 * `@montr/telemetry` already ships the SCRUBBER that redacts log fields on the
 * hot path. This module is the independent VERIFIER/assertion layer WS-N owns:
 * it PROVES that no source-code body and no secret value can reach a log or
 * audit sink. Two roles:
 *
 *   1. Redaction helpers ({@link redactSensitive}) — a self-contained redactor
 *      that, in addition to sensitive-key + oversize redaction (telemetry's
 *      model), also detects secret-VALUE formats and code-like BODIES by content
 *      (key-independent). Strictly stronger than a key/size-only scrubber.
 *   2. Assertions ({@link assertNoSecretsOrCode}, {@link findLogViolations}) and
 *      a scrubber CERTIFIER ({@link assertScrubberNeutralizes}) that runs an
 *      adversarial battery through ANY scrubber and proves the output is clean.
 *
 * Fail-safe by design: over-redaction is acceptable, leaking is not. The verifier
 * never echoes an offending value — violations carry only a path + kind + size.
 * Dependency-free (no telemetry import) so it is an INDEPENDENT check; the tests
 * point it at telemetry's real scrubber to certify it.
 */

/** Default placeholder recognised as "already redacted". Matches telemetry. */
export const REDACTED = "[REDACTED]";

/** Strings longer than this are treated as a suspected body (aligns w/ telemetry). */
export const DEFAULT_MAX_STRING_LENGTH = 1024;

/** Code-like detection only considers strings at least this long. */
export const CODE_MIN_LENGTH = 40;

/** Hard recursion bound (cycle-safe walk also uses a WeakSet). */
const HARD_MAX_DEPTH = 64;

/**
 * Field names that carry code or secret bodies. Broad by design and aligned with
 * `@montr/telemetry`'s DEFAULT_SENSITIVE_KEY_PATTERN so telemetry-scrubbed output
 * verifies clean. Redacting a benign field is acceptable; leaking a secret is not.
 */
export const SENSITIVE_KEY_PATTERN =
  /(pass(word|phrase)?|pwd|secret|token|api[-_]?key|authorization|auth[-_]?token|bearer|jwt|session[-_]?id|cookie|credential|private[-_]?key|access[-_]?key|refresh[-_]?token|code|source|body|patch|diff|snippet|prompt|content|evidence|key)/i;

/** Well-known, low-false-positive secret VALUE formats. */
export interface SecretMatcher {
  readonly name: string;
  readonly re: RegExp;
}

export const SECRET_VALUE_MATCHERS: readonly SecretMatcher[] = [
  { name: "aws_access_key_id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "github_pat", re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: "github_fine_grained_pat", re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { name: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "anthropic_api_key", re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/ },
  { name: "openai_api_key", re: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { name: "pem_private_key", re: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/ },
  { name: "bearer_credential", re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/ },
];

/** Structural / keyword signals that a string is a source-code body. */
const CODE_SIGNALS: readonly RegExp[] = [
  /\b(function|const|let|var|import|export|return|class|new|await|async|require|yield|throw|typeof)\b/,
  /=>/,
  /\bdef\s+\w+\s*\(/, // python
  /\b(public|private|protected|static|void|final)\b/, // jvm-ish
  /<[a-zA-Z/][^>]{0,200}>/, // html / jsx tag (bounded, ReDoS-safe)
  /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,4000}?\b(FROM|INTO|SET|WHERE)\b/i, // sql
  /[;{}]\s*\n/, // statement / brace + newline
  /^\s*(if|for|while|switch|catch)\s*\(/m,
  /#include\b|package\s+[\w.]+;/,
];

export type LogViolationKind =
  "sensitive_value" | "secret_value" | "code_body" | "oversize" | "unloggable";

/** A leak the verifier found. NEVER carries the offending value itself. */
export interface LogViolation {
  /** JSON-ish path to the node, e.g. `$.request.patch`. */
  readonly path: string;
  readonly kind: LogViolationKind;
  /** Metadata-only description (size, matcher name) — never the value. */
  readonly detail: string;
}

export interface ScrubVerifyOptions {
  readonly sensitiveKeyPattern?: RegExp;
  readonly maxStringLength?: number;
  readonly placeholder?: string;
  /** Extra secret-value matchers to add to the defaults. */
  readonly extraSecretMatchers?: readonly SecretMatcher[];
}

interface Resolved {
  readonly sensitiveKeyPattern: RegExp;
  readonly maxStringLength: number;
  readonly placeholder: string;
  readonly matchers: readonly SecretMatcher[];
}

function resolve(opts?: ScrubVerifyOptions): Resolved {
  return {
    sensitiveKeyPattern: opts?.sensitiveKeyPattern ?? SENSITIVE_KEY_PATTERN,
    maxStringLength: opts?.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH,
    placeholder: opts?.placeholder ?? REDACTED,
    matchers: opts?.extraSecretMatchers
      ? [...SECRET_VALUE_MATCHERS, ...opts.extraSecretMatchers]
      : SECRET_VALUE_MATCHERS,
  };
}

/** True if the string is (or begins with) a redaction placeholder. */
export function isRedactionPlaceholder(value: string, placeholder = REDACTED): boolean {
  return value === placeholder || value.startsWith(placeholder);
}

/** Return the name of the first secret format matched, or undefined. */
export function detectSecretValue(
  value: string,
  matchers = SECRET_VALUE_MATCHERS,
): string | undefined {
  for (const m of matchers) {
    if (m.re.test(value)) return m.name;
  }
  return undefined;
}

/**
 * Heuristic: does this string look like a source-code body? Conservative toward
 * NOT flagging short/prose strings; combined with the oversize cap, long code
 * bodies are caught regardless. Fail-safe: over-flagging code is acceptable.
 */
export function looksLikeSourceCode(value: string): boolean {
  if (value.length < CODE_MIN_LENGTH) return false;
  let hits = 0;
  for (const re of CODE_SIGNALS) {
    if (re.test(value)) hits++;
    if (hits >= 3) return true;
  }
  return value.includes("\n") && hits >= 2;
}

interface WalkCtx {
  readonly path: string;
  readonly sensitive: boolean;
}

function checkString(value: string, ctx: WalkCtx, o: Resolved, out: LogViolation[]): void {
  if (isRedactionPlaceholder(value, o.placeholder)) return;
  if (ctx.sensitive) {
    out.push({
      path: ctx.path,
      kind: "sensitive_value",
      detail: `${value.length}b under a sensitive key was not redacted`,
    });
    return;
  }
  if (value.length > o.maxStringLength) {
    out.push({ path: ctx.path, kind: "oversize", detail: `${value.length}b string exceeds cap` });
    return;
  }
  const secret = detectSecretValue(value, o.matchers);
  if (secret) {
    out.push({ path: ctx.path, kind: "secret_value", detail: `matched ${secret}` });
    return;
  }
  if (looksLikeSourceCode(value)) {
    out.push({ path: ctx.path, kind: "code_body", detail: `${value.length}b code-like body` });
  }
}

function walk(
  value: unknown,
  ctx: WalkCtx,
  o: Resolved,
  out: LogViolation[],
  seen: WeakSet<object>,
  depth: number,
): void {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    checkString(value, ctx, o, out);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return;
  if (value instanceof Date) return;
  if (typeof value === "function" || typeof value === "symbol") {
    out.push({ path: ctx.path, kind: "unloggable", detail: typeof value });
    return;
  }
  if (depth >= HARD_MAX_DEPTH) return;
  if (typeof value === "object") {
    if (seen.has(value)) return; // cycle guard
    seen.add(value);
    if (value instanceof Error) {
      // Only the message can echo input; stack/other props are dropped by scrubbers.
      checkString(value.message, { path: `${ctx.path}.message`, sensitive: ctx.sensitive }, o, out);
      return;
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        walk(
          value[i],
          { path: `${ctx.path}[${i}]`, sensitive: ctx.sensitive },
          o,
          out,
          seen,
          depth + 1,
        );
      }
      return;
    }
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      const sensitive = ctx.sensitive || o.sensitiveKeyPattern.test(key);
      walk(v, { path: `${ctx.path}.${key}`, sensitive }, o, out, seen, depth + 1);
    }
  }
}

/**
 * Find every place a code body or secret value could leak into a log/audit sink.
 * Returns an empty array when the value is safe to persist.
 */
export function findLogViolations(value: unknown, opts?: ScrubVerifyOptions): LogViolation[] {
  const out: LogViolation[] = [];
  walk(value, { path: "$", sensitive: false }, resolve(opts), out, new WeakSet(), 0);
  return out;
}

/** Thrown by {@link assertNoSecretsOrCode}. Carries metadata-only violations. */
export class LogScrubViolationError extends Error {
  readonly violations: readonly LogViolation[];
  constructor(violations: readonly LogViolation[]) {
    const kinds = [...new Set(violations.map((v) => v.kind))].join(", ");
    super(
      `log-scrub verifier: ${violations.length} violation(s) [${kinds}] — a code body or secret value would reach the log sink`,
    );
    this.name = "LogScrubViolationError";
    this.violations = violations;
    Object.setPrototypeOf(this, LogScrubViolationError.prototype);
  }
}

/**
 * Assert a value is safe to log/persist: throws {@link LogScrubViolationError} if
 * any code body or secret value survives. Use on already-scrubbed payloads to
 * PROVE the scrubber did its job (golden rule #1).
 */
export function assertNoSecretsOrCode(value: unknown, opts?: ScrubVerifyOptions): void {
  const violations = findLogViolations(value, opts);
  if (violations.length > 0) throw new LogScrubViolationError(violations);
}

// ---------------------------------------------------------------------------
// Redaction helper (self-contained redactor — stronger than key/size-only).
// ---------------------------------------------------------------------------

function redactString(value: string, ctx: WalkCtx, o: Resolved): string {
  if (isRedactionPlaceholder(value, o.placeholder)) return value;
  if (ctx.sensitive) return o.placeholder;
  if (value.length > o.maxStringLength) return `${o.placeholder}:oversize:${value.length}b`;
  if (detectSecretValue(value, o.matchers)) return `${o.placeholder}:secret`;
  if (looksLikeSourceCode(value)) return `${o.placeholder}:code`;
  return value;
}

function redactWalk(
  value: unknown,
  ctx: WalkCtx,
  o: Resolved,
  seen: WeakSet<object>,
  depth: number,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value, ctx, o);
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "function" || typeof value === "symbol")
    return `${o.placeholder}:unloggable`;
  if (depth >= HARD_MAX_DEPTH) return `${o.placeholder}:depth`;
  if (typeof value === "object") {
    if (seen.has(value)) return `${o.placeholder}:cycle`;
    seen.add(value);
    if (value instanceof Error) {
      return { name: value.name, message: redactString(value.message, ctx, o) };
    }
    if (Array.isArray(value)) {
      return value.map((v, i) =>
        redactWalk(v, { path: `${ctx.path}[${i}]`, sensitive: ctx.sensitive }, o, seen, depth + 1),
      );
    }
    const outObj: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      const sensitive = ctx.sensitive || o.sensitiveKeyPattern.test(key);
      outObj[key] = redactWalk(v, { path: `${ctx.path}.${key}`, sensitive }, o, seen, depth + 1);
    }
    return outObj;
  }
  return `${o.placeholder}:unloggable`;
}

/**
 * Return a redacted CLONE safe to log/persist: sensitive keys are replaced
 * wholesale, oversize strings capped, and secret-value / code-like strings
 * neutralised by content (key-independent). `assertNoSecretsOrCode` on the
 * result always passes.
 */
export function redactSensitive(value: unknown, opts?: ScrubVerifyOptions): unknown {
  return redactWalk(value, { path: "$", sensitive: false }, resolve(opts), new WeakSet(), 0);
}

// ---------------------------------------------------------------------------
// Scrubber certifier — proves an arbitrary scrubber neutralises a battery.
// ---------------------------------------------------------------------------

/** A long, code-like body (multiline, many signals) used as an adversarial input. */
const CODE_BODY = [
  "export async function handler(req, res) {",
  "  const id = req.query.id;",
  "  const rows = await db.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);",
  "  return res.json(rows);",
  "}",
].join("\n");

const OVERSIZE = "A".repeat(DEFAULT_MAX_STRING_LENGTH + 500);

/**
 * REALISTIC threats: every item is neutralisable by a key/size-only scrubber
 * (secret/code lives under a sensitive KEY, or the payload is oversize). Any
 * compliant scrubber — including telemetry's — must neutralise all of these.
 */
export const REALISTIC_LOG_THREATS: readonly unknown[] = [
  { patch: CODE_BODY },
  { code: CODE_BODY },
  { snippet: `${CODE_BODY}\n${CODE_BODY}` },
  { apiKey: "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX" },
  { token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQRstuv" },
  { authorization: "Bearer abcdefghijklmnopqrstuvwxyz0123456789" },
  { password: "correct-horse-battery-staple-0123456789" },
  { cookie: "session=abcdef0123456789abcdef0123456789" },
  { request: { headers: { authorization: "Bearer 0123456789abcdef0123456789abcdef" } } },
  OVERSIZE,
  { blob: OVERSIZE },
];

/**
 * ADVERSARIAL threats: superset that also hides secrets/code under INNOCUOUS
 * keys at sub-oversize length. Requires a CONTENT-aware scrubber (like
 * {@link redactSensitive}); a key/size-only scrubber will leak these.
 */
export const ADVERSARIAL_LOG_THREATS: readonly unknown[] = [
  ...REALISTIC_LOG_THREATS,
  { note: CODE_BODY }, // code under an innocuous key
  { info: "aws key AKIAIOSFODNN7EXAMPLE leaked" },
  { detail: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----" },
  { message: "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVwxyz" },
];

/** A scrubber under test: takes an arbitrary value, returns a log-safe value. */
export type ScrubberFn = (value: unknown) => unknown;

/** Thrown by {@link assertScrubberNeutralizes} when a sample leaks. */
export class ScrubberCertificationError extends Error {
  readonly failures: ReadonlyArray<{ sampleIndex: number; violations: readonly LogViolation[] }>;
  constructor(
    failures: ReadonlyArray<{ sampleIndex: number; violations: readonly LogViolation[] }>,
  ) {
    super(
      `scrubber certification FAILED: ${failures.length} sample(s) leaked a code body or secret value`,
    );
    this.name = "ScrubberCertificationError";
    this.failures = failures;
    Object.setPrototypeOf(this, ScrubberCertificationError.prototype);
  }
}

export interface CertificationReport {
  readonly certified: boolean;
  readonly samplesChecked: number;
  readonly failures: ReadonlyArray<{ sampleIndex: number; violations: readonly LogViolation[] }>;
}

/**
 * Run each sample through `scrub` and verify the OUTPUT has no violations.
 * Proves the scrubber neutralises the battery. Throws
 * {@link ScrubberCertificationError} on any leak (metadata only — never values).
 *
 * @param scrub    the scrubber under test (e.g. telemetry's `scrubValue`).
 * @param samples  battery of adversarial inputs (default {@link REALISTIC_LOG_THREATS}).
 */
export function assertScrubberNeutralizes(
  scrub: ScrubberFn,
  samples: readonly unknown[] = REALISTIC_LOG_THREATS,
  opts?: ScrubVerifyOptions,
): CertificationReport {
  const failures: Array<{ sampleIndex: number; violations: readonly LogViolation[] }> = [];
  samples.forEach((sample, sampleIndex) => {
    let scrubbed: unknown;
    try {
      scrubbed = scrub(sample);
    } catch (e) {
      failures.push({
        sampleIndex,
        violations: [
          { path: "$", kind: "unloggable", detail: `scrubber threw: ${(e as Error).name}` },
        ],
      });
      return;
    }
    const violations = findLogViolations(scrubbed, opts);
    if (violations.length > 0) failures.push({ sampleIndex, violations });
  });
  if (failures.length > 0) throw new ScrubberCertificationError(failures);
  return { certified: true, samplesChecked: samples.length, failures: [] };
}
