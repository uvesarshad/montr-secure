/**
 * Log SCRUBBER (§10, golden rule #1). GUARANTEES that no code body or secret
 * value is ever emitted to a log sink. THREE independent defenses:
 *
 *   1. Known-sensitive FIELD redaction — any key whose name matches
 *      {@link DEFAULT_SENSITIVE_KEY_PATTERN} (patch/code/snippet/prompt/token/
 *      apiKey/password/cookie/…) is replaced wholesale, regardless of value.
 *   2. Body-size GUARD — any string longer than `maxStringLength` is redacted
 *      (an oversize string is assumed to be a code or data body).
 *   3. CONTENT GUARD (key-independent) — any string that matches a known secret
 *      VALUE format or looks like a source-code BODY is redacted even under an
 *      innocuous, sub-cap key. This closes the gap where a secret/code payload
 *      hides under a benign field name (certified by @montr/security's
 *      `assertScrubberNeutralizes(scrubValue, ADVERSARIAL_LOG_THREATS)`).
 *
 * The scrubber is deterministic and dependency-free so it can run inside the
 * hot logging path and inside the audit-log write path. Over-redaction is the
 * intended failure mode (fail-safe: never leak).
 */

/** Placeholder written in place of a redacted value. */
export const REDACTED = "[REDACTED]";

/**
 * Field names that carry code or secret bodies. Broad by design — redacting a
 * benign field (e.g. `keyTier`) is acceptable; leaking a secret is not.
 */
export const DEFAULT_SENSITIVE_KEY_PATTERN =
  /(pass(word|phrase)?|pwd|secret|token|api[-_]?key|authorization|auth[-_]?token|bearer|jwt|session[-_]?id|cookie|credential|private[-_]?key|access[-_]?key|refresh[-_]?token|code|source|body|patch|diff|snippet|prompt|content|evidence|key)/i;

/** Content-guard only inspects strings at least this long for code-like bodies. */
const CODE_MIN_LENGTH = 40;

/**
 * Well-known, low-false-positive secret VALUE formats. Kept in sync with (but
 * intentionally independent of) `@montr/security`'s `SECRET_VALUE_MATCHERS`, so
 * telemetry's hot-path scrubber stays dependency-free while still neutralising a
 * secret that hides under an innocuous key.
 */
const SECRET_VALUE_MATCHERS: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/, // aws access key id
  /\bghp_[A-Za-z0-9]{36}\b/, // github pat
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/, // github fine-grained pat
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, // slack token
  /\bsk-ant-[A-Za-z0-9_-]{16,}\b/, // anthropic api key
  /\bsk-[A-Za-z0-9]{20,}\b/, // openai api key
  /\bAIza[0-9A-Za-z_-]{35}\b/, // google api key
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, // jwt
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/, // pem private key
  /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/, // bearer credential
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

/** True if `value` matches a known secret VALUE format. */
function looksLikeSecretValue(value: string): boolean {
  for (const re of SECRET_VALUE_MATCHERS) if (re.test(value)) return true;
  return false;
}

/**
 * Heuristic: does this string look like a source-code body? Conservative toward
 * NOT flagging short/prose strings (needs 3 signals, or 2 + a newline); the
 * oversize cap catches long bodies regardless. Over-flagging code is acceptable.
 */
function looksLikeSourceCode(value: string): boolean {
  if (value.length < CODE_MIN_LENGTH) return false;
  let hits = 0;
  for (const re of CODE_SIGNALS) {
    if (re.test(value)) hits++;
    if (hits >= 3) return true;
  }
  return value.includes("\n") && hits >= 2;
}

export interface ScrubberOptions {
  /** Keys matching this pattern are always redacted. */
  readonly sensitiveKeyPattern?: RegExp;
  /** Strings longer than this are redacted as a suspected body (default 1024). */
  readonly maxStringLength?: number;
  /** Recursion guard — nested structures deeper than this are collapsed (default 8). */
  readonly maxDepth?: number;
  /** Placeholder written for redacted values. */
  readonly placeholder?: string;
}

interface ResolvedOptions {
  readonly sensitiveKeyPattern: RegExp;
  readonly maxStringLength: number;
  readonly maxDepth: number;
  readonly placeholder: string;
}

function resolve(opts?: ScrubberOptions): ResolvedOptions {
  return {
    sensitiveKeyPattern: opts?.sensitiveKeyPattern ?? DEFAULT_SENSITIVE_KEY_PATTERN,
    maxStringLength: opts?.maxStringLength ?? 1024,
    maxDepth: opts?.maxDepth ?? 8,
    placeholder: opts?.placeholder ?? REDACTED,
  };
}

/**
 * Redact an oversize / secret-valued / code-like string; benign short strings
 * pass through unchanged. The content checks are key-independent so a secret or
 * code body under an innocuous field name is still neutralised (golden rule #1).
 */
function guardString(value: string, o: ResolvedOptions): string {
  if (value.length > o.maxStringLength) {
    return `${o.placeholder}:oversize:${value.length}b`;
  }
  if (looksLikeSecretValue(value)) return `${o.placeholder}:secret`;
  if (looksLikeSourceCode(value)) return `${o.placeholder}:code`;
  return value;
}

function scrubUnknown(value: unknown, o: ResolvedOptions, depth: number): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return guardString(value, o);
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }
  if (depth >= o.maxDepth) return `${o.placeholder}:depth`;
  if (Array.isArray(value)) {
    return value.map((v) => scrubUnknown(v, o, depth + 1));
  }
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) {
    // Never spread an Error blindly — its `message` can carry echoed input.
    return { name: value.name, message: guardString(value.message, o) };
  }
  if (typeof value === "object") {
    return scrubRecord(value as Record<string, unknown>, o, depth);
  }
  // functions, symbols — never log.
  return `${o.placeholder}:unloggable`;
}

function scrubRecord(
  record: Record<string, unknown>,
  o: ResolvedOptions,
  depth: number,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (o.sensitiveKeyPattern.test(key)) {
      out[key] = o.placeholder;
    } else {
      out[key] = scrubUnknown(value, o, depth + 1);
    }
  }
  return out;
}

/**
 * Scrub an arbitrary value for safe logging / audit persistence.
 * Objects are recursed; oversize strings and sensitive keys are redacted.
 */
export function scrubValue(value: unknown, opts?: ScrubberOptions): unknown {
  return scrubUnknown(value, resolve(opts), 0);
}

/**
 * Scrub a structured log-fields record. Backwards-compatible signature: given a
 * `Record<string, unknown>` (or undefined) it returns a redacted record.
 */
export function scrubFields(
  fields: Record<string, unknown> | undefined,
  opts?: ScrubberOptions,
): Record<string, unknown> {
  if (!fields) return {};
  return scrubRecord(fields, resolve(opts), 0);
}

/** Create a reusable scrubber bound to a fixed option set. */
export function createScrubber(opts?: ScrubberOptions): {
  scrubValue: (value: unknown) => unknown;
  scrubFields: (fields: Record<string, unknown> | undefined) => Record<string, unknown>;
} {
  const resolved = resolve(opts);
  return {
    scrubValue: (value) => scrubUnknown(value, resolved, 0),
    scrubFields: (fields) => (fields ? scrubRecord(fields, resolved, 0) : {}),
  };
}
