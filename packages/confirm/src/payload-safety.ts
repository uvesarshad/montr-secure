/**
 * A16 (2026-09-12 red/blue agentic-posture audit) — the deterministic SAFETY
 * PREDICATE that gates a model-COMPOSED live-DAST payload before it is ever
 * allowed to leave the process.
 *
 * Context: `live.ts`'s E3 adaptive loop previously let the model choose only
 * an id from a small, hardcoded, pre-authored `PAYLOAD_VARIANTS` catalog —
 * "AI-driven" meant picking one of three or four pre-written strings. This
 * module is the new, genuinely restrictive piece that lets the model instead
 * COMPOSE a payload's literal text, while guaranteeing it can never be used
 * unless it independently clears every rule below. This predicate is NOT a
 * replacement for `guard.ts` — it constrains the PAYLOAD's content (what
 * string gets sent), while `guard.ts`'s `ScopeGuard` independently constrains
 * the REQUEST (target allowlist, production block, blast-radius/rate caps,
 * egress) regardless of where the payload came from. Both gates must pass;
 * neither one substitutes for the other (defense in depth, golden rule #4).
 *
 * Design (fail-closed throughout — any ambiguity rejects, never permits):
 *   1. A hard length cap and a strict printable-ASCII character-class bound
 *      per category, rejecting anything that could smuggle binary/shellcode
 *      or control-character tricks.
 *   2. A STRUCTURAL check that the payload actually looks like a proof for
 *      the category being tested (e.g. an SSRF proposal must parse as an
 *      absolute http(s) URL; a SQLi proposal must contain a SQL-shaped
 *      token). A payload that doesn't match the category's expected proof
 *      shape is rejected even if it's otherwise "safe" text.
 *   3. A DESTRUCTIVE-OPERATION check, category-aware: SQL keywords that
 *      mutate or drop data (DROP/DELETE/UPDATE/INSERT/TRUNCATE/ALTER/…),
 *      shell commands beyond a tiny read-only allowlist (id/whoami/echo/
 *      pwd/hostname/uname/sleep, bounded), dangerous HTML sinks/tags for
 *      XSS (exfiltration, iframes, eval), non-http(s) URL schemes and
 *      embedded credentials for SSRF, and traversal targets that reach
 *      credential/key material for path traversal.
 *
 * Only categories with a clear, boundable "prove without harming" shape are
 * eligible for composition at all — see {@link COMPOSABLE_LIVE_CATEGORIES}.
 * Every other live-confirmable category (nosql_injection, open_redirect,
 * idor, broken_access_control, xxe, insecure_deserialization) stays
 * pre-written-PAYLOAD_VARIANTS-only; `evaluateComposedPayloadSafety` always
 * rejects them (defense in depth even if a caller mistakenly invokes it).
 */
import type { Category } from "@montr/contracts";

/**
 * Categories eligible for model-COMPOSED (not just model-SELECTED) live-DAST
 * payloads. Deliberately a SUBSET of `LIVE_CONFIRMABLE_CATEGORIES` — only
 * categories with an unambiguous, boundable "prove without harming" shape:
 *
 *   - sql_injection: a SQL-shaped read/boolean/time-based proof is
 *     structurally distinguishable from a mutating statement (keyword
 *     denylist + no stacked queries).
 *   - xss: a small, checkable tag/attribute allowlist plus a required,
 *     harness-supplied marker keeps proof strictly to "does it reflect
 *     unescaped", never exfiltration.
 *   - ssrf: the payload IS a URL — trivially structurally validated (scheme,
 *     no embedded credentials) independent of what internal target it names.
 *   - path_traversal: a traversal-sequence-shaped string, denylisted against
 *     credential/key file targets and shell metacharacters.
 *   - command_injection: an injection-connector-shaped string whose actual
 *     command token is checked against a tiny read-only allowlist
 *     (id/whoami/echo/pwd/hostname/uname/sleep, all non-mutating).
 *
 * LEFT ON PRE-WRITTEN-ONLY, deliberately, and why:
 *   - nosql_injection: its safe proof space is a handful of curated,
 *     non-mutating comparison OPERATORS ($ne/$gt/$regex/$exists). NoSQL
 *     injection commonly also reaches UPDATE/DELETE-shaped operators
 *     ($set/$unset/$rename/$push) — a free-form composed operator payload
 *     risks constructing one of those. The curated set already covers the
 *     recognizable technique family; composition adds little and raises the
 *     ceiling on what a "read-only" claim could hide.
 *   - open_redirect: the payload is just an off-site URL/encoding trick; the
 *     three pre-written variants (protocol-relative, backslash, userinfo@)
 *     already exhaustively cover the realistic bypass-encoding space, and a
 *     structural predicate here ("is it a URL-ish string") barely
 *     distinguishes anything — composition adds surface without adding
 *     signal.
 *   - idor: the proof is choosing a different RESOURCE ID, not authoring
 *     content. Nothing to safely "compose" beyond what far_id/negative_id
 *     already try.
 *   - broken_access_control: the proof is STRIPPING auth headers, not
 *     payload content — again, nothing to compose.
 *   - xxe: composing free-form XML/DOCTYPE/ENTITY bodies is high risk — an
 *     attacker-shaped ENTITY SYSTEM URI can reach network resources
 *     (SSRF-via-XXE) or nested nested nested entities can cause a
 *     billion-laughs-style resource-exhaustion DoS. The two pre-written
 *     variants already prove the sink parses external entities via a fixed,
 *     reviewed, local-file-only target.
 *   - insecure_deserialization: by explicit design (see live.ts's own
 *     AGENT NOTE) this category NEVER sends a gadget chain. A composed
 *     typed/polymorphic marker risks accidentally shaping something
 *     gadget-chain-like; staying pre-written keeps that guarantee absolute.
 */
export const COMPOSABLE_LIVE_CATEGORIES: ReadonlySet<Category> = new Set<Category>([
  "sql_injection",
  "xss",
  "ssrf",
  "path_traversal",
  "command_injection",
]);

export function isComposableLiveCategory(category: Category): boolean {
  return COMPOSABLE_LIVE_CATEGORIES.has(category);
}

export interface PayloadSafetyVerdict {
  safe: boolean;
  /** Always populated — the exact rule that passed or failed, for audit/log. */
  reason: string;
}

function reject(reason: string): PayloadSafetyVerdict {
  return { safe: false, reason };
}

function ok(reason: string): PayloadSafetyVerdict {
  return { safe: true, reason };
}

/** Absolute ceiling for every category — real proofs never need more. */
const HARD_MAX_LENGTH = 300;

/** Printable ASCII only (0x20–0x7E). Blocks binary/shellcode/control-char/NUL tricks. */
const PRINTABLE_ASCII_ONLY = /^[\x20-\x7E]*$/;

function checkGenericBounds(payload: string, maxLength: number): PayloadSafetyVerdict | undefined {
  if (typeof payload !== "string" || payload.length === 0) {
    return reject("payload must be a non-empty string");
  }
  if (payload.length > Math.min(maxLength, HARD_MAX_LENGTH)) {
    return reject(`payload exceeds the max allowed length (${maxLength} chars)`);
  }
  if (!PRINTABLE_ASCII_ONLY.test(payload)) {
    return reject("payload contains non-printable/binary characters (printable ASCII only)");
  }
  return undefined;
}

/* --------------------------------- sql_injection --------------------------------- */

const SQLI_MAX_LENGTH = 150;
/** A payload must LOOK like SQL — a quote, or a recognizable SQLi keyword/operator. */
const SQLI_SHAPE = /'|"|\b(or|and|union|select|sleep|waitfor|benchmark)\b/i;
/** Mutating/destructive/exfiltrating SQL keywords — never permitted in a proof payload. */
const SQLI_DESTRUCTIVE = new RegExp(
  "\\b(drop|delete|truncate|update|insert|alter|create|exec|execute|grant|revoke|attach|" +
    "shutdown|xp_cmdshell|load_file)\\b|into\\s+(outfile|dumpfile)",
  "i",
);
/** Bound any SLEEP/WAITFOR DELAY argument to a small non-destructive value. */
const SQLI_SLEEP_ARG = /\b(?:sleep|pg_sleep)\s*\(\s*(\d+(?:\.\d+)?)\s*\)/i;
const SQLI_WAITFOR_ARG = /waitfor\s+delay\s+'0*(\d+):(\d+):(\d+)'/i;
const SQLI_MAX_SLEEP_SECONDS = 5;

function evaluateSqlInjectionPayload(payload: string): PayloadSafetyVerdict {
  const bounds = checkGenericBounds(payload, SQLI_MAX_LENGTH);
  if (bounds) return bounds;
  if (payload.includes(";")) {
    return reject("semicolon (stacked-query risk) is never permitted in a composed SQLi payload");
  }
  if (!SQLI_SHAPE.test(payload)) {
    return reject(
      "payload does not structurally resemble a SQL-injection proof (no quote/keyword)",
    );
  }
  if (SQLI_DESTRUCTIVE.test(payload)) {
    return reject(
      "payload contains a data-mutating/destructive SQL keyword — proof must be read-only",
    );
  }
  const sleepMatch = SQLI_SLEEP_ARG.exec(payload);
  if (sleepMatch) {
    const seconds = Number(sleepMatch[1]);
    if (!Number.isFinite(seconds) || seconds > SQLI_MAX_SLEEP_SECONDS) {
      return reject(
        `SLEEP()/pg_sleep() argument exceeds the ${SQLI_MAX_SLEEP_SECONDS}s non-destructive bound`,
      );
    }
  }
  const waitforMatch = SQLI_WAITFOR_ARG.exec(payload);
  if (waitforMatch) {
    const [, hh, mm, ss] = waitforMatch;
    const totalSeconds = Number(hh) * 3600 + Number(mm) * 60 + Number(ss);
    if (totalSeconds > SQLI_MAX_SLEEP_SECONDS) {
      return reject(`WAITFOR DELAY exceeds the ${SQLI_MAX_SLEEP_SECONDS}s non-destructive bound`);
    }
  }
  return ok("SQL-shaped, non-destructive, within bounds");
}

/* ------------------------------------- xss -------------------------------------- */

const XSS_MAX_LENGTH = 200;
/** Only these tags/vectors are permitted — a small, checkable allowlist. */
const XSS_ALLOWED_TAG = /<\s*(script|img|svg)\b/i;
const XSS_EVENT_HANDLER_OR_TAG = /<\/?\w+[^>]*>|on\w+\s*=|javascript:/i;
/** Dangerous sinks/tags/exfiltration vectors — never permitted. */
const XSS_DANGEROUS = new RegExp(
  "<\\s*(iframe|object|embed|form|meta|link|base)\\b|document\\.cookie|fetch\\s*\\(|" +
    "xmlhttprequest|eval\\s*\\(|localstorage|sessionstorage|<\\s*style\\b|import\\s*\\(",
  "i",
);
/** No external URLs — a proof only ever needs to prove REFLECTION, never exfiltration. */
const XSS_EXTERNAL_URL = /https?:\/\//i;

function evaluateXssPayload(payload: string, marker: string | undefined): PayloadSafetyVerdict {
  const bounds = checkGenericBounds(payload, XSS_MAX_LENGTH);
  if (bounds) return bounds;
  if (!XSS_EVENT_HANDLER_OR_TAG.test(payload)) {
    return reject("payload does not structurally resemble an XSS proof (no tag/event handler)");
  }
  if (XSS_DANGEROUS.test(payload)) {
    return reject("payload uses a disallowed tag/sink (iframe/object/form/cookie/fetch/eval/…)");
  }
  if (XSS_EXTERNAL_URL.test(payload)) {
    return reject("payload references an external URL — proof must never attempt exfiltration");
  }
  // If the tag-based form is used, it must be one of the small allowed set.
  const tagMatch = /<\s*(\w+)/.exec(payload);
  if (tagMatch && !XSS_ALLOWED_TAG.test(payload)) {
    return reject(`<${tagMatch[1]}> is not on the allowed tag list (script/img/svg only)`);
  }
  if (!marker) {
    return reject("no harness marker supplied — cannot verify reflection deterministically");
  }
  if (!payload.includes(marker)) {
    return reject(
      "payload does not embed the required harness marker — reflection cannot be verified",
    );
  }
  return ok("tag/vector-allowlisted, marker-verifiable, no exfiltration, within bounds");
}

/* ------------------------------------- ssrf -------------------------------------- */

const SSRF_MAX_LENGTH = 300;
const SSRF_ALLOWED_SCHEMES = new Set(["http:", "https:"]);

function evaluateSsrfPayload(payload: string): PayloadSafetyVerdict {
  const bounds = checkGenericBounds(payload, SSRF_MAX_LENGTH);
  if (bounds) return bounds;
  let url: URL;
  try {
    url = new URL(payload);
  } catch {
    return reject("payload does not parse as an absolute URL — SSRF proof must target a URL");
  }
  if (!SSRF_ALLOWED_SCHEMES.has(url.protocol)) {
    return reject(
      `scheme "${url.protocol}" is not permitted — only http/https (no file:/gopher:/dict:/ftp:/…)`,
    );
  }
  if (url.username || url.password) {
    return reject("payload embeds URL credentials (userinfo) — not permitted");
  }
  if (!url.host) {
    return reject("payload URL has no host");
  }
  return ok("valid http(s) URL, no embedded credentials, within bounds");
}

/* --------------------------------- path_traversal --------------------------------- */

const PATH_TRAVERSAL_MAX_LENGTH = 200;
const PATH_TRAVERSAL_SHAPE = /(\.\.\/|\.\.\\|%2e%2e(%2f|%5c|\/|\\)|\.\.%2f|\.\.%5c)/i;
/** Shell metacharacters have no business in a path-parameter value. */
const PATH_TRAVERSAL_SHELL_METACHARS = /[;|`$<>]/;
/** Credential/key-material targets are disproportionate blast radius even for a "read". */
const PATH_TRAVERSAL_SENSITIVE_TARGET =
  /shadow|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem\b|\.ppk\b|\.ssh\//i;

function evaluatePathTraversalPayload(payload: string): PayloadSafetyVerdict {
  const bounds = checkGenericBounds(payload, PATH_TRAVERSAL_MAX_LENGTH);
  if (bounds) return bounds;
  if (!PATH_TRAVERSAL_SHAPE.test(payload)) {
    return reject(
      "payload does not contain a directory-traversal sequence (../, ..\\, or an encoded form)",
    );
  }
  if (PATH_TRAVERSAL_SHELL_METACHARS.test(payload)) {
    return reject(
      "payload contains shell metacharacters — not permitted in a path-parameter value",
    );
  }
  if (PATH_TRAVERSAL_SENSITIVE_TARGET.test(payload)) {
    return reject(
      "payload targets credential/private-key material — disproportionate blast radius",
    );
  }
  return ok("traversal-shaped, no shell metacharacters, non-sensitive target, within bounds");
}

/* ------------------------------- command_injection -------------------------------- */

const COMMAND_INJECTION_MAX_LENGTH = 100;
/** An injection connector followed by the actual command to run. */
const COMMAND_INJECTION_CONNECTOR = /(;|\||`|\$\(|&&)/;
/** Redirection/backgrounding — never permitted (could write files / detach a process). */
const COMMAND_INJECTION_REDIRECTION = /[><]|(?<!&)&(?!&)/;
/** The ONLY command tokens ever permitted — every one is read-only / non-mutating. */
const COMMAND_INJECTION_ALLOWED_COMMAND =
  /(?:^|[;|`&(]|\$\()\s*(id|whoami|pwd|hostname|uname(?:\s+-a)?|echo\s+[\w.-]{1,64}|sleep\s+([0-5])(?:\.\d+)?)\s*(?:[)`]|;|\||&&|$)/i;
/**
 * Explicit denylist of dangerous/mutating binaries and shells, scanned across
 * the WHOLE payload (not just the segment the allowlist regex happened to
 * match) — closes a smuggling gap where a payload like `"; id; rm -rf /; echo
 * M"` would otherwise satisfy the allowlist-PRESENCE check above via its `id`
 * or `echo` segment while a destructive command rides along in another
 * connector-joined segment. Any hit here rejects the entire payload.
 */
const COMMAND_INJECTION_DENYLIST = new RegExp(
  "\\b(rm|dd|mkfs|chmod|chown|chgrp|kill|shutdown|reboot|halt|poweroff|curl|wget|nc|ncat|" +
    "netcat|telnet|ssh|scp|sftp|ftp|python[0-9.]*|perl|ruby|php|bash|zsh|ksh|csh|sh|" +
    "powershell|cmd|mv|cp|useradd|userdel|usermod|groupadd|passwd|iptables|systemctl|" +
    "service|mkdir|rmdir|touch|tee|base64|eval|exec|nohup|crontab|xargs|awk|sed|" +
    "su|sudo|reg|regedit|taskkill|format|del|erase|shred|truncate)\\b",
  "i",
);

/**
 * Every occurrence of `sleep` anywhere in the payload must carry a bounded
 * (0-5 second) numeric argument. Checked INDEPENDENTLY of
 * `COMMAND_INJECTION_ALLOWED_COMMAND` (which only tests for the PRESENCE of
 * some allowed command somewhere) — otherwise `"...; sleep 60; echo M"`
 * would slip through on the strength of its unrelated `echo M` segment while
 * carrying an unbounded (effectively denial-of-service) delay.
 */
const COMMAND_INJECTION_SLEEP_TOKEN = /\bsleep\b\s*([^\s;|&`)]*)/gi;
const COMMAND_INJECTION_MAX_SLEEP_SECONDS = 5;

function evaluateCommandInjectionPayload(
  payload: string,
  marker: string | undefined,
): PayloadSafetyVerdict {
  const bounds = checkGenericBounds(payload, COMMAND_INJECTION_MAX_LENGTH);
  if (bounds) return bounds;
  if (!COMMAND_INJECTION_CONNECTOR.test(payload)) {
    return reject("payload has no injection connector (;, |, `, $(), or &&)");
  }
  if (COMMAND_INJECTION_REDIRECTION.test(payload)) {
    return reject("payload uses redirection/backgrounding (>, <, or a lone &) — not permitted");
  }
  if (COMMAND_INJECTION_DENYLIST.test(payload)) {
    return reject(
      "payload references a disallowed/destructive command — not on the read-only allowlist",
    );
  }
  for (const m of payload.matchAll(COMMAND_INJECTION_SLEEP_TOKEN)) {
    const arg = m[1] ?? "";
    const seconds = Number(arg);
    if (!Number.isFinite(seconds) || seconds < 0 || seconds > COMMAND_INJECTION_MAX_SLEEP_SECONDS) {
      return reject(
        `sleep argument "${arg}" exceeds the ${COMMAND_INJECTION_MAX_SLEEP_SECONDS}s non-destructive bound`,
      );
    }
  }
  if (!COMMAND_INJECTION_ALLOWED_COMMAND.test(payload)) {
    return reject(
      "command is not on the read-only allowlist (id/whoami/pwd/hostname/uname/echo/sleep 0-5 only)",
    );
  }
  if (!marker) {
    return reject("no harness marker supplied — cannot verify command execution deterministically");
  }
  if (!payload.includes(marker)) {
    return reject(
      "payload does not embed the required harness marker — execution cannot be verified",
    );
  }
  return ok("connector + read-only allowlisted command, marker-verifiable, within bounds");
}

/* ------------------------------------ dispatch ------------------------------------ */

export interface EvaluateComposedPayloadOptions {
  /**
   * Harness-generated marker the payload must embed verbatim so success can
   * be verified deterministically by `live.ts`'s oracle, rather than trusting
   * the model's own claim. Required for xss and command_injection (the two
   * composable categories whose proof depends on an echoed/reflected token);
   * ignored for the others.
   */
  marker?: string;
}

/**
 * The safety predicate. Every model-composed live-DAST payload MUST pass
 * this before `live.ts` will ever build a request from it — fail-closed:
 * an unrecognized/non-composable category, malformed input, or any single
 * failing rule rejects the whole payload. Never a "best effort" pass.
 */
export function evaluateComposedPayloadSafety(
  category: Category,
  payload: string,
  options: EvaluateComposedPayloadOptions = {},
): PayloadSafetyVerdict {
  if (typeof payload !== "string") {
    return reject("payload must be a string");
  }
  switch (category) {
    case "sql_injection":
      return evaluateSqlInjectionPayload(payload);
    case "xss":
      return evaluateXssPayload(payload, options.marker);
    case "ssrf":
      return evaluateSsrfPayload(payload);
    case "path_traversal":
      return evaluatePathTraversalPayload(payload);
    case "command_injection":
      return evaluateCommandInjectionPayload(payload, options.marker);
    default:
      // Fail-closed: every category NOT in COMPOSABLE_LIVE_CATEGORIES is
      // categorically rejected, even if a caller mistakenly invokes this.
      return reject(`category "${category}" is not eligible for composed live-DAST payloads`);
  }
}
