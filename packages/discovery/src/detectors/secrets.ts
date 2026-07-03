/**
 * Secrets & Config agent (§5.2). Two deterministic sources:
 *   1. gitleaks subprocess (injectable; degrades gracefully if the binary is
 *      absent) — hardcoded credentials.
 *   2. Custom, offline regex detectors — hardcoded keys, client-exposed env
 *      secrets, weak crypto defaults, permissive CORS, missing security headers,
 *      and insecure cookie flags.
 *
 * ⛔ Secret VALUES are never stored: every evidence snippet is redacted here, so
 * no live credential ever lands in the candidate row, the audit log, or a log
 * line (golden rule #1, defense-in-depth on top of the telemetry scrubber).
 */
import nodePath from "node:path";
import { randomUUID } from "node:crypto";
import type { Category, CandidateFinding, CweId, Severity, ToolSource } from "@montr/contracts";
import type { DetectorContext, GitleaksFinding, GitleaksRunner } from "../types.js";
import { buildCandidate } from "../util/candidate.js";
import { isSourceFile, readAll, type RepoFile } from "../util/files.js";
import { errMessage, isBinaryMissing } from "../util/text.js";

export interface DetectSecretsOptions {
  runner?: GitleaksRunner;
  /**
   * Language-specific EXTRA custom detectors, run per file IN ADDITION to the
   * always-on base set. Selected by the caller from the ruleset registry
   * (`selectCustomDetectors(appMap)`); empty for the Phase-1 TS/JS path, so
   * behavior is unchanged. Python/JVM agents author detectors under
   * `rulesets/<lang>/`.
   */
  extraDetectors?: readonly FileDetector[];
}

// ---------------------------------------------------------------------------
// gitleaks
// ---------------------------------------------------------------------------

/** Default runner: shells out to `gitleaks` (dynamically imported execa). */
export const defaultGitleaksRunner: GitleaksRunner = async ({ repoRoot, signal }) => {
  const { execa } = await import("execa");
  const os = await import("node:os");
  const fs = await import("node:fs/promises");
  const report = nodePath.join(os.tmpdir(), `montr-gitleaks-${randomUUID()}.json`);
  try {
    const res = await execa(
      "gitleaks",
      [
        "detect",
        "--source",
        repoRoot,
        "--no-git",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        report,
      ],
      // execa v9 renamed the abort option `signal` → `cancelSignal`.
      { reject: false, cancelSignal: signal, timeout: 300_000 },
    );
    const raw = await fs.readFile(report, "utf8").catch(() => "");
    await fs.rm(report, { force: true }).catch(() => undefined);
    if (raw.trim()) {
      const parsed: unknown = JSON.parse(raw);
      return Array.isArray(parsed) ? (parsed as GitleaksFinding[]) : [];
    }
    // No report written: a failed spawn (binary absent) → signal unavailable so
    // the detector degrades with a warning; a clean run reports no leaks.
    if (res.failed) return null;
    return [];
  } catch (err) {
    if (isBinaryMissing(err)) return null;
    throw err;
  }
};

function candidatesFromGitleaks(
  ctx: DetectorContext,
  findings: GitleaksFinding[],
): CandidateFinding[] {
  const out: CandidateFinding[] = [];
  for (const f of findings) {
    const rule = f.RuleID ?? "gitleaks-secret";
    out.push(
      buildCandidate(ctx, {
        source: "gitleaks",
        ruleId: rule,
        category: "hardcoded_secret",
        file: (f.File ?? "").replace(/^\.\//, ""),
        line: f.StartLine ?? 0,
        endLine: f.EndLine,
        rawSeverity: "high",
        // NEVER f.Secret / f.Match — redacted, metadata-grade only.
        snippet: `secret detected by gitleaks rule '${rule}' (value redacted)`,
        title: f.Description ?? `Hardcoded secret (${rule})`,
        metadata: { detector: "gitleaks", rule },
      }),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// Custom detectors (deterministic, offline)
// ---------------------------------------------------------------------------

/** A raw detector hit (pre-{@link buildCandidate}). Exported so per-language
 *  ruleset plugins can author {@link FileDetector}s under `rulesets/<lang>/`. */
export interface RawFinding {
  source?: ToolSource;
  rule: string;
  category: Category;
  cwe?: CweId[];
  severity: Severity;
  line: number;
  snippet: string;
  title: string;
  metadata?: Record<string, unknown>;
}

function lineAt(content: string, index: number): number {
  let line = 1;
  const end = Math.min(index, content.length);
  for (let i = 0; i < end; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

function maskSecret(value: string): string {
  const v = value.trim();
  if (v.length <= 4) return "****";
  return `${v.slice(0, 4)}…[REDACTED]`;
}

function looksLikePlaceholder(value: string): boolean {
  const v = value.trim();
  if (v.length < 8) return true;
  if (/process\.env/.test(v)) return true;
  if (/^\$\{?[A-Za-z0-9_]+\}?$/.test(v)) return true; // ${ENV} / $ENV
  if (/^[x*]+$/i.test(v)) return true;
  if (/^(?:changeme|change-me|example|placeholder|dummy|todo|your[_-].*|<[^>]+>)$/i.test(v))
    return true;
  return false;
}

interface SecretRule {
  rule: string;
  re: RegExp;
  /** Specific = high-signal prefix; never placeholder-filtered. */
  specific: boolean;
  /** Capture group holding the secret value (for placeholder-filtering generics). */
  valueGroup?: number;
  title: string;
}

const SECRET_RULES: readonly SecretRule[] = [
  {
    rule: "stripe-live-secret-key",
    re: /sk_live_[0-9a-zA-Z]{10,}/g,
    specific: true,
    title: "Hardcoded Stripe live secret key",
  },
  {
    rule: "stripe-test-secret-key",
    re: /sk_test_[0-9a-zA-Z]{10,}/g,
    specific: true,
    title: "Hardcoded Stripe test secret key",
  },
  {
    rule: "aws-access-key-id",
    re: /AKIA[0-9A-Z]{16}/g,
    specific: true,
    title: "Hardcoded AWS access key id",
  },
  {
    rule: "google-api-key",
    re: /AIza[0-9A-Za-z\-_]{35}/g,
    specific: true,
    title: "Hardcoded Google API key",
  },
  {
    rule: "slack-token",
    re: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    specific: true,
    title: "Hardcoded Slack token",
  },
  {
    rule: "github-token",
    re: /gh[pousr]_[0-9A-Za-z]{20,}/g,
    specific: true,
    title: "Hardcoded GitHub token",
  },
  {
    rule: "private-key-block",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    specific: true,
    title: "Hardcoded private key",
  },
  {
    rule: "generic-assigned-secret",
    re: /(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([^"']{12,})["']/gi,
    specific: false,
    valueGroup: 1,
    title: "Hardcoded credential assignment",
  },
];

function detectSecretsInFile(file: RepoFile): RawFinding[] {
  const out: RawFinding[] = [];
  const claimed = new Set<number>(); // lines already claimed by a specific rule
  for (const rule of SECRET_RULES) {
    const re = new RegExp(
      rule.re.source,
      rule.re.flags.includes("g") ? rule.re.flags : `${rule.re.flags}g`,
    );
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.content)) !== null) {
      const line = lineAt(file.content, m.index);
      const value = rule.valueGroup ? (m[rule.valueGroup] ?? m[0]) : m[0];
      if (!rule.specific && (looksLikePlaceholder(value) || claimed.has(line))) {
        if (m.index === re.lastIndex) re.lastIndex++;
        continue;
      }
      if (rule.specific) claimed.add(line);
      out.push({
        rule: `secrets.${rule.rule}`,
        category: "hardcoded_secret",
        severity: "high",
        line,
        snippet: `${rule.rule}; value redacted: ${maskSecret(value)}`,
        title: rule.title,
        metadata: { detector: "custom-secret", rule: rule.rule },
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return out;
}

const CORS_RE = /Access-Control-Allow-Origin["']?\s*(?::|,|=>|=)\s*["']\*["']/gi;
const CORS_CREDENTIALS_RE = /Access-Control-Allow-Credentials["']?\s*(?::|,|=>|=)\s*["']?true/i;

function detectCorsInFile(file: RepoFile): RawFinding[] {
  const out: RawFinding[] = [];
  const withCredentials = CORS_CREDENTIALS_RE.test(file.content);
  let m: RegExpExecArray | null;
  const re = new RegExp(CORS_RE.source, CORS_RE.flags);
  while ((m = re.exec(file.content)) !== null) {
    out.push({
      rule: "config.permissive-cors",
      category: "permissive_cors",
      severity: withCredentials ? "high" : "medium",
      line: lineAt(file.content, m.index),
      snippet: "Access-Control-Allow-Origin: * (wildcard origin)",
      title: withCredentials
        ? "Permissive CORS: wildcard origin WITH credentials"
        : "Permissive CORS: wildcard origin",
      metadata: { detector: "custom-cors", withCredentials },
    });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

const CRYPTO_RULES: ReadonlyArray<{ rule: string; re: RegExp; title: string }> = [
  {
    rule: "weak-hash",
    re: /createHash\(\s*["'](?:md5|sha1)["']/gi,
    title: "Weak hash function (MD5/SHA-1)",
  },
  {
    rule: "weak-cipher",
    re: /createCipher(?:iv)?\(\s*["'](?:des|des-ecb|rc4|rc4-hmac|aes-128-ecb|aes-256-ecb|bf|blowfish)["']/gi,
    title: "Insecure/weak cipher (DES/RC4/ECB)",
  },
  {
    rule: "legacy-createcipher",
    re: /crypto\.createCipher\(/g,
    title: "Deprecated crypto.createCipher (no IV)",
  },
  {
    rule: "insecure-randomness",
    re: /(?:token|secret|otp|nonce|password|api[_-]?key|session[_-]?id)[^;\n]{0,40}Math\.random\s*\(/gi,
    title: "Insufficient randomness for a security value",
  },
];

function detectWeakCryptoInFile(file: RepoFile): RawFinding[] {
  const out: RawFinding[] = [];
  for (const rule of CRYPTO_RULES) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.content)) !== null) {
      out.push({
        rule: `crypto.${rule.rule}`,
        category: "weak_crypto",
        severity: "medium",
        line: lineAt(file.content, m.index),
        snippet: rule.title,
        title: rule.title,
        metadata: { detector: "custom-crypto", rule: rule.rule },
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return out;
}

const NEXT_PUBLIC_SECRET_RE =
  /NEXT_PUBLIC_[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)[A-Z0-9_]*/g;

function detectExposedEnvInFile(file: RepoFile): RawFinding[] {
  const out: RawFinding[] = [];
  const re = new RegExp(NEXT_PUBLIC_SECRET_RE.source, NEXT_PUBLIC_SECRET_RE.flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.content)) !== null) {
    out.push({
      rule: "config.client-exposed-secret-env",
      category: "sensitive_data_exposure",
      severity: "high",
      line: lineAt(file.content, m.index),
      snippet: `client-exposed secret env var: ${m[0]}`,
      title: "Secret exposed to the browser via NEXT_PUBLIC_ env var",
      metadata: { detector: "custom-env", var: m[0] },
    });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

const COOKIE_SETTER_RE =
  /(?:res\.cookie|response\.cookies\.set|cookies\(\)\.set|setHeader\(\s*["']set-cookie["'])/gi;

function detectInsecureCookieInFile(file: RepoFile): RawFinding[] {
  const out: RawFinding[] = [];
  const re = new RegExp(COOKIE_SETTER_RE.source, COOKIE_SETTER_RE.flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(file.content)) !== null) {
    const windowText = file.content.slice(m.index, m.index + 200);
    const httpOnly = /httponly/i.test(windowText);
    const secure = /\bsecure\b/i.test(windowText);
    if (httpOnly && secure) {
      if (m.index === re.lastIndex) re.lastIndex++;
      continue;
    }
    const missing = [!httpOnly ? "httpOnly" : null, !secure ? "secure" : null].filter(Boolean);
    out.push({
      rule: "config.insecure-cookie",
      category: "insecure_cookie",
      severity: "medium",
      line: lineAt(file.content, m.index),
      snippet: `cookie set without ${missing.join(" + ")} flag(s)`,
      title: "Insecure cookie: missing HttpOnly/Secure flags",
      metadata: { detector: "custom-cookie", missing },
    });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function detectMissingHeadersInFile(file: RepoFile): RawFinding[] {
  const base = nodePath.posix.basename(file.path);
  if (!/^next\.config\.(?:js|mjs|cjs|ts)$/.test(base)) return [];
  const hasHeaders = /(?:async\s+)?headers\s*[(:]/.test(file.content);
  if (hasHeaders) return [];
  const anchor = file.content.search(
    /module\.exports|export\s+default|const\s+nextConfig|let\s+nextConfig/,
  );
  return [
    {
      rule: "nextjs.missing-security-headers",
      category: "missing_security_headers",
      severity: "medium",
      line: anchor >= 0 ? lineAt(file.content, anchor) : 1,
      snippet: "next.config defines no headers() → no CSP / HSTS / X-Frame-Options",
      title: "Missing security headers (no headers() in next.config)",
      metadata: { detector: "custom-headers", confidence: "low" },
    },
  ];
}

/** A per-file custom detector. Per-language ruleset plugins export these. */
export type FileDetector = (file: RepoFile) => RawFinding[];

/**
 * Always-on base custom detectors. These are largely stack-agnostic (secret
 * literals, wildcard CORS, weak crypto, insecure cookies) with a couple of
 * Node/Next specifics; per-language plugins ADD to them via `extraDetectors`.
 */
const FILE_DETECTORS: readonly FileDetector[] = [
  detectSecretsInFile,
  detectCorsInFile,
  detectWeakCryptoInFile,
  detectExposedEnvInFile,
  detectInsecureCookieInFile,
  detectMissingHeadersInFile,
];

/**
 * Run the base custom detectors (plus any language-specific `extra` ones) across
 * one file's content. Exposed for unit tests. `extra` defaults to empty, so the
 * single-arg call is unchanged.
 */
export function runCustomDetectors(
  file: RepoFile,
  extra: readonly FileDetector[] = [],
): RawFinding[] {
  return [...FILE_DETECTORS, ...extra].flatMap((d) => d(file));
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function detectSecretsAndConfig(
  ctx: DetectorContext,
  opts: DetectSecretsOptions = {},
): Promise<CandidateFinding[]> {
  if (ctx.signal?.aborted) return [];
  const out: CandidateFinding[] = [];

  // 1. gitleaks (optional; degrade gracefully).
  const runner = opts.runner;
  if (runner || ctx.repoRoot) {
    let findings: GitleaksFinding[] | null = null;
    try {
      findings = await (runner ?? defaultGitleaksRunner)({
        repoRoot: ctx.repoRoot ?? ".",
        signal: ctx.signal,
      });
    } catch (err) {
      ctx.warn("secrets", `gitleaks run failed; secrets scan degraded. ${errMessage(err)}`);
    }
    if (findings === null) {
      ctx.warn("secrets", "gitleaks binary unavailable; relying on custom detectors only.");
    } else {
      out.push(...candidatesFromGitleaks(ctx, findings));
    }
  }

  // 2. Custom detectors over text files (always run — fully offline). Base
  // detectors + any language-specific extras selected from the ruleset registry.
  const extraDetectors = opts.extraDetectors ?? [];
  const files = await readAll(ctx.files, (p) => isTextForSecrets(p));
  for (const file of files) {
    if (ctx.signal?.aborted) break;
    for (const raw of runCustomDetectors(file, extraDetectors)) {
      out.push(
        buildCandidate(ctx, {
          source: raw.source ?? "custom",
          ruleId: raw.rule,
          category: raw.category,
          cwe: raw.cwe,
          file: file.path,
          line: raw.line,
          rawSeverity: raw.severity,
          snippet: raw.snippet,
          title: raw.title,
          metadata: raw.metadata,
        }),
      );
    }
  }
  return out;
}

/** Text files worth scanning for secrets/config issues. */
function isTextForSecrets(path: string): boolean {
  const base = nodePath.posix.basename(path);
  if (base.startsWith(".env")) return true;
  if (isSourceFile(path)) return true;
  return /\.(?:json|ya?ml|toml|ini|conf|prisma)$/i.test(path);
}
