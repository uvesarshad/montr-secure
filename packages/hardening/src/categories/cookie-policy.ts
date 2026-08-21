/**
 * Cookie policy (B9). Detects session-looking cookies set via a
 * `.cookie(name, value[, opts])` / `.setCookie(name, value[, opts])` call
 * (Express `res.cookie`, Fastify `reply.setCookie`, and any framework
 * sharing that call shape) that are missing `Secure`/`HttpOnly`/`SameSite`.
 * Deliberately independent of `packages/fix/src/strategies.ts`'s own
 * (mechanical-fix) cookie-flag regex — this module is read-only detection
 * for an advisory, not a patch generator, and must not import `@montr/fix`
 * at all (see this package's index.ts module doc).
 *
 * Only flags cookies whose NAME looks session-related (session/sid/auth/
 * token/jwt/connect.sid) — a generic non-auth cookie (an A/B-test flag, a
 * theme preference) missing these flags is a real but much lower-stakes gap,
 * and out of scope for "session/cookie handling" per this task's brief. A
 * cookie call with every flag already set produces NO recommendation
 * (precision).
 */
import { isSourceFile, readAll, type FileProvider } from "@montr/discovery";
import type { RecommendationDraft } from "../types.js";

const COOKIE_CALL_RE =
  /\.(?:cookie|setCookie)\(\s*(['"`])((?:(?!\1).)*)\1\s*,\s*[^,()]+(?:\([^)]*\))?\s*(?:,\s*(\{[^{}]*\}))?\s*\)/g;
const SESSION_LOOKING_NAME_RE = /session|sid|auth|token|jwt|connect\.sid/i;

function missingFlags(opts: string | undefined): string[] {
  const o = opts ?? "";
  const missing: string[] = [];
  if (!/\bsecure\s*:\s*true\b/i.test(o)) missing.push("Secure");
  if (!/\bhttponly\s*:\s*true\b/i.test(o)) missing.push("HttpOnly");
  if (!/\bsamesite\s*:/i.test(o)) missing.push("SameSite");
  return missing;
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

export async function detectCookiePolicyGaps(files: FileProvider): Promise<RecommendationDraft[]> {
  const sources = await readAll(files, isSourceFile);
  const drafts: RecommendationDraft[] = [];

  for (const f of sources) {
    const re = new RegExp(COOKIE_CALL_RE.source, COOKIE_CALL_RE.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(f.content)) !== null) {
      const name = m[2] ?? "";
      if (!SESSION_LOOKING_NAME_RE.test(name)) continue;
      const missing = missingFlags(m[3]);
      if (missing.length === 0) continue; // fully hardened already — no redundant recommendation.

      const line = lineAt(f.content, m.index);
      drafts.push({
        category: "cookie_policy",
        severity: missing.includes("Secure") || missing.includes("HttpOnly") ? "high" : "medium",
        title: `Add missing ${missing.join("/")} attribute(s) to the "${name}" cookie`,
        gap: `${f.path}:${line} sets a session-looking cookie ("${name}") missing ${missing.join(", ")}.`,
        recommendation: `Set ${missing.map((flag) => `\`${flag}\``).join(", ")} on the "${name}" cookie, e.g.: .cookie("${name}", value, { ...existingOptions, ${missing
          .map((flag) =>
            flag === "Secure"
              ? "secure: true"
              : flag === "HttpOnly"
                ? "httpOnly: true"
                : 'sameSite: "lax"',
          )
          .join(", ")} })`,
        rationale:
          "A session cookie without Secure can be sent over plain HTTP; without HttpOnly it is readable by client-side script (XSS cookie theft); without SameSite it is sent cross-site (CSRF).",
        evidence: [`${f.path}:${line}: .cookie("${name}", ...) missing ${missing.join(", ")}`],
      });
    }
  }

  return drafts;
}
