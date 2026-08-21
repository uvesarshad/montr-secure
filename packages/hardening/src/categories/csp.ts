/**
 * Content-Security-Policy (B9). A real, App-Map-grounded CSP recommendation
 * — never a generic boilerplate string. Two decisions are grounded:
 *
 *   1. Whether to recommend anything at all: skipped when the repo already
 *      sets a Content-Security-Policy header/meta tag with no obviously weak
 *      directive (a bare `*` source or `unsafe-inline` for script-src).
 *   2. WHICH directives to recommend: `script-src`/`style-src` are widened
 *      (with an explicit nonce-migration note, never a blanket
 *      `unsafe-inline` grant) only when inline `<script>`/`dangerouslySetInnerHTML`
 *      or inline `style=`/`style={{` usage is actually detected in the repo.
 *
 * Scope, stated honestly: file discovery reuses `@montr/discovery`'s
 * `isTextFile` (`packages/discovery/src/util/files.ts`), which is scoped to
 * source/config extensions for SAST-style scanning and deliberately does NOT
 * include raw `.html`/`.ejs`/`.pug` template files. In practice this means
 * inline-script/style detection here is real for JSX/TSX
 * (`dangerouslySetInnerHTML`, `style={{...}}`, a literal `<script>` embedded
 * in a `.tsx` return) but blind to a server-rendered static HTML/templating
 * layer — a target using those would need its own detector, out of scope
 * for this pass.
 */
import type { AppMap } from "@montr/contracts";
import { isTextFile, readAll, type FileProvider } from "@montr/discovery";
import type { RecommendationDraft } from "../types.js";

const CSP_MENTION_RE = /content-security-policy/i;
// Matches `.setHeader("Content-Security-Policy", "...")` or a headers()-array
// `{ key: "Content-Security-Policy", value: "..." }` — captures via a
// backreference to the OPENING quote character (not a `[^"'\`]+` class) so an
// embedded single-quoted CSP source keyword like `'unsafe-inline'` inside a
// double-quoted header value string is not truncated at the first apostrophe.
const CSP_VALUE_RE =
  /content-security-policy["'`]?\s*[:,]\s*(?:value\s*[:=]\s*)?(['"`])((?:(?!\1).)*)\1/i;
// `<meta http-equiv="Content-Security-Policy" content="...">` — same
// backreference approach for the `content` attribute's value.
const CSP_META_RE =
  /<meta[^>]+http-equiv=(['"])content-security-policy\1[^>]*\bcontent=(['"])((?:(?!\2).)*)\2/i;

const INLINE_SCRIPT_RE = /<script(?![^>]*\bsrc=)[^>]*>\s*[^<\s][^<]*<\/script>/i;
const DANGEROUS_HTML_RE = /dangerouslySetInnerHTML/;
const INLINE_STYLE_ATTR_RE = /<[a-zA-Z][a-zA-Z0-9]*\s+[^>]*\bstyle\s*=\s*["']/;
const JSX_INLINE_STYLE_RE = /\bstyle=\{\{/;

function isWeakCsp(value: string): boolean {
  return /unsafe-inline/i.test(value) || /(^|[\s;])(default|script)-src\s+[^;]*\*/i.test(value);
}

export async function detectCspGap(
  appMap: AppMap,
  files: FileProvider,
): Promise<RecommendationDraft[]> {
  // CSP is meaningless for an app with no HTTP surface.
  if (appMap.routes.length === 0) return [];

  const textFiles = await readAll(files, isTextFile);

  for (const f of textFiles) {
    const metaMatch = CSP_META_RE.exec(f.content);
    const headerMatch = CSP_VALUE_RE.exec(f.content);
    const value = metaMatch?.[3] ?? headerMatch?.[2];
    if (value) {
      if (isWeakCsp(value)) {
        return [
          {
            category: "csp",
            severity: "medium",
            title: "Tighten the existing Content-Security-Policy",
            gap: `${f.path} sets a Content-Security-Policy that allows \`unsafe-inline\` and/or a wildcard source: \`${value}\`.`,
            recommendation:
              "Replace the wildcard/`unsafe-inline` source(s) with `'self'` plus, if inline script is genuinely required, a per-request nonce (e.g. `script-src 'self' 'nonce-<per-request-value>'`) rather than `unsafe-inline`.",
            rationale:
              "`unsafe-inline` and wildcard sources defeat CSP's main purpose (blocking injected/attacker-controlled script), leaving XSS findings exploitable even with a header present.",
            evidence: [`${f.path}: Content-Security-Policy value "${value}"`],
          },
        ];
      }
      // A present, non-obviously-weak CSP — do not recommend redundantly (precision).
      return [];
    }
    if (CSP_MENTION_RE.test(f.content)) {
      // Mentioned but the value could not be safely extracted (e.g. built from
      // an object of directives) — fail-safe to silence rather than guess.
      return [];
    }
  }

  // No CSP found anywhere — ground the recommended directives in actual inline usage.
  let hasInlineScript = false;
  let hasInlineStyle = false;
  const scriptEvidence: string[] = [];
  const styleEvidence: string[] = [];
  for (const f of textFiles) {
    if (
      !hasInlineScript &&
      (INLINE_SCRIPT_RE.test(f.content) || DANGEROUS_HTML_RE.test(f.content))
    ) {
      hasInlineScript = true;
      scriptEvidence.push(`${f.path}: inline <script> or dangerouslySetInnerHTML usage`);
    }
    if (
      !hasInlineStyle &&
      (INLINE_STYLE_ATTR_RE.test(f.content) || JSX_INLINE_STYLE_RE.test(f.content))
    ) {
      hasInlineStyle = true;
      styleEvidence.push(`${f.path}: inline style attribute usage`);
    }
    if (hasInlineScript && hasInlineStyle) break;
  }

  const scriptSrc = hasInlineScript
    ? "script-src 'self' 'nonce-<per-request-value>'; # inline <script>/dangerouslySetInnerHTML detected — migrate to a nonce, do not add 'unsafe-inline'"
    : "script-src 'self';";
  const styleSrc = hasInlineStyle
    ? "style-src 'self' 'unsafe-inline'; # inline style= usage detected — tolerated for style (lower XSS impact than script), migrate to CSS classes/CSS-in-JS nonces when practical"
    : "style-src 'self';";

  const evidence = [
    'No Content-Security-Policy header or <meta http-equiv="Content-Security-Policy"> found anywhere in the repo',
    ...scriptEvidence.slice(0, 3),
    ...styleEvidence.slice(0, 3),
  ];

  return [
    {
      category: "csp",
      severity: "medium",
      title: "Add a Content-Security-Policy",
      gap: "No Content-Security-Policy is set anywhere in the app.",
      recommendation: [
        "Content-Security-Policy:",
        "  default-src 'self';",
        `  ${scriptSrc}`,
        `  ${styleSrc}`,
        "  object-src 'none';",
        "  base-uri 'self';",
        "  frame-ancestors 'none';",
      ].join("\n"),
      rationale:
        "With no CSP, a successful XSS finding has no second line of defense — injected script runs with full page privileges.",
      evidence,
    },
  ];
}
