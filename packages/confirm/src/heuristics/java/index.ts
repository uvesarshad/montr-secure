/**
 * JVM (Spring / JPA) confirmation heuristics (Layer 3a).
 *
 * Registered in `../registry.ts`; the confirmation engine (`static.ts` /
 * `taxonomy.ts`) is untouched. These EXTRA lexical hints are APPENDED to the
 * stack-agnostic base — they can only make the deterministic source→sink proof
 * MORE precise, never bypass it (golden rules #4, #6).
 *
 * The markers are aligned with the sink descriptions emitted by the JVM App-Map
 * taint analyzer (`@montr/appmap` `languages/java/extract.ts`). Every unsafe
 * marker is deliberately free of any base SAFE-marker substring (`parameteri`,
 * `escap`, `saniti`, `validate`, `allowlist`, `placeholder`, `prepared`,
 * `bound param`) so a dangerous JVM sink is never mis-read as sanitized. The base
 * already treats `orm_raw_query`, `command_exec`, `eval`, and `deserialize` as
 * inherently raw, so those confirm off the base alone; the extra markers make
 * `sql_query` (string-concatenated JDBC), `redirect` (open redirect), and the
 * SpEL/reflection `eval` phrasings confirmable, and add JVM sanitizer names
 * (`setParameter`, `CriteriaBuilder`, `HtmlUtils.htmlEscape`, OWASP encoders) so
 * a genuinely parameterized/escaped path is correctly demoted. No extra
 * `rawSinkKinds` — a bare `sql_query` with no marker stays unconfirmed (fail-safe).
 */
import type { Language } from "@montr/contracts";
import type { ConfirmationHeuristics } from "../types.js";

export const javaHeuristics: ConfirmationHeuristics = {
  id: "java",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("java");
  },

  unsafeMarkers: [
    // Raw JDBC / JPQL string building (aligned with extract.ts sink notes).
    "raw sql",
    "string concatenation",
    "native query",
    "jpql",
    "createnativequery",
    // OS command execution.
    "runtime.getruntime",
    "runtime.exec",
    ".exec(",
    "processbuilder",
    "os command",
    // Unsafe deserialization.
    "objectinputstream",
    "readobject",
    // Reflection + SpEL expression evaluation.
    "class.forname",
    "reflective class loading",
    "parseexpression",
    "spel expression",
    // Open redirect.
    "sendredirect",
    "caller-influenced url",
  ],

  safeMarkers: [
    // Genuine JVM sanitizers/validators — only ever appear in a SAFE note.
    "setparameter",
    "criteriabuilder",
    "htmlutils.htmlescape",
    "htmlescape",
    "owasp encoder",
    "esapi",
    "policyfactory",
    "jsoup.clean",
    "@valid",
    "typedquery",
  ],

  paramPatterns: [
    // `@RequestParam q`, `@PathVariable userId`, `@RequestBody dto` (extract.ts note).
    /@(?:RequestParam|PathVariable|RequestHeader|CookieValue|RequestBody|ModelAttribute)\s+([A-Za-z0-9_]+)/,
    // `getParameter("id")`, `getHeader("X-Api-Key")` from an HttpServletRequest.
    /get(?:Parameter|ParameterValues|Header|Part)\(\s*["']([A-Za-z0-9_]+)["']/,
  ],

  // Base already covers the raw JVM sink kinds; nothing extra to add.
  rawSinkKinds: [],
};
