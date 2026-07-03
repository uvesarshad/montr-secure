/**
 * Python (Django / FastAPI / Flask) confirmation heuristics (Layer 3a).
 *
 * ⛔ SEAM FOR THE PYTHON STACK AGENT (build-plan §7 Wave 4, PRD §16 Phase 3).
 * Registered in `../registry.ts`; the confirmation engine (`static.ts` /
 * `taxonomy.ts`) is untouched. These EXTRA lexical hints are APPENDED to the
 * stack-agnostic base — they can only make the deterministic source→sink proof
 * MORE precise, never bypass it (golden rules #4, #6).
 *
 * The markers are aligned with the sink descriptions emitted by the Python App-Map
 * taint analyzer (`@montr/appmap` `languages/python/taint.ts`). Every unsafe marker
 * is deliberately free of any base SAFE-marker substring (`parameteri`, `escap`,
 * `saniti`, `validate`, `allowlist`, `placeholder`) so a dangerous Python sink is
 * never mis-read as sanitized. The base already treats `orm_raw_query`,
 * `command_exec`, `eval`, `deserialize`, `html_render`, and `template_render` as
 * inherently raw, so no extra `rawSinkKinds` are needed — the extra markers make
 * `sql_query`, `http_client` (SSRF), `redirect`, and `fs_*` (path traversal)
 * confirmable when their note shows an unsanitized construct.
 */
import type { Language } from "@montr/contracts";
import type { ConfirmationHeuristics } from "../types.js";

export const pythonHeuristics: ConfirmationHeuristics = {
  id: "python",
  appliesTo(languages: readonly Language[]): boolean {
    return languages.includes("python");
  },

  unsafeMarkers: [
    "raw sql",
    "raw orm",
    "raw html",
    ".raw(",
    ".extra(",
    "os.system",
    "os.popen",
    "subprocess",
    "shell=true",
    "mark_safe",
    "render_template_string",
    "template injection",
    "|safe",
    "pickle.loads",
    "pickle.load",
    "yaml.load(",
    "marshal.loads",
    "ssrf",
    "server-side request",
    "open redirect",
    "path traversal",
  ],

  safeMarkers: [
    // Genuine Python sanitizers/validators — only ever appear in a SAFE note.
    "bleach",
    "is_safe_url",
    "url_has_allowed_host",
    "yaml.safe_load",
    "get_object_or_404",
    "serializer.is_valid",
  ],

  paramPatterns: [
    // `request.GET.get("uid")`, `request.form.get("name")`, `request.data.get(...)`
    /request\.(?:GET|POST|args|form|values|query_params|data|files|COOKIES|cookies|headers)\.get\(['"]([A-Za-z0-9_]+)/,
    // `request.GET["uid"]`, `request.form['name']`
    /request\.(?:GET|POST|args|form|values|query_params|data|files)\[['"]([A-Za-z0-9_]+)/,
  ],

  // Base already covers the raw Python sink kinds; nothing extra to add.
  rawSinkKinds: [],
};
