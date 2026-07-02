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
 */
import {
  KillSwitchActivatedError,
  type AppMap,
  type Category,
  type HttpExchange,
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

/** Categories with a SAFE, high-signal live oracle. Others stay static-only. */
export const LIVE_CONFIRMABLE_CATEGORIES = new Set<Category>([
  "sql_injection",
  "nosql_injection",
  "xss",
  "open_redirect",
]);

export function isLiveEligible(category: Category): boolean {
  return LIVE_CONFIRMABLE_CATEGORIES.has(category);
}

interface Probe {
  request: { method: string; url: string; headers?: Record<string, string> };
  role: "baseline" | "payload";
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
};

/** Craft the (non-destructive, GET-only) probe set for a live-confirmable finding. */
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

  switch (finding.category) {
    case "sql_injection":
    case "nosql_injection":
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
    default:
      return [];
  }
}

interface Collected {
  probe: Probe;
  response: LiveHttpResponse;
}

const SQL_ERROR_MARKERS = [
  "sql syntax",
  "syntax error",
  "sqlite",
  "sqlstate",
  "pg::",
  "ora-",
  "you have an error in your sql",
  "unclosed quotation",
];

interface Verdict {
  success: boolean;
  note: string;
}

/** Category-specific success oracle over the captured exchanges. */
function oracle(finding: ProbableFinding, collected: Collected[]): Verdict {
  const payload = collected.find((c) => c.probe.role === "payload");
  const baseline = collected.find((c) => c.probe.role === "baseline");
  if (!payload) return { success: false, note: "no payload response captured" };
  const { response } = payload;
  const body = response.body ?? "";
  const lower = body.toLowerCase();

  switch (finding.category) {
    case "sql_injection":
    case "nosql_injection": {
      if (SQL_ERROR_MARKERS.some((m) => lower.includes(m))) {
        return {
          success: true,
          note: "SQL error leaked in the response (injection reached the query)",
        };
      }
      if (response.status >= 200 && response.status < 300 && baseline) {
        if (body.length >= baseline.response.body.length + 20) {
          return {
            success: true,
            note: "boolean-true payload returned materially more data than the baseline",
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
    default:
      return { success: false, note: "category has no live oracle" };
  }
}

function toExchange(probe: Probe, response: LiveHttpResponse): HttpExchange {
  const reqHeaders = safeHeaders(probe.request.headers);
  const resHeaders = safeHeaders(response.headers);
  return {
    request: {
      method: probe.request.method,
      url: probe.request.url,
      ...(reqHeaders ? { headers: reqHeaders } : {}),
    },
    response: {
      status: response.status,
      ...(resHeaders ? { headers: resHeaders } : {}),
      bodySnippet: truncate(response.body ?? ""),
    },
    note: probe.note,
  };
}

/** Default outbound transport (undici). Loaded lazily — never in offline tests. */
async function defaultTransport(): Promise<LiveHttpTransport> {
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

  const verdict = oracle(finding, collected);
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
