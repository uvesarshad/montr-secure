/**
 * OWASP-Top-10-mapped starter catalogue for the red-team scenario library
 * (Phase-4 / Wave 5, PRD §16, build-plan §8 — item A27).
 *
 * The scenario library (storage in {@link ../phase4.js}'s
 * `RedTeamScenarioRepositoryImpl`, structural validation + the Layer-3
 * live-DAST gate in `@montr/confirm`) is real infrastructure but ships with
 * ZERO scenario content — clients have to author every scenario from scratch.
 * This module is a static, versionable catalogue of well-known attack
 * scenario TEMPLATES, one or more per OWASP Top 10 (2021) category, each
 * grounded in a named, established testing methodology (the OWASP Web
 * Security Testing Guide — WSTG v4.2 — or, where WSTG has no dedicated
 * chapter, PTES / the relevant CWE).
 *
 * WHY A STATIC DATA FILE (not a DB seed migration):
 *   - `RedTeamScenarioRepositoryImpl` requires a live Postgres connection AND
 *     a field-encryption cipher (`steps` is encrypted at rest, §11) — neither
 *     is available at build/typecheck time, and a migration can't carry a
 *     per-client `clientId`/`createdBy` (rows are client-scoped; there is no
 *     "global" scenario row, unlike e.g. PromptVersion).
 *   - The API route (`apps/api/src/routes/scenarios.ts`) already has a real,
 *     fully-gated `POST /scenarios` create path that structurally validates
 *     (`validateScenario`), Zod-parses, forces `enabled: false`, and audits
 *     every scenario — so the correct "seed" shape is a list of TEMPLATES an
 *     operator (via a script, an admin action, or a future "start from
 *     catalogue" UI affordance) feeds through that SAME create path, not a
 *     side-channel that writes rows directly and bypasses it.
 *   - `scripts/seed-redteam-scenarios.mjs` in this package is the runnable
 *     delivery mechanism: it goes through `createStateStore` +
 *     `store.redTeamScenarios.create` (the real repository, real encryption,
 *     real per-client scoping) for operators who want a one-shot DB seed
 *     instead of clicking through the API.
 *
 * ⛔ SAFETY: templates carry NO `targetAllowlistRef` — that binds a scenario
 * to a live target and is inherently client- and environment-specific. A
 * hardcoded ref here (even a "safe-looking" one) risks a copy-paste into a
 * real allowlist. Callers MUST supply their own allowlisted staging target
 * via {@link instantiateScenario}. Every instantiated scenario is also always
 * `enabled: false` (the repository/route's existing disabled-by-default
 * invariant, §11) — a seeded scenario cannot run until an approver explicitly
 * reviews and enables it.
 */
import type { RedTeamCategory, RedTeamScenario, RedTeamStep } from "@montr/contracts";
import { RedTeamScenarioSchema } from "@montr/contracts";
import type { RedTeamScenarioRepository } from "./types.js";

/** OWASP Top 10 (2021 edition) category identifiers. */
export type OwaspTop10Id =
  "A01" | "A02" | "A03" | "A04" | "A05" | "A06" | "A07" | "A08" | "A09" | "A10";

/** OWASP Top 10 (2021) titles, for reference / display. */
export const OWASP_TOP_10_2021: Record<OwaspTop10Id, string> = {
  A01: "A01:2021 – Broken Access Control",
  A02: "A02:2021 – Cryptographic Failures",
  A03: "A03:2021 – Injection",
  A04: "A04:2021 – Insecure Design",
  A05: "A05:2021 – Security Misconfiguration",
  A06: "A06:2021 – Vulnerable and Outdated Components",
  A07: "A07:2021 – Identification and Authentication Failures",
  A08: "A08:2021 – Software and Data Integrity Failures",
  A09: "A09:2021 – Security Logging and Monitoring Failures",
  A10: "A10:2021 – Server-Side Request Forgery (SSRF)",
};

/** All 10 OWASP Top 10 (2021) ids, in order — used to assert full coverage. */
export const ALL_OWASP_TOP_10_2021_IDS: readonly OwaspTop10Id[] = [
  "A01",
  "A02",
  "A03",
  "A04",
  "A05",
  "A06",
  "A07",
  "A08",
  "A09",
  "A10",
];

/**
 * A catalogue entry: everything a {@link RedTeamScenario} needs EXCEPT the
 * per-client/per-run fields (`id`, `clientId`, `targetAllowlistRef`,
 * `createdBy`, `createdAt`, `version`, `enabled`) that only exist once a
 * client instantiates it against their own allowlisted target.
 */
export interface RedTeamScenarioTemplate {
  /** Stable catalogue key (slug) — used for idempotent re-seeding. */
  key: string;
  /** OWASP Top 10 (2021) category this scenario demonstrates. */
  owasp: OwaspTop10Id;
  /** `RedTeamScenario.name` — kept under 200 chars (schema limit). */
  name: string;
  category: RedTeamCategory;
  /**
   * Named testing standard(s) this scenario's steps are drawn from (OWASP
   * WSTG v4.2 chapter/test-ID, PTES phase, or CWE). The schema has no
   * dedicated description field on `RedTeamScenario`, so this citation is
   * carried in the catalogue (surfaced by {@link owaspCoverageReport}) and
   * echoed into the step `action`/`expectation` text itself, which IS
   * persisted.
   */
  methodologySource: string;
  steps: RedTeamStep[];
}

const step = (
  order: number,
  action: string,
  opts: { method?: RedTeamStep["method"]; path?: string; expectation?: string } = {},
): RedTeamStep => ({ order, action, ...opts });

/* ========================================================================
 * A01:2021 – Broken Access Control
 * ==================================================================== */

const A01_IDOR: RedTeamScenarioTemplate = {
  key: "owasp-a01-idor",
  owasp: "A01",
  name: "A01 Broken Access Control — Insecure Direct Object Reference (OWASP WSTG-ATHZ-04)",
  category: "access_control",
  methodologySource: "OWASP WSTG v4.2 WSTG-ATHZ-04 — Testing for Insecure Direct Object References",
  steps: [
    step(
      0,
      "Authenticate as low-privilege user A and request A's own resource to record a baseline object reference and response shape (WSTG-ATHZ-04 step 1: map object reference points).",
      {
        method: "GET",
        path: "/api/orders/:ownResourceId",
        expectation: "200 with user A's own order data — establishes the baseline for comparison.",
      },
    ),
    step(
      1,
      "Re-request the same endpoint substituting a sequential/adjacent object id belonging to a different user, with no other change to identity or session (WSTG-ATHZ-04 step 2: reference parameter manipulation).",
      {
        method: "GET",
        path: "/api/orders/:otherUsersResourceId",
        expectation: "Server should return 403/404 — a 200 with another user's data confirms IDOR.",
      },
    ),
    step(
      2,
      "Repeat the substitution against a mutating endpoint for the same object to check write-side IDOR, not just read-side (capped by dast.scope.maxMutatingRequests — 0 by default).",
      {
        method: "PUT",
        path: "/api/orders/:otherUsersResourceId",
        expectation:
          "Server should reject with 403 — any 2xx confirms an attacker can modify another tenant's data.",
      },
    ),
    step(
      3,
      "Vary the reference format (UUID vs sequential ID, base64/hashid-encoded id) to rule out security-by-obscurity masking an unenforced authorization check.",
      {
        method: "GET",
        path: "/api/orders?ref=:otherUsersEncodedRef",
        expectation:
          "Authorization must hold regardless of id encoding — decoding to another tenant's row and returning data confirms the flaw is in the authz check, not the id format.",
      },
    ),
  ],
};

const A01_PRIVESC: RedTeamScenarioTemplate = {
  key: "owasp-a01-privilege-escalation",
  owasp: "A01",
  name: "A01 Broken Access Control — Vertical Privilege Escalation & Forced Browsing (OWASP WSTG-ATHZ-02/03)",
  category: "access_control",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema; WSTG-ATHZ-03 — Testing for Privilege Escalation",
  steps: [
    step(
      0,
      "As an unauthenticated or standard-role session, force-browse to a known/guessed admin-only route discovered during recon (WSTG-ATHZ-02 step 1: enumerate role-gated endpoints).",
      {
        method: "GET",
        path: "/admin/users",
        expectation:
          "Should be 401/403 for a non-admin session — 200 confirms a missing server-side role check.",
      },
    ),
    step(
      1,
      "Call an admin-only API action directly (skip the UI, which may merely hide the control rather than the server enforcing it) with a standard-user bearer token (WSTG-ATHZ-03: confirm the check is enforced server-side, not just UI-hidden).",
      {
        method: "POST",
        path: "/api/admin/users/:targetUserId/role",
        expectation:
          "Should be 403 regardless of UI affordances — success proves horizontal-to-vertical escalation via direct API access.",
      },
    ),
    step(
      2,
      "Replay the same admin action while tampering with a client-controlled trust signal (e.g. an `X-Role`/`X-User-Role` header or a JWT with an attacker-modified `role` claim, unsigned or re-signed with `alg=none`) to test whether authorization trusts client input (WSTG-ATHZ-02 step 2).",
      {
        method: "POST",
        path: "/api/admin/users/:targetUserId/role",
        expectation:
          "Server must derive role from its own session/token verification, never from a client-supplied header or unverified claim — any success here is a critical authZ bypass.",
      },
    ),
  ],
};

/* ========================================================================
 * A02:2021 – Cryptographic Failures
 * ==================================================================== */

const A02_CRYPTO_EXPOSURE: RedTeamScenarioTemplate = {
  key: "owasp-a02-crypto-failures",
  owasp: "A02",
  name: "A02 Cryptographic Failures — Sensitive Data in Transit & Weak Transport Config (OWASP WSTG-CRYP-01/03, WSTG-CONF-07)",
  category: "other",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-CRYP-01 — Testing for Weak Transport Layer Security; WSTG-CRYP-03 — Testing for Sensitive Information Sent via Unencrypted Channels; WSTG-CONF-07 — Test HTTP Strict Transport Security",
  steps: [
    step(
      0,
      "Request the login page and inspect the response for a Strict-Transport-Security header and whether an HTTP (non-TLS) origin is even reachable (WSTG-CONF-07 / WSTG-CRYP-01).",
      {
        method: "GET",
        path: "/login",
        expectation:
          "HSTS header present with a meaningful max-age; plain-HTTP origin should redirect to HTTPS, never serve the form.",
      },
    ),
    step(
      1,
      "Submit the login form and inspect the exact request line/URL to confirm credentials travel only in the POST body over TLS, never appended to a URL/query string (WSTG-CRYP-03: unencrypted-channel / logging-adjacent exposure of secrets).",
      {
        method: "POST",
        path: "/api/auth/login",
        expectation:
          "Credentials must never appear in the URL (query strings are logged/cached/stored in browser history) — only in an encrypted request body.",
      },
    ),
    step(
      2,
      "Fetch an authenticated page containing PII/financial data and check `Cache-Control`/`Pragma` response headers (WSTG-CRYP-03 extension: sensitive data must not be cacheable by shared/proxy caches).",
      {
        method: "GET",
        path: "/api/account/profile",
        expectation:
          "Cache-Control: no-store (or equivalent) on any response containing PII — its absence risks sensitive data persisting in shared caches.",
      },
    ),
  ],
};

/* ========================================================================
 * A03:2021 – Injection
 * ==================================================================== */

const A03_SQLI: RedTeamScenarioTemplate = {
  key: "owasp-a03-sql-injection",
  owasp: "A03",
  name: "A03 Injection — SQL Injection: Parameter ID → Error/Blind/Time-Based Confirmation → Extraction Proof (OWASP WSTG-INPV-05)",
  category: "injection",
  methodologySource: "OWASP WSTG v4.2 WSTG-INPV-05 — Testing for SQL Injection",
  steps: [
    step(
      0,
      "Send a baseline request with a known-valid parameter value and record the normal response shape/latency (WSTG-INPV-05 step 1: identify injectable parameters).",
      {
        method: "GET",
        path: "/api/products?id=1",
        expectation:
          "Baseline 200 with expected product payload — reference point for every later diff.",
      },
    ),
    step(
      1,
      "Inject a single-quote error-based probe (`id=1'`) into the identified parameter (WSTG-INPV-05 step 2: error-based confirmation).",
      {
        method: "GET",
        path: "/api/products?id=1'",
        expectation:
          "A raw DB error, 500, or a response shape change vs. baseline indicates the input reaches an unsanitized query.",
      },
    ),
    step(
      2,
      "If no verbose error surfaces, send paired boolean-based blind probes (`id=1 AND 1=1` vs `id=1 AND 1=2`) and diff the two responses (WSTG-INPV-05 step 3: boolean-based blind confirmation).",
      {
        method: "GET",
        path: "/api/products?id=1 AND 1=1",
        expectation:
          "A behavioral difference between the always-true and always-false payload (content length, status, or specific markup) confirms blind SQLi even with no visible errors.",
      },
    ),
    step(
      3,
      "Send a time-based blind probe (`id=1;SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--`) and measure response latency (WSTG-INPV-05 step 4: time-based blind confirmation, for cases where output is fully suppressed).",
      {
        method: "GET",
        path: "/api/products?id=1;SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        expectation:
          "~5s added latency vs. baseline (repeat 2-3x to rule out network jitter) confirms the query executes attacker-controlled conditional logic server-side.",
      },
    ),
    step(
      4,
      "Once confirmed, run a UNION-based extraction probe to produce concrete proof of data access rather than just a behavioral signal (WSTG-INPV-05 step 5: extraction proof).",
      {
        method: "GET",
        path: "/api/products?id=-1 UNION SELECT NULL,version(),NULL--",
        expectation:
          "The database version string (or another verifiably out-of-band value) appearing in the response body is definitive proof of injection, not just a signal — required before this is reported as confirmed.",
      },
    ),
  ],
};

const A03_CMD_INJECTION: RedTeamScenarioTemplate = {
  key: "owasp-a03-command-injection",
  owasp: "A03",
  name: "A03 Injection — OS Command Injection via Shell Metacharacter & Blind Time-Based Confirmation (OWASP WSTG-INPV-12)",
  category: "injection",
  methodologySource: "OWASP WSTG v4.2 WSTG-INPV-12 — Testing for Command Injection",
  steps: [
    step(
      0,
      "Identify a parameter that plausibly reaches a shell/subprocess call (e.g. a filename, hostname, or export-format field) and send a baseline valid value (WSTG-INPV-12 step 1).",
      {
        method: "POST",
        path: "/api/reports/export",
        expectation:
          "Baseline 200/202 with the expected export artifact — reference point for later diffs.",
      },
    ),
    step(
      1,
      "Append a benign command-chaining metacharacter payload to the parameter (`; id`, `| whoami`, `` `id` ``, `$(id)`) to test for direct output reflection (WSTG-INPV-12 step 2: metacharacter injection).",
      {
        method: "POST",
        path: "/api/reports/export",
        expectation:
          "Command output (e.g. a uid/gid string or username) appearing in the response is direct proof of command injection.",
      },
    ),
    step(
      2,
      "If output isn't reflected, send a blind time-based payload (`; sleep 5`, `| ping -c 5 127.0.0.1`) and measure latency vs. baseline (WSTG-INPV-12 step 3: blind confirmation when output is suppressed).",
      {
        method: "POST",
        path: "/api/reports/export",
        expectation:
          "~5s added latency (repeated to rule out jitter) confirms the injected command executed server-side even with no visible output.",
      },
    ),
  ],
};

const A03_XSS: RedTeamScenarioTemplate = {
  key: "owasp-a03-xss",
  owasp: "A03",
  name: "A03 Injection — Reflected & Stored Cross-Site Scripting (OWASP WSTG-INPV-01/02)",
  category: "xss",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-INPV-01 — Testing for Reflected Cross Site Scripting; WSTG-INPV-02 — Testing for Stored Cross Site Scripting",
  steps: [
    step(
      0,
      "Submit a unique, non-executing canary string in a search/query parameter and check whether it's reflected unencoded in the response (WSTG-INPV-01 step 1: identify reflection points).",
      {
        method: "GET",
        path: "/search?q=mtr_xss_canary_001",
        expectation:
          "The canary should be HTML-entity-encoded in the response — raw/unencoded reflection is the precondition for reflected XSS.",
      },
    ),
    step(
      1,
      "Replace the canary with a proof-of-concept script payload (`<script>document.title='mtr-xss-poc'</script>` or an event-handler variant for attribute contexts) (WSTG-INPV-01 step 2: confirm script execution context, not just reflection).",
      {
        method: "GET",
        path: "/search?q=<script>document.title='mtr-xss-poc'</script>",
        expectation:
          "Unencoded `<script>` in the response body confirms a reflected-XSS-capable sink; execution should be verified out-of-band in a headless browser, never assumed from the raw HTTP response alone.",
      },
    ),
    step(
      2,
      "Submit the same class of payload through a field that is persisted and rendered back to OTHER users (e.g. a display name or comment) to test the stored variant (WSTG-INPV-02: stored XSS is higher severity — it fires for every viewer, not just the submitter).",
      {
        method: "POST",
        path: "/api/comments",
        expectation:
          "The stored payload must be encoded/sanitized on render for ALL viewers, not just escaped in the submitter's own response — verify by re-fetching the content as a second, unrelated session.",
      },
    ),
  ],
};

/* ========================================================================
 * A04:2021 – Insecure Design
 * ==================================================================== */

const A04_BUSINESS_LOGIC: RedTeamScenarioTemplate = {
  key: "owasp-a04-business-logic-abuse",
  owasp: "A04",
  name: "A04 Insecure Design — Workflow Bypass & Business Logic Abuse (OWASP WSTG-BUSL-01/05/06)",
  category: "business_logic",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-BUSL-01 — Test Business Logic Data Validation; WSTG-BUSL-05 — Test Number of Times a Function Can Be Used Limits; WSTG-BUSL-06 — Testing for the Circumvention of Work Flows",
  steps: [
    step(
      0,
      "Walk the intended multi-step flow once (e.g. cart → shipping → payment → confirm) and record which endpoint each step calls (WSTG-BUSL-06 step 1: map the intended workflow order).",
      {
        method: "GET",
        path: "/api/checkout/state",
        expectation: "Baseline: server tracks and enforces a linear step order.",
      },
    ),
    step(
      1,
      "Call a later-step endpoint directly, skipping an earlier required step (e.g. hit the order-confirm endpoint without a completed payment step) (WSTG-BUSL-06 step 2: sequence-skipping).",
      {
        method: "POST",
        path: "/api/checkout/confirm",
        expectation:
          "Server should reject with a workflow-state error — accepting it confirms the state machine is enforced client-side only.",
      },
    ),
    step(
      2,
      "Resubmit a value the server should treat as fixed/derived (unit price, discount amount, quantity) with a client-tampered value (WSTG-BUSL-01: server-side re-validation of data the client should not control).",
      {
        method: "POST",
        path: "/api/checkout/cart-item",
        expectation:
          "Server must recompute price/total server-side from catalogue data — accepting a client-supplied price/negative quantity is a critical logic flaw.",
      },
    ),
    step(
      3,
      "Fire several near-simultaneous redemption requests for a single-use coupon/discount code to test for a race-condition bypass of a use-once limit (WSTG-BUSL-05: function usage-limit enforcement under concurrency).",
      {
        method: "POST",
        path: "/api/checkout/apply-coupon",
        expectation:
          "Exactly one of the concurrent requests should succeed — multiple successful redemptions confirm a TOCTOU race in the usage-limit check.",
      },
    ),
  ],
};

/* ========================================================================
 * A05:2021 – Security Misconfiguration
 * ==================================================================== */

const A05_MISCONFIG: RedTeamScenarioTemplate = {
  key: "owasp-a05-security-misconfiguration",
  owasp: "A05",
  name: "A05 Security Misconfiguration — Verbose Errors, Exposed Admin Interfaces & Unsafe HTTP Methods (OWASP WSTG-CONF-02/05/06, WSTG-ERRH-02)",
  category: "other",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-CONF-02 — Test Application Platform Configuration; WSTG-CONF-05 — Enumerate Infrastructure and Application Admin Interfaces; WSTG-CONF-06 — Test HTTP Methods; WSTG-ERRH-02 — Testing for Stack Traces",
  steps: [
    step(
      0,
      "Send a malformed/unexpected input designed to trigger a framework-level error and inspect the response for a stack trace or internal path/version disclosure (WSTG-ERRH-02: default-config error handling should not leak implementation detail).",
      {
        method: "GET",
        path: "/api/products/%00malformed",
        expectation:
          "A generic error response — a raw stack trace, file path, or framework banner is a misconfiguration (verbose error handling left at development defaults).",
      },
    ),
    step(
      1,
      "Probe common default/debug/admin surface paths left enabled by platform defaults (WSTG-CONF-05: enumerate exposed admin/debug interfaces).",
      {
        method: "GET",
        path: "/actuator/env",
        expectation:
          "404/403 expected — a 200 exposing environment/config data is a critical misconfiguration.",
      },
    ),
    step(
      2,
      "Probe for an exposed API schema/docs endpoint that may over-disclose internal routes not meant for public consumption (WSTG-CONF-02: platform config review extended to auto-generated docs).",
      {
        method: "GET",
        path: "/swagger.json",
        expectation:
          "If present, should require auth or be intentionally public — unauthenticated exposure of internal-only routes/schemas broadens the attack surface for every other scenario in this catalogue.",
      },
    ),
    step(
      3,
      "Send an HTTP TRACE/OPTIONS request to confirm unsafe/diagnostic methods are disabled at the edge (WSTG-CONF-06: Test HTTP Methods — TRACE can enable Cross-Site Tracing to bypass HttpOnly cookie protections).",
      {
        method: "OPTIONS",
        path: "/",
        expectation:
          "The `Allow` header should list only methods the app actually needs — TRACE in particular should never be enabled.",
      },
    ),
  ],
};

/* ========================================================================
 * A06:2021 – Vulnerable and Outdated Components
 * ==================================================================== */

const A06_COMPONENT_FINGERPRINT: RedTeamScenarioTemplate = {
  key: "owasp-a06-vulnerable-components",
  owasp: "A06",
  name: "A06 Vulnerable and Outdated Components — Fingerprinting & Known-CVE Correlation (OWASP WSTG-INFO-02/08/09)",
  category: "recon",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-INFO-02 — Fingerprint Web Server; WSTG-INFO-08 — Fingerprint Web Application Framework; WSTG-INFO-09 — Fingerprint Web Application; cross-referenced against the OSV/NVD advisory databases (as this tool's own SCA detector does offline)",
  steps: [
    step(
      0,
      "Request the root document and record the `Server`/`X-Powered-By` response headers and any HTML generator meta tag (WSTG-INFO-02: banner-grab the web server/platform).",
      {
        method: "GET",
        path: "/",
        expectation:
          "Server/framework name AND version string, if present, become inputs to an offline CVE lookup — this step itself is non-intrusive recon only.",
      },
    ),
    step(
      1,
      "Fetch a bundled static asset whose filename or content commonly embeds a library version string (e.g. a vendor bundle) (WSTG-INFO-08: fingerprint client-side framework/library versions).",
      {
        method: "GET",
        path: "/static/vendor.js",
        expectation:
          "An extractable version string enables a precise (not guessed) CVE correlation for that exact release.",
      },
    ),
    step(
      2,
      "Probe for accidentally-published dependency manifests that enumerate exact installed versions server-side (WSTG-INFO-09 extension: manifest/lockfile exposure is a direct, unambiguous fingerprint).",
      {
        method: "GET",
        path: "/package.json",
        expectation:
          "Should be 404 — if exposed, every listed dependency + version should be correlated against OSV/NVD/GHSA for known CVEs (offline lookup, not a live exploit attempt).",
      },
    ),
    step(
      3,
      "Document every fingerprinted component/version pair and cross-reference against the advisory database this platform already ingests, flagging any match with a known-exploitable CVE as the confirmed finding (proof-of-concept exploitation of the specific CVE is a SEPARATE, explicitly-scoped scenario — this one stops at confirmed-vulnerable-version identification).",
      {
        expectation:
          "A documented component→CVE mapping is the deliverable of this scenario; it is deliberately non-exploitative recon.",
      },
    ),
  ],
};

/* ========================================================================
 * A07:2021 – Identification and Authentication Failures
 * ==================================================================== */

const A07_AUTH_FAILURES: RedTeamScenarioTemplate = {
  key: "owasp-a07-auth-failures",
  owasp: "A07",
  name: "A07 Identification & Authentication Failures — Weak Lockout, Session Fixation & Reset-Token Weakness (OWASP WSTG-ATHN-03/09, WSTG-SESS-03)",
  category: "authentication",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-ATHN-03 — Testing for Weak Lock Out Mechanism; WSTG-SESS-03 — Testing for Session Fixation; WSTG-ATHN-09 — Testing for Weak Password Change or Reset Functionalities",
  steps: [
    step(
      0,
      "Submit a sequence of failed login attempts against a single known username and observe whether/when the account or source is throttled or locked (WSTG-ATHN-03 step 1: probe lockout threshold and lockout scope).",
      {
        method: "POST",
        path: "/api/auth/login",
        expectation:
          "A rate limit/lockout should engage well before credential-stuffing volumes — no throttling at all is a critical finding.",
      },
    ),
    step(
      1,
      "Obtain a pre-authentication session identifier, then complete a successful login WITHOUT the server rotating that identifier, and check whether the pre-auth value remains valid post-auth (WSTG-SESS-03: session fixation — the server must issue a fresh session token on privilege change).",
      {
        method: "POST",
        path: "/api/auth/login",
        expectation:
          "The session identifier must be rotated on login — an attacker who fixed the pre-auth token being able to reuse it as an authenticated session is a session-fixation vulnerability.",
      },
    ),
    step(
      2,
      "Request a password-reset token, then inspect it for predictability (sequential, timestamp-derived, short) and confirm it expires and is single-use (WSTG-ATHN-09: reset-token strength and lifecycle).",
      {
        method: "POST",
        path: "/api/auth/password-reset",
        expectation:
          "Token must be high-entropy, single-use, and time-bound — a second use, or use after expected expiry, must be rejected.",
      },
    ),
  ],
};

/* ========================================================================
 * A08:2021 – Software and Data Integrity Failures
 * ==================================================================== */

const A08_INTEGRITY_FAILURES: RedTeamScenarioTemplate = {
  key: "owasp-a08-software-data-integrity",
  owasp: "A08",
  name: "A08 Software & Data Integrity Failures — Unverified Deserialization & Missing Integrity Checks (OWASP WSTG-BUSL-03; CWE-502)",
  category: "other",
  methodologySource:
    "OWASP WSTG v4.2 WSTG-BUSL-03 — Test Integrity Checks; CWE-502 — Deserialization of Untrusted Data (the specific integrity failure class OWASP A08:2021 elevated to Top-10 status)",
  steps: [
    step(
      0,
      "Identify any endpoint that accepts a serialized object, signed payload, or webhook body, and capture a legitimate example (WSTG-BUSL-03 step 1: locate integrity-dependent data flows).",
      {
        method: "POST",
        path: "/api/webhooks/receive",
        expectation:
          "Baseline accepted payload — establishes the expected structure and any signature/HMAC header present.",
      },
    ),
    step(
      1,
      "Resubmit the SAME payload with its integrity signature/HMAC stripped or altered by one byte, all else unchanged (WSTG-BUSL-03 step 2: confirm the integrity check is actually enforced, not merely present in docs).",
      {
        method: "POST",
        path: "/api/webhooks/receive",
        expectation:
          "Server must reject a payload with an invalid/missing signature — silent acceptance means the integrity control is decorative.",
      },
    ),
    step(
      2,
      "Where the payload is a serialized object (not just JSON), attempt to substitute a benign-but-unexpected type/class marker to probe whether deserialization is type-constrained (CWE-502: unrestricted deserialization is the classic A08 gadget-chain precondition).",
      {
        method: "POST",
        path: "/api/webhooks/receive",
        expectation:
          "Deserialization must be restricted to an explicit allowlist of expected types — accepting arbitrary type markers is the precondition for a gadget-chain RCE and must be reported even without a full exploit chain.",
      },
    ),
  ],
};

/* ========================================================================
 * A09:2021 – Security Logging and Monitoring Failures
 * ==================================================================== */

const A09_LOGGING_FAILURES: RedTeamScenarioTemplate = {
  key: "owasp-a09-logging-monitoring",
  owasp: "A09",
  name: "A09 Security Logging & Monitoring Failures — Undetected Auth-Attack Signal & Log-Injection Probe (OWASP A09:2021; CWE-117; PTES reporting/detection-assessment phase)",
  category: "other",
  methodologySource:
    "OWASP Top 10 A09:2021 guidance (no dedicated WSTG chapter exists for logging/monitoring — this scenario reuses the WSTG-ATHN-03 auth-failure trigger as an observable proxy event, per PTES's post-engagement detection-effectiveness assessment); CWE-117 — Improper Output Neutralization for Logs",
  steps: [
    step(
      0,
      "Generate an unambiguous, high-signal security event (a burst of failed logins for one account, as in the A07 lockout scenario) and note the exact timestamps/count sent (this is the event a monitoring pipeline SHOULD alert on).",
      {
        method: "POST",
        path: "/api/auth/login",
        expectation:
          "This step only generates the event; detection is assessed out-of-band by the client's own SOC/SIEM confirming an alert fired for this exact activity within a reasonable window — absence of any alert is the A09 finding.",
      },
    ),
    step(
      1,
      "Submit a value containing CRLF/newline sequences in a field that is commonly logged verbatim (e.g. a User-Agent or free-text field), to test whether unsanitized input can forge or split log entries (CWE-117: log injection).",
      {
        method: "GET",
        path: "/api/health",
        expectation:
          "The application/logging layer should neutralize CR/LF before writing to logs — this cannot be confirmed purely from the HTTP response and requires the client to check their own log output for a forged/split entry.",
      },
    ),
    step(
      2,
      "Trigger an authorization failure (reuse the A01 forced-browsing probe) and confirm the request produced a distinguishable log line, not just a generic 403 with no correlateable identifier (OWASP A09:2021: access-control failures must be logged with enough context to investigate).",
      {
        method: "GET",
        path: "/admin/users",
        expectation:
          "The client's log pipeline should retain enough of this request (actor, target, timestamp, outcome) to support an incident investigation — a bare 403 with no corresponding log entry is the A09 finding.",
      },
    ),
  ],
};

/* ========================================================================
 * A10:2021 – Server-Side Request Forgery (SSRF)
 * ==================================================================== */

const A10_SSRF: RedTeamScenarioTemplate = {
  key: "owasp-a10-ssrf",
  owasp: "A10",
  name: "A10 SSRF — Internal/Metadata-Endpoint Probe via Server-Fetched URL Parameter (OWASP WSTG-INPV-19)",
  category: "ssrf",
  methodologySource: "OWASP WSTG v4.2 WSTG-INPV-19 — Testing for Server-Side Request Forgery",
  steps: [
    step(
      0,
      "Identify a feature where the server itself fetches a URL supplied by the client (webhook registration, avatar-by-URL import, PDF/link preview) and confirm it with a benign externally-reachable URL first (WSTG-INPV-19 step 1: identify the SSRF injection point).",
      {
        method: "POST",
        path: "/api/integrations/webhook-url",
        expectation:
          "Baseline 200 confirming the server does fetch the supplied URL and returns a fetch-dependent result.",
      },
    ),
    step(
      1,
      "Resubmit pointing the same parameter at a loopback/internal address (`http://127.0.0.1/`, `http://localhost/`) to test whether the server enforces any destination restriction (WSTG-INPV-19 step 2: internal-network reachability probe).",
      {
        method: "POST",
        path: "/api/integrations/webhook-url",
        expectation:
          "Server should refuse to fetch non-public/loopback destinations — a differing response (vs. an unreachable-external-host error) indicates the fetch reached an internal service.",
      },
    ),
    step(
      2,
      "Resubmit pointing at the cloud-provider instance-metadata address (`http://169.254.169.254/latest/meta-data/`) — the highest-impact, most common real-world SSRF target (WSTG-INPV-19 step 3: cloud metadata service probe).",
      {
        method: "POST",
        path: "/api/integrations/webhook-url",
        expectation:
          "Any content reflected back from the metadata service (instance role, IAM credential material) is a critical, immediately-actionable finding — must be reported with the highest urgency and the credential treated as compromised.",
      },
    ),
    step(
      3,
      "For a blind variant where no fetch result is reflected to the client, point the parameter at an out-of-band collaborator endpoint the tester controls and check for an inbound callback (WSTG-INPV-19 step 4: blind SSRF confirmation via out-of-band interaction).",
      {
        method: "POST",
        path: "/api/integrations/webhook-url",
        expectation:
          "An inbound request to the tester-controlled collaborator endpoint, timed to this step, is proof of blind SSRF even when the application never surfaces the fetch result.",
      },
    ),
  ],
};

/**
 * The full starter catalogue — every OWASP Top 10 (2021) category has at
 * least one scenario; A01/A03 (the categories clients most commonly ask to
 * test) carry more than one.
 */
export const REDTEAM_SCENARIO_CATALOGUE: readonly RedTeamScenarioTemplate[] = [
  A01_IDOR,
  A01_PRIVESC,
  A02_CRYPTO_EXPOSURE,
  A03_SQLI,
  A03_CMD_INJECTION,
  A03_XSS,
  A04_BUSINESS_LOGIC,
  A05_MISCONFIG,
  A06_COMPONENT_FINGERPRINT,
  A07_AUTH_FAILURES,
  A08_INTEGRITY_FAILURES,
  A09_LOGGING_FAILURES,
  A10_SSRF,
];

/** The set of OWASP Top 10 ids the catalogue currently covers. */
export function owaspCoverage(
  templates: readonly RedTeamScenarioTemplate[] = REDTEAM_SCENARIO_CATALOGUE,
): Set<OwaspTop10Id> {
  return new Set(templates.map((t) => t.owasp));
}

export interface InstantiateScenarioParams {
  id: string;
  clientId: string;
  /**
   * ⛔ The client's own allowlisted DAST target/scope reference. Required —
   * deliberately NOT defaulted here (see module doc: no hardcoded fake
   * target that could be copy-pasted into a real allowlist).
   */
  targetAllowlistRef: string;
  createdBy: string;
  createdAt: string;
}

/**
 * Turn a catalogue template into a real, Zod-validated {@link RedTeamScenario}
 * ready to hand to `store.redTeamScenarios.create` (or the `POST /scenarios`
 * route body). Always `enabled: false, version: 1` — matches the route's own
 * disabled-by-default invariant (§11); an operator must explicitly review and
 * enable it before it is runnable.
 */
export function instantiateScenario(
  template: RedTeamScenarioTemplate,
  params: InstantiateScenarioParams,
): RedTeamScenario {
  return RedTeamScenarioSchema.parse({
    id: params.id,
    clientId: params.clientId,
    name: template.name,
    category: template.category,
    steps: template.steps,
    targetAllowlistRef: params.targetAllowlistRef,
    version: 1,
    enabled: false,
    createdBy: params.createdBy,
    createdAt: params.createdAt,
  });
}

export interface SeedRedTeamCatalogueOptions {
  clientId: string;
  /** The client's own allowlisted DAST target/scope reference — see {@link InstantiateScenarioParams}. */
  targetAllowlistRef: string;
  createdBy: string;
  /** Id generator — defaults to a `scn_<key>_<random>` slug (mirrors the API's `deps.idgen("scn")` prefix). */
  idgen?: (template: RedTeamScenarioTemplate) => string;
  /** Clock — defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => Date;
  templates?: readonly RedTeamScenarioTemplate[];
}

export interface SeedRedTeamCatalogueResult {
  created: RedTeamScenario[];
  /** Templates skipped because a scenario with the same name already exists for this client (idempotent re-seed). */
  skipped: RedTeamScenarioTemplate[];
}

/**
 * Idempotently seed the OWASP-mapped starter catalogue for one client through
 * the REAL repository — same `create` path, same AES-256-GCM encryption at
 * rest, same disabled-by-default/version-1 invariants as the `POST
 * /scenarios` route. Safe to re-run: templates whose `name` already exists
 * for this client are skipped rather than duplicated.
 */
export async function seedRedTeamCatalogue(
  repo: RedTeamScenarioRepository,
  opts: SeedRedTeamCatalogueOptions,
): Promise<SeedRedTeamCatalogueResult> {
  const templates = opts.templates ?? REDTEAM_SCENARIO_CATALOGUE;
  const existing = await repo.list(opts.clientId);
  const existingNames = new Set(existing.map((s) => s.name));
  const now = opts.now ?? (() => new Date());
  const idgen =
    opts.idgen ??
    ((template: RedTeamScenarioTemplate) =>
      `scn_${template.key}_${Math.random().toString(36).slice(2, 10)}`);

  const created: RedTeamScenario[] = [];
  const skipped: RedTeamScenarioTemplate[] = [];

  for (const template of templates) {
    if (existingNames.has(template.name)) {
      skipped.push(template);
      continue;
    }
    const scenario = instantiateScenario(template, {
      id: idgen(template),
      clientId: opts.clientId,
      targetAllowlistRef: opts.targetAllowlistRef,
      createdBy: opts.createdBy,
      createdAt: now().toISOString(),
    });
    created.push(await repo.create(opts.clientId, scenario));
  }

  return { created, skipped };
}
