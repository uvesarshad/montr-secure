import {
  complianceForCategory,
  type Scan,
  type AppMap,
  type CostEstimate,
  type ConfirmedFinding,
  type UnconfirmedFinding,
  type Fix,
  type PullRequest,
  type Report,
  type ProgressEvent,
  type AuditEvent,
  type AuditAction,
  type AuditActor,
  type Id,
  type Role,
} from "@montr/contracts";
import type { CurrentUser } from "../lib/rbac.js";

/**
 * In-memory, contract-typed mock dataset backing the MSW handlers. Every literal
 * is `satisfies <ContractType>` so `tsc` verifies it matches @montr/contracts
 * exactly (golden rule #10). Mutations (estimate/fix approval, DAST
 * authorization, kill switch, FP-marking) mutate this store AND append an
 * AuditEvent, so the audit-log viewer reflects every action (golden rule #7).
 */

const CLIENT_ID = "client_demo_0001";

/* ------------------------------------ users ------------------------------------ */

export const USERS: Record<Role, CurrentUser> = {
  operator: {
    id: "user_operator_0001",
    email: "priya.ops@montr.internal",
    name: "Priya Nair",
    role: "operator",
  },
  approver: {
    id: "user_approver_0001",
    email: "sam.lead@montr.internal",
    name: "Sam Okafor",
    role: "approver",
  },
  viewer: {
    id: "user_viewer_0001",
    email: "val.audit@montr.internal",
    name: "Val Chen",
    role: "viewer",
  },
};

/* --------------------------------- timestamps ---------------------------------- */

const T = {
  created: "2026-07-01T09:00:00.000Z",
  estimate: "2026-07-01T09:01:00.000Z",
  approved: "2026-07-01T09:02:00.000Z",
  l0: "2026-07-01T09:03:00.000Z",
  l2: "2026-07-01T09:05:00.000Z",
  l3: "2026-07-01T09:07:00.000Z",
  dast: "2026-07-01T09:08:00.000Z",
  confirmed: "2026-07-01T09:09:00.000Z",
  fix: "2026-07-01T09:10:00.000Z",
  pr: "2026-07-01T09:11:00.000Z",
  done: "2026-07-01T09:12:00.000Z",
  report: "2026-07-01T09:12:30.000Z",
} as const;

/* -------------------------------- audit log (chain) ---------------------------- */

let auditSeq = 0;
let prevHash = "";
const auditLog: AuditEvent[] = [];

/** Mock, deterministic stand-in for the real sha256 hash chain (owned by WS-C/WS-N). */
function fakeHash(seq: number): string {
  return `sha256:${seq.toString(16).padStart(60, "0")}`;
}

function appendAudit(input: {
  scanId?: Id;
  actor: AuditActor;
  action: AuditAction;
  targetType?: string;
  targetId?: Id;
  summary: string;
  metadata?: Record<string, unknown>;
  at: string;
}): AuditEvent {
  auditSeq += 1;
  const hash = fakeHash(auditSeq);
  const ev: AuditEvent = {
    id: `audit_${auditSeq.toString().padStart(4, "0")}`,
    clientId: CLIENT_ID,
    sequence: auditSeq,
    scanId: input.scanId,
    actor: input.actor,
    action: input.action,
    targetType: input.targetType,
    targetId: input.targetId,
    summary: input.summary,
    metadata: input.metadata ?? {},
    prevHash,
    hash,
    at: input.at,
  };
  prevHash = hash;
  auditLog.push(ev);
  return ev;
}

const agent: AuditActor = { type: "agent", id: "agent_pipeline" };
const systemActor: AuditActor = { type: "system", id: "system" };
const operatorActor: AuditActor = { type: "user", id: USERS.operator.id, role: "operator" };
const approverActor: AuditActor = { type: "user", id: USERS.approver.id, role: "approver" };

/* ---------------------------------- app map ------------------------------------ */

const COMMIT = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

const appMapCompleted = {
  id: "appmap_demo_0001",
  clientId: CLIENT_ID,
  scanId: "scan_demo_completed",
  repo: "git@github.com:montr/shop-web.git",
  branch: "main",
  commitSha: COMMIT,
  createdAt: T.l0,
  languages: ["typescript", "javascript"],
  frameworks: ["nextjs", "react", "prisma"],
  entrypoints: [
    {
      kind: "http_route",
      name: "GET /api/users",
      location: { file: "app/api/users/route.ts", line: 5 },
    },
    {
      kind: "http_route",
      name: "GET /api/orders/[id]",
      location: { file: "app/api/orders/[id]/route.ts", line: 7 },
    },
    { kind: "http_route", name: "GET /search", location: { file: "app/search/page.tsx", line: 3 } },
  ],
  routes: [
    {
      id: "route_users",
      path: "/api/users",
      method: "GET",
      authState: "public",
      isApiRoute: true,
      handler: { file: "app/api/users/route.ts", line: 5 },
    },
    {
      id: "route_orders",
      path: "/api/orders/[id]",
      method: "GET",
      authState: "authenticated",
      isApiRoute: true,
      authGate: "requireSession",
      handler: { file: "app/api/orders/[id]/route.ts", line: 7 },
    },
    {
      id: "route_search",
      path: "/search",
      method: "GET",
      authState: "public",
      isApiRoute: false,
      handler: { file: "app/search/page.tsx", line: 3 },
    },
  ],
  dataStores: [{ kind: "postgres", name: "shop_db", accessedVia: "prisma" }],
  ormModels: [
    {
      name: "User",
      dataStore: "shop_db",
      file: "prisma/schema.prisma",
      fields: [
        { name: "id", type: "Int", isId: true },
        { name: "email", type: "String", isId: false },
      ],
    },
    {
      name: "Order",
      dataStore: "shop_db",
      file: "prisma/schema.prisma",
      fields: [
        { name: "id", type: "Int", isId: true },
        { name: "userId", type: "Int", isId: false },
      ],
    },
  ],
  thirdPartyCalls: [{ kind: "http", name: "payments API", target: "api.payments.internal" }],
  envSecretSurfaces: [
    { kind: "config_file", name: "PAYMENTS_API_KEY", location: { file: "lib/config.ts", line: 2 } },
  ],
  taintSources: [
    {
      kind: "query_param",
      location: { file: "app/api/users/route.ts", line: 6 },
      description: "searchParams.get('q')",
      routeId: "route_users",
    },
    {
      kind: "path_param",
      location: { file: "app/api/orders/[id]/route.ts", line: 8 },
      description: "params.id",
      routeId: "route_orders",
    },
  ],
  taintSinks: [
    {
      kind: "orm_raw_query",
      location: { file: "app/api/users/route.ts", line: 9 },
      description: "prisma.$queryRawUnsafe(`... ${q} ...`)",
    },
    {
      kind: "orm_raw_query",
      location: { file: "app/api/orders/[id]/route.ts", line: 12 },
      description: "prisma.order.findFirst({ where: { id } }) — no ownership check",
    },
    {
      kind: "html_render",
      location: { file: "app/search/page.tsx", line: 8 },
      description: "dangerouslySetInnerHTML={{ __html: q }}",
    },
  ],
  taintFlows: [],
  stale: false,
  rebuildPolicy: "rebuild_on_stale_commit",
} satisfies AppMap;

/* ------------------------------- cost estimates -------------------------------- */

function estimateFor(scanId: string, projectedUsd: number): CostEstimate {
  return {
    scanId,
    mode: "full",
    projectedInputTokens: 120_000,
    projectedOutputTokens: 30_000,
    projectedTotalTokens: 150_000,
    projectedUsd,
    projectedWallClockSeconds: 180,
    basis: "routes × sinks × full-mode multiplier",
    byLayer: [
      {
        key: "layer2",
        usage: { inputTokens: 60_000, outputTokens: 15_000, totalTokens: 75_000 },
        usd: projectedUsd / 2,
      },
      {
        key: "layer3",
        usage: { inputTokens: 60_000, outputTokens: 15_000, totalTokens: 75_000 },
        usd: projectedUsd / 2,
      },
    ],
    createdAt: T.estimate,
  } satisfies CostEstimate;
}

const estimateCompleted = estimateFor("scan_demo_completed", 0.66);
const estimateRunning = estimateFor("scan_demo_running", 0.72);
const estimatePending = estimateFor("scan_demo_pending", 1.9);
const estimateBlocked = estimateFor("scan_demo_blocked", 4.2);

/* ------------------------------ confirmed findings ----------------------------- */

const confSqli = {
  id: "conf_sqli_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  probableId: "prob_sqli_0001",
  title: "SQL Injection in GET /api/users (q parameter)",
  category: "sql_injection",
  cwe: ["CWE-89"],
  owasp: "A03:2021",
  severity: "critical",
  exposure: "public",
  location: { file: "app/api/users/route.ts", line: 9 },
  impact: "Full read of the User table; potential write/RCE depending on DB privileges.",
  proofType: "static",
  proofArtifact: {
    kind: "static",
    argument:
      "Tainted `q` (query_param, public route) reaches prisma.$queryRawUnsafe with no sanitizer on the path.",
    dataFlow: [
      {
        location: { file: "app/api/users/route.ts", line: 6 },
        authState: "public",
        transform: "searchParams.get('q')",
        note: "Untrusted input enters here.",
      },
      {
        location: { file: "app/api/users/route.ts", line: 9 },
        authState: "public",
        transform: "string interpolation into raw SQL",
        note: "Reaches the sink unsanitized.",
      },
    ],
    sanitizersBypassed: [],
  },
  status: "confirmed",
  createdAt: T.confirmed,
} satisfies ConfirmedFinding;

const confXss = {
  id: "conf_xss_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  probableId: "prob_xss_0001",
  title: "Reflected XSS in /search",
  category: "xss",
  cwe: ["CWE-79"],
  owasp: "A03:2021",
  severity: "high",
  exposure: "public",
  location: { file: "app/search/page.tsx", line: 8 },
  impact: "Arbitrary script execution in the victim's session context.",
  proofType: "static",
  proofArtifact: {
    kind: "static",
    argument: "`q` searchParam is rendered via dangerouslySetInnerHTML with no escaping.",
    dataFlow: [
      {
        location: { file: "app/search/page.tsx", line: 4 },
        authState: "public",
        transform: "searchParams.q",
      },
      {
        location: { file: "app/search/page.tsx", line: 8 },
        authState: "public",
        transform: "dangerouslySetInnerHTML",
      },
    ],
    sanitizersBypassed: [],
  },
  status: "confirmed",
  createdAt: T.confirmed,
} satisfies ConfirmedFinding;

const confIdor = {
  id: "conf_idor_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  probableId: "prob_idor_0001",
  title: "Broken Access Control (IDOR) in GET /api/orders/[id]",
  category: "broken_access_control",
  cwe: ["CWE-639", "CWE-284"],
  owasp: "A01:2021",
  severity: "high",
  exposure: "authed",
  location: { file: "app/api/orders/[id]/route.ts", line: 12 },
  impact:
    "Any authenticated user can read another user's orders by changing the id path parameter.",
  proofType: "live",
  proofArtifact: {
    kind: "live",
    target: "https://staging.shop.internal",
    transcript: [
      {
        request: {
          method: "GET",
          url: "https://staging.shop.internal/api/orders/1002",
          headers: { cookie: "session=<user-A session>" },
        },
        response: {
          status: 200,
          bodySnippet: '{"id":1002,"userId":77,"total":"$420.00"}',
        },
        note: "User A (id 42) successfully read User B's (id 77) order — no ownership check.",
      },
    ],
  },
  status: "confirmed",
  createdAt: T.confirmed,
} satisfies ConfirmedFinding;

const confirmedByScan: Record<string, ConfirmedFinding[]> = {
  scan_demo_completed: [confSqli, confXss, confIdor],
};

/* ----------------------------- unconfirmed appendix ---------------------------- */

const unconfirmedCors = {
  id: "prob_cors_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  rootCauseId: "rc_cors_0001",
  category: "permissive_cors",
  mergedCandidateIds: ["cand_cors_0001"],
  reachabilityHypothesis: "Wildcard CORS on a public, non-credentialed read endpoint.",
  exploitHypothesis: "Low impact without credentials/cookies on the endpoint.",
  exposure: "public",
  routeId: "route_users",
  location: { file: "app/api/users/route.ts", line: 12 },
  reachabilityScore: 0.5,
  exposureScore: 0.6,
  impactScore: 0.2,
  rank: 3,
  status: "unconfirmed",
  unconfirmedReason:
    "Endpoint carries no credentials/cookies; wildcard CORS is not exploitable in this context.",
  createdAt: T.confirmed,
} satisfies UnconfirmedFinding;

/* ---------------------------------- fixes -------------------------------------- */

const fixSqli = {
  id: "fix_sqli_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  confirmedFindingId: "conf_sqli_0001",
  patch: [
    "--- a/app/api/users/route.ts",
    "+++ b/app/api/users/route.ts",
    "@@ -6,7 +6,5 @@ export async function GET(req: NextRequest) {",
    '   const q = req.nextUrl.searchParams.get("q") ?? "";',
    "-  const rows = await prisma.$queryRawUnsafe(",
    "-    `SELECT * FROM \"User\" WHERE name = '${q}'`,",
    "-  );",
    "+  const rows = await prisma.user.findMany({ where: { name: { contains: q } } });",
    "   return Response.json(rows);",
    " }",
    "",
  ].join("\n"),
  rationale:
    "Replace the interpolated raw query with a parameterized Prisma query so `q` can never alter SQL structure.",
  proofOfFixTest: {
    filePath: "app/api/users/route.test.ts",
    framework: "vitest",
    code: [
      'it("neutralizes SQLi payloads", async () => {',
      "  const res = await GET(reqWith(\"' OR '1'='1\"));",
      "  expect(await res.json()).toEqual([]);",
      "});",
    ].join("\n"),
    failsPrePatch: true,
    passesPostPatch: true,
  },
  riskClass: "auto-eligible",
  riskClassRationale:
    "Mechanical parameterization; no auth/session/crypto/access-control code touched.",
  status: "pr-open",
  pullRequestId: "pr_0001",
  createdAt: T.fix,
  updatedAt: T.pr,
} satisfies Fix;

const fixXss = {
  id: "fix_xss_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  confirmedFindingId: "conf_xss_0001",
  patch: [
    "--- a/app/search/page.tsx",
    "+++ b/app/search/page.tsx",
    "@@ -6,3 +6,3 @@ export default function Search({ searchParams }) {",
    '   const q = searchParams.q ?? "";',
    "-  return <div dangerouslySetInnerHTML={{ __html: q }} />;",
    "+  return <div>{q}</div>;",
    " }",
    "",
  ].join("\n"),
  rationale: "Render user input as text (auto-escaped by React) instead of raw HTML.",
  proofOfFixTest: {
    filePath: "app/search/page.test.tsx",
    framework: "vitest",
    code: [
      'it("escapes injected markup", () => {',
      '  const { container } = render(<Search searchParams={{ q: "<img onerror=x>" }} />);',
      '  expect(container.querySelector("img")).toBeNull();',
      "});",
    ].join("\n"),
    failsPrePatch: true,
    passesPostPatch: true,
  },
  riskClass: "auto-eligible",
  riskClassRationale: "Output-encoding fix; low blast radius, no access-control logic.",
  status: "pr-open",
  pullRequestId: "pr_0001",
  createdAt: T.fix,
  updatedAt: T.pr,
} satisfies Fix;

const fixIdor = {
  id: "fix_idor_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  confirmedFindingId: "conf_idor_0001",
  patch: [
    "--- a/app/api/orders/[id]/route.ts",
    "+++ b/app/api/orders/[id]/route.ts",
    "@@ -10,4 +10,7 @@ export async function GET(req, { params }) {",
    "   const session = await requireSession(req);",
    "-  const order = await prisma.order.findFirst({ where: { id: Number(params.id) } });",
    "+  const order = await prisma.order.findFirst({",
    "+    where: { id: Number(params.id), userId: session.userId },",
    "+  });",
    '+  if (!order) return new Response("Not found", { status: 404 });',
    "   return Response.json(order);",
    "",
  ].join("\n"),
  rationale:
    "Scope the lookup to the authenticated user's id so users can only read their own orders.",
  proofOfFixTest: {
    filePath: "app/api/orders/[id]/route.test.ts",
    framework: "vitest",
    code: [
      'it("blocks cross-user order access", async () => {',
      '  const res = await GET(reqAs(userA), { params: { id: "1002" } });',
      "  expect(res.status).toBe(404);",
      "});",
    ].join("\n"),
    failsPrePatch: true,
    passesPostPatch: true,
  },
  riskClass: "human-required",
  riskClassRationale:
    "Touches access-control logic (ownership check). Auth/access-control fixes are ALWAYS human-required (§11, golden rule #3) — never auto-applied.",
  status: "proposed",
  createdAt: T.fix,
} satisfies Fix;

const fixesByScan: Record<string, Fix[]> = {
  scan_demo_completed: [fixSqli, fixXss, fixIdor],
};

/* ------------------------------- pull requests --------------------------------- */

const prCompleted = {
  id: "pr_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  provider: "github",
  url: "https://github.com/montr/shop-web/pull/128",
  number: 128,
  branch: "montr/auto-fix-scan_demo_completed",
  baseBranch: "main",
  title: "Montr Secure: fix 2 auto-eligible confirmed findings (SQLi, XSS)",
  bodySummary:
    "Auto-eligible fixes for 2 confirmed findings, each with a proof-of-fix test. The IDOR fix touches access control and is human-required, so it is a recommendation in the report — not in this PR.",
  fixIds: ["fix_sqli_0001", "fix_xss_0001"],
  status: "open",
  createdAt: T.pr,
} satisfies PullRequest;

const pullRequestsByScan: Record<string, PullRequest[]> = {
  scan_demo_completed: [prCompleted],
};

/* ----------------------------------- report ------------------------------------ */

const reportCompleted = {
  id: "report_0001",
  scanId: "scan_demo_completed",
  clientId: CLIENT_ID,
  generatedAt: T.report,
  executiveSummary: {
    totalConfirmed: 3,
    confirmedBySeverity: { info: 0, low: 0, medium: 0, high: 2, critical: 1 },
    postureDelta: { newIssues: 1, resolvedIssues: 2, netDelta: -1 },
    toolsConsolidated: ["semgrep", "gitleaks", "osv", "playwright-dast"],
  },
  confirmedFindings: [
    { finding: confSqli, fix: fixSqli, compliance: complianceForCategory("sql_injection") },
    { finding: confXss, fix: fixXss, compliance: complianceForCategory("xss") },
    { finding: confIdor, fix: fixIdor, compliance: complianceForCategory("broken_access_control") },
  ],
  fixStatus: {
    autoEligibleFixIds: ["fix_sqli_0001", "fix_xss_0001"],
    humanRequiredFixIds: ["fix_idor_0001"],
    pullRequests: [prCompleted],
  },
  unconfirmedAppendix: [unconfirmedCors],
  complianceMapping: [
    complianceForCategory("sql_injection"),
    complianceForCategory("xss"),
    complianceForCategory("broken_access_control"),
    complianceForCategory("permissive_cors"),
  ],
  costAndScope: {
    scope: {
      mode: "full",
      includePaths: ["app/", "lib/", "prisma/"],
      excludePaths: [],
      changedFiles: [],
      reachableFromChanges: false,
      routeCount: 3,
      fileCount: 24,
      stagingUrl: "https://staging.shop.internal",
    },
    cost: {
      scanId: "scan_demo_completed",
      estimate: estimateCompleted,
      actual: {
        scanId: "scan_demo_completed",
        usage: { inputTokens: 118_000, outputTokens: 26_000, totalTokens: 144_000 },
        actualUsd: 0.6,
        wallClockSeconds: 172,
        byLayer: [
          {
            key: "layer2",
            usage: { inputTokens: 59_000, outputTokens: 13_000, totalTokens: 72_000 },
            usd: 0.3,
          },
          {
            key: "layer3",
            usage: { inputTokens: 59_000, outputTokens: 13_000, totalTokens: 72_000 },
            usd: 0.3,
          },
        ],
        byModel: [
          {
            key: "claude-sonnet-5",
            usage: { inputTokens: 90_000, outputTokens: 20_000, totalTokens: 110_000 },
            usd: 0.45,
          },
          {
            key: "claude-opus-4-8",
            usage: { inputTokens: 28_000, outputTokens: 6_000, totalTokens: 34_000 },
            usd: 0.15,
          },
        ],
        updatedAt: T.done,
      },
      costPerFindingUsd: 0.2,
      variancePct: -0.09,
    },
  },
  // B10/B11 — blue-team sections, populated with real, finding-grounded
  // sample data (not empty stubs) so the B11 console pages under
  // scans/[scanId]/blue-team are actually visually testable under MSW.
  // Every id/technique/rule below is derived from the SAME three confirmed
  // findings above (confSqli/confXss/confIdor) — no invented findings.
  blueTeam: {
    mitreAttack: {
      findings: [
        {
          findingId: "conf_sqli_0001",
          title: confSqli.title,
          category: "sql_injection",
          severity: "critical",
          techniques: [
            {
              id: "T1190",
              name: "Exploit Public-Facing Application",
              tactic: "Initial Access",
              framework: "attack-enterprise",
              url: "https://attack.mitre.org/techniques/T1190/",
            },
            {
              id: "T1213",
              name: "Data from Information Repositories",
              tactic: "Collection",
              framework: "attack-enterprise",
              url: "https://attack.mitre.org/techniques/T1213/",
            },
          ],
        },
        {
          findingId: "conf_xss_0001",
          title: confXss.title,
          category: "xss",
          severity: "high",
          techniques: [
            {
              id: "T1059.007",
              name: "Command and Scripting Interpreter: JavaScript",
              tactic: "Execution",
              framework: "attack-enterprise",
              url: "https://attack.mitre.org/techniques/T1059/007/",
            },
            {
              id: "T1539",
              name: "Steal Web Session Cookie",
              tactic: "Credential Access",
              framework: "attack-enterprise",
              url: "https://attack.mitre.org/techniques/T1539/",
            },
          ],
        },
        {
          findingId: "conf_idor_0001",
          title: confIdor.title,
          category: "broken_access_control",
          severity: "high",
          techniques: [
            {
              id: "T1548",
              name: "Abuse Elevation Control Mechanism",
              tactic: "Privilege Escalation, Defense Evasion",
              framework: "attack-enterprise",
              url: "https://attack.mitre.org/techniques/T1548/",
            },
            {
              id: "T1078",
              name: "Valid Accounts",
              tactic: "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
              framework: "attack-enterprise",
              url: "https://attack.mitre.org/techniques/T1078/",
            },
          ],
        },
      ],
      coverage: [
        {
          technique: {
            id: "T1059.007",
            name: "Command and Scripting Interpreter: JavaScript",
            tactic: "Execution",
            framework: "attack-enterprise",
            url: "https://attack.mitre.org/techniques/T1059/007/",
          },
          findingCount: 1,
          findingIds: ["conf_xss_0001"],
        },
        {
          technique: {
            id: "T1078",
            name: "Valid Accounts",
            tactic: "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
            framework: "attack-enterprise",
            url: "https://attack.mitre.org/techniques/T1078/",
          },
          findingCount: 1,
          findingIds: ["conf_idor_0001"],
        },
        {
          technique: {
            id: "T1190",
            name: "Exploit Public-Facing Application",
            tactic: "Initial Access",
            framework: "attack-enterprise",
            url: "https://attack.mitre.org/techniques/T1190/",
          },
          findingCount: 1,
          findingIds: ["conf_sqli_0001"],
        },
        {
          technique: {
            id: "T1213",
            name: "Data from Information Repositories",
            tactic: "Collection",
            framework: "attack-enterprise",
            url: "https://attack.mitre.org/techniques/T1213/",
          },
          findingCount: 1,
          findingIds: ["conf_sqli_0001"],
        },
        {
          technique: {
            id: "T1539",
            name: "Steal Web Session Cookie",
            tactic: "Credential Access",
            framework: "attack-enterprise",
            url: "https://attack.mitre.org/techniques/T1539/",
          },
          findingCount: 1,
          findingIds: ["conf_xss_0001"],
        },
        {
          technique: {
            id: "T1548",
            name: "Abuse Elevation Control Mechanism",
            tactic: "Privilege Escalation, Defense Evasion",
            framework: "attack-enterprise",
            url: "https://attack.mitre.org/techniques/T1548/",
          },
          findingCount: 1,
          findingIds: ["conf_idor_0001"],
        },
      ],
    },
    detectionEngineering: {
      rules: [
        {
          id: "detrule_sqli_0001",
          clientId: CLIENT_ID,
          scanId: "scan_demo_completed",
          findingId: "conf_sqli_0001",
          format: "sigma",
          content: [
            "title: SQL injection attempt on GET /api/users",
            "id: montr-conf_sqli_0001",
            "status: stable",
            "logsource:",
            "  category: webserver",
            "detection:",
            "  selection:",
            "    cs-uri-stem|startswith: '/api/users'",
            "    cs-method: 'GET'",
            '    cs-uri-query|contains: "\'"',
            "  condition: selection",
            "level: high",
            "tags:",
            "  - attack.initial-access",
            "  - attack.t1190",
            "  - attack.collection",
            "  - attack.t1213",
            "",
          ].join("\n"),
          mitreTechniques: ["T1190", "T1213"],
          provenance: "static",
          logSignature: {
            fields: ["cs-uri-query", "cs-method", "cs-uri-stem"],
            pattern: 'cs-uri-stem startswith "/api/users" AND cs-uri-query contains "\'"',
            falseAlarmSources: [
              'An internal reporting/BI tool bulk-exporting user records whose free-text name fields legitimately contain apostrophes (e.g. "O\'Brien").',
            ],
          },
          createdAt: T.report,
        },
        {
          id: "detrule_xss_0001",
          clientId: CLIENT_ID,
          scanId: "scan_demo_completed",
          findingId: "conf_xss_0001",
          format: "otel",
          content: [
            "-- OTTL filter/transform condition (montr-conf_xss_0001)",
            'condition: attributes["http.route"] == "/search" and',
            '  IsMatch(attributes["http.request.header.referer"], ".*<script.*|.*onerror=.*")',
          ].join("\n"),
          mitreTechniques: ["T1059.007", "T1539"],
          provenance: "static",
          logSignature: {
            fields: ["http.route", "http.request.header.referer", "http.request.query.q"],
            pattern: 'http.route == "/search" AND query.q matches <script|onerror=',
            falseAlarmSources: [
              "A documentation/QA crawler submitting literal HTML snippets as search terms during content review.",
            ],
          },
          createdAt: T.report,
        },
        {
          id: "detrule_idor_0001",
          clientId: CLIENT_ID,
          scanId: "scan_demo_completed",
          findingId: "conf_idor_0001",
          format: "siem_query",
          content: [
            'index=web_access sourcetype=access_combined uri_path="/api/orders/*" method=GET',
            '| eval order_id=mvindex(split(uri_path, "/"), -1)',
            "| stats values(order_id) as orders_viewed count by user, src_ip",
            "| where count > 20",
          ].join("\n"),
          mitreTechniques: ["T1548", "T1078"],
          provenance: "live",
          logSignature: {
            fields: ["uri_path", "user", "src_ip"],
            pattern:
              "single session requesting > 20 distinct /api/orders/{id} values in a short window",
            falseAlarmSources: [
              "A customer-support agent's admin tool paging through many orders on behalf of different customers in one session.",
            ],
          },
          createdAt: T.report,
        },
      ],
      coverage: [
        {
          id: "detcov_sqli_0001",
          clientId: CLIENT_ID,
          scanId: "scan_demo_completed",
          findingId: "conf_sqli_0001",
          detected: true,
          reasoning:
            "app/api/users/route.ts logs via a structured logger (winston) that captures the request query string; the Sigma rule's cs-uri-query condition matches a real logged field.",
          detectionRuleId: "detrule_sqli_0001",
          verification: {
            scenarioId: "scenario_sqli_0001",
            fired: true,
            verifiedAt: T.report,
            evidence:
              "purple-team run purple_run_0007 — rule matched the injected payload in the captured request.",
          },
          createdAt: T.report,
        },
        {
          id: "detcov_xss_0001",
          clientId: CLIENT_ID,
          scanId: "scan_demo_completed",
          findingId: "conf_xss_0001",
          detected: "unknown",
          reasoning:
            "app/search/page.tsx only has console.* logging (no structured fields) — cannot confirm whether an alerting pipeline would actually capture the referer header the rule depends on.",
          detectionRuleId: "detrule_xss_0001",
          createdAt: T.report,
        },
        {
          id: "detcov_idor_0001",
          clientId: CLIENT_ID,
          scanId: "scan_demo_completed",
          findingId: "conf_idor_0001",
          detected: false,
          reasoning:
            "app/api/orders/[id]/route.ts has no request logging at all (a silent route, per the B6 telemetry-surface scan) — the SPL rule has no log source to alert against.",
          detectionRuleId: "detrule_idor_0001",
          verification: {
            scenarioId: "scenario_idor_0001",
            fired: false,
            verifiedAt: T.report,
            evidence:
              "purple-team run purple_run_0007 — no matching log line for the scenario's requests.",
          },
          createdAt: T.report,
        },
      ],
    },
    attackPaths: [
      {
        id: "attackpath_0001",
        clientId: CLIENT_ID,
        scanId: "scan_demo_completed",
        steps: [
          {
            findingId: "conf_sqli_0001",
            note: "SQL injection on the public GET /api/users route dumps the User table, including session/auth-adjacent fields — enough for an attacker to reuse a real identity.",
          },
          {
            findingId: "conf_idor_0001",
            note: "Using a harvested identity, the attacker walks GET /api/orders/[id] sequentially — no ownership check — to read every customer's order history.",
          },
        ],
        feasibilityScore: 0.62,
        severity: "critical",
        narrative:
          "An unauthenticated SQL injection on GET /api/users leaks enough user data to let an attacker impersonate a real account, then pivot into the IDOR-exposed orders endpoint and enumerate every customer's order history end to end.",
        createdAt: T.report,
      },
    ],
    threatModel: {
      present: true,
      summary:
        "Two trust boundaries carry real, exploitable risk: an unauthenticated public API surface (SQL injection, reflected XSS) and a session-authenticated account boundary with no ownership checks (IDOR). Both should be prioritized before the next release.",
      markdown: [
        "# Threat model — shop-web",
        "",
        "This application exposes confirmed, reachable attack surfaces across its public catalog API and its authenticated account API.",
        "",
        "## Trust boundaries",
        "",
        "- **Public API boundary** (`/api/users`, `/search`) — unauthenticated; Spoofing and Tampering both apply, corroborated by the confirmed SQL injection and reflected XSS findings on these exact routes.",
        "- **Authenticated account boundary** (`/api/orders/[id]`) — session-authenticated but has no per-user ownership check, so Tampering and Information Disclosure both apply despite the auth requirement.",
        "",
        "## STRIDE roll-up",
        "",
        "- Spoofing: 1 boundary",
        "- Tampering: 2 boundaries",
        "- Information disclosure: 2 boundaries",
        "- Elevation of privilege: 1 boundary",
        "",
        "## Abuse cases",
        "",
        "- An anonymous attacker enumerates the `q` search parameter against `/api/users` to exfiltrate the full user table via SQL injection.",
        "- An authenticated low-privilege user increments the numeric order id in `/api/orders/[id]` to read other customers' order history.",
        "",
      ].join("\n"),
    },
    hardening: {
      advisoryOnly: true,
      recommendations: [
        {
          id: "harden_headers_0001",
          category: "security_headers",
          severity: "medium",
          title: "Add hardened response headers to the Next.js response pipeline",
          gap: "No helmet/@fastify/helmet dependency and no next.config.js headers() export were detected — responses ship with no X-Content-Type-Options, X-Frame-Options, or Strict-Transport-Security header.",
          recommendation: [
            "// next.config.js",
            "async headers() {",
            "  return [{",
            '    source: "/:path*",',
            "    headers: [",
            '      { key: "X-Content-Type-Options", value: "nosniff" },',
            '      { key: "X-Frame-Options", value: "DENY" },',
            '      { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },',
            "    ],",
            "  }];",
            "}",
          ].join("\n"),
          rationale:
            "Missing security headers make clickjacking and MIME-sniffing easier to chain with the confirmed reflected XSS in /search.",
          evidence: [
            "package.json: no helmet/@fastify/helmet dependency",
            "next.config.js: no headers() export",
          ],
          framework: "nextjs",
          relatedFindingIds: ["conf_xss_0001"],
          createdAt: T.report,
        },
        {
          id: "harden_cookie_0001",
          category: "cookie_policy",
          severity: "high",
          title: "Set Secure, HttpOnly, and SameSite on the session cookie",
          gap: "The session cookie observed in the IDOR live-DAST transcript is set with no Secure/HttpOnly/SameSite attributes.",
          recommendation:
            'res.setHeader("Set-Cookie", `session=${token}; Secure; HttpOnly; SameSite=Lax; Path=/`);',
          rationale:
            "An unattributed session cookie is readable by client-side script (compounding the confirmed XSS) and can be replayed cross-site.",
          evidence: [
            "app/api/orders/[id]/route.ts: Set-Cookie header has no Secure/HttpOnly/SameSite attributes",
            "conf_idor_0001 live-DAST transcript: session cookie sent with no attributes",
          ],
          framework: "nextjs",
          relatedFindingIds: ["conf_idor_0001", "conf_xss_0001"],
          createdAt: T.report,
        },
        {
          id: "harden_waf_0001",
          category: "waf_rules",
          severity: "high",
          title: "Enable managed SQLi + XSS rule groups at the edge",
          gap: "No WAF/managed-rule-group configuration was detected in front of the public API surface confirmed vulnerable to SQL injection and reflected XSS.",
          recommendation:
            "AWS WAF: enable AWSManagedRulesSQLiRuleSet and AWSManagedRulesCommonRuleSet. Cloudflare: enable the Managed Ruleset's SQLi and XSS rule groups. ModSecurity/OWASP CRS: include REQUEST-942-APPLICATION-ATTACK-SQLI.conf and REQUEST-941-APPLICATION-ATTACK-XSS.conf.",
          rationale:
            "A managed WAF rule group gives immediate perimeter mitigation for both confirmed injection classes while the code-level fixes go through PR review.",
          evidence: [
            "conf_sqli_0001: confirmed SQL injection, no WAF layer detected in front of the route",
            "conf_xss_0001: confirmed reflected XSS, no WAF layer detected in front of the route",
          ],
          relatedFindingIds: ["conf_sqli_0001", "conf_xss_0001"],
          createdAt: T.report,
        },
      ],
    },
    purpleTeam: {
      entries: [
        {
          scenarioId: "scenario_sqli_0001",
          scenarioName: "SQLi data-exfil via GET /api/users?q=",
          findingId: "conf_sqli_0001",
          findingCategory: "sql_injection",
          detectionRuleId: "detrule_sqli_0001",
          detected: true,
          reason:
            "The Sigma rule's cs-uri-query|contains \"'\" condition matched the scenario's actual injected payload in the captured request.",
        },
        {
          scenarioId: "scenario_idor_0001",
          scenarioName: "IDOR cross-user order enumeration",
          findingId: "conf_idor_0001",
          findingCategory: "broken_access_control",
          detectionRuleId: "detrule_idor_0001",
          detected: false,
          reason:
            "The route has no request logging at all (a silent route, per the B6 telemetry-surface scan) — the SPL rule has no log source to alert against, so it structurally could not fire.",
        },
      ],
      totalScenarios: 2,
      detectedCount: 1,
      undetectedCount: 1,
    },
  },
} satisfies Report;

const reportsByScan: Record<string, Report> = {
  scan_demo_completed: reportCompleted,
};

/* ----------------------------------- scans ------------------------------------- */

const scanCompleted = {
  id: "scan_demo_completed",
  clientId: CLIENT_ID,
  appMapId: "appmap_demo_0001",
  repo: "git@github.com:montr/shop-web.git",
  branch: "main",
  commitSha: COMMIT,
  mode: "full",
  scope: {
    mode: "full",
    includePaths: ["app/", "lib/", "prisma/"],
    excludePaths: [],
    changedFiles: [],
    reachableFromChanges: false,
    routeCount: 3,
    fileCount: 24,
    stagingUrl: "https://staging.shop.internal",
  },
  status: "completed",
  gateState: "approved",
  operator: USERS.operator.id,
  approver: USERS.approver.id,
  budgetPolicy: {
    maxUsd: 5,
    enforcement: "hard_halt",
    requireEstimateApproval: true,
    warnThresholdPct: 0.8,
  },
  costEstimate: estimateCompleted,
  costActual: reportCompleted.costAndScope.cost.actual,
  startedAt: T.approved,
  finishedAt: T.done,
  createdAt: T.created,
} satisfies Scan;

const scanRunning = {
  id: "scan_demo_running",
  clientId: CLIENT_ID,
  appMapId: "appmap_demo_0001",
  repo: "git@github.com:montr/billing-svc.git",
  branch: "release/2026.7",
  commitSha: "bb11cc22dd33ee44ff5500112233445566778899",
  mode: "diff",
  scope: {
    mode: "diff",
    includePaths: [],
    excludePaths: [],
    changedFiles: ["app/api/invoices/route.ts", "lib/pdf.ts"],
    reachableFromChanges: true,
    routeCount: 1,
    fileCount: 2,
    stagingUrl: "https://staging.billing.internal",
  },
  status: "running",
  gateState: "running",
  operator: USERS.operator.id,
  budgetPolicy: {
    maxUsd: 5,
    enforcement: "hard_halt",
    requireEstimateApproval: true,
    warnThresholdPct: 0.8,
  },
  costEstimate: estimateRunning,
  startedAt: T.approved,
  createdAt: T.created,
} satisfies Scan;

const scanPending = {
  id: "scan_demo_pending",
  clientId: CLIENT_ID,
  repo: "git@github.com:montr/shop-web.git",
  branch: "feat/checkout-v2",
  commitSha: "cc22dd33ee44ff550011223344556677889900aa",
  mode: "full",
  scope: {
    mode: "full",
    includePaths: ["app/", "lib/"],
    excludePaths: ["**/*.test.ts"],
    changedFiles: [],
    reachableFromChanges: false,
    routeCount: 12,
    fileCount: 88,
  },
  status: "queued",
  gateState: "estimate_pending",
  operator: USERS.operator.id,
  budgetPolicy: {
    maxUsd: 3,
    enforcement: "hard_halt",
    requireEstimateApproval: true,
    warnThresholdPct: 0.8,
  },
  costEstimate: estimatePending,
  createdAt: T.created,
} satisfies Scan;

const scanBlocked = {
  id: "scan_demo_blocked",
  clientId: CLIENT_ID,
  repo: "git@github.com:montr/monorepo.git",
  branch: "main",
  commitSha: "dd33ee44ff550011223344556677889900aabbcc",
  mode: "full",
  scope: {
    mode: "full",
    includePaths: ["."],
    excludePaths: [],
    changedFiles: [],
    reachableFromChanges: false,
    routeCount: 140,
    fileCount: 2100,
  },
  status: "partial",
  gateState: "blocked",
  operator: USERS.operator.id,
  budgetPolicy: {
    maxUsd: 4,
    enforcement: "hard_halt",
    requireEstimateApproval: true,
    warnThresholdPct: 0.8,
  },
  costEstimate: estimateBlocked,
  startedAt: T.approved,
  finishedAt: T.l3,
  createdAt: T.created,
} satisfies Scan;

const scans: Scan[] = [scanCompleted, scanRunning, scanPending, scanBlocked];
const scansById = new Map<string, Scan>(scans.map((s) => [s.id, s]));

const estimatesByScan: Record<string, CostEstimate> = {
  scan_demo_completed: estimateCompleted,
  scan_demo_running: estimateRunning,
  scan_demo_pending: estimatePending,
  scan_demo_blocked: estimateBlocked,
};

const appMapsByScan: Record<string, AppMap> = {
  scan_demo_completed: appMapCompleted,
  scan_demo_running: appMapCompleted,
};

/* -------------------------------- progress ------------------------------------- */

function progressFor(scanId: string, upto: number): ProgressEvent[] {
  const all: ProgressEvent[] = [
    { scanId, layer: "layer0", phase: "app-map", pct: 100, message: "App Map built", at: T.l0 },
    {
      scanId,
      layer: "layer1",
      phase: "discovery",
      pct: 100,
      message: "SAST · secrets · SCA complete",
      at: T.l2,
    },
    {
      scanId,
      layer: "layer2",
      phase: "correlation",
      pct: 100,
      message: "Ranked probable findings",
      at: T.l2,
    },
    {
      scanId,
      layer: "layer3",
      phase: "static-proof",
      pct: 100,
      message: "Confirmed exploitable findings",
      at: T.l3,
    },
    {
      scanId,
      layer: "layer4",
      phase: "fix-gen",
      pct: 100,
      message: "Fixes generated with tests",
      at: T.fix,
    },
    {
      scanId,
      layer: "layer5",
      phase: "report",
      pct: 100,
      message: "Report + gated PRs",
      at: T.report,
    },
  ];
  return all.slice(0, upto);
}

const progressByScan: Record<string, ProgressEvent[]> = {
  scan_demo_completed: progressFor("scan_demo_completed", 6),
  scan_demo_running: [
    ...progressFor("scan_demo_running", 2),
    {
      scanId: "scan_demo_running",
      layer: "layer2",
      phase: "correlation",
      pct: 45,
      message: "Correlating candidates against App Map",
      at: T.l2,
    },
  ],
  scan_demo_pending: [],
  scan_demo_blocked: [
    ...progressFor("scan_demo_blocked", 2),
    {
      scanId: "scan_demo_blocked",
      layer: "layer2",
      phase: "correlation",
      pct: 60,
      message: "Budget ceiling reached — hard halt",
      at: T.l3,
    },
  ],
};

/* ------------------------------ mutable extra state ---------------------------- */

const dastAuthorized = new Set<string>(["scan_demo_completed"]);
const falsePositives = new Set<string>();

/* ------------------------------- seed audit log -------------------------------- */

(function seedAudit() {
  appendAudit({
    scanId: scanCompleted.id,
    actor: operatorActor,
    action: "scan.created",
    targetType: "scan",
    targetId: scanCompleted.id,
    summary: "Scan created for montr/shop-web@main",
    at: T.created,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "gate.estimate_presented",
    summary: "Pre-scan estimate $0.66 presented",
    metadata: { projectedUsd: 0.66 },
    at: T.estimate,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: operatorActor,
    action: "gate.estimate_approved",
    summary: "Operator approved the cost estimate",
    at: T.approved,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "appmap.built",
    summary: "App Map built (3 routes, 3 sinks)",
    metadata: { routes: 3, sinks: 3 },
    at: T.l0,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "llm.call",
    summary: "LLM correlation pass (metadata only)",
    metadata: {
      model: "claude-sonnet-5",
      layer: "layer2",
      inputTokens: 59_000,
      outputTokens: 13_000,
    },
    at: T.l2,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: approverActor,
    action: "dast.authorized",
    summary: "Approver authorized live DAST against staging.shop.internal",
    metadata: { target: "https://staging.shop.internal" },
    at: T.dast,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "dast.probe",
    summary: "DAST probe against allowlisted staging target",
    metadata: { target: "https://staging.shop.internal", rateLimited: true },
    at: T.dast,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "finding.confirmed",
    targetType: "finding",
    targetId: confSqli.id,
    summary: "Confirmed: SQL Injection in GET /api/users",
    at: T.confirmed,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "finding.confirmed",
    targetType: "finding",
    targetId: confIdor.id,
    summary: "Confirmed (live): IDOR in GET /api/orders/[id]",
    at: T.confirmed,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "fix.generated",
    targetType: "fix",
    targetId: fixSqli.id,
    summary: "Fix generated (auto-eligible): parameterize query",
    metadata: { riskClass: "auto-eligible" },
    at: T.fix,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "fix.generated",
    targetType: "fix",
    targetId: fixIdor.id,
    summary: "Fix generated (human-required): add ownership check",
    metadata: { riskClass: "human-required" },
    at: T.fix,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: approverActor,
    action: "gate.fix_approved",
    summary: "Approver cleared the fix gate for auto-eligible fixes",
    at: T.pr,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "fix.pr_opened",
    targetType: "pull_request",
    targetId: prCompleted.id,
    summary: "Opened PR #128 for 2 auto-eligible fixes",
    metadata: { url: prCompleted.url },
    at: T.pr,
  });
  appendAudit({
    scanId: scanCompleted.id,
    actor: agent,
    action: "scan.completed",
    summary: "Scan completed; report generated",
    at: T.done,
  });

  appendAudit({
    scanId: scanPending.id,
    actor: operatorActor,
    action: "scan.created",
    targetType: "scan",
    targetId: scanPending.id,
    summary: "Scan created for montr/shop-web@feat/checkout-v2",
    at: T.created,
  });
  appendAudit({
    scanId: scanPending.id,
    actor: agent,
    action: "gate.estimate_presented",
    summary: "Pre-scan estimate $1.90 presented — awaiting approval",
    metadata: { projectedUsd: 1.9 },
    at: T.estimate,
  });

  appendAudit({
    scanId: scanRunning.id,
    actor: operatorActor,
    action: "scan.created",
    targetType: "scan",
    targetId: scanRunning.id,
    summary: "Diff scan created for montr/billing-svc",
    at: T.created,
  });
  appendAudit({
    scanId: scanRunning.id,
    actor: operatorActor,
    action: "gate.estimate_approved",
    summary: "Operator approved the cost estimate",
    at: T.approved,
  });
  appendAudit({
    scanId: scanRunning.id,
    actor: agent,
    action: "scan.started",
    summary: "Pipeline started (diff mode)",
    at: T.approved,
  });

  appendAudit({
    scanId: scanBlocked.id,
    actor: operatorActor,
    action: "scan.created",
    targetType: "scan",
    targetId: scanBlocked.id,
    summary: "Full scan created for montr/monorepo",
    at: T.created,
  });
  appendAudit({
    scanId: scanBlocked.id,
    actor: operatorActor,
    action: "gate.estimate_approved",
    summary: "Operator approved the cost estimate",
    at: T.approved,
  });
  appendAudit({
    scanId: scanBlocked.id,
    actor: systemActor,
    action: "budget.exceeded",
    summary: "Budget ceiling $4.00 exceeded — hard halt, partial report emitted",
    metadata: { ceilingUsd: 4, spentUsd: 4.01 },
    at: T.l3,
  });
})();

/* --------------------------------- accessors ----------------------------------- */

export const db = {
  clientId: CLIENT_ID,
  users: USERS,

  listScans(): Scan[] {
    return [...scansById.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },
  getScan(id: string): Scan | undefined {
    return scansById.get(id);
  },
  getEstimate(id: string): CostEstimate | undefined {
    return estimatesByScan[id];
  },
  getAppMap(id: string): AppMap | undefined {
    return appMapsByScan[id];
  },
  getProgress(id: string): ProgressEvent[] {
    return progressByScan[id] ?? [];
  },
  getReport(id: string): Report | undefined {
    return reportsByScan[id];
  },
  getFixes(id: string): Fix[] {
    return fixesByScan[id] ?? [];
  },
  getScanPullRequests(id: string): PullRequest[] {
    return pullRequestsByScan[id] ?? [];
  },
  listPullRequests(): PullRequest[] {
    return Object.values(pullRequestsByScan).flat();
  },
  listAudit(scanId?: string): AuditEvent[] {
    const rows = scanId ? auditLog.filter((e) => e.scanId === scanId) : auditLog;
    return [...rows].sort((a, b) => b.sequence - a.sequence);
  },
  isDastAuthorized(id: string): boolean {
    return dastAuthorized.has(id);
  },
  isFalsePositive(findingId: string): boolean {
    return falsePositives.has(findingId);
  },
  falsePositiveIds(): string[] {
    return [...falsePositives];
  },

  /* -------- mutations (each appends an AuditEvent) -------- */

  approveEstimate(id: string, actor: AuditActor): { scan: Scan; audit: AuditEvent } | undefined {
    const scan = scansById.get(id);
    if (!scan) return undefined;
    scan.gateState = "estimate_approved";
    scan.status = "running";
    scan.approver = actor.role === "approver" ? actor.id : scan.approver;
    scan.startedAt ??= new Date().toISOString();
    const audit = appendAudit({
      scanId: id,
      actor,
      action: "gate.estimate_approved",
      summary: `Cost estimate approved by ${actor.role ?? actor.type}`,
      at: new Date().toISOString(),
    });
    return { scan, audit };
  },

  approveFixGate(id: string, actor: AuditActor): { scan: Scan; audit: AuditEvent } | undefined {
    const scan = scansById.get(id);
    if (!scan) return undefined;
    scan.gateState = "approved";
    scan.approver = actor.id;
    const audit = appendAudit({
      scanId: id,
      actor,
      action: "gate.fix_approved",
      summary: "Approver cleared the fix gate",
      at: new Date().toISOString(),
    });
    return { scan, audit };
  },

  authorizeDast(
    id: string,
    actor: AuditActor,
    stagingUrl: string,
  ): { scan: Scan; audit: AuditEvent } | undefined {
    const scan = scansById.get(id);
    if (!scan) return undefined;
    dastAuthorized.add(id);
    scan.scope = { ...scan.scope, stagingUrl };
    scan.approver = actor.id;
    const audit = appendAudit({
      scanId: id,
      actor,
      action: "dast.authorized",
      summary: `Live DAST authorized against ${stagingUrl}`,
      metadata: { target: stagingUrl },
      at: new Date().toISOString(),
    });
    return { scan, audit };
  },

  killSwitch(
    id: string,
    actor: AuditActor,
    reason: string,
  ): { scan: Scan; audit: AuditEvent } | undefined {
    const scan = scansById.get(id);
    if (!scan) return undefined;
    scan.status = "cancelled";
    scan.gateState = "blocked";
    scan.finishedAt = new Date().toISOString();
    const audit = appendAudit({
      scanId: id,
      actor,
      action: "dast.kill_switch",
      summary: `Kill switch activated: ${reason}`,
      metadata: { reason },
      at: new Date().toISOString(),
    });
    return { scan, audit };
  },

  markFalsePositive(
    findingId: string,
    actor: AuditActor,
    reason: string,
  ): { scanId: string; finding: ConfirmedFinding; audit: AuditEvent } | undefined {
    // The real API looks up a confirmed finding by id alone (findings are not
    // addressed by scanId in the URL — see apps/api/src/routes/findings.ts);
    // mirror that here by searching across every scan's confirmed findings.
    let scanId: string | undefined;
    let finding: ConfirmedFinding | undefined;
    for (const [sid, findings] of Object.entries(confirmedByScan)) {
      const match = findings.find((f) => f.id === findingId);
      if (match) {
        scanId = sid;
        finding = match;
        break;
      }
    }
    if (!finding || !scanId) return undefined;
    falsePositives.add(findingId);
    const audit = appendAudit({
      scanId,
      actor,
      action: "finding.marked_false_positive",
      targetType: "finding",
      targetId: findingId,
      summary: `Marked "${finding.title}" as false positive`,
      metadata: { reason },
      at: new Date().toISOString(),
    });
    return { scanId, finding, audit };
  },
} as const;
