import { FixSchema, PullRequestSchema, type Fix, type PullRequest } from "@montr/contracts";
import {
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
  FIX_SQLI_ID,
  FIX_XSS_ID,
  PR_ID,
  CONFIRMED_SQLI_ID,
  CONFIRMED_XSS_ID,
} from "./ids.js";

export const mockFixes: Fix[] = [
  FixSchema.parse({
    id: FIX_SQLI_ID,
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    confirmedFindingId: CONFIRMED_SQLI_ID,
    patch: [
      "--- a/app/api/users/route.ts",
      "+++ b/app/api/users/route.ts",
      "@@",
      "-  const rows = await prisma.$queryRawUnsafe(",
      "-    `SELECT * FROM \"User\" WHERE name = '${q}'`,",
      "-  );",
      "+  const rows = await prisma.user.findMany({ where: { name: q } });",
      "",
    ].join("\n"),
    rationale:
      "Replace the interpolated raw query with a parameterized Prisma query so `q` can never alter SQL structure.",
    proofOfFixTest: {
      filePath: "app/api/users/route.test.ts",
      framework: "vitest",
      code: "expect(await GET(req(\"' OR '1'='1\"))).not.toContain('all rows');",
      failsPrePatch: true,
      passesPostPatch: true,
    },
    riskClass: "auto-eligible",
    riskClassRationale: "Mechanical parameterization; no auth/crypto/access-control code touched.",
    status: "proposed",
    createdAt: FIXED_NOW,
  }),
  FixSchema.parse({
    id: FIX_XSS_ID,
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    confirmedFindingId: CONFIRMED_XSS_ID,
    patch: [
      "--- a/app/search/page.tsx",
      "+++ b/app/search/page.tsx",
      "@@",
      "-  return <div dangerouslySetInnerHTML={{ __html: q }} />;",
      "+  return <div>{q}</div>;",
      "",
    ].join("\n"),
    rationale: "Render user input as text (auto-escaped by React) instead of raw HTML.",
    proofOfFixTest: {
      filePath: "app/search/page.test.tsx",
      framework: "vitest",
      code: "expect(render(<Search q='<img onerror=x>' />)).not.toContain('onerror');",
      failsPrePatch: true,
      passesPostPatch: true,
    },
    riskClass: "auto-eligible",
    riskClassRationale: "Output-encoding fix; low blast radius, no access-control logic.",
    status: "proposed",
    createdAt: FIXED_NOW,
  }),
];

export const mockPullRequest: PullRequest = PullRequestSchema.parse({
  id: PR_ID,
  scanId: SCAN_ID,
  clientId: CLIENT_ID,
  provider: "github",
  url: "https://github.example.internal/montr/vulnerable-nextjs/pull/42",
  number: 42,
  branch: "montr/auto-fix-scan_fixture_0001",
  baseBranch: "main",
  title: "Montr Secure: fix 2 confirmed vulnerabilities (SQLi, XSS)",
  bodySummary:
    "Auto-eligible fixes for 2 confirmed findings. Each includes a proof-of-fix test. Human-required fixes are listed as recommendations in the report, not here.",
  fixIds: [FIX_SQLI_ID, FIX_XSS_ID],
  status: "open",
  createdAt: FIXED_NOW,
});
