# vulnerable-nextjs-owasp (golden corpus)

Intentionally vulnerable Next.js (App Router) + Prisma repo covering OWASP
Top-10 cases **not** already in `@montr/fixtures`. Ground truth lives in
`corpus/ground-truth.manifest.json`. Do not "fix" these — they are the labels
the precision/recall gate scores against.

| #   | Vuln                                 | Category                | CWE     | OWASP    | File                           |
| --- | ------------------------------------ | ----------------------- | ------- | -------- | ------------------------------ |
| 1   | SSRF (unvalidated server fetch)      | `ssrf`                  | CWE-918 | A10:2021 | `app/api/fetch/route.ts`       |
| 2   | IDOR (no ownership check)            | `idor`                  | CWE-639 | A01:2021 | `app/api/orders/[id]/route.ts` |
| 3   | Broken access control (no role gate) | `broken_access_control` | CWE-284 | A01:2021 | `app/api/admin/route.ts`       |
| 4   | Insecure cookie flags                | `insecure_cookie`       | CWE-614 | A05:2021 | `app/api/login/route.ts`       |

All four are `exploitable: true` (should reach the CONFIRMED tier). The
access-control cases (IDOR, broken access control) must classify
`human-required` (golden rule #3); the SSRF and cookie fixes are mechanical and
`auto-eligible`.
