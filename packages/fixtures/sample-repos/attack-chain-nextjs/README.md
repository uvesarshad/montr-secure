# attack-chain-nextjs (fixture)

⚠️ **Intentionally vulnerable.** Do not deploy.

Purpose-built for `apps/worker/src/e2e-scan.test.ts`'s dedicated Blue Team
regression guard (A6, 2026-09-12): unlike `vulnerable-nextjs` (whose two
confirmed categories, `sql_injection` and `xss`, never satisfy any
`packages/correlation/src/attack-paths/conditions.ts` chain condition), this
repo pairs an RCE-class finding with a second finding on a different route so
a real `buildAttackPaths` (B8) chain is genuinely producible end to end, not
just a structurally-empty array regardless of whether Layer 5 threads the App
Map into `buildReport`. Not part of the golden corpus (`corpus/`) or its
ground-truth manifest — used only by the dedicated pipeline run in
`e2e-scan.test.ts`'s Blue Team describe block, with its own seeded (not live
Semgrep/gitleaks) Layer 1 candidate pile, so it never affects
`corpus/baseline.json` scoring or the shared `vulnerable-nextjs` scan's
false-positive grading.

Known vulnerabilities:

| # | Vuln | File | Line | CWE | OWASP |
|---|------|------|------|-----|-------|
| 1 | SQL injection (raw query) | `app/api/users/route.ts` | 9 | CWE-89 | A03:2021 |
| 2 | OS command injection | `app/api/run/route.ts` | 7 | CWE-78 | A03:2021 |

Finding #2 is `command_injection`-class (RCE), which unconditionally forms
`buildAttackPaths`' `rce-post-exploitation` chain condition with any other
confirmed finding on the same scan (`conditions.ts`'s `isRceClass` branch
needs no shared route/model evidence) — so a 2-hop attack path is expected to
be produced from just these two findings.
