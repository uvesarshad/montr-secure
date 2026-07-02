# vulnerable-nextjs (fixture)

⚠️ **Intentionally vulnerable.** Do not deploy. Used by the golden corpus to
measure detection precision/recall. Ground truth: `../ground-truth.manifest.json`
(and the typed `groundTruthManifest` export from `@montr/fixtures`).

Known vulnerabilities:

| # | Vuln | File | Line | CWE | OWASP |
|---|------|------|------|-----|-------|
| 1 | SQL injection (raw query) | `app/api/users/route.ts` | 9 | CWE-89 | A03:2021 |
| 2 | Reflected XSS | `app/search/page.tsx` | 8 | CWE-79 | A03:2021 |
| 3 | Hard-coded secret | `lib/config.ts` | 2 | CWE-798 | A07:2021 |
| 4 | Vulnerable dependency (lodash) | `package.json` | 14 | CWE-1321 | A06:2021 |
| 5 | Permissive CORS (wildcard) | `app/api/users/route.ts` | 12 | CWE-942 | A05:2021 |
