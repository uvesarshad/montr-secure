# corpus — golden test corpus (WS-P)

Curated **vulnerable + clean** repositories across Next.js/JS-TS, Python, and
JVM, with machine-readable **ground-truth labels**. The CI regression gate
scores a scan's confirmed findings against these labels to measure
precision/recall and the headline **false-positive rate**.

**Current size: 16 repos, 44 exploitable (confirmable) ground-truth findings +
3 explicitly-demoted (`exploitable: false`) markers, across 3 language
stacks.** (Grown from the original 8 repos / 19 findings — see "A17: corpus
growth" below for how and why.)

## Layout

```
corpus/
  ground-truth.manifest.json        shared manifest: repos/vulnerable-nextjs-owasp, repos/clean-nextjs-owasp
  baseline.json                     committed regression thresholds (the gate reads this)
  repos/
    vulnerable-nextjs-owasp/        SSRF, IDOR, broken access control, insecure cookie (synthetic)
    clean-nextjs-owasp/             the secured counterpart (0 confirmed findings)
  python-vuln/, python-clean/       synthetic Django app (SQLi, XSS, SSRF, IDOR, hardcoded secret)
  jvm-vuln/, jvm-clean/             synthetic Spring Boot app (SQLi, cmd-injection, deser, BAC, secret)
  dvna/                             REAL: appsecco/dvna (Damn Vulnerable NodeJS Application)
  pygoat/                           REAL: OWASP PyGoat (Django OWASP Top-10 labs)
  javaseccode/                      REAL: JoyChou93/java-sec-code (Spring Boot, one class per vuln)
  log4shell-vulnerable-app/         REAL: christophetd/log4shell-vulnerable-app (CVE-2021-44228)
  spring-petclinic/                 REAL: spring-projects/spring-petclinic (production-grade, 1 real finding)
  validatorjs-clean/                REAL clean: validatorjs/validator.js (JS/TS negative example)
  requests-clean/                   REAL clean: psf/requests (Python negative example)
  gson-clean/                       REAL clean: google/gson (JVM negative example)
```

Every directory above (both the `corpus/repos/*` entries in the shared
manifest and every standalone `corpus/<name>/ground-truth.manifest.json`) is
auto-discovered and merged by `loadCorpus()` in `@montr/qa`, together with the
`@montr/fixtures` seed repos (`vulnerable-nextjs`, `clean-nextjs`, which
contribute SQLi, XSS, hard-coded secret, vulnerable dependency, and permissive
CORS). See "Adding a case" below for the exact mechanism — nothing about
`loadCorpus()`/`corpus-scan.mjs`/the scorer changed to add the eight new repos
below; they use the same standalone-manifest mechanism `python-vuln`/`jvm-vuln`
already established.

| Category                   | CWE               | OWASP    | Source(s)                                        | Exploitable | Fix class      |
| --------------------------- | ----------------- | -------- | ------------------------------------------------- | ----------- | --------------- |
| `sql_injection`             | CWE-89            | A03:2021 | fixtures, python-vuln, dvna, pygoat, javaseccode   | yes         | auto-eligible   |
| `xss`                       | CWE-79            | A03:2021 | fixtures, python-vuln, pygoat                      | yes         | auto-eligible   |
| `command_injection`         | CWE-78            | A03:2021 | jvm-vuln, dvna, pygoat (×2), javaseccode           | yes         | auto-eligible   |
| `ssrf`                      | CWE-918           | A10:2021 | corpus, python-vuln, pygoat, javaseccode           | yes         | auto-eligible   |
| `idor`                      | CWE-639           | A01:2021 | corpus, python-vuln                                | yes         | human-required  |
| `broken_access_control`     | CWE-284           | A01:2021 | corpus, jvm-vuln, dvna, pygoat                     | yes         | human-required  |
| `insecure_cookie`           | CWE-614           | A05:2021 | corpus                                             | yes         | auto-eligible   |
| `hardcoded_secret`          | CWE-798           | A07:2021 | fixtures, python-vuln, jvm-vuln, pygoat, javaseccode | yes       | human-required  |
| `vulnerable_dependency`     | CWE-1104/CWE-937  | A06:2021 | fixtures, log4shell-vulnerable-app (CVE-2021-44228)| yes         | auto-eligible   |
| `permissive_cors`           | CWE-942           | A05:2021 | fixtures                                           | no (demote) | auto-eligible   |
| `insecure_deserialization`  | CWE-502           | A08:2021 | jvm-vuln, dvna, pygoat (×2)                        | yes         | auto-eligible   |
| `xxe`                       | CWE-611           | A05:2021 | dvna, pygoat, javaseccode                          | yes         | auto-eligible   |
| `open_redirect`             | CWE-601           | A01:2021 | dvna                                               | yes         | auto-eligible   |
| `path_traversal`            | CWE-22            | A01:2021 | pygoat                                             | yes         | auto-eligible   |
| `weak_crypto`               | CWE-327           | A02:2021 | dvna, requests-clean (×3, demoted)                 | mixed       | auto-eligible   |
| `sensitive_data_exposure`   | CWE-200/CWE-489/CWE-16 | A02:2021 | dvna, pygoat (×2), spring-petclinic          | yes         | mixed           |

`exploitable: false` cases must be **demoted to the appendix** (present, not
confirmed) — confirming one is a false positive. Access-control fixes
(`idor`, `broken_access_control`) are labelled `human-required` per golden
rule #3.

## Running the gate

```bash
# 1. Run the REAL apps/worker pipeline over every corpus repo (real App Map,
#    real semgrep/gitleaks discovery, real correlation + static confirmation;
#    FAKE in-process LLM gateway, so no live LLM credentials needed) and write
#    the aggregated confirmed findings to scan.json:
pnpm corpus:scan                                             # == node scripts/corpus-scan.mjs --out scan.json

# 2. Score that REAL scan against ground truth — THIS is the release gate:
pnpm --filter @montr/qa qa:corpus -- --findings scan.json

# Synthetic self-check (perfectScanner echoes ground truth back at itself —
# precision/FP-rate are tautologically perfect; proves the corpus/scorer/
# baseline/exit-code PLUMBING works, nothing about detection quality). NOT the
# release gate — that always requires --findings from a real scan (above).
pnpm --filter @montr/qa qa:corpus:selfcheck

pnpm --filter @montr/qa qa:variance               # model-variance matrix (fake adapter)
```

`corpus:scan` needs `semgrep` and `gitleaks` on `PATH` to exercise real L1
discovery (CI installs both — see `.github/workflows/ci.yml`'s `golden-corpus`
job); without them the pipeline degrades gracefully to empty discovery + a
warning rather than failing.

Exit codes: `0` OK · `1` REGRESSION · `2` USAGE · `3` CORPUS_ERROR · `4` RUNTIME_ERROR.
CI (`.github/workflows/ci.yml`'s `golden-corpus` job) runs both steps above in
order and blocks a release on any non-zero code from `qa:corpus`.

## A17: corpus growth (2026-08-19)

The original 8-repo / 19-finding corpus (4 synthetic Next.js/Python/JVM
vulnerable+clean pairs) was smoke-test sized: at that N, a single false
positive swings precision/recall by tens of points, so the old `< 5%` FP-rate
claim was illustrative, not defensible, and every repo was hand-authored
synthetic code, not real-world code with real vulnerability patterns and real
authoring "noise" (comments, unrelated helper code, varied style).

**Sampling method.** The goal was to roughly 2x the corpus with *genuinely
real* code — not more synthetic toys — while keeping every new repo small
enough to vendor a snapshot of and every finding individually hand-verifiable
by reading the vendored source. For each of the three scored stacks
(Next.js/JS-TS, Python, JVM), one small, well-known, actively-referenced
**intentionally-vulnerable teaching app** was selected as the positive
(vulnerable) example, plus one **real, popular, actively-maintained clean
library** as the negative (clean) example, chosen for having no security
surface likely to trip the categories being scored (no DB/network/subprocess/
credential code). JVM additionally got two more real positive examples — a
single-CVE minimal reproduction (Log4Shell) and a real production-grade
reference app (Spring PetClinic) — because the pre-A17 JVM corpus had zero
real-world representation at all. Selection criteria, in order:

1. **Real, not synthetic.** Every new vulnerable repo is an unmodified
   (only trimmed) snapshot of an actual published project with its own
   GitHub history, README, and (for the teaching apps) documented lab
   structure — not code written for this repo.
2. **Small enough to vendor a full or trimmed snapshot.** Full app vendored
   where the whole app is small (`log4shell-vulnerable-app`: 2 Java files;
   `gson-clean`/`validatorjs-clean`: complete library source, ~90-115 small
   files each). Trimmed to the security-relevant application code where the
   upstream project is larger (`dvna`, `pygoat`, `javaseccode`,
   `spring-petclinic`: views/docs/tests/static-assets/CI-config dropped,
   controllers/models/settings kept) — trimming never edited a kept file's
   content, only which files were kept.
3. **Pinned to an exact commit**, recorded in that repo's
   `ground-truth.manifest.json` `$provenance` field alongside the upstream
   URL, license, and exactly what was trimmed and why — so any finding below
   can be independently re-verified against the same bytes.
4. **Every finding hand-verified by reading the vendored source**, not
   inferred from the upstream project's own lab/vulnerability-class naming.
   Two cases where this mattered: PyGoat's `ssrf_lab` function is actually a
   local-file-read (path traversal), not SSRF — the real `ssrf_lab2` function
   was used for the SSRF finding instead, and `ssrf_lab` was labelled
   `path_traversal` to match its actual behaviour. Conversely, an initial real
   pipeline scan surfaced two apparent false positives in already-vendored
   PyGoat files (`introduction/mitre.py:233` command injection,
   `introduction/views.py:560` PyYAML unsafe-load deserialization) — re-reading
   both confirmed they are genuine, independently-exploitable vulnerabilities
   this pass had simply not catalogued on the first read, so they were added
   as true findings rather than left mislabelled as false positives.
5. **Clean repos were swept, not assumed clean.** Each clean candidate was
   grepped for hardcoded-credential, weak-hash, `eval`/`exec`/subprocess, and
   SQL-string-building patterns before inclusion (see each repo's
   `ground-truth.manifest.json` `$provenance` for the exact sweep). Two
   near-misses this caught: `spring-petclinic`'s default
   `application.properties` genuinely sets
   `management.endpoints.web.exposure.include=*` (confirmed real — the file's
   own comment says "Don't do this in production"), so it is labelled
   **`vulnerable`** with that one real finding rather than force-fit as
   clean. `requests`' `auth.py` genuinely calls `hashlib.md5()`/`hashlib.sha1()`
   inside its HTTP Digest Authentication implementation — mandated by the
   Digest Auth RFC and explicitly marked `usedforsecurity=False` by its
   maintainers, so it is listed in `requests-clean`'s manifest as three
   **`exploitable: false`** (demoted) markers rather than silently dropped: a
   naive scanner may still flag the pattern, and if it does, the scorer
   correctly counts that as a false positive.

**Provenance (source URL, pinned commit, license) for every new repo:**

| Repo                        | Source                                                          | Commit (pinned)                            | License          |
| ---------------------------- | ---------------------------------------------------------------- | ------------------------------------------- | ----------------- |
| `dvna`                       | https://github.com/appsecco/dvna                                 | `9ba473add536f66ac9007966acb2a775dd31277`   | MIT               |
| `pygoat`                     | https://github.com/adeyosemanputra/pygoat                        | `19d17cc8874861142b330636d068bbde54e86b85`  | MIT               |
| `javaseccode`                | https://github.com/JoyChou93/java-sec-code                       | `4711f4e186258c6e0dd5c3863e7c9592e7e9026a`  | none upstream (small excerpt, internal QA use only, same basis as other vendored teaching apps) |
| `log4shell-vulnerable-app`   | https://github.com/christophetd/log4shell-vulnerable-app         | `c962aabb31a6af0a77f0e9bbc7100e175c7c04e`   | MIT               |
| `spring-petclinic`           | https://github.com/spring-projects/spring-petclinic              | `88e37c15cf6fc8490b01bc3e8e2c800cec1ac272`  | Apache-2.0        |
| `validatorjs-clean`          | https://github.com/validatorjs/validator.js                      | `a79ff980ab14257e795332989e497bdff3218e87`  | MIT               |
| `requests-clean`             | https://github.com/psf/requests                                  | `8f8b212de8c2129d7954c6cd373762880375620a`  | Apache-2.0        |
| `gson-clean`                 | https://github.com/google/gson                                   | `dae37cf0fe12235b76fb09f01118a0a8c8823f42`  | Apache-2.0        |

**Real, measured numbers (not aspirational) as of this growth — see
`corpus/baseline.json`'s `$measurement` for the full detail:** running the
REAL `apps/worker` pipeline (real semgrep + gitleaks discovery, fake LLM
gateway) over the full 16-repo / 44-finding corpus measured **precision
100.0%, recall 25.0% (11/44), FP-rate 0.0%, 16/16 repos scored**. `baseline.json`
was recalibrated to sit a small safety margin below/above (as appropriate)
that real measurement — it is **not** a target the pipeline should aspire to
hit later; it is what the pipeline can honestly clear today, so the gate
means something and will catch a real regression from here. `idor` and
`broken_access_control` are honestly at 0% real recall (the confirmation
pipeline doesn't yet reason about ownership/role checks for any stack) and
that is reflected as `recallMin: 0` for those two categories rather than
hidden.

## Adding a case

1. Add the repo either under `corpus/repos/<name>/` + an entry in the shared
   `corpus/ground-truth.manifest.json` (validated against
   `GroundTruthManifestSchema` from `@montr/fixtures`), OR as its own
   `corpus/<name>/ground-truth.manifest.json` next to the repo's source
   (the mechanism `python-vuln`, `jvm-vuln`, and all eight A17 repos above
   use — `loadCorpus()` auto-discovers every `corpus/*/ground-truth.manifest.json`,
   so this needs no edit to the shared manifest or `@montr/qa`).
2. `loadCorpus()` auto-discovers `corpus/repos/*` and warns on any repo that is
   present on disk but not declared (and errors on a declared repo that is
   missing).
3. If vendoring real-world code (recommended over hand-writing more synthetic
   samples — see "A17: corpus growth" above for the method), pin an exact
   commit/version, record full provenance (source URL, commit, license, what
   was trimmed and why) in that repo's manifest `$provenance` field, and
   hand-verify every finding by reading the vendored bytes, not by trusting
   the upstream project's own lab names or assuming a "clean" pick is
   actually clean.

> These repos contain **intentionally vulnerable code** (or, for `dvna` /
> `pygoat` / `javaseccode` / `log4shell-vulnerable-app` / `spring-petclinic`,
> real vulnerable/imperfect production code vendored as-is). Like
> `packages/fixtures/sample-repos/**`, all of `corpus/**` is excluded from
> lint/format/typecheck (`eslint.config.js`, `.prettierignore`).
