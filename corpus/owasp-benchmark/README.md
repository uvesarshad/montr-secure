# corpus/owasp-benchmark — external OWASP Benchmark subset (E14, closes A29)

A small, vendored **excerpt** of the real
[OWASP Benchmark for Java](https://owasp.org/www-project-benchmark/)
(`OWASP-Benchmark/BenchmarkJava` on GitHub) — an independently-curated,
publicly available, labelled vulnerability-detection benchmark this product's
own team did not author. Scored **separately** from `corpus/`'s internal
golden corpus (see "Why this is not part of `corpus/ground-truth.manifest.json`"
below) by `@montr/qa`'s `owasp-benchmark.ts` / `owasp-benchmark-cli.ts`
(`pnpm --filter @montr/qa qa:owasp-benchmark`).

## License correction

E14's task brief assumed OWASP Benchmark is Apache-2.0. **It is not** —
`BenchmarkJava`'s `LICENSE` file is the **GNU General Public License v2**, not
Apache-2.0. GPL-2.0 still permits redistributing verbatim, unmodified source
(which is exactly what this excerpt does — every vendored `.java` file below
is byte-for-byte unmodified from upstream), and this repo already vendors
teaching-app excerpts under other permissive-but-different licenses
(`corpus/README.md`'s `dvna` is MIT, `javaseccode` ships no upstream LICENSE
at all). Documented here rather than silently repeating the incorrect
Apache-2.0 assumption.

## What is vendored (excerpt, NOT the whole project)

`OWASP-Benchmark/BenchmarkJava` ships **2,740** individually-labelled test
case servlets across 11 vulnerability categories plus a large Maven build
(helpers, a runner harness, VM configs, scorecards). Vendoring the whole
project would be disproportionate for a representative sample and would slow
this harness's real-pipeline run far past what is practical to run and
re-verify by hand. This excerpt vendors **24 test-case source files** (4 per
category: 3 real-vulnerability + 1 real-negative "false positive trap" case,
for 6 of the 11 categories) plus a trimmed **24-row** slice of OWASP
Benchmark's own real `expectedresults-1.2.csv` ground-truth file — every row
copied verbatim, never hand-relabelled.

- **Source**: https://github.com/OWASP-Benchmark/BenchmarkJava
- **Commit (pinned)**: `ba2e3f9a29fa3bde6a5c073d679393c9b94f025f` (2026-08-20)
- **License**: GPL-2.0 (see "License correction" above)
- **Vendored scope**: **excerpt**, 24 of 2,740 test-case `.java` files (0.9%)
  under `src/main/java/org/owasp/benchmark/testcode/`, plus
  `expectedresults-subset.csv` (24 of 2,740 rows of the real
  `expectedresults-1.2.csv`). No helper classes, build config, runner
  scripts, or scorecard tooling were vendored — this harness drives the
  vendored source directly through this product's own real Layer 0-3
  pipeline, it does not run OWASP Benchmark's own Maven/Tomcat harness.
  `pom.xml` was deliberately NOT vendored: this product's JVM App-Map
  analyzer detects a Java repo purely from `**/*.java` presence
  (`packages/appmap/src/languages/java/index.ts`'s `detect()`), and OWASP
  Benchmark's real `pom.xml` is 1,274 lines of dependency management
  irrelevant to a 24-file excerpt — including it would only add SCA-detector
  noise unrelated to the categories being benchmarked.

## Category selection and why

OWASP Benchmark ships 11 categories: `cmdi`, `crypto`, `hash`, `ldapi`,
`pathtraver`, `securecookie`, `sqli`, `trustbound`, `weakrand`, `xpathi`,
`xss`. This product's `Category` taxonomy
(`packages/contracts/src/compliance.ts`) has a real, unambiguous detector
target for six of them — `sqli`→`sql_injection`, `cmdi`→`command_injection`,
`pathtraver`→`path_traversal`, `xss`→`xss`, `securecookie`→`insecure_cookie`,
`crypto`/`hash`/`weakrand`→`weak_crypto` (see
`packages/qa/src/owasp-benchmark.ts`'s `OWASP_CATEGORY_TO_MONTR_CATEGORY`).
`ldapi`, `xpathi`, and `trustbound` have **no** detector anywhere in this
pipeline for **any** supported language — scoring them would either fabricate
a false negative for every case (a different claim than "never tested") or
require inventing an unjustified mapping. This excerpt only samples the six
mapped categories; the CLI reports any unmapped case it is handed as
explicitly **excluded**, never silently dropped.

## Selection method

For each of the 6 mapped categories: the first 3 `realVulnerability=true`
rows and the first 1 `realVulnerability=false` row, in `expectedresults-1.2.csv`
file order (deterministic, not cherry-picked for a favorable result — see
`packages/qa/src/owasp-benchmark.ts`'s test suite, which reproduces the exact
same selection from the real upstream CSV). The `false` rows are OWASP
Benchmark's intentional "false-positive traps" — code that LOOKS structurally
identical to a real vulnerability but is not exploitable (verified for
`BenchmarkTest00052`: it string-concatenates a value into a SQL "CallableStatement"
exactly like the real-vulnerable `BenchmarkTest00008`, but the value is
retrieved through a different accessor OWASP Benchmark's own ground truth
says does not carry attacker-controlled taint the same way) — these are what
actually let this harness measure a false-positive rate, not just recall.

| Test | Category | CWE | Real vuln? |
| --- | --- | --- | --- |
| BenchmarkTest00008 | sqli | 89 | true |
| BenchmarkTest00018 | sqli | 89 | true |
| BenchmarkTest00024 | sqli | 89 | true |
| BenchmarkTest00052 | sqli | 89 | **false** (FP trap) |
| BenchmarkTest00006 | cmdi | 78 | true |
| BenchmarkTest00007 | cmdi | 78 | true |
| BenchmarkTest00015 | cmdi | 78 | true |
| BenchmarkTest00051 | cmdi | 78 | **false** (FP trap) |
| BenchmarkTest00001 | pathtraver | 22 | true |
| BenchmarkTest00002 | pathtraver | 22 | true |
| BenchmarkTest00011 | pathtraver | 22 | true |
| BenchmarkTest00063 | pathtraver | 22 | **false** (FP trap) |
| BenchmarkTest00013 | xss | 79 | true |
| BenchmarkTest00014 | xss | 79 | true |
| BenchmarkTest00030 | xss | 79 | true |
| BenchmarkTest00147 | xss | 79 | **false** (FP trap) |
| BenchmarkTest00087 | securecookie | 614 | true |
| BenchmarkTest00169 | securecookie | 614 | true |
| BenchmarkTest00170 | securecookie | 614 | true |
| BenchmarkTest00016 | securecookie | 614 | **false** (FP trap) |
| BenchmarkTest00005 | crypto | 327 | true |
| BenchmarkTest00019 | crypto | 327 | true |
| BenchmarkTest00020 | crypto | 327 | true |
| BenchmarkTest00054 | crypto | 327 | **false** (FP trap) |

## A known, real detection gap: `@WebServlet`, not Spring/JAX-RS

OWASP Benchmark's test cases are plain `javax.servlet.http.HttpServlet`
subclasses annotated `@WebServlet` — **not** Spring MVC (`@RestController`/
`@RequestMapping`) or JAX-RS (`@Path`), which are the only route-annotation
families `packages/appmap/src/languages/java/extract.ts` recognizes today.
This means the App Map's Layer 0 **route/entrypoint detection does not fire**
on this subset (`AppMap.routes` is empty for every vendored file); `Route`
detection is out of scope for this change (`packages/appmap/src/**` is
explicitly off-limits — see the task that produced this harness). Taint
SOURCES (`HttpServletRequest.getHeader`/`getParameter`) and SINKS (JDBC
`prepareCall`, `ProcessBuilder`, etc.) are still extracted file-wide
regardless of route linkage, so Layer 0/3 are not entirely blind to this
subset — but this is a genuine, honestly-reported coverage gap, not a
polished demo: a future widening of the JVM route extractor to recognize
`@WebServlet` (mirroring how `packages/appmap/src/languages/typescript/express.ts`
was added for plain Express) would likely change these numbers. Recorded here
so a reader of the benchmark report is not misled into thinking a low score
on this subset reflects the ceiling of this product's real-world JVM Spring
coverage — see `corpus/jvm-vuln`/`corpus/javaseccode`/`corpus/spring-petclinic`
(all real Spring apps) for that.

## Why this is not part of `corpus/ground-truth.manifest.json`

`corpus/README.md`'s `loadCorpus()` auto-discovers every
`corpus/*/ground-truth.manifest.json`. This directory's ground truth is
deliberately named `expectedresults-subset.csv` instead — OWASP Benchmark's
own real format, parsed as-is — so it is **never** auto-merged into the
internal `qa:corpus` gate or `corpus/baseline.json`'s thresholds. A18/A29's
whole point is that a scanner tuned against its own golden corpus will always
look good on that corpus; keeping this external dataset's scoring completely
separate (its own CLI, its own report, its own — currently unset — pass/fail
posture) is what keeps it a real, independent check rather than another
line item quietly folded into the number this product's own team already
controls.

## Running the harness

```bash
# 1. Run the REAL apps/worker pipeline (real App Map, real Semgrep when on
#    PATH — SAST is a REQUIRED detector, A4 — real correlation + static
#    confirmation; FAKE in-process LLM gateway) over the vendored subset:
node scripts/benchmark-owasp.mjs --out owasp-benchmark-scan.json

# 2. (Competitor) Run raw Semgrep directly against the same subset, same
#    primary OWASP ruleset this product's own SAST detector uses:
node scripts/benchmark-semgrep.mjs --out owasp-benchmark-semgrep.json

# 3. (Competitor, scaffold-only in this sandbox) CodeQL — requires the
#    CodeQL CLI, not installed here. Prints exact commands and exits
#    non-fabricating when unavailable:
node scripts/benchmark-codeql.mjs

# 4. Score both against OWASP Benchmark's OWN ground truth + methodology
#    (TP/FP/TN/FN -> TPR/FPR -> "Benchmark score" = TPR - FPR):
pnpm --filter @montr/qa qa:owasp-benchmark -- \
  --our-findings owasp-benchmark-scan.json \
  --semgrep-json owasp-benchmark-semgrep.json
```

See `docs/infra/testing.md` for the real numbers measured from an actual run
of this harness, and honest caveats about the subset's size.
