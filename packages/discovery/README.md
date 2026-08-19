# @montr/discovery

Layer 1 — parallel SAST + secrets/config + SCA discovery agents.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Internal dependencies

- `@montr/contracts`
- `@montr/config`
- `@montr/llm-gateway`
- `@montr/state-store`
- `@montr/telemetry`

## Design

Deterministic tools **detect**; the LLM only **triages/explains** (golden rule #6), and never before the App Map exists. Layer 1 is deliberately **over-inclusive** and is **never surfaced to the user** — it is the candidate pile Layer 2 correlates, ranks, and demotes (never deletes).

Three sub-detectors fan out concurrently, each emitting `CandidateFinding[]` tagged with `source / ruleId / category (CWE) / file / line / rawSeverity / evidenceSnippet`:

- **SAST** (`detectSast`) — Semgrep subprocess (`--json`, curated rulesets: `p/owasp-top-ten`, `p/typescript`, `p/nextjs`, `p/react`, `p/secrets`). The runner is injectable; a missing binary degrades to empty + a warning.
- **Secrets & Config** (`detectSecretsAndConfig`) — gitleaks subprocess **plus** offline custom detectors: hardcoded keys, client-exposed env, weak crypto, permissive CORS, missing security headers, insecure cookies. ⛔ Secret **values are redacted** before they reach a candidate row, the audit log, or a log line.
- **Dependency / SCA** (`detectDependencies`) — offline OSV/GHSA advisory mirror matched against the lockfile (pnpm/npm) or `package.json`, **plus an import-graph reachability check** so present-but-unimported vulns are tagged `reachable: false` for Layer 2 to demote.

## The offline advisory mirror

`src/advisories.ts` matches installed packages against `ADVISORY_DB` — a real (not fabricated) snapshot of [OSV.dev](https://osv.dev) data, which already merges in GHSA advisories, so OSV alone covers both. Nothing here ever calls the network at scan time: `ADVISORY_DB` is built once at import from static JSON checked into the repo.

### Layout

```
src/advisories-data/
  npm.json     883 records, 172 packages  (ecosystem: "npm")
  pypi.json   1471 records,  97 packages  (ecosystem: "PyPI")
  maven.json  1261 records,  81 packages  (ecosystem: "Maven", package = "groupId:artifactId")
```

Each record is an `Advisory` (see `src/advisories.ts` for the exact type):

```jsonc
{
  "id": "GHSA-jf85-cpcp-j695", // primary id (GHSA-… or CVE-…)
  "aliases": ["CVE-2019-10744"],
  "package": "lodash", // npm name / PyPI project / Maven "group:artifact"
  "ecosystem": "npm", // "npm" | "PyPI" | "Maven"
  "vulnerableRange": "<4.17.12", // comparator groups, `||`-joined (src/semver.ts's `satisfies`)
  "fixedVersion": "4.17.12", // first fixed version, if known
  "cwe": ["CWE-1321"],
  "severity": "critical", // info|low|medium|high|critical
  "summary": "Prototype pollution in lodash (defaultsDeep).",
  "source": "ghsa", // "osv" | "ghsa" — drives the CandidateFinding.source tag
}
```

`matchAdvisories(pkg, version, db = ADVISORY_DB, ecosystem = "npm")` filters `db` to advisories whose `package`/`ecosystem` match and whose `vulnerableRange` the installed `version` satisfies. The Phase-1 SCA detector (`detectDependencies`) only resolves npm packages today (from `pnpm-lock.yaml` / `package-lock.json` / `package.json`), so it calls `matchAdvisories` with the `ecosystem` default — the PyPI/Maven rows ship ready for the Python/JVM lockfile resolvers declared in `rulesets/{python,java}` (build-plan §7 Wave 4) to consume through the same seam once they exist.

### How it was built

Filtering the full OSV bulk export down to a curated, still-genuinely-useful subset: `scripts/refresh-advisories.mjs` downloads `https://osv-vulnerabilities.storage.googleapis.com/<npm|PyPI|Maven>/all.zip` (200k+ raw advisory files across the three ecosystems), keeps only records affecting a curated allow-list of popular / historically-significant packages (`scripts/popular-packages.json` — ~200 npm, ~150 PyPI, ~120 Maven entries spanning the Next.js/Python/JVM stacks this repo targets), transforms each into the `Advisory` shape above, collapses GHSA advisories that were re-issued under a new id for the same CVE (keeping the most-recently-published range assessment), and writes the three JSON files this package ships.

### Refreshing the mirror

```
node packages/discovery/scripts/refresh-advisories.mjs
```

Requires network access to `*.storage.googleapis.com` and the `unzip` binary on PATH (present on macOS/Linux CI images). Pass `--zip-dir <dir>` to reuse already-downloaded `npm.zip` / `PyPI.zip` / `Maven.zip` files instead of re-downloading (useful for iterating on the filter/transform logic offline). Widen or narrow coverage by editing `scripts/popular-packages.json` and re-running. Regenerating produces a plain diff to `src/advisories-data/*.json` — review it like any other data change before committing.

### Known coverage & limitations

- **Curated subset, not full OSV coverage.** ~3,600 records across ~350 packages — real, current data (fetched live from OSV.dev), but bounded to the allow-listed packages, not every package OSV knows about. A package outside the allow-list will never match, even if it has real advisories. Widen `popular-packages.json` to cover more.
- **Severity** prefers OSV/GHSA's own `database_specific.severity` bucket; where a record only carries a CVSS vector, `refresh-advisories.mjs` computes the real CVSS v3.1 base-score formula (v3/v3.1 vectors) or a coarser high/critical heuristic (v4 vectors) and buckets that instead. A record with neither defaults to `"medium"`.
- **Version ranges** are re-expressed as this package's simplified comparator grammar (`src/semver.ts`'s `satisfies` — AND within a group, `||` across groups; no full node-semver). This is a conservative approximation of OSV's range events, not a byte-for-byte reproduction.
- **PyPI/Maven data ships but is not yet consumed** — see "How it was built" above; wiring in the Python/JVM lockfile resolvers is separate follow-up work outside this detector.
- Because this is real, live data, re-running the refresh script WILL change results as new CVEs are published — including on fixtures. `tests/discovery.detectors.test.ts` and `tests/discovery.pipeline.test.ts` are written to tolerate that (they assert known headline CVEs are present/absent at the right version boundary, not exact match counts).

## Public API

- `runDiscovery(input) → Layer1Output` — pure entry point (orchestrator persists the output).
- `runDiscoveryDetailed(input)` — output + degradation warnings + source counts.
- `runDiscoveryToStore(input, { store, audit })` — runs, persists via `@montr/state-store`, and **audit-logs the write** (metadata-only; golden rule #7).
- Detectors, parsers, the advisory matcher, semver helpers, and file providers are all exported for reuse/testing.

External scanners and the filesystem are expressed as **injectable interfaces**, so every path is fully offline and mockable (see `tests/discovery.*.test.ts`).

## Status

Implemented (Wave 2, WS-F). Build + lint clean; `tests/discovery.detectors.test.ts` + `tests/discovery.pipeline.test.ts` green offline.
