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

## Public API

- `runDiscovery(input) → Layer1Output` — pure entry point (orchestrator persists the output).
- `runDiscoveryDetailed(input)` — output + degradation warnings + source counts.
- `runDiscoveryToStore(input, { store, audit })` — runs, persists via `@montr/state-store`, and **audit-logs the write** (metadata-only; golden rule #7).
- Detectors, parsers, the advisory matcher, semver helpers, and file providers are all exported for reuse/testing.

External scanners and the filesystem are expressed as **injectable interfaces**, so every path is fully offline and mockable (see `tests/discovery.*.test.ts`).

## Status

Implemented (Wave 2, WS-F). Build + lint clean; `tests/discovery.detectors.test.ts` + `tests/discovery.pipeline.test.ts` green offline.
