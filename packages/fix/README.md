# @montr/fix

Layer 4 — patch + proof-of-fix test + safety risk classifier.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Internal dependencies

- `@montr/contracts`
- `@montr/llm-gateway`
- `@montr/state-store`
- `@montr/telemetry`

## What it does

`generateFixes(input)` turns `ConfirmedFinding[]` into the `Layer4Output` contract (`Fix[]`). Per confirmed finding it:

1. Asks the LLM (via `@montr/llm-gateway`, purpose `fix_generation` — the only egress path) to _propose_ a fix.
2. Falls back to a deterministic, mechanical transform; **prefers whichever proposal VALIDATES** — the unified-diff patch applies cleanly (`diff`), and the proof-of-fix predicate _fails pre-patch and passes post-patch_.
3. **Risk-classifies deterministically** (`classifyConfirmedFindingRisk`) — never from the LLM. ⛔ auth/session/crypto/access-control, wide blast radius, or _any_ uncertainty ⇒ `human-required`. Only mechanical, low-blast-radius, cleanly-validated fixes are `auto-eligible`.
4. Audit-logs a `fix.generated` event (metadata only — never code bodies).

If no validated mechanical fix is possible it emits an **advisory** fix that is always `human-required` (fail-safe).

### Public API

- `generateFixes` / `GenerateFixesInput` / `FixGenerationContext`
- `classifyFixRisk` (the base rule) + `classifyConfirmedFindingRisk` / `deriveRiskSignals` / `ALWAYS_HUMAN_REQUIRED_CATEGORIES` / `AUTO_ELIGIBLE_CATEGORIES`
- `FIX_STRATEGIES` / `pickStrategy` — deterministic transforms (SQLi, XSS, permissive CORS, hard-coded secret)
- `buildUnifiedDiff` / `validatePatch` / `countChangedLines`
- `createFsSourceReader` / `createMapSourceReader` (`SourceReader` — inject file access; keeps the layer offline-testable)

## Status

Implemented (Wave 2, WS-I). Builds clean, lint clean, tested against fixtures (`tests/fix.*.test.ts`) fully offline via the fake LLM adapter. The orchestrator injects the real gateway + sandbox `SourceReader` at integration.
