# @montr/correlation

Layer 2 — **the moat**. Turns the deliberately over-inclusive `CandidateFinding[]`
pile from Layer 1 into a ranked `ProbableFinding[]`, grounded in the App Map.

## What it does (build-plan §5.3, PRD §7)

`correlate({ clientId, scanId, appMap, candidates, gateway? })` → `Layer2Output`:

- **Cross-references** every candidate against the App Map: is it on a route/entry
  point that actually exists and is registered? public or behind which auth state?
  does tainted input actually reach the sink, or does a validator/sanitizer
  interrupt the path?
- **Deduplicates** the same root cause reported by multiple tools into one issue
  (`mergedCandidateIds[]`) — injection findings key on the mapped sink location so
  two tools flagging different lines of one flow still merge.
- **Ranks** by reachability × exposure × impact (`reachabilityScore`,
  `exposureScore`, `impactScore`, `rank`) — never raw CVSS.
- **Demotes** uncorroborated candidates to `demoted[]` (the appendix) — never
  deletes them.
- Emits each `ProbableFinding` with a **reachability hypothesis + exploit
  hypothesis**.

### Deterministic-first (golden rules #6, #4, #1)

The App Map grounding is authoritative for existence, exposure, and demotion. The
LLM (via `@montr/llm-gateway`) is used only for the semantic reachability/exposure
narrative and a **bounded** ranking nudge, grounded in App Map structure — it can
never un-demote a finding or change its exposure. No LLM call fires before the App
Map exists; prompts carry structured metadata only (never code bodies); a bad or
absent gateway falls back to the deterministic result. Every promotion, demotion,
and LLM call is audit-logged with metadata only when an audit client is injected.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Internal dependencies

- `@montr/contracts`
- `@montr/state-store`
- `@montr/telemetry`

## Status

Wave 2 — implemented (WS-G). Deterministic App Map grounding, dedup, ranking, and
demotion with optional LLM-refined hypotheses. Build + lint clean; offline tests
in `tests/correlation.*.test.ts` (fixtures + fake LLM adapter). Wired into the real
pipeline at integration.
