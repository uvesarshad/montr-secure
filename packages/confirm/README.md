# @montr/confirm

Layer 3 — turns **probable → confirmed**. Static data-flow proof ships by default;
live DAST is premium and heavily gated (build-plan §5.4, PRD §7 L3).

## Public API

```ts
import { confirmFindings, type ConfirmInput, type ConfirmDeps } from "@montr/confirm";

const out: Layer3Output = await confirmFindings(input, deps);
// out = { confirmed: ConfirmedFinding[], unconfirmed: UnconfirmedFinding[] }
```

`confirmFindings` consumes the correlation output (`ProbableFinding[]`) + the App Map
and emits the frozen `Layer3Output` from `@montr/contracts`. With no `deps` it runs
**fully offline** as pure static confirmation (no target touched).

## 3a — Static confirmation (default, any repo)

Deterministic engine (the "tools detect" half of golden rule #6):

- Builds a `source → transforms → sink` data flow, tracking **auth state at each hop**.
- Confirms only when a tainted source provably reaches an **unsanitized** sink of the
  matching kind; a validator/parameterizer on the path leaves the finding unconfirmed.
- Emits `ConfirmedFinding{ proofType: "static", proofArtifact: StaticProof }` — a
  proof-of-reachability argument. **No requests are fired.**
- An optional confirmation-tier LLM (`deps.llm`) only **enriches** the argument or
  **vetoes** (demotes) — it can never promote a finding (fail-safe, golden rule #4).

## 3b — Live DAST (premium, OFF by default, ⛔ heavily gated)

A recon+exploit agent that fires crafted, non-destructive probes at an
approver-authorized, allowlisted **staging** target and captures the full
request/response **transcript** as proof (`proofType: "live"`). Every guardrail is
re-enforced here at the HTTP layer (defense in depth), via `ScopeGuard`:

- ⛔ **target allowlist** (strict host match — no suffix/substring bypass) + scope contract;
- ⛔ **production blocked** by policy;
- ⛔ **approver authorization** required before any run (`assertLiveAuthorized`);
- ⛔ **kill switch** halts probing instantly (`AbortSignal`);
- ⛔ **rate limit + blast-radius caps** (per-scan + mutating-request caps);
- ⛔ all outbound routed through **`@montr/security`'s egress guard** (`{ includeDastTargets: true }`).

Authenticated flows use a `BrowserDriver` (playwright-core by default, injected in
tests). A failed/blocked live attempt never discards the static proof; probables that
neither mode confirms are kept in the **Unconfirmed appendix** (never deleted).

## Internal dependencies

`@montr/contracts`, `@montr/config`, `@montr/security` (egress guard), `@montr/llm-gateway`,
`@montr/state-store`, `@montr/telemetry`. Runtime: `undici` (HTTP), `playwright-core` (auth flows).

> Note: `@montr/security` was added to this package's `dependencies` during Layer-3
> implementation — a `pnpm install` is needed to sync the workspace lockfile.

## Tests

`tests/confirm.static.test.ts`, `tests/confirm.guards.test.ts`, `tests/confirm.live.test.ts`
— all offline (HTTP + browser mocked; the real egress guard + kill switch are exercised).
