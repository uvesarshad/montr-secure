# @montr/worker

BullMQ worker host that runs the orchestrator + the six layer agents (build-plan §8.1).

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## What it delivers

- **`startWorker(config, deps)`** — the durable worker. Asserts the ⛔ default-deny
  egress policy at boot (golden rule #1), then brings up the BullMQ scheduler
  (one queue + worker per layer over ioredis) and an orchestrator that consumes
  per-layer jobs, runs the real layer runners, streams progress/lifecycle events,
  and honors the kill-switch + resume-token + retry contracts. Redis is only
  touched by `start()`, so the boot guard runs even where Redis is absent.
- **The six `LayerRunner` adapters** (`createLayerRunners`) — each converts the
  orchestrator's `LayerContext<L>` into the layer's native input (from
  `ctx.priorOutputs`, falling back to the state store on a resumed/distributed
  run) and calls the **pure** layer function:
  - L0 → `@montr/appmap` `createLayer0Runner` (App Map + scope + cost estimate)
  - L1 → `@montr/discovery` `runDiscovery` (candidate pile; App Map + scope)
  - L2 → `@montr/correlation` `correlate` (App Map + candidates → probable)
  - L3 → `@montr/confirm` `confirmFindings` (App Map + probable → confirmed + unconfirmed)
  - L4 → `@montr/fix` `generateFixes` (confirmed → fixes)
  - L5 → `@montr/report` `buildReport` (confirmed + unconfirmed + fixes → report + PRs)
- **In-process driver** (`runScanInProcess` / `createInProcessOrchestrator`) —
  drives the FSM through L0→L5 over the orchestrator's inline scheduler with **no
  Redis/BullMQ**, for CI / the E2E golden-corpus scan.

## ⛔ Persistence division (honored)

`orchestrator/persist.ts` owns **every** store write. The runners call the PURE
layer functions (`runDiscovery`, not `runDiscoveryToStore`; `createLayer0Runner`
defaults `persist:false`) so nothing double-writes. The Layer-2 _demoted_ appendix
is not persisted, so the report runner reads it from the in-process
`Layer2Output.demoted` cache (a superset — the L1 candidate pile — is used on a
resumed run). The `audit` sink passed to the layers records append-only metadata
events, which is a different concern from entity persistence.

## Internal dependencies

`@montr/orchestrator`, `@montr/appmap`, `@montr/discovery`, `@montr/correlation`,
`@montr/confirm`, `@montr/fix`, `@montr/report`, `@montr/cost-meter`,
`@montr/state-store`, `@montr/security`, `@montr/telemetry`, `@montr/config`,
`@montr/contracts` (+ `@montr/fixtures` for tests). BullMQ/ioredis are owned by
`@montr/orchestrator` (lazily imported), so this app declares no infra deps.

## Testing

Offline, deterministic, against `@montr/fixtures` (fake LLM adapter + in-memory
store). Run `pnpm --filter @montr/worker build` and the worker test suite
(`apps/worker/src/*.test.ts`).
