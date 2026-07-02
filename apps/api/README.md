# @montr/api

Fastify HTTP API + RBAC + OpenAPI (Wave 1: WS-L / WS-D).

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Internal dependencies

- `@montr/contracts`
- `@montr/config`
- `@montr/state-store`
- `@montr/orchestrator`
- `@montr/telemetry`

## Status

Wave 0 stub — exported function/class signatures match the frozen contracts so downstream agents have exact build targets. Implementation lands in the wave noted above.
