# @montr/state-store

Prisma client wrapper, typed repositories, field-level encryption, per-client isolation, resumable pipeline state, and the tamper-evident audit log.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Internal dependencies

- `@montr/contracts`
- `@montr/telemetry`

## Status

Wave 0 stub — exported function/class signatures match the frozen contracts so downstream agents have exact build targets. Implementation lands in the wave noted above.
