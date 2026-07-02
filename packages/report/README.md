# @montr/report

Layer 5 — report model, exports (SARIF/PDF/JSON), gated auto-fix PR flow.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Internal dependencies

- `@montr/contracts`
- `@montr/state-store`
- `@montr/telemetry`

## Status

Wave 0 stub — exported function/class signatures match the frozen contracts so downstream agents have exact build targets. Implementation lands in the wave noted above.
