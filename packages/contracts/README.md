# @montr/contracts

Zod schemas, inferred types, enums, layer I/O contracts, queue jobs, LLM gateway interface, cost/audit/error/compliance types. The interface spine — everything imports from here.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the package-ownership map and the 10 golden rules).

## Contracts

Every exported shape MUST come from `@montr/contracts`. Do not invent finding/layer shapes locally.

## Status

Wave 0 stub — exported function/class signatures match the frozen contracts so downstream agents have exact build targets. Implementation lands in the wave noted above.
