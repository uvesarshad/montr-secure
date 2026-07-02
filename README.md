# Montr Secure

AI security orchestration platform — on-prem, bring-your-own LLM key, report-first
with gated auto-fix. It consolidates SAST + SCA + secrets + DAST + red-team probing
into one pipeline, **correlates** findings against a structural model of the app,
**confirms** which issues are actually exploitable, and delivers a short,
prioritized, exploit-validated report with merge-ready fixes.

> See `docs/plan/montr-secure-prd.md` (product) and
> `docs/plan/montr-secure-build-plan.md` (build order). Read `CONTRIBUTING.md`
> first — the 10 golden safety rules are non-negotiable.

## Status

**Wave 0 (foundation) complete.** Interfaces are frozen: `@montr/contracts`,
`@montr/config`, the Prisma schema, queue/event contracts, the LLM gateway
interface, `@montr/fixtures`, CI, and the deploy skeleton. Pipeline packages are
typed stubs whose signatures match the contracts. Waves 1–5 fan out from here.

## Monorepo layout

```
packages/
  contracts/    Zod schemas, types, layer I/O, queue jobs, gateway interface, errors  (the spine)
  config/       config schema + loader (hardened, safety-first defaults)
  telemetry/    logging + OTel wrappers + audit-log client interface
  llm-gateway/  provider-agnostic LLM gateway  (the ONLY place a provider SDK may live)
  cost-meter/   estimate / meter / budget hard-halt
  state-store/  Prisma client, repos, encryption, resumable state, audit log
  orchestrator/ FSM, BullMQ workers, gate state, kill switch
  appmap/       Layer 0 — intake + App Map + cost estimate
  discovery/    Layer 1 — SAST + secrets + SCA
  correlation/  Layer 2 — the moat
  confirm/      Layer 3 — static proof + gated live DAST
  fix/          Layer 4 — patch + test + risk classifier
  report/       Layer 5 — report model + exports + gated PR flow
  fixtures/     shared deterministic fixtures + fake LLM adapter + sample repos
apps/
  api/          Fastify HTTP API + RBAC + OpenAPI
  worker/       BullMQ worker host
  web/          Next.js operator console + report UI
deploy/         Dockerfiles, docker-compose, Helm chart, air-gap tooling
corpus/         golden test corpus (vuln + clean repos, ground truth)
```

## Quickstart

```bash
nvm use            # Node 20 (.nvmrc)
pnpm install
pnpm typecheck && pnpm build
pnpm test
```

## Locked tech choices

pnpm + Turborepo · TypeScript strict · Zod (single source of truth) · Fastify ·
BullMQ + Redis · Prisma + PostgreSQL 16 · custom LLM gateway (BYO-key) ·
Next.js 14 · Vitest · distroless containers · GitHub Actions.

## Safety posture (defaults)

Auto-fix **OFF** · DAST **OFF** · budget **hard-halt** · telemetry **OFF** ·
egress **default-deny** (only the client LLM endpoint). See `CONTRIBUTING.md`.
