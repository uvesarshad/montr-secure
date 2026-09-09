# Montr Secure

**AI Security Orchestration Platform — on-prem, bring-your-own-LLM-key, report-first with gated auto-fix.**

Montr Secure is not another scanner. It is an **orchestration layer** that runs every security
discipline (SAST, SCA, secrets, DAST/red-team), **correlates** their findings against a structural
model of the app, **confirms** which issues are actually exploitable, and delivers a short,
prioritized, **exploit-validated** report with **merge-ready fixes** — optionally auto-applied under
strict, gated conditions. It runs entirely inside the client's perimeter; the only outbound call is
to the client's own LLM key.

## The pipeline (6 layers)

```
Repo/PR ─► L0 Intake & Scoping    App Map (routes, ORM models, taint sources/sinks) + cost estimate
        ─► L1 Parallel Discovery  Semgrep + gitleaks + OSV/reachability → candidate findings (noisy, never surfaced)
        ─► L2 Correlation         reachability × exposure × impact, dedup, demote-never-delete   ← the moat
        ─► L3 Exploit Confirmation static data-flow proof (default) │ gated live DAST (premium)
        ─► L4 Fix Generation      diff patch + proof-of-fix test + human-required safety classifier
        ─► L5 Human Gate & Output report (confirmed-headline) │ PR-only auto-fix for auto-eligible
```

Cross-cutting: **Orchestrator** (resumable FSM + kill switch), **State Store** (Postgres, encrypted,
append-only hash-chained audit log), **LLM Gateway** (BYO-key over ten providers:
Anthropic / Bedrock / Vertex / Azure OpenAI, plus OpenAI / Google / xAI / Moonshot / Zhipu /
DeepSeek through a shared OpenAI-compatible adapter), **Cost Meter** (estimate → meter → hard-halt ceiling).

## Supported stacks

- **Node / Next.js / Prisma / Postgres** (deep — the wedge)
- **Python** — Django / FastAPI / Flask
- **JVM** — Spring / JAX-RS / JPA

Correlation, fix-classification, and reporting are **stack-agnostic**; a new stack adds only a
Layer-0 parser + Layer-1 rulesets + Layer-3 heuristics. This is machine- and runtime-verified
(`tests/stack-agnostic.invariant.test.ts`).

## Safety guarantees (non-negotiable — PRD §11)

- **No code egress** — client source only leaves the perimeter inside a call to the client's own LLM
  key; logs are metadata-only.
- **Auth / session / crypto / access-control fixes are always `human-required`** — hard rule.
- **DAST is allowlist-gated** — production blocked by policy, approver-authorized, kill-switch, rate
  - blast-radius caps, egress-guarded.
- **Budget hard-halt** — a ceiling breach stops the scan with a partial report; never a silent burn.
- **Everything audit-logged** — append-only, hash-chained, tamper-evident, exportable for auditors.

Hardened defaults: auto-fix **OFF** · DAST **OFF** · budget **hard-halt** · telemetry **OFF** ·
egress **default-deny** (only the client LLM endpoint).

## Quickstart (docker-compose)

```bash
cp deploy/docker/.env.example deploy/docker/.env && $EDITOR deploy/docker/.env   # set LLM provider + key
docker compose -f deploy/docker/docker-compose.yml up -d                          # api + worker + web + postgres + redis
open http://localhost:3000                                                        # operator console
```

See **[DEPLOY.md](./DEPLOY.md)** (compose / Helm / air-gapped install), **[RUNBOOK.md](./RUNBOOK.md)**
(operations), and **[DOD.md](./DOD.md)** (Definition-of-Done evidence).

## Monorepo layout

```
packages/
  contracts/    Zod schemas, types, layer I/O, queue jobs, gateway interface, errors  (the spine)
  config/       config schema + loader (hardened, safety-first defaults)
  telemetry/    structured logging + content-aware scrubber + OTel + audit-log client
  llm-gateway/  provider-agnostic LLM gateway  (the ONLY place a provider SDK may live)
  cost-meter/   estimate / meter / budget hard-halt
  state-store/  Prisma client, repos, field encryption, resumable state, hash-chained audit log
  orchestrator/ resumable FSM, BullMQ workers, gate state, kill switch
  appmap/       Layer 0 — App Map (TS/JS + Python + JVM plugins) + cost estimate
  discovery/    Layer 1 — SAST + secrets + SCA
  correlation/  Layer 2 — the moat
  confirm/      Layer 3 — static proof + gated live DAST
  fix/          Layer 4 — patch + proof-of-fix test + risk classifier
  report/       Layer 5 — report model + SARIF/SOC2/ISO/OWASP exports + gated PR flow
  qa/           golden-corpus precision/recall/FP-rate scorer
  security/     egress guard, log-scrubber verifier, audit hash-chain tamper CLI
  fixtures/     deterministic fixtures + fake LLM adapter + sample repos
apps/
  api/          Fastify HTTP API + RBAC (operator/approver/viewer) + OpenAPI
  worker/       BullMQ worker host + in-process pipeline driver
  web/          Next.js operator console + report UI + Phase-4 dashboards
deploy/         Dockerfiles, docker-compose, Helm chart, air-gap tooling
corpus/         golden test corpus — 8 vuln/clean repos across TS/JS + Python + JVM
```

## Develop

```bash
pnpm install
pnpm -w typecheck && pnpm -w build && pnpm test   # 632 tests, fully offline
pnpm e2e                                           # full scan of a vulnerable fixture repo → report
```

pnpm + Turborepo · TypeScript strict · Node 20. Package boundaries and the 10 golden rules are in
`docs/plan/montr-secure-build-plan.md` and `CONTRIBUTING.md`.

## License

Proprietary — Montr AI Labs.

## Documentation

Full project documentation lives in /docs and is written for both humans and AI coding agents.

Start here: [docs/overview.md](docs/overview.md)

The overview contains the project's tech stack, architecture decisions, directory map of all doc files, and a glossary of domain terms. All other doc files are linked from there.

To UPDATE the docs after a change, read docs/maintenance.md.

AI agents (Claude Code, Gemini CLI, Codex, Cursor, etc.) should read docs/overview.md before making any changes to this codebase.

AGENT NOTE: If you are an AI agent reading this README, stop here and open docs/overview.md before proceeding with any task.
