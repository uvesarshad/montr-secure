# Contributing to Montr Secure

Montr Secure is a security product. **Correctness and safety beat cleverness
everywhere.** When two designs conflict, choose the one with fewer false
positives and less autonomous code modification.

## The 10 Golden Rules (violations block merge)

1. ⛔ **No code egress.** Client source only ever leaves the perimeter _inside_ a
   call to the client's own LLM key. Log call **metadata only**, never code
   bodies. (§11, §6.5)
2. ⛔ **Gateway abstraction from commit one.** No provider SDK import outside
   `@montr/llm-gateway`. (Enforced by ESLint `no-restricted-imports`; §8.2)
3. ⛔ **Auth/session/crypto/access-control fixes are ALWAYS `human-required`.** A
   hard rule, not a heuristic. (§4, §11 — see `classifyFixRisk` in `@montr/fix`)
4. ⛔ **Uncertainty resolves toward less autonomy, more human review.** Fail-safe
   default. (§11)
5. ⛔ **Code changes only via PR, never direct commit; only for `auto-eligible`
   fixes that pass the gate.** (§7 L5)
6. **Deterministic-first:** tools detect; the LLM triages/correlates/confirms/
   fixes. No LLM call before the App Map exists. (§6.1)
7. **Everything audit-logged**, append-only, tamper-evident (hash-chained). (§8.5)
8. **Cost is a first-class output:** estimate before, meter during, report after.
9. Contribute against **contracts + fixtures**, not against other agents' live
   code. Own your package.
10. Every finding tier and every layer boundary uses the exact `@montr/contracts`
    types. Don't invent shapes.

> If any requested feature conflicts with the safety rules, **stop and flag for a
> human decision. Never build a bypass.** (§11)

## Package-ownership map

| Package / app                                 | Workstream                        | Scope                                                                       |
| --------------------------------------------- | --------------------------------- | --------------------------------------------------------------------------- |
| `@montr/contracts`                            | **WS-A** (Wave 0)                 | Zod schemas, types, enums, layer I/O, queue jobs, gateway interface, errors |
| `@montr/config`                               | **WS-A** (Wave 0)                 | Config schema + loader, hardened defaults                                   |
| `@montr/fixtures`                             | **WS-A** (Wave 0)                 | Shared deterministic fixtures, fake LLM adapter, sample repos, ground truth |
| Prisma schema (`packages/state-store/prisma`) | **WS-A** authored → **WS-C** owns | Frozen early so everyone builds on it                                       |
| CI + deploy skeleton                          | **WS-A** → **WS-O**/**WS-P**      | `.github/workflows`, `deploy/`                                              |
| `@montr/llm-gateway` + `@montr/cost-meter`    | **WS-B**                          | Provider adapters, token accounting, budget hard-halt                       |
| `@montr/state-store` + audit log              | **WS-C**                          | Prisma client, repos, field encryption, resumable state                     |
| `@montr/orchestrator`                         | **WS-D**                          | FSM, BullMQ workers, gate state, kill switch                                |
| `@montr/appmap` (Layer 0)                     | **WS-E**                          | Intake, deterministic App Map, cost estimate                                |
| `@montr/discovery` (Layer 1)                  | **WS-F**                          | SAST + secrets + SCA                                                        |
| `@montr/correlation` (Layer 2)                | **WS-G**                          | The moat                                                                    |
| `@montr/confirm` (Layer 3)                    | **WS-H**                          | Static proof + gated live DAST                                              |
| `@montr/fix` (Layer 4)                        | **WS-I**                          | Patch + test + risk classifier                                              |
| `@montr/report` (Layer 5)                     | **WS-J**                          | Report model, exports, auto-fix PR flow                                     |
| `apps/web`                                    | **WS-K**                          | Next.js operator console                                                    |
| `apps/api`                                    | **WS-L**                          | Fastify API + auth/RBAC                                                     |
| `@montr/telemetry`                            | **WS-N**/**WS-P**                 | Logging, OTel, audit-log client                                             |
| `deploy/`                                     | **WS-O**                          | Dockerfiles, compose, Helm, air-gap                                         |
| QA harness + golden corpus                    | **WS-P**                          | Vitest, scorer, regression gate                                             |
| Security-of-Montr-Secure                      | **WS-N**                          | Egress/secrets/SBOM/signing, standing reviewer                              |

## Definition of "done" per package

Builds clean, unit tests green, exports match `@montr/contracts`, a fixture-driven
demo path passes, README stub written.

## Local workflow

```bash
pnpm install
pnpm typecheck        # tsc -b (project references)
pnpm lint             # turbo run lint  (or: pnpm exec eslint .)
pnpm test             # vitest
pnpm build            # turbo run build
pnpm prisma:validate  # validate the Prisma schema
```

Commits run `lint-staged` via Husky. Work on a branch and open a PR; never commit
to `main` directly.
