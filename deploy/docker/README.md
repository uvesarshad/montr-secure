# deploy/docker

Single-host **docker-compose** stack for Montr Secure:
`api`, `worker`, `web`, `postgres:16`, `redis:7`.

## One-command bring-up

```bash
cp .env.example .env          # fill in POSTGRES_PASSWORD + MONTR_LLM_API_KEY
docker compose config         # validate (structure + interpolation)
docker compose up --build     # build images + start the stack
```

Ports: API `:3001`, web console `:3000`.

## Files

| File                            | Purpose                                                              |
| ------------------------------- | -------------------------------------------------------------------- |
| `Dockerfile.api`                | Multi-stage, distroless, non-root image for `@montr/api`.            |
| `Dockerfile.worker`             | Same shape for the BullMQ worker host.                               |
| `Dockerfile.web`                | Same shape for the Next.js console (see Next-standalone note in it). |
| `docker-compose.yml`            | Full hardened stack + volumes + healthchecks + `depends_on`.         |
| `.env.example`                  | Every env-mapped `@montr/config` key (hardened defaults).            |
| `config.example.json`           | Full `MontrConfig` for keys with no env var (retention/rbac/etc.).   |
| `.dockerignore` (+ per-service) | Lean build context; see note below.                                  |

## Image hardening

- **Multi-stage**: build on `node:20-bookworm-slim`, ship on
  `gcr.io/distroless/nodejs20-debian12:nonroot` — no shell, no package manager.
- **Non-root** (`uid:gid 65532`), **all caps dropped**, **no-new-privileges**.
- **Read-only root filesystem**; the only writable paths are `tmpfs /tmp` and,
  for the worker, the `workspacedata` volume at `/workspace` (repo checkouts).
- **Healthchecks** run the distroless `node` binary directly (no shell): the API
  and web hit their HTTP health route; the worker TCP-checks Redis.

## Configuration

Two complementary sources (env overrides file where both apply):

1. **`.env`** — every `@montr/config` key that has an env mapping in
   `packages/config/src/loader.ts`, plus infra (`DATABASE_URL`, `REDIS_URL`,
   `POSTGRES_*`). Loaded into the app containers via `env_file`.
2. **`config.json`** (optional) — for keys with no env var (retention, RBAC,
   nested budget / DAST scope / auto-fix policy). Copy `config.example.json`, then
   uncomment `MONTR_CONFIG_FILE` + the `./config.json:/etc/montr/config.json:ro`
   mount for the `api`/`worker` services in `docker-compose.yml`.

All defaults are the **hardened, safety-first** ones: auto-fix OFF, DAST OFF,
budget hard-halt ON, telemetry OFF, egress default-deny.

## Database migrations

Prisma migrations are owned by `@montr/state-store`. The one-shot `migrate`
service (`prisma migrate deploy`, via `apps/api/src/migrate.ts`) runs as part of
the normal `docker compose up` — `api` and `worker` both declare
`depends_on: { migrate: { condition: service_completed_successfully } }`, so a
fresh database is always migrated before either app service starts. No extra
step or profile flag is needed for the one-command bring-up above.

To (re-)run migrations on their own, without starting the rest of the stack:

```bash
docker compose run --rm migrate
```

## `.dockerignore` note

The build **context is the repo root** (`context: ../..`) so the monorepo can
compile. BuildKit applies the ignore file matching the Dockerfile being built —
`deploy/docker/Dockerfile.<svc>.dockerignore` — which overrides the repo-root
`.dockerignore`. Those per-service files are byte-identical to the canonical
`deploy/docker/.dockerignore` and are a **superset** of the repo-root ignore, so
no build ever regresses to a fat context.

## Egress / safety

At runtime the **only intended outbound call is the client's LLM endpoint**
(golden rule #1 / §14). Everything else is intra-stack traffic on the `montr`
bridge network. Compose does not enforce egress at L3 — use the Helm
`NetworkPolicy` (default-deny egress) for hard enforcement in Kubernetes, or a
host firewall for single-VM installs. `.env` / `config.json` are git-ignored;
never commit real secrets.

## Status

`apps/api`, `apps/worker`, and `apps/web` are real production bootstraps — the
compose stack starts the full Fastify API, BullMQ worker, and Next.js console,
not placeholder stubs.
