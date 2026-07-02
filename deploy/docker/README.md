# deploy/docker

Single-VM docker-compose stack: `api`, `worker`, `web`, `postgres:16`, `redis:7`.

```bash
cp .env.example .env         # then fill in secrets
docker compose config        # validate
docker compose up --build    # bring up the stack
```

- Dockerfiles are multi-stage and run on a **distroless** base as **non-root**.
- The only outbound network dependency at runtime is the client's LLM endpoint
  (golden rule #1 / §14). Everything else is internal service traffic.
- `.env` is git-ignored; never commit real secrets.
