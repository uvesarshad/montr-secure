> Source audit: [26-08-17-audit-build-state](./26-08-17-audit-build-state.md)
> Updated: 26-08-19 · 38/42 done

# Tasks — Montr Secure build state

## P0 — broken / at-risk

- [x] **(A1, P0)** Add real entrypoints for `apps/api` and `apps/worker`: a `main.ts` in each that actually calls `createApiServer(...).listen()` / `worker.start()`, with graceful shutdown and signal handling. Add `start` scripts to both `package.json`s, point the Docker `CMD`s at the new entry (`Dockerfile.api:57`, `Dockerfile.worker:67`), and replace the `createInMemoryDeps()` / `createStubOrchestrator` wiring with real dependency construction for production. Also implement the `--migrate` argv path the compose `migrate` service invokes, or drop that service.
- [x] **(A2, P0)** Make the golden-corpus CI gate score real pipeline output. Have the E2E scan emit a `scan.json` of confirmed findings and change `.github/workflows/ci.yml:84` to `qa:corpus -- --findings scan.json`. Keep `perfectScanner` only as an explicitly-labelled plumbing self-check, never as the release gate.
- [x] **(A3, P0)** Converge the web↔API contract. Pick one URL scheme (recommend versioning the API under `/api/v1`) and one auth mechanism (JWT cookie/bearer), align `apps/web/src/lib/api/config.ts:10-30` with the routes in `apps/api/src/routes/`, delete the `x-montr-actor-id` / `x-montr-actor-role` header shim, and flip the MSW default in `apps/web/src/components/providers.tsx:10` to off.
- [x] **(A4, P0)** Fix the osv-scanner download in `deploy/docker/Dockerfile.worker:53-54` — the real v1.9.1 asset is `osv-scanner_linux_amd64` (no version in the filename); the current versioned URL 404s and breaks the image build and the CI docker job. Add a checksum verification step while there.
- [x] **(A5, P0)** Remove or correct `args: ["dist/index.js"]` in `deploy/helm/montr-secure/templates/deployment-web.yaml:42` — the web image only contains the Next standalone tree, so it must run `apps/web/server.js` (or simply inherit the image `CMD`). Currently the pod crash-loops on `Cannot find module`.

## P1 — should fix

- [x] **(A6, P1)** Build the air-gap tooling that `DEPLOY.md:88,91` already documents: `deploy/airgap/build-bundle.sh --sign` and `deploy/airgap/import-bundle.sh <file>`. Neither exists — the directory holds only a README and a JSON schema. Either ship the scripts or correct `DEPLOY.md` and the `DOD.md` ✅.
- [x] **(A7, P1)** Make the CI dogfood real: add the missing `selfscan` script so the "Montr self-scan hook" (`ci.yml:122-129`) actually runs the product against its own source, and drop `continue-on-error: true` once the tree is clean so it becomes a blocking gate.
- [x] **(A8, P1)** Replace the three-entry hardcoded advisory array in `packages/discovery/src/advisories.ts:1-9` with a real OSV/GHSA offline mirror. The matcher and import-graph reachability check are already sound; only the data is missing.
- [x] **(A9, P1)** Wire the prompt registry. `PromptVersion` exists in `schema.prisma` but has zero readers/writers in `packages/state-store/src` or `packages/llm-gateway/src`; the §15 regression-tuning loop has no versioned prompt to tune against.
- [x] **(A10, P1)** Add a unit test suite to `packages/cost-meter` (currently `--passWithNoTests` with no test files), covering the estimate formula, live metering, the `BudgetExceededError` hard halt (`variance.ts:64-74`), and the ±15% variance calculation.
- [x] **(A11, P1)** Build the dashboards and alerting checked off in build-plan §10 lines 485-486: Grafana dashboard JSON, Prometheus recording/alert rules, and dedicated counters for budget breach, kill-switch activation and gate-bypass attempts (none exist in `packages/telemetry/src/metrics.ts` today).
- [x] **(A12, P1)** Make the NetworkPolicy genuinely default-deny. `deploy/helm/montr-secure/values.yaml:242` ships `cidr: "0.0.0.0/0"` on port 443, permitting egress anywhere on install. Require an explicit LLM-endpoint CIDR (fail the install if unset) rather than defaulting open.
- [x] **(A13, P1)** Fill the Wave-5 stub UI seams: `apps/web/src/app/dashboards/page.tsx` is explicitly "intentionally data-free", and the `rules` / `scenarios` / `schedules` pages hit routes registered as declared stub seams (`apps/api/src/routes/rules.ts`). The backing contracts and `PostureRepositoryImpl` are real — connect them. _(Re-audit found `rules`/`scenarios`/`schedules` already fully wired end-to-end by prior work — real forms/tables/hooks against real, Prisma-backed routes; only their header comments were stale. `dashboards/page.tsx` was the sole genuine stub — built a real org-wide posture dashboard (`apps/web/src/app/dashboards/{page.tsx,hooks.ts}`) consuming `GET /analytics/posture` + `GET /analytics/trends`, both already real against `PostureRepositoryImpl`.)_
- [x] **(A14, P1)** Reconcile `AUTO_ELIGIBLE_CATEGORIES` (`packages/fix/src/risk.ts:28-37`, 8 categories) with `FIX_STRATEGIES` (`strategies.ts:155-160`, 4 implemented). Either implement the missing mechanical strategies or trim the list so the advertised auto-fix surface matches reality. Fails safe today, so this is accuracy not safety.
- [x] **(A15, P1)** Add the missing `POST /scans/:id/kill` route to `apps/api/src/routes/` — the orchestrator kill switch and the web client's `killSwitch` endpoint both exist, but the ⛔ kill switch is unreachable over HTTP.
- [x] **(A16, P1)** Exercise the Semgrep/gitleaks integration against the real binaries. `parseSemgrepJson` and `candidatesFromGitleaks` have only ever seen hand-built fixture JSON; add a CI job (or container-based test) that runs the actual tools so the live-discovery path is proven. Blocked on A4.
- [x] **(A17, P1)** Grow the golden corpus beyond its current 8 repos / 19 labelled findings, with a documented sampling method and real-world code, so the `<5%` FP claim is defensible rather than illustrative.
- [x] **(A18, P1)** Add `thresholds` to the coverage block in `vitest.config.ts:33-37` and enforce them in CI — build-plan §4.7 checks off "coverage thresholds" but none are configured, so coverage can drop silently.

## P2 — nice to have

- [x] **(A19, P2)** Make `pnpm -w build` cover the web app. `@montr/web`'s `build` script is only `tsc -b`; the real Next build lives in `build:next`, so the "19/19 green" never compiled the console. (Verified `build:next` does succeed — 15 routes, webpack.)
- [x] **(A20, P2)** Correct build-plan §4.4: it specifies argon2, but `apps/api/src/auth/password.ts` uses `node:crypto` scrypt with a constant-time compare. Cryptographically fine — update the plan (or switch to argon2 if that was the intent).
- [x] **(A21, P2)** Correct the build-plan's Azure adapter entry: it names `@azure/openai`, the code uses the `openai` package's `AzureOpenAI` class (`openai@^6.45.0`). Functionally equivalent, factually divergent.
- [x] **(A22, P2)** Implement real Vault/KMS integration, or downgrade the claim. Key sourcing is currently env/file/secret-mount bytes only — a pluggable seam, not an integration. Done: `packages/config/src/key-source.ts` adds a real `VaultKeySource` (HashiCorp Vault KV v2 over HTTP, static-token or AppRole auth) behind the same `KeySource` contract as the existing env/file backend, selected via `security.keySource` (`MONTR_KEY_SOURCE=vault` + `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_SECRET_PATH` etc.). 16 unit tests mock the HTTP layer against Vault's documented KV v2 + AppRole response shapes.
- [x] **(A23, P2)** Harden audit-log immutability at the database layer: revoke UPDATE/DELETE from the application role or add a trigger (`schema.prisma:519-539`). Tamper-evidence via the hash chain is solid; tamper-prevention is currently an app-layer config toggle (`retention.ts:57-62`).
- [ ] **(A24, P2)** Upgrade Layer 2 taint reachability from the same-file nearest-line proximity heuristic + sanitizer regex (`packages/correlation/src/grounding.ts:174-196`) to real interprocedural dataflow, so cross-file flows are covered.
- [x] **(A25, P2)** Fix `exploitHypothesis` always citing `appMap.ormModels[0]` regardless of the model actually involved (`packages/correlation/src/hypotheses.ts:105`).
- [x] **(A26, P2)** Make `validatePatch` (`packages/fix/src/patch.ts:54-71`) actually execute the emitted `.proof-of-fix.test.ts` through vitest rather than re-evaluating the same predicate, so "the proof-of-fix test passes post-patch" is literally true.
- [x] **(A27, P2)** Seed the red-team scenario library with actual content — today it is storage, versioning and a well-gated execution engine with zero shipped scenarios.
- [x] **(A28, P2)** Resolve the worker uid mismatch: `docker-compose.yml:21,148` forces `user: "65532:65532"` while the image is `node:20-bookworm-slim` chowned to `node` (~uid 1000). Verify on a real run and align.
- [x] **(A29, P2)** Update the stale comment at `packages/appmap/src/languages/registry.ts:22-23` calling Python/JVM "pre-registered stubs" — both analyzers are fully implemented.
- [x] **(A30, P2)** Add own test suites for `packages/contracts` and for `llm-gateway`'s retry/backoff, model-floor and key-tier logic (currently only egress guards are covered).

## Suggested enhancements

- [x] Add real entrypoints for api and worker with graceful shutdown, `start` scripts and corrected Docker CMDs — the single unblocking change.
- [x] Wire the corpus gate to real scan output so the headline FP metric stops being decorative.
- [x] Pick one web↔API contract and converge on it: version the API under `/api/v1`, move the web client to JWT/cookie auth, delete the actor-header shim.
- [x] Ship the real OSV/GHSA offline mirror together with the signed-bundle importer, closing the SCA data gap and the air-gap DoD box in one pass.
- [x] Reconcile `DOD.md` with the code — four ✅ marks (Helm-on-cluster, self-scan, air-gap, FP-rate) are unsupported; an overstating doc is worse than an unchecked box.
- [ ] Implement Python/JVM mechanical fix strategies (the handoff's existing follow-up), and align the auto-eligible category list with what is actually implemented.
- [ ] Upgrade Layer 2 to real interprocedural dataflow — this is the actual moat and currently the weakest link in the precision story.
- [x] Grow the corpus toward real-world repos with a documented sampling method so the `<5%` claim can be defended.
- [x] Ship Grafana dashboards and Prometheus alert rules for budget breach, kill-switch activation and gate-bypass attempts, with dedicated counters.
- [x] Harden the audit log at the database layer so immutability survives an application-layer compromise.
- [x] Seed the red-team scenario library with a starter catalogue mapped to the OWASP Top 10.
- [ ] Add a real integration smoke test in CI — compose up, hit `/health`, run one scan end to end. That single test would have caught A1, A3 and A5 before they were checked off.
