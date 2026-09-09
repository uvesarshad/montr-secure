# Audit — July-line divergence recovery

**Date:** 2026-09-09
**Scope:** Comparison of `main` (current, Sept 2026) against the abandoned July 2026 line
(`origin/archive-july-2026`, tip `786baea`, last commit 2026-07-04).
**Method:** Four parallel agents compared the two working trees file-by-file across the LLM
gateway, fix/remediation, runtime/deploy, and scanner/persistence areas. P0 findings were
independently re-verified against the live tree before publication.

## Background

The two lines share an early ancestor but no git merge base — the local history was recreated
rather than branched, so `git` treats them as unrelated. The July line carried ~14 commits of
work that never reached `main`. `main` has since advanced far past it (audit findings A1–A33,
enhancements E1–E16, blue-team B1–B12). This audit establishes what, if anything, from the
July line is still worth recovering — and surfaces two defects in _current_ code found during
the comparison.

Findings A1, A2, A6 and A7 are defects in **current** code (regressions or gaps versus July).
Findings A3, A4 and A5 are **capabilities** the July line had that current lacks.

---

## A1 (P0) — Documented one-command bring-up starts the stack against an empty database

`deploy/docker/README.md:11` presents `docker compose up --build` as the primary bring-up.
The `migrate` service is profile-gated (`deploy/docker/docker-compose.yml:86`,
`profiles: ["migrate"]`), and neither `api` (line 122) nor `worker` (line 159) declares a
`depends_on` on it — both wait only on `postgres` and `redis` health. Migrations therefore run
only via `docker compose --profile migrate run --rm migrate`, documented separately at
`README.md:60`.

Consequence: anyone following the stack's own primary instruction against a fresh `pgdata`
volume boots api and worker against a schema-less database. First-deploy failure.

The July line auto-migrated on `up` — its `migrate` service declared no `profiles` key
(apparently unintentionally, as its comment claimed profile-gating) and api/worker depended on
it with `condition: service_completed_successfully`.

**Fix:** restore `depends_on: migrate: {condition: service_completed_successfully}` on api and
worker, and either drop the profile gate or make the README's primary path explicit.
Note that current's migration entrypoint is `dist/main.js --migrate` in `apps/api/src/migrate.ts`,
not July's `apps/worker/src/migrate-cli.ts` — wire the existing service, do not port July's.
**Effort:** under an hour.

## A2 (P1) — Five developer/CI scripts cannot run on Windows

`scripts/e2e-scan.mjs:25`, `selfscan.mjs:35`, `corpus-scan.mjs:34`, `benchmark-owasp.mjs:34`
and `blue-team-corpus-scan.mjs:36` all spawn `node_modules/.bin/vitest` directly. On Windows
that shim has no `.exe`/`.cmd` resolution when spawned without a shell, so every one of these
scripts fails outright.

This is a regression: July's `e2e-scan.mjs` deliberately spawned `process.execPath` against
`node_modules/vitest/vitest.mjs`, with a comment explaining precisely this Windows breakage.
Current reverted to the shim, with a comment asserting "CI/dev hosts are darwin/linux".

Note the related App Map path-normalization work is _not_ regressed — current applies the
`posix()` helpers more widely than July did (`route-models.ts`, `express.ts`, `taint.ts`,
`surfaces.ts`, `callgraph.ts`, `fastify.ts`).

**Fix:** swap each `.bin/<tool>` spawn for the `process.execPath` + package entry-point pattern.
**Effort:** under an hour for all five.

## A3 (P1) — LLM gateway supports only the Anthropic model family

`ProviderSchema` in `packages/contracts/src/llm.ts` admits four providers: `anthropic`,
`bedrock`, `vertex`, `azure` — four transport routes to essentially one model family. The
adapter factory in `packages/llm-gateway/src/adapters/index.ts` switches on the same four.

The July line supported ten, adding `openai`, `google`, `xai`, `moonshot`, `zhipu` and
`deepseek` through a single generic `OpenAiCompatibleAdapter`
(`packages/llm-gateway/src/adapters/openai-compatible.ts`) — the OpenAI SDK with a per-provider
`baseURL` and bearer key.

Consequence: for a BYO-key product this is a commercial constraint, not just a technical one.
A prospect standardised on OpenAI, or running Chinese-market models, cannot use the platform.

Porting is favourable: the July adapter is idiomatic to current's own conventions (thin adapter,
lazy SDK import, threaded egress guard), and `PROVIDER_DEFAULT_HOSTS` in
`packages/security/src/egress-guard.ts` already carries the six additional provider hosts in the
exact shape current uses.

**Obstacles:** `buildBody` is private in current's `azure.ts` (July exported it), and the shared
body-builder must also carry current's newer structured-output / effort / prompt-caching logic
that July never had. Extending the provider union also touches `keytier.ts` (new providers
default to `"unknown"`, as in July) and the adapter factory switch — both mechanical.
**Effort:** 1–2 days, mostly mechanical.

## A4 (P1) — Gateway cannot round-trip a tool exchange into a following turn

Current has genuine tool-calling (A8): all four adapters forward `request.tools` in their wire
format and parse `tool_use` / `tool_calls` / `functionCall` responses into `LLMToolCall[]`.
What is missing is the return path. `packages/llm-gateway/src/mapping.ts`
(`toAnthropicMessages`, `toOpenAiMessages`, `toVertexContents`) only ever emits plain
user/assistant text turns, and `LLMMessageSchema` carries no `toolCalls` field — so an
assistant's prior tool call and its result cannot be re-encoded onto the wire.

Consequence: the gateway supports single-turn "the model asked for a tool" but cannot sustain a
tool conversation. This is the structural reason A5 cannot simply be switched on.

July had this working, with explicit Anthropic `tool_use`/`tool_result`, Vertex
`functionCall`/`functionResponse` and OpenAI `tool_calls`/`tool_call_id` branches, verified
across all three wire families in `tests/llm-gateway.tools.test.ts`.

**Obstacles:** field-name drift — July's `LLMToolCall.arguments` versus current's `.input`,
already shipped in four adapters and their tests; porting July's mapping verbatim would create
two names for one concept. Adding `toolCalls` to the message schema is additive and safe, but
honouring it means rewriting all three mappers and touching all four adapters. A naive port
would regress current's structured output, effort/adaptive-thinking, prompt-caching, real token
counting and Batch API support, none of which existed in July.
**Effort:** 2–4 days.

## A5 (P1) — Layer-4 fix generation is single-shot, with no retry and no multi-file context

`proposeFixWithLlm` in `packages/fix/src/generate.ts` makes one attempt. It cannot retry on
failure, cannot feed a validation failure back to the model, and cannot read sibling files
before answering.

July's `proposeFixWithAgent` (same file, July line) ran a bounded loop: propose, validate
against the deterministic oracle, feed back a specific reason ("your fix didn't apply",
"vulnerability still present"), retry to `maxIterations`; and with `maxToolCalls > 0` exposed a
sandboxed `read_file` tool via `SourceReader` for genuine multi-file context gathering.

Consequence: fixes spanning more than one file are materially handicapped.

**Dependency:** A5 requires A4. A retry loop with tool use needs a gateway that can carry a tool
exchange forward. Treat A4 and A5 as one project.

**Design obstacle — do not port naively.** July's loop was viable because its oracle was an
instant in-process check. Current's `validatePatch` (`packages/fix/src/patch.ts`) spawns real
vitest subprocesses (seconds each), and with `containerProof` enabled a Docker build per
iteration. Looping that directly would make every fix attempt unacceptably slow. The loop needs
a cheap static check per iteration, reserving real vitest and container replay for the final
accepted candidate. July's whole-file `fixedSource` candidates also need adapting to current's
line-anchored edit-list format (`edits.ts`), and `agentFeedback` messaging reconciling with that
format's validation errors.

`SourceReader` (`packages/fix/src/source.ts`) is identical in both lines and ports cleanly.
The contracts spine (`tools`, `toolCalls`, `stopReason: "tool_use"`, `role: "tool"` with
`toolCallId`) is also largely unchanged from July.
**Effort:** a few days, concentrated in loop/oracle redesign rather than plumbing.

## A6 (P2) — No `.gitattributes`; format gate is non-deterministic across platforms

July enforced `text=auto eol=lf` (plus `*.sh` LF-only, lockfile marked no-diff, binary asset
markers) specifically to keep `prettier --check` deterministic regardless of a contributor's
`core.autocrlf`. Current has no `.gitattributes` at all.

Consequence: spurious format-gate failures in CI for a Windows contributor. Cosmetic churn,
not a functional break — but it compounds A2.
**Fix:** copy the file across as-is. **Effort:** minutes.

## A7 (P2) — `deploy/docker/README.md` still documents the apps as Wave-0 stubs

`README.md:84` carries a "Wave-0 stub caveat" section stating that `apps/api`, `apps/worker` and
`apps/web` are stubs. They are real production bootstraps. Misleading to any new operator, and
directly adjacent to the A1 bring-up error.
**Effort:** minutes; fold into the A1 fix.

---

## Verified as NOT gaps

The comparison cleared four areas outright. Recorded so they are not re-investigated:

- **User/auth persistence.** July's standalone `apps/api/src/auth/users-prisma.ts` has no
  counterpart file, but its functionality is present as `PrismaUserStore` in
  `apps/api/src/prisma-store.ts`, wired for production in `apps/api/src/production-deps.ts:152`.
  `InMemoryUserStore` is dev/test-only (`apps/api/src/store.ts:508`). Production users are
  database-backed. A file-location difference, not a defect.
- **Scanner subprocess cancellation.** Both lines pin execa `^9.6.1` and use `cancelSignal`
  with a 300s timeout. Current extends the pattern further than July, into
  `packages/fix/src/patch.ts` and `container-harness.ts`.
- **Finding-persistence idempotency.** `FindingRepo.bulkCreate`
  (`packages/state-store/src/repositories.ts`) uses `createMany({ skipDuplicates: true })` over
  deterministic content-derived IDs, making a BullMQ redelivery a safe no-op. Equivalent to
  July, better documented.
- **Air-gapped bundle tooling.** Current's `build-bundle.sh` (335 lines) and `import-bundle.sh`
  (260 lines) are roughly double July's (167/132) against the same manifest schema — a superset.

Two further July capabilities are **obsolete, superseded by current** — do not port:

- **Proof-of-fix.** July's `proof-runner.ts` ran a ~40-line hand-rolled vitest _shim_ under
  plain Node, asserting by regex. Current runs the real vitest binary against a temp workspace,
  parses the JSON report, and distinguishes a genuine test failure from a launch failure so a
  crashed run is never misread as "vulnerability present". Current then adds container-based
  exploit replay (`container-harness.ts`, `container-validate.ts`, `exploit-replay.ts`) — a
  runtime proof with no July analog.
- **Whole-file fix format.** Current's line-anchored edit list replaced it deliberately, to fix
  truncation on files over ~1,500 lines.

---

## Feature suggestions, enhancements & upgrades

- **Ship multi-provider support as a positioning change, not just a feature.** A3 converts
  "BYO Anthropic key" into "BYO any key". Worth stating explicitly in the README and product
  surface once landed, since it removes a hard disqualifier in evaluations.
- **Treat A4 + A5 as a single "agentic remediation" epic.** Sequence A4 first; A5 is
  unimplementable without it. Landing both is what makes genuine multi-file autonomous fixing
  possible, which is the stated product direction.
- **Add a CI job that runs the documented bring-up from a clean volume.** A1 is exactly the
  class of defect that only a from-scratch deploy test catches — the code was correct in
  isolation, the wiring was not.
- **Add a Windows CI leg, or drop the pretence.** A2 and A6 are both Windows-only breakage that
  no current CI leg would catch. Either test the platform or state plainly that it is unsupported.
- **Retire the redundant backup branch.** `backup/pre-rewrite-2026-09-09` duplicates
  `archive-july-2026` exactly. Keep one.
- **Consider a from-scratch deploy smoke test in the release checklist.** Related to A1 but
  broader: the DoD sign-off did not catch a broken primary bring-up path.
