# Testing Strategy and Quality Assurance

Scope: Test automation strategy, frameworks, directory coverage, golden corpus scoring, and CI execution.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Montr Secure implements a comprehensive, multi-tiered testing framework encompassing over six hundred unit, integration, invariant, and end-to-end test suites. All tests execute completely offline without outbound network calls, utilizing deterministic mock fixtures and fake LLM adapters. Automated quality gates enforce code coverage baselines, architecture boundary rules, stack-agnostic invariants, and statistical precision and recall thresholds measured against a curated golden vulnerability corpus.

Test Types and Scopes
Unit Tests: Located across packages/_/src/\**/_.test.ts and apps/_/src/\**/_.test.ts, testing isolated functions, Zod schema validation, state machines, and algorithmic units using Vitest.
Integration Tests: Located in tests/ and apps/worker/src/**/*.test.ts, testing multi-package interactions, Fastify API endpoints, Prisma database repositories, and BullMQ queue orchestration.
Invariant Tests: Located in tests/stack-agnostic.invariant.test.ts, tests/security.invariants.test.ts, and tests/package-boundaries.test.ts, verifying that Layer 2 correlation and Layer 4 fix generation remain independent of specific language ASTs, that egress guard rules hold, and that internal monorepo package boundary rules are strictly maintained.
End-to-End Scans: Executed via scripts/e2e-scan.mjs and apps/worker/src/e2e-scan.test.ts, running full six-layer pipeline workflows against realistic repository fixtures to generate verified reports and fix pull requests.
Golden Corpus Evaluation: Managed by packages/qa and executed via scripts/corpus-scan.mjs, running scans against sixteen curated vulnerable and clean repositories in corpus/ (44 labelled exploitable findings) across TypeScript, Python, and JVM stacks to calculate precision, recall, and false positive rates. The CI gate (packages/qa/src/baseline.ts evaluateBaseline, thresholds in corpus/baseline.json) enforces recallMin with the same weight as fpRateMax/precisionMin — a recall regression fails the build exactly like a precision/FP-rate regression, not just an informational number (AGENT NOTE: never report FP-rate/precision without recall alongside it — packages/qa/src/report.ts is the single place both are rendered together, in text (formatCorpusScore) and JSON (toJsonReport)). At the current real measurement (TP=11, FP=0, precision 100%, recall 25.0%), the 0% FP-rate is honestly measured but not yet statistically meaningful at that sample size; formatCorpusScore's sampleSizeCaveat prints this caveat automatically in every qa:corpus run while confirmed findings (TP+FP) stay below 30, and the same caveat is stated in DOD.md item 4 and corpus/baseline.json's $statisticalCaveat.
Self-Scan Dogfooding: Executed via scripts/selfscan.mjs, running the Montr Secure engine directly against its own monorepo to verify pipeline stability and self-detect security concerns.
Unwired-Seam Check (A10): scripts/check-unwired-seams.mjs (pnpm run check:unwired-seams) grep-asserts that every declared "seam" — an exported factory function or gateway method meant to be consumed in production, such as packages/config's resolveFieldEncryptionKey/createKeySource, the LLM gateway's resolvePrompt, createLlmGateway, packages/cost-meter's createBudgetRegistry, and store.falsePositiveMarks — has at least one non-test caller outside the package that defines it. This is a direct regression guard for the "built but unwired" pattern the audit found (real, fully-tested code with zero production callers); a seam intentionally left unconsumed (currently only gateway.stream() — see docs/modules/llm-gateway.md) is listed as a documented, informational exception rather than silently omitted. Blocking in CI, run right after typecheck (build-plan §3.7/§4.7 job in .github/workflows/ci.yml).

Test Frameworks and Tooling
Vitest: Primary test runner configured in vitest.config.ts, resolving internal package source code directly via path aliases to support testing without intermediate build steps.
V8 Coverage: Code coverage engine configured in vitest.config.ts with enforced threshold floors of fifty-five percent statements, sixty-eight percent branches, sixty-one percent functions, and fifty-five percent lines.
Fake LLM Gateway: Provided by packages/fixtures/src/fake-llm.ts, simulating deterministic model responses for triage, correlation, confirmation, and fix generation without external API calls.
Memory Store: In-memory repository implementations provided by packages/state-store/src/memory-store.ts allowing high-speed isolated test runs without requiring running Postgres instances.

Running Tests Locally
Standard Suite: Execute pnpm test from the repository root to run all unit, integration, and invariant tests.
Coverage Report: Execute pnpm test:coverage to run the test suite and evaluate V8 code coverage against mandatory thresholds.
Turbo Parallel Tests: Execute pnpm test:turbo to run tests across individual workspace packages using Turborepo caching.
End-to-End Test: Execute pnpm e2e to run a full pipeline scan against fixture repositories.
Corpus Benchmark: Execute pnpm corpus:scan to run the golden corpus benchmark and generate precision/recall metrics.
Smoke Integration: Execute pnpm smoke to run an API and worker integration smoke test.
Unwired-Seam Check: Execute pnpm run check:unwired-seams to verify every declared production seam still has a real, non-test caller.

Update Triggers
Update this file when test frameworks change, when coverage threshold floors are modified in vitest.config.ts, when new invariant tests or scripts are added to tests/ or scripts/, or when golden corpus evaluation procedures in packages/qa are updated.

Related Docs
docs/infra/deployment.md — CI/CD pipeline and deployment validation steps.
docs/modules/orchestration.md — Pipeline execution testing and worker runners.
