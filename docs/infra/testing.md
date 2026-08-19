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
Golden Corpus Evaluation: Managed by packages/qa and executed via scripts/corpus-scan.mjs, running scans against eight curated vulnerable and clean repositories in corpus/ across TypeScript, Python, and JVM stacks to calculate precision, recall, and false positive rates.
Self-Scan Dogfooding: Executed via scripts/selfscan.mjs, running the Montr Secure engine directly against its own monorepo to verify pipeline stability and self-detect security concerns.

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

Update Triggers
Update this file when test frameworks change, when coverage threshold floors are modified in vitest.config.ts, when new invariant tests or scripts are added to tests/ or scripts/, or when golden corpus evaluation procedures in packages/qa are updated.

Related Docs
docs/infra/deployment.md — CI/CD pipeline and deployment validation steps.
docs/modules/orchestration.md — Pipeline execution testing and worker runners.
