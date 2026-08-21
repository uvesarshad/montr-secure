# Montr Secure System Overview

Scope: High-level architecture, mental model, directory index, and domain glossary for Montr Secure.
Rendering context: Isomorphic
Project tier: 4
Last updated: auto

Overview
Montr Secure is an on-premises, bring-your-own-LLM-key security orchestration platform that unifies static analysis, software composition analysis, secret detection, and dynamic exploit validation into an automated, six-layer analysis pipeline. The platform correlates raw multi-engine findings against structural application models, confirms genuine exploitability through static data-flow proofs and gated live DAST, synthesizes validated patches with proof-of-fix tests, and outputs compliance-ready reports with gated pull request automation. The codebase is organized as a Turborepo monorepo comprising a Fastify REST API, a Next.js operator console, a BullMQ pipeline worker, and sixteen decoupled TypeScript packages.

System Mental Model
The system operates as an end-to-end security pipeline structured across six distinct processing layers orchestrated by a resumable finite state machine.
Layer 0 intake and scoping builds a comprehensive structural application map of routes, data models, and taint surfaces while calculating token and cost estimates.
Layer 1 discovery executes multi-engine static analyzers, secret detectors, and dependency reachability scanners concurrently to capture raw candidate findings.
Layer 2 correlation scores candidates across reachability, exposure, and business impact to merge duplicate root causes into ranked probable findings without discarding evidence.
Layer 3 exploit confirmation proves vulnerability exploitability via deterministic interprocedural taint tracing and approver-gated live dynamic security testing against staging environments.
Layer 4 fix generation produces unified diff patches, proof-of-fix regression tests, and safety classifications that partition fixes into auto-eligible or human-required.
Layer 5 gate and reporting generates executive summaries, compliance exports across SARIF, SOC2, ISO27001, and OWASP, and opens automated pull requests for eligible remediations.

Key Architectural Decisions
Strict perimeter containment ensures that source code never leaves the client infrastructure except when transmitted directly to the client configured LLM provider endpoint.
Row-scoped multitenancy guarantees complete isolation across clients in Postgres, with high-security fields encrypted at rest using AES-256-GCM.
Resumable state machines allow long-running analysis workflows to pause at estimate and fix gates, survive worker crashes, and resume from checkpoints without re-running completed layers.
Budget hard-halt policies continuously meter token expenditure against user ceilings, stopping pipeline execution and producing partial reports before budget overruns occur.
Append-only hash-chained audit logging cryptographically seals all system actions, gate approvals, and operator decisions to provide tamper-evident compliance trails.

Cross-Cutting Concerns
Authentication and access control employ Argon2 password hashing, JSON Web Tokens, CSRF tokens, and role-based permissions dividing capabilities across Operator, Approver, and Viewer roles.
Error handling relies on custom domain error classes defined in packages/contracts/src/errors.ts mapped to standardized HTTP status codes and structured log envelopes.
Telemetry and logging utilize a content-aware scrubber in packages/telemetry/src/scrubber.ts to strip credentials, tokens, and raw code snippets before writing to stdout or OpenTelemetry collectors.
Styling across the operator web console uses Tailwind CSS v4 design tokens with a dark-first color scheme and semantic severity badges.

Documentation Directory Map
docs/overview.md — Master entry point, architecture summary, directory map, and glossary.
docs/maintenance.md — Step-by-step update guide and decision tree for maintaining documentation after code changes.
docs/architecture/folder-structure.md — Structural layout of packages, apps, tests, and configuration files.
docs/architecture/rendering-strategy.md — Rendering architecture across the Next.js console and Fastify backend.
docs/architecture/data-flow.md — Complete lifecycle of data, pipeline transitions, and serialization boundaries.
docs/ui/component-library.md — Reusable UI primitives and domain widgets in the operator web console.
docs/ui/layout-system.md — Root and nested layout hierarchies, route wrappers, and navigation chrome.
docs/ui/theming.md — Color system, dark theme tokens, severity scales, and typography definitions.
docs/api/route-handlers.md — Fastify HTTP route handlers, path parameters, role requirements, and response contracts.
docs/api/external-services.md — Third-party integrations including LLM providers, VCS platforms, and vulnerability databases.
docs/api/database.md — Prisma relational schema, multitenancy design, encrypted fields, and audit log chaining.
docs/state/client-state.md — TanStack React Query cache management, role context, and local component state.
docs/state/server-state.md — Postgres persistence, Redis BullMQ queues, resume checkpoints, and cache policies.
docs/auth/auth-flow.md — Session lifecycle, token issuance, password hashing, and authentication guards.
docs/auth/authorization.md — Role-based permission matrix, gate approval constraints, and DAST authorization rules.
docs/infra/environment.md — Complete catalog of environment variables, defaults, and exposure levels.
docs/infra/deployment.md — Docker Compose configurations, Kubernetes Helm charts, and air-gapped installation procedures.
docs/infra/testing.md — Vitest test suites, coverage floors, golden corpus evaluation, and smoke tests.
docs/modules/orchestration.md — Resumable pipeline state machine, worker concurrency, and kill switch mechanisms.
docs/modules/appmap.md — Layer 0 AST extraction, route discovery, ORM mapping, and taint modeling.
docs/modules/discovery.md — Layer 1 static analysis engines, secret detection, SCA reachability, and custom rules.
docs/modules/correlation.md — Layer 2 candidate scoring, root-cause deduplication, and grounding algorithms.
docs/modules/confirmation.md — Layer 3 static data-flow solver and gated live DAST execution engine.
docs/modules/fix-generation.md — Layer 4 patch synthesis, proof test generation, and safety risk classifier.
docs/modules/reporting-vcs.md — Layer 5 report generation, compliance exporters, and automated PR management.
docs/modules/llm-gateway.md — Multi-provider BYO-key LLM gateway, model matrix, and real-time cost meter.
docs/modules/web-console.md — Next.js 14 operator console interface, real-time monitors, and management views.

Domain Glossary
App Map: A structured graph of an application containing detected routes, ORM models, entrypoints, and potential taint flows.
Candidate Finding: A raw, noisy issue surfaced by Layer 1 static tools prior to reachability correlation.
Probable Finding: A correlated finding with computed reachability, exposure, and impact scores mapped to an application root cause.
Confirmed Finding: A high-confidence vulnerability backed by either an interprocedural static proof or a successful live DAST exploit.
Unconfirmed Finding: A candidate demoted due to unreachability or unverified exploitability, retained in report appendixes.
Auto-Eligible Fix: A low-risk remediation (such as header hardening or dependency bump) permitted for automated pull request creation.
Human-Required Fix: A sensitive remediation (touching authentication, cryptography, or access control) requiring manual engineer review.
Kill Switch: An emergency control that aborts active pipeline scans and live HTTP DAST probing across all worker processes.

Recent Changes
[2026-08-22] Real-time cost metering now actually accumulates in production: packages/llm-gateway/src/gateway.ts's account() records every completed call's usage into the per-scan CostMeter resolved from budgetRegistry (the same instance orchestrator/controller.ts registers, hands to layers as ctx.costMeter, and reads in enforceBudget) instead of only the unused constructor-level costMeter option apps/worker/src/main.ts never set (audit finding A32, follow-on to A2); updated docs/modules/llm-gateway.md, docs/modules/orchestration.md.
[2026-08-22] Scan resumability is now reachable in production: POST /api/v1/scans/:id/resume route, apps/worker boot-time reconciliation (reconcile.ts) for scans stuck at status running, BullMQ Worker lock/stall tuning, and FindingRepo.bulkCreate skipDuplicates fix for redelivered layer jobs (A3); also closed four confirmed-404 web routes — GET /scans/:id/progress, GET /scans/:id/appmap, cross-scan GET /pull-requests, and a scan-scoped POST /scans/:id/dast/authorize wrapper around the real target-based DAST flow (A5); updated docs/api/route-handlers.md, docs/modules/orchestration.md, docs/state/server-state.md, docs/auth/authorization.md.
[2026-08-22] LLM gateway now enforces a pre-call budget guard (estimated cost checked against the live CostMeter/BudgetPolicy before dispatch, refusing a single over-budget call mid-layer instead of only between layers, audit finding A2); new packages/cost-meter/src/registry.ts BudgetRegistry wired through apps/worker/src/main.ts; updated docs/modules/llm-gateway.md, docs/modules/orchestration.md.
[2026-08-22] SAST is now a required detector and air-gapped installs can wire it to a local Semgrep ruleset directory (discovery.rulesetsDir / MONTR_DISCOVERY_RULESETS_DIR, audit finding A4); updated docs/modules/discovery.md, docs/infra/environment.md, docs/infra/deployment.md.
[2026-08-22] Cost meter fails closed on unknown model ids instead of pricing at $0 (A1); rate card in packages/contracts/src/llm.ts gained claude-opus-5 and claude-fable-5; docs/modules/llm-gateway.md updated.
[2026-08-19] Initial creation of comprehensive AI-readable architecture documentation.

Update Triggers
Update this file when top-level architectural patterns change, when new packages or apps are introduced, when global cross-cutting policies evolve, or when files are added or removed from the docs directory.

Related Docs
docs/maintenance.md — Maintenance rules and decision tree for updating documentation.
docs/architecture/folder-structure.md — Detailed folder mapping of all packages and applications.
