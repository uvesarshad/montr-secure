# Monorepo Folder Structure

Scope: Structural organization, package boundaries, naming conventions, and file placement rules.
Rendering context: N/A
Project tier: 4
Last updated: auto

Overview
Montr Secure is architected as a modular TypeScript monorepo managed with pnpm workspaces and Turborepo. Application entry points are partitioned into three dedicated workloads under the apps directory, shared business logic and layer implementations are divided into sixteen isolated packages under the packages directory, and infrastructure definitions reside in deploy. Dependencies flow inward toward contracts, ensuring strict separation of concerns and eliminating circular dependencies.

Top-Level Directories
apps: Application entry points containing user-facing interfaces, HTTP servers, and worker daemon processes.
packages: Decoupled, reusable TypeScript domain packages containing the core security pipeline and data access layers.
deploy: Containerization, Kubernetes Helm charts, observability configurations, and air-gapped deployment utilities.
corpus: Curated golden benchmark repositories spanning TypeScript, Python, and JVM stacks used for accuracy evaluation.
scripts: Automation scripts for end-to-end pipeline execution, corpus benchmarking, self-scanning, and smoke testing.
tests: High-level architectural invariant suites, security boundary verifications, and cross-package integration tests.
docs: Comprehensive AI-readable system documentation and maintenance guidelines.

Applications in apps
apps/api: Fastify REST API server exposing authenticated endpoints for scan management, gate approvals, DAST control, audit queries, and Swagger documentation.
apps/web: Next.js 14 operator console providing real-time scan monitoring, interactive report review, DAST configuration, and compliance exports.
apps/worker: Background worker daemon executing BullMQ job consumers and pipeline layer runners.

Core Packages in packages
packages/contracts: The monorepo spine containing Zod schemas, TypeScript types, layer input and output definitions, queue job contracts, error classes, and shared enums.
packages/config: Centralized configuration schema with hardened defaults, environment variable loaders, and HashiCorp Vault key sources.
packages/telemetry: Structured logger, content-aware secret and code scrubber, OpenTelemetry exporters, and audit log client.
packages/llm-gateway: Provider-agnostic BYO-key client supporting Anthropic, AWS Bedrock, GCP Vertex, and Azure OpenAI, with key-tier safety guards and prompt registries.
packages/cost-meter: Token cost estimation, real-time consumption metering, provider pricing models, and hard-halt ceiling enforcement.
packages/state-store: Prisma database client, PostgreSQL repositories, row-scoped tenant scoping, AES-256-GCM field encryption, and hash-chained audit storage.
packages/orchestrator: Resumable 6-layer finite state machine, BullMQ job queue schedulers, gate lifecycle controllers, and emergency kill switch mechanisms.

Pipeline Layer Packages in packages
packages/appmap: Layer 0 AST extraction for TypeScript, Python, and JVM, route discovery, Prisma ORM mapping, taint source/sink identification, and cost estimation.
packages/discovery: Layer 1 multi-engine SAST runner (Semgrep), secret scanner (gitleaks), software composition analysis reachability (OSV), and custom rule execution.
packages/correlation: Layer 2 candidate scoring across reachability, exposure, and impact, root-cause deduplication, and grounding against the App Map.
packages/confirm: Layer 3 interprocedural static taint flow solver and approver-gated live DAST runner with blast-radius limits.
packages/fix: Layer 4 unified diff patch generator, proof-of-fix regression test synthesizer, and safety risk classifier.
packages/report: Layer 5 report generation, executive summaries, compliance exporters (SARIF, SOC2, ISO27001, OWASP), and GitHub/GitLab pull request integration.

Support Packages in packages
packages/qa: Precision, recall, and false-positive rate evaluation harness for golden corpus benchmarks.
packages/security: Default-deny network egress guard, log scrubber verifier, and audit log hash-chain verification CLI.
packages/fixtures: Deterministic test fixtures, sample repositories, and mock LLM gateway adapters.

Naming Conventions and Co-Location
File Naming: Kebab-case for all TypeScript files, routes, components, and utilities (example finding-card.tsx, route-handlers.ts).
React Components: PascalCase for exported component identifiers, co-located in apps/web/src/components.
Types and Schemas: PascalCase for types and Zod schemas with a Schema suffix (example ScanScopeSchema and ScanScope).
Co-Location: Unit tests are co-located alongside their source files using the dot-test-dot-ts naming suffix.

Update Triggers
Update this file when top-level directories are added or removed, when new packages or apps are introduced, or when project naming conventions change.

Related Docs
docs/overview.md — High-level architecture and master directory index.
docs/architecture/data-flow.md — Cross-package communication and pipeline data flow.
