# End-to-End Pipeline Data Flow

Scope: Complete lifecycle of security scan data, cross-layer transformations, serialization boundaries, and error propagation.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Data in Montr Secure flows through a six-stage sequential pipeline managed by a resumable state machine in packages/orchestrator. High-volume raw scanner output is progressively filtered, correlated against structural application models, validated through static and dynamic exploit proofs, and synthesized into actionable remediation patches. Every stage boundary represents a strictly validated serialization point backed by Zod contracts and persistent Postgres storage.

Pipeline Data Lifecycle
Stage 0 Intake and Scoping: The user triggers a scan through apps/api or apps/worker cron schedules. The orchestrator persists a Scan record in packages/state-store and enqueues a Layer 0 job on Redis. The Layer 0 runner in packages/appmap parses the repository source tree, extracts routes, data stores, ORM models, and taint surfaces, and queries packages/cost-meter to compute token cost estimates. If estimate approval is required, the state machine transitions to estimate_pending and pauses execution.
Stage 1 Parallel Discovery: Upon estimate approval, the orchestrator enqueues Layer 1. The discovery runner in packages/discovery executes Semgrep, gitleaks, and OSV Scanner concurrently, transforming raw CLI outputs into normalized CandidateFinding records written to Postgres. Raw candidates remain unexposed to final report headlines.
Stage 2 Correlation: The correlation runner in packages/correlation reads the AppMap and CandidateFindings. It groups findings by root-cause location, traces route reachability, calculates multidimensional reachability, exposure, and impact scores, and creates ranked ProbableFinding records. Candidates lacking valid data paths are marked unconfirmed and demoted to appendix records.
Stage 3 Exploit Confirmation: The confirmation runner in packages/confirm evaluates each ProbableFinding. Static confirmation verifies interprocedural taint flow using LLM reasoning; live confirmation triggers approver-gated HTTP probes against allowlisted staging URLs under strict egress and blast-radius controls. Exploit-verified issues are written to ConfirmedFinding records with attached ProofArtifact objects.
Stage 4 Fix Generation: The fix runner in packages/fix synthesizes a unified diff patch and a proof-of-fix test for every ConfirmedFinding. The safety classifier evaluates modified AST nodes and marks each fix as auto-eligible or human-required. All changes touching authentication, session management, access control, or cryptography are strictly classified as human-required.
Stage 5 Human Gate and Output: The report runner in packages/report aggregates confirmed findings, fix recommendations, and cost metrics into a monolithic Report document. It generates SARIF, SOC2, ISO27001, and OWASP exports and writes a PostureSnapshot. If auto-fix is enabled and fixes are auto-eligible, packages/report calls the VCS adapter to create a branch and open a pull request.

Serialization and Transport Boundaries
Client to API Boundary: The browser client transmits JSON over HTTP to Fastify route handlers. Inbound request bodies and parameters are validated using Zod schemas in apps/api/src/schemas.ts.
API to Worker Boundary: Fastify route handlers push typed JSON job payloads onto BullMQ Redis queues using schemas defined in packages/contracts/src/queue.ts.
Worker to LLM Gateway Boundary: Pipeline layers communicate with packages/llm-gateway using typed LlmRequest and LlmResponse interfaces in packages/contracts/src/llm.ts. Prompts and source snippets are scrubbed before transmission.
Storage Boundary: Prisma client in packages/state-store serializes structured models to PostgreSQL tables. High-security fields (such as LLM API keys and red team attack steps) are encrypted at rest with AES-256-GCM.

Error Propagation and Kill Switch Handling
Pipeline Layer Errors: Unhandled exceptions during layer execution transition the scan state to failed, record an error summary in ScanState, write a failed audit log event, and notify waiting client polls.
Budget Overrun: When token expenditures exceed configured ceilings, packages/cost-meter throws a BudgetExceededError, prompting packages/orchestrator to immediately transition the scan to partial status and trigger Layer 5 to build a partial report.
Kill Switch Activation: When triggered by an operator via the API or UI, the kill switch broadcasts an abort signal across Redis pub/sub, aborting in-flight worker executions and active live DAST HTTP requests immediately.

Update Triggers
Update this file when pipeline stages are added or reordered, when serialization contracts change in packages/contracts, or when cross-package data boundaries evolve.

Related Docs
docs/modules/orchestration.md — Orchestrator state machine and queue handling.
docs/modules/correlation.md — Candidate to probable finding correlation logic.
