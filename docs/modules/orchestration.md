# Module: Pipeline Orchestration and State Machine

Scope: Architecture and execution lifecycle of the resumable 6-layer pipeline, finite state machine, BullMQ queues, and emergency kill switch.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The Orchestration module manages the lifecycle, execution order, state transitions, and concurrency of the security analysis pipeline. Implemented in packages/orchestrator and executed by daemon workers in apps/worker, it coordinates work across all six analysis layers using a resumable finite state machine. The orchestrator handles estimate and fix review gates, enforces token budget ceilings, persists execution checkpoints to Postgres, and distributes emergency kill signals across nodes via Redis pub/sub.

Entry Points and Workloads
Worker Entry Point: apps/worker/src/main.ts initializes database connections, Redis brokers, and BullMQ worker listeners.
Pipeline Driver: packages/orchestrator/src/controller.ts provides the primary API for creating, starting, pausing, resuming, cancelling, and killing scans.
Queue Scheduler: packages/orchestrator/src/bullmq-scheduler.ts manages job creation and worker subscriptions on Redis.

Key Components and Services
ScanController: In packages/orchestrator/src/controller.ts. Core coordinator that initializes scans, advances layer transitions, persists checkpoints, and triggers report generation upon completion.
ScanFsm: In packages/orchestrator/src/fsm.ts. Finite state machine validating legal state transitions between queued, running, paused, completed, failed, cancelled, and partial states.
KillSwitchService: In packages/orchestrator/src/kill-switch.ts. Listens on Redis pub/sub channels and dispatches AbortController signals to immediately abort running worker tasks.
QueueWorkers: In apps/worker/src/runners.ts. Executes individual layer worker routines, mapping layer input contracts to package runner functions. Its Layer 2 and Layer 3 runners also call loadFpTuning() to load prior operator false-positive marks and pass them as fpTuning into correlate()/confirmFindings() (§15 tuning loop, A10 — see docs/state/server-state.md). Its Layer 3 runner also passes emitProgress: ctx.emitProgress straight through into ConfirmDeps (E10, closing the last E10 gap — see docs/modules/confirmation.md's Live Progress Narration entry and docs/modules/llm-gateway.md's Streaming entry): the real per-scan LayerContext.emitProgress callback below now reaches packages/confirm/src/investigate.ts's agentic investigation loop, which calls it once per tool-call turn.

API Routes and Gate Interactions
POST /api/v1/scans: Calls ScanController createScan and start methods to initialize and enqueue Layer 0.
POST /api/v1/scans/:id/cancel: Calls ScanController cancel method to transition running jobs to cancelled.
POST /api/v1/scans/:id/resume: Calls ScanController resume method directly, the operator-triggered counterpart to apps/worker's boot-time reconciliation below.
POST /api/v1/scans/:id/kill: Calls KillSwitchService kill method to broadcast emergency abort signals.
POST /api/v1/scans/:id/gate/estimate: Calls ScanController approveEstimate method, transitioning gate state from estimate_pending to estimate_approved and enqueuing Layer 1.
POST /api/v1/scans/:id/gate/fix: Calls ScanController approveFixGate method, transitioning gate state to approved and triggering Layer 5 PR creation.

State Management and Resumability
Checkpoint Storage: The ScanState database model stores the active layer, completed layer history, and serialized layer checkpoint tokens.
Resume Token Flow: When paused at estimate or fix gates, the state machine saves checkpoint data. Upon approval, the orchestrator retrieves the checkpoint and enqueues the next layer without re-running completed layers.
Budget Interruption: If packages/cost-meter signals a budget limit breach, the controller halts pipeline progression, updates scan status to partial, and delegates to Layer 5 to build an incomplete report. This BETWEEN-layers check (ScanController's private enforceBudget) runs only after a layer's executeLayer call resolves, so it catches drift between the pre-scan estimate and provider-reported actuals but cannot stop a single in-flight layer from issuing one over-budget call.
Pre-Call Budget Guard: When OrchestratorDeps.budgetRegistry is supplied, ScanController registers each running scan's live CostMeter and effective BudgetPolicy (packages/orchestrator/src/fsm.ts's effectiveBudgetPolicy) into it immediately before executing a layer job (controller.ts's runLayerJob, before executeLayer) and unregisters it on scan cleanup. packages/llm-gateway/src/gateway.ts reads the same registry (keyed by the LLM request's metadata.scanId) inside complete()/stream(), BEFORE dispatching to a provider adapter, and refuses a call whose estimated cost would clear the ceiling — additive to, not a replacement for, the between-layers check above. apps/worker/src/main.ts constructs one BudgetRegistry (packages/cost-meter/src/registry.ts's createBudgetRegistry) per worker process and threads the same instance into both createOrchestrator and createLlmGateway.
Real-Time Spend Closes The Loop (A32): The CostMeter instance controller.ts's runLayerJob registers into budgetRegistry is the same instance getMeter(scanId) caches and hands to the layer as ctx.costMeter, and the same instance enforceBudget reads afterward — one meter per scan, reused across its whole lifecycle. packages/llm-gateway/src/gateway.ts's account() (called after every completed call) now writes that call's real token usage into this exact meter, resolved via budgetRegistry.get(scanId).meter — mirroring assertPreCallBudget's lookup. Before A32, account() only wrote to the gateway's constructor-level costMeter option, which apps/worker/src/main.ts never configured, so enforceBudget's between-layers check was permanently reading $0 spent regardless of real usage; the pre-call guard's "spend-so-far" term was equally always zero. Both checks now see real accumulated spend.

Constraints and Edge Cases
AGENT NOTE: Long-running scans must survive worker process crashes. apps/worker/src/main.ts calls apps/worker/src/reconcile.ts's reconcileStuckScans right after the durable BullMQ scheduler starts: it lists every scan at status running for this deployment's client, and for each one whose resume checkpoint (ScanRepository.listByStatus plus ResumeRepository.get's updatedAt, falling back to Scan.startedAt/createdAt when no checkpoint exists yet) has not advanced within a configurable threshold (MONTR_STUCK_SCAN_THRESHOLD_MS, default 10 minutes), calls ScanController.resume directly. A scan still legitimately mid-layer keeps advancing its checkpoint and is left alone; a scan orphaned by a crashed process is resumed automatically. POST /api/v1/scans/:id/resume is the same mechanism triggered by an operator instead of boot-time reconciliation.
AGENT NOTE: BullMQ Worker options in packages/orchestrator/src/bullmq-scheduler.ts's createRealBullMqTransport set lockDuration to 10 minutes, stalledInterval to 30 seconds, and maxStalledCount to 1, so a legitimately long-running layer job (a multi-minute Semgrep subprocess, synchronous AST/tree-sitter parsing, or an LLM call with retries) is not marked stalled and redelivered prematurely. A truly crashed worker's job is still redelivered once via BullMQ's stalled detection, and reconcileStuckScans above is the backstop if BullMQ ultimately marks it failed. FindingRepo.bulkCreate (packages/state-store/src/repositories.ts) passes skipDuplicates: true to Prisma's createMany, since finding ids are deterministic hashes of their content (see candidateId/makeProbableId/defaultConfirmedId) — a redelivered job's re-inserted findings collide harmlessly on the primary key instead of throwing and failing the scan.
AGENT NOTE: budgetRegistry is optional on OrchestratorDeps; omitting it leaves only the between-layers enforceBudget check, and that check's "spend-so-far" reading will be permanently $0 unless a standalone costMeter is separately wired into createLlmGateway (today's prior fallback behavior). A caller that wires it must pass the identical BudgetRegistry instance to createLlmGateway's budgetRegistry option, or both the gateway's pre-call guard AND real-time spend accounting (A32) silently no-op for that scan.
AGENT AVOID: Never execute pipeline layers synchronously in Fastify request threads. Always enqueue jobs onto Redis BullMQ queues via bullmq-scheduler.ts.
AGENT NOTE: Per-tenant queue isolation (A27, opt-in, OFF by default) — BullMqJobScheduler and apps/api's EnqueueOnlyScheduler both accept a BullMqSchedulerOptions (tenantIsolation, tenantIds) derived via bullmq-scheduler.ts's deriveTenantSchedulerOptions(config); when off, queue/worker registration is byte-for-byte identical to before. See docs/state/server-state.md's "Per-Tenant Queue Isolation" entry for the full mechanism.

Update Triggers
Update this file when state machine states change in packages/orchestrator/src/fsm.ts, when queue job structures evolve in packages/contracts/src/queue.ts, or when worker concurrency models change in apps/worker.

Related Docs
docs/architecture/data-flow.md — Pipeline stage transitions and data transformations.
docs/state/server-state.md — Server state, BullMQ queues, and database checkpoints.
