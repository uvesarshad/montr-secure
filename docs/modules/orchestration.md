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
QueueWorkers: In apps/worker/src/runners.ts. Executes individual layer worker routines, mapping layer input contracts to package runner functions.

API Routes and Gate Interactions
POST /api/v1/scans: Calls ScanController createScan and start methods to initialize and enqueue Layer 0.
POST /api/v1/scans/:id/cancel: Calls ScanController cancel method to transition running jobs to cancelled.
POST /api/v1/scans/:id/kill: Calls KillSwitchService kill method to broadcast emergency abort signals.
POST /api/v1/scans/:id/gate/estimate: Calls ScanController approveEstimate method, transitioning gate state from estimate_pending to estimate_approved and enqueuing Layer 1.
POST /api/v1/scans/:id/gate/fix: Calls ScanController approveFixGate method, transitioning gate state to approved and triggering Layer 5 PR creation.

State Management and Resumability
Checkpoint Storage: The ScanState database model stores the active layer, completed layer history, and serialized layer checkpoint tokens.
Resume Token Flow: When paused at estimate or fix gates, the state machine saves checkpoint data. Upon approval, the orchestrator retrieves the checkpoint and enqueues the next layer without re-running completed layers.
Budget Interruption: If packages/cost-meter signals a budget limit breach, the controller halts pipeline progression, updates scan status to partial, and delegates to Layer 5 to build an incomplete report.

Constraints and Edge Cases
AGENT NOTE: Long-running scans must survive worker process crashes. When a worker process reboots, it inspects incomplete ScanState records and resumes from the last successfully persisted layer checkpoint.
AGENT AVOID: Never execute pipeline layers synchronously in Fastify request threads. Always enqueue jobs onto Redis BullMQ queues via bullmq-scheduler.ts.

Update Triggers
Update this file when state machine states change in packages/orchestrator/src/fsm.ts, when queue job structures evolve in packages/contracts/src/queue.ts, or when worker concurrency models change in apps/worker.

Related Docs
docs/architecture/data-flow.md — Pipeline stage transitions and data transformations.
docs/state/server-state.md — Server state, BullMQ queues, and database checkpoints.
