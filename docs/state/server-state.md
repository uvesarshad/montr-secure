# Server-Side State and Queue Architecture

Scope: Database persistence, Redis message queues, resumable checkpoint state machines, and cache invalidation.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
Server-side state in Montr Secure is partitioned across durable relational storage in PostgreSQL and distributed message queues and pub/sub channels in Redis. Background workers in apps/worker process pipeline tasks asynchronously via BullMQ, while packages/orchestrator maintains fine-grained execution checkpoints in the database. This architecture guarantees that long-running analysis jobs can be paused at review gates, resumed after worker restarts, or aborted across distributed nodes in real time.

Durable Persistence in packages/state-store
Prisma Repositories: Entity operations are encapsulated within specialized repositories in packages/state-store/src/repositories. Every mutation and read is row-scoped by client identifier to enforce tenant isolation.
Encrypted Secret Storage: API keys, refresh tokens, and sensitive attack scenarios are encrypted transparently before persisting to Postgres tables using AES-256-GCM.
Append-Only Audit Logs: The AuditEvent table maintains a strict sequence counter and cryptographic SHA-256 hash chaining, preventing retroactive modification or deletion of operational records.
False-Positive Tuning Loop (§15, A10): packages/state-store/src/repositories.ts's FalsePositiveMarkRepositoryImpl (exposed as store.falsePositiveMarks) reads finding.marked_false_positive audit events back out per client — it does not duplicate the mark into a second table, since apps/api/src/routes/findings.ts's mark-as-false-positive route already writes the audit log as the authoritative record. apps/worker/src/runners.ts's loadFpTuning() calls listByClient(clientId) at the start of every Layer 2 and Layer 3 run and wraps the result in an isKnownFalsePositive(category, file, line, ruleId?) matcher, passed as fpTuning into both correlate() (packages/correlation) and confirmFindings() (packages/confirm). A match demotes/skips the repeat instead of re-promoting it — additive and fail-safe (a store read failure degrades to "no prior marks", never blocks the layer); it can only make a later scan MORE conservative, never promote a finding the deterministic engine wouldn't have.

BullMQ Queue Architecture and Job Types
Queue Infrastructure: Managed via packages/orchestrator/src/bullmq-scheduler.ts over Redis connections configured in packages/config.
Layer Jobs: Individual queue jobs correspond to pipeline layer executions defined in packages/contracts/src/queue.ts, including Layer0AppMapJob, Layer1DiscoveryJob, Layer2CorrelationJob, Layer3ConfirmJob, Layer4FixJob, and Layer5ReportJob.
Concurrency and Workers: apps/worker spawns BullMQ worker listeners with configurable concurrency, pulling jobs, executing layer logic, and updating scan state upon completion.
Stalled-Job Tuning: Each per-layer BullMQ Worker in bullmq-scheduler.ts's createRealBullMqTransport is constructed with lockDuration 10 minutes, stalledInterval 30 seconds, and maxStalledCount 1, so a layer job that legitimately runs for minutes is not marked stalled and redelivered while still in flight, while a genuinely crashed worker's lock still expires and triggers one redelivery. Because layer job ids are deterministic (buildIdempotencyKey) and BullMQ enqueues with attempts 1 (retry is centralized in the orchestrator, not BullMQ), a redelivered job re-runs the same layer from scratch; FindingRepo.bulkCreate in packages/state-store/src/repositories.ts passes skipDuplicates: true to Prisma's createMany so re-inserting the same (deterministically-id'd) findings is a harmless no-op instead of a unique-constraint failure that used to permanently fail the scan.

Resumable Checkpoints and Gate Lifecycle
ScanState Model: For every scan run, packages/orchestrator persists a ScanState record storing the active layer, a list of completed layers, and serialized checkpoint data.
Gate Pausing: When a scan requires estimate approval (after Layer 0) or fix approval (after Layer 4), the state machine updates the gate state and stops queue progression without failing the job.
Resuming from Checkpoint: Upon gate approval via API calls, packages/orchestrator reads the ScanState checkpoint, marks the gate approved, and enqueues the next sequential layer without re-running previously completed layers.
Boot-Time Reconciliation: apps/worker/src/reconcile.ts's reconcileStuckScans runs once at worker startup (apps/worker/src/main.ts, right after the BullMQ scheduler comes up). It calls the new ScanRepository.listByStatus(clientId, "running") to find candidate scans, judges staleness from ResumeRepository.get's checkpoint updatedAt (falling back to Scan.startedAt/createdAt), and calls ScanController.resume for every scan whose checkpoint has not advanced within a configurable threshold. This is what makes a worker crash mid-layer recoverable without a human noticing a scan is stuck; POST /api/v1/scans/:id/resume is the equivalent operator-triggered action.

Cross-Process Event Bus and Kill Switch
Redis Pub/Sub: packages/orchestrator/src/events.ts manages a Redis pub/sub channel broadcasting scan state changes, gate transitions, and budget alerts across API and worker instances.
Kill Switch Propagation: packages/orchestrator/src/kill-switch.ts broadcasts emergency kill signals over Redis. Active worker processes subscribe to this channel and trigger AbortController signals to terminate running scanner processes and active HTTP DAST requests immediately.

Update Triggers
Update this file when BullMQ queue contracts change in packages/contracts/src/queue.ts, when state machine transitions evolve in packages/orchestrator, or when database repository patterns change in packages/state-store.

Related Docs
docs/modules/orchestration.md — State machine implementation and worker controllers.
docs/api/database.md — Database models backing server state.
