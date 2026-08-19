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

BullMQ Queue Architecture and Job Types
Queue Infrastructure: Managed via packages/orchestrator/src/bullmq-scheduler.ts over Redis connections configured in packages/config.
Layer Jobs: Individual queue jobs correspond to pipeline layer executions defined in packages/contracts/src/queue.ts, including Layer0AppMapJob, Layer1DiscoveryJob, Layer2CorrelationJob, Layer3ConfirmJob, Layer4FixJob, and Layer5ReportJob.
Concurrency and Workers: apps/worker spawns BullMQ worker listeners with configurable concurrency, pulling jobs, executing layer logic, and updating scan state upon completion.

Resumable Checkpoints and Gate Lifecycle
ScanState Model: For every scan run, packages/orchestrator persists a ScanState record storing the active layer, a list of completed layers, and serialized checkpoint data.
Gate Pausing: When a scan requires estimate approval (after Layer 0) or fix approval (after Layer 4), the state machine updates the gate state and stops queue progression without failing the job.
Resuming from Checkpoint: Upon gate approval via API calls, packages/orchestrator reads the ScanState checkpoint, marks the gate approved, and enqueues the next sequential layer without re-running previously completed layers.

Cross-Process Event Bus and Kill Switch
Redis Pub/Sub: packages/orchestrator/src/events.ts manages a Redis pub/sub channel broadcasting scan state changes, gate transitions, and budget alerts across API and worker instances.
Kill Switch Propagation: packages/orchestrator/src/kill-switch.ts broadcasts emergency kill signals over Redis. Active worker processes subscribe to this channel and trigger AbortController signals to terminate running scanner processes and active HTTP DAST requests immediately.

Update Triggers
Update this file when BullMQ queue contracts change in packages/contracts/src/queue.ts, when state machine transitions evolve in packages/orchestrator, or when database repository patterns change in packages/state-store.

Related Docs
docs/modules/orchestration.md — State machine implementation and worker controllers.
docs/api/database.md — Database models backing server state.
