# Agent Instructions — Montr Secure

This project uses CLAUDE.md as the canonical agent bootstrap file. Read CLAUDE.md first, then docs/overview.md.

For documentation update tasks, read docs/maintenance.md.

Hard rules, the before-every-task workflow, and the docs update tags all live in CLAUDE.md. Do not duplicate them here — that creates two sources of truth that drift.

## Stack summary

Node.js 20+ · TypeScript strict · Turborepo · Fastify REST API · Next.js 14 App Router · BullMQ · Redis 7 · PostgreSQL 16 · Prisma ORM · Tailwind CSS v4 · Vitest · Anthropic/Bedrock/Vertex/Azure LLM Gateway

## Key paths

- apps/api — Fastify REST API and RBAC authentication
- apps/web — Next.js 14 operator console and report dashboards
- apps/worker — BullMQ background worker daemon and pipeline driver
- packages/contracts — Zod schemas, TypeScript types, and layer I/O spine
- packages/orchestrator — Resumable 6-layer FSM and kill switch controller
- packages/state-store — Prisma database client and encrypted audit store
- packages/llm-gateway — Multi-provider BYO-key LLM gateway and cost meter

AGENT NOTE: keep AGENTS.md as a pointer only. If a tool you use requires the full instruction set in AGENTS.md, copy CLAUDE.md's body verbatim and add it to the "Bootstrap file sync" rule so both are updated together.
