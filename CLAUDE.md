# Agent Instructions — Montr Secure

## Start here

Read docs/overview.md before doing anything else. It contains the full mental model: stack, architecture, data flow, module map, and glossary.

## Documentation index

docs/overview.md lists every doc file and what it covers. Navigate from there. Do not rely on memory or assumptions.

## For documentation updates

If this task is to update or maintain documentation (after a refactor or coding session), read docs/maintenance.md and follow it. Do not re-run first-time generation.

## Before every task

1. Read docs/overview.md
2. Read the relevant module doc in docs/modules/ if one exists
3. Make the change
4. Follow docs/maintenance.md and the AGENT UPDATE: tags in the affected doc files
5. Output a DOCS UPDATED summary before marking the task complete

## Hard rules

- Never invent file paths, component names, or type names. Always verify against the actual codebase.
- Never add 'use client' to a Server Component without checking docs/architecture/rendering-strategy.md first.
- Never add an environment variable without updating docs/infra/environment.md.
- Never modify the database schema without updating docs/api/database.md.
- If a docs/ file would exceed 200 lines after your update, split it and update docs/overview.md to list both parts.

## Docs update tags

Throughout the /docs files you will find:

- AGENT NOTE: — constraint you must follow
- AGENT SEE: — cross-reference to read
- AGENT AVOID: — anti-pattern to skip
- AGENT UPDATE: — doc files to update when this area changes

## Bootstrap file sync

CLAUDE.md and AGENTS.md must stay identical in their Stack summary and Key paths sections. When either changes, update both.

## Stack summary

Node.js 20+ · TypeScript strict · Turborepo · Fastify REST API · Next.js 14 App Router · BullMQ · Redis 7 · PostgreSQL 16 · Prisma ORM · Tailwind CSS v4 · Vitest · 10-provider BYO-key LLM Gateway (Anthropic/Bedrock/Vertex/Azure + OpenAI/Google/xAI/Moonshot/Zhipu/DeepSeek)

## Key paths

- apps/api — Fastify REST API and RBAC authentication
- apps/cli — montr CLI: HTTP-driven scan trigger + CI severity gate
- apps/web — Next.js 14 operator console and report dashboards
- apps/worker — BullMQ background worker daemon and pipeline driver
- packages/contracts — Zod schemas, TypeScript types, and layer I/O spine
- packages/orchestrator — Resumable 6-layer FSM and kill switch controller
- packages/state-store — Prisma database client and encrypted audit store
- packages/llm-gateway — Multi-provider BYO-key LLM gateway and cost meter

AGENT NOTE: CLAUDE.md must stay under 80 lines. It is a bootstrap file, not a full reference. All detail lives in /docs. Keep it short and hard.
