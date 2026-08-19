# Documentation Maintenance Guide

Scope: How to update existing documentation after a code change, feature refactor, or development session.
Rendering context: N/A
Project tier: 4
Last updated: auto

When to use this file
Read this file when the task is to UPDATE documentation after a refactor, feature change, or coding session — not first-time generation. For first-time generation, the original generation prompt is used instead.

Before you start

1. Read docs/overview.md for the current mental model.
2. Identify every code change in this session (diff, branch, or summary).
3. Run the decision tree below against each change.

Decision tree — run after every code change

- New or changed page, route, or layout? -> docs/architecture/rendering-strategy.md, docs/ui/layout-system.md, and docs/overview.md (if major)
- New or changed shared UI primitive or domain security component? -> docs/ui/component-library.md
- Design token, CSS variable, or theme color change? -> docs/ui/theming.md
- New or changed Fastify API route handler? -> docs/api/route-handlers.md
- New or changed external service, LLM provider adapter, or VCS platform? -> docs/api/external-services.md
- New or changed Prisma model, field, enum, or database relationship? -> docs/api/database.md
- New or changed React Query hook, client query key, or role context? -> docs/state/client-state.md
- New or changed BullMQ job queue, checkpoint model, or Redis pub/sub? -> docs/state/server-state.md
- New or changed environment variable or config schema default? -> docs/infra/environment.md
- Dockerfile, Helm chart, or air-gap installation script change? -> docs/infra/deployment.md
- New test framework, coverage floor, or golden corpus benchmark change? -> docs/infra/testing.md
- Authentication flow, JWT signing, password hashing, or CSRF change? -> docs/auth/auth-flow.md
- Role permissions, gate guard rule, or DAST authorization change? -> docs/auth/authorization.md
- Monorepo folder layout, package addition, or naming convention change? -> docs/architecture/folder-structure.md
- Pipeline data flow, layer lifecycle, or serialization boundary change? -> docs/architecture/data-flow.md
- Pipeline orchestration, FSM state transition, or kill switch change? -> docs/modules/orchestration.md
- Layer 0 AST extraction, route discovery, or taint source change? -> docs/modules/appmap.md
- Layer 1 SAST scanner, secret detection, or custom rule change? -> docs/modules/discovery.md
- Layer 2 correlation algorithm, scoring formula, or deduplication change? -> docs/modules/correlation.md
- Layer 3 static proof solver, live DAST engine, or blast-radius change? -> docs/modules/confirmation.md
- Layer 4 patch generator, proof test synthesis, or risk classification change? -> docs/modules/fix-generation.md
- Layer 5 report builder, compliance export, or automated PR flow change? -> docs/modules/reporting-vcs.md
- LLM gateway, model matrix floor, or cost metering change? -> docs/modules/llm-gateway.md
- Operator console page, dashboard view, or modal interaction change? -> docs/modules/web-console.md
- Does any of the above affect the top-level mental model? -> docs/overview.md (Recent Changes section)
- Did the set of doc files change, or the stack / key paths? -> docs/maintenance.md (its decision tree) + CLAUDE.md + AGENTS.md

Multiple files may need updating for a single change. Update all of them.

What update means

- Modified entry: Locate by exact path or name, replace only outdated lines. Add AGENT NOTE: if the change introduces a new constraint.
- New entry: Follow the existing format in that section exactly. Add AGENT SEE: cross-reference in related files.
- Removed entry: Delete entirely. Remove all references to it in other files. Add a one-line note in docs/overview.md Recent Changes.

What never needs a doc update

- Refactors with no behavioral or structural change
- Style or CSS-only changes with no design token impact
- Bug fixes that do not alter documented behavior
- Test additions that do not change architecture

File constraints

- No code blocks anywhere in the docs. Plain language and exact path references only.
- No file exceeds 200 lines; if an update pushes a file over, split it into -part1/-part2 and update docs/overview.md to list both parts.
- All paths and names must match the codebase exactly.
- Follow AGENT NOTE / SEE / AVOID / UPDATE tags in each touched file.

Bootstrap files to update

- docs/overview.md — append to Recent Changes (newest first, max 10 entries). Format: [YYYY-MM-DD] what changed and which doc updated.
- CLAUDE.md — update Stack summary / Key paths if they changed.
- AGENTS.md — keep in sync with CLAUDE.md per its sync rule.

Completion checklist
Before marking any task complete:

1. Decision tree run against the change
2. All flagged doc files updated
3. No references to deleted paths or old names remain
4. No file exceeds 200 lines (split if needed, update docs/overview.md)
5. AGENT NOTE / AGENT SEE / AGENT AVOID annotations added where relevant
6. No code blocks introduced anywhere
7. All file paths and names match the actual codebase exactly
8. docs/overview.md Recent Changes section appended
9. CLAUDE.md and AGENTS.md Stack summary / Key paths still accurate
10. docs/maintenance.md decision tree still lists every doc file

Required output
End every update task with the DOCS UPDATED summary block:
DOCS UPDATED

- docs/<file>.md — <what changed and why> (list only files actually changed)

AGENT NOTE: maintenance.md is the entry point for all update sessions. It must stay in sync with the UPDATE RULES. If the decision tree or the set of doc files changes, update this file.
AGENT UPDATE: update maintenance.md when any doc file is added or removed (its decision tree must list every doc file), or when the update workflow changes.
