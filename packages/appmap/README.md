# @montr/appmap

Layer 0 — **Intake & Scoping** (build-plan §5.1, PRD §7 Layer 0). Builds the
**App Map** that is the substrate for correlation (Layer 2), projects the scan
scope + cost, and emits the exact `Layer0Output { AppMap, ScanScope, CostEstimate }`.

## Ownership

Part of the **Montr Secure** monorepo (see `/CONTRIBUTING.md` for the
package-ownership map and the 10 golden rules). Owner: **WS-E**.

## What it does

1. **Intake** — accepts a repo path **or** git URL, branch, scan mode
   (`full` | `diff`), and an optional authorized staging URL. Local paths are
   scanned in place; URLs are cloned into a **sandboxed workspace** that is
   always cleaned up (`workspace.ts`).
2. **Deterministic App Map builders (first, no LLM):**
   - language + framework detection (`sources.ts`)
   - registered routes via Next.js introspection — app router (`route.ts` +
     `page.tsx`), pages router, and API routes — via **ts-morph** (`routes.ts`)
   - data stores + ORM models via **Prisma DMMF** (`@prisma/internals` `getDMMF`,
     regex fallback) (`prisma.ts`)
   - third-party call surface + env/secret surface (`surfaces.ts`)
   - taint **sources → sinks** catalog (`taint.ts`)
3. **⛔ LLM semantic pass (only after the deterministic map exists)** — labels
   **auth boundaries** and fills only the gaps the deterministic pass left; the
   prompt is structural (route metadata) with **no code egress**, and the model
   may only narrow `unknown` states, never override a known one (`llm.ts`).
4. **diff mode** — scope = changed files + the reachable import/call graph
   (`diff.ts`).
5. **Cost estimate** — projects tokens + wall-clock from map size × mode via
   `@montr/cost-meter` (`cost.ts`).
6. **Persistence (DECIDE-2)** — per-client, encrypted (via `@montr/state-store`),
   with **stale-commit invalidation** + fresh-map reuse, every mutation
   audit-logged (`persist.ts`).

## Public API

- `buildAppMap(input, deps?) → Promise<Layer0Output>` — the injectable core
  (gateway, store, audit, git, clock all injected ⇒ fully offline-testable).
- `createLayer0Runner({ gateway }) → LayerRunner<"layer0">` — orchestrator adapter
  (does **not** double-persist; the orchestrator owns `store.appMaps.create`).
- The individual builders (`scanRoutes`, `scanPrisma`, `scanTaint`, …) are also
  exported for reuse + focused testing.

## Golden rules honored

- **#1** no code egress / metadata-only logging · **#6** deterministic-first, no
  LLM before the map · **#4** fail-safe (uncertainty → deterministic default) ·
  **#7** every persisted mutation audit-logged · **#8** cost is a first-class
  output · **#10** emits the exact `@montr/contracts` shapes.

## Tests

`tests/appmap.build.test.ts` — offline, against the `@montr/fixtures` sample
vulnerable + clean Next.js/Prisma repos and the fake LLM adapter.
