# Module: Layer 0 Intake and App Map Generation

Scope: AST parsing across TypeScript, Python, and JVM stacks, route detection, ORM mapping, taint modeling, and cost estimation.
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The App Map module implements Layer 0 of the analysis pipeline within packages/appmap. It inspects repository source code to build a comprehensive structural map of the target application. Layer 0 discovers HTTP and API routes, database models, data store connections, external service calls, and potential taint sources and sinks. It simultaneously calculates token expenditure projections and dollar cost estimates before expensive analysis begins.

Entry Points and Core Runners
Layer 0 Runner: packages/appmap/src/runner.ts exports runLayer0AppMap, which orchestrates repository checkout, language detection, AST walking, and cost estimation.
Module Export: packages/appmap/src/index.ts exports public interfaces, AST builder functions, and schema definitions.

Key Components and Parsers
Language Extractors: Located in packages/appmap/src/languages, containing specialized AST parsers for TypeScript and JavaScript, Python (Django, FastAPI, Flask), and JVM languages (Spring, JAX-RS, JPA).
TypeScript Route Extractors: packages/appmap/src/languages/typescript/routes.ts covers Next.js (App Router and Pages Router). packages/appmap/src/languages/typescript/express.ts and packages/appmap/src/languages/typescript/fastify.ts cover Express and Fastify respectively, both ts-morph AST based and receiver-agnostic (match on the HTTP-verb call shape, not a fixed app/router identifier name). Express and Fastify extractors only run when languages/typescript/index.ts detects the matching framework dependency in package.json. Express resolves same-file app.use(mountPath, router) mount-prefix composition; cross-file router composition is not resolved. Fastify covers both the verb-call form and the app.route({ method, url, handler }) object form; app.register(plugin, opts) prefix composition is not resolved.
Route-to-Model Linker: packages/appmap/src/languages/typescript/route-models.ts statically links each route's handler to the ORM model(s) it queries, populating Route.referencedModels (an array of { modelName, operations } where operations is a subset of read, write, delete). It resolves a direct prisma.<model>.<method>(...) call inside the handler, plus one hop through a locally declared helper function (same file or a relative import), mirroring callgraph.ts's own bounded-hop convention. It does not resolve through class-method/repository-pattern indirection (e.g. a route calling a repository object whose method internally calls Prisma) or through bare/workspace package imports — only relative imports are followed. Raw queries ($queryRaw/$executeRaw) are not attributed to a model since there is no static model name in the call.
Structural Builder: packages/appmap/src/build.ts aggregates discovered routes, ORM entities, and entry points into a normalized AppMap data structure. languages/typescript/index.ts merges the per-framework route scans (Next.js/Express/Fastify) before running the route-to-model linker.
Taint Surface Detector: packages/appmap/src/sources.ts identifies user-controlled inputs (query parameters, request bodies, route params, headers) as TaintSources and dangerous execution sinks (SQL queries, shell commands, file systems) as TaintSinks.
Diff Scoper: packages/appmap/src/diff.ts performs git diff analysis for diff-mode scans to limit the structural map to modified files and affected downstream dependencies.
Cost Estimator: packages/appmap/src/cost.ts measures repository size, route count, and AST complexity, querying packages/cost-meter to calculate estimated token and dollar costs.

Database Models and Persistence
AppMap Model: Written to Postgres via packages/state-store. Stores languages, frameworks, entrypoints, data stores, ORM models, third-party calls, and taint flow graphs.
Route, TaintSource, TaintSink Models: Stored as relational entities linked to the parent AppMap, enabling fast indexed queries during Layer 2 correlation and Layer 3 confirmation.
Rebuild Policy: AppMap persistence honors rebuild policies (rebuild_on_stale_commit, always_rebuild, never_rebuild) to avoid re-parsing unchanged repository commits.

Constraints and Edge Cases
AGENT NOTE: Downstream pipeline layers (L1 through L5) must remain completely stack-agnostic. All language-specific AST nuances must be resolved within packages/appmap into standardized AppMap entities.
AGENT AVOID: Never attempt live network connections or clone remote repositories without validating workspace boundaries in packages/appmap/src/workspace.ts.
AGENT NOTE: Route.referencedModels is populated on the in-memory AppMap object returned by buildAppMap and is available to any consumer that reads that same object within the run. The Postgres Route model (packages/state-store/prisma/schema.prisma) does not yet have a column for it, so a Route reloaded from the database after a fresh appMaps.get() will not carry referencedModels — persisting it requires a Prisma migration on the Route table plus mapper changes in packages/state-store/src/mappers.ts (routeToCreate/routeFromRow), which is out of scope of the current change and tracked as a follow-up.

Update Triggers
Update this file when language AST extractors change in packages/appmap/src/languages, when new taint source or sink patterns are added to packages/appmap/src/sources.ts, or when the AppMap schema changes in packages/contracts/src/appmap.ts.

Related Docs
docs/architecture/data-flow.md — Structural intake and pipeline data progression.
docs/modules/correlation.md — Correlation engine consuming the App Map.
