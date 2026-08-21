# Module: Semantic Codebase Index

Scope: AST chunking, embedding generation, pgvector storage, and cosine-similarity retrieval over a scanned repository's source (E5).
Rendering context: Server
Project tier: 4
Last updated: auto

Overview
The semantic codebase index (packages/semantic-index) is a standalone, fully tested library that chunks a repository's source into function/method/class-sized units, embeds each chunk, and stores the vectors in Postgres via pgvector for cosine-similarity retrieval. It is meant to be built once per commit alongside the App Map (Layer 0) and reused by diff scans, giving correlation and confirmation genuine cross-file context without sending whole files through the token budget, and enabling "find every other place this pattern occurs" — turning one confirmed finding into a swept class of findings. It is NOT wired into any pipeline layer yet — see Consumption Status below.

Entry Points
buildSemanticIndex(input): packages/semantic-index/src/build.ts. Chunks a local checkout directory, embeds every chunk, and persists the result via a CodeChunkRepository. Meant to run once per commit, alongside runLayer0AppMap.
querySemanticIndex(input): packages/semantic-index/src/build.ts. Embeds a query string (a finding's code snippet, or a natural-language description) and returns the top-K most similar indexed chunks, scoped to a client/repo(/commit).

AST Chunking (chunk.ts)
Reuses packages/appmap's own parser loaders rather than duplicating WASM-loading/project-setup logic: ts-morph's createProject for TypeScript/JavaScript, and web-tree-sitter's getPythonParser/parseModule and getJavaParser/parseJava for Python and Java, all re-exported additively from packages/appmap/src/index.ts for this purpose.
Granularity: one chunk per function-like unit — a top-level function declaration, a top-level const-assigned arrow/function expression, or a class method. A whole class becomes one chunk only when it has no methods at all (a plain DTO/data class), so nothing is silently dropped. Chosen over file-level chunking (would blow both the embedding-request size and the eventual LLM-context token budget E5 exists to avoid) and matches the unit correlation/confirmation already reason about — a route handler, a query helper, a sanitizer are each functions. Route handlers are not separately labeled: a route handler is a function or method, captured by the same rule; a consumer wanting "is this chunk a route handler" cross-references AppMap's Route.handler source location against a chunk's file/line range.
Known gaps, documented not silently swallowed: TypeScript skips object-literal method shorthand, get/set accessors, IIFEs, and overload signatures; Python's function_definition grammar node does not distinguish a method from a module-level function, so every Python chunk is kind "function" (never "method"); Java chunks method_declaration and constructor_declaration, with a class/interface-level fallback when neither is present.
Chunks are truncated at MAX_CHUNK_CHARS (8,000) with a marker, and skipped entirely below 2 lines (boilerplate not worth indexing).

Embedding Generation (embed.ts + packages/llm-gateway/src/embeddings.ts)
embedChunks batches chunk content into an injected EmbeddingProviderAdapter, DEFAULT_EMBED_BATCH_SIZE (64) inputs per call; a failed batch is dropped (reported via onError) rather than failing the whole build.
Provider decision (documented per this being a real product choice, not an implementation detail): Anthropic has no embeddings endpoint at all. Of the remaining BYO providers this gateway speaks, only azure is implemented today (AzureEmbeddingAdapter, reusing the openai SDK's AzureOpenAI client already a dependency of adapters/azure.ts's chat path — the OpenAI wire format needs no new request/response mapping). Bedrock (Titan/Cohere-on-Bedrock) and Vertex (text-embedding-*) each have real embedding models, but each is a genuinely different wire protocol from those providers' existing chat adapters — implementing them is real, protocol-specific follow-up work, not done here; both throw NotImplementedError, matching how packages/llm-gateway/src/adapters/types.ts's optional submitBatch/pollBatch/getBatchResults already signal a per-provider capability gap. A deployer without Azure configured has no embeddings path today; packages/semantic-index depends on the adapter INTERFACE, not a concrete provider, so a Bedrock/Vertex (or local/offline) implementation is a drop-in addition later.

Storage and Retrieval (packages/state-store/src/code-chunk.ts)
CodeChunkRepository (createCodeChunkRepository(prisma)) is the pgvector-backed store, deliberately kept OUT of the main StateStore aggregate — see docs/api/database.md's Semantic Codebase Index section for the schema, the Unsupported("vector(1536)") column, and the pgvector extension requirement the bundled deploy/docker and deploy/helm Postgres images do not currently meet.
querySimilar issues a real pgvector <=> cosine-distance ORDER BY, scoped to clientId + repo (+ optionally one commitSha).
query.ts additionally provides pure, dependency-free cosine-similarity math (cosineSimilarity, rankBySimilarity) used both to unit-test retrieval ranking without a live database and as a genuine in-memory fallback ranking primitive for a deployment that has not yet enabled the pgvector extension.

Consumption Status (intended, not yet wired)
Nothing in packages/correlation or packages/confirm calls buildSemanticIndex or querySemanticIndex today — those two packages were off-limits for this change (concurrent work was touching them), and this task's own scope was to ship a correct, tested library first rather than force a same-day integration into a layer being actively edited elsewhere. The intended call sites: Layer 0's runLayer0AppMap (packages/appmap/src/runner.ts) would call buildSemanticIndex immediately after buildAppMap succeeds, passing the same workspace dir/clientId/repo/commitSha and the freshly persisted AppMap's id; Layer 2 correlation and Layer 3 confirmation would call querySemanticIndex with a candidate/probable finding's code snippet as queryText to retrieve structurally similar chunks elsewhere in the repo — the "sweep a confirmed finding into a class of findings" use case E5 names. scripts/check-unwired-seams.mjs records both the embeddings adapter and this package's two entry points as known, documented exceptions (informational, non-blocking) rather than silently-dropped seams.

Constraints and Edge Cases
AGENT NOTE: The pgvector Postgres extension is REQUIRED for CodeChunk's embedding column and is NOT present in deploy/docker/docker-compose.yml's postgres:16-alpine image or deploy/helm/montr-secure's default postgres.image — prisma migrate deploy fails outright on migration 5_semantic_code_index against either bundled image until the image is swapped for one that ships pgvector (e.g. pgvector/pgvector:pg16). This was deliberately NOT changed in deploy/ by this task (an infra/image decision outside its code scope) and is tracked as a required follow-up.
AGENT NOTE: The embedding column width (1536) is fixed to Azure's text-embedding-3-small. A different-dimensionality provider needs either a migration widening the column (only while no ANN index depends on the old width) or a dedicated table — see the migration file's comment.
AGENT AVOID: Do not add a second embeddings request shape onto LLMRequest — embeddings are intentionally a separate interface (EmbeddingProviderAdapter) from the chat ProviderAdapter; see embeddings.ts's header comment.
AGENT SEE: docs/api/database.md's Semantic Codebase Index section for the CodeChunk schema and migration. docs/modules/appmap.md for the parser-reuse seam. docs/modules/llm-gateway.md's Embeddings Capability section for the adapter.

Update Triggers
Update this file when chunking granularity, the embedding provider matrix, or the CodeChunkRepository query shape changes in packages/semantic-index or packages/state-store/src/code-chunk.ts, or when a pipeline layer starts calling buildSemanticIndex/querySemanticIndex (update Consumption Status).

Related Docs
docs/api/database.md — CodeChunk schema, pgvector requirement, migration.
docs/modules/appmap.md — Layer 0 App Map build this index is meant to run alongside.
docs/modules/llm-gateway.md — Embeddings adapter and provider-choice rationale.
