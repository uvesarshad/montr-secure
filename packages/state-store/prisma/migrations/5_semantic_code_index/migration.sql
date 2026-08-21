-- E5: semantic codebase index — pgvector-backed embeddings over AST-chunked
-- code, built once per commit alongside the App Map (see packages/semantic-index).
--
-- ⛔ REQUIRES the `pgvector` Postgres extension. The bundled dev/starter
-- Postgres images do NOT currently include it:
--   - deploy/docker/docker-compose.yml pins `postgres:16-alpine` (the official
--     image — no pgvector).
--   - deploy/helm/montr-secure/templates/postgres.yaml's bundled single-
--     replica Postgres runs whatever `.Values.postgres.image` is set to,
--     which also defaults to a plain, non-pgvector Postgres 16 image today.
-- Before this migration can run against either bundled deployment, the image
-- must be swapped for one that ships pgvector (e.g. `pgvector/pgvector:pg16`,
-- which is Postgres 16 + the extension pre-built) or a custom image layering
-- it on top. This migration intentionally does NOT change deploy/docker or
-- deploy/helm itself — that is an infra/image decision outside this change's
-- code scope — so it is tracked as a required follow-up; see the "Semantic
-- Code Index" section of docs/api/database.md. Any managed/BYO Postgres
-- target must also have pgvector available (it is a "trusted" extension
-- installable without a superuser role on most managed providers as of
-- Postgres 13+, but this is NOT guaranteed everywhere — confirm before
-- relying on it in an air-gapped or locked-down environment).
--
-- `CREATE EXTENSION` itself requires a role with CREATE privilege on the
-- database — the same single application role every service already connects
-- as in this codebase (see migration 3's comment on the audit-immutability
-- trigger for the same "no separate migration/admin role" caveat). If that
-- role lacks the privilege, this migration fails outright and `prisma migrate
-- deploy` reports it clearly; there is no silent partial-apply.
CREATE EXTENSION IF NOT EXISTS vector;

-- CreateTable
CREATE TABLE "CodeChunk" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "appMapId" TEXT NOT NULL,
    "repo" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "file" TEXT NOT NULL,
    "startLine" INTEGER NOT NULL,
    "endLine" INTEGER NOT NULL,
    "language" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "symbolName" TEXT,
    "contentHash" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "embeddingModel" TEXT NOT NULL,
    -- Fixed at 1536 dims — matches the one embedding model
    -- @montr/llm-gateway implements today (Azure OpenAI
    -- text-embedding-3-small; see packages/llm-gateway/src/embeddings.ts).
    -- pgvector's ANN index requires a compile-time-fixed dimension, so a
    -- different-width embedding model needs either a migration widening this
    -- column (only possible while no index depends on the old width) or a
    -- dedicated table — see docs/api/database.md.
    "embedding" vector(1536),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CodeChunk_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "CodeChunk" ADD CONSTRAINT "CodeChunk_appMapId_fkey" FOREIGN KEY ("appMapId") REFERENCES "AppMap"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- CreateIndex
CREATE INDEX "CodeChunk_clientId_idx" ON "CodeChunk"("clientId");
CREATE INDEX "CodeChunk_appMapId_idx" ON "CodeChunk"("appMapId");
CREATE INDEX "CodeChunk_clientId_repo_commitSha_idx" ON "CodeChunk"("clientId", "repo", "commitSha");

-- ANN index for cosine-similarity retrieval (ivfflat). This is a write-once
-- per commit, read-many table (a rebuild inserts a fresh batch of rows keyed
-- by the new commitSha rather than updating rows in place), which suits
-- ivfflat's poor incremental-update characteristics fine. `lists = 100` is
-- pgvector's own rule-of-thumb starting point (roughly sqrt(row count) for a
-- corpus in the tens-of-thousands-of-chunks range) — revisit if a single
-- client's chunk count grows far beyond that.
CREATE INDEX "CodeChunk_embedding_cosine_idx" ON "CodeChunk" USING ivfflat ("embedding" vector_cosine_ops) WITH (lists = 100);
