-- A24: resolved interprocedural taint flows (real call-graph proof a source
-- reaches a sink, vs. grounding.ts's same-file proximity heuristic). Stored as
-- a plain JSON column on AppMap (like `thirdPartyCalls`/`entrypoints`) rather
-- than a relational table: it's consumed by file-keyed lookup only, never
-- joined/filtered at the DB layer. STRICTLY ADDITIVE.

-- AlterTable
ALTER TABLE "AppMap" ADD COLUMN "taintFlows" JSONB NOT NULL DEFAULT '[]';
