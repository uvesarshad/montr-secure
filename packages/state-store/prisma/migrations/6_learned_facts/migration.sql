-- E8: cross-scan memory. Adds `LearnedFact`, a durable, per-(clientId, repo)
-- store of learned facts (custom sanitizer names, framework idioms, operator
-- decisions) injected as optional, additive context into LATER scans'
-- Layer 1/2/3 LLM prompts. `confirmed_false_positive` facts are deliberately
-- NOT persisted here — see LearnedFactType's schema.prisma doc comment; they
-- are read back from the existing `finding.marked_false_positive` audit
-- events (A10) and merged in at read time. STRICTLY ADDITIVE.

-- CreateEnum
CREATE TYPE "LearnedFactType" AS ENUM ('custom_sanitizer', 'framework_idiom', 'operator_decision');

-- CreateTable
CREATE TABLE "LearnedFact" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "repo" TEXT NOT NULL,
    "type" "LearnedFactType" NOT NULL,
    "content" JSONB NOT NULL,
    "provenance" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LearnedFact_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "LearnedFact_clientId_idx" ON "LearnedFact"("clientId");

-- CreateIndex
CREATE INDEX "LearnedFact_clientId_repo_idx" ON "LearnedFact"("clientId", "repo");

-- CreateIndex
CREATE INDEX "LearnedFact_clientId_repo_type_idx" ON "LearnedFact"("clientId", "repo", "type");

-- AddForeignKey
ALTER TABLE "LearnedFact" ADD CONSTRAINT "LearnedFact_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
