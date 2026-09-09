-- Activates the PromptVersion model (§8.2, §15 regression-tuning loop): adds
-- `isActive` so a repository can promote a specific version to be the one
-- llm-gateway resolves at call time. STRICTLY ADDITIVE.

-- AlterTable
ALTER TABLE "PromptVersion" ADD COLUMN "isActive" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE INDEX "PromptVersion_name_clientId_isActive_idx" ON "PromptVersion"("name", "clientId", "isActive");
