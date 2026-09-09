-- B1: extends the contracts spine with the blue-team entities and promotes
-- `ThreatModel` from an in-memory-only field on the Zod `AppMap` type to a
-- genuinely persisted column. Adds `DetectionRule` (a generated Sigma/OTel/
-- SIEM detection rule for a confirmed finding), `AttackPath` (a chained
-- kill-chain across >= 2 confirmed findings), and `DetectionCoverage`
-- (whether existing telemetry would catch a confirmed finding if exploited,
-- with a tri-state `detected` verdict and a `verification` slot B5's
-- purple-team loop will populate). STRICTLY ADDITIVE — no existing table,
-- column, or enum value is removed or renamed.
--
-- ENCRYPTION: `DetectionRule.content`/`AttackPath.narrative`/
-- `DetectionCoverage.reasoning` are intentionally NOT encrypted — see
-- schema.prisma's header comment on this section and docs/api/database.md
-- for the reasoning (mirrors `CustomRule.body` and the already-unencrypted
-- `ConfirmedFinding.proofArtifact`).

-- AlterTable: promote ThreatModel to a persisted AppMap column (E6/B1).
ALTER TABLE "AppMap" ADD COLUMN "threatModel" JSONB;

-- CreateEnum
CREATE TYPE "DetectionStatus" AS ENUM ('detected', 'not_detected', 'unknown');

-- CreateTable
CREATE TABLE "DetectionRule" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "format" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "mitreTechniques" JSONB NOT NULL DEFAULT '[]',
    "provenance" "ProofType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DetectionRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AttackPath" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "steps" JSONB NOT NULL,
    "feasibilityScore" DOUBLE PRECISION NOT NULL,
    "severity" "Severity" NOT NULL,
    "narrative" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AttackPath_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectionCoverage" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "detected" "DetectionStatus" NOT NULL,
    "reasoning" TEXT NOT NULL,
    "detectionRuleId" TEXT,
    "verification" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DetectionCoverage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DetectionRule_clientId_idx" ON "DetectionRule"("clientId");
CREATE INDEX "DetectionRule_clientId_scanId_idx" ON "DetectionRule"("clientId", "scanId");
CREATE INDEX "DetectionRule_clientId_findingId_idx" ON "DetectionRule"("clientId", "findingId");

-- CreateIndex
CREATE INDEX "AttackPath_clientId_idx" ON "AttackPath"("clientId");
CREATE INDEX "AttackPath_clientId_scanId_idx" ON "AttackPath"("clientId", "scanId");

-- CreateIndex
CREATE INDEX "DetectionCoverage_clientId_idx" ON "DetectionCoverage"("clientId");
CREATE INDEX "DetectionCoverage_clientId_scanId_idx" ON "DetectionCoverage"("clientId", "scanId");
CREATE INDEX "DetectionCoverage_clientId_findingId_idx" ON "DetectionCoverage"("clientId", "findingId");

-- AddForeignKey
ALTER TABLE "DetectionRule" ADD CONSTRAINT "DetectionRule_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "DetectionRule" ADD CONSTRAINT "DetectionRule_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AttackPath" ADD CONSTRAINT "AttackPath_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "AttackPath" ADD CONSTRAINT "AttackPath_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DetectionCoverage" ADD CONSTRAINT "DetectionCoverage_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "DetectionCoverage" ADD CONSTRAINT "DetectionCoverage_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
