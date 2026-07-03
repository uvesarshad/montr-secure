-- Phase-4 (Wave 5) — Scale & Intelligence. STRICTLY ADDITIVE (append-only).
-- Custom rules, red-team scenarios, scan schedules, posture snapshots.
-- Every table is per-client isolated (clientId + index, FK to Client).

-- CreateEnum
CREATE TYPE "RuleEngine" AS ENUM ('semgrep', 'secret');

-- CreateTable
CREATE TABLE "CustomRule" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "language" TEXT NOT NULL,
    "engine" "RuleEngine" NOT NULL,
    "body" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CustomRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RedTeamScenario" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "steps" TEXT NOT NULL,
    "targetAllowlistRef" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RedTeamScenario_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanSchedule" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "repo" TEXT NOT NULL,
    "mode" "ScanMode" NOT NULL DEFAULT 'full',
    "cron" TEXT NOT NULL,
    "budgetCeiling" DOUBLE PRECISION NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "nextRunAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PostureSnapshot" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "repo" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confirmedBySeverity" JSONB NOT NULL,
    "total" INTEGER NOT NULL DEFAULT 0,
    "delta" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PostureSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CustomRule_clientId_idx" ON "CustomRule"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "CustomRule_clientId_name_version_key" ON "CustomRule"("clientId", "name", "version");

-- CreateIndex
CREATE INDEX "RedTeamScenario_clientId_idx" ON "RedTeamScenario"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "RedTeamScenario_clientId_name_version_key" ON "RedTeamScenario"("clientId", "name", "version");

-- CreateIndex
CREATE INDEX "ScanSchedule_clientId_idx" ON "ScanSchedule"("clientId");

-- CreateIndex
CREATE INDEX "ScanSchedule_clientId_repo_idx" ON "ScanSchedule"("clientId", "repo");

-- CreateIndex
CREATE INDEX "PostureSnapshot_clientId_idx" ON "PostureSnapshot"("clientId");

-- CreateIndex
CREATE INDEX "PostureSnapshot_clientId_repo_idx" ON "PostureSnapshot"("clientId", "repo");

-- CreateIndex
CREATE INDEX "PostureSnapshot_clientId_scanId_idx" ON "PostureSnapshot"("clientId", "scanId");

-- AddForeignKey
ALTER TABLE "CustomRule" ADD CONSTRAINT "CustomRule_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RedTeamScenario" ADD CONSTRAINT "RedTeamScenario_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanSchedule" ADD CONSTRAINT "ScanSchedule_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PostureSnapshot" ADD CONSTRAINT "PostureSnapshot_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
