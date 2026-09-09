-- CreateEnum
CREATE TYPE "Provider" AS ENUM ('anthropic', 'bedrock', 'vertex', 'azure');

-- CreateEnum
CREATE TYPE "ScanMode" AS ENUM ('full', 'diff');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled', 'partial');

-- CreateEnum
CREATE TYPE "GateState" AS ENUM ('not_started', 'estimate_pending', 'estimate_approved', 'running', 'fix_gate_pending', 'auto_approved', 'approved', 'rejected', 'blocked');

-- CreateEnum
CREATE TYPE "LayerId" AS ENUM ('layer0', 'layer1', 'layer2', 'layer3', 'layer4', 'layer5');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('info', 'low', 'medium', 'high', 'critical');

-- CreateEnum
CREATE TYPE "Exposure" AS ENUM ('public', 'authed');

-- CreateEnum
CREATE TYPE "ProofType" AS ENUM ('static', 'live');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('candidate', 'probable', 'confirmed', 'unconfirmed');

-- CreateEnum
CREATE TYPE "RiskClass" AS ENUM ('auto-eligible', 'human-required');

-- CreateEnum
CREATE TYPE "FixStatus" AS ENUM ('proposed', 'pr-open', 'merged', 'rejected');

-- CreateEnum
CREATE TYPE "VcsProvider" AS ENUM ('github', 'gitlab');

-- CreateEnum
CREATE TYPE "PullRequestStatus" AS ENUM ('draft', 'open', 'merged', 'closed');

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('operator', 'approver', 'viewer');

-- CreateEnum
CREATE TYPE "AppMapRebuildPolicy" AS ENUM ('rebuild_on_stale_commit', 'always_rebuild', 'never_rebuild');

-- CreateEnum
CREATE TYPE "Category" AS ENUM ('sql_injection', 'nosql_injection', 'command_injection', 'xss', 'ssrf', 'path_traversal', 'insecure_deserialization', 'hardcoded_secret', 'vulnerable_dependency', 'permissive_cors', 'missing_security_headers', 'insecure_cookie', 'weak_crypto', 'broken_access_control', 'broken_authentication', 'open_redirect', 'xxe', 'csrf', 'sensitive_data_exposure', 'insufficient_logging', 'idor', 'mass_assignment', 'rate_limit_missing', 'other');

-- CreateTable
CREATE TABLE "Client" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Client_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'viewer',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LlmCredential" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "provider" "Provider" NOT NULL,
    "endpoint" TEXT,
    "apiKey" TEXT NOT NULL,
    "refreshToken" TEXT,
    "keyTier" TEXT NOT NULL DEFAULT 'unknown',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LlmCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AppMap" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "repo" TEXT NOT NULL,
    "branch" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "languages" JSONB NOT NULL,
    "frameworks" JSONB NOT NULL,
    "entrypoints" JSONB NOT NULL,
    "dataStores" JSONB NOT NULL,
    "ormModels" JSONB NOT NULL,
    "thirdPartyCalls" JSONB NOT NULL,
    "envSecretSurfaces" JSONB NOT NULL,
    "stale" BOOLEAN NOT NULL DEFAULT false,
    "rebuildPolicy" "AppMapRebuildPolicy" NOT NULL DEFAULT 'rebuild_on_stale_commit',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AppMap_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Route" (
    "id" TEXT NOT NULL,
    "appMapId" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "authState" TEXT NOT NULL,
    "isApiRoute" BOOLEAN NOT NULL DEFAULT false,
    "authGate" TEXT,
    "handler" JSONB,

    CONSTRAINT "Route_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TaintSource" (
    "id" TEXT NOT NULL,
    "appMapId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "location" JSONB NOT NULL,
    "description" TEXT,
    "routeId" TEXT,

    CONSTRAINT "TaintSource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TaintSink" (
    "id" TEXT NOT NULL,
    "appMapId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "location" JSONB NOT NULL,
    "description" TEXT,

    CONSTRAINT "TaintSink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "appMapId" TEXT,
    "repo" TEXT NOT NULL,
    "branch" TEXT NOT NULL,
    "commitSha" TEXT,
    "mode" "ScanMode" NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'queued',
    "gateState" "GateState" NOT NULL DEFAULT 'not_started',
    "operatorId" TEXT NOT NULL,
    "approverId" TEXT,
    "scope" JSONB NOT NULL,
    "budgetPolicy" JSONB,
    "costEstimate" JSONB,
    "costActual" JSONB,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanState" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "layer" "LayerId" NOT NULL,
    "status" "ScanStatus" NOT NULL,
    "completedLayers" JSONB NOT NULL,
    "checkpoint" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanState_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CandidateFinding" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "category" "Category" NOT NULL,
    "cwe" JSONB NOT NULL,
    "file" TEXT NOT NULL,
    "line" INTEGER NOT NULL,
    "rawSeverity" "Severity" NOT NULL,
    "evidenceSnippet" TEXT NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'candidate',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CandidateFinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProbableFinding" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "rootCauseId" TEXT NOT NULL,
    "category" "Category" NOT NULL,
    "mergedCandidateIds" JSONB NOT NULL,
    "reachabilityHypothesis" TEXT NOT NULL,
    "exploitHypothesis" TEXT NOT NULL,
    "exposure" "Exposure" NOT NULL,
    "authGate" TEXT,
    "routeId" TEXT,
    "file" TEXT NOT NULL,
    "line" INTEGER NOT NULL,
    "reachabilityScore" DOUBLE PRECISION NOT NULL,
    "exposureScore" DOUBLE PRECISION NOT NULL,
    "impactScore" DOUBLE PRECISION NOT NULL,
    "rank" INTEGER NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'probable',
    "unconfirmedReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ProbableFinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConfirmedFinding" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "probableId" TEXT,
    "title" TEXT NOT NULL,
    "category" "Category" NOT NULL,
    "cwe" JSONB NOT NULL,
    "owasp" TEXT,
    "severity" "Severity" NOT NULL,
    "exposure" "Exposure" NOT NULL,
    "file" TEXT NOT NULL,
    "line" INTEGER NOT NULL,
    "impact" TEXT NOT NULL,
    "proofType" "ProofType" NOT NULL,
    "proofArtifact" JSONB NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'confirmed',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ConfirmedFinding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Fix" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "confirmedFindingId" TEXT NOT NULL,
    "patch" TEXT NOT NULL,
    "rationale" TEXT NOT NULL,
    "proofOfFixTest" JSONB NOT NULL,
    "riskClass" "RiskClass" NOT NULL,
    "riskClassRationale" TEXT NOT NULL,
    "status" "FixStatus" NOT NULL DEFAULT 'proposed',
    "pullRequestId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Fix_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PullRequest" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "provider" "VcsProvider" NOT NULL,
    "url" TEXT,
    "number" INTEGER,
    "branch" TEXT NOT NULL,
    "baseBranch" TEXT NOT NULL DEFAULT 'main',
    "title" TEXT NOT NULL,
    "bodySummary" TEXT NOT NULL,
    "fixIds" JSONB NOT NULL,
    "status" "PullRequestStatus" NOT NULL DEFAULT 'open',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PullRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "document" JSONB NOT NULL,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PromptVersion" (
    "id" TEXT NOT NULL,
    "clientId" TEXT,
    "name" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "layer" "LayerId",
    "template" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PromptVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DastTarget" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "scopeContract" JSONB NOT NULL,
    "approvedById" TEXT,
    "approvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DastTarget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL,
    "scanId" TEXT,
    "actorType" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "actorRole" "Role",
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "summary" TEXT NOT NULL,
    "metadata" JSONB NOT NULL,
    "prevHash" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "User_clientId_idx" ON "User"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "User_clientId_email_key" ON "User"("clientId", "email");

-- CreateIndex
CREATE UNIQUE INDEX "LlmCredential_clientId_key" ON "LlmCredential"("clientId");

-- CreateIndex
CREATE INDEX "AppMap_clientId_idx" ON "AppMap"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "AppMap_clientId_repo_commitSha_key" ON "AppMap"("clientId", "repo", "commitSha");

-- CreateIndex
CREATE INDEX "Route_appMapId_idx" ON "Route"("appMapId");

-- CreateIndex
CREATE INDEX "TaintSource_appMapId_idx" ON "TaintSource"("appMapId");

-- CreateIndex
CREATE INDEX "TaintSink_appMapId_idx" ON "TaintSink"("appMapId");

-- CreateIndex
CREATE INDEX "Scan_clientId_idx" ON "Scan"("clientId");

-- CreateIndex
CREATE INDEX "Scan_clientId_status_idx" ON "Scan"("clientId", "status");

-- CreateIndex
CREATE INDEX "ScanState_clientId_scanId_idx" ON "ScanState"("clientId", "scanId");

-- CreateIndex
CREATE INDEX "CandidateFinding_clientId_scanId_idx" ON "CandidateFinding"("clientId", "scanId");

-- CreateIndex
CREATE INDEX "ProbableFinding_clientId_scanId_idx" ON "ProbableFinding"("clientId", "scanId");

-- CreateIndex
CREATE INDEX "ConfirmedFinding_clientId_scanId_idx" ON "ConfirmedFinding"("clientId", "scanId");

-- CreateIndex
CREATE INDEX "Fix_clientId_scanId_idx" ON "Fix"("clientId", "scanId");

-- CreateIndex
CREATE INDEX "PullRequest_clientId_scanId_idx" ON "PullRequest"("clientId", "scanId");

-- CreateIndex
CREATE UNIQUE INDEX "Report_scanId_key" ON "Report"("scanId");

-- CreateIndex
CREATE INDEX "Report_clientId_idx" ON "Report"("clientId");

-- CreateIndex
CREATE INDEX "PromptVersion_clientId_idx" ON "PromptVersion"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "PromptVersion_name_version_key" ON "PromptVersion"("name", "version");

-- CreateIndex
CREATE INDEX "DastTarget_clientId_idx" ON "DastTarget"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "DastTarget_clientId_url_key" ON "DastTarget"("clientId", "url");

-- CreateIndex
CREATE INDEX "AuditEvent_clientId_scanId_idx" ON "AuditEvent"("clientId", "scanId");

-- CreateIndex
CREATE UNIQUE INDEX "AuditEvent_clientId_sequence_key" ON "AuditEvent"("clientId", "sequence");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LlmCredential" ADD CONSTRAINT "LlmCredential_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppMap" ADD CONSTRAINT "AppMap_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Route" ADD CONSTRAINT "Route_appMapId_fkey" FOREIGN KEY ("appMapId") REFERENCES "AppMap"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TaintSource" ADD CONSTRAINT "TaintSource_appMapId_fkey" FOREIGN KEY ("appMapId") REFERENCES "AppMap"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TaintSink" ADD CONSTRAINT "TaintSink_appMapId_fkey" FOREIGN KEY ("appMapId") REFERENCES "AppMap"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_appMapId_fkey" FOREIGN KEY ("appMapId") REFERENCES "AppMap"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_operatorId_fkey" FOREIGN KEY ("operatorId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_approverId_fkey" FOREIGN KEY ("approverId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanState" ADD CONSTRAINT "ScanState_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CandidateFinding" ADD CONSTRAINT "CandidateFinding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProbableFinding" ADD CONSTRAINT "ProbableFinding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConfirmedFinding" ADD CONSTRAINT "ConfirmedFinding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Fix" ADD CONSTRAINT "Fix_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Fix" ADD CONSTRAINT "Fix_confirmedFindingId_fkey" FOREIGN KEY ("confirmedFindingId") REFERENCES "ConfirmedFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Fix" ADD CONSTRAINT "Fix_pullRequestId_fkey" FOREIGN KEY ("pullRequestId") REFERENCES "PullRequest"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PullRequest" ADD CONSTRAINT "PullRequest_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DastTarget" ADD CONSTRAINT "DastTarget_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DastTarget" ADD CONSTRAINT "DastTarget_approvedById_fkey" FOREIGN KEY ("approvedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

