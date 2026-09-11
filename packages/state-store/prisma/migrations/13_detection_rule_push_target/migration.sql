-- Detection-rule PUSH integrations (suggested enhancement, 2026-09-12
-- red/blue agentic-posture audit — "ship detection rules as a real push
-- integration (Splunk, Elastic, Sentinel) rather than only a download").
-- Adds one new table so an operator can configure a single push destination
-- per client (mirrors LlmCredential's clientId-unique 1:1-per-client shape).
-- `type` is a plain TEXT column (not a Postgres enum), mirroring
-- `DetectionRule.format`'s existing precedent, so a future real Elastic/
-- Sentinel adapter needs no migration of its own. `hecToken` is a live
-- reversible secret and is field-encrypted at the application layer exactly
-- like `LlmCredential.apiKey` (see packages/state-store/src/crypto.ts).
-- STRICTLY ADDITIVE — no existing table, column, or enum value is removed,
-- renamed, or made non-nullable.

-- CreateTable
CREATE TABLE "DetectionRulePushTarget" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'splunk_hec',
    "endpointUrl" TEXT NOT NULL,
    "hecToken" TEXT NOT NULL,
    "index" TEXT,
    "sourcetype" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DetectionRulePushTarget_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DetectionRulePushTarget_clientId_key" ON "DetectionRulePushTarget"("clientId");

-- AddForeignKey
ALTER TABLE "DetectionRulePushTarget" ADD CONSTRAINT "DetectionRulePushTarget_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "Client"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
