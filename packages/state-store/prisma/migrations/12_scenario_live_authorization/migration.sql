-- A1 (2026-09-12 red/blue agentic-posture audit): red-team scenarios can now
-- be executed for REAL by apps/worker (genuine live-DAST HTTP probing against
-- a customer's staging target) — previously `POST /scenarios/:id/run` only
-- ever ran in gate-only mode (no transport supplied), so probing never
-- actually happened anywhere. Real worker-side execution is gated behind an
-- explicit, auditable WRITTEN authorization beyond RBAC + the allowlist: an
-- Approver must record a free-text authorization reference (a ticket number,
-- a signed agreement reference, etc.) via `POST /scenarios/:id/authorize`
-- before a scenario may ever be run with a real transport.
--
-- Mirrors `DastTarget`'s existing approvedById/approvedAt authorize pattern
-- (see this same file, migration 00_init) but adds the required free-text
-- reference that flow never captured, and binds the authorization to one
-- specific scenario VERSION: any edit to the scenario (steps, target, etc.)
-- bumps `version`, and apps/api/src/routes/scenarios.ts's PUT handler clears
-- these four columns on every edit, so a stale authorization can never cover
-- a changed scenario. STRICTLY ADDITIVE — no existing column, table, or enum
-- value is removed, renamed, or made non-nullable.

-- AlterTable
ALTER TABLE "RedTeamScenario" ADD COLUMN "liveAuthorizedById" TEXT;
ALTER TABLE "RedTeamScenario" ADD COLUMN "liveAuthorizationReference" TEXT;
ALTER TABLE "RedTeamScenario" ADD COLUMN "liveAuthorizedAt" TIMESTAMP(3);
ALTER TABLE "RedTeamScenario" ADD COLUMN "liveAuthorizedForVersion" INTEGER;

-- AddForeignKey
ALTER TABLE "RedTeamScenario" ADD CONSTRAINT "RedTeamScenario_liveAuthorizedById_fkey" FOREIGN KEY ("liveAuthorizedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
