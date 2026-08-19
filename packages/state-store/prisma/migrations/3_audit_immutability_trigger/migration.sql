-- Database-level audit-log immutability (closes: tamper-evidence-only gap).
--
-- The audit hash chain (hash-chain.ts) gives tamper-EVIDENCE: any rewrite of
-- history breaks the chain and is detectable on verification. Until now,
-- nothing stopped the rewrite itself — a compromised application-layer DB
-- credential (the same role every service connects as; there is no separate
-- migration/admin vs. runtime role in this codebase) could UPDATE or DELETE
-- "AuditEvent" rows directly and the chain would simply be gone, not merely
-- broken.
--
-- This migration adds tamper-PREVENTION: a BEFORE UPDATE OR DELETE trigger on
-- "AuditEvent" that unconditionally raises an exception, at the database
-- engine level, regardless of which role issues the statement (short of a
-- role with privileges to drop the trigger/function outright, which is an
-- infra-level access-control concern, not something a single migration can
-- close). This is intentionally the most portable option — no new DB role or
-- GRANT provisioning required, works the same in docker-compose and in any
-- managed Postgres.
--
-- retention.ts's `auditImmutable` app-level flag no longer has a delete path
-- to gate: the DB now rejects the delete outright whenever it's attempted.

CREATE OR REPLACE FUNCTION prevent_audit_tampering() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'AuditEvent rows are immutable: % on "AuditEvent" (id=%) is not permitted. The audit log is append-only by design (hash-chain tamper-evidence backed by DB-level tamper-prevention).', TG_OP, OLD."id";
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_event_prevent_tampering
  BEFORE UPDATE OR DELETE ON "AuditEvent"
  FOR EACH ROW
  EXECUTE FUNCTION prevent_audit_tampering();
