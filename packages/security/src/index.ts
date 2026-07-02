/**
 * @montr/security — security-of-Montr-Secure utilities (build-plan §4.8, WS-N).
 * node:crypto-only; no native crypto dependency.
 *
 * Three production controls plus tooling:
 *   1. Log-scrubber VERIFIER ({@link ./scrubber}) — redaction helpers + an
 *      assertion utility that PROVES no source-code body or secret value can
 *      reach a log/audit sink, and a certifier for any scrubber (golden rule #1).
 *   2. Egress GUARD ({@link ./egress-guard}) — a default-deny policy asserting the
 *      only outbound destination is the configured client LLM endpoint (§11).
 *   3. Audit hash-chain VERIFIER ({@link ./audit-verify}) — recomputes/validates
 *      the append-only, tamper-evident audit log; the `montr-audit-verify` CLI
 *      exits non-zero on any break (golden rule #7).
 *
 * Field-level secret encryption (AES-256-GCM) lives in `@montr/state-store`
 * (`crypto.ts`) — this package does not duplicate it.
 */
export * from "./scrubber.js";
export * from "./egress-guard.js";
export * from "./audit-verify.js";
export * from "./exit-codes.js";
export { run as runAuditVerifyCli } from "./audit-verify-cli.js";
