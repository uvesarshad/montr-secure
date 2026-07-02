/**
 * @montr/report — Layer 5: the report model (§12), report exports
 * (SARIF/PDF/HTML/JSON/CSV/OWASP), and the gated auto-fix PR flow.
 *
 * ⛔ Golden rules enforced here:
 *   - Never headline raw counts — the headline is CONFIRMED + prioritized; the
 *     candidate pile's breadth lives in the unconfirmed appendix (`./headline`).
 *   - PRs only for `auto-eligible` fixes, never direct commits; `human-required`
 *     fixes are always recommendations (`./gate`, `./auto-fix`).
 *   - No PR without passing the auto-eligible bar OR explicit approver approval —
 *     enforced as an explicit gate state, re-asserted before every network call.
 *   - Every opened PR / generated export is audit-logged (metadata only).
 *
 * `buildReport` and `exportReport` keep their frozen Wave-0 signatures. Layer 5
 * emits {@link Layer5Output} = { report, pullRequests }.
 */

// Assembly inputs, the VCS-opener seam, and gate-state constants.
export * from "./types.js";

// ⛔ The PR gate (auto-eligible bar OR approver approval).
export * from "./gate.js";

// Report model assembly (buildReport + the composable pieces).
export * from "./report-builder.js";

// Headline safety (confirmed-only; never a raw count).
export * from "./headline.js";

// Auto-fix PR flow (planning + opening; offline via an injected opener).
export * from "./auto-fix.js";

// Concrete GitHub/GitLab openers (lazy Octokit / gitbeaker + simple-git).
export * from "./vcs.js";

// Exports: SARIF, JSON, HTML, PDF, CSV, OWASP-JSON (+ Wave-3 registry seam).
export * from "./exports/index.js";
