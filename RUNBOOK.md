# Montr Secure — Operations Runbook

## Roles (RBAC)

| Role         | Can                                                                         |
| ------------ | --------------------------------------------------------------------------- |
| **viewer**   | read reports + dashboards for permitted repos                               |
| **operator** | run scans, author custom rules, schedule scans, mark false positives        |
| **approver** | everything operator can, **plus** approve the human gate and authorize DAST |

The human gate and DAST authorization **require an approver** — hard guard. Every mutating action is
recorded in the append-only, hash-chained audit log with the actor + role.

## Running a scan

1. Register a repo (path/URL, branch) and pick mode: `full` or `diff` (diff = changed files +
   reachable call graph — cheap incremental).
2. Montr builds the **App Map** and shows a **pre-scan cost estimate** (tokens + wall-clock). Per
   config this must be approved before Layer 1 runs.
3. The pipeline runs L0→L5. The **report headlines confirmed, prioritized findings** — never raw
   counts. Breadth (unconfirmed candidates) lives in a clearly separated appendix.
4. Each confirmed finding carries a **proof** (static data-flow argument or live DAST transcript), an
   **impact**, an **OWASP/CWE** mapping, and a **merge-ready fix + proof-of-fix test**.

## The human gate & auto-fix

- Default is **report-first**: every fix is a recommendation.
- With auto-fix **ON**, Montr opens a **PR (never a direct commit)** for each `auto-eligible` fix
  (mechanical, low blast radius). Each PR is independently reviewable and carries its proof-of-fix
  test.
- `human-required` fixes — anything touching **auth / session / crypto / access-control** or with
  wide blast radius — are **always** recommendations, regardless of the toggle.

## Live confirmation (DAST) — gated

Only run against a **client-authorized, allowlisted staging target**. Production is blocked by policy.
An **approver** must authorize each run. Rate limits + blast-radius caps apply, and all outbound goes
through the egress guard. The **kill switch** halts all active probing immediately.

## Scheduled scans

Operators can schedule recurring scans (cron). A scheduled run goes through the **same** gate, budget
ceiling, and cost estimate as a manual scan — auto-fix stays PR-only and the gate is never bypassed.

## Custom rules & red-team scenarios

- **Custom rules**: author Semgrep/secret rules; they are **validated before enable** and versioned,
  then loaded alongside the curated rulesets.
- **Red-team scenarios**: reusable, versioned DAST scenarios that only parameterize the existing gated
  DAST engine — they cannot reach a non-allowlisted or production target.

## Reports, exports & compliance

From a report you can export: **SARIF 2.1.0**, generic **OWASP** (JSON/HTML/PDF), **SOC 2** evidence
(CC-series, JSON+CSV), and **ISO 27001** (Annex A, JSON+CSV) — each with control coverage and a link to
the tamper-evident audit trail. The audit log itself is exportable (JSON/CSV) for third-party auditors.

## False-positive feedback

Mark a confirmed finding as a false positive (RBAC-guarded, audited). It feeds the regression corpus,
counts against precision / the FP-rate metric, and tunes correlation/confirmation thresholds
(tuning can only **demote** — never promote — so a stale corpus only makes the pipeline more conservative).

## Cost control

Every scan surfaces an estimate up front, meters live, and reports actuals. A **budget ceiling** breach
**hard-halts** the scan and emits a partial report — client tokens are never silently burned.

## Backup / restore

Back up the Postgres volume (App Maps, findings at each tier, scan history, audit log — encrypted at
rest) and your config/secret. Restore = redeploy + restore the volume. Verify audit-log integrity with
the tamper CLI: `montr-audit-verify --client <id>` (exits non-zero on a broken hash chain).

## Kill switch

A single action halts all active work — especially live DAST probing — everywhere, and records it in
the audit log.
