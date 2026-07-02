# Security of Montr Secure (`@montr/security`)

Cross-cutting security controls for Montr Secure itself (build-plan §4.8, PRD §11/§14,
workstream **WS-N**). This package is `node:crypto`-only — no native crypto dependency.

Montr Secure handles the most sensitive asset a customer has: **their source code** and
**their LLM key**. The controls here exist to make the platform's own promises verifiable,
not merely asserted. They are fail-safe: over-redaction and over-denial are acceptable;
leaking or reaching the wrong host is not.

## Threat model (what these controls defend against)

| Threat                                                         | Control                    |
| -------------------------------------------------------------- | -------------------------- |
| Client **source code** leaking into logs / audit metadata      | Log-scrubber verifier      |
| A **secret value** (LLM key, token, cookie) reaching a sink    | Log-scrubber verifier      |
| Any **outbound connection** other than the client LLM endpoint | Egress guard               |
| **Tampering** with the append-only audit log                   | Audit hash-chain verifier  |
| A vulnerable/known-bad **dependency** shipping in a release    | SBOM + self-scan (dogfood) |

## Golden-rule mapping

- **#1 No code egress; log metadata only** → log-scrubber verifier + egress guard.
- **#7 Everything audit-logged, append-only, tamper-evident** → audit hash-chain verifier.
- **§4.8 / §14 Security of itself** → SBOM (`syft`) + self-scan (`gitleaks`/`semgrep`/`osv-scanner`).

---

## 1. Log-scrubber verifier (`scrubber.ts`)

`@montr/telemetry` owns the SCRUBBER that redacts fields on the logging hot path. This
package owns the independent **verifier** that _proves_ a scrubber's output is safe.

- `findLogViolations(value)` / `assertNoSecretsOrCode(value)` — deep-scan a would-be log
  payload and flag/throw on any surviving code body or secret value. Detections:
  sensitive-keyed values, oversize strings, known secret-VALUE formats (AWS/GitHub/Slack/
  Anthropic/OpenAI/Google keys, JWTs, PEM private keys, bearer credentials), and code-like
  bodies (heuristic, content-based). Errors carry only a path + kind + size — **never the
  offending value**.
- `redactSensitive(value)` — a self-contained redactor that is _strictly stronger_ than a
  key/size-only scrubber: it also neutralises secret/code by **content**, so a secret hidden
  under an innocuous key is still caught.
- `assertScrubberNeutralizes(scrub, samples)` — certify **any** scrubber (e.g. telemetry's
  `scrubValue`) against an adversarial battery; throws `ScrubberCertificationError` if a
  sample leaks. Used in CI to keep the scrubber honest.

```ts
import { scrubValue } from "@montr/telemetry";
import { assertScrubberNeutralizes, REALISTIC_LOG_THREATS } from "@montr/security";

// startup / CI self-check: prove the telemetry scrubber neutralises real threats
assertScrubberNeutralizes((v) => scrubValue(v), REALISTIC_LOG_THREATS);
```

## 2. Egress guard (`egress-guard.ts`)

⛔ The only permitted outbound destination is the **configured client LLM endpoint**.
The guard compiles a **default-deny** policy from configuration and denies everything else.

```ts
import { createEgressGuard } from "@montr/security";
import { loadConfig } from "@montr/config";

const guard = createEgressGuard(await loadConfig(), { onWarning: (w) => log.warn(w) }); // startup
// ... later, before ANY outbound request:
guard.assert(targetUrl); // throws EgressBlockedError unless it is the LLM endpoint
```

- If `llm.endpoint` is set, egress is narrowed to that single host. If not, the provider
  default host is used; broad-suffix defaults (Bedrock/Vertex/Azure) emit a **warning**
  advising `llm.endpoint` be set.
- `security.allowedEgressHosts` adds operator-approved infra (e.g. an offline OSV/ruleset
  mirror). An opt-in telemetry endpoint is allowed only when `telemetry.enabled`.
- DAST staging targets are **not** general egress; they are folded in only with
  `{ includeDastTargets: true }` (worker process, after approver authorization).

This complements the deploy-layer **NetworkPolicy default-deny egress** (build-plan §4.6):
defense in depth at both the cluster and application layers.

## 3. Audit hash-chain verifier (`audit-verify.ts` + `montr-audit-verify` CLI)

Recomputes and validates the append-only, hash-chained audit log and **exits non-zero on any
break** (insert / delete / reorder / field edit / head truncation). It validates each record
against `AuditEventSchema` (`@montr/contracts`) and re-derives hashes with canonical helpers
(`hash-chain.ts`) that **mirror `@montr/state-store` byte-for-byte** — a conformance test
cross-checks both, so the verifier can never drift from how events were hashed on append.
Keeping the hashing in-package makes the verifier a dependency-light leaf: it never pulls the
Prisma runtime just to check hashes.

```bash
# verify a JSON audit export (produced by the state-store audit exporter)
montr-audit-verify --file audit-export.json            # exit 1 on tamper
cat audit-export.json | montr-audit-verify --json      # machine-readable
```

To verify the live audit table, run the `@montr/state-store` audit exporter and pipe its JSON
output into this CLI (or call state-store's own `verifyChain` directly).

Exit codes: `0` OK · `1` CHAIN_BROKEN · `2` USAGE · `3` INPUT_ERROR · `4` RUNTIME_ERROR.
Output is metadata-only (sequence numbers, actions, break location) — never audit metadata
bodies (which are already scrubbed at write time).

## 4. Supply chain: SBOM + self-scan (`scripts/`)

Best-effort by default so they never break a developer machine; set the `*_STRICT` env var to
enforce in CI once the tools are installed on the runner.

- `pnpm --filter @montr/security sbom` → `scripts/sbom.sh` — generates an SPDX SBOM with
  [`syft`](https://github.com/anchore/syft) (build-plan §4.8: "SBOM per release"). Set
  `MONTR_SBOM_STRICT=1` to fail if `syft` is absent.
- `pnpm --filter @montr/security self-scan` → `scripts/self-scan.sh` — dogfoods the platform's
  own detectors over this repo: `gitleaks` (secrets), `semgrep` (SAST), `osv-scanner` (deps).
  Set `MONTR_SELFSCAN_STRICT=1` to fail on missing tools or findings. This is the seed of the
  CI **self-scan gate** (build-plan §9.2: "Montr Secure scans itself clean in CI").

## Reporting a vulnerability

Do not open a public issue. Email the maintainers with a description and reproduction. Auth /
session / crypto / access-control issues are treated as **critical** and, per golden rule #3,
any fix in those areas is always `human-required`.
