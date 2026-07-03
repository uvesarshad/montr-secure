# Montr Secure — On-Prem Deployment

Montr Secure deploys entirely inside your perimeter. The **only** permitted outbound connection is to
your own LLM endpoint (or an internal model proxy). Three install modes: **docker-compose** (single
VM), **Helm** (Kubernetes), and **air-gapped** (offline signed bundle).

---

## 0. Prerequisites

- An **enterprise-tier LLM key** for one of: Anthropic, AWS Bedrock, GCP Vertex, Azure OpenAI.
  Montr warns/blocks on a suspected data-retaining (non-enterprise) key tier.
- Recommended confirmation-tier model: Claude Opus 4.8 or Sonnet 5; Haiku 4.5 for cheap triage.
  A model below the published floor triggers an accuracy warning.
- docker-compose mode: Docker Engine + Compose v2. Helm mode: a Kubernetes cluster + Helm 3.

## 1. Configuration

All configuration is via `@montr/config` (Zod-validated; invalid config is fatal). Key settings:

| Setting                | Env / values.yaml                                      | Notes                                               |
| ---------------------- | ------------------------------------------------------ | --------------------------------------------------- |
| LLM provider           | `anthropic` \| `bedrock` \| `vertex` \| `azure-openai` | BYO-key                                             |
| LLM endpoint + key     | `MONTR_LLM_*` / k8s Secret / Vault                     | never logged, never egressed except to its provider |
| Model matrix           | triage / default / confirmation                        | warns below the floor                               |
| Budget ceiling         | hard-halt (default)                                    | breach → partial report, never a silent burn        |
| Auto-fix policy        | **OFF** by default                                     | ON opens PRs for `auto-eligible` fixes only         |
| DAST allowlist + scope | **OFF** by default                                     | staging targets only; production blocked by policy  |
| Retention              | scan/audit retention window                            |                                                     |
| Telemetry              | **OFF** by default                                     | opt-in anonymized health metrics only               |

The **hardened defaults are safety-first**: auto-fix OFF, DAST OFF, budget hard-halt ON, telemetry
OFF, egress default-deny.

---

## 2. docker-compose (single VM)

```bash
cp deploy/docker/.env.example deploy/docker/.env
$EDITOR deploy/docker/.env          # set MONTR_LLM_PROVIDER, endpoint, key, budget ceiling
docker compose -f deploy/docker/docker-compose.yml up -d
```

Brings up **api + worker + web + postgres + redis** with healthchecks. The worker image bundles the
Layer-1 scanners (Semgrep, gitleaks, osv-scanner) so discovery runs **live**. Open the operator
console at `http://<host>:3000`, create an operator account, register a repo, and run a scan.

- `docker compose ... config -q` validates the file.
- Postgres + Redis are included so the **durable** BullMQ worker path runs (not just the in-process
  driver used in CI). Data persists in named volumes; back these up.

---

## 3. Helm (Kubernetes)

```bash
helm install montr-secure deploy/helm/montr-secure \
  --set llm.provider=anthropic \
  --set-string llm.apiKey=$MONTR_LLM_KEY \
  --set budget.hardHalt=true
```

The chart ships **hardened defaults**:

- Deployments for **api / worker / web**, Services, Ingress, HPA, PodDisruptionBudget.
- **Least-privilege ServiceAccounts** (one per component, `automountServiceAccountToken: false`).
- Hardened `securityContext`: `runAsNonRoot`, dropped capabilities, `readOnlyRootFilesystem`
  (a writable `emptyDir` is mounted for the worker's repo checkout + Next.js ISR cache).
- A **default-deny-egress NetworkPolicy** allowing only DNS + intra-namespace traffic + the client
  LLM endpoint. Nothing else can leave the namespace.
- LLM key via a k8s **Secret**, with an optional Vault / Secrets-Store CSI path.

Validate before install: `helm lint --strict deploy/helm/montr-secure` and `helm template …`
(both render clean; schema-validated with kubeconform). Point it at an external Postgres/Redis or use
the bundled subcharts per `values.yaml`.

---

## 4. Air-gapped install

For a true air-gap, Montr needs no inbound internet at runtime and only the (possibly internal) LLM
endpoint outbound. Deterministic tool rulesets and the CVE/OSV database update **offline** via a
**signed bundle**:

```bash
# on a connected host: build + sign the bundle (Semgrep rulesets + OSV/CVE DB)
deploy/airgap/build-bundle.sh --sign

# on the air-gapped host: verify signature + import
deploy/airgap/import-bundle.sh montr-bundle-<date>.tar.gz.sig
```

Point the LLM gateway at an internal model proxy; the egress guard permits only that host.

---

## 5. Upgrades & operations

Versioned images; no vendor telemetry by default. Rolling upgrades via compose pull / `helm upgrade`.
See **[RUNBOOK.md](./RUNBOOK.md)** for RBAC setup, running/approving scans, the kill switch, report
exports, and backup/restore. Montr Secure scans **itself** in CI (dogfood); releases are cosign-signed
with an SBOM.
