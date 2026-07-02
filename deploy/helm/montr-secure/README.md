# montr-secure (Helm chart)

On-prem, BYO-key deployment of Montr Secure with **hardened, safety-first
defaults** (§11): auto-fix OFF, DAST OFF, budget hard-halt ON, telemetry OFF,
**default-deny egress**. Designed to install on a clean cluster with only a
client LLM key.

## Install

```bash
# Bundled Postgres/Redis (starter tier) — only the LLM key is required:
helm install montr ./deploy/helm/montr-secure \
  --namespace montr --create-namespace \
  --set-file secrets.llmApiKey=./llm.key \
  --set-file secrets.fieldEncryptionKey=./field.key \
  --set networkPolicy.llmEndpoint.cidr=<LLM_IP>/32
```

Production (managed datastores, no bundled DB):

```bash
helm install montr ./deploy/helm/montr-secure -n montr --create-namespace \
  --set postgres.enabled=false --set redis.enabled=false \
  --set redis.externalUrl=redis://redis.data.svc:6379 \
  --set secrets.databaseUrl='postgresql://user:pass@pg.data.svc:5432/montr?schema=public' \
  --set-file secrets.llmApiKey=./llm.key \
  --set networkPolicy.llmEndpoint.cidr=<LLM_IP>/32 \
  --set 'networkPolicy.extraEgress[0].to[0].ipBlock.cidr=<DB_CIDR>' \
  --set 'networkPolicy.extraEgress[0].ports[0].port=5432' \
  --set 'networkPolicy.extraEgress[0].ports[0].protocol=TCP'
```

Validate without a cluster:

```bash
helm lint deploy/helm/montr-secure
helm template montr deploy/helm/montr-secure | kubeconform -strict -ignore-missing-schemas
```

## What it deploys

| Kind                      | Notes                                                          |
| ------------------------- | -------------------------------------------------------------- |
| Deployment ×3             | `api`, `worker`, `web` (distroless, non-root, RO root FS).     |
| Deployment/PVC/Service ×2 | Bundled `postgres` + `redis` (optional; `*.enabled=false`).    |
| Service ×2                | `api`, `web` (ClusterIP).                                      |
| ServiceAccount ×3         | One per component, least-privilege, no token auto-mount.       |
| ConfigMap ×2              | Infra env + the full `MontrConfig` as `config.json`.           |
| Secret                    | LLM key, field-encryption key, DB creds (unless CSI/existing). |
| NetworkPolicy             | ⛔ Default-deny egress (+ optional restrictive ingress).       |
| Ingress / HPA / PDB       | Optional (see values).                                         |
| SecretProviderClass       | Optional Vault/CSI secret mounting.                            |

## Configuration model

- **Non-secret config** — the entire `@montr/config` `MontrConfig` lives under
  `values.montrConfig`. It is rendered to `/etc/montr/config.json` (a ConfigMap)
  and mounted read-only; `MONTR_CONFIG_FILE` points the loader at it. This is the
  single place to set provider, model matrix, budgets, auto-fix policy, DAST
  scope, **retention**, **RBAC**, telemetry, and egress allow-list.
- **Infra env** — `REDIS_URL` (derived) via the `-config` ConfigMap.
- **Secrets** — see below. `DATABASE_URL` is composed automatically from
  `postgres.auth` + a generated password when the bundled DB is enabled.

A `checksum/config` pod annotation rolls the app pods whenever `config.json`
changes. Optional/URL-typed fields (`llm.endpoint`, budget ceilings,
`telemetry.endpoint`) are commented out in `values.yaml` so they are omitted from
the JSON rather than rendered as invalid empty strings.

## Secrets — three options

1. **Chart-managed Secret** (default): set `secrets.llmApiKey` /
   `secrets.fieldEncryptionKey` (prefer `--set-file`). The chart renders a
   `Secret`; the bundled-DB password is auto-generated and kept stable across
   upgrades via a `lookup` on the existing Secret.
2. **Existing Secret** (BYO): `secrets.existingSecret=<name>`. It must contain
   `MONTR_LLM_API_KEY`, `MONTR_FIELD_ENCRYPTION_KEY_REF`, `DATABASE_URL`
   (+ `POSTGRES_PASSWORD` if bundled Postgres is on).
3. **Vault / Secrets Store CSI** (`secrets.csi.enabled=true`): the chart renders
   a `SecretProviderClass`; secrets are mounted as **files** at
   `secrets.csi.mountPath` and the loader reads them via `MONTR_SECRETS_DIR`.
   `objects[].objectName` **must** be `llm-api-key` / `field-encryption-key` to
   match the loader's file map. Requires the secrets-store CSI driver + provider
   installed in the cluster.

## ⛔ NetworkPolicy (default-deny egress)

`networkPolicy.enabled=true` (default) applies an egress policy to every pod in
the release. The only egress allowed is DNS, intra-namespace traffic, and the
client LLM endpoint (`networkPolicy.llmEndpoint.cidr:port`). **Scope the CIDR**
to the real endpoint — the `0.0.0.0/0` default only restricts by port until you
do. For a broad public-LLM CIDR you can carve out private ranges via
`llmEndpoint.except`. External datastores (when bundled DB is disabled) or an
internal LLM proxy go in `networkPolicy.extraEgress`. Enforcement requires a CNI
that implements NetworkPolicy (Calico, Cilium, etc.).

## Hardening

Pod/container security contexts are values-driven (`podSecurityContext`,
`containerSecurityContext`) and default to: `runAsNonRoot`, uid/gid 65532,
`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities
dropped, `seccompProfile: RuntimeDefault`. Writable paths are `emptyDir /tmp`
(all) and `emptyDir /workspace` (worker). The `web` console runs with **no
Secret** mounted (no LLM key, no DB URL).

## Air-gapped installs

See [`../../airgap`](../../airgap) for the signed offline bundle importer
(Semgrep rulesets + CVE DB) and the internal-LLM-proxy path. In air-gapped mode,
set `montrConfig.llm.endpoint` to the internal proxy and scope
`networkPolicy.llmEndpoint.cidr` to it.

## Uninstall

```bash
helm uninstall montr -n montr
# PVCs are retained by design; delete explicitly if desired:
kubectl -n montr delete pvc -l app.kubernetes.io/instance=montr
```
