# deploy/airgap

Air-gapped install tooling (§10, §9.3). Signed offline update bundles for the
deterministic-tool rulesets (Semgrep, gitleaks) and the CVE database
(OSV/GHSA/CVE mirror) — updatable without internet. The only outbound call at
runtime stays the (possibly internal) LLM endpoint (golden rule #1 / §14).

## Contents

- **`build-bundle.sh`** — run on a CONNECTED host. Packages artifacts into a
  tarball with a `manifest.json` (per `manifest.schema.json`) that carries a
  SHA-256 for every artifact, optionally emits a syft SBOM, and signs the tarball
  with cosign.
- **`import-bundle.sh`** — run on the AIR-GAPPED host. Verifies the cosign
  signature, then verifies every artifact's SHA-256 against the manifest, then
  installs each artifact to its target. **Fail-closed:** nothing installs unless
  the signature AND every hash check pass.
- **`manifest.schema.json`** — JSON Schema (draft 2020-12) for the bundle manifest.

## Build (connected host)

```bash
deploy/airgap/build-bundle.sh \
  --name montr-rules --version 1.4.2 --producer montr-ci --montr-min-version 1.0.0 \
  --add /path/to/semgrep-rules   semgrep-rules  semgrep \
  --add /path/to/gitleaks.toml   gitleaks-rules gitleaks \
  --add /path/to/osv-mirror.json osv-mirror     cve \
  --sbom --sign --key cosign.key \
  --out ./dist
# → ./dist/montr-rules-1.4.2.tar.gz (+ .sig [+ .pem for keyless] [+ .sbom.spdx.json])
```

`--add <src> <type> [installTo]` — repeatable. A directory `src` is packed as a
deterministic `.tar.gz` inside the bundle. `<type>` ∈ `semgrep-rules |
gitleaks-rules | osv-mirror | ghsa-mirror | cve-db | other`; `installTo` ∈
`semgrep | gitleaks | cve | custom`. Omit `--sign` only for testing (the importer
then requires `--insecure-skip-verify`).

## Import (air-gapped host)

```bash
# Key-based verification:
deploy/airgap/import-bundle.sh montr-rules-1.4.2.tar.gz \
  --key cosign.pub \
  --semgrep-dir /etc/montr/semgrep --gitleaks-dir /etc/montr/gitleaks --cve-dir /etc/montr/cve

# Keyless (Fulcio/Rekor) verification:
deploy/airgap/import-bundle.sh montr-rules-1.4.2.tar.gz \
  --cert bundle.pem --cert-identity ci@montr.ai \
  --cert-oidc-issuer https://token.actions.githubusercontent.com --cve-dir ...

# Verify integrity without installing:
deploy/airgap/import-bundle.sh montr-rules-1.4.2.tar.gz --key cosign.pub --verify-only
```

## Requirements

`bash`, `jq`, `tar`, `sha256sum`/`shasum`. `cosign` is required to sign
(`build --sign`) and to verify (`import`, unless `--insecure-skip-verify`);
`syft` is required for `--sbom`. Both scripts degrade gracefully / fail with a
clear message when an optional tool is missing.
