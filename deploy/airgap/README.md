# deploy/airgap

Air-gapped install tooling (§10, §9.3).

`build-bundle.sh` and `import-bundle.sh` are real, working scripts — run
`--help` on either for full usage. What they do:

- **`build-bundle.sh`** (run on a connected host): packages deterministic
  scanner-ruleset / advisory-mirror artifacts into a tarball plus a
  `manifest.json` that conforms to [`manifest.schema.json`](./manifest.schema.json)
  (real SHA-256 + size per artifact). `--sign` adds a detached signature via
  `cosign` when it's installed, or falls back to a plain SHA-256 checksum file
  with an explicit "this is not a cryptographic signature" warning when it
  isn't.
- **`import-bundle.sh`** (run on the air-gapped host): verifies the signature
  or checksum (refuses to import an unverified bundle unless you pass
  `--insecure-skip-verify` explicitly), re-checks every artifact's hash
  against the manifest, and stages the verified files under `--dest-dir`
  (default `/opt/montr/airgap`), grouped by the manifest's `installTo`.

## Honest current scope

The bundle format (per `manifest.schema.json`) covers **deterministic tool
content only**: `semgrep-rules`, `gitleaks-rules`, `osv-mirror`,
`ghsa-mirror`, `cve-db`, `other`. It does **not** cover container images —
getting `api`/`web`/`worker` images onto an air-gapped host (`docker
save`/`docker load` or a private registry mirror) is a separate concern and
isn't built yet.

As of this writing, the only artifact that ships with real content by default
is `gitleaks-rules`, bundled from `.github/gitleaks.toml`. The other artifact
types have no real source data in this repo yet and `build-bundle.sh` will
**not** fabricate them:

- Semgrep rules run live against the Semgrep Registry (`p/owasp-top-ten`,
  `p/typescript`, `p/nextjs`, `p/react`, `p/secrets` —
  `packages/discovery/src/detectors/sast.ts`). There's no offline copy in
  this repo; pass `--semgrep-rules-dir` with your own pre-fetched rule YAML
  if you have one.
- The OSV/GHSA advisory data is currently a 3-entry hardcoded seed
  (`packages/discovery/src/advisories.ts`) — building a real offline mirror
  is tracked separately (audit finding A8), not by this tool. `--osv-mirror-dir`
  / `--ghsa-mirror-dir` / `--cve-db-file` let you bundle real mirror data once
  you have it.
- **No runtime code in this repo reads the files `import-bundle.sh` installs
  yet** (no "load ruleset from disk" path exists in `packages/discovery`).
  Wiring the worker to consume `--dest-dir` is future work; today
  `import-bundle.sh` verifies and stages artifacts for that work to build on.

Internal model-proxy support (so the only outbound call at runtime is the
LLM endpoint, golden rule #1 / §14) is configured separately per `DEPLOY.md`
§4 — this tool doesn't touch that.

SBOM via syft is not built here.
