# deploy/airgap

Air-gapped install tooling (§10, §9.3). Owned by **WS-O** (built out in a later
wave). Wave 0 is a placeholder.

Goals:

- **Signed offline bundle** import for deterministic tool rulesets (Semgrep,
  gitleaks) and the CVE database (OSV/GHSA mirror) — updatable without internet.
- Internal model-proxy support so the only outbound call is the (possibly
  internal) LLM endpoint (golden rule #1 / §14).
- Bundle build + verification via cosign; SBOM via syft.

Nothing here ships in Wave 0; this directory reserves the layout so the air-gap
workstream has a home.
