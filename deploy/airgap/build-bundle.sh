#!/usr/bin/env bash
#
# deploy/airgap/build-bundle.sh — build a signed(-ish) offline update bundle.
#
# Run on a CONNECTED host. Produces a tarball containing whatever deterministic
# scanner-ruleset / advisory-mirror artifacts are available, plus a
# manifest.json conforming to deploy/airgap/manifest.schema.json, so it can be
# carried across the air gap and installed with import-bundle.sh.
#
# ⚠️  HONEST SCOPE (read this before relying on the bundle):
#
#   - manifest.schema.json only describes deterministic-tool content:
#     semgrep-rules, gitleaks-rules, osv-mirror, ghsa-mirror, cve-db, other.
#     It does NOT cover container images. Getting api/web/worker images onto
#     an air-gapped host is a separate concern (`docker save`/`docker load`
#     against the tags in deploy/docker/docker-compose.yml, or a private
#     registry mirror) — out of scope for this tool, and not yet built.
#
#   - As of this writing, the ONLY real local ruleset file in this repo is
#     .github/gitleaks.toml. Semgrep runs against live Semgrep Registry packs
#     (p/owasp-top-ten, p/typescript, p/nextjs, p/react, p/secrets — see
#     packages/discovery/src/detectors/sast.ts), and the OSV/GHSA advisory
#     "database" is a 3-entry hardcoded seed array
#     (packages/discovery/src/advisories.ts) — tracked as its own gap
#     (audit finding A8), NOT a real offline mirror yet. This script will NOT
#     fabricate mirror content to fill those artifact types. If you have real
#     pre-fetched semgrep rule YAML / an OSV or GHSA mirror dump / a CVE DB
#     export, point this script at them with the flags below and they will be
#     bundled for real, with real hashes.
#
#   - Nothing in this repo today reads the files import-bundle.sh installs
#     (no runtime "load rulesets from disk" path exists in packages/discovery
#     yet). That wiring is future work; this tool stages the artifacts at a
#     documented location so that work has something to consume.
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"

BUNDLE_NAME="montr-secure-airgap"
OUT_DIR="${SCRIPT_DIR}/dist"
BUNDLE_VERSION=""
SIGN=0
GITLEAKS_CONFIG="${REPO_ROOT}/.github/gitleaks.toml"
SEMGREP_RULES_DIR=""
OSV_MIRROR_DIR=""
GHSA_MIRROR_DIR=""
CVE_DB_FILE=""
COSIGN_KEY="${COSIGN_KEY:-}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Builds an air-gap update bundle (deterministic scanner rulesets + advisory
mirror data) as a tarball + manifest.json conforming to manifest.schema.json.

Options:
  --sign                   Produce a detached signature for the bundle.
                            Uses 'cosign sign-blob' if cosign is installed
                            (set COSIGN_KEY=/path/to/cosign.key for
                            cosign-key signing; without a key, cosign
                            keyless signing is attempted, which needs
                            network/OIDC and is NOT recommended for a
                            genuinely air-gapped workflow).
                            If cosign is NOT installed, falls back to a
                            SHA-256 checksum file — this is INTEGRITY ONLY,
                            not a cryptographic signature. A clear warning
                            and marker file are written either way so this
                            is never silently mistaken for a real signature.
  --out-dir DIR             Output directory (default: deploy/airgap/dist).
  --version VER             Bundle content SemVer (default: repo
                             package.json version, currently used as-is).
  --gitleaks-config FILE    Gitleaks ruleset to bundle
                             (default: .github/gitleaks.toml).
  --semgrep-rules-dir DIR   Directory of pre-fetched semgrep rule YAML to
                             bundle as the 'semgrep-rules' artifact.
                             No default — none exists in this repo yet.
  --osv-mirror-dir DIR      Directory of an OSV advisory mirror dump to
                             bundle as the 'osv-mirror' artifact.
  --ghsa-mirror-dir DIR     Directory of a GHSA advisory mirror dump to
                             bundle as the 'ghsa-mirror' artifact.
  --cve-db-file FILE        A CVE database export file to bundle as the
                             'cve-db' artifact.
  -h, --help                Show this help and exit.

At least one real artifact is required to produce a valid bundle (the
manifest schema requires artifacts.minItems=1). By default that's
.github/gitleaks.toml, so a bare '$(basename "$0")' run still works.

Examples:
  $(basename "$0") --sign
  $(basename "$0") --sign --semgrep-rules-dir ./fetched/semgrep-rules \\
                    --osv-mirror-dir ./fetched/osv
EOF
}

log()  { printf '[build-bundle] %s\n' "$*" >&2; }
warn() { printf '[build-bundle] WARNING: %s\n' "$*" >&2; }
die()  { printf '[build-bundle] ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sign) SIGN=1; shift ;;
    --out-dir) OUT_DIR="${2:?--out-dir requires a value}"; shift 2 ;;
    --version) BUNDLE_VERSION="${2:?--version requires a value}"; shift 2 ;;
    --gitleaks-config) GITLEAKS_CONFIG="${2:?--gitleaks-config requires a value}"; shift 2 ;;
    --semgrep-rules-dir) SEMGREP_RULES_DIR="${2:?--semgrep-rules-dir requires a value}"; shift 2 ;;
    --osv-mirror-dir) OSV_MIRROR_DIR="${2:?--osv-mirror-dir requires a value}"; shift 2 ;;
    --ghsa-mirror-dir) GHSA_MIRROR_DIR="${2:?--ghsa-mirror-dir requires a value}"; shift 2 ;;
    --cve-db-file) CVE_DB_FILE="${2:?--cve-db-file requires a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (see --help)" ;;
  esac
done

command -v jq >/dev/null 2>&1 || die "jq is required (used to build a schema-conformant manifest.json)."
command -v tar >/dev/null 2>&1 || die "tar is required."

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "Neither sha256sum nor shasum is available."
  fi
}

size_of() {
  if stat -f%z "$1" >/dev/null 2>&1; then
    stat -f%z "$1"       # BSD/macOS
  else
    stat -c%s "$1"        # GNU/Linux
  fi
}

if [ -z "$BUNDLE_VERSION" ]; then
  if [ -f "${REPO_ROOT}/package.json" ] && command -v jq >/dev/null 2>&1; then
    BUNDLE_VERSION="$(jq -r '.version // "0.0.0"' "${REPO_ROOT}/package.json")"
  else
    BUNDLE_VERSION="0.0.0"
  fi
fi
case "$BUNDLE_VERSION" in
  [0-9]*.[0-9]*.[0-9]*) : ;;
  *) die "Bundle version '$BUNDLE_VERSION' is not SemVer (X.Y.Z) as required by manifest.schema.json." ;;
esac

DATE_STAMP="$(date -u +%Y%m%d)"
CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_BASENAME="montr-bundle-${DATE_STAMP}"

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/montr-airgap-build.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$STAGE_DIR/artifacts"
mkdir -p "$OUT_DIR"

ARTIFACTS_JSON="$STAGE_DIR/.artifacts.jsonl"
: >"$ARTIFACTS_JSON"

add_artifact() {
  # add_artifact <source-path> <dest-relative-dir> <type> <installTo>
  local src="$1" dest_dir="$2" type="$3" install_to="$4"
  local base dest rel sha size
  base="$(basename "$src")"
  mkdir -p "$STAGE_DIR/artifacts/$dest_dir"
  dest="$STAGE_DIR/artifacts/$dest_dir/$base"
  cp -p "$src" "$dest"
  rel="artifacts/$dest_dir/$base"
  sha="$(sha256_of "$dest")"
  size="$(size_of "$dest")"
  jq -nc \
    --arg path "$rel" \
    --arg type "$type" \
    --arg sha256 "$sha" \
    --argjson sizeBytes "$size" \
    --arg installTo "$install_to" \
    '{path: $path, type: $type, sha256: $sha256, sizeBytes: $sizeBytes, installTo: $installTo}' \
    >>"$ARTIFACTS_JSON"
  log "bundled ($type): $rel  sha256=$sha  size=${size}B"
}

# --- gitleaks-rules ---------------------------------------------------------
if [ -f "$GITLEAKS_CONFIG" ]; then
  add_artifact "$GITLEAKS_CONFIG" "gitleaks" "gitleaks-rules" "gitleaks"
else
  warn "gitleaks config not found at '$GITLEAKS_CONFIG' — no gitleaks-rules artifact bundled."
fi

# --- semgrep-rules (operator-supplied; none ship in this repo yet) ---------
if [ -n "$SEMGREP_RULES_DIR" ]; then
  [ -d "$SEMGREP_RULES_DIR" ] || die "--semgrep-rules-dir '$SEMGREP_RULES_DIR' is not a directory."
  count=0
  while IFS= read -r -d '' f; do
    add_artifact "$f" "semgrep" "semgrep-rules" "semgrep"
    count=$((count + 1))
  done < <(find "$SEMGREP_RULES_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
  [ "$count" -gt 0 ] || warn "--semgrep-rules-dir '$SEMGREP_RULES_DIR' had no *.yml/*.yaml files."
else
  warn "No --semgrep-rules-dir given. Semgrep currently runs against LIVE Semgrep" \
       "Registry packs (p/owasp-top-ten, p/typescript, p/nextjs, p/react, p/secrets —" \
       "see packages/discovery/src/detectors/sast.ts); no offline copy ships in this" \
       "repo. Skipping the semgrep-rules artifact rather than fabricating one."
fi

# --- osv-mirror / ghsa-mirror (aspirational — see audit finding A8) --------
if [ -n "$OSV_MIRROR_DIR" ]; then
  [ -d "$OSV_MIRROR_DIR" ] || die "--osv-mirror-dir '$OSV_MIRROR_DIR' is not a directory."
  count=0
  while IFS= read -r -d '' f; do
    add_artifact "$f" "osv" "osv-mirror" "cve"
    count=$((count + 1))
  done < <(find "$OSV_MIRROR_DIR" -type f -print0)
  [ "$count" -gt 0 ] || warn "--osv-mirror-dir '$OSV_MIRROR_DIR' was empty."
else
  warn "No --osv-mirror-dir given. This repo's OSV/GHSA advisory data is currently" \
       "a 3-entry hardcoded seed array (packages/discovery/src/advisories.ts, see" \
       "audit finding A8) — there is no real offline OSV mirror to bundle yet."
fi

if [ -n "$GHSA_MIRROR_DIR" ]; then
  [ -d "$GHSA_MIRROR_DIR" ] || die "--ghsa-mirror-dir '$GHSA_MIRROR_DIR' is not a directory."
  count=0
  while IFS= read -r -d '' f; do
    add_artifact "$f" "ghsa" "ghsa-mirror" "cve"
    count=$((count + 1))
  done < <(find "$GHSA_MIRROR_DIR" -type f -print0)
  [ "$count" -gt 0 ] || warn "--ghsa-mirror-dir '$GHSA_MIRROR_DIR' was empty."
fi

# --- cve-db (operator-supplied) --------------------------------------------
if [ -n "$CVE_DB_FILE" ]; then
  [ -f "$CVE_DB_FILE" ] || die "--cve-db-file '$CVE_DB_FILE' does not exist."
  add_artifact "$CVE_DB_FILE" "cve" "cve-db" "cve"
fi

ARTIFACT_COUNT="$(wc -l <"$ARTIFACTS_JSON" | tr -d ' ')"
if [ "$ARTIFACT_COUNT" -lt 1 ]; then
  die "No artifacts to bundle (manifest.schema.json requires artifacts.minItems=1)." \
      "Nothing existed at the default sources and no --*-dir/--*-file flags were given."
fi

ARTIFACTS_ARRAY_JSON="$(jq -sc '.' "$ARTIFACTS_JSON")"

PRODUCER="$(id -un 2>/dev/null || echo unknown)@$(hostname 2>/dev/null || echo unknown-host) via deploy/airgap/build-bundle.sh"

jq -n \
  --arg schemaVersion "1" \
  --arg name "$BUNDLE_NAME" \
  --arg version "$BUNDLE_VERSION" \
  --arg createdAt "$CREATED_AT" \
  --arg producer "$PRODUCER" \
  --arg montrMinVersion "$BUNDLE_VERSION" \
  --argjson artifacts "$ARTIFACTS_ARRAY_JSON" \
  '{
    schemaVersion: $schemaVersion,
    name: $name,
    version: $version,
    createdAt: $createdAt,
    producer: $producer,
    montrMinVersion: $montrMinVersion,
    artifacts: $artifacts
  }' >"$STAGE_DIR/manifest.json"

cp "${SCRIPT_DIR}/manifest.schema.json" "$STAGE_DIR/manifest.schema.json"

log "manifest.json built with $ARTIFACT_COUNT artifact(s)."

TARBALL="${OUT_DIR}/${OUT_BASENAME}.tar.gz"
tar -czf "$TARBALL" -C "$STAGE_DIR" manifest.json manifest.schema.json artifacts
log "wrote $TARBALL"

if [ "$SIGN" -eq 1 ]; then
  if command -v cosign >/dev/null 2>&1; then
    SIG_FILE="${TARBALL}.sig"
    if [ -n "$COSIGN_KEY" ]; then
      log "signing with cosign (key: $COSIGN_KEY)..."
      cosign sign-blob --key "$COSIGN_KEY" --output-signature "$SIG_FILE" --yes "$TARBALL"
      METHOD="cosign-key"
    else
      warn "COSIGN_KEY not set — attempting cosign KEYLESS signing. This requires" \
           "network/OIDC access at sign time and Rekor connectivity to VERIFY later," \
           "which does not fit a genuinely air-gapped workflow. Prefer" \
           "COSIGN_KEY=/path/to/cosign.key for real offline-verifiable signing."
      cosign sign-blob --output-signature "$SIG_FILE" --yes "$TARBALL"
      METHOD="cosign-keyless"
    fi
    log "wrote $SIG_FILE (method: $METHOD)"
    cat >"${TARBALL}.SIGNING-METHOD.txt" <<EOF
Signed with real cosign ($METHOD) at $CREATED_AT.
Verify with: cosign verify-blob --signature ${OUT_BASENAME}.tar.gz.sig ${OUT_BASENAME}.tar.gz
EOF
  else
    # ⚠️  Honest fallback: NOT a cryptographic signature. See DEPLOY.md / README.
    CHECKSUM_FILE="${TARBALL}.sha256"
    (cd "$OUT_DIR" && sha256_of "$(basename "$TARBALL")") >/dev/null # sanity
    printf '%s  %s\n' "$(sha256_of "$TARBALL")" "$(basename "$TARBALL")" >"$CHECKSUM_FILE"
    warn "cosign is NOT installed in this environment. Falling back to a" \
         "SHA-256 checksum file ($CHECKSUM_FILE)."
    warn "THIS IS INTEGRITY-ONLY, NOT A CRYPTOGRAPHIC SIGNATURE: it proves the" \
         "tarball wasn't corrupted in transit, but NOT who produced it — anyone" \
         "who can replace the .sha256 file alongside the tarball can forge it."
    warn "For real provenance guarantees, install cosign and re-run with --sign" \
         "(and set COSIGN_KEY to a real offline keypair)."
    cat >"${TARBALL}.UNSIGNED-CHECKSUM-ONLY.txt" <<EOF
No cosign binary was available on this build host at $CREATED_AT.
${CHECKSUM_FILE} is a SHA-256 checksum, NOT a cryptographic signature —
it detects corruption/tampering-in-transit only, and carries no proof of
who built this bundle. Treat a bundle verified only against this file as
UNSIGNED. For real signing: install cosign, set COSIGN_KEY, re-run
'build-bundle.sh --sign'.
EOF
  fi
else
  log "built unsigned (pass --sign to add a signature/checksum)."
fi

log "done."
log "  tarball:  $TARBALL"
log "  manifest: $ARTIFACT_COUNT artifact(s), version=$BUNDLE_VERSION"
log "Next: copy '$TARBALL' (and any .sig/.sha256/.cert sibling files) across the"
log "gap, then on the air-gapped host run: deploy/airgap/import-bundle.sh '$(basename "$TARBALL")'"
